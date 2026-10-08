//! Epochs (I9, E1): one write refuses every grant of a scope authenticated at
//! or before it, at the rotation script and at the access check, while a later
//! authentication is unaffected; `logout/all` sets the user epoch instead of
//! planting the user tombstone. The last section pins the other writer of client
//! epochs: the start-up sync of static clients.

use super::*;
use crate::db::{ClientClass, ClientEntry, DBClient, SiwxClientMetadata};
use openidconnect::RedirectUrl;

/// Redis `TIME` in milliseconds.
async fn redis_ms(client: &RedisClient) -> i64 {
    let (secs, micros): (String, String) = raw(client, &["TIME"]).await;
    secs.parse::<i64>().expect("TIME") * 1000 + micros.parse::<i64>().expect("TIME") / 1000
}

fn grant_of(username: &str, client_id: &str, device_id: &str, auth_ms: Option<i64>) -> NewGrant {
    let mut g = matrix_grant(username, device_id);
    g.client_id = client_id.to_string();
    if device_id.is_empty() {
        g.kind = GrantKind::Oidc;
    }
    g.auth_ms = auth_ms;
    g
}

/// The access token of `issued` is refused by the access check.
async fn access_refused(client: &RedisClient, issued: &IssuedGrant, what: &str) {
    assert!(
        client
            .check_access_token(&issued.access_token)
            .await
            .unwrap()
            .is_none(),
        "{what}: the access token is still accepted"
    );
}

/// The refresh token `presented` is refused by an epoch.
async fn refresh_revoked(client: &RedisClient, presented: &str, what: &str) {
    assert_eq!(
        rotate(client, presented).await,
        RotateOutcome::Invalid(InvalidReason::Revoked),
        "{what}: the refresh token is not refused by the epoch"
    );
}

/// The grant `issued` is accepted at both checks; returns its rotation.
async fn accepted(client: &RedisClient, issued: &IssuedGrant, what: &str) -> RotatedPair {
    assert!(
        client
            .check_access_token(&issued.access_token)
            .await
            .unwrap()
            .is_some(),
        "{what}: the access token is refused"
    );
    match rotate(client, issued.refresh_token.as_deref().unwrap()).await {
        RotateOutcome::Rotated(pair) => pair,
        other => panic!("{what}: the refresh token is refused: {other:?}"),
    }
}

async fn exists(client: &RedisClient, key: &str) -> bool {
    raw::<i64>(client, &["EXISTS", key]).await == 1
}

/// E1: after one user-epoch write, every grant of the user authenticated
/// before it is refused at the access check and at the rotation script (the
/// current token and a replay alike), with no grant enumerated or deleted by
/// the write; another user's grant is untouched.
#[tokio::test]
async fn e1_one_user_epoch_refuses_every_older_grant_of_the_user() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("epu{}", nonce());
    let other = format!("epuo{}", nonce());
    let a = issue(&client, &grant_of(&user, "client-a", "DEVA", None)).await;
    let a_rt = a.refresh_token.clone().unwrap();
    let a1 = rotated(rotate(&client, &a_rt).await);
    let b = issue(&client, &grant_of(&user, "client-b", "", None)).await;
    let c = issue(&client, &grant_of(&other, "client-a", "DEVA", None)).await;

    client.set_epoch(EpochScope::User(&user)).await.unwrap();

    access_refused(&client, &a, "older generation").await;
    let a1_access = IssuedGrant {
        access_token: a1.pair.access_token.clone(),
        ..a.clone()
    };
    access_refused(&client, &a1_access, "rotated pair").await;
    access_refused(&client, &b, "deviceless grant").await;
    for g in [&a, &b] {
        assert!(
            exists(&client, &grant_key(&g.grant_id)).await,
            "the epoch write alone refuses: no grant is enumerated or deleted"
        );
    }
    refresh_revoked(&client, &a_rt, "a replay of the previous token").await;
    refresh_revoked(&client, b.refresh_token.as_deref().unwrap(), "deviceless").await;
    for g in [&a, &b] {
        assert!(
            !exists(&client, &grant_key(&g.grant_id)).await,
            "a grant an epoch refused is deleted at the refresh"
        );
    }
    accepted(&client, &c, "another user's grant").await;
}

/// E1, the half that fails on the tombstone: `logout/all` (and deactivation,
/// erasure: `revoke_all_user_tokens`) sets the user epoch and plants no user
/// tombstone, so a sign-in right after it refreshes at once, while the grants
/// from before are gone.
#[tokio::test]
async fn e1_after_logout_all_a_new_sign_in_refreshes_at_once() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("eplo{}", nonce());
    let old = issue(&client, &grant_of(&user, "client-a", "DEVA", None)).await;
    client.revoke_all_user_tokens(&user).await.unwrap();
    assert!(
        exists(&client, &EpochScope::User(&user).key()).await,
        "logout/all sets the user epoch"
    );
    assert!(
        !exists(&client, &user_tombstone_key(&user)).await,
        "logout/all plants no user tombstone"
    );
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let new = issue(&client, &grant_of(&user, "client-a", "DEVB", None)).await;
    let pair = accepted(&client, &new, "a sign-in after logout/all").await;
    match rotate(&client, new.refresh_token.as_deref().unwrap()).await {
        RotateOutcome::Replayed(replayed) => {
            assert_eq!(
                replayed.pair, pair.pair,
                "its replay recovers the same pair"
            )
        }
        other => panic!("a replay after logout/all: {other:?}"),
    }
    access_refused(&client, &old, "the grant from before logout/all").await;
    assert_eq!(
        rotate(&client, old.refresh_token.as_deref().unwrap()).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant),
        "the grant from before logout/all is deleted"
    );
}

/// The epoch comparison, to the millisecond: a grant authenticated before the
/// epoch or in its own millisecond is refused, one a millisecond later is
/// not. A grant written without `auth_ms` (before epochs existed) counts from
/// the start of its `auth_time` second, so it is refused when the epoch falls
/// in that second.
#[tokio::test]
async fn the_epoch_comparison_is_at_or_before_to_the_millisecond() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let client_id = format!("epms-{}", nonce());
    let epoch = client
        .set_epoch(EpochScope::Client(&client_id))
        .await
        .unwrap();
    let user = |tag: &str| format!("epms{tag}{}", nonce());
    for (offset, refused) in [(-1, true), (0, true), (1, false)] {
        let g = issue(
            &client,
            &grant_of(&user("o"), &client_id, "", Some(epoch + offset)),
        )
        .await;
        let what = format!("auth_ms = epoch {offset:+}");
        if refused {
            access_refused(&client, &g, &what).await;
            refresh_revoked(&client, g.refresh_token.as_deref().unwrap(), &what).await;
        } else {
            accepted(&client, &g, &what).await;
        }
    }
    let second = epoch.div_euclid(1000);
    for (auth_time, refused) in [(second, true), (second + 1, false)] {
        let g = issue(
            &client,
            &grant_of(&user("s"), &client_id, "", Some(epoch + 1)),
        )
        .await;
        let key = grant_key(&g.grant_id);
        let _: i64 = raw(&client, &["HDEL", &key, "auth_ms"]).await;
        let _: i64 = raw(
            &client,
            &["HSET", &key, "auth_time", &auth_time.to_string()],
        )
        .await;
        let what = format!(
            "no auth_ms, auth_time = epoch second + {}",
            auth_time - second
        );
        if refused {
            access_refused(&client, &g, &what).await;
            refresh_revoked(&client, g.refresh_token.as_deref().unwrap(), &what).await;
        } else {
            accepted(&client, &g, &what).await;
        }
    }
}

/// E1: a client epoch refuses that client's older grants only: another
/// client's grant of the same user lives on, and a later grant of the client
/// is accepted.
#[tokio::test]
async fn e1_a_client_epoch_refuses_that_clients_older_grants_only() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let x = format!("epcx-{}", nonce());
    let y = format!("epcy-{}", nonce());
    let user = format!("epc{}", nonce());
    let x1 = issue(&client, &grant_of(&user, &x, "DEVA", None)).await;
    let x2 = issue(
        &client,
        &grant_of(&format!("epc2{}", nonce()), &x, "", None),
    )
    .await;
    let y1 = issue(&client, &grant_of(&user, &y, "DEVB", None)).await;
    let epoch = client.set_epoch(EpochScope::Client(&x)).await.unwrap();
    for (g, what) in [
        (&x1, "the client's grant"),
        (&x2, "another user's grant of the client"),
    ] {
        access_refused(&client, g, what).await;
        refresh_revoked(&client, g.refresh_token.as_deref().unwrap(), what).await;
    }
    accepted(&client, &y1, "another client's grant").await;
    let later = issue(&client, &grant_of(&user, &x, "DEVC", Some(epoch + 1))).await;
    accepted(&client, &later, "a later grant of the client").await;
}

/// E1: a global epoch refuses every older grant, of any client and user. It
/// runs in its own Redis database: a global epoch in the shared one would
/// refuse the grants of every test running beside it.
#[tokio::test]
async fn e1_a_global_epoch_refuses_every_older_grant() {
    let Some(_) = crate::test_support::redis().await else {
        return;
    };
    let mut url = crate::test_support::redis_url();
    url.set_path("/12");
    let client = RedisClient::new(&url).await.expect("client on database 12");
    let older = [
        issue(
            &client,
            &grant_of(&format!("epg{}", nonce()), "client-a", "DEVA", None),
        )
        .await,
        issue(
            &client,
            &grant_of(&format!("epg{}", nonce()), "client-b", "", None),
        )
        .await,
    ];
    let epoch = client.set_epoch(EpochScope::Global).await.unwrap();
    let mut failures = Vec::new();
    for (i, g) in older.iter().enumerate() {
        if client
            .check_access_token(&g.access_token)
            .await
            .unwrap()
            .is_some()
        {
            failures.push(format!("older grant {i}: access token accepted"));
        }
        let outcome = rotate(&client, g.refresh_token.as_deref().unwrap()).await;
        if outcome != RotateOutcome::Invalid(InvalidReason::Revoked) {
            failures.push(format!("older grant {i}: refresh gave {outcome:?}"));
        }
    }
    let later = issue(
        &client,
        &grant_of(&format!("epg{}", nonce()), "client-a", "", Some(epoch + 1)),
    )
    .await;
    let later_ok = matches!(
        rotate(&client, later.refresh_token.as_deref().unwrap()).await,
        RotateOutcome::Rotated(_)
    );
    let _: i64 = raw(&client, &["DEL", KV_EPOCH_GLOBAL]).await;
    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        later_ok,
        "a grant authenticated after the global epoch rotates"
    );
}

/// A legacy refresh token whose entry predates an epoch is not lifted (the
/// entry stays as it is), and a legacy access token that predates it is
/// refused by the access check.
#[tokio::test]
async fn a_legacy_token_older_than_an_epoch_is_refused() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("eplg{}", nonce());
    let (refresh, _) = seed_legacy(&client, &user, "DEVL", REFRESH_TOKEN_TTL as i64, true).await;
    let (access, _) = seed_legacy(&client, &user, "DEVL", ACCESS_TOKEN_TTL as i64, true).await;
    assert!(client.check_access_token(&access).await.unwrap().is_some());
    client.set_epoch(EpochScope::User(&user)).await.unwrap();
    assert!(
        client.check_access_token(&access).await.unwrap().is_none(),
        "a legacy access token older than the epoch is refused"
    );
    let legacy = peek_legacy(&client, &refresh).await;
    assert_eq!(
        client
            .lift_legacy_refresh_token(&request(&refresh), &legacy, false)
            .await
            .unwrap(),
        RotateOutcome::Invalid(InvalidReason::Revoked)
    );
    assert!(
        exists(&client, &format!("token/{refresh}")).await,
        "a refused legacy token stays as it is"
    );
}

/// The epoch comparison made outside the scripts for a legacy access token
/// follows the scripts' rule (`the_epoch_comparison_is_at_or_before_to_the_millisecond`):
/// its `iat`, counted from the start of its second, is refused by an epoch in
/// that very millisecond or after it, and accepted by one a millisecond earlier.
#[tokio::test]
async fn the_legacy_access_check_refuses_at_or_before_the_epoch_to_the_millisecond() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("eplms{}", nonce());
    let (access, meta) = seed_legacy(&client, &user, "DEVL", ACCESS_TOKEN_TTL as i64, true).await;
    let key = EpochScope::User(&user).key();
    let auth_ms = meta.iat * 1000;
    for (offset, refused) in [(-1, true), (0, true), (1, false)] {
        let _: () = raw(&client, &["SET", &key, &(auth_ms - offset).to_string()]).await;
        assert_eq!(
            client.check_access_token(&access).await.unwrap().is_none(),
            refused,
            "iat ms = epoch {offset:+}: refused must be {refused}"
        );
    }
    let _: i64 = raw(&client, &["DEL", &key]).await;
}

/// The same rule at teardown's resolver ([`RedisClient::resolve_refresh_token`]):
/// a refresh token whose grant was authenticated in the epoch's millisecond or
/// before it resolves to nothing, one authenticated a millisecond later to its
/// grant; a grant written without `auth_ms` counts from the start of its
/// `auth_time` second.
#[tokio::test]
async fn the_teardown_resolver_refuses_at_or_before_the_epoch_to_the_millisecond() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("eprms{}", nonce());
    let auth_ms = redis_ms(&client).await;
    let g = issue(&client, &grant_of(&user, "client-a", "DEVR", Some(auth_ms))).await;
    let refresh = g.refresh_token.clone().unwrap();
    let key = EpochScope::User(&user).key();
    for (offset, refused) in [(-1, true), (0, true), (1, false)] {
        let _: () = raw(&client, &["SET", &key, &(auth_ms - offset).to_string()]).await;
        assert_eq!(
            client
                .resolve_refresh_token(&refresh)
                .await
                .unwrap()
                .is_none(),
            refused,
            "auth_ms = epoch {offset:+}: refused must be {refused}"
        );
    }
    let grant = grant_key(&g.grant_id);
    let second = auth_ms.div_euclid(1000);
    let _: i64 = raw(&client, &["HDEL", &grant, "auth_ms"]).await;
    let _: i64 = raw(&client, &["HSET", &grant, "auth_time", &second.to_string()]).await;
    for (epoch, refused) in [(second * 1000, true), (second * 1000 - 1, false)] {
        let _: () = raw(&client, &["SET", &key, &epoch.to_string()]).await;
        assert_eq!(
            client
                .resolve_refresh_token(&refresh)
                .await
                .unwrap()
                .is_none(),
            refused,
            "no auth_ms, epoch = auth_time second {:+} ms: refused must be {refused}",
            epoch - second * 1000
        );
    }
    let _: i64 = raw(&client, &["DEL", &key]).await;
}

/// The library function behind the operator path: the epoch is Redis `TIME`
/// in milliseconds, persistent, and never moves earlier.
#[tokio::test]
async fn set_epoch_takes_redis_time_and_never_moves_earlier() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let client_id = format!("epset-{}", nonce());
    let scope = EpochScope::Client(&client_id);
    let before = redis_ms(&client).await;
    let epoch = client.set_epoch(scope).await.unwrap();
    let after = redis_ms(&client).await;
    assert!(
        (before..=after).contains(&epoch),
        "{before} <= {epoch} <= {after}"
    );
    assert_eq!(
        raw::<i64>(&client, &["TTL", &scope.key()]).await,
        -1,
        "persistent"
    );
    let later = after + 3_600_000;
    let _: () = raw(&client, &["SET", &scope.key(), &later.to_string()]).await;
    assert_eq!(
        client.set_epoch(scope).await.unwrap(),
        later,
        "an epoch never moves earlier"
    );
    let _: i64 = raw(&client, &["DEL", &scope.key()]).await;
}

/// The scripts read the epochs under the names [`EpochScope::key`] writes.
#[test]
fn the_scripts_name_the_epoch_keys_the_library_writes() {
    assert_eq!(EpochScope::Global.key(), "epoch:global");
    assert_eq!(EpochScope::Client("c").key(), "epoch:client/c");
    assert_eq!(EpochScope::User("u").key(), "epoch:user/u");
    for name in [
        format!("'{KV_EPOCH_GLOBAL}'"),
        format!("'{KV_EPOCH_CLIENT_PREFIX}/' .. client_id"),
        format!("'{KV_EPOCH_USER_PREFIX}/' .. username"),
    ] {
        assert!(LUA_EPOCH.contains(&name), "LUA_EPOCH must read {name}");
    }
}

// -- The start-up sync of static clients ---------------------------------------------------
//
// Every test syncs through a client from `test_support`, which records static clients in a
// set of its own, and names its own client ids, so none prunes or ends the grants of a stack
// that shares this Redis. A client carries one set: a test that needs the starts of several
// independent clients takes a fresh client for each.

const MAIL: [&str; 2] = ["openid", "io.inblock.mail"];

/// A static client as `default_clients` configures it.
fn static_client(class: ClientClass, allowed: Option<&[&str]>) -> ClientEntry {
    ClientEntry {
        class,
        allowed_scopes: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
        ..ClientEntry::new(
            "not-a-secret-test-fixture",
            SiwxClientMetadata::new(
                vec![RedirectUrl::new("https://mail.example.org/cb".into()).unwrap()],
                Default::default(),
            ),
            None,
        )
    }
}

fn generic_client(allowed: &[&str]) -> ClientEntry {
    static_client(ClientClass::Generic, Some(allowed))
}

fn matrix_client() -> ClientEntry {
    static_client(ClientClass::Matrix, None)
}

/// The client epoch of `id`; `None` when none was ever set.
async fn client_epoch(client: &RedisClient, id: &str) -> Option<i64> {
    client
        .get_raw(&EpochScope::Client(id).key())
        .await
        .unwrap()
        .map(|epoch| epoch.parse().expect("an epoch is a number"))
}

/// One start of the server: the static clients in Redis become `clients`. Returns how many
/// clients the start deleted.
async fn start_with(client: &RedisClient, clients: Vec<(&str, ClientEntry)>) -> usize {
    let clients = clients
        .into_iter()
        .map(|(id, entry)| (id.to_string(), entry))
        .collect();
    client
        .sync_static_clients(clients)
        .await
        .expect("the sync succeeds")
}

async fn forget(client: &RedisClient, ids: &[&str]) {
    for id in ids {
        client.del_raw(&format!("clients/{id}")).await.ok();
        client.del_raw(&EpochScope::Client(id).key()).await.ok();
    }
    client.del_raw(&client.static_clients_key).await.ok();
}

/// A start that finds the configuration it left behind sets no epoch, whatever order the
/// scopes are listed in, and every grant issued before it keeps working.
#[tokio::test]
async fn a_restart_with_an_unchanged_configuration_sets_no_epoch() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let id = format!("sync-same-{}", nonce());
    let user = format!("sync{}", nonce());
    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    let older = issue(&client, &grant_of(&user, &id, "", None)).await;

    let reordered = ["io.inblock.mail", "openid", "io.inblock.mail"];
    for scopes in [&MAIL[..], &reordered[..]] {
        let deleted = start_with(&client, vec![(&id, generic_client(scopes))]).await;
        assert_eq!(deleted, 0);
    }

    assert_eq!(
        client_epoch(&client, &id).await,
        None,
        "a restart with the same configuration must not end a session"
    );
    accepted(&client, &older, "a grant issued before the restarts").await;
    forget(&client, &[&id]).await;
}

/// Removing a generic client from the configuration ends every grant it holds, and no
/// other client's. The id keeps its epoch when it is configured again: what was issued
/// before stays refused, and a sign-in after it works at once.
#[tokio::test]
async fn removing_a_generic_static_client_ends_its_grants() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let id = format!("sync-removed-{}", nonce());
    let other = format!("sync-other-{}", nonce());
    let user = format!("sync{}", nonce());
    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    let older = issue(&client, &grant_of(&user, &id, "", None)).await;
    let bystander = issue(&client, &grant_of(&user, &other, "", None)).await;

    let deleted = start_with(&client, Vec::new()).await;

    assert_eq!(deleted, 1);
    assert!(client.get_client(id.clone()).await.unwrap().is_none());
    let epoch = client_epoch(&client, &id)
        .await
        .expect("the removal set the client epoch");
    access_refused(&client, &older, "a grant of the removed client").await;
    refresh_revoked(&client, older.refresh_token.as_deref().unwrap(), "removed").await;
    accepted(&client, &bystander, "another client's grant").await;

    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    assert_eq!(
        client_epoch(&client, &id).await,
        Some(epoch),
        "configuring the id again neither moves nor clears its epoch"
    );
    let later = issue(&client, &grant_of(&user, &id, "", Some(epoch + 1))).await;
    accepted(&client, &later, "a sign-in after the removal").await;
    forget(&client, &[&id, &other]).await;
}

/// A Matrix-class client's sessions are Matrix sessions: removing the client ends none.
#[tokio::test]
async fn removing_a_matrix_class_static_client_sets_no_epoch() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let id = format!("sync-matrix-{}", nonce());
    start_with(&client, vec![(&id, matrix_client())]).await;
    let session = issue(
        &client,
        &grant_of(&format!("sync{}", nonce()), &id, "DEVA", None),
    )
    .await;

    let deleted = start_with(&client, Vec::new()).await;

    assert_eq!(deleted, 1);
    assert!(client.get_client(id.clone()).await.unwrap().is_none());
    assert_eq!(client_epoch(&client, &id).await, None);
    accepted(&client, &session, "a Matrix session of the removed client").await;
    forget(&client, &[&id]).await;
}

/// A client that changes class ends its grants, in either direction.
#[tokio::test]
async fn a_class_change_ends_the_grants_in_either_direction() {
    let cases = [
        (
            "generic to Matrix",
            generic_client(&MAIL),
            matrix_client(),
            "",
        ),
        (
            "Matrix to generic",
            matrix_client(),
            generic_client(&MAIL),
            "DEVA",
        ),
    ];
    for (what, before, after, device_id) in cases {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let id = format!("sync-class-{}", nonce());
        start_with(&client, vec![(&id, before)]).await;
        let older = issue(
            &client,
            &grant_of(&format!("sync{}", nonce()), &id, device_id, None),
        )
        .await;

        let deleted = start_with(&client, vec![(&id, after)]).await;

        assert_eq!(deleted, 0, "{what}");
        assert!(client_epoch(&client, &id).await.is_some(), "{what}");
        access_refused(&client, &older, what).await;
        refresh_revoked(&client, older.refresh_token.as_deref().unwrap(), what).await;
        forget(&client, &[&id]).await;
    }
}

/// A generic client whose allowed scopes change, narrowed or widened or one swapped for
/// another, ends its grants; a change to nothing but its secret and redirect URI does not.
#[tokio::test]
async fn a_change_of_the_allowed_scopes_ends_the_grants_and_nothing_else_does() {
    let cases = [
        ("narrowed", generic_client(&["openid"]), true),
        (
            "widened",
            generic_client(&["openid", "io.inblock.mail", "offline_access"]),
            true,
        ),
        ("one swapped", generic_client(&["openid", "profile"]), true),
        (
            "another secret and redirect URI",
            ClientEntry {
                secret_digest: crate::db::tokens::digest("another-secret"),
                metadata: SiwxClientMetadata::new(
                    vec![RedirectUrl::new("https://other.example.org/cb".into()).unwrap()],
                    Default::default(),
                ),
                ..generic_client(&MAIL)
            },
            false,
        ),
    ];
    for (what, after, ends) in cases {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let id = format!("sync-scopes-{}", nonce());
        start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
        let older = issue(
            &client,
            &grant_of(&format!("sync{}", nonce()), &id, "", None),
        )
        .await;

        start_with(&client, vec![(&id, after)]).await;

        assert_eq!(client_epoch(&client, &id).await.is_some(), ends, "{what}");
        if ends {
            access_refused(&client, &older, what).await;
            refresh_revoked(&client, older.refresh_token.as_deref().unwrap(), what).await;
        } else {
            accepted(&client, &older, what).await;
        }
        forget(&client, &[&id]).await;
    }
}

/// Each epoch the sync sets is a warning that names the client and the reason, so an
/// operator who started an instance with another map sees what it ended; a start that
/// changes nothing says nothing of the kind.
#[tokio::test]
async fn the_sync_logs_each_epoch_it_sets_with_the_client_and_the_reason() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let id = format!("sync-log-{}", nonce());
    let log = crate::test_support::LogCapture::start();

    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    assert!(
        !log.output().contains(&id),
        "a start that changes nothing logs nothing about the client: {}",
        log.output()
    );
    start_with(&client, vec![(&id, generic_client(&["openid"]))]).await;
    start_with(&client, Vec::new()).await;

    let output = log.output();
    let ended: Vec<&str> = output.lines().filter(|l| l.contains(&id)).collect();
    assert_eq!(ended.len(), 2, "one line per epoch: {output}");
    for (line, reason) in ended.iter().zip(["scopes_changed", "removed"]) {
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains(&format!("client_id={id}")), "{line}");
        assert!(line.contains(&format!("reason=\"{reason}\"")), "{line}");
    }
    forget(&client, &[&id]).await;
}

/// The stored entry says which class a client's grants were issued under. One that is
/// missing, or that this build cannot read, says nothing, and ending sessions that may be
/// Matrix sessions is the worse error: no epoch. The sync still replaces or deletes it.
#[tokio::test]
async fn a_missing_or_unreadable_stored_entry_sets_no_epoch() {
    let unreadable = [
        ("not json", "not json".to_string()),
        (
            "a class this build does not know",
            serde_json::json!({
                "secret_digest": "d",
                "metadata": {"redirect_uris": ["https://mail.example.org/cb"]},
                "class": "from-a-later-build",
            })
            .to_string(),
        ),
    ];
    for (what, stored) in unreadable {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let replaced = format!("sync-unreadable-{}", nonce());
        let removed = format!("sync-unreadable-{}", nonce());
        for id in [&replaced, &removed] {
            client
                .set_raw(&format!("clients/{id}"), &stored)
                .await
                .unwrap();
        }
        let tracking = client.static_clients_key.clone();
        let _: i64 = raw(&client, &["SADD", &tracking, &removed]).await;

        let deleted = start_with(&client, vec![(&replaced, generic_client(&MAIL))]).await;

        assert_eq!(deleted, 1, "{what}");
        assert!(client.get_client(replaced.clone()).await.unwrap().is_some());
        assert!(client.get_client(removed.clone()).await.unwrap().is_none());
        for id in [&replaced, &removed] {
            assert_eq!(client_epoch(&client, id).await, None, "{what}");
        }
        forget(&client, &[&replaced, &removed]).await;
    }

    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let missing = format!("sync-missing-{}", nonce());
    let tracking = client.static_clients_key.clone();
    let _: i64 = raw(&client, &["SADD", &tracking, &missing]).await;
    assert_eq!(start_with(&client, Vec::new()).await, 1);
    assert_eq!(client_epoch(&client, &missing).await, None);
    forget(&client, &[&missing]).await;
}

/// The epoch is written BEFORE the entry is replaced or deleted. When it cannot be written
/// the start fails with the old entry in place and its id still tracked, so the next start
/// decides again and sets it. The other order could lose the change for good: the next
/// start would find the new entry and see no change.
#[tokio::test]
async fn a_failed_epoch_write_leaves_the_old_entry_so_the_next_start_repeats_it() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let id = format!("sync-order-{}", nonce());
    let narrowed = generic_client(&["openid"]);
    start_with(&client, vec![(&id, generic_client(&MAIL))]).await;
    let older = issue(
        &client,
        &grant_of(&format!("sync{}", nonce()), &id, "", None),
    )
    .await;
    // A list where the epoch belongs: the script that writes it fails.
    let epoch_key = EpochScope::Client(&id).key();
    let _: i64 = raw(&client, &["LPUSH", &epoch_key, "not-an-epoch"]).await;

    let failed = client
        .sync_static_clients(vec![(id.clone(), narrowed.clone())])
        .await;
    assert!(failed.is_err(), "a start that cannot end the grants fails");
    let stored = client.get_client(id.clone()).await.unwrap().unwrap();
    assert_eq!(
        stored.allowed_scopes,
        Some(MAIL.iter().map(|s| s.to_string()).collect()),
        "the old entry is still in place"
    );
    let _: i64 = raw(&client, &["DEL", &epoch_key]).await;
    start_with(&client, vec![(&id, narrowed)]).await;
    assert!(client_epoch(&client, &id).await.is_some());
    access_refused(&client, &older, "after the repeated start").await;

    let _: i64 = raw(&client, &["DEL", &epoch_key]).await;
    let _: i64 = raw(&client, &["LPUSH", &epoch_key, "not-an-epoch"]).await;
    let failed = client.sync_static_clients(Vec::new()).await;
    assert!(failed.is_err(), "so does a removal");
    assert!(
        client.get_client(id.clone()).await.unwrap().is_some(),
        "the client is still registered"
    );
    let tracking = client.static_clients_key.clone();
    let still_tracked: i64 = raw(&client, &["SISMEMBER", &tracking, &id]).await;
    assert_eq!(still_tracked, 1, "and still tracked, for the next start");
    forget(&client, &[&id]).await;
}
