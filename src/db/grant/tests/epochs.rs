//! Epochs (I9, E1): one write refuses every grant of a scope authenticated at
//! or before it, at the rotation script and at the access check, while a later
//! authentication is unaffected; `logout/all` sets the user epoch instead of
//! planting the user tombstone.

use super::*;

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
