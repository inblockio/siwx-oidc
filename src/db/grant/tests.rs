//! Redis-backed tests of the grant layer (`crate::test_support::redis`).

use super::*;
use crate::db::{ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique suffix so tests sharing one Redis never see each other's keys.
fn nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{t}x{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

async fn raw<T: redis::FromRedisValue>(client: &RedisClient, args: &[&str]) -> T {
    let mut conn = client.pool.get().await.expect("pool");
    let mut cmd = redis::cmd(args[0]);
    for a in &args[1..] {
        cmd.arg(*a);
    }
    cmd.query_async(&mut *conn).await.expect("redis command")
}

/// Whether the tombstone `key` is planted.
async fn tombstone(client: &RedisClient, key: &str) -> bool {
    raw::<i64>(client, &["EXISTS", key]).await == 1
}

async fn hgetall(client: &RedisClient, key: &str) -> HashMap<String, String> {
    raw(client, &["HGETALL", key]).await
}

fn matrix_grant(username: &str, device_id: &str) -> NewGrant {
    NewGrant {
        kind: GrantKind::MatrixDevice,
        username: username.to_string(),
        did: format!("did:key:z6Mk{username}"),
        client_id: "client-a".to_string(),
        confidential_client: false,
        device_id: device_id.to_string(),
        scope: "openid urn:matrix:client:api:*".to_string(),
        name: "n".to_string(),
        auth_ms: Some(1_700_000_000_000),
        access_ttl: ACCESS_TOKEN_TTL,
        refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
    }
}

async fn issue(client: &RedisClient, new: &NewGrant) -> IssuedGrant {
    client.issue_grant(new).await.expect("issue_grant")
}

async fn rotate(client: &RedisClient, presented: &str) -> RotateOutcome {
    client
        .rotate_refresh_token(&RotateRequest {
            presented,
            client_id: None,
            refuse_confidential: false,
        })
        .await
        .expect("rotate_refresh_token")
}

fn rotated(outcome: RotateOutcome) -> RotatedPair {
    match outcome {
        RotateOutcome::Rotated(p) => p,
        other => panic!("expected Rotated, got {other:?}"),
    }
}

/// `pair` without the instant it was answered at. `at` (the Redis second
/// `expires_in` counts from) belongs to each answer, so a rotation and its
/// replay, or two concurrent answers, that straddle a second differ there;
/// everything else (the grant, the generation and the pair, byte for byte)
/// must still be equal.
fn timeless_pair(pair: RotatedPair) -> RotatedPair {
    RotatedPair { at: 0, ..pair }
}

/// `outcome` with the instant of its answer cleared ([`timeless_pair`]).
fn timeless(outcome: RotateOutcome) -> RotateOutcome {
    match outcome {
        RotateOutcome::Rotated(p) => RotateOutcome::Rotated(timeless_pair(p)),
        RotateOutcome::Replayed(p) => RotateOutcome::Replayed(timeless_pair(p)),
        other => other,
    }
}

/// Waits until Redis `TIME` has passed the second `at`, so that the next
/// answer is given in a later second than one stamped `at`.
async fn after_second(client: &RedisClient, at: i64) {
    while client.redis_time().await.expect("TIME") <= at {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn reuse_branch(outcome: &RotateOutcome) -> Option<ReuseBranch> {
    match outcome {
        RotateOutcome::Reuse(e) => Some(e.branch),
        _ => None,
    }
}

/// Every key and value of `keys` (strings, hashes, sets), concatenated.
async fn dump(client: &RedisClient, keys: &[String]) -> String {
    let mut out = String::new();
    for key in keys {
        out.push_str(key);
        out.push('\n');
        let ty: String = raw(client, &["TYPE", key]).await;
        match ty.as_str() {
            "hash" => {
                for (k, v) in hgetall(client, key).await {
                    out.push_str(&format!("{k}={v}\n"));
                }
            }
            "set" => {
                let m: Vec<String> = raw(client, &["SMEMBERS", key]).await;
                out.push_str(&m.join("\n"));
            }
            "string" => {
                let v: String = raw(client, &["GET", key]).await;
                out.push_str(&v);
            }
            _ => {}
        }
        out.push('\n');
    }
    out
}

#[tokio::test]
async fn issue_grant_writes_the_grant_its_access_entry_and_both_indices() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("issue{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let refresh = issued.refresh_token.clone().expect("a refresh token");
    assert!(issued.access_token.starts_with(tokens::ACCESS_TOKEN_PREFIX));
    let parsed = tokens::parse_refresh_token(&refresh).expect("current format");
    assert_eq!(GrantId::of_handle(parsed.handle), issued.grant_id);
    assert_eq!(issued.access_exp - issued.iat, ACCESS_TOKEN_TTL as i64);

    let g = hgetall(&client, &grant_key(&issued.grant_id)).await;
    assert_eq!(g["kind"], "matrix_device");
    assert_eq!(g["username"], user);
    assert_eq!(g["device_id"], "DEV1");
    assert_eq!(g["client_id"], "client-a");
    assert_eq!(g["confidential"], "0");
    assert_eq!(g["generation"], "0");
    assert_eq!(g["current_rt"], digest(&refresh));
    assert_eq!(g["previous_rt"], "");
    let ttl: i64 = raw(&client, &["TTL", &grant_key(&issued.grant_id)]).await;
    assert!(
        ttl > (REFRESH_TOKEN_TTL - 60) as i64,
        "grant TTL is the inactivity, got {ttl}"
    );

    let at = hgetall(&client, &at_key(&issued.access_token)).await;
    assert_eq!(at["grant"], issued.grant_id.as_str());
    assert_eq!(at["generation"], "0");
    assert_eq!(at["kind"], "access");
    let at_ttl: i64 = raw(&client, &["TTL", &at_key(&issued.access_token)]).await;
    assert!(at_ttl > 0 && at_ttl <= ACCESS_TOKEN_TTL as i64);

    for idx in [user_idx_key(&user), device_idx_key(&user, "DEV1")] {
        let members: Vec<String> = raw(&client, &["SMEMBERS", &idx]).await;
        assert_eq!(members, vec![issued.grant_id.as_str().to_string()], "{idx}");
    }

    // I1: no key or value written names either token.
    let keys = vec![
        grant_key(&issued.grant_id),
        at_key(&issued.access_token),
        user_idx_key(&user),
        device_idx_key(&user, "DEV1"),
    ];
    let all = dump(&client, &keys).await;
    for secret in [&issued.access_token, &refresh] {
        assert!(
            !all.contains(secret.as_str()),
            "a stored value names a token"
        );
        assert!(!all.contains(&secret[4..]));
    }
}

#[tokio::test]
async fn a_refresh_less_grant_and_a_service_grant_live_as_long_as_their_access_token() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("norefresh{}", nonce());
    let mut oidc = matrix_grant(&user, "");
    oidc.kind = GrantKind::Oidc;
    oidc.refresh_inactivity_secs = None;
    let issued = issue(&client, &oidc).await;
    assert_eq!(issued.refresh_token, None);
    let g = hgetall(&client, &grant_key(&issued.grant_id)).await;
    assert_eq!(g["current_rt"], "");
    let ttl: i64 = raw(&client, &["TTL", &grant_key(&issued.grant_id)]).await;
    assert!(ttl > 0 && ttl <= ACCESS_TOKEN_TTL as i64, "got {ttl}");
    assert!(client
        .lookup_access_token(&issued.access_token)
        .await
        .unwrap()
        .is_some());

    let service = NewGrant {
        kind: GrantKind::Service,
        username: format!("admin{}", nonce()),
        did: "did:web:service".into(),
        client_id: "siwx-oidc-admin".into(),
        confidential_client: true,
        device_id: String::new(),
        scope: "urn:matrix:client:api:* urn:synapse:admin:*".into(),
        name: "admin".into(),
        auth_ms: None,
        access_ttl: 120,
        refresh_inactivity_secs: None,
    };
    let admin = issue(&client, &service).await;
    assert!(admin.access_token.starts_with(tokens::ADMIN_TOKEN_PREFIX));
    assert_eq!(admin.refresh_token, None);
    assert_eq!(admin.access_exp - admin.iat, 120);
    let ttl: i64 = raw(&client, &["TTL", &grant_key(&admin.grant_id)]).await;
    assert!(ttl > 0 && ttl <= 120, "got {ttl}");
    let found = client
        .lookup_access_token(&admin.access_token)
        .await
        .unwrap()
        .expect("the admin token is accepted");
    assert_eq!(found.grant.kind, GrantKind::Service);
    assert_eq!(found.metadata().device_id, "");
    assert_eq!(found.metadata().kind, Some(TokenKind::Access));

    let mut bad = service.clone();
    bad.refresh_inactivity_secs = Some(60);
    assert!(
        client.issue_grant(&bad).await.is_err(),
        "a service grant never carries a refresh token"
    );
}

#[tokio::test]
async fn an_access_token_resolves_to_its_grant_until_the_grant_is_gone() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("lookup{}", nonce());
    let new = matrix_grant(&user, "DEV1");
    let issued = issue(&client, &new).await;
    let found = client
        .lookup_access_token(&issued.access_token)
        .await
        .unwrap()
        .expect("accepted");
    let meta = found.metadata();
    assert_eq!(meta.username, user);
    assert_eq!(meta.device_id, "DEV1");
    assert_eq!(meta.scope, new.scope);
    assert_eq!(meta.client_id, new.client_id);
    assert_eq!(meta.did, new.did);
    assert_eq!((meta.iat, meta.exp), (issued.iat, issued.access_exp));
    assert_eq!(found.grant.grant_id, issued.grant_id);

    // A refresh token is not an access token, and an unknown string is nothing.
    let refresh = issued.refresh_token.clone().unwrap();
    assert!(client
        .lookup_access_token(&refresh)
        .await
        .unwrap()
        .is_none());
    assert!(client
        .lookup_access_token("mat_nope")
        .await
        .unwrap()
        .is_none());

    // Deleting the grant makes every token of it inert at once.
    let _: i64 = raw(&client, &["DEL", &grant_key(&issued.grant_id)]).await;
    assert!(client
        .lookup_access_token(&issued.access_token)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn the_current_refresh_token_rotates_into_a_new_pair() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("rot{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let p = rotated(rotate(&client, &t0).await);
    assert_eq!(p.grant_id, issued.grant_id);
    assert_eq!(p.generation, 1);
    let t1 = &p.pair.refresh_token;
    assert_ne!(t1, &t0);
    assert_eq!(
        tokens::parse_refresh_token(t1).map(|x| x.handle),
        tokens::parse_refresh_token(&t0).map(|x| x.handle),
        "the handle names the grant for the whole chain"
    );
    let g = hgetall(&client, &grant_key(&issued.grant_id)).await;
    assert_eq!(g["current_rt"], digest(t1));
    assert_eq!(g["previous_rt"], digest(&t0));
    assert_eq!(g["generation"], "1");
    assert_eq!(g["successor_used"], "0");
    assert!(!g["successor_sealed"].is_empty());
    let found = client
        .lookup_access_token(&p.pair.access_token)
        .await
        .unwrap()
        .expect("the new access token is accepted");
    assert_eq!(found.generation, 1);
    assert_eq!(found.exp, p.pair.access_exp);
}

/// I4 / H2 (unit): the replay of the previous token returns the same pair at
/// any delay while the successor is unused, and is reuse after its first use.
#[tokio::test]
async fn a_replay_returns_the_same_pair_until_the_successor_is_used() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("replay{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let first = rotated(rotate(&client, &t0).await);
    // Replays answered in a later second than the rotation: only `at` differs.
    after_second(&client, first.at).await;
    for _ in 0..2 {
        let replay = rotate(&client, &t0).await;
        assert!(
            matches!(&replay, RotateOutcome::Replayed(p) if p.at > first.at),
            "answered in a later second: {replay:?}"
        );
        assert_eq!(
            timeless(replay),
            timeless(RotateOutcome::Replayed(first.clone()))
        );
    }

    // An hour later by the grant's own record: the decision reads no clock.
    let key = grant_key(&issued.grant_id);
    let _: i64 = raw(&client, &["HINCRBY", &key, "last_used", "-3600"]).await;
    let _: i64 = raw(&client, &["HINCRBY", &key, "auth_time", "-3600"]).await;
    assert_eq!(
        timeless(rotate(&client, &t0).await),
        timeless(RotateOutcome::Replayed(first.clone()))
    );

    // The successor's access token is accepted once: from now on, reuse.
    assert!(client
        .lookup_access_token(&first.pair.access_token)
        .await
        .unwrap()
        .is_some());
    let g = hgetall(&client, &key).await;
    assert_eq!(g["successor_used"], "1");
    assert!(!g.contains_key("successor_sealed") || g["successor_sealed"].is_empty());
    assert_eq!(
        reuse_branch(&rotate(&client, &t0).await),
        Some(ReuseBranch::PreviousAfterUse)
    );
    // The current token still rotates.
    rotated(rotate(&client, &first.pair.refresh_token).await);
}

#[tokio::test]
async fn an_access_token_of_an_older_generation_does_not_use_the_successor() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("oldgen{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let first = rotated(rotate(&client, &t0).await);
    // The generation-0 access token is still valid, and using it says nothing
    // about whether the client received the generation-1 pair.
    let old = client
        .lookup_access_token(&issued.access_token)
        .await
        .unwrap()
        .expect("still valid until it expires");
    assert_eq!(old.generation, 0);
    assert_eq!(
        timeless(rotate(&client, &t0).await),
        timeless(RotateOutcome::Replayed(first.clone()))
    );
}

#[tokio::test]
async fn rotating_the_successor_counts_as_its_use_and_older_tokens_are_reuse() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("chain{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let p1 = rotated(rotate(&client, &t0).await);
    let p2 = rotated(rotate(&client, &p1.pair.refresh_token).await);
    assert_eq!(p2.generation, 2);
    let reuse = match rotate(&client, &t0).await {
        RotateOutcome::Reuse(e) => e,
        other => panic!("expected Reuse, got {other:?}"),
    };
    assert_eq!(reuse.branch, ReuseBranch::Superseded);
    assert_eq!(reuse.generation, 2);
    assert_eq!(reuse.client_id, "client-a");
    assert_eq!(reuse.grant_kind, GrantKind::MatrixDevice);
    assert_eq!(reuse.grant_fp, issued.grant_id.fingerprint());
    // t1 is now the previous token and t2 is unused: t1 replays t2's pair.
    assert_eq!(
        timeless(rotate(&client, &p1.pair.refresh_token).await),
        timeless(RotateOutcome::Replayed(p2.clone()))
    );
    // A secret this grant never issued, under its live handle, is reuse too.
    let handle = tokens::parse_refresh_token(&t0).unwrap().handle.to_string();
    let forged = format!("mcr_{handle}_{}", "Z".repeat(tokens::SECRET_LEN));
    assert_eq!(
        reuse_branch(&rotate(&client, &forged).await),
        Some(ReuseBranch::Superseded)
    );
    // Reuse revokes nothing in phase A.
    rotated(rotate(&client, &p2.pair.refresh_token).await);
}

/// I3 (unit form of H1): concurrent rotations of one token converge on one
/// pair, and exactly one chain stays live.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_rotations_of_one_token_converge_on_one_pair() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("race{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let client = client.clone();
        let t0 = t0.clone();
        tasks.push(tokio::spawn(async move { rotate(&client, &t0).await }));
    }
    let mut pairs = Vec::new();
    let mut rotations = 0;
    for task in tasks {
        match task.await.unwrap() {
            RotateOutcome::Rotated(p) => {
                rotations += 1;
                pairs.push(p);
            }
            RotateOutcome::Replayed(p) => pairs.push(p),
            other => panic!("every concurrent refresh succeeds, got {other:?}"),
        }
    }
    assert_eq!(rotations, 1, "exactly one request rotates");
    assert_eq!(pairs.len(), 50);
    assert!(
        pairs
            .iter()
            .all(|p| timeless_pair(p.clone()) == timeless_pair(pairs[0].clone())),
        "all carry the same pair"
    );
    let g = hgetall(&client, &grant_key(&issued.grant_id)).await;
    assert_eq!(g["generation"], "1");
    // The returned refresh token rotates once; no second branch exists.
    let next = rotated(rotate(&client, &pairs[0].pair.refresh_token).await);
    assert_eq!(next.generation, 2);
    assert!(reuse_branch(&rotate(&client, &t0).await).is_some());
}

#[tokio::test]
async fn a_missing_grant_or_a_malformed_token_is_invalid() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let unknown = tokens::new_refresh_token(&tokens::new_grant_handle());
    assert_eq!(
        rotate(&client, &unknown).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant)
    );
    for token in ["", "mcr_legacyAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "mat_x"] {
        assert_eq!(
            rotate(&client, token).await,
            RotateOutcome::Invalid(InvalidReason::NotCurrentFormat),
            "{token:?}"
        );
    }
}

#[tokio::test]
async fn a_tombstoned_device_or_user_refuses_rotation_and_replay() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("tomb{}", nonce());
    // Device tombstone.
    let a = issue(&client, &matrix_grant(&user, "DEVA")).await;
    let a0 = a.refresh_token.clone().unwrap();
    let a1 = rotated(rotate(&client, &a0).await);
    client
        .set_ex_raw(&device_tombstone_key(&user, "DEVA"), "1", 60)
        .await
        .unwrap();
    for t in [&a0, &a1.pair.refresh_token] {
        assert_eq!(
            rotate(&client, t).await,
            RotateOutcome::Invalid(InvalidReason::Revoked)
        );
    }
    assert_eq!(
        hgetall(&client, &grant_key(&a.grant_id)).await["generation"],
        "1"
    );
    // User tombstone, deviceless grant: no build writes one any more (the user
    // epoch replaced it), but one a previous build wrote still refuses for its
    // lifetime, so it is seeded the way that build planted it.
    let user2 = format!("tombu{}", nonce());
    let mut new = matrix_grant(&user2, "");
    new.kind = GrantKind::Oidc;
    let b = issue(&client, &new).await;
    let b0 = b.refresh_token.clone().unwrap();
    let b1 = rotated(rotate(&client, &b0).await);
    client
        .set_ex_raw(&user_tombstone_key(&user2), "1", TOMBSTONE_TTL_SECS)
        .await
        .unwrap();
    for t in [&b0, &b1.pair.refresh_token] {
        assert_eq!(
            rotate(&client, t).await,
            RotateOutcome::Invalid(InvalidReason::Revoked),
            "a user tombstone written by the previous build still refuses"
        );
    }
}

#[tokio::test]
async fn an_inactive_grant_is_expired_and_deleted() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("idle{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let key = grant_key(&issued.grant_id);
    let back = format!("-{}", REFRESH_TOKEN_TTL + 10);
    let _: i64 = raw(&client, &["HINCRBY", &key, "last_used", &back]).await;
    assert_eq!(
        rotate(&client, issued.refresh_token.as_deref().unwrap()).await,
        RotateOutcome::Invalid(InvalidReason::Expired)
    );
    let exists: i64 = raw(&client, &["EXISTS", &key]).await;
    assert_eq!(exists, 0, "an expired grant is deleted");
}

#[tokio::test]
async fn another_client_or_a_refused_confidential_client_cannot_rotate() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("cli{}", nonce());
    let mut new = matrix_grant(&user, "DEV1");
    new.confidential_client = true;
    let issued = issue(&client, &new).await;
    let t0 = issued.refresh_token.clone().unwrap();
    let req = |client_id, refuse_confidential| RotateRequest {
        presented: &t0,
        client_id,
        refuse_confidential,
    };
    assert_eq!(
        client
            .rotate_refresh_token(&req(Some("client-b"), false))
            .await
            .unwrap(),
        RotateOutcome::ClientMismatch
    );
    assert_eq!(
        client.rotate_refresh_token(&req(None, true)).await.unwrap(),
        RotateOutcome::ConfidentialClient
    );
    assert_eq!(
        hgetall(&client, &grant_key(&issued.grant_id)).await["generation"],
        "0"
    );
    let peek = client.peek_refresh_grant(&t0).await.unwrap().expect("peek");
    assert_eq!(peek.client_id, "client-a");
    assert!(peek.confidential_client);
    rotated(
        client
            .rotate_refresh_token(&req(Some("client-a"), false))
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn revoking_a_device_deletes_its_grants_only_and_plants_the_tombstone() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("revdev{}", nonce());
    let other = format!("revdevo{}", nonce());
    let a1 = issue(&client, &matrix_grant(&user, "DEVA")).await;
    let a2 = issue(&client, &matrix_grant(&user, "DEVA")).await;
    let b = issue(&client, &matrix_grant(&user, "DEVB")).await;
    let c = issue(&client, &matrix_grant(&other, "DEVA")).await;
    assert_eq!(
        client
            .revoke_grants_for_device(&user, "DEVA")
            .await
            .unwrap(),
        2
    );
    for gone in [&a1, &a2] {
        assert!(client
            .lookup_access_token(&gone.access_token)
            .await
            .unwrap()
            .is_none());
    }
    for kept in [&b, &c] {
        assert!(client
            .lookup_access_token(&kept.access_token)
            .await
            .unwrap()
            .is_some());
    }
    assert!(tombstone(&client, &device_tombstone_key(&user, "DEVA")).await);
    let members: Vec<String> = raw(&client, &["SMEMBERS", &user_idx_key(&user)]).await;
    assert_eq!(members, vec![b.grant_id.as_str().to_string()]);
}

#[tokio::test]
async fn revoking_a_user_deletes_every_grant_of_the_user() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("revuser{}", nonce());
    let other = format!("revusero{}", nonce());
    let a = issue(&client, &matrix_grant(&user, "DEVA")).await;
    let mut deviceless = matrix_grant(&user, "");
    deviceless.kind = GrantKind::Oidc;
    let b = issue(&client, &deviceless).await;
    let c = issue(&client, &matrix_grant(&other, "DEVA")).await;
    assert_eq!(client.revoke_grants_for_user(&user).await.unwrap(), 2);
    for gone in [&a, &b] {
        assert!(client
            .lookup_access_token(&gone.access_token)
            .await
            .unwrap()
            .is_none());
    }
    assert!(client
        .lookup_access_token(&c.access_token)
        .await
        .unwrap()
        .is_some());
    assert!(
        tombstone(&client, &EpochScope::User(&user).key()).await,
        "revoking a user sets the user epoch"
    );
    assert!(
        !tombstone(&client, &user_tombstone_key(&user)).await,
        "and plants no user tombstone"
    );
    for idx in [user_idx_key(&user), device_idx_key(&user, "DEVA")] {
        let exists: i64 = raw(&client, &["EXISTS", &idx]).await;
        assert_eq!(exists, 0, "{idx}");
    }
}

#[tokio::test]
async fn revoking_by_token_deletes_the_grant_of_an_accepted_token_only() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("revtok{}", nonce());
    // By access token.
    let a = issue(&client, &matrix_grant(&user, "DEVA")).await;
    let view = client
        .revoke_grant_of_token(&a.access_token)
        .await
        .unwrap()
        .expect("deleted");
    assert_eq!(
        (view.grant_id, view.device_id.as_str()),
        (a.grant_id.clone(), "DEVA")
    );
    assert!(client
        .peek_refresh_grant(a.refresh_token.as_deref().unwrap())
        .await
        .unwrap()
        .is_none());
    // A superseded refresh token deletes nothing; the current one does.
    let b = issue(&client, &matrix_grant(&user, "DEVB")).await;
    let b0 = b.refresh_token.clone().unwrap();
    let b1 = rotated(rotate(&client, &b0).await);
    let b2 = rotated(rotate(&client, &b1.pair.refresh_token).await);
    assert_eq!(client.revoke_grant_of_token(&b0).await.unwrap(), None);
    assert!(client
        .lookup_access_token(&b2.pair.access_token)
        .await
        .unwrap()
        .is_some());
    // The previous refresh token revokes only while its successor is unused:
    // b2 has now been used, so b1 deletes nothing.
    assert_eq!(
        client
            .revoke_grant_of_token(&b1.pair.refresh_token)
            .await
            .unwrap(),
        None,
        "the previous token revokes nothing once its successor was used"
    );
    assert!(
        client
            .peek_refresh_grant(&b2.pair.refresh_token)
            .await
            .unwrap()
            .is_some(),
        "the grant is intact"
    );
    assert!(client
        .revoke_grant_of_token(&b2.pair.refresh_token)
        .await
        .unwrap()
        .is_some());
    assert!(client
        .lookup_access_token(&b2.pair.access_token)
        .await
        .unwrap()
        .is_none());
    let members: Vec<String> = raw(&client, &["SMEMBERS", &user_idx_key(&user)]).await;
    assert!(members.is_empty(), "the indices drop revoked grants");
    // Deleting one access token leaves its grant.
    let c = issue(&client, &matrix_grant(&user, "DEVC")).await;
    assert!(client.delete_access_token(&c.access_token).await.unwrap());
    assert!(client
        .lookup_access_token(&c.access_token)
        .await
        .unwrap()
        .is_none());
    assert!(client
        .peek_refresh_grant(c.refresh_token.as_deref().unwrap())
        .await
        .unwrap()
        .is_some());
}

#[test]
fn the_reuse_event_carries_its_fields_and_fingerprints_only() {
    let capture = crate::test_support::LogCapture::start();
    let event = ReuseEvent {
        grant_fp: "0a1b2c3d".into(),
        generation: 7,
        client_id: "client-a".into(),
        grant_kind: GrantKind::Oidc,
        branch: ReuseBranch::PreviousAfterUse,
    };
    event.emit();
    let out = capture.output();
    for needle in [
        REUSE_EVENT_MESSAGE,
        "WARN",
        "security_event=\"refresh_token_reuse\"",
        "grant_fp=0a1b2c3d",
        "generation=7",
        "client_id=client-a",
        "grant_kind=oidc",
        "branch=\"previous_after_use\"",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in {out:?}");
    }
    assert_eq!(out.matches(REUSE_EVENT_MESSAGE).count(), 1, "one event");
}

/// H3: over 1,000 rotations of one grant every superseded token is recognised
/// as reuse (never as unknown), and the grant's persistent keys stay constant.
#[tokio::test]
async fn h3_a_thousand_rotations_recognise_every_superseded_token_in_constant_storage() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("h3{}", nonce());
    let issued = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let gid = issued.grant_id.clone();

    // Persistent keys of this grant: everything naming the user or the grant
    // id, except the expiring access-token entries.
    async fn persistent(client: &RedisClient, user: &str, gid: &GrantId) -> (Vec<String>, i64) {
        let mut keys: Vec<String> = raw(client, &["KEYS", &format!("*{user}*")]).await;
        let by_id: Vec<String> = raw(client, &["KEYS", &format!("*{}*", gid.as_str())]).await;
        keys.extend(by_id);
        keys.sort();
        keys.dedup();
        let hlen: i64 = raw(client, &["HLEN", &grant_key(gid)]).await;
        (keys, hlen)
    }

    let mut superseded = Vec::new();
    let mut current = issued.refresh_token.clone().unwrap();
    let mut last_access = issued.access_token.clone();
    let mut baseline = None;
    for i in 0..1000u64 {
        let p = rotated(rotate(&client, &current).await);
        assert_eq!(p.generation, i + 1);
        superseded.push(std::mem::replace(&mut current, p.pair.refresh_token));
        last_access = p.pair.access_token;
        if i % 100 == 0 || i == 999 {
            let now = persistent(&client, &user, &gid).await;
            match &baseline {
                None => baseline = Some(now),
                Some(b) => assert_eq!(&now, b, "persistent keys after {} rotations", i + 1),
            }
        }
    }
    let (keys, _) = baseline.unwrap();
    assert_eq!(keys.len(), 3, "grant hash and two indices: {keys:?}");

    // Every access-token entry this grant wrote expires.
    let at_keys: Vec<String> = raw(&client, &["KEYS", "at/*"]).await;
    let mut mine = 0;
    for k in &at_keys {
        let owner: Option<String> = raw(&client, &["HGET", k, "grant"]).await;
        if owner.as_deref() == Some(gid.as_str()) {
            mine += 1;
            let ttl: i64 = raw(&client, &["TTL", k]).await;
            assert!(ttl > 0 && ttl <= ACCESS_TOKEN_TTL as i64, "{ttl}");
        }
    }
    assert_eq!(mine, 1001);

    // Use the newest pair, then present every superseded token.
    assert!(client
        .lookup_access_token(&last_access)
        .await
        .unwrap()
        .is_some());
    for (i, t) in superseded.iter().enumerate() {
        let outcome = rotate(&client, t).await;
        let expected = if i == 999 {
            ReuseBranch::PreviousAfterUse
        } else {
            ReuseBranch::Superseded
        };
        assert_eq!(
            reuse_branch(&outcome),
            Some(expected),
            "token {i}: {outcome:?}"
        );
    }
    // Still one live chain, untouched by the reuse events.
    rotated(rotate(&client, &current).await);
}

/// A legacy refresh token as a build before the grant record wrote it:
/// `token/{raw}` holding the metadata JSON (without `kind`, as 3547bd2 wrote
/// it, or with it, as the builds after the token kinds wrote it), lifetime 90
/// days, plus the member `token/{raw}` of the legacy device index.
async fn seed_legacy(
    client: &RedisClient,
    username: &str,
    device_id: &str,
    lifetime: i64,
    with_kind: bool,
) -> (String, TokenMetadata) {
    let raw_token = format!(
        "mcr_{}",
        &tokens::new_access_token()[tokens::ACCESS_TOKEN_PREFIX.len()..]
    );
    let now = chrono::Utc::now().timestamp();
    let meta = TokenMetadata {
        username: username.to_string(),
        device_id: device_id.to_string(),
        scope: format!("openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}"),
        client_id: "client-legacy".to_string(),
        iat: now - 60,
        exp: now - 60 + lifetime,
        did: format!("did:key:z6Mk{username}"),
        name: "legacy name".to_string(),
        kind: with_kind.then_some(if lifetime <= crate::db::ACCESS_TOKEN_MAX_LIFETIME {
            TokenKind::Access
        } else {
            TokenKind::Refresh
        }),
    };
    let key = format!("token/{raw_token}");
    let json = serde_json::to_string(&meta).unwrap();
    let ttl = (meta.exp - now).to_string();
    let _: () = raw(client, &["SET", &key, &json, "EX", &ttl]).await;
    if !device_id.is_empty() {
        let idx = format!("idx:user_device/{username}/{device_id}");
        let _: i64 = raw(client, &["SADD", &idx, &key]).await;
    }
    (raw_token, meta)
}

fn request(presented: &str) -> RotateRequest<'_> {
    RotateRequest {
        presented,
        client_id: None,
        refuse_confidential: false,
    }
}

async fn peek_legacy(client: &RedisClient, token: &str) -> LegacyRefresh {
    match client.peek_refresh_token(token).await.expect("peek") {
        RefreshPeek::Legacy(legacy) => legacy,
        other => panic!("expected a legacy refresh token, got {other:?}"),
    }
}

/// Item 10: the first presentation lifts the legacy token into a grant (legacy
/// entry and index member gone, pointer written, the new pair current and
/// unused); every later presentation follows I4 through the pointer: the same
/// pair while unused, reuse after, and the chain goes on from the new token.
#[tokio::test]
async fn a_legacy_refresh_token_is_lifted_once_and_its_replays_follow_the_same_rule() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("lift{}", nonce());
    for with_kind in [false, true] {
        let device = format!("DEVL{with_kind}");
        let (legacy_rt, meta) =
            seed_legacy(&client, &user, &device, REFRESH_TOKEN_TTL as i64, with_kind).await;
        let legacy = peek_legacy(&client, &legacy_rt).await;
        assert_eq!(legacy.meta.username, user);

        let lifted = rotated(
            client
                .lift_legacy_refresh_token(&request(&legacy_rt), &legacy, false)
                .await
                .expect("lift"),
        );
        assert!(lifted.pair.access_token.starts_with("mat_"));
        assert!(
            tokens::parse_refresh_token(&lifted.pair.refresh_token).is_some(),
            "new format"
        );
        assert_eq!(lifted.generation, 1);

        let legacy_key = format!("token/{legacy_rt}");
        let exists: i64 = raw(&client, &["EXISTS", &legacy_key]).await;
        assert_eq!(exists, 0, "the legacy entry is deleted by the lift");
        let in_idx: i64 = raw(
            &client,
            &[
                "SISMEMBER",
                &format!("idx:user_device/{user}/{device}"),
                &legacy_key,
            ],
        )
        .await;
        assert_eq!(in_idx, 0, "the legacy index member is removed");
        let pointer: Option<String> = raw(&client, &["GET", &legacy_rt_key(&legacy_rt)]).await;
        assert_eq!(
            pointer.as_deref(),
            Some(lifted.grant_id.as_str()),
            "pointer to the grant"
        );

        let g = hgetall(&client, &grant_key(&lifted.grant_id)).await;
        assert_eq!(g["previous_rt"], digest(&legacy_rt));
        assert_eq!(g["current_rt"], digest(&lifted.pair.refresh_token));
        assert_eq!(g["generation"], "1");
        assert_eq!(g["successor_used"], "0");
        assert_eq!(g["kind"], "matrix_device");
        assert_eq!(g["username"], user);
        assert_eq!(g["device_id"], device);
        assert_eq!(g["client_id"], meta.client_id);
        assert_eq!(g["confidential"], "0");
        assert_eq!(g["auth_time"], meta.iat.to_string());
        for idx in [user_idx_key(&user), device_idx_key(&user, &device)] {
            let m: i64 = raw(&client, &["SISMEMBER", &idx, lifted.grant_id.as_str()]).await;
            assert_eq!(m, 1, "{idx} holds the lifted grant");
        }
        match client.peek_refresh_token(&legacy_rt).await.unwrap() {
            RefreshPeek::Grant(view) => assert_eq!(view.grant_id, lifted.grant_id),
            other => panic!("a lifted token names its grant, got {other:?}"),
        }

        // A replay, and a presenter that read the legacy entry before the lift.
        match rotate(&client, &legacy_rt).await {
            RotateOutcome::Replayed(p) => assert_eq!(p.pair, lifted.pair),
            other => panic!("replay before use: {other:?}"),
        }
        match client
            .lift_legacy_refresh_token(&request(&legacy_rt), &legacy, false)
            .await
            .unwrap()
        {
            RotateOutcome::Replayed(p) => assert_eq!(p.pair, lifted.pair),
            other => panic!("a late lift follows the pointer: {other:?}"),
        }

        client
            .lookup_access_token(&lifted.pair.access_token)
            .await
            .unwrap()
            .expect("active");
        assert_eq!(
            reuse_branch(&rotate(&client, &legacy_rt).await),
            Some(ReuseBranch::PreviousAfterUse),
            "after use, the legacy token is reuse"
        );
        rotated(rotate(&client, &lifted.pair.refresh_token).await);
        assert_eq!(
            reuse_branch(&rotate(&client, &legacy_rt).await),
            Some(ReuseBranch::Superseded),
            "two rotations on, the legacy token is still recognised"
        );
    }
}

/// Concurrent presentations of one legacy token, each peeking then lifting or
/// rotating as an endpoint does, converge on one pair: exactly one lift.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_presentations_of_one_legacy_token_converge_on_one_pair() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("liftc{}", nonce());
    let (legacy_rt, _) = seed_legacy(&client, &user, "DEVC", REFRESH_TOKEN_TTL as i64, false).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(20));
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let (client, token, barrier) = (client.clone(), legacy_rt.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match client.peek_refresh_token(&token).await.unwrap() {
                RefreshPeek::Legacy(legacy) => client
                    .lift_legacy_refresh_token(&request(&token), &legacy, false)
                    .await
                    .unwrap(),
                RefreshPeek::Grant(_) => {
                    client.rotate_refresh_token(&request(&token)).await.unwrap()
                }
                RefreshPeek::Unknown => panic!("a concurrent presentation found nothing"),
            }
        }));
    }
    let mut pairs = Vec::new();
    let mut lifts = 0;
    for t in tasks {
        match t.await.unwrap() {
            RotateOutcome::Rotated(p) => {
                lifts += 1;
                pairs.push(p.pair);
            }
            RotateOutcome::Replayed(p) => pairs.push(p.pair),
            other => panic!("every presentation succeeds, got {other:?}"),
        }
    }
    assert_eq!(lifts, 1, "exactly one presentation lifts");
    assert!(pairs.windows(2).all(|w| w[0] == w[1]), "one pair for all");
}

/// What must not be lifted stays as it was: a legacy access token, a
/// confidential client's token at an endpoint that refuses those, a request
/// naming another client, an entry past its `exp`, a tombstoned session, an
/// unknown string.
#[tokio::test]
async fn a_legacy_token_that_may_not_be_lifted_stays_untouched() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("liftn{}", nonce());
    let (legacy_at, _) = seed_legacy(&client, &user, "DEVN", ACCESS_TOKEN_TTL as i64, false).await;
    assert!(matches!(
        client.peek_refresh_token(&legacy_at).await.unwrap(),
        RefreshPeek::Unknown
    ));
    assert!(matches!(
        client
            .peek_refresh_token("mcr_not_a_token_anywhere")
            .await
            .unwrap(),
        RefreshPeek::Unknown
    ));

    let (legacy_rt, meta) =
        seed_legacy(&client, &user, "DEVN", REFRESH_TOKEN_TTL as i64, false).await;
    let legacy = peek_legacy(&client, &legacy_rt).await;
    let refusing = RotateRequest {
        presented: &legacy_rt,
        client_id: None,
        refuse_confidential: true,
    };
    assert_eq!(
        client
            .lift_legacy_refresh_token(&refusing, &legacy, true)
            .await
            .unwrap(),
        RotateOutcome::ConfidentialClient
    );
    let other = RotateRequest {
        presented: &legacy_rt,
        client_id: Some("another-client"),
        refuse_confidential: false,
    };
    assert_eq!(
        client
            .lift_legacy_refresh_token(&other, &legacy, false)
            .await
            .unwrap(),
        RotateOutcome::ClientMismatch
    );
    // A legacy refresh entry whose `exp` has passed while its Redis TTL is
    // still live: the lift reads the entry's own expiry, not the key's TTL.
    let (expired_rt, _) =
        seed_legacy(&client, &user, "DEVN", REFRESH_TOKEN_TTL as i64, false).await;
    let now = chrono::Utc::now().timestamp();
    let stale = TokenMetadata {
        iat: now - 60 - REFRESH_TOKEN_TTL as i64,
        exp: now - 60,
        ..meta.clone()
    };
    let stale_json = serde_json::to_string(&stale).unwrap();
    let expired_key = format!("token/{expired_rt}");
    let _: () = raw(&client, &["SET", &expired_key, &stale_json, "EX", "3600"]).await;
    let expired = peek_legacy(&client, &expired_rt).await;
    assert_eq!(
        expired.meta.exp, stale.exp,
        "the expired entry is the one read"
    );
    assert_eq!(
        client
            .lift_legacy_refresh_token(&request(&expired_rt), &expired, false)
            .await
            .unwrap(),
        RotateOutcome::Invalid(InvalidReason::Expired),
        "a legacy token past its exp is expired whatever its TTL"
    );
    let left: Option<String> = raw(&client, &["GET", &expired_key]).await;
    assert_eq!(
        left.as_deref(),
        Some(stale_json.as_str()),
        "the expired entry is left as it was"
    );
    // A user tombstone as the previous build planted it (still read for one
    // release; the user epoch refuses a lift too, see the epochs tests).
    client
        .set_ex_raw(&user_tombstone_key(&meta.username), "1", TOMBSTONE_TTL_SECS)
        .await
        .unwrap();
    assert_eq!(
        client
            .lift_legacy_refresh_token(&request(&legacy_rt), &legacy, false)
            .await
            .unwrap(),
        RotateOutcome::Invalid(InvalidReason::Revoked)
    );
    for token in [&legacy_at, &legacy_rt, &expired_rt] {
        let exists: i64 = raw(&client, &["EXISTS", &format!("token/{token}")]).await;
        assert_eq!(exists, 1, "the legacy entry is untouched");
        let pointer: i64 = raw(&client, &["EXISTS", &legacy_rt_key(token)]).await;
        assert_eq!(pointer, 0, "no pointer was written");
    }
}

/// A lifted legacy token is resolved and revoked like its grant's previous
/// token: while its successor is unused, revoking it deletes the grant.
#[tokio::test]
async fn a_lifted_legacy_token_is_resolved_and_revoked_like_its_grants_previous_token() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("liftr{}", nonce());
    let (legacy_rt, _) = seed_legacy(&client, &user, "", REFRESH_TOKEN_TTL as i64, false).await;
    let legacy = peek_legacy(&client, &legacy_rt).await;
    let lifted = rotated(
        client
            .lift_legacy_refresh_token(&request(&legacy_rt), &legacy, false)
            .await
            .unwrap(),
    );
    let resolved = client
        .resolve_refresh_token(&legacy_rt)
        .await
        .unwrap()
        .expect("resolved");
    assert_eq!(resolved.grant_id, lifted.grant_id);
    let revoked = client
        .revoke_grant_of_token(&legacy_rt)
        .await
        .unwrap()
        .expect("revoked");
    assert_eq!(revoked.grant_id, lifted.grant_id);
    assert!(
        hgetall(&client, &grant_key(&lifted.grant_id))
            .await
            .is_empty(),
        "grant gone"
    );
    assert_eq!(
        rotate(&client, &lifted.pair.refresh_token).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant)
    );
    assert_eq!(
        rotate(&client, &legacy_rt).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant)
    );
}

#[test]
fn a_lifted_grant_is_a_matrix_device_grant_exactly_when_its_scope_carries_the_matrix_api() {
    let meta = |scope: &str| TokenMetadata {
        username: "u".into(),
        device_id: String::new(),
        scope: scope.into(),
        client_id: "c".into(),
        iat: 0,
        exp: 1,
        did: "did:key:z".into(),
        name: "n".into(),
        kind: None,
    };
    for (scope, kind) in [
        (
            "openid urn:matrix:client:api:* urn:matrix:client:device:D",
            GrantKind::MatrixDevice,
        ),
        (
            "openid urn:matrix:client:api:* urn:matrix:client:device:",
            GrantKind::MatrixDevice,
        ),
        (
            "openid urn:matrix:org.matrix.msc2967.client:api:*",
            GrantKind::MatrixDevice,
        ),
        ("openid profile offline_access", GrantKind::Oidc),
        ("openid urn:matrix:client:api:*x", GrantKind::Oidc),
        ("", GrantKind::Oidc),
    ] {
        assert_eq!(legacy_grant_kind(&meta(scope)), kind, "{scope:?}");
    }
}

mod epochs;
mod lifetime;

// -- `sid` (I8, Phase 4) ------------------------------------------------------

/// The grant's `sid` and what its index names, read from the store.
async fn sid_of(client: &RedisClient, id: &GrantId) -> Option<String> {
    raw::<Option<String>>(client, &["HGET", &grant_key(id), "sid"]).await
}

async fn sid_index(client: &RedisClient, sid: &str) -> Option<String> {
    raw::<Option<String>>(
        client,
        &["GET", &format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}")],
    )
    .await
}

/// Whether `sid` and `other` share a run of [`SID_WINDOW`] characters: a sid
/// cut from (or embedding) a credential or identifier shares one with it,
/// while a random 22-character base62 sid does so with odds below 1e-9.
const SID_WINDOW: usize = 8;
fn shares_a_window(sid: &str, other: &str) -> bool {
    sid.len() >= SID_WINDOW
        && (0..=sid.len() - SID_WINDOW).any(|i| other.contains(&sid[i..i + SID_WINDOW]))
}

/// Every grant that comes with an ID token (`matrix_device`, `oidc`) gets its
/// own random `sid`: 22 base62 characters, different per grant, indexed
/// `idx:grants:sid/{sid}` -> grant id for no longer than the grant lives. A
/// `service` grant (an admin token, no ID token) has none.
///
/// Randomness itself is not observable from outside; what is pinned is its
/// consequence: across many grants every sid is distinct, and no sid shares
/// an 8-character run with anything an RP or another user could learn or
/// that names the grant (the grant handle and id, the access and refresh
/// tokens and their digests, the device id, the username, the DID). A sid
/// derived from any of them (a prefix, a substring, a slice of a digest)
/// fails here.
#[tokio::test]
async fn every_grant_with_an_id_token_has_its_own_random_sid() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("sid{}", nonce());
    let device = format!("SIWX_{}", nonce());
    let mut a = matrix_grant(&user, "");
    a.kind = GrantKind::Oidc;
    let a = issue(&client, &a).await;
    let mut b = matrix_grant(&user, "");
    b.kind = GrantKind::Oidc;
    let b = issue(&client, &b).await;
    let c = issue(&client, &matrix_grant(&user, &device)).await;

    let mut seen = Vec::new();
    for issued in [&a, &b, &c] {
        let sid = sid_of(&client, &issued.grant_id)
            .await
            .expect("a grant with an ID token carries a sid");
        assert_eq!(sid.len(), 22, "sid {sid:?}");
        assert!(sid.chars().all(|ch| ch.is_ascii_alphanumeric()), "{sid:?}");
        assert!(!sid.contains(&device) && !device.contains(&sid));
        assert_ne!(sid, issued.grant_id.as_str());
        assert!(!seen.contains(&sid), "every grant gets its own sid");
        assert_eq!(
            sid_index(&client, &sid).await.as_deref(),
            Some(issued.grant_id.as_str()),
            "the sid index names its grant"
        );
        let idx_ttl: i64 = raw(
            &client,
            &["TTL", &format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}")],
        )
        .await;
        let grant_ttl: i64 = raw(&client, &["TTL", &grant_key(&issued.grant_id)]).await;
        assert!(
            idx_ttl > 0 && idx_ttl <= grant_ttl,
            "index TTL {idx_ttl}, grant TTL {grant_ttl}"
        );
        seen.push(sid);
    }

    // Many grants: every sid distinct, none sharing a run with what names the
    // grant or with any credential or identifier of it.
    let mut sids: std::collections::HashSet<String> = seen.into_iter().collect();
    for i in 0..40 {
        let mut new = matrix_grant(&format!("{user}m{i}"), &format!("SIWX_{}", nonce()));
        if i % 2 == 0 {
            new.kind = GrantKind::Oidc;
            new.device_id = String::new();
        }
        let issued = issue(&client, &new).await;
        let sid = sid_of(&client, &issued.grant_id)
            .await
            .expect("a grant with an ID token carries a sid");
        assert!(sids.insert(sid.clone()), "sid {sid:?} issued twice");
        let refresh = issued
            .refresh_token
            .clone()
            .expect("a grant with an ID token here has a refresh token");
        let handle = refresh
            .strip_prefix(tokens::REFRESH_TOKEN_PREFIX)
            .and_then(|rest| rest.split('_').next())
            .expect("mcr_{handle}_{secret}")
            .to_string();
        assert_eq!(GrantId::of_handle(&handle), issued.grant_id);
        let named = [
            ("the grant handle", handle.clone()),
            ("the grant id", issued.grant_id.as_str().to_string()),
            ("the access token", issued.access_token.clone()),
            (
                "the access token digest",
                tokens::digest(&issued.access_token),
            ),
            ("the refresh token", refresh.clone()),
            ("the refresh token digest", tokens::digest(&refresh)),
            ("the device id", new.device_id),
            ("the username", new.username),
            ("the DID", new.did),
        ];
        for (what, value) in named {
            assert!(
                !shares_a_window(&sid, &value),
                "sid {sid:?} shares an {SID_WINDOW}-character run with {what}"
            );
        }
    }
    assert_eq!(sids.len(), 43, "every grant gets its own sid");

    let admin = issue(
        &client,
        &NewGrant {
            kind: GrantKind::Service,
            username: format!("admin{}", nonce()),
            did: "did:web:service".into(),
            client_id: "siwx-oidc-admin".into(),
            confidential_client: true,
            device_id: String::new(),
            scope: "urn:synapse:admin:*".into(),
            name: "admin".into(),
            auth_ms: None,
            access_ttl: 120,
            refresh_inactivity_secs: None,
        },
    )
    .await;
    assert_eq!(sid_of(&client, &admin.grant_id).await, None);
}

/// The sid index lives exactly as long as its grant: a rotation extends both
/// to the same TTL, and every script that deletes a grant deletes its index
/// entry with it.
#[tokio::test]
async fn the_sid_index_lives_and_dies_with_its_grant() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("sidlife{}", nonce());
    let mut new = matrix_grant(&user, "");
    new.kind = GrantKind::Oidc;
    new.auth_ms = None;
    let issued = issue(&client, &new).await;
    let sid = sid_of(&client, &issued.grant_id)
        .await
        .expect("the grant carries a sid");
    let idx = format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}");
    raw::<i64>(&client, &["EXPIRE", &idx, "60"]).await;
    raw::<i64>(&client, &["EXPIRE", &grant_key(&issued.grant_id), "60"]).await;
    let pair = rotated(rotate(&client, issued.refresh_token.as_deref().unwrap()).await);
    let grant_ttl: i64 = raw(&client, &["TTL", &grant_key(&issued.grant_id)]).await;
    let idx_ttl: i64 = raw(&client, &["TTL", &idx]).await;
    assert!(
        grant_ttl > 60,
        "the rotation extends the grant: {grant_ttl}"
    );
    assert!(
        (grant_ttl - idx_ttl).abs() <= 1,
        "the rotation extends the index with it: grant {grant_ttl}, index {idx_ttl}"
    );
    assert_eq!(
        sid_of(&client, &issued.grant_id).await.as_deref(),
        Some(sid.as_str()),
        "a rotation keeps the sid"
    );

    client
        .revoke_grant_of_token(&pair.pair.refresh_token)
        .await
        .unwrap()
        .expect("the current refresh token names the grant");
    assert_eq!(
        sid_index(&client, &sid).await,
        None,
        "revoke drops the index"
    );

    // The user-wide and device-wide revocations drop it too.
    let device = format!("SIWX_{}", nonce());
    let d = issue(&client, &matrix_grant(&user, &device)).await;
    let d_sid = sid_of(&client, &d.grant_id).await.expect("sid");
    client
        .revoke_grants_for_device(&user, &device)
        .await
        .unwrap();
    assert_eq!(
        sid_index(&client, &d_sid).await,
        None,
        "device revoke drops it"
    );
    let mut u = matrix_grant(&user, "");
    u.kind = GrantKind::Oidc;
    u.auth_ms = None;
    let u = issue(&client, &u).await;
    let u_sid = sid_of(&client, &u.grant_id).await.expect("sid");
    client.revoke_grants_for_user(&user).await.unwrap();
    assert_eq!(
        sid_index(&client, &u_sid).await,
        None,
        "user revoke drops it"
    );
}

/// The scripts spell the sid index the way the library reads it.
#[test]
fn the_scripts_name_the_sid_index_the_library_reads() {
    let literal = format!("'{KV_GRANT_SID_IDX_PREFIX}/'");
    for (name, script) in [
        ("drop_grant", LUA_DROP),
        ("issue", ISSUE_LUA),
        ("rotate", ROTATE_LUA),
    ] {
        assert!(script.contains(&literal), "{name} must name {literal}");
    }
}

/// `drop_grant` queues into the outbox the worker reads.
#[test]
fn drop_grant_names_the_outbox_the_worker_reads() {
    let literal = format!("'{}'", crate::db::outbox::KV_BACKCHANNEL_OUTBOX);
    assert!(
        LUA_DROP.contains(&literal),
        "drop_grant must name {literal}"
    );
}

/// `end_grant_by_sid` deletes exactly the grant the sid names, with its index
/// entries, only for the client and DID it was issued to; any other sid, or a
/// second call, deletes nothing.
#[tokio::test]
async fn end_grant_by_sid_deletes_exactly_the_named_grant_of_its_client_and_did() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("endsid{}", nonce());
    let device = format!("SIWX_{}", nonce());
    let new = matrix_grant(&user, &device);
    let named = issue(&client, &new).await;
    let sibling = issue(&client, &matrix_grant(&user, &device)).await;
    let sid = named.sid.clone().expect("a matrix grant carries a sid");
    assert_eq!(
        sid_of(&client, &named.grant_id).await.as_deref(),
        Some(sid.as_str())
    );

    for (client_id, did) in [
        ("client-b", new.did.as_str()),
        ("client-a", "did:key:zOther"),
    ] {
        assert_eq!(
            client.end_grant_by_sid(&sid, client_id, did).await.unwrap(),
            EndedGrant::Mismatch,
            "{client_id} {did}"
        );
    }
    assert!(client
        .lookup_access_token(&named.access_token)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        client
            .end_grant_by_sid("NoSuchSid0000000000000", "client-a", &new.did)
            .await
            .unwrap(),
        EndedGrant::NotFound
    );

    assert_eq!(
        client
            .end_grant_by_sid(&sid, "client-a", &new.did)
            .await
            .unwrap(),
        EndedGrant::Ended {
            grant_id: named.grant_id.clone(),
            kind: GrantKind::MatrixDevice
        }
    );
    assert!(client
        .lookup_access_token(&named.access_token)
        .await
        .unwrap()
        .is_none());
    assert_eq!(sid_index(&client, &sid).await, None);
    let members: Vec<String> = raw(&client, &["SMEMBERS", &user_idx_key(&user)]).await;
    assert_eq!(members, vec![sibling.grant_id.as_str().to_string()]);
    let members: Vec<String> = raw(&client, &["SMEMBERS", &device_idx_key(&user, &device)]).await;
    assert_eq!(members, vec![sibling.grant_id.as_str().to_string()]);
    assert!(
        !tombstone(&client, &device_tombstone_key(&user, &device)).await,
        "ending one grant plants no device tombstone"
    );
    assert!(client
        .lookup_access_token(&sibling.access_token)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        client
            .end_grant_by_sid(&sid, "client-a", &new.did)
            .await
            .unwrap(),
        EndedGrant::NotFound
    );
}
