//! Redis-backed tests of the grant layer (`crate::test_support::redis`).

use super::*;
use crate::db::{DBClient, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};
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
        auth_time: 1_700_000_000,
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
        auth_time: 0,
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
    for _ in 0..2 {
        assert_eq!(
            rotate(&client, &t0).await,
            RotateOutcome::Replayed(first.clone())
        );
    }

    // An hour later by the grant's own record: the decision reads no clock.
    let key = grant_key(&issued.grant_id);
    let _: i64 = raw(&client, &["HINCRBY", &key, "last_used", "-3600"]).await;
    let _: i64 = raw(&client, &["HINCRBY", &key, "auth_time", "-3600"]).await;
    assert_eq!(
        rotate(&client, &t0).await,
        RotateOutcome::Replayed(first.clone())
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
        rotate(&client, &t0).await,
        RotateOutcome::Replayed(first.clone())
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
        rotate(&client, &p1.pair.refresh_token).await,
        RotateOutcome::Replayed(p2.clone())
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
        pairs.iter().all(|p| p == &pairs[0]),
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
    // User tombstone, deviceless grant.
    let user2 = format!("tombu{}", nonce());
    let mut new = matrix_grant(&user2, "");
    new.kind = GrantKind::Oidc;
    let b = issue(&client, &new).await;
    client.mark_user_deactivated(&user2).await.unwrap();
    assert_eq!(
        rotate(&client, b.refresh_token.as_deref().unwrap()).await,
        RotateOutcome::Invalid(InvalidReason::Revoked)
    );
    assert!(client.is_user_deactivated(&user2).await.unwrap());
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
    assert!(client.is_device_revoked(&user, "DEVA").await.unwrap());
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
    assert!(client.is_user_deactivated(&user).await.unwrap());
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
