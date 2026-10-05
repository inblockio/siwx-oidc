//! Reuse enforcement (I5 phase B, `reuse_revokes_grant`): off, a reuse event
//! revokes nothing; on, it deletes the grant through `drop_grant` in the
//! rotation script that detected it, never the device, and never on a replay
//! of a lost response (I4).

use super::*;

/// The same store, with reuse enforcement on.
fn enforcing(client: &RedisClient) -> RedisClient {
    client.clone().with_reuse_enforcement(true)
}

fn oidc_grant(username: &str, client_id: &str) -> NewGrant {
    NewGrant {
        kind: GrantKind::Oidc,
        username: username.to_string(),
        did: format!("did:key:z6Mk{username}"),
        client_id: client_id.to_string(),
        confidential_client: false,
        device_id: String::new(),
        scope: "openid offline_access".to_string(),
        name: "n".to_string(),
        auth_ms: Some(1_700_000_000_000),
        access_ttl: ACCESS_TOKEN_TTL,
        refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
    }
}

fn reuse_event(outcome: RotateOutcome) -> ReuseEvent {
    match outcome {
        RotateOutcome::Reuse(e) => e,
        other => panic!("expected Reuse, got {other:?}"),
    }
}

/// The back-channel logout entries queued for grant `id`.
async fn logout_entries(client: &RedisClient, id: &GrantId) -> Vec<crate::db::outbox::LogoutEntry> {
    client
        .pending_logout_entries()
        .await
        .expect("pending_logout_entries")
        .into_iter()
        .map(|(e, _)| e)
        .filter(|e| e.grant == id.as_str())
        .collect()
}

async fn exists(client: &RedisClient, key: &str) -> bool {
    raw::<i64>(client, &["EXISTS", key]).await == 1
}

async fn is_member(client: &RedisClient, set: &str, member: &str) -> bool {
    raw::<i64>(client, &["SISMEMBER", set, member]).await == 1
}

/// Flag off (phase A, the default): a superseded refresh token is reuse, the
/// event says nothing was revoked, and the grant, its indices, its current
/// tokens and its outbox stay exactly as they were.
#[tokio::test]
async fn with_enforcement_off_reuse_leaves_the_grant_intact() {
    let Some(client) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("reuseoff{}", nonce());
    let rp = format!("rp-off-{}", nonce());
    for new in [matrix_grant(&user, "DEV1"), oidc_grant(&user, &rp)] {
        let issued = issue(&client, &new).await;
        let t0 = issued.refresh_token.clone().unwrap();
        let p1 = rotated(rotate(&client, &t0).await);
        let p2 = rotated(rotate(&client, &p1.pair.refresh_token).await);
        let before = hgetall(&client, &grant_key(&issued.grant_id)).await;

        let event = reuse_event(rotate(&client, &t0).await);
        assert_eq!(event.branch, ReuseBranch::Superseded);
        assert!(!event.grant_revoked, "phase A revokes nothing: {event:?}");

        let id = issued.grant_id.as_str();
        assert_eq!(
            hgetall(&client, &grant_key(&issued.grant_id)).await,
            before,
            "the grant is untouched"
        );
        assert!(is_member(&client, &user_idx_key(&user), id).await);
        if !new.device_id.is_empty() {
            assert!(is_member(&client, &device_idx_key(&user, "DEV1"), id).await);
        }
        if let Some(sid) = &issued.sid {
            assert!(exists(&client, &format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}")).await);
        }
        assert!(
            logout_entries(&client, &issued.grant_id).await.is_empty(),
            "nothing is sent to the RP"
        );
        assert!(client
            .lookup_access_token(&p2.pair.access_token)
            .await
            .unwrap()
            .is_some());
        rotated(rotate(&client, &p2.pair.refresh_token).await);
    }
}

/// Flag on (phase B): a reuse event deletes its grant in the script that
/// detected it. The current holder is refused from then on (its access token
/// at once, its refresh token at the next refresh); an `oidc` grant queues
/// exactly one back-channel logout entry, a Matrix grant none; the device is
/// untouched: no tombstone, and another grant of the same device keeps working.
#[tokio::test]
async fn with_enforcement_on_reuse_deletes_the_grant_and_never_the_device() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let client = enforcing(&base);
    let user = format!("reuseon{}", nonce());
    let rp = format!("rp-on-{}", nonce());

    // A Matrix device grant, reused with an older token of its chain.
    let matrix = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let sibling = issue(&client, &matrix_grant(&user, "DEV1")).await;
    let t0 = matrix.refresh_token.clone().unwrap();
    let p1 = rotated(rotate(&client, &t0).await);
    let p2 = rotated(rotate(&client, &p1.pair.refresh_token).await);
    let event = reuse_event(rotate(&client, &t0).await);
    assert_eq!(event.branch, ReuseBranch::Superseded);
    assert!(event.grant_revoked, "the event records the revocation");
    let id = matrix.grant_id.as_str();
    assert!(!exists(&client, &grant_key(&matrix.grant_id)).await);
    assert!(!is_member(&client, &user_idx_key(&user), id).await);
    assert!(!is_member(&client, &device_idx_key(&user, "DEV1"), id).await);
    let sid = matrix.sid.clone().expect("a Matrix grant has a sid");
    assert!(!exists(&client, &format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}")).await);
    assert!(
        logout_entries(&client, &matrix.grant_id).await.is_empty(),
        "a Matrix grant sends no logout token"
    );
    assert!(
        client
            .lookup_access_token(&p2.pair.access_token)
            .await
            .unwrap()
            .is_none(),
        "the current access token is refused at once"
    );
    assert_eq!(
        rotate(&client, &p2.pair.refresh_token).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant),
        "the current refresh token is refused at its next refresh"
    );
    assert!(
        !tombstone(&client, &device_tombstone_key(&user, "DEV1")).await,
        "reuse plants no device tombstone"
    );
    assert!(
        is_member(
            &client,
            &device_idx_key(&user, "DEV1"),
            sibling.grant_id.as_str()
        )
        .await
    );
    rotated(rotate(&client, sibling.refresh_token.as_deref().unwrap()).await);

    // An `oidc` grant, reused with its previous token after the successor's use.
    let oidc = issue(&client, &oidc_grant(&user, &rp)).await;
    let t0 = oidc.refresh_token.clone().unwrap();
    let p1 = rotated(rotate(&client, &t0).await);
    assert!(client
        .lookup_access_token(&p1.pair.access_token)
        .await
        .unwrap()
        .is_some());
    let event = reuse_event(rotate(&client, &t0).await);
    assert_eq!(event.branch, ReuseBranch::PreviousAfterUse);
    assert!(event.grant_revoked);
    assert!(!exists(&client, &grant_key(&oidc.grant_id)).await);
    let sid = oidc.sid.clone().expect("an oidc grant has a sid");
    assert!(!exists(&client, &format!("{KV_GRANT_SID_IDX_PREFIX}/{sid}")).await);
    let entries = logout_entries(&client, &oidc.grant_id).await;
    assert_eq!(entries.len(), 1, "exactly one logout entry: {entries:?}");
    assert_eq!(entries[0].client_id, rp);
    assert_eq!(entries[0].sub, format!("did:key:z6Mk{user}"));
    assert_eq!(entries[0].sid, sid);
    assert_eq!(
        rotate(&client, &p1.pair.refresh_token).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant)
    );
    // The reused token again: the grant is gone, so it is unknown, not a
    // second event, and nothing more is queued.
    assert_eq!(
        rotate(&client, &t0).await,
        RotateOutcome::Invalid(InvalidReason::UnknownGrant)
    );
    assert_eq!(logout_entries(&client, &oidc.grant_id).await.len(), 1);

    base.revoke_grants_for_user(&user).await.ok();
}

/// Flag on, I4: a replay of the previous token while its successor is unused
/// is a lost response, never reuse. It returns the same pair, sequentially and
/// concurrently, and deletes nothing: the grant is byte for byte unchanged and
/// no logout entry is queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn with_enforcement_on_a_lost_response_replay_returns_the_same_pair_and_deletes_nothing() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let client = enforcing(&base);
    let user = format!("reusereplay{}", nonce());
    let rp = format!("rp-replay-{}", nonce());
    let issued = issue(&client, &oidc_grant(&user, &rp)).await;
    let key = grant_key(&issued.grant_id);
    let t0 = issued.refresh_token.clone().unwrap();
    let first = rotated(rotate(&client, &t0).await);
    let before = hgetall(&client, &key).await;

    assert_eq!(
        timeless(rotate(&client, &t0).await),
        timeless(RotateOutcome::Replayed(first.clone()))
    );
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let client = client.clone();
        let t0 = t0.clone();
        tasks.push(tokio::spawn(async move { rotate(&client, &t0).await }));
    }
    for task in tasks {
        assert_eq!(
            timeless(task.await.unwrap()),
            timeless(RotateOutcome::Replayed(first.clone())),
            "every concurrent replay gets the same pair"
        );
    }

    assert_eq!(
        hgetall(&client, &key).await,
        before,
        "the replay wrote nothing"
    );
    assert!(logout_entries(&client, &issued.grant_id).await.is_empty());
    rotated(rotate(&client, &first.pair.refresh_token).await);

    base.revoke_grants_for_user(&user).await.ok();
}
