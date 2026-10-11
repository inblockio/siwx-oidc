//! The guest teardown (S5, design D2): the one entry point the reaper (S5b) calls for a
//! guest that is due, and the only code that erases a guest.
//!
//! [`teardown_guest`] is idempotent and crash-safe as a whole. The record is dropped
//! LAST, so a crash at any step leaves it in `reaping` with its `guest:due` entry, and the
//! next call resumes at the first step again; every step is safe to repeat (see
//! [`crate::teardown`]). Order:
//!
//! 1. CAS to `reaping` (refuses a `claimed` account: [`GuestTeardown::Claimed`]);
//! 2. epoch bump, revoke every grant, end the DID's own sessions;
//! 3. `delete_device` for each device of `guest:devices/<lp>`;
//! 4. `erased:user/<lp>` and `erased:did/<hash>` (the DID tombstone: the DID never signs in
//!    again, a redeem gives `did_in_use`, Path B gives `guest_identity`);
//! 5. `delete_user` with erase;
//! 6. drop the record, its device set, hand-off window, `guest:due` entry and
//!    `guest:by_invite` membership.

use siwx_oidc::db::guest_records::ReapCas;
use siwx_oidc::db::RedisClient;

use crate::synapse_client::SynapseClient;
use crate::teardown::{self, Erasure, Step, TeardownError};

/// What [`teardown_guest`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestTeardown {
    /// All steps ran; the record is gone.
    Erased,
    /// There was no record: an earlier call finished.
    AlreadyGone,
    /// The account was claimed: nothing was touched. The reaper drops it from its schedule.
    Claimed,
}

/// Tear down the guest `localpart`. Call it for a record that is due (`guest:due`); it
/// does not check the deadline itself. Errors are returned for the caller's backoff; the
/// state left behind is always safe to call again.
pub async fn teardown_guest(
    redis: &RedisClient,
    synapse: &SynapseClient,
    server_name: &str,
    localpart: &str,
) -> Result<GuestTeardown, TeardownError> {
    run(redis, synapse, server_name, localpart, None).await
}

/// [`teardown_guest`] stopping after `until`, as if the process died there (tests).
pub(crate) async fn run(
    redis: &RedisClient,
    synapse: &SynapseClient,
    server_name: &str,
    localpart: &str,
    until: Option<Step>,
) -> Result<GuestTeardown, TeardownError> {
    let err = |step| move |source| TeardownError { step, source };
    let Some((did, _state, promoted)) = redis
        .read_guest_for_teardown(localpart)
        .await
        .map_err(err(Step::Mark))?
    else {
        return Ok(GuestTeardown::AlreadyGone);
    };
    if promoted {
        return Ok(GuestTeardown::Claimed);
    }
    match redis
        .cas_guest_reaping(localpart)
        .await
        .map_err(err(Step::Mark))?
    {
        ReapCas::Claimed => return Ok(GuestTeardown::Claimed),
        ReapCas::Gone => return Ok(GuestTeardown::AlreadyGone),
        ReapCas::Marked | ReapCas::Already => {}
    }
    if until == Some(Step::Mark) {
        return Ok(GuestTeardown::Erased);
    }
    let devices = redis
        .guest_device_ids(localpart)
        .await
        .map_err(err(Step::Devices))?;
    teardown::run(
        &Erasure {
            redis,
            synapse,
            server_name,
            localpart,
            did: &did,
            devices: &devices,
            guest: true,
            missing_account_ok: true,
            purge_with: None,
        },
        until,
    )
    .await?;
    if until.is_some() {
        return Ok(GuestTeardown::Erased);
    }
    redis
        .drop_guest_record(localpart)
        .await
        .map_err(err(Step::Record))?;
    Ok(GuestTeardown::Erased)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post as ax_post;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    type Log = Arc<Mutex<Vec<(String, String)>>>;

    async fn mock() -> (Log, SynapseClient) {
        let log: Log = Arc::default();
        let l1 = log.clone();
        let l2 = log.clone();
        let app = axum::Router::new()
            .route(
                "/_synapse/mas/delete_device",
                ax_post(move |b: String| {
                    let l = l1.clone();
                    async move {
                        l.lock().unwrap().push(("delete_device".into(), b));
                        "{}"
                    }
                }),
            )
            .route(
                "/_synapse/mas/delete_user",
                ax_post(move |b: String| {
                    let l = l2.clone();
                    async move {
                        l.lock().unwrap().push(("delete_user".into(), b));
                        "{}"
                    }
                }),
            );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (
            log,
            SynapseClient::new(&format!("http://{addr}"), "shared-secret"),
        )
    }

    fn calls(log: &Log, what: &str) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c == what)
            .map(|(_, b)| b.clone())
            .collect()
    }

    struct Fixture {
        redis: RedisClient,
        localpart: String,
        did: String,
        access: String,
    }

    async fn fixture(redis: &RedisClient, state: &str) -> Fixture {
        use siwx_oidc::db::grant::{GrantKind, NewGrant};
        let id = uuid::Uuid::new_v4().simple().to_string();
        let did = format!("did:key:z6Mk{id}");
        let localpart = siwx_oidc::mxid::localpart_for(&did);
        redis
            .put_guest_for_test(&localpart, &did, state, 600, &id)
            .await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&localpart);
        redis
            .hset_raw_for_test(&key, "invite_id", &format!("inv{id}"))
            .await;
        let by_invite = siwx_oidc::db::guest_records::by_invite_key(&format!("inv{id}"));
        redis.sadd_raw_for_test(&by_invite, &localpart).await;
        let devices = siwx_oidc::db::guest_records::devices_key(&localpart);
        redis.sadd_raw_for_test(&devices, "DEVICE_A").await;
        redis.sadd_raw_for_test(&devices, "DEVICE_B").await;
        redis.end_guest_now(&localpart).await.unwrap();
        let issued = redis
            .issue_grant(&NewGrant {
                kind: GrantKind::MatrixDevice,
                username: localpart.clone(),
                did: did.clone(),
                client_id: "meet-guest".into(),
                confidential_client: false,
                device_id: "DEVICE_A".into(),
                scope: "openid".into(),
                name: "g".into(),
                auth_ms: None,
                access_ttl: 300,
                refresh_inactivity_secs: Some(3600),
                absolute_deadline: None,
            })
            .await
            .unwrap();
        Fixture {
            redis: redis.clone(),
            localpart,
            did,
            access: issued.access_token,
        }
    }

    impl Fixture {
        async fn record_exists(&self) -> bool {
            !self
                .redis
                .hgetall_for_test(&siwx_oidc::db::guest_invites::guest_account_key(
                    &self.localpart,
                ))
                .await
                .is_empty()
        }
        async fn state(&self) -> Option<String> {
            self.redis
                .get_hash_field_for_test(
                    &siwx_oidc::db::guest_invites::guest_account_key(&self.localpart),
                    "state",
                )
                .await
        }
    }

    const STEPS: [Step; 6] = [
        Step::Mark,
        Step::Revoke,
        Step::Devices,
        Step::Markers,
        Step::Synapse,
        Step::Purge,
    ];

    /// S5 (teardown crash points): the process dies after each step in turn; the next full
    /// call completes cleanly and the end state is the same, with nothing left behind.
    #[tokio::test]
    async fn a_teardown_rerun_after_a_crash_at_each_step_completes_cleanly() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        for crash in STEPS {
            let (log, synapse) = mock().await;
            let f = fixture(&redis, "active").await;
            // The crash: nothing may be left half-true that blocks the re-run.
            let r = run(&redis, &synapse, "example.org", &f.localpart, Some(crash)).await;
            assert_eq!(r.unwrap(), GuestTeardown::Erased, "crash after {crash:?}");
            assert!(f.record_exists().await, "the record outlives {crash:?}");
            assert_eq!(f.state().await.as_deref(), Some("reaping"));
            // The re-run.
            let r = teardown_guest(&redis, &synapse, "example.org", &f.localpart).await;
            assert_eq!(r.unwrap(), GuestTeardown::Erased, "re-run after {crash:?}");
            assert!(!f.record_exists().await, "record dropped ({crash:?})");
            assert!(
                redis.check_access_token(&f.access).await.unwrap().is_none(),
                "grants revoked ({crash:?})"
            );
            assert!(redis.is_account_erased(&f.localpart, &f.did).await.unwrap());
            assert!(redis
                .get_raw(&format!(
                    "erased:did/{}",
                    siwx_oidc::guest_admission::did_sha256_hex(&f.did)
                ))
                .await
                .unwrap()
                .is_some_and(|v| v.starts_with("guest ")));
            assert!(redis.guest_record_exists_for_did(&f.did).await.unwrap());
            // Path B (and every signature site) refuses the reaped DID for good.
            assert!(matches!(
                crate::oidc::refuse_guest_did(&redis, &f.did).await,
                Err(crate::oidc::CustomError::Coded {
                    status: 403,
                    code: "guest_identity"
                })
            ));
            assert_eq!(redis.zscore_for_test("guest:due", &f.localpart).await, None);
            assert_eq!(
                redis
                    .scard_for_test(&siwx_oidc::db::guest_records::devices_key(&f.localpart))
                    .await,
                0
            );
            let erases = calls(&log, "delete_user");
            assert!(!erases.is_empty() && erases.iter().all(|b| b.contains("\"erase\":true")));
            let mut devs = calls(&log, "delete_device");
            devs.sort();
            devs.dedup();
            assert_eq!(devs.len(), 2, "both devices deleted ({crash:?}): {devs:?}");
            // And a third call has nothing to do.
            let r = teardown_guest(&redis, &synapse, "example.org", &f.localpart).await;
            assert_eq!(r.unwrap(), GuestTeardown::AlreadyGone);
        }
    }

    /// A `claimed` account is never torn down, and nothing is called.
    #[tokio::test]
    async fn a_claimed_account_is_not_torn_down() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let (log, synapse) = mock().await;
        let f = fixture(&redis, "claimed").await;
        let r = teardown_guest(&redis, &synapse, "example.org", &f.localpart).await;
        assert_eq!(r.unwrap(), GuestTeardown::Claimed);
        assert_eq!(f.state().await.as_deref(), Some("claimed"));
        assert!(log.lock().unwrap().is_empty());
        assert!(!redis.is_account_erased(&f.localpart, &f.did).await.unwrap());
    }

    /// A failing Synapse leaves the record `reaping` for the reaper's retry; the error
    /// names the step. A guest that never had a Synapse account (404) still completes.
    #[tokio::test]
    async fn a_synapse_failure_is_returned_and_leaves_the_record_for_a_retry() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        // Nothing listens on this port.
        let dead = SynapseClient::new("http://127.0.0.1:9", "shared-secret");
        let f = fixture(&redis, "active").await;
        let e = teardown_guest(&redis, &dead, "example.org", &f.localpart)
            .await
            .unwrap_err();
        assert_eq!(e.step, Step::Devices);
        assert_eq!(f.state().await.as_deref(), Some("reaping"));
        let (_, ok) = mock().await;
        assert_eq!(
            teardown_guest(&redis, &ok, "example.org", &f.localpart)
                .await
                .unwrap(),
            GuestTeardown::Erased
        );
    }
}
