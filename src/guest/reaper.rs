//! The guest reaper (S5b, contract section 6): every tick it tears down the guests whose
//! deadline has passed, whether the deadline ran out or was moved to now by
//! `POST /guest/end` or a host.
//!
//! It runs on every instance, **whether or not `guest_enabled` is set** (a guest must
//! still be erased after an operator turns guests off), and many instances can share one
//! Redis:
//!
//! - **Lease.** An entry is claimed with `SET guest:reap:lease/<lp> <owner> NX PX 120000`
//!   inside the claim script, so two instances never run one teardown at once. A holder
//!   that dies leaves a lease that expires; the next claim resumes from the top, which
//!   [`teardown_guest`] makes safe (idempotent, the record is dropped last).
//! - **Backoff.** A failed teardown sets `guest:reap:retry/<lp>` for
//!   `min(15 s * 2^(n-1), 15 min)` (`n` from `guest:reap:fail/<lp>`); the claim skips the
//!   entry until it expires. The log names the failing step, never a name or a DID.
//! - **Done.** `Erased`, `AlreadyGone` and `Claimed` remove the entry from `guest:due`
//!   together with its lease and backoff state.
//! - **Shutdown.** On stop the loop takes no new entries; teardowns in flight get
//!   [`ReaperPolicy::shutdown_grace`] to finish, then they are abandoned and their leases
//!   given back, so the next instance resumes at once (and if even that is skipped, at
//!   lease expiry).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use siwx_oidc::db::RedisClient;

use super::teardown::{teardown_guest, GuestTeardown};
use crate::synapse_client::SynapseClient;

/// The reaper's timings and bounds.
#[derive(Clone, Debug)]
pub struct ReaperPolicy {
    /// Between two ticks (`guest_reaper_interval_secs`).
    pub interval: Duration,
    /// Teardowns started per tick (and run concurrently).
    pub batch: usize,
    /// How many due entries one claim looks at; leased and backing-off ones in front do
    /// not starve the ones behind.
    pub scan: usize,
    /// A claimed entry is hidden from other instances this long.
    pub lease: Duration,
    /// The first retry after a failure waits this long; each further failure doubles it.
    pub backoff_base: Duration,
    /// The longest a failing entry waits between tries.
    pub backoff_cap: Duration,
    /// On stop, how long a teardown in flight may finish before it is abandoned.
    pub shutdown_grace: Duration,
}

impl ReaperPolicy {
    pub fn from_interval_secs(secs: u64) -> Self {
        Self {
            interval: Duration::from_secs(secs.max(1)),
            ..Self::default()
        }
    }
}

impl Default for ReaperPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            batch: 16,
            scan: 256,
            lease: Duration::from_secs(120),
            backoff_base: Duration::from_secs(15),
            backoff_cap: Duration::from_secs(900),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One reaper instance.
#[derive(Clone)]
pub struct Reaper {
    pub redis: RedisClient,
    pub synapse: Arc<SynapseClient>,
    pub server_name: String,
    pub policy: ReaperPolicy,
    /// This instance's lease token; unique per process.
    pub owner: String,
}

/// Resolves when the stop flag is set (or its sender is gone).
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

impl Reaper {
    pub fn new(
        redis: RedisClient,
        synapse: Arc<SynapseClient>,
        server_name: String,
        policy: ReaperPolicy,
    ) -> Self {
        Self {
            redis,
            synapse,
            server_name,
            policy,
            owner: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    /// Tick until `stop` is set. Returns after the in-flight teardowns finished or were
    /// abandoned (at most [`ReaperPolicy::shutdown_grace`] after the stop).
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        info!(
            interval_secs = self.policy.interval.as_secs(),
            owner = %self.owner,
            "guest reaper started"
        );
        loop {
            if *stop.borrow() {
                break;
            }
            self.tick(&stop).await;
            tokio::select! {
                () = tokio::time::sleep(self.policy.interval) => {}
                () = stopped(&mut stop) => break,
            }
        }
        info!("guest reaper stopped");
    }

    /// One pass: claim the due guests (bounded by the batch) and tear them down
    /// concurrently. Returns how many were claimed. A store fault is logged and the
    /// next tick tries again.
    pub async fn tick(&self, stop: &watch::Receiver<bool>) -> usize {
        let claimed = match self
            .redis
            .claim_due_guests(
                &self.owner,
                millis(self.policy.lease),
                self.policy.batch,
                self.policy.scan,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(e) => {
                warn!(error = %e, "guest reaper: the schedule is unavailable");
                return 0;
            }
        };
        let count = claimed.len();
        let mut tasks = JoinSet::new();
        for localpart in &claimed {
            let reaper = self.clone();
            let localpart = localpart.clone();
            tasks.spawn(async move { reaper.handle(&localpart).await });
        }
        let mut abandon = stop.clone();
        let deadline = async {
            stopped(&mut abandon).await;
            tokio::time::sleep(self.policy.shutdown_grace).await;
        };
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                joined = tasks.join_next() => {
                    if joined.is_none() {
                        break;
                    }
                }
                () = &mut deadline => {
                    warn!(
                        in_flight = tasks.len(),
                        "guest reaper: shutting down, abandoning teardowns in flight (the next instance resumes them)"
                    );
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    for localpart in &claimed {
                        if let Err(e) = self.redis.reap_release(localpart, &self.owner).await {
                            warn!(localpart, error = %e, "guest reaper: could not release a lease, it expires on its own");
                        }
                    }
                    break;
                }
            }
        }
        count
    }

    async fn handle(&self, localpart: &str) {
        let result = teardown_guest(&self.redis, &self.synapse, &self.server_name, localpart).await;
        match result {
            Ok(outcome) => {
                match outcome {
                    GuestTeardown::Erased => info!(localpart, "guest reaped"),
                    GuestTeardown::AlreadyGone => debug!(localpart, "guest reaper: already gone"),
                    GuestTeardown::Claimed => {
                        info!(
                            localpart,
                            "guest reaper: the account is claimed, dropped from the schedule"
                        )
                    }
                }
                if let Err(e) = self.redis.reap_done(localpart, &self.owner).await {
                    warn!(localpart, error = %e, "guest reaper: could not clear the entry, it is retried after the lease");
                }
            }
            Err(e) => {
                match self
                    .redis
                    .reap_failed(
                        localpart,
                        &self.owner,
                        millis(self.policy.backoff_base),
                        millis(self.policy.backoff_cap),
                    )
                    .await
                {
                    Ok((attempt, delay_ms)) => warn!(
                        localpart,
                        step = e.step.name(),
                        attempt,
                        retry_in_ms = delay_ms,
                        error = %e.source,
                        "guest teardown failed, will retry"
                    ),
                    Err(store) => warn!(
                        localpart,
                        step = e.step.name(),
                        error = %e.source,
                        store_error = %store,
                        "guest teardown failed, retried after the lease"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post as ax_post;
    use siwx_oidc::db::grant::{GrantKind, NewGrant};
    use siwx_oidc::db::guest_records::{reap_fail_key, reap_lease_key, reap_retry_key, DUE_KEY};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// The reaper tests claim every due entry of their database, so they own database 15
    /// and take turns on it.
    static DB15: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Default)]
    struct Mock {
        calls: Mutex<Vec<(String, String)>>,
        fail: AtomicBool,
        /// Delay of `delete_user`, in ms.
        delete_user_delay_ms: AtomicU64,
    }

    impl Mock {
        fn count(&self, what: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c == what)
                .count()
        }
        fn bodies(&self, what: &str) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c == what)
                .map(|(_, b)| b.clone())
                .collect()
        }
    }

    async fn mock() -> (Arc<Mock>, Arc<SynapseClient>) {
        async fn handler(
            State((m, what)): State<(Arc<Mock>, &'static str)>,
            body: String,
        ) -> (StatusCode, &'static str) {
            m.calls.lock().unwrap().push((what.into(), body));
            if what == "delete_user" {
                let d = m.delete_user_delay_ms.load(Ordering::SeqCst);
                if d > 0 {
                    tokio::time::sleep(Duration::from_millis(d)).await;
                }
            }
            if m.fail.load(Ordering::SeqCst) {
                (StatusCode::INTERNAL_SERVER_ERROR, "{}")
            } else {
                (StatusCode::OK, "{}")
            }
        }
        let m = Arc::new(Mock::default());
        let app = axum::Router::new()
            .route(
                "/_synapse/mas/delete_device",
                ax_post(handler).with_state((m.clone(), "delete_device")),
            )
            .route(
                "/_synapse/mas/delete_user",
                ax_post(handler).with_state((m.clone(), "delete_user")),
            );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (
            m,
            Arc::new(SynapseClient::new(
                &format!("http://{addr}"),
                "shared-secret",
            )),
        )
    }

    async fn db() -> Option<RedisClient> {
        let redis = siwx_oidc::test_support::redis_db(15).await?;
        redis.flush_db_for_test().await;
        Some(redis)
    }

    struct Guest {
        localpart: String,
        did: String,
        access: String,
    }

    /// A due guest with two devices and a live grant, as S5a's fixture builds it.
    async fn due_guest(redis: &RedisClient) -> Guest {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let did = format!("did:key:z6Mk{id}");
        let localpart = siwx_oidc::mxid::localpart_for(&did);
        redis
            .put_guest_for_test(&localpart, &did, "active", 600, &id)
            .await;
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
        Guest {
            localpart,
            did,
            access: issued.access_token,
        }
    }

    impl Guest {
        async fn record_exists(&self, redis: &RedisClient) -> bool {
            !redis
                .hgetall_for_test(&siwx_oidc::db::guest_invites::guest_account_key(
                    &self.localpart,
                ))
                .await
                .is_empty()
        }
        async fn gone(&self, redis: &RedisClient) -> bool {
            !self.record_exists(redis).await
                && redis
                    .zscore_for_test(DUE_KEY, &self.localpart)
                    .await
                    .is_none()
        }
    }

    fn fast() -> ReaperPolicy {
        ReaperPolicy {
            interval: Duration::from_millis(50),
            shutdown_grace: Duration::from_millis(300),
            ..ReaperPolicy::default()
        }
    }

    fn reaper(redis: &RedisClient, synapse: &Arc<SynapseClient>, policy: ReaperPolicy) -> Reaper {
        Reaper::new(redis.clone(), synapse.clone(), "example.org".into(), policy)
    }

    fn never_stop() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    /// ST-11/ST-42 (S5): a due guest is gone within one tick: record dropped, the DID
    /// tombstoned, the devices deleted, the account erased, the grant revoked, the entry
    /// removed from the schedule, no reaper state left behind. The guest flag is not
    /// consulted anywhere (ST-33: a live overdue record is reaped with guests off).
    #[tokio::test]
    async fn a_due_guest_is_gone_within_one_tick_with_the_guest_flag_off() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let g = due_guest(&redis).await;
        // The reaper has no configuration: nothing it does reads `guest_enabled`.
        let (_tx, rx) = never_stop();
        let r = reaper(&redis, &synapse, fast());
        assert_eq!(r.tick(&rx).await, 1);
        assert!(g.gone(&redis).await);
        assert!(redis.is_account_erased(&g.localpart, &g.did).await.unwrap());
        assert!(redis.check_access_token(&g.access).await.unwrap().is_none());
        assert_eq!(m.count("delete_device"), 2);
        let erases = m.bodies("delete_user");
        assert_eq!(erases.len(), 1);
        assert!(erases[0].contains("\"erase\":true"));
        for key in [
            reap_lease_key(&g.localpart),
            reap_retry_key(&g.localpart),
            reap_fail_key(&g.localpart),
        ] {
            assert_eq!(redis.get_raw(&key).await.unwrap(), None, "{key}");
        }
        // A reaped DID never signs in again (Path B refuses it; a redeem gives did_in_use).
        assert!(redis.guest_record_exists_for_did(&g.did).await.unwrap());
        // The redeem handler asks exactly this, and answers 409 did_in_use.
        let hash = siwx_oidc::guest_admission::did_sha256_hex(&g.did);
        assert!(redis
            .guest_did_known(&g.did, &hash, &[g.localpart.as_str()])
            .await
            .unwrap());
        assert!(matches!(
            crate::oidc::refuse_guest_did(&redis, &g.did).await,
            Err(crate::oidc::CustomError::Coded {
                status: 403,
                code: "guest_identity"
            })
        ));
        // And the next tick has nothing to do.
        assert_eq!(r.tick(&rx).await, 0);
        assert_eq!(m.count("delete_user"), 1);
    }

    /// A guest whose deadline is still ahead is left alone.
    #[tokio::test]
    async fn a_guest_before_its_deadline_is_not_touched() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let did = format!("did:key:z6Mk{id}");
        let lp = siwx_oidc::mxid::localpart_for(&did);
        redis
            .put_guest_for_test(&lp, &did, "active", 600, &id)
            .await;
        let (_tx, rx) = never_stop();
        assert_eq!(reaper(&redis, &synapse, fast()).tick(&rx).await, 0);
        assert!(m.calls.lock().unwrap().is_empty());
    }

    /// ST-22 (S5, two instances): N due guests, two reapers ticking at once on one Redis:
    /// every teardown runs exactly once.
    #[tokio::test]
    async fn two_reapers_on_one_redis_tear_each_guest_down_once() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        const N: usize = 12;
        let mut guests = Vec::new();
        for _ in 0..N {
            guests.push(due_guest(&redis).await);
        }
        let policy = ReaperPolicy { batch: 5, ..fast() };
        let (a, b) = (
            reaper(&redis, &synapse, policy.clone()),
            reaper(&redis, &synapse, policy),
        );
        assert_ne!(a.owner, b.owner);
        let (_tx, rx) = never_stop();
        let mut total = 0;
        for _ in 0..6 {
            let (x, y) = tokio::join!(a.tick(&rx), b.tick(&rx));
            assert!(x <= 5 && y <= 5, "the batch bounds a tick");
            total += x + y;
            if total >= N {
                break;
            }
        }
        assert_eq!(total, N, "each guest was claimed exactly once");
        for g in &guests {
            assert!(g.gone(&redis).await);
        }
        assert_eq!(m.count("delete_user"), N);
        assert_eq!(m.count("delete_device"), 2 * N);
        let users: HashSet<_> = m.bodies("delete_user").into_iter().collect();
        assert_eq!(users.len(), N, "no guest was erased twice");
    }

    /// ST-22 (S5, crashed holder): an instance takes the lease, runs some steps, and
    /// dies. Nothing else runs the guest while the lease holds; after it expires another
    /// instance finishes cleanly.
    #[tokio::test]
    async fn a_lease_of_a_dead_holder_expires_and_another_instance_resumes() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let g = due_guest(&redis).await;
        // The dead holder: a short lease, the first steps run (up to the device deletes),
        // never released.
        let dead = "dead-holder";
        assert_eq!(
            redis.claim_due_guests(dead, 700, 16, 256).await.unwrap(),
            vec![g.localpart.clone()]
        );
        let crashed = super::super::teardown::run(
            &redis,
            &synapse,
            "example.org",
            &g.localpart,
            Some(crate::teardown::Step::Devices),
        )
        .await;
        assert!(crashed.is_ok());
        assert!(g.record_exists(&redis).await);
        let (_tx, rx) = never_stop();
        let r = reaper(&redis, &synapse, fast());
        assert_eq!(r.tick(&rx).await, 0, "the lease holds the entry back");
        assert!(g.record_exists(&redis).await);
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(r.tick(&rx).await, 1, "the lease expired");
        assert!(g.gone(&redis).await);
        assert!(redis.is_account_erased(&g.localpart, &g.did).await.unwrap());
        assert_eq!(m.count("delete_user"), 1);
    }

    /// ST-22 (S5, SIGTERM during a slow `delete_user`): the loop exits within the bound,
    /// leaving the guest for the next start, which completes it.
    #[tokio::test]
    async fn shutdown_during_a_slow_delete_user_is_bounded_and_the_next_start_completes() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        m.delete_user_delay_ms.store(5_000, Ordering::SeqCst);
        let g = due_guest(&redis).await;
        let (tx, rx) = watch::channel(false);
        let r = reaper(&redis, &synapse, fast());
        let handle = tokio::spawn(r.run(rx));
        // Wait until the slow call is in flight.
        let started = std::time::Instant::now();
        while m.count("delete_user") == 0 {
            assert!(started.elapsed() < Duration::from_secs(3), "never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stop_at = std::time::Instant::now();
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the loop exits within the grace bound, not the 5 s Synapse call")
            .unwrap();
        assert!(stop_at.elapsed() < Duration::from_millis(1500));
        // The guest is still there, in `reaping`, its lease given back.
        assert!(g.record_exists(&redis).await);
        assert_eq!(
            redis.get_raw(&reap_lease_key(&g.localpart)).await.unwrap(),
            None
        );
        // The next start: a fast Synapse; it completes the guest.
        m.delete_user_delay_ms.store(0, Ordering::SeqCst);
        let (_tx2, rx2) = never_stop();
        assert_eq!(reaper(&redis, &synapse, fast()).tick(&rx2).await, 1);
        assert!(g.gone(&redis).await);
        assert!(redis.is_account_erased(&g.localpart, &g.did).await.unwrap());
    }

    /// A stop that is already set makes the loop take no entry at all.
    #[tokio::test]
    async fn a_stopped_reaper_takes_no_new_entries() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let g = due_guest(&redis).await;
        let (tx, rx) = watch::channel(false);
        tx.send(true).unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            reaper(&redis, &synapse, fast()).run(rx),
        )
        .await
        .unwrap();
        assert!(m.calls.lock().unwrap().is_empty());
        assert!(g.record_exists(&redis).await);
    }

    /// Backoff: a failing Synapse gates the entry (growing, capped), the log-visible
    /// count rises, and once Synapse heals the guest completes and the state is cleared.
    #[tokio::test]
    async fn a_failing_synapse_backs_the_entry_off_and_a_healed_one_completes() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        m.fail.store(true, Ordering::SeqCst);
        let g = due_guest(&redis).await;
        let policy = ReaperPolicy {
            backoff_base: Duration::from_millis(300),
            backoff_cap: Duration::from_millis(600),
            ..fast()
        };
        let r = reaper(&redis, &synapse, policy);
        let (_tx, rx) = never_stop();
        assert_eq!(r.tick(&rx).await, 1);
        assert!(g.record_exists(&redis).await, "a failure keeps the record");
        assert!(redis.zscore_for_test(DUE_KEY, &g.localpart).await.is_some());
        let tries = m.count("delete_device");
        assert!(tries >= 1);
        assert_eq!(
            redis.get_raw(&reap_lease_key(&g.localpart)).await.unwrap(),
            None,
            "the lease is given back on a failure"
        );
        assert_eq!(
            redis
                .get_raw(&reap_fail_key(&g.localpart))
                .await
                .unwrap()
                .as_deref(),
            Some("1")
        );
        // Backing off: the next tick does not even claim it.
        assert_eq!(r.tick(&rx).await, 0);
        assert_eq!(m.count("delete_device"), tries);
        // After the first delay it is tried (and fails) again; the delay doubles to the cap.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(r.tick(&rx).await, 1);
        assert_eq!(
            redis
                .get_raw(&reap_fail_key(&g.localpart))
                .await
                .unwrap()
                .as_deref(),
            Some("2")
        );
        let ttl = redis.pttl_for_test(&reap_retry_key(&g.localpart)).await;
        assert!(
            (300..=600).contains(&ttl),
            "second delay 600 ms (cap), got {ttl}"
        );
        // Healed: it completes once the gate opens, and the state is cleared.
        m.fail.store(false, Ordering::SeqCst);
        assert_eq!(r.tick(&rx).await, 0, "still gated after a heal");
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(r.tick(&rx).await, 1);
        assert!(g.gone(&redis).await);
        for key in [reap_retry_key(&g.localpart), reap_fail_key(&g.localpart)] {
            assert_eq!(redis.get_raw(&key).await.unwrap(), None, "{key}");
        }
    }

    /// A claimed account is dropped from the schedule and left alone.
    #[tokio::test]
    async fn a_claimed_account_leaves_the_schedule_untouched() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let g = due_guest(&redis).await;
        redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&g.localpart),
                "state",
                "claimed",
            )
            .await;
        let (_tx, rx) = never_stop();
        assert_eq!(reaper(&redis, &synapse, fast()).tick(&rx).await, 1);
        assert!(g.record_exists(&redis).await);
        assert_eq!(redis.zscore_for_test(DUE_KEY, &g.localpart).await, None);
        assert!(m.calls.lock().unwrap().is_empty());
    }
}
