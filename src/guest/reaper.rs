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
//! - **Deferred.** A hand-off holding the record's lease is not a failure: the entry is
//!   gated for 10 s, the failure count is left alone, and the audit outcome is `deferred`.
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
use tracing::{debug, error, info, warn};

use siwx_oidc::db::RedisClient;

use super::teardown::{teardown_guest, GuestTeardown};
use crate::synapse_client::SynapseClient;

/// The thresholds of the audit alerts (S6, GP-SEC-47). A zero switches an alert off.
#[derive(Clone, Debug)]
pub struct AlertPolicy {
    /// A `reaping` record due for longer than this many seconds.
    pub reaping_secs: u64,
    /// Live guests as a percentage of `global_max`.
    pub live_pct: u64,
    /// Guests minted today as a percentage of `daily_max`.
    pub daily_pct: u64,
    /// Refused guest requests in one minute.
    pub refusals_per_min: u64,
    pub global_max: u64,
    pub daily_max: u64,
}

impl Default for AlertPolicy {
    fn default() -> Self {
        Self {
            reaping_secs: 900,
            live_pct: 80,
            daily_pct: 80,
            refusals_per_min: 50,
            global_max: 50,
            daily_max: 500,
        }
    }
}

/// What this instance saw last tick, for the change event and the burst-alert dedupe.
#[derive(Default)]
struct Seen {
    control: Option<String>,
    refusal_minute: u64,
}

/// How long a deferred entry (a hand-off holds the record) waits before the next try. The
/// hand-off lease (120 s) bounds how often this repeats.
const DEFERRED_GATE: Duration = Duration::from_secs(10);

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
    pub alerts: AlertPolicy,
}

impl ReaperPolicy {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            alerts: AlertPolicy {
                reaping_secs: config.guest_alert_reaping_secs,
                live_pct: config.guest_alert_live_pct,
                daily_pct: config.guest_alert_daily_pct,
                refusals_per_min: config.guest_alert_refusals_per_min,
                global_max: config.guest_global_max_active,
                daily_max: config.guest_daily_mint_max,
            },
            ..Self::from_interval_secs(config.guest_reaper_interval_secs)
        }
    }

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
            alerts: AlertPolicy::default(),
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
    seen: Arc<std::sync::Mutex<Seen>>,
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
            seen: Arc::default(),
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
        self.control_pass().await;
        self.claim_revoke_pass().await;
        let count = self.reap_due(stop).await;
        self.alerts().await;
        count
    }

    /// Finish the device revocation of any claim a crash interrupted (S7a): the commit puts
    /// the localpart on `guest:claim_revoke`, the handler takes it off when done. Idempotent.
    async fn claim_revoke_pass(&self) {
        let pending = match self.redis.pending_claim_revokes().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "guest reaper: guest:claim_revoke cannot be read");
                return;
            }
        };
        for localpart in pending {
            let synapse = Some((self.synapse.as_ref(), self.server_name.as_str()));
            if let Err(e) =
                super::claim::finish_claim_revoke(&self.redis, synapse, &localpart).await
            {
                warn!(error = %e, localpart, "guest reaper: claim revocation retry failed");
            }
        }
    }

    /// The operator's switches (S6): log a change, then make the guests that
    /// `guest:control reap_before` or `guest:banned_hosts` name due now. A fault here is
    /// logged and never stops the normal reap of what is already due.
    async fn control_pass(&self) {
        let control = match self.redis.guest_control().await {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(error = %e, "guest reaper: guest:control cannot be read, reaping what is due");
                None
            }
        };
        let banned = match self.redis.guest_banned_hosts().await {
            Ok(b) => Some(b),
            Err(e) => {
                warn!(error = %e, "guest reaper: guest:banned_hosts cannot be read");
                None
            }
        };
        if let (Some(c), Some(b)) = (control, banned.as_ref()) {
            let disabled = c.disabled.to_string();
            let reap_before = c.reap_before.map(|v| v.to_string()).unwrap_or_default();
            let hosts = b.join(",");
            let now = format!("{disabled}|{reap_before}|{hosts}");
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            let before = seen.control.get_or_insert_with(|| "false||".to_string());
            if *before != now {
                super::audit::control_changed(&disabled, &reap_before, &hosts);
                seen.control = Some(now);
            }
        }
        let reap_before = control.and_then(|c| c.reap_before);
        if reap_before.is_none() && banned.as_ref().is_none_or(|b| b.is_empty()) {
            return;
        }
        match self.redis.enforce_guest_control(reap_before).await {
            Ok(m) if m.by_reap_before + m.by_ban > 0 => info!(
                by_reap_before = m.by_reap_before,
                by_banned_host = m.by_ban,
                "guest reaper: guests made due by the operator's control"
            ),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "guest reaper: the control pass failed"),
        }
    }

    /// The alerts of GP-SEC-47: one `error` line per condition per tick at most.
    async fn alerts(&self) {
        let a = &self.policy.alerts;
        let f = match self.redis.guest_alert_figures(a.reaping_secs).await {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "guest reaper: the alert figures cannot be read");
                return;
            }
        };
        if a.reaping_secs > 0 && f.stuck_reaping > 0 {
            error!(target: "guest_audit", alert = "reaping_stuck", count = f.stuck_reaping,
                oldest_secs = f.oldest_stuck_secs, threshold_secs = a.reaping_secs,
                "guest alert: records stuck in reaping");
        }
        if a.live_pct > 0 && a.global_max > 0 && f.live * 100 >= a.live_pct * a.global_max {
            error!(target: "guest_audit", alert = "live_guests_high", live = f.live,
                max = a.global_max, threshold_pct = a.live_pct,
                "guest alert: live guests near the global cap");
        }
        if a.daily_pct > 0 && a.daily_max > 0 && f.daily_mints * 100 >= a.daily_pct * a.daily_max {
            error!(target: "guest_audit", alert = "daily_mints_high", minted = f.daily_mints,
                max = a.daily_max, threshold_pct = a.daily_pct,
                "guest alert: daily mints near the quota");
        }
        if a.refusals_per_min > 0 && f.refusals_per_min > a.refusals_per_min {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            if seen.refusal_minute != f.refusal_minute {
                seen.refusal_minute = f.refusal_minute;
                error!(target: "guest_audit", alert = "refusal_burst", refusals = f.refusals_per_min,
                    threshold = a.refusals_per_min, "guest alert: many refused guest requests in a minute");
            }
        }
    }

    async fn reap_due(&self, stop: &watch::Receiver<bool>) -> usize {
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
                    GuestTeardown::Erased => {
                        info!(localpart, "guest reaped");
                        super::audit::reap("due", "erased", 0)
                    }
                    GuestTeardown::AlreadyGone => {
                        debug!(localpart, "guest reaper: already gone");
                        super::audit::reap("due", "already_gone", 0)
                    }
                    GuestTeardown::Claimed => {
                        super::audit::reap("due", "claimed", 0);
                        info!(
                            localpart,
                            "guest reaper: the account is claimed, dropped from the schedule"
                        )
                    }
                    GuestTeardown::Deferred => {
                        super::audit::reap("due", "deferred", 0);
                        debug!(
                            localpart,
                            "guest reaper: a hand-off holds the record, retried shortly"
                        );
                        if let Err(e) = self
                            .redis
                            .reap_deferred(localpart, &self.owner, millis(DEFERRED_GATE))
                            .await
                        {
                            warn!(localpart, error = %e, "guest reaper: could not gate a deferred entry, it is retried after the lease");
                        }
                        return;
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
                    Ok((attempt, delay_ms)) => {
                        super::audit::reap("due", "failed", attempt);
                        warn!(
                            localpart,
                            step = e.step.name(),
                            attempt,
                            retry_in_ms = delay_ms,
                            error = %e.source,
                            "guest teardown failed, will retry"
                        )
                    }
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
        let g = live_guest(redis, "active", 0, "host-a").await;
        redis.end_guest_now(&g.localpart).await.unwrap();
        g
    }

    /// A live guest (`state`, a deadline ten minutes out, in `guest:due`) minted at Redis
    /// `TIME` + `minted_offset`, of `host`, with two devices and a live grant.
    async fn live_guest(redis: &RedisClient, state: &str, minted_offset: i64, host: &str) -> Guest {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let did = format!("did:key:z6Mk{id}");
        let localpart = siwx_oidc::mxid::localpart_for(&did);
        redis
            .put_guest_for_test(&localpart, &did, state, 600, &id)
            .await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&localpart);
        let now = chrono::Utc::now().timestamp();
        redis
            .hset_raw_for_test(&key, "created_at", &(now + minted_offset).to_string())
            .await;
        redis.hset_raw_for_test(&key, "host", host).await;
        redis.zadd_for_test(DUE_KEY, now + 600, &localpart).await;
        let devices = siwx_oidc::db::guest_records::devices_key(&localpart);
        redis.sadd_raw_for_test(&devices, "DEVICE_A").await;
        redis.sadd_raw_for_test(&devices, "DEVICE_B").await;
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

    /// SS4 flag 2 (8.12): the guest reaper plants no deleted-id marker, even with the
    /// markers on in its Synapse client (`erased:did` already refuses a reaped guest DID).
    #[tokio::test]
    async fn marker_not_planted_by_guest_reaper() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let synapse = Arc::new(
            Arc::try_unwrap(synapse)
                .ok()
                .expect("one owner")
                .with_deleted_markers(Some(600)),
        );
        let g = due_guest(&redis).await;
        let (_tx, rx) = never_stop();
        assert_eq!(reaper(&redis, &synapse, fast()).tick(&rx).await, 1);
        assert_eq!(m.count("delete_device"), 2, "the devices are deleted");
        for dev in ["DEVICE_A", "DEVICE_B"] {
            assert!(
                !siwx_oidc::db::DBClient::is_deleted_device(&redis, &g.localpart, dev)
                    .await
                    .unwrap(),
                "{dev}"
            );
        }
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

    /// #54 L2: a hand-off holding the record defers the teardown without counting a
    /// failure: nothing is touched, the lease is given back, a short gate is set, and once
    /// the hand-off lease lapses the next try erases the guest.
    #[tokio::test]
    async fn a_live_hand_off_defers_the_teardown_without_a_failure() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let g = due_guest(&redis).await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&g.localpart);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        redis
            .hset_raw_for_test(&key, "lease_owner", "attempt-1")
            .await;
        redis
            .hset_raw_for_test(&key, "lease_until", &(now + 120).to_string())
            .await;
        let r = reaper(&redis, &synapse, fast());
        let (_tx, rx) = never_stop();
        assert_eq!(r.tick(&rx).await, 1);
        assert!(g.record_exists(&redis).await);
        assert!(redis.zscore_for_test(DUE_KEY, &g.localpart).await.is_some());
        assert_eq!(m.count("delete_device"), 0);
        assert_eq!(m.count("delete_user"), 0);
        assert_eq!(
            redis.get_raw(&reap_lease_key(&g.localpart)).await.unwrap(),
            None
        );
        assert_eq!(
            redis.get_raw(&reap_fail_key(&g.localpart)).await.unwrap(),
            None,
            "a deferral is not a failure"
        );
        let ttl = redis.pttl_for_test(&reap_retry_key(&g.localpart)).await;
        assert!((9_000..=10_000).contains(&ttl), "a 10 s gate, got {ttl}");
        assert_eq!(r.tick(&rx).await, 0, "gated");
        // The hand-off ends (`0`: the script compares with Redis `TIME`) and the gate opens.
        redis.hset_raw_for_test(&key, "lease_until", "0").await;
        redis.del_raw(&reap_retry_key(&g.localpart)).await.unwrap();
        assert_eq!(r.tick(&rx).await, 1);
        assert!(g.gone(&redis).await);
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

    // ---- S6: the kill switch, banned hosts, alerts -------------------------------------

    use siwx_oidc::db::guest_invites::{guest_account_key, BANNED_HOSTS_KEY, CONTROL_KEY};

    async fn state_of(redis: &RedisClient, g: &Guest) -> Option<String> {
        redis
            .hgetall_for_test(&guest_account_key(&g.localpart))
            .await
            .get("state")
            .cloned()
    }

    async fn refresh_allowed(redis: &RedisClient, g: &Guest) -> anyhow::Result<bool> {
        let read = redis.guest_refresh_read(&g.localpart, "DEVICE_A").await?;
        Ok(crate::guest::handoff::refresh_verdict(&read))
    }

    /// ST-22 (second half): `reap_before` reaps with Synapse down. Every matching live
    /// record goes to `reaping` and its grants are revoked in the first tick; when Synapse
    /// returns the next ticks finish the reap. A guest minted after it and a claimed
    /// account are untouched, and the refresh guard refuses a matching guest at once.
    #[tokio::test]
    async fn st22_reap_before_reaps_with_synapse_down() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (m, synapse) = mock().await;
        let old = live_guest(&redis, "active", -100, "host-a").await;
        let old2 = live_guest(&redis, "minted", -50, "host-b").await;
        let newer = live_guest(&redis, "active", 1_000, "host-a").await;
        let claimed = live_guest(&redis, "claimed", -100, "host-a").await;
        assert!(refresh_allowed(&redis, &old).await.unwrap());
        let now = chrono::Utc::now().timestamp();
        redis
            .hset_raw_for_test(CONTROL_KEY, "reap_before", &now.to_string())
            .await;
        // The refresh guard needs no tick.
        assert!(!refresh_allowed(&redis, &old).await.unwrap());
        assert!(refresh_allowed(&redis, &newer).await.unwrap());
        assert!(refresh_allowed(&redis, &claimed).await.unwrap());

        m.fail.store(true, Ordering::SeqCst);
        let policy = ReaperPolicy {
            backoff_base: Duration::from_millis(1),
            backoff_cap: Duration::from_millis(5),
            ..fast()
        };
        let r = reaper(&redis, &synapse, policy);
        let (_tx, stop) = never_stop();
        r.tick(&stop).await;
        for g in [&old, &old2] {
            assert_eq!(state_of(&redis, g).await.as_deref(), Some("reaping"));
            assert!(
                redis.check_access_token(&g.access).await.unwrap().is_none(),
                "the grant is revoked while Synapse is down"
            );
            assert!(!refresh_allowed(&redis, g).await.unwrap());
        }
        assert_eq!(state_of(&redis, &newer).await.as_deref(), Some("active"));
        assert_eq!(state_of(&redis, &claimed).await.as_deref(), Some("claimed"));
        assert!(redis
            .check_access_token(&newer.access)
            .await
            .unwrap()
            .is_some());

        m.fail.store(false, Ordering::SeqCst);
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            r.tick(&stop).await;
        }
        assert!(old.gone(&redis).await && old2.gone(&redis).await);
        assert_eq!(state_of(&redis, &newer).await.as_deref(), Some("active"));
        assert_eq!(state_of(&redis, &claimed).await.as_deref(), Some("claimed"));
        redis.flush_db_for_test().await;
    }

    /// A banned host's live guests are reaped; another host's are not; the ban lifts.
    #[tokio::test]
    async fn a_banned_hosts_guests_are_reaped_and_others_are_not() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (_m, synapse) = mock().await;
        let bad = live_guest(&redis, "active", -10, "bad-host").await;
        let good = live_guest(&redis, "active", -10, "good-host").await;
        redis.sadd_raw(BANNED_HOSTS_KEY, "bad-host").await.unwrap();
        assert!(redis.guest_host_banned("bad-host").await.unwrap());
        assert!(!redis.guest_host_banned("good-host").await.unwrap());
        let r = reaper(&redis, &synapse, fast());
        let (_tx, stop) = never_stop();
        r.tick(&stop).await;
        assert!(bad.gone(&redis).await);
        assert_eq!(state_of(&redis, &good).await.as_deref(), Some("active"));
        redis.flush_db_for_test().await;
    }

    /// `disabled` engages on `1`/`true` only; clearing restores; a WRONGTYPE key or an
    /// unparseable value is an error (every caller fails closed), the reaper still reaps
    /// what is due, and the change is logged once.
    #[tokio::test]
    async fn the_control_hash_parses_and_fails_closed() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (_m, synapse) = mock().await;
        let g = live_guest(&redis, "active", 0, "host-a").await;
        assert!(!redis.guest_control().await.unwrap().disabled);
        for (v, engaged) in [("1", true), ("true", true), ("0", false), ("false", false)] {
            redis.hset_raw_for_test(CONTROL_KEY, "disabled", v).await;
            assert_eq!(
                redis.guest_control().await.unwrap().disabled,
                engaged,
                "{v}"
            );
            assert_eq!(refresh_allowed(&redis, &g).await.unwrap(), !engaged, "{v}");
        }
        redis.hset_raw_for_test(CONTROL_KEY, "disabled", "1").await;
        let cap = siwx_oidc::test_support::LogCapture::start();
        let r = reaper(&redis, &synapse, fast());
        let (_tx, stop) = never_stop();
        r.tick(&stop).await;
        r.tick(&stop).await;
        assert_eq!(cap.output().matches("guest_control_changed").count(), 1);
        redis.del_raw(CONTROL_KEY).await.unwrap();
        // Unparseable values.
        redis
            .hset_raw_for_test(CONTROL_KEY, "disabled", "maybe")
            .await;
        assert!(redis.guest_control().await.is_err());
        assert!(refresh_allowed(&redis, &g).await.is_err());
        redis.del_raw(CONTROL_KEY).await.unwrap();
        redis
            .hset_raw_for_test(CONTROL_KEY, "reap_before", "soon")
            .await;
        assert!(refresh_allowed(&redis, &g).await.is_err());
        // WRONGTYPE: the old plain-string key.
        redis.del_raw(CONTROL_KEY).await.unwrap();
        redis.set_raw(CONTROL_KEY, "disabled").await.unwrap();
        assert!(redis.guest_control().await.is_err());
        assert!(refresh_allowed(&redis, &g).await.is_err());
        assert!(crate::guest::handoff::guest_kill_switch_engaged(&redis)
            .await
            .is_err());
        // The reaper keeps reaping what is due, with the control unreadable.
        let due = due_guest(&redis).await;
        r.tick(&stop).await;
        assert!(due.gone(&redis).await);
        assert_eq!(state_of(&redis, &g).await.as_deref(), Some("active"));
        redis.flush_db_for_test().await;
    }

    /// ST-32: each of the four alert conditions emits its alert; a quiet system emits none.
    #[tokio::test]
    async fn st32_each_alert_condition_emits_its_alert() {
        let _turn = DB15.lock().await;
        let Some(redis) = db().await else { return };
        let (_m, synapse) = mock().await;
        let (_tx, stop) = never_stop();
        let policy = ReaperPolicy {
            alerts: AlertPolicy {
                reaping_secs: 900,
                live_pct: 80,
                daily_pct: 80,
                refusals_per_min: 5,
                global_max: 10,
                daily_max: 10,
            },
            // keep a failing teardown from retrying inside the test
            ..fast()
        };
        let r = reaper(&redis, &synapse, policy);
        let cap = siwx_oidc::test_support::LogCapture::start();
        r.tick(&stop).await;
        assert!(!cap.output().contains("alert"), "{}", cap.output());

        // 1. a record stuck in reaping for over 15 minutes
        let stuck = live_guest(&redis, "reaping", 0, "h").await;
        let now = chrono::Utc::now().timestamp();
        redis
            .zadd_for_test(DUE_KEY, now - 2_000, &stuck.localpart)
            .await;
        // the same guest is also backing off, so the tick does not claim it
        redis
            .set_raw(&reap_retry_key(&stuck.localpart), "1")
            .await
            .unwrap();
        r.tick(&stop).await;
        assert!(cap.output().contains("reaping_stuck"), "{}", cap.output());
        redis.flush_db_for_test().await;

        // 2. live guests at 80 % of the cap (8 of 10)
        for i in 0..8 {
            redis
                .zadd_for_test(DUE_KEY, now + 600, &format!("lp{i}"))
                .await;
        }
        r.tick(&stop).await;
        assert!(cap.output().contains("live_guests_high"));
        redis.flush_db_for_test().await;

        // 3. daily mints at 80 % of the quota
        redis
            .set_raw(&format!("guest:quota/daily_mint/{}", now / 86_400), "8")
            .await
            .unwrap();
        r.tick(&stop).await;
        assert!(cap.output().contains("daily_mints_high"));
        redis.flush_db_for_test().await;

        // 4. a refusal burst (12 across at most two minutes; the larger minute is > 5)
        let before = cap.output().matches("refusal_burst").count();
        for _ in 0..12 {
            redis.count_guest_refusal().await.unwrap();
        }
        r.tick(&stop).await;
        r.tick(&stop).await;
        assert_eq!(cap.output().matches("refusal_burst").count(), before + 1);
        redis.flush_db_for_test().await;
    }
}
