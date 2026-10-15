//! The device reaper (SS4 flag 3, `SIWXOIDC_DEVICE_REAPER_ENABLED`; model 8.14).
//!
//! A Synapse device whose session ended without its device being deleted (a client
//! that lost its storage, a revoke before flag 1, a refresh token that ran out) stays
//! listed forever: a ghost no client can use. This task pages the Synapse admin user
//! list, lists each account's devices and deletes a device only when **all** hold:
//!
//! | Rule | Why |
//! |---|---|
//! | the account is not in `SIWXOIDC_DEVICE_REAPER_SPARE_USERS` | agent and bot accounts are spared by listing them |
//! | Synapse's `last_seen_ts` is not NULL | a device that was never seen may be seconds old |
//! | `last_seen_ts` is older than the idle threshold | the refresh-token lifetime (90 d) plus `SIWXOIDC_DEVICE_REAPER_MARGIN_SECS` (7 d), or `SIWXOIDC_DEVICE_REAPER_MIN_IDLE_SECS` when set |
//! | the device has no live grant | `EXISTS` on its grant index and on the legacy device index, nothing else ([`siwx_oidc::db::device_has_live_grant_on`]) |
//!
//! The checks run in that order, so Redis is read only for a device that passed the
//! other three. Refreshes reach siwx-oidc, never Synapse, so `last_seen` alone does not
//! bound a grant's last use: the grant check is what keeps a live session's device.
//!
//! A delete runs in the teardown order (8.23): the Synapse delete, then the deleted-id
//! marker when flag 2 is on ([`crate::compat::plant_deleted_marker`]). No revoke: the
//! device has no grant. A delete Synapse refuses is counted and the pass goes on.
//!
//! **Dry run** (`SIWXOIDC_DEVICE_REAPER_DRY_RUN`, true by default): a pass deletes
//! nothing. Either way the log carries counts only (and, for a real delete, the hashed
//! ids); the full list, with Matrix ids in clear, goes only to
//! `SIWXOIDC_DEVICE_REAPER_REPORT_PATH` when it is set.
//!
//! Several instances can share one Redis: a pass runs only for the instance that wins
//! `SET device_reaper:lease 1 NX EX <interval>`. With flag 3 off nothing here runs:
//! [`spawn`] starts no task.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use siwx_oidc::db::{RedisClient, REFRESH_TOKEN_TTL};
use siwx_oidc::redact::fingerprint;

use crate::config::Config;
use crate::synapse_client::{DeviceDelete, SynapseClient};

pub const LEASE_KEY: &str = "device_reaper:lease";
/// A pass stops after this many pages (100 users each), so a misbehaving upstream cannot
/// keep it looping.
const MAX_PAGES: usize = 1000;

/// The live-grant check, a trait so a test can record the Redis commands it sends.
#[async_trait]
pub trait LiveGrants: Send + Sync {
    async fn has_live_grant(&self, username: &str, device_id: &str) -> Result<bool>;
}

#[async_trait]
impl LiveGrants for RedisClient {
    async fn has_live_grant(&self, username: &str, device_id: &str) -> Result<bool> {
        self.device_has_live_grant(username, device_id).await
    }
}

/// The reaper's settings, read once at startup.
#[derive(Debug, Clone)]
pub struct ReaperPolicy {
    pub dry_run: bool,
    pub interval: Duration,
    /// A device idle (by Synapse's `last_seen_ts`) for longer than this is a candidate.
    pub min_idle: Duration,
    /// Spared localparts, lowercased.
    pub spare_users: HashSet<String>,
    pub report_path: Option<String>,
}

impl ReaperPolicy {
    pub fn from_config(c: &Config) -> Self {
        let min_idle = c
            .device_reaper_min_idle_secs
            .unwrap_or(REFRESH_TOKEN_TTL.saturating_add(c.device_reaper_margin_secs));
        Self {
            dry_run: c.device_reaper_dry_run,
            interval: Duration::from_secs(c.device_reaper_interval_secs.max(1)),
            min_idle: Duration::from_secs(min_idle),
            spare_users: c
                .device_reaper_spare_users
                .iter()
                .map(|u| spare_localpart(u))
                .collect(),
            report_path: c.device_reaper_report_path.clone(),
        }
    }
}

/// A spare-list entry as a lowercased localpart: `agent`, `@agent:example.org` and
/// `Agent` all name the same account.
fn spare_localpart(entry: &str) -> String {
    let e = entry.trim();
    let e = e.strip_prefix('@').unwrap_or(e);
    e.split(':').next().unwrap_or(e).to_lowercase()
}

/// What happened to one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    SparedListed,
    SparedNullLastSeen,
    SparedRecent,
    SparedLiveGrant,
    /// The grant check failed: spared, since a failure can only spare.
    SparedCheckFailed,
    /// A candidate in a dry run.
    WouldDelete,
    Deleted,
    DeleteFailed,
}

/// The counts of one pass, the only thing a pass logs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PassReport {
    pub users: u64,
    pub devices: u64,
    /// Accounts whose devices could not be listed (skipped).
    pub list_failed: u64,
    pub spared_listed: u64,
    pub spared_null_last_seen: u64,
    pub spared_recent: u64,
    pub spared_live_grant: u64,
    pub check_failed: u64,
    /// Devices that met every rule (deleted, or would be in a dry run).
    pub candidates: u64,
    pub deleted: u64,
    pub failed: u64,
}

/// One line of the report file.
#[derive(Serialize)]
struct Row<'a> {
    user: &'a str,
    user_type: Option<&'a str>,
    device_id: &'a str,
    last_seen_ts: Option<i64>,
    verdict: Verdict,
}

pub struct DeviceReaper {
    pub redis: RedisClient,
    pub grants: Arc<dyn LiveGrants>,
    pub synapse: Arc<SynapseClient>,
    pub server_name: String,
    pub policy: ReaperPolicy,
}

/// Start the reaper when flag 3 is on and Synapse is configured; `None` otherwise.
/// With the flag off this does nothing at all, not even a log line.
pub fn spawn(
    config: &Config,
    redis: RedisClient,
    synapse: Option<Arc<SynapseClient>>,
    stop: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !config.device_reaper_enabled {
        return None;
    }
    let (Some(synapse), Some(server_name)) = (synapse, config.matrix_server_name.clone()) else {
        warn!("device reaper not started: synapse_endpoint, mas_shared_secret or matrix_server_name is not set");
        return None;
    };
    let policy = ReaperPolicy::from_config(config);
    info!(
        dry_run = policy.dry_run,
        interval_secs = policy.interval.as_secs(),
        min_idle_secs = policy.min_idle.as_secs(),
        min_idle_override = config.device_reaper_min_idle_secs.is_some(),
        spare_users = policy.spare_users.len(),
        report_file = policy.report_path.is_some(),
        "device reaper started"
    );
    let reaper = DeviceReaper {
        grants: Arc::new(redis.clone()),
        redis,
        synapse,
        server_name,
        policy,
    };
    Some(tokio::spawn(reaper.run(stop)))
}

impl DeviceReaper {
    /// Wake, and run a pass when this instance wins the lease, until `stop` is set.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let poll = self.policy.interval.min(Duration::from_secs(300));
        let mut wait = poll.min(Duration::from_secs(60));
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = stop.wait_for(|s| *s) => break,
            }
            wait = poll;
            if let Err(e) = self.pass_if_leased().await {
                warn!(error = %e, "device reaper pass failed");
            }
        }
    }

    /// One attempt: take the lease, then [`pass_once`](Self::pass_once). `None`: another
    /// instance holds the lease.
    pub async fn pass_if_leased(&self) -> Result<Option<PassReport>> {
        if !self
            .redis
            .try_lease(LEASE_KEY, self.policy.interval.as_secs())
            .await?
        {
            return Ok(None);
        }
        self.pass_once().await.map(Some)
    }

    /// One pass over every active account: page the users, list each one's devices,
    /// decide each device ([`Verdict`]), delete the candidates unless this is a dry run,
    /// log the counts and write the report file.
    pub async fn pass_once(&self) -> Result<PassReport> {
        let suffix = format!(":{}", self.server_name);
        let idle_ms = i64::try_from(self.policy.min_idle.as_millis()).unwrap_or(i64::MAX);
        let mut report = PassReport::default();
        let mut rows: Vec<String> = Vec::new();
        let mut from: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = self
                .synapse
                .admin_users_page(from.as_deref(), false)
                .await?;
            for row in &page.users {
                let Some(localpart) = row
                    .name
                    .strip_prefix('@')
                    .and_then(|n| n.strip_suffix(suffix.as_str()))
                else {
                    continue;
                };
                report.users += 1;
                let listed = self.policy.spare_users.contains(&localpart.to_lowercase());
                let devices = match self
                    .synapse
                    .list_devices(localpart, &self.server_name)
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        report.list_failed += 1;
                        warn!(error = %e, user = %fingerprint(localpart), "device reaper: devices not listed; account skipped");
                        continue;
                    }
                };
                for d in &devices {
                    report.devices += 1;
                    let verdict = self
                        .decide(
                            localpart,
                            listed,
                            &d.device_id,
                            d.last_seen_ts,
                            idle_ms,
                            &mut report,
                        )
                        .await;
                    if self.policy.report_path.is_some() {
                        rows.push(serde_json::to_string(&Row {
                            user: &row.name,
                            user_type: row.user_type.as_deref(),
                            device_id: &d.device_id,
                            last_seen_ts: d.last_seen_ts,
                            verdict,
                        })?);
                    }
                }
            }
            from = page.next_token.filter(|t| !t.is_empty());
            if from.is_none() {
                break;
            }
        }
        info!(
            dry_run = self.policy.dry_run,
            users = report.users,
            devices = report.devices,
            list_failed = report.list_failed,
            spared_listed = report.spared_listed,
            spared_null_last_seen = report.spared_null_last_seen,
            spared_recent = report.spared_recent,
            spared_live_grant = report.spared_live_grant,
            check_failed = report.check_failed,
            candidates = report.candidates,
            deleted = report.deleted,
            failed = report.failed,
            "device reaper pass finished"
        );
        if let Some(path) = &self.policy.report_path {
            rows.push(serde_json::to_string(&serde_json::json!({
                "summary": report,
                "dry_run": self.policy.dry_run,
                "min_idle_secs": self.policy.min_idle.as_secs(),
            }))?);
            if let Err(e) = write_report(path, &rows).await {
                warn!(error = %e, "device reaper: report file not written");
            }
        }
        Ok(report)
    }

    /// One device, by the rules in their order (module docs); deletes a candidate unless
    /// this is a dry run.
    async fn decide(
        &self,
        localpart: &str,
        listed: bool,
        device_id: &str,
        last_seen_ts: Option<i64>,
        idle_ms: i64,
        report: &mut PassReport,
    ) -> Verdict {
        if listed {
            report.spared_listed += 1;
            return Verdict::SparedListed;
        }
        let Some(seen) = last_seen_ts else {
            report.spared_null_last_seen += 1;
            return Verdict::SparedNullLastSeen;
        };
        if chrono::Utc::now().timestamp_millis().saturating_sub(seen) <= idle_ms {
            report.spared_recent += 1;
            return Verdict::SparedRecent;
        }
        match self.grants.has_live_grant(localpart, device_id).await {
            Ok(true) => {
                report.spared_live_grant += 1;
                return Verdict::SparedLiveGrant;
            }
            Ok(false) => {}
            Err(e) => {
                report.check_failed += 1;
                warn!(error = %e, "device reaper: grant check failed; device spared");
                return Verdict::SparedCheckFailed;
            }
        }
        report.candidates += 1;
        if self.policy.dry_run {
            return Verdict::WouldDelete;
        }
        let (user, device) = (fingerprint(localpart), fingerprint(device_id));
        // The teardown order (8.23): Synapse delete, then the marker (flag 2). No revoke:
        // there is no grant.
        match self
            .synapse
            .delete_device_status(localpart, device_id, &self.server_name)
            .await
        {
            DeviceDelete::Deleted | DeviceDelete::NotFound => {
                match crate::compat::plant_deleted_marker(
                    &self.redis,
                    &self.synapse,
                    localpart,
                    device_id,
                )
                .await
                {
                    Ok(()) => {
                        report.deleted += 1;
                        info!(%user, %device, "device reaper: device deleted");
                        Verdict::Deleted
                    }
                    Err(e) => {
                        report.failed += 1;
                        warn!(error = %e, %user, %device, "device reaper: device deleted, deleted-id marker not written");
                        Verdict::DeleteFailed
                    }
                }
            }
            answer => {
                report.failed += 1;
                warn!(?answer, %user, %device, "device reaper: Synapse did not delete the device; continuing");
                Verdict::DeleteFailed
            }
        }
    }
}

/// Replace `path` with `rows`, one per line, mode 0600, through a temporary file.
async fn write_report(path: &str, rows: &[String]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = format!("{path}.tmp");
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .await
        .context("open")?;
    let mut body = rows.join("\n");
    body.push('\n');
    f.write_all(body.as_bytes()).await.context("write")?;
    f.sync_all().await.context("sync")?;
    tokio::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .await
        .context("chmod")?;
    tokio::fs::rename(&tmp, path).await.context("rename")?;
    Ok(())
}

#[cfg(test)]
mod tests;
