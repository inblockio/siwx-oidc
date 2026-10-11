//! The report-only orphan scan (S6, GP-SEC-50).
//!
//! A guest account in Synapse (`user_type = io.inblock.guest`) that has no guest record is
//! an orphan: the reaper can never find it, so only an operator can. This task pages the
//! Synapse admin user list every `guest_orphan_report_secs` and **reports**, one
//! `guest_orphan` event per orphan (the localpart only) and one `guest_orphan_scan`
//! summary. It never erases, deactivates or writes anything, in Synapse or in Redis.
//!
//! Several instances can share one Redis: a scan runs only for the instance that wins
//! `SET guest:orphan_scan:lease 1 NX EX <interval>`, so the fleet scans once per interval.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use tracing::{info, warn};

use siwx_oidc::db::RedisClient;

use super::handoff::GUEST_USER_TYPE;
use crate::synapse_client::SynapseClient;

pub const LEASE_KEY: &str = "guest:orphan_scan:lease";
/// A scan stops after this many pages (100 users each), so a misbehaving upstream cannot
/// keep it looping.
const MAX_PAGES: usize = 1000;

/// What one scan saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrphanReport {
    pub scanned: u64,
    pub guests: u64,
    pub orphans: u64,
}

#[derive(Clone)]
pub struct OrphanScan {
    pub redis: RedisClient,
    pub synapse: Arc<SynapseClient>,
    pub server_name: String,
    pub interval: Duration,
}

impl OrphanScan {
    /// Wake, and scan when this instance wins the lease, until `stop` is set.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let poll = self.interval.min(Duration::from_secs(300));
        let mut wait = poll.min(Duration::from_secs(60));
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = stop.wait_for(|s| *s) => break,
            }
            wait = poll;
            if let Err(e) = self.scan_if_leased().await {
                warn!(error = %e, "guest orphan scan failed");
            }
        }
    }

    /// One attempt: take the lease, then [`scan_once`](Self::scan_once). `None`: another
    /// instance holds the lease.
    pub async fn scan_if_leased(&self) -> Result<Option<OrphanReport>> {
        if !self
            .redis
            .try_lease(LEASE_KEY, self.interval.as_secs())
            .await?
        {
            return Ok(None);
        }
        self.scan_once().await.map(Some)
    }

    /// Page the typed users once (`not_user_type=`: accounts without a type are not asked
    /// for). The client-side filter on `io.inblock.guest` stays, since bots and support
    /// accounts carry a type too. Read-only.
    pub async fn scan_once(&self) -> Result<OrphanReport> {
        let suffix = format!(":{}", self.server_name);
        let mut report = OrphanReport::default();
        let mut from: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = self.synapse.admin_users_page(from.as_deref(), true).await?;
            for row in &page.users {
                report.scanned += 1;
                if row.user_type.as_deref() != Some(GUEST_USER_TYPE) {
                    continue;
                }
                report.guests += 1;
                let Some(localpart) = row
                    .name
                    .strip_prefix('@')
                    .and_then(|n| n.strip_suffix(suffix.as_str()))
                else {
                    continue;
                };
                if !self.redis.guest_record_present(localpart).await? {
                    report.orphans += 1;
                    info!(target: "guest_audit", event = "guest_orphan", localpart);
                }
            }
            from = page.next_token.filter(|t| !t.is_empty());
            if from.is_none() {
                break;
            }
        }
        info!(
            target: "guest_audit", event = "guest_orphan_scan",
            scanned = report.scanned, guests = report.guests, orphans = report.orphans,
            "guest orphan scan finished (report only)"
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// Every request the mock saw: `(method, path-and-query)`.
    type Seen = Arc<Mutex<Vec<(Method, String)>>>;

    async fn mock() -> (Seen, Arc<SynapseClient>, RedisClient) {
        let redis = siwx_oidc::test_support::redis_db(8).await.unwrap();
        redis.flush_db_for_test().await;
        let seen: Seen = Arc::default();
        let s = seen.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let s = s.clone();
            async move {
                let path = req.uri().path().to_string();
                let q = req.uri().query().unwrap_or("").to_string();
                s.lock().unwrap().push((req.method().clone(), format!("{path}?{q}")));
                if path == "/_synapse/admin/v2/users" {
                    let user = |lp: &str, t: Option<&str>| {
                        json!({"name": format!("@{lp}:example.org"), "user_type": t})
                    };
                    let body = if q.contains("from=100") {
                        json!({"users": [user("orphan2", Some("io.inblock.guest")), user("bob", None)]})
                    } else {
                        json!({"users": [
                            user("withrecord", Some("io.inblock.guest")),
                            user("orphan1", Some("io.inblock.guest")),
                            user("alice", None),
                            user("support", Some("support"))],
                            "next_token": "100"})
                    };
                    // Like Synapse: `not_user_type=` (empty) leaves out untyped accounts.
                    let mut body = body;
                    if q.split('&').any(|p| p == "not_user_type=") {
                        body["users"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|u| !u["user_type"].is_null());
                    }
                    return Json(body).into_response();
                }
                (StatusCode::OK, Json(json!({}))).into_response()
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let synapse = SynapseClient::new(&format!("http://{addr}"), "secret").with_admin_mint(
            redis.clone(),
            "siwx-admin".into(),
            300,
        );
        (seen, Arc::new(synapse), redis)
    }

    /// ST-34: a marked Synapse user without a record is reported (localpart only), one with
    /// a record and an unmarked one are not, paging over `next_token` works, and nothing is
    /// erased, deactivated or written, in Synapse or in Redis. The lease keeps a second
    /// scan inside the interval away.
    #[tokio::test]
    async fn st34_the_orphan_scan_reports_and_erases_nothing() {
        let (seen, synapse, redis) = mock().await;
        redis
            .put_guest_for_test("withrecord", "did:key:zX", "active", 600, "h")
            .await;
        let before = redis.hgetall_for_test("guest:acct/withrecord").await;
        let scan = OrphanScan {
            redis: redis.clone(),
            synapse,
            server_name: "example.org".into(),
            interval: Duration::from_secs(3600),
        };
        let cap = siwx_oidc::test_support::LogCapture::start();
        seen.lock().unwrap().clear();
        let report = scan.scan_if_leased().await.unwrap().unwrap();
        assert_eq!(
            report,
            OrphanReport {
                scanned: 4,
                guests: 3,
                orphans: 2
            }
        );
        let out = cap.output();
        assert_eq!(out.matches("event=\"guest_orphan\"").count(), 2, "{out}");
        assert!(out.contains("orphan1") && out.contains("orphan2"), "{out}");
        assert!(
            !out.contains("withrecord") && !out.contains("alice"),
            "{out}"
        );
        let calls: Vec<_> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p.starts_with("/_synapse/admin/"))
            .cloned()
            .collect();
        assert!(
            calls.iter().all(|(m, _)| *m == Method::GET),
            "read-only: {calls:?}"
        );
        assert!(calls.iter().any(|(_, p)| p.contains("from=100")), "paged");
        assert!(
            calls.iter().all(|(_, p)| p.contains("&not_user_type=")),
            "the scan asks for typed accounts only: {calls:?}"
        );
        assert_eq!(
            redis.hgetall_for_test("guest:acct/withrecord").await,
            before
        );
        // no guest key was added or dropped
        assert!(redis
            .hgetall_for_test("guest:acct/orphan1")
            .await
            .is_empty());
        assert!(scan.scan_if_leased().await.unwrap().is_none(), "leased");
        redis.flush_db_for_test().await;
    }
}
