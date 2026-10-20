//! The planted-case table of the device reaper (SS4 WP8, model 8.14, SD-07, SD-08,
//! PH-47, AG-09): a mock Synapse in process, the grants in a real Redis.

use super::*;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use bb8_redis::redis::aio::{ConnectionLike, MultiplexedConnection};
use bb8_redis::redis::{Arg, Cmd, Pipeline, RedisFuture, Value};
use serde_json::{json, Value as Json_};
use siwx_oidc::db::grant::{GrantKind, NewGrant};
use siwx_oidc::db::{device_has_live_grant_on, DBClient};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::net::TcpListener;

const SERVER: &str = "example.org";
const DAY_MS: i64 = 86_400_000;

#[derive(Default)]
struct MockState {
    /// `(mxid, user_type)` in listing order.
    users: Vec<(String, Option<String>)>,
    devices: HashMap<String, Vec<Json_>>,
    /// Device ids whose delete answers 500.
    fail_delete: HashSet<String>,
    /// Every request: `(method path, body)`.
    calls: Vec<(String, String)>,
}

type Mock = Arc<Mutex<MockState>>;

impl MockState {
    fn count(&self, what: &str) -> usize {
        self.calls.iter().filter(|(c, _)| c.contains(what)).count()
    }
    fn listed(&self, lp: &str, device: &str) -> bool {
        self.devices
            .get(&mxid(lp))
            .is_some_and(|ds| ds.iter().any(|d| d["device_id"] == device))
    }
}

fn mxid(lp: &str) -> String {
    format!("@{lp}:{SERVER}")
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// A device last seen `days` ago (`None`: never seen, NULL).
fn device(id: &str, days: Option<i64>) -> Json_ {
    json!({"device_id": id, "display_name": null, "last_seen_ip": null,
           "last_seen_ts": days.map(|d| now_ms() - d * DAY_MS)})
}

/// The users listing pages two users at a time, so every test pages.
async fn mock_synapse(m: Mock) -> String {
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let m = m.clone();
        async move {
            let method = req.method().clone();
            let path = req.uri().path().to_string();
            let q = req.uri().query().unwrap_or("").to_string();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            let body: Json_ = serde_json::from_slice(&body).unwrap_or(Json_::Null);
            let mut s = m.lock().unwrap();
            s.calls.push((format!("{method} {path}"), body.to_string()));
            if path == "/_synapse/admin/v2/users" {
                let from: usize = q
                    .split('&')
                    .find_map(|p| p.strip_prefix("from="))
                    .and_then(|f| f.parse().ok())
                    .unwrap_or(0);
                let page: Vec<Json_> = s
                    .users
                    .iter()
                    .skip(from)
                    .take(2)
                    .map(|(n, t)| json!({"name": n, "user_type": t}))
                    .collect();
                let mut out = json!({ "users": page });
                if from + 2 < s.users.len() {
                    out["next_token"] = json!((from + 2).to_string());
                }
                return Json(out).into_response();
            }
            if let Some(user) = path
                .strip_prefix("/_synapse/admin/v2/users/")
                .and_then(|p| p.strip_suffix("/devices"))
            {
                let user = urlencoding::decode(user).unwrap().into_owned();
                let devs = s.devices.get(&user).cloned().unwrap_or_default();
                return Json(json!({ "devices": devs })).into_response();
            }
            if path == "/_synapse/mas/delete_device" {
                let lp = body["localpart"].as_str().unwrap_or("").to_string();
                let dev = body["device_id"].as_str().unwrap_or("").to_string();
                if s.fail_delete.contains(&dev) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "{}").into_response();
                }
                if let Some(ds) = s.devices.get_mut(&mxid(&lp)) {
                    ds.retain(|d| d["device_id"] != dev.as_str());
                }
                return StatusCode::NO_CONTENT.into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

/// The reaper tests' own database; no test flushes it (every test uses accounts of
/// its own), so they may run in parallel.
async fn db() -> Option<RedisClient> {
    siwx_oidc::test_support::redis_db(12).await
}

struct Fixture {
    mock: Mock,
    synapse: Arc<SynapseClient>,
    redis: RedisClient,
}

impl Fixture {
    /// `markers`: SS4 flag 2 on (a 600 s marker TTL) or off.
    async fn new(markers: bool) -> Option<Self> {
        let redis = db().await?;
        let mock: Mock = Arc::default();
        let url = mock_synapse(mock.clone()).await;
        let synapse = SynapseClient::new(&url, "shared-secret")
            .with_admin_mint(redis.clone(), "siwx-admin".into(), 300)
            .with_deleted_markers(markers.then_some(600));
        Some(Self {
            mock,
            synapse: Arc::new(synapse),
            redis,
        })
    }

    /// A fresh account with `devices`, `user_type` none.
    fn account(&self, devices: Vec<Json_>) -> String {
        let lp = format!("rp{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let mut s = self.mock.lock().unwrap();
        s.users.push((mxid(&lp), None));
        s.devices.insert(mxid(&lp), devices);
        lp
    }

    async fn grant(&self, lp: &str, device: &str) {
        self.redis
            .issue_grant(&NewGrant {
                kind: GrantKind::MatrixDevice,
                username: lp.into(),
                did: format!("did:key:z6Mk{lp}"),
                client_id: "reaper-test".into(),
                confidential_client: false,
                device_id: device.into(),
                scope: "openid".into(),
                name: "t".into(),
                auth_ms: None,
                access_ttl: 300,
                refresh_inactivity_secs: Some(3600),
                absolute_deadline: None,
            })
            .await
            .unwrap();
    }

    fn reaper(&self, c: &Config) -> DeviceReaper {
        DeviceReaper {
            redis: self.redis.clone(),
            grants: Arc::new(self.redis.clone()),
            synapse: self.synapse.clone(),
            server_name: SERVER.into(),
            policy: ReaperPolicy::from_config(c),
        }
    }

    fn deletes(&self) -> usize {
        self.mock.lock().unwrap().count("delete_device")
    }

    fn listed(&self, lp: &str, device: &str) -> bool {
        self.mock.lock().unwrap().listed(lp, device)
    }
}

/// Flag 3 on, a real pass (not a dry run), the default threshold (97 d).
fn live() -> Config {
    Config {
        device_reaper_enabled: true,
        device_reaper_dry_run: false,
        ..Config::default()
    }
}

/// SD-08, PH-47: a device with a live grant is spared however old its `last_seen` is
/// (refreshes reach siwx-oidc, never Synapse).
#[tokio::test]
async fn reaper_spares_live_grant_with_old_last_seen() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![device("DEVICE_A", Some(400))]);
    f.grant(&lp, "DEVICE_A").await;
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!(r.spared_live_grant, 1);
    assert_eq!((r.candidates, r.deleted), (0, 0));
    assert_eq!(f.deletes(), 0);
    assert!(f.listed(&lp, "DEVICE_A"));
}

/// SD-07, SD-04, SD-15: no grant and last seen 98 days ago: deleted.
#[tokio::test]
async fn reaper_deletes_no_grant_old_last_seen() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![device("DEVICE_A", Some(98))]);
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!((r.candidates, r.deleted, r.failed), (1, 1, 0));
    assert!(!f.listed(&lp, "DEVICE_A"));
    let s = f.mock.lock().unwrap();
    assert!(s
        .calls
        .iter()
        .any(|(c, b)| c.ends_with("delete_device") && b.contains(&lp) && b.contains("DEVICE_A")));
}

/// No grant, but seen 96 days ago (inside 90 d + 7 d): spared.
#[tokio::test]
async fn reaper_spares_no_grant_recent_last_seen() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![
        device("DEVICE_A", Some(96)),
        device("DEVICE_B", Some(0)),
    ]);
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!(r.spared_recent, 2);
    assert_eq!(f.deletes(), 0);
    assert!(f.listed(&lp, "DEVICE_A") && f.listed(&lp, "DEVICE_B"));
}

/// A device Synapse has never seen (`last_seen_ts` NULL, as just after its creation,
/// before the first request) is spared, grant or not.
#[tokio::test]
async fn reaper_spares_null_last_seen_just_after_creation() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![device("DEVICE_A", None)]);
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!(r.spared_null_last_seen, 1);
    assert_eq!(f.deletes(), 0);
    assert!(f.listed(&lp, "DEVICE_A"));
}

/// A member of the legacy device index (`idx:user_device/…`, raw token keys) counts as a
/// live grant, even when the token it names is long gone: a stale entry can only spare.
#[tokio::test]
async fn reaper_legacy_index_entry_counts_as_live() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![device("DEVICE_A", Some(400))]);
    f.redis
        .sadd_raw_for_test(&format!("idx:user_device/{lp}/DEVICE_A"), "token/stale")
        .await;
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!(r.spared_live_grant, 1);
    assert_eq!(f.deletes(), 0);
    assert!(f.listed(&lp, "DEVICE_A"));
}

/// AG-09: an account on `SIWXOIDC_DEVICE_REAPER_SPARE_USERS` (by localpart or Matrix id,
/// any case) keeps every device; an unlisted account in the same pass does not.
#[tokio::test]
async fn reaper_spares_agent_account_on_spare_list() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let agent = f.account(vec![device("DEVICE_A", Some(400))]);
    let bot = f.account(vec![device("DEVICE_A", Some(400))]);
    let other = f.account(vec![device("DEVICE_A", Some(400))]);
    let c = Config {
        device_reaper_spare_users: vec![agent.to_uppercase(), mxid(&bot)],
        ..live()
    };
    let r = f.reaper(&c).pass_once().await.unwrap();
    assert_eq!(r.spared_listed, 2);
    assert_eq!(r.deleted, 1);
    assert!(f.listed(&agent, "DEVICE_A") && f.listed(&bot, "DEVICE_A"));
    assert!(!f.listed(&other, "DEVICE_A"));
}

/// A connection that records the name of every command sent through it.
struct Recorder {
    inner: MultiplexedConnection,
    seen: Arc<Mutex<Vec<String>>>,
}

impl ConnectionLike for Recorder {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        let name = match cmd.args_iter().next() {
            Some(Arg::Simple(b)) => String::from_utf8_lossy(b).to_uppercase(),
            _ => "?".into(),
        };
        self.seen.lock().unwrap().push(name);
        self.inner.req_packed_command(cmd)
    }
    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        self.seen.lock().unwrap().push("PIPELINE".into());
        self.inner.req_packed_commands(cmd, offset, count)
    }
    fn get_db(&self) -> i64 {
        self.inner.get_db()
    }
}

struct Recording(tokio::sync::Mutex<Recorder>);

#[async_trait]
impl LiveGrants for Recording {
    async fn has_live_grant(&self, username: &str, device_id: &str) -> Result<bool> {
        let mut conn = self.0.lock().await;
        device_has_live_grant_on(&mut *conn, username, device_id).await
    }
}

/// 8.29: the grant check sends `EXISTS` (or `SCARD`) and nothing else: never
/// `SMEMBERS`, `SCAN` or `KEYS`, whose answers would carry raw token keys. Recorded on
/// the wire over the whole planted table, verdicts unchanged.
#[tokio::test]
async fn reaper_uses_only_exists_and_scard() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![
        device("DEVICE_A", Some(400)),
        device("DEVICE_B", Some(400)),
        device("DEVICE_C", Some(400)),
        device("DEVICE_D", Some(1)),
        device("DEVICE_E", None),
    ]);
    f.grant(&lp, "DEVICE_A").await;
    f.redis
        .sadd_raw_for_test(&format!("idx:user_device/{lp}/DEVICE_B"), "token/stale")
        .await;
    let url = siwx_oidc::test_support::redis_db_url(12);
    let inner = siwx_oidc::test_support::raw_connection(&url).await.unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut reaper = f.reaper(&live());
    reaper.grants = Arc::new(Recording(tokio::sync::Mutex::new(Recorder {
        inner,
        seen: seen.clone(),
    })));
    let r = reaper.pass_once().await.unwrap();
    assert_eq!(
        (
            r.spared_live_grant,
            r.deleted,
            r.spared_recent,
            r.spared_null_last_seen
        ),
        (2, 1, 1, 1)
    );
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "one check per old device: {seen:?}");
    for c in &seen {
        assert!(c == "EXISTS" || c == "SCARD", "{c} sent: {seen:?}");
    }
    for banned in ["SMEMBERS", "SSCAN", "SCAN", "KEYS"] {
        assert!(!seen.iter().any(|c| c == banned), "{banned}");
    }
}

/// The dry run (the default with flag 3 on) deletes nothing, logs counts only (no
/// localpart, no Matrix id, no device id), and writes the full list, Matrix ids and
/// verdicts with the account's type, to the report file, mode 0600.
#[tokio::test]
async fn reaper_dry_run_deletes_nothing_and_writes_report() {
    let Some(f) = Fixture::new(true).await else {
        return;
    };
    let lp = f.account(vec![
        device("DEVICE_GHOST", Some(400)),
        device("DEVICE_LIVE", Some(400)),
        device("DEVICE_NEW", None),
    ]);
    f.mock.lock().unwrap().users.last_mut().unwrap().1 = Some("bot".into());
    f.grant(&lp, "DEVICE_LIVE").await;
    let path = std::env::temp_dir().join(format!("ss4-reaper-{lp}.jsonl"));
    let c = Config {
        device_reaper_enabled: true,
        device_reaper_report_path: Some(path.to_string_lossy().into_owned()),
        ..Config::default()
    };
    assert!(ReaperPolicy::from_config(&c).dry_run, "dry run by default");
    let logs = siwx_oidc::test_support::LogCapture::start();
    let r = f.reaper(&c).pass_once().await.unwrap();
    let out = logs.output();
    assert_eq!((r.candidates, r.deleted, r.spared_live_grant), (1, 0, 1));
    assert_eq!(f.deletes(), 0, "a dry run deletes nothing");
    assert!(f.listed(&lp, "DEVICE_GHOST"));
    assert!(!f
        .redis
        .is_deleted_device(&lp, "DEVICE_GHOST")
        .await
        .unwrap());
    assert!(out.contains("candidates=1"), "{out}");
    for clear in [lp.as_str(), "DEVICE_GHOST", "DEVICE_LIVE", "DEVICE_NEW"] {
        assert!(!out.contains(clear), "{clear} in the log: {out}");
    }

    let report = std::fs::read_to_string(&path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    std::fs::remove_file(&path).unwrap();
    assert_eq!(mode, 0o600);
    let rows: Vec<Json_> = report
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let verdict = |d: &str| {
        rows.iter()
            .find(|r| r["device_id"] == d)
            .map(|r| r["verdict"].clone())
    };
    assert_eq!(verdict("DEVICE_GHOST"), Some(json!("would_delete")));
    assert_eq!(verdict("DEVICE_LIVE"), Some(json!("spared_live_grant")));
    assert_eq!(verdict("DEVICE_NEW"), Some(json!("spared_null_last_seen")));
    assert!(rows
        .iter()
        .filter(|r| r.get("device_id").is_some())
        .all(|r| r["user"] == mxid(&lp) && r["user_type"] == "bot"));
    let summary = rows.last().unwrap();
    assert_eq!(summary["summary"]["candidates"], 1);
    assert_eq!(summary["dry_run"], true);
}

/// SD-07 with flag 2 on: the reaper's delete plants the deleted-id marker like every
/// other delete path (8.12); with flag 2 off it plants none.
#[tokio::test]
async fn reaper_plants_marker_flag2_on() {
    let Some(on) = Fixture::new(true).await else {
        return;
    };
    let lp = on.account(vec![device("DEVICE_A", Some(400))]);
    assert_eq!(on.reaper(&live()).pass_once().await.unwrap().deleted, 1);
    assert!(on.redis.is_deleted_device(&lp, "DEVICE_A").await.unwrap());

    let Some(off) = Fixture::new(false).await else {
        return;
    };
    let lp = off.account(vec![device("DEVICE_A", Some(400))]);
    assert_eq!(off.reaper(&live()).pass_once().await.unwrap().deleted, 1);
    assert!(!off.redis.is_deleted_device(&lp, "DEVICE_A").await.unwrap());
}

/// [B2]: flag 3 is off by default, and off no task starts and Synapse is never asked.
/// On (and Synapse configured), the task starts.
#[tokio::test]
async fn reaper_disabled_by_default_is_inert() {
    let Some(f) = Fixture::new(true).await else {
        return;
    };
    f.account(vec![device("DEVICE_A", Some(400))]);
    let (stop, rx) = watch::channel(false);
    let off = Config {
        device_reaper_interval_secs: 1,
        matrix_server_name: Some(SERVER.into()),
        ..Config::default()
    };
    assert!(!off.device_reaper_enabled);
    assert!(spawn(&off, f.redis.clone(), Some(f.synapse.clone()), rx.clone()).is_none());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        f.mock.lock().unwrap().calls.is_empty(),
        "flag 3 off: no call"
    );

    let on = Config {
        device_reaper_enabled: true,
        ..off.clone()
    };
    assert!(
        spawn(&on, f.redis.clone(), None, rx.clone()).is_none(),
        "no Synapse"
    );
    let task = spawn(&on, f.redis.clone(), Some(f.synapse.clone()), rx).expect("started");
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("stops")
        .unwrap();
}

/// A delete Synapse fails (5xx) is counted, leaves the device listed with no marker, and
/// the pass goes on to the next device.
#[tokio::test]
async fn reaper_synapse_delete_failure_counts_and_continues() {
    let Some(f) = Fixture::new(true).await else {
        return;
    };
    let lp = f.account(vec![
        device("DEVICE_FAIL", Some(400)),
        device("DEVICE_A", Some(400)),
    ]);
    let next = f.account(vec![device("DEVICE_B", Some(400))]);
    f.mock
        .lock()
        .unwrap()
        .fail_delete
        .insert("DEVICE_FAIL".into());
    let r = f.reaper(&live()).pass_once().await.unwrap();
    assert_eq!((r.candidates, r.deleted, r.failed), (3, 2, 1));
    assert!(f.listed(&lp, "DEVICE_FAIL"));
    assert!(!f.redis.is_deleted_device(&lp, "DEVICE_FAIL").await.unwrap());
    assert!(!f.listed(&lp, "DEVICE_A") && !f.listed(&next, "DEVICE_B"));
    assert!(f.redis.is_deleted_device(&next, "DEVICE_B").await.unwrap());
}

/// `SIWXOIDC_DEVICE_REAPER_MIN_IDLE_SECS` replaces the threshold only when set: a
/// grantless device seen 10 days ago is spared by default and deleted with a 1-day
/// override; a live grant, a NULL `last_seen` and a spared account still keep theirs.
#[tokio::test]
async fn reaper_min_idle_override_lowers_threshold_only_when_set() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let lp = f.account(vec![
        device("DEVICE_GHOST", Some(10)),
        device("DEVICE_LIVE", Some(10)),
        device("DEVICE_NEW", None),
        device("DEVICE_TODAY", Some(0)),
    ]);
    f.grant(&lp, "DEVICE_LIVE").await;
    let agent = f.account(vec![device("DEVICE_A", Some(10))]);

    let base = Config {
        device_reaper_spare_users: vec![agent.clone()],
        ..live()
    };
    let r = f.reaper(&base).pass_once().await.unwrap();
    assert_eq!((r.candidates, r.spared_recent), (0, 3));
    assert_eq!(f.deletes(), 0, "default threshold: 97 days");

    let lowered = Config {
        device_reaper_min_idle_secs: Some(86_400),
        ..base
    };
    let r = f.reaper(&lowered).pass_once().await.unwrap();
    assert_eq!(r.deleted, 1);
    assert_eq!(
        (
            r.spared_live_grant,
            r.spared_null_last_seen,
            r.spared_listed,
            r.spared_recent
        ),
        (1, 1, 1, 1)
    );
    assert!(!f.listed(&lp, "DEVICE_GHOST"));
    for d in ["DEVICE_LIVE", "DEVICE_NEW", "DEVICE_TODAY"] {
        assert!(f.listed(&lp, d), "{d}");
    }
    assert!(f.listed(&agent, "DEVICE_A"));
}
