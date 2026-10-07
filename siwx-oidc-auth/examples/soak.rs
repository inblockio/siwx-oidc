//! Population soak: holds N throwaway sessions against a live deployment for a
//! while, typically across a switch of the siwx-oidc build, and reports what
//! they saw once a minute.
//!
//! ```text
//! SIWX_SERVER=https://siwx.example.org SIWX_HOMESERVER=https://matrix.example.org \
//!   cargo run -p siwx-oidc-auth --example soak -- --sessions 25 --duration 1800
//! ```
//!
//! Each session is a freshly generated Ed25519 key that signs in once (a new
//! account; every third one on an Element X shaped device id with `/` and
//! `+`). Each refreshes at `POST /token` when its access token is about to
//! expire and, once a minute, calls whoami and
//! `GET /_matrix/client/v3/sync?timeout=0` on the homeserver.
//!
//! One JSON line per minute goes to stdout: the counts of that minute
//! (refreshes that succeeded, refreshes refused by reason, 401s, device
//! changes, requests that found the service unavailable) and the number of
//! sessions whose refresh token is in the current format `mcr_{handle}_{secret}`.
//! A final line carries the totals and the verdict.
//!
//! The run fails (exit 1) on any refused refresh, any 401, any change of a
//! session's account or device, any session that found the service
//! unavailable for more than 120 s in a row, and any session still holding a
//! refresh token of the previous format 330 s after the first refresh into
//! the current format (the switch). A connection error, or a 502, 503 or 504
//! (the edge while the server is recreated, a store fault), is retried and
//! counted separately; it fails the run only past those 120 s.
//!
//! At the end, and on SIGINT or SIGTERM, every account is deactivated. Exit
//! codes: 0 pass, 1 a failure above, 2 the setup failed (no target, a sign-in
//! failed), 3 interrupted before the duration (not a pass). Tokens are never
//! printed.

#[path = "../tests/live/mod.rs"]
mod live;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use live::{
    deactivate, element_x_device_id, is_refresh_token, random_upper, register_public_client,
    target_from_env, token_refresh, whoami, Failure, Target, REDIRECT_URI,
};
use serde::Serialize;
use siwx_oidc_auth::{authenticate_with_device, SiwxKey};
use tokio::sync::watch;
use tokio::time::Instant;

const CLIENT_NAME: &str = "siwx-oidc-auth soak";
/// Refresh this long before the access token expires.
const REFRESH_LEAD: Duration = Duration::from_secs(15);
const PROBE_EVERY: Duration = Duration::from_secs(60);
const RETRY_AFTER: Duration = Duration::from_secs(5);
/// Unavailability for longer than this, in a row, is a failure.
const UNAVAILABLE_LIMIT: Duration = Duration::from_secs(120);
/// Every session is in the current format this long after the first one is.
const FORMAT_WINDOW: Duration = Duration::from_secs(330);
const ACCESS_TTL_DEFAULT: u64 = 300;

#[derive(Parser)]
#[command(about = "Hold N throwaway sessions against SIWX_SERVER / SIWX_HOMESERVER")]
struct Args {
    /// Number of sessions (each a new throwaway account).
    #[arg(long, default_value_t = 25)]
    sessions: usize,
    /// How long to hold them, in seconds.
    #[arg(long, default_value_t = 1800)]
    duration: u64,
}

#[derive(Clone, Default, Serialize)]
struct Counts {
    refresh_ok: u64,
    /// Refused refreshes by error code (or HTTP status when the body has none).
    refresh_failed: BTreeMap<String, u64>,
    unauthorized: u64,
    device_changes: u64,
    whoami_ok: u64,
    sync_ok: u64,
    /// Requests that found the service unavailable (retried).
    unavailable: u64,
}

#[derive(Default)]
struct Shared {
    minute: Counts,
    total: Counts,
    /// Per session: whether its refresh token is in the current format.
    current_format: Vec<bool>,
    failures: Vec<String>,
    /// The first refresh into the current format.
    switch_seen_at: Option<Instant>,
    legacy_after_switch_reported: bool,
    /// Sessions that stopped after a failure.
    stopped: usize,
}

impl Shared {
    fn count(&mut self, f: impl Fn(&mut Counts)) {
        f(&mut self.minute);
        f(&mut self.total);
    }
    fn fail(&mut self, why: String) {
        eprintln!("FAILED  {why}");
        self.failures.push(why);
    }
    /// A failure after which the session cannot go on.
    fn stop(&mut self, s: &mut Session, why: String) {
        self.fail(why);
        if !s.dead {
            s.dead = true;
            self.stopped += 1;
        }
    }
}

struct Session {
    index: usize,
    key: SiwxKey,
    device_id: String,
    mxid: String,
    access_token: String,
    refresh_token: String,
    access_deadline: Instant,
    since: Option<String>,
    unavailable_since: Option<Instant>,
    dead: bool,
}

type SharedRef = Arc<Mutex<Shared>>;

/// A request found the service unavailable: count it and fail past the limit.
fn unavailable(shared: &SharedRef, s: &mut Session, what: &str, why: &str) {
    let now = Instant::now();
    let since = *s.unavailable_since.get_or_insert(now);
    let mut sh = shared.lock().unwrap();
    sh.count(|c| c.unavailable += 1);
    if now - since > UNAVAILABLE_LIMIT {
        sh.stop(
            s,
            format!(
                "session {}: {what} unavailable for {} s ({why})",
                s.index,
                (now - since).as_secs()
            ),
        );
    }
}

async fn refresh_session(target: &Target, client_id: &str, s: &mut Session, shared: &SharedRef) {
    match token_refresh(target, client_id, &s.refresh_token).await {
        Ok(pair) => {
            s.unavailable_since = None;
            s.access_token = pair.access_token;
            s.refresh_token = pair.refresh_token;
            s.access_deadline =
                Instant::now() + Duration::from_secs(pair.expires_in.unwrap_or(ACCESS_TTL_DEFAULT));
            let current = is_refresh_token(&s.refresh_token);
            let mut sh = shared.lock().unwrap();
            sh.count(|c| c.refresh_ok += 1);
            sh.current_format[s.index] = current;
            if current && sh.switch_seen_at.is_none() {
                sh.switch_seen_at = Some(Instant::now());
            }
        }
        Err(Failure::Unavailable(why)) => {
            unavailable(shared, s, "refresh", &why);
            s.access_deadline = Instant::now() + REFRESH_LEAD + RETRY_AFTER;
        }
        Err(Failure::Refused { status, code }) => {
            let reason = if code.is_empty() {
                format!("HTTP {status}")
            } else {
                code
            };
            let mut sh = shared.lock().unwrap();
            sh.count(|c| *c.refresh_failed.entry(reason.clone()).or_default() += 1);
            sh.stop(
                s,
                format!("session {}: refresh refused ({reason})", s.index),
            );
        }
    }
}

async fn probe_session(target: &Target, s: &mut Session, shared: &SharedRef) {
    match whoami(target, &s.access_token).await {
        Ok(me) => {
            s.unavailable_since = None;
            let mut sh = shared.lock().unwrap();
            sh.count(|c| c.whoami_ok += 1);
            if me.user_id != s.mxid || me.device_id.as_deref() != Some(s.device_id.as_str()) {
                sh.count(|c| c.device_changes += 1);
                sh.fail(format!(
                    "session {}: whoami names another account or device",
                    s.index
                ));
            }
        }
        Err(Failure::Unavailable(why)) => unavailable(shared, s, "whoami", &why),
        Err(e) => {
            let mut sh = shared.lock().unwrap();
            if e.is_unauthorized() {
                sh.count(|c| c.unauthorized += 1);
            }
            sh.fail(format!("session {}: whoami answered {e}", s.index));
        }
    }
    let mut query = vec![("timeout", "0".to_string())];
    if let Some(since) = &s.since {
        query.push(("since", since.clone()));
    }
    let synced = live::classify(
        live::http()
            .get(format!("{}/_matrix/client/v3/sync", target.homeserver))
            .query(&query)
            .bearer_auth(&s.access_token)
            .send()
            .await,
    )
    .await;
    match synced {
        Ok(body) => {
            s.unavailable_since = None;
            s.since = body
                .get("next_batch")
                .and_then(|b| b.as_str())
                .map(str::to_string);
            shared.lock().unwrap().count(|c| c.sync_ok += 1);
        }
        Err(Failure::Unavailable(why)) => unavailable(shared, s, "sync", &why),
        Err(e) => {
            let mut sh = shared.lock().unwrap();
            if e.is_unauthorized() {
                sh.count(|c| c.unauthorized += 1);
            }
            sh.fail(format!("session {}: sync answered {e}", s.index));
        }
    }
}

/// One session's loop: refresh at expiry, probe once a minute, until `stop`.
async fn run_session(
    target: Target,
    client_id: String,
    mut s: Session,
    total: usize,
    shared: SharedRef,
    mut stop: watch::Receiver<bool>,
) -> Session {
    // Spread the probes of the sessions evenly over the minute, so that an
    // outage of a few seconds meets some of them.
    let mut next_probe = Instant::now() + PROBE_EVERY * s.index as u32 / total.max(1) as u32;
    loop {
        if *stop.borrow() {
            break;
        }
        let refresh_at = s
            .access_deadline
            .checked_sub(REFRESH_LEAD)
            .unwrap_or(s.access_deadline);
        let wake = if s.dead {
            Instant::now() + Duration::from_secs(3600)
        } else {
            let now = Instant::now();
            // A probe due while the access token has expired waits for the refresh.
            let probe_at = if next_probe <= now && now >= s.access_deadline {
                refresh_at
            } else {
                next_probe
            };
            refresh_at.min(probe_at)
        };
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {}
            _ = stop.changed() => break,
        }
        if s.dead {
            continue;
        }
        if Instant::now() >= refresh_at {
            refresh_session(&target, &client_id, &mut s, &shared).await;
        }
        // A probe waits for a refresh that is still being retried: an expired
        // access token would read as a 401 that the outage, not the server, caused.
        if !s.dead && Instant::now() >= next_probe && Instant::now() < s.access_deadline {
            probe_session(&target, &mut s, &shared).await;
            next_probe = (next_probe + PROBE_EVERY).max(Instant::now());
        }
    }
    s
}

async fn sign_in(target: &Target, client_id: &str, index: usize) -> anyhow::Result<Session> {
    let key = SiwxKey::generate_ed25519();
    let device_id = if index % 3 == 2 {
        element_x_device_id()
    } else {
        format!("AQUA_SOAK{}", random_upper(10))
    };
    let tokens = authenticate_with_device(
        &target.server,
        client_id,
        REDIRECT_URI,
        &key,
        Some(&device_id),
    )
    .await?;
    let refresh_token = tokens
        .refresh_token
        .ok_or_else(|| anyhow::anyhow!("the code exchange issued no refresh token"))?;
    let me = whoami(target, &tokens.access_token)
        .await
        .map_err(|e| anyhow::anyhow!("whoami answered {e}"))?;
    anyhow::ensure!(
        me.device_id.as_deref() == Some(device_id.as_str()),
        "whoami names another device"
    );
    Ok(Session {
        index,
        key,
        device_id,
        mxid: me.user_id,
        access_token: tokens.access_token,
        refresh_token,
        access_deadline: Instant::now()
            + Duration::from_secs(tokens.expires_in.unwrap_or(ACCESS_TTL_DEFAULT)),
        since: None,
        unavailable_since: None,
        dead: false,
    })
}

#[derive(Serialize)]
struct MinuteLine<'a> {
    minute: u64,
    elapsed_s: u64,
    sessions: usize,
    active: usize,
    current_format: usize,
    #[serde(flatten)]
    counts: &'a Counts,
    failures_so_far: usize,
}

/// Deactivate every account; returns how many failed.
async fn deactivate_all(target: &Target, keys: &[&SiwxKey]) -> usize {
    let mut failed = 0;
    for key in keys {
        if let Err(e) = deactivate(target, key).await {
            eprintln!("FAILED  deactivating {}: {e:#}", key.did());
            failed += 1;
        }
    }
    failed
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let target = match target_from_env() {
        Ok(t) => t,
        Err(why) => {
            eprintln!("soak: {why}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "soak: {} sessions for {} s against {} / {}",
        args.sessions, args.duration, target.server, target.homeserver
    );
    let client_id = match register_public_client(&target, CLIENT_NAME).await {
        Ok(reg) => reg.client_id,
        Err(e) => {
            eprintln!("soak: {e:#}");
            std::process::exit(2);
        }
    };
    let mut sessions = Vec::new();
    for index in 0..args.sessions {
        match sign_in(&target, &client_id, index).await {
            Ok(s) => sessions.push(s),
            Err(e) => {
                eprintln!("soak: session {index} could not sign in: {e:#}");
                let keys: Vec<&SiwxKey> = sessions.iter().map(|s| &s.key).collect();
                let failed = deactivate_all(&target, &keys).await;
                eprintln!(
                    "soak: deactivated {} of {} accounts",
                    keys.len() - failed,
                    keys.len()
                );
                std::process::exit(2);
            }
        }
    }
    let shared: SharedRef = Arc::new(Mutex::new(Shared {
        current_format: sessions
            .iter()
            .map(|s| is_refresh_token(&s.refresh_token))
            .collect(),
        ..Shared::default()
    }));
    eprintln!("soak: {} sessions signed in", sessions.len());

    let (stop_tx, stop_rx) = watch::channel(false);
    let total = sessions.len();
    let tasks: Vec<_> = sessions
        .into_iter()
        .map(|s| {
            tokio::spawn(run_session(
                target.clone(),
                client_id.clone(),
                s,
                total,
                shared.clone(),
                stop_rx.clone(),
            ))
        })
        .collect();

    let started = Instant::now();
    let end = started + Duration::from_secs(args.duration);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    let mut minute = 0u64;
    let interrupted = loop {
        let next = (started + Duration::from_secs(60 * (minute + 1))).min(end);
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            _ = tokio::signal::ctrl_c() => break true,
            _ = sigterm.recv() => break true,
        }
        minute += 1;
        let mut sh = shared.lock().unwrap();
        // Every session in the current format within the window after the first.
        if let Some(seen) = sh.switch_seen_at {
            let legacy = sh.current_format.iter().filter(|c| !**c).count();
            if legacy > 0 && seen.elapsed() > FORMAT_WINDOW && !sh.legacy_after_switch_reported {
                sh.legacy_after_switch_reported = true;
                sh.fail(format!(
                    "{legacy} session(s) still hold a previous-format refresh token {} s after \
                     the first refresh into the current format",
                    seen.elapsed().as_secs()
                ));
            }
        }
        let line = MinuteLine {
            minute,
            elapsed_s: started.elapsed().as_secs(),
            sessions: sh.current_format.len(),
            active: sh.current_format.len() - sh.stopped,
            current_format: sh.current_format.iter().filter(|c| **c).count(),
            counts: &sh.minute,
            failures_so_far: sh.failures.len(),
        };
        println!("{}", serde_json::to_string(&line).unwrap());
        sh.minute = Counts::default();
        drop(sh);
        if Instant::now() >= end {
            break false;
        }
    };

    stop_tx.send(true).ok();
    let mut finished = Vec::new();
    for task in tasks {
        match task.await {
            Ok(s) => finished.push(s),
            Err(e) => eprintln!("soak: a session task ended abnormally: {e}"),
        }
    }
    let active = finished.iter().filter(|s| !s.dead).count();
    let keys: Vec<&SiwxKey> = finished.iter().map(|s| &s.key).collect();
    let deactivation_failed = deactivate_all(&target, &keys).await;
    let sh = shared.lock().unwrap();
    let pass = sh.failures.is_empty() && deactivation_failed == 0 && !interrupted;
    println!(
        "{}",
        serde_json::json!({
            "final": true,
            "elapsed_s": started.elapsed().as_secs(),
            "sessions": sh.current_format.len(),
            "active_at_end": active,
            "current_format": sh.current_format.iter().filter(|c| **c).count(),
            "totals": sh.total,
            "failures": sh.failures,
            "deactivated": keys.len() - deactivation_failed,
            "deactivation_failed": deactivation_failed,
            "interrupted": interrupted,
            "pass": pass,
        })
    );
    let code = if !sh.failures.is_empty() || deactivation_failed > 0 {
        1
    } else if interrupted {
        3
    } else {
        0
    };
    std::process::exit(code);
}
