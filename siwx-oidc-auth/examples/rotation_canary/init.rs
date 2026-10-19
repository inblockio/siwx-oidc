//! `init`: make the environment's persistent identity.
//!
//! The key is written (0600, never over another file) before the first request
//! that could create an account with it, so an account never exists without its
//! key on disk, and `client.json` follows before the sign-in, with the account
//! not yet known (an empty `mxid`), so a half-made identity is recognisable.
//! `--replace` first erases the old account with the old key
//! (`io.inblock.account_erase`; a deactivated account can be brought back by
//! whoever holds the key) and only then deletes the old files. An erase the
//! server refuses because the key has no account (the sign-in never got that
//! far) leaves nothing to erase and goes on.

use std::path::Path;
use std::time::Duration;

use siwx_oidc_auth::SiwxKey;

use crate::cli::InitConfig;
use crate::flow::{self, EraseOutcome, Tokens, DISPLAY_NAME};
use crate::hygiene::Secret;
use crate::identity::{self, Attempt, ClientRecord, LogoutRoute};
use crate::jose::issuers_match;
use crate::net::send;
use crate::report::{emit, Reason, Verdict};

const LOCK_WAIT: Duration = Duration::from_secs(120);

fn fail(check: &str, reason: Reason, fields: &[(&str, String)], code: i32) -> i32 {
    emit(check, Verdict::Fail, reason, fields);
    code
}

pub async fn run(cfg: InitConfig, root: &Path) -> i32 {
    let dir = match identity::ensure_dir(root, &cfg.env) {
        Ok(dir) => dir,
        Err(reason) => return fail("init_identity", reason, &[], 2),
    };
    let _lock = match identity::acquire_lock(&dir, LOCK_WAIT).await {
        Ok(lock) => lock,
        Err(reason) => return fail("lock", reason, &[], 1),
    };
    let http = match flow::http() {
        Ok(http) => http,
        Err(reason) => return fail("client", reason, &[], 1),
    };
    let issuer = cfg.issuer.as_str();

    if identity::key_exists(&dir) || identity::client_exists(&dir) {
        if !cfg.replace {
            return fail("init_identity", Reason::IdentityExists, &[], 2);
        }
        // The record names the issuer the key belongs to and the account it
        // made: refuse to guess when it cannot be read.
        let old = if identity::client_exists(&dir) {
            match identity::read_client(&dir) {
                Ok(old) => Some(old),
                Err(reason) => return fail("init_identity", reason, &[], 2),
            }
        } else {
            None
        };
        if let Some(old) = &old {
            if !issuers_match(&old.issuer, issuer) {
                return fail("init_identity", Reason::StoredIssuerDiffers, &[], 2);
            }
        }
        if identity::key_exists(&dir) {
            let old_key = match identity::load_key(&dir) {
                Ok(key) => key,
                Err(reason) => return fail("init_erase", reason, &[], 2),
            };
            match flow::erase_account(&http, issuer, &old_key).await {
                Ok(outcome) => emit(
                    "init_erase",
                    Verdict::Ok,
                    Reason::Ok,
                    &[(
                        "erased",
                        if outcome == EraseOutcome::Erased {
                            "yes"
                        } else {
                            "no_account"
                        }
                        .to_string(),
                    )],
                ),
                Err((reason, status)) => {
                    return fail("init_erase", reason, &[("status", status.to_string())], 1)
                }
            }
        } else if let Some(old) = old.filter(|o| !o.mxid.is_empty()) {
            // The record names an account, and the key that could erase it is
            // gone: replacing now would strand the account.
            return fail("init_erase", Reason::KeyMissing, &[("mxid", old.mxid)], 2);
        }
        if let Err(reason) = identity::remove_identity(&dir) {
            return fail("init_identity", reason, &[], 1);
        }
    }

    let key = SiwxKey::generate_ed25519();
    let pem = match key.to_pem() {
        Ok(pem) => Secret::new(pem),
        Err(_) => return fail("init_key", Reason::Internal, &[], 1),
    };
    if let Err(reason) = identity::write_new_key(&dir, &pem) {
        return fail(
            "init_key",
            reason,
            &[],
            if reason == Reason::IdentityExists {
                2
            } else {
                1
            },
        );
    }
    emit(
        "init_key",
        Verdict::Ok,
        Reason::Ok,
        &[
            ("dir_mode", "700".to_string()),
            ("key_mode", "600".to_string()),
        ],
    );

    let client_id = match flow::register_client(&http, issuer).await {
        Ok(id) => id,
        Err(reason) => return fail("init_client", reason, &[], 1),
    };
    // Nothing is recorded on an answer that does not say how `/logout` is routed.
    let route = match flow::probe_logout_route(&http, &cfg.matrix.homeserver).await {
        Ok(route) => route,
        Err((reason, status)) => {
            let fields = if status == 0 {
                vec![]
            } else {
                vec![("status", status.to_string())]
            };
            return fail("init_client", reason, &fields, 1);
        }
    };
    let record = ClientRecord {
        version: 1,
        issuer: cfg.issuer.clone(),
        client_id: client_id.clone(),
        logout_route: route,
        mxid: String::new(),
    };
    if let Err(reason) = identity::write_client(&dir, &record) {
        return fail("init_client", reason, &[], 1);
    }
    emit(
        "init_client",
        Verdict::Ok,
        Reason::Ok,
        &[
            ("client", "registered".to_string()),
            ("logout_route", route.word().to_string()),
        ],
    );

    // The server creates the device at `/sign_in`, before the code exchange: a
    // sign-in that fails from here on may leave one this run never saw.
    let attempt = Attempt {
        id: format!("{:016x}", rand::random::<u64>()),
        at: chrono::Utc::now().timestamp(),
    };
    let attempt_id = attempt.id.clone();
    if let Err(reason) = identity::update_ledger(&dir, |ledger| ledger.attempts.push(attempt)) {
        return fail("init_sign_in", reason, &[], 1);
    }
    let tokens = match flow::sign_in(&http, issuer, &client_id, &key).await {
        Ok(tokens) => tokens,
        Err(reason) => return fail("init_sign_in", reason, &[], 1),
    };
    // From here on an account exists: whatever happens, the session is ended.
    let outcome = signed_in(&http, &cfg, &dir, record, &attempt_id, &tokens).await;
    let logout = flow::logout_and_prove(
        &http,
        issuer,
        Some(&cfg.matrix.homeserver),
        route,
        &client_id,
        &tokens,
    )
    .await;
    let logout_fields = [
        ("route", logout.route.word().to_string()),
        (
            "logout_status",
            logout
                .logout_status
                .map(|s| s.to_string())
                .unwrap_or_default(),
        ),
        ("refresh", logout.refresh.to_string()),
    ];
    if logout.reason == Reason::Ok {
        // A proven logout through `/logout` deleted the device: off the ledger.
        if route == LogoutRoute::Matrix {
            if let Ok((_, Some(device))) = &outcome {
                let _ = identity::update_ledger(&dir, |ledger| {
                    ledger.pending.remove(device);
                });
            }
        }
        emit("init_logout", Verdict::Ok, Reason::Ok, &logout_fields);
    } else {
        emit("init_logout", Verdict::Fail, logout.reason, &logout_fields);
    }
    match (outcome.map(|(mxid, _)| mxid), logout.reason) {
        (Ok(mxid), Reason::Ok) => {
            emit(
                "init",
                Verdict::Ok,
                Reason::Ok,
                &[("env", cfg.env.clone()), ("mxid", mxid)],
            );
            0
        }
        (_, reason) if reason != Reason::Ok => fail("init", reason, &[], 3),
        (Err(reason), _) => fail("init", reason, &[], 1),
        (Ok(_), _) => 1,
    }
}

/// Everything between the sign-in and the logout: whoami, the client record
/// (now with the account), the device on the ledger, the display name. Returns
/// the account's MXID and the device the sign-in made.
async fn signed_in(
    http: &reqwest::Client,
    cfg: &InitConfig,
    dir: &Path,
    mut record: ClientRecord,
    attempt_id: &str,
    tokens: &Tokens,
) -> Result<(String, Option<String>), Reason> {
    let homeserver = cfg.matrix.homeserver.as_str();
    let reply = send(
        http.get(format!("{homeserver}/_matrix/client/v3/account/whoami"))
            .bearer_auth(tokens.access.expose()),
    )
    .await;
    let (mxid, device) = match reply {
        Ok(r) if r.status == 200 => (
            r.str_field("user_id").map(str::to_string),
            r.str_field("device_id").map(str::to_string),
        ),
        _ => (None, None),
    };
    // The device is the canary's from now on, and the attempt that made it is
    // finished: a run that dies before its logout leaves a device the next run
    // knows.
    if let Some(device) = &device {
        let id = attempt_id.to_string();
        let _ = identity::update_ledger(dir, |ledger| {
            ledger.pending.insert(device.clone());
            ledger.attempts.retain(|a| a.id != id);
        });
    }
    let on_server =
        |m: &str| m.starts_with('@') && m.ends_with(&format!(":{}", cfg.matrix.server_name));
    let mxid = match mxid {
        Some(m) if on_server(&m) => m,
        Some(m) => {
            emit(
                "init_sign_in",
                Verdict::Fail,
                Reason::ServerNameMismatch,
                &[("mxid", m)],
            );
            return Err(Reason::ServerNameMismatch);
        }
        None => {
            emit("init_sign_in", Verdict::Fail, Reason::WhoamiStatus, &[]);
            return Err(Reason::WhoamiStatus);
        }
    };
    record.mxid = mxid.clone();
    if let Err(reason) = identity::write_client(dir, &record) {
        emit("init_sign_in", Verdict::Fail, reason, &[("mxid", mxid)]);
        return Err(reason);
    }
    emit(
        "init_sign_in",
        Verdict::Ok,
        Reason::Ok,
        &[("mxid", mxid.clone())],
    );

    let named = send(
        http.put(format!(
            "{homeserver}/_matrix/client/v3/profile/{}/displayname",
            urlencoding::encode(&mxid)
        ))
        .bearer_auth(tokens.access.expose())
        .json(&serde_json::json!({ "displayname": DISPLAY_NAME })),
    )
    .await;
    match named {
        Ok(r) if (200..300).contains(&r.status) => {
            emit(
                "init_display_name",
                Verdict::Ok,
                Reason::Ok,
                &[("display_name", DISPLAY_NAME.to_string())],
            );
            Ok((mxid, device))
        }
        other => {
            let status = other.map(|r| r.status.to_string()).unwrap_or_default();
            emit(
                "init_display_name",
                Verdict::Fail,
                Reason::DisplayNameFailed,
                &[("status", status)],
            );
            Err(Reason::DisplayNameFailed)
        }
    }
}
