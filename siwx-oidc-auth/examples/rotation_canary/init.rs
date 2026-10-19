//! `init`: make the environment's persistent identity.
//!
//! The key is written (0600, never over another file) before the first request
//! that could create an account with it, so an account never exists without its
//! key on disk. `--replace` first erases the old account with the old key
//! (`io.inblock.account_erase`; a deactivated account can be brought back by
//! whoever holds the key) and only then deletes the old files.

use std::path::Path;
use std::time::Duration;

use siwx_oidc_auth::SiwxKey;

use crate::cli::InitConfig;
use crate::flow::{self, Tokens, DISPLAY_NAME};
use crate::hygiene::Secret;
use crate::identity::{self, ClientRecord, LogoutRoute};
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
        if let Ok(old) = identity::read_client(&dir) {
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
                Ok(()) => emit(
                    "init_erase",
                    Verdict::Ok,
                    Reason::Ok,
                    &[("erased", "yes".to_string())],
                ),
                Err((reason, status)) => {
                    return fail("init_erase", reason, &[("status", status.to_string())], 1)
                }
            }
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
    let route = match flow::probe_logout_route(&http, &cfg.matrix.homeserver).await {
        Ok(route) => route,
        Err(reason) => return fail("init_client", reason, &[], 1),
    };
    emit(
        "init_client",
        Verdict::Ok,
        Reason::Ok,
        &[
            ("client", "registered".to_string()),
            ("logout_route", route.word().to_string()),
        ],
    );

    let tokens = match flow::sign_in(&http, issuer, &client_id, &key).await {
        Ok(tokens) => tokens,
        Err(reason) => return fail("init_sign_in", reason, &[], 1),
    };
    // From here on an account exists: whatever happens, the session is ended.
    let outcome = signed_in(&http, &cfg, &dir, &client_id, route, &tokens).await;
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
        emit("init_logout", Verdict::Ok, Reason::Ok, &logout_fields);
    } else {
        emit("init_logout", Verdict::Fail, logout.reason, &logout_fields);
    }
    match (outcome, logout.reason) {
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

/// Everything between the sign-in and the logout: whoami, the client record,
/// the display name. Returns the account's MXID.
async fn signed_in(
    http: &reqwest::Client,
    cfg: &InitConfig,
    dir: &Path,
    client_id: &str,
    route: LogoutRoute,
    tokens: &Tokens,
) -> Result<String, Reason> {
    let homeserver = cfg.matrix.homeserver.as_str();
    let reply = send(
        http.get(format!("{homeserver}/_matrix/client/v3/account/whoami"))
            .bearer_auth(tokens.access.expose()),
    )
    .await;
    let mxid = match reply {
        Ok(r) if r.status == 200 => r.str_field("user_id").map(str::to_string),
        _ => None,
    };
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
    let record = ClientRecord {
        version: 1,
        issuer: cfg.issuer.clone(),
        client_id: client_id.to_string(),
        logout_route: route,
        mxid: mxid.clone(),
    };
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
            Ok(mxid)
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
