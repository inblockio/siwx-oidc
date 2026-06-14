//! MSC4191 account management page and MSC4312 cross-signing reset flow.
//!
//! Provides:
//! - `GET /account` — renders the account management page
//! - `POST /account/wallet` — wallet (CAIP-122) re-auth + action execution
//! - `POST /account/passkey/start` — start passkey authentication
//! - `POST /account/passkey/finish` — finish passkey auth + action execution

use axum::response::Html;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::oidc::{did_to_localpart, CustomError};
use crate::synapse_client::{DeviceInfo, SynapseClient};
use crate::webauthn as wa;
use siwx_oidc::db::RedisClient;

// -- Authenticated account-management session ---------------------------------
//
// The account page is a sequence of sensitive actions (list sessions, sign one
// out, view the profile, erase). Requiring a fresh wallet/passkey signature for
// EACH action is the "multiple authentications" defect. Instead, the first
// successful re-auth mints a short-lived session bound to the verified DID; the
// page then executes subsequent actions against `POST /account/action` carrying
// only the session cookie (no new signature) until it expires.
//
// Security: the cookie is HttpOnly + SameSite=Strict + Path=/account and lives
// for [`ACCOUNT_SESSION_TTL`] only. Every action POST must also echo the
// session's CSRF token (defence in depth on top of SameSite=Strict). The session
// is bound to one verified DID and never grants cross-user access.

/// Cookie name for the authenticated account-management session.
pub const ACCOUNT_SESSION_COOKIE: &str = "acct_session";
/// Redis key prefix for stored account sessions.
const ACCOUNT_SESSION_PREFIX: &str = "account_session";
/// How long one re-auth keeps the account page authenticated (seconds).
pub const ACCOUNT_SESSION_TTL: u64 = 600; // 10 minutes

/// A short-lived authenticated account-management session.
#[derive(Serialize, Deserialize)]
pub struct AccountSession {
    /// The verified DID this session acts as.
    pub did: String,
    /// CSRF token that every `/account/action` POST must echo.
    pub csrf: String,
    /// Absolute Unix-seconds expiry (defence in depth on top of the Redis TTL).
    pub exp: i64,
}

/// Mint a fresh account session bound to `did`, store it in Redis (TTL
/// [`ACCOUNT_SESSION_TTL`]), and return `(session_token, csrf_token)`.
pub async fn create_account_session(
    db: &RedisClient,
    did: &str,
) -> Result<(String, String), CustomError> {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let csrf = Uuid::new_v4().simple().to_string();
    let session = AccountSession {
        did: did.to_string(),
        csrf: csrf.clone(),
        exp: Utc::now().timestamp() + ACCOUNT_SESSION_TTL as i64,
    };
    let json = serde_json::to_string(&session)
        .map_err(|e| anyhow::anyhow!("serialize account session: {e}"))?;
    db.set_ex_raw(
        &format!("{}/{}", ACCOUNT_SESSION_PREFIX, token),
        &json,
        ACCOUNT_SESSION_TTL,
    )
    .await?;
    Ok((token, csrf))
}

/// Look up a live account session by token, or `None` if it is missing, expired,
/// or unreadable (fail-safe: any failure forces a fresh re-auth).
pub async fn lookup_account_session(db: &RedisClient, token: &str) -> Option<AccountSession> {
    let raw = db
        .get_raw(&format!("{}/{}", ACCOUNT_SESSION_PREFIX, token))
        .await
        .ok()??;
    let session: AccountSession = serde_json::from_str(&raw).ok()?;
    if session.exp < Utc::now().timestamp() {
        return None;
    }
    Some(session)
}

/// Delete an account session (used after a terminal action like erase/deactivate
/// invalidates the identity it was bound to). Best-effort.
pub async fn destroy_account_session(db: &RedisClient, token: &str) {
    let _ = db
        .del_raw(&format!("{}/{}", ACCOUNT_SESSION_PREFIX, token))
        .await;
}

// -- Request/response types ---------------------------------------------------

#[derive(Deserialize)]
pub struct AccountPageQuery {
    pub action: Option<String>,
    /// MSC4191 target device for `device_view` / `device_delete`.
    #[serde(default)]
    pub device_id: Option<String>,
    #[allow(dead_code)]
    pub id_token_hint: Option<String>,
}

#[derive(Deserialize)]
pub struct AccountWalletRequest {
    pub action: String,
    pub did: String,
    pub message: String,
    pub signature: String,
    /// MSC4191 target device for `device_view` / `device_delete`.
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Deserialize)]
pub struct AccountPasskeyFinishRequest {
    pub action: String,
    /// MSC4191 target device for `device_view` / `device_delete`.
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(flatten)]
    pub credential: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct AccountActionResponse {
    pub status: String,
    pub action: String,
    /// CSRF token for the active account session, returned so the page JS can
    /// drive subsequent `POST /account/action` calls without a new signature.
    /// Present only when this response established/continued a session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf: Option<String>,
    /// What the (re-authenticated) action produced, for the page to render.
    #[serde(flatten)]
    pub outcome: ActionOutcome,
}

/// A successfully re-authenticated action plus the verified DID it ran as, so the
/// route handler can mint the account session cookie.
pub struct AuthedAction {
    pub response: AccountActionResponse,
    pub did: String,
}

/// Body of `POST /account/action`: execute an action using the existing account
/// session (no fresh signature). The session cookie carries the identity; `csrf`
/// must match the session's stored token.
#[derive(Deserialize)]
pub struct AccountActionRequest {
    pub action: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
}

/// The result of a successfully executed account action, tagged by `kind` so
/// the account page's client JS can render the appropriate view.
#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// A side-effecting action with nothing to render (cross_signing_reset).
    Completed,
    /// The user's identity (profile).
    Profile { did: String, user_id: String },
    /// The user's full device list (devices_list).
    Devices { devices: Vec<DeviceInfo> },
    /// A single device's details (device_view).
    Device { device: DeviceInfo },
    /// Confirmation that a device was signed out (device_delete).
    Deleted { device_id: String },
    /// Confirmation that the account was deactivated (account_deactivate).
    Deactivated,
    /// Confirmation that the account was irreversibly erased (account_erase).
    Erased,
    /// Confirmation that the account was reactivated (account_reactivate).
    Reactivated,
}

// -- Supported actions --------------------------------------------------------

const ACTION_CROSS_SIGNING_RESET: &str = "org.matrix.cross_signing_reset";

/// A normalized MSC4191 account-management action.
///
/// The wire protocol has two generations of action strings: the stable
/// `device_*` set (Matrix v1.18) and the older `session_*` aliases. Both are
/// accepted on input (see [`canonical_action`]) and collapse onto these
/// variants, so the rest of the code only ever reasons about one set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// `org.matrix.profile` — view the account profile/identity.
    Profile,
    /// `org.matrix.devices_list` / `org.matrix.sessions_list`.
    DevicesList,
    /// `org.matrix.device_view` / `org.matrix.session_view` (needs `device_id`).
    DeviceView,
    /// `org.matrix.device_delete` / `org.matrix.session_end` (needs `device_id`).
    DeviceDelete,
    /// `org.matrix.cross_signing_reset` (MSC4312).
    CrossSigningReset,
    /// `org.matrix.account_deactivate`: permanently deactivate the account
    /// (keeps profile/media; reversible via [`Action::Reactivate`]).
    AccountDeactivate,
    /// `org.matrix.account_erase`: irreversibly erase the account
    /// (GDPR `erase:true` + Redis identity purge).
    AccountErase,
    /// `org.matrix.account_reactivate`: restore an `erase:false`-deactivated account.
    Reactivate,
}

/// The full superset of MSC4191 action strings this server advertises in
/// `account_management_actions_supported`, in stable-then-alias order.
///
/// This is the single source of truth: it drives the discovery metadata
/// (`oidc::provider_metadata_value`), page validation, and dispatch
/// ([`canonical_action`]). matrix.org advertises both naming generations and
/// different client versions emit different ones, so we advertise the superset.
pub const SUPPORTED_ACTIONS: &[&str] = &[
    "org.matrix.profile",
    "org.matrix.devices_list",
    "org.matrix.device_view",
    "org.matrix.device_delete",
    ACTION_CROSS_SIGNING_RESET,
    "org.matrix.account_deactivate",
    "org.matrix.account_erase",
    "org.matrix.account_reactivate",
    // session_* aliases (older naming, accepted for compatibility):
    "org.matrix.sessions_list",
    "org.matrix.session_view",
    "org.matrix.session_end",
];

/// Map an action string (stable `device_*` or legacy `session_*`) to its
/// canonical [`Action`]. Returns `None` for unknown/unsupported actions.
pub fn canonical_action(action: &str) -> Option<Action> {
    match action {
        "org.matrix.profile" => Some(Action::Profile),
        "org.matrix.devices_list" | "org.matrix.sessions_list" => Some(Action::DevicesList),
        "org.matrix.device_view" | "org.matrix.session_view" => Some(Action::DeviceView),
        "org.matrix.device_delete" | "org.matrix.session_end" => Some(Action::DeviceDelete),
        ACTION_CROSS_SIGNING_RESET => Some(Action::CrossSigningReset),
        "org.matrix.account_deactivate" => Some(Action::AccountDeactivate),
        "org.matrix.account_erase" => Some(Action::AccountErase),
        "org.matrix.account_reactivate" => Some(Action::Reactivate),
        _ => None,
    }
}

/// Parse an account action string, distinguishing an absent action from an
/// unknown one so the client gets an actionable error.
///
/// Element Web's generic "Manage account" entry opens the account page with no
/// `action`, then re-auth POSTs an empty action string; surfacing "Missing
/// action" (rather than "Unsupported action: ") tells the client this is a
/// menu-only page, not a bad action.
fn parse_action(raw: &str) -> Result<Action, CustomError> {
    if raw.is_empty() {
        return Err(CustomError::BadRequest("Missing action".to_string()));
    }
    canonical_action(raw)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported action: {}", raw)))
}

/// Sanitize a user-supplied action string for safe HTML interpolation.
fn sanitize_action(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
        .take(64)
        .collect()
}

/// Escape a user-supplied device id for safe interpolation into the
/// `data-device-id="..."` HTML attribute, PRESERVING the exact id.
///
/// A character allowlist (the previous approach) corrupts real device ids:
/// matrix-rust-sdk / Element X mint device ids as standard base64, which contain
/// `/`, `+`, and `=`. Stripping those produced a different id, so the MSC4191
/// `device_view` / `device_delete` deep links ("Manage this session") could never
/// match the device — the page showed "That device is not among your active
/// sessions". Escaping the five HTML metacharacters keeps the attribute injection
/// -safe while the browser hands the id back verbatim via `dataset.deviceId`. A
/// length cap bounds pathological input.
fn escape_device_id_attr(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars().take(255) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// -- Action prerequisites -----------------------------------------------------

fn require_synapse(synapse: Option<&SynapseClient>) -> Result<&SynapseClient, CustomError> {
    synapse.ok_or_else(|| {
        CustomError::BadRequest("This action requires Synapse integration".to_string())
    })
}

fn require_server_name(server_name: Option<&str>) -> Result<&str, CustomError> {
    server_name.filter(|s| !s.is_empty()).ok_or_else(|| {
        CustomError::BadRequest(
            "This action requires the Matrix server_name to be configured".to_string(),
        )
    })
}

fn require_device_id(device_id: Option<&str>) -> Result<&str, CustomError> {
    device_id
        .filter(|d| !d.is_empty())
        .ok_or_else(|| CustomError::BadRequest("This action requires a device_id".to_string()))
}

// -- Action execution ---------------------------------------------------------

/// Execute a (canonicalized) account action for an already-authenticated `did`.
///
/// `device_id` is required only for [`Action::DeviceView`] / [`Action::DeviceDelete`].
/// Device actions need both a Synapse client and a configured `server_name`;
/// when either is absent a clear `BadRequest` is returned rather than panicking,
/// so standalone (no-Synapse) deployments degrade gracefully.
async fn execute_action(
    action: Action,
    device_id: Option<&str>,
    did: &str,
    synapse_client: Option<&SynapseClient>,
    db_client: &RedisClient,
    server_name: Option<&str>,
) -> Result<ActionOutcome, CustomError> {
    let localpart = did_to_localpart(did);
    match action {
        Action::CrossSigningReset => {
            let synapse = require_synapse(synapse_client)?;
            synapse
                .allow_cross_signing_reset(&localpart)
                .await
                .map_err(|e| {
                    warn!(error = %e, "allow_cross_signing_reset failed during account action");
                    CustomError::BadRequest("Failed to reset cross-signing keys".to_string())
                })?;
            info!(did = %did, "cross-signing reset allowed via account management page");
            Ok(ActionOutcome::Completed)
        }
        Action::Profile => {
            let server = require_server_name(server_name)?;
            Ok(ActionOutcome::Profile {
                did: did.to_string(),
                user_id: format!("@{localpart}:{server}"),
            })
        }
        Action::DevicesList => {
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            let devices = synapse
                .list_devices(&localpart, server)
                .await
                .map_err(|e| {
                    warn!(error = %e, "list_devices failed during account action");
                    CustomError::BadRequest(format!("Failed to list devices: {e}"))
                })?;
            Ok(ActionOutcome::Devices { devices })
        }
        Action::DeviceView => {
            let device_id = require_device_id(device_id)?;
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            let device = synapse
                .get_device(&localpart, device_id, server)
                .await
                .map_err(|e| {
                    warn!(error = %e, "get_device failed during account action");
                    CustomError::BadRequest(
                        "Could not reach the homeserver to fetch this device".to_string(),
                    )
                })?
                // get_device is scoped to this user, so a missing/foreign id is "not found".
                .ok_or_else(|| {
                    CustomError::BadRequest(
                        "That device is not among your active sessions".to_string(),
                    )
                })?;
            Ok(ActionOutcome::Device { device })
        }
        Action::DeviceDelete => {
            let device_id = require_device_id(device_id)?;
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            // Confirm the device belongs to the authenticated user before deleting
            // (defence in depth; the admin call is already mxid-scoped).
            let owned = synapse
                .get_device(&localpart, device_id, server)
                .await
                .map_err(|e| {
                    warn!(error = %e, "get_device (pre-delete) failed during account action");
                    CustomError::BadRequest(
                        "Could not reach the homeserver to verify this device".to_string(),
                    )
                })?
                .is_some();
            if !owned {
                return Err(CustomError::BadRequest(
                    "That device is not among your active sessions".to_string(),
                ));
            }
            synapse
                .delete_device(&localpart, device_id, server)
                .await
                .map_err(|e| {
                    warn!(error = %e, "delete_device failed during account action");
                    CustomError::BadRequest("Failed to sign out device".to_string())
                })?;
            // Revoke the OAuth session so introspection reports it inactive (AC3).
            // Key on the localpart (== TokenMetadata.username), which is stable
            // across address-case differences between sign-in and re-auth DIDs.
            // Best-effort: the Synapse device is already gone if this fails.
            let revoked = db_client
                .revoke_device_tokens(&localpart, device_id)
                .await
                .unwrap_or_else(|e| {
                    warn!(error = %e, "revoke_device_tokens failed during account action");
                    0
                });
            info!(did = %did, device_id = %device_id, revoked = revoked as u64, "device signed out via account management");
            Ok(ActionOutcome::Deleted {
                device_id: device_id.to_string(),
            })
        }
        Action::AccountDeactivate => {
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            synapse
                .deactivate_user(&localpart, server, false)
                .await
                .map_err(|e| {
                    warn!(error = %e, "deactivate_user failed during account action");
                    CustomError::BadRequest(format!("Failed to deactivate account: {e}"))
                })?;
            // Revoke ALL of the user's OAuth sessions so introspection reports every
            // session inactive (Synapse deactivate already drops Synapse-side tokens).
            let revoked = db_client
                .revoke_all_user_tokens(&localpart)
                .await
                .unwrap_or_else(|e| {
                    warn!(error = %e, "revoke_all_user_tokens failed during account deactivation");
                    0
                });
            info!(did = %did, revoked = revoked as u64, "account deactivated via account management");
            Ok(ActionOutcome::Deactivated)
        }
        Action::AccountErase => {
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            // Irreversible: GDPR erasure removes profile, media, and room
            // memberships in addition to deactivating the account.
            synapse
                .deactivate_user(&localpart, server, true)
                .await
                .map_err(|e| {
                    warn!(error = %e, "deactivate_user(erase=true) failed during account action");
                    CustomError::BadRequest(format!("Failed to erase account: {e}"))
                })?;
            // Revoke ALL OAuth sessions (best-effort) so introspection reports
            // every session inactive.
            let revoked = db_client
                .revoke_all_user_tokens(&localpart)
                .await
                .unwrap_or_else(|e| {
                    warn!(error = %e, "revoke_all_user_tokens failed during account erasure");
                    0
                });
            // Purge WebAuthn identity artifacts (best-effort) so the erased DID
            // cannot be silently re-derived from a leftover passkey/link. The
            // standalone-credential pass reuses the webauthn layer's single
            // source of truth for did:key derivation.
            let purged = db_client
                .purge_identity(did, wa::derive_did_from_credential_json)
                .await
                .unwrap_or_else(|e| {
                    warn!(error = %e, "purge_identity failed during account erasure");
                    0
                });
            info!(
                did = %did,
                revoked = revoked as u64,
                purged = purged as u64,
                "account erased via account management"
            );
            Ok(ActionOutcome::Erased)
        }
        Action::Reactivate => {
            let synapse = require_synapse(synapse_client)?;
            let server = require_server_name(server_name)?;
            // Valid only for accounts deactivated with erase:false; an erased
            // account cannot be restored. Self-service reactivation is verified
            // working under MSC3861 (see SynapseClient::reactivate_user).
            synapse
                .reactivate_user(&localpart, server)
                .await
                .map_err(|e| {
                    warn!(error = %e, "reactivate_user failed during account action");
                    // Reactivation is verified working under MSC3861 (live probe
                    // 2026-06-10), so this branch is a genuine error path (e.g.
                    // erased account, Synapse unreachable). Keep the honest
                    // fallback: a server admin can always reactivate directly.
                    CustomError::BadRequest(
                        "Reactivation failed. Under delegated auth (MSC3861) the homeserver \
                         may not support self-service reactivation; ask a server admin to \
                         reactivate the account."
                            .to_string(),
                    )
                })?;
            info!(did = %did, "account reactivated via account management");
            Ok(ActionOutcome::Reactivated)
        }
    }
}

// -- Wallet re-authentication -------------------------------------------------

pub async fn account_wallet(
    config: &Config,
    req: AccountWalletRequest,
    synapse_client: Option<&SynapseClient>,
    db_client: &RedisClient,
    server_name: Option<&str>,
) -> Result<AuthedAction, CustomError> {
    let action = parse_action(&req.action)?;

    let sig_hex = req.signature.strip_prefix("0x").unwrap_or(&req.signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    let did_method = aqua_auth::find_did_method(&req.did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", req.did)))?;

    if !config
        .supported_did_methods
        .iter()
        .any(|m| m == did_method.method_name())
    {
        return Err(CustomError::BadRequest(format!(
            "DID method '{}' is not enabled on this server",
            did_method.method_name()
        )));
    }

    let valid = did_method
        .verify(&req.did, &req.message, &sig_bytes)
        .map_err(|e| CustomError::BadRequest(format!("Verification error: {}", e)))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    let outcome = execute_action(
        action,
        req.device_id.as_deref(),
        &req.did,
        synapse_client,
        db_client,
        server_name,
    )
    .await?;

    Ok(AuthedAction {
        response: AccountActionResponse {
            status: "completed".to_string(),
            action: req.action,
            csrf: None,
            outcome,
        },
        did: req.did,
    })
}

// -- Passkey re-authentication ------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn account_passkey_finish(
    db_client: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    req: AccountPasskeyFinishRequest,
    synapse_client: Option<&SynapseClient>,
    server_name: Option<&str>,
) -> Result<AuthedAction, CustomError> {
    let action = parse_action(&req.action)?;

    let auth_response: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(req.credential)
            .map_err(|e| CustomError::BadRequest(format!("Invalid credential: {}", e)))?;

    let resp = wa::verify_credential(db_client, session_id, rp_id, rp_origin, &auth_response)
        .await
        .map_err(|e| CustomError::BadRequest(e.to_string()))?;

    let outcome = execute_action(
        action,
        req.device_id.as_deref(),
        &resp.did,
        synapse_client,
        db_client,
        server_name,
    )
    .await?;

    Ok(AuthedAction {
        response: AccountActionResponse {
            status: "completed".to_string(),
            action: req.action,
            csrf: None,
            outcome,
        },
        did: resp.did,
    })
}

// -- Session-backed action (no fresh signature) -------------------------------

/// Execute an account action using an existing authenticated account session
/// (the [`ACCOUNT_SESSION_COOKIE`] established by a prior wallet/passkey re-auth),
/// so the user does not have to sign again for every action.
///
/// `session_token` is the cookie value; `csrf` is the token the page echoed.
/// Fails closed: a missing/expired session is `Unauthorized` (the page falls
/// back to re-auth), a CSRF mismatch is `Unauthorized` as well.
pub async fn account_action(
    db_client: &RedisClient,
    session_token: Option<&str>,
    req: AccountActionRequest,
    synapse_client: Option<&SynapseClient>,
    server_name: Option<&str>,
) -> Result<AccountActionResponse, CustomError> {
    let action = parse_action(&req.action)?;

    let token =
        session_token.ok_or_else(|| CustomError::Unauthorized("No account session".to_string()))?;
    let session = lookup_account_session(db_client, token)
        .await
        .ok_or_else(|| CustomError::Unauthorized("Account session expired".to_string()))?;

    // CSRF: the page must echo the session's token (defence in depth over
    // SameSite=Strict). Constant work either way; a mismatch is unauthorized.
    if req.csrf.as_deref() != Some(session.csrf.as_str()) {
        return Err(CustomError::Unauthorized("CSRF token mismatch".to_string()));
    }

    let outcome = execute_action(
        action,
        req.device_id.as_deref(),
        &session.did,
        synapse_client,
        db_client,
        server_name,
    )
    .await?;

    Ok(AccountActionResponse {
        status: "completed".to_string(),
        action: req.action,
        csrf: Some(session.csrf),
        outcome,
    })
}

// -- Account management page --------------------------------------------------

/// Wallet sign-in button. `{disabled}` is either `""` or `" disabled"` so the
/// deactivate confirmation gate can render it disabled until the user confirms.
const WALLET_BUTTON_HTML: &str = r##"<button class="btn btn-primary" id="btn-wallet" onclick="authWallet()"{disabled}>
          <svg xmlns="http://www.w3.org/2000/svg" clip-rule="evenodd" fill-rule="evenodd" viewBox="170 30 220 350" class="btn-icon eth-icon">
            <g fill-rule="nonzero" transform="matrix(.781253 0 0 .781253 180 37.1453)">
              <path d="m127.961 0-2.795 9.5v275.668l2.795 2.79 127.962-75.638z" fill="#343434"/>
              <path d="m127.962 0-127.962 212.32 127.962 75.639v-133.801z" fill="#8c8c8c"/>
              <path d="m127.961 312.187-1.575 1.92v98.199l1.575 4.601 128.038-180.32z" fill="#3c3c3b"/>
              <path d="m127.962 416.905v-104.72l-127.962-75.6z" fill="#8c8c8c"/>
              <path d="m127.961 287.958 127.96-75.637-127.96-58.162z" fill="#141414"/>
              <path d="m.001 212.321 127.96 75.637v-133.799z" fill="#393939"/>
            </g>
          </svg>
          <span>Sign with wallet</span>
        </button>"##;

/// `or` divider between the wallet and passkey buttons.
const BUTTON_DIVIDER_HTML: &str = r##"<div class="divider">
          <div class="divider-line"></div>
          <span class="divider-text">or</span>
          <div class="divider-line"></div>
        </div>"##;

/// Passkey sign-in button. `{disabled}` works as for [`WALLET_BUTTON_HTML`].
const PASSKEY_BUTTON_HTML: &str = r##"<button class="btn btn-secondary" id="btn-passkey" onclick="authPasskey()"{disabled}>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="btn-icon">
            <path fill-rule="evenodd" d="M15.75 1.5a6.75 6.75 0 0 0-6.651 7.906c.067.39-.032.717-.221.906l-6.5 6.499a3 3 0 0 0-.878 2.121v2.818c0 .414.336.75.75.75H6a.75.75 0 0 0 .75-.75v-1.5h1.5A.75.75 0 0 0 9 19.5V18h1.5a.75.75 0 0 0 .53-.22l2.658-2.658c.19-.189.517-.288.906-.22A6.75 6.75 0 1 0 15.75 1.5Zm0 3a.75.75 0 0 0 0 1.5A2.25 2.25 0 0 1 18 8.25a.75.75 0 0 0 1.5 0 3.75 3.75 0 0 0-3.75-3.75Z" clip-rule="evenodd"/>
          </svg>
          <span>Sign with passkey</span>
        </button>"##;

/// The wallet + passkey re-auth buttons, optionally rendered `disabled` (used by
/// the danger confirmation gates, which enable them once their box is checked).
fn auth_buttons_html(disabled: bool) -> String {
    let attr = if disabled { " disabled" } else { "" };
    format!(
        "{wallet}\n\n        {divider}\n\n        {passkey}",
        wallet = WALLET_BUTTON_HTML.replace("{disabled}", attr),
        divider = BUTTON_DIVIDER_HTML,
        passkey = PASSKEY_BUTTON_HTML.replace("{disabled}", attr),
    )
}

/// A danger confirmation gate: a warning box + a single confirm checkbox that
/// gates the (initially disabled) auth buttons. Shared by deactivate and erase
/// so there is one rendering path; the checkbox `id` is what the page JS keys on
/// to enable the buttons (see `gateButtons` in the embedded JS).
fn danger_gate_html(checkbox_id: &str, warning: &str, confirm_label: &str) -> String {
    format!(
        r##"<div class="warning-box">
          {warning}
        </div>
        <label class="confirm-label">
          <input type="checkbox" id="{checkbox_id}">
          <span>{confirm_label}</span>
        </label>
        {buttons}"##,
        warning = warning,
        checkbox_id = checkbox_id,
        confirm_label = confirm_label,
        buttons = auth_buttons_html(true)
    )
}

/// An already-authenticated single-click action button (no signature). `id` is
/// `btn-confirm`, which the page JS wires to `confirmAction()`. Used when the
/// account session is live, so a destructive action needs one click, not a fresh
/// wallet/passkey ceremony.
fn authed_confirm_button_html(label: &str, danger: bool, disabled: bool) -> String {
    let cls = if danger {
        "btn btn-danger"
    } else {
        "btn btn-primary"
    };
    let attr = if disabled { " disabled" } else { "" };
    format!(
        r##"<button class="{cls}" id="btn-confirm" onclick="confirmAction()"{attr}>
          <span>{label}</span>
        </button>"##
    )
}

/// An already-authenticated danger gate: warning + confirm checkbox gating a
/// single confirm button (no signature). The checkbox `id` matches the
/// non-authenticated gate so the page JS gate wiring is shared.
fn danger_gate_authed_html(
    checkbox_id: &str,
    warning: &str,
    confirm_label: &str,
    button_label: &str,
) -> String {
    format!(
        r##"<div class="warning-box">
          {warning}
        </div>
        <label class="confirm-label">
          <input type="checkbox" id="{checkbox_id}">
          <span>{confirm_label}</span>
        </label>
        {button}"##,
        button = authed_confirm_button_html(button_label, true, true)
    )
}

/// The account-home menu of links (shown for the empty/landing action).
fn menu_html(base: &str) -> String {
    format!(
        r##"<div class="menu-list">
          <a class="btn btn-secondary" href="{base}/account?action=org.matrix.profile">Your account</a>
          <a class="btn btn-secondary" href="{base}/account?action=org.matrix.devices_list">Your sessions</a>
          <a class="btn btn-danger" href="{base}/account?action=org.matrix.account_deactivate">Deactivate account</a>
          <a class="btn btn-danger" href="{base}/account?action=org.matrix.account_erase">Erase account</a>
          <a class="btn btn-secondary" href="{base}/account?action=org.matrix.account_reactivate">Reactivate account</a>
        </div>"##,
        base = base
    )
}

/// Build the inner HTML of `#auth-section`, keyed on the (canonical) action and
/// whether an account session is already live (`authed`).
///
/// - empty action: the account-home MENU of links (both states);
/// - `authed == false`: the original re-auth shapes (wallet/passkey buttons, or a
///   danger gate above them for deactivate/erase);
/// - `authed == true`: NO signature needed. Destructive actions render a single
///   confirm button (gated by the danger checkbox for deactivate/erase); the
///   read actions render a placeholder and the page JS auto-runs them.
fn auth_section_html(
    action_opt: Option<Action>,
    action_is_empty: bool,
    base: &str,
    authed: bool,
) -> String {
    if action_is_empty {
        return menu_html(base);
    }

    if !authed {
        return match action_opt {
            Some(Action::AccountDeactivate) => danger_gate_html(
                "confirm-deactivate",
                "This permanently deactivates your Matrix account and signs you out of every session. This cannot be undone.",
                "I understand this is permanent",
            ),
            Some(Action::AccountErase) => danger_gate_html(
                "confirm-erase",
                "This is irreversible. Erasing your account permanently deletes your profile, media, and room memberships, and signs you out of every session. This cannot be undone.",
                "I understand my account and all its data will be permanently erased",
            ),
            _ => auth_buttons_html(false),
        };
    }

    // Authenticated: reuse the live session, no fresh signature.
    match action_opt {
        Some(Action::AccountDeactivate) => danger_gate_authed_html(
            "confirm-deactivate",
            "This permanently deactivates your Matrix account and signs you out of every session. This cannot be undone.",
            "I understand this is permanent",
            "Deactivate my account",
        ),
        Some(Action::AccountErase) => danger_gate_authed_html(
            "confirm-erase",
            "This is irreversible. Erasing your account permanently deletes your profile, media, and room memberships, and signs you out of every session. This cannot be undone.",
            "I understand my account and all its data will be permanently erased",
            "Erase my account",
        ),
        Some(Action::DeviceDelete) => authed_confirm_button_html("Sign out this device", true, false),
        // Read actions + benign actions: the page JS auto-runs them on load.
        _ => r##"<p class="subtitle" id="auto-hint">Loading…</p>"##.to_string(),
    }
}

/// Render the account page with no active session (the common unauthenticated
/// entry, and the signature used by the page-rendering unit tests).
#[allow(dead_code)]
pub fn account_page(query: AccountPageQuery, base_url: &str) -> Html<String> {
    account_page_inner(query, base_url, None)
}

/// Render the account page. `authed_csrf` is `Some(csrf)` when the request
/// carried a live account session, which switches the page into "already
/// authenticated" mode: no fresh signature, and subsequent actions are driven
/// in-page against `POST /account/action` carrying `csrf`.
pub fn account_page_inner(
    query: AccountPageQuery,
    base_url: &str,
    authed_csrf: Option<&str>,
) -> Html<String> {
    let action = query
        .action
        .as_deref()
        .map(sanitize_action)
        .unwrap_or_default();
    let device_id = query
        .device_id
        .as_deref()
        .map(escape_device_id_attr)
        .unwrap_or_default();
    let base = base_url.trim_end_matches('/');

    // Title/subtitle keyed on the canonical action so session_* aliases render
    // identically to their device_* form.
    let (title, subtitle) = match canonical_action(&action) {
        Some(Action::CrossSigningReset) => (
            "Reset encryption keys",
            "Authenticate to confirm resetting your cross-signing keys. \
             This allows your client to set up new encryption keys.",
        ),
        Some(Action::Profile) => ("Your account", "Authenticate to view your account."),
        Some(Action::DevicesList) => (
            "Your sessions",
            "Authenticate to view and manage your signed-in devices.",
        ),
        Some(Action::DeviceView) => ("Session details", "Authenticate to view this device."),
        Some(Action::DeviceDelete) => ("Sign out device", "Authenticate to sign this device out."),
        Some(Action::AccountDeactivate) => (
            "Deactivate account",
            "Confirm to permanently deactivate your account.",
        ),
        Some(Action::AccountErase) => (
            "Erase account",
            "Confirm to irreversibly erase your account and all of its data.",
        ),
        Some(Action::Reactivate) => (
            "Reactivate account",
            "Authenticate to reactivate your previously deactivated account.",
        ),
        None if action.is_empty() => ("Account", "Manage your account settings."),
        None => ("Account action", "Authenticate to continue."),
    };

    // Body of #auth-section depends on the action AND whether a session is live:
    // menu (empty), re-auth buttons / danger gate (unauthenticated), or a
    // single-click confirm / auto-run (authenticated).
    let authenticated = authed_csrf.is_some();
    let auth_section = auth_section_html(
        canonical_action(&action),
        action.is_empty(),
        base,
        authenticated,
    );

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · inblock.io</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link href="https://api.fontshare.com/css?f[]=satoshi@300,400,500,700,900&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body data-action="{action}" data-base="{base}" data-device-id="{device_id}" data-authenticated="{authenticated}" data-csrf="{csrf}">
<div class="login-page">
  <div class="ambient-glow"></div>
  <div class="login-card">
    <div class="card-inner">
      <div class="logo-area">
        <img src="/img/inblockio-logo.png" alt="inblock.io" class="logo logo-single">
      </div>

      <div id="auth-section" class="auth-section">
        <div class="action-badge">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="action-icon">
            <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 0 0-5.25 5.25v3a3 3 0 0 0-3 3v6.75a3 3 0 0 0 3 3h10.5a3 3 0 0 0 3-3v-6.75a3 3 0 0 0-3-3v-3c0-2.9-2.35-5.25-5.25-5.25Zm3.75 8.25v-3a3.75 3.75 0 1 0-7.5 0v3h7.5Z" clip-rule="evenodd"/>
          </svg>
        </div>
        <h1 class="title">{title}</h1>
        <p class="subtitle">{subtitle}</p>

        {auth_section}
      </div>

      <div id="terminal-section" class="auth-section hidden">
        <div class="success-badge" id="terminal-badge"></div>
        <h1 class="title" id="terminal-title"></h1>
        <p class="subtitle" id="terminal-subtitle">You can close this page.</p>
        <div id="terminal-actions"></div>
      </div>

      <div id="result-section" class="result-section hidden"></div>

      <div id="status" class="error-msg hidden">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="error-icon">
          <path fill-rule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4.5a.75.75 0 0 1-1.5 0v-4.5A.75.75 0 0 1 10 5Zm0 10a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clip-rule="evenodd"/>
        </svg>
        <span id="status-text"></span>
      </div>

      <div class="footer">
        <p>By continuing you agree to the
          <a href="/legal/terms-of-use.html">Terms of Use</a> and
          <a href="/legal/privacy-policy.html">Privacy Policy</a>.
        </p>
      </div>
    </div>
  </div>
</div>
<script>{js}</script>
</body>
</html>"##,
        css = ACCOUNT_PAGE_CSS,
        js = ACCOUNT_PAGE_JS,
        title = title,
        subtitle = subtitle,
        action = action,
        base = base,
        device_id = device_id,
        authenticated = authenticated,
        csrf = authed_csrf.unwrap_or(""),
        auth_section = auth_section,
    );
    Html(html)
}

const ACCOUNT_PAGE_CSS: &str = r##"
:root {
  --bg: #f5f5f5;
  --card-bg: #ffffff;
  --text: #1a1a1a;
  --text-dim: rgba(0,0,0,0.4);
  --text-mute: rgba(0,0,0,0.3);
  --border: rgba(0,0,0,0.06);
  --border-strong: rgba(0,0,0,0.12);
  --accent: #E8611A;
  --accent-strong: #EF5402;
  --accent-deep: #D4570F;
  --danger: #dc2626;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  width: 100%;
  min-height: 100%;
  background: var(--bg);
  overflow-x: hidden;
  font-family: 'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: var(--text);
}
.hidden { display: none !important; }
.login-page {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
  animation: fadeIn 0.6s ease both;
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.ambient-glow {
  position: fixed;
  top: -30%;
  left: 50%;
  transform: translateX(-50%);
  width: 800px;
  height: 600px;
  background: radial-gradient(ellipse at center,
    rgba(232,97,26,0.06) 0%,
    rgba(232,97,26,0.02) 40%,
    transparent 70%);
  pointer-events: none;
  z-index: 0;
}
.login-card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 400px;
  border-radius: 20px;
  background: var(--card-bg);
  border: 1px solid var(--border);
  box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 32px -8px rgba(0,0,0,0.08);
}
.card-inner {
  padding: 40px 36px 32px;
  display: flex;
  flex-direction: column;
}
.logo-area { display: flex; justify-content: center; margin-bottom: 32px; }
.logo { width: 56px; height: 56px; object-fit: contain; border-radius: 12px; }
.auth-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}
.title {
  font-family: 'Satoshi', sans-serif;
  font-weight: 700;
  font-size: 22px;
  line-height: 1.3;
  color: var(--text);
  margin: 0 0 6px;
  letter-spacing: -0.3px;
}
.subtitle {
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-dim);
  margin: 0 0 24px;
  max-width: 300px;
}
.action-badge {
  margin-bottom: 16px;
  display: flex;
  justify-content: center;
}
.action-icon {
  width: 44px;
  height: 44px;
  color: var(--accent);
}
.btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 48px;
  padding: 0 20px;
  border-radius: 12px;
  font-family: 'Satoshi', sans-serif;
  font-weight: 600;
  font-size: 14px;
  letter-spacing: 0.1px;
  cursor: pointer;
  transition: all 0.15s ease;
  border: none;
  outline: none;
  width: 100%;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn + .btn { margin-top: 10px; }
.btn-primary {
  background: linear-gradient(135deg, var(--accent-strong) 0%, var(--accent-deep) 100%);
  color: #fff;
  box-shadow: 0 1px 2px rgba(0,0,0,0.1), 0 0 0 1px rgba(232,97,26,0.12) inset;
}
.btn-primary:not(:disabled):hover {
  background: linear-gradient(135deg, #ff6a1a 0%, var(--accent-strong) 100%);
  box-shadow: 0 4px 16px rgba(232,97,26,0.25), 0 0 0 1px rgba(232,97,26,0.15) inset;
  transform: translateY(-1px);
}
.btn-primary:not(:disabled):active { transform: translateY(0); }
.btn-secondary {
  background: rgba(0,0,0,0.03);
  color: var(--text);
  border: 1px solid rgba(0,0,0,0.08);
}
.btn-secondary:not(:disabled):hover {
  background: rgba(0,0,0,0.06);
  border-color: rgba(0,0,0,0.12);
  transform: translateY(-1px);
}
.btn-icon { width: 18px; height: 18px; flex-shrink: 0; }
.eth-icon { width: 14px; height: 22px; }
.divider {
  display: flex;
  align-items: center;
  gap: 14px;
  margin: 14px 0;
  width: 100%;
}
.divider-line { flex: 1; height: 1px; background: rgba(0,0,0,0.07); }
.divider-text {
  font-size: 12px;
  color: rgba(0,0,0,0.25);
  text-transform: uppercase;
  letter-spacing: 1px;
  font-weight: 500;
}
.success-badge { margin-bottom: 16px; display: flex; justify-content: center; }
.success-icon { width: 44px; height: 44px; color: var(--accent); }
.error-msg {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 16px;
  padding: 10px 14px;
  border-radius: 10px;
  background: rgba(239,68,68,0.05);
  border: 1px solid rgba(239,68,68,0.12);
}
.error-msg span {
  font-size: 13px;
  line-height: 1.4;
  color: var(--danger);
}
.error-icon {
  width: 16px;
  height: 16px;
  color: var(--danger);
  flex-shrink: 0;
  margin-top: 1px;
}
.footer {
  margin-top: 28px;
  padding-top: 20px;
  border-top: 1px solid rgba(0,0,0,0.05);
  text-align: center;
}
.footer p {
  font-size: 11px;
  line-height: 1.5;
  color: rgba(0,0,0,0.3);
  margin: 0;
}
.footer a {
  color: rgba(0,0,0,0.45);
  text-decoration: none;
  transition: color 0.15s ease;
}
.footer a:hover { color: rgba(0,0,0,0.7); }
.result-section { display: flex; flex-direction: column; align-items: stretch; text-align: center; }
.result-section .title { text-align: center; }
.menu-list { display: flex; flex-direction: column; width: 100%; gap: 10px; }
.menu-list .btn { text-decoration: none; margin-top: 0; }
.warning-box {
  width: 100%;
  margin: 4px 0 16px;
  padding: 12px 14px;
  border-radius: 12px;
  background: rgba(220,38,38,0.06);
  border: 1px solid rgba(220,38,38,0.18);
  font-size: 13px;
  line-height: 1.5;
  color: var(--danger);
  text-align: left;
}
.confirm-label {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  margin-bottom: 16px;
  font-size: 13px;
  color: var(--text);
  cursor: pointer;
}
.confirm-label input { width: 16px; height: 16px; flex-shrink: 0; accent-color: var(--danger); }
.btn-danger {
  background: var(--danger);
  color: #fff;
  text-decoration: none;
  margin-top: 16px;
}
.btn-danger:hover { background: #b91c1c; transform: translateY(-1px); }
.btn-secondary[href] { text-decoration: none; margin-top: 16px; }
.device-list { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; text-align: left; }
.device-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid var(--border-strong);
  background: rgba(0,0,0,0.02);
}
.device-meta { min-width: 0; }
.device-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.device-sub {
  font-size: 12px;
  color: var(--text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.device-actions { display: flex; gap: 12px; flex-shrink: 0; }
.btn-link {
  appearance: none;
  -webkit-appearance: none;
  background: none;
  border: none;
  padding: 0;
  margin: 0;
  font-family: inherit;
  line-height: inherit;
  font-size: 13px;
  font-weight: 600;
  color: var(--accent-strong);
  text-decoration: none;
  cursor: pointer;
}
.btn-link:hover { text-decoration: underline; }
.btn-link.danger { color: var(--danger); }
.info-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 12px 0;
  text-align: left;
}
.info-row {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 10px 12px;
  border-radius: 10px;
  background: rgba(0,0,0,0.03);
}
.info-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-mute);
}
.info-value { font-size: 13px; color: var(--text); word-break: break-all; }
"##;

const ACCOUNT_PAGE_JS: &str = r#"
const BASE = document.body.dataset.base;
const ACTION = document.body.dataset.action;
const DEVICE_ID = document.body.dataset.deviceId || '';
// Session state: set by the server on load (returning visit), or by the first
// re-auth response (this visit). Once authenticated, actions run against
// /account/action with the CSRF token and no fresh signature.
let AUTHED = document.body.dataset.authenticated === 'true';
let CSRF = document.body.dataset.csrf || '';
const $ = (id) => document.getElementById(id);

const CHECK_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="success-icon"><path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd"/></svg>';

// -- Session-backed action (no fresh signature) ------------------------------
// Runs an action against the live account session. Returns true on success.
async function accountAction(action, deviceId) {
  hideStatus();
  try {
    const r = await fetch(BASE + '/account/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, device_id: deviceId || null, csrf: CSRF })
    });
    if (r.ok) {
      const data = await r.json();
      if (data.csrf) CSRF = data.csrf;
      renderOutcome(data);
      return true;
    }
    if (r.status === 401) {
      // Session expired/invalid: drop back to a fresh re-auth.
      AUTHED = false;
      showReauth('Your session expired — please authenticate again.');
      return false;
    }
    showStatus((await r.text()) || 'Action failed.');
    return false;
  } catch (e) {
    showStatus('Error: ' + (e.message || e));
    return false;
  }
}

// Single-click confirm button (authenticated device_delete / deactivate / erase).
function confirmAction() {
  setBusy('btn-confirm', true, 'Working...');
  accountAction(ACTION, DEVICE_ID).finally(() => setBusy('btn-confirm', false));
}

// Session gone: reload so the page renders the unauthenticated re-auth buttons.
function showReauth(msg) {
  if (msg) showStatus(msg);
  setTimeout(() => { try { location.reload(); } catch (_) {} }, 1200);
}

async function authWallet() {
  hideStatus();
  setBusy('btn-wallet', true, 'Requesting signature...');
  try {
    if (!window.ethereum) { showStatus('No wallet detected. Install MetaMask or another EIP-1193 wallet.'); return; }
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];
    const did = 'did:pkh:eip155:1:' + address;
    const domain = new URL(BASE).hostname;
    const nonce = Math.random().toString(36).substring(2, 18);
    const issuedAt = new Date().toISOString();
    const message = domain + ' wants you to sign in with your Ethereum account:\n' +
      address + '\n\nConfirm account action.\n\nURI: ' + BASE + '\nVersion: 1\nChain ID: 1\n' +
      'Nonce: ' + nonce + '\nIssued At: ' + issuedAt;
    const signature = await window.ethereum.request({ method: 'personal_sign', params: [message, address] });
    const r = await fetch(BASE + '/account/wallet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: ACTION, did, message, signature, device_id: DEVICE_ID || null })
    });
    if (r.ok) {
      const data = await r.json();
      AUTHED = true; if (data.csrf) CSRF = data.csrf;
      renderOutcome(data);
    } else {
      const t = await r.text();
      showStatus(t || 'Action failed.');
    }
  } catch (e) {
    showStatus('Wallet error: ' + (e.message || e));
  } finally {
    setBusy('btn-wallet', false);
  }
}

async function authPasskey() {
  hideStatus();
  setBusy('btn-passkey', true, 'Authenticating...');
  try {
    const startR = await fetch(BASE + '/account/passkey/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: ACTION })
    });
    if (!startR.ok) { showStatus('Failed to start passkey authentication.'); return; }
    const startData = await startR.json();
    const sessionId = startData.session_id;
    const options = startData;
    options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      if (options.publicKey.allowCredentials.length === 0) {
        showStatus('No passkeys registered on this server. Register a passkey first.');
        return;
      }
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((c) => ({ ...c, id: base64ToBuffer(c.id) }));
    }
    const credential = await navigator.credentials.get({ publicKey: options.publicKey });
    const finishR = await fetch(BASE + '/account/passkey/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: ACTION,
        device_id: DEVICE_ID || null,
        session_id: sessionId,
        id: credential.id,
        rawId: bufferToBase64(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
          signature: bufferToBase64(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64(credential.response.userHandle) : null
        }
      })
    });
    if (finishR.ok) {
      const data = await finishR.json();
      AUTHED = true; if (data.csrf) CSRF = data.csrf;
      renderOutcome(data);
    } else {
      const t = await finishR.text();
      showStatus(t || 'Passkey authentication failed.');
    }
  } catch (e) {
    showStatus('Passkey error: ' + (e.message || e));
  } finally {
    setBusy('btn-passkey', false);
  }
}

// -- Outcome rendering (MSC4191) ---------------------------------------------

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function actionUrl(action, deviceId) {
  let u = BASE + '/account?action=' + encodeURIComponent(action);
  if (deviceId) u += '&device_id=' + encodeURIComponent(deviceId);
  return u;
}

function lastSeen(d) {
  if (!d.last_seen_ts) return 'never';
  try { return new Date(d.last_seen_ts).toLocaleString(); } catch (_) { return String(d.last_seen_ts); }
}

function infoRow(label, value) {
  return '<div class="info-row"><span class="info-label">' + esc(label) +
    '</span><span class="info-value">' + esc(value) + '</span></div>';
}

function renderOutcome(data) {
  switch (data && data.kind) {
    case 'completed':
      showTerminal('Encryption keys reset',
        'Your client can now set up new encryption keys. You can close this page.', true);
      break;
    case 'deleted':
      showTerminal('Session signed out', 'This device can no longer access your account.', false);
      // Stay in-session: re-list without a fresh signature.
      $('terminal-actions').innerHTML =
        '<button class="btn btn-secondary" data-act="org.matrix.devices_list">Back to your sessions</button>';
      break;
    case 'deactivated':
      showTerminal('Account deactivated', 'Your account has been deactivated and you have been signed out everywhere.', false);
      break;
    case 'erased':
      showTerminal('Account erased', 'Your account and all of its data have been permanently erased. This cannot be undone.', false);
      break;
    case 'reactivated':
      showTerminal('Account reactivated', 'Your account is active again. You can sign in as usual.', false);
      break;
    case 'profile':
      showResult('<div class="success-badge">' + CHECK_SVG + '</div>' +
        '<h1 class="title">Your account</h1>' +
        '<div class="info-list">' + infoRow('Matrix ID', data.user_id) + infoRow('DID', data.did) + '</div>');
      break;
    case 'devices':
      renderDevices(data.devices || []);
      break;
    case 'device':
      renderDevice(data.device);
      break;
    default:
      showTerminal('Done', 'You can close this page.', true);
  }
}

function deviceRow(d) {
  const name = esc(d.display_name || d.device_id);
  const ip = d.last_seen_ip ? ' &middot; ' + esc(d.last_seen_ip) : '';
  return '<div class="device-row"><div class="device-meta">' +
    '<div class="device-name">' + name + '</div>' +
    '<div class="device-sub">' + esc(d.device_id) + ' &middot; ' + esc(lastSeen(d)) + ip + '</div>' +
    '</div><div class="device-actions">' +
    '<button class="btn-link" data-act="org.matrix.device_view" data-dev="' + esc(d.device_id) + '">View</button>' +
    '<button class="btn-link danger" data-act="org.matrix.device_delete" data-dev="' + esc(d.device_id) + '">Sign out</button>' +
    '</div></div>';
}

function renderDevices(devices) {
  const body = devices.length
    ? '<div class="device-list">' + devices.map(deviceRow).join('') + '</div>'
    : '<p class="subtitle">No active sessions.</p>';
  showResult('<h1 class="title">Your sessions</h1>' + body);
}

function renderDevice(d) {
  if (!d) { showStatus('Device not found.'); return; }
  showResult('<h1 class="title">Session details</h1>' +
    '<div class="info-list">' +
      infoRow('Name', d.display_name || '(unnamed)') +
      infoRow('Device ID', d.device_id) +
      infoRow('Last seen', lastSeen(d)) +
      (d.last_seen_ip ? infoRow('Last IP', d.last_seen_ip) : '') +
    '</div>' +
    '<button class="btn btn-danger" data-act="org.matrix.device_delete" data-dev="' + esc(d.device_id) + '">Sign out this session</button>');
}

function showResult(html) {
  $('auth-section').classList.add('hidden');
  $('terminal-section').classList.add('hidden');
  hideStatus();
  const el = $('result-section');
  el.innerHTML = html;
  el.classList.remove('hidden');
}

function showTerminal(title, subtitle, autoClose) {
  $('auth-section').classList.add('hidden');
  $('result-section').classList.add('hidden');
  hideStatus();
  const section = $('terminal-section');
  $('terminal-badge').innerHTML = CHECK_SVG;
  $('terminal-title').textContent = title;
  $('terminal-subtitle').textContent = subtitle || 'You can close this page.';
  $('terminal-actions').innerHTML = '';
  section.classList.remove('hidden');
  // Auto-close only for terminal side effects (works when opened by window.open).
  if (autoClose) setTimeout(() => { try { window.close(); } catch (_) {} }, 3000);
}

function showStatus(msg) {
  const el = $('status');
  $('status-text').textContent = msg;
  el.classList.remove('hidden');
}

function hideStatus() { $('status').classList.add('hidden'); }

function setBusy(id, busy, label) {
  const el = $(id);
  if (!el) return;
  el.disabled = !!busy;
  if (label !== undefined) {
    if (busy) {
      if (!el.dataset.origLabel) el.dataset.origLabel = el.querySelector('span').textContent;
      el.querySelector('span').textContent = label;
    } else if (el.dataset.origLabel) {
      el.querySelector('span').textContent = el.dataset.origLabel;
      delete el.dataset.origLabel;
    }
  }
}

function base64ToBuffer(b64) {
  const padding = '='.repeat((4 - (b64.length % 4)) % 4);
  const s = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(s);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  bytes.forEach((b) => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Danger confirmation gate (deactivate or erase): keep the action buttons
// disabled until the user ticks the confirm box. Covers BOTH the unauthenticated
// re-auth buttons (btn-wallet/btn-passkey) and the authenticated single-click
// confirm button (btn-confirm). Only the checkbox id differs per gate.
(function () {
  const cb = $('confirm-deactivate') || $('confirm-erase');
  if (!cb) return;
  const sync = () => {
    ['btn-wallet', 'btn-passkey', 'btn-confirm'].forEach((id) => {
      const b = $(id);
      if (b) b.disabled = !cb.checked;
    });
  };
  cb.addEventListener('change', sync);
  sync();
})();

// In-page session actions: device View/Sign out buttons and the "back to
// sessions" button carry data-act/data-dev and run against the live session
// (no navigation, no fresh signature).
document.addEventListener('click', (ev) => {
  const b = ev.target.closest('[data-act]');
  if (!b) return;
  ev.preventDefault();
  accountAction(b.getAttribute('data-act'), b.getAttribute('data-dev') || null);
});

// Authenticated landing: read actions auto-run on load (no button); destructive
// actions render their own single confirm button (handled above). The empty
// landing action shows the menu, which navigates normally.
(function () {
  if (!AUTHED || !ACTION) return;
  const AUTO_RUN = [
    'org.matrix.profile',
    'org.matrix.devices_list', 'org.matrix.sessions_list',
    'org.matrix.device_view', 'org.matrix.session_view',
    'org.matrix.account_reactivate',
    'org.matrix.cross_signing_reset'
  ];
  if (AUTO_RUN.indexOf(ACTION) !== -1) accountAction(ACTION, DEVICE_ID);
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_page_renders_cross_signing_reset() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Reset encryption keys"));
        assert!(html.contains("cross-signing keys"));
        assert!(html.contains(r#"data-action="org.matrix.cross_signing_reset""#));
        assert!(html.contains(r#"data-base="https://siwx.example.com""#));
    }

    #[test]
    fn account_page_renders_without_action() {
        let html = account_page(
            AccountPageQuery {
                action: None,
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Account"));
        assert!(html.contains("Manage your account"));
        assert!(html.contains(r#"data-action="""#));
    }

    #[test]
    fn account_page_empty_action_renders_menu() {
        // Element Web's generic "Manage account" opens the bare page (no action).
        // It must render a navigable menu, NOT the auth buttons.
        let html = account_page(
            AccountPageQuery {
                action: None,
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("action=org.matrix.profile"),
            "menu must link to profile"
        );
        assert!(
            html.contains("action=org.matrix.devices_list"),
            "menu must link to sessions"
        );
        assert!(
            html.contains("action=org.matrix.account_deactivate"),
            "menu must link to deactivate"
        );
        // The auth BUTTONS (which invoke authWallet on click) must be absent so
        // an empty action is never POSTed. The bare `authWallet` function lives
        // in the shared embedded JS regardless, so assert on the onclick that is
        // unique to the rendered button, not on the function name.
        assert!(
            !html.contains(r#"onclick="authWallet()""#),
            "menu must NOT render the auth buttons (no empty-action POST)"
        );
    }

    #[test]
    fn account_page_deactivate_shows_confirmation() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.account_deactivate".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("permanently"),
            "deactivate gate must warn it is permanent"
        );
        assert!(
            html.contains("cannot be undone"),
            "deactivate gate must warn it cannot be undone"
        );
        assert!(
            html.contains(r#"id="confirm-deactivate""#),
            "deactivate gate must have the confirm checkbox"
        );
        assert!(
            html.contains(r#"onclick="authWallet()" disabled>"#),
            "deactivate gate must start with the wallet button disabled"
        );
        assert!(
            html.contains(r#"onclick="authPasskey()" disabled>"#),
            "deactivate gate must start with the passkey button disabled"
        );
        assert!(
            html.contains(r#"onclick="authWallet()""#),
            "deactivate gate still has the (gated) auth buttons"
        );
    }

    #[test]
    fn account_page_erase_shows_stronger_confirmation() {
        // AC3/AC5: erasure is irreversible and must gate the auth buttons behind
        // a danger confirmation that is stronger than deactivate: it warns the
        // erasure is permanent AND that profile/media/room memberships are
        // deleted, behind a #confirm-erase checkbox.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.account_erase".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("irreversible"),
            "erase gate must warn it is irreversible"
        );
        assert!(
            html.contains("permanently deletes"),
            "erase gate must warn it permanently deletes data"
        );
        assert!(
            html.to_lowercase().contains("room membership"),
            "erase gate must spell out profile/media/room memberships are deleted"
        );
        assert!(
            html.contains(r#"id="confirm-erase""#),
            "erase gate must have the #confirm-erase checkbox"
        );
        assert!(
            html.contains(r#"onclick="authWallet()" disabled>"#),
            "erase gate must start with the wallet button disabled"
        );
        assert!(
            html.contains(r#"onclick="authPasskey()" disabled>"#),
            "erase gate must start with the passkey button disabled"
        );
    }

    #[test]
    fn account_page_menu_links_erase() {
        // The bare /account home menu must offer a danger-styled erase entry.
        let html = account_page(
            AccountPageQuery {
                action: None,
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("action=org.matrix.account_erase"),
            "home menu must link to account_erase"
        );
        // It must be the danger-styled entry (stronger than deactivate's link).
        assert!(
            html.contains(r#"class="btn btn-danger" href="https://siwx.example.com/account?action=org.matrix.account_erase""#),
            "erase menu entry must be danger-styled"
        );
    }

    #[test]
    fn account_page_reactivate_is_benign_no_scary_gate() {
        // Reactivation is benign: it keeps the plain auth buttons (no confirm
        // gate, buttons NOT disabled) and renders its own title.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.account_reactivate".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("Reactivate account"),
            "reactivate page must have its own title"
        );
        assert!(
            html.contains(r#"onclick="authWallet()""#)
                && !html.contains(r#"onclick="authWallet()" disabled>"#),
            "reactivate must keep the (enabled) auth buttons, no confirm gate"
        );
        assert!(
            !html.contains(r#"id="confirm-erase""#),
            "reactivate must not show the erase confirm gate"
        );
    }

    #[test]
    fn account_page_js_renders_erased_and_reactivated_and_gates_confirm() {
        // The page JS must render the new outcomes and wire #confirm-erase.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.account_erase".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("case 'erased':"),
            "JS must render the erased outcome"
        );
        assert!(
            html.contains("case 'reactivated':"),
            "JS must render the reactivated outcome"
        );
        assert!(
            html.contains("confirm-erase"),
            "JS must reference the confirm-erase checkbox"
        );
    }

    #[test]
    fn account_page_normal_action_keeps_auth_buttons() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.profile".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains(r#"onclick="authWallet()""#),
            "normal action keeps wallet button"
        );
        assert!(
            html.contains(r#"onclick="authPasskey()""#),
            "normal action keeps passkey button"
        );
        assert!(
            !html.contains(r#"id="confirm-deactivate""#),
            "normal action has no deactivate confirm gate"
        );
        assert!(
            !html.contains("action=org.matrix.devices_list"),
            "normal action does not render the menu"
        );
    }

    #[test]
    fn account_page_sanitizes_action() {
        let html = account_page(
            AccountPageQuery {
                action: Some("<script>alert(1)</script>".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("data-action=\"scriptalert1script\""));
    }

    #[test]
    fn account_page_uses_brand_styling() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("api.fontshare.com/css?f[]=satoshi"),
            "Satoshi font must be loaded"
        );
        assert!(
            html.contains("--accent: #E8611A"),
            "brand accent must be set"
        );
        assert!(
            html.contains("ambient-glow"),
            "ambient glow must be present"
        );
        assert!(html.contains("inblockio-logo.png"), "logo must be present");
    }

    #[test]
    fn account_page_has_wallet_and_passkey_buttons() {
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.cross_signing_reset".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Sign with wallet"));
        assert!(html.contains("Sign with passkey"));
        assert!(html.contains("/account/wallet"));
        assert!(html.contains("/account/passkey/start"));
        assert!(html.contains("/account/passkey/finish"));
    }

    #[test]
    fn account_page_renders_device_view_with_device_id() {
        // AC2: the device_view deep link must render without an "Unsupported
        // action" error and carry the device_id through to the client.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.device_view".to_string()),
                device_id: Some("ABCDEFGHIJ".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains(r#"data-action="org.matrix.device_view""#));
        assert!(html.contains(r#"data-device-id="ABCDEFGHIJ""#));
        assert!(html.contains("Session details"));
        assert!(!html.contains("Unsupported action"));
    }

    #[test]
    fn account_page_renders_session_alias_like_device() {
        // session_view must render identically to device_view (same title).
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.session_view".to_string()),
                device_id: Some("DEV".to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html.contains("Session details"));
    }

    #[test]
    fn account_page_titles_match_action() {
        let title_for = |action: &str| {
            account_page(
                AccountPageQuery {
                    action: Some(action.to_string()),
                    device_id: Some("D".to_string()),
                    id_token_hint: None,
                },
                "https://siwx.example.com",
            )
            .0
        };
        assert!(title_for("org.matrix.devices_list").contains("Your sessions"));
        assert!(title_for("org.matrix.profile").contains("Your account"));
        assert!(title_for("org.matrix.device_delete").contains("Sign out device"));
    }

    #[test]
    fn account_page_escapes_device_id_no_xss() {
        // A malicious device_id must not break out of the data-device-id attribute
        // or inject a <script>: the HTML metacharacters are escaped, not stripped.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.device_view".to_string()),
                device_id: Some(r#""><script>alert(1)</script>"#.to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(!html.contains("<script>alert"), "no raw script injection");
        assert!(
            !html.contains(r#"data-device-id=""><script"#),
            "the closing quote must be escaped so the attribute cannot break out"
        );
        assert!(
            html.contains(r#"data-device-id="&quot;&gt;&lt;script&gt;"#),
            "device_id metacharacters must be HTML-escaped, not stripped"
        );
    }

    #[test]
    fn account_page_preserves_base64_device_id() {
        // REGRESSION: matrix-rust-sdk / Element X device ids are standard base64
        // (contain '/', '+', '='). The page must embed them VERBATIM so the
        // device_view / device_delete deep link can match the real device.
        let dev = "MjGFNfjj95k5VngxejhaWTG0i0/apJk84AyFCtzlVjQ";
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.device_view".to_string()),
                device_id: Some(dev.to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains(&format!(r#"data-device-id="{dev}""#)),
            "base64 device id (with '/') must be preserved verbatim, got page:\n{}",
            &html[..html.find("data-device-id").map(|i| i + 80).unwrap_or(0)]
        );
        // And the plus/equals variants survive too.
        let dev2 = "dU+Mpp7R3CwoAmVUyJlVEFxpdxxDQbx3OD9Gtv0OxnU=";
        let html2 = account_page(
            AccountPageQuery {
                action: Some("org.matrix.device_delete".to_string()),
                device_id: Some(dev2.to_string()),
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(html2.contains(&format!(r#"data-device-id="{dev2}""#)));
    }

    #[test]
    fn account_page_js_has_outcome_render_hooks() {
        // The page JS must render every ActionOutcome kind (H8).
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.devices_list".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        for hook in [
            "renderOutcome",
            "renderDevices",
            "renderDevice",
            "result-section",
            "org.matrix.device_delete",
            "org.matrix.devices_list",
            "DEVICE_ID",
        ] {
            assert!(html.contains(hook), "account page JS missing hook: {hook}");
        }
    }

    #[test]
    fn account_page_js_renders_deactivated_and_gates_confirm() {
        // The page JS must render the 'deactivated' outcome and wire the
        // confirm-deactivate checkbox to the auth buttons.
        let html = account_page(
            AccountPageQuery {
                action: Some("org.matrix.account_deactivate".to_string()),
                device_id: None,
                id_token_hint: None,
            },
            "https://siwx.example.com",
        )
        .0;
        assert!(
            html.contains("case 'deactivated':"),
            "JS must render the deactivated outcome"
        );
        assert!(
            html.contains("Account deactivated"),
            "deactivated terminal title must be present"
        );
        assert!(
            html.contains("confirm-deactivate"),
            "JS must reference the confirm-deactivate checkbox"
        );
    }

    #[test]
    fn sanitize_action_strips_unsafe_chars() {
        assert_eq!(sanitize_action(""), "");
        assert_eq!(
            sanitize_action("org.matrix.cross_signing_reset"),
            "org.matrix.cross_signing_reset"
        );
        assert_eq!(
            sanitize_action("<script>alert(1)</script>"),
            "scriptalert1script"
        );
        assert_eq!(sanitize_action("'; DROP TABLE--"), "DROPTABLE");
        assert_eq!(sanitize_action(&"A".repeat(100)).len(), 64);
    }

    #[test]
    fn canonical_action_maps_stable_names() {
        assert_eq!(
            canonical_action("org.matrix.profile"),
            Some(Action::Profile)
        );
        assert_eq!(
            canonical_action("org.matrix.devices_list"),
            Some(Action::DevicesList)
        );
        assert_eq!(
            canonical_action("org.matrix.device_view"),
            Some(Action::DeviceView)
        );
        assert_eq!(
            canonical_action("org.matrix.device_delete"),
            Some(Action::DeviceDelete)
        );
        assert_eq!(
            canonical_action("org.matrix.cross_signing_reset"),
            Some(Action::CrossSigningReset)
        );
    }

    #[test]
    fn canonical_action_accepts_account_deactivate() {
        assert_eq!(
            canonical_action("org.matrix.account_deactivate"),
            Some(Action::AccountDeactivate)
        );
    }

    #[test]
    fn canonical_action_accepts_erase_and_reactivate() {
        assert_eq!(
            canonical_action("org.matrix.account_erase"),
            Some(Action::AccountErase)
        );
        assert_eq!(
            canonical_action("org.matrix.account_reactivate"),
            Some(Action::Reactivate)
        );
    }

    #[test]
    fn supported_actions_include_erase_and_reactivate() {
        // H6/AC5: both new lifecycle actions must be advertised (and so flow into
        // OIDC discovery), and every advertised action must be dispatchable.
        assert!(
            SUPPORTED_ACTIONS.contains(&"org.matrix.account_erase"),
            "SUPPORTED_ACTIONS must advertise account_erase"
        );
        assert!(
            SUPPORTED_ACTIONS.contains(&"org.matrix.account_reactivate"),
            "SUPPORTED_ACTIONS must advertise account_reactivate"
        );
        for action in SUPPORTED_ACTIONS {
            assert!(
                canonical_action(action).is_some(),
                "advertised action {action} has no canonical mapping"
            );
        }
    }

    #[test]
    fn erase_and_reactivate_outcomes_serialize_with_kind_tag() {
        use serde_json::json;
        assert_eq!(
            serde_json::to_value(ActionOutcome::Erased).unwrap(),
            json!({ "kind": "erased" })
        );
        assert_eq!(
            serde_json::to_value(ActionOutcome::Reactivated).unwrap(),
            json!({ "kind": "reactivated" })
        );
    }

    #[test]
    fn parse_action_empty_is_missing_action() {
        match parse_action("") {
            Err(CustomError::BadRequest(msg)) => assert!(
                msg.contains("Missing action"),
                "empty action message should say 'Missing action', got: {msg}"
            ),
            other => panic!("expected BadRequest(Missing action), got {other:?}"),
        }
    }

    #[test]
    fn parse_action_unknown_is_unsupported_action() {
        match parse_action("org.matrix.foo") {
            Err(CustomError::BadRequest(msg)) => assert!(
                msg.contains("Unsupported action: org.matrix.foo"),
                "unknown action message should echo the action, got: {msg}"
            ),
            other => panic!("expected BadRequest(Unsupported action), got {other:?}"),
        }
    }

    #[test]
    fn parse_action_known_returns_action() {
        assert_eq!(
            parse_action("org.matrix.account_deactivate").unwrap(),
            Action::AccountDeactivate
        );
    }

    #[test]
    fn canonical_action_collapses_session_aliases() {
        // session_* aliases must behave identically to their device_* form.
        assert_eq!(
            canonical_action("org.matrix.sessions_list"),
            canonical_action("org.matrix.devices_list")
        );
        assert_eq!(
            canonical_action("org.matrix.session_view"),
            canonical_action("org.matrix.device_view")
        );
        assert_eq!(
            canonical_action("org.matrix.session_end"),
            canonical_action("org.matrix.device_delete")
        );
    }

    #[test]
    fn canonical_action_rejects_unknown() {
        assert_eq!(canonical_action("org.matrix.unknown"), None);
        assert_eq!(canonical_action(""), None);
        assert_eq!(canonical_action("device_view"), None); // missing namespace
    }

    #[test]
    fn supported_actions_cover_acceptance_criteria() {
        // AC1: the advertised set must contain at least these four real actions
        // plus their session_* aliases, plus cross_signing_reset.
        for required in [
            "org.matrix.profile",
            "org.matrix.devices_list",
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.cross_signing_reset",
            "org.matrix.account_deactivate",
            "org.matrix.sessions_list",
            "org.matrix.session_view",
            "org.matrix.session_end",
        ] {
            assert!(
                SUPPORTED_ACTIONS.contains(&required),
                "SUPPORTED_ACTIONS missing {required}"
            );
        }
        // Every advertised action must be dispatchable (no advertised-but-unhandled drift).
        for action in SUPPORTED_ACTIONS {
            assert!(
                canonical_action(action).is_some(),
                "advertised action {action} has no canonical mapping"
            );
        }
    }

    // -- Prerequisite guards (H6/H7) ------------------------------------------

    #[test]
    fn require_device_id_rejects_missing_and_empty() {
        assert!(require_device_id(None).is_err());
        assert!(require_device_id(Some("")).is_err());
        assert_eq!(require_device_id(Some("DEV")).unwrap(), "DEV");
    }

    #[test]
    fn require_server_name_rejects_missing_and_empty() {
        assert!(require_server_name(None).is_err());
        assert!(require_server_name(Some("")).is_err());
        assert_eq!(
            require_server_name(Some("matrix.example.com")).unwrap(),
            "matrix.example.com"
        );
    }

    #[test]
    fn require_synapse_rejects_absent_client() {
        assert!(require_synapse(None).is_err());
        let client = SynapseClient::new("http://synapse", "secret");
        assert!(require_synapse(Some(&client)).is_ok());
    }

    #[test]
    fn escape_device_id_attr_preserves_base64_escapes_markup() {
        // Plain Synapse ids and base64 (matrix-rust-sdk) ids pass through verbatim.
        assert_eq!(escape_device_id_attr("SIWX_2b1f-9c"), "SIWX_2b1f-9c");
        assert_eq!(escape_device_id_attr("OztBTB56qC"), "OztBTB56qC");
        assert_eq!(
            escape_device_id_attr("MjGFNfjj95k5VngxejhaWTG0i0/apJk84AyFCtzlVjQ"),
            "MjGFNfjj95k5VngxejhaWTG0i0/apJk84AyFCtzlVjQ"
        );
        assert_eq!(escape_device_id_attr("dU+Mpp/v0=="), "dU+Mpp/v0==");
        // HTML metacharacters are escaped (not stripped) so they cannot break out.
        assert_eq!(
            escape_device_id_attr(r#""><script>x</script>"#),
            "&quot;&gt;&lt;script&gt;x&lt;/script&gt;"
        );
        assert_eq!(escape_device_id_attr("a&b"), "a&amp;b");
        // Length is capped (after counting chars, before escaping expands).
        assert!(escape_device_id_attr(&"A".repeat(300)).len() <= 255);
    }

    // -- ActionOutcome wire contract (H3/H8) ----------------------------------

    #[test]
    fn action_outcome_serializes_with_kind_tag() {
        use serde_json::json;
        assert_eq!(
            serde_json::to_value(ActionOutcome::Completed).unwrap(),
            json!({"kind": "completed"})
        );
        assert_eq!(
            serde_json::to_value(ActionOutcome::Deleted {
                device_id: "DEV".to_string()
            })
            .unwrap(),
            json!({"kind": "deleted", "device_id": "DEV"})
        );
        assert_eq!(
            serde_json::to_value(ActionOutcome::Deactivated).unwrap(),
            json!({"kind": "deactivated"})
        );
        let profile = serde_json::to_value(ActionOutcome::Profile {
            did: "did:pkh:eip155:1:0xabc".to_string(),
            user_id: "@did-pkh-eip155-1-0xabc:matrix.example.com".to_string(),
        })
        .unwrap();
        assert_eq!(profile["kind"], "profile");
        assert_eq!(
            profile["user_id"],
            "@did-pkh-eip155-1-0xabc:matrix.example.com"
        );
    }

    #[test]
    fn account_action_response_flattens_outcome() {
        let resp = AccountActionResponse {
            status: "completed".to_string(),
            action: "org.matrix.device_view".to_string(),
            csrf: None,
            outcome: ActionOutcome::Device {
                device: DeviceInfo {
                    device_id: "DEV".to_string(),
                    display_name: Some("Element".to_string()),
                    last_seen_ip: None,
                    last_seen_ts: None,
                },
            },
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["status"], "completed");
        assert_eq!(v["action"], "org.matrix.device_view");
        assert_eq!(v["kind"], "device"); // flattened from the outcome
        assert_eq!(v["device"]["device_id"], "DEV");
    }

    // -- execute_action dispatch (H6/H7) --------------------------------------
    //
    // These connect to Redis on localhost and skip cleanly if it is unavailable.
    // The guard branches exercised here fail before any Synapse network call.

    async fn test_redis() -> Option<RedisClient> {
        RedisClient::new(&url::Url::parse("redis://localhost").unwrap())
            .await
            .ok()
    }

    #[tokio::test]
    async fn execute_profile_builds_user_id_without_synapse() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let outcome = execute_action(
            Action::Profile,
            None,
            "did:pkh:eip155:1:0xABC",
            None, // no Synapse needed for profile
            &redis,
            Some("matrix.example.com"),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ActionOutcome::Profile {
                did: "did:pkh:eip155:1:0xABC".to_string(),
                user_id: "@did-pkh-eip155-1-0xabc:matrix.example.com".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn execute_device_view_requires_device_id() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let err = execute_action(
            Action::DeviceView,
            None,
            "did:test",
            None,
            &redis,
            Some("matrix.example.com"),
        )
        .await;
        assert!(err.is_err(), "device_view without device_id must error");
    }

    #[tokio::test]
    async fn execute_device_actions_require_synapse() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // DevicesList with no Synapse client -> clear error, no panic.
        let err = execute_action(
            Action::DevicesList,
            None,
            "did:test",
            None,
            &redis,
            Some("matrix.example.com"),
        )
        .await;
        assert!(err.is_err(), "devices_list requires Synapse");

        // cross_signing_reset preserves prior behaviour (requires Synapse).
        let err = execute_action(
            Action::CrossSigningReset,
            None,
            "did:test",
            None,
            &redis,
            None,
        )
        .await;
        assert!(err.is_err(), "cross_signing_reset requires Synapse");
    }

    #[tokio::test]
    async fn execute_action_deactivate_requires_synapse() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // account_deactivate with no Synapse client must degrade to a clear
        // BadRequest (never a 500), matching the device actions.
        let err = execute_action(
            Action::AccountDeactivate,
            None,
            "did:test",
            None,
            &redis,
            Some("matrix.example.com"),
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::BadRequest(_))),
            "account_deactivate without Synapse must be a BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_action_erase_requires_synapse() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // AccountErase with no Synapse client must degrade to a clear BadRequest
        // (never a 500), matching the other Synapse-backed actions.
        let err = execute_action(
            Action::AccountErase,
            None,
            "did:test",
            None,
            &redis,
            Some("matrix.example.com"),
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::BadRequest(_))),
            "account_erase without Synapse must be a BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_action_reactivate_requires_synapse() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // Reactivate with no Synapse client must degrade to a clear BadRequest.
        let err = execute_action(
            Action::Reactivate,
            None,
            "did:test",
            None,
            &redis,
            Some("matrix.example.com"),
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::BadRequest(_))),
            "account_reactivate without Synapse must be a BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_action_reactivate_requires_server_name() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let client = SynapseClient::new("http://synapse", "secret");
        // Synapse present but server_name missing -> error before any network call.
        let err = execute_action(
            Action::Reactivate,
            None,
            "did:test",
            Some(&client),
            &redis,
            None,
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::BadRequest(_))),
            "reactivate without server_name must be a BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn execute_device_view_requires_server_name() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let client = SynapseClient::new("http://synapse", "secret");
        // device_id present + Synapse present, but server_name missing -> error
        // before any network call.
        let err = execute_action(
            Action::DeviceView,
            Some("DEV"),
            "did:test",
            Some(&client),
            &redis,
            None,
        )
        .await;
        assert!(err.is_err(), "device_view requires server_name");
    }

    // -- Account session + session-backed action (Fix C) ----------------------

    #[tokio::test]
    async fn account_session_roundtrips_and_unknown_token_is_none() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let did = "did:pkh:eip155:1:0xSESSION";
        let (token, csrf) = create_account_session(&redis, did).await.unwrap();
        let s = lookup_account_session(&redis, &token)
            .await
            .expect("freshly created session must be found");
        assert_eq!(s.did, did);
        assert_eq!(s.csrf, csrf);
        assert!(
            lookup_account_session(&redis, "no-such-token")
                .await
                .is_none(),
            "an unknown token must not resolve to a session"
        );
        destroy_account_session(&redis, &token).await;
        assert!(
            lookup_account_session(&redis, &token).await.is_none(),
            "a destroyed session must not resolve"
        );
    }

    #[tokio::test]
    async fn account_action_requires_a_session() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let err = account_action(
            &redis,
            None, // no session cookie
            AccountActionRequest {
                action: "org.matrix.profile".to_string(),
                device_id: None,
                csrf: None,
            },
            None,
            Some("matrix.test"),
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::Unauthorized(_))),
            "no session must be Unauthorized, got {err:?}"
        );
    }

    #[tokio::test]
    async fn account_action_rejects_csrf_mismatch() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let (token, _csrf) = create_account_session(&redis, "did:pkh:eip155:1:0xCSRF")
            .await
            .unwrap();
        let err = account_action(
            &redis,
            Some(&token),
            AccountActionRequest {
                action: "org.matrix.profile".to_string(),
                device_id: None,
                csrf: Some("wrong-token".to_string()),
            },
            None,
            Some("matrix.test"),
        )
        .await;
        assert!(
            matches!(err, Err(CustomError::Unauthorized(_))),
            "csrf mismatch must be Unauthorized, got {err:?}"
        );
    }

    #[tokio::test]
    async fn account_action_with_valid_session_runs_without_signature() {
        let Some(redis) = test_redis().await else {
            return;
        };
        let did = "did:pkh:eip155:1:0xRUN";
        let (token, csrf) = create_account_session(&redis, did).await.unwrap();
        // Profile needs only server_name (no Synapse), so it exercises the
        // session+csrf path end-to-end without a network dependency.
        let resp = account_action(
            &redis,
            Some(&token),
            AccountActionRequest {
                action: "org.matrix.profile".to_string(),
                device_id: None,
                csrf: Some(csrf),
            },
            None,
            Some("matrix.test"),
        )
        .await
        .expect("valid session + csrf must execute the action");
        assert!(matches!(resp.outcome, ActionOutcome::Profile { .. }));
    }
}
