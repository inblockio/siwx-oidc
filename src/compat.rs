//! Matrix legacy compatibility endpoints and OAuth2 token revocation (MSC3861).
//!
//! Provides:
//! - `POST /oauth2/revoke` (RFC 7009)
//! - `GET /_matrix/client/v3/login` (login flows discovery)
//! - `POST /_matrix/client/v3/logout` (single-session logout)
//! - `POST /_matrix/client/v3/logout/all` (bulk sign-out, all sessions)
//! - `POST /_matrix/client/v3/refresh` (token refresh)
//!
//! ## Session teardown vs. account deactivation
//!
//! Teardown always revokes the *ending* session's OAuth tokens. Whether it also
//! deletes the Synapse device depends on the caller's intent (see
//! [`TeardownPolicy`]): an explicit `POST /_matrix/client/v3/logout` deletes the
//! device; a bare RFC 7009 `POST /oauth2/revoke` is token hygiene and does NOT
//! (clients fire revoke on rotation and on dialog dismissals, where deleting the
//! device strands the user's identity — the 2026-06-12 login incident).
//!
//! Deleting a device that is *ending* (on explicit logout) is distinct from device
//! *recycling* (re-issuing the same `device_id` with new keys), which Synapse
//! cannot do cleanly: its `delete_device` does not drop the device's
//! `e2e_cross_signing_signatures` rows, and the signature-upload handler then
//! skips fresh uploads. Sign-in therefore never deletes-then-reuses a device id;
//! it upserts a fresh `SIWX_{uuid}`, so the explicit-logout delete is safe
//! precisely because the id is not reused. None of this code touches sign-in or
//! token issuance (`oidc.rs`); see CLAUDE.md "MSC3861 device lifecycle".

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::introspect::generate_opaque_token;
// Use the binary crate's own `synapse_client` module (the same one `axum_lib`
// and `account` use) so `CompatState.synapse_client` is type-compatible with
// `AppState.synapse_client`. The lib crate re-exposes the same file as
// `siwx_oidc::synapse_client`, which is a *distinct* type here.
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::{DBClient, RedisClient, TokenMetadata, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};

// -- Shared state for compat endpoints ----------------------------------------

#[derive(Clone)]
pub struct CompatState {
    pub redis_client: RedisClient,
    /// Synapse client for MSC3861 device teardown. `None` in standalone mode,
    /// where teardown degrades to Redis-only token revocation.
    pub synapse_client: Option<Arc<SynapseClient>>,
    /// Matrix `server_name` (e.g. `matrix.inblock.io`), needed to build the
    /// mxid for Synapse admin-API device calls. `None` in standalone mode.
    pub server_name: Option<String>,
}

// -- Request/response types ---------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeForm {
    pub token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// -- Session teardown (shared by logout + revoke) -----------------------------

/// Whether a teardown is allowed to delete the ending session's Synapse device.
///
/// Deleting a Synapse device is destructive: it drops the device's E2EE / cross
/// signing state, and if it races an in-flight key upload it strands the user's
/// identity. It must therefore be driven by an explicit "sign this device out"
/// intent, never by transport-level token hygiene.
///
/// - A bare RFC 7009 `POST /oauth2/revoke` is token hygiene: clients fire it on
///   token rotation and on dialog dismissals (Element's forced-recovery loop
///   revoked tokens on every escape). Deleting the device there destroyed devices
///   mid-flight and wedged accounts (2026-06-12 login incident, amplifier B). So
///   revoke is [`TeardownPolicy::TokensOnly`].
/// - `POST /_matrix/client/v3/logout` is an explicit sign-out, so it is
///   [`TeardownPolicy::DeleteDevice`]. (The MSC4191 `device_delete` / `session_end`
///   actions in `account.rs` are the other explicit-intent path and delete there.)
///
/// Device ids are never recycled (sign-in upserts a fresh `SIWX_{uuid}`), so in
/// Synapse mode exactly one session references a given device; an explicit logout
/// can delete it safely without racing another live session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TeardownPolicy {
    /// Revoke the session's OAuth tokens only; leave the Synapse device intact.
    TokensOnly,
    /// Revoke tokens AND delete the ending session's Synapse device.
    DeleteDevice,
}

impl TeardownPolicy {
    /// True only for explicit-sign-out callers that should delete the device.
    fn deletes_device(self) -> bool {
        matches!(self, TeardownPolicy::DeleteDevice)
    }
}

/// Tear down the single session identified by `token`.
///
/// Two-phase, best-effort, idempotent, and graceful:
/// 1. If `policy` is [`TeardownPolicy::DeleteDevice`] AND the token resolves to
///    [`TokenMetadata`] AND a Synapse client + `server_name` are configured,
///    delete that session's Synapse device (best-effort: a failure is logged at
///    `warn!` and does not abort). [`TeardownPolicy::TokensOnly`] skips this
///    entirely, so a bare RFC 7009 revoke never destroys a device.
/// 2. Always revoke the OAuth tokens for the session: every token for
///    `(username, device_id)` in Redis (access + paired refresh), or just the
///    presented token when there is no device_id / no Synapse integration.
///
/// Never fails the caller: every error is logged and swallowed so the HTTP
/// handler can always return 200 (RFC 7009 for revoke; Matrix expects 200 for
/// logout). Keyed on [`TokenMetadata::username`] (the lowercased localpart
/// Synapse uses), never the raw DID, so revocation is robust to address-case
/// differences between sign-in and re-auth DIDs.
async fn teardown_session(state: &CompatState, token: &str, ctx: &str, policy: TeardownPolicy) {
    let meta = match state.redis_client.get_token(token).await {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, ctx, "teardown_session: get_token failed; falling back to delete_token");
            None
        }
    };

    let Some(meta) = meta else {
        // Unknown token (idempotent no-op) or lookup error: best-effort delete.
        if let Err(e) = state.redis_client.delete_token(token).await {
            warn!(error = %e, ctx, "teardown_session: delete_token (fallback) failed");
        }
        return;
    };

    // Phase 1: delete the ending session's Synapse device (best-effort) — only for
    // explicit-sign-out callers. A bare RFC 7009 revoke (TokensOnly) must never
    // delete a device: that is what wedged users in the 2026-06-12 login incident.
    if policy.deletes_device() {
        if let (Some(synapse), Some(server_name)) =
            (state.synapse_client.as_ref(), state.server_name.as_deref())
        {
            if meta.device_id.is_empty() {
                debug!(
                    ctx,
                    username = %meta.username,
                    "teardown_session: token has no device_id; skipping Synapse device delete"
                );
            } else if let Err(e) = synapse
                .delete_device(&meta.username, &meta.device_id, server_name)
                .await
            {
                warn!(error = %e, ctx, username = %meta.username, device_id = %meta.device_id,
                    "teardown_session: Synapse delete_device failed (best-effort)");
            }
        }
    }

    // Phase 2: revoke the OAuth session's tokens.
    //
    // Single-session semantics: in standalone mode every token carries an empty
    // device_id, so `revoke_device_tokens(username, "")` would match (and revoke)
    // EVERY session of that user. To keep single-session logout / revoke scoped to
    // the presented session (RFC 7009), revoke only the presented token when there
    // is no device_id. In Synapse mode the device_id is a unique `SIWX_{uuid}`, so
    // revoking by (username, device_id) correctly scopes to this one device's
    // access + paired refresh tokens.
    if meta.device_id.is_empty() {
        match state.redis_client.delete_token(token).await {
            Ok(()) => info!(
                ctx,
                username = %meta.username,
                "session torn down (standalone, presented token only)"
            ),
            Err(e) => {
                warn!(error = %e, ctx, "teardown_session: delete_token failed")
            }
        }
        return;
    }

    // Phase 2 (device session): revoke this device's tokens (access + paired refresh).
    match state
        .redis_client
        .revoke_device_tokens(&meta.username, &meta.device_id)
        .await
    {
        Ok(revoked) => info!(
            ctx,
            username = %meta.username,
            device_id = %meta.device_id,
            revoked = revoked as u64,
            "session torn down"
        ),
        Err(e) => {
            warn!(error = %e, ctx, "teardown_session: revoke_device_tokens failed; deleting token directly");
            // Last-resort: at least remove the presented token.
            if let Err(e) = state.redis_client.delete_token(token).await {
                warn!(error = %e, ctx, "teardown_session: delete_token (last resort) failed");
            }
        }
    }
}

// -- POST /oauth2/revoke (RFC 7009) -------------------------------------------

pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    // RFC 7009 is token hygiene, not a device sign-out: revoke tokens only, never
    // delete the Synapse device (see TeardownPolicy).
    teardown_session(&state, &form.token, "revoke", TeardownPolicy::TokensOnly).await;
    StatusCode::OK
}

// -- GET /_matrix/client/v3/login ---------------------------------------------

pub async fn login_flows() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "flows": [{
            "type": "m.login.sso",
            "identity_providers": [{
                "id": "siwx-oidc",
                "name": "Sign in with Wallet"
            }]
        }]
    }))
}

// -- POST /_matrix/client/v3/logout -------------------------------------------

/// Single-session logout: tears down the session bound to the bearer token
/// (Synapse device + Redis tokens). Always returns 200 with `{}` (Matrix
/// expects an empty object), even with no bearer or an unknown token.
pub async fn logout(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    if let Some(TypedHeader(auth)) = bearer {
        // Explicit single-session sign-out: revoke tokens AND delete the device.
        teardown_session(&state, auth.token(), "logout", TeardownPolicy::DeleteDevice).await;
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- POST /_matrix/client/v3/logout/all ---------------------------------------

/// Bulk sign-out: invalidates EVERY session of the bearer token's user.
///
/// Resolves the user from the bearer token, then (when Synapse + `server_name`
/// are configured) lists the user's Synapse devices and deletes each one
/// best-effort (a per-device failure is logged and the loop continues), and
/// finally revokes ALL of the user's OAuth tokens in Redis.
///
/// This is session invalidation, NOT account deactivation: the account stays
/// active and the user can sign in again. It therefore must NEVER call
/// `deactivate_user`. Degrades to Redis-only revocation in standalone mode and
/// is an idempotent 200 no-op when the bearer token is missing or unknown.
pub async fn logout_all(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    let Some(TypedHeader(auth)) = bearer else {
        return (StatusCode::OK, Json(serde_json::json!({})));
    };

    let meta = match state.redis_client.get_token(auth.token()).await {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::OK, Json(serde_json::json!({}))), // idempotent no-op
        Err(e) => {
            warn!(error = %e, "logout_all: get_token failed");
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    };
    let username = meta.username;

    // Phase 1: delete every Synapse device for the user (best-effort per device).
    if let (Some(synapse), Some(server_name)) =
        (state.synapse_client.as_ref(), state.server_name.as_deref())
    {
        match synapse.list_devices(&username, server_name).await {
            Ok(devices) => {
                for dev in devices {
                    if let Err(e) = synapse
                        .delete_device(&username, &dev.device_id, server_name)
                        .await
                    {
                        warn!(error = %e, username = %username, device_id = %dev.device_id,
                            "logout_all: Synapse delete_device failed (best-effort, continuing)");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, username = %username,
                    "logout_all: Synapse list_devices failed; revoking Redis tokens anyway");
            }
        }
    }

    // Phase 2: ALWAYS revoke every OAuth token for the user (never deactivate).
    match state.redis_client.revoke_all_user_tokens(&username).await {
        Ok(revoked) => {
            info!(username = %username, revoked = revoked as u64, "all sessions torn down")
        }
        Err(e) => {
            warn!(error = %e, username = %username, "logout_all: revoke_all_user_tokens failed")
        }
    }

    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- Legacy CS-API device management (MSC3861 delegated) ----------------------
//
// Element's in-client "session manager" signs a device out with the legacy CS
// API (`DELETE /_matrix/client/v3/devices/{id}` or `POST .../delete_devices`),
// NOT the MSC4191 account-page deep link. Under MSC3861 the homeserver delegates
// auth, so — when the deployment proxies these specific paths to siwx-oidc — we
// service them here: resolve the user from their bearer token, delete the target
// Synapse device via the admin API, and revoke that device's OAuth tokens. This
// is the same safe "delete an ending device" teardown as logout/revoke (the id is
// never reused), just initiated by the client's session manager.
//
// We accept the bearer as sufficient authorization (no UIA challenge): auth is
// delegated to us, so a valid access token already proves the caller, mirroring
// how MAS makes delegated device deletion UIA-free.

/// Body of `POST /_matrix/client/v3/delete_devices`.
#[derive(Deserialize)]
pub struct DeleteDevicesRequest {
    #[serde(default)]
    pub devices: Vec<String>,
}

/// Resolve the bearer token to its owning localpart (`TokenMetadata.username`),
/// or `None` if the token is missing/unknown.
async fn username_from_bearer(
    state: &CompatState,
    bearer: &Option<TypedHeader<Authorization<Bearer>>>,
) -> Option<String> {
    let TypedHeader(auth) = bearer.as_ref()?;
    state
        .redis_client
        .get_token(auth.token())
        .await
        .ok()
        .flatten()
        .map(|m| m.username)
}

/// Delete one of `username`'s Synapse devices (admin API) and revoke its tokens.
/// Best-effort, idempotent, never fails the caller — same teardown as logout.
async fn teardown_device(state: &CompatState, username: &str, device_id: &str, ctx: &str) {
    if device_id.is_empty() {
        return;
    }
    if let (Some(synapse), Some(server_name)) =
        (state.synapse_client.as_ref(), state.server_name.as_deref())
    {
        if let Err(e) = synapse
            .delete_device(username, device_id, server_name)
            .await
        {
            warn!(error = %e, ctx, username = %username, device_id = %device_id,
                "compat device teardown: Synapse delete_device failed (best-effort)");
        }
    }
    match state
        .redis_client
        .revoke_device_tokens(username, device_id)
        .await
    {
        Ok(revoked) => info!(
            ctx,
            username = %username, device_id = %device_id, revoked = revoked as u64,
            "compat device torn down"
        ),
        Err(e) => warn!(error = %e, ctx, "compat device teardown: revoke_device_tokens failed"),
    }
}

const UNKNOWN_TOKEN: &str = "M_UNKNOWN_TOKEN";

fn unknown_token_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "errcode": UNKNOWN_TOKEN,
            "error": "Invalid or missing access token"
        })),
    )
}

/// `DELETE /_matrix/client/v3/devices/{device_id}` — sign out a single device
/// from the in-client session manager. Scoped to the bearer's user (a foreign
/// device id is a no-op, since the admin delete is mxid-scoped).
pub async fn delete_device(
    State(state): State<CompatState>,
    Path(device_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    let Some(username) = username_from_bearer(&state, &bearer).await else {
        return unknown_token_response();
    };
    teardown_device(&state, &username, &device_id, "compat_delete_device").await;
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /_matrix/client/v3/delete_devices` — bulk sign-out of specific devices.
pub async fn delete_devices(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(body): Json<DeleteDevicesRequest>,
) -> impl IntoResponse {
    let Some(username) = username_from_bearer(&state, &bearer).await else {
        return unknown_token_response();
    };
    for device_id in &body.devices {
        teardown_device(&state, &username, device_id, "compat_delete_devices").await;
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- POST /_matrix/client/v3/refresh ------------------------------------------

pub async fn refresh(
    State(state): State<CompatState>,
    Json(body): Json<RefreshRequest>,
) -> impl IntoResponse {
    // Look up the refresh token.
    let metadata = match state.redis_client.get_token(&body.refresh_token).await {
        Ok(Some(m)) => m,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Invalid refresh token"
                })),
            );
        }
    };

    // Verify the refresh token has not expired.
    if metadata.exp <= Utc::now().timestamp() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Invalid refresh token"
            })),
        );
    }

    // Generate new access token with same metadata.
    let new_access_token = generate_opaque_token("mat_");
    let now = Utc::now().timestamp();
    let access_meta = TokenMetadata {
        username: metadata.username.clone(),
        device_id: metadata.device_id.clone(),
        scope: metadata.scope.clone(),
        client_id: metadata.client_id.clone(),
        iat: now,
        exp: now + ACCESS_TOKEN_TTL as i64,
        did: metadata.did.clone(),
        name: metadata.name.clone(),
    };

    if let Err(e) = state
        .redis_client
        .set_token(&new_access_token, &access_meta, ACCESS_TOKEN_TTL)
        .await
    {
        warn!("refresh: failed to store new access token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "errcode": "M_UNKNOWN",
                "error": "Internal server error"
            })),
        );
    }

    // Rotate the refresh token.
    let new_refresh_token = generate_opaque_token("mcr_");
    let refresh_meta = TokenMetadata {
        username: metadata.username.clone(),
        device_id: metadata.device_id.clone(),
        scope: metadata.scope.clone(),
        client_id: metadata.client_id.clone(),
        iat: now,
        exp: now + REFRESH_TOKEN_TTL as i64,
        did: metadata.did.clone(),
        name: metadata.name.clone(),
    };

    if let Err(e) = state
        .redis_client
        .set_token(&new_refresh_token, &refresh_meta, REFRESH_TOKEN_TTL)
        .await
    {
        warn!("refresh: failed to store new refresh token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "errcode": "M_UNKNOWN",
                "error": "Internal server error"
            })),
        );
    }

    // Delete the old refresh token.
    let _ = state.redis_client.delete_token(&body.refresh_token).await;

    debug!(
        username = %metadata.username,
        "refresh: tokens rotated successfully"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": new_access_token,
            "expires_in_ms": ACCESS_TOKEN_TTL * 1000,
            "refresh_token": new_refresh_token,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Form, State};
    use axum::response::IntoResponse;
    use siwx_oidc::db::DBClient;
    use url::Url;

    /// Connect to the local Redis, or `None` if unavailable (CI provides one).
    async fn redis() -> Option<RedisClient> {
        RedisClient::new(&Url::parse("redis://localhost").unwrap())
            .await
            .ok()
    }

    /// A unique nanosecond nonce so parallel tests / stale entries never collide
    /// on the shared Redis instance.
    fn nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn token_meta(username: &str, device_id: &str) -> TokenMetadata {
        TokenMetadata {
            username: username.to_string(),
            device_id: device_id.to_string(),
            scope: "openid".to_string(),
            client_id: "c".to_string(),
            iat: 0,
            exp: i64::MAX,
            // did is stored verbatim from sign-in; revocation keys on username,
            // so the did case here intentionally differs from the username.
            did: format!("did:pkh:eip155:1:0X{}", username.to_uppercase()),
            name: "n".to_string(),
        }
    }

    /// Standalone-mode state: Redis only, no Synapse client / server_name.
    fn standalone_state(redis_client: RedisClient) -> CompatState {
        CompatState {
            redis_client,
            synapse_client: None,
            server_name: None,
        }
    }

    fn bearer(token: &str) -> Option<TypedHeader<Authorization<Bearer>>> {
        Some(TypedHeader(Authorization::bearer(token).unwrap()))
    }

    /// Policy mapping (no Redis needed): only an explicit sign-out deletes the
    /// Synapse device; a bare RFC 7009 revoke must not. Regression guard for the
    /// 2026-06-12 login incident, where revoke deleted a device on every dialog
    /// escape and wedged the user's cross-signing identity.
    #[test]
    fn teardown_policy_only_deletes_device_on_explicit_signout() {
        assert!(
            !TeardownPolicy::TokensOnly.deletes_device(),
            "RFC 7009 revoke must never delete the Synapse device"
        );
        assert!(
            TeardownPolicy::DeleteDevice.deletes_device(),
            "explicit logout must delete the ending session's device"
        );
    }

    /// H7: standalone (no Synapse) logout still revokes the session's Redis
    /// tokens (access + paired refresh) and returns 200.
    #[tokio::test]
    async fn logout_standalone_revokes_session_tokens() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("logout-user-{n}");
        let dev = format!("DEV_{n}");
        let access = format!("compat_logout_access_{n}");
        let refresh = format!("compat_logout_refresh_{n}");
        let other = format!("compat_logout_other_{n}");

        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        // Same user, different device: must survive a single-session logout.
        client
            .set_token(&other, &token_meta(&user, &format!("OTHER_{n}")), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout(State(state), bearer(&access)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&access).await.unwrap().is_none(),
            "access token of the session must be revoked"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "paired refresh token (same device) must be revoked"
        );
        assert!(
            client.get_token(&other).await.unwrap().is_some(),
            "another device's token must survive a single-session logout"
        );

        client.delete_token(&other).await.ok();
    }

    /// HIGH-defect regression guard: in standalone mode EVERY token carries an
    /// empty device_id, so `revoke_device_tokens(user, "")` would match every
    /// session of that user. A single-session logout must revoke ONLY the
    /// presented token (RFC 7009 / single-session semantics), leaving the user's
    /// other standalone sessions intact.
    #[tokio::test]
    async fn logout_standalone_empty_device_id_revokes_only_presented_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("empty-dev-user-{n}");
        let session_a = format!("compat_empty_a_{n}");
        let session_b = format!("compat_empty_b_{n}");

        // Two distinct standalone sessions for the SAME user, both device_id == "".
        client
            .set_token(&session_a, &token_meta(&user, ""), 120)
            .await
            .unwrap();
        client
            .set_token(&session_b, &token_meta(&user, ""), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout(State(state), bearer(&session_a))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&session_a).await.unwrap().is_none(),
            "the presented session token must be revoked"
        );
        assert!(
            client.get_token(&session_b).await.unwrap().is_some(),
            "a DIFFERENT standalone session of the same user must survive a single logout"
        );

        client.delete_token(&session_b).await.ok();
    }

    /// Same single-session guarantee for RFC 7009 revoke with empty device_id.
    #[tokio::test]
    async fn revoke_standalone_empty_device_id_revokes_only_presented_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("empty-dev-revoke-{n}");
        let session_a = format!("compat_empty_rev_a_{n}");
        let session_b = format!("compat_empty_rev_b_{n}");

        client
            .set_token(&session_a, &token_meta(&user, ""), 120)
            .await
            .unwrap();
        client
            .set_token(&session_b, &token_meta(&user, ""), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: session_a.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            client.get_token(&session_a).await.unwrap().is_none(),
            "the presented token must be revoked"
        );
        assert!(
            client.get_token(&session_b).await.unwrap().is_some(),
            "another standalone session of the same user must survive revoke"
        );

        client.delete_token(&session_b).await.ok();
    }

    /// H7: standalone revoke (RFC 7009) revokes the session's tokens and 200s.
    #[tokio::test]
    async fn revoke_standalone_revokes_session_tokens() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("revoke-user-{n}");
        let dev = format!("DEV_{n}");
        let access = format!("compat_revoke_access_{n}");
        let refresh = format!("compat_revoke_refresh_{n}");

        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &token_meta(&user, &dev), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: access.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            client.get_token(&access).await.unwrap().is_none(),
            "revoked access token must be gone"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "paired refresh token must be gone"
        );
    }

    /// Idempotency: logout / revoke with a token not in Redis must not panic and
    /// must still return 200.
    #[tokio::test]
    async fn logout_and_revoke_unknown_token_are_idempotent() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let unknown = format!("compat_unknown_{n}");

        let state = standalone_state(client.clone());
        let resp = logout(State(state.clone()), bearer(&unknown))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout no-op must 200");

        let form = RevokeForm {
            token: unknown.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK, "revoke no-op must 200");
    }

    /// logout with no Authorization header is a 200 no-op.
    #[tokio::test]
    async fn logout_without_bearer_is_noop_200() {
        let Some(client) = redis().await else { return };
        let state = standalone_state(client);
        let resp = logout(State(state), None).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// H3: logout_all revokes EVERY token for the user (across devices) and
    /// leaves other users untouched. Standalone mode (no Synapse): never
    /// deactivates, just revokes Redis tokens.
    #[tokio::test]
    async fn logout_all_revokes_all_user_tokens_standalone() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("logoutall-user-{n}");
        let other_user = format!("logoutall-other-{n}");
        let d1 = format!("DEV1_{n}");
        let d2 = format!("DEV2_{n}");
        let bearer_tok = format!("compat_la_bearer_{n}");
        let t2 = format!("compat_la_t2_{n}");
        let t3 = format!("compat_la_t3_{n}");
        let foreign = format!("compat_la_foreign_{n}");

        // Three tokens for the user across two devices (bearer + two more).
        client
            .set_token(&bearer_tok, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t2, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t3, &token_meta(&user, &d2), 120)
            .await
            .unwrap();
        // A different user's token must survive.
        client
            .set_token(&foreign, &token_meta(&other_user, &d1), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout_all(State(state), bearer(&bearer_tok))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        for (tok, label) in [
            (&bearer_tok, "bearer token"),
            (&t2, "same-device second token"),
            (&t3, "other-device token"),
        ] {
            assert!(
                client.get_token(tok).await.unwrap().is_none(),
                "logout_all must revoke the user's {label}"
            );
        }
        assert!(
            client.get_token(&foreign).await.unwrap().is_some(),
            "logout_all must not touch another user's token"
        );

        client.delete_token(&foreign).await.ok();
    }

    /// logout_all with no bearer / an unknown token is an idempotent 200 no-op
    /// and must not revoke unrelated tokens.
    #[tokio::test]
    async fn logout_all_no_bearer_or_unknown_is_noop() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let survivor = format!("compat_la_survivor_{n}");
        client
            .set_token(&survivor, &token_meta(&format!("u-{n}"), "D"), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());

        // No bearer.
        let resp = logout_all(State(state.clone()), None).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        // Unknown bearer.
        let resp = logout_all(State(state), bearer(&format!("compat_la_unknown_{n}")))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&survivor).await.unwrap().is_some(),
            "no-op logout_all must not revoke unrelated tokens"
        );
        client.delete_token(&survivor).await.ok();
    }

    // -- Legacy CS-API device delete (Fix A: client session-manager wiring) ---

    /// H5: `DELETE /devices/{id}` resolves the user from the bearer, revokes the
    /// TARGET device's tokens (standalone: no Synapse), and leaves other devices'
    /// tokens intact. Returns 200.
    #[tokio::test]
    async fn compat_delete_device_revokes_target_and_keeps_others() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("legacy-user-{n}");
        let bearer_tok = format!("compat_dd_bearer_{n}");
        let target_tok = format!("compat_dd_target_{n}");
        let other_tok = format!("compat_dd_other_{n}");

        // Bearer belongs to the user (its own device). Target + other are two of
        // the user's device sessions.
        client
            .set_token(&bearer_tok, &token_meta(&user, &format!("SELF_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&target_tok, &token_meta(&user, &format!("TARGET_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&other_tok, &token_meta(&user, &format!("OTHER_{n}")), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = delete_device(
            State(state),
            axum::extract::Path(format!("TARGET_{n}")),
            bearer(&bearer_tok),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&target_tok).await.unwrap().is_none(),
            "the targeted device's token must be revoked"
        );
        assert!(
            client.get_token(&other_tok).await.unwrap().is_some(),
            "a different device's token must survive"
        );
        // bearer's own session is untouched by deleting a *different* device.
        assert!(
            client.get_token(&bearer_tok).await.unwrap().is_some(),
            "the caller's own session must survive deleting another device"
        );

        client.delete_token(&bearer_tok).await.ok();
        client.delete_token(&other_tok).await.ok();
    }

    /// `DELETE /devices/{id}` with no/unknown bearer must be 401 (M_UNKNOWN_TOKEN).
    #[tokio::test]
    async fn compat_delete_device_unknown_bearer_is_401() {
        let Some(client) = redis().await else { return };
        let state = standalone_state(client);
        let resp = delete_device(
            State(state.clone()),
            axum::extract::Path("ANY".to_string()),
            None,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = delete_device(
            State(state),
            axum::extract::Path("ANY".to_string()),
            bearer("compat_dd_nope"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// H5: `POST /delete_devices` bulk-revokes every named device's tokens.
    #[tokio::test]
    async fn compat_delete_devices_bulk_revokes_each() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("bulk-user-{n}");
        let bearer_tok = format!("compat_bulk_bearer_{n}");
        let d1 = format!("D1_{n}");
        let d2 = format!("D2_{n}");
        let t1 = format!("compat_bulk_t1_{n}");
        let t2 = format!("compat_bulk_t2_{n}");

        client
            .set_token(&bearer_tok, &token_meta(&user, &format!("SELF_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&t1, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t2, &token_meta(&user, &d2), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = delete_devices(
            State(state),
            bearer(&bearer_tok),
            Json(DeleteDevicesRequest {
                devices: vec![d1.clone(), d2.clone()],
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&t1).await.unwrap().is_none(),
            "D1 token must be revoked"
        );
        assert!(
            client.get_token(&t2).await.unwrap().is_none(),
            "D2 token must be revoked"
        );
        client.delete_token(&bearer_tok).await.ok();
    }
}
