//! Matrix legacy compatibility endpoints and OAuth2 token revocation (MSC3861).
//!
//! Provides:
//! - `POST /oauth2/revoke` (RFC 7009)
//! - `GET /_matrix/client/v3/login` (login flows discovery)
//! - `POST /_matrix/client/v3/logout` (single-session logout)
//! - `POST /_matrix/client/v3/logout/all` (bulk sign-out, all sessions)
//! - `DELETE /_matrix/client/v3/devices/{device_id}` and
//!   `POST /_matrix/client/v3/delete_devices` (legacy in-client device sign-out)
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
//! precisely because the id is not reused. Apart from the Matrix-shaped
//! `refresh`, none of this code touches sign-in or token issuance (`oidc.rs`);
//! see `docs/matrix-integration.md`, "Accounts and devices".

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

// Use the binary crate's own `synapse_client` module (the same one `axum_lib`
// and `account` use) so `CompatState.synapse_client` is type-compatible with
// `AppState.synapse_client`. The lib crate used to re-expose the same file as
// `siwx_oidc::synapse_client`, which was a *distinct* type here; it no longer
// does (see the note in `src/lib.rs`).
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::grant::{InvalidReason, RotateOutcome, RotateRequest};
use siwx_oidc::db::{DBClient, RedisClient, TokenKind, ACCESS_TOKEN_TTL};

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
/// `required` is the token kind the caller accepts: `Some(Access)` for logout,
/// whose bearer must be an access token, and `None` for RFC 7009 revoke, which
/// accepts either kind. A token of another kind is answered like an unknown
/// token: nothing is torn down and the token itself is left untouched.
///
/// Never fails the caller: every error is logged and swallowed so the HTTP
/// handler can always return 200 (RFC 7009 for revoke; Matrix expects 200 for
/// logout). Keyed on [`TokenMetadata::username`] (the lowercased localpart
/// Synapse uses), never the raw DID, so revocation is robust to address-case
/// differences between sign-in and re-auth DIDs.
async fn teardown_session(
    state: &CompatState,
    token: &str,
    ctx: &str,
    policy: TeardownPolicy,
    required: Option<TokenKind>,
) {
    let meta = match resolve_presented(state, token).await {
        Ok(Some(m)) => m,
        // Unknown token: an idempotent no-op.
        Ok(None) => return,
        Err(e) => {
            warn!(error = %e, ctx, "teardown_session: token lookup failed; deleting the presented token");
            // Best effort: whichever layout the token is in.
            let _ = state.redis_client.delete_access_token(token).await;
            if let Err(e) = state.redis_client.delete_token(token).await {
                warn!(error = %e, ctx, "teardown_session: delete_token (fallback) failed");
            }
            return;
        }
    };
    if required.is_some_and(|kind| meta.kind != Some(kind)) {
        debug!(
            ctx,
            "teardown_session: token of another kind; nothing to tear down"
        );
        return;
    }
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
    // the presented session (RFC 7009), revoke only the presented credential when
    // there is no device_id: an access token alone, or a refresh token's whole
    // grant (RFC 7009 §2.1; its live access token goes with it). In Synapse mode
    // the device_id is a unique `SIWX_{uuid}`, so revoking by (username,
    // device_id) correctly scopes to this one device's grants.
    if meta.device_id.is_empty() {
        match delete_presented(state, token, meta.source).await {
            Ok(()) => info!(
                ctx,
                username = %meta.username,
                "session torn down (standalone, presented token only)"
            ),
            Err(e) => {
                warn!(error = %e, ctx, "teardown_session: deleting the presented token failed")
            }
        }
        return;
    }
    // Phase 2 (device session): revoke this device's grants (access + refresh).
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
            if let Err(e) = delete_presented(state, token, meta.source).await {
                warn!(error = %e, ctx, "teardown_session: deleting the presented token (last resort) failed");
            }
        }
    }
}

/// Where a presented token is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSource {
    /// A grant's access token (`at/{digest}`).
    GrantAccess,
    /// A grant's refresh token that the refresh endpoints would accept now.
    GrantRefresh,
    /// A `token/{raw}` entry written before the grant record.
    Legacy,
}

/// What teardown needs to know about a presented token.
struct PresentedToken {
    username: String,
    device_id: String,
    kind: Option<TokenKind>,
    source: TokenSource,
}

/// Resolve a token for teardown: a grant's live access token, a grant's refresh
/// token the refresh endpoints would accept (a superseded one is unknown), or a
/// legacy entry.
///
/// TODO(M3): the legacy read stays while legacy refresh tokens (90 days) can
/// still be presented; the migration decides when it goes.
async fn resolve_presented(
    state: &CompatState,
    token: &str,
) -> anyhow::Result<Option<PresentedToken>> {
    if let Some(access) = state.redis_client.lookup_access_token(token).await? {
        return Ok(Some(PresentedToken {
            username: access.grant.username,
            device_id: access.grant.device_id,
            kind: Some(TokenKind::Access),
            source: TokenSource::GrantAccess,
        }));
    }
    if let Some(grant) = state.redis_client.resolve_refresh_token(token).await? {
        return Ok(Some(PresentedToken {
            username: grant.username,
            device_id: grant.device_id,
            kind: Some(TokenKind::Refresh),
            source: TokenSource::GrantRefresh,
        }));
    }
    Ok(state.redis_client.get_token(token).await?.map(|m| {
        let kind = [TokenKind::Access, TokenKind::Refresh]
            .into_iter()
            .find(|k| m.is_kind(*k));
        PresentedToken {
            username: m.username,
            device_id: m.device_id,
            kind,
            source: TokenSource::Legacy,
        }
    }))
}

/// Delete only the presented credential: an access token's entry (its grant
/// stays), a refresh token's whole grant (D-M1-1, RFC 7009 §2.1), or a legacy
/// entry.
async fn delete_presented(
    state: &CompatState,
    token: &str,
    source: TokenSource,
) -> anyhow::Result<()> {
    match source {
        TokenSource::GrantAccess => state
            .redis_client
            .delete_access_token(token)
            .await
            .map(|_| ()),
        TokenSource::GrantRefresh => state
            .redis_client
            .revoke_grant_of_token(token)
            .await
            .map(|_| ()),
        TokenSource::Legacy => state.redis_client.delete_token(token).await,
    }
}

// -- POST /oauth2/revoke (RFC 7009) -------------------------------------------

pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    // RFC 7009 is token hygiene, not a device sign-out: revoke tokens only, never
    // delete the Synapse device (see TeardownPolicy).
    // Either kind of token may be revoked.
    teardown_session(
        &state,
        &form.token,
        "revoke",
        TeardownPolicy::TokensOnly,
        None,
    )
    .await;
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
        // The bearer must be an access token.
        teardown_session(
            &state,
            auth.token(),
            "logout",
            TeardownPolicy::DeleteDevice,
            Some(TokenKind::Access),
        )
        .await;
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

    let meta = match state.redis_client.check_access_token(auth.token()).await {
        // The bearer must be an access token; any other entry is a no-op like an
        // unknown token.
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::OK, Json(serde_json::json!({}))), // idempotent no-op
        Err(e) => {
            warn!(error = %e, "logout_all: token lookup failed");
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
// Synapse device via the MAS API (`/_synapse/mas/delete_device`), and revoke that
// device's OAuth tokens. This is the same safe "delete an ending device" teardown
// as logout (the id is never reused), just initiated by the client's session
// manager.
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

/// Resolve the bearer token to its owning localpart (`TokenMetadata.username`).
///
/// `Ok(None)` when the token is missing, unknown, or not an access token: the
/// route answers `M_UNKNOWN_TOKEN`. `Err` when the store could not answer: the
/// route answers the retryable 503 (`token_store_unavailable`), never
/// `M_UNKNOWN_TOKEN`, which a Matrix client takes for "signed out".
async fn username_from_bearer(
    state: &CompatState,
    bearer: &Option<TypedHeader<Authorization<Bearer>>>,
) -> anyhow::Result<Option<String>> {
    let Some(TypedHeader(auth)) = bearer.as_ref() else {
        return Ok(None);
    };
    Ok(state
        .redis_client
        .check_access_token(auth.token())
        .await?
        .map(|m| m.username))
}

/// The bearer's owner for a device-deletion route, or the response to send:
/// `M_UNKNOWN_TOKEN` for an unknown bearer, the retryable 503 for a store fault.
async fn bearer_owner(
    state: &CompatState,
    bearer: &Option<TypedHeader<Authorization<Bearer>>>,
    ctx: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    match username_from_bearer(state, bearer).await {
        Ok(Some(username)) => Ok(username),
        Ok(None) => Err(unknown_token_response()),
        Err(e) => {
            warn!(error = %e, ctx, "bearer lookup: token store failed (infrastructure); returning retryable 503");
            Err(token_store_unavailable())
        }
    }
}

/// Delete one of `username`'s Synapse devices (MAS API) and revoke its tokens.
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
/// device id is a no-op, since the MAS delete is scoped to the user's localpart).
pub async fn delete_device(
    State(state): State<CompatState>,
    Path(device_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    let username = match bearer_owner(&state, &bearer, "compat_delete_device").await {
        Ok(username) => username,
        Err(response) => return response,
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
    let username = match bearer_owner(&state, &bearer, "compat_delete_devices").await {
        Ok(username) => username,
        Err(response) => return response,
    };
    for device_id in &body.devices {
        teardown_device(&state, &username, device_id, "compat_delete_devices").await;
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- POST /_matrix/client/v3/refresh ------------------------------------------

/// 503 for a token-store fault during a refresh or a bearer lookup: retryable,
/// never `M_UNKNOWN_TOKEN`.
fn token_store_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": "Token store temporarily unavailable; retry"
        })),
    )
}

/// `POST /_matrix/client/v3/refresh` (MSC2918): rotate a refresh token.
///
/// **Public clients only.** The OAuth refresh grant (`oidc::token_refresh`)
/// checks that the request comes from the client the token was issued to and
/// authenticates a confidential one (I7). The Matrix client-server API gives
/// this request no client identity (the body is the refresh token and nothing
/// else), so this endpoint cannot authenticate a client: it refuses, exactly
/// like an unknown token, the refresh token of a grant whose client is
/// confidential (recorded on the grant at issuance by
/// `oidc::client_is_confidential`, the rule the token endpoint applies), and
/// leaves it untouched for `POST /token`. A public client's token needs no
/// authentication, so this endpoint is bound as far as the binding reaches at
/// `POST /token` without a named client. Matrix clients (Element Web, Element
/// X) register as public clients. Do not "fix" the rest by demanding a client
/// here: no Matrix client can send one.
///
/// Rotation, the replay of a lost response and the refusals are the rotation
/// script's (`RedisClient::rotate_refresh_token`), the same one `POST /token`
/// runs.
pub async fn refresh(
    State(state): State<CompatState>,
    Json(body): Json<RefreshRequest>,
) -> impl IntoResponse {
    // The one rotation script (I3) decides atomically: rotate, replay the
    // unused successor of a lost response (I4), or refuse. No client is named
    // (this endpoint has none), and a confidential client's grant is refused
    // (see above).
    let outcome = state
        .redis_client
        .rotate_refresh_token(&RotateRequest {
            presented: &body.refresh_token,
            client_id: None,
            refuse_confidential: true,
        })
        .await;
    let (pair, expires_in) = match outcome {
        Ok(RotateOutcome::Rotated(rotated)) => (rotated.pair, ACCESS_TOKEN_TTL),
        Ok(RotateOutcome::Replayed(replayed)) => {
            let left = (replayed.pair.access_exp - Utc::now().timestamp()).max(0) as u64;
            (replayed.pair, left.min(ACCESS_TOKEN_TTL))
        }
        // Reuse (I5, phase A): recorded, and answered like an unknown token.
        Ok(RotateOutcome::Reuse(event)) => {
            event.emit();
            return invalid_refresh_token("Invalid refresh token");
        }
        Ok(RotateOutcome::Invalid(InvalidReason::Revoked)) => {
            debug!("refresh refused: device/account torn down");
            return invalid_refresh_token("Session has been revoked");
        }
        // TODO(M3): a legacy refresh token (`NotCurrentFormat`: `token/{raw}`,
        // written before the grant record) is lifted into a grant (design 5.8).
        // Until then it is an unknown token.
        // `ConfidentialClient`: a client this endpoint cannot authenticate
        // (see above), answered like an unknown token. `ClientMismatch` cannot
        // happen: no client is named.
        Ok(RotateOutcome::Invalid(_))
        | Ok(RotateOutcome::ClientMismatch)
        | Ok(RotateOutcome::ConfidentialClient) => {
            return invalid_refresh_token("Invalid refresh token");
        }
        Err(e) => {
            // Infrastructure failure, NOT an authorization failure. `M_UNKNOWN_TOKEN`
            // is terminal for a Matrix client (it signs out and clears its crypto
            // store, and under MSC3861 Synapse never offers a soft logout), so
            // reporting a Redis error that way would turn a transient fault into
            // permanent session and cryptographic-identity loss. 503 is retryable,
            // and the script either ran entirely or not at all.
            warn!(error = %e, "refresh: token store failed (infrastructure); returning retryable 503");
            return token_store_unavailable();
        }
    };

    debug!("refresh: tokens rotated successfully");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": pair.access_token,
            "expires_in_ms": expires_in * 1000,
            "refresh_token": pair.refresh_token,
        })),
    )
}

/// `M_UNKNOWN_TOKEN` for a refresh token this endpoint refuses.
fn invalid_refresh_token(error: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "errcode": "M_UNKNOWN_TOKEN",
            "error": error
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Form, State};
    use axum::response::IntoResponse;
    use siwx_oidc::db::grant::{GrantKind, IssuedGrant, NewGrant};
    use siwx_oidc::db::tokens;
    use siwx_oidc::db::{DBClient, TokenMetadata};

    /// The test Redis, or `None` after a loud skip (`siwx_oidc::test_support`).
    async fn redis() -> Option<RedisClient> {
        siwx_oidc::test_support::redis().await
    }

    /// A unique nonce so parallel tests / stale entries never collide on the
    /// shared Redis instance. The nanosecond clock alone can collide across tests
    /// that start in the same instant on different threads, so a process-wide
    /// atomic counter is OR'd in to guarantee uniqueness for any run subset.
    fn nonce() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        (base << 20) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF)
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
            kind: Some(TokenKind::Access),
        }
    }

    fn refresh_meta(username: &str, device_id: &str) -> TokenMetadata {
        TokenMetadata {
            kind: Some(TokenKind::Refresh),
            ..token_meta(username, device_id)
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

    /// The bearer of a logout, bulk logout or device deletion must be an access
    /// token. A refresh token there is answered like an unknown token: nothing
    /// is torn down, and the refresh token itself survives.
    #[tokio::test]
    async fn a_refresh_token_as_the_bearer_tears_nothing_down() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("kind-bearer-{n}");
        let dev = format!("KIND_{n}");
        let access = format!("compat_kind_access_{n}");
        let refresh = format!("compat_kind_refresh_{n}");
        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &refresh_meta(&user, &dev), 120)
            .await
            .unwrap();
        let state = standalone_state(client.clone());

        let resp = logout(State(state.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout answers 200");
        let resp = logout_all(State(state.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout/all answers 200");
        let resp = delete_device(State(state.clone()), Path(dev.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "device deletion refuses a refresh token as its bearer"
        );

        assert!(
            client.get_token(&access).await.unwrap().is_some(),
            "the session's access token survives"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_some(),
            "the presented refresh token is left untouched"
        );
        client.delete_token(&access).await.ok();
        client.delete_token(&refresh).await.ok();
    }

    /// `POST /_matrix/client/v3/refresh` with a refresh token: status and JSON body.
    async fn matrix_refresh(state: &CompatState, token: &str) -> (StatusCode, serde_json::Value) {
        let response = refresh(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: token.to_string(),
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// A grant with a refresh token, for the refresh and revoke tests.
    async fn seed_grant(client: &RedisClient, user: &str, dev: &str) -> IssuedGrant {
        seed_grant_for(client, user, dev, false).await
    }

    /// A grant with a refresh token issued to a public or a confidential client.
    async fn seed_grant_for(
        client: &RedisClient,
        user: &str,
        dev: &str,
        confidential_client: bool,
    ) -> IssuedGrant {
        client
            .issue_grant(&NewGrant {
                kind: if dev.is_empty() {
                    GrantKind::Oidc
                } else {
                    GrantKind::MatrixDevice
                },
                username: user.to_string(),
                did: format!("did:key:z{user}"),
                client_id: "compat-test".into(),
                confidential_client,
                device_id: dev.to_string(),
                scope: "openid".into(),
                name: user.to_string(),
                auth_time: Utc::now().timestamp(),
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: Some(120),
            })
            .await
            .unwrap()
    }

    /// `POST /_matrix/client/v3/refresh` carries no client identity, so it
    /// cannot authenticate a confidential client (I7): it refuses that client's
    /// refresh token exactly like an unknown token and leaves it untouched, so
    /// the client can still refresh at `POST /token` with its secret. A public
    /// client's token rotates there as before.
    #[tokio::test]
    async fn the_matrix_endpoint_refuses_a_confidential_clients_refresh_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("conf-user-{n}");
        let dev = format!("CONF_{n}");
        let state = standalone_state(client.clone());

        let never_issued = tokens::new_refresh_token(&tokens::new_grant_handle());
        let (_, unknown) = matrix_refresh(&state, &never_issued).await;
        let confidential = seed_grant_for(&client, &user, &dev, true)
            .await
            .refresh_token
            .unwrap();
        let (status, body) = matrix_refresh(&state, &confidential).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a confidential client's refresh token is refused: {body}"
        );
        assert_eq!(body, unknown, "refused exactly like an unknown token");
        let grant = client
            .resolve_refresh_token(&confidential)
            .await
            .unwrap()
            .expect("the refused token is still the grant's current refresh token");
        assert_eq!(grant.generation, 0, "the refusal rotated nothing");

        let public = seed_grant_for(&client, &user, &dev, false)
            .await
            .refresh_token
            .unwrap();
        let (status, body) = matrix_refresh(&state, &public).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a public client's token rotates: {body}"
        );

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// A store fault: Redis answers the operation that reads `key` with an
    /// error (`WRONGTYPE`: a string planted where a hash is read). The handler
    /// gets the same `Err` from the store that a lost connection, a timeout or
    /// an out-of-memory refusal gives it. The key expires on its own.
    async fn plant_store_fault(key: &str) {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: () = bb8_redis::redis::cmd("SET")
            .arg(key)
            .arg("planted store fault")
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    /// The retryable answer to a store fault: 503 with `M_UNKNOWN`.
    fn assert_retryable_503(status: StatusCode, body: &serde_json::Value, what: &str) {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{what}: a store fault is a retryable 503: {body}"
        );
        assert_eq!(
            body["errcode"], "M_UNKNOWN",
            "{what}: never M_UNKNOWN_TOKEN, which signs a Matrix client out: {body}"
        );
    }

    /// A store fault during `POST /_matrix/client/v3/refresh` is a retryable
    /// 503, never `M_UNKNOWN_TOKEN`: a Matrix client treats that as "signed
    /// out" and clears its crypto store, so a transient Redis fault would cost
    /// the session and its cryptographic identity.
    #[tokio::test]
    async fn a_store_fault_at_the_matrix_refresh_endpoint_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let rt = tokens::new_refresh_token(&tokens::new_grant_handle());
        let handle = tokens::parse_refresh_token(&rt).unwrap().handle;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_GRANT_PREFIX,
            siwx_oidc::db::grant::GrantId::of_handle(handle).as_str()
        ))
        .await;

        let (status, body) = matrix_refresh(&state, &rt).await;
        assert_retryable_503(status, &body, &format!("refresh {n}"));
    }

    /// A store fault while resolving the bearer of a device-deletion route is
    /// the same retryable 503 as at the refresh endpoint, never the
    /// `M_UNKNOWN_TOKEN` 401 of an unknown token.
    #[tokio::test]
    async fn a_store_fault_on_a_bearer_route_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("fault-user-{n}");
        let dev = format!("FAULT_{n}");
        let state = standalone_state(client.clone());
        let access = seed_grant(&client, &user, &dev).await.access_token;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            tokens::digest(&access)
        ))
        .await;

        let response = delete_device(State(state.clone()), Path(dev.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "DELETE /devices/{id}");

        let response = delete_devices(
            State(state.clone()),
            bearer(&access),
            Json(DeleteDevicesRequest {
                devices: vec![dev.clone()],
            }),
        )
        .await
        .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "POST /delete_devices");

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    async fn status_and_json(
        response: axum::response::Response,
    ) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The Matrix endpoint's replay follows the rule of the OAuth grant (I4):
    /// it returns the successor pair only while that pair is live and unused.
    /// After the successor was rotated away or its grant revoked, the replay is
    /// answered like an unknown token. (The endpoint cannot bind the replay to
    /// a client: the Matrix API carries none.)
    #[tokio::test]
    async fn a_matrix_refresh_replay_needs_its_successor_live() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("replay-user-{n}");
        let dev = format!("REPLAY_{n}");
        let state = standalone_state(client.clone());

        // Rotated: the client received the successor and has since used it.
        let old = seed_grant(&client, &user, &dev)
            .await
            .refresh_token
            .unwrap();
        let (status, first) = matrix_refresh(&state, &old).await;
        assert_eq!(status, StatusCode::OK, "the rotation succeeds: {first}");
        let successor = first["refresh_token"].as_str().unwrap().to_string();

        let (status, replay) = matrix_refresh(&state, &old).await;
        assert_eq!(status, StatusCode::OK, "a replay with a live successor");
        assert_eq!(
            replay["refresh_token"], first["refresh_token"],
            "while the successor is live the replay returns the same pair"
        );

        let (status, second) = matrix_refresh(&state, &successor).await;
        assert_eq!(status, StatusCode::OK, "the successor rotates: {second}");
        let (status, body) = matrix_refresh(&state, &old).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a replay whose successor was rotated gets no pair: {body}"
        );
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");

        // Revoked: the successor's grant was deleted before the client used it.
        let old = seed_grant(&client, &user, &dev)
            .await
            .refresh_token
            .unwrap();
        let (_, first) = matrix_refresh(&state, &old).await;
        let successor = first["refresh_token"].as_str().unwrap().to_string();
        client
            .revoke_grant_of_token(&successor)
            .await
            .unwrap()
            .expect("the successor's grant is revoked");
        let (status, body) = matrix_refresh(&state, &old).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a replay whose successor was revoked gets no pair: {body}"
        );
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// D-M1-1 (provisional): RFC 7009 revoke of a deviceless grant's refresh
    /// token revokes the whole grant, its live access token included (RFC 7009
    /// §2.1); revoking its access token removes only that access token.
    #[tokio::test]
    async fn revoking_a_deviceless_refresh_token_revokes_its_grant_an_access_token_only_itself() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let revoke_token = |token: &str| {
            revoke(
                State(state.clone()),
                Form(RevokeForm {
                    token: token.to_string(),
                    token_type_hint: None,
                }),
            )
        };

        let by_refresh = seed_grant(&client, &format!("grant-revoke-rt-{n}"), "").await;
        let refresh_token = by_refresh.refresh_token.clone().unwrap();
        assert_eq!(revoke_token(&refresh_token).await, StatusCode::OK);
        assert!(
            client
                .check_access_token(&by_refresh.access_token)
                .await
                .unwrap()
                .is_none(),
            "revoking the refresh token takes the grant's access token with it"
        );
        let (status, body) = matrix_refresh(&state, &refresh_token).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the refresh token is gone: {body}"
        );

        let by_access = seed_grant(&client, &format!("grant-revoke-at-{n}"), "").await;
        assert_eq!(revoke_token(&by_access.access_token).await, StatusCode::OK);
        assert!(
            client
                .check_access_token(&by_access.access_token)
                .await
                .unwrap()
                .is_none(),
            "the access token is revoked"
        );
        let (status, body) =
            matrix_refresh(&state, by_access.refresh_token.as_deref().unwrap()).await;
        assert_eq!(status, StatusCode::OK, "the grant itself survives: {body}");
    }

    /// RFC 7009 revoke accepts either kind: a refresh token is revoked.
    #[tokio::test]
    async fn revoke_accepts_a_refresh_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("kind-revoke-{n}");
        let refresh = format!("compat_kind_revoke_{n}");
        client
            .set_token(&refresh, &refresh_meta(&user, ""), 120)
            .await
            .unwrap();
        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: refresh.clone(),
            token_type_hint: None,
        };
        assert_eq!(revoke(State(state), Form(form)).await, StatusCode::OK);
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "revoke removes a refresh token"
        );
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
