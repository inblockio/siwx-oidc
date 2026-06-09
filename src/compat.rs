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
//! Logout and revocation tear down the *ending* session: when a Synapse client
//! and `server_name` are configured they delete that session's Synapse device
//! (a clean, one-time deletion of a session that is going away) and then revoke
//! the OAuth tokens for it. This is deliberately distinct from device *recycling*
//! (re-issuing the same `device_id` with new keys), which Synapse cannot do
//! cleanly: its `delete_device` does not drop the device's
//! `e2e_cross_signing_signatures` rows, and the signature-upload handler then
//! skips fresh uploads. Sign-in therefore never deletes-then-reuses a device id;
//! it upserts a fresh `SIWX_{uuid}`. Deleting a device that is *ending* (here) is
//! safe precisely because the id is not reused. None of this code touches sign-in
//! or token issuance (`oidc.rs`); see CLAUDE.md "MSC3861 device lifecycle".

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
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

/// Tear down the single session identified by `token`.
///
/// Two-phase, best-effort, idempotent, and graceful:
/// 1. If the token resolves to [`TokenMetadata`] AND a Synapse client +
///    `server_name` are configured, delete that session's Synapse device
///    (best-effort: a failure is logged at `warn!` and does not abort), then
///    revoke every OAuth token for `(username, device_id)` in Redis (this
///    removes the access token and its paired refresh token).
/// 2. If the token is unknown (already gone, or this is a no-op call) OR there
///    is no Synapse integration, fall back to deleting just this token so the
///    behaviour is at least the prior Redis-only teardown.
///
/// Never fails the caller: every error is logged and swallowed so the HTTP
/// handler can always return 200 (RFC 7009 for revoke; Matrix expects 200 for
/// logout). Keyed on [`TokenMetadata::username`] (the lowercased localpart
/// Synapse uses), never the raw DID, so revocation is robust to address-case
/// differences between sign-in and re-auth DIDs.
async fn teardown_session(state: &CompatState, token: &str, ctx: &str) {
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

    // Phase 1: delete the ending session's Synapse device (best-effort).
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

    // Phase 2: revoke the OAuth session's tokens (access + paired refresh).
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
    teardown_session(&state, &form.token, "revoke").await;
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
        teardown_session(&state, auth.token(), "logout").await;
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
}
