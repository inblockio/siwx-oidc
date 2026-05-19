//! Matrix legacy compatibility endpoints and OAuth2 token revocation (MSC3861).
//!
//! Provides:
//! - `POST /oauth2/revoke` (RFC 7009)
//! - `GET /_matrix/client/v3/login` (login flows discovery)
//! - `POST /_matrix/client/v3/logout` (session logout)
//! - `POST /_matrix/client/v3/refresh` (token refresh)

use axum::{
    extract::State,
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
use std::sync::Arc;
use tracing::{debug, warn};

use crate::introspect::generate_opaque_token;
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::{DBClient, RedisClient, TokenMetadata, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};

// -- Shared state for compat endpoints ----------------------------------------

#[derive(Clone)]
pub struct CompatState {
    pub redis_client: RedisClient,
    pub synapse_client: Option<Arc<SynapseClient>>,
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

// -- POST /oauth2/revoke (RFC 7009) -------------------------------------------

pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    // Look up token metadata so we can clean up the Synapse device.
    if let Ok(Some(meta)) = state.redis_client.get_token(&form.token).await {
        if let Some(ref synapse) = state.synapse_client {
            if let Err(e) = synapse.delete_device(&meta.username, &meta.device_id).await {
                warn!("revoke: delete_device failed: {}", e);
            }
        }
    }
    if let Err(e) = state.redis_client.delete_token(&form.token).await {
        warn!(error = %e, "revoke: failed to delete token from Redis");
    }
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

pub async fn logout(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    if let Some(TypedHeader(auth)) = bearer {
        if let Ok(Some(meta)) = state.redis_client.get_token(auth.token()).await {
            if let Some(ref synapse) = state.synapse_client {
                if let Err(e) = synapse.delete_device(&meta.username, &meta.device_id).await {
                    warn!("logout: delete_device failed: {}", e);
                }
            }
        }
        if let Err(e) = state.redis_client.delete_token(auth.token()).await {
            warn!(error = %e, "logout: failed to delete token from Redis");
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
