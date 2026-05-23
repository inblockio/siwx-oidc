//! MSC3861 token introspection endpoint (RFC 7662).
//!
//! When `mas_shared_secret` is configured, this module provides:
//! - `POST /oauth2/introspect` for Synapse to validate opaque access tokens
//! - `generate_opaque_token` for issuing `mat_`/`mcr_`-prefixed tokens

use axum::{
    extract::{Form, State},
    http::StatusCode,
    Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use siwx_oidc::db::DBClient;

use super::axum_lib::IntrospectState;

/// Base62 alphabet for opaque token generation.
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Generate an opaque token with a given prefix and 32 random base62 characters.
///
/// Access tokens use prefix `mat_`, refresh tokens use `mcr_`.
pub fn generate_opaque_token(prefix: &str) -> String {
    let mut rng = thread_rng();
    let random: String = (0..32)
        .map(|_| BASE62[rng.gen_range(0..62)] as char)
        .collect();
    format!("{}{}", prefix, random)
}

/// Form body for the introspection request.
#[derive(Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    /// RFC 7662 hint (e.g. "access_token", "refresh_token"). Not used for lookup
    /// but accepted per spec.
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    /// client_secret_post auth: client_id in form body (accepted but not validated).
    #[serde(default)]
    #[allow(dead_code)]
    pub client_id: Option<String>,
    /// client_secret_post auth: client_secret in form body (alternative to Bearer).
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// RFC 7662 introspection endpoint.
///
/// Authentication (either method accepted):
/// - `Authorization: Bearer {shared_secret}` (Bearer token)
/// - `client_id=X&client_secret={shared_secret}` in form body (client_secret_post)
///
/// Body: `token=X&token_type_hint=access_token` (form-urlencoded)
///
/// Returns active token metadata or `{"active": false}`.
pub async fn introspect(
    State(state): State<IntrospectState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Form(form): Form<IntrospectForm>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let secret = state.mas_shared_secret.as_ref().ok_or_else(|| {
        warn!("introspect: endpoint called but mas_shared_secret not configured");
        StatusCode::NOT_FOUND
    })?;

    // Accept either Bearer token OR client_secret in form body (client_secret_post).
    let provided = if let Some(ref b) = bearer {
        b.token().as_bytes()
    } else if let Some(ref cs) = form.client_secret {
        cs.as_bytes()
    } else {
        warn!("introspect: no Bearer token or client_secret provided");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let expected = secret.as_bytes();
    if provided.len() != expected.len() || !bool::from(provided.ct_eq(expected)) {
        warn!("introspect: invalid shared secret");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Look up the token in Redis.
    let metadata = state
        .redis_client
        .get_token(&form.token)
        .await
        .map_err(|e| {
            debug!("introspect: Redis error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match metadata {
        Some(m) if m.exp > Utc::now().timestamp() => {
            let now = Utc::now().timestamp();
            Ok(Json(serde_json::json!({
                "active": true,
                "username": m.username,
                "device_id": m.device_id,
                "scope": m.scope,
                "sub": m.did,
                "name": m.name,
                "client_id": m.client_id,
                "token_type": "Bearer",
                "exp": m.exp,
                "expires_in": m.exp - now,
                "iat": m.iat,
            })))
        }
        _ => Ok(Json(serde_json::json!({"active": false}))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_opaque_token_format() {
        let token = generate_opaque_token("mat_");
        assert!(token.starts_with("mat_"));
        // prefix (4) + 32 random chars = 36
        assert_eq!(token.len(), 36);
        // All chars after prefix are base62.
        for c in token[4..].chars() {
            assert!(c.is_ascii_alphanumeric());
        }
    }

    #[test]
    fn test_generate_refresh_token_format() {
        let token = generate_opaque_token("mcr_");
        assert!(token.starts_with("mcr_"));
        assert_eq!(token.len(), 36);
    }

    #[test]
    fn test_tokens_are_unique() {
        let t1 = generate_opaque_token("mat_");
        let t2 = generate_opaque_token("mat_");
        assert_ne!(t1, t2);
    }
}
