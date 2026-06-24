use axum::{
    extract::{Form, Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Router,
};
use axum_extra::{
    headers::{
        authorization::{Basic, Bearer},
        Authorization, ContentType,
    },
    TypedHeader,
};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use headers::Header;
use openidconnect::core::{
    CoreClientMetadata, CoreClientRegistrationResponse, CoreErrorResponseType, CoreJsonWebKeySet,
    CoreUserInfoClaims, CoreUserInfoJsonWebToken,
};
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::{
    classify::ServerErrorsFailureClass,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use webauthn_rs::prelude::*;

use super::account;
use super::compat;
use super::config;
use super::device_auth;
use super::introspect;
use super::oidc::{self, CustomError, EcdsaSigningKey};
use super::synapse_client::SynapseClient;
use super::webauthn as wa;
use aqua_auth::{all_cipher_suites, all_did_methods};
use openidconnect::JsonWebKeyId;
use siwx_oidc::db::*;

// -- Shared application state ----------------------------------------------

#[derive(Clone)]
struct AppState {
    signing_key: Arc<EcdsaSigningKey>,
    config: config::Config,
    redis_client: RedisClient,
    webauthn: Arc<Webauthn>,
    rp_id: String,
    rp_origin: String,
    synapse_client: Option<Arc<SynapseClient>>,
}

/// State subset exposed to the introspection endpoint.
#[derive(Clone)]
pub struct IntrospectState {
    pub mas_shared_secret: Option<String>,
    pub redis_client: RedisClient,
}

impl From<&AppState> for IntrospectState {
    fn from(state: &AppState) -> Self {
        Self {
            mas_shared_secret: state.config.mas_shared_secret.clone(),
            redis_client: state.redis_client.clone(),
        }
    }
}

// -- Error → Response conversion -------------------------------------------

impl IntoResponse for CustomError {
    fn into_response(self) -> Response {
        match &self {
            CustomError::BadRequest(msg) => {
                warn!(error = %msg, "bad_request");
            }
            CustomError::BadRequestRegister(e) => {
                warn!(error = ?e, "bad_request_register");
            }
            CustomError::BadRequestToken(e) => {
                warn!(error = ?e, "bad_request_token");
            }
            CustomError::Unauthorized(msg) => {
                warn!(error = %msg, "unauthorized");
            }
            CustomError::UnknownCredential(cred_id) => {
                // Expected user condition (stale/revoked passkey), NOT a server fault.
                warn!(credential_id = %cred_id, "unknown_credential");
            }
            CustomError::Other(e) => {
                warn!(error = %e, "internal_error");
            }
            CustomError::NotFound | CustomError::Redirect(_) => {}
        }

        match self {
            CustomError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            CustomError::BadRequestRegister(e) => {
                (StatusCode::BAD_REQUEST, Json(e)).into_response()
            }
            CustomError::BadRequestToken(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
            CustomError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            // 401 + machine-readable discriminator. The client keys on `error` to
            // call `signalUnknownCredential` and shows `message` to the user. The
            // echoed `credential_id` is the exact id the client just presented, so
            // signaling enumerates nothing the caller did not already hold.
            CustomError::UnknownCredential(cred_id) => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unknown_credential",
                    "credential_id": cred_id,
                    "message": "This passkey is no longer valid on this server. \
                                Remove it from your device's passkey settings, or sign \
                                in another way and register a new passkey.",
                })),
            )
                .into_response(),
            CustomError::NotFound => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
            CustomError::Redirect(uri) => Redirect::to(&uri).into_response(),
            CustomError::Other(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}

// -- Route handlers --------------------------------------------------------

async fn jwk_set(State(state): State<AppState>) -> Result<Json<CoreJsonWebKeySet>, CustomError> {
    let jwks = oidc::jwks(&state.signing_key)?;
    Ok(jwks.into())
}

async fn provider_metadata(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, CustomError> {
    let value = oidc::provider_metadata_value(
        state.config.base_url.clone(),
        state.config.account_management_uri.as_ref(),
    )?;
    Ok(value.into())
}

async fn token(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    basic: Option<TypedHeader<Authorization<Basic>>>,
    Form(form): Form<oidc::TokenForm>,
) -> Result<Json<serde_json::Value>, CustomError> {
    let secret = if let Some(b) = bearer {
        Some(b.0 .0.token().to_string())
    } else {
        basic.map(|b| b.0 .0.password().to_string())
    };
    let token_response = oidc::token(
        form,
        secret,
        &state.signing_key,
        &state.config,
        &state.redis_client,
        state.synapse_client.as_deref(),
    )
    .await
    .map_err(|e| {
        // OAuth2 RFC 6749 §5.2: token endpoint errors MUST be JSON.
        // Wrap non-Token errors so they always produce a JSON body.
        match e {
            CustomError::BadRequestToken(_) => e,
            CustomError::Unauthorized(msg) => CustomError::BadRequestToken(oidc::TokenError {
                error: CoreErrorResponseType::InvalidClient,
                error_description: msg,
            }),
            other => CustomError::BadRequestToken(oidc::TokenError {
                error: CoreErrorResponseType::InvalidRequest,
                error_description: other.to_string(),
            }),
        }
    })?;
    // Strip null fields (e.g. "id_token": null on refresh responses) because
    // oidc-client-ts treats a present-but-null id_token as a validation target
    // and fails when it cannot decode it as a JWT.
    let mut value = serde_json::to_value(token_response)
        .map_err(|e| anyhow::anyhow!("Failed to serialize token response: {}", e))?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.retain(|_, v| !v.is_null());
    }
    Ok(value.into())
}

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<oidc::AuthorizeParams>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    let (url, session_cookie) = oidc::authorize(params, &state.redis_client).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie.to_string().parse().unwrap(),
    );
    Ok((headers, Redirect::to(&url)))
}

async fn sign_in(
    State(state): State<AppState>,
    Query(params): Query<oidc::SignInParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), CustomError> {
    // `sign_in` returns ONLY on the success path (a real login that issued a code),
    // surfacing the resolved DID (covers BOTH passkey and wallet, and runs only
    // after the browser confirmed the new-user gate). Error/early returns short-
    // circuit via `?` so the cookie is never set on a failed login.
    let (url, did) = oidc::sign_in(
        &state.config.base_url,
        &state.config.supported_did_methods,
        &state.config.supported_pkh_namespaces,
        params,
        cookies,
        &state.redis_client,
        state.synapse_client.as_deref(),
    )
    .await?;

    // Mint an opaque login user-session bound to the DID and Set-Cookie it (Path=/,
    // HttpOnly, SameSite=Strict, Secure on https). The cookie value is the opaque
    // token only; the DID lives solely in Redis. A failure to mint must not break a
    // successful login, so it degrades to no cookie (next login is usernameless).
    let mut headers = HeaderMap::new();
    match state.redis_client.create_user_session(&did).await {
        Ok(token) => {
            let cookie = user_cookie_set(&state.config.base_url, &token);
            if let Ok(v) = cookie.parse() {
                headers.insert(header::SET_COOKIE, v);
            }
        }
        Err(e) => warn!(error = %e, "sign_in: failed to mint user-session cookie"),
    }
    Ok((headers, Redirect::to(url.as_str())))
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<CoreClientMetadata>,
) -> Result<(StatusCode, Json<CoreClientRegistrationResponse>), CustomError> {
    let registration = oidc::register(payload, state.config.base_url, &state.redis_client).await?;
    Ok((StatusCode::CREATED, registration.into()))
}

struct UserInfoResponseJWT(Json<CoreUserInfoJsonWebToken>);

impl IntoResponse for UserInfoResponseJWT {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(ContentType::name(), "application/jwt")
            .body(axum::body::Body::from(
                serde_json::to_string(&self.0 .0).unwrap().replace('"', ""),
            ))
            .unwrap()
    }
}

enum UserInfoResponse {
    Json(Json<CoreUserInfoClaims>),
    Jwt(UserInfoResponseJWT),
}

impl IntoResponse for UserInfoResponse {
    fn into_response(self) -> Response {
        match self {
            UserInfoResponse::Json(j) => j.into_response(),
            UserInfoResponse::Jwt(j) => j.into_response(),
        }
    }
}

async fn userinfo(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<UserInfoResponse, CustomError> {
    let payload = oidc::UserInfoPayload { access_token: None };
    let claims = oidc::userinfo(
        &state.config,
        &state.signing_key,
        bearer.map(|b| b.0 .0),
        payload,
        &state.redis_client,
    )
    .await?;
    Ok(match claims {
        oidc::UserInfoResponse::Json(c) => UserInfoResponse::Json(c.into()),
        oidc::UserInfoResponse::Jwt(c) => UserInfoResponse::Jwt(UserInfoResponseJWT(c.into())),
    })
}

async fn userinfo_post(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Form(payload): Form<oidc::UserInfoPayload>,
) -> Result<UserInfoResponse, CustomError> {
    let claims = oidc::userinfo(
        &state.config,
        &state.signing_key,
        bearer.map(|b| b.0 .0),
        payload,
        &state.redis_client,
    )
    .await?;
    Ok(match claims {
        oidc::UserInfoResponse::Json(c) => UserInfoResponse::Json(c.into()),
        oidc::UserInfoResponse::Jwt(c) => UserInfoResponse::Jwt(UserInfoResponseJWT(c.into())),
    })
}

async fn clientinfo(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<Json<CoreClientMetadata>, CustomError> {
    Ok(oidc::clientinfo(client_id, &state.redis_client)
        .await?
        .into())
}

async fn client_update(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(payload): Json<CoreClientMetadata>,
) -> Result<(), CustomError> {
    oidc::client_update(
        client_id,
        payload,
        bearer.map(|b| b.0 .0),
        &state.redis_client,
    )
    .await
}

async fn client_delete(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<(StatusCode, ()), CustomError> {
    Ok((
        StatusCode::NO_CONTENT,
        oidc::client_delete(client_id, bearer.map(|b| b.0 .0), &state.redis_client).await?,
    ))
}

async fn healthcheck() {}

// -- RFC 8628 device authorization handlers ---------------------------------

async fn device_authorization_handler(
    State(state): State<AppState>,
    Form(form): Form<device_auth::DeviceAuthRequest>,
) -> Result<Json<device_auth::DeviceAuthResponse>, CustomError> {
    let resp = device_auth::device_authorization(&state.config, &state.redis_client, form).await?;
    Ok(Json(resp))
}

async fn device_page_handler(
    State(state): State<AppState>,
    Query(query): Query<device_auth::DevicePageQuery>,
) -> axum::response::Html<String> {
    device_auth::device_page(query, state.config.base_url.as_str())
}

async fn device_verify_handler(
    State(state): State<AppState>,
    Query(query): Query<device_auth::DevicePageQuery>,
) -> Result<StatusCode, CustomError> {
    let code = query.user_code.as_deref().unwrap_or("");
    device_auth::device_verify(&state.redis_client, code).await?;
    Ok(StatusCode::OK)
}

async fn device_nonce_handler(
    State(state): State<AppState>,
    Query(query): Query<device_auth::DevicePageQuery>,
) -> Result<Json<device_auth::DeviceNonceResponse>, CustomError> {
    let code = query.user_code.as_deref().unwrap_or("");
    let resp = device_auth::device_nonce(&state.config, &state.redis_client, code).await?;
    Ok(Json(resp))
}

async fn device_approve_handler(
    State(state): State<AppState>,
    Json(req): Json<device_auth::DeviceApproveRequest>,
) -> Result<Json<device_auth::DeviceApproveResponse>, CustomError> {
    let synapse = state.synapse_client.as_deref();
    let resp =
        device_auth::device_approve(&state.config, &state.redis_client, req, synapse).await?;
    Ok(Json(resp))
}

/// `true` when a `/account|/device/passkey/start` body carries `{"all": true}` — the
/// "use a different passkey" escape hatch that forces usernameless even with a valid
/// `siwx_user` cookie (mirrors the login `AuthenticateStartBody.all`, H11).
fn payload_force_all(payload: &serde_json::Value) -> bool {
    payload
        .get("all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Extract the opaque `siwx_user` cookie token to scope a passkey picker, or `None`
/// when `force_all` (the `{"all":true}` escape hatch wins) or the cookie is absent.
/// Pure (no Redis) so the escape-hatch + absent-cookie branches are unit-testable; the
/// resolve-to-DID step is [`user_session_scope_did`].
fn user_session_token<'a>(
    cookies: &'a Option<TypedHeader<headers::Cookie>>,
    force_all: bool,
) -> Option<&'a str> {
    if force_all {
        return None;
    }
    cookies
        .as_ref()
        .and_then(|TypedHeader(c)| c.get(USER_SESSION_COOKIE))
}

/// Resolve the opaque `siwx_user` login cookie to a DID for scoping a passkey picker,
/// or `None` (usernameless) when `force_all`, or when the cookie is absent, forged, or
/// expired. NEVER errors: a Redis hiccup degrades to `None`. The login handler inlines
/// the same read; the account + device re-auth start handlers share this.
///
/// Enumeration-safety: the cookie value is an opaque server token (two UUIDs); a
/// forged/guessed value is a Redis miss -> `None` -> usernameless, leaking nothing.
/// The picker is only an OFFER — `verify_credential` (+ `reject_if_new_identity` on
/// the re-auth flows) still runs under the PROVEN DID, so this never relaxes auth.
async fn user_session_scope_did(
    redis: &RedisClient,
    cookies: &Option<TypedHeader<headers::Cookie>>,
    force_all: bool,
) -> Option<String> {
    let token = user_session_token(cookies, force_all)?;
    redis.lookup_user_session(token).await.ok().flatten()
}

/// Build the `detected_mxid` affordance (`@localpart:server_name`) for a scoped
/// picker, or `None` when unscoped or no `matrix_server_name` is configured. Leaks
/// nothing: the DID came from an opaque server-side cookie the caller already owns.
fn detected_mxid_for(server_name: Option<&str>, scope_did: Option<&str>) -> Option<String> {
    let did = scope_did?;
    let server_name = server_name?;
    Some(format!("@{}:{}", oidc::did_to_localpart(did), server_name))
}

async fn device_passkey_start_handler(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<headers::Cookie>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<AuthenticateStartResponse>, CustomError> {
    let user_code = payload
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing user_code".to_string()))?;
    device_auth::device_verify(&state.redis_client, user_code).await?;
    let session_id = format!("device_passkey_{}", user_code);
    // Identity-scope the picker to the APPROVER's own passkeys when their opaque
    // `siwx_user` login cookie is present (Path=/ reaches this endpoint via the
    // same-origin fetch from the served /device page — no client change needed). The
    // offer is never the security check: `verify_credential` + `reject_if_new_identity`
    // still run under the PROVEN DID. Degrade open: absent/forged/expired cookie, or
    // the `{"all":true}` escape hatch -> None -> usernameless, never an error.
    let scope_did =
        user_session_scope_did(&state.redis_client, &cookies, payload_force_all(&payload)).await;
    let rcr = wa::authenticate_start(
        &state.webauthn,
        &state.redis_client,
        &session_id,
        scope_did.as_deref(),
    )
    .await?;
    let detected_mxid =
        detected_mxid_for(state.config.matrix_server_name.as_deref(), scope_did.as_deref());
    Ok(Json(AuthenticateStartResponse {
        challenge: rcr,
        detected_mxid,
    }))
}

async fn device_passkey_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<device_auth::DeviceApproveResponse>, CustomError> {
    let user_code = payload
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing user_code".to_string()))?
        .to_string();
    let auth_response: PublicKeyCredential = serde_json::from_value(payload.clone())
        .map_err(|e| CustomError::BadRequest(format!("Invalid credential: {}", e)))?;
    let session_id = format!("device_passkey_{}", user_code);
    let resp = wa::verify_credential(
        &state.redis_client,
        &session_id,
        &state.rp_id,
        &state.rp_origin,
        &auth_response,
    )
    .await
    // Route the stale-passkey case to the structured 401 discriminator; keep every
    // other verification failure as the existing 400 BadRequest for this flow.
    .map_err(|e| match e {
        wa::VerifyError::UnknownCredential(id) => CustomError::UnknownCredential(id),
        wa::VerifyError::Other(inner) => CustomError::BadRequest(inner.to_string()),
    })?;
    let synapse = state.synapse_client.as_deref();
    let server_name = state.config.matrix_server_name.as_deref();
    let result = device_auth::device_approve_passkey(
        &state.redis_client,
        &user_code,
        &resp.did,
        synapse,
        server_name,
    )
    .await?;
    Ok(Json(result))
}

// -- WebAuthn route handlers -----------------------------------------------

async fn webauthn_register_start(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(payload): Json<wa::RegisterStartRequest>,
) -> Result<Json<CreationChallengeResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let ccr = wa::register_start(
        &state.webauthn,
        &state.redis_client,
        session_id,
        payload.display_name,
    )
    .await?;
    Ok(Json(ccr))
}

async fn webauthn_register_finish(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(reg_response): Json<RegisterPublicKeyCredential>,
) -> Result<Json<wa::RegisterFinishResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let resp = wa::register_finish(
        &state.webauthn,
        &state.redis_client,
        session_id,
        reg_response,
    )
    .await?;
    Ok(Json(resp))
}

/// Optional escape-hatch signals for `/webauthn/authenticate/start`. Both forms
/// force usernameless (all keys) even when a valid `siwx_user` cookie is present,
/// for the "use a different passkey" affordance (H11). The body is OPTIONAL: the
/// `#[serde(default)]` + `Option<Json<…>>` keep the existing `body: '{}'` callers
/// working untouched (`{}` deserializes with `all = false`; a missing/unparseable
/// body -> `None` -> not forced).
#[derive(serde::Deserialize, Default)]
struct AuthenticateStartBody {
    #[serde(default)]
    all: bool,
}

#[derive(serde::Deserialize, Default)]
struct AuthenticateStartQuery {
    /// `?all=1` (or any truthy value) forces usernameless from a GET-style caller.
    all: Option<String>,
}

/// Wrapper around the WebAuthn `RequestChallengeResponse` returned by
/// `/webauthn/authenticate/start`. The challenge fields stay EXACTLY where the
/// frontend expects them (`#[serde(flatten)]` keeps `publicKey.challenge` /
/// `publicKey.allowCredentials` / `publicKey.rpId` at the top level), and we add
/// one sibling field the login page uses for the detected-account affordance:
///
/// * `detected_mxid` — `@{localpart}:{server_name}` of the DID this request is
///   scoped to, or `null` when UNSCOPED (no/forged `siwx_user` cookie, `all=1`,
///   or no `server_name` configured). Never leaks anything the caller cannot
///   already prove ownership of (the cookie is an opaque server token).
///
/// When unscoped `detected_mxid` is `null` and the response is byte-shape-identical
/// (modulo the null sibling) to the previous bare `RequestChallengeResponse`,
/// so behavior is unchanged for the usernameless path. Method availability is NOT
/// predicted server-side: the offer is scoped by identity (`allowCredentials`) and
/// whether a method can run here is resolved live by the ceremony / locally by the
/// client, never by a server-reported `methods` hint.
#[derive(serde::Serialize)]
struct AuthenticateStartResponse {
    #[serde(flatten)]
    challenge: RequestChallengeResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    detected_mxid: Option<String>,
}

async fn webauthn_authenticate_start(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Query(query): Query<AuthenticateStartQuery>,
    body: Option<Json<AuthenticateStartBody>>,
) -> Result<Json<AuthenticateStartResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;

    // Escape hatch: `?all=1` OR JSON `{"all": true}` forces usernameless even with
    // a cookie ("use a different passkey").
    let force_all = body.map(|Json(b)| b.all).unwrap_or(false)
        || query
            .all
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    // Read the opaque `siwx_user` cookie -> DID (Redis). A missing/forged/expired
    // token resolves to None -> usernameless (enumeration-safe). When forced, skip
    // the lookup entirely.
    let scope_did = if force_all {
        None
    } else {
        match cookies.get(USER_SESSION_COOKIE) {
            Some(token) => state
                .redis_client
                .lookup_user_session(token)
                .await
                .ok()
                .flatten(),
            None => None,
        }
    };

    let challenge = wa::authenticate_start(
        &state.webauthn,
        &state.redis_client,
        session_id,
        scope_did.as_deref(),
    )
    .await?;

    // When (and only when) scoped by a valid cookie, surface the detected account
    // so the login page can show "Signing in as …". Needs server_name; without it
    // we report null. The picker is scoped by identity (allowCredentials); whether a
    // method can actually run here is resolved live by the ceremony / locally by the
    // client, never predicted server-side.
    let detected_mxid = match scope_did.as_deref() {
        Some(did) => state
            .config
            .matrix_server_name
            .as_deref()
            .map(|server_name| format!("@{}:{}", oidc::did_to_localpart(did), server_name)),
        // Unscoped (no/forged cookie or all=1): behavior identical to before.
        None => None,
    };

    Ok(Json(AuthenticateStartResponse {
        challenge,
        detected_mxid,
    }))
}

/// Login passkey-finish response: the verified DID plus a server-REPORTED
/// new-user signal so the browser can gate accidental new-account creation.
///
/// New-account creation at login is GATED in the FRONTEND (Task 5): the server
/// does NOT block here. `authenticate_finish` only stores `verified_did` in the
/// session; provisioning still happens exclusively at `/sign_in`, which the
/// browser navigates to only after the user confirms. So `new_user: true` +
/// cancel = no `/sign_in` = zero Synapse state. When no Synapse client is
/// configured we cannot detect new identities, so `new_user` is `false` (behaves
/// exactly as before) and `mxid` is empty.
#[derive(serde::Serialize)]
struct WebauthnAuthenticateFinishResponse {
    ok: bool,
    did: String,
    /// True iff this DID has NO existing Matrix account (signing in would CREATE
    /// one). Server-reported only; the browser decides whether to proceed.
    new_user: bool,
    /// The `@localpart:server_name` this DID resolves to (empty when no Synapse
    /// client / server_name is configured), so the gate can show the user which
    /// account they are about to create / enter.
    mxid: String,
}

async fn webauthn_authenticate_finish(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(auth_response): Json<PublicKeyCredential>,
) -> Result<Json<WebauthnAuthenticateFinishResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let resp = wa::authenticate_finish(
        &state.redis_client,
        session_id,
        &state.rp_id,
        &state.rp_origin,
        auth_response,
    )
    .await?;

    // Detection only (no blocking, no change to provisioning). The verified DID
    // is already stored in the session by authenticate_finish; the new-user gate
    // is enforced by the frontend, which navigates to /sign_in only on confirm.
    // new_user detection depends ONLY on the Synapse client (None -> false, i.e.
    // behave as today, cannot detect). mxid additionally needs server_name to be
    // a well-formed @localpart:server_name; without it we report the empty string.
    let (new_user, mxid) = match state.synapse_client.as_deref() {
        Some(synapse) => {
            // is_new_identity == true means the localpart is AVAILABLE (no account).
            let new_user = wa::is_new_identity(synapse, &resp.did).await.unwrap_or(false);
            let mxid = match state.config.matrix_server_name.as_deref() {
                Some(server_name) => {
                    let localpart = oidc::did_to_localpart(&resp.did);
                    format!("@{}:{}", localpart, server_name)
                }
                None => String::new(),
            };
            (new_user, mxid)
        }
        // No Synapse client -> cannot detect; behave as today.
        None => (false, String::new()),
    };

    Ok(Json(WebauthnAuthenticateFinishResponse {
        ok: resp.ok,
        did: resp.did,
        new_user,
        mxid,
    }))
}

// -- Account linking route handlers (Phase 2) ------------------------------

async fn webauthn_link_start(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<Json<CreationChallengeResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let session = state
        .redis_client
        .get_session(session_id.to_string())
        .await?
        .ok_or_else(|| CustomError::BadRequest("Session not found".to_string()))?;

    // Verify the siwx cookie to prove DID ownership.
    let primary_did = oidc::verify_siwx_cookie(
        &cookies,
        &session,
        &state.config.supported_did_methods,
        &state.config.supported_pkh_namespaces,
    )?;

    let ccr = wa::link_start(
        &state.webauthn,
        &state.redis_client,
        session_id,
        &primary_did,
        None,
    )
    .await?;
    Ok(Json(ccr))
}

async fn webauthn_link_finish(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(reg_response): Json<RegisterPublicKeyCredential>,
) -> Result<Json<wa::LinkFinishResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let resp = wa::link_finish(
        &state.webauthn,
        &state.redis_client,
        session_id,
        reg_response,
    )
    .await?;
    Ok(Json(resp))
}

// -- Account management route handlers (MSC4191/MSC4312) --------------------

/// `Set-Cookie` value that establishes the authenticated account session.
fn account_cookie_set(base_url: &url::Url, token: &str) -> String {
    let secure = if base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={}; Max-Age={}; Path=/account; HttpOnly; SameSite=Strict{}",
        account::ACCOUNT_SESSION_COOKIE,
        token,
        account::ACCOUNT_SESSION_TTL,
        secure
    )
}

/// `Set-Cookie` value that clears the account session (terminal actions).
fn account_cookie_clear(base_url: &url::Url) -> String {
    let secure = if base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}=; Max-Age=0; Path=/account; HttpOnly; SameSite=Strict{}",
        account::ACCOUNT_SESSION_COOKIE,
        secure
    )
}

/// Cookie name for the opaque login user-session (the identity hint that scopes
/// the passkey picker). Distinct from [`account::ACCOUNT_SESSION_COOKIE`]: this
/// one is `Path=/` so it is sent to `/webauthn/authenticate/start`, and its value
/// is an OPAQUE token (never a DID). A forged/expired value is a Redis miss ->
/// usernameless fallback (the enumeration-safety invariant).
const USER_SESSION_COOKIE: &str = "siwx_user";

/// `Set-Cookie` value that establishes the opaque login user-session. Mirrors
/// [`account_cookie_set`] but with `Path=/` (so it reaches the login-time
/// `/webauthn/authenticate/start`) and the longer [`USER_SESSION_LIFETIME`].
fn user_cookie_set(base_url: &url::Url, token: &str) -> String {
    let secure = if base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict{}",
        USER_SESSION_COOKIE, token, USER_SESSION_LIFETIME, secure
    )
}

/// `Set-Cookie` value that clears the opaque login user-session (escape hatch /
/// sign-out). Mirrors [`account_cookie_clear`] with `Path=/`.
#[allow(dead_code)]
fn user_cookie_clear(base_url: &url::Url) -> String {
    let secure = if base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict{}",
        USER_SESSION_COOKIE, secure
    )
}

/// True for outcomes that destroy the identity the session was bound to, so the
/// cookie must be cleared rather than (re)issued.
fn outcome_is_terminal(outcome: &account::ActionOutcome) -> bool {
    matches!(
        outcome,
        account::ActionOutcome::Erased | account::ActionOutcome::Deactivated
    )
}

/// Read the account-session cookie value, tolerating a wholly-absent Cookie
/// header (first-time visitors have no cookies at all).
fn account_session_token(cookies: &Option<TypedHeader<headers::Cookie>>) -> Option<&str> {
    cookies
        .as_ref()
        .and_then(|TypedHeader(c)| c.get(account::ACCOUNT_SESSION_COOKIE))
}

/// Turn a successful re-auth ([`account::AuthedAction`]) into a response that
/// also (a) issues the account-session cookie, and (b) carries the CSRF token so
/// the page can drive subsequent actions without a fresh signature. Terminal
/// outcomes (erase/deactivate) clear the cookie instead.
async fn authed_action_response(
    state: &AppState,
    authed: account::AuthedAction,
) -> Result<(axum::http::HeaderMap, Json<account::AccountActionResponse>), CustomError> {
    let mut response = authed.response;
    let mut headers = axum::http::HeaderMap::new();
    let cookie = if outcome_is_terminal(&response.outcome) {
        account_cookie_clear(&state.config.base_url)
    } else {
        let (token, csrf) =
            account::create_account_session(&state.redis_client, &authed.did).await?;
        response.csrf = Some(csrf);
        // Re-inject the login scoping cookie: a user who just proved ownership of
        // `authed.did` to manage their account also gets an opaque login
        // user-session, so their next login picker is scoped. Reuses the same DID;
        // best-effort (a mint failure must not fail account management).
        match state.redis_client.create_user_session(&authed.did).await {
            Ok(user_token) => {
                let user_cookie = user_cookie_set(&state.config.base_url, &user_token);
                if let Ok(v) = axum::http::HeaderValue::from_str(&user_cookie) {
                    // append (not insert): coexist with the account-session Set-Cookie.
                    headers.append(axum::http::header::SET_COOKIE, v);
                }
            }
            Err(e) => warn!(error = %e, "account re-auth: failed to mint user-session cookie"),
        }
        account_cookie_set(&state.config.base_url, &token)
    };
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
        headers.append(axum::http::header::SET_COOKIE, v);
    }
    Ok((headers, Json(response)))
}

async fn account_page_handler(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<headers::Cookie>>,
    Query(query): Query<account::AccountPageQuery>,
) -> axum::response::Html<String> {
    // If a live account session is present, render the page already-authenticated
    // (no fresh signature for this or subsequent actions).
    let csrf = match account_session_token(&cookies) {
        Some(token) => account::lookup_account_session(&state.redis_client, token)
            .await
            .map(|s| s.csrf),
        None => None,
    };
    account::account_page_inner(query, state.config.base_url.as_str(), csrf.as_deref())
}

async fn account_nonce_handler(
    State(state): State<AppState>,
    Query(query): Query<account::AccountPageQuery>,
) -> Result<Json<account::AccountNonceResponse>, CustomError> {
    let action = query.action.as_deref().unwrap_or("");
    let resp = account::account_nonce(&state.config, &state.redis_client, action).await?;
    Ok(Json(resp))
}

async fn account_wallet_handler(
    State(state): State<AppState>,
    Json(req): Json<account::AccountWalletRequest>,
) -> Result<(axum::http::HeaderMap, Json<account::AccountActionResponse>), CustomError> {
    let synapse = state.synapse_client.as_deref();
    let authed = account::account_wallet(
        &state.config,
        req,
        synapse,
        &state.redis_client,
        state.config.matrix_server_name.as_deref(),
    )
    .await?;
    authed_action_response(&state, authed).await
}

/// `POST /account/action` — execute an action against the live account session
/// (cookie + CSRF), with NO fresh wallet/passkey signature. This is what removes
/// the "multiple authentications" defect: one re-auth covers the whole session.
async fn account_action_handler(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<headers::Cookie>>,
    Json(req): Json<account::AccountActionRequest>,
) -> Result<(axum::http::HeaderMap, Json<account::AccountActionResponse>), CustomError> {
    let token = account_session_token(&cookies);
    let synapse = state.synapse_client.as_deref();
    let response = account::account_action(
        &state.redis_client,
        token,
        req,
        synapse,
        state.config.matrix_server_name.as_deref(),
    )
    .await?;

    let mut headers = axum::http::HeaderMap::new();
    if outcome_is_terminal(&response.outcome) {
        if let Some(t) = token {
            account::destroy_account_session(&state.redis_client, t).await;
        }
        if let Ok(v) =
            axum::http::HeaderValue::from_str(&account_cookie_clear(&state.config.base_url))
        {
            headers.insert(axum::http::header::SET_COOKIE, v);
        }
    }
    Ok((headers, Json(response)))
}

async fn account_passkey_start_handler(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<headers::Cookie>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, CustomError> {
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action.is_empty() {
        return Err(CustomError::BadRequest("Missing action".to_string()));
    }
    let session_id = format!("account_passkey_{}", uuid::Uuid::new_v4());
    // Identity-scope the account re-auth picker to the OWNER's own passkeys when their
    // opaque `siwx_user` login cookie is present (Path=/ reaches this endpoint). The
    // offer is never the security check: `reject_if_new_identity` + the proven DID at
    // `/account/passkey/finish` enforce account ownership. Degrade open: absent/forged/
    // expired cookie or the `{"all":true}` escape hatch -> None -> usernameless.
    let scope_did =
        user_session_scope_did(&state.redis_client, &cookies, payload_force_all(&payload)).await;
    let rcr = wa::authenticate_start(
        &state.webauthn,
        &state.redis_client,
        &session_id,
        scope_did.as_deref(),
    )
    .await?;
    let mut value = serde_json::to_value(&rcr)
        .map_err(|e| anyhow::anyhow!("Failed to serialize challenge: {}", e))?;
    value["session_id"] = serde_json::json!(session_id);
    if let Some(mxid) =
        detected_mxid_for(state.config.matrix_server_name.as_deref(), scope_did.as_deref())
    {
        value["detected_mxid"] = serde_json::json!(mxid);
    }
    Ok(Json(value))
}

async fn account_passkey_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<(axum::http::HeaderMap, Json<account::AccountActionResponse>), CustomError> {
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing action".to_string()))?
        .to_string();

    let session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing session_id".to_string()))?;

    let device_id = payload
        .get("device_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let synapse = state.synapse_client.as_deref();
    let req = account::AccountPasskeyFinishRequest {
        action,
        device_id,
        credential: payload.clone(),
    };
    let authed = account::account_passkey_finish(
        &state.redis_client,
        session_id,
        &state.rp_id,
        &state.rp_origin,
        req,
        synapse,
        state.config.matrix_server_name.as_deref(),
    )
    .await?;
    authed_action_response(&state, authed).await
}

// -- Application entry point -----------------------------------------------

pub async fn main() {
    let config = Figment::from(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("siwe-oidc.toml").nested())
        .merge(Env::prefixed("SIWEOIDC_").split("__").global());
    let config = config.extract::<config::Config>().unwrap();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("siwx_oidc=info,tower_http=info,warn"));

    match config.log_format.as_str() {
        "json" => {
            fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .init();
        }
        _ => {
            fmt().with_env_filter(env_filter).with_target(true).init();
        }
    }

    // Validate configured DID methods against the aqua-auth registry.
    {
        let registered: Vec<String> = all_did_methods()
            .iter()
            .map(|m| m.method_name().to_string())
            .collect();
        for method in &config.supported_did_methods {
            assert!(
                registered.contains(method),
                "FATAL: configured DID method '{}' is not registered in aqua-auth (registered: {:?})",
                method, registered
            );
        }
        let registered_ns: Vec<String> = all_cipher_suites()
            .iter()
            .map(|cs| cs.namespace().to_string())
            .collect();
        for ns in &config.supported_pkh_namespaces {
            assert!(
                registered_ns.contains(ns),
                "FATAL: configured pkh namespace '{}' is not registered in aqua-auth (registered: {:?})",
                ns, registered_ns
            );
        }
    }

    let redis_client = RedisClient::new(&config.redis_url)
        .await
        .expect("Could not build Redis client");

    for (id, entry) in &config.default_clients.clone() {
        let entry: ClientEntry =
            serde_json::from_str(entry).expect("Deserialisation of ClientEntry failed");
        redis_client
            .set_client(id.to_string(), entry.clone())
            .await
            .unwrap();
    }

    let signing_key = if let Some(key) = &config.signing_key_pem {
        EcdsaSigningKey::from_pem(key, Some(JsonWebKeyId::new("key1".to_string())))
            .expect("Failed to load signing key from PEM")
    } else {
        info!("Generating ephemeral ES256 signing key...");
        let key = EcdsaSigningKey::generate(Some(JsonWebKeyId::new("key1".to_string())));
        // SECURITY: never log private key material. Log only a non-sensitive
        // fingerprint of the *public* key so operators can correlate the live
        // key without exposing the secret. This key rotates on every restart
        // (sessions break on restart) — set SIWEOIDC_SIGNING_KEY_PEM to persist.
        info!(
            kid = "key1",
            pubkey_fp = %key.public_key_fingerprint(),
            "Generated ephemeral ES256 signing key (NOT persisted). \
             Set SIWEOIDC_SIGNING_KEY_PEM to use a stable key in production."
        );
        key
    };

    let wa_config = wa::build_webauthn(
        &config.base_url,
        config.rp_id.as_deref(),
        config.rp_origin.as_deref(),
    )
    .expect("Failed to initialize WebAuthn — check SIWEOIDC_BASE_URL, SIWEOIDC_RP_ID, SIWEOIDC_RP_ORIGIN");

    // Initialize Synapse client for MSC3861 device lifecycle (optional).
    let synapse_client = match (&config.synapse_endpoint, &config.mas_shared_secret) {
        (Some(endpoint), Some(secret)) => {
            info!("Synapse client enabled: {}", endpoint);
            Some(Arc::new(SynapseClient::new(endpoint.as_str(), secret)))
        }
        _ => None,
    };

    let state = AppState {
        signing_key: Arc::new(signing_key),
        config: config.clone(),
        redis_client,
        webauthn: Arc::new(wa_config.webauthn),
        rp_id: wa_config.rp_id,
        rp_origin: wa_config.rp_origin,
        synapse_client,
    };

    let introspect_state = IntrospectState::from(&state);
    let compat_state = compat::CompatState {
        redis_client: state.redis_client.clone(),
        synapse_client: state.synapse_client.clone(),
        server_name: state.config.matrix_server_name.clone(),
    };

    let app = Router::new()
        .nest_service("/build", ServeDir::new("./static/build"))
        .nest_service("/legal", ServeDir::new("./static/legal"))
        .nest_service("/img", ServeDir::new("./static/img"))
        .route_service("/", ServeFile::new("./static/index.html"))
        .route_service("/error", ServeFile::new("./static/error.html"))
        .route_service("/favicon.png", ServeFile::new("./static/favicon.png"))
        .route(oidc::METADATA_PATH, get(provider_metadata))
        .route(oidc::JWK_PATH, get(jwk_set))
        .route(oidc::TOKEN_PATH, post(token))
        .route(oidc::AUTHORIZE_PATH, get(authorize))
        .route(oidc::REGISTER_PATH, post(register))
        .route(oidc::USERINFO_PATH, get(userinfo).post(userinfo_post))
        .route(
            &format!("{}/{{id}}", oidc::CLIENT_PATH),
            get(clientinfo).delete(client_delete).post(client_update),
        )
        .route(oidc::SIGNIN_PATH, get(sign_in))
        .route("/webauthn/register/start", post(webauthn_register_start))
        .route("/webauthn/register/finish", post(webauthn_register_finish))
        .route(
            "/webauthn/authenticate/start",
            post(webauthn_authenticate_start),
        )
        .route(
            "/webauthn/authenticate/finish",
            post(webauthn_authenticate_finish),
        )
        .route("/link/webauthn/start", post(webauthn_link_start))
        .route("/link/webauthn/finish", post(webauthn_link_finish))
        .route("/health", get(healthcheck))
        .route("/device_authorization", post(device_authorization_handler))
        .route(
            "/device",
            get(device_page_handler).post(device_approve_handler),
        )
        .route("/device/verify", get(device_verify_handler))
        .route("/device/nonce", get(device_nonce_handler))
        .route("/device/passkey/start", post(device_passkey_start_handler))
        .route(
            "/device/passkey/finish",
            post(device_passkey_finish_handler),
        )
        // MSC4191/MSC4312: account management + cross-signing reset
        .route("/account", get(account_page_handler))
        .route("/account/nonce", get(account_nonce_handler))
        .route("/account/wallet", post(account_wallet_handler))
        .route("/account/action", post(account_action_handler))
        .route(
            "/account/passkey/start",
            post(account_passkey_start_handler),
        )
        .route(
            "/account/passkey/finish",
            post(account_passkey_finish_handler),
        )
        .with_state(state)
        // MSC3861 introspection — separate state (only needs secret + Redis)
        .route(
            "/oauth2/introspect",
            post(introspect::introspect).with_state(introspect_state),
        )
        // MSC3861 compat endpoints — revocation + Matrix legacy login/logout/refresh
        .route(
            "/oauth2/revoke",
            post(compat::revoke).with_state(compat_state.clone()),
        )
        .route("/_matrix/client/v3/login", get(compat::login_flows))
        // Legacy CS-API device management (in-client session manager). Effective
        // only when the deployment proxies these paths to siwx-oidc; harmless
        // otherwise. See docs/2026-06-14-account-management-e2e-findings.md.
        .route(
            "/_matrix/client/v3/devices/{device_id}",
            delete(compat::delete_device).with_state(compat_state.clone()),
        )
        .route(
            "/_matrix/client/v3/delete_devices",
            post(compat::delete_devices).with_state(compat_state.clone()),
        )
        .route(
            "/_matrix/client/v3/logout",
            post(compat::logout).with_state(compat_state.clone()),
        )
        .route(
            "/_matrix/client/v3/logout/all",
            post(compat::logout_all).with_state(compat_state.clone()),
        )
        .route(
            "/_matrix/client/v3/refresh",
            post(compat::refresh).with_state(compat_state),
        )
        .layer(
            TraceLayer::new_for_http()
                .on_request(|req: &axum::http::Request<_>, _span: &tracing::Span| {
                    info!(
                        method = %req.method(),
                        path = %req.uri().path(),
                        "request"
                    );
                })
                .on_response(
                    |res: &axum::http::Response<_>, latency: Duration, _span: &tracing::Span| {
                        info!(
                            status = res.status().as_u16(),
                            latency_ms = latency.as_millis() as u64,
                            "response"
                        );
                    },
                )
                .on_failure(
                    |error: ServerErrorsFailureClass, latency: Duration, _span: &tracing::Span| {
                        warn!(
                            error = %error,
                            latency_ms = latency.as_millis() as u64,
                            "request failed"
                        );
                    },
                ),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
        );

    let addr = SocketAddr::from((config.address, config.port));
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod unknown_credential_response_tests {
    //! Deterministic, infra-free guards for the stale-passkey server contract.
    //! No Redis or network: they exercise the typed-error mapping and the HTTP
    //! rendering the frontend keys on. The full ceremony path is covered by the
    //! browser E2E (`e2e/browser/stale-credential.spec.mjs`).
    use super::*;
    use crate::webauthn::VerifyError;

    /// H1/H2: the unknown-credential case maps to `CustomError::UnknownCredential`
    /// and renders as HTTP 401 with the machine-readable JSON discriminator
    /// `{error:"unknown_credential", credential_id, message}` (NOT a 500).
    #[tokio::test]
    async fn unknown_credential_maps_to_401_discriminator() {
        let ce: CustomError = VerifyError::UnknownCredential("AAAABBBB".to_string()).into();
        assert!(
            matches!(&ce, CustomError::UnknownCredential(id) if id == "AAAABBBB"),
            "VerifyError::UnknownCredential must map to CustomError::UnknownCredential"
        );

        let resp = ce.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "unknown_credential");
        assert_eq!(json["credential_id"], "AAAABBBB");
        assert!(json["message"]
            .as_str()
            .expect("message present")
            .contains("no longer valid"));
    }

    /// H1 isolation: every OTHER verification failure (signature, challenge, flags,
    /// counter, I/O) stays `Other` -> HTTP 500 and is never mistaken for the
    /// unknown-credential discriminator, so a valid passkey is never signaled.
    #[tokio::test]
    async fn other_verify_error_stays_internal_error() {
        let ce: CustomError = VerifyError::Other(anyhow::anyhow!("signature failed")).into();
        assert!(matches!(ce, CustomError::Other(_)));
        let resp = ce.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// H4: the login passkey-finish response now carries the server-REPORTED
    /// new-user signal (`new_user`) and the resolved `mxid`, in addition to the
    /// `ok`/`did` fields the existing frontend already reads. This is a pure
    /// detection signal: the server does NOT block, and provisioning still happens
    /// only at /sign_in (which the browser reaches on confirm). Deterministic,
    /// infra-free: just the wire contract.
    #[test]
    fn login_finish_response_carries_new_user_and_mxid() {
        let json = serde_json::to_value(WebauthnAuthenticateFinishResponse {
            ok: true,
            did: "did:key:zDnNEW".to_string(),
            new_user: true,
            mxid: "@did-key-zdnnew:matrix.example.com".to_string(),
        })
        .unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["did"], "did:key:zDnNEW");
        assert_eq!(json["new_user"], true);
        assert_eq!(json["mxid"], "@did-key-zdnnew:matrix.example.com");

        // Existing-identity / no-Synapse shape: new_user false, mxid empty. The
        // frontend gate (Task 5) only fires on new_user==true, so this is the
        // unchanged-behavior path.
        let json = serde_json::to_value(WebauthnAuthenticateFinishResponse {
            ok: true,
            did: "did:key:zDnEXISTING".to_string(),
            new_user: false,
            mxid: String::new(),
        })
        .unwrap();
        assert_eq!(json["new_user"], false);
        assert_eq!(json["mxid"], "");
    }

    /// H7/H8: the `/webauthn/authenticate/start` wrapper keeps the WebAuthn
    /// challenge fields EXACTLY where the existing JS reads them
    /// (`publicKey.challenge` / `publicKey.allowCredentials`, via `#[serde(flatten)]`)
    /// while adding the scoped-only `detected_mxid` sibling. Unscoped, the extra is
    /// omitted, so the shape is byte-compatible with the previous bare
    /// `RequestChallengeResponse`. Deterministic, infra-free: pure wire contract.
    #[test]
    fn authenticate_start_wrapper_preserves_publickey_and_adds_siblings() {
        // Minimal valid RequestChallengeResponse (deserializable) the wrapper flattens.
        let rcr: RequestChallengeResponse = serde_json::from_value(serde_json::json!({
            "publicKey": {
                "challenge": "AAECAwQFBgcICQ",
                "allowCredentials": [],
                "rpId": "matrix.example.com",
                "userVerification": "preferred"
            }
        }))
        .unwrap();

        // Scoped: detected_mxid present; publicKey untouched at top level.
        let scoped = serde_json::to_value(AuthenticateStartResponse {
            challenge: rcr.clone(),
            detected_mxid: Some("@did-key-zdn:matrix.example.com".to_string()),
        })
        .unwrap();
        assert_eq!(scoped["publicKey"]["challenge"], "AAECAwQFBgcICQ");
        assert_eq!(scoped["publicKey"]["rpId"], "matrix.example.com");
        assert!(scoped["publicKey"]["allowCredentials"].is_array());
        assert_eq!(scoped["detected_mxid"], "@did-key-zdn:matrix.example.com");

        // Unscoped: extra omitted entirely; publicKey still intact.
        let unscoped = serde_json::to_value(AuthenticateStartResponse {
            challenge: rcr,
            detected_mxid: None,
        })
        .unwrap();
        assert_eq!(unscoped["publicKey"]["challenge"], "AAECAwQFBgcICQ");
        assert!(unscoped.get("detected_mxid").is_none());
    }

    /// H3 (escape hatch): the account/device `{"all":true}` body flag forces
    /// usernameless; everything else (absent, non-bool, unrelated body) means "scope
    /// as normal". Pure wire contract, infra-free.
    #[test]
    fn payload_force_all_reads_escape_hatch_only_on_literal_true() {
        assert!(payload_force_all(&serde_json::json!({ "all": true })));
        assert!(!payload_force_all(&serde_json::json!({ "all": false })));
        // Absent / wrong-typed / unrelated payloads must NOT force open.
        assert!(!payload_force_all(&serde_json::json!({ "action": "org.matrix.profile" })));
        assert!(!payload_force_all(&serde_json::json!({ "user_code": "ABC-DEF" })));
        assert!(!payload_force_all(&serde_json::json!({ "all": "true" })));
        assert!(!payload_force_all(&serde_json::json!({})));
    }

    /// H3 (cookie extraction + escape hatch): `user_session_token` returns the
    /// opaque `siwx_user` value when present and not forced, `None` for an absent
    /// cookie (first-time visitor, no Cookie header), `None` when another cookie is
    /// present but `siwx_user` is not, and `None` whenever `force_all` is set even if
    /// a valid cookie is present. Pure (no Redis).
    #[test]
    fn user_session_token_reads_cookie_and_honors_escape_hatch() {
        // Absent Cookie header entirely -> None (degrade open; no panic).
        let none: Option<TypedHeader<headers::Cookie>> = None;
        assert_eq!(user_session_token(&none, false), None);
        assert_eq!(user_session_token(&none, true), None);

        // A present `siwx_user` cookie is read out verbatim (the opaque token).
        let hv = axum::http::HeaderValue::from_static("siwx_user=tok123abc; foo=bar");
        let cookie = headers::Cookie::decode(&mut std::iter::once(&hv)).expect("decode cookie");
        let present = Some(TypedHeader(cookie));
        assert_eq!(user_session_token(&present, false), Some("tok123abc"));
        // ...but the `{"all":true}` escape hatch wins even with a valid cookie present.
        assert_eq!(user_session_token(&present, true), None);

        // A Cookie header WITHOUT `siwx_user` -> None (other cookies never scope).
        let hv2 = axum::http::HeaderValue::from_static("acct_session=zzz; foo=bar");
        let cookie2 = headers::Cookie::decode(&mut std::iter::once(&hv2)).expect("decode cookie");
        assert_eq!(user_session_token(&Some(TypedHeader(cookie2)), false), None);
    }

    /// The `detected_mxid` affordance is present ONLY when both a scoped DID and a
    /// configured `matrix_server_name` exist; otherwise `None` (unscoped, or a
    /// standalone deployment with no server_name). Pure, infra-free.
    #[test]
    fn detected_mxid_only_when_scoped_and_server_named() {
        // Unscoped (no DID) -> None regardless of server_name.
        assert_eq!(detected_mxid_for(Some("matrix.example.com"), None), None);
        // Scoped but no server_name configured -> None (standalone degrades cleanly).
        assert_eq!(detected_mxid_for(None, Some("did:key:zDnABC")), None);
        // Scoped + server_name -> @localpart:server.
        let mxid = detected_mxid_for(Some("matrix.example.com"), Some("did:key:zDnABC"))
            .expect("scoped + server_name -> Some");
        assert!(mxid.starts_with('@'), "mxid starts with @: {mxid}");
        assert!(
            mxid.ends_with(":matrix.example.com"),
            "mxid ends with the server name: {mxid}"
        );
    }

    /// H3/AC6 (degrade-open on a Redis ERROR, not merely a miss): the load-bearing
    /// `.ok().flatten()` in `user_session_scope_did` must turn a Redis fault into a
    /// usernameless `None`, NEVER propagate it (which would 500 the picker). A future
    /// refactor to `?` would break this invariant while every miss-path test stayed
    /// green — so pin the error path here. We force a real, fast `WRONGTYPE` error by
    /// storing the `user:session/{token}` key as a SET, so the `GET` in
    /// `lookup_user_session` errors. Requires Redis on localhost; skips if absent.
    #[tokio::test]
    async fn user_session_scope_did_degrades_open_on_redis_error() {
        let redis = match RedisClient::new(&url::Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
        };
        let token = format!("wrongtype{}", uuid::Uuid::new_v4().simple());
        // KV_USER_SESSION_PREFIX is in scope via `use siwx_oidc::db::*` at the top.
        let key = format!("{}/{}", KV_USER_SESSION_PREFIX, token);
        // SET-typed value at the exact key lookup_user_session GETs -> WRONGTYPE error.
        redis.sadd_raw(&key, "x").await.expect("seed wrong-type key");

        let header = format!("siwx_user={token}");
        let hv = axum::http::HeaderValue::from_str(&header).expect("header value");
        let cookie = headers::Cookie::decode(&mut std::iter::once(&hv)).expect("decode cookie");

        let scope = user_session_scope_did(&redis, &Some(TypedHeader(cookie)), false).await;
        assert!(
            scope.is_none(),
            "a Redis GET error MUST degrade open to None (usernameless), never propagate"
        );

        redis.del_raw(&key).await.ok();
    }
}
