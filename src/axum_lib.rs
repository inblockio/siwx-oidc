use axum::{
    extract::{Form, Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
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
    let pm = oidc::metadata(state.config.base_url.clone())?;
    let mut value = serde_json::to_value(pm)
        .map_err(|e| anyhow::anyhow!("Failed to serialize metadata: {}", e))?;
    let base_url = state.config.base_url.as_str().trim_end_matches('/');
    value["code_challenge_methods_supported"] = serde_json::json!(["S256"]);
    value["introspection_endpoint"] = serde_json::json!(format!("{}/oauth2/introspect", base_url));
    value["introspection_endpoint_auth_methods_supported"] =
        serde_json::json!(["client_secret_post", "bearer"]);
    value["grant_types_supported"] = serde_json::json!([
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code"
    ]);
    value["device_authorization_endpoint"] =
        serde_json::json!(format!("{}/device_authorization", base_url));
    value["revocation_endpoint"] = serde_json::json!(format!("{}/oauth2/revoke", base_url));
    value["token_endpoint_auth_methods_supported"] =
        serde_json::json!(["client_secret_post", "none"]);
    // MSC4191: account management discovery (stable v1.18)
    let account_uri = state
        .config
        .account_management_uri
        .as_ref()
        .map(|u| u.as_str().to_string())
        .unwrap_or_else(|| format!("{}/account", base_url));
    value["account_management_uri"] = serde_json::json!(account_uri);
    value["account_management_actions_supported"] =
        serde_json::json!(["org.matrix.cross_signing_reset"]);
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
) -> Result<Redirect, CustomError> {
    let url = oidc::sign_in(
        &state.config.base_url,
        &state.config.supported_did_methods,
        &state.config.supported_pkh_namespaces,
        params,
        cookies,
        &state.redis_client,
        state.synapse_client.as_deref(),
    )
    .await?;
    Ok(Redirect::to(url.as_str()))
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

async fn device_approve_handler(
    State(state): State<AppState>,
    Json(req): Json<device_auth::DeviceApproveRequest>,
) -> Result<Json<device_auth::DeviceApproveResponse>, CustomError> {
    let synapse = state.synapse_client.as_deref();
    let resp =
        device_auth::device_approve(&state.config, &state.redis_client, req, synapse).await?;
    Ok(Json(resp))
}

async fn device_passkey_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<RequestChallengeResponse>, CustomError> {
    let user_code = payload
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing user_code".to_string()))?;
    device_auth::device_verify(&state.redis_client, user_code).await?;
    let session_id = format!("device_passkey_{}", user_code);
    let rcr = wa::authenticate_start(&state.webauthn, &state.redis_client, &session_id).await?;
    Ok(Json(rcr))
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
    .map_err(|e| CustomError::BadRequest(e.to_string()))?;
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

async fn webauthn_authenticate_start(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<Json<RequestChallengeResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let rcr = wa::authenticate_start(&state.webauthn, &state.redis_client, session_id).await?;
    Ok(Json(rcr))
}

async fn webauthn_authenticate_finish(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(auth_response): Json<PublicKeyCredential>,
) -> Result<Json<wa::AuthenticateFinishResponse>, CustomError> {
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
    Ok(Json(resp))
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

async fn account_page_handler(
    State(state): State<AppState>,
    Query(query): Query<account::AccountPageQuery>,
) -> axum::response::Html<String> {
    account::account_page(query, state.config.base_url.as_str())
}

async fn account_wallet_handler(
    State(state): State<AppState>,
    Json(req): Json<account::AccountWalletRequest>,
) -> Result<Json<account::AccountActionResponse>, CustomError> {
    let synapse = state.synapse_client.as_deref();
    let resp = account::account_wallet(&state.config, req, synapse).await?;
    Ok(Json(resp))
}

async fn account_passkey_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, CustomError> {
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action.is_empty() {
        return Err(CustomError::BadRequest("Missing action".to_string()));
    }
    let session_id = format!("account_passkey_{}", uuid::Uuid::new_v4());
    let rcr = wa::authenticate_start(&state.webauthn, &state.redis_client, &session_id).await?;
    let mut value = serde_json::to_value(&rcr)
        .map_err(|e| anyhow::anyhow!("Failed to serialize challenge: {}", e))?;
    value["session_id"] = serde_json::json!(session_id);
    Ok(Json(value))
}

async fn account_passkey_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<account::AccountActionResponse>, CustomError> {
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing action".to_string()))?
        .to_string();

    let session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomError::BadRequest("Missing session_id".to_string()))?;

    let synapse = state.synapse_client.as_deref();
    let req = account::AccountPasskeyFinishRequest {
        action,
        credential: payload.clone(),
    };
    let resp = account::account_passkey_finish(
        &state.redis_client,
        session_id,
        &state.rp_id,
        &state.rp_origin,
        req,
        synapse,
    )
    .await?;
    Ok(Json(resp))
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
        info!("Generating ES256 signing key...");
        let key = EcdsaSigningKey::generate(Some(JsonWebKeyId::new("key1".to_string())));
        info!("Generated ES256 key. PEM:\n{}", key.to_pem().unwrap());
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
        .route("/device/passkey/start", post(device_passkey_start_handler))
        .route(
            "/device/passkey/finish",
            post(device_passkey_finish_handler),
        )
        // MSC4191/MSC4312: account management + cross-signing reset
        .route("/account", get(account_page_handler))
        .route("/account/wallet", post(account_wallet_handler))
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
        .route(
            "/_matrix/client/v3/logout",
            post(compat::logout).with_state(compat_state.clone()),
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
