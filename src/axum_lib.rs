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
    CoreTokenResponse, CoreUserInfoClaims, CoreUserInfoJsonWebToken,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use webauthn_rs::prelude::*;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::info;

use super::config;
use super::oidc::{self, CustomError, EcdsaSigningKey};
use super::webauthn as wa;
use openidconnect::JsonWebKeyId;
use siwx_core::{all_cipher_suites, all_did_methods};
use siwx_oidc::db::*;

// -- Shared application state ----------------------------------------------

#[derive(Clone)]
struct AppState {
    signing_key: Arc<EcdsaSigningKey>,
    config: config::Config,
    redis_client: RedisClient,
    webauthn: Arc<Webauthn>,
}

// -- Error → Response conversion -------------------------------------------

impl IntoResponse for CustomError {
    fn into_response(self) -> Response {
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
    let pm = oidc::metadata(state.config.base_url)?;
    let mut value = serde_json::to_value(pm)
        .map_err(|e| anyhow::anyhow!("Failed to serialize metadata: {}", e))?;
    value["code_challenge_methods_supported"] = serde_json::json!(["S256"]);
    Ok(value.into())
}

async fn token(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    basic: Option<TypedHeader<Authorization<Basic>>>,
    Form(form): Form<oidc::TokenForm>,
) -> Result<Json<CoreTokenResponse>, CustomError> {
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
    Ok(token_response.into())
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
    let rcr =
        wa::authenticate_start(&state.webauthn, &state.redis_client, session_id).await?;
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
        &state.webauthn,
        &state.redis_client,
        session_id,
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

// -- Application entry point -----------------------------------------------

pub async fn main() {
    let config = Figment::from(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("siwe-oidc.toml").nested())
        .merge(Env::prefixed("SIWEOIDC_").split("__").global());
    let config = config.extract::<config::Config>().unwrap();

    tracing_subscriber::fmt::init();

    // Validate configured DID methods against the siwx-core registry.
    {
        let registered: Vec<String> = all_did_methods()
            .iter()
            .map(|m| m.method_name().to_string())
            .collect();
        for method in &config.supported_did_methods {
            assert!(
                registered.contains(method),
                "FATAL: configured DID method '{}' is not registered in siwx-core (registered: {:?})",
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
                "FATAL: configured pkh namespace '{}' is not registered in siwx-core (registered: {:?})",
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

    let webauthn = wa::build_webauthn(
        &config.base_url,
        config.rp_id.as_deref(),
        config.rp_origin.as_deref(),
    )
    .expect("Failed to initialize WebAuthn — check SIWEOIDC_BASE_URL, SIWEOIDC_RP_ID, SIWEOIDC_RP_ORIGIN");

    let state = AppState {
        signing_key: Arc::new(signing_key),
        config: config.clone(),
        redis_client,
        webauthn: Arc::new(webauthn),
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
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from((config.address, config.port));
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
