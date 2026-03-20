use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use cookie::{Cookie, SameSite};
use headers::{self, authorization::Bearer};
use openidconnect::{
    core::{
        CoreAuthErrorResponseType, CoreAuthPrompt, CoreClaimName, CoreClientAuthMethod,
        CoreClientMetadata, CoreClientRegistrationResponse, CoreErrorResponseType, CoreGenderClaim,
        CoreGrantType, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKey,
        CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRegisterErrorResponseType, CoreResponseType, CoreSubjectIdentifierType,
        CoreTokenResponse, CoreTokenType, CoreUserInfoClaims, CoreUserInfoJsonWebToken,
    },
    registration::{EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse},
    url::Url,
    AccessToken, Audience, AuthUrl, ClientConfigUrl, ClientId, ClientSecret, EmptyAdditionalClaims,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndUserName, EndUserPictureUrl,
    EndUserUsername, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, LocalizedClaim, Nonce, OpPolicyUrl,
    OpTosUrl, PrivateSigningKey, RedirectUrl, RegistrationAccessToken, RegistrationUrl, RequestUrl,
    ResponseTypes, Scope, SigningError, StandardClaims, SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::time;
use thiserror::Error;
use tracing::{debug, error, info};
use urlencoding::decode;
use uuid::Uuid;

use siwx_core::find_did_method;
use siwx_oidc::db::*;
use subtle::ConstantTimeEq;

/// Constant-time string comparison to prevent timing attacks on secrets.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---------------------------------------------------------------------------
// ES256 signing key (replaces RSA — eliminates RUSTSEC-2023-0071 Marvin attack)
// ---------------------------------------------------------------------------

lazy_static::lazy_static! {
    static ref SCOPES: [Scope; 2] = [
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
    ];
}
const SIGNING_ALG: [CoreJwsSigningAlgorithm; 1] = [CoreJwsSigningAlgorithm::EcdsaP256Sha256];
pub const METADATA_PATH: &str = "/.well-known/openid-configuration";
pub const JWK_PATH: &str = "/jwk";
pub const TOKEN_PATH: &str = "/token";
pub const AUTHORIZE_PATH: &str = "/authorize";
pub const REGISTER_PATH: &str = "/register";
pub const CLIENT_PATH: &str = "/client";
pub const USERINFO_PATH: &str = "/userinfo";
pub const SIGNIN_PATH: &str = "/sign_in";
pub const SIWX_COOKIE_KEY: &str = "siwx";
pub const TOU_PATH: &str = "/legal/terms-of-use.pdf";
pub const PP_PATH: &str = "/legal/privacy-policy.pdf";

type DBClientType = dyn DBClient + Sync;

// -- ES256 key wrapper implementing openidconnect's PrivateSigningKey ------

#[derive(Clone)]
pub struct EcdsaSigningKey {
    key: SigningKey,
    kid: Option<JsonWebKeyId>,
}

impl EcdsaSigningKey {
    pub fn from_pem(pem: &str, kid: Option<JsonWebKeyId>) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("Invalid ECDSA private key PEM: {}", e))?;
        Ok(Self { key, kid })
    }

    pub fn generate(kid: Option<JsonWebKeyId>) -> Self {
        let key = SigningKey::random(&mut rand::thread_rng());
        Self { key, kid }
    }

    pub fn to_pem(&self) -> Result<String> {
        let pem = self
            .key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| anyhow!("Failed to encode key as PEM: {}", e))?;
        Ok(pem.to_string())
    }
}

impl PrivateSigningKey for EcdsaSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        _signature_alg: &<CoreJsonWebKey as openidconnect::JsonWebKey>::SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        let sig: Signature = self.key.sign(message);
        // JWS ES256 requires the raw r||s encoding (64 bytes), not DER.
        Ok(sig.to_bytes().to_vec())
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        let verifying_key = self.key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let mut jwk_value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "use": "sig",
            "alg": "ES256",
        });
        if let Some(kid) = &self.kid {
            jwk_value["kid"] = serde_json::Value::String(kid.as_str().to_string());
        }
        serde_json::from_value(jwk_value).expect("Failed to construct EC JWK")
    }
}

// -- Error types -----------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct TokenError {
    pub error: CoreErrorResponseType,
    pub error_description: String,
}

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0:?}")]
    BadRequestRegister(RegisterError),
    #[error("{0:?}")]
    BadRequestToken(TokenError),
    #[error("{0}")]
    Unauthorized(String),
    #[error("Not found")]
    NotFound,
    #[error("{0:?}")]
    Redirect(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// -- JWK / metadata helpers ------------------------------------------------

pub fn jwks(signing_key: &EcdsaSigningKey) -> Result<CoreJsonWebKeySet, CustomError> {
    let jwks = CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);
    Ok(jwks)
}

pub fn metadata(base_url: Url) -> Result<CoreProviderMetadata, CustomError> {
    let pm = CoreProviderMetadata::new(
        IssuerUrl::from_url(base_url.clone()),
        AuthUrl::from_url(
            base_url
                .join(AUTHORIZE_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        JsonWebKeySetUrl::from_url(
            base_url
                .join(JWK_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        vec![
            ResponseTypes::new(vec![CoreResponseType::Code]),
            ResponseTypes::new(vec![CoreResponseType::IdToken]),
            ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        SIGNING_ALG.to_vec(),
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::from_url(
        base_url
            .join(TOKEN_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_endpoint(Some(UserInfoUrl::from_url(
        base_url
            .join(USERINFO_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_signing_alg_values_supported(Some(SIGNING_ALG.to_vec()))
    .set_scopes_supported(Some(SCOPES.to_vec()))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("preferred_username".to_string()),
        CoreClaimName::new("name".to_string()),
        CoreClaimName::new("picture".to_string()),
    ]))
    .set_registration_endpoint(Some(RegistrationUrl::from_url(
        base_url
            .join(REGISTER_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_token_endpoint_auth_methods_supported(Some(vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
    ]))
    .set_op_policy_uri(Some(OpPolicyUrl::from_url(
        base_url
            .join(PP_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_op_tos_uri(Some(OpTosUrl::from_url(
        base_url
            .join(TOU_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )));

    Ok(pm)
}

// -- ENS resolution via Universal Resolver --------------------------------
//
// alloy's built-in lookup_address() uses the legacy ENS registry which
// doesn't support NameWrapper-based reverse records. Primary names set
// through the modern ENS app require the Universal Resolver.

alloy::sol! {
    #[sol(rpc)]
    interface IUniversalResolver {
        function reverse(bytes calldata reverseName) external view
            returns (string name, address resolvedAddress, address reverseResolverAddress, address resolverAddress);
    }
}

/// DNS-encode `<hex_addr>.addr.reverse` for the Universal Resolver (RFC 1035 wire format).
///
/// For address 0x4B23da…, produces:
/// `\x28` + 40-char lowercase hex (no 0x) + `\x04addr\x07reverse\x00`
fn dns_encode_reverse(address: &Address) -> Vec<u8> {
    // Use hex::encode on raw bytes — guaranteed lowercase, no prefix, exactly 40 chars.
    let hex_addr = hex::encode(address.as_slice());
    debug_assert_eq!(hex_addr.len(), 40);
    let labels: [&[u8]; 3] = [hex_addr.as_bytes(), b"addr", b"reverse"];
    let mut buf = Vec::with_capacity(55); // 1+40 + 1+4 + 1+7 + 1 = 55
    for label in &labels {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }
    buf.push(0); // root terminator
    buf
}

/// ENS Universal Resolver on mainnet.
const UNIVERSAL_RESOLVER: Address =
    alloy_primitives::address!("0xeeeeeeee14d718c2b47d9923deab1335e144eeee");

async fn resolve_name(eth_provider: Option<Url>, address: Address) -> Result<String, String> {
    let address_string = address.to_checksum(None);
    let eth_provider = match eth_provider {
        Some(p) => p,
        None => return Err(address_string),
    };
    let provider = alloy::providers::ProviderBuilder::new().connect_http(eth_provider);
    let resolver = IUniversalResolver::new(UNIVERSAL_RESOLVER, &provider);
    let reverse_name = dns_encode_reverse(&address);
    let reverse_bytes: alloy_primitives::Bytes = reverse_name.into();
    debug!(
        "ENS reverse lookup: address={}, encoded_len={}",
        address_string,
        reverse_bytes.len()
    );
    match resolver.reverse(reverse_bytes).call().await {
        Ok(result) if !result.name.is_empty() => {
            info!("ENS resolved: {} -> {}", address_string, result.name);
            Ok(result.name)
        }
        Ok(_) => {
            debug!("ENS reverse returned empty name for {}", address_string);
            Err(address_string)
        }
        Err(e) => {
            error!(
                "ENS Universal Resolver revert for {}: {:?}",
                address_string, e
            );
            Err(address_string)
        }
    }
}

async fn resolve_avatar(_eth_provider: Option<Url>, _ens_name: &str) -> Option<Url> {
    // Avatar resolution requires ENS text record lookup which is not yet
    // available in alloy's ENS extension. This can be added when alloy
    // exposes get_ens_text or via direct contract calls.
    None
}

async fn resolve_claims(eth_provider: Option<Url>, did: &str) -> StandardClaims<CoreGenderClaim> {
    // canonical_subject is the OIDC sub claim — full DID string for did:pkh.
    let subject = find_did_method(did)
        .and_then(|m| m.canonical_subject(did).ok())
        .unwrap_or_else(|| did.to_string());

    // address_for_message is used for ENS resolution input.
    let address_str = find_did_method(did)
        .and_then(|m| m.address_for_message(did).ok())
        .unwrap_or_else(|| did.to_string());

    // ENS resolution only for eip155 DIDs.
    let ens_result = if did.starts_with("did:pkh:eip155:") {
        if let Ok(addr) = address_str.parse::<Address>() {
            Some(resolve_name(eth_provider.clone(), addr).await)
        } else {
            None
        }
    } else {
        None
    };

    let avatar = match ens_result {
        Some(Ok(ref n)) => resolve_avatar(eth_provider, n).await,
        _ => None,
    };

    // preferred_username is ALWAYS the full DID (used as Matrix username).
    // name is the ENS name when available (used as Matrix display name).
    let mut claims = StandardClaims::new(SubjectIdentifier::new(subject))
        .set_preferred_username(Some(EndUserUsername::new(did.to_string())))
        .set_picture(avatar.map(|a| {
            let mut m = LocalizedClaim::new();
            m.insert(None, EndUserPictureUrl::new(a.to_string()));
            m
        }));
    if let Some(Ok(ens_name)) = ens_result {
        let mut m = LocalizedClaim::new();
        m.insert(None, EndUserName::new(ens_name));
        claims = claims.set_name(Some(m));
    }
    claims
}

// -- Token endpoint --------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct TokenForm {
    pub code: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: CoreGrantType,
    /// PKCE code verifier (required if code_challenge was sent in /authorize).
    pub code_verifier: Option<String>,
}

pub async fn token(
    form: TokenForm,
    secret: Option<String>,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<CoreTokenResponse, CustomError> {
    // Validate grant_type.
    if form.grant_type != CoreGrantType::AuthorizationCode {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::UnsupportedGrantType,
            error_description: "Only authorization_code is supported.".to_string(),
        }));
    }

    // Atomically consume the code (prevents race-condition replay).
    let code_entry = db_client
        .try_consume_code(form.code.to_string())
        .await?
        .ok_or_else(|| {
            CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "Unknown or already-exchanged code.".to_string(),
            })
        })?;

    let client_id = if let Some(c) = form.client_id.clone() {
        c
    } else {
        code_entry.client_id.clone()
    };

    if let Some(secret) = if let Some(b) = secret {
        Some(b)
    } else {
        form.client_secret.clone()
    } {
        let client_entry = db_client
            .get_client(client_id.clone())
            .await?
            .ok_or_else(|| CustomError::Unauthorized("Unrecognised client id.".to_string()))?;
        if !constant_time_eq(&secret, &client_entry.secret) {
            return Err(CustomError::Unauthorized("Bad secret.".to_string()));
        }
    } else if config.require_secret {
        return Err(CustomError::Unauthorized("Secret required.".to_string()));
    }

    // PKCE: validate code_verifier if a code_challenge was issued.
    if let Some(ref challenge) = code_entry.code_challenge {
        let verifier = form.code_verifier.as_ref().ok_or_else(|| {
            CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "code_verifier required (PKCE).".to_string(),
            })
        })?;
        let method = code_entry
            .code_challenge_method
            .as_deref()
            .unwrap_or("S256");
        let computed = match method {
            "S256" => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(hash)
            }
            "plain" => verifier.clone(),
            _ => {
                return Err(CustomError::BadRequest(
                    "Unsupported code_challenge_method.".to_string(),
                ))
            }
        };
        if !constant_time_eq(&computed, challenge) {
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "code_verifier mismatch.".to_string(),
            }));
        }
    }

    // Generate a distinct access token (not the code itself).
    let access_token_id = Uuid::new_v4().to_string();
    db_client
        .set_code(access_token_id.clone(), code_entry.clone())
        .await?;
    let access_token = AccessToken::new(access_token_id);
    let core_id_token = CoreIdTokenClaims::new(
        IssuerUrl::from_url(config.base_url.clone()),
        vec![Audience::new(client_id.clone())],
        Utc::now() + Duration::seconds(config.id_token_ttl_secs as i64),
        Utc::now(),
        resolve_claims(config.eth_provider.clone(), &code_entry.did).await,
        EmptyAdditionalClaims {},
    )
    .set_nonce(code_entry.nonce)
    .set_auth_time(Some(code_entry.auth_time));

    let id_token = CoreIdToken::new(
        core_id_token,
        signing_key,
        CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        Some(&access_token),
        None,
    )
    .map_err(|e| anyhow!("{}", e))?;

    let mut response = CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(
        ENTRY_LIFETIME.try_into().unwrap(),
    )));
    Ok(response)
}

// -- Authorize endpoint ----------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: RedirectUrl,
    pub scope: Scope,
    pub response_type: Option<CoreResponseType>,
    pub state: Option<String>,
    pub nonce: Option<Nonce>,
    pub prompt: Option<CoreAuthPrompt>,
    pub request_uri: Option<RequestUrl>,
    pub request: Option<String>,
    /// PKCE code_challenge.
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method ("S256" or "plain").
    pub code_challenge_method: Option<String>,
}

pub async fn authorize(
    params: AuthorizeParams,
    db_client: &DBClientType,
) -> Result<(String, Box<Cookie<'_>>), CustomError> {
    let client_entry = db_client
        .get_client(params.client_id.clone())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
    if client_entry.is_none() {
        return Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        ));
    }

    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let mut r_u = params.redirect_uri.clone().url().clone();
    r_u.set_query(None);
    let mut r_us: Vec<Url> = client_entry
        .unwrap()
        .metadata
        .redirect_uris()
        .clone()
        .iter_mut()
        .map(|u| u.url().clone())
        .collect();
    r_us.iter_mut().for_each(|u| u.set_query(None));
    if !r_us.contains(&r_u) {
        return Err(CustomError::Redirect(
            "/error?message=unregistered_redirect_uri".to_string(),
        ));
    }

    let state = if let Some(s) = params.state.clone() {
        s
    } else if params.request_uri.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestUriNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else if params.request.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing state");
        return Err(CustomError::Redirect(url.to_string()));
    };

    if let Some(CoreAuthPrompt::None) = params.prompt {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::InteractionRequired.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    }

    if params.response_type.is_none() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing response_type");
        return Err(CustomError::Redirect(url.to_string()));
    }
    let _response_type = params.response_type.as_ref().unwrap();

    for scope in params.scope.as_str().trim().split(' ') {
        if !SCOPES.contains(&Scope::new(scope.to_string())) {
            return Err(anyhow!("Scope not supported: {}", scope).into());
        }
    }

    let session_id = Uuid::new_v4();
    let session_secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    db_client
        .set_session(
            session_id.to_string(),
            SessionEntry {
                siwe_nonce: nonce.clone(),
                oidc_nonce: params.nonce.clone(),
                secret: session_secret.clone(),
                signin_count: 0,
            },
        )
        .await?;
    let is_https = params.redirect_uri.url().scheme() == "https";
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .same_site(SameSite::Strict)
        .http_only(true)
        .secure(is_https)
        .max_age(cookie::time::Duration::seconds(
            SESSION_LIFETIME.try_into().unwrap(),
        ))
        .build();

    let domain = params
        .redirect_uri
        .url()
        .host()
        .ok_or_else(|| CustomError::BadRequest("redirect_uri has no host".to_string()))?;
    let oidc_nonce_param = if let Some(n) = &params.nonce {
        format!("&oidc_nonce={}", n.secret())
    } else {
        "".to_string()
    };
    let pkce_params = match (&params.code_challenge, &params.code_challenge_method) {
        (Some(cc), Some(ccm)) => format!("&code_challenge={cc}&code_challenge_method={ccm}"),
        (Some(cc), None) => format!("&code_challenge={cc}&code_challenge_method=S256"),
        _ => "".to_string(),
    };
    Ok((
        format!(
            "/?nonce={}&domain={}&redirect_uri={}&state={}&client_id={}{}{}",
            nonce,
            domain,
            *params.redirect_uri,
            state,
            params.client_id,
            oidc_nonce_param,
            pkce_params
        ),
        Box::new(session_cookie),
    ))
}

// -- SiwX sign-in ----------------------------------------------------------

/// Cookie set by the frontend after the user signs the CAIP-122 challenge.
#[derive(Serialize, Deserialize)]
pub struct SiwxCookie {
    pub did: String,
    /// The canonical CAIP-122 message string that was signed.
    pub message: String,
    /// Hex-encoded signature bytes, optionally prefixed with "0x".
    pub signature: String,
}

/// Extract the `Nonce: {value}` line from a CAIP-122 message.
fn extract_nonce(message: &str) -> Option<&str> {
    message
        .lines()
        .find(|l| l.starts_with("Nonce: "))
        .map(|l| l.trim_start_matches("Nonce: ").trim())
}

/// Extract resource URIs from the `Resources:` section of a CAIP-122 message.
fn extract_resources(message: &str) -> Vec<&str> {
    let mut in_resources = false;
    let mut out = vec![];
    for line in message.lines() {
        if line == "Resources:" {
            in_resources = true;
        } else if in_resources && line.starts_with("- ") {
            out.push(line[2..].trim());
        } else if in_resources {
            break;
        }
    }
    out
}

#[derive(Deserialize)]
pub struct SignInParams {
    pub redirect_uri: RedirectUrl,
    pub state: String,
    pub oidc_nonce: Option<Nonce>,
    pub client_id: String,
    /// PKCE code_challenge (passed through from /authorize).
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method ("S256" or "plain").
    pub code_challenge_method: Option<String>,
}

pub async fn sign_in(
    _base_url: &Url,
    allowed_did_methods: &[String],
    allowed_pkh_namespaces: &[String],
    params: SignInParams,
    cookies: headers::Cookie,
    db_client: &DBClientType,
) -> Result<Url, CustomError> {
    let session_id = if let Some(c) = cookies.get(SESSION_COOKIE_NAME) {
        c
    } else {
        return Err(CustomError::BadRequest(
            "Session cookie not found".to_string(),
        ));
    };
    let session_entry = if let Some(e) = db_client.get_session(session_id.to_string()).await? {
        e
    } else {
        return Err(CustomError::BadRequest("Session not found".to_string()));
    };

    // Atomically mark session as signed-in (prevents race-condition double sign-in).
    if !db_client
        .try_mark_session_signed_in(session_id.to_string())
        .await?
    {
        return Err(CustomError::BadRequest(
            "Session has already logged in".to_string(),
        ));
    }

    let siwx_cookie: SiwxCookie = match cookies.get(SIWX_COOKIE_KEY) {
        Some(c) => serde_json::from_str(
            &decode(c).map_err(|e| anyhow!("Could not decode siwx cookie: {}", e))?,
        )
        .map_err(|e| anyhow!("Could not deserialize siwx cookie: {}", e))?,
        None => {
            return Err(anyhow!("No `siwx` cookie").into());
        }
    };

    // Hex-decode signature ("0x…" or raw hex).
    let sig_hex = siwx_cookie
        .signature
        .strip_prefix("0x")
        .unwrap_or(&siwx_cookie.signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    // Dispatch to the appropriate DID method and verify.
    let did_method = find_did_method(&siwx_cookie.did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", &siwx_cookie.did)))?;

    // Enforce configured allow-lists.
    if !allowed_did_methods
        .iter()
        .any(|m| m == did_method.method_name())
    {
        return Err(CustomError::BadRequest(format!(
            "DID method '{}' is not enabled on this server",
            did_method.method_name()
        )));
    }
    if did_method.method_name() == "pkh" {
        let namespace = siwx_cookie
            .did
            .strip_prefix("did:pkh:")
            .and_then(|s| s.split(':').next())
            .unwrap_or("");
        if !allowed_pkh_namespaces.iter().any(|n| n == namespace) {
            return Err(CustomError::BadRequest(format!(
                "did:pkh namespace '{namespace}' is not enabled on this server"
            )));
        }
    }

    info!("sign_in: did={}", siwx_cookie.did);
    let valid = did_method
        .verify(&siwx_cookie.did, &siwx_cookie.message, &sig_bytes)
        .map_err(|e| anyhow!("Verification error: {}", e))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    // Nonce must match the session.
    let msg_nonce = extract_nonce(&siwx_cookie.message)
        .ok_or_else(|| anyhow!("Nonce not found in CAIP-122 message"))?;
    if msg_nonce != session_entry.siwe_nonce {
        return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
    }

    // At least one resource must match the redirect_uri.
    let redirect_url = params.redirect_uri.url();
    if !extract_resources(&siwx_cookie.message)
        .iter()
        .any(|r| Url::parse(r).ok().as_ref() == Some(redirect_url))
    {
        return Err(anyhow!("Missing or mismatched resource in CAIP-122 message").into());
    }

    let code_entry = CodeEntry {
        did: siwx_cookie.did,
        nonce: params.oidc_nonce.clone(),
        exchange_count: 0,
        client_id: params.client_id.clone(),
        auth_time: Utc::now(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
    };

    let code = Uuid::new_v4();
    db_client.set_code(code.to_string(), code_entry).await?;

    let mut url = params.redirect_uri.url().clone();
    url.query_pairs_mut().append_pair("code", &code.to_string());
    url.query_pairs_mut().append_pair("state", &params.state);
    Ok(url)
}

// -- Client registration ---------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RegisterError {
    error: CoreRegisterErrorResponseType,
}

pub async fn register(
    payload: CoreClientMetadata,
    base_url: Url,
    db_client: &DBClientType,
) -> Result<CoreClientRegistrationResponse, CustomError> {
    let id = Uuid::new_v4();
    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let redirect_uris = payload.redirect_uris().to_vec();
    for uri in redirect_uris.iter() {
        if uri.url().fragment().is_some() {
            return Err(CustomError::BadRequestRegister(RegisterError {
                error: CoreRegisterErrorResponseType::InvalidRedirectUri,
            }));
        }
    }

    let access_token = RegistrationAccessToken::new(
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(11)
            .map(char::from)
            .collect(),
    );

    let entry = ClientEntry {
        secret: secret.clone(),
        metadata: payload,
        access_token: Some(access_token.clone()),
    };
    db_client.set_client(id.to_string(), entry).await?;

    Ok(CoreClientRegistrationResponse::new(
        ClientId::new(id.to_string()),
        redirect_uris,
        EmptyAdditionalClientMetadata::default(),
        EmptyAdditionalClientRegistrationResponse::default(),
    )
    .set_client_secret(Some(ClientSecret::new(secret)))
    .set_registration_client_uri(Some(ClientConfigUrl::from_url(
        base_url
            .join(&format!("{}/{}", CLIENT_PATH, id))
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_registration_access_token(Some(access_token)))
}

// -- Client info / update / delete -----------------------------------------

async fn client_access(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<ClientEntry, CustomError> {
    let access_token = if let Some(b) = bearer {
        b.token().to_string()
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };
    let client_entry = db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?;
    let stored_access_token = client_entry.access_token.clone();
    let stored = stored_access_token
        .as_ref()
        .ok_or_else(|| CustomError::Unauthorized("Bad access token.".to_string()))?;
    if !constant_time_eq(stored.secret(), &access_token) {
        return Err(CustomError::Unauthorized("Bad access token.".to_string()));
    }
    Ok(client_entry)
}

pub async fn clientinfo(
    client_id: String,
    db_client: &DBClientType,
) -> Result<CoreClientMetadata, CustomError> {
    Ok(db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?
        .metadata)
}

pub async fn client_delete(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    client_access(client_id.clone(), bearer, db_client).await?;
    Ok(db_client.delete_client(client_id).await?)
}

pub async fn client_update(
    client_id: String,
    payload: CoreClientMetadata,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    let mut client_entry = client_access(client_id.clone(), bearer, db_client).await?;
    client_entry.metadata = payload;
    Ok(db_client.set_client(client_id, client_entry).await?)
}

// -- UserInfo endpoint -----------------------------------------------------

#[derive(Deserialize)]
pub struct UserInfoPayload {
    pub access_token: Option<String>,
}

pub enum UserInfoResponse {
    Json(CoreUserInfoClaims),
    Jwt(CoreUserInfoJsonWebToken),
}

pub async fn userinfo(
    base_url: Url,
    eth_provider: Option<Url>,
    signing_key: &EcdsaSigningKey,
    bearer: Option<Bearer>,
    payload: UserInfoPayload,
    db_client: &DBClientType,
) -> Result<UserInfoResponse, CustomError> {
    let code = if let Some(b) = bearer {
        b.token().to_string()
    } else if let Some(c) = payload.access_token {
        c
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };
    let code_entry = if let Some(c) = db_client.get_code(code).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown code.".to_string()));
    };

    let client_entry = if let Some(c) = db_client.get_client(code_entry.client_id.clone()).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown client.".to_string()));
    };

    let response = CoreUserInfoClaims::new(
        resolve_claims(eth_provider, &code_entry.did).await,
        EmptyAdditionalClaims::default(),
    )
    .set_issuer(Some(IssuerUrl::from_url(base_url.clone())))
    .set_audiences(Some(vec![Audience::new(code_entry.client_id)]));
    match client_entry.metadata.userinfo_signed_response_alg() {
        None => Ok(UserInfoResponse::Json(response)),
        Some(alg) => Ok(UserInfoResponse::Jwt(
            CoreUserInfoJsonWebToken::new(response, signing_key, alg.clone())
                .map_err(|_| anyhow!("Error signing response."))?,
        )),
    }
}

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use sha3::{Digest, Keccak256};
    use siwx_core::did::{address_from_verifying_key, eip55_checksum};
    use test_log::test;

    #[test]
    fn test_dns_encode_reverse() {
        let addr: Address = "0x4B23da593596D94035c57Adf6C2454216449B1B2"
            .parse()
            .unwrap();
        let encoded = dns_encode_reverse(&addr);
        // \x28 + 40-char hex + \x04 + "addr" + \x07 + "reverse" + \x00
        assert_eq!(encoded.len(), 55);
        assert_eq!(encoded[0], 0x28); // label length = 40
        assert_eq!(&encoded[1..41], b"4b23da593596d94035c57adf6c2454216449b1b2");
        assert_eq!(encoded[41], 0x04);
        assert_eq!(&encoded[42..46], b"addr");
        assert_eq!(encoded[46], 0x07);
        assert_eq!(&encoded[47..54], b"reverse");
        assert_eq!(encoded[54], 0x00);
    }

    async fn default_config() -> (Config, RedisClient) {
        let config = Config::default();
        let db_client = RedisClient::new(&config.redis_url).await.unwrap();
        db_client
            .set_client(
                "client".into(),
                ClientEntry {
                    secret: "secret".into(),
                    metadata: CoreClientMetadata::new(
                        vec![RedirectUrl::new("https://example.com".into()).unwrap()],
                        EmptyAdditionalClientMetadata {},
                    ),
                    access_token: None,
                },
            )
            .await
            .unwrap();
        (config, db_client)
    }

    #[test(tokio::test)]
    async fn test_claims_without_ens() {
        // Without eth_provider, preferred_username is always the full DID.
        let did = "did:pkh:eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let res = resolve_claims(None, did).await;
        assert_eq!(
            res.preferred_username().map(|u| u.to_string()),
            Some(did.to_string())
        );
        // No ENS resolution → name claim should be absent.
        assert!(res.name().is_none());
    }

    #[test(tokio::test)]
    async fn test_claims_non_eip155() {
        // Non-eip155 DID — preferred_username is the full DID, no ENS attempt.
        let did = "did:pkh:ed25519:0xabcdef1234567890";
        let res = resolve_claims(None, did).await;
        assert_eq!(
            res.preferred_username().map(|u| u.to_string()),
            Some(did.to_string())
        );
    }

    #[derive(Deserialize)]
    struct AuthorizeQueryParams {
        nonce: String,
    }

    #[derive(Deserialize)]
    struct SignInQueryParams {
        code: String,
    }

    /// EIP-191 sign helper — mirrors Eip155Suite::verify's prehash logic.
    fn eth_sign(key: &k256::ecdsa::SigningKey, msg: &str) -> String {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(rec_id) + 27;
        format!("0x{}", hex::encode(bytes))
    }

    #[tokio::test]
    async fn e2e_flow() {
        let (_config, db_client) = default_config().await;

        // Generate an eip155 keypair (same approach as Eip155Suite tests).
        let secret = k256::SecretKey::random(&mut rand::thread_rng());
        let signing_key = k256::ecdsa::SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let address_str = format!("0x{}", eip55_checksum(&addr));
        let did = format!("did:pkh:eip155:1:{address_str}");

        let base_url = Url::parse("https://example.com").unwrap();
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(base_url.clone()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::IdToken),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();
        let params: SignInParams = serde_urlencoded::from_str(&redirect_url).unwrap();

        // Build the CAIP-122 message (EIP-4361 format for eip155).
        let message = format!(
            "example.com wants you to sign in with your Ethereum account:\n\
             {address_str}\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: {}\n\
             Issued At: 2023-04-17T11:01:24.862Z\n\
             Resources:\n\
             - https://example.com",
            authorize_params.nonce,
        );
        let signature = eth_sign(&signing_key, &message);
        let siwx_cookie = serde_json::to_string(&SiwxCookie {
            did,
            message,
            signature,
        })
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{cookie}; {SIWX_COOKIE_KEY}={siwx_cookie}")).unwrap(),
        );
        let cookie = headers.typed_get::<headers::Cookie>().unwrap();
        let default_methods = vec!["pkh".to_string()];
        let default_namespaces = vec![
            "eip155".to_string(),
            "ed25519".to_string(),
            "p256".to_string(),
        ];
        let redirect_url = sign_in(
            &base_url,
            &default_methods,
            &default_namespaces,
            params,
            cookie,
            &db_client,
        )
        .await
        .unwrap();
        let signin_params: SignInQueryParams =
            serde_urlencoded::from_str(redirect_url.query().unwrap()).unwrap();
        let oidc_signing_key =
            EcdsaSigningKey::generate(Some(JsonWebKeyId::new("key1".to_string())));
        let _ = userinfo(
            base_url,
            None,
            &oidc_signing_key,
            None,
            UserInfoPayload {
                access_token: Some(signin_params.code),
            },
            &db_client,
        )
        .await
        .unwrap();
    }
}
