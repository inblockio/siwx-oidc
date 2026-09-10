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
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndUserName, EndUserUsername,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, LocalizedClaim, Nonce, OpPolicyUrl, OpTosUrl,
    PrivateSigningKey, RedirectUrl, RefreshToken, RegistrationAccessToken, RegistrationUrl,
    RequestUrl, ResponseTypes, Scope, SigningError, StandardClaims, SubjectIdentifier, TokenUrl,
    UserInfoUrl,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::time;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use urlencoding::decode;
use uuid::Uuid;

use aqua_auth::find_did_method;
use siwx_oidc::db::*;
use subtle::ConstantTimeEq;

use crate::did_assertion::DidPublication;
use crate::synapse_client::{PublishOutcome, SynapseClient};

use crate::introspect::generate_opaque_token;

/// Constant-time string comparison to prevent timing attacks on secrets.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---------------------------------------------------------------------------
// ES256 signing key (replaces RSA — eliminates RUSTSEC-2023-0071 Marvin attack)
// ---------------------------------------------------------------------------

lazy_static::lazy_static! {
    static ref SCOPES: Vec<Scope> = vec![
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
        // Stable Matrix scopes (MSC2967 graduated)
        Scope::new("urn:matrix:client:api:*".to_string()),
        Scope::new("urn:matrix:client:device:*".to_string()),
        // MSC2967 unstable prefixes (still used by Element X)
        Scope::new("urn:matrix:org.matrix.msc2967.client:api:*".to_string()),
        Scope::new("urn:matrix:org.matrix.msc2967.client:device:*".to_string()),
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
pub const TOU_PATH: &str = "/legal/terms-of-use.html";
pub const PP_PATH: &str = "/legal/privacy-policy.html";

type DBClientType = dyn DBClient + Sync;

// -- ES256 key wrapper implementing openidconnect's PrivateSigningKey ------

/// The provider's ES256 signing key, carrying the two facts that anything
/// *durable* signed by it needs to know: **which** key it is (`kid`), and
/// whether it will still exist after the next restart (`ephemeral`).
///
/// # `kid` identifies the KEY, not the slot
///
/// This wrapper used to take a caller-supplied `kid`, and both construction
/// sites in `axum_lib::main` passed the literal `"key1"` — the operator's
/// configured key and the randomly generated fallback were stamped with the
/// SAME identifier. `"key1"` is a *slot* name, not a *key* name, and the
/// distinction stops being cosmetic the moment we sign something that outlives
/// the process.
///
/// DID assertions (`crate::did_assertion`) are written into a user's Synapse
/// profile and stay there indefinitely. Under a constant `kid`, a restart that
/// mints a fresh ephemeral key yields **a different key under the same `kid`**,
/// so every previously stored assertion fails verification as
/// `bad signature` — the single worst diagnostic available, because to a
/// verifier "bad signature" reads as *forgery*, and to an operator it offers
/// nothing to grep for. Deriving `kid` from the public key turns exactly that
/// event into `kid "3f2a…" is not present in the JWKS`: honest, self-describing,
/// and immediately actionable ("the key rotated; set SIWEOIDC_SIGNING_KEY_PEM").
///
/// See `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`
/// §"`kid` must identify the key, not the slot" (hypothesis H4), pinned by
/// `oidc::tests::h4_two_generated_keys_get_different_kids` and
/// `oidc::tests::h4_the_same_pem_yields_the_same_kid_across_constructions`.
///
/// **Do not reintroduce a caller-supplied `kid`.** The constructors deliberately
/// accept no `kid` argument, so a slot name cannot be stamped onto a key again;
/// that absence IS the fix. Likewise, do not "simplify" `kid` back to an
/// `Option<JsonWebKeyId>`: a JWKS entry without a `kid` forces every verifier to
/// trial-verify against every key, which erases the unknown-kid diagnostic this
/// type exists to produce.
#[derive(Clone)]
pub struct EcdsaSigningKey {
    key: SigningKey,
    /// Always present and always derived from `key` — never configured.
    /// See the type-level doc.
    kid: JsonWebKeyId,
    /// `true` when the key was generated at startup and therefore dies with the
    /// process. Read by `did_assertion::mint_did_assertion`, which refuses to
    /// mint a durable, off-server artifact with a key it knows is temporary.
    ephemeral: bool,
}

impl EcdsaSigningKey {
    /// Load the operator's durable key (`SIWEOIDC_SIGNING_KEY_PEM`).
    ///
    /// The resulting key is marked NON-ephemeral, which is what unlocks DID
    /// assertion minting. That marking is a claim about *operator intent*
    /// (a PEM was configured, so the same key is expected across restarts), not
    /// a proof — nothing here can verify the operator will keep passing the same
    /// PEM. The key-derived `kid` is the safety net for when they do not.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("Invalid ECDSA private key PEM: {}", e))?;
        Ok(Self::with_derived_kid(key, false))
    }

    /// Generate a throwaway key for a deployment with no configured PEM.
    ///
    /// Marked ephemeral: tokens signed by it stop verifying at the next restart
    /// (which is merely annoying — clients re-authenticate), and DID assertions
    /// are suppressed entirely (which is the point — see `did_assertion`).
    pub fn generate() -> Self {
        Self::with_derived_kid(SigningKey::random(&mut rand::thread_rng()), true)
    }

    /// The single place a `kid` is computed. Both constructors funnel through
    /// here precisely so the "derive it, never accept it" rule cannot be
    /// violated by adding a third constructor that forgets.
    fn with_derived_kid(key: SigningKey, ephemeral: bool) -> Self {
        let kid = JsonWebKeyId::new(Self::fingerprint_of(&key));
        Self {
            key,
            kid,
            ephemeral,
        }
    }

    /// First 16 hex chars of SHA-256 over the SEC1 **uncompressed** public key.
    ///
    /// 64 bits of a cryptographic hash: not collision-resistant in the
    /// adversarial sense, and it does not need to be. `kid` is a *lookup hint*
    /// into a JWKS this provider publishes — a collision would only ever pick
    /// the wrong key of our own, and the signature check then fails. It is not a
    /// security boundary; the signature is.
    fn fingerprint_of(key: &SigningKey) -> String {
        use sha2::{Digest, Sha256};
        let pubkey = key.verifying_key().to_encoded_point(false);
        let digest = Sha256::digest(pubkey.as_bytes());
        let hex = hex::encode(digest);
        hex[..16].to_string()
    }

    /// Non-sensitive identifier for the signing key: the first 16 hex chars of a
    /// SHA-256 over the SEC1-encoded *public* key. Safe to log — it reveals no
    /// private material but lets operators correlate which ephemeral key is live.
    ///
    /// Identical by construction to `kid()`; kept as a distinct name because the
    /// startup log lines read as "fingerprint" and the JWS header reads as
    /// "kid", and conflating the two names in either place would obscure one of
    /// them.
    pub fn public_key_fingerprint(&self) -> String {
        Self::fingerprint_of(&self.key)
    }

    /// The `kid` published in the JWKS and stamped into every JWS header this
    /// key produces. Derived from the public key; see the type-level doc.
    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    /// `true` when this key was generated at startup and will not survive the
    /// process.
    ///
    /// The one caller that matters is `did_assertion::mint_did_assertion`:
    /// writing a durable assertion into a user's Synapse profile with a key we
    /// KNOW is about to disappear is writing garbage into someone else's
    /// database. Invariant 5 of the plan: never write a durable assertion with
    /// an ephemeral key.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Raw ES256 signature over `message`: **r‖s, exactly 64 bytes, never DER**.
    ///
    /// RFC 7515 §3.1 / RFC 7518 §3.4 mandate the fixed-width concatenation; the
    /// `ecdsa` crate's `Signature::to_bytes()` is already that encoding, while
    /// its `to_der()` is the 70–72 byte X.509 form that every JWS verifier
    /// rejects. Do not "helpfully" switch to DER: the failure is silent at mint
    /// time and only surfaces as an unverifiable proof in a stranger's profile.
    /// `did_assertion::tests::signature_is_64_raw_bytes_never_der` asserts the
    /// length explicitly for exactly this reason.
    pub fn sign_es256(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().to_vec()
    }
}

impl PrivateSigningKey for EcdsaSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        _signature_alg: &<CoreJsonWebKey as openidconnect::JsonWebKey>::SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        // JWS ES256 requires the raw r||s encoding (64 bytes), not DER.
        // Delegated so the ID-token path and the DID-assertion path can never
        // drift onto different signature encodings.
        Ok(self.sign_es256(message))
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
        // Always present: a JWKS entry with no `kid` forces verifiers to
        // trial-verify against every published key, which destroys the
        // "unknown kid" diagnostic that the key-derived `kid` exists to give
        // (see the `EcdsaSigningKey` doc, H4).
        jwk_value["kid"] = serde_json::Value::String(self.kid.as_str().to_string());
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
    /// A presented passkey credential is not registered on this server (a stale or
    /// revoked key chosen from the platform picker). Renders as HTTP 401 with a
    /// machine-readable JSON discriminator so the client can prune it via
    /// `signalUnknownCredential`. Carries the base64url credential id. This is an
    /// EXPECTED user condition, not an internal error: it is logged as
    /// `unknown_credential`, never `internal_error`.
    #[error("unknown_credential: {0}")]
    UnknownCredential(String),
    #[error("Not found")]
    NotFound,
    #[error("{0:?}")]
    Redirect(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<crate::webauthn::VerifyError> for CustomError {
    fn from(e: crate::webauthn::VerifyError) -> Self {
        match e {
            // The single typed case: surface it so handlers return a structured 401.
            crate::webauthn::VerifyError::UnknownCredential(cred_id) => {
                CustomError::UnknownCredential(cred_id)
            }
            // Every other verification failure keeps its existing 500/Other behavior.
            crate::webauthn::VerifyError::Other(inner) => CustomError::Other(inner),
        }
    }
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
    .set_scopes_supported(Some(SCOPES.clone()))
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

/// Build the full OIDC provider-metadata document served at [`METADATA_PATH`],
/// including the non-standard Matrix/MSC extensions that the `openidconnect`
/// crate cannot represent natively (introspection, device authorization,
/// revocation, prompt values, and MSC4191 account management).
///
/// `account_management_uri` is the MSC4191 account-management URL; when `None`
/// it defaults to `{base_url}/account`. The advertised
/// `account_management_actions_supported` list is sourced from
/// [`crate::account::SUPPORTED_ACTIONS`] so discovery and dispatch never drift.
pub fn provider_metadata_value(
    base_url: Url,
    account_management_uri: Option<&Url>,
) -> Result<serde_json::Value, CustomError> {
    let pm = metadata(base_url.clone())?;
    let mut value =
        serde_json::to_value(pm).map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
    let base = base_url.as_str().trim_end_matches('/');
    value["code_challenge_methods_supported"] = serde_json::json!(["S256"]);
    // matrix-js-sdk v42 (Element Web >= 1.12.24) `isValidAuthMetadata` hard-
    // requires BOTH modes here, else it silently falls back to legacy SSO
    // (404 under MSC3861). Only advertised because /sign_in honors fragment —
    // advertising without honoring would be strictly worse for v42 clients.
    value["response_modes_supported"] = serde_json::json!(["query", "fragment"]);
    value["introspection_endpoint"] = serde_json::json!(format!("{}/oauth2/introspect", base));
    value["introspection_endpoint_auth_methods_supported"] =
        serde_json::json!(["client_secret_post", "bearer"]);
    value["grant_types_supported"] = serde_json::json!([
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code"
    ]);
    value["device_authorization_endpoint"] =
        serde_json::json!(format!("{}/device_authorization", base));
    value["revocation_endpoint"] = serde_json::json!(format!("{}/oauth2/revoke", base));
    value["token_endpoint_auth_methods_supported"] =
        serde_json::json!(["client_secret_post", "none"]);
    value["prompt_values_supported"] = serde_json::json!(["login", "create"]);
    // MSC4191: account management discovery (stable v1.18).
    let account_uri = account_management_uri
        .map(|u| u.as_str().to_string())
        .unwrap_or_else(|| format!("{}/account", base));
    value["account_management_uri"] = serde_json::json!(account_uri);
    value["account_management_actions_supported"] =
        serde_json::json!(crate::account::SUPPORTED_ACTIONS);
    Ok(value)
}

// -- ENS resolution -------------------------------------------------------
//
// Primary strategy: HTTP API (handles CCIP Read / NameWrapper / offchain
// names server-side). Default: api.ensdata.net. Override via ens_api_url.
//
// Fallback: on-chain via alloy's legacy ENS registry (eth_provider).
// Does not support NameWrapper but handles classic reverse records.

/// Resolve ENS primary name via HTTP API.
/// API must accept GET /{address} and return JSON with `ens_primary` field.
async fn resolve_name_http(api_url: &Url, address_string: &str) -> Option<String> {
    let url = format!(
        "{}/{}",
        api_url.as_str().trim_end_matches('/'),
        address_string
    );
    let client = reqwest::Client::new();
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(name) = json.get("ens_primary").and_then(|v| v.as_str()) {
                    if !name.is_empty() {
                        info!("ENS resolved (HTTP API): {} -> {}", address_string, name);
                        return Some(name.to_string());
                    }
                }
            }
            None
        }
        Ok(resp) => {
            debug!(
                "ENS API returned status {} for {}",
                resp.status(),
                address_string
            );
            None
        }
        Err(e) => {
            debug!("ENS API request failed for {}: {}", address_string, e);
            None
        }
    }
}

/// Resolve ENS primary name via on-chain legacy ENS registry.
async fn resolve_name_onchain(eth_provider: &Url, address: &Address) -> Option<String> {
    use alloy::ens::ProviderEnsExt;
    let provider = alloy::providers::ProviderBuilder::new().connect_http(eth_provider.clone());
    match provider.lookup_address(address).await {
        Ok(n) => {
            info!("ENS resolved (on-chain): {} -> {}", address, n);
            Some(n)
        }
        Err(e) => {
            debug!("ENS on-chain lookup failed for {}: {}", address, e);
            None
        }
    }
}

async fn resolve_name(
    ens_api_url: Option<&Url>,
    eth_provider: Option<&Url>,
    address: &Address,
) -> Option<String> {
    let address_string = address.to_checksum(None);

    // eth_provider overrides: use on-chain ENS registry directly.
    if let Some(provider) = eth_provider {
        if let Some(name) = resolve_name_onchain(provider, address).await {
            return Some(name);
        }
    }

    // Default: HTTP API (handles CCIP Read / NameWrapper / offchain names).
    if let Some(api_url) = ens_api_url {
        if let Some(name) = resolve_name_http(api_url, &address_string).await {
            return Some(name);
        }
    }

    None
}

async fn resolve_claims(
    config: &crate::config::Config,
    did: &str,
) -> StandardClaims<CoreGenderClaim> {
    // canonical_subject is the OIDC sub claim — full DID string for did:pkh.
    let subject = find_did_method(did)
        .and_then(|m| m.canonical_subject(did).ok())
        .unwrap_or_else(|| did.to_string());

    // address_for_message is used for ENS resolution input.
    let address_str = find_did_method(did)
        .and_then(|m| m.address_for_message(did).ok())
        .unwrap_or_else(|| did.to_string());

    // ENS resolution only for eip155 DIDs.
    let ens_name = if did.starts_with("did:pkh:eip155:") {
        if let Ok(addr) = address_str.parse::<Address>() {
            resolve_name(
                config.ens_api_url.as_ref(),
                config.eth_provider.as_ref(),
                &addr,
            )
            .await
        } else {
            None
        }
    } else {
        None
    };

    // preferred_username is ALWAYS the full DID (used as Matrix username).
    // name is the ENS name when available (used as Matrix display name).
    let mut claims = StandardClaims::new(SubjectIdentifier::new(subject))
        .set_preferred_username(Some(EndUserUsername::new(did.to_string())));
    if let Some(name) = ens_name {
        let mut m = LocalizedClaim::new();
        m.insert(None, EndUserName::new(name));
        claims = claims.set_name(Some(m));
    }
    claims
}

// -- Token endpoint --------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct TokenForm {
    pub code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: CoreGrantType,
    /// PKCE code verifier (required if code_challenge was sent in /authorize).
    pub code_verifier: Option<String>,
    /// Refresh token (required when grant_type=refresh_token).
    pub refresh_token: Option<String>,
    /// Device code (required when grant_type=device_code).
    pub device_code: Option<String>,
}

pub async fn token(
    form: TokenForm,
    secret: Option<String>,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
) -> Result<CoreTokenResponse, CustomError> {
    match form.grant_type {
        CoreGrantType::AuthorizationCode => {
            token_authorization_code(form, secret, signing_key, config, db_client).await
        }
        CoreGrantType::RefreshToken => {
            token_refresh(form, config, db_client).await
        }
        CoreGrantType::DeviceCode => {
            token_device_code(form, signing_key, config, db_client, synapse_client).await
        }
        _ => Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::UnsupportedGrantType,
            error_description: "Supported grant_types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:device_code."
                .to_string(),
        })),
    }
}

async fn token_refresh(
    form: TokenForm,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<CoreTokenResponse, CustomError> {
    let rt = form.refresh_token.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "refresh_token parameter is required.".to_string(),
        })
    })?;

    let metadata = match db_client.get_token(&rt).await? {
        Some(m) => m,
        None => {
            // Grace replay (lost-response recovery): a rotated refresh token is
            // deleted, but its successor pair is recorded under a short grace
            // window. If the client lost the rotation response and retries with the
            // old token, return the SAME successor instead of signing it out.
            // Bounded by REFRESH_GRACE_TTL; genuinely unknown/expired tokens (no
            // grace record) still fail closed below.
            if let Some(succ) = db_client.get_rotated_token(&rt).await? {
                let expires_in = (succ.access_exp - Utc::now().timestamp()).max(0) as u64;
                let mut response = CoreTokenResponse::new(
                    AccessToken::new(succ.access_token),
                    CoreTokenType::Bearer,
                    CoreIdTokenFields::new(None, EmptyExtraTokenFields {}),
                );
                response.set_expires_in(Some(&time::Duration::from_secs(expires_in)));
                response.set_refresh_token(Some(RefreshToken::new(succ.refresh_token)));
                return Ok(response);
            }
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "Unknown or expired refresh token.".to_string(),
            }));
        }
    };

    if metadata.exp <= Utc::now().timestamp() {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Refresh token has expired.".to_string(),
        }));
    }

    // Race guard (S3-3 / H3 + S3-4 / H6): refuse to rotate if this device was just
    // signed out or the user was just deactivated/erased. Mirrors the same check
    // in compat::refresh so neither refresh entry point can resurrect access for a
    // torn-down device / terminated account.
    let device_revoked = !metadata.device_id.is_empty()
        && db_client
            .is_device_revoked(&metadata.username, &metadata.device_id)
            .await?;
    if device_revoked || db_client.is_user_deactivated(&metadata.username).await? {
        let _ = db_client.delete_token(&rt).await;
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Session has been revoked.".to_string(),
        }));
    }

    let (access_prefix, refresh_prefix) = if config.mas_shared_secret.is_some() {
        ("mat_", "mcr_")
    } else {
        ("", "")
    };

    let now = Utc::now().timestamp();

    let new_access = generate_opaque_token(access_prefix);
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
    db_client
        .set_token(&new_access, &access_meta, ACCESS_TOKEN_TTL)
        .await?;

    let new_refresh = generate_opaque_token(refresh_prefix);
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
    db_client
        .set_token(&new_refresh, &refresh_meta, REFRESH_TOKEN_TTL)
        .await?;

    let _ = db_client.delete_token(&rt).await;

    // Check-mint-recheck (S3-3 / H3 + S3-4 / H6): if a revoke/deactivate sweep
    // tombstoned this device/user in the gap between our pre-mint check and our
    // writes, roll back the just-minted tokens so none can be resurrected.
    //
    // Fail OPEN on an indeterminate probe (Redis I/O error), CLOSED only on a
    // definite tombstone. By this point `rt` has already been deleted and the
    // grace pointer is not yet written, so a rollback here leaves the client
    // holding neither the old nor the new refresh token — an unrecoverable
    // sign-out. Treating an I/O error as a tombstone would convert a transient
    // fault into permanent session loss; the tombstone TTL bounds the opposite
    // risk to one access-token cycle (see `RevocationState`).
    let revoked_now = db_client
        .probe_revocation(&metadata.username, &metadata.device_id)
        .await;
    if revoked_now == RevocationState::Indeterminate {
        warn!(
            username = %metadata.username,
            device_id = %metadata.device_id,
            "refresh: revocation probe indeterminate after mint; committing \
             (fail-open, bounded by tombstone TTL)"
        );
    }
    if revoked_now.must_refuse() {
        let _ = db_client.delete_token(&new_access).await;
        let _ = db_client.delete_token(&new_refresh).await;
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Session has been revoked.".to_string(),
        }));
    }

    // Grace window: record old refresh token -> the successor pair we just minted,
    // so a client that LOSES this rotation response (common on mobile) can replay
    // the old token once within REFRESH_GRACE_TTL and recover instead of being
    // signed out. Written only here, on the committed success path (after the
    // H3/H6 check-mint-recheck), so it can never resolve to rolled-back tokens.
    // Best-effort: a failure must not fail the rotation the client will observe.
    let _ = db_client
        .set_rotated_token(
            &rt,
            &RotatedToken {
                access_token: new_access.clone(),
                refresh_token: new_refresh.clone(),
                access_exp: now + ACCESS_TOKEN_TTL as i64,
            },
            REFRESH_GRACE_TTL,
        )
        .await;

    let mut response = CoreTokenResponse::new(
        AccessToken::new(new_access),
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(None, EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(ACCESS_TOKEN_TTL)));
    response.set_refresh_token(Some(RefreshToken::new(new_refresh)));
    Ok(response)
}

fn device_code_error(error: &str, description: &str) -> CustomError {
    CustomError::BadRequestToken(TokenError {
        error: CoreErrorResponseType::Extension(error.to_string()),
        error_description: description.to_string(),
    })
}

async fn token_device_code(
    form: TokenForm,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
) -> Result<CoreTokenResponse, CustomError> {
    if config.mas_shared_secret.is_none() {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::UnsupportedGrantType,
            error_description: "device_code grant requires MSC3861 mode.".to_string(),
        }));
    }

    let dc = form.device_code.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "device_code parameter is required.".to_string(),
        })
    })?;
    let client_id = form.client_id.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "client_id parameter is required.".to_string(),
        })
    })?;

    let mut entry = db_client
        .get_device_code(&dc)
        .await?
        .ok_or_else(|| device_code_error("expired_token", "Device code expired or not found."))?;

    if entry.client_id != client_id {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "client_id mismatch.".to_string(),
        }));
    }

    // Rate limiting: reject if polling faster than the interval.
    let now_ts = Utc::now().timestamp();
    if let Some(last) = entry.last_poll {
        if now_ts - last < DEVICE_CODE_INTERVAL as i64 {
            entry.last_poll = Some(now_ts);
            let _ = db_client
                .update_device_code(&dc, &entry, DEVICE_CODE_LIFETIME)
                .await;
            return Err(device_code_error(
                "slow_down",
                "Polling too fast. Increase interval.",
            ));
        }
    }
    entry.last_poll = Some(now_ts);
    let _ = db_client
        .update_device_code(&dc, &entry, DEVICE_CODE_LIFETIME)
        .await;

    match entry.status {
        DeviceCodeStatus::Pending => Err(device_code_error(
            "authorization_pending",
            "User has not yet approved.",
        )),
        DeviceCodeStatus::Denied => {
            let _ = db_client.delete_device_code(&dc).await;
            let _ = db_client.delete_user_code_mapping(&entry.user_code).await;
            Err(device_code_error(
                "access_denied",
                "User denied the request.",
            ))
        }
        DeviceCodeStatus::Approved => {
            // Atomically claim this approved device_code BEFORE issuing any token
            // (S3-1 / H9). Without this, two concurrent polls both pass the
            // `status == Approved` check and each mint a token pair (+ a phantom
            // device). The SETNX-style claim ensures exactly one poll issues
            // tokens; concurrent losers fall back to authorization_pending (the
            // winner deletes the device_code at the end, so a subsequent poll then
            // gets expired_token — same as a normal completed flow).
            if !db_client.try_claim_device_code(&dc).await? {
                debug!(device_code = %dc, "device_code already claimed by a concurrent poll");
                return Err(device_code_error(
                    "authorization_pending",
                    "Device code is being processed.",
                ));
            }

            let did = entry
                .did
                .as_ref()
                .ok_or_else(|| device_code_error("server_error", "Approved but no DID."))?
                .clone();

            let proposed_device_id = extract_device_id_from_scope(&entry.scope);
            debug!(
                scope = %entry.scope,
                extracted_device_id = ?proposed_device_id,
                "device_code grant: scope extraction"
            );

            let dev_id = if let Some(ref proposed) = proposed_device_id {
                info!(proposed_device_id = %proposed, "using client-proposed device_id from scope");
                proposed.clone()
            } else {
                let generated = format!("SIWX_{}", &Uuid::new_v4().to_string()[..8]);
                warn!(
                    scope = %entry.scope,
                    generated_device_id = %generated,
                    "no device_id found in scope, generating one"
                );
                generated
            };

            // Resolve ONCE (grandfathering decision) and reuse it for both
            // provisioning and TokenMetadata.username, exactly like sign_in.
            // Best-effort: a Synapse hiccup degrades to the legacy localpart
            // (never modern — see resolve_identity_or_legacy's fail-safe
            // direction), matching the pre-existing degraded-provisioning path.
            let resolved = crate::localpart::resolve_identity_or_legacy(&did, synapse_client).await;
            // Same DID publication as the wallet/passkey login path: the QR
            // flow provisions a real session for a real identity, so it must
            // publish (and re-assert) the same attested field. Both call sites
            // route through the ONE `provision_synapse_device`, so there is no
            // third place this could be forgotten.
            let publication = DidPublication {
                key: signing_key,
                issuer: config.base_url.as_str(),
            };
            provision_synapse_device(
                &did,
                &resolved.localpart,
                synapse_client,
                "Element X",
                Some(&dev_id),
                config.matrix_server_name.as_deref(),
                Some(&publication),
            )
            .await;

            let now = Utc::now();
            let iat = now.timestamp();
            let username = resolved.localpart;
            let scope = format!(
                "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
                dev_id
            );

            let claims = resolve_claims(config, &did).await;
            let display_name = claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string())
                .unwrap_or_else(|| did.clone());

            let access_token = generate_opaque_token("mat_");
            let access_meta = TokenMetadata {
                username: username.clone(),
                device_id: dev_id.clone(),
                scope: scope.clone(),
                client_id: client_id.clone(),
                iat,
                exp: iat + ACCESS_TOKEN_TTL as i64,
                did: did.clone(),
                name: display_name.clone(),
            };
            db_client
                .set_token(&access_token, &access_meta, ACCESS_TOKEN_TTL)
                .await?;

            let refresh_token = generate_opaque_token("mcr_");
            let refresh_meta = TokenMetadata {
                username,
                device_id: dev_id.clone(),
                scope: scope.clone(),
                client_id: client_id.clone(),
                iat,
                exp: iat + REFRESH_TOKEN_TTL as i64,
                did: did.clone(),
                name: display_name,
            };
            db_client
                .set_token(&refresh_token, &refresh_meta, REFRESH_TOKEN_TTL)
                .await?;

            let core_id_token = CoreIdTokenClaims::new(
                IssuerUrl::from_url(config.base_url.clone()),
                vec![Audience::new(client_id)],
                now + Duration::seconds(config.id_token_ttl_secs as i64),
                now,
                claims,
                EmptyAdditionalClaims {},
            );

            let id_token = CoreIdToken::new(
                core_id_token,
                signing_key,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                Some(&AccessToken::new(access_token.clone())),
                None,
            )
            .map_err(|e| anyhow!("{}", e))?;

            // Cleanup
            let _ = db_client.delete_device_code(&dc).await;
            let _ = db_client.delete_user_code_mapping(&entry.user_code).await;

            info!(did = %did, device_id = %dev_id, "device_code grant: tokens issued");

            let mut response = CoreTokenResponse::new(
                AccessToken::new(access_token),
                CoreTokenType::Bearer,
                CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
            );
            response.set_expires_in(Some(&time::Duration::from_secs(ACCESS_TOKEN_TTL)));
            response.set_refresh_token(Some(RefreshToken::new(refresh_token)));
            response.set_scopes(Some(
                scope
                    .split_whitespace()
                    .map(|s| Scope::new(s.to_string()))
                    .collect(),
            ));
            Ok(response)
        }
    }
}

async fn token_authorization_code(
    form: TokenForm,
    secret: Option<String>,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<CoreTokenResponse, CustomError> {
    let code = form.code.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "code parameter is required.".to_string(),
        })
    })?;

    let code_entry = db_client.try_consume_code(code).await?.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Unknown or already-exchanged code.".to_string(),
        })
    })?;

    // C2 Step 1: bind the auth code to the client it was issued to. A correct
    // client presents the same `client_id` at /authorize and /token. If the code
    // carries a client_id (always set by `sign_in`), the request's client_id —
    // when present — must match it, and the rest of the function runs against the
    // code's client (never the request's). This prevents a leaked confidential
    // client's code from being redeemed by a different (public) client.
    if !code_entry.client_id.is_empty() {
        if let Some(ref req_client_id) = form.client_id {
            if !constant_time_eq(req_client_id, &code_entry.client_id) {
                return Err(CustomError::BadRequestToken(TokenError {
                    error: CoreErrorResponseType::InvalidGrant,
                    error_description: "client_id does not match the authorization code."
                        .to_string(),
                }));
            }
        }
    }
    let client_id = if !code_entry.client_id.is_empty() {
        code_entry.client_id.clone()
    } else if let Some(c) = form.client_id.clone() {
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
    } else {
        let client_entry = db_client
            .get_client(client_id.clone())
            .await?
            .ok_or_else(|| CustomError::Unauthorized("Unrecognised client id.".to_string()))?;
        match client_entry.metadata.token_endpoint_auth_method() {
            Some(CoreClientAuthMethod::None) => {}
            Some(_) => {
                return Err(CustomError::Unauthorized("Secret required.".to_string()));
            }
            None if config.require_secret => {
                return Err(CustomError::Unauthorized("Secret required.".to_string()));
            }
            None => {}
        }
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
        // C2 Step 4b: reject the `plain` PKCE method. Discovery advertises S256
        // only (`code_challenge_methods_supported = ["S256"]`); no compliant
        // client sends `plain`, and the downgrade weakens the PKCE binding.
        let computed = match method {
            "S256" => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(hash)
            }
            _ => {
                return Err(CustomError::BadRequestToken(TokenError {
                    error: CoreErrorResponseType::InvalidGrant,
                    error_description: "Unsupported code_challenge_method (only S256 is allowed)."
                        .to_string(),
                }));
            }
        };
        if !constant_time_eq(&computed, challenge) {
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "code_verifier mismatch.".to_string(),
            }));
        }
    }

    let msc3861_mode = config.mas_shared_secret.is_some();

    let now = Utc::now();
    let iat = now.timestamp();
    // This request is DIFFERENT from the sign_in that provisioned the account,
    // so the resolved localpart travels via `CodeEntry.localpart` (set at
    // sign_in) rather than being recomputed here. `None` means the entry was
    // written by a pre-migration build with no such field — every account
    // that predates this field is, by definition, a legacy account, so
    // `legacy_localpart` is the correct (not merely best-effort) fallback.
    let username = code_entry
        .localpart
        .clone()
        .unwrap_or_else(|| crate::localpart::legacy_localpart(&code_entry.did));
    let claims = resolve_claims(config, &code_entry.did).await;
    let display_name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .unwrap_or_else(|| code_entry.did.clone());

    let (access_prefix, refresh_prefix, scope) = if msc3861_mode {
        let device_id = code_entry.device_id.clone().unwrap_or_default();
        (
            "mat_",
            "mcr_",
            format!(
                "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
                device_id
            ),
        )
    } else {
        ("", "", "openid profile".to_string())
    };

    let device_id = code_entry.device_id.clone().unwrap_or_default();

    let opaque = generate_opaque_token(access_prefix);
    let access_metadata = TokenMetadata {
        username: username.clone(),
        device_id: device_id.clone(),
        scope: scope.clone(),
        client_id: client_id.clone(),
        iat,
        exp: iat + ACCESS_TOKEN_TTL as i64,
        did: code_entry.did.clone(),
        name: display_name.clone(),
    };
    db_client
        .set_token(&opaque, &access_metadata, ACCESS_TOKEN_TTL)
        .await?;

    let refresh_opaque = generate_opaque_token(refresh_prefix);
    let refresh_metadata = TokenMetadata {
        username,
        device_id,
        scope,
        client_id: client_id.clone(),
        iat,
        exp: iat + REFRESH_TOKEN_TTL as i64,
        did: code_entry.did.clone(),
        name: display_name,
    };
    db_client
        .set_token(&refresh_opaque, &refresh_metadata, REFRESH_TOKEN_TTL)
        .await?;

    let access_token = AccessToken::new(opaque);
    let refresh_token = Some(RefreshToken::new(refresh_opaque));

    let core_id_token = CoreIdTokenClaims::new(
        IssuerUrl::from_url(config.base_url.clone()),
        vec![Audience::new(client_id.clone())],
        now + Duration::seconds(config.id_token_ttl_secs as i64),
        now,
        claims,
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

    let expires_in_secs = ACCESS_TOKEN_TTL;

    let mut response = CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(expires_in_secs)));
    response.set_refresh_token(refresh_token);
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
    /// OAuth response_mode ("query" or "fragment"). matrix-js-sdk v42
    /// (Element Web >= 1.12.24) sends `fragment` and reads the authorization
    /// response ONLY from the URL fragment.
    pub response_mode: Option<String>,
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

    let scope_str = params.scope.as_str().trim();
    let scopes: Vec<&str> = scope_str.split(' ').filter(|s| !s.is_empty()).collect();
    let has_openid = scopes.contains(&"openid");
    let has_matrix_scope = scopes.iter().any(|s| s.starts_with("urn:matrix:"));
    if !has_openid && !has_matrix_scope {
        return Err(
            anyhow!("The 'openid' scope or a Matrix scope (urn:matrix:*) is required.").into(),
        );
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
                verified_did: None,
                scope: Some(params.scope.as_str().to_string()),
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
        .map(|h| h.to_string())
        .unwrap_or_else(|| params.redirect_uri.url().scheme().to_string());
    let oidc_nonce_param = if let Some(n) = &params.nonce {
        format!("&oidc_nonce={}", n.secret())
    } else {
        "".to_string()
    };
    // Validate response_mode strictly (invalid_request semantics): discovery
    // advertises exactly {"query","fragment"}, so anything else is a 400 rather
    // than a silently-ignored param the client then waits on.
    if let Some(rm) = &params.response_mode {
        if rm != "query" && rm != "fragment" {
            return Err(CustomError::BadRequest(format!(
                "Unsupported response_mode '{rm}' (only 'query' and 'fragment' are supported)."
            )));
        }
    }
    // Round-trip the non-default mode through the login SPA to /sign_in (same
    // client-side round-trip as the PKCE params). Absent/"query" appends
    // nothing, keeping the SPA URL byte-identical for existing clients.
    let response_mode_param = if params.response_mode.as_deref() == Some("fragment") {
        "&response_mode=fragment".to_string()
    } else {
        "".to_string()
    };
    // C2 Step 4b: reject `code_challenge_method=plain` up front so a `plain`
    // challenge is never carried into /sign_in or stored on the CodeEntry.
    // Discovery advertises S256 only. A missing method defaults to S256.
    if let Some(ccm) = &params.code_challenge_method {
        if ccm != "S256" {
            return Err(CustomError::BadRequest(
                "Unsupported code_challenge_method (only S256 is allowed).".to_string(),
            ));
        }
    }
    // C2 Step 4a: require S256 PKCE for the authorization-code flow. PKCE is the
    // only backstop that binds a redeemed code to the browser that initiated the
    // request; without it, a leaked or stolen code is freely redeemable. Every
    // real client already sends S256 (Element X per the Matrix OAuth 2.0 profile,
    // the in-house `siwx-oidc-auth` lib, and all e2e flows), so requiring it is a
    // spec-compliance tightening that breaks no compliant client. Scope: ALL
    // code-flow clients — every registered `ClientEntry` carries a server-issued
    // secret regardless of `token_endpoint_auth_method`, so there is no client
    // class that legitimately omits PKCE to exempt. The device-code grant (RFC
    // 8628) does NOT pass through /authorize and is unaffected.
    if matches!(_response_type, CoreResponseType::Code) && params.code_challenge.is_none() {
        return Err(CustomError::BadRequest(
            "code_challenge is required (S256 PKCE) for the authorization-code flow.".to_string(),
        ));
    }
    let pkce_params = match (&params.code_challenge, &params.code_challenge_method) {
        (Some(cc), Some(ccm)) => format!("&code_challenge={cc}&code_challenge_method={ccm}"),
        (Some(cc), None) => format!("&code_challenge={cc}&code_challenge_method=S256"),
        _ => "".to_string(),
    };
    Ok((
        format!(
            "/?nonce={}&domain={}&redirect_uri={}&state={}&client_id={}{}{}{}",
            nonce,
            domain,
            *params.redirect_uri,
            state,
            params.client_id,
            oidc_nonce_param,
            pkce_params,
            response_mode_param
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

/// Extract the `Nonce: {value}` line from a CAIP-122 message. Public so the
/// device/account CAIP-122 paths can read the nonce to consume it from the
/// server-issued single-use nonce store (C1) before validating the envelope.
pub fn extract_nonce_pub(message: &str) -> Option<&str> {
    extract_nonce(message)
}

/// Extract the `Nonce: {value}` line from a CAIP-122 message.
fn extract_nonce(message: &str) -> Option<&str> {
    message
        .lines()
        .find(|l| l.starts_with("Nonce: "))
        .map(|l| l.trim_start_matches("Nonce: ").trim())
}

/// Extract the `Expiration Time: {value}` line from a CAIP-122 message.
fn extract_expiration_time(message: &str) -> Option<&str> {
    message
        .lines()
        .find(|l| l.starts_with("Expiration Time: "))
        .map(|l| l.trim_start_matches("Expiration Time: ").trim())
}

/// C1 (login path): enforce the CAIP-122 `Expiration Time` **only when present**.
/// The browser login frontend (`App.svelte`) sets a 48h `expirationTime`, so for
/// it this closes the "valid forever" replay gap on the login path. A ~120s skew
/// allowance absorbs client/server clock drift.
///
/// **Enforce-if-present (don't break headless clients).** The in-house headless
/// client `siwx-oidc-auth` (the exact login path used by the production agent
/// fleet) does NOT emit an `Expiration Time` line in its CAIP-122 message
/// (`siwx-oidc-auth/src/lib.rs::build_message`). Rejecting messages that omit the
/// line would brick every agent. So a message with NO `Expiration Time` is
/// accepted; a message that HAS one is rejected only when it is actually expired
/// (past, beyond the skew). The replay window for an omitted exp is bounded
/// elsewhere by the single-use nonce / session lifetime.
///
/// Out of scope: the device-approval and account paths (their builders do not set
/// an expiration yet — those are the breaking C1 parts handled in a follow-up).
const CAIP122_EXPIRY_SKEW_SECS: i64 = 120;

fn enforce_login_expiration(message: &str, now: chrono::DateTime<Utc>) -> Result<(), CustomError> {
    // Enforce-if-present: a missing Expiration Time is accepted (headless clients
    // like siwx-oidc-auth legitimately omit it). Only enforce when one is set.
    let Some(raw) = extract_expiration_time(message) else {
        return Ok(());
    };
    let exp = chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| CustomError::BadRequest(format!("Invalid Expiration Time: {}", e)))?
        .with_timezone(&Utc);
    if now - chrono::Duration::seconds(CAIP122_EXPIRY_SKEW_SECS) >= exp {
        return Err(CustomError::BadRequest(
            "CAIP-122 signature has expired".to_string(),
        ));
    }
    Ok(())
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

/// What a CAIP-122 message MUST satisfy for the device-approval / account paths.
///
/// `nonce` is the exact server-issued single-use nonce that was minted for this
/// operation; `resources` is the set of resource URIs that MUST all appear in the
/// message `Resources:` block (this is the operation/domain binding — e.g. the
/// account audience names the specific `action`, so a signature minted for one
/// action cannot be replayed for another).
pub struct Caip122Expectation<'a> {
    pub nonce: &'a str,
    pub resources: &'a [String],
}

/// C1 shared envelope validator for the device-approval and account CAIP-122
/// paths. Unlike the login path (`enforce_login_expiration`, which is lenient
/// because the headless `siwx-oidc-auth` lib omits an Expiration Time), these
/// paths are driven ONLY by the embedded pages, which we update to always emit a
/// server nonce + Expiration Time + Resources — so here all three are MANDATORY.
///
/// Checks, in order:
///  - `Nonce:` is present and exactly equals the expected server-issued nonce
///    (single-use consumption happens at the caller, against the Redis store);
///  - `Expiration Time:` is present, RFC3339-parseable, and not expired (with a
///    [`CAIP122_EXPIRY_SKEW_SECS`] clock-skew allowance) — ABSENT is rejected;
///  - every expected resource URI appears in the message `Resources:` block.
///
/// The single-use / cross-context-binding guarantee is provided by the caller
/// consuming the nonce from the Redis nonce store and checking the bound context;
/// this function validates the *contents* of the signed message.
pub fn validate_caip122_envelope(
    message: &str,
    expected: &Caip122Expectation,
    now: chrono::DateTime<Utc>,
) -> Result<(), CustomError> {
    let msg_nonce = extract_nonce(message).ok_or_else(|| {
        CustomError::BadRequest("Nonce not found in CAIP-122 message".to_string())
    })?;
    if msg_nonce != expected.nonce {
        return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
    }

    // Expiration Time is MANDATORY on these paths (the pages always set it).
    let raw_exp = extract_expiration_time(message).ok_or_else(|| {
        CustomError::BadRequest("CAIP-122 message is missing an Expiration Time".to_string())
    })?;
    let exp = chrono::DateTime::parse_from_rfc3339(raw_exp)
        .map_err(|e| CustomError::BadRequest(format!("Invalid Expiration Time: {}", e)))?
        .with_timezone(&Utc);
    if now - chrono::Duration::seconds(CAIP122_EXPIRY_SKEW_SECS) >= exp {
        return Err(CustomError::BadRequest(
            "CAIP-122 signature has expired".to_string(),
        ));
    }

    // Operation/domain binding: every expected resource must be present.
    let present = extract_resources(message);
    for want in expected.resources {
        if !present.iter().any(|r| r == want) {
            return Err(CustomError::BadRequest(format!(
                "Missing or mismatched resource: {}",
                want
            )));
        }
    }
    Ok(())
}

/// C2 Step 3: re-validate a `redirect_uri` against the client's *registered*
/// redirect_uris, mirroring the exact check in `authorize` (query-stripped exact
/// match). Used by `sign_in` so a code is never appended to an unregistered (e.g.
/// attacker-controlled) redirect_uri — closing the open-redirect on BOTH the
/// wallet (Path B) and WebAuthn (Path A) login paths.
async fn validate_registered_redirect_uri(
    client_id: &str,
    redirect_uri: &RedirectUrl,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    let client_entry = db_client
        .get_client(client_id.to_string())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?
        .ok_or_else(|| CustomError::Unauthorized("Unrecognised client id.".to_string()))?;

    let mut r_u = redirect_uri.url().clone();
    r_u.set_query(None);
    let mut r_us: Vec<Url> = client_entry
        .metadata
        .redirect_uris()
        .clone()
        .iter_mut()
        .map(|u| u.url().clone())
        .collect();
    r_us.iter_mut().for_each(|u| u.set_query(None));
    if !r_us.contains(&r_u) {
        return Err(CustomError::BadRequest(
            "redirect_uri is not registered for this client.".to_string(),
        ));
    }
    Ok(())
}

/// Verify the `siwx` cookie's CAIP-122 signature and nonce against the session.
/// Returns the verified DID on success. Does NOT consume the session.
pub fn verify_siwx_cookie(
    cookies: &headers::Cookie,
    session: &SessionEntry,
    allowed_did_methods: &[String],
    allowed_pkh_namespaces: &[String],
) -> Result<String, CustomError> {
    let siwx_cookie: SiwxCookie = match cookies.get(SIWX_COOKIE_KEY) {
        Some(c) => serde_json::from_str(
            &decode(c).map_err(|e| anyhow!("Could not decode siwx cookie: {}", e))?,
        )
        .map_err(|e| anyhow!("Could not deserialize siwx cookie: {}", e))?,
        None => {
            return Err(CustomError::BadRequest(
                "No `siwx` cookie — sign in with a wallet first".to_string(),
            ));
        }
    };

    let sig_hex = siwx_cookie
        .signature
        .strip_prefix("0x")
        .unwrap_or(&siwx_cookie.signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    let did_method = find_did_method(&siwx_cookie.did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", &siwx_cookie.did)))?;

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

    let valid = did_method
        .verify(&siwx_cookie.did, &siwx_cookie.message, &sig_bytes)
        .map_err(|e| anyhow!("Verification error: {}", e))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    let msg_nonce = extract_nonce(&siwx_cookie.message)
        .ok_or_else(|| anyhow!("Nonce not found in CAIP-122 message"))?;
    if msg_nonce != session.siwe_nonce {
        return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
    }

    // C1 (login path): enforce the message Expiration Time.
    enforce_login_expiration(&siwx_cookie.message, Utc::now())?;

    Ok(siwx_cookie.did)
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
    /// OAuth response_mode (passed through from /authorize; validated there).
    pub response_mode: Option<String>,
}

/// Extract a device_id from a scope string containing `urn:matrix:client:device:XXX`.
fn extract_device_id_from_scope(scope: &str) -> Option<String> {
    const STABLE_PREFIX: &str = "urn:matrix:client:device:";
    const MSC2967_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";
    scope
        .split_whitespace()
        .find_map(|s| {
            s.strip_prefix(STABLE_PREFIX)
                .or_else(|| s.strip_prefix(MSC2967_PREFIX))
                .map(|id| id.to_string())
        })
        .filter(|id| !id.is_empty())
}

/// Resolve the device_id to provision: use the client-proposed id when present,
/// otherwise mint a fresh `SIWX_{uuid8}`.
fn resolve_device_id(proposed_device_id: Option<&str>) -> String {
    match proposed_device_id {
        Some(proposed) => proposed.to_string(),
        None => format!("SIWX_{}", &Uuid::new_v4().to_string()[..8]),
    }
}

/// Provision a Synapse user+device for a DID. Best-effort: failures are logged
/// but never fail the auth flow. Idempotent: re-provisioning the same device_id
/// is a plain upsert that preserves the device's E2EE keys. Never deletes an
/// existing device (device teardown is explicit — see `compat` / account actions).
///
/// **Cross-signing reset arm (product 3B, 2026-07-25):** after upsert, always
/// best-effort `allow_cross_signing_reset` so a half-reset client can publish
/// replacement public keys without requiring a separate `/account` visit on
/// every recovery path. First-time bootstrap still relies on MSC3967 when no
/// master exists; this call is a no-op or soft-fail in that case and must not
/// fail sign-in. Explicit MSC4312 account reauth remains available and still
/// uses the honesty gate in `account.rs`.
///
/// `proposed_device_id`: the client-supplied device_id from the OAuth scope
/// (stable for Element Web and Element X). When `None`, a fresh `SIWX_{uuid}`
/// is minted.
///
/// **Loud failure + self-heal (2026-08-01 incident, discriminator corrected
/// 2026-08-02):** a `provision_user` failure at first sign-in used to be
/// logged at `warn!` and never retried, leaving the account with a Synapse
/// `users` row but no `profiles` row — permanently unable to set a
/// displayname (upstream Synapse #19702). A first-sign-in failure is now
/// logged at `error!`. For an *existing* account (the
/// `is_localpart_available == false` branch), if `server_name` is supplied
/// this also best-effort self-heals: it checks
/// `SynapseClient::has_profile_row` and, only when the row is confirmed
/// truly absent, re-runs `provision_user`. That confirmation is
/// errcode-discriminated (`M_UNKNOWN` = absent, everything else = present or
/// unknown/fail-safe) — a naive "404 = absent" check was live-falsified on
/// Synapse 1.154.0 (a row with a null displayname AND null avatar also
/// 404s) and clobbered a deliberately-cleared displayname before this fix.
/// See the table on `SynapseClient::has_profile_row`. The repair call itself
/// is currently inert on Synapse builds still affected by
/// element-hq/synapse#19702 (`set_displayname` 500s on a row-less account);
/// it self-activates once the deployment's Synapse image is bumped past that
/// fix — see the comment on the heal branch below. `server_name: None` (no
/// `SIWEOIDC_MATRIX_SERVER_NAME` configured) skips the check entirely,
/// preserving prior behavior for standalone deployments. See
/// `docs/superpowers/plans/2026-08-01-provision-retry-hardening.md`.
///
/// `localpart` is the value already decided by
/// [`crate::localpart::resolve_identity`] for this sign-in (grandfathered
/// legacy, already-migrated modern, or a genuinely new modern identity) — it
/// is the single source of truth here; this function does not (re)compute a
/// localpart from `did` itself. The `is_localpart_available` probe below is
/// therefore an idempotent re-confirmation of a decision already made by the
/// caller, not a fresh decision.
///
/// # The three identity tiers, and why they are separated here
///
/// | Tier | Value | Owner | Mutable | Where |
/// |---|---|---|---|---|
/// | alias | a display name | the **user** | yes, freely | Synapse `displayname` |
/// | MXID | `@{base36(sha256(did)[..10])}:{server}` | derived | no (no rename API) | Synapse `users` row |
/// | DID | `did:key:…` / `did:pkh:…` + provider signature | the **provider** | no | profile field `io.inblock.did` |
///
/// Until 2026-09-10 tiers 1 and 3 were **conflated**: `provision_user` was
/// called with `did` as its displayname argument, so a user's only published
/// DID lived in a field the user can rewrite at will (verified live — the ACL
/// probe's leg 5: `displayname` routes through `set_field` → `set_displayname`
/// and never reaches the guard that protects `io.inblock.did`). A consumer
/// reading displayname-as-a-DID could therefore be handed *somebody else's*
/// DID. Splitting the tiers is the security fix; the assertion below is what
/// makes the split checkable off-server. See
/// `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`.
///
/// `did_publication` carries the signing key and issuer for that third tier;
/// `None` disables publication entirely.
pub async fn provision_synapse_device(
    did: &str,
    localpart: &str,
    synapse_client: Option<&SynapseClient>,
    display_name: &str,
    proposed_device_id: Option<&str>,
    server_name: Option<&str>,
    did_publication: Option<&DidPublication<'_>>,
) -> Option<String> {
    let synapse = synapse_client?;
    let dev_id = resolve_device_id(proposed_device_id);
    debug!("provisioning device_id={} for did={}", dev_id, did);

    match synapse.is_localpart_available(localpart).await {
        Ok(true) => {
            // ALIAS TIER SEED — deliberately the localpart, NEVER the DID.
            //
            // `provision_user`'s second argument is the user's *displayname*, a
            // user-writable field. Seeding it with the DID published a
            // provider-looking assertion into a surface any user can rewrite
            // (see the three-tier table above). The localpart is the honest
            // replacement: it is a valid non-empty string, so Synapse still
            // creates the `profiles` row (which is what keeps #19702 at bay for
            // new accounts), and it is exactly what Element renders for a user
            // whose displayname is unset anyway — so nothing regresses
            // visually. A friendlier generated name is an explicit non-goal
            // (plan exclusions): it is a product decision, and this change is a
            // security one.
            if let Err(e) = synapse.provision_user(localpart, localpart).await {
                error!(
                    did = %did,
                    error = %e,
                    "provision_user failed at first sign-in — account may be half-provisioned (no profile row); will retry at next login"
                );
            }
        }
        Ok(false) => {
            // Self-heal: re-check for the case where a PRIOR first-sign-in
            // provision_user call failed, leaving a `users` row but no
            // `profiles` row. Never runs when server_name is unavailable
            // (standalone deployments) and never overwrites an existing row
            // (see SynapseClient::has_profile_row's discriminator table —
            // corrected 2026-08-02 after a live falsification on Synapse
            // 1.154.0 where the original "any 404 = absent" premise clobbered
            // a deliberately-cleared displayname).
            //
            // Repair is currently INERT on Synapse builds affected by
            // element-hq/synapse#19702 (`_check_profile_size` crashes on a
            // row-less account): the has_profile_row check correctly detects
            // the absent row and this branch correctly re-calls
            // provision_user, but that MAS `set_displayname` call itself hits
            // the same upstream bug and 500s (traced live to
            // profile_handler.set_displayname -> profile.py:354). The
            // resulting `error!` line below is intentional per-login
            // observability, not a new failure mode — first-time provisioning
            // is unaffected (registration creates the row before
            // set_displayname is ever called). The heal becomes effective
            // automatically once the deployment's pinned Synapse image is
            // bumped past the upstream fix; no code change will be needed
            // here when that happens.
            //
            // Erasure note: `has_profile_row` also reads a GDPR-erased
            // account's purged row (see account::execute_action's
            // `org.matrix.account_erase`, which calls
            // `SynapseClient::deactivate_user(.., erase: true)`) as "truly
            // absent" by the same M_UNKNOWN discriminator. If an erased
            // account ever completed sign-in again, this would resurrect a
            // bare profile row (displayname = the localpart, since 2026-09-10)
            // — accepted, since that reveals nothing beyond the mxid the caller
            // already presented to authenticate.
            if let Some(server_name) = server_name {
                match synapse.has_profile_row(localpart, server_name).await {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(
                            did = %did,
                            "existing account has no profile row — re-running provisioning (self-heal)"
                        );
                        // Same alias-tier seed as the first-sign-in branch
                        // above: the localpart, never the DID.
                        if let Err(e) = synapse.provision_user(localpart, localpart).await {
                            error!(
                                did = %did,
                                error = %e,
                                "provision_user self-heal retry failed — account remains half-provisioned (expected on Synapse builds still affected by element-hq/synapse#19702; resolves automatically once the pinned image is bumped)"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            did = %did,
                            error = %e,
                            "has_profile_row check failed — skipping self-heal this login"
                        );
                    }
                }
            }
        }
        Err(e) => warn!("is_localpart_available check failed: {}", e),
    }

    // DID TIER — publish the provider-attested DID into the ACL-protected
    // profile field, on EVERY sign-in.
    //
    // # Why re-assert every time instead of only at provisioning
    //
    // This is the self-heal, and it is load-bearing rather than defensive. The
    // Synapse write-ACL we carry (a backport of element-hq/synapse#19980; see
    // `docs/audits/2026-09-10-msc4133-acl-probe.md`) is **prospective only**:
    // it refuses new user writes to this field but neither validates nor
    // migrates a value that was written BEFORE the denylist was applied.
    // Upstream has the identical gap, acknowledged in the PR's review thread
    // `r3783167037`. Re-asserting on every login closes it from the other side,
    // with no janitor process and no migration script: any account whose field
    // a user clobbered while the server was unprotected is corrected the next
    // time that user signs in. The write is idempotent, so the steady-state
    // cost is one PUT per login.
    //
    // # Best-effort, exactly like its neighbours
    //
    // Plan invariant 1: sign-in NEVER fails because of this feature. Every
    // outcome — including a 500 from a row-less account (#19702) — is logged
    // and dropped, the same contract `upsert_device` and
    // `allow_cross_signing_reset` have immediately below.
    //
    // # No `server_name`, no publication
    //
    // The assertion binds an `mxid`, which cannot be built without the server
    // name, and an assertion binding a guessed mxid would be worse than none
    // (it would verify for nobody, or — far worse — for the wrong account on a
    // homeserver that later adopts that name). A standalone deployment with no
    // `SIWEOIDC_MATRIX_SERVER_NAME` therefore skips this entirely, exactly like
    // the self-heal branch above: degrade, never 500.
    if let (Some(publication), Some(server_name)) = (did_publication, server_name) {
        let mxid = crate::synapse_client::matrix_user_id(localpart, server_name);
        let value = crate::did_assertion::did_profile_value(
            publication.key,
            publication.issuer,
            did,
            &mxid,
            Utc::now().timestamp(),
        );
        match synapse
            .publish_did_field(localpart, server_name, &value)
            .await
        {
            Ok(PublishOutcome::Written) => info!(
                did = %did,
                %mxid,
                "published the attested DID profile field"
            ),
            // NOT `error!`: a known, bounded condition of a known-buggy
            // dependency (see SynapseClient::publish_did_field). It resolves by
            // itself once the pinned Synapse image is bumped past #19702.
            Ok(PublishOutcome::RowLessAccount) => warn!(
                did = %did,
                %mxid,
                "attested DID field not written: this account has no profile row                  (element-hq/synapse#19702). Retried automatically at the next sign-in"
            ),
            Err(e) => warn!(
                did = %did,
                %mxid,
                error = %e,
                "publishing the attested DID profile field failed (non-fatal)"
            ),
        }
    }

    if let Err(e) = synapse
        .upsert_device(localpart, &dev_id, Some(display_name))
        .await
    {
        warn!("upsert_device failed: {}", e);
    }

    // 3B: arm reset window after every successful login provision (best-effort).
    if let Err(e) = synapse.allow_cross_signing_reset(localpart).await {
        warn!(
            did = %did,
            error = %e,
            "allow_cross_signing_reset after login provision failed (non-fatal)"
        );
    } else {
        info!(
            did = %did,
            "allow_cross_signing_reset armed after login provision"
        );
    }

    Some(dev_id)
}

/// `did_publication` carries the provider's signing key + issuer for the
/// attested `io.inblock.did` profile field (see
/// [`provision_synapse_device`]). It is built by the axum handler, which is the
/// one place that holds both `AppState::signing_key` and `config.base_url`;
/// `None` disables publication.
#[allow(clippy::too_many_arguments)]
pub async fn sign_in(
    _base_url: &Url,
    allowed_did_methods: &[String],
    allowed_pkh_namespaces: &[String],
    params: SignInParams,
    cookies: headers::Cookie,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
    server_name: Option<&str>,
    did_publication: Option<&DidPublication<'_>>,
) -> Result<(Url, String), CustomError> {
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

    // -- Determine the authenticated DID --
    // Path A: Server-verified ceremony (WebAuthn). The DID was already verified
    //         by the ceremony endpoint and stored in the Redis session — trusted.
    // Path B: Client-set CAIP-122 cookie (existing wallet flow — untrusted, must verify).
    let did = if let Some(ref verified_did) = session_entry.verified_did {
        info!("sign_in: server-verified did={}", verified_did);
        let did_method = find_did_method(verified_did)
            .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", verified_did)))?;
        if !allowed_did_methods
            .iter()
            .any(|m| m == did_method.method_name())
        {
            return Err(CustomError::BadRequest(format!(
                "DID method '{}' is not enabled on this server",
                did_method.method_name()
            )));
        }
        // Enforce pkh namespace allowlist (same check as CAIP-122 path).
        if did_method.method_name() == "pkh" {
            let namespace = verified_did
                .strip_prefix("did:pkh:")
                .and_then(|s| s.split(':').next())
                .unwrap_or("");
            if !allowed_pkh_namespaces.iter().any(|n| n == namespace) {
                return Err(CustomError::BadRequest(format!(
                    "did:pkh namespace '{namespace}' is not enabled on this server"
                )));
            }
        }
        verified_did.clone()
    } else {
        // Path B: CAIP-122 cookie verification (unchanged from original)
        let siwx_cookie: SiwxCookie = match cookies.get(SIWX_COOKIE_KEY) {
            Some(c) => serde_json::from_str(
                &decode(c).map_err(|e| anyhow!("Could not decode siwx cookie: {}", e))?,
            )
            .map_err(|e| anyhow!("Could not deserialize siwx cookie: {}", e))?,
            None => {
                return Err(anyhow!("No `siwx` cookie").into());
            }
        };

        let sig_hex = siwx_cookie
            .signature
            .strip_prefix("0x")
            .unwrap_or(&siwx_cookie.signature);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

        let did_method = find_did_method(&siwx_cookie.did).ok_or_else(|| {
            CustomError::BadRequest(format!("Unsupported DID: {}", &siwx_cookie.did))
        })?;

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

        let msg_nonce = extract_nonce(&siwx_cookie.message)
            .ok_or_else(|| anyhow!("Nonce not found in CAIP-122 message"))?;
        if msg_nonce != session_entry.siwe_nonce {
            return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
        }

        let redirect_url = params.redirect_uri.url();
        if !extract_resources(&siwx_cookie.message)
            .iter()
            .any(|r| Url::parse(r).ok().as_ref() == Some(redirect_url))
        {
            return Err(anyhow!("Missing or mismatched resource in CAIP-122 message").into());
        }

        // C1 (login path): enforce the message Expiration Time. The login
        // frontend already sets a 48h `expirationTime`, so this is server-only
        // and non-breaking. Only the wallet (Path B) CAIP-122 path is affected;
        // the WebAuthn (Path A) ceremony has no CAIP-122 message to expire.
        enforce_login_expiration(&siwx_cookie.message, Utc::now())?;

        siwx_cookie.did
    };

    // Deactivation gate. Synapse's delegated-auth path never checks
    // `users.deactivated` (zero references in `api/auth/mas.py`, 1.159.0) — it
    // trusts our introspection — and `is_localpart_available` reports a
    // deactivated user's localpart as *taken*, so without this a deactivated or
    // erased account signed straight back in and got a full session. Placed
    // after the DID is proven but BEFORE `provision_synapse_device`, so a
    // rejected sign-in leaves no Synapse state behind.
    crate::webauthn::reject_if_deactivated(synapse_client, &did).await?;

    // C2 Step 3: re-validate the request redirect_uri against the client's
    // registered set before issuing the code. `authorize` checks this, but
    // `sign_in` re-receives `redirect_uri` as a query param and previously
    // appended the code to whatever URL was supplied. This closes the open
    // redirect on BOTH the wallet (Path B) and WebAuthn (Path A) paths. Path B
    // additionally binds the redirect via the signed `Resources:` list above;
    // this is the only redirect binding Path A has.
    validate_registered_redirect_uri(&params.client_id, &params.redirect_uri, db_client).await?;

    // Extract client-proposed device_id from the session's stored scope (if any).
    let proposed_device_id = session_entry
        .scope
        .as_deref()
        .and_then(extract_device_id_from_scope);
    // Resolve ONCE (grandfathering decision), and reuse the result as the
    // single source of truth for both provisioning and the CodeEntry the
    // eventual /token exchange reads back. Best-effort: a Synapse hiccup here
    // must not fail sign-in, so an error degrades to the legacy localpart
    // (never the modern one — see resolve_identity_or_legacy's fail-safe
    // direction) exactly like the pre-existing degraded-provisioning path.
    let resolved = crate::localpart::resolve_identity_or_legacy(&did, synapse_client).await;
    let device_id = provision_synapse_device(
        &did,
        &resolved.localpart,
        synapse_client,
        "Element Web",
        proposed_device_id.as_deref(),
        server_name,
        did_publication,
    )
    .await;

    let code_entry = CodeEntry {
        did: did.clone(),
        nonce: params.oidc_nonce.clone(),
        exchange_count: 0,
        client_id: params.client_id.clone(),
        auth_time: Utc::now(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        localpart: Some(resolved.localpart.clone()),
        device_id,
    };

    let code = Uuid::new_v4();
    db_client.set_code(code.to_string(), code_entry).await?;

    let mut url = params.redirect_uri.url().clone();
    if params.response_mode.as_deref() == Some("fragment") {
        // matrix-js-sdk v42 requested `response_mode=fragment` on /authorize
        // (round-tripped here via the login SPA) and reads the authorization
        // response ONLY from the URL fragment. ALL response params go in the
        // fragment; any query the registered redirect_uri already carries stays
        // untouched with nothing appended to it.
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code.to_string())
            .append_pair("state", &params.state)
            .finish();
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().append_pair("code", &code.to_string());
        url.query_pairs_mut().append_pair("state", &params.state);
    }
    // Surface the resolved DID alongside the redirect so the HTTP handler can mint
    // the opaque login user-session cookie ONLY on this success path (a real login
    // that just issued a code). Error/early returns never reach here.
    Ok((url, did))
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
    config: &crate::config::Config,
    signing_key: &EcdsaSigningKey,
    bearer: Option<Bearer>,
    payload: UserInfoPayload,
    db_client: &DBClientType,
) -> Result<UserInfoResponse, CustomError> {
    let token_str = if let Some(b) = bearer {
        b.token().to_string()
    } else if let Some(c) = payload.access_token {
        c
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };

    // Try TokenMetadata first (covers both MSC3861 mat_ tokens and standalone tokens).
    if let Some(metadata) = db_client.get_token(&token_str).await? {
        if metadata.exp <= Utc::now().timestamp() {
            return Err(CustomError::BadRequest("Token expired.".to_string()));
        }
        let client_entry = db_client
            .get_client(metadata.client_id.clone())
            .await?
            .ok_or_else(|| CustomError::BadRequest("Unknown client.".to_string()))?;
        let response = CoreUserInfoClaims::new(
            resolve_claims(config, &metadata.did).await,
            EmptyAdditionalClaims::default(),
        )
        .set_issuer(Some(IssuerUrl::from_url(config.base_url.clone())))
        .set_audiences(Some(vec![Audience::new(metadata.client_id)]));
        return match client_entry.metadata.userinfo_signed_response_alg() {
            None => Ok(UserInfoResponse::Json(response)),
            Some(alg) => Ok(UserInfoResponse::Jwt(
                CoreUserInfoJsonWebToken::new(response, signing_key, alg.clone())
                    .map_err(|_| anyhow!("Error signing response."))?,
            )),
        };
    }

    // Legacy fallback: UUID-based access token backed by code entry (pre-refresh-token deployments).
    let code_entry = if let Some(c) = db_client.get_code(token_str).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown token.".to_string()));
    };

    let client_entry = if let Some(c) = db_client.get_client(code_entry.client_id.clone()).await? {
        c
    } else {
        return Err(CustomError::BadRequest("Unknown client.".to_string()));
    };

    let response = CoreUserInfoClaims::new(
        resolve_claims(config, &code_entry.did).await,
        EmptyAdditionalClaims::default(),
    )
    .set_issuer(Some(IssuerUrl::from_url(config.base_url.clone())))
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
    use aqua_auth::{address_from_verifying_key, eip55_checksum};
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use sha3::{Digest, Keccak256};
    use test_log::test;

    // -- Signing key identity (H4/H5) -------------------------------------
    //
    // These pin the property the whole DID-assertion feature rests on: a `kid`
    // names a KEY, so a key swap is diagnosable. See the `EcdsaSigningKey` doc
    // and `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`.

    /// H4: two independently generated keys must NOT share a `kid`.
    ///
    /// The regression this catches is the old behaviour verbatim — both
    /// constructors were handed the literal `"key1"`, so a restart produced a
    /// different key under an identical `kid` and every durably-stored
    /// assertion started failing as "bad signature" (indistinguishable from
    /// forgery) instead of "unknown kid" (obviously a key rotation).
    #[test]
    fn h4_two_generated_keys_get_different_kids() {
        let a = EcdsaSigningKey::generate();
        let b = EcdsaSigningKey::generate();
        assert_ne!(
            a.kid(),
            b.kid(),
            "independently generated keys must not share a kid"
        );
        assert_eq!(a.kid(), a.public_key_fingerprint());
        assert_eq!(
            a.kid().len(),
            16,
            "kid is the first 16 hex chars of SHA-256 over the SEC1 public key"
        );
        assert!(a.kid().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// H4, the other half: the `kid` is a pure function of the key, so the SAME
    /// PEM yields the SAME `kid` across constructions — which is what makes a
    /// restart with a configured key a no-op for previously issued assertions.
    #[test]
    fn h4_the_same_pem_yields_the_same_kid_across_constructions() {
        let pem = crate::did_assertion::test_p256_pem();
        let first = EcdsaSigningKey::from_pem(&pem).expect("test PEM must load");
        let second = EcdsaSigningKey::from_pem(&pem).expect("test PEM must load");
        assert_eq!(
            first.kid(),
            second.kid(),
            "the same PEM must always produce the same kid"
        );

        // And it really is key-derived, not a constant: a different PEM differs.
        let other = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        assert_ne!(first.kid(), other.kid());
    }

    /// H5 at the key layer: provenance is recorded, and it is the PEM (operator
    /// intent to persist) that marks a key durable.
    #[test]
    fn h5_generated_keys_are_ephemeral_and_pem_keys_are_durable() {
        assert!(
            EcdsaSigningKey::generate().is_ephemeral(),
            "a generated key dies with the process and must say so"
        );
        assert!(
            !EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
                .expect("test PEM must load")
                .is_ephemeral(),
            "a configured PEM is the operator asserting the key persists"
        );
    }

    /// The JWKS a relying party fetches must always carry a `kid`; without one,
    /// a verifier has to trial-verify against every published key and the
    /// "unknown kid" diagnostic disappears.
    #[test]
    fn published_jwk_always_carries_the_derived_kid() {
        use openidconnect::JsonWebKey;
        for key in [
            EcdsaSigningKey::generate(),
            EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem()).unwrap(),
        ] {
            let jwk = key.as_verification_key();
            assert_eq!(
                jwk.key_id().map(|k| k.as_str().to_string()),
                Some(key.kid().to_string()),
                "every published JWK must carry the key-derived kid"
            );
        }
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

    fn config_no_ens() -> Config {
        Config {
            ens_api_url: None,
            eth_provider: None,
            ..Config::default()
        }
    }

    #[test(tokio::test)]
    async fn test_claims_without_ens() {
        // Without ENS config, preferred_username is always the full DID.
        let did = "did:pkh:eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let config = config_no_ens();
        let res = resolve_claims(&config, did).await;
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
        let config = config_no_ens();
        let res = resolve_claims(&config, did).await;
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
        let (config, db_client) = default_config().await;

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
            response_mode: None,
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();
        let params: SignInParams = serde_urlencoded::from_str(&redirect_url).unwrap();

        // Build the CAIP-122 message (EIP-4361 format for eip155). The login
        // path now enforces the Expiration Time (C1 safe subset), so include a
        // future exp — exactly as the real frontend already does.
        let expiration_time =
            (Utc::now() + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let message = format!(
            "example.com wants you to sign in with your Ethereum account:\n\
             {address_str}\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: {}\n\
             Issued At: 2023-04-17T11:01:24.862Z\n\
             Expiration Time: {expiration_time}\n\
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
        let (redirect_url, _did) = sign_in(
            &base_url,
            &default_methods,
            &default_namespaces,
            params,
            cookie,
            &db_client,
            None, // no synapse_client in tests
            None, // no matrix_server_name in tests
            None, // DID publication is off: no Synapse to publish into
        )
        .await
        .unwrap();
        // Default (no response_mode): query delivery, never a fragment.
        assert!(
            redirect_url.fragment().is_none(),
            "default sign_in redirect must not carry a fragment: {redirect_url}"
        );
        let signin_params: SignInQueryParams =
            serde_urlencoded::from_str(redirect_url.query().unwrap()).unwrap();
        let oidc_signing_key = EcdsaSigningKey::generate();
        let _ = userinfo(
            &config,
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

    /// js-sdk v42 path: authorize with `response_mode=fragment` forwards the
    /// mode to the SPA, and sign_in delivers `#code=…&state=…` with NO query
    /// residue (v42 reads the authorization response ONLY from the fragment).
    #[tokio::test]
    async fn e2e_flow_fragment_response_mode() {
        let (_config, db_client) = default_config().await;

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
            response_mode: Some("fragment".into()),
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        assert!(
            redirect_url.contains("&response_mode=fragment"),
            "authorize must forward response_mode to the SPA: {redirect_url}"
        );
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();
        // Same client round-trip as the real SPA: SignInParams reads
        // response_mode back out of the forwarded URL.
        let params: SignInParams = serde_urlencoded::from_str(&redirect_url).unwrap();
        assert_eq!(params.response_mode.as_deref(), Some("fragment"));

        let expiration_time =
            (Utc::now() + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let message = format!(
            "example.com wants you to sign in with your Ethereum account:\n\
             {address_str}\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: {}\n\
             Issued At: 2023-04-17T11:01:24.862Z\n\
             Expiration Time: {expiration_time}\n\
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
        let (redirect_url, _did) = sign_in(
            &base_url,
            &["pkh".to_string()],
            &["eip155".to_string()],
            params,
            cookie,
            &db_client,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            redirect_url.query().is_none(),
            "fragment mode must leave the redirect query untouched: {redirect_url}"
        );
        let fragment = redirect_url
            .fragment()
            .expect("fragment mode must deliver the response in the fragment");
        assert!(
            fragment.contains("code="),
            "fragment must carry the code: {redirect_url}"
        );
        assert!(
            fragment.contains("state=state"),
            "fragment must carry the state: {redirect_url}"
        );
    }

    #[tokio::test]
    async fn authorize_rejects_unsupported_response_mode() {
        let (_config, db_client) = default_config().await;
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("form_post".into()),
        };
        match authorize(params, &db_client).await {
            Err(CustomError::BadRequest(msg)) => {
                assert!(
                    msg.contains("form_post"),
                    "rejection must name the bad value: {msg}"
                );
            }
            other => panic!("expected BadRequest for response_mode=form_post, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_accepts_query_response_mode_without_forwarding() {
        // Explicit "query" is valid but default: the SPA URL stays byte-identical
        // to the absent-param case (nothing forwarded).
        let (_config, db_client) = default_config().await;
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("query".into()),
        };
        let (redirect_url, _cookie) = authorize(params, &db_client).await.unwrap();
        assert!(
            !redirect_url.contains("response_mode"),
            "explicit query mode must not be forwarded: {redirect_url}"
        );
    }

    #[test]
    fn provider_metadata_advertises_response_modes() {
        // js-sdk v42 `isValidAuthMetadata` hard-requires both modes.
        let base = Url::parse("https://siwx-oidc.example.com/").unwrap();
        let value = provider_metadata_value(base, None).unwrap();
        assert_eq!(
            value["response_modes_supported"],
            serde_json::json!(["query", "fragment"])
        );
    }

    #[tokio::test]
    async fn authorize_accepts_matrix_scopes() {
        let (_config, db_client) = default_config().await;
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(
                Url::parse("https://example.com").unwrap(),
            ),
            scope: Scope::new(
                "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEF".to_string(),
            ),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            // C2 Step 4a: PKCE is mandatory for the code flow — a valid S256
            // challenge so this scope-acceptance test exercises the real path.
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_ok(),
            "authorize must accept Matrix scopes: {:?}",
            result.err()
        );
    }

    #[test]
    fn discovery_metadata_contains_matrix_scopes() {
        let base = Url::parse("https://siwx-oidc.example.com").unwrap();
        let pm = metadata(base).unwrap();
        let json = serde_json::to_value(&pm).unwrap();
        let scopes = json["scopes_supported"]
            .as_array()
            .expect("scopes_supported must be an array");
        let scope_strings: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();

        // Core OIDC scopes
        assert!(scope_strings.contains(&"openid"), "missing openid");
        assert!(scope_strings.contains(&"profile"), "missing profile");

        // Stable Matrix scopes
        assert!(
            scope_strings.contains(&"urn:matrix:client:api:*"),
            "missing stable urn:matrix:client:api:*"
        );
        assert!(
            scope_strings.contains(&"urn:matrix:client:device:*"),
            "missing stable urn:matrix:client:device:*"
        );

        // MSC2967 unstable Matrix scopes (used by Element X)
        assert!(
            scope_strings.contains(&"urn:matrix:org.matrix.msc2967.client:api:*"),
            "missing unstable urn:matrix:org.matrix.msc2967.client:api:*"
        );
        assert!(
            scope_strings.contains(&"urn:matrix:org.matrix.msc2967.client:device:*"),
            "missing unstable urn:matrix:org.matrix.msc2967.client:device:*"
        );
    }

    #[test]
    fn provider_metadata_advertises_msc4191_account_management() {
        // AC1: served metadata must include account_management_uri and an
        // account_management_actions_supported array containing the four real
        // actions plus their session_* aliases. Synapse forwards this document
        // verbatim to /_matrix/client/v1/auth_metadata (verified live).
        let base = Url::parse("https://siwx-oidc.example.com/").unwrap();
        let value = provider_metadata_value(base, None).unwrap();

        assert_eq!(
            value["account_management_uri"], "https://siwx-oidc.example.com/account",
            "account_management_uri must default to {{base}}/account"
        );

        let actions: Vec<&str> = value["account_management_actions_supported"]
            .as_array()
            .expect("account_management_actions_supported must be an array")
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        for required in [
            "org.matrix.profile",
            "org.matrix.devices_list",
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.cross_signing_reset",
            "org.matrix.account_deactivate",
            "org.matrix.account_erase",
            "org.matrix.account_reactivate",
            "org.matrix.sessions_list",
            "org.matrix.session_view",
            "org.matrix.session_end",
        ] {
            assert!(actions.contains(&required), "missing action {required}");
        }
    }

    #[test]
    fn provider_metadata_honours_account_management_uri_override() {
        let base = Url::parse("https://siwx-oidc.example.com/").unwrap();
        let override_uri = Url::parse("https://account.example.com/manage").unwrap();
        let value = provider_metadata_value(base, Some(&override_uri)).unwrap();
        assert_eq!(
            value["account_management_uri"],
            "https://account.example.com/manage"
        );
    }

    #[tokio::test]
    async fn authorize_accepts_matrix_only_scopes_without_openid() {
        let (_config, db_client) = default_config().await;
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(
                Url::parse("https://example.com").unwrap(),
            ),
            scope: Scope::new(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEF".to_string(),
            ),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            // C2 Step 4a: PKCE is mandatory for the code flow — a valid S256
            // challenge so this scope-acceptance test exercises the real path.
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_ok(),
            "authorize must accept Matrix-only scopes (no openid): {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn authorize_rejects_invalid_scope() {
        let (_config, db_client) = default_config().await;
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("profile email".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_err(),
            "authorize must reject scopes without openid or urn:matrix:*"
        );
    }

    #[test]
    fn test_extract_device_id_from_scope() {
        // Stable prefix
        assert_eq!(
            extract_device_id_from_scope(
                "openid urn:matrix:client:api:* urn:matrix:client:device:W6ujlqyJoG5+BxH9eLdYgizkylgTS9z6ZzWqRM0FIBQ"
            ),
            Some("W6ujlqyJoG5+BxH9eLdYgizkylgTS9z6ZzWqRM0FIBQ".to_string())
        );
        assert_eq!(
            extract_device_id_from_scope(
                "openid urn:matrix:client:api:* urn:matrix:client:device:SIWX_43efbac7"
            ),
            Some("SIWX_43efbac7".to_string())
        );
        // MSC2967 unstable prefix (used by Element X)
        assert_eq!(
            extract_device_id_from_scope(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:CW2fdkGgZZW8StwGioe2CVKBb3685OjKt8wRUR0iZyc"
            ),
            Some("CW2fdkGgZZW8StwGioe2CVKBb3685OjKt8wRUR0iZyc".to_string())
        );
        // Device ID with slash (base64url-encoded, as sent by Element X)
        assert_eq!(
            extract_device_id_from_scope(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:r8LXBERpNLfhbR3a/Wy1m9xE6ennsd2RJltz0xLrt3A"
            ),
            Some("r8LXBERpNLfhbR3a/Wy1m9xE6ennsd2RJltz0xLrt3A".to_string())
        );
        assert_eq!(extract_device_id_from_scope("openid"), None);
        assert_eq!(
            extract_device_id_from_scope("openid urn:matrix:client:api:*"),
            None
        );
        assert_eq!(
            extract_device_id_from_scope("openid urn:matrix:client:device:"),
            None
        );
    }

    #[test]
    fn test_resolve_device_id_uses_proposed() {
        let id = resolve_device_id(Some("2VeUcPZUV5"));
        assert_eq!(id, "2VeUcPZUV5");
    }

    #[test]
    fn test_resolve_device_id_mints_when_absent() {
        let id = resolve_device_id(None);
        assert!(id.starts_with("SIWX_"));
        assert_eq!(id.len(), "SIWX_".len() + 8);
    }

    /// Build a minimal CAIP-122-shaped message, optionally carrying an
    /// `Expiration Time:` line (mirrors what the browser frontend would emit).
    fn login_message_with_exp(exp: Option<&str>) -> String {
        let mut msg = String::from(
            "example.com wants you to sign in with your Ethereum account:\n\
             0xabc\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: deadbeef\n\
             Issued At: 2023-04-17T11:01:24.862Z\n",
        );
        if let Some(e) = exp {
            msg.push_str(&format!("Expiration Time: {e}\n"));
        }
        msg.push_str("Resources:\n- https://example.com");
        msg
    }

    /// Enforce-if-present: a message with NO `Expiration Time` line is ACCEPTED.
    /// This is the headless-client (siwx-oidc-auth) login path — its
    /// `build_message` omits the line, and rejecting it would brick the agent
    /// fleet.
    #[test]
    fn login_expiration_missing_is_accepted() {
        let now = Utc::now();
        let msg = login_message_with_exp(None);
        assert!(
            enforce_login_expiration(&msg, now).is_ok(),
            "a message with no Expiration Time must be accepted (headless clients omit it)"
        );
    }

    /// Enforce-if-present: a message WITH an Expiration Time in the PAST (beyond
    /// the skew) is REJECTED with an "expired" error.
    #[test]
    fn login_expiration_present_but_expired_is_rejected() {
        let now = Utc::now();
        let past = (now - Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let msg = login_message_with_exp(Some(&past));
        let err = enforce_login_expiration(&msg, now)
            .expect_err("a present-but-expired Expiration Time must be rejected");
        let rendered = format!("{err:?}").to_lowercase();
        assert!(
            rendered.contains("expire"),
            "rejection must mention expiry: {rendered}"
        );
    }

    /// Enforce-if-present: a message WITH a future Expiration Time is ACCEPTED.
    #[test]
    fn login_expiration_present_and_future_is_accepted() {
        let now = Utc::now();
        let future =
            (now + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let msg = login_message_with_exp(Some(&future));
        assert!(
            enforce_login_expiration(&msg, now).is_ok(),
            "a future Expiration Time must be accepted"
        );
    }
}

/// **H11** — the alias tier and the DID tier stay separated.
///
/// # What is being pinned, and why it is a security test
///
/// `SynapseClient::provision_user`'s second argument is the account's
/// **displayname**, and displayname is user-writable: it routes through
/// Synapse's `set_field` -> `set_displayname` and never reaches the
/// profile-field guard the `io.inblock.did` denylist installs. That was not
/// inferred, it was measured — `docs/audits/2026-09-10-msc4133-acl-probe.md`
/// leg 5, where a plain user's PUT to `displayname` answered **200** on the
/// very image where the same user's PUT to `io.inblock.did` answered 403.
///
/// So passing the DID there published a provider-looking DID into a field any
/// user can rewrite, and a consumer reading displayname-as-a-DID could be
/// handed somebody else's. The fix is one argument; the test is here because
/// nothing else about the system changes if it regresses — provisioning still
/// succeeds, sign-in still works, and every other test stays green.
///
/// # The mock
///
/// Extends `localpart.rs`'s `spawn_mock_synapse` pattern (in-process axum on an
/// ephemeral port, built only from crates already in `[dependencies]`) to the
/// four MAS endpoints `provision_synapse_device` touches, recording every
/// request body. `did_publication` is `None` throughout: these tests are about
/// the alias tier, and `None` keeps them free of the Redis-backed admin mint
/// that the DID tier needs.
#[cfg(test)]
mod provision_synapse_device_tests {
    use super::*;
    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// Mixed case ON PURPOSE: a `did:key` payload is case-sensitive, and the
    /// legacy localpart derived from it is lowercased. A test using an
    /// all-lowercase DID could not tell "displayname is the localpart" apart
    /// from "displayname is the DID, lowercased".
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const LOCALPART: &str = "k3f9x2q7ab4d8m1p";
    const SERVER_NAME: &str = "inblock.io";

    #[derive(Clone)]
    struct MockState {
        /// Request bodies, keyed by the MAS endpoint's last path segment.
        calls: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
        /// True when `is_localpart_available` should answer "free" (a brand-new
        /// account), false when it should answer "taken" (a returning one).
        localpart_free: bool,
        /// Body served by `GET /_matrix/client/v3/profile/{mxid}`, as a
        /// `(status, json)` pair. `M_UNKNOWN` at 404 is the ONLY shape
        /// `has_profile_row` reads as "truly absent" (see its table).
        profile_reply: (axum::http::StatusCode, serde_json::Value),
    }

    async fn record(
        state: &MockState,
        endpoint: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        state
            .calls
            .lock()
            .unwrap()
            .entry(endpoint.to_string())
            .or_default()
            .push(body);
        (axum::http::StatusCode::OK, Json(serde_json::json!({}))).into_response()
    }

    async fn spawn(
        localpart_free: bool,
        profile_reply: (axum::http::StatusCode, serde_json::Value),
    ) -> (
        SynapseClient,
        Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let calls: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = MockState {
            calls: calls.clone(),
            localpart_free,
            profile_reply,
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mock-synapse port");
        let addr = listener.local_addr().expect("mock-synapse local_addr");

        let app = Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                get(|State(s): State<MockState>| async move {
                    if s.localpart_free {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"available": true})),
                        )
                            .into_response()
                    } else {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"errcode": "M_USER_IN_USE"})),
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/_synapse/mas/provision_user",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "provision_user", b).await
                    },
                ),
            )
            .route(
                "/_synapse/mas/upsert_device",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "upsert_device", b).await
                    },
                ),
            )
            .route(
                "/_synapse/mas/allow_cross_signing_reset",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "allow_cross_signing_reset", b).await
                    },
                ),
            )
            .route(
                "/_matrix/client/v3/profile/{mxid}",
                get(|State(s): State<MockState>| async move {
                    (s.profile_reply.0, Json(s.profile_reply.1.clone())).into_response()
                }),
            )
            .route(
                "/_matrix/client/v3/profile/{mxid}/{field}",
                axum::routing::put(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "publish_did_field", b).await
                    },
                ),
            )
            // Anything the routes above do not claim is recorded under
            // `unmatched`, so a test can assert that a request was NOT made.
            // Without this, "no profile write happened" would be a vacuous
            // assertion about a key the mock never writes under any
            // circumstances — the exact shape of a test that passes while
            // proving nothing.
            .fallback(
                |State(s): State<MockState>, req: axum::extract::Request| async move {
                    let seen = serde_json::json!({
                        "method": req.method().to_string(),
                        "path": req.uri().path().to_string(),
                    });
                    record(&s, "unmatched", seen).await
                },
            )
            .with_state(state);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock-synapse");
        });
        let client = SynapseClient::new(&format!("http://{addr}"), "shared-secret");
        (client, calls, handle)
    }

    /// Every `provision_user` body recorded by the mock.
    fn provision_bodies(
        calls: &Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
    ) -> Vec<serde_json::Value> {
        calls
            .lock()
            .unwrap()
            .get("provision_user")
            .cloned()
            .unwrap_or_default()
    }

    /// Assert a recorded `provision_user` body seeds the displayname with the
    /// localpart and NOT with the DID, in any spelling.
    fn assert_alias_is_not_the_did(body: &serde_json::Value) {
        let display = body["set_displayname"]
            .as_str()
            .expect("provision_user must send set_displayname");
        assert_eq!(
            body["localpart"].as_str().unwrap(),
            LOCALPART,
            "the localpart must be the one the caller resolved, not one re-derived here"
        );
        assert_eq!(
            display, LOCALPART,
            "the displayname seed must be the localpart (ACL probe leg 5: displayname is \
             USER-WRITABLE, so a DID published there is not provider-owned)"
        );
        assert_ne!(display, DID, "the DID must never be the displayname");
        // Case-insensitively too: `legacy_localpart` lowercases, so a
        // regression that passed a lowercased DID would still be a DID in a
        // user-writable field.
        assert!(
            !display.to_ascii_lowercase().contains("did:"),
            "no DID in any spelling may reach the alias tier: {display}"
        );
    }

    /// H11, first sign-in: a brand-new account is provisioned with the
    /// localpart as its displayname.
    #[tokio::test]
    async fn h11_first_signin_seeds_displayname_with_the_localpart_never_the_did() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ true,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;

        let device_id = provision_synapse_device(
            DID,
            LOCALPART,
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None, // DID publication off: this test is about the alias tier
        )
        .await;
        assert_eq!(device_id.as_deref(), Some("SIWX_test"));

        let bodies = provision_bodies(&calls);
        assert_eq!(
            bodies.len(),
            1,
            "a new account is provisioned exactly once: {bodies:?}"
        );
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// H11, self-heal: the row-absent repair path uses the same seed.
    ///
    /// This is the second (and only other) `provision_user` call site. A fix
    /// applied to just the first one would leave the DID leaking into
    /// displayname for exactly the accounts that are already damaged.
    #[tokio::test]
    async fn h11_self_heal_seeds_displayname_with_the_localpart_never_the_did() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            // The one 404 shape `has_profile_row` reads as truly absent.
            (
                axum::http::StatusCode::NOT_FOUND,
                serde_json::json!({"errcode": "M_UNKNOWN", "error": "No row found"}),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            LOCALPART,
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        let bodies = provision_bodies(&calls);
        assert_eq!(
            bodies.len(),
            1,
            "the self-heal must re-run provisioning exactly once: {bodies:?}"
        );
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// GRANDFATHERING: a returning account with a profile row is never
    /// re-provisioned, so a displayname the user chose is never clobbered.
    ///
    /// This is the claim that makes the seed change safe to ship without a
    /// migration. It is asserted rather than assumed because it is a claim
    /// about a code path (`Ok(false)` + `has_profile_row == true` -> no call),
    /// not about intent, and the same argument is what protects the deliberate
    /// clearing of a displayname that the 2026-08-02 discriminator fix was
    /// written for.
    #[tokio::test]
    async fn existing_account_with_a_profile_row_is_never_reprovisioned() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (
                axum::http::StatusCode::OK,
                serde_json::json!({"displayname": "A Name The User Chose"}),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            LOCALPART,
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        assert!(
            provision_bodies(&calls).is_empty(),
            "a returning account with a profile row must NOT be re-provisioned; \
             doing so would overwrite the user's own displayname"
        );
        // The rest of the login-time provisioning still ran.
        let calls = calls.lock().unwrap();
        assert!(calls.contains_key("upsert_device"));
        assert!(calls.contains_key("allow_cross_signing_reset"));
        handle.abort();
    }

    /// The POSITIVE wiring test: with a `server_name` and a publication
    /// context, `provision_synapse_device` really does write the attested DID
    /// field.
    ///
    /// The `no_server_name_…` test below proves the feature can be turned off;
    /// on its own that is also what a deleted call site looks like. This one
    /// proves the call site exists and is reached from the function BOTH
    /// sign-in paths route through — which is the single insertion point the
    /// whole design depends on.
    ///
    /// Needs Redis, because publication goes through the admin mint (see
    /// `synapse_client`'s publish tests for the same constraint and the pure
    /// classifier that keeps the classification covered when this skips).
    #[tokio::test]
    async fn publication_is_wired_into_the_shared_signin_path() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;
        let Ok(redis) =
            siwx_oidc::db::RedisClient::new(&url::Url::parse("redis://localhost").unwrap()).await
        else {
            eprintln!(
                "SKIP publication_is_wired_into_the_shared_signin_path: no Redis on localhost"
            );
            handle.abort();
            return;
        };
        let synapse = synapse.with_admin_mint(redis, "siwx-admin".to_string(), 300);

        let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        let publication = DidPublication {
            key: &key,
            issuer: "https://issuer.example",
        };

        provision_synapse_device(
            DID,
            LOCALPART,
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            Some(&publication),
        )
        .await;

        let calls = calls.lock().unwrap();
        let published = calls
            .get("publish_did_field")
            .expect("the DID field must be published on every sign-in");
        assert_eq!(published.len(), 1, "exactly one write per sign-in");
        let value = &published[0][crate::did_assertion::DID_PROFILE_FIELD];
        assert_eq!(
            value["did"].as_str(),
            Some(DID),
            "the exact-case DID must be what lands in the profile: {:?}",
            published[0]
        );
        assert!(
            value["proof"]
                .as_str()
                .is_some_and(|p| p.split('.').count() == 3),
            "a durable key must publish a three-part compact JWS: {:?}",
            published[0]
        );
        handle.abort();
    }

    /// With no `server_name`, nothing is published and nothing 500s.
    ///
    /// A standalone deployment (no `SIWEOIDC_MATRIX_SERVER_NAME`) cannot build
    /// an mxid, and an assertion binding a guessed mxid would be worse than
    /// none. The DID tier is skipped entirely; the rest of provisioning is
    /// unaffected. Plan invariant: degrade, never 500.
    #[tokio::test]
    async fn no_server_name_skips_publication_without_disturbing_provisioning() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ true,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;

        let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        let publication = DidPublication {
            key: &key,
            issuer: "https://issuer.example",
        };

        let device_id = provision_synapse_device(
            DID,
            LOCALPART,
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            None, // no SIWEOIDC_MATRIX_SERVER_NAME
            Some(&publication),
        )
        .await;

        assert_eq!(device_id.as_deref(), Some("SIWX_test"));
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.get("unmatched"),
            None,
            "no request may be made outside the four MAS endpoints — in particular no              PUT to the profile route — when there is no server_name to build an mxid from"
        );
        assert!(calls.contains_key("provision_user"));
        assert!(calls.contains_key("upsert_device"));
        handle.abort();
    }
}
