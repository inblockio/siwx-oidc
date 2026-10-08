//! Headless OIDC client for siwx-oidc.
//!
//! Performs the full authorization code flow using a local Ed25519 or P-256
//! private key, without any browser or user interaction. The key is identified
//! as a `did:key` DID; the server must have `"key"` in `supported_did_methods`.
//!
//! # Example
//!
//! ```no_run
//! use siwx_oidc_auth::{SiwxKey, authenticate};
//!
//! #[tokio::main]
//! async fn main() {
//!     let key = SiwxKey::from_pem_file("identity.pem".as_ref()).unwrap();
//!     let tokens = authenticate(
//!         "https://siwx.example.com",
//!         "my-client-id",
//!         "https://app.example.com/callback",
//!         &key,
//!     ).await.unwrap();
//!     println!("id_token: {:?}", tokens.id_token);
//! }
//! ```

pub mod did_assertion;

/// Verification of the provider-attested DID published in a Matrix profile.
///
/// Re-exported at the crate root so a consumer never has to know which module
/// the binding check lives in. Read [`did_assertion`]'s module docs before
/// using any of it: the field is a **discovery hint**, not an authorization
/// source, and [`fetch_and_verify_did`] is the entry point that makes the
/// anti-replay mxid binding impossible to forget.
pub use did_assertion::{
    fetch_and_verify_did, verify_did_assertion, DidAssertionError, VerifiedDid, DID_PROFILE_FIELD,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer, SigningKey as Ed25519SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;
use reqwest::{header, redirect::Policy, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;
use urlencoding::encode;

// Multicodec varint prefixes (same as aqua-auth key module)
const ED25519_PREFIX: &[u8] = &[0xED, 0x01];
const P256_PREFIX: &[u8] = &[0x80, 0x24];

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// A local signing key used for headless authentication.
pub enum SiwxKey {
    Ed25519(Ed25519SigningKey),
    P256(P256SigningKey),
}

impl SiwxKey {
    // -- PEM (primary) -----------------------------------------------------

    /// Load a private key from a PKCS#8 PEM string.
    ///
    /// Auto-detects Ed25519 vs P-256 from the PKCS#8 algorithm OID.
    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(key) = Ed25519SigningKey::from_pkcs8_pem(pem) {
            return Ok(SiwxKey::Ed25519(key));
        }
        if let Ok(key) = <P256SigningKey as DecodePrivateKey>::from_pkcs8_pem(pem) {
            return Ok(SiwxKey::P256(key));
        }
        bail!("PEM does not contain a recognized Ed25519 or P-256 PKCS#8 private key")
    }

    /// Load a private key from a PKCS#8 PEM file.
    ///
    /// Auto-detects Ed25519 vs P-256 from the PKCS#8 algorithm OID.
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read key file: {}", path.display()))?;
        Self::from_pem(&pem)
    }

    /// Export the private key as a PKCS#8 PEM string.
    pub fn to_pem(&self) -> Result<String> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use p256::pkcs8::LineEnding;
        match self {
            SiwxKey::Ed25519(key) => {
                let pem = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| anyhow!("failed to encode Ed25519 key as PEM: {e}"))?;
                Ok(pem.to_string())
            }
            SiwxKey::P256(key) => {
                let pem = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| anyhow!("failed to encode P-256 key as PEM: {e}"))?;
                Ok(pem.to_string())
            }
        }
    }

    // -- Hex (dev / testing) -----------------------------------------------

    /// Load an Ed25519 key from a 32-byte hex-encoded seed.
    pub fn ed25519_from_hex(hex_seed: &str) -> Result<Self> {
        let bytes = hex::decode(hex_seed).context("invalid hex for Ed25519 seed")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("Ed25519 seed must be 32 bytes"))?;
        Ok(SiwxKey::Ed25519(Ed25519SigningKey::from_bytes(&seed)))
    }

    /// Load a P-256 key from a 32-byte hex-encoded scalar.
    pub fn p256_from_hex(hex_scalar: &str) -> Result<Self> {
        let bytes = hex::decode(hex_scalar).context("invalid hex for P-256 scalar")?;
        let key = P256SigningKey::from_slice(&bytes).context("invalid P-256 scalar")?;
        Ok(SiwxKey::P256(key))
    }

    // -- Generation --------------------------------------------------------

    /// Generate a random Ed25519 key.
    pub fn generate_ed25519() -> Self {
        SiwxKey::Ed25519(Ed25519SigningKey::generate(&mut OsRng))
    }

    /// Generate a random P-256 key.
    pub fn generate_p256() -> Self {
        SiwxKey::P256(P256SigningKey::random(&mut OsRng))
    }

    // -- DID derivation ----------------------------------------------------

    /// The `did:key:z…` DID derived from this key.
    pub fn did(&self) -> String {
        match self {
            SiwxKey::Ed25519(key) => {
                let mut bytes = ED25519_PREFIX.to_vec();
                bytes.extend_from_slice(key.verifying_key().as_bytes());
                format!("did:key:z{}", bs58::encode(&bytes).into_string())
            }
            SiwxKey::P256(key) => {
                let compressed = key.verifying_key().to_encoded_point(true);
                let mut bytes = P256_PREFIX.to_vec();
                bytes.extend_from_slice(compressed.as_bytes());
                format!("did:key:z{}", bs58::encode(&bytes).into_string())
            }
        }
    }

    /// The key type label for display.
    pub fn type_label(&self) -> &'static str {
        match self {
            SiwxKey::Ed25519(_) => "Ed25519",
            SiwxKey::P256(_) => "P-256",
        }
    }

    /// Sign `message` and return the hex-encoded signature.
    fn sign(&self, message: &str) -> String {
        match self {
            SiwxKey::Ed25519(key) => {
                let sig = key.sign(message.as_bytes());
                hex::encode(sig.to_bytes())
            }
            SiwxKey::P256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(message.as_bytes());
                hex::encode(sig.to_bytes())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CAIP-122 message building
// ---------------------------------------------------------------------------

fn build_message(domain: &str, key: &SiwxKey, redirect_uri: &str, nonce: &str) -> String {
    let did = key.did();
    let z_encoded = did.strip_prefix("did:key:").unwrap_or(&did);
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    format!(
        "{domain} wants you to sign in with your {type_label} key:\n\
         {z_encoded}\n\n\
         You are signing in to {domain}.\n\n\
         URI: {redirect_uri}\n\
         Version: 1\n\
         Nonce: {nonce}\n\
         Issued At: {now}\n\
         Resources:\n\
         - {redirect_uri}",
        type_label = key.type_label(),
    )
}

// ---------------------------------------------------------------------------
// OAuth scope construction
// ---------------------------------------------------------------------------

/// The scopes every flow asks for, whether or not a device is proposed.
///
/// - `offline_access`: the client relies on refresh tokens (`refresh`, and the
///   advice to refresh instead of signing in again). A generic-mode server
///   issues one only for this scope.
/// - `urn:matrix:client:api:*`: the access token is used against a Matrix
///   homeserver's client-server API. A Matrix deployment grants this scope
///   whatever is asked today; asking for it keeps the client working against a
///   server that grants it only on request.
///
/// A server that does not know a scope ignores it at `/authorize`, so this is
/// harmless against a deployment that has no use for it.
const RELIED_ON_SCOPES: [&str; 2] = ["offline_access", "urn:matrix:client:api:*"];

/// Build the OAuth `scope` requested at `/authorize`.
///
/// - `None`: `openid profile` plus [`RELIED_ON_SCOPES`].
/// - `Some(id)`: the same, plus the stable Matrix device URN so the server pins
///   this exact Synapse device_id instead of minting a fresh `SIWX_<uuid>` on
///   every login. The siwx-oidc server validates the scope (it contains
///   `openid`) and extracts the id via `extract_device_id_from_scope`, which
///   strips the `urn:matrix:client:device:` prefix. The stable prefix is
///   preferred over the `urn:matrix:org.matrix.msc2967.client:device:`
///   (MSC2967 unstable) form.
fn build_scope(device_id: Option<&str>) -> String {
    let mut scopes = vec!["openid", "profile"];
    scopes.extend(RELIED_ON_SCOPES);
    let mut scope = scopes.join(" ");
    if let Some(id) = device_id {
        scope.push_str(" urn:matrix:client:device:");
        scope.push_str(id);
    }
    scope
}

/// The `scope` [`authenticate_with_device`] requests at `/authorize` for
/// `device_id` (and [`authenticate`] for `None`).
///
/// A Matrix-mode server records the Matrix scope whatever was requested and
/// never echoes the request, so a live check cannot read the scope off the
/// server; it reads it here. The unit test
/// `the_code_flow_sends_the_scope_it_relies_on` pins that this is exactly the
/// value on the wire.
pub fn code_flow_scope(device_id: Option<&str>) -> String {
    build_scope(device_id)
}

/// The `scope` the device flow requests at `/device_authorization`:
/// `openid` plus [`RELIED_ON_SCOPES`].
fn build_device_flow_scope() -> String {
    let mut scopes = vec!["openid"];
    scopes.extend(RELIED_ON_SCOPES);
    scopes.join(" ")
}

// ---------------------------------------------------------------------------
// Token response
// ---------------------------------------------------------------------------

/// Tokens returned by a successful headless authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    /// Token lifetime in seconds (from the server's `expires_in` field).
    pub expires_in: Option<u64>,
    /// Refresh token for obtaining new access tokens without re-authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The `did:key:z…` DID that authenticated.
    pub did: String,
}

// ---------------------------------------------------------------------------
// Internal wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeRedirectParams {
    nonce: String,
    state: String,
    redirect_uri: String,
    client_id: String,
}

#[derive(Serialize)]
struct SiwxCookie<'a> {
    did: &'a str,
    message: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct TokenResponseRaw {
    access_token: String,
    token_type: String,
    id_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuthResponseRaw {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

// ---------------------------------------------------------------------------
// Authorization code flow
// ---------------------------------------------------------------------------

/// Perform the full siwx-oidc authorization code flow with a local signing key.
///
/// - `server_url`: Base URL of the siwx-oidc server (e.g. `"https://siwx.example.com"`).
/// - `client_id`: OIDC client ID registered with the server.
/// - `redirect_uri`: Registered redirect URI. The server validates the CAIP-122
///   message contains this URI in its `Resources:` section.
/// - `key`: Local signing key used to derive the DID and sign the challenge.
///
/// The server must have `"key"` in `supported_did_methods` for `did:key` to work.
///
/// To re-authenticate when tokens expire, call this function again — the flow
/// is stateless and the key is deterministic.
///
/// This is the backward-compatible entry point: it requests no device, so the
/// server mints a fresh `SIWX_<uuid>` Synapse device on each login. To pin a
/// stable device_id, use [`authenticate_with_device`]. The scope it requests is
/// `openid profile offline_access urn:matrix:client:api:*`; a client that is not
/// a Matrix client chooses its own with [`authenticate_with_scope`].
pub async fn authenticate(
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
) -> Result<AuthTokens> {
    authenticate_with_device(server_url, client_id, redirect_uri, key, None).await
}

/// Perform the authorization code flow, optionally pinning a stable Matrix
/// device_id.
///
/// Same as [`authenticate`], plus:
///
/// - `device_id`: when `Some(id)`, requests the `urn:matrix:client:device:{id}`
///   scope so the siwx-oidc server provisions (and re-provisions) that exact
///   Synapse device rather than minting a fresh `SIWX_<uuid>` on every login.
///   Re-provisioning the same id is an idempotent upsert that preserves the
///   device's E2EE keys, so a long-lived service account keeps one stable
///   device. When `None`, behaves identically to [`authenticate`].
pub async fn authenticate_with_device(
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
    device_id: Option<&str>,
) -> Result<AuthTokens> {
    let client = flow_client()?;
    code_flow(
        &client,
        server_url,
        client_id,
        redirect_uri,
        key,
        &build_scope(device_id),
    )
    .await
}

/// Perform the authorization code flow for a scope the caller chooses.
///
/// Same flow as [`authenticate`], except for `scope`, which is sent to
/// `/authorize` exactly as given: nothing is added (the scopes the other entry
/// points rely on, [`RELIED_ON_SCOPES`], are not appended), nothing is removed,
/// and nothing is checked. An empty scope, or one without `openid`, is for the
/// server to refuse.
///
/// This is the entry point for a client that is not a Matrix client. A
/// generic-class client (a mail client, say) is granted only the scopes its
/// registration allows, and a Matrix scope in its request is dropped, so
/// [`authenticate`], which always asks for `urn:matrix:client:api:*`, is the
/// wrong choice for it:
///
/// ```no_run
/// # async fn demo(key: &siwx_oidc_auth::SiwxKey) -> anyhow::Result<()> {
/// let tokens = siwx_oidc_auth::authenticate_with_scope(
///     "https://siwx.example.com",
///     "my-mail-client",
///     "https://mail.example.com/callback",
///     key,
///     "openid io.inblock.mail offline_access",
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// The returned [`AuthTokens`] does not say which scope the server granted.
/// A refresh token is present only when the server issued one, which for a
/// generic-class client takes `offline_access` in the scope.
///
/// A server that refuses the request (a scope the client may not have, for
/// one) is reported with the reason it gave:
/// `/authorize refused the request: invalid_scope: ...`.
///
/// Builds its own HTTP client, which does not follow redirects. To use your own
/// (a proxy, a timeout, a root certificate), call
/// [`authenticate_with_scope_using`].
pub async fn authenticate_with_scope(
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
    scope: &str,
) -> Result<AuthTokens> {
    let client = flow_client()?;
    authenticate_with_scope_using(&client, server_url, client_id, redirect_uri, key, scope).await
}

/// [`authenticate_with_scope`] over a `client` the caller built.
///
/// **`client` must not follow redirects**: build it with
/// `reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())`.
/// The flow reads the `Location` header of the redirects from `/authorize` and
/// `/sign_in` itself, and a client that follows them hands it a page instead.
/// A 2xx where a 303 is due is reported as an error that names the redirect
/// policy. Reqwest cannot tell the flow which policy a client has, so this is
/// the only check.
///
/// The flow sends its cookies itself, so `client` should carry no cookie store.
/// Timeouts, proxies and root certificates set on `client` apply to every
/// request of the flow.
pub async fn authenticate_with_scope_using(
    client: &reqwest::Client,
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
    scope: &str,
) -> Result<AuthTokens> {
    code_flow(client, server_url, client_id, redirect_uri, key, scope).await
}

/// The HTTP client the flows build for themselves. It must not follow
/// redirects: the code flow reads the `Location` header of two of them.
fn flow_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .context("failed to build HTTP client")
}

/// The error for a response from `endpoint` that is not the 303 redirect the
/// code flow is waiting for.
///
/// A success status gets its own message, because it is what a client that
/// follows redirects sees at the end of the redirect: the login page, a 200.
fn not_the_redirect(endpoint: &str, status: StatusCode, body: Option<&str>) -> anyhow::Error {
    if status.is_success() {
        return anyhow!(
            "{endpoint} returned {status} where a 303 redirect was expected: either the HTTP \
             client followed the redirect, or the server did not redirect. The flow reads the \
             Location header itself, so the client must be built with \
             `reqwest::redirect::Policy::none()`"
        );
    }
    match body {
        Some(body) => anyhow!("{endpoint} returned {status}: {body}"),
        None => anyhow!("{endpoint} returned {status} instead of 303"),
    }
}

/// What the server says when it refuses the authorization request.
///
/// `/authorize` refuses a request it can still answer, an unsupported scope for
/// one, with a 303 to the redirect URI whose query carries `error` and
/// `error_description`. That redirect sets no session cookie, so a flow that read
/// the cookie first would report a missing cookie and hide the reason. `None`
/// when `location` is no refusal.
fn authorize_refusal(base: &Url, location: &str) -> Option<String> {
    let redirect = base.join(location).ok()?;
    let mut error = None;
    let mut description = None;
    for (name, value) in redirect.query_pairs() {
        match name.as_ref() {
            "error" => error = Some(value.into_owned()),
            "error_description" => description = Some(value.into_owned()),
            _ => {}
        }
    }
    let error = error?;
    Some(match description {
        Some(description) => format!("{error}: {description}"),
        None => error,
    })
}

/// The authorization code flow every code-flow entry point runs: PKCE,
/// `/authorize`, the CAIP-122 signature at `/sign_in`, and the code exchange at
/// `/token`. `scope` is sent as given; the callers decide what it is.
async fn code_flow(
    client: &reqwest::Client,
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
    scope: &str,
) -> Result<AuthTokens> {
    let base = Url::parse(server_url).context("invalid server_url")?;

    // -----------------------------------------------------------------------
    // PKCE: generate code_verifier and code_challenge (S256)
    // -----------------------------------------------------------------------
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    let code_verifier: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(128)
        .map(char::from)
        .collect();
    let code_challenge = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    };

    // -----------------------------------------------------------------------
    // Step 1: GET /authorize — get nonce + session cookie
    // -----------------------------------------------------------------------
    let authorize_url = base.join("/authorize")?;
    let resp = client
        .get(authorize_url)
        .query(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", scope),
            ("response_type", "code"),
            ("state", "headless"),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .context("GET /authorize failed")?;

    if resp.status() != StatusCode::SEE_OTHER {
        return Err(not_the_redirect("/authorize", resp.status(), None));
    }

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    if let Some(reason) = location.and_then(|location| authorize_refusal(&base, location)) {
        return Err(anyhow!("/authorize refused the request: {reason}"));
    }

    let session_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("session=") {
                Some(s.split(';').next()?.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("/authorize response missing session cookie"))?;

    let location =
        location.ok_or_else(|| anyhow!("/authorize response missing Location header"))?;

    let redirect_url = base.join(location).context("invalid Location header")?;
    let params: AuthorizeRedirectParams =
        serde_urlencoded::from_str(redirect_url.query().unwrap_or(""))
            .context("failed to parse authorize redirect query params")?;

    // -----------------------------------------------------------------------
    // Step 2: Build CAIP-122 message and sign
    // -----------------------------------------------------------------------
    let domain = base
        .host_str()
        .ok_or_else(|| anyhow!("server_url has no host"))?;
    let message = build_message(domain, key, redirect_uri, &params.nonce);
    let did = key.did();
    let signature = key.sign(&message);

    // -----------------------------------------------------------------------
    // Step 3: GET /sign_in with session + siwx cookies
    // -----------------------------------------------------------------------
    let siwx_json = serde_json::to_string(&SiwxCookie {
        did: &did,
        message: &message,
        signature: &signature,
    })?;
    let siwx_cookie_value = encode(&siwx_json);
    let cookie_header = format!("{session_cookie}; siwx={siwx_cookie_value}");

    let sign_in_url = base.join("/sign_in")?;
    let resp = client
        .get(sign_in_url)
        .query(&[
            ("redirect_uri", params.redirect_uri.as_str()),
            ("state", params.state.as_str()),
            ("client_id", params.client_id.as_str()),
        ])
        .header(header::COOKIE, &cookie_header)
        .send()
        .await
        .context("GET /sign_in failed")?;

    if resp.status() != StatusCode::SEE_OTHER {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(not_the_redirect("/sign_in", status, Some(&body)));
    }

    let code_location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("/sign_in response missing Location header"))?;

    let code_url = Url::parse(code_location)
        .or_else(|_| base.join(code_location))
        .context("invalid Location from /sign_in")?;

    let code = code_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow!("no 'code' in /sign_in redirect: {code_location}"))?;

    // -----------------------------------------------------------------------
    // Step 4: POST /token — exchange code for tokens
    // -----------------------------------------------------------------------
    let token_url = base.join("/token")?;
    let resp = client
        .post(token_url)
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .context("POST /token failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("/token returned {status}: {body}");
    }

    let raw: TokenResponseRaw = resp.json().await.context("/token JSON parse failed")?;
    Ok(AuthTokens {
        access_token: raw.access_token,
        token_type: raw.token_type,
        id_token: raw.id_token,
        expires_in: raw.expires_in,
        refresh_token: raw.refresh_token,
        did,
    })
}

// ---------------------------------------------------------------------------
// Refresh token exchange
// ---------------------------------------------------------------------------

/// Exchange a refresh token for a new set of tokens.
///
/// The server rotates the refresh token on each use: the returned `AuthTokens`
/// contains a new `refresh_token` that replaces the one passed in.
///
/// - `server_url`: Base URL of the siwx-oidc server.
/// - `client_id`: OIDC client ID.
/// - `refresh_token`: The refresh token from a previous `authenticate()` or `refresh()` call.
/// - `did`: The DID associated with this session, copied into the returned
///   `AuthTokens::did` for the caller. It is not sent: the refresh request
///   carries no signature and needs no key, and its response has no ID token.
pub async fn refresh(
    server_url: &str,
    client_id: &str,
    refresh_token: &str,
    did: &str,
) -> Result<AuthTokens> {
    let base = Url::parse(server_url).context("invalid server_url")?;
    let client = flow_client()?;

    let token_url = base.join("/token")?;
    let resp = client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("POST /token (refresh) failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("/token refresh returned {status}: {body}");
    }

    let raw: TokenResponseRaw = resp
        .json()
        .await
        .context("/token refresh JSON parse failed")?;
    Ok(AuthTokens {
        access_token: raw.access_token,
        token_type: raw.token_type,
        id_token: raw.id_token,
        expires_in: raw.expires_in,
        refresh_token: raw.refresh_token,
        did: did.to_string(),
    })
}

// ---------------------------------------------------------------------------
// DID extraction from JWT
// ---------------------------------------------------------------------------

fn extract_did_from_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// RFC 8628 Device Authorization Grant
// ---------------------------------------------------------------------------

/// Perform the RFC 8628 device authorization grant flow.
///
/// No local signing key is needed; the user approves on another device
/// (browser with wallet or passkey). Intended for headless servers and CI.
///
/// - `server_url`: Base URL of the siwx-oidc server.
/// - `client_id`: OIDC client ID registered with the server.
///
/// Requests the scope `openid offline_access urn:matrix:client:api:*`: the
/// tokens are used against a Matrix homeserver and refreshed.
///
/// Prints the user code and verification URI to stderr, then polls until
/// approved, denied, or expired.
pub async fn authenticate_device_flow(server_url: &str, client_id: &str) -> Result<AuthTokens> {
    let base = Url::parse(server_url).context("invalid server_url")?;
    let client = reqwest::Client::new();

    // Step 1: POST /device_authorization
    let device_auth_url = base.join("/device_authorization")?;
    let resp = client
        .post(device_auth_url)
        .form(&[
            ("client_id", client_id),
            ("scope", build_device_flow_scope().as_str()),
        ])
        .send()
        .await
        .context("POST /device_authorization failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("/device_authorization returned {status}: {body}");
    }

    let device_auth: DeviceAuthResponseRaw = resp
        .json()
        .await
        .context("/device_authorization JSON parse failed")?;

    // Step 2: Display instructions
    eprintln!();
    eprintln!("To approve this device, open:");
    eprintln!("  {}", device_auth.verification_uri_complete);
    eprintln!();
    eprintln!(
        "Or go to {} and enter code: {}",
        device_auth.verification_uri, device_auth.user_code
    );
    eprintln!();
    eprintln!(
        "Waiting for approval (expires in {}s)...",
        device_auth.expires_in
    );

    // Step 3: Poll POST /token until approved
    let token_url = base.join("/token")?;
    let mut interval = device_auth.interval;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(device_auth.expires_in);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

        if std::time::Instant::now() > deadline {
            bail!(
                "Device code expired (no approval within {}s)",
                device_auth.expires_in
            );
        }

        let resp = client
            .post(token_url.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_auth.device_code.as_str()),
                ("client_id", client_id),
            ])
            .send()
            .await
            .context("POST /token (device poll) failed")?;

        if resp.status().is_success() {
            let raw: TokenResponseRaw = resp.json().await.context("/token JSON parse failed")?;
            let did = raw
                .id_token
                .as_ref()
                .and_then(|t| extract_did_from_id_token(t))
                .unwrap_or_default();
            eprintln!("Approved!");
            return Ok(AuthTokens {
                access_token: raw.access_token,
                token_type: raw.token_type,
                id_token: raw.id_token,
                expires_in: raw.expires_in,
                refresh_token: raw.refresh_token,
                did,
            });
        }

        let body = resp.text().await.unwrap_or_default();
        let err: TokenErrorResponse =
            serde_json::from_str(&body).unwrap_or_else(|_| TokenErrorResponse {
                error: "unknown".to_string(),
                error_description: Some(body),
            });

        match err.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => {
                interval += 5;
            }
            "access_denied" => {
                bail!("Device login was denied by the user");
            }
            "expired_token" => {
                bail!("Device code expired");
            }
            other => {
                let desc = err.error_description.unwrap_or_default();
                bail!("/token error: {other}: {desc}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// What the client asks for in the code flow, in the order it asks.
    const CODE_FLOW_SCOPE: &str = "openid profile offline_access urn:matrix:client:api:*";
    /// What the client asks for in the device flow.
    const DEVICE_FLOW_SCOPE: &str = "openid offline_access urn:matrix:client:api:*";

    #[test]
    fn build_scope_none_asks_for_what_the_client_relies_on() {
        assert_eq!(build_scope(None), CODE_FLOW_SCOPE);
    }

    #[test]
    fn build_scope_some_requests_stable_device() {
        let scope = build_scope(Some("agent-x"));
        // Must contain the stable Matrix device URN the server extracts from.
        assert_eq!(
            scope,
            format!("{CODE_FLOW_SCOPE} urn:matrix:client:device:agent-x")
        );
        assert!(scope.contains("urn:matrix:client:device:agent-x"));
        // Still an OIDC request (keeps openid + profile).
        assert!(scope.starts_with("openid profile"));
    }

    /// The client relies on a refresh token (`offline_access`: a generic-mode
    /// server issues one only for it) and, against a Matrix deployment, on the
    /// Matrix client-server API (`urn:matrix:client:api:*`: a server that grants
    /// it only when asked would otherwise hand out tokens Synapse refuses). It
    /// asks for both in every flow, whether or not a device is proposed.
    #[test]
    fn every_flow_asks_for_offline_access_and_the_matrix_api() {
        for scope in [
            build_scope(None),
            build_scope(Some("agent-x")),
            build_device_flow_scope(),
        ] {
            let asked: Vec<&str> = scope.split(' ').collect();
            for needed in ["openid", "offline_access", "urn:matrix:client:api:*"] {
                assert!(asked.contains(&needed), "`{scope}` lacks {needed}");
            }
        }
        assert_eq!(build_device_flow_scope(), DEVICE_FLOW_SCOPE);
    }

    /// One request a stub server received.
    struct Received {
        /// The request line and the headers.
        head: String,
        body: String,
    }

    impl Received {
        fn request_line(&self) -> &str {
            self.head.lines().next().unwrap_or("")
        }

        fn header(&self, name: &str) -> Option<String> {
            self.head.lines().skip(1).find_map(|line| {
                let (field, value) = line.split_once(':')?;
                field
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
        }
    }

    fn read_request(stream: &mut TcpStream) -> Received {
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head_end, content_length) = loop {
            let n = stream.read(&mut chunk).unwrap();
            received.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&received).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                break (end + 4, length);
            }
        };
        while received.len() < head_end + content_length {
            let n = stream.read(&mut chunk).unwrap();
            received.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&received).to_string();
        Received {
            head: text[..head_end].to_string(),
            body: text[head_end..].to_string(),
        }
    }

    /// A raw HTTP response with an empty body that closes the connection.
    fn raw_response(status: &str, headers: &[&str]) -> String {
        let mut response =
            format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n");
        for header in headers {
            response.push_str(header);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response
    }

    /// Answer one connection per entry of `responses`, in order, and hand back
    /// what each one sent.
    fn serve_in_order(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<Received>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = read_request(&mut stream);
                    let _ = stream.write_all(response.as_bytes());
                    request
                })
                .collect()
        });
        (base, handle)
    }

    /// Answer the first request with a 500 and hand back the request line and
    /// body. Enough server to see what a flow sends first.
    fn capture_first_request() -> (String, std::thread::JoinHandle<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
            (request.request_line().to_string(), request.body)
        });
        (base, handle)
    }

    fn scope_in(query_or_form: &str) -> String {
        let fields: HashMap<String, String> = serde_urlencoded::from_str(query_or_form).unwrap();
        fields
            .get("scope")
            .unwrap_or_else(|| panic!("no scope in `{query_or_form}`"))
            .clone()
    }

    /// The scope the code flow puts on the wire at `/authorize`, with and
    /// without a proposed device.
    #[tokio::test]
    async fn the_code_flow_sends_the_scope_it_relies_on() {
        let key = SiwxKey::generate_ed25519();
        for (device, expected) in [
            (None, CODE_FLOW_SCOPE.to_string()),
            (
                Some("agent-x"),
                format!("{CODE_FLOW_SCOPE} urn:matrix:client:device:agent-x"),
            ),
        ] {
            let (base, request) = capture_first_request();
            let outcome = authenticate_with_device(
                &base,
                "client",
                "https://agent.example.org/callback",
                &key,
                device,
            )
            .await;
            assert!(outcome.is_err(), "the stub answers 500");
            let (request_line, _) = request.join().unwrap();
            let target = request_line.split(' ').nth(1).unwrap();
            let (path, query) = target.split_once('?').expect("a query");
            assert_eq!(path, "/authorize");
            assert_eq!(scope_in(query), expected, "device {device:?}");
            assert_eq!(
                scope_in(query),
                code_flow_scope(device),
                "device {device:?}"
            );
        }
    }

    /// The scope the device flow puts on the wire at `/device_authorization`.
    #[tokio::test]
    async fn the_device_flow_sends_the_scope_it_relies_on() {
        let (base, request) = capture_first_request();
        let outcome = authenticate_device_flow(&base, "client").await;
        assert!(outcome.is_err(), "the stub answers 500");
        let (request_line, body) = request.join().unwrap();
        assert!(
            request_line.starts_with("POST /device_authorization"),
            "{request_line}"
        );
        assert_eq!(scope_in(&body), DEVICE_FLOW_SCOPE);
    }

    const REDIRECT_URI: &str = "https://agent.example.org/callback";

    /// A client built the way [`authenticate_with_scope_using`] asks a caller to.
    fn caller_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap()
    }

    /// The `scope` of the `/authorize` request a stub received.
    fn authorize_scope(request: std::thread::JoinHandle<(String, String)>) -> String {
        let (request_line, _) = request.join().unwrap();
        let target = request_line.split(' ').nth(1).unwrap();
        let (path, query) = target.split_once('?').expect("a query");
        assert_eq!(path, "/authorize");
        scope_in(query)
    }

    /// The scope a caller names is the scope on the wire: nothing is added (the
    /// Matrix scopes the other entry points rely on included), removed,
    /// normalised or checked.
    #[tokio::test]
    async fn the_scope_entry_points_send_the_scope_exactly_as_given() {
        let key = SiwxKey::generate_ed25519();
        for scope in [
            "openid io.inblock.mail",
            "openid",
            "openid io.inblock.mail offline_access",
            "openid urn:matrix:client:api:*",
            "openid  io.inblock.mail ",
            "",
        ] {
            let (base, request) = capture_first_request();
            let outcome = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, scope).await;
            assert!(outcome.is_err(), "the stub answers 500");
            assert_eq!(authorize_scope(request), scope, "authenticate_with_scope");

            let (base, request) = capture_first_request();
            let outcome = authenticate_with_scope_using(
                &caller_client(),
                &base,
                "client",
                REDIRECT_URI,
                &key,
                scope,
            )
            .await;
            assert!(outcome.is_err(), "the stub answers 500");
            assert_eq!(
                authorize_scope(request),
                scope,
                "authenticate_with_scope_using"
            );
        }
    }

    /// `authenticate_with_scope_using` runs the flow through the client it is
    /// given, not through one of its own.
    #[tokio::test]
    async fn the_caller_chosen_client_sends_the_flow() {
        let key = SiwxKey::generate_ed25519();
        let caller = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent("caller-client/1")
            .build()
            .unwrap();
        let (base, served) = serve_in_order(vec![raw_response("500 Internal Server Error", &[])]);
        let outcome = authenticate_with_scope_using(
            &caller,
            &base,
            "client",
            REDIRECT_URI,
            &key,
            "openid io.inblock.mail",
        )
        .await;
        assert!(outcome.is_err(), "the stub answers 500");
        let requests = served.join().unwrap();
        assert_eq!(
            requests[0].header("user-agent").as_deref(),
            Some("caller-client/1")
        );
    }

    /// A client that follows redirects ends the flow on the login page, a 200
    /// where the 303 is due, and the error says why.
    #[tokio::test]
    async fn a_client_that_follows_redirects_gets_an_error_naming_the_redirect_policy() {
        let key = SiwxKey::generate_ed25519();
        let (base, served) = serve_in_order(vec![
            raw_response(
                "303 See Other",
                &["location: /login", "set-cookie: session=abc; Path=/"],
            ),
            raw_response("200 OK", &[]),
        ]);
        let following = reqwest::Client::new();
        let error = authenticate_with_scope_using(
            &following,
            &base,
            "client",
            REDIRECT_URI,
            &key,
            "openid io.inblock.mail",
        )
        .await
        .expect_err("the login page is not a redirect");
        let message = format!("{error:#}");
        assert!(
            message.contains("/authorize returned 200 OK where a 303 redirect was expected"),
            "{message}"
        );
        assert!(
            message.contains("reqwest::redirect::Policy::none()"),
            "{message}"
        );
        let requests = served.join().unwrap();
        assert_eq!(requests.len(), 2, "the client did follow the redirect");
        assert!(requests[1].request_line().starts_with("GET /login"));
    }

    /// The same error at the second redirect, when a server answers `/sign_in`
    /// with a page instead.
    #[tokio::test]
    async fn a_sign_in_that_answers_with_a_page_names_the_redirect_policy_too() {
        let key = SiwxKey::generate_ed25519();
        let authorize_redirect = format!(
            "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
            urlencoding::encode(REDIRECT_URI)
        );
        let (base, served) = serve_in_order(vec![
            raw_response(
                "303 See Other",
                &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
            ),
            raw_response("200 OK", &[]),
        ]);
        let error = authenticate_with_scope(
            &base,
            "client",
            REDIRECT_URI,
            &key,
            "openid io.inblock.mail",
        )
        .await
        .expect_err("a page is not a redirect");
        let message = format!("{error:#}");
        assert!(
            message.contains("/sign_in returned 200 OK where a 303 redirect was expected"),
            "{message}"
        );
        assert!(
            message.contains("reqwest::redirect::Policy::none()"),
            "{message}"
        );
        let requests = served.join().unwrap();
        assert!(requests[1].request_line().starts_with("GET /sign_in"));
        assert!(requests[1]
            .header("cookie")
            .is_some_and(|cookie| cookie.starts_with("session=abc; siwx=")));
    }

    /// A status that is neither a 303 nor a success keeps the plain message.
    #[tokio::test]
    async fn an_error_status_at_authorize_is_not_blamed_on_the_redirect_policy() {
        let key = SiwxKey::generate_ed25519();
        let (base, request) = capture_first_request();
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("the stub answers 500");
        request.join().unwrap();
        assert_eq!(
            format!("{error:#}"),
            "/authorize returned 500 Internal Server Error instead of 303"
        );
    }

    /// A server that refuses the scope answers `/authorize` with a 303 to the
    /// redirect URI, `error` and `error_description` in its query and no session
    /// cookie. The error carries what the server said, through both entry points
    /// that take a scope.
    #[tokio::test]
    async fn a_refused_scope_is_reported_with_the_servers_reason() {
        let key = SiwxKey::generate_ed25519();
        let refusal = format!(
            "location: {REDIRECT_URI}?state=headless&error=invalid_scope&error_description={}",
            urlencoding::encode("the openid scope is required")
        );
        let expected =
            "/authorize refused the request: invalid_scope: the openid scope is required";

        let (base, served) = serve_in_order(vec![raw_response("303 See Other", &[&refusal])]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "io.inblock.mail")
            .await
            .expect_err("the server refused the scope");
        assert_eq!(format!("{error:#}"), expected);
        assert_eq!(
            served.join().unwrap().len(),
            1,
            "the flow stops at the refusal"
        );

        let (base, served) = serve_in_order(vec![raw_response("303 See Other", &[&refusal])]);
        let error = authenticate_with_scope_using(
            &caller_client(),
            &base,
            "client",
            REDIRECT_URI,
            &key,
            "io.inblock.mail",
        )
        .await
        .expect_err("the server refused the scope");
        assert_eq!(format!("{error:#}"), expected);
        served.join().unwrap();
    }

    /// A refusal without a description still names its error, and a redirect
    /// with an `error` but also a cookie is a refusal all the same.
    #[tokio::test]
    async fn a_refusal_without_a_description_still_names_the_error() {
        let key = SiwxKey::generate_ed25519();
        let refusal = format!("location: {REDIRECT_URI}?state=headless&error=invalid_scope");
        let (base, served) = serve_in_order(vec![raw_response(
            "303 See Other",
            &[&refusal, "set-cookie: session=abc; Path=/"],
        )]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "io.inblock.mail")
            .await
            .expect_err("the server refused the scope");
        assert_eq!(
            format!("{error:#}"),
            "/authorize refused the request: invalid_scope"
        );
        served.join().unwrap();
    }

    /// A redirect that is no refusal and sets no cookie keeps its own message.
    #[tokio::test]
    async fn a_redirect_without_a_cookie_or_an_error_still_reports_the_missing_cookie() {
        let key = SiwxKey::generate_ed25519();
        let (base, served) = serve_in_order(vec![raw_response(
            "303 See Other",
            &["location: /login?nonce=n1&state=headless"],
        )]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("no session cookie");
        assert_eq!(
            format!("{error:#}"),
            "/authorize response missing session cookie"
        );
        served.join().unwrap();
    }
}
