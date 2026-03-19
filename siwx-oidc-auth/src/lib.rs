//! Headless OIDC client for siwx-oidc.
//!
//! Performs the full authorization code flow using a local Ed25519 or P-256
//! private key, without any browser or user interaction. Useful for CI,
//! service accounts, and automated testing.
//!
//! # Example
//!
//! ```no_run
//! use siwx_oidc_auth::{SiwxKey, authenticate};
//!
//! #[tokio::main]
//! async fn main() {
//!     let key = SiwxKey::generate_ed25519();
//!     let tokens = authenticate(
//!         "http://localhost:8000",
//!         "my-client-id",
//!         "https://app.example.com/callback",
//!         &key,
//!     ).await.unwrap();
//!     println!("id_token: {:?}", tokens.id_token);
//! }
//! ```

use anyhow::{anyhow, bail, Context, Result};
use bs58;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;
use reqwest::{header, redirect::Policy, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;
use urlencoding::encode;

// Multicodec varint prefixes (same as siwx-core/src/key/mod.rs)
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
    /// Generate a random Ed25519 key.
    pub fn generate_ed25519() -> Self {
        SiwxKey::Ed25519(Ed25519SigningKey::generate(&mut OsRng))
    }

    /// Generate a random P-256 key.
    pub fn generate_p256() -> Self {
        SiwxKey::P256(P256SigningKey::random(&mut OsRng))
    }

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

    /// The key type label for display in CAIP-122 messages.
    fn type_label(&self) -> &'static str {
        match self {
            SiwxKey::Ed25519(_) => "Ed25519",
            SiwxKey::P256(_) => "P-256",
        }
    }

    /// Sign `message` bytes and return the hex-encoded signature.
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

/// Build a minimal CAIP-122 message that satisfies siwx-oidc's nonce and
/// resource checks. The message is unsigned; call `SiwxKey::sign` on the result.
fn build_message(
    domain: &str,
    key: &SiwxKey,
    redirect_uri: &str,
    nonce: &str,
) -> String {
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
// Token response
// ---------------------------------------------------------------------------

/// Tokens returned by a successful headless authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    /// The `did:key:z…` DID that authenticated.
    pub did: String,
}

// ---------------------------------------------------------------------------
// Internal wire types (serde mirrors of server JSON)
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
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Perform the full siwx-oidc authorization code flow with a local signing key.
///
/// - `server_url`: Base URL of the siwx-oidc server (e.g. `"http://localhost:8000"`).
/// - `client_id`: OIDC client ID registered with the server.
/// - `redirect_uri`: Registered redirect URI. The server validates the CAIP-122
///   message contains this URI in its `Resources:` section.
/// - `key`: Local signing key used to derive the DID and sign the challenge.
pub async fn authenticate(
    server_url: &str,
    client_id: &str,
    redirect_uri: &str,
    key: &SiwxKey,
) -> Result<AuthTokens> {
    let base = Url::parse(server_url).context("invalid server_url")?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .context("failed to build HTTP client")?;

    // -----------------------------------------------------------------------
    // Step 1: GET /authorize — get nonce + session cookie
    // -----------------------------------------------------------------------
    let authorize_url = base.join("/authorize")?;
    let resp = client
        .get(authorize_url)
        .query(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "openid profile"),
            ("response_type", "code"),
            ("state", "headless"),
        ])
        .send()
        .await
        .context("GET /authorize failed")?;

    if resp.status() != StatusCode::SEE_OTHER {
        bail!(
            "/authorize returned {} instead of 303",
            resp.status()
        );
    }

    // Extract session cookie from Set-Cookie header.
    let session_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("session=") {
                // take just "session={value}" (strip attributes)
                Some(s.split(';').next()?.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("/authorize response missing session cookie"))?;

    // Extract redirect URL (relative, e.g. "/?nonce=...&state=...&...").
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("/authorize response missing Location header"))?;

    // Resolve the relative Location against the server base URL to parse params.
    let redirect_url = base.join(location).context("invalid Location header")?;
    let params: AuthorizeRedirectParams = serde_urlencoded::from_str(redirect_url.query().unwrap_or(""))
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
        bail!("/sign_in returned {status}: {body}");
    }

    // Extract the auth code from the redirect Location.
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
        did,
    })
}
