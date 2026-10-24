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
pub mod directory;

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

/// What an access token is assumed to live, in seconds, when its answer names no
/// usable `expires_in` (no field, `null`, a string, a boolean, an array, an
/// object).
pub const TOKEN_LIFETIME_DEFAULT_SECS: u64 = 60;
/// The least a token is assumed to live, in seconds, whatever `expires_in` says
/// (zero, negative or a fraction of a second would have a caller sign in again
/// on every call).
pub const TOKEN_LIFETIME_MIN_SECS: u64 = 10;
/// The most a token is trusted to live, in seconds (24 hours), whatever
/// `expires_in` says: a server that names a year is renewed daily all the same.
pub const TOKEN_LIFETIME_MAX_SECS: u64 = 24 * 60 * 60;

/// The lifetime a token answer's `expires_in` (JSON text, if the field is there)
/// stands for: a number is cut to whole seconds and held between
/// [`TOKEN_LIFETIME_MIN_SECS`] and [`TOKEN_LIFETIME_MAX_SECS`], and anything
/// else is [`TOKEN_LIFETIME_DEFAULT_SECS`].
///
/// Read from the raw text, because serde would refuse what a server may well
/// send (`3600.5`, `1e20`, a count above `u64`, `1e999`), and the answer that
/// carries it also carries the new token pair.
fn token_lifetime_secs(expires_in: Option<&serde_json::value::RawValue>) -> u64 {
    let Some(raw) = expires_in else {
        return TOKEN_LIFETIME_DEFAULT_SECS;
    };
    let text = raw.get().trim();
    // JSON text is a number exactly when it starts with `-` or a digit.
    if !(text.starts_with('-') || text.starts_with(|c: char| c.is_ascii_digit())) {
        return TOKEN_LIFETIME_DEFAULT_SECS;
    }
    match text.parse::<f64>() {
        // `as` saturates: a count above `u64` or infinity is the maximum, a
        // negative number is zero.
        Ok(seconds) => (seconds as u64).clamp(TOKEN_LIFETIME_MIN_SECS, TOKEN_LIFETIME_MAX_SECS),
        Err(_) => TOKEN_LIFETIME_DEFAULT_SECS,
    }
}

/// Tokens returned by a successful headless authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    /// Token lifetime in seconds, from the server's `expires_in` field and
    /// always within [`TOKEN_LIFETIME_MIN_SECS`] and [`TOKEN_LIFETIME_MAX_SECS`]:
    /// a number is read however it is spelled (`3600.5`, `1e20`, above `u64`) and
    /// bounded, anything else (no field, `null`, a string, ...) is
    /// [`TOKEN_LIFETIME_DEFAULT_SECS`]. A token answer is never refused for its
    /// `expires_in`, since the refresh token that earned it is already spent.
    /// The flows in this crate always set it; it is an `Option` for callers that
    /// build the struct themselves.
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
    /// Kept as text: see [`token_lifetime_secs`].
    expires_in: Option<Box<serde_json::value::RawValue>>,
    refresh_token: Option<String>,
}

impl TokenResponseRaw {
    fn lifetime_secs(&self) -> u64 {
        token_lifetime_secs(self.expires_in.as_deref())
    }
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

/// A sign-in that siwx-oidc refused: at `/sign_in` with the authorization error
/// response (a 303 to the redirect URI whose query carries `error` and
/// `error_description` instead of a code, which siwx-oidc does when
/// `SIWXOIDC_REFUSE_DELETED_DEVICE_IDS` is on; otherwise its refusals there are
/// pages, reported as untyped errors), or at `/authorize` for a client id it does
/// not know.
///
/// The code-flow entry points return it inside their [`anyhow::Error`]: recover
/// it with `err.downcast_ref::<AuthError>()`, or ask [`is_device_refused`] and
/// [`is_transient`]. What each kind asks of the caller:
///
/// - [`AuthError::DeviceRefused`]: the proposed device id cannot be used again
///   (it was signed out). Forget it, sign in with a new id; retrying the same id
///   is refused again.
/// - [`AuthError::AccessDenied`]: the account cannot sign in (deactivated or
///   erased). Final: stop, and report it once.
/// - [`AuthError::TemporarilyUnavailable`]: the homeserver could not be asked or
///   could not set up the device. Transient: retry as after an outage.
/// - [`AuthError::SignInRefused`]: any other `error` code.
/// - [`AuthError::UnknownClient`]: the one that is not a `/sign_in` redirect. The
///   server does not know the client id, which it answers at `/authorize` with a
///   401 that carries no `WWW-Authenticate` header (no OAuth `error` code: the
///   body is plain text). A dynamic client lapses after 30 days without a use.
///   Register a client again and keep the new id; retrying changes nothing.
/// - [`AuthError::Unauthorized`]: a 401 at `/authorize` *with* a
///   `WWW-Authenticate` challenge. That is not the server's own answer for an
///   unregistered client but something in front of it (a proxy's or a gateway's
///   auth wall) asking for credentials of its own. Registering again does not
///   get past it; the deployment's access has to be fixed.
///
/// A refusal carries the `error` code and nothing else the server wrote: the
/// `error_description` of the redirect is free text, so it is in no `Display` or
/// `Debug` of the error (and not in the type), and a code outside the short
/// fixed charset of the OAuth vocabulary is reported as `unrecognised_error`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// `invalid_scope`: the device id the scope proposes is refused.
    DeviceRefused,
    /// `access_denied`: the account is deactivated or erased.
    AccessDenied,
    /// `temporarily_unavailable`: no grant was issued; try again later.
    TemporarilyUnavailable,
    /// `/authorize` answered 401 without a `WWW-Authenticate` challenge: the
    /// server does not know the client id. [`AuthError::error_code`] is
    /// `invalid_client`, the code RFC 6749 names for it; the server sent none.
    UnknownClient,
    /// `/authorize` answered 401 with a `WWW-Authenticate` challenge: something
    /// in front of the server wants credentials first. Not an unknown client.
    Unauthorized,
    /// Any other `error` code at `/sign_in`.
    SignInRefused { error: String },
}

/// The `error` code reported when the server's is not a short OAuth/Matrix token.
const UNRECOGNISED_ERROR: &str = "unrecognised_error";

impl AuthError {
    fn from_refusal(error: String) -> Self {
        match error.as_str() {
            "invalid_scope" => AuthError::DeviceRefused,
            "access_denied" => AuthError::AccessDenied,
            "temporarily_unavailable" => AuthError::TemporarilyUnavailable,
            _ => AuthError::SignInRefused { error },
        }
    }

    /// The `error` code the server sent (for [`AuthError::UnknownClient`], which
    /// came with none, `invalid_client`; for [`AuthError::Unauthorized`], which
    /// is not the server's, `unauthorized`).
    pub fn error_code(&self) -> &str {
        match self {
            AuthError::UnknownClient => "invalid_client",
            AuthError::Unauthorized => "unauthorized",
            AuthError::DeviceRefused => "invalid_scope",
            AuthError::AccessDenied => "access_denied",
            AuthError::TemporarilyUnavailable => "temporarily_unavailable",
            AuthError::SignInRefused { error } => error,
        }
    }

    /// Whether this is [`AuthError::UnknownClient`].
    pub fn is_unknown_client(&self) -> bool {
        matches!(self, AuthError::UnknownClient)
    }

    /// Whether this is [`AuthError::DeviceRefused`].
    pub fn is_device_refused(&self) -> bool {
        matches!(self, AuthError::DeviceRefused)
    }

    /// Whether this is [`AuthError::TemporarilyUnavailable`], the one refusal to
    /// retry unchanged.
    pub fn is_transient(&self) -> bool {
        matches!(self, AuthError::TemporarilyUnavailable)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The status line is the one this error replaced, so a consumer that
            // matched the text keeps working until it matches the type.
            AuthError::UnknownClient => write!(
                f,
                "/authorize returned 401 Unauthorized instead of 303: the client id is not \
                 registered at the server"
            ),
            AuthError::Unauthorized => write!(
                f,
                "/authorize returned 401 Unauthorized instead of 303, with a WWW-Authenticate \
                 challenge: something in front of the server asks for credentials first, which \
                 is not the server's answer for an unregistered client"
            ),
            _ => write!(f, "/sign_in refused the request: {}", self.error_code()),
        }
    }
}

impl std::error::Error for AuthError {}

/// Whether `err` is an [`AuthError::UnknownClient`] from a code-flow entry point.
pub fn is_unknown_client(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AuthError>()
        .is_some_and(|e| matches!(e, AuthError::UnknownClient))
}

/// Whether `err` is an [`AuthError::DeviceRefused`] from a code-flow entry point.
pub fn is_device_refused(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AuthError>()
        .is_some_and(AuthError::is_device_refused)
}

/// Whether `err` is an [`AuthError::TemporarilyUnavailable`] from a code-flow
/// entry point. An untyped error (a network fault, say) answers `false`: the
/// caller decides for those as before.
pub fn is_transient(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AuthError>()
        .is_some_and(AuthError::is_transient)
}

/// How a server refused a request, as far as this client repeats it: the status
/// and, when the body is a JSON object with a Matrix `errcode` or an OAuth
/// `error` that is a short token, that code. Never the body itself, which is
/// whatever the server (or whatever answers in its place) chose to write.
struct Refusal {
    status: StatusCode,
    code: Option<String>,
}

impl Refusal {
    /// Read an error answer. At most [`ERROR_BODY_CAP`] bytes are read and kept;
    /// a longer body, or one that cannot be read, has no code and the status
    /// still stands.
    async fn of(resp: reqwest::Response) -> Refusal {
        Refusal::within(resp, ERROR_BODY_CAP).await
    }

    /// [`Refusal::of`] with the read bounded by `cap` instead.
    async fn within(resp: reqwest::Response, cap: usize) -> Refusal {
        let status = resp.status();
        let code = did_assertion::read_at_most(resp, cap)
            .await
            .ok()
            .flatten()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .and_then(|json| {
                // Matrix names its code `errcode` and puts a sentence in
                // `error`; OAuth names its code `error`.
                ["errcode", "error"]
                    .into_iter()
                    .find_map(|field| directory::short_code(json.get(field)?.as_str()?))
            });
        Refusal { status, code }
    }

    /// `{what} returned {status}`, then `({code})` when there is one.
    fn into_error(self, what: &str) -> anyhow::Error {
        match self.code {
            Some(code) => anyhow!("{what} returned {} ({code})", self.status),
            None => anyhow!("{what} returned {}", self.status),
        }
    }
}

/// The most of an error answer that is read, the same bound the directory client
/// puts on every body.
const ERROR_BODY_CAP: usize = did_assertion::DEFAULT_BODY_CAP;

/// The error for a response from `endpoint` that is not the 303 redirect the
/// code flow is waiting for.
///
/// A success status gets its own message, because it is what a client that
/// follows redirects sees at the end of the redirect: the login page, a 200.
fn not_the_redirect(endpoint: &str, status: StatusCode, code: Option<&str>) -> anyhow::Error {
    if status.is_success() {
        return anyhow!(
            "{endpoint} returned {status} where a 303 redirect was expected: either the HTTP \
             client followed the redirect, or the server did not redirect. The flow reads the \
             Location header itself, so the client must be built with \
             `reqwest::redirect::Policy::none()`"
        );
    }
    match code {
        Some(code) => anyhow!("{endpoint} returned {status} instead of 303 ({code})"),
        None => anyhow!("{endpoint} returned {status} instead of 303"),
    }
}

/// What the server says when it refuses the authorization request: the `error`
/// code, or `None` when `location` is no refusal.
///
/// `/authorize` refuses a request it can still answer, an unsupported scope for
/// one, with a 303 to the redirect URI whose query carries `error` and
/// `error_description`. That redirect sets no session cookie, so a flow that read
/// the cookie first would report a missing cookie and hide the reason. `/sign_in`
/// refuses the same way when siwx-oidc runs `SIWXOIDC_REFUSE_DELETED_DEVICE_IDS`
/// (see [`AuthError`]).
///
/// Only the code is kept, and only when it is a short token of the OAuth
/// vocabulary ([`directory::short_code`]; otherwise `unrecognised_error`): the
/// `error_description` is text the server (or whatever answers in its place)
/// wrote, and it is read by no one.
fn authorize_refusal(base: &Url, location: &str) -> Option<String> {
    let redirect = base.join(location).ok()?;
    let error = redirect
        .query_pairs()
        .fold(None, |error, (name, value)| match name.as_ref() {
            "error" => Some(value.into_owned()),
            _ => error,
        })?;
    Some(directory::short_code(&error).unwrap_or_else(|| UNRECOGNISED_ERROR.to_string()))
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
        .map_err(reqwest::Error::without_url)
        .context("GET /authorize failed")?;

    if resp.status() != StatusCode::SEE_OTHER {
        // The server answers an unregistered client id with a 401 here (and
        // answers 401 at `/authorize` for nothing else), without a
        // `WWW-Authenticate` header (`CustomError::Unauthorized` in the server).
        if resp.status() == StatusCode::UNAUTHORIZED {
            // Its own answer carries no challenge; a proxy's auth wall does.
            return Err(if resp.headers().contains_key(header::WWW_AUTHENTICATE) {
                AuthError::Unauthorized
            } else {
                AuthError::UnknownClient
            }
            .into());
        }
        if resp.status().is_success() {
            return Err(not_the_redirect("/authorize", resp.status(), None));
        }
        let refusal = Refusal::of(resp).await;
        return Err(not_the_redirect(
            "/authorize",
            refusal.status,
            refusal.code.as_deref(),
        ));
    }

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    if let Some(error) = location.and_then(|location| authorize_refusal(&base, location)) {
        return Err(anyhow!("/authorize refused the request: {error}"));
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
        .map_err(reqwest::Error::without_url)
        .context("GET /sign_in failed")?;

    if resp.status() != StatusCode::SEE_OTHER {
        if resp.status().is_success() {
            return Err(not_the_redirect("/sign_in", resp.status(), None));
        }
        let refusal = Refusal::of(resp).await;
        return Err(not_the_redirect(
            "/sign_in",
            refusal.status,
            refusal.code.as_deref(),
        ));
    }

    let code_location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("/sign_in response missing Location header"))?;

    // A refusal is the authorization error response, typed for the caller.
    if let Some(error) = authorize_refusal(&base, code_location) {
        return Err(AuthError::from_refusal(error).into());
    }

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
        .map_err(reqwest::Error::without_url)
        .context("POST /token failed")?;

    if !resp.status().is_success() {
        return Err(Refusal::of(resp).await.into_error("/token"));
    }

    let raw: TokenResponseRaw = did_assertion::read_json(resp, did_assertion::DEFAULT_BODY_CAP)
        .await
        .context("/token JSON parse failed")?;
    Ok(AuthTokens {
        expires_in: Some(raw.lifetime_secs()),
        access_token: raw.access_token,
        token_type: raw.token_type,
        id_token: raw.id_token,
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
        .map_err(reqwest::Error::without_url)
        .context("POST /token (refresh) failed")?;

    if !resp.status().is_success() {
        return Err(Refusal::of(resp).await.into_error("/token refresh"));
    }

    let raw: TokenResponseRaw = did_assertion::read_json(resp, did_assertion::DEFAULT_BODY_CAP)
        .await
        .context("/token refresh JSON parse failed")?;
    Ok(AuthTokens {
        expires_in: Some(raw.lifetime_secs()),
        access_token: raw.access_token,
        token_type: raw.token_type,
        id_token: raw.id_token,
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
        .map_err(reqwest::Error::without_url)
        .context("POST /device_authorization failed")?;

    if !resp.status().is_success() {
        return Err(Refusal::of(resp).await.into_error("/device_authorization"));
    }

    let device_auth: DeviceAuthResponseRaw =
        did_assertion::read_json(resp, did_assertion::DEFAULT_BODY_CAP)
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
            .map_err(reqwest::Error::without_url)
            .context("POST /token (device poll) failed")?;

        if resp.status().is_success() {
            let raw: TokenResponseRaw =
                did_assertion::read_json(resp, did_assertion::DEFAULT_BODY_CAP)
                    .await
                    .context("/token JSON parse failed")?;
            let did = raw
                .id_token
                .as_ref()
                .and_then(|t| extract_did_from_id_token(t))
                .unwrap_or_default();
            eprintln!("Approved!");
            return Ok(AuthTokens {
                expires_in: Some(raw.lifetime_secs()),
                access_token: raw.access_token,
                token_type: raw.token_type,
                id_token: raw.id_token,
                refresh_token: raw.refresh_token,
                did,
            });
        }

        let refusal = Refusal::of(resp).await;
        match refusal.code.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => {
                interval += 5;
            }
            Some("access_denied") => {
                bail!("Device login was denied by the user");
            }
            Some("expired_token") => {
                bail!("Device code expired");
            }
            Some(other) => {
                bail!("/token error: {other} ({})", refusal.status);
            }
            None => return Err(refusal.into_error("/token")),
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

    /// A raw HTTP response with a body that closes the connection.
    fn raw_response_with_body(status: &str, headers: &[&str], body: &str) -> String {
        let mut response = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        );
        for header in headers {
            response.push_str(header);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(body);
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
    /// cookie. The error carries the code the server sent and not its
    /// description, through both entry points that take a scope.
    #[tokio::test]
    async fn a_refused_scope_is_reported_with_the_servers_code() {
        let key = SiwxKey::generate_ed25519();
        let refusal = format!(
            "location: {REDIRECT_URI}?state=headless&error=invalid_scope&error_description={}",
            urlencoding::encode("the openid scope is required")
        );
        let expected = "/authorize refused the request: invalid_scope";

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

    /// A refusal without a description names its error as well, and a redirect
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

    // ---- SS4 WP7: a /sign_in refusal is a typed error (8.19) ----

    /// Run the code flow with a proposed device against a server whose `/authorize`
    /// redirects to the login page and whose `/sign_in` answers with `sign_in_location`.
    async fn sign_in_answering(sign_in_location: &str) -> anyhow::Error {
        let key = SiwxKey::generate_ed25519();
        let authorize_redirect = format!(
            "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
            urlencoding::encode(REDIRECT_URI)
        );
        let sign_in_redirect = format!("location: {sign_in_location}");
        let (base, served) = serve_in_order(vec![
            raw_response(
                "303 See Other",
                &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
            ),
            raw_response("303 See Other", &[&sign_in_redirect]),
        ]);
        let error = authenticate_with_device(&base, "client", REDIRECT_URI, &key, Some("DEVICE_A"))
            .await
            .expect_err("the sign-in redirect carries no code");
        assert_eq!(
            served.join().unwrap().len(),
            2,
            "the flow stops at /sign_in, before /token"
        );
        error
    }

    fn sign_in_refusal(error: &str, description: &str) -> String {
        format!(
            "{REDIRECT_URI}?error={error}&error_description={}&state=headless",
            urlencoding::encode(description)
        )
    }

    #[tokio::test]
    async fn auth_sign_in_invalid_scope_redirect_is_device_refused() {
        let description = "The requested device id was signed out and cannot be used again.";
        let error = sign_in_answering(&sign_in_refusal("invalid_scope", description)).await;
        assert_eq!(
            error.downcast_ref::<AuthError>(),
            Some(&AuthError::DeviceRefused)
        );
        assert!(is_device_refused(&error));
        assert!(!is_transient(&error), "a refused id is not retried as is");
        assert_eq!(
            format!("{error:#}"),
            "/sign_in refused the request: invalid_scope"
        );
    }

    #[tokio::test]
    async fn auth_sign_in_access_denied_redirect_is_typed() {
        let description = "This account has been deactivated.";
        let error = sign_in_answering(&sign_in_refusal("access_denied", description)).await;
        let typed = error
            .downcast_ref::<AuthError>()
            .expect("access_denied is typed");
        assert_eq!(typed, &AuthError::AccessDenied);
        assert!(!typed.is_device_refused());
        assert!(
            !typed.is_transient(),
            "access_denied is final, never retried"
        );
    }

    #[tokio::test]
    async fn auth_sign_in_temporarily_unavailable_is_transient() {
        let error = sign_in_answering(&sign_in_refusal(
            "temporarily_unavailable",
            "Please try again shortly.",
        ))
        .await;
        assert!(matches!(
            error.downcast_ref::<AuthError>(),
            Some(AuthError::TemporarilyUnavailable)
        ));
        assert!(is_transient(&error), "retried like an outage");
        assert!(!is_device_refused(&error));
    }

    #[tokio::test]
    async fn auth_is_device_refused_matches_only_that_error() {
        let device_refused = AuthError::DeviceRefused;
        assert!(device_refused.is_device_refused());
        for other in [
            AuthError::AccessDenied,
            AuthError::TemporarilyUnavailable,
            AuthError::Unauthorized,
            AuthError::UnknownClient,
            AuthError::SignInRefused {
                error: "server_error".to_string(),
            },
        ] {
            assert!(!other.is_device_refused(), "{other:?}");
            assert!(!is_device_refused(&anyhow::Error::new(other)));
        }
        assert!(!is_device_refused(&anyhow!("invalid_scope")), "untyped");
        // An unknown error code at /sign_in is typed, but neither refusal kind.
        let error = sign_in_answering(&sign_in_refusal("server_error", "boom")).await;
        assert_eq!(
            error.downcast_ref::<AuthError>(),
            Some(&AuthError::SignInRefused {
                error: "server_error".to_string(),
            })
        );
        assert!(!is_device_refused(&error));
        // `/authorize`'s own invalid_scope (a scope refusal, not a device refusal) stays
        // its untyped message.
        let key = SiwxKey::generate_ed25519();
        let refusal = format!("location: {REDIRECT_URI}?state=headless&error=invalid_scope");
        let (base, served) = serve_in_order(vec![raw_response("303 See Other", &[&refusal])]);
        let error = authenticate_with_device(&base, "client", REDIRECT_URI, &key, Some("DEVICE_A"))
            .await
            .expect_err("refused at /authorize");
        assert!(!is_device_refused(&error));
        assert_eq!(
            format!("{error:#}"),
            "/authorize refused the request: invalid_scope"
        );
        served.join().unwrap();
    }

    // ---- Error answers are read under a cap and never echoed ----

    /// A string a hostile or merely chatty server puts in its error body.
    const MARKER: &str = "MARKER-7f3a9c-echoed-by-the-server";

    /// Everything an error can print.
    fn printed(error: &anyhow::Error) -> String {
        format!("{error} | {error:#} | {error:?} | {error:#?}")
    }

    fn assert_body_free(error: &anyhow::Error) {
        let text = printed(error);
        assert!(!text.contains(MARKER), "the body was echoed: {text}");
    }

    /// The code flow up to `/token`: an authorize redirect, a sign-in redirect
    /// carrying a code, then `token_response`.
    async fn token_answering(token_response: String) -> anyhow::Error {
        let key = SiwxKey::generate_ed25519();
        let authorize_redirect = format!(
            "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
            urlencoding::encode(REDIRECT_URI)
        );
        let sign_in_redirect = format!("location: {REDIRECT_URI}?code=abc&state=headless");
        let (base, served) = serve_in_order(vec![
            raw_response(
                "303 See Other",
                &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
            ),
            raw_response("303 See Other", &[&sign_in_redirect]),
            token_response,
        ]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("the token endpoint refuses");
        served.join().unwrap();
        error
    }

    #[tokio::test]
    async fn a_sign_in_page_is_reported_by_its_status_and_never_its_body() {
        let key = SiwxKey::generate_ed25519();
        let authorize_redirect = format!(
            "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
            urlencoding::encode(REDIRECT_URI)
        );
        for (body, code) in [
            (format!("<html>{MARKER}</html>"), None),
            (
                format!(r#"{{"error":"invalid_request","error_description":"{MARKER}"}}"#),
                Some("invalid_request"),
            ),
        ] {
            let (base, served) = serve_in_order(vec![
                raw_response(
                    "303 See Other",
                    &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
                ),
                raw_response_with_body("500 Internal Server Error", &[], &body),
            ]);
            let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
                .await
                .expect_err("not a redirect");
            served.join().unwrap();
            assert_body_free(&error);
            let message = format!("{error:#}");
            assert!(
                message.starts_with("/sign_in returned 500 Internal Server Error"),
                "{message}"
            );
            assert_eq!(
                message.contains("invalid_request"),
                code.is_some(),
                "{message}"
            );
        }
    }

    #[tokio::test]
    async fn a_token_error_is_reported_by_its_status_and_code_and_never_its_body() {
        for (body, code) in [
            (format!("<html>{MARKER}</html>"), None),
            (
                format!(r#"{{"error":"invalid_grant","error_description":"{MARKER}"}}"#),
                Some("invalid_grant"),
            ),
            // A code is a short token; anything else is body text.
            (format!(r#"{{"error":"{MARKER} <b>x</b>"}}"#), None),
            (format!(r#"{{"error":"{}"}}"#, "a".repeat(65)), None),
            (format!(r#"{{"error":["{MARKER}"]}}"#), None),
        ] {
            let error = token_answering(raw_response_with_body(
                "400 Bad Request",
                &["content-type: application/json"],
                &body,
            ))
            .await;
            assert_body_free(&error);
            let message = format!("{error:#}");
            match code {
                Some(code) => {
                    assert_eq!(message, format!("/token returned 400 Bad Request ({code})"))
                }
                None => assert_eq!(message, "/token returned 400 Bad Request"),
            }
        }
    }

    #[tokio::test]
    async fn a_refresh_error_is_reported_by_its_status_and_code_and_never_its_body() {
        for (body, expected) in [
            (
                format!(r#"{{"error":"invalid_grant","error_description":"{MARKER}"}}"#),
                "/token refresh returned 400 Bad Request (invalid_grant)",
            ),
            (
                format!("plain {MARKER}"),
                "/token refresh returned 400 Bad Request",
            ),
        ] {
            let (base, served) =
                serve_in_order(vec![raw_response_with_body("400 Bad Request", &[], &body)]);
            let error = refresh(&base, "client", "rt-1", "did:key:zFixture")
                .await
                .expect_err("refused");
            served.join().unwrap();
            assert_body_free(&error);
            assert_eq!(format!("{error:#}"), expected);
        }
    }

    #[tokio::test]
    async fn an_error_body_over_the_cap_is_not_buffered_and_keeps_its_status() {
        // 2 MiB with the marker at both ends: the answer is the status, and the
        // reader stops at the cap.
        let mut body = String::from(MARKER);
        body.push_str(&" ".repeat(2 * 1024 * 1024));
        body.push_str(MARKER);
        let error = token_answering(raw_response_with_body(
            "503 Service Unavailable",
            &[],
            &body,
        ))
        .await;
        assert_body_free(&error);
        assert_eq!(
            format!("{error:#}"),
            "/token returned 503 Service Unavailable"
        );

        let (base, served) = serve_in_order(vec![raw_response_with_body(
            "500 Internal Server Error",
            &[],
            &body,
        )]);
        let error = refresh(&base, "client", "rt-1", "did:key:zFixture")
            .await
            .expect_err("refused");
        served.join().unwrap();
        assert_body_free(&error);
        assert_eq!(
            format!("{error:#}"),
            "/token refresh returned 500 Internal Server Error"
        );
    }

    /// A success answer is parsed under the cap too, and a parse failure says
    /// only that the shape is wrong: serde's own message quotes the offending
    /// value (`invalid type: string "..."`).
    #[tokio::test]
    async fn a_success_answer_of_the_wrong_shape_is_reported_without_its_content() {
        let json = ["content-type: application/json"];
        let wrong_shape = "JSON parse failed: the body is JSON of another shape than expected";
        for body in [
            format!(r#""{MARKER}""#),
            format!(r#"{{"access_token":{{"x":"{MARKER}"}},"token_type":"b"}}"#),
        ] {
            let error = token_answering(raw_response_with_body("200 OK", &json, &body)).await;
            assert_body_free(&error);
            assert_eq!(format!("{error:#}"), format!("/token {wrong_shape}"));

            let (base, served) =
                serve_in_order(vec![raw_response_with_body("200 OK", &json, &body)]);
            let error = refresh(&base, "client", "rt-1", "did:key:zFixture")
                .await
                .expect_err("not a token answer");
            served.join().unwrap();
            assert_body_free(&error);
            assert_eq!(
                format!("{error:#}"),
                format!("/token refresh {wrong_shape}")
            );
        }

        let body = format!(
            r#"{{"device_code":"d","user_code":"u","verification_uri":"v",
                "verification_uri_complete":"c","expires_in":"{MARKER}","interval":5}}"#
        );
        let (base, served) = serve_in_order(vec![raw_response_with_body("200 OK", &json, &body)]);
        let error = authenticate_device_flow(&base, "client")
            .await
            .expect_err("not a device authorization");
        served.join().unwrap();
        assert_body_free(&error);
        assert_eq!(
            format!("{error:#}"),
            format!("/device_authorization {wrong_shape}")
        );
    }

    #[tokio::test]
    async fn a_success_answer_over_the_cap_is_refused_unread() {
        let mut body = String::from(r#"{"access_token":""#);
        body.push_str(&"a".repeat(2 * 1024 * 1024));
        body.push_str(MARKER);
        let error = token_answering(raw_response_with_body(
            "200 OK",
            &["content-type: application/json"],
            &body,
        ))
        .await;
        assert_body_free(&error);
        assert!(
            format!("{error:#}").starts_with("/token JSON parse failed: response body exceeds"),
            "{error:#}"
        );
    }

    // ---- The server does not know the client id ----

    /// `/authorize` answers 401 and a plain-text body for an unregistered client
    /// (`oidc::authorize` in the server: `CustomError::Unauthorized`). It is a
    /// typed error, whatever the body says.
    #[tokio::test]
    async fn an_unregistered_client_at_authorize_is_a_typed_error() {
        let key = SiwxKey::generate_ed25519();
        for body in ["Unrecognised client id.", ""] {
            let (base, served) = serve_in_order(vec![raw_response_with_body(
                "401 Unauthorized",
                &["content-type: text/plain"],
                body,
            )]);
            let error = authenticate_with_device(&base, "client", REDIRECT_URI, &key, Some("D"))
                .await
                .expect_err("the client is unknown");
            served.join().unwrap();
            assert_eq!(
                error.downcast_ref::<AuthError>(),
                Some(&AuthError::UnknownClient)
            );
            assert!(is_unknown_client(&error));
            assert!(!is_device_refused(&error) && !is_transient(&error));
            let unknown = error.downcast_ref::<AuthError>().unwrap();
            assert_eq!(unknown.error_code(), "invalid_client");
            assert!(unknown.is_unknown_client());
            // The text a consumer matched before the type existed still reads
            // the same.
            assert!(
                format!("{error:#}").starts_with("/authorize returned 401 Unauthorized"),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn no_other_authorize_failure_is_an_unknown_client() {
        let key = SiwxKey::generate_ed25519();
        for status in [
            "400 Bad Request",
            "403 Forbidden",
            "404 Not Found",
            "500 Internal Server Error",
        ] {
            let (base, served) = serve_in_order(vec![raw_response(status, &[])]);
            let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
                .await
                .expect_err("refused");
            served.join().unwrap();
            assert!(!is_unknown_client(&error), "{status}: {error:#}");
        }
    }

    #[tokio::test]
    async fn auth_missing_code_without_error_keeps_old_message() {
        let location = format!("{REDIRECT_URI}?state=headless");
        let error = sign_in_answering(&location).await;
        assert!(error.downcast_ref::<AuthError>().is_none());
        assert_eq!(
            format!("{error:#}"),
            format!("no 'code' in /sign_in redirect: {location}")
        );
    }

    // ---- Round 3 of the review: URLs, descriptions, lifetimes, challenges ----

    /// A base URL nothing listens on.
    fn dead_base() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    }

    /// What a request URL of the code flow would put into a message: the query
    /// (client id, redirect URI, scope, challenge, state) or any URL at all.
    fn assert_no_request_url(error: &anyhow::Error) {
        let text = printed(error);
        for needle in [
            "client_id=",
            "redirect_uri=",
            "code_challenge",
            "state=headless",
            "http://",
        ] {
            assert!(!text.contains(needle), "`{needle}` in: {text}");
        }
    }

    #[tokio::test]
    async fn a_transport_error_names_the_endpoint_and_never_the_request_url() {
        let key = SiwxKey::generate_ed25519();

        // /authorize
        let error = authenticate_with_scope(&dead_base(), "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("nothing listens");
        assert_no_request_url(&error);
        assert!(
            format!("{error:#}").starts_with("GET /authorize failed"),
            "{error:#}"
        );

        // /sign_in: the server answers /authorize and is gone afterwards.
        let authorize_redirect = format!(
            "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
            urlencoding::encode(REDIRECT_URI)
        );
        let (base, served) = serve_in_order(vec![raw_response(
            "303 See Other",
            &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
        )]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("no /sign_in");
        served.join().unwrap();
        assert_no_request_url(&error);
        assert!(
            format!("{error:#}").starts_with("GET /sign_in failed"),
            "{error:#}"
        );

        // /token
        let sign_in_redirect = format!("location: {REDIRECT_URI}?code=abc&state=headless");
        let (base, served) = serve_in_order(vec![
            raw_response(
                "303 See Other",
                &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
            ),
            raw_response("303 See Other", &[&sign_in_redirect]),
        ]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
            .await
            .expect_err("no /token");
        served.join().unwrap();
        assert_no_request_url(&error);
        assert!(
            format!("{error:#}").starts_with("POST /token failed"),
            "{error:#}"
        );

        // The refresh and the device flow.
        let error = refresh(&dead_base(), "client", "rt-1", "did:key:zFixture")
            .await
            .expect_err("nothing listens");
        assert_no_request_url(&error);
        let error = authenticate_device_flow(&dead_base(), "client")
            .await
            .expect_err("nothing listens");
        assert_no_request_url(&error);
    }

    #[tokio::test]
    async fn a_body_read_error_names_no_url_either() {
        // The head promises 100 bytes and the connection ends after three.
        let truncated =
            "HTTP/1.1 200 OK\r\ncontent-length: 100\r\ncontent-type: application/json\r\n\
                         connection: close\r\n\r\nabc"
                .to_string();
        let (base, served) = serve_in_order(vec![truncated]);
        let error = refresh(&base, "client", "rt-1", "did:key:zFixture")
            .await
            .expect_err("the body ends early");
        served.join().unwrap();
        assert_no_request_url(&error);
    }

    #[tokio::test]
    async fn a_refusals_description_is_in_no_error_text() {
        for code in [
            "invalid_scope",
            "access_denied",
            "temporarily_unavailable",
            "server_error",
        ] {
            let error = sign_in_answering(&sign_in_refusal(code, MARKER)).await;
            assert_body_free(&error);
            let typed = error.downcast_ref::<AuthError>().expect("typed");
            assert_eq!(typed.error_code(), code);
            assert_eq!(
                format!("{error:#}"),
                format!("/sign_in refused the request: {code}")
            );
        }

        // The `error` is held to the short fixed charset as well: a value
        // outside it is not repeated.
        let hostile = urlencoding::encode(&format!("{MARKER} <b>x</b>")).into_owned();
        let location = format!("{REDIRECT_URI}?error={hostile}&state=headless");
        let error = sign_in_answering(&location).await;
        assert_body_free(&error);
        assert!(error.downcast_ref::<AuthError>().is_some(), "{error:#}");

        // At /authorize.
        let key = SiwxKey::generate_ed25519();
        let refusal = format!(
            "location: {REDIRECT_URI}?state=headless&error=invalid_scope&error_description={}",
            urlencoding::encode(MARKER)
        );
        let (base, served) = serve_in_order(vec![raw_response("303 See Other", &[&refusal])]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "io.inblock.mail")
            .await
            .expect_err("refused");
        served.join().unwrap();
        assert_body_free(&error);
        assert_eq!(
            format!("{error:#}"),
            "/authorize refused the request: invalid_scope"
        );
        let hostile = format!("location: {REDIRECT_URI}?state=headless&error={hostile}");
        let (base, served) = serve_in_order(vec![raw_response("303 See Other", &[&hostile])]);
        let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "io.inblock.mail")
            .await
            .expect_err("refused");
        served.join().unwrap();
        assert_body_free(&error);
    }

    /// A token answer with `expires_in` spelled as `raw` (JSON text), or none.
    async fn tokens_with_expires_in(raw: Option<&str>) -> AuthTokens {
        let body = match raw {
            Some(raw) => format!(
                r#"{{"access_token":"new-a","token_type":"Bearer","refresh_token":"new-r","expires_in":{raw}}}"#
            ),
            None => r#"{"access_token":"new-a","token_type":"Bearer","refresh_token":"new-r"}"#
                .to_string(),
        };
        let (base, served) = serve_in_order(vec![raw_response_with_body(
            "200 OK",
            &["content-type: application/json"],
            &body,
        )]);
        let tokens = refresh(&base, "client", "old-r", "did:key:zFixture")
            .await
            .unwrap_or_else(|e| panic!("expires_in {raw:?} lost the pair: {e:#}"));
        served.join().unwrap();
        assert_eq!(tokens.access_token, "new-a");
        assert_eq!(tokens.refresh_token.as_deref(), Some("new-r"));
        tokens
    }

    #[tokio::test]
    async fn any_expires_in_keeps_the_new_pair_with_a_bounded_lifetime() {
        const DAY: u64 = 24 * 60 * 60;
        for (raw, lifetime) in [
            (Some("300"), 300),
            (Some("3600.5"), 3600),
            (Some("1e20"), DAY),
            (Some("1e999"), DAY),
            (Some("18446744073709551615"), DAY),
            (Some("18446744073709551616"), DAY),
            (Some("99999999999999999999999999"), DAY),
            (Some("-5"), 10),
            (Some("-1e999"), 10),
            (Some("0"), 10),
            (Some("3"), 10),
            (Some("0.5"), 10),
            // No number: the documented default.
            (Some("\"3600\""), 60),
            (Some("\"soon\""), 60),
            (Some("null"), 60),
            (Some("true"), 60),
            (Some("[1]"), 60),
            (Some(r#"{"a":1}"#), 60),
            (None, 60),
        ] {
            let tokens = tokens_with_expires_in(raw).await;
            assert_eq!(tokens.expires_in, Some(lifetime), "expires_in {raw:?}");
        }
    }

    #[tokio::test]
    async fn the_code_flow_and_the_device_flow_read_expires_in_the_same_way() {
        let key = SiwxKey::generate_ed25519();
        let tokens = {
            let body = r#"{"access_token":"a","token_type":"Bearer","expires_in":1e20}"#;
            let authorize_redirect = format!(
                "location: /login?nonce=n1&state=headless&client_id=client&redirect_uri={}",
                urlencoding::encode(REDIRECT_URI)
            );
            let sign_in_redirect = format!("location: {REDIRECT_URI}?code=abc&state=headless");
            let (base, served) = serve_in_order(vec![
                raw_response(
                    "303 See Other",
                    &[&authorize_redirect, "set-cookie: session=abc; Path=/"],
                ),
                raw_response("303 See Other", &[&sign_in_redirect]),
                raw_response_with_body("200 OK", &["content-type: application/json"], body),
            ]);
            let tokens = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
                .await
                .expect("the pair is kept");
            served.join().unwrap();
            tokens
        };
        assert_eq!(tokens.access_token, "a");
        assert_eq!(tokens.expires_in, Some(24 * 60 * 60));
    }

    /// A proxy's auth wall is a 401 with a challenge; the server's own answer
    /// for an unregistered client has none. Only the latter is a client that
    /// registering again would fix.
    #[tokio::test]
    async fn a_401_with_a_challenge_at_authorize_is_not_an_unknown_client() {
        let key = SiwxKey::generate_ed25519();
        for challenge in [r#"Basic realm="corp""#, "Bearer", r#"Negotiate"#] {
            let header = format!("www-authenticate: {challenge}");
            let (base, served) = serve_in_order(vec![raw_response_with_body(
                "401 Unauthorized",
                &["content-type: text/html", &header],
                "<html>please sign in</html>",
            )]);
            let error = authenticate_with_scope(&base, "client", REDIRECT_URI, &key, "openid")
                .await
                .expect_err("refused by the wall");
            served.join().unwrap();
            assert!(!is_unknown_client(&error), "{challenge}: {error:#}");
            assert_eq!(
                error.downcast_ref::<AuthError>(),
                Some(&AuthError::Unauthorized),
                "{challenge}: {error:#}"
            );
            assert_eq!(
                error.downcast_ref::<AuthError>().unwrap().error_code(),
                "unauthorized"
            );
            assert!(!is_transient(&error) && !is_device_refused(&error));
            assert!(
                format!("{error:#}").contains("401"),
                "the status is named: {error:#}"
            );
        }
    }
}
