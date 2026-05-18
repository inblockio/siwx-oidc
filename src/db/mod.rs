use anyhow::Result;
use async_trait::async_trait;
use chrono::{offset::Utc, DateTime};
use openidconnect::{core::CoreClientMetadata, Nonce, RegistrationAccessToken};
use serde::{Deserialize, Serialize};

mod redis;
pub use self::redis::RedisClient;

const KV_CLIENT_PREFIX: &str = "clients";
const KV_SESSION_PREFIX: &str = "sessions";
const KV_CODE_PREFIX: &str = "codes";
const KV_TOKEN_PREFIX: &str = "token";
const KV_DEVICE_PREFIX: &str = "device_ids";
pub const ENTRY_LIFETIME: usize = 300; // 5min — auth codes must outlive redirect chains
pub const SESSION_LIFETIME: u64 = 300; // 5min
pub const CLIENT_LIFETIME: u64 = 30 * 24 * 3600; // 30 days
pub const SESSION_COOKIE_NAME: &str = "session";

/// TTL for opaque access tokens (MSC3861 mode).
pub const ACCESS_TOKEN_TTL: u64 = 3000; // 50 minutes
/// TTL for opaque refresh tokens (MSC3861 mode).
pub const REFRESH_TOKEN_TTL: u64 = 86400; // 24 hours

#[derive(Clone, Serialize, Deserialize)]
pub struct CodeEntry {
    pub exchange_count: usize,
    /// The authenticated DID (e.g. `did:pkh:eip155:1:0x…`).
    pub did: String,
    pub nonce: Option<Nonce>,
    pub client_id: String,
    pub auth_time: DateTime<Utc>,
    /// PKCE code_challenge (S256-hashed verifier, base64url-encoded).
    #[serde(default)]
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method ("S256" or "plain").
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// Device ID generated during Synapse provisioning (MSC3861).
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub secret: String,
    pub metadata: CoreClientMetadata,
    pub access_token: Option<RegistrationAccessToken>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub siwe_nonce: String,
    pub oidc_nonce: Option<Nonce>,
    pub secret: String,
    pub signin_count: u64,
    /// Set by a server-verified ceremony (e.g. WebAuthn) before redirecting to /sign_in.
    /// When present, sign_in trusts this DID without re-verifying a CAIP-122 cookie.
    #[serde(default)]
    pub verified_did: Option<String>,
}

/// Metadata stored alongside an opaque token in Redis (MSC3861 introspection).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// The Matrix-compatible username (DID with colons replaced by dashes).
    pub username: String,
    /// Device ID assigned by this provider (deterministic from token).
    pub device_id: String,
    /// Space-separated OAuth2 scopes granted.
    pub scope: String,
    /// The client_id that requested the token.
    pub client_id: String,
    /// Token issued-at (Unix timestamp).
    pub iat: i64,
    /// Token expiry (Unix timestamp).
    pub exp: i64,
}

#[async_trait]
pub trait DBClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()>;
    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>>;
    async fn delete_client(&self, client_id: String) -> Result<()>;
    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()>;
    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>>;
    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()>;
    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>>;
    /// Atomically consume an authorization code. Returns the entry if this is
    /// the first call for this code, or None if already consumed / not found.
    async fn try_consume_code(&self, code: String) -> Result<Option<CodeEntry>>;
    /// Atomically mark a session as signed-in. Returns true on first call,
    /// false if the session was already signed-in.
    async fn try_mark_session_signed_in(&self, id: String) -> Result<bool>;

    // -- Opaque token storage (MSC3861) ----------------------------------------

    /// Store an opaque token with metadata and a TTL in seconds.
    async fn set_token(&self, token: &str, metadata: &TokenMetadata, ttl: u64) -> Result<()>;
    /// Retrieve metadata for an opaque token (returns None if expired/missing).
    async fn get_token(&self, token: &str) -> Result<Option<TokenMetadata>>;
    /// Delete an opaque token (e.g. on revocation).
    async fn delete_token(&self, token: &str) -> Result<()>;

    // -- Device ID persistence ----------------------------------------------------

    /// Look up the persistent device ID for a DID.
    async fn get_device_id(&self, did: &str) -> Result<Option<String>>;
    /// Store a persistent device ID for a DID (no TTL).
    async fn set_device_id(&self, did: &str, device_id: &str) -> Result<()>;
    /// Remove the persistent device ID for a DID (called at logout so the next
    /// login creates a fresh device for clients that clear their crypto store).
    async fn delete_device_id(&self, did: &str) -> Result<()>;
}
