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
/// Secondary index: a Redis SET of token keys per `(username, device_id)`, kept
/// in sync on every token mint/refresh so revocation is an atomic O(members)
/// delete instead of a racy `KEYS` scan (S3-3 / H3 fix).
const KV_DEVICE_TOKEN_IDX_PREFIX: &str = "idx:user_device";
/// Short-lived tombstone marking a `(username, device_id)` as just-revoked, so an
/// in-flight refresh that completes right after the sweep cannot leave a survivor
/// (S3-3 / H3 fix). Checked by the refresh/mint paths.
const KV_DEVICE_TOMBSTONE_PREFIX: &str = "tombstone:device";
/// Per-user deactivation tombstone set BEFORE the deactivate/erase sweep so any
/// concurrent refresh/mint refuses to issue tokens for a terminating user
/// (S3-4 / H6 fix). Checked by the refresh/mint paths.
const KV_USER_TOMBSTONE_PREFIX: &str = "tombstone:user";
pub const ENTRY_LIFETIME: usize = 300; // 5min — auth codes must outlive redirect chains
pub const SESSION_LIFETIME: u64 = 300; // 5min
pub const CLIENT_LIFETIME: u64 = 30 * 24 * 3600; // 30 days
pub const SESSION_COOKIE_NAME: &str = "session";

/// TTL for opaque access tokens (MSC3861 mode).
pub const ACCESS_TOKEN_TTL: u64 = 300; // 5 minutes
/// TTL for opaque refresh tokens (MSC3861 mode).
pub const REFRESH_TOKEN_TTL: u64 = 7_776_000; // 90 days

/// Default device code lifetime (RFC 8628 `expires_in`).
pub const DEVICE_CODE_LIFETIME: u64 = 1800; // 30 minutes
/// Minimum polling interval for device code grant (seconds).
pub const DEVICE_CODE_INTERVAL: u64 = 5;

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
    /// Original scope from /authorize, preserved so sign_in can extract a client-proposed device_id.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Status of an RFC 8628 device authorization code.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
}

/// An RFC 8628 device authorization code stored in Redis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceCodeEntry {
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub status: DeviceCodeStatus,
    pub did: Option<String>,
    pub device_id: Option<String>,
    pub last_poll: Option<i64>,
    pub created_at: i64,
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
    /// The original DID (used as OIDC `sub` claim for consistency with ID token).
    pub did: String,
    /// Display name (ENS name or DID) for Synapse display name updates.
    pub name: String,
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

    /// Atomically claim an *approved* device code for redemption. Returns `true`
    /// only for the first caller; concurrent polls get `false` and must not issue
    /// tokens (S3-1 / H9). Mirrors [`try_consume_code`](Self::try_consume_code):
    /// a `SET .../redeemed 1 NX EX <ttl>` so exactly one poll wins.
    async fn try_claim_device_code(&self, device_code: &str) -> Result<bool>;

    /// Whether a `(username, device_id)` pair currently carries a device-revoked
    /// tombstone (set by [`revoke_device_tokens`]). A refresh/mint that sees this
    /// must refuse so it cannot resurrect a just-signed-out device (S3-3 / H3).
    async fn is_device_revoked(&self, username: &str, device_id: &str) -> Result<bool>;

    /// Whether a user currently carries a deactivation tombstone (set by
    /// `account_deactivate` / `account_erase` BEFORE the token sweep). A
    /// refresh/mint that sees this must refuse so it cannot resurrect access for a
    /// terminating account (S3-4 / H6).
    async fn is_user_deactivated(&self, username: &str) -> Result<bool>;

    // -- Opaque token storage (MSC3861) ----------------------------------------

    /// Store an opaque token with metadata and a TTL in seconds.
    async fn set_token(&self, token: &str, metadata: &TokenMetadata, ttl: u64) -> Result<()>;
    /// Retrieve metadata for an opaque token (returns None if expired/missing).
    async fn get_token(&self, token: &str) -> Result<Option<TokenMetadata>>;
    /// Delete an opaque token (e.g. on revocation).
    async fn delete_token(&self, token: &str) -> Result<()>;

    // -- RFC 8628 device code storage -----------------------------------------

    /// Store a device code entry with a TTL in seconds.
    async fn set_device_code(
        &self,
        device_code: &str,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()>;
    /// Retrieve a device code entry.
    async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>>;
    /// Update a device code entry (preserving original TTL is caller's responsibility).
    async fn update_device_code(
        &self,
        device_code: &str,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()>;
    /// Delete a device code entry.
    async fn delete_device_code(&self, device_code: &str) -> Result<()>;
    /// Look up a device code by its user-facing code.
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<(String, DeviceCodeEntry)>>;
    /// Store the user_code -> device_code reverse mapping with a TTL.
    async fn set_user_code_mapping(
        &self,
        user_code: &str,
        device_code: &str,
        ttl: u64,
    ) -> Result<()>;
    /// Delete the user_code -> device_code mapping.
    async fn delete_user_code_mapping(&self, user_code: &str) -> Result<()>;
}
