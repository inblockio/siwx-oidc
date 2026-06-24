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
/// Prefix for server-issued, single-use CAIP-122 nonces (C1). Used by the
/// device-approval and account CAIP-122 paths, which (unlike the login path) have
/// no session to carry the nonce: it is minted on a dedicated GET and consumed on
/// submit. The stored value is the operation context the nonce is bound to.
const KV_CAIP122_NONCE_PREFIX: &str = "caip122_nonce";
/// TTL for a server-issued CAIP-122 device/account nonce (seconds). Long enough
/// for the user to read the page and complete a wallet signing prompt, short
/// enough to bound the replay window. Matches the auth-code lifetime.
pub const CAIP122_NONCE_TTL_SECS: u64 = 300; // 5 min
pub const ENTRY_LIFETIME: usize = 300; // 5min — auth codes must outlive redirect chains
pub const SESSION_LIFETIME: u64 = 300; // 5min
pub const CLIENT_LIFETIME: u64 = 30 * 24 * 3600; // 30 days
pub const SESSION_COOKIE_NAME: &str = "session";

/// Redis key prefix for the `webauthn:by_did/{did}` reverse index: a SET of the
/// `cred_id_b64` values registered/linked for a DID. Maintained at
/// `register_finish` / `link_finish` (SADD) and `purge_identity` (SREM), so a
/// login-time `get_passkeys_for_did` lookup is an O(members) SMEMBERS instead of
/// a full credential keyspace scan. Advisory: a read-only scan twin self-heals a
/// missing/stale index, so the index never becomes load-bearing for correctness.
pub const KV_WEBAUTHN_BY_DID_PREFIX: &str = "webauthn:by_did";

/// Redis key prefix for the opaque login user-session: `user:session/{token}` ->
/// DID. The token is the identity hint that scopes the passkey picker's
/// `allowCredentials` on a returning login. It is an OPAQUE random token (never a
/// plaintext DID), so a forged/guessed value is a Redis miss -> safe usernameless
/// fallback (the load-bearing enumeration-safety invariant).
pub const KV_USER_SESSION_PREFIX: &str = "user:session";

/// TTL for an opaque login user-session (seconds). Long enough that a returning
/// user's picker stays scoped across normal usage, bounded so a leaked token does
/// not scope forever. 30 days mirrors a typical "remember this device" horizon.
pub const USER_SESSION_LIFETIME: u64 = 30 * 24 * 3600; // 30 days

/// TTL for opaque access tokens (MSC3861 mode).
pub const ACCESS_TOKEN_TTL: u64 = 300; // 5 minutes
/// TTL for opaque refresh tokens (MSC3861 mode).
pub const REFRESH_TOKEN_TTL: u64 = 7_776_000; // 90 days

/// Prefix for the short-lived refresh-token rotation grace pointer:
/// `token_rotated/{old_refresh}` -> the successor token pair already minted by the
/// rotation that consumed `old_refresh`. Lets a client that LOST the rotation
/// response (common on mobile: radio handoff, app suspension, cross-process
/// refresh) replay the old refresh token once within the grace window and receive
/// the same successor, instead of being signed out by `invalid_grant`.
const KV_ROTATED_PREFIX: &str = "token_rotated";
/// Grace window (seconds) for replaying a just-rotated refresh token. Bounded well
/// under [`ACCESS_TOKEN_TTL`] so the successor access token stored in the pointer
/// is still valid when replayed. It does NOT widen the refresh lifetime: the old
/// token is still removed as a live credential, and unknown/expired tokens are
/// still rejected.
pub const REFRESH_GRACE_TTL: u64 = 60; // 1 min

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

/// The successor token pair recorded under [`KV_ROTATED_PREFIX`] when a refresh
/// token is rotated, so a lost-response replay of the old refresh token can recover
/// it idempotently within the grace window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotatedToken {
    /// The successor access token minted by the rotation.
    pub access_token: String,
    /// The successor refresh token minted by the rotation.
    pub refresh_token: String,
    /// Absolute Unix expiry of the successor access token (drives `expires_in` on replay).
    pub access_exp: i64,
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

    /// Record the successor pair for a just-rotated refresh token so a lost-response
    /// replay of `old_refresh` within the grace window returns the same pair instead
    /// of `invalid_grant`. Best-effort at the call site: a failure must not fail the
    /// rotation the client already observed.
    async fn set_rotated_token(
        &self,
        old_refresh: &str,
        successor: &RotatedToken,
        ttl: u64,
    ) -> Result<()>;
    /// Look up the successor pair for a just-rotated refresh token (grace replay).
    /// Returns None once the grace window has expired (Redis TTL).
    async fn get_rotated_token(&self, old_refresh: &str) -> Result<Option<RotatedToken>>;

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

    // -- CAIP-122 server-issued single-use nonce store (C1) -------------------

    /// Mint a server-issued single-use CAIP-122 nonce in `category`, bound to
    /// `binding` (the operation context, e.g. the device `user_code` or the
    /// account `action`). Returns the nonce string to embed in the page's signed
    /// message. TTL is [`CAIP122_NONCE_TTL_SECS`].
    async fn mint_caip122_nonce(&self, category: &str, binding: &str) -> Result<String>;

    /// Atomically consume a previously-minted CAIP-122 nonce in `category`.
    /// Returns `Some(binding)` for the FIRST consumer (the operation context the
    /// nonce was minted for); `None` if the nonce is unknown/expired OR was already
    /// consumed (replay). Single-use via SETNX, mirroring [`Self::try_consume_code`].
    async fn try_consume_caip122_nonce(
        &self,
        category: &str,
        nonce: &str,
    ) -> Result<Option<String>>;
}
