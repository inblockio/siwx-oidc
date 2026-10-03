// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{offset::Utc, DateTime};
use openidconnect::{core::CoreClientMetadata, Nonce, RegistrationAccessToken};
use serde::{Deserialize, Serialize};

pub mod grant;
mod redis;
pub mod seal;
pub mod tokens;
pub use self::redis::RedisClient;

const KV_CLIENT_PREFIX: &str = "clients";
const KV_SESSION_PREFIX: &str = "sessions";
const KV_CODE_PREFIX: &str = "codes";
/// Legacy token entries `token/{raw}`, written by builds before the grant record
/// and only read and deleted now (see [`DBClient::set_token`]).
const KV_TOKEN_PREFIX: &str = "token";
/// Legacy secondary index: a Redis SET of `token/{raw}` keys per
/// `(username, device_id)`, which builds before the grant record kept so
/// revocation was an atomic O(members) delete (S3-3 / H3 fix). Revocation still
/// sweeps it; the lift of a legacy refresh token removes its member.
const KV_DEVICE_TOKEN_IDX_PREFIX: &str = "idx:user_device";
/// Short-lived tombstone marking a `(username, device_id)` as just-revoked, so an
/// in-flight refresh that completes right after the sweep cannot leave a survivor
/// (S3-3 / H3 fix). Checked by the rotation and lift scripts (`db::grant`).
const KV_DEVICE_TOMBSTONE_PREFIX: &str = "tombstone:device";
/// Per-user deactivation tombstone set BEFORE the deactivate/erase sweep so any
/// concurrent refresh refuses to issue tokens for a terminating user (S3-4 / H6
/// fix). Checked by the rotation and lift scripts (`db::grant`).
const KV_USER_TOMBSTONE_PREFIX: &str = "tombstone:user";
/// Durable erasure markers: `erased:user/{localpart}` and
/// `erased:did/{hex(sha256(canonical DID))}`, written with NO TTL before an
/// account is erased and checked before any reactivation. They are what makes
/// an erasure final: Synapse's `reactivate_user` (1.161.0) clears its own erased
/// flag and recreates the profile row, and `query_user` does not report erasure.
/// The DID is stored as a hash so an erased account leaves no DID in cleartext.
const KV_ERASED_USER_PREFIX: &str = "erased:user";
const KV_ERASED_DID_PREFIX: &str = "erased:did";
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

/// Redis key prefix for a stored passkey credential:
/// `webauthn:credential/{cred_id_b64}` -> the raw serialized `webauthn_rs::Passkey`
/// JSON. Written by `register_finish`/`link_finish` and rewritten on every login
/// (the sign counter lives INSIDE this blob, at `cred.counter`).
pub const KV_WEBAUTHN_CREDENTIAL_PREFIX: &str = "webauthn:credential";

/// Redis key prefix for an account link: `webauthn:link/{cred_id_b64}` -> a JSON
/// `{ primary_did, label }`. Owned and written by the binary's account-linking
/// ceremony (`link_start`/`link_finish`); nothing else may write it.
///
/// It is declared here because it is part of the credential **read** path, not
/// because ownership moves: a link OVERRIDES the DID derived from the passkey, so
/// any reader that resolves a credential's identity has to consult it or it will
/// silently attribute a linked credential to the wrong principal. Reading is not
/// owning. See [`crate::credential_migration`].
pub const KV_WEBAUTHN_LINK_PREFIX: &str = "webauthn:link";

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

/// Lifetime of an access token (both modes).
pub const ACCESS_TOKEN_TTL: u64 = 300; // 5 minutes
/// Inactivity lifetime of a grant with a refresh token: it ends this long after
/// its last rotation (both modes).
pub const REFRESH_TOKEN_TTL: u64 = 7_776_000; // 90 days

/// The longest lifetime (`exp - iat`) an access token is ever written with: a
/// user access token lives [`ACCESS_TOKEN_TTL`] and a minted admin token at most
/// 900 s (`admin_token::ADMIN_TOKEN_TTL_MAX`, which a const assertion in that
/// module ties to this value). Every refresh token lives [`REFRESH_TOKEN_TTL`].
/// Read only by [`legacy_token_kind`].
pub const ACCESS_TOKEN_MAX_LIFETIME: i64 = 900;

const _: () = assert!(
    (ACCESS_TOKEN_TTL as i64) <= ACCESS_TOKEN_MAX_LIFETIME
        && ACCESS_TOKEN_MAX_LIFETIME < REFRESH_TOKEN_TTL as i64,
    "the lifetimes of the two token kinds must not overlap, or legacy_token_kind \
     cannot tell them apart"
);

/// The scope Synapse tests in `is_server_admin()`. Only a minted admin token
/// (an access token) ever carries it; see [`legacy_token_kind`].
pub const SYNAPSE_ADMIN_SCOPE: &str = "urn:synapse:admin:*";

/// TTL for the short-lived device/user revocation tombstones, which revocation
/// plants and the rotation and lift scripts (`grant::ROTATE_LUA`,
/// `grant::LIFT_LUA`) refuse a grant under.
/// Long enough to outlast a refresh that was in flight when a revoke sweep ran.
/// A lingering tombstone only makes a refresh refuse (a user tombstone also
/// refuses the refresh of a grant signed in after `logout/all` or deactivation,
/// for at most this long; Phase 3's epochs replace tombstones), and a fresh
/// sign-in never consults it.
pub const TOMBSTONE_TTL_SECS: u64 = 900; // 15 min

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
    /// PKCE code_challenge_method. Only "S256" is accepted: /authorize rejects
    /// "plain", and /token refuses any stored method other than "S256".
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// Device ID generated during Synapse provisioning (MSC3861).
    #[serde(default)]
    pub device_id: Option<String>,
    /// The Matrix localpart `resolve_identity` resolved at `sign_in` time
    /// (grandfathered legacy, already-migrated modern, or a genuinely new
    /// modern identity — see `localpart::resolve_identity`). The
    /// `authorization_code` grant runs in a SEPARATE request from the sign_in
    /// that provisioned the account, so it reads this back rather than
    /// recomputing a localpart from `did` (which could otherwise land on the
    /// wrong scheme for a grandfathered account). `#[serde(default)]` so an
    /// entry written by a pre-migration build deserializes to `None`; callers
    /// fall back to `localpart::legacy_localpart(&did)` in that case — correct
    /// for every account that predates this field, since accounts that
    /// existed before grandfathering are, by definition, legacy accounts.
    #[serde(default)]
    pub localpart: Option<String>,
    /// The scope the authorization request asked for, exactly as `/authorize`
    /// bound it to the session. The token endpoint reads what was requested
    /// from here, never from the front channel. `#[serde(default)]` so a code
    /// written by an earlier build, which a new build reads for up to
    /// [`ENTRY_LIFETIME`], deserializes to `None`: the token endpoint then
    /// answers as it did before the scope travelled.
    #[serde(default)]
    pub scope: Option<String>,
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
    /// The authorization request `/authorize` validated and bound to this
    /// session. `sign_in` issues the code for this request, never for
    /// front-channel parameters. `None` only on a session written by an older
    /// build, which `sign_in` refuses with a "restart sign-in" error.
    #[serde(default)]
    pub request: Option<AuthorizationRequest>,
}

/// An authorization request as `/authorize` validated it, bound to the login
/// session (the OIDC nonce is [`SessionEntry::oidc_nonce`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    /// Exactly as sent, and registered for `client_id`.
    pub redirect_uri: String,
    pub state: String,
    /// `query` (or absent) or `fragment`.
    #[serde(default)]
    pub response_mode: Option<String>,
    /// The S256 PKCE challenge (base64url). The method is always S256:
    /// `/authorize` refuses any other.
    pub code_challenge: String,
}

/// Status of an RFC 8628 device authorization code.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
}

/// An RFC 8628 device authorization code stored in Redis.
///
/// `Debug` is written by hand: the user code is a credential for the approval
/// page, so it prints as its fingerprint (see [`crate::redact`]).
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for DeviceCodeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCodeEntry")
            .field("user_code_fp", &crate::redact::fingerprint(&self.user_code))
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("status", &self.status)
            .field("did", &self.did)
            .field("device_id", &self.device_id)
            .field("last_poll", &self.last_poll)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// What a stored token may be presented for.
///
/// Every endpoint accepts exactly one kind, and answers a token of the other
/// kind exactly like an unknown token, leaving it untouched:
///
/// | Endpoint | Accepts |
/// |---|---|
/// | `POST /token` (`grant_type=refresh_token`), `POST /_matrix/client/v3/refresh` | [`TokenKind::Refresh`] |
/// | `POST /oauth2/introspect`, `/userinfo`, the bearer-authenticated Matrix routes (`logout`, `logout/all`, device deletion) | [`TokenKind::Access`] |
/// | `POST /oauth2/revoke` (RFC 7009) | either |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// A bearer credential. A minted admin token is an access token.
    Access,
    /// Presented only to a refresh endpoint, to rotate into a new pair.
    Refresh,
}

/// Classify a token entry written before [`TokenMetadata::kind`] existed.
///
/// Every writer of such an entry used a fixed lifetime (`exp - iat`), and the
/// lifetimes of the two kinds do not overlap:
///
/// | Writer | Lifetime | Prefix in Matrix mode |
/// |---|---|---|
/// | access token (code, refresh and device-code grants, Matrix refresh) | [`ACCESS_TOKEN_TTL`] = 300 s | `mat_` |
/// | minted admin token | 30 s to 900 s | `msa_` |
/// | refresh token (the same four writers) | [`REFRESH_TOKEN_TTL`] = 90 days | `mcr_` |
///
/// so the lifetime alone decides, in both modes (generic mode has no prefix,
/// and the prefixes agree with this rule in Matrix mode). The admin scope was
/// only ever written on minted admin tokens, which are access tokens, so a
/// long-lived entry that carries it fits no writer's shape: it gets no kind,
/// and every endpoint answers it like an unknown token. Revocation still
/// removes it.
pub fn legacy_token_kind(meta: &TokenMetadata) -> Option<TokenKind> {
    if meta.exp - meta.iat <= ACCESS_TOKEN_MAX_LIFETIME {
        Some(TokenKind::Access)
    } else if meta.scope.split(' ').any(|s| s == SYNAPSE_ADMIN_SCOPE) {
        None
    } else {
        Some(TokenKind::Refresh)
    }
}

/// Metadata stored alongside an opaque token in Redis (MSC3861 introspection).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// The Matrix-compatible username: the localpart `resolve_identity`
    /// resolved for this DID (`localpart::resolve_identity`). NOT simply "DID
    /// with colons replaced by dashes" any more — that legacy, always-colons-
    /// to-dashes shape (`localpart::legacy_localpart`) is used ONLY for an
    /// account that already existed under it (grandfathering); a genuinely new
    /// identity gets the opaque base36 shape (`localpart::localpart_for`)
    /// instead, because matrix.org's policy server refuses the long,
    /// hyphen-heavy legacy shape (see `localpart` module doc).
    pub username: String,
    /// The Synapse device this token is bound to: the client-proposed id from
    /// the scope, or a fresh `SIWX_{uuid}` minted at provisioning. Empty for
    /// deviceless tokens (standalone mode, minted admin tokens, failed
    /// provisioning), which introspection renders as JSON `null`.
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
    /// Display name (for a user token: the ENS name, else the DID). Echoed as
    /// `name` by introspection; Synapse does not read it, and the Matrix
    /// displayname is the alias seeded at first sign-in.
    pub name: String,
    /// Which kind of token this is. Every writer sets it, and
    /// [`DBClient::set_token`] refuses an entry without one. `None` therefore
    /// appears only on an entry written before the field existed. Readers go
    /// through [`TokenMetadata::is_kind`], never this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TokenKind>,
}

impl TokenMetadata {
    /// The kind this entry is accepted as: the recorded kind, or for an entry
    /// written before kinds were recorded, [`legacy_token_kind`]. `None` means
    /// the entry is accepted nowhere.
    pub fn effective_kind(&self) -> Option<TokenKind> {
        self.kind.or_else(|| legacy_token_kind(self))
    }

    /// Whether this entry may be presented where `kind` is required.
    pub fn is_kind(&self, kind: TokenKind) -> bool {
        self.effective_kind() == Some(kind)
    }
}

#[async_trait]
pub trait DBClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()>;
    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>>;
    async fn delete_client(&self, client_id: String) -> Result<()>;
    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()>;
    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()>;
    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>>;
    /// Atomically consume an authorization code: read and delete its entry in
    /// one step. Returns the entry to exactly one caller, or None if the code is
    /// unknown, expired or already consumed. There is no other reader of codes:
    /// a code is redeemable only here, at the token endpoint.
    async fn try_consume_code(&self, code: String) -> Result<Option<CodeEntry>>;
    /// Atomically mark a session as signed-in. Returns true on first call,
    /// false if the session was already signed-in.
    async fn try_mark_session_signed_in(&self, id: String) -> Result<bool>;

    /// Atomically claim an *approved* device code for redemption. Returns `true`
    /// only for the first caller; concurrent polls get `false` and must not issue
    /// tokens (S3-1 / H9): a `SET .../redeemed 1 NX EX <ttl>` so exactly one
    /// poll wins, as exactly one caller of
    /// [`try_consume_code`](Self::try_consume_code) receives a code.
    async fn try_claim_device_code(&self, device_code: &str) -> Result<bool>;

    // -- Legacy token entries (`token/{raw}`) -----------------------------------
    //
    // Builds before the grant record stored every token this way. Tokens now
    // live in grants (`db::grant`); these entries are only read (the access
    // check's fallback, teardown, the migration of refresh tokens) and deleted.

    /// Store a legacy token entry with a TTL in seconds. No production code
    /// writes one any more; tests use it to seed the layout an older build
    /// left. Refuses an entry whose [`TokenMetadata::kind`] is unset.
    async fn set_token(&self, token: &str, metadata: &TokenMetadata, ttl: u64) -> Result<()>;
    /// Retrieve a legacy token entry (None if expired or missing).
    async fn get_token(&self, token: &str) -> Result<Option<TokenMetadata>>;
    /// Delete a legacy token entry (e.g. on revocation).
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

    // -- CAIP-122 server-issued single-use nonce store (C1) -------------------

    /// Mint a server-issued single-use CAIP-122 nonce in `category`, bound to
    /// `binding` (the operation context, e.g. the device `user_code` or the
    /// account `action`). Returns the nonce string to embed in the page's signed
    /// message. TTL is [`CAIP122_NONCE_TTL_SECS`].
    async fn mint_caip122_nonce(&self, category: &str, binding: &str) -> Result<String>;

    /// Atomically consume a previously-minted CAIP-122 nonce in `category`.
    /// Returns `Some(binding)` for the FIRST consumer (the operation context the
    /// nonce was minted for); `None` if the nonce is unknown/expired OR was already
    /// consumed (replay). Single-use via SETNX on a companion flag.
    async fn try_consume_caip122_nonce(
        &self,
        category: &str,
        nonce: &str,
    ) -> Result<Option<String>>;
}

#[cfg(test)]
mod token_kind_tests {
    use super::*;

    /// An entry exactly as a build without the `kind` field serialized it.
    fn legacy_json(iat: i64, lifetime: i64, scope: &str, device_id: &str) -> String {
        serde_json::json!({
            "username": "k3f9x2q7ab4d8m1p",
            "device_id": device_id,
            "scope": scope,
            "client_id": "c",
            "iat": iat,
            "exp": iat + lifetime,
            "did": "did:key:zDnaeLegacy",
            "name": "n",
        })
        .to_string()
    }

    fn classify(json: &str) -> Option<TokenKind> {
        let meta: TokenMetadata =
            serde_json::from_str(json).expect("a legacy entry must still deserialize");
        assert_eq!(meta.kind, None, "a legacy entry records no kind");
        meta.effective_kind()
    }

    const MATRIX_SCOPE: &str = "openid urn:matrix:client:api:* urn:matrix:client:device:SIWX_a";
    const ADMIN_SCOPE: &str = "urn:matrix:client:api:* urn:synapse:admin:*";

    /// Every shape a pre-kind build wrote, in both modes, gets its correct kind,
    /// so no live session breaks when the kinds start being enforced.
    #[test]
    fn every_legacy_entry_shape_is_classified() {
        let iat = 1_790_000_000;
        let refresh = REFRESH_TOKEN_TTL as i64;
        let access = ACCESS_TOKEN_TTL as i64;
        // Matrix mode (mat_ / mcr_), from the code, refresh, device-code grants
        // and the Matrix refresh endpoint.
        assert_eq!(
            classify(&legacy_json(iat, access, MATRIX_SCOPE, "SIWX_a")),
            Some(TokenKind::Access)
        );
        assert_eq!(
            classify(&legacy_json(iat, refresh, MATRIX_SCOPE, "SIWX_a")),
            Some(TokenKind::Refresh)
        );
        // Generic mode (no prefix, no device).
        assert_eq!(
            classify(&legacy_json(iat, access, "openid profile", "")),
            Some(TokenKind::Access)
        );
        assert_eq!(
            classify(&legacy_json(iat, refresh, "openid profile", "")),
            Some(TokenKind::Refresh)
        );
        // Minted admin tokens (msa_), at both ends of the clamped TTL window.
        for ttl in [30, 300, ACCESS_TOKEN_MAX_LIFETIME] {
            assert_eq!(
                classify(&legacy_json(iat, ttl, ADMIN_SCOPE, "")),
                Some(TokenKind::Access),
                "an admin token with a {ttl} s lifetime is an access token"
            );
        }
    }

    /// No writer ever stored the admin scope with a refresh lifetime, so such an
    /// entry gets no kind and is accepted nowhere.
    #[test]
    fn a_long_lived_admin_scoped_legacy_entry_has_no_kind() {
        let json = legacy_json(1_790_000_000, REFRESH_TOKEN_TTL as i64, ADMIN_SCOPE, "");
        assert_eq!(classify(&json), None);
        let meta: TokenMetadata = serde_json::from_str(&json).unwrap();
        assert!(!meta.is_kind(TokenKind::Access));
        assert!(!meta.is_kind(TokenKind::Refresh));
    }

    /// The boundary sits between the longest access lifetime and the refresh one.
    #[test]
    fn the_lifetime_boundary_is_the_longest_access_lifetime() {
        let iat = 1_790_000_000;
        assert_eq!(
            classify(&legacy_json(iat, ACCESS_TOKEN_MAX_LIFETIME, "openid", "")),
            Some(TokenKind::Access)
        );
        assert_eq!(
            classify(&legacy_json(
                iat,
                ACCESS_TOKEN_MAX_LIFETIME + 1,
                "openid",
                ""
            )),
            Some(TokenKind::Refresh)
        );
    }

    /// A recorded kind is authoritative and round-trips through the store's
    /// JSON; the lifetime is consulted only when no kind is recorded.
    #[test]
    fn a_recorded_kind_wins_and_round_trips() {
        let meta = TokenMetadata {
            username: "u".into(),
            device_id: String::new(),
            scope: "openid".into(),
            client_id: "c".into(),
            iat: 0,
            exp: 60,
            did: "did:key:zDnaeRecorded".into(),
            name: "n".into(),
            kind: Some(TokenKind::Refresh),
        };
        assert!(meta.is_kind(TokenKind::Refresh), "recorded kind wins");
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""kind":"refresh""#), "{json}");
        let back: TokenMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, Some(TokenKind::Refresh));
    }
}

#[cfg(test)]
mod code_entry_tests {
    use super::*;

    /// A code is stored for [`ENTRY_LIFETIME`] (300 s), so a build that adds a
    /// field reads the codes its predecessor wrote for that long. Such a code
    /// has no `scope`, which the token endpoint reads as "requested nothing
    /// known" and answers with the behaviour that predates the field.
    #[test]
    fn a_code_written_before_the_scope_travelled_has_none() {
        let before = r#"{
            "exchange_count": 0,
            "did": "did:key:zDnaeOLD",
            "nonce": null,
            "client_id": "client",
            "auth_time": "2026-10-02T00:00:00Z",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "device_id": null,
            "localpart": null
        }"#;
        let entry: CodeEntry = serde_json::from_str(before).expect("an old code still reads");
        assert_eq!(entry.scope, None);

        let with_scope = CodeEntry {
            scope: Some("openid offline_access".to_string()),
            ..entry
        };
        let round_trip: CodeEntry =
            serde_json::from_str(&serde_json::to_string(&with_scope).unwrap()).unwrap();
        assert_eq!(round_trip.scope.as_deref(), Some("openid offline_access"));
    }
}
