// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

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

/// TTL for opaque access tokens (both modes).
pub const ACCESS_TOKEN_TTL: u64 = 300; // 5 minutes
/// TTL for opaque refresh tokens (both modes).
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

/// TTL for the short-lived device/user revocation tombstones. Long enough to
/// outlast an in-flight refresh that started before a revoke sweep, **and** to
/// outlive the bounded fail-open window below with real margin.
///
/// Raised from 600s to 900s on 2026-07-25: at 600 the margin against
/// `2 * ACCESS_TOKEN_TTL` was exactly **zero** (600 == 600), so a tombstone
/// expired at precisely the moment the second refresh cycle completed, leaving no
/// slack for clock skew or a delayed refresh. The assertion below caught this on
/// its first compile. Lengthening is cheap: a lingering tombstone only makes a
/// refresh refuse, and a fresh sign-in never consults it.
pub const TOMBSTONE_TTL_SECS: u64 = 900; // 15 min

/// Compile-time guarantee that failing OPEN on an *indeterminate* revocation
/// probe (see [`RevocationState::Indeterminate`]) is self-limiting.
///
/// A tombstone must still be readable on the refresh that follows an outage. As
/// long as the tombstone outlives two access-token cycles, a genuine revocation
/// planted while Redis was unreachable is observed at the next rotation, so the
/// fail-open window is bounded by one access-token lifetime rather than being
/// open-ended. Shortening the tombstone TTL or lengthening the access-token TTL
/// past this bound breaks the build instead of silently widening the hole.
const _: () = assert!(
    TOMBSTONE_TTL_SECS > 2 * ACCESS_TOKEN_TTL,
    "fail-open on an indeterminate revocation probe is only safe while the \
     tombstone outlives two access-token cycles; adjust TOMBSTONE_TTL_SECS"
);

/// Outcome of probing the revocation tombstones for a session.
///
/// The distinction that matters is **definite vs indeterminate**. A definite
/// tombstone must tear the session down; an infrastructure error must NOT.
///
/// Why the asymmetry is load-bearing: at the post-mint recheck the caller has
/// already deleted the presented refresh token and has not yet written the grace
/// pointer, so rolling back leaves the client holding *neither* the old nor the
/// new token — an unrecoverable sign-out. Treating an I/O error as a revocation
/// therefore converts a transient fault into permanent, silent session loss.
/// Treating it as "proceed" costs at most one access-token cycle of extra life
/// for a session that may already be revoked, which the tombstone TTL bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    /// A tombstone is definitely present. Fail **closed**: refuse or roll back.
    Revoked,
    /// No tombstone is present. Proceed.
    Live,
    /// The probe could not complete (I/O error). Fail **open**: proceed.
    Indeterminate,
}

impl RevocationState {
    /// Whether this outcome must tear the session down.
    ///
    /// Only [`Revoked`](Self::Revoked) does. This is the single place the
    /// fail-open policy is expressed, so it cannot drift between call sites.
    pub fn must_refuse(self) -> bool {
        matches!(self, RevocationState::Revoked)
    }
}

/// Collapse the two tombstone probes into one [`RevocationState`].
///
/// Extracted as a pure function so the policy can be exercised exhaustively
/// (all nine combinations) without standing up a `DBClient` double — the
/// decision here is security-relevant enough that it should not be reachable
/// only through an integration path.
///
/// Precedence is deliberate: a **definite** `Ok(true)` on either axis wins even
/// when the other probe errored. Erring on one axis must never mask a tombstone
/// we did successfully read on the other.
pub(crate) fn collapse_revocation(device: Result<bool>, user: Result<bool>) -> RevocationState {
    if matches!(device, Ok(true)) || matches!(user, Ok(true)) {
        return RevocationState::Revoked;
    }
    if device.is_err() || user.is_err() {
        return RevocationState::Indeterminate;
    }
    RevocationState::Live
}

#[cfg(test)]
mod revocation_policy_tests {
    use super::*;
    use anyhow::anyhow;

    fn err() -> Result<bool> {
        Err(anyhow!("redis i/o"))
    }

    // -- The regression guard. A DEFINITE tombstone must always fail closed. ----
    // If any of these three start returning anything but `Revoked`, the fail-open
    // change has destroyed the property it was required to preserve (invariant
    // I8). Do not "fix" a failure here by relaxing the assertion.

    #[test]
    fn definite_device_tombstone_fails_closed() {
        assert_eq!(
            collapse_revocation(Ok(true), Ok(false)),
            RevocationState::Revoked
        );
    }

    #[test]
    fn definite_user_tombstone_fails_closed() {
        assert_eq!(
            collapse_revocation(Ok(false), Ok(true)),
            RevocationState::Revoked
        );
    }

    #[test]
    fn definite_tombstone_wins_over_an_errored_sibling_probe() {
        // The dangerous middle case: one axis errored, the other definitively
        // says revoked. Fail-open must NOT swallow the tombstone we did read.
        assert_eq!(
            collapse_revocation(err(), Ok(true)),
            RevocationState::Revoked
        );
        assert_eq!(
            collapse_revocation(Ok(true), err()),
            RevocationState::Revoked
        );
    }

    // -- Fail open only when the answer is genuinely unknown -------------------

    #[test]
    fn io_error_on_either_axis_is_indeterminate() {
        assert_eq!(
            collapse_revocation(err(), Ok(false)),
            RevocationState::Indeterminate
        );
        assert_eq!(
            collapse_revocation(Ok(false), err()),
            RevocationState::Indeterminate
        );
        assert_eq!(
            collapse_revocation(err(), err()),
            RevocationState::Indeterminate
        );
    }

    #[test]
    fn no_tombstone_is_live() {
        assert_eq!(
            collapse_revocation(Ok(false), Ok(false)),
            RevocationState::Live
        );
    }

    #[test]
    fn only_revoked_refuses() {
        assert!(RevocationState::Revoked.must_refuse());
        assert!(!RevocationState::Live.must_refuse());
        assert!(!RevocationState::Indeterminate.must_refuse());
    }

    #[test]
    fn fail_open_window_is_bounded_by_the_tombstone_ttl() {
        // Mirrors the compile-time assertion, so the reasoning is visible in the
        // test suite too rather than only as a build error.
        //
        // `const { .. }` because both operands are constants: clippy's
        // `assertions_on_constants` correctly points out that a plain `assert!`
        // over constants is evaluated at compile time anyway. Keeping it in a
        // const block preserves the intent (a build error if the invariant is
        // broken) while making that explicit rather than incidental.
        const {
            assert!(
                TOMBSTONE_TTL_SECS > 2 * ACCESS_TOKEN_TTL,
                "tombstone must outlive two access-token cycles for fail-open to be bounded"
            );
        }
    }
}

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

    /// Whether a `(username, device_id)` pair currently carries a device-revoked
    /// tombstone (set by [`revoke_device_tokens`]). A refresh/mint that sees this
    /// must refuse so it cannot resurrect a just-signed-out device (S3-3 / H3).
    async fn is_device_revoked(&self, username: &str, device_id: &str) -> Result<bool>;

    /// Whether a user currently carries a deactivation tombstone (set by
    /// `account_deactivate` / `account_erase` BEFORE the token sweep). A
    /// refresh/mint that sees this must refuse so it cannot resurrect access for a
    /// terminating account (S3-4 / H6).
    async fn is_user_deactivated(&self, username: &str) -> Result<bool>;

    /// Probe both revocation tombstones for a session and collapse them into a
    /// single [`RevocationState`].
    ///
    /// `Revoked` **dominates**: a definite tombstone on either axis fails closed
    /// even if the other probe errored. Only when neither probe found a tombstone
    /// *and* at least one could not complete is the result `Indeterminate`.
    /// An empty `device_id` means "no device to revoke" and skips that probe.
    ///
    /// This is the one place the fail-open policy lives, so the four call sites
    /// (pre- and post-mint, in both `oidc::token_refresh` and `compat::refresh`)
    /// cannot drift apart.
    async fn probe_revocation(&self, username: &str, device_id: &str) -> RevocationState {
        let device = if device_id.is_empty() {
            Ok(false)
        } else {
            self.is_device_revoked(username, device_id).await
        };
        let user = self.is_user_deactivated(username).await;
        collapse_revocation(device, user)
    }

    // -- Opaque token storage (MSC3861) ----------------------------------------

    /// Store an opaque token with metadata and a TTL in seconds. Refuses an
    /// entry whose [`TokenMetadata::kind`] is unset.
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
