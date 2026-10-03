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

// Credentials a client holds are stored only as their SHA-256 digest
// ([`tokens::digest`]): authorization codes `code/{digest}`, login sessions
// `session/{digest}`, device codes `device_code/{digest}`, user codes
// `user_code/{digest}`, CAIP-122 nonces `caip122/{category}/{digest}` and
// WebAuthn ceremony state under [`Ceremony`]. Each prefix differs from the
// legacy one it replaces, so the legacy read below can never reach a digest
// entry: a client presenting a stored digest as its credential reads
// `codes/{digest}`, which nothing writes.
const KV_CODE_DIGEST_PREFIX: &str = "code";
const KV_SESSION_DIGEST_PREFIX: &str = "session";
const KV_DEVICE_CODE_DIGEST_PREFIX: &str = "device_code";
const KV_USER_CODE_DIGEST_PREFIX: &str = "user_code";
const KV_CAIP122_NONCE_DIGEST_PREFIX: &str = "caip122";

// The raw-keyed layout of the builds before digest keys. Entries in it are
// read, and used once, for their remaining lifetime (codes and sessions 300 s,
// device codes 1800 s, nonces 300 s, ceremonies 120 s) and never written anew.
// TODO(remove one release after Phase 2b): the legacy reads.
const KV_SESSION_PREFIX: &str = "sessions";
const KV_CODE_PREFIX: &str = "codes";
const KV_LEGACY_DEVICE_CODE_PREFIX: &str = "device_codes";
const KV_LEGACY_USER_CODE_PREFIX: &str = "user_codes";
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
/// Per-user tombstone that builds before the user epoch (I9) planted at
/// `logout/all`, deactivation and erasure. No build writes it any more; the
/// rotation and lift scripts (`db::grant`) still read it so one a previous
/// build planted refuses for the rest of its lifetime. TODO(remove one release
/// after Phase 3): the read, and this key.
const KV_USER_TOMBSTONE_PREFIX: &str = "tombstone:user";
/// Durable erasure markers: `erased:user/{localpart}` and
/// `erased:did/{hex(sha256(canonical DID))}`, written with NO TTL before an
/// account is erased and checked before any reactivation. They are what makes
/// an erasure final: Synapse's `reactivate_user` (1.161.0) clears its own erased
/// flag and recreates the profile row, and `query_user` does not report erasure.
/// The DID is stored as a hash so an erased account leaves no DID in cleartext.
const KV_ERASED_USER_PREFIX: &str = "erased:user";
const KV_ERASED_DID_PREFIX: &str = "erased:did";
/// Legacy prefix for server-issued, single-use CAIP-122 nonces (C1), now stored
/// under `caip122/{category}/{digest}`. Used by the device-approval and account
/// CAIP-122 paths, which (unlike the login path) have no session to carry the
/// nonce: it is minted on a dedicated GET and consumed on submit. The stored
/// value is the operation context the nonce is bound to.
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

/// The state of a WebAuthn ceremony between its start and its finish, keyed by
/// the digest of the ceremony id the client holds (the login `session` cookie,
/// the `session_id` the account re-auth start returns, or the device approval's
/// `device_passkey_{user_code}`). See [`RedisClient::put_ceremony_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    /// Registration or authentication: `webauthn:ceremony/{digest}`.
    Challenge,
    /// Linking a passkey to an account: `webauthn:link_ceremony/{digest}`.
    Link,
}

impl Ceremony {
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Ceremony::Challenge => "webauthn:ceremony",
            Ceremony::Link => "webauthn:link_ceremony",
        }
    }

    /// Where a build before digest keys stored the same state, by raw id.
    pub(crate) fn legacy_prefix(self) -> &'static str {
        match self {
            Ceremony::Challenge => "webauthn:challenge",
            Ceremony::Link => "webauthn:link_challenge",
        }
    }
}

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

/// TTL of the short-lived device tombstone, which device revocation plants
/// and the rotation and lift scripts (`grant::ROTATE_LUA`, `grant::LIFT_LUA`)
/// refuse a grant under (and of the user tombstone builds before the user
/// epoch planted, still read for one release).
/// Long enough to outlast a refresh that was in flight when a revoke sweep ran.
/// A lingering tombstone only makes a refresh refuse, and a fresh sign-in never
/// consults it.
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

/// A client's registration. The client secret and the registration access
/// token are stored only as their SHA-256 digests ([`tokens::digest`]), and a
/// presented value is compared with them digest against digest
/// ([`ClientEntry::secret_matches`], [`ClientEntry::access_token_matches`]).
/// Both are random (16 and 11 alphanumeric characters from `POST /register`),
/// so an unsalted digest is enough; an operator-chosen `default_clients`
/// secret may be weak, but its plaintext sits in the configuration anyway.
///
/// Deserializes from the stored form (`secret_digest`, `access_token_digest`)
/// and from the form a build before digest keys stored and `default_clients`
/// still configures (`secret`, `access_token`, in the clear), which it digests
/// on the way in; it serializes only the digests. The member names differ on
/// purpose: a stored digest presented as the secret is digested again and
/// never matches.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "StoredClientEntry")]
pub struct ClientEntry {
    pub secret_digest: String,
    pub metadata: CoreClientMetadata,
    pub access_token_digest: Option<String>,
}

/// Every form a client entry is read in; see [`ClientEntry`].
#[derive(Deserialize)]
struct StoredClientEntry {
    #[serde(default)]
    secret_digest: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    metadata: CoreClientMetadata,
    #[serde(default)]
    access_token_digest: Option<String>,
    #[serde(default)]
    access_token: Option<RegistrationAccessToken>,
}

impl TryFrom<StoredClientEntry> for ClientEntry {
    type Error = &'static str;

    fn try_from(stored: StoredClientEntry) -> Result<Self, Self::Error> {
        let secret_digest = match (stored.secret_digest, stored.secret) {
            (Some(digest), None) => digest,
            (None, Some(secret)) => tokens::digest(&secret),
            (Some(_), Some(_)) => {
                return Err("a client entry holds its secret both as a digest and in the clear")
            }
            (None, None) => return Err("a client entry holds no secret"),
        };
        let access_token_digest =
            match (stored.access_token_digest, stored.access_token) {
                (digest, None) => digest,
                (None, Some(token)) => Some(tokens::digest(token.secret())),
                (Some(_), Some(_)) => return Err(
                    "a client entry holds its registration access token both as a digest and in \
                     the clear",
                ),
            };
        Ok(ClientEntry {
            secret_digest,
            metadata: stored.metadata,
            access_token_digest,
        })
    }
}

impl ClientEntry {
    /// The registration of a client with `secret` and, if it has one, the
    /// registration access token `access_token`; it keeps their digests.
    pub fn new(secret: &str, metadata: CoreClientMetadata, access_token: Option<&str>) -> Self {
        ClientEntry {
            secret_digest: tokens::digest(secret),
            metadata,
            access_token_digest: access_token.map(tokens::digest),
        }
    }

    /// Whether `presented` is the client secret.
    pub fn secret_matches(&self, presented: &str) -> bool {
        digests_match(&tokens::digest(presented), &self.secret_digest)
    }

    /// Whether `presented` is the registration access token. A client without
    /// one (a `default_clients` entry that configures none) matches nothing.
    pub fn access_token_matches(&self, presented: &str) -> bool {
        self.access_token_digest
            .as_deref()
            .is_some_and(|stored| digests_match(&tokens::digest(presented), stored))
    }
}

/// Constant-time comparison of two digests. Both are 64 hex characters, so
/// the length check never short-circuits on a real comparison.
fn digests_match(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// The digest-only form of a stored client entry that holds its secret or its
/// registration access token in the clear (written by a build before digest
/// keys), or `None` when it holds neither. Only those two members change, so
/// nothing else the entry holds is lost.
/// TODO(remove once no entry a build before Phase 2b wrote can be alive:
/// [`CLIENT_LIFETIME`] after the deploy).
pub fn client_entry_without_plaintext(stored: &serde_json::Value) -> Option<serde_json::Value> {
    let object = stored.as_object()?;
    if !object.contains_key("secret") && !object.contains_key("access_token") {
        return None;
    }
    let mut upgraded = object.clone();
    for (plain, digested) in [
        ("secret", "secret_digest"),
        ("access_token", "access_token_digest"),
    ] {
        if let Some(value) = upgraded.remove(plain) {
            let digest = match value {
                serde_json::Value::String(plain) => {
                    serde_json::Value::String(tokens::digest(&plain))
                }
                _ => serde_json::Value::Null,
            };
            upgraded.insert(digested.to_string(), digest);
        }
    }
    Some(serde_json::Value::Object(upgraded))
}

/// A login session, started at `/authorize`.
///
/// Deserializes through [`StoredSessionEntry`], which also reads the form a
/// build before Phase 2b stored, with the scope and the OIDC nonce beside the
/// bound request instead of in it, and moves them into the request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "StoredSessionEntry")]
pub struct SessionEntry {
    pub siwe_nonce: String,
    pub secret: String,
    pub signin_count: u64,
    /// Set by a server-verified ceremony (e.g. WebAuthn) before redirecting to /sign_in.
    /// When present, sign_in trusts this DID without re-verifying a CAIP-122 cookie.
    #[serde(default)]
    pub verified_did: Option<String>,
    /// The authorization request `/authorize` validated and bound to this
    /// session. `sign_in` issues the code for this request, never for
    /// front-channel parameters. `None` only on a session written by an older
    /// build, which `sign_in` refuses with a "restart sign-in" error.
    #[serde(default)]
    pub request: Option<AuthorizationRequest>,
}

/// Every form a login session is read in; see [`SessionEntry`].
#[derive(Deserialize)]
struct StoredSessionEntry {
    siwe_nonce: String,
    secret: String,
    signin_count: u64,
    #[serde(default)]
    verified_did: Option<String>,
    #[serde(default)]
    request: Option<AuthorizationRequest>,
    /// Beside the request in a session a build before Phase 2b stored; it
    /// lives [`SESSION_LIFETIME`]. TODO(remove one release after Phase 2b).
    #[serde(default)]
    oidc_nonce: Option<Nonce>,
    /// Same.
    #[serde(default)]
    scope: Option<String>,
}

impl From<StoredSessionEntry> for SessionEntry {
    fn from(stored: StoredSessionEntry) -> Self {
        let request = stored.request.map(|mut request| {
            request.scope = request.scope.or(stored.scope);
            request.nonce = request.nonce.or(stored.oidc_nonce);
            request
        });
        SessionEntry {
            siwe_nonce: stored.siwe_nonce,
            secret: stored.secret,
            signin_count: stored.signin_count,
            verified_did: stored.verified_did,
            request,
        }
    }
}

/// An authorization request as `/authorize` validated it, bound to the login
/// session as one value.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// The scope as requested. `sign_in` copies it into the code (where the
    /// token endpoint reads what was requested) and takes a client-proposed
    /// device id from it.
    #[serde(default)]
    pub scope: Option<String>,
    /// The OIDC `nonce`, which the ID token carries.
    #[serde(default)]
    pub nonce: Option<Nonce>,
}

/// Written out because [`Nonce`] has no `PartialEq`; destructured so that a
/// field added later cannot be left out of the comparison.
impl PartialEq for AuthorizationRequest {
    fn eq(&self, other: &Self) -> bool {
        let AuthorizationRequest {
            client_id,
            redirect_uri,
            state,
            response_mode,
            code_challenge,
            scope,
            nonce,
        } = self;
        *client_id == other.client_id
            && *redirect_uri == other.redirect_uri
            && *state == other.state
            && *response_mode == other.response_mode
            && *code_challenge == other.code_challenge
            && *scope == other.scope
            && nonce.as_ref().map(Nonce::secret) == other.nonce.as_ref().map(Nonce::secret)
    }
}

impl Eq for AuthorizationRequest {}

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
    /// SHA-256 digest of the user code ([`tokens::digest`]); the user code
    /// itself is never stored. Empty in an entry a build before digest keys
    /// wrote until [`DeviceCodeEntry::from_stored`] fills it in.
    #[serde(default)]
    pub user_code_digest: String,
    /// The user code in the clear: present only in an entry a build before
    /// digest keys wrote (as `user_code`), never in a new one. It names that
    /// entry's legacy `user_codes/{raw}` mapping, deleted with it.
    /// TODO(remove one release after Phase 2b).
    #[serde(default, rename = "user_code", skip_serializing_if = "Option::is_none")]
    pub legacy_user_code: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub status: DeviceCodeStatus,
    pub did: Option<String>,
    pub device_id: Option<String>,
    pub last_poll: Option<i64>,
    pub created_at: i64,
    /// When the user approved the request (Unix milliseconds, Redis `TIME`):
    /// the authentication, so the grant's `auth_ms` and `auth_time`. `None` before approval and
    /// in an entry an older build approved, whose grant then counts from the
    /// poll that redeems it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_ms: Option<i64>,
}

impl std::fmt::Debug for DeviceCodeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCodeEntry")
            // A fingerprint is the digest's first eight hex characters.
            .field(
                "user_code_fp",
                &self.user_code_digest.get(..8).unwrap_or_default(),
            )
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("status", &self.status)
            .field("did", &self.did)
            .field("device_id", &self.device_id)
            .field("last_poll", &self.last_poll)
            .field("created_at", &self.created_at)
            .field("auth_ms", &self.auth_ms)
            .finish()
    }
}

impl DeviceCodeEntry {
    /// A new entry for the user code `user_code`, which it stores as a digest.
    pub fn new(user_code: &str, client_id: String, scope: String, created_at: i64) -> Self {
        DeviceCodeEntry {
            user_code_digest: tokens::digest(user_code),
            legacy_user_code: None,
            client_id,
            scope,
            status: DeviceCodeStatus::Pending,
            did: None,
            device_id: None,
            last_poll: None,
            created_at,
            auth_ms: None,
        }
    }

    /// Parse a stored entry, in either layout: an entry a build before digest
    /// keys wrote carries the user code in the clear and gets its digest here.
    pub fn from_stored(json: &str) -> serde_json::Result<Self> {
        let mut entry: DeviceCodeEntry = serde_json::from_str(json)?;
        if entry.user_code_digest.is_empty() {
            if let Some(user_code) = &entry.legacy_user_code {
                entry.user_code_digest = tokens::digest(user_code);
            }
        }
        Ok(entry)
    }
}

/// Where a device code's entry is stored. It comes from a lookup
/// ([`DBClient::get_device_code`], [`DBClient::get_device_code_by_user_code`])
/// and names the entry for the update or delete that follows, in the layout
/// the lookup found it in: an entry a build before digest keys wrote under
/// `device_codes/{raw}` is updated and deleted there, and its user-code
/// mapping still holds the raw device code, so it stays in that layout until it
/// is redeemed or expires. Its `Debug` prints a fingerprint.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCodeRef {
    pub(crate) digest: String,
    /// The raw device code, set only when the entry was found under the
    /// legacy `device_codes/{raw}`. TODO(remove one release after Phase 2b).
    pub(crate) legacy: Option<String>,
}

impl std::fmt::Debug for DeviceCodeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCodeRef")
            .field("fp", &self.digest.get(..8).unwrap_or_default())
            .field("legacy", &self.legacy.is_some())
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
    /// tokens (S3-1 / H9): a `SET device_code/{digest}/redeemed 1 NX EX <ttl>`
    /// so exactly one poll wins, as exactly one caller of
    /// [`try_consume_code`](Self::try_consume_code) receives a code. A claim a
    /// build before digest keys left (`device_codes/{raw}/redeemed`) counts too.
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
    //
    // A device code is stored under its digest, `device_code/{digest}`, and a
    // user code as `user_code/{digest}` -> the device code's digest. The entry
    // holds the user code's digest, never the code.

    /// Store a new device code entry with a TTL in seconds.
    async fn set_device_code(
        &self,
        device_code: &str,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()>;
    /// Look up the device code a client presents.
    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<(DeviceCodeRef, DeviceCodeEntry)>>;
    /// Update the entry a lookup returned, where the lookup found it, with a
    /// TTL in seconds (preserving the original TTL is the caller's
    /// responsibility).
    async fn update_device_code(
        &self,
        device_code: &DeviceCodeRef,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()>;
    /// Redis `TIME` in Unix milliseconds: the clock of every lifetime deadline
    /// (I6) and of the epochs (I9), so instances with skewed clocks agree.
    async fn server_time_ms(&self) -> Result<i64>;
    /// Delete the entry a lookup returned.
    async fn delete_device_code(&self, device_code: &DeviceCodeRef) -> Result<()>;
    /// Look up a device code by the user code a person presents, exactly as
    /// presented: the server never normalised user codes (the approval page
    /// trims and upper-cases what the person types before sending it).
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<(DeviceCodeRef, DeviceCodeEntry)>>;
    /// Store the user code -> device code mapping with a TTL.
    async fn set_user_code_mapping(
        &self,
        user_code: &str,
        device_code: &str,
        ttl: u64,
    ) -> Result<()>;
    /// Delete the user-code mapping of `entry`, in the layout it was written.
    async fn delete_user_code_mapping(&self, entry: &DeviceCodeEntry) -> Result<()>;

    // -- CAIP-122 server-issued single-use nonce store (C1) -------------------

    /// Mint a server-issued single-use CAIP-122 nonce in `category`, bound to
    /// `binding` (the operation context, e.g. the device `user_code` or the
    /// account `action`). Returns the nonce string to embed in the page's signed
    /// message. TTL is [`CAIP122_NONCE_TTL_SECS`].
    async fn mint_caip122_nonce(&self, category: &str, binding: &str) -> Result<String>;

    /// Atomically consume a previously-minted CAIP-122 nonce in `category`.
    /// Returns `Some(binding)` for the FIRST consumer (the operation context the
    /// nonce was minted for); `None` if the nonce is unknown/expired OR was already
    /// consumed (replay). Single use: the entry is read and deleted in one
    /// atomic step. A legacy nonce's binding is returned as that build stored
    /// it (for the device category, the user code in the clear).
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

#[cfg(test)]
mod client_entry_tests {
    use super::*;
    use openidconnect::RedirectUrl;

    fn metadata() -> CoreClientMetadata {
        CoreClientMetadata::new(
            vec![RedirectUrl::new("https://rp.example.org/cb".into()).unwrap()],
            Default::default(),
        )
    }

    /// The entry as a build before digest keys stored it, and as
    /// `default_clients` configures it.
    fn plaintext_entry() -> serde_json::Value {
        serde_json::json!({
            "secret": "the-client-secret",
            "metadata": metadata(),
            "access_token": "the-registration-token",
        })
    }

    #[test]
    fn a_client_entry_stores_only_the_digests_of_its_credentials() {
        let entry = ClientEntry::new(
            "the-client-secret",
            metadata(),
            Some("the-registration-token"),
        );
        let stored = serde_json::to_string(&entry).unwrap();
        assert!(!stored.contains("the-client-secret"), "{stored}");
        assert!(!stored.contains("the-registration-token"), "{stored}");
        assert!(stored.contains(&tokens::digest("the-client-secret")));
        assert!(stored.contains(&tokens::digest("the-registration-token")));
        let read: ClientEntry = serde_json::from_str(&stored).unwrap();
        assert!(read.secret_matches("the-client-secret"));
        assert!(read.access_token_matches("the-registration-token"));
    }

    /// A previous build's entry (and a configured one) authenticates exactly
    /// as before: the same secret and token match, nothing else does.
    #[test]
    fn a_plaintext_client_entry_authenticates_as_before() {
        let entry: ClientEntry = serde_json::from_value(plaintext_entry()).unwrap();
        assert!(entry.secret_matches("the-client-secret"));
        assert!(entry.access_token_matches("the-registration-token"));
        assert!(!entry.secret_matches("the-client-secre"));
        assert!(!entry.secret_matches("the-registration-token"));
        assert!(!entry.access_token_matches("the-client-secret"));
        let mut tokenless = plaintext_entry();
        tokenless["access_token"] = serde_json::Value::Null;
        let tokenless: ClientEntry = serde_json::from_value(tokenless).unwrap();
        assert!(!tokenless.access_token_matches(""));
        assert!(!tokenless.access_token_matches("the-registration-token"));
    }

    /// Someone who can read Redis cannot present what is stored there.
    #[test]
    fn a_stored_digest_presented_as_a_credential_matches_nothing() {
        let entry = ClientEntry::new("the-client-secret", metadata(), Some("tok"));
        assert!(!entry.secret_matches(&entry.secret_digest));
        assert!(!entry.access_token_matches(entry.access_token_digest.as_deref().unwrap()));
    }

    /// The upgrade replaces exactly the two credentials by their digests and
    /// keeps every other member, including one this build does not know.
    #[test]
    fn the_digest_only_form_changes_only_the_two_credentials() {
        let mut stored = plaintext_entry();
        stored["io.example.unknown"] = serde_json::json!({"kept": true});
        let upgraded = client_entry_without_plaintext(&stored).expect("a plaintext entry");
        let mut expected = stored.as_object().unwrap().clone();
        expected.remove("secret");
        expected.remove("access_token");
        expected.insert(
            "secret_digest".into(),
            tokens::digest("the-client-secret").into(),
        );
        expected.insert(
            "access_token_digest".into(),
            tokens::digest("the-registration-token").into(),
        );
        assert_eq!(upgraded, serde_json::Value::Object(expected));
        let read: ClientEntry = serde_json::from_value(upgraded.clone()).unwrap();
        assert!(read.secret_matches("the-client-secret"));
        assert!(read.access_token_matches("the-registration-token"));
        assert_eq!(
            client_entry_without_plaintext(&upgraded),
            None,
            "idempotent"
        );

        let mut tokenless = plaintext_entry();
        tokenless["access_token"] = serde_json::Value::Null;
        let upgraded = client_entry_without_plaintext(&tokenless).unwrap();
        assert_eq!(upgraded["access_token_digest"], serde_json::Value::Null);
        assert!(upgraded.get("access_token").is_none());
    }

    #[test]
    fn a_client_entry_with_a_credential_in_both_forms_is_refused() {
        let mut both = plaintext_entry();
        both["secret_digest"] = tokens::digest("other").into();
        assert!(serde_json::from_value::<ClientEntry>(both).is_err());
        let mut both = plaintext_entry();
        both["access_token_digest"] = tokens::digest("other").into();
        assert!(serde_json::from_value::<ClientEntry>(both).is_err());
        let mut none = plaintext_entry();
        none.as_object_mut().unwrap().remove("secret");
        assert!(serde_json::from_value::<ClientEntry>(none).is_err());
    }
}

#[cfg(test)]
mod session_entry_tests {
    use super::*;

    /// A session as the previous build serialized it: the scope and the OIDC
    /// nonce beside the bound request.
    fn previous_build_session() -> serde_json::Value {
        serde_json::json!({
            "siwe_nonce": "siwe-nonce",
            "oidc_nonce": "oidc-nonce",
            "secret": "s",
            "signin_count": 0,
            "verified_did": null,
            "scope": "openid urn:matrix:client:device:ABC",
            "request": {
                "client_id": "client",
                "redirect_uri": "https://rp.example.org/cb",
                "state": "state",
                "response_mode": null,
                "code_challenge": "challenge",
            },
        })
    }

    /// It deserializes with the scope and the nonce moved into the request,
    /// and is written back as one request with nothing beside it.
    #[test]
    fn a_previous_build_session_reads_its_scope_and_nonce_into_the_request() {
        let session: SessionEntry = serde_json::from_value(previous_build_session()).unwrap();
        let request = session.request.clone().expect("the bound request");
        assert_eq!(
            request.scope.as_deref(),
            Some("openid urn:matrix:client:device:ABC")
        );
        assert_eq!(
            request
                .nonce
                .as_ref()
                .map(Nonce::secret)
                .map(String::as_str),
            Some("oidc-nonce")
        );
        assert_eq!(request.client_id, "client");
        assert_eq!(request.code_challenge, "challenge");

        let written = serde_json::to_value(&session).unwrap();
        assert!(written.get("scope").is_none(), "{written}");
        assert!(written.get("oidc_nonce").is_none(), "{written}");
        assert_eq!(
            written["request"]["scope"],
            "openid urn:matrix:client:device:ABC"
        );
        assert_eq!(written["request"]["nonce"], "oidc-nonce");
        let again: SessionEntry = serde_json::from_value(written).unwrap();
        assert_eq!(again.request, Some(request));
    }

    /// A previous-build session without a nonce or scope has none in its
    /// request, and one that predates the bound request still has none (sign_in
    /// refuses it with "restart sign-in").
    #[test]
    fn absent_legacy_members_stay_absent() {
        let mut stored = previous_build_session();
        stored["oidc_nonce"] = serde_json::Value::Null;
        stored.as_object_mut().unwrap().remove("scope");
        let session: SessionEntry = serde_json::from_value(stored.clone()).unwrap();
        let request = session.request.unwrap();
        assert!(request.scope.is_none() && request.nonce.is_none());
        stored.as_object_mut().unwrap().remove("request");
        let session: SessionEntry = serde_json::from_value(stored).unwrap();
        assert!(session.request.is_none());
    }
}
