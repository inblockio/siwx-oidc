//! The grant record (I2), digest-keyed access tokens (I1), the one rotation
//! script (I3), state-based lost-response recovery (I4) and reuse detection,
//! phase A (I5). Design: `docs/design/2026-10-02-token-lifecycle-rework.md`
//! sections 5.1 to 5.4.
//!
//! # Keyspace
//!
//! | Key | Type | Content | TTL |
//! |---|---|---|---|
//! | `grant/{digest(handle)}` | hash | the grant (fields below) | `inactivity_secs`, refreshed by every rotation, never past `absolute_exp` |
//! | `at/{digest(access token)}` | hash | `grant`, `generation`, `kind` (`access`), `iat`, `exp` | the token's lifetime, never past the grant's `absolute_exp` |
//! | `idx:grants:user/{username}` | set | grant ids of the user | the longest grant TTL written into it |
//! | `idx:grants:user_device/{username}/{device_id}` | set | grant ids of the device | as above |
//! | `legacy_rt/{digest(legacy refresh token)}` | string | the grant id a legacy refresh token was lifted into | `inactivity_secs` at the lift |
//!
//! A grant id is `digest(handle)` (see [`super::tokens`]). No key or value
//! written here contains a token: refresh tokens appear only as digests in
//! `current_rt` / `previous_rt`, and the one value that must be handed back
//! later, the successor pair, is sealed under a key only the presenter of the
//! previous token can derive ([`super::seal`]).
//!
//! # Legacy refresh tokens (design 5.8)
//!
//! A refresh token written before the grant record (`token/{raw}`, see
//! [`super::legacy_token_kind`]) is lifted into a grant the first time it is
//! presented at either refresh endpoint ([`RedisClient::lift_legacy_refresh_token`]).
//! One script deletes the legacy entry (and its member of the legacy device
//! index), creates a grant whose `previous_rt` is the legacy token's digest and
//! whose `current_rt` is the new refresh token, at generation 1 with the new
//! pair sealed under the legacy token and unused, writes the new access entry,
//! the grant indices and the pointer `legacy_rt/{digest(legacy token)}`. Every
//! later presentation of the legacy token, concurrent or replayed, finds the
//! pointer and goes through the rotation script like the grant's own previous
//! token: the same pair while it is unused, reuse after. The kind of a lifted
//! grant follows the legacy scope ([`legacy_grant_kind`]); its `auth_time` is
//! the legacy entry's `iat` (never later than Redis `TIME`), the earliest time
//! the store still knows: the legacy chain's last rotation, not the sign-in,
//! which no legacy build recorded. A configured cap therefore counts from that
//! rotation (provisional: the lift time would be later still, and the iat is
//! stricter). Legacy
//! grace pointers (`token_rotated/{raw}`, 60 s) are not read: they lived one
//! minute, and a lost response in the minute before the upgrade is the only case
//! they would cover.
//!
//! # Grant fields
//!
//! | Field | Meaning |
//! |---|---|
//! | `kind` | [`GrantKind`] |
//! | `username`, `did`, `client_id` | owner and client; revocation keys on `username` |
//! | `confidential` | `1` when the client authenticates with a secret, else `0` |
//! | `device_id` | the Matrix device, empty when none (JSON `null` on the wire) |
//! | `scope`, `name` | as granted; `name` is echoed by introspection |
//! | `auth_time` | the original authentication, Redis `TIME` (the sign-in or the device approval) |
//! | `absolute_exp` | `auth_time` + the cap, when one applied ([`GrantLifetime`]); only ever moves earlier |
//! | `access_ttl` | lifetime of each access token of this grant |
//! | `inactivity_secs`, `last_used` | the grant ends `inactivity_secs` after `last_used` |
//! | `generation` | 0 at issue, + 1 per rotation |
//! | `current_rt`, `previous_rt` | digests of the live refresh token and its predecessor; empty when none |
//! | `successor_used` | `0` from a rotation until the new pair is first used, else `1` |
//! | `successor_sealed` | the current pair, sealed under `previous_rt`'s plaintext, while unused |
//!
//! Phase 3 M2 adds the epochs, Phase 4 `sid`.
//!
//! # The rotation decision ([`RedisClient::rotate_refresh_token`])
//!
//! One Lua script decides, with `now` from Redis `TIME`, in this order:
//!
//! | Grant state | Presented token | Outcome |
//! |---|---|---|
//! | missing | any | [`RotateOutcome::Invalid`] (`UnknownGrant`) |
//! | user or device tombstone present | any | `Invalid` (`Revoked`) |
//! | `last_used` + `inactivity_secs` passed, or the absolute expiry (the earlier of `absolute_exp` and `auth_time` + the cap now configured) | any | `Invalid` (`Expired`); the grant is deleted |
//! | the request names another client | any | [`RotateOutcome::ClientMismatch`] |
//! | confidential client, caller refuses those | any | [`RotateOutcome::ConfidentialClient`] |
//! | live | `current_rt` | [`RotateOutcome::Rotated`]: previous <- current, current <- candidate, generation + 1, `successor_used` 0, sealed candidate stored, candidate access entry written (its `exp` no later than the absolute expiry), `absolute_exp` written back when one applies, `last_used` and TTLs bumped |
//! | live | `previous_rt`, `successor_used` 0 | [`RotateOutcome::Replayed`]: the candidate is discarded, the sealed successor returned and opened by the caller |
//! | live | `previous_rt`, `successor_used` 1 | [`RotateOutcome::Reuse`] (`PreviousAfterUse`) |
//! | live | anything else carrying this handle | `Reuse` (`Superseded`) |
//!
//! Nothing in the replay-or-reuse decision reads a clock: only state does. The
//! access entry of a rotation is written inside the script, so no interleaving
//! can mint a token for a grant that a revocation is deleting.
//!
//! # When a successor counts as used ([`RedisClient::lookup_access_token`])
//!
//! When an access token whose generation equals the grant's is first accepted,
//! a second small script sets `successor_used` to 1 and drops
//! `successor_sealed`, atomically. Rotating the new refresh token supersedes
//! the old one entirely, which counts as use too. There is no timer.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bb8_redis::redis;
use tracing::{info, warn};

use super::redis::{device_tombstone_key, user_tombstone_key};
use super::seal::{self, SuccessorPair};
use super::tokens::{self, digest};
use super::{
    DBClient, RedisClient, TokenKind, TokenMetadata, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL,
    TOMBSTONE_TTL_SECS,
};

/// Prefix of the grant hashes: `grant/{grant id}`.
pub const KV_GRANT_PREFIX: &str = "grant";
/// Prefix of the access-token entries: `at/{digest(access token)}`.
pub const KV_ACCESS_TOKEN_PREFIX: &str = "at";
/// Prefix of the per-user grant index: `idx:grants:user/{username}`.
pub const KV_GRANT_USER_IDX_PREFIX: &str = "idx:grants:user";
/// Prefix of the per-device grant index:
/// `idx:grants:user_device/{username}/{device_id}`.
pub const KV_GRANT_DEVICE_IDX_PREFIX: &str = "idx:grants:user_device";

/// Prefix of the pointer from a lifted legacy refresh token to its grant:
/// `legacy_rt/{digest(legacy refresh token)}`.
pub const KV_LEGACY_RT_PREFIX: &str = "legacy_rt";

/// The message of the reuse security event. Stable: dashboards count it.
pub const REUSE_EVENT_MESSAGE: &str = "refresh token reuse detected";

/// What kind of grant this is (design section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantKind {
    /// A Matrix-mode code or device-code grant: one per Synapse device.
    MatrixDevice,
    /// A generic-mode code grant.
    Oidc,
    /// A minted admin token: no refresh token, lives as long as its token.
    Service,
}

impl GrantKind {
    /// The value stored in the grant's `kind` field.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantKind::MatrixDevice => "matrix_device",
            GrantKind::Oidc => "oidc",
            GrantKind::Service => "service",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "matrix_device" => Some(GrantKind::MatrixDevice),
            "oidc" => Some(GrantKind::Oidc),
            "service" => Some(GrantKind::Service),
            _ => None,
        }
    }
}

impl std::fmt::Display for GrantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A grant id: the digest of the grant handle. Not a credential (the handle and
/// a secret are needed to act), but logged only as [`GrantId::fingerprint`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GrantId(String);

impl GrantId {
    /// The id of the grant named by `handle`.
    pub fn of_handle(handle: &str) -> Self {
        GrantId(digest(handle))
    }

    /// The hex digest itself.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A short prefix for log lines. It equals `redact::fingerprint(handle)`,
    /// so an operator holding a refresh token finds the lines about its grant.
    pub fn fingerprint(&self) -> &str {
        &self.0[..crate::redact::FINGERPRINT_HEX_LEN.min(self.0.len())]
    }
}

impl std::fmt::Debug for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GrantId({})", self.fingerprint())
    }
}

fn grant_key(id: &GrantId) -> String {
    format!("{KV_GRANT_PREFIX}/{}", id.as_str())
}

fn at_key(access_token: &str) -> String {
    format!("{KV_ACCESS_TOKEN_PREFIX}/{}", digest(access_token))
}

fn user_idx_key(username: &str) -> String {
    format!("{KV_GRANT_USER_IDX_PREFIX}/{username}")
}

fn device_idx_key(username: &str, device_id: &str) -> String {
    format!("{KV_GRANT_DEVICE_IDX_PREFIX}/{username}/{device_id}")
}

fn legacy_rt_key(legacy_refresh_token: &str) -> String {
    format!("{KV_LEGACY_RT_PREFIX}/{}", digest(legacy_refresh_token))
}

/// The key a build before the grant record stored a token under.
fn legacy_token_key(token: &str) -> String {
    format!("{}/{token}", super::KV_TOKEN_PREFIX)
}

/// The global epoch (I9): every grant authenticated at or before it is refused.
pub const KV_EPOCH_GLOBAL: &str = "epoch:global";
/// Prefix of the per-client epochs: `epoch:client/{client_id}`.
pub const KV_EPOCH_CLIENT_PREFIX: &str = "epoch:client";
/// Prefix of the per-user epochs: `epoch:user/{username}`.
pub const KV_EPOCH_USER_PREFIX: &str = "epoch:user";

/// Whose grants an epoch refuses (I9). An epoch is a persistent not-before
/// timestamp in Unix milliseconds from Redis `TIME`: a grant whose `auth_ms`
/// is at or before the largest epoch that applies to it is refused, so a
/// grant authenticated in the epoch's own millisecond is refused too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochScope<'a> {
    /// Every grant.
    Global,
    /// The grants of one client id.
    Client(&'a str),
    /// The grants of one username (the localpart revocation keys on).
    User(&'a str),
}

impl EpochScope<'_> {
    /// The Redis key of this epoch.
    pub fn key(&self) -> String {
        match self {
            EpochScope::Global => KV_EPOCH_GLOBAL.to_string(),
            EpochScope::Client(client_id) => format!("{KV_EPOCH_CLIENT_PREFIX}/{client_id}"),
            EpochScope::User(username) => format!("{KV_EPOCH_USER_PREFIX}/{username}"),
        }
    }
}

/// The operator's absolute-lifetime caps, in seconds (I6; decision D1,
/// provisional): one global value and one per client id, both unset by
/// default, which caps nothing (a grant then ends only by inactivity). The
/// cap of a grant is its client's value when one is set, else the global
/// default: a per-client value overrides the global one, longer or shorter
/// (design 5.5: "per-client setting with a global default").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantLifetime {
    pub global_secs: Option<u64>,
    pub per_client_secs: std::sync::Arc<HashMap<String, u64>>,
}

impl GrantLifetime {
    /// The cap for a grant of `client_id`, `None` when no value applies.
    pub fn cap_for(&self, client_id: &str) -> Option<u64> {
        self.per_client_secs
            .get(client_id)
            .copied()
            .or(self.global_secs)
    }

    /// Whether any cap is configured.
    pub fn is_configured(&self) -> bool {
        self.global_secs.is_some() || !self.per_client_secs.is_empty()
    }
}

/// The absolute expiry in force for a grant: the earlier of the one written
/// into it (`stored`) and `auth_time` + `cap`; `None` when neither exists.
/// This is the recomputation the rotation script runs, so a lowered cap
/// applies at the next rotation and nothing moves the deadline later.
pub fn effective_absolute_exp(
    auth_time: i64,
    stored: Option<i64>,
    cap: Option<u64>,
) -> Option<i64> {
    let from_cap = cap.map(|c| auth_time.saturating_add(i64::try_from(c).unwrap_or(i64::MAX)));
    [stored, from_cap].into_iter().flatten().min()
}

/// An access token's `exp`: its own lifetime from `now`, never past the
/// grant's absolute expiry.
fn clamped_access_exp(now: i64, access_ttl: u64, deadline: Option<i64>) -> i64 {
    let own = now + access_ttl as i64;
    deadline.map_or(own, |d| own.min(d))
}

/// What [`RedisClient::issue_grant`] creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewGrant {
    pub kind: GrantKind,
    /// The Matrix localpart (or the generic-mode username); revocation keys on it.
    pub username: String,
    pub did: String,
    pub client_id: String,
    /// Whether the client authenticates with a secret. Recorded so a refresh
    /// endpoint that cannot authenticate a client can refuse such a grant.
    pub confidential_client: bool,
    /// The Matrix device; empty when none.
    pub device_id: String,
    pub scope: String,
    pub name: String,
    /// The original authentication (Unix milliseconds, Redis `TIME`): the
    /// grant's `auth_ms`, compared with the epochs (I9), and, in whole
    /// seconds, its `auth_time`, the base of the absolute expiry (I6). `None`:
    /// the authentication is this request, and the script takes Redis `TIME`.
    pub auth_ms: Option<i64>,
    /// Lifetime of each access token, in seconds.
    pub access_ttl: u64,
    /// `Some(inactivity)` issues a refresh token and keeps the grant for that
    /// many seconds after its last rotation; `None` issues none, and the grant
    /// lives exactly as long as its access token. A `service` grant takes `None`.
    pub refresh_inactivity_secs: Option<u64>,
}

/// The tokens [`RedisClient::issue_grant`] hands out.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedGrant {
    pub grant_id: GrantId,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Issued-at and expiry of the access token, from Redis `TIME`.
    pub iat: i64,
    pub access_exp: i64,
}

impl std::fmt::Debug for IssuedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedGrant")
            .field("grant_id", &self.grant_id)
            .field(
                "access_token_fp",
                &crate::redact::fingerprint(&self.access_token),
            )
            .field(
                "refresh_token_fp",
                &self
                    .refresh_token
                    .as_deref()
                    .map(crate::redact::fingerprint),
            )
            .field("iat", &self.iat)
            .field("access_exp", &self.access_exp)
            .finish()
    }
}

/// A grant as stored, without its token digests and sealed successor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantView {
    pub grant_id: GrantId,
    pub kind: GrantKind,
    pub username: String,
    pub did: String,
    pub client_id: String,
    pub confidential_client: bool,
    pub device_id: String,
    pub scope: String,
    pub name: String,
    pub auth_time: i64,
    /// The authentication in Unix milliseconds, compared with the epochs
    /// (I9): the written `auth_ms`, else (a grant written before epochs
    /// existed) the start of `auth_time`'s second, so such a grant whose
    /// authentication falls in an epoch's second is refused.
    pub auth_ms: i64,
    /// The absolute expiry written into the grant (Unix seconds); `None` when
    /// no cap applied when it was written (see [`GrantLifetime`]).
    pub absolute_exp: Option<i64>,
    pub access_ttl: u64,
    pub generation: u64,
}

impl GrantView {
    fn from_fields(grant_id: GrantId, f: &HashMap<String, String>) -> Option<Self> {
        let s = |k: &str| f.get(k).cloned();
        Some(GrantView {
            grant_id,
            kind: GrantKind::parse(f.get("kind")?)?,
            username: s("username")?,
            did: s("did")?,
            client_id: s("client_id")?,
            confidential_client: f.get("confidential")? == "1",
            device_id: s("device_id")?,
            scope: s("scope")?,
            name: s("name")?,
            auth_time: f.get("auth_time")?.parse().ok()?,
            auth_ms: match f.get("auth_ms") {
                Some(v) => v.parse().ok()?,
                None => f.get("auth_time")?.parse::<i64>().ok()?.checked_mul(1000)?,
            },
            absolute_exp: match f.get("absolute_exp") {
                Some(v) => Some(v.parse().ok()?),
                None => None,
            },
            access_ttl: f.get("access_ttl")?.parse().ok()?,
            generation: f.get("generation")?.parse().ok()?,
        })
    }
}

/// An accepted access token and the grant it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessGrant {
    pub grant: GrantView,
    /// The generation the token was issued in.
    pub generation: u64,
    pub iat: i64,
    pub exp: i64,
}

impl AccessGrant {
    /// The token's claims in the shape introspection and `/userinfo` read.
    pub fn metadata(&self) -> TokenMetadata {
        TokenMetadata {
            username: self.grant.username.clone(),
            device_id: self.grant.device_id.clone(),
            scope: self.grant.scope.clone(),
            client_id: self.grant.client_id.clone(),
            iat: self.iat,
            exp: self.exp,
            did: self.grant.did.clone(),
            name: self.grant.name.clone(),
            kind: Some(TokenKind::Access),
        }
    }
}

/// A refresh request for [`RedisClient::rotate_refresh_token`].
#[derive(Clone, Copy)]
pub struct RotateRequest<'a> {
    /// The refresh token the client presented.
    pub presented: &'a str,
    /// The client the request names or authenticated as; `None` skips the check.
    pub client_id: Option<&'a str>,
    /// Refuse a grant whose client is confidential: for an endpoint that cannot
    /// authenticate a client (`POST /_matrix/client/v3/refresh`).
    pub refuse_confidential: bool,
}

/// A new or replayed pair, with the grant it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotatedPair {
    pub grant_id: GrantId,
    /// The grant's generation after the rotation the pair came from.
    pub generation: u64,
    pub pair: SuccessorPair,
}

/// Why a refresh token was refused as unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    /// Not a refresh token in the current format: garbage, another kind of
    /// token, or a legacy refresh token (which the migration handles).
    NotCurrentFormat,
    /// No grant carries this handle.
    UnknownGrant,
    /// A device or user tombstone refuses the grant.
    Revoked,
    /// The grant's inactivity or absolute expiry has passed; it was deleted
    /// (by the lift: the legacy token is past the cap, and stays as it is).
    Expired,
    /// A replay of the previous token found no sealed successor to return.
    NoSuccessor,
}

/// Which superseded token a reuse event saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReuseBranch {
    /// The immediately previous token, after its successor was used.
    PreviousAfterUse,
    /// An older token of the chain, or a secret this grant never issued.
    Superseded,
}

impl ReuseBranch {
    pub fn as_str(self) -> &'static str {
        match self {
            ReuseBranch::PreviousAfterUse => "previous_after_use",
            ReuseBranch::Superseded => "superseded",
        }
    }
}

/// The security event of a reuse (I5, phase A): answered like an unknown
/// token, logged once by [`ReuseEvent::emit`], nothing revoked. Every field is
/// safe to log; the grant appears only as its fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReuseEvent {
    pub grant_fp: String,
    pub generation: u64,
    pub client_id: String,
    pub grant_kind: GrantKind,
    pub branch: ReuseBranch,
}

impl ReuseEvent {
    /// Log the event: one `warn!` with the message [`REUSE_EVENT_MESSAGE`] and
    /// the fields `security_event = "refresh_token_reuse"`, `grant_fp`,
    /// `generation`, `client_id`, `grant_kind`, `branch`.
    pub fn emit(&self) {
        warn!(
            security_event = "refresh_token_reuse",
            grant_fp = %self.grant_fp,
            generation = self.generation,
            client_id = %self.client_id,
            grant_kind = %self.grant_kind,
            branch = self.branch.as_str(),
            "{}",
            REUSE_EVENT_MESSAGE
        );
    }
}

/// The outcome of [`RedisClient::rotate_refresh_token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The presented token was current: here is the new pair.
    Rotated(RotatedPair),
    /// The presented token was the previous one and its successor is unused:
    /// here is that same successor (lost response, or a concurrent loser).
    Replayed(RotatedPair),
    /// A superseded token of a live grant. Answer like an unknown token and
    /// [`emit`](ReuseEvent::emit) the event.
    Reuse(ReuseEvent),
    /// Answer like an unknown token.
    Invalid(InvalidReason),
    /// The request names another client than the grant's.
    ClientMismatch,
    /// The grant's client is confidential and the caller refuses those.
    ConfidentialClient,
}

/// A legacy refresh token (`token/{raw}`, written before the grant record)
/// that has not been lifted into a grant yet.
#[derive(Clone, Debug)]
pub struct LegacyRefresh {
    /// The entry exactly as read; the lift acts only on an unchanged entry.
    stored: String,
    pub meta: TokenMetadata,
}

/// What a presented refresh token names, before any decision about it
/// ([`RedisClient::peek_refresh_token`]).
#[derive(Clone, Debug)]
pub enum RefreshPeek {
    /// A grant: the token's handle names it, or the token is a legacy refresh
    /// token already lifted into it.
    Grant(GrantView),
    /// A legacy refresh token not lifted yet:
    /// [`RedisClient::lift_legacy_refresh_token`] lifts it.
    Legacy(LegacyRefresh),
    /// Nothing: answer like an unknown token.
    Unknown,
}

/// The kind of the grant a legacy refresh token is lifted into: `matrix_device`
/// when its scope carries the Matrix client API (every Matrix-mode writer put it
/// there, with or without a device), else `oidc`.
pub fn legacy_grant_kind(meta: &TokenMetadata) -> GrantKind {
    let matrix = meta.scope.split(' ').any(|s| {
        s == "urn:matrix:client:api:*" || s == "urn:matrix:org.matrix.msc2967.client:api:*"
    });
    if matrix {
        GrantKind::MatrixDevice
    } else {
        GrantKind::Oidc
    }
}

/// Extend a key's TTL to at least `secs`, never shorten it. An index holds
/// grants of different lifetimes and must outlive the longest.
const LUA_EXTEND: &str = r#"
local function extend(key, secs)
  if redis.call('TTL', key) < secs then
    redis.call('EXPIRE', key, secs)
  end
end
"#;

/// Redis `TIME` in milliseconds and the epochs (I9). `epoch_refuses` says
/// whether an epoch that applies to a grant of `username` and `client_id` is
/// at or after its authentication `auth_ms` (`auth_ms_of` falls back to the
/// start of `auth_time`'s second for a grant written before epochs existed);
/// `set_epoch` moves an epoch to
/// now, never earlier. The key names are [`EpochScope::key`]'s, pinned by
/// `the_scripts_name_the_epoch_keys_the_library_writes`.
const LUA_EPOCH: &str = r#"
local function now_ms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local function auth_ms_of(auth_ms, auth_time)
  if auth_ms then return tonumber(auth_ms) end
  return tonumber(auth_time) * 1000
end
local function epoch_refuses(auth_ms, username, client_id)
  local epochs = redis.call('MGET', 'epoch:global', 'epoch:client/' .. client_id,
    'epoch:user/' .. username)
  for i = 1, 3 do
    if epochs[i] and tonumber(epochs[i]) >= auth_ms then
      return true
    end
  end
  return false
end
local function set_epoch(key)
  local ms = now_ms()
  local current = tonumber(redis.call('GET', key) or '0')
  if ms > current then
    redis.call('SET', key, string.format('%.0f', ms))
    current = ms
  end
  return current
end
"#;

/// Set one epoch to Redis `TIME`, never earlier than it was. Needs
/// [`LUA_EPOCH`]. KEYS: 1 the epoch. Returns the epoch in force.
const SET_EPOCH_LUA: &str = r#"
return string.format('%.0f', set_epoch(KEYS[1]))
"#;

/// Add grant `id` to the index `key`, pruning members whose grant (under
/// `prefix`) is gone, and extend the index to `ttl`. Needs [`LUA_EXTEND`].
const LUA_INDEX: &str = r#"
local function index(key, id, prefix, ttl)
  for _, member in ipairs(redis.call('SMEMBERS', key)) do
    if redis.call('EXISTS', prefix .. member) == 0 then
      redis.call('SREM', key, member)
    end
  end
  redis.call('SADD', key, id)
  extend(key, ttl)
end
"#;

/// Create a grant, its first access entry and its index entries.
///
/// KEYS: 1 grant, 2 access entry, 3 user index, 4 device index.
/// ARGV: 1 grant id, 2 grant key prefix (`grant/`), 3 has device (`1`/`0`),
/// 4 kind, 5 username, 6 did, 7 client_id, 8 confidential, 9 device_id,
/// 10 scope, 11 name, 12 auth_ms (`` = now), 13 access_ttl, 14 inactivity
/// (`0`: no refresh token, the grant lives as long as its access token),
/// 15 current_rt, 16 the absolute-lifetime cap (`` = none).
/// `auth_time` is `auth_ms` in whole seconds.
/// With a cap, `absolute_exp` = `auth_time` + cap is written, the access token
/// and the keys expire no later than it, and an authentication already older
/// than the cap is an error. Returns `{iat, exp}` of the access token. Index
/// members whose grant is gone are pruned, so an index holds live grants only.
const ISSUE_LUA: &str = r#"
local clock = redis.call('TIME')
local now = tonumber(clock[1])
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.error_reply('grant id collision')
end
local access_ttl = tonumber(ARGV[13])
local grant_ttl = tonumber(ARGV[14])
if grant_ttl == 0 then grant_ttl = access_ttl end
local inactivity = grant_ttl
local auth_ms = now * 1000 + math.floor(tonumber(clock[2]) / 1000)
if ARGV[12] ~= '' then auth_ms = tonumber(ARGV[12]) end
local auth_time = math.floor(auth_ms / 1000)
local access_exp = now + access_ttl
local access_life = access_ttl
local absolute_exp = nil
if ARGV[16] ~= '' then
  absolute_exp = auth_time + tonumber(ARGV[16])
  if now >= absolute_exp then
    return redis.error_reply('authentication older than the absolute lifetime')
  end
  access_exp = math.min(access_exp, absolute_exp)
  access_life = math.min(access_life, absolute_exp - now)
  grant_ttl = math.min(grant_ttl, absolute_exp - now)
end
redis.call('HSET', KEYS[1], 'kind', ARGV[4], 'username', ARGV[5], 'did', ARGV[6],
  'client_id', ARGV[7], 'confidential', ARGV[8], 'device_id', ARGV[9], 'scope', ARGV[10],
  'name', ARGV[11], 'auth_time', tostring(auth_time),
  'auth_ms', string.format('%.0f', auth_ms), 'access_ttl', ARGV[13],
  'inactivity_secs', tostring(inactivity), 'last_used', tostring(now), 'generation', '0',
  'current_rt', ARGV[15], 'previous_rt', '', 'successor_used', '1')
if absolute_exp then
  redis.call('HSET', KEYS[1], 'absolute_exp', tostring(absolute_exp))
end
redis.call('EXPIRE', KEYS[1], grant_ttl)
redis.call('HSET', KEYS[2], 'grant', ARGV[1], 'generation', '0', 'kind', 'access',
  'iat', tostring(now), 'exp', tostring(access_exp))
redis.call('EXPIRE', KEYS[2], access_life)
index(KEYS[3], ARGV[1], ARGV[2], grant_ttl)
if ARGV[3] == '1' then index(KEYS[4], ARGV[1], ARGV[2], grant_ttl) end
return {tostring(now), tostring(access_exp)}
"#;

/// Lift a legacy refresh token into a new grant (design 5.8; module docs).
///
/// KEYS: 1 legacy entry (`token/{raw}`), 2 pointer (`legacy_rt/…`), 3 grant,
/// 4 new access entry, 5 user tombstone, 6 device tombstone, 7 user index,
/// 8 device index, 9 legacy device index (`idx:user_device/…`).
/// ARGV: 1 legacy entry as read, 2 grant id, 3 grant key prefix, 4 has device,
/// 5 kind, 6 username, 7 did, 8 client_id, 9 confidential, 10 device_id,
/// 11 scope, 12 name, 13 auth_time, 14 access_ttl, 15 inactivity, 16 digest of
/// the legacy token, 17 digest of the new refresh token, 18 the new pair sealed
/// under the legacy token, 19 the new access token's `exp`, 20 requesting
/// client_id (`` = unchecked), 21 the legacy entry's `exp`, 22 the
/// absolute-lifetime cap (`` = none). The grant's `auth_time` is the legacy
/// entry's `iat`, never later than now; an epoch at or after it refuses the
/// lift (`revoked`, the legacy entry left as it is); with a cap it is refused as expired
/// once `auth_time` + cap has passed, else `absolute_exp` is written and the
/// access token and keys expire no later than it.
/// Replies `{'lifted', grant id}` when the pointer already exists (the caller
/// then runs the rotation script on that grant), else `{'lifted_now'}` or a
/// refusal shaped like the rotation script's.
const LIFT_LUA: &str = r#"
local lifted = redis.call('GET', KEYS[2])
if lifted then
  return {'lifted', lifted}
end
local entry = redis.call('GET', KEYS[1])
if not entry or entry ~= ARGV[1] then
  return {'invalid', 'unknown_grant'}
end
if redis.call('EXISTS', KEYS[5]) == 1 or (ARGV[4] == '1' and redis.call('EXISTS', KEYS[6]) == 1) then
  return {'invalid', 'revoked'}
end
local now = tonumber(redis.call('TIME')[1])
if now >= tonumber(ARGV[21]) then
  return {'invalid', 'expired'}
end
local auth_time = math.min(tonumber(ARGV[13]), now)
if epoch_refuses(auth_time * 1000, ARGV[6], ARGV[8]) then
  return {'invalid', 'revoked'}
end
local absolute_exp = nil
if ARGV[22] ~= '' then
  absolute_exp = auth_time + tonumber(ARGV[22])
  if now >= absolute_exp then
    return {'invalid', 'expired'}
  end
end
if ARGV[20] ~= '' and ARGV[20] ~= ARGV[8] then
  return {'client_mismatch'}
end
if redis.call('EXISTS', KEYS[3]) == 1 then
  return redis.error_reply('grant id collision')
end
local access_ttl = tonumber(ARGV[14])
local inactivity = tonumber(ARGV[15])
local access_exp = tonumber(ARGV[19])
local access_life = access_ttl
local grant_ttl = inactivity
if absolute_exp then
  access_exp = math.min(access_exp, absolute_exp)
  access_life = math.min(access_life, absolute_exp - now)
  grant_ttl = math.min(grant_ttl, absolute_exp - now)
end
redis.call('DEL', KEYS[1])
if ARGV[4] == '1' then redis.call('SREM', KEYS[9], KEYS[1]) end
redis.call('HSET', KEYS[3], 'kind', ARGV[5], 'username', ARGV[6], 'did', ARGV[7],
  'client_id', ARGV[8], 'confidential', ARGV[9], 'device_id', ARGV[10], 'scope', ARGV[11],
  'name', ARGV[12], 'auth_time', tostring(auth_time),
  'auth_ms', string.format('%.0f', auth_time * 1000), 'access_ttl', ARGV[14],
  'inactivity_secs', ARGV[15], 'last_used', tostring(now), 'generation', '1',
  'current_rt', ARGV[17], 'previous_rt', ARGV[16], 'successor_used', '0',
  'successor_sealed', ARGV[18])
if absolute_exp then
  redis.call('HSET', KEYS[3], 'absolute_exp', tostring(absolute_exp))
end
redis.call('EXPIRE', KEYS[3], grant_ttl)
redis.call('HSET', KEYS[4], 'grant', ARGV[2], 'generation', '1', 'kind', 'access',
  'iat', tostring(now), 'exp', tostring(access_exp))
redis.call('EXPIRE', KEYS[4], access_life)
redis.call('SET', KEYS[2], ARGV[2], 'EX', inactivity)
index(KEYS[7], ARGV[2], ARGV[3], grant_ttl)
if ARGV[4] == '1' then index(KEYS[8], ARGV[2], ARGV[3], grant_ttl) end
return {'lifted_now'}
"#;

/// The one rotation script (design 5.3; the decision table is in the module docs).
///
/// KEYS: 1 grant, 2 candidate access entry, 3 user tombstone, 4 device
/// tombstone, 5 user index, 6 device index.
/// ARGV: 1 digest of the presented token, 2 digest of the candidate refresh
/// token, 3 sealed candidate, 4 username, 5 device_id (both as the caller read
/// them to name the tombstones), 6 requesting client_id (`` = unchecked),
/// 7 refuse a confidential client (`1`/`0`), 8 grant id, 9 has device,
/// 10 the candidate access token's `exp`, 11 the absolute-lifetime cap now
/// configured for the grant's client (`` = none). A tombstone refuses the grant
/// (`revoked`; the user tombstone is only read, for one release, see
/// [`RedisClient::revoke_grants_for_user`]); an epoch at or after its `auth_ms`
/// refuses and deletes it (`revoked`, I9). The absolute expiry in force
/// is the earlier of the written `absolute_exp` and `auth_time` + cap
/// ([`effective_absolute_exp`]); past it the grant is deleted like an
/// inactive one, and a rotation writes it back, so a lowered cap applies at
/// the next rotation and nothing moves it later. An empty candidate digest (ARGV 2)
/// means the caller has no handle to mint a candidate with (a lifted legacy
/// token, which is never `current_rt`): the rotate branch is then never taken.
const ROTATE_LUA: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'username', 'device_id', 'client_id', 'confidential',
  'current_rt', 'previous_rt', 'successor_used', 'successor_sealed', 'generation',
  'last_used', 'inactivity_secs', 'access_ttl', 'auth_time', 'absolute_exp', 'auth_ms')
if not f[1] or f[1] ~= ARGV[4] or f[2] ~= ARGV[5] then
  return {'invalid', 'unknown_grant'}
end
if redis.call('EXISTS', KEYS[3]) == 1 or (ARGV[9] == '1' and redis.call('EXISTS', KEYS[4]) == 1) then
  return {'invalid', 'revoked'}
end
if epoch_refuses(auth_ms_of(f[15], f[13]), f[1], f[3]) then
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[5], ARGV[8])
  if ARGV[9] == '1' then redis.call('SREM', KEYS[6], ARGV[8]) end
  return {'invalid', 'revoked'}
end
local now = tonumber(redis.call('TIME')[1])
local inactivity = tonumber(f[11])
local absolute_exp = nil
if f[14] then absolute_exp = tonumber(f[14]) end
if ARGV[11] ~= '' then
  local capped = tonumber(f[13]) + tonumber(ARGV[11])
  if not absolute_exp or capped < absolute_exp then absolute_exp = capped end
end
if now - tonumber(f[10]) > inactivity or (absolute_exp and now >= absolute_exp) then
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[5], ARGV[8])
  if ARGV[9] == '1' then redis.call('SREM', KEYS[6], ARGV[8]) end
  return {'invalid', 'expired'}
end
if ARGV[6] ~= '' and ARGV[6] ~= f[3] then
  return {'client_mismatch'}
end
if ARGV[7] == '1' and f[4] == '1' then
  return {'confidential_client'}
end
local generation = tonumber(f[9])
if ARGV[2] ~= '' and f[5] ~= '' and ARGV[1] == f[5] then
  local next_gen = tostring(generation + 1)
  local access_life = tonumber(f[12])
  local access_exp = tonumber(ARGV[10])
  local grant_ttl = inactivity
  if absolute_exp then
    access_exp = math.min(access_exp, absolute_exp)
    access_life = math.min(access_life, absolute_exp - now)
    grant_ttl = math.min(grant_ttl, absolute_exp - now)
    redis.call('HSET', KEYS[1], 'absolute_exp', tostring(absolute_exp))
  end
  redis.call('HSET', KEYS[1], 'previous_rt', f[5], 'current_rt', ARGV[2],
    'generation', next_gen, 'successor_used', '0', 'successor_sealed', ARGV[3],
    'last_used', tostring(now))
  redis.call('EXPIRE', KEYS[1], grant_ttl)
  redis.call('HSET', KEYS[2], 'grant', ARGV[8], 'generation', next_gen, 'kind', 'access',
    'iat', tostring(now), 'exp', tostring(access_exp))
  redis.call('EXPIRE', KEYS[2], access_life)
  extend(KEYS[5], grant_ttl)
  if ARGV[9] == '1' then extend(KEYS[6], grant_ttl) end
  return {'rotated', next_gen}
end
if f[6] ~= '' and ARGV[1] == f[6] then
  if f[7] == '0' then
    if not f[8] or f[8] == '' then
      return {'invalid', 'no_successor'}
    end
    return {'replayed', tostring(generation), f[8]}
  end
  return {'reuse', 'previous_after_use', tostring(generation)}
end
return {'reuse', 'superseded', tostring(generation)}
"#;

/// Accept an access token's grant, marking the successor used (design 5.4),
/// unless an epoch refuses the grant (I9) or it is past its absolute expiry (I6).
///
/// KEYS: 1 grant. ARGV: 1 the access token's generation, 2 `1` when a cap is
/// configured, so a grant written without `absolute_exp` must first be judged
/// by the caller against `auth_time` + its client's cap.
/// Returns nil when the grant is gone, `{'revoked'}` when an epoch at or after
/// its `auth_ms` refuses it (nothing written), `{'expired'}` past the written
/// `absolute_exp`, `{'check', now, fields…}` for the caller to judge (nothing
/// written), else `{'ok', now, fields…}` after the update. `now` is Redis `TIME`.
const MARK_USED_LUA: &str = r#"
local now = redis.call('TIME')[1]
local f = redis.call('HMGET', KEYS[1], 'generation', 'successor_used', 'absolute_exp',
  'username', 'client_id', 'auth_ms', 'auth_time')
if not f[1] then
  return false
end
if epoch_refuses(auth_ms_of(f[6], f[7]), f[4], f[5]) then
  return {'revoked'}
end
local status = 'ok'
if f[3] then
  if tonumber(now) >= tonumber(f[3]) then
    return {'expired'}
  end
elseif ARGV[2] == '1' then
  status = 'check'
end
if status == 'ok' and f[1] == ARGV[1] and f[2] == '0' then
  redis.call('HSET', KEYS[1], 'successor_used', '1')
  redis.call('HDEL', KEYS[1], 'successor_sealed')
end
local reply = {status, now}
for _, v in ipairs(redis.call('HGETALL', KEYS[1])) do
  reply[#reply + 1] = v
end
return reply
"#;

/// Delete every grant of one device and plant the device tombstone.
///
/// KEYS: 1 device index, 2 device tombstone, 3 user index.
/// ARGV: 1 tombstone TTL, 2 grant key prefix.
const REVOKE_DEVICE_LUA: &str = r#"
local n = 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  n = n + redis.call('DEL', ARGV[2] .. id)
  redis.call('SREM', KEYS[3], id)
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[1]))
return n
"#;

/// Set the user epoch and delete every grant of the user, with their device
/// indices. Needs [`LUA_EPOCH`].
///
/// KEYS: 1 user index, 2 user epoch.
/// ARGV: 1 grant key prefix, 2 this user's device index prefix
/// (`idx:grants:user_device/{username}/`).
const REVOKE_USER_LUA: &str = r#"
set_epoch(KEYS[2])
local n = 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local device = redis.call('HGET', ARGV[1] .. id, 'device_id')
  if device and device ~= '' then
    redis.call('DEL', ARGV[2] .. device)
  end
  n = n + redis.call('DEL', ARGV[1] .. id)
end
redis.call('DEL', KEYS[1])
return n
"#;

/// Delete one grant if the presented token is one the endpoints would accept.
///
/// KEYS: 1 grant, 2 user index, 3 device index.
/// ARGV: 1 grant id, 2 digest of a presented refresh token (`` for an access
/// token, whose entry the caller already resolved), 3 has device.
const REVOKE_ONE_LUA: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'username', 'current_rt', 'previous_rt', 'successor_used')
if not f[1] then
  return 0
end
if ARGV[2] ~= '' then
  local current = f[2] ~= '' and ARGV[2] == f[2]
  local previous = f[3] ~= '' and ARGV[2] == f[3] and f[4] == '0'
  if not (current or previous) then
    return 0
  end
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
if ARGV[3] == '1' then redis.call('SREM', KEYS[3], ARGV[1]) end
return 1
"#;

/// A cap as a script argument: `` for none.
fn cap_arg(cap: Option<u64>) -> String {
    cap.map(|c| c.to_string()).unwrap_or_default()
}

fn flag(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn number<T: std::str::FromStr>(value: Option<&str>, what: &str) -> Result<T> {
    value
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow!("grant store: malformed {what}"))
}

impl RedisClient {
    /// This client with the operator's absolute-lifetime caps (I6). Clones
    /// share one connection pool, so tests can look at one store through
    /// different caps, as instances do after a configuration change.
    pub fn with_grant_lifetime(mut self, lifetime: GrantLifetime) -> Self {
        self.lifetime = lifetime;
        self
    }

    async fn eval<T: redis::FromRedisValue>(
        &self,
        script: &str,
        keys: &[&str],
        args: &[&str],
    ) -> Result<T> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(script).arg(keys.len());
        for key in keys {
            cmd.arg(*key);
        }
        for arg in args {
            cmd.arg(*arg);
        }
        cmd.query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store script: {e}"))
    }

    /// The grant `id` as stored, `None` when it is gone.
    async fn grant_view(&self, id: &GrantId) -> Result<Option<GrantView>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let fields: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(grant_key(id))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store HGETALL: {e}"))?;
        view_or_none(id.clone(), &fields)
    }

    /// Redis `TIME` (seconds) and the grant `id`, in one round trip.
    async fn time_and_grant(&self, id: &GrantId) -> Result<(i64, Option<GrantView>)> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let ((secs, _micros), fields): ((String, String), HashMap<String, String>) = redis::pipe()
            .cmd("TIME")
            .cmd("HGETALL")
            .arg(grant_key(id))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store TIME/HGETALL: {e}"))?;
        Ok((
            number(Some(&secs), "TIME")?,
            view_or_none(id.clone(), &fields)?,
        ))
    }

    /// Create a grant, its first access token, its refresh token when asked
    /// for, and its index entries, in one atomic step.
    pub async fn issue_grant(&self, new: &NewGrant) -> Result<IssuedGrant> {
        if new.kind == GrantKind::Service && new.refresh_inactivity_secs.is_some() {
            return Err(anyhow!("a service grant never carries a refresh token"));
        }
        if new.access_ttl == 0 || new.refresh_inactivity_secs == Some(0) {
            return Err(anyhow!("a grant needs non-zero lifetimes"));
        }
        let handle = tokens::new_grant_handle();
        let grant_id = GrantId::of_handle(&handle);
        let access_token = match new.kind {
            GrantKind::Service => tokens::new_admin_token(),
            GrantKind::MatrixDevice | GrantKind::Oidc => tokens::new_access_token(),
        };
        let refresh_token = new
            .refresh_inactivity_secs
            .map(|_| tokens::new_refresh_token(&handle));
        let current_rt = refresh_token.as_deref().map(digest).unwrap_or_default();
        let has_device = !new.device_id.is_empty();
        let script = format!("{LUA_EXTEND}{LUA_INDEX}{ISSUE_LUA}");
        let reply: Vec<String> = self
            .eval(
                &script,
                &[
                    &grant_key(&grant_id),
                    &at_key(&access_token),
                    &user_idx_key(&new.username),
                    &device_idx_key(&new.username, &new.device_id),
                ],
                &[
                    grant_id.as_str(),
                    &format!("{KV_GRANT_PREFIX}/"),
                    flag(has_device),
                    new.kind.as_str(),
                    &new.username,
                    &new.did,
                    &new.client_id,
                    flag(new.confidential_client),
                    &new.device_id,
                    &new.scope,
                    &new.name,
                    &new.auth_ms.map(|t| t.to_string()).unwrap_or_default(),
                    &new.access_ttl.to_string(),
                    &new.refresh_inactivity_secs.unwrap_or(0).to_string(),
                    &current_rt,
                    &cap_arg(self.lifetime.cap_for(&new.client_id)),
                ],
            )
            .await?;
        let field = |i: usize| reply.get(i).map(String::as_str);
        Ok(IssuedGrant {
            grant_id,
            access_token,
            refresh_token,
            iat: number(field(0), "issue reply")?,
            access_exp: number(field(1), "issue reply")?,
        })
    }

    /// The grant an access token belongs to, or `None` when the token is
    /// unknown, expired, or its grant is gone. The first acceptance of a token
    /// of the grant's current generation marks the successor used.
    pub async fn lookup_access_token(&self, token: &str) -> Result<Option<AccessGrant>> {
        let entry: HashMap<String, String> = {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| anyhow!("Redis pool: {e}"))?;
            redis::cmd("HGETALL")
                .arg(at_key(token))
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("grant store HGETALL: {e}"))?
        };
        if entry.is_empty() {
            return Ok(None);
        }
        if entry.get("kind").map(String::as_str) != Some("access") {
            return Ok(None);
        }
        let get = |k: &str| entry.get(k).map(String::as_str);
        let grant_id = GrantId(
            get("grant")
                .ok_or_else(|| anyhow!("grant store: access entry without a grant"))?
                .to_string(),
        );
        let generation: u64 = number(get("generation"), "access entry")?;
        let iat = number(get("iat"), "access entry")?;
        let exp: i64 = number(get("exp"), "access entry")?;
        let mut judge = self.lifetime.is_configured();
        let mark_used = format!("{LUA_EPOCH}{MARK_USED_LUA}");
        let grant = loop {
            let reply: Option<Vec<String>> = self
                .eval(
                    &mark_used,
                    &[&grant_key(&grant_id)],
                    &[&generation.to_string(), flag(judge)],
                )
                .await?;
            let Some(reply) = reply else {
                return Ok(None);
            };
            let (status, now) = match reply.as_slice() {
                [status, now, ..] => (status.as_str(), number::<i64>(Some(now), "TIME")?),
                [status] if status == "expired" || status == "revoked" => return Ok(None),
                _ => return Err(anyhow!("grant store: unexpected access-check reply")),
            };
            let fields: HashMap<String, String> = reply[2..]
                .chunks_exact(2)
                .map(|kv| (kv[0].clone(), kv[1].clone()))
                .collect();
            let Some(view) = view_or_none(grant_id.clone(), &fields)? else {
                return Ok(None);
            };
            if self.access_deadline(&view).is_some_and(|d| now >= d) {
                return Ok(None);
            }
            match status {
                // A grant written without `absolute_exp` is inside its
                // client's cap: now count it as used.
                "check" => judge = false,
                "ok" => break view,
                _ => return Err(anyhow!("grant store: unexpected access-check status")),
            }
        };
        let exp = self.access_deadline(&grant).map_or(exp, |d| exp.min(d));
        Ok(Some(AccessGrant {
            grant,
            generation,
            iat,
            exp,
        }))
    }

    /// The absolute expiry the access check enforces: the one written into the
    /// grant, else (a grant written while no cap applied) `auth_time` + the cap
    /// now configured for its client. A lowered cap reaches a grant that has
    /// one written at its next rotation; its access tokens live at most
    /// [`ACCESS_TOKEN_TTL`] beyond.
    fn access_deadline(&self, view: &GrantView) -> Option<i64> {
        view.absolute_exp.or_else(|| {
            effective_absolute_exp(view.auth_time, None, self.lifetime.cap_for(&view.client_id))
        })
    }

    /// The grant a refresh token's handle names, without judging the token:
    /// a superseded or forged secret with a live handle finds the grant too.
    /// Only for deciding which client to authenticate before
    /// [`rotate_refresh_token`](Self::rotate_refresh_token), never for
    /// accepting the token.
    pub async fn peek_refresh_grant(&self, token: &str) -> Result<Option<GrantView>> {
        Ok(match self.peek_refresh_token(token).await? {
            RefreshPeek::Grant(view) => Some(view),
            RefreshPeek::Legacy(_) | RefreshPeek::Unknown => None,
        })
    }

    /// What a presented refresh token names, without judging it (like
    /// [`peek_refresh_grant`](Self::peek_refresh_grant)): the grant its handle
    /// names, the grant a legacy token was lifted into, a legacy refresh token
    /// not lifted yet, or nothing. A legacy entry of another kind (an access
    /// token) is nothing. The legacy entry and the pointer are read in one
    /// `MGET`, so a lift between two reads cannot hide both.
    pub async fn peek_refresh_token(&self, token: &str) -> Result<RefreshPeek> {
        if let Some(parsed) = tokens::parse_refresh_token(token) {
            return Ok(
                match self.grant_view(&GrantId::of_handle(parsed.handle)).await? {
                    Some(view) => RefreshPeek::Grant(view),
                    None => RefreshPeek::Unknown,
                },
            );
        }
        let (stored, lifted): (Option<String>, Option<String>) = {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| anyhow!("Redis pool: {e}"))?;
            redis::cmd("MGET")
                .arg(legacy_token_key(token))
                .arg(legacy_rt_key(token))
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("grant store MGET: {e}"))?
        };
        if let Some(id) = lifted {
            return Ok(match self.grant_view(&GrantId(id)).await? {
                Some(view) => RefreshPeek::Grant(view),
                None => RefreshPeek::Unknown,
            });
        }
        let Some(stored) = stored else {
            return Ok(RefreshPeek::Unknown);
        };
        let meta: TokenMetadata = serde_json::from_str(&stored)
            .map_err(|e| anyhow!("grant store: malformed legacy token entry: {e}"))?;
        Ok(if meta.is_kind(TokenKind::Refresh) {
            RefreshPeek::Legacy(LegacyRefresh { stored, meta })
        } else {
            RefreshPeek::Unknown
        })
    }

    /// The grant a refresh token belongs to and, for a token in the current
    /// format, its handle: the handle names the grant, and a legacy token
    /// already lifted names it through its `legacy_rt/…` pointer (no handle).
    async fn refresh_grant_id<'t>(
        &self,
        token: &'t str,
    ) -> Result<Option<(GrantId, Option<&'t str>)>> {
        if let Some(parsed) = tokens::parse_refresh_token(token) {
            return Ok(Some((
                GrantId::of_handle(parsed.handle),
                Some(parsed.handle),
            )));
        }
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let lifted: Option<String> = redis::cmd("GET")
            .arg(legacy_rt_key(token))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store GET: {e}"))?;
        Ok(lifted.map(|id| (GrantId(id), None)))
    }

    /// Set the epoch of `scope` to Redis `TIME`, never moving it earlier
    /// (I9): from this one write on, the rotation script and the access check
    /// refuse every grant of that scope authenticated at or before it. Returns
    /// the epoch in force, in Unix milliseconds. Behind `logout/all`,
    /// deactivation and erasure (the user epoch) and the operator subcommand
    /// `siwx-oidc epoch` (global and client epochs).
    pub async fn set_epoch(&self, scope: EpochScope<'_>) -> Result<i64> {
        let script = format!("{LUA_EPOCH}{SET_EPOCH_LUA}");
        let epoch: String = self.eval(&script, &[&scope.key()], &[]).await?;
        number(Some(&epoch), "epoch")
    }

    /// Redis `TIME`, in milliseconds.
    pub(super) async fn redis_time_ms(&self) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (secs, micros): (String, String) = redis::cmd("TIME")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store TIME: {e}"))?;
        let secs: i64 = number(Some(&secs), "TIME")?;
        let micros: i64 = number(Some(&micros), "TIME")?;
        Ok(secs * 1000 + micros / 1000)
    }

    /// Redis `TIME`, in seconds.
    pub(super) async fn redis_time(&self) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (secs, _micros): (String, String) = redis::cmd("TIME")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store TIME: {e}"))?;
        number(Some(&secs), "TIME")
    }

    /// Lift a legacy refresh token into a new grant and answer it with a pair
    /// in the current format (design 5.8; the module docs say what is written).
    ///
    /// `legacy` is what [`peek_refresh_token`](Self::peek_refresh_token) read;
    /// `confidential_client` is the caller's verdict on the legacy entry's
    /// client (`oidc::client_is_confidential`, as at every issuance). A caller
    /// that refuses confidential clients gets
    /// [`RotateOutcome::ConfidentialClient`] for one and the entry stays as it
    /// is, for `POST /token`. When another presentation lifted the token first,
    /// the rotation script decides on that grant exactly as for its previous
    /// token: the same pair while it is unused, reuse after.
    pub async fn lift_legacy_refresh_token(
        &self,
        req: &RotateRequest<'_>,
        legacy: &LegacyRefresh,
        confidential_client: bool,
    ) -> Result<RotateOutcome> {
        if req.refuse_confidential && confidential_client {
            return Ok(RotateOutcome::ConfidentialClient);
        }
        let meta = &legacy.meta;
        let kind = legacy_grant_kind(meta);
        let handle = tokens::new_grant_handle();
        let grant_id = GrantId::of_handle(&handle);
        let now = self.redis_time().await?;
        let cap = self.lifetime.cap_for(&meta.client_id);
        let candidate = SuccessorPair {
            access_token: tokens::new_access_token(),
            refresh_token: tokens::new_refresh_token(&handle),
            access_exp: clamped_access_exp(
                now,
                ACCESS_TOKEN_TTL,
                effective_absolute_exp(meta.iat.min(now), None, cap),
            ),
        };
        let sealed = seal::seal(req.presented, grant_id.as_str(), &candidate)?;
        let has_device = !meta.device_id.is_empty();
        let script = format!("{LUA_EXTEND}{LUA_INDEX}{LUA_EPOCH}{LIFT_LUA}");
        let reply: Vec<String> = self
            .eval(
                &script,
                &[
                    &legacy_token_key(req.presented),
                    &legacy_rt_key(req.presented),
                    &grant_key(&grant_id),
                    &at_key(&candidate.access_token),
                    &user_tombstone_key(&meta.username),
                    &device_tombstone_key(&meta.username, &meta.device_id),
                    &user_idx_key(&meta.username),
                    &device_idx_key(&meta.username, &meta.device_id),
                    &super::redis::device_token_idx_key(&meta.username, &meta.device_id),
                ],
                &[
                    &legacy.stored,
                    grant_id.as_str(),
                    &format!("{KV_GRANT_PREFIX}/"),
                    flag(has_device),
                    kind.as_str(),
                    &meta.username,
                    &meta.did,
                    &meta.client_id,
                    flag(confidential_client),
                    &meta.device_id,
                    &meta.scope,
                    &meta.name,
                    &meta.iat.to_string(),
                    &ACCESS_TOKEN_TTL.to_string(),
                    &REFRESH_TOKEN_TTL.to_string(),
                    &digest(req.presented),
                    &digest(&candidate.refresh_token),
                    &sealed,
                    &candidate.access_exp.to_string(),
                    req.client_id.unwrap_or(""),
                    &meta.exp.to_string(),
                    &cap_arg(cap),
                ],
            )
            .await?;
        let field = |i: usize| reply.get(i).map(String::as_str);
        Ok(match field(0) {
            Some("lifted_now") => {
                info!(
                    grant_fp = %grant_id.fingerprint(),
                    legacy_fp = %crate::redact::fingerprint(req.presented),
                    grant_kind = %kind,
                    client_id = %meta.client_id,
                    "legacy refresh token lifted into a grant"
                );
                RotateOutcome::Rotated(RotatedPair {
                    grant_id,
                    generation: 1,
                    pair: candidate,
                })
            }
            Some("lifted") => self.rotate_refresh_token(req).await?,
            Some("invalid") => RotateOutcome::Invalid(match field(1) {
                Some("unknown_grant") => InvalidReason::UnknownGrant,
                Some("revoked") => InvalidReason::Revoked,
                Some("expired") => InvalidReason::Expired,
                _ => return Err(anyhow!("lift script: unknown invalid reason")),
            }),
            Some("client_mismatch") => RotateOutcome::ClientMismatch,
            _ => return Err(anyhow!("lift script: unexpected reply")),
        })
    }

    /// Rotate a refresh token through the one rotation script.
    ///
    /// The caller's part: parse the handle, read the grant's owner (to name the
    /// tombstones) and Redis `TIME` in one round trip, mint a candidate pair,
    /// seal it under the presented token, run the script, and on a replay open
    /// the sealed successor with the presented token.
    ///
    /// A legacy refresh token already lifted into a grant reaches that grant
    /// through its pointer and is judged like the grant's previous token; the
    /// caller has no handle for it, so no candidate is minted and the script
    /// cannot rotate it (it is never `current_rt`). A token that is neither
    /// in the current format nor lifted is
    /// [`InvalidReason::NotCurrentFormat`]: a legacy refresh token not lifted
    /// yet ([`lift_legacy_refresh_token`](Self::lift_legacy_refresh_token)),
    /// another kind of token, or garbage.
    pub async fn rotate_refresh_token(&self, req: &RotateRequest<'_>) -> Result<RotateOutcome> {
        let Some((grant_id, handle)) = self.refresh_grant_id(req.presented).await? else {
            return Ok(RotateOutcome::Invalid(InvalidReason::NotCurrentFormat));
        };
        let (now, view) = self.time_and_grant(&grant_id).await?;
        let Some(view) = view else {
            return Ok(RotateOutcome::Invalid(InvalidReason::UnknownGrant));
        };
        let cap = self.lifetime.cap_for(&view.client_id);
        let candidate = SuccessorPair {
            access_token: tokens::new_access_token(),
            refresh_token: handle.map(tokens::new_refresh_token).unwrap_or_default(),
            access_exp: clamped_access_exp(
                now,
                view.access_ttl,
                effective_absolute_exp(view.auth_time, view.absolute_exp, cap),
            ),
        };
        let (candidate_digest, sealed) = match handle {
            Some(_) => (
                digest(&candidate.refresh_token),
                seal::seal(req.presented, grant_id.as_str(), &candidate)?,
            ),
            None => (String::new(), String::new()),
        };
        let has_device = !view.device_id.is_empty();
        let script = format!("{LUA_EXTEND}{LUA_EPOCH}{ROTATE_LUA}");
        let reply: Vec<String> = self
            .eval(
                &script,
                &[
                    &grant_key(&grant_id),
                    &at_key(&candidate.access_token),
                    &user_tombstone_key(&view.username),
                    &device_tombstone_key(&view.username, &view.device_id),
                    &user_idx_key(&view.username),
                    &device_idx_key(&view.username, &view.device_id),
                ],
                &[
                    &digest(req.presented),
                    &candidate_digest,
                    &sealed,
                    &view.username,
                    &view.device_id,
                    req.client_id.unwrap_or(""),
                    flag(req.refuse_confidential),
                    grant_id.as_str(),
                    flag(has_device),
                    &candidate.access_exp.to_string(),
                    &cap_arg(cap),
                ],
            )
            .await?;
        let field = |i: usize| reply.get(i).map(String::as_str);
        Ok(match field(0) {
            Some("rotated") if handle.is_none() => {
                return Err(anyhow!("rotation script rotated a token without a handle"))
            }
            Some("rotated") => RotateOutcome::Rotated(RotatedPair {
                grant_id,
                generation: number(field(1), "rotation reply")?,
                pair: candidate,
            }),
            Some("replayed") => {
                let generation = number(field(1), "rotation reply")?;
                match field(2).and_then(|s| seal::open(req.presented, grant_id.as_str(), s)) {
                    Some(pair) => RotateOutcome::Replayed(RotatedPair {
                        grant_id,
                        generation,
                        pair,
                    }),
                    None => RotateOutcome::Invalid(InvalidReason::NoSuccessor),
                }
            }
            Some("reuse") => RotateOutcome::Reuse(ReuseEvent {
                grant_fp: grant_id.fingerprint().to_string(),
                generation: number(field(2), "rotation reply")?,
                client_id: view.client_id,
                grant_kind: view.kind,
                branch: match field(1) {
                    Some("previous_after_use") => ReuseBranch::PreviousAfterUse,
                    Some("superseded") => ReuseBranch::Superseded,
                    _ => return Err(anyhow!("rotation script: unknown reuse branch")),
                },
            }),
            Some("invalid") => RotateOutcome::Invalid(match field(1) {
                Some("unknown_grant") => InvalidReason::UnknownGrant,
                Some("revoked") => InvalidReason::Revoked,
                Some("expired") => InvalidReason::Expired,
                Some("no_successor") => InvalidReason::NoSuccessor,
                _ => return Err(anyhow!("rotation script: unknown invalid reason")),
            }),
            Some("client_mismatch") => RotateOutcome::ClientMismatch,
            Some("confidential_client") => RotateOutcome::ConfidentialClient,
            _ => return Err(anyhow!("rotation script: unexpected reply")),
        })
    }

    /// Delete every grant of `(username, device_id)` and plant the device
    /// tombstone, in one atomic step. Returns the number of grants deleted.
    pub async fn revoke_grants_for_device(&self, username: &str, device_id: &str) -> Result<usize> {
        self.eval(
            REVOKE_DEVICE_LUA,
            &[
                &device_idx_key(username, device_id),
                &device_tombstone_key(username, device_id),
                &user_idx_key(username),
            ],
            &[
                &TOMBSTONE_TTL_SECS.to_string(),
                &format!("{KV_GRANT_PREFIX}/"),
            ],
        )
        .await
    }

    /// Set the user epoch (I9) and delete every grant of `username`, in one
    /// atomic step. Returns the number of grants deleted. The epoch alone
    /// refuses every grant of the user authenticated until now, wherever it is
    /// (the deletion keeps the store small and is no longer what revokes), and
    /// unlike the user tombstone it replaced it refuses nothing newer: a
    /// sign-in right after it refreshes at once.
    ///
    /// No build writes the user tombstone any more. TODO(remove one release
    /// after Phase 3): the rotation and lift scripts still READ
    /// `tombstone:user/{username}`, so one a previous build planted refuses for
    /// the rest of its 900 s.
    pub async fn revoke_grants_for_user(&self, username: &str) -> Result<usize> {
        let script = format!("{LUA_EPOCH}{REVOKE_USER_LUA}");
        self.eval(
            &script,
            &[&user_idx_key(username), &EpochScope::User(username).key()],
            &[
                &format!("{KV_GRANT_PREFIX}/"),
                &format!("{KV_GRANT_DEVICE_IDX_PREFIX}/{username}/"),
            ],
        )
        .await
    }

    /// Delete the grant of a token the endpoints would accept: a live access
    /// token, the current refresh token, or the previous one while its
    /// successor is unused. Any other token deletes nothing (`None`). Plants no
    /// tombstone. Returns the deleted grant.
    pub async fn revoke_grant_of_token(&self, token: &str) -> Result<Option<GrantView>> {
        let (grant_id, presented) = match tokens::parse_refresh_token(token) {
            Some(parsed) => (GrantId::of_handle(parsed.handle), digest(token)),
            None => {
                let owner: Option<String> = {
                    let mut conn = self
                        .pool
                        .get()
                        .await
                        .map_err(|e| anyhow!("Redis pool: {e}"))?;
                    redis::cmd("HGET")
                        .arg(at_key(token))
                        .arg("grant")
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| anyhow!("grant store HGET: {e}"))?
                };
                match owner {
                    Some(id) => (GrantId(id), String::new()),
                    // A legacy refresh token lifted into a grant: judged like
                    // the grant's previous token.
                    None => match self.refresh_grant_id(token).await? {
                        Some((id, _)) => (id, digest(token)),
                        None => return Ok(None),
                    },
                }
            }
        };
        let Some(view) = self.grant_view(&grant_id).await? else {
            return Ok(None);
        };
        let deleted: i64 = self
            .eval(
                REVOKE_ONE_LUA,
                &[
                    &grant_key(&grant_id),
                    &user_idx_key(&view.username),
                    &device_idx_key(&view.username, &view.device_id),
                ],
                &[
                    grant_id.as_str(),
                    &presented,
                    flag(!view.device_id.is_empty()),
                ],
            )
            .await?;
        Ok((deleted == 1).then_some(view))
    }

    /// Delete one access token's entry, leaving its grant. Returns whether one existed.
    pub async fn delete_access_token(&self, token: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = redis::cmd("DEL")
            .arg(at_key(token))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store DEL: {e}"))?;
        Ok(n > 0)
    }
}

impl RedisClient {
    /// The access check of every bearer endpoint (introspection, `/userinfo`,
    /// the bearer-authenticated Matrix routes): the claims of a live access
    /// token, or `None`. A grant's access token is looked up first
    /// ([`lookup_access_token`](Self::lookup_access_token), which marks the
    /// successor of a rotation used), then a legacy `token/{raw}` access entry.
    /// An `Err` means the store could not answer, never "inactive".
    ///
    /// TODO(remove one release after Phase 2a): the legacy read. Builds before
    /// the grant record wrote access tokens as `token/{raw}` with a lifetime of
    /// at most 900 s, so one release later none is left.
    pub async fn check_access_token(&self, token: &str) -> Result<Option<TokenMetadata>> {
        if let Some(access) = self.lookup_access_token(token).await? {
            return Ok(Some(access.metadata()));
        }
        let Some(meta) = self
            .get_token(token)
            .await?
            .filter(|m| m.is_kind(TokenKind::Access))
        else {
            return Ok(None);
        };
        // An epoch refuses a legacy access token issued at or before it, its
        // `iat` counted from the start of its second like a grant's `auth_time`.
        if meta.iat.saturating_mul(1000) <= self.epoch_for(&meta.username, &meta.client_id).await? {
            return Ok(None);
        }
        Ok(Some(meta))
    }

    /// The largest epoch that applies to a grant of `username` at `client_id`
    /// (Unix milliseconds; 0 when none is set), for the checks made outside
    /// the scripts (I9).
    async fn epoch_for(&self, username: &str, client_id: &str) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let epochs: Vec<Option<String>> = redis::cmd("MGET")
            .arg(EpochScope::Global.key())
            .arg(EpochScope::Client(client_id).key())
            .arg(EpochScope::User(username).key())
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("grant store MGET: {e}"))?;
        epochs.iter().flatten().try_fold(0, |max, epoch| {
            number::<i64>(Some(epoch), "epoch").map(|e| max.max(e))
        })
    }

    /// The grant of a refresh token the refresh endpoints would accept now:
    /// the current one, or the previous one while its successor is unused.
    /// Reads only; a superseded token, one whose grant is gone, or one an epoch
    /// refuses (I9) is `None`. A
    /// legacy token lifted into a grant counts as that grant's previous token.
    /// For teardown, which must not act on a token the endpoints refuse.
    pub async fn resolve_refresh_token(&self, token: &str) -> Result<Option<GrantView>> {
        let Some((grant_id, _)) = self.refresh_grant_id(token).await? else {
            return Ok(None);
        };
        let fields: HashMap<String, String> = {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| anyhow!("Redis pool: {e}"))?;
            redis::cmd("HGETALL")
                .arg(grant_key(&grant_id))
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("grant store HGETALL: {e}"))?
        };
        let presented = digest(token);
        let field = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
        let is_current = !field("current_rt").is_empty() && field("current_rt") == presented;
        let is_unused_previous = !field("previous_rt").is_empty()
            && field("previous_rt") == presented
            && field("successor_used") == "0";
        if !(is_current || is_unused_previous) {
            return Ok(None);
        }
        let Some(view) = view_or_none(grant_id, &fields)? else {
            return Ok(None);
        };
        if view.auth_ms <= self.epoch_for(&view.username, &view.client_id).await? {
            return Ok(None);
        }
        Ok(Some(view))
    }
}

/// A [`GrantView`] from a grant's fields; `None` for no fields (the grant is
/// gone), an error for fields that do not form a grant.
fn view_or_none(id: GrantId, fields: &HashMap<String, String>) -> Result<Option<GrantView>> {
    if fields.is_empty() {
        return Ok(None);
    }
    GrantView::from_fields(id, fields)
        .map(Some)
        .ok_or_else(|| anyhow!("grant store: malformed grant"))
}

#[cfg(test)]
mod tests;
