//! The grant record (I2), digest-keyed access tokens (I1), the one rotation
//! script (I3), state-based lost-response recovery (I4) and reuse detection,
//! phase A (I5). Design: `docs/design/2026-10-02-token-lifecycle-rework.md`
//! sections 5.1 to 5.4.
//!
//! # Keyspace
//!
//! | Key | Type | Content | TTL |
//! |---|---|---|---|
//! | `grant/{digest(handle)}` | hash | the grant (fields below) | `inactivity_secs`, refreshed by every rotation |
//! | `at/{digest(access token)}` | hash | `grant`, `generation`, `kind` (`access`), `iat`, `exp` | the token's lifetime |
//! | `idx:grants:user/{username}` | set | grant ids of the user | the longest grant TTL written into it |
//! | `idx:grants:user_device/{username}/{device_id}` | set | grant ids of the device | as above |
//!
//! A grant id is `digest(handle)` (see [`super::tokens`]). No key or value
//! written here contains a token: refresh tokens appear only as digests in
//! `current_rt` / `previous_rt`, and the one value that must be handed back
//! later, the successor pair, is sealed under a key only the presenter of the
//! previous token can derive ([`super::seal`]).
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
//! | `auth_time` | the original authentication (the base of Phase 3's absolute expiry) |
//! | `access_ttl` | lifetime of each access token of this grant |
//! | `inactivity_secs`, `last_used` | the grant ends `inactivity_secs` after `last_used` |
//! | `generation` | 0 at issue, + 1 per rotation |
//! | `current_rt`, `previous_rt` | digests of the live refresh token and its predecessor; empty when none |
//! | `successor_used` | `0` from a rotation until the new pair is first used, else `1` |
//! | `successor_sealed` | the current pair, sealed under `previous_rt`'s plaintext, while unused |
//!
//! Phase 3 adds `absolute_exp` and the epochs, Phase 4 `sid`.
//!
//! # The rotation decision ([`RedisClient::rotate_refresh_token`])
//!
//! One Lua script decides, with `now` from Redis `TIME`, in this order:
//!
//! | Grant state | Presented token | Outcome |
//! |---|---|---|
//! | missing | any | [`RotateOutcome::Invalid`] (`UnknownGrant`) |
//! | user or device tombstone present | any | `Invalid` (`Revoked`) |
//! | `last_used` + `inactivity_secs` passed | any | `Invalid` (`Expired`); the grant is deleted |
//! | the request names another client | any | [`RotateOutcome::ClientMismatch`] |
//! | confidential client, caller refuses those | any | [`RotateOutcome::ConfidentialClient`] |
//! | live | `current_rt` | [`RotateOutcome::Rotated`]: previous <- current, current <- candidate, generation + 1, `successor_used` 0, sealed candidate stored, candidate access entry written, `last_used` and TTLs bumped |
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
use tracing::warn;

use super::redis::{device_tombstone_key, user_tombstone_key};
use super::seal::{self, SuccessorPair};
use super::tokens::{self, digest};
use super::{RedisClient, TokenKind, TokenMetadata, TOMBSTONE_TTL_SECS};

/// Prefix of the grant hashes: `grant/{grant id}`.
pub const KV_GRANT_PREFIX: &str = "grant";
/// Prefix of the access-token entries: `at/{digest(access token)}`.
pub const KV_ACCESS_TOKEN_PREFIX: &str = "at";
/// Prefix of the per-user grant index: `idx:grants:user/{username}`.
pub const KV_GRANT_USER_IDX_PREFIX: &str = "idx:grants:user";
/// Prefix of the per-device grant index:
/// `idx:grants:user_device/{username}/{device_id}`.
pub const KV_GRANT_DEVICE_IDX_PREFIX: &str = "idx:grants:user_device";

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
    /// The original authentication (Unix seconds).
    pub auth_time: i64,
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
    /// The grant's inactivity expiry has passed; it was deleted.
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

/// Extend a key's TTL to at least `secs`, never shorten it. An index holds
/// grants of different lifetimes and must outlive the longest.
const LUA_EXTEND: &str = r#"
local function extend(key, secs)
  if redis.call('TTL', key) < secs then
    redis.call('EXPIRE', key, secs)
  end
end
"#;

/// Create a grant, its first access entry and its index entries.
///
/// KEYS: 1 grant, 2 access entry, 3 user index, 4 device index.
/// ARGV: 1 grant id, 2 grant key prefix (`grant/`), 3 has device (`1`/`0`),
/// 4 kind, 5 username, 6 did, 7 client_id, 8 confidential, 9 device_id,
/// 10 scope, 11 name, 12 auth_time, 13 access_ttl, 14 inactivity (`0`: no
/// refresh token, the grant lives as long as its access token), 15 current_rt.
/// Returns `{iat, exp}` of the access token. Index members whose grant is gone
/// are pruned, so an index holds live grants only.
const ISSUE_LUA: &str = r#"
local now = tonumber(redis.call('TIME')[1])
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.error_reply('grant id collision')
end
local access_ttl = tonumber(ARGV[13])
local grant_ttl = tonumber(ARGV[14])
if grant_ttl == 0 then grant_ttl = access_ttl end
redis.call('HSET', KEYS[1], 'kind', ARGV[4], 'username', ARGV[5], 'did', ARGV[6],
  'client_id', ARGV[7], 'confidential', ARGV[8], 'device_id', ARGV[9], 'scope', ARGV[10],
  'name', ARGV[11], 'auth_time', ARGV[12], 'access_ttl', ARGV[13],
  'inactivity_secs', tostring(grant_ttl), 'last_used', tostring(now), 'generation', '0',
  'current_rt', ARGV[15], 'previous_rt', '', 'successor_used', '1')
redis.call('EXPIRE', KEYS[1], grant_ttl)
redis.call('HSET', KEYS[2], 'grant', ARGV[1], 'generation', '0', 'kind', 'access',
  'iat', tostring(now), 'exp', tostring(now + access_ttl))
redis.call('EXPIRE', KEYS[2], access_ttl)
local function index(key)
  for _, id in ipairs(redis.call('SMEMBERS', key)) do
    if redis.call('EXISTS', ARGV[2] .. id) == 0 then
      redis.call('SREM', key, id)
    end
  end
  redis.call('SADD', key, ARGV[1])
  extend(key, grant_ttl)
end
index(KEYS[3])
if ARGV[3] == '1' then index(KEYS[4]) end
return {tostring(now), tostring(now + access_ttl)}
"#;

/// The one rotation script (design 5.3; the decision table is in the module docs).
///
/// KEYS: 1 grant, 2 candidate access entry, 3 user tombstone, 4 device
/// tombstone, 5 user index, 6 device index.
/// ARGV: 1 digest of the presented token, 2 digest of the candidate refresh
/// token, 3 sealed candidate, 4 username, 5 device_id (both as the caller read
/// them to name the tombstones), 6 requesting client_id (`` = unchecked),
/// 7 refuse a confidential client (`1`/`0`), 8 grant id, 9 has device,
/// 10 the candidate access token's `exp`.
const ROTATE_LUA: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'username', 'device_id', 'client_id', 'confidential',
  'current_rt', 'previous_rt', 'successor_used', 'successor_sealed', 'generation',
  'last_used', 'inactivity_secs', 'access_ttl')
if not f[1] or f[1] ~= ARGV[4] or f[2] ~= ARGV[5] then
  return {'invalid', 'unknown_grant'}
end
if redis.call('EXISTS', KEYS[3]) == 1 or (ARGV[9] == '1' and redis.call('EXISTS', KEYS[4]) == 1) then
  return {'invalid', 'revoked'}
end
local now = tonumber(redis.call('TIME')[1])
local inactivity = tonumber(f[11])
if now - tonumber(f[10]) > inactivity then
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
if f[5] ~= '' and ARGV[1] == f[5] then
  local next_gen = tostring(generation + 1)
  local access_ttl = tonumber(f[12])
  redis.call('HSET', KEYS[1], 'previous_rt', f[5], 'current_rt', ARGV[2],
    'generation', next_gen, 'successor_used', '0', 'successor_sealed', ARGV[3],
    'last_used', tostring(now))
  redis.call('EXPIRE', KEYS[1], inactivity)
  redis.call('HSET', KEYS[2], 'grant', ARGV[8], 'generation', next_gen, 'kind', 'access',
    'iat', tostring(now), 'exp', ARGV[10])
  redis.call('EXPIRE', KEYS[2], access_ttl)
  extend(KEYS[5], inactivity)
  if ARGV[9] == '1' then extend(KEYS[6], inactivity) end
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

/// Accept an access token's grant, marking the successor used (design 5.4).
///
/// KEYS: 1 grant. ARGV: 1 the access token's generation.
/// Returns the grant's fields after the update, or nil when the grant is gone.
const MARK_USED_LUA: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'generation', 'successor_used')
if not f[1] then
  return false
end
if f[1] == ARGV[1] and f[2] == '0' then
  redis.call('HSET', KEYS[1], 'successor_used', '1')
  redis.call('HDEL', KEYS[1], 'successor_sealed')
end
return redis.call('HGETALL', KEYS[1])
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

/// Delete every grant of one user, with their device indices, and plant the
/// user tombstone.
///
/// KEYS: 1 user index, 2 user tombstone.
/// ARGV: 1 tombstone TTL, 2 grant key prefix, 3 this user's device index
/// prefix (`idx:grants:user_device/{username}/`).
const REVOKE_USER_LUA: &str = r#"
local n = 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local device = redis.call('HGET', ARGV[2] .. id, 'device_id')
  if device and device ~= '' then
    redis.call('DEL', ARGV[3] .. device)
  end
  n = n + redis.call('DEL', ARGV[2] .. id)
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[1]))
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
        let script = format!("{LUA_EXTEND}{ISSUE_LUA}");
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
                    &new.auth_time.to_string(),
                    &new.access_ttl.to_string(),
                    &new.refresh_inactivity_secs.unwrap_or(0).to_string(),
                    &current_rt,
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
        let exp = number(get("exp"), "access entry")?;
        let fields: Option<HashMap<String, String>> = self
            .eval(
                MARK_USED_LUA,
                &[&grant_key(&grant_id)],
                &[&generation.to_string()],
            )
            .await?;
        let Some(grant) = fields
            .map(|f| view_or_none(grant_id, &f))
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        Ok(Some(AccessGrant {
            grant,
            generation,
            iat,
            exp,
        }))
    }

    /// The grant a refresh token's handle names, without judging the token:
    /// a superseded or forged secret with a live handle finds the grant too.
    /// Only for deciding which client to authenticate before
    /// [`rotate_refresh_token`](Self::rotate_refresh_token), never for
    /// accepting the token.
    pub async fn peek_refresh_grant(&self, token: &str) -> Result<Option<GrantView>> {
        match tokens::parse_refresh_token(token) {
            Some(parsed) => self.grant_view(&GrantId::of_handle(parsed.handle)).await,
            None => Ok(None),
        }
    }

    /// Rotate a refresh token through the one rotation script.
    ///
    /// The caller's part: parse the handle, read the grant's owner (to name the
    /// tombstones) and Redis `TIME` in one round trip, mint a candidate pair,
    /// seal it under the presented token, run the script, and on a replay open
    /// the sealed successor with the presented token.
    pub async fn rotate_refresh_token(&self, req: &RotateRequest<'_>) -> Result<RotateOutcome> {
        let Some(parsed) = tokens::parse_refresh_token(req.presented) else {
            return Ok(RotateOutcome::Invalid(InvalidReason::NotCurrentFormat));
        };
        let grant_id = GrantId::of_handle(parsed.handle);
        let (now, view) = self.time_and_grant(&grant_id).await?;
        let Some(view) = view else {
            return Ok(RotateOutcome::Invalid(InvalidReason::UnknownGrant));
        };
        let candidate = SuccessorPair {
            access_token: tokens::new_access_token(),
            refresh_token: tokens::new_refresh_token(parsed.handle),
            access_exp: now + view.access_ttl as i64,
        };
        let sealed = seal::seal(req.presented, grant_id.as_str(), &candidate)?;
        let has_device = !view.device_id.is_empty();
        let script = format!("{LUA_EXTEND}{ROTATE_LUA}");
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
                    &digest(&candidate.refresh_token),
                    &sealed,
                    &view.username,
                    &view.device_id,
                    req.client_id.unwrap_or(""),
                    flag(req.refuse_confidential),
                    grant_id.as_str(),
                    flag(has_device),
                    &candidate.access_exp.to_string(),
                ],
            )
            .await?;
        let field = |i: usize| reply.get(i).map(String::as_str);
        Ok(match field(0) {
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

    /// Delete every grant of `username` and plant the user tombstone, in one
    /// atomic step. Returns the number of grants deleted.
    pub async fn revoke_grants_for_user(&self, username: &str) -> Result<usize> {
        self.eval(
            REVOKE_USER_LUA,
            &[&user_idx_key(username), &user_tombstone_key(username)],
            &[
                &TOMBSTONE_TTL_SECS.to_string(),
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
                let mut conn = self
                    .pool
                    .get()
                    .await
                    .map_err(|e| anyhow!("Redis pool: {e}"))?;
                let owner: Option<String> = redis::cmd("HGET")
                    .arg(at_key(token))
                    .arg("grant")
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| anyhow!("grant store HGET: {e}"))?;
                match owner {
                    Some(id) => (GrantId(id), String::new()),
                    None => return Ok(None),
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
