//! The guest record store (work package S3b, design 01 §4.1, contract §4).
//!
//! | Key | Holds |
//! |---|---|
//! | `guest:acct/{localpart}` | HASH: `state` (`minted`), `did`, `invite_id`, `host`, `room_id`, `first_name`, `second_name`, `email` (only if given), `consent_version`, `consent_variant`, `created_at`, `deadline`. No secret, no key material. No TTL: the reaper (S5) needs the record to erase the account |
//! | (same hash, S4b) | `state` `minted`/`provisioning`/`active`; while a hand-off runs `lease_owner`, `lease_until` (Redis `TIME` + 120 s) and the write-ahead `device_id` |
//! | `guest:devices/{localpart}` | SET of device ids handed to the guest (the cap of `guest_max_devices`), no TTL |
//! | `guest:handoff/{localpart}` | ZSET of admitted hand-off attempts by `TIME`, the sliding window of `guest_handoff_per_minute` |
//! | `guest:due` | ZSET `localpart -> deadline` |
//! | `guest:by_invite/{id}` | SET of the invite's localparts |
//! | `guest:handle/{sha256(handle)}` | the localpart, TTL until the deadline |
//! | `guest:quota/daily_mint/{day}` | counter of identities minted that UTC day |
//!
//! [`RedisClient::redeem_guest`] is one script: the kill switch, the invite's state
//! and its bounded guest count, the quotas and the `NX` write of the record are
//! decided and applied in one atomic step on Redis `TIME`, so a refusal writes
//! nothing and N concurrent redeems mint exactly the invite's `max_guests`.
//! The scripts build keys from prefixes in `ARGV`, which is fine on the single
//! Redis this service runs against and would have to change for a cluster.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bb8_redis::redis::{cmd, Value};

use super::guest_invites::{
    by_host_key, guest_account_key, invite_key, reap_before_matches, GuestControl,
    BANNED_HOSTS_KEY, CONTROL_KEY,
};
use super::RedisClient;

pub const DUE_KEY: &str = "guest:due";
const BY_INVITE_PREFIX: &str = "guest:by_invite/";
const HANDLE_PREFIX: &str = "guest:handle/";
const DAILY_PREFIX: &str = "guest:quota/daily_mint/";
const REAP_LEASE_PREFIX: &str = "guest:reap:lease/";
const REAP_RETRY_PREFIX: &str = "guest:reap:retry/";
const REAP_FAIL_PREFIX: &str = "guest:reap:fail/";
/// The reaper's per-entry lease: `guest:reap:lease/{localpart}` holds the owner token, with
/// a `PX` lifetime. `NX` is what keeps two instances off one teardown.
pub fn reap_lease_key(localpart: &str) -> String {
    format!("{REAP_LEASE_PREFIX}{localpart}")
}
/// The reaper's backoff gate: `guest:reap:retry/{localpart}` exists (with a `PX` lifetime
/// of the backoff delay) after a failed teardown; the entry is not claimed meanwhile.
pub fn reap_retry_key(localpart: &str) -> String {
    format!("{REAP_RETRY_PREFIX}{localpart}")
}
/// The reaper's failure count: `guest:reap:fail/{localpart}`, one hour from the last failure.
pub fn reap_fail_key(localpart: &str) -> String {
    format!("{REAP_FAIL_PREFIX}{localpart}")
}

/// Claim due entries. `KEYS[1]` the due set. `ARGV`: 1 owner token, 2 lease ms, 3 batch,
/// 4 lease prefix, 5 retry prefix, 6 how many due entries to look at. An entry that is
/// leased or backing off is skipped (it does not starve the ones behind it). Returns the
/// claimed localparts.
const CLAIM_DUE: &str = r#"
local now = tonumber(redis.call('TIME')[1])
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, tonumber(ARGV[6]))
local out = {}
local batch = tonumber(ARGV[3])
for _, lp in ipairs(due) do
  if #out >= batch then break end
  if redis.call('EXISTS', ARGV[5] .. lp) == 0 then
    if redis.call('SET', ARGV[4] .. lp, ARGV[1], 'NX', 'PX', ARGV[2]) then
      out[#out + 1] = lp
    end
  end
end
return out
"#;

/// A failed teardown. `KEYS`: 1 lease, 2 failure count, 3 retry gate. `ARGV`: 1 owner
/// token, 2 base ms, 3 cap ms, 4 failure-count lifetime ms. Counts the failure, sets the
/// gate to `min(base * 2^(n-1), cap)` and releases the lease if it is still ours. Returns
/// `{n, delay_ms}`.
const REAP_FAILED: &str = r#"
local n = redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], ARGV[4])
local delay = tonumber(ARGV[2]) * (2 ^ (math.min(n, 30) - 1))
local cap = tonumber(ARGV[3])
if delay > cap then delay = cap end
delay = math.floor(delay)
redis.call('SET', KEYS[3], tostring(n), 'PX', delay)
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end
return {n, delay}
"#;

/// A finished teardown (erased, already gone or claimed). `KEYS`: 1 lease, 2 failure
/// count, 3 retry gate, 4 due set. `ARGV`: 1 owner token, 2 localpart. Leaves nothing of
/// the entry behind.
const REAP_DONE: &str = r#"
redis.call('ZREM', KEYS[4], ARGV[2])
redis.call('DEL', KEYS[2], KEYS[3])
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end
return 1
"#;

/// Give a lease back without counting a failure (shutdown abandoned the teardown).
const REAP_RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
"#;

/// A key that never exists: a lookup for a malformed invite id reads this, so every
/// peek and redeem does exactly one invite lookup (GP-SEC-09).
const DUMMY_INVITE_ID: &str = "-";

pub fn by_invite_key(id: &str) -> String {
    format!("{BY_INVITE_PREFIX}{id}")
}
pub fn handle_key(handle_sha256_hex: &str) -> String {
    format!("{HANDLE_PREFIX}{handle_sha256_hex}")
}

/// The state of an invite as a guest sees it (derived: expiry and the guest count are
/// compared with Redis `TIME`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteState {
    Active,
    Expired,
    Exhausted,
    Revoked,
}

impl InviteState {
    pub fn as_str(self) -> &'static str {
        match self {
            InviteState::Active => "active",
            InviteState::Expired => "expired",
            InviteState::Exhausted => "exhausted",
            InviteState::Revoked => "revoked",
        }
    }
}

/// What peek and redeem read of an invite, in one lookup. The secret hash is here
/// because the caller compares it; nothing of this goes into a response.
#[derive(Debug, Clone)]
pub struct InviteGate {
    pub secret_hash: String,
    pub state: InviteState,
    pub host: String,
    pub session_secs: u64,
    pub recording_expected: bool,
}

/// Why a redeem was refused. Nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemRefusal {
    /// The kill switch is on.
    Disabled,
    /// The invite vanished or its secret changed between the check and the script.
    InvalidLink,
    Expired,
    Exhausted,
    Revoked,
    /// A record, an erasure marker or a known account already holds this DID.
    DidInUse,
    /// A quota, by class: `global_active`, `daily_mint` or `host_live_guests`.
    Quota(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedeemOutcome {
    /// Minted. `deadline` and `now` are Redis `TIME` seconds.
    Minted {
        deadline: i64,
        now: i64,
    },
    Refused(RedeemRefusal),
}

/// One redeem, after every input check.
pub struct NewGuest<'a> {
    pub invite_id: &'a str,
    pub secret_hash: &'a str,
    pub localpart: &'a str,
    /// `mxid::legacy_localpart(did)`: its erasure marker is checked in the script too.
    pub legacy_localpart: &'a str,
    pub did: &'a str,
    pub did_sha256_hex: &'a str,
    pub first_name: &'a str,
    pub second_name: &'a str,
    pub email: Option<&'a str>,
    pub consent_version: &'a str,
    pub consent_variant: &'a str,
    /// `hex(sha256(handle))`.
    pub handle_sha256_hex: &'a str,
}

/// The quotas a redeem is counted against.
pub struct RedeemLimits {
    pub global_active: u64,
    pub daily_mint: u64,
    pub host_live_guests: u64,
}

/// Mint one guest record, or refuse. `KEYS`: 1 invite, 2 record, 3 due, 4 by_invite,
/// 5 handle, 6 control, 7 host's invite set, 8 daily-quota prefix, 9 `erased:did`,
/// 10 `erased:user/<localpart>`, 11 `erased:user/<legacy localpart>`, 12 banned hosts. `KEYS[6]`
/// is the control HASH (`disabled` field). `ARGV`: 1 secret
/// hash, 2 localpart, 3 did, 4 first, 5 second, 6 email (`""` for none), 7 consent
/// version, 8 consent variant, 9 invite id, 10 global max, 11 daily max, 12 host live
/// max, 13 record key prefix, 14 by_invite key prefix.
/// Returns `{0, reason[, quota]}` or `{1, deadline, now}`.
const REDEEM: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1])
local dis = redis.call('HGET', KEYS[6], 'disabled')
if dis and dis ~= '0' and dis ~= 'false' and dis ~= '' then return {0, 'disabled'} end
local f = redis.call('HMGET', KEYS[1], 'state', 'expires_at', 'used', 'max_guests', 'host', 'room_id', 'session_secs', 'secret_hash')
if not f[1] then return {0, 'expired'} end
if f[8] ~= ARGV[1] then return {0, 'invalid_link'} end
if f[1] == 'revoked' then return {0, 'revoked'} end
-- a banned host's invites answer as revoked
if redis.call('SISMEMBER', KEYS[12], f[5]) == 1 then return {0, 'revoked'} end
if tonumber(f[2]) <= now then return {0, 'expired'} end
-- the bounded guest count: a single-use invite (max_guests 1) burns here
if tonumber(f[3]) >= tonumber(f[4]) then return {0, 'exhausted'} end
for i = 9, 11 do
  if redis.call('EXISTS', KEYS[i]) == 1 then return {0, 'did_in_use'} end
end
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[10]) then return {0, 'quota', 'global_active'} end
local day = KEYS[8] .. math.floor(now / 86400)
if tonumber(redis.call('GET', day) or '0') >= tonumber(ARGV[11]) then return {0, 'quota', 'daily_mint'} end
local live = 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[7])) do
  for _, lp in ipairs(redis.call('SMEMBERS', ARGV[14] .. id)) do
    local s = redis.call('HGET', ARGV[13] .. lp, 'state')
    if s == 'minted' or s == 'provisioning' or s == 'active' or s == 'reaping' then live = live + 1 end
  end
end
if live >= tonumber(ARGV[12]) then return {0, 'quota', 'host_live_guests'} end
-- the record is written only if it does not exist (SET NX): the last refusal point
if redis.call('HSETNX', KEYS[2], 'state', 'minted') == 0 then return {0, 'did_in_use'} end
local session = math.max(1, tonumber(f[7]))
local deadline = now + session
redis.call('HSET', KEYS[2], 'did', ARGV[3], 'invite_id', ARGV[9], 'host', f[5], 'room_id', f[6],
  'first_name', ARGV[4], 'second_name', ARGV[5], 'consent_version', ARGV[7], 'consent_variant', ARGV[8],
  'created_at', tostring(now), 'deadline', tostring(deadline))
if ARGV[6] ~= '' then redis.call('HSET', KEYS[2], 'email', ARGV[6]) end
redis.call('HINCRBY', KEYS[1], 'used', 1)
redis.call('ZADD', KEYS[3], deadline, ARGV[2])
redis.call('SADD', KEYS[4], ARGV[2])
redis.call('SET', KEYS[5], ARGV[2], 'EX', session)
redis.call('INCR', day)
redis.call('EXPIRE', day, 172800)
return {1, deadline, now}
"#;

/// The invite hash, `TIME` and whether the invite's host is banned. `KEYS`: 1 invite,
/// 2 banned hosts. Returns `{hash, now, banned}`.
const INVITE_GATE: &str = r#"
local h = redis.call('HGETALL', KEYS[1])
local host = redis.call('HGET', KEYS[1], 'host') or ''
local banned = redis.call('SISMEMBER', KEYS[2], host)
return {h, redis.call('TIME')[1], banned}
"#;

/// The reaper's control pass (S6): make due now every live, unclaimed guest the operator's
/// switches name. `KEYS`: 1 due, 2 banned hosts. `ARGV`: 1 record prefix, 2 `reap_before`
/// (`""`: none), 3 how many future-dated members to look at. Walks `guest:due` only (every
/// live guest is in it), never the keyspace. A record without `created_at` matches
/// `reap_before`. Returns `{moved by reap_before, moved by ban}`.
const ENFORCE_CONTROL: &str = r#"
local now = tonumber(redis.call('TIME')[1])
local rb = tonumber(ARGV[2])
local by_rb, by_ban = 0, 0
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. now, '+inf', 'LIMIT', 0, tonumber(ARGV[3]))
for _, lp in ipairs(members) do
  local k = ARGV[1] .. lp
  local f = redis.call('HMGET', k, 'state', 'created_at', 'promoted_at', 'host')
  if (f[1] == 'minted' or f[1] == 'provisioning' or f[1] == 'active') and not f[3] then
    local why = nil
    if f[4] and redis.call('SISMEMBER', KEYS[2], f[4]) == 1 then
      why = 'ban'
    elseif rb and ((not tonumber(f[2])) or tonumber(f[2]) <= rb) then
      why = 'rb'
    end
    if why then
      redis.call('ZADD', KEYS[1], now, lp)
      redis.call('HSET', k, 'deadline', tostring(now))
      if why == 'ban' then by_ban = by_ban + 1 else by_rb = by_rb + 1 end
    end
  end
end
return {by_rb, by_ban}
"#;

/// The alert figures (S6). `KEYS`: 1 due. `ARGV`: 1 record prefix, 2 daily-quota prefix,
/// 3 reaping age secs, 4 refusal-counter prefix. Returns `{live, daily, stuck, oldest
/// stuck age, refusals, minute}`: `stuck` counts `reaping` records due for longer than
/// `ARGV[3]` (the 256 longest-overdue are looked at); `refusals` is the larger of the
/// current and the previous minute, `minute` the one it came from.
const ALERT_FIGURES: &str = r#"
local now = tonumber(redis.call('TIME')[1])
local live = redis.call('ZCARD', KEYS[1])
local daily = tonumber(redis.call('GET', ARGV[2] .. math.floor(now / 86400)) or '0')
local stuck, oldest = 0, 0
local late = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now - tonumber(ARGV[3]), 'WITHSCORES', 'LIMIT', 0, 256)
for i = 1, #late, 2 do
  if redis.call('HGET', ARGV[1] .. late[i], 'state') == 'reaping' then
    stuck = stuck + 1
    local age = now - tonumber(late[i + 1])
    if age > oldest then oldest = age end
  end
end
local m = math.floor(now / 60)
local cur = tonumber(redis.call('GET', ARGV[4] .. m) or '0')
local prev = tonumber(redis.call('GET', ARGV[4] .. (m - 1)) or '0')
local refusals, minute = cur, m
if prev >= cur then refusals, minute = prev, m - 1 end
return {live, daily, stuck, oldest, refusals, minute}
"#;

/// Count one refusal in the current minute's counter. `ARGV`: 1 counter prefix.
const COUNT_REFUSAL: &str = r#"
local k = ARGV[1] .. math.floor(tonumber(redis.call('TIME')[1]) / 60)
redis.call('INCR', k)
redis.call('EXPIRE', k, 180)
return 1
"#;

/// A per-minute refusal counter: `guest:refusals/{minute}`, three minutes of life.
const REFUSAL_PREFIX: &str = "guest:refusals/";

/// What the control pass moved to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ControlMoved {
    pub by_reap_before: u64,
    pub by_ban: u64,
}

/// The figures behind the alerts, from one script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AlertFigures {
    pub live: u64,
    pub daily_mints: u64,
    pub stuck_reaping: u64,
    pub oldest_stuck_secs: u64,
    pub refusals_per_min: u64,
    pub refusal_minute: u64,
}

/// Move the deadline of every unclaimed guest of the given invites to now, never
/// later. `KEYS[1]` due; `ARGV`: 1 record prefix, 2 by_invite prefix, then invite ids.
/// A `claimed` or `reaping` record is not touched. Returns how many moved.
const MOVE_DEADLINES: &str = r#"
local now = tonumber(redis.call('TIME')[1])
local moved = 0
for i = 3, #ARGV do
  for _, lp in ipairs(redis.call('SMEMBERS', ARGV[2] .. ARGV[i])) do
    local k = ARGV[1] .. lp
    local f = redis.call('HMGET', k, 'state', 'deadline', 'promoted_at')
    if (f[1] == 'minted' or f[1] == 'provisioning' or f[1] == 'active') and not f[3]
       and tonumber(f[2]) and tonumber(f[2]) > now then
      redis.call('ZADD', KEYS[1], now, lp)
      redis.call('HSET', k, 'deadline', tostring(now))
      moved = moved + 1
    end
  end
end
return moved
"#;

/// `POST /guest/end`: move one guest's deadline to now. `KEYS`: 1 record, 2 due.
/// `ARGV`: 1 localpart. `claimed` (or a host-promoted record) is refused; a record that
/// is already `reaping` or already due is left as it is (`ending`).
const END_NOW: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'state', 'deadline', 'promoted_at')
if not f[1] then return 'gone' end
if f[1] == 'claimed' or f[3] then return 'claimed' end
if f[1] == 'reaping' then return 'ending' end
local now = tonumber(redis.call('TIME')[1])
local d = tonumber(f[2])
if d and d <= now then
  redis.call('ZADD', KEYS[2], 'NX', d, ARGV[1])
  return 'ending'
end
redis.call('HSET', KEYS[1], 'deadline', tostring(now))
redis.call('ZADD', KEYS[2], now, ARGV[1])
return 'moved'
"#;

/// The CAS to `reaping`, refusing a `claimed` (or promoted) record. `KEYS`: 1 record.
const CAS_REAPING: &str = r#"
local s = redis.call('HGET', KEYS[1], 'state')
if not s then return 'gone' end
if s == 'claimed' or redis.call('HEXISTS', KEYS[1], 'promoted_at') == 1 then return 'claimed' end
if s == 'reaping' then return 'already' end
local lu = tonumber(redis.call('HGET', KEYS[1], 'lease_until'))
if lu and lu > tonumber(redis.call('TIME')[1]) then return 'busy' end
redis.call('HSET', KEYS[1], 'state', 'reaping')
return 'marked'
"#;

/// Drop a guest record and everything keyed by its localpart. `KEYS`: 1 record, 2 device
/// set, 3 hand-off window, 4 due. `ARGV`: 1 localpart, 2 by_invite prefix. Idempotent.
const DROP_RECORD: &str = r#"
local inv = redis.call('HGET', KEYS[1], 'invite_id')
if inv then redis.call('SREM', ARGV[2] .. inv, ARGV[1]) end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
redis.call('ZREM', KEYS[4], ARGV[1])
return 1
"#;

/// GP-CLM-16: the erase of a CLAIMED account frees its slot. Drops the record and what is
/// keyed by its localpart, and removes it from `guest:claimed` and `guest:claim_revoke`.
/// `KEYS`: 1 record, 2 device set, 3 hand-off window, 4 due, 5 claimed set, 6 claim_revoke
/// set. `ARGV`: 1 localpart, 2 by_invite prefix. Returns `released` (a claimed record was
/// dropped), `cleaned` (no record: only a leftover set member was removed) or `kept` (the
/// record is not `claimed`: an unclaimed guest is the reaper's, not an account erase's).
/// Idempotent, one atomic script: never half done.
const RELEASE_CLAIMED: &str = r#"
local s = redis.call('HGET', KEYS[1], 'state')
if s and s ~= 'claimed' then return 'kept' end
local inv = redis.call('HGET', KEYS[1], 'invite_id')
if inv then redis.call('SREM', ARGV[2] .. inv, ARGV[1]) end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
redis.call('ZREM', KEYS[4], ARGV[1])
redis.call('SREM', KEYS[5], ARGV[1])
redis.call('SREM', KEYS[6], ARGV[1])
if s then return 'released' end
return 'cleaned'
"#;

/// What [`RedisClient::end_guest_now`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOutcome {
    /// The deadline moved to now; the reaper finds the guest due.
    Moved,
    /// Already due or `reaping`: nothing to move (the caller answers 200 as well).
    Ending,
    /// A `claimed` account (the caller answers 409).
    Claimed,
    /// No record.
    Gone,
}

/// What [`RedisClient::cas_guest_reaping`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapCas {
    Marked,
    Already,
    Claimed,
    Gone,
    /// A hand-off holds the lease (`lease_until` after Redis `TIME`): nothing was
    /// changed. The caller retries after its backoff; the lease lapses within
    /// [`HANDOFF_LEASE_SECS`] even if the hand-off dies (#49 F3).
    Busy,
}

/// What the refresh guard needs of a guest, read in one round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRefreshRead {
    /// `None`: no record.
    pub state: Option<String>,
    pub deadline: Option<i64>,
    /// The device is in `guest:devices/{localpart}`.
    pub device_recorded: bool,
    /// Redis `TIME` at the read.
    pub now: i64,
    /// The record's mint time (`created_at`).
    pub created_at: Option<i64>,
    /// The kill switch is engaged (`guest:control` `disabled`).
    pub disabled: bool,
    /// `guest:control` `reap_before`.
    pub reap_before: Option<i64>,
}

impl GuestRefreshRead {
    /// An unclaimed guest the operator's `reap_before` makes due now.
    pub fn reap_before_due(&self) -> bool {
        reap_before_matches(self.created_at, self.reap_before)
    }
}

impl RedisClient {
    /// The deadline a guest grant is capped at: `Some` for a record that is `minted`,
    /// `provisioning`, `active` or `reaping` (a reaping record's deadline is already
    /// past, which refuses the issue), `None` for no record or a `claimed` one.
    pub async fn guest_grant_deadline(&self, localpart: &str) -> Result<Option<i64>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let f: Vec<Option<String>> = cmd("HMGET")
            .arg(guest_account_key(localpart))
            .arg("state")
            .arg("deadline")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest deadline: {e}"))?;
        match (f.first(), f.get(1)) {
            (Some(Some(state)), Some(Some(d)))
                if matches!(
                    state.as_str(),
                    "minted" | "provisioning" | "active" | "reaping"
                ) =>
            {
                Ok(Some(d.parse().map_err(|e| anyhow!("guest deadline: {e}"))?))
            }
            _ => Ok(None),
        }
    }

    /// The refresh guard's read (S5): record state and deadline, whether `device_id` is a
    /// recorded device, and Redis `TIME`. One pipeline; an error is the caller's 5xx.
    pub async fn guest_refresh_read(
        &self,
        localpart: &str,
        device_id: &str,
    ) -> Result<GuestRefreshRead> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        /// Record fields, control fields, device membership, Redis `TIME`.
        type Read = (
            Vec<Option<String>>,
            Vec<Option<String>>,
            i64,
            (String, String),
        );
        let (f, ctl, recorded, (secs, _)): Read = bb8_redis::redis::pipe()
            .cmd("HMGET")
            .arg(guest_account_key(localpart))
            .arg("state")
            .arg("deadline")
            .arg("created_at")
            .cmd("HMGET")
            .arg(CONTROL_KEY)
            .arg("disabled")
            .arg("reap_before")
            .cmd("SISMEMBER")
            .arg(devices_key(localpart))
            .arg(device_id)
            .cmd("TIME")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest refresh guard: {e}"))?;
        let control = GuestControl::parse(
            ctl.first().and_then(|v| v.as_deref()),
            ctl.get(1).and_then(|v| v.as_deref()),
        )?;
        Ok(GuestRefreshRead {
            created_at: f
                .get(2)
                .cloned()
                .flatten()
                .map(|d| d.parse())
                .transpose()
                .map_err(|e| anyhow!("guest refresh guard: {e}"))?,
            disabled: control.disabled,
            reap_before: control.reap_before,
            state: f.first().cloned().flatten(),
            deadline: f
                .get(1)
                .cloned()
                .flatten()
                .map(|d| d.parse())
                .transpose()
                .map_err(|e| anyhow!("guest refresh guard: {e}"))?,
            device_recorded: recorded == 1,
            now: secs
                .parse()
                .map_err(|e| anyhow!("guest refresh guard: {e}"))?,
        })
    }

    /// `POST /guest/end`: move this guest's deadline to now (never later).
    pub async fn end_guest_now(&self, localpart: &str) -> Result<EndOutcome> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let r: String = cmd("EVAL")
            .arg(END_NOW)
            .arg(2)
            .arg(guest_account_key(localpart))
            .arg(DUE_KEY)
            .arg(localpart)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest end: {e}"))?;
        Ok(match r.as_str() {
            "moved" => EndOutcome::Moved,
            "ending" => EndOutcome::Ending,
            "claimed" => EndOutcome::Claimed,
            _ => EndOutcome::Gone,
        })
    }

    /// The CAS of the teardown: `minted`/`provisioning`/`active` to `reaping`; a
    /// `claimed` account is refused, `reaping` is already there, no record is `Gone`, and
    /// a live hand-off lease is `Busy` (the hand-off may be provisioning the account).
    pub async fn cas_guest_reaping(&self, localpart: &str) -> Result<ReapCas> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let r: String = cmd("EVAL")
            .arg(CAS_REAPING)
            .arg(1)
            .arg(guest_account_key(localpart))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest reaping CAS: {e}"))?;
        Ok(match r.as_str() {
            "marked" => ReapCas::Marked,
            "already" => ReapCas::Already,
            "claimed" => ReapCas::Claimed,
            "busy" => ReapCas::Busy,
            _ => ReapCas::Gone,
        })
    }

    /// The DID of a guest record and whether it may be torn down, for the teardown:
    /// `(did, state, promoted)`; `None` when there is no record.
    pub async fn read_guest_for_teardown(
        &self,
        localpart: &str,
    ) -> Result<Option<(String, String, bool)>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let f: Vec<Option<String>> = cmd("HMGET")
            .arg(guest_account_key(localpart))
            .arg("did")
            .arg("state")
            .arg("promoted_at")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest teardown read: {e}"))?;
        match (f.first(), f.get(1)) {
            (Some(Some(did)), Some(Some(state))) => Ok(Some((
                did.clone(),
                state.clone(),
                f.get(2).is_some_and(Option::is_some),
            ))),
            _ => Ok(None),
        }
    }

    /// The device ids recorded for a guest (the write-ahead set).
    pub async fn guest_device_ids(&self, localpart: &str) -> Result<Vec<String>> {
        let mut ids = self.smembers_raw(&devices_key(localpart)).await?;
        ids.sort();
        Ok(ids)
    }

    /// The last step of a teardown: drop the record, its device set, its hand-off window,
    /// its `guest:due` member and its `guest:by_invite` membership. Idempotent.
    pub async fn drop_guest_record(&self, localpart: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("EVAL")
            .arg(DROP_RECORD)
            .arg(4)
            .arg(guest_account_key(localpart))
            .arg(devices_key(localpart))
            .arg(handoff_rate_key(localpart))
            .arg(DUE_KEY)
            .arg(localpart)
            .arg(BY_INVITE_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest record drop: {e}"))?;
        Ok(())
    }

    /// GP-CLM-16: the account of `localpart` was erased. If it holds a `claimed` guest
    /// record, drop the record and free its slot in `guest:claimed`; an account with no
    /// record, or an unclaimed guest, is left as it is. Returns whether a claimed record
    /// was dropped. Idempotent; a Redis error is returned for the caller to fail on.
    pub async fn release_claimed_guest(&self, localpart: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let out: String = cmd("EVAL")
            .arg(RELEASE_CLAIMED)
            .arg(6)
            .arg(guest_account_key(localpart))
            .arg(devices_key(localpart))
            .arg(handoff_rate_key(localpart))
            .arg(DUE_KEY)
            .arg(CLAIMED_KEY)
            .arg(CLAIM_REVOKE_KEY)
            .arg(localpart)
            .arg(BY_INVITE_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claimed release: {e}"))?;
        Ok(out == "released")
    }

    /// The reaper's claim: up to `batch` due guests (deadline <= Redis `TIME`) that are
    /// neither leased by another owner nor backing off, each leased to `owner` for
    /// `lease_ms`. Looks at no more than `scan` due entries.
    pub async fn claim_due_guests(
        &self,
        owner: &str,
        lease_ms: u64,
        batch: usize,
        scan: usize,
    ) -> Result<Vec<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        cmd("EVAL")
            .arg(CLAIM_DUE)
            .arg(1)
            .arg(DUE_KEY)
            .arg(owner)
            .arg(lease_ms)
            .arg(batch)
            .arg(REAP_LEASE_PREFIX)
            .arg(REAP_RETRY_PREFIX)
            .arg(scan)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest reaper claim: {e}"))
    }

    /// Record a failed teardown of a claimed guest: bump the failure count, gate the entry
    /// for `min(base_ms * 2^(n-1), cap_ms)` and release the lease. Returns `(n, delay_ms)`.
    pub async fn reap_failed(
        &self,
        localpart: &str,
        owner: &str,
        base_ms: u64,
        cap_ms: u64,
    ) -> Result<(u64, u64)> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (n, delay): (u64, u64) = cmd("EVAL")
            .arg(REAP_FAILED)
            .arg(3)
            .arg(reap_lease_key(localpart))
            .arg(reap_fail_key(localpart))
            .arg(reap_retry_key(localpart))
            .arg(owner)
            .arg(base_ms)
            .arg(cap_ms)
            .arg(3_600_000u64)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest reaper failure: {e}"))?;
        Ok((n, delay))
    }

    /// A claimed guest is done (erased, already gone or claimed): remove its schedule entry,
    /// its backoff state and its lease.
    pub async fn reap_done(&self, localpart: &str, owner: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("EVAL")
            .arg(REAP_DONE)
            .arg(4)
            .arg(reap_lease_key(localpart))
            .arg(reap_fail_key(localpart))
            .arg(reap_retry_key(localpart))
            .arg(DUE_KEY)
            .arg(owner)
            .arg(localpart)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest reaper done: {e}"))?;
        Ok(())
    }

    /// Give back a lease that is still `owner`'s (a teardown abandoned at shutdown), so the
    /// next instance resumes at once instead of after the lease lifetime.
    pub async fn reap_release(&self, localpart: &str, owner: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("EVAL")
            .arg(REAP_RELEASE)
            .arg(1)
            .arg(reap_lease_key(localpart))
            .arg(owner)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest reaper release: {e}"))?;
        Ok(())
    }
}

/// A guest as the host sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestView {
    pub first_name: String,
    pub second_name: String,
    pub email: Option<String>,
    pub state: String,
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::BulkString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Value::SimpleString(s) => Some(s.clone()),
        _ => None,
    }
}

fn parse_redeem(reply: &[Value]) -> Result<RedeemOutcome> {
    let int = |v: Option<&Value>| match v {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    };
    match int(reply.first()) {
        Some(1) => Ok(RedeemOutcome::Minted {
            deadline: int(reply.get(1)).ok_or_else(|| anyhow!("bad reply"))?,
            now: int(reply.get(2)).ok_or_else(|| anyhow!("bad reply"))?,
        }),
        Some(0) => {
            let reason = reply.get(1).and_then(text).unwrap_or_default();
            let quota = reply.get(2).and_then(text).unwrap_or_default();
            Ok(RedeemOutcome::Refused(match reason.as_str() {
                "disabled" => RedeemRefusal::Disabled,
                "invalid_link" => RedeemRefusal::InvalidLink,
                "expired" => RedeemRefusal::Expired,
                "exhausted" => RedeemRefusal::Exhausted,
                "revoked" => RedeemRefusal::Revoked,
                "did_in_use" => RedeemRefusal::DidInUse,
                "quota" => RedeemRefusal::Quota(match quota.as_str() {
                    "global_active" => "global_active",
                    "daily_mint" => "daily_mint",
                    "host_live_guests" => "host_live_guests",
                    _ => return Err(anyhow!("guest redeem: unknown quota")),
                }),
                _ => return Err(anyhow!("guest redeem: unknown refusal")),
            }))
        }
        _ => Err(anyhow!("guest redeem: bad reply")),
    }
}

// ---------------------------------------------------------------------------------
// The claim (S7a, design 05 section 4.3)
// ---------------------------------------------------------------------------------

/// `guest:claimed`: SET of the localparts of claimed accounts (the `guest_max_claimed` count).
pub const CLAIMED_KEY: &str = "guest:claimed";
/// `guest:claim_revoke`: SET of claimed localparts whose pre-claim devices are not yet revoked.
pub const CLAIM_REVOKE_KEY: &str = "guest:claim_revoke";
/// How long the handle of a claimed guest still resolves, for `resume` and a retry.
pub const CLAIMED_HANDLE_SECS: u64 = 600;
/// The single-flight lock of one guest's `claim/finish`.
pub const CLAIM_LOCK_SECS: u64 = 30;

/// `guest:claimed_handle/{sha256(handle)}`: the localpart, `CLAIMED_HANDLE_SECS`, no personal data.
pub fn claimed_handle_key(handle_sha256_hex: &str) -> String {
    format!("guest:claimed_handle/{handle_sha256_hex}")
}
/// `claim_lock/{sha256(handle)}`.
pub fn claim_lock_key(handle_sha256_hex: &str) -> String {
    format!("claim_lock/{handle_sha256_hex}")
}
/// The lowercase hex SHA-256 of a cookie handle, the form every handle-keyed key uses.
pub fn handle_hash(handle: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(handle.as_bytes()))
}

/// The commit: `active` to `claimed`, atomically with everything that makes it final.
/// `KEYS`: 1 record, 2 due, 3 claimed set, 4 claim_revoke set, 5 device set, 6 claimed
/// handle, 7 handle. `ARGV`: 1 localpart, 2 max claimed, 3 credential id, 4 keep_email
/// (`1`/`0`), 5 marker secs, 6 by_invite prefix.
/// Returns `claimed`, `already`, `capped`, `gone` or `lost` (not `active`, past the
/// deadline by Redis `TIME`, or promoted). A refusal writes nothing.
const COMMIT_CLAIM: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'state', 'deadline', 'invite_id')
if not f[1] then return 'gone' end
if f[1] == 'claimed' then return 'already' end
if f[1] ~= 'active' then return 'lost' end
local now = tonumber(redis.call('TIME')[1])
local d = tonumber(f[2])
if not d or now >= d then return 'lost' end
if redis.call('HEXISTS', KEYS[1], 'promoted_at') == 1 then return 'lost' end
if redis.call('SISMEMBER', KEYS[3], ARGV[1]) == 0
   and redis.call('SCARD', KEYS[3]) >= tonumber(ARGV[2]) then return 'capped' end
-- `,` is a safe separator only because a device id is validated at /authorize, sign_in
-- and the device grant to [A-Za-z0-9._~+/-]{1,64} (`oidc::device_id_is_valid`): no id
-- can hold a comma, so `read_pre_claim_devices` and `device_is_pre_claim_for_did` split it
-- back losslessly.
local devices = redis.call('SMEMBERS', KEYS[5])
table.sort(devices)
redis.call('HSET', KEYS[1], 'state', 'claimed', 'claimed_at', tostring(now),
  'claim_credential', ARGV[3], 'pre_claim_devices', table.concat(devices, ','))
redis.call('HDEL', KEYS[1], 'deadline')
if ARGV[4] ~= '1' then redis.call('HDEL', KEYS[1], 'email') end
redis.call('ZREM', KEYS[2], ARGV[1])
if f[3] then redis.call('SREM', ARGV[6] .. f[3], ARGV[1]) end
redis.call('SADD', KEYS[3], ARGV[1])
redis.call('SADD', KEYS[4], ARGV[1])
redis.call('DEL', KEYS[7])
redis.call('SET', KEYS[6], ARGV[1], 'EX', tonumber(ARGV[5]))
return 'claimed'
"#;

/// Release the claim lock only when it is still ours. `KEYS`: 1 lock. `ARGV`: 1 token.
const CLAIM_UNLOCK: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
"#;

/// What the claim gate reads of a record, in one round trip, with Redis `TIME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRead {
    pub localpart: String,
    pub did: String,
    pub state: String,
    pub deadline: Option<i64>,
    pub now: i64,
    pub invite_id: String,
    pub room_id: String,
    pub host: String,
    pub first_name: String,
    pub second_name: String,
    pub email_present: bool,
    pub host_banned: bool,
    /// Members of `guest:claimed`.
    pub claimed_count: u64,
}

/// What [`RedisClient::commit_guest_claim`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimCas {
    /// `active` to `claimed`.
    Claimed,
    /// Already `claimed`.
    Already,
    /// `guest_max_claimed` reached.
    Capped,
    /// Not `active`, past the deadline, or promoted: the reaper (or the clock) won.
    Lost,
    /// No record.
    Gone,
}

impl RedisClient {
    /// The record behind a claim, for the gate (CP-02/03/04 and the cap).
    pub async fn read_claim(&self, localpart: &str) -> Result<Option<ClaimRead>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (f, (secs, _), count): (HashMap<String, String>, (String, String), u64) =
            bb8_redis::redis::pipe()
                .cmd("HGETALL")
                .arg(guest_account_key(localpart))
                .cmd("TIME")
                .cmd("SCARD")
                .arg(CLAIMED_KEY)
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("guest claim read: {e}"))?;
        let (Some(state), Some(did)) = (f.get("state"), f.get("did")) else {
            return Ok(None);
        };
        let host = f.get("host").cloned().unwrap_or_default();
        let host_banned: i64 = cmd("SISMEMBER")
            .arg(BANNED_HOSTS_KEY)
            .arg(&host)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claim read: {e}"))?;
        let get = |k: &str| f.get(k).cloned().unwrap_or_default();
        Ok(Some(ClaimRead {
            localpart: localpart.to_string(),
            did: did.clone(),
            state: state.clone(),
            deadline: f.get("deadline").and_then(|d| d.parse().ok()),
            now: secs.parse().map_err(|e| anyhow!("guest claim read: {e}"))?,
            invite_id: get("invite_id"),
            room_id: get("room_id"),
            host,
            first_name: get("first_name"),
            second_name: get("second_name"),
            email_present: f.get("email").is_some_and(|e| !e.is_empty()),
            host_banned: host_banned == 1,
            claimed_count: count,
        }))
    }

    /// The localpart a cookie handle maps to for `CLAIMED_HANDLE_SECS` after a claim.
    pub async fn read_claimed_handle(&self, handle: &str) -> Result<Option<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        cmd("GET")
            .arg(claimed_handle_key(&handle_hash(handle)))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claimed handle: {e}"))
    }

    /// `SET claim_lock/{h} {token} NX EX 30`. `false`: another finish holds it.
    pub async fn take_claim_lock(&self, hash: &str, token: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let set: Option<String> = cmd("SET")
            .arg(claim_lock_key(hash))
            .arg(token)
            .arg("NX")
            .arg("EX")
            .arg(CLAIM_LOCK_SECS)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("claim lock: {e}"))?;
        Ok(set.is_some())
    }

    /// Give the claim lock back (only if the token is still ours). Best effort.
    pub async fn release_claim_lock(&self, hash: &str, token: &str) {
        let Ok(mut conn) = self.pool.get().await else {
            return;
        };
        let _: Result<i64, _> = cmd("EVAL")
            .arg(CLAIM_UNLOCK)
            .arg(1)
            .arg(claim_lock_key(hash))
            .arg(token)
            .query_async(&mut *conn)
            .await;
    }

    /// The commit point of the claim ([`COMMIT_CLAIM`]).
    pub async fn commit_guest_claim(
        &self,
        localpart: &str,
        hash: &str,
        credential_id: &str,
        max_claimed: u64,
        keep_email: bool,
    ) -> Result<ClaimCas> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let out: String = cmd("EVAL")
            .arg(COMMIT_CLAIM)
            .arg(7)
            .arg(guest_account_key(localpart))
            .arg(DUE_KEY)
            .arg(CLAIMED_KEY)
            .arg(CLAIM_REVOKE_KEY)
            .arg(devices_key(localpart))
            .arg(claimed_handle_key(hash))
            .arg(handle_key(hash))
            .arg(localpart)
            .arg(max_claimed)
            .arg(credential_id)
            .arg(if keep_email { "1" } else { "0" })
            .arg(CLAIMED_HANDLE_SECS)
            .arg(BY_INVITE_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claim commit: {e}"))?;
        Ok(match out.as_str() {
            "claimed" => ClaimCas::Claimed,
            "already" => ClaimCas::Already,
            "capped" => ClaimCas::Capped,
            "gone" => ClaimCas::Gone,
            _ => ClaimCas::Lost,
        })
    }

    /// The device ids a claim revokes (the record's `pre_claim_devices`).
    pub async fn read_pre_claim_devices(&self, localpart: &str) -> Result<Vec<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let v: Option<String> = cmd("HGET")
            .arg(guest_account_key(localpart))
            .arg("pre_claim_devices")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claim devices: {e}"))?;
        Ok(v.unwrap_or_default()
            .split(',')
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// GP-CLM-26: whether `device_id` is one of the `pre_claim_devices` kept on the guest
    /// record of this DID (modern or legacy localpart). One pipelined round trip of two
    /// `HGET`s, no scan. An account with no guest record has no such field, so the answer
    /// is `false` for every ordinary account. A Redis error is an `Err`: the caller fails
    /// closed, since the error hides whether a record exists.
    pub async fn device_is_pre_claim_for_did(&self, did: &str, device_id: &str) -> Result<bool> {
        let modern = crate::mxid::localpart_for(did);
        let legacy = crate::mxid::legacy_localpart(did);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut pipe = bb8_redis::redis::pipe();
        pipe.cmd("HGET")
            .arg(guest_account_key(&modern))
            .arg("pre_claim_devices");
        if legacy != modern {
            pipe.cmd("HGET")
                .arg(guest_account_key(&legacy))
                .arg("pre_claim_devices");
        }
        let lists: Vec<Option<String>> = pipe
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest pre-claim devices: {e}"))?;
        Ok(lists
            .into_iter()
            .flatten()
            .any(|l| l.split(',').any(|d| d == device_id)))
    }

    /// The claims whose revocation a crash may have left unfinished.
    pub async fn pending_claim_revokes(&self) -> Result<Vec<String>> {
        self.smembers_raw(CLAIM_REVOKE_KEY).await
    }

    /// The revocation of this claim is done.
    pub async fn claim_revoke_done(&self, localpart: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("SREM")
            .arg(CLAIM_REVOKE_KEY)
            .arg(localpart)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest claim revoke done: {e}"))?;
        Ok(())
    }

    /// Whether any guest is still scheduled (`guest:due` is not empty; every live guest is
    /// in it). The orphan scan runs on an install with guests off only while this holds.
    pub async fn guests_scheduled(&self) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EXISTS")
            .arg(DUE_KEY)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest due exists: {e}"))?;
        Ok(n > 0)
    }

    /// Test helper: the score of `member` in `guest:due`.
    #[doc(hidden)]
    pub async fn due_score_for_test(&self, member: &str) -> Option<f64> {
        let mut conn = self.pool.get().await.unwrap();
        cmd("ZSCORE")
            .arg(DUE_KEY)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .unwrap()
    }

    /// Test helper: schedule `member` in `guest:due` at `score`.
    #[doc(hidden)]
    pub async fn due_add_for_test(&self, member: &str, score: i64) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("ZADD")
            .arg(DUE_KEY)
            .arg(score)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    /// Test helper: set one field of a record.
    #[doc(hidden)]
    pub async fn hset_for_test(&self, key: &str, field: &str, value: &str) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(value)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }
}

/// How long a hand-off holds its lease on the record. An expired lease may be re-taken.
pub const HANDOFF_LEASE_SECS: u64 = 120;

/// `guest:devices/{localpart}`: SET of the device ids a guest has been handed (written
/// ahead of provisioning, so the cap counts an attempt in flight). No TTL; the reaper
/// removes it with the record.
pub fn devices_key(localpart: &str) -> String {
    format!("guest:devices/{localpart}")
}
/// `guest:handoff/{localpart}`: ZSET of admitted hand-off attempts, scored by Redis `TIME`
/// seconds; the sliding window of the per-minute limit.
pub fn handoff_rate_key(localpart: &str) -> String {
    format!("guest:handoff/{localpart}")
}

/// `KEYS`: 1 record, 2 device set, 3 rate window. `ARGV`: 1 attempt, 2 lease secs, 3 max
/// devices, 4 hand-offs per minute, 5 device id. Returns `{1, prior_state, acct_checked}`
/// or `{0, reason}`.
const HANDOFF_BEGIN: &str = r#"
local now = tonumber(redis.call('TIME')[1])
local f = redis.call('HMGET', KEYS[1], 'state', 'deadline', 'lease_until', 'lease_owner', 'acct_checked')
if not f[1] then return {0, 'no_record'} end
if f[1] ~= 'minted' and f[1] ~= 'provisioning' and f[1] ~= 'active' then return {0, 'not_live'} end
if (not f[2]) or tonumber(f[2]) <= now then return {0, 'not_live'} end
if f[3] and tonumber(f[3]) > now and f[4] ~= ARGV[1] then return {0, 'busy'} end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now - 60)
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[4]) then return {0, 'rate'} end
if redis.call('SISMEMBER', KEYS[2], ARGV[5]) == 0 then
  if redis.call('SCARD', KEYS[2]) >= tonumber(ARGV[3]) then return {0, 'devices'} end
  redis.call('SADD', KEYS[2], ARGV[5])
end
redis.call('ZADD', KEYS[3], now, ARGV[1])
redis.call('EXPIRE', KEYS[3], 120)
if f[1] ~= 'active' then redis.call('HSET', KEYS[1], 'state', 'provisioning') end
redis.call('HSET', KEYS[1], 'lease_owner', ARGV[1], 'lease_until', tostring(now + tonumber(ARGV[2])), 'device_id', ARGV[5])
return {1, f[1], f[5] or ''}
"#;

/// `KEYS`: 1 record. `ARGV`: 1 attempt.
const HANDOFF_MARK_CHECKED: &str = r#"
if redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'acct_checked', '1')
return 1
"#;

/// `KEYS`: 1 record. `ARGV`: 1 attempt.
const HANDOFF_ACTIVATE: &str = r#"
local f = redis.call('HMGET', KEYS[1], 'state', 'lease_owner')
if f[2] ~= ARGV[1] then return 0 end
if f[1] ~= 'provisioning' and f[1] ~= 'active' then return 0 end
redis.call('HSET', KEYS[1], 'state', 'active')
redis.call('HDEL', KEYS[1], 'lease_owner', 'lease_until')
return 1
"#;

/// `KEYS`: 1 record, 2 device set. `ARGV`: 1 attempt, 2 device id to drop (`""` for none).
const HANDOFF_RELEASE: &str = r#"
if redis.call('HGET', KEYS[1], 'lease_owner') == ARGV[1] then
  redis.call('HDEL', KEYS[1], 'lease_owner', 'lease_until')
  if ARGV[2] ~= '' then redis.call('SREM', KEYS[2], ARGV[2]) end
end
return 1
"#;

/// The outcome of the hand-off fence.
#[derive(Debug, PartialEq, Eq)]
pub enum HandoffBegin {
    /// The lease is held. `was_active`: the account was provisioned by an earlier hand-off.
    /// `account_checked`: an earlier attempt of this record already found no foreign account
    /// under the localpart (`acct_checked`, written under the lease before `provision_user`).
    Started {
        was_active: bool,
        account_checked: bool,
    },
    Refused(HandoffRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRefusal {
    /// No record, a state a hand-off may not start from, or past the deadline.
    NotLive,
    /// Another attempt holds a live lease.
    Busy,
    /// The per-minute hand-off limit.
    Rate,
    /// The device cap.
    Devices,
}

/// What `GET /guest/context` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestContext {
    pub room_id: String,
    pub deadline: i64,
    pub invite_id: String,
    pub meeting_name: String,
}

/// What `GET /guest/resume` reads from the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestResume {
    pub first_name: String,
    pub second_name: String,
    pub state: String,
    pub did: String,
    pub email_present: bool,
}

/// A guest record as `/authorize` and `/guest/continue` read it through the cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestSession {
    /// The record key suffix: the guest's localpart, and the `guest_id` of a session.
    pub localpart: String,
    pub did: String,
    pub state: String,
    pub deadline: i64,
    /// Redis `TIME` at the read.
    pub now: i64,
}

impl GuestSession {
    /// `minted`, `provisioning` or `active`, and before the deadline. `reaping`,
    /// `claimed` and anything else is not a session a hand-off may start from.
    pub fn is_live(&self) -> bool {
        matches!(self.state.as_str(), "minted" | "provisioning" | "active")
            && self.now < self.deadline
    }
}

impl RedisClient {
    /// The record behind a session-cookie handle, with Redis `TIME`: handle hash to
    /// localpart to record, in two round trips. `None` for an unknown or expired handle
    /// (its key has a TTL until the deadline) or a record that no longer exists.
    pub async fn read_guest_session(&self, handle: &str) -> Result<Option<GuestSession>> {
        use sha2::{Digest, Sha256};
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let hash = hex::encode(Sha256::digest(handle.as_bytes()));
        let localpart: Option<String> = cmd("GET")
            .arg(handle_key(&hash))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest session: {e}"))?;
        let Some(localpart) = localpart else {
            return Ok(None);
        };
        drop(conn);
        self.read_guest_by_localpart(&localpart).await
    }

    /// The record of a localpart, with Redis `TIME`. `None` when it does not exist.
    pub async fn read_guest_by_localpart(&self, localpart: &str) -> Result<Option<GuestSession>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (f, (secs, _)): (Vec<Option<String>>, (String, String)) = bb8_redis::redis::pipe()
            .cmd("HMGET")
            .arg(guest_account_key(localpart))
            .arg("state")
            .arg("did")
            .arg("deadline")
            .cmd("TIME")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest session: {e}"))?;
        let (Some(Some(state)), Some(Some(did)), Some(Some(deadline))) =
            (f.first(), f.get(1), f.get(2))
        else {
            return Ok(None);
        };
        Ok(Some(GuestSession {
            localpart: localpart.to_string(),
            did: did.clone(),
            state: state.clone(),
            deadline: deadline
                .parse()
                .map_err(|e| anyhow!("guest session: {e}"))?,
            now: secs.parse().map_err(|e| anyhow!("guest session: {e}"))?,
        }))
    }

    /// M6: whether a guest record exists for this DID, under the modern or the legacy
    /// localpart. Any record state counts, `claimed` too: the DID of a guest never signs
    /// in by signature again outside `/guest/continue`.
    pub async fn guest_record_exists_for_did(&self, did: &str) -> Result<bool> {
        let modern = crate::mxid::localpart_for(did);
        let legacy = crate::mxid::legacy_localpart(did);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut c = cmd("EXISTS");
        c.arg(guest_account_key(&modern));
        if legacy != modern {
            c.arg(guest_account_key(&legacy));
        }
        let n: i64 = c
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest record lookup: {e}"))?;
        if n > 0 {
            return Ok(true);
        }
        // S5: the tombstone of a reaped guest (`mark_guest_erased`) keeps the DID refused
        // after its record is gone. An erasure marker of a registered user is not one.
        let marker: Option<String> = cmd("GET")
            .arg(super::redis::erased_did_key(did))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest record lookup: {e}"))?;
        Ok(marker.is_some_and(|m| m.starts_with("guest ")))
    }

    /// The fence of a hand-off (`sign_in`, S4b): one script, on Redis `TIME`.
    ///
    /// Refuses a record that is not `minted`, `provisioning` or `active`, or is past its
    /// deadline (`NotLive`); a live lease held by another attempt (`Busy`); a fourth
    /// hand-off inside 60 s (`Rate`, a sliding window in `guest:handoff/{localpart}`, only
    /// admitted attempts count); a ninth distinct device (`Devices`). Otherwise it writes
    /// the device id ahead of provisioning (`guest:devices/{localpart}` and the record's
    /// `device_id`), takes the lease (`lease_owner`, `lease_until`) and moves `minted` or
    /// `provisioning` to `provisioning`. An `active` record stays `active`: its account
    /// is already provisioned and the lease only serializes the device hand-offs.
    pub async fn guest_handoff_begin(
        &self,
        localpart: &str,
        attempt: &str,
        device_id: &str,
        max_devices: u64,
        per_minute: u64,
    ) -> Result<HandoffBegin> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let reply: Vec<Value> = cmd("EVAL")
            .arg(HANDOFF_BEGIN)
            .arg(3)
            .arg(guest_account_key(localpart))
            .arg(devices_key(localpart))
            .arg(handoff_rate_key(localpart))
            .arg(attempt)
            .arg(HANDOFF_LEASE_SECS)
            .arg(max_devices)
            .arg(per_minute)
            .arg(device_id)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest hand-off begin: {e}"))?;
        let int = matches!(reply.first(), Some(Value::Int(1)));
        let why = reply.get(1).and_then(text).unwrap_or_default();
        if int {
            return Ok(HandoffBegin::Started {
                was_active: why == "active",
                account_checked: reply.get(2).and_then(text).as_deref() == Some("1"),
            });
        }
        Ok(HandoffBegin::Refused(match why.as_str() {
            "busy" => HandoffRefusal::Busy,
            "rate" => HandoffRefusal::Rate,
            "devices" => HandoffRefusal::Devices,
            "not_live" | "no_record" => HandoffRefusal::NotLive,
            _ => return Err(anyhow!("guest hand-off begin: unknown refusal")),
        }))
    }

    /// Records that this attempt found no foreign account under the localpart
    /// (`acct_checked = 1`), only while it holds the lease; `false` when it lost the lease.
    /// Written before `provision_user`, so every later attempt that skips the account
    /// check does so because a check passed, never because of the state alone.
    pub async fn guest_handoff_mark_checked(&self, localpart: &str, attempt: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EVAL")
            .arg(HANDOFF_MARK_CHECKED)
            .arg(1)
            .arg(guest_account_key(localpart))
            .arg(attempt)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest hand-off mark checked: {e}"))?;
        Ok(n == 1)
    }

    /// The last step of a hand-off: `provisioning` (or `active`) to `active` and the
    /// lease released, only for the attempt that holds the lease. `false` when the lease
    /// was lost or the record left those states (reaping): no code may follow.
    pub async fn guest_handoff_activate(&self, localpart: &str, attempt: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EVAL")
            .arg(HANDOFF_ACTIVATE)
            .arg(1)
            .arg(guest_account_key(localpart))
            .arg(attempt)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest hand-off activate: {e}"))?;
        Ok(n == 1)
    }

    /// A failed attempt: release the lease it holds (the state stays `provisioning`, so a
    /// retry re-takes it at once) and, when `drop_device`, take the write-ahead device id
    /// back out of the device set.
    pub async fn guest_handoff_release(
        &self,
        localpart: &str,
        attempt: &str,
        drop_device: Option<&str>,
    ) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("EVAL")
            .arg(HANDOFF_RELEASE)
            .arg(2)
            .arg(guest_account_key(localpart))
            .arg(devices_key(localpart))
            .arg(attempt)
            .arg(drop_device.unwrap_or(""))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest hand-off release: {e}"))?;
        Ok(())
    }

    /// Whether a token or ID token of this localpart is a guest's: the record exists and
    /// is `minted`, `provisioning`, `active` or `reaping`. A `claimed` account is a
    /// persistent account and carries no guest claim (S7).
    pub async fn guest_flag(&self, localpart: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let state: Option<String> = cmd("HGET")
            .arg(guest_account_key(localpart))
            .arg("state")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest flag: {e}"))?;
        Ok(matches!(
            state.as_deref(),
            Some("minted" | "provisioning" | "active" | "reaping")
        ))
    }

    /// What `GET /guest/context` returns: the record's room, deadline and invite, and the
    /// invite's label as the meeting name. `None` when there is no record for the
    /// localpart. No Synapse call.
    pub async fn read_guest_context(&self, localpart: &str) -> Result<Option<GuestContext>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let f: HashMap<String, String> = cmd("HGETALL")
            .arg(guest_account_key(localpart))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest context: {e}"))?;
        if f.is_empty() || !f.contains_key("did") {
            return Ok(None);
        }
        let invite_id = f.get("invite_id").cloned().unwrap_or_default();
        let label: Option<String> = if crate::guest_invite::valid_invite_id(&invite_id) {
            cmd("HGET")
                .arg(invite_key(&invite_id))
                .arg("label")
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("guest context: {e}"))?
        } else {
            None
        };
        Ok(Some(GuestContext {
            room_id: f.get("room_id").cloned().unwrap_or_default(),
            deadline: f.get("deadline").and_then(|v| v.parse().ok()).unwrap_or(0),
            invite_id,
            meeting_name: label.unwrap_or_default(),
        }))
    }

    /// What `GET /guest/resume` returns, for a localpart the cookie named. The caller has
    /// decided that the record is live.
    pub async fn read_guest_resume(&self, localpart: &str) -> Result<Option<GuestResume>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let f: HashMap<String, String> = cmd("HGETALL")
            .arg(guest_account_key(localpart))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest resume: {e}"))?;
        let (Some(state), Some(did)) = (f.get("state"), f.get("did")) else {
            return Ok(None);
        };
        Ok(Some(GuestResume {
            first_name: f.get("first_name").cloned().unwrap_or_default(),
            second_name: f.get("second_name").cloned().unwrap_or_default(),
            state: state.clone(),
            did: did.clone(),
            email_present: f.get("email").is_some_and(|e| !e.is_empty()),
        }))
    }

    /// The one invite lookup of peek and redeem: the invite's hash and Redis `TIME` in
    /// one round trip. A malformed id reads a key that never exists, so the work is the
    /// same for every input. `None` when there is no such invite.
    pub async fn read_invite_gate(&self, invite_id: &str) -> Result<Option<InviteGate>> {
        let key = if crate::guest_invite::valid_invite_id(invite_id) {
            invite_key(invite_id)
        } else {
            invite_key(DUMMY_INVITE_ID)
        };
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        // One script, so the banned-host test costs the same for every input (GP-SEC-09).
        let (h, secs, banned): (HashMap<String, String>, String, i64) = cmd("EVAL")
            .arg(INVITE_GATE)
            .arg(2)
            .arg(&key)
            .arg(BANNED_HOSTS_KEY)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest invite gate: {e}"))?;
        if h.is_empty() {
            return Ok(None);
        }
        let now: i64 = secs
            .parse()
            .map_err(|e| anyhow!("guest invite gate: {e}"))?;
        let num = |k: &str| h.get(k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        let get = |k: &str| h.get(k).cloned().unwrap_or_default();
        // A banned host's invites answer as an ended one (revoked): no new oracle.
        let state = if get("state") == "revoked" || banned == 1 {
            InviteState::Revoked
        } else if num("expires_at") <= now {
            InviteState::Expired
        } else if num("used") >= num("max_guests") {
            InviteState::Exhausted
        } else {
            InviteState::Active
        };
        Ok(Some(InviteGate {
            secret_hash: get("secret_hash"),
            state,
            host: get("host"),
            session_secs: num("session_secs").max(0) as u64,
            recording_expected: get("recording_expected") == "1",
        }))
    }

    /// Whether siwx-oidc already knows an account for this DID: an erasure marker (by
    /// DID or by either localpart), grants or a tombstone under either localpart, a
    /// passkey index for the DID, or a guest record under the legacy localpart. No
    /// Synapse call: the `sign_in` fence (S4) refuses a Synapse-side account.
    pub async fn guest_did_known(
        &self,
        did: &str,
        did_sha256_hex: &str,
        localparts: &[&str],
    ) -> Result<bool> {
        let mut keys = vec![
            format!("{}/{did_sha256_hex}", super::KV_ERASED_DID_PREFIX),
            format!("{}/{did}", super::KV_WEBAUTHN_BY_DID_PREFIX),
        ];
        for lp in localparts {
            keys.push(format!("{}/{lp}", super::KV_ERASED_USER_PREFIX));
            keys.push(format!("{}/{lp}", super::grant::KV_GRANT_USER_IDX_PREFIX));
            keys.push(format!("{}/{lp}", super::KV_USER_TOMBSTONE_PREFIX));
            keys.push(guest_account_key(lp));
        }
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut p = bb8_redis::redis::pipe();
        for k in &keys {
            p.cmd("EXISTS").arg(k);
        }
        let found: Vec<i64> = p
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest did known: {e}"))?;
        Ok(found.iter().any(|n| *n > 0))
    }

    /// Mint a guest record in one atomic step, or refuse with the reason.
    pub async fn redeem_guest(
        &self,
        host: &str,
        g: &NewGuest<'_>,
        limits: &RedeemLimits,
    ) -> Result<RedeemOutcome> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let erased = |lp: &str| format!("{}/{lp}", super::KV_ERASED_USER_PREFIX);
        let reply: Vec<Value> = cmd("EVAL")
            .arg(REDEEM)
            .arg(12)
            .arg(invite_key(g.invite_id))
            .arg(guest_account_key(g.localpart))
            .arg(DUE_KEY)
            .arg(by_invite_key(g.invite_id))
            .arg(handle_key(g.handle_sha256_hex))
            .arg(CONTROL_KEY)
            .arg(by_host_key(host))
            .arg(DAILY_PREFIX)
            .arg(format!(
                "{}/{}",
                super::KV_ERASED_DID_PREFIX,
                g.did_sha256_hex
            ))
            .arg(erased(g.localpart))
            .arg(erased(g.legacy_localpart))
            .arg(BANNED_HOSTS_KEY)
            .arg(g.secret_hash)
            .arg(g.localpart)
            .arg(g.did)
            .arg(g.first_name)
            .arg(g.second_name)
            .arg(g.email.unwrap_or(""))
            .arg(g.consent_version)
            .arg(g.consent_variant)
            .arg(g.invite_id)
            .arg(limits.global_active)
            .arg(limits.daily_mint)
            .arg(limits.host_live_guests)
            .arg(guest_account_key(""))
            .arg(BY_INVITE_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest redeem: {e}"))?;
        parse_redeem(&reply)
    }

    /// The guests of each invite, for the host's list. A reaped guest has no record
    /// and is not listed. Order within an invite is by localpart, which is stable.
    pub async fn guests_of_invites(
        &self,
        invite_ids: &[String],
    ) -> Result<HashMap<String, Vec<GuestView>>> {
        let mut out = HashMap::new();
        for id in invite_ids {
            let mut members = self.smembers_raw(&by_invite_key(id)).await?;
            members.sort();
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|e| anyhow!("Redis pool: {e}"))?;
            let mut guests = Vec::new();
            for lp in members {
                let f: Vec<Option<String>> = cmd("HMGET")
                    .arg(guest_account_key(&lp))
                    .arg("first_name")
                    .arg("second_name")
                    .arg("email")
                    .arg("state")
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| anyhow!("guest list: {e}"))?;
                if let [Some(first_name), Some(second_name), email, Some(state)] = &f[..] {
                    guests.push(GuestView {
                        first_name: first_name.clone(),
                        second_name: second_name.clone(),
                        email: email.clone(),
                        state: state.clone(),
                    });
                }
            }
            out.insert(id.clone(), guests);
        }
        Ok(out)
    }

    /// Move the deadline of the unclaimed guests of these invites to now (never later;
    /// a `claimed` or `reaping` record is skipped). Returns how many moved.
    pub async fn move_guest_deadlines_to_now(&self, invite_ids: &[String]) -> Result<u64> {
        if invite_ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut c = cmd("EVAL");
        c.arg(MOVE_DEADLINES)
            .arg(1)
            .arg(DUE_KEY)
            .arg(guest_account_key(""))
            .arg(BY_INVITE_PREFIX);
        for id in invite_ids {
            c.arg(id);
        }
        let n: i64 = c
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest deadlines: {e}"))?;
        Ok(n.max(0) as u64)
    }

    /// The reaper's control pass: moves the deadline of every live unclaimed guest that
    /// `reap_before` or a banned host names to now (ZADD `guest:due`, then HSET).
    pub async fn enforce_guest_control(&self, reap_before: Option<i64>) -> Result<ControlMoved> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let r: Vec<i64> = cmd("EVAL")
            .arg(ENFORCE_CONTROL)
            .arg(2)
            .arg(DUE_KEY)
            .arg(BANNED_HOSTS_KEY)
            .arg(guest_account_key(""))
            .arg(reap_before.map(|v| v.to_string()).unwrap_or_default())
            .arg(1000)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest control pass: {e}"))?;
        let n = |i: usize| r.get(i).copied().unwrap_or(0).max(0) as u64;
        Ok(ControlMoved {
            by_reap_before: n(0),
            by_ban: n(1),
        })
    }

    /// The figures the alerts compare with their thresholds.
    pub async fn guest_alert_figures(&self, reaping_secs: u64) -> Result<AlertFigures> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let r: Vec<i64> = cmd("EVAL")
            .arg(ALERT_FIGURES)
            .arg(1)
            .arg(DUE_KEY)
            .arg(guest_account_key(""))
            .arg(DAILY_PREFIX)
            .arg(reaping_secs)
            .arg(REFUSAL_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest alert figures: {e}"))?;
        let n = |i: usize| r.get(i).copied().unwrap_or(0).max(0) as u64;
        Ok(AlertFigures {
            live: n(0),
            daily_mints: n(1),
            stuck_reaping: n(2),
            oldest_stuck_secs: n(3),
            refusals_per_min: n(4),
            refusal_minute: n(5),
        })
    }

    /// Count one refused guest request in this minute's instance-wide counter.
    pub async fn count_guest_refusal(&self) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = cmd("EVAL")
            .arg(COUNT_REFUSAL)
            .arg(0)
            .arg(REFUSAL_PREFIX)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest refusal counter: {e}"))?;
        Ok(())
    }

    /// `SET key 1 NX EX secs`: whether this caller took the lease.
    pub async fn try_lease(&self, key: &str, secs: u64) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let r: Option<String> = cmd("SET")
            .arg(key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(secs.max(1))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("lease: {e}"))?;
        Ok(r.is_some())
    }

    /// Whether `guest:acct/{localpart}` exists (any state).
    pub async fn guest_record_present(&self, localpart: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EXISTS")
            .arg(guest_account_key(localpart))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest record: {e}"))?;
        Ok(n == 1)
    }

    /// Test helper: `ZADD key score member`.
    #[doc(hidden)]
    pub async fn zadd_for_test(&self, key: &str, score: i64, member: &str) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("ZADD")
            .arg(key)
            .arg(score)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    /// Test helper: a guest record and its cookie handle, as redeem leaves them, with
    /// `state` and a deadline `deadline_in` seconds from Redis `TIME` (negative: past).
    /// The handle key lives an hour regardless, so an expired record is still found.
    #[doc(hidden)]
    pub async fn put_guest_for_test(
        &self,
        localpart: &str,
        did: &str,
        state: &str,
        deadline_in: i64,
        handle: &str,
    ) {
        use sha2::{Digest, Sha256};
        let mut conn = self.pool.get().await.unwrap();
        let (secs, _): (String, String) = cmd("TIME").query_async(&mut *conn).await.unwrap();
        let deadline = secs.parse::<i64>().unwrap() + deadline_in;
        let _: () = cmd("HSET")
            .arg(guest_account_key(localpart))
            .arg("state")
            .arg(state)
            .arg("did")
            .arg(did)
            .arg("deadline")
            .arg(deadline.to_string())
            .query_async(&mut *conn)
            .await
            .unwrap();
        let _: () = cmd("SET")
            .arg(handle_key(&hex::encode(Sha256::digest(handle.as_bytes()))))
            .arg(localpart)
            .arg("EX")
            .arg(3600)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    /// Test helper: add `member` to the set at `key`.
    #[doc(hidden)]
    pub async fn sadd_raw_for_test(&self, key: &str, member: &str) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("SADD")
            .arg(key)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    /// Test helper: the cardinality of the set at `key`.
    #[doc(hidden)]
    pub async fn scard_for_test(&self, key: &str) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        cmd("SCARD").arg(key).query_async(&mut *conn).await.unwrap()
    }

    /// Test helper: the whole hash at `key`.
    #[doc(hidden)]
    pub async fn hgetall_for_test(&self, key: &str) -> HashMap<String, String> {
        let mut conn = self.pool.get().await.unwrap();
        cmd("HGETALL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .unwrap()
    }

    /// Test helper: a sorted-set score.
    #[doc(hidden)]
    pub async fn zscore_for_test(&self, key: &str, member: &str) -> Option<f64> {
        let mut conn = self.pool.get().await.unwrap();
        cmd("ZSCORE")
            .arg(key)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .unwrap()
    }

    /// Test helper: the TTL of a key in seconds (-1 none, -2 absent).
    #[doc(hidden)]
    pub async fn pttl_for_test(&self, key: &str) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        cmd("PTTL").arg(key).query_async(&mut *conn).await.unwrap()
    }

    #[doc(hidden)]
    pub async fn ttl_for_test(&self, key: &str) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        cmd("TTL").arg(key).query_async(&mut *conn).await.unwrap()
    }

    /// Test helper: the number of keys in this database, not counting the audit refusal
    /// counters (`guest:refusals/*`): a refused request writes no state, only a count.
    #[doc(hidden)]
    pub async fn dbsize_for_test(&self) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        let all: i64 = cmd("DBSIZE").query_async(&mut *conn).await.unwrap();
        let counters: Vec<String> = cmd("KEYS")
            .arg(format!("{REFUSAL_PREFIX}*"))
            .query_async(&mut *conn)
            .await
            .unwrap();
        all - counters.len() as i64
    }

    /// Test helper: refusals counted so far in `guest:refusals/*`, summed over the minutes
    /// still alive (so a minute boundary inside a test cannot split the figure).
    #[doc(hidden)]
    pub async fn guest_refusal_total_for_test(&self) -> u64 {
        let mut conn = self.pool.get().await.unwrap();
        let keys: Vec<String> = cmd("KEYS")
            .arg(format!("{REFUSAL_PREFIX}*"))
            .query_async(&mut *conn)
            .await
            .unwrap();
        let mut total = 0;
        for k in keys {
            let n: Option<u64> = cmd("GET").arg(&k).query_async(&mut *conn).await.unwrap();
            total += n.unwrap_or(0);
        }
        total
    }

    /// Test helper: empty this database. Only for a test that owns its database.
    #[doc(hidden)]
    pub async fn flush_db_for_test(&self) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut *conn).await.unwrap();
    }
}
