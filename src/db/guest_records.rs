//! The guest record store (work package S3b, design 01 §4.1, contract §4).
//!
//! | Key | Holds |
//! |---|---|
//! | `guest:acct/{localpart}` | HASH: `state` (`minted`), `did`, `invite_id`, `host`, `room_id`, `first_name`, `second_name`, `email` (only if given), `consent_version`, `consent_variant`, `created_at`, `deadline`. No secret, no key material. No TTL: the reaper (S5) needs the record to erase the account |
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

use super::guest_invites::{by_host_key, guest_account_key, invite_key, CONTROL_KEY};
use super::RedisClient;

pub const DUE_KEY: &str = "guest:due";
const BY_INVITE_PREFIX: &str = "guest:by_invite/";
const HANDLE_PREFIX: &str = "guest:handle/";
const DAILY_PREFIX: &str = "guest:quota/daily_mint/";
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
/// 10 `erased:user/<localpart>`, 11 `erased:user/<legacy localpart>`. `ARGV`: 1 secret
/// hash, 2 localpart, 3 did, 4 first, 5 second, 6 email (`""` for none), 7 consent
/// version, 8 consent variant, 9 invite id, 10 global max, 11 daily max, 12 host live
/// max, 13 record key prefix, 14 by_invite key prefix.
/// Returns `{0, reason[, quota]}` or `{1, deadline, now}`.
const REDEEM: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1])
if redis.call('GET', KEYS[6]) == 'disabled' then return {0, 'disabled'} end
local f = redis.call('HMGET', KEYS[1], 'state', 'expires_at', 'used', 'max_guests', 'host', 'room_id', 'session_secs', 'secret_hash')
if not f[1] then return {0, 'expired'} end
if f[8] ~= ARGV[1] then return {0, 'invalid_link'} end
if f[1] == 'revoked' then return {0, 'revoked'} end
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
      redis.call('HSET', k, 'deadline', tostring(now))
      redis.call('ZADD', KEYS[1], now, lp)
      moved = moved + 1
    end
  end
end
return moved
"#;

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

impl RedisClient {
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
        let (h, (secs, _)): (HashMap<String, String>, (String, String)) = bb8_redis::redis::pipe()
            .cmd("HGETALL")
            .arg(&key)
            .cmd("TIME")
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
        let state = if get("state") == "revoked" {
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
            .arg(11)
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
    pub async fn ttl_for_test(&self, key: &str) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        cmd("TTL").arg(key).query_async(&mut *conn).await.unwrap()
    }

    /// Test helper: the number of keys in this database.
    #[doc(hidden)]
    pub async fn dbsize_for_test(&self) -> i64 {
        let mut conn = self.pool.get().await.unwrap();
        cmd("DBSIZE").query_async(&mut *conn).await.unwrap()
    }

    /// Test helper: empty this database. Only for a test that owns its database.
    #[doc(hidden)]
    pub async fn flush_db_for_test(&self) {
        let mut conn = self.pool.get().await.unwrap();
        let _: () = cmd("FLUSHDB").query_async(&mut *conn).await.unwrap();
    }
}
