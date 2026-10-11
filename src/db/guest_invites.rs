//! The guest invite store (work package S2b, design 01 §4.1, contract §4).
//!
//! Keys (all written by one script per call, so a refused call writes nothing and
//! the quotas are counted in the same step as the state change, GP-SEC-02):
//!
//! | Key | Holds |
//! |---|---|
//! | `guest:invite/{id}` | HASH: `host`, `host_did`, `room_id`, `label`, `kind`, `state` (`active`/`revoked`), `max_guests`, `used`, `session_secs`, `recording_expected`, `secret_hash`, `created_at`, `expires_at`. TTL = lifetime + `guest_session_max_secs` + slack |
//! | `guest:by_host/{host}` | SET of the host's invite ids (`host` = `TokenMetadata.username`) |
//! | `guest:by_room/{host}/{sha256(room_id)}` | SET of the host's invite ids for one room, for `meetings/end` |
//! | `guest:quota/host_invites_hour/{host}/{hour}` | counter, one hour window of Redis `TIME` |
//! | `guest:acct/{localpart}` | HASH of a guest record (written from S3); read here only to refuse a guest as a host |
//! | `guest:control` | HASH, written by an operator only: `disabled` (`1`/`true` engages the kill switch), `reap_before` (epoch seconds; every unclaimed guest minted at or before it is due now) |
//! | `guest:banned_hosts` | SET of host identities (`TokenMetadata.username`); operator only |
//!
//! Every instant is Redis `TIME`, never an instance clock (GP-SEC-08). The scripts
//! build the `guest:invite/{id}` keys they scan from `ARGV[1]`, which is fine on the
//! single Redis this service runs against and would have to change for a cluster.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bb8_redis::redis::cmd;
use sha2::{Digest, Sha256};

use super::RedisClient;
use crate::guest_invite::Kind;

const INVITE_PREFIX: &str = "guest:invite/";
/// Slack added to an invite's TTL beyond its expiry and the session ceiling.
const TTL_SLACK_SECS: u64 = 300;

pub fn invite_key(id: &str) -> String {
    format!("{INVITE_PREFIX}{id}")
}
pub fn by_host_key(host: &str) -> String {
    format!("guest:by_host/{host}")
}
pub fn by_room_key(host: &str, room_id: &str) -> String {
    format!(
        "guest:by_room/{host}/{}",
        hex::encode(Sha256::digest(room_id))
    )
}
fn quota_hour_key(host: &str) -> String {
    format!("guest:quota/host_invites_hour/{host}/")
}
pub fn guest_account_key(localpart: &str) -> String {
    format!("guest:acct/{localpart}")
}
pub const CONTROL_KEY: &str = "guest:control";
pub const BANNED_HOSTS_KEY: &str = "guest:banned_hosts";

/// The operator's switches in `guest:control` (GP-SEC-48, S6). Redis holds a HASH with up
/// to two fields; both absent is the normal state. A value that does not parse, or a key
/// of another type, is an `Err` and every caller fails closed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestControl {
    /// `disabled` is `1` or `true`: no mint, redeem, hand-off or refresh.
    pub disabled: bool,
    /// `reap_before`: unclaimed guests minted at or before this epoch second are due now.
    pub reap_before: Option<i64>,
}

impl GuestControl {
    /// The two hash fields as read. `0`, `false` and an empty value are "off".
    pub fn parse(disabled: Option<&str>, reap_before: Option<&str>) -> Result<Self> {
        let disabled = match disabled {
            None | Some("" | "0" | "false") => false,
            Some("1" | "true") => true,
            Some(_) => return Err(anyhow!("guest:control: `disabled` is not 1 or true")),
        };
        let reap_before = reap_before
            .map(|v| {
                v.parse::<i64>()
                    .map_err(|_| anyhow!("guest:control: `reap_before` is not an integer"))
            })
            .transpose()?;
        Ok(Self {
            disabled,
            reap_before,
        })
    }
}

/// Whether an unclaimed guest minted at `created_at` is due under `reap_before`. A record
/// without a mint time matches (fail closed).
pub fn reap_before_matches(created_at: Option<i64>, reap_before: Option<i64>) -> bool {
    match (reap_before, created_at) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(rb), Some(c)) => c <= rb,
    }
}

/// Create `count` invites for one host, or refuse all of them. `KEYS[1]` the
/// host's set, `KEYS[2]` the hour-quota key prefix, `KEYS[3]` the room set,
/// `KEYS[4..]` the new invite keys. `ARGV`: 1 key prefix, 2 max active, 3 max
/// open, 4 per hour, 5 kind, 6 lifetime, 7 grace, 8 room id, 9 host, 10 host
/// DID, 11 max guests, 12 session secs, 13 recording, then `(secret_hash,
/// label, id)` per invite. Returns `{0, quota}` (refused) or `{1, now, expires_at}`.
const CREATE: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1])
local kind = ARGV[5]
local count = #KEYS - 3
local active, open = 0, 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local f = redis.call('HMGET', ARGV[1] .. id, 'state', 'expires_at', 'kind')
  if not f[1] then
    redis.call('SREM', KEYS[1], id)
  elseif f[1] == 'active' and tonumber(f[2]) > now then
    active = active + 1
    if f[3] == 'open' then open = open + 1 end
  end
end
if active + count > tonumber(ARGV[2]) then return {0, 'host_invites'} end
if kind == 'open' and open + count > tonumber(ARGV[3]) then return {0, 'host_open_invites'} end
local hour = KEYS[2] .. math.floor(now / 3600)
local used = tonumber(redis.call('GET', hour) or '0')
if used + count > tonumber(ARGV[4]) then return {0, 'host_invites_per_hour'} end
redis.call('INCRBY', hour, count)
redis.call('EXPIRE', hour, 3600)
local expires_at = now + tonumber(ARGV[6])
local ttl = tonumber(ARGV[6]) + tonumber(ARGV[7])
for i = 1, count do
  local base = 13 + (i - 1) * 3
  local key = KEYS[3 + i]
  redis.call('HSET', key,
    'host', ARGV[9], 'host_did', ARGV[10], 'room_id', ARGV[8], 'label', ARGV[base + 2],
    'kind', kind, 'state', 'active', 'max_guests', ARGV[11], 'used', '0',
    'session_secs', ARGV[12], 'recording_expected', ARGV[13],
    'secret_hash', ARGV[base + 1], 'created_at', tostring(now), 'expires_at', tostring(expires_at))
  redis.call('EXPIRE', key, ttl)
  redis.call('SADD', KEYS[1], ARGV[base + 3])
  redis.call('SADD', KEYS[3], ARGV[base + 3])
end
for _, k in ipairs({KEYS[1], KEYS[3]}) do
  if redis.call('TTL', k) < ttl then redis.call('EXPIRE', k, ttl) end
end
return {1, now, expires_at}
"#;

/// Revoke invites. `KEYS[1]` the set to walk (the host's invites for one room,
/// or the one id), `ARGV[1]` the key prefix, `ARGV[2]` the caller's host. Only an
/// invite whose `host` is the caller is touched. Returns how many are revoked
/// now or were already (idempotent), so 0 means "none of yours".
const REVOKE: &str = r#"
local n = 0
for _, id in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local k = ARGV[1] .. id
  if redis.call('HGET', k, 'host') == ARGV[2] then
    redis.call('HSET', k, 'state', 'revoked')
    n = n + 1
  end
end
return n
"#;

/// The limits one create is counted against.
pub struct QuotaLimits {
    pub max_invites: u64,
    pub max_open_invites: u64,
    pub per_hour: u64,
    /// `guest_session_max_secs`: part of the key lifetime.
    pub session_max_secs: u64,
}

/// One invite to store: its id, the SHA-256 of its secret, and its label.
pub struct NewInvite {
    pub id: String,
    pub secret_hash: String,
    pub label: String,
}

/// What every invite of one create shares.
pub struct NewBatch<'a> {
    pub host: &'a str,
    pub host_did: &'a str,
    pub room_id: &'a str,
    pub kind: Kind,
    pub max_guests: u64,
    pub expires_in: u64,
    pub session_secs: u64,
    pub recording_expected: bool,
    pub invites: &'a [NewInvite],
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created {
        created_at: i64,
        expires_at: i64,
    },
    /// Refused by this quota class; nothing was written.
    Refused(&'static str),
}

/// A stored invite as a host may see it. There is no field for the secret hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteView {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub state: String,
    pub room_id: String,
    pub max_guests: u64,
    pub used: u64,
    pub session_secs: u64,
    pub recording_expected: bool,
    pub created_at: i64,
    pub expires_at: i64,
}

impl RedisClient {
    async fn server_time_secs(&self) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (secs, _): (String, String) = cmd("TIME")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest invites TIME: {e}"))?;
        secs.parse().map_err(|e| anyhow!("guest invites TIME: {e}"))
    }

    /// Store a batch of invites in one atomic step, or refuse it with the quota class.
    pub async fn create_guest_invites(
        &self,
        batch: &NewBatch<'_>,
        limits: &QuotaLimits,
    ) -> Result<CreateOutcome> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut c = cmd("EVAL");
        c.arg(CREATE)
            .arg(3 + batch.invites.len())
            .arg(by_host_key(batch.host))
            .arg(quota_hour_key(batch.host))
            .arg(by_room_key(batch.host, batch.room_id));
        for i in batch.invites {
            c.arg(invite_key(&i.id));
        }
        c.arg(INVITE_PREFIX)
            .arg(limits.max_invites)
            .arg(limits.max_open_invites)
            .arg(limits.per_hour)
            .arg(batch.kind.as_str())
            .arg(batch.expires_in)
            .arg(limits.session_max_secs + TTL_SLACK_SECS)
            .arg(batch.room_id)
            .arg(batch.host)
            .arg(batch.host_did)
            .arg(batch.max_guests)
            .arg(batch.session_secs)
            .arg(if batch.recording_expected { "1" } else { "0" });
        for i in batch.invites {
            c.arg(&i.secret_hash).arg(&i.label).arg(&i.id);
        }
        let reply: Vec<bb8_redis::redis::Value> = c
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest invites create: {e}"))?;
        parse_create(&reply)
    }

    /// The host's own invites, oldest first. Expired and exhausted are derived.
    pub async fn list_guest_invites(&self, host: &str) -> Result<Vec<InviteView>> {
        let now = self.server_time_secs().await?;
        let ids = self.smembers_raw(&by_host_key(host)).await?;
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let mut out = Vec::new();
        for id in ids {
            let h: HashMap<String, String> = cmd("HGETALL")
                .arg(invite_key(&id))
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("guest invites list: {e}"))?;
            // Another host's id in this set would be a bug; never show it.
            if h.get("host").map(String::as_str) != Some(host) {
                continue;
            }
            out.push(view_of(&id, &h, now));
        }
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(out)
    }

    /// Revoke one invite of `host`. `false` when it is not theirs or unknown.
    pub async fn revoke_guest_invite(&self, host: &str, id: &str) -> Result<bool> {
        // A one-member scratch set would be a second write path; walk the host's
        // own set instead and filter on the id in Rust.
        if !self
            .smembers_raw(&by_host_key(host))
            .await?
            .iter()
            .any(|m| m == id)
        {
            return Ok(false);
        }
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EVAL")
            .arg(
                r#"if redis.call('HGET', KEYS[1], 'host') == ARGV[1] then
                     redis.call('HSET', KEYS[1], 'state', 'revoked') return 1 end
                   return 0"#,
            )
            .arg(1)
            .arg(invite_key(id))
            .arg(host)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest invites revoke: {e}"))?;
        Ok(n == 1)
    }

    /// Revoke every invite `host` made for `room_id`; returns how many.
    pub async fn revoke_guest_invites_for_room(&self, host: &str, room_id: &str) -> Result<u64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("EVAL")
            .arg(REVOKE)
            .arg(1)
            .arg(by_room_key(host, room_id))
            .arg(INVITE_PREFIX)
            .arg(host)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest invites end meeting: {e}"))?;
        Ok(n.max(0) as u64)
    }

    /// Whether `localpart` holds a guest record that has not been promoted
    /// (GP-FLOW-10): the record exists and has no `promoted_at`. S3 writes the records.
    pub async fn is_unpromoted_guest(&self, localpart: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let (exists, promoted): (i64, i64) = bb8_redis::redis::pipe()
            .cmd("EXISTS")
            .arg(guest_account_key(localpart))
            .cmd("HEXISTS")
            .arg(guest_account_key(localpart))
            .arg("promoted_at")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest record read: {e}"))?;
        Ok(exists == 1 && promoted == 0)
    }

    /// Test helper: set one field of a hash.
    #[doc(hidden)]
    pub async fn hset_raw_for_test(&self, key: &str, field: &str, value: &str) {
        let mut conn = self.pool.get().await.unwrap();
        let _: i64 = cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(value)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    /// Test helper: read one field of a hash.
    #[doc(hidden)]
    pub async fn get_hash_field_for_test(&self, key: &str, field: &str) -> Option<String> {
        let mut conn = self.pool.get().await.unwrap();
        cmd("HGET")
            .arg(key)
            .arg(field)
            .query_async(&mut *conn)
            .await
            .unwrap()
    }

    /// The operator's switches (`guest:control`). `Err` on a read failure, a WRONGTYPE
    /// (an old plain-string key) or a value that does not parse.
    pub async fn guest_control(&self) -> Result<GuestControl> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let f: Vec<Option<String>> = cmd("HMGET")
            .arg(CONTROL_KEY)
            .arg("disabled")
            .arg("reap_before")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest control: {e}"))?;
        GuestControl::parse(
            f.first().and_then(|v| v.as_deref()),
            f.get(1).and_then(|v| v.as_deref()),
        )
    }

    /// Whether the operator banned this host (`guest:banned_hosts`).
    pub async fn guest_host_banned(&self, host: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let n: i64 = cmd("SISMEMBER")
            .arg(BANNED_HOSTS_KEY)
            .arg(host)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("guest banned hosts: {e}"))?;
        Ok(n == 1)
    }

    /// The banned hosts, sorted.
    pub async fn guest_banned_hosts(&self) -> Result<Vec<String>> {
        let mut v = self.smembers_raw(BANNED_HOSTS_KEY).await?;
        v.sort();
        Ok(v)
    }
}

fn parse_create(reply: &[bb8_redis::redis::Value]) -> Result<CreateOutcome> {
    use bb8_redis::redis::Value;
    let int = |v: &Value| match v {
        Value::Int(n) => Some(*n),
        _ => None,
    };
    match reply.first().and_then(int) {
        Some(1) => Ok(CreateOutcome::Created {
            created_at: reply
                .get(1)
                .and_then(int)
                .ok_or_else(|| anyhow!("bad reply"))?,
            expires_at: reply
                .get(2)
                .and_then(int)
                .ok_or_else(|| anyhow!("bad reply"))?,
        }),
        Some(0) => {
            let class = match reply.get(1) {
                Some(Value::BulkString(b)) => String::from_utf8_lossy(b).into_owned(),
                Some(Value::SimpleString(s)) => s.clone(),
                _ => String::new(),
            };
            Ok(CreateOutcome::Refused(match class.as_str() {
                "host_invites" => "host_invites",
                "host_open_invites" => "host_open_invites",
                "host_invites_per_hour" => "host_invites_per_hour",
                _ => return Err(anyhow!("guest invites create: unknown refusal")),
            }))
        }
        _ => Err(anyhow!("guest invites create: bad reply")),
    }
}

fn view_of(id: &str, h: &HashMap<String, String>, now: i64) -> InviteView {
    let num = |k: &str| h.get(k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let get = |k: &str| h.get(k).cloned().unwrap_or_default();
    let (expires_at, used, max) = (
        num("expires_at"),
        num("used") as u64,
        num("max_guests") as u64,
    );
    let state = if get("state") == "revoked" {
        "revoked"
    } else if expires_at <= now {
        "expired"
    } else if used >= max {
        "exhausted"
    } else {
        "active"
    };
    InviteView {
        id: id.to_string(),
        label: get("label"),
        kind: get("kind"),
        state: state.to_string(),
        room_id: get("room_id"),
        max_guests: max,
        used,
        session_secs: num("session_secs") as u64,
        recording_expected: get("recording_expected") == "1",
        created_at: num("created_at"),
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_invite::{new_invite_id, secret_hash};

    fn nonce() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    fn invites(n: usize) -> Vec<NewInvite> {
        (0..n)
            .map(|i| NewInvite {
                id: new_invite_id(),
                secret_hash: secret_hash(&format!("gi_{i}")),
                label: format!("guest {i}"),
            })
            .collect()
    }

    fn limits(max: u64, open: u64, hour: u64) -> QuotaLimits {
        QuotaLimits {
            max_invites: max,
            max_open_invites: open,
            per_hour: hour,
            session_max_secs: 7200,
        }
    }

    async fn create(
        db: &RedisClient,
        host: &str,
        room: &str,
        kind: Kind,
        n: usize,
        l: &QuotaLimits,
    ) -> CreateOutcome {
        let list = invites(n);
        let batch = NewBatch {
            host,
            host_did: "did:key:zH",
            room_id: room,
            kind,
            max_guests: if kind == Kind::Open { 5 } else { 1 },
            expires_in: 3600,
            session_secs: 7200,
            recording_expected: false,
            invites: &list,
        };
        db.create_guest_invites(&batch, l).await.unwrap()
    }

    /// ST-02: each host ceiling refuses exactly at its number, and a refusal writes nothing.
    #[tokio::test]
    async fn st02_host_ceilings_hold_exactly_and_a_refusal_writes_nothing() {
        let Some(db) = crate::test_support::redis().await else {
            return;
        };
        let host = format!("h{}", nonce());
        let l = limits(3, 1, 4);
        assert!(matches!(
            create(&db, &host, "!r:e", Kind::Single, 2, &l).await,
            CreateOutcome::Created { .. }
        ));
        // 2 + 2 > 3 refuses the whole batch.
        assert_eq!(
            create(&db, &host, "!r:e", Kind::Single, 2, &l).await,
            CreateOutcome::Refused("host_invites")
        );
        assert_eq!(db.list_guest_invites(&host).await.unwrap().len(), 2);
        assert!(matches!(
            create(&db, &host, "!r:e", Kind::Single, 1, &l).await,
            CreateOutcome::Created { .. }
        ));
        assert_eq!(
            create(&db, &host, "!r:e", Kind::Single, 1, &l).await,
            CreateOutcome::Refused("host_invites")
        );

        // The hourly ceiling counts links made, revoked or not.
        let host2 = format!("h{}", nonce());
        let l2 = limits(100, 1, 3);
        assert!(matches!(
            create(&db, &host2, "!r:e", Kind::Single, 3, &l2).await,
            CreateOutcome::Created { .. }
        ));
        assert_eq!(
            create(&db, &host2, "!r:e", Kind::Single, 1, &l2).await,
            CreateOutcome::Refused("host_invites_per_hour")
        );

        // One open link per host.
        let host3 = format!("h{}", nonce());
        assert!(matches!(
            create(&db, &host3, "!r:e", Kind::Open, 1, &l).await,
            CreateOutcome::Created { .. }
        ));
        assert_eq!(
            create(&db, &host3, "!r:e", Kind::Open, 1, &l).await,
            CreateOutcome::Refused("host_open_invites")
        );
    }

    /// ST-02: atomic under 50 concurrent calls.
    #[tokio::test]
    async fn st02_the_ceiling_is_atomic_under_fifty_concurrent_creates() {
        let Some(db) = crate::test_support::redis().await else {
            return;
        };
        let host = format!("h{}", nonce());
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let (db, host) = (db.clone(), host.clone());
            tasks.push(tokio::spawn(async move {
                create(&db, &host, "!r:e", Kind::Single, 1, &limits(5, 1, 100)).await
            }));
        }
        let mut created = 0;
        for t in tasks {
            if matches!(t.await.unwrap(), CreateOutcome::Created { .. }) {
                created += 1;
            }
        }
        assert_eq!(created, 5);
        assert_eq!(db.list_guest_invites(&host).await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn only_the_creator_can_revoke_and_it_is_idempotent() {
        let Some(db) = crate::test_support::redis().await else {
            return;
        };
        let (a, b) = (format!("a{}", nonce()), format!("b{}", nonce()));
        let l = limits(5, 1, 20);
        create(&db, &a, "!r:e", Kind::Single, 1, &l).await;
        let id = db.list_guest_invites(&a).await.unwrap()[0].id.clone();
        assert!(
            !db.revoke_guest_invite(&b, &id).await.unwrap(),
            "host B cannot end host A's invite"
        );
        assert_eq!(db.list_guest_invites(&a).await.unwrap()[0].state, "active");
        assert!(db.revoke_guest_invite(&a, &id).await.unwrap());
        assert!(db.revoke_guest_invite(&a, &id).await.unwrap());
        assert_eq!(db.list_guest_invites(&a).await.unwrap()[0].state, "revoked");
        assert!(db.list_guest_invites(&b).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ending_a_meeting_revokes_only_that_room_of_that_host() {
        let Some(db) = crate::test_support::redis().await else {
            return;
        };
        let (a, b) = (format!("a{}", nonce()), format!("b{}", nonce()));
        let l = limits(10, 1, 20);
        create(&db, &a, "!one:e", Kind::Single, 2, &l).await;
        create(&db, &a, "!two:e", Kind::Single, 1, &l).await;
        create(&db, &b, "!one:e", Kind::Single, 1, &l).await;
        assert_eq!(
            db.revoke_guest_invites_for_room(&a, "!one:e")
                .await
                .unwrap(),
            2
        );
        let states: Vec<_> = db
            .list_guest_invites(&a)
            .await
            .unwrap()
            .into_iter()
            .map(|i| (i.room_id, i.state))
            .collect();
        assert!(states.contains(&("!one:e".into(), "revoked".into())));
        assert!(states.contains(&("!two:e".into(), "active".into())));
        assert_eq!(db.list_guest_invites(&b).await.unwrap()[0].state, "active");
        assert_eq!(
            db.revoke_guest_invites_for_room(&a, "!none:e")
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_guest_record_without_promoted_at_is_a_guest() {
        let Some(db) = crate::test_support::redis().await else {
            return;
        };
        let lp = format!("g{}", nonce());
        assert!(!db.is_unpromoted_guest(&lp).await.unwrap());
        let mut conn = db.pool.get().await.unwrap();
        let _: i64 = cmd("HSET")
            .arg(guest_account_key(&lp))
            .arg("state")
            .arg("active")
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(db.is_unpromoted_guest(&lp).await.unwrap());
        let _: i64 = cmd("HSET")
            .arg(guest_account_key(&lp))
            .arg("promoted_at")
            .arg("1")
            .query_async(&mut *conn)
            .await
            .unwrap();
        assert!(!db.is_unpromoted_guest(&lp).await.unwrap());
        let _: i64 = cmd("DEL")
            .arg(guest_account_key(&lp))
            .query_async(&mut *conn)
            .await
            .unwrap();
    }
}
