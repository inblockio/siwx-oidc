// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bb8_redis::{
    bb8::{self, Pool},
    redis::AsyncCommands,
    RedisConnectionManager,
};
use tracing::debug;

use crate::redact::{fingerprint, redact_key};
use url::Url;

use super::tokens::digest;
use super::*;

// `TOMBSTONE_TTL_SECS` now lives in `super` (db/mod.rs), next to
// `ACCESS_TOKEN_TTL`, so the const assertion tying the two together can see both.
// It reaches here via the `use super::*` above.

#[derive(Clone)]
pub struct RedisClient {
    pub(super) pool: Pool<RedisConnectionManager>,
    /// The operator's absolute-lifetime caps (I6); none by default. Set with
    /// [`RedisClient::with_grant_lifetime`].
    pub(super) lifetime: super::grant::GrantLifetime,
    /// Whether a reuse event revokes its grant (I5 phase B); off by default.
    /// Set with [`RedisClient::with_reuse_enforcement`].
    pub(super) reuse_revokes_grant: bool,
}

/// Redis key for the per-`(username, device_id)` token index SET.
pub(super) fn device_token_idx_key(username: &str, device_id: &str) -> String {
    format!("{}/{}/{}", KV_DEVICE_TOKEN_IDX_PREFIX, username, device_id)
}

/// Redis key for the short-lived device-revoked tombstone.
pub(super) fn device_tombstone_key(username: &str, device_id: &str) -> String {
    format!("{}/{}/{}", KV_DEVICE_TOMBSTONE_PREFIX, username, device_id)
}

/// Redis key for the per-user deactivation tombstone.
pub(super) fn user_tombstone_key(username: &str) -> String {
    format!("{}/{}", KV_USER_TOMBSTONE_PREFIX, username)
}

/// Redis key for the durable erasure marker of a localpart.
fn erased_user_key(localpart: &str) -> String {
    format!("{}/{}", KV_ERASED_USER_PREFIX, localpart)
}

/// Redis key for the durable erasure marker of a DID: the SHA-256 of its
/// canonical form (`mxid::canonicalize`), so the case variants of one `did:pkh`
/// share a marker and the DID itself is not kept in cleartext.
fn erased_did_key(did: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(crate::mxid::canonicalize(did).as_bytes());
    format!("{}/{}", KV_ERASED_DID_PREFIX, hex::encode(digest))
}

/// Read and delete a single-use entry in one atomic step, in either layout.
///
/// `KEYS[1]` is the digest key, `KEYS[2]` the raw key a build before digest
/// keys used, and the optional `KEYS[3]` a marker such a build set on an entry
/// it had used without deleting it (`codes/{raw}/consumed`). Returns the entry
/// only to the one caller that deletes it, and a legacy entry only when no
/// marker exists. Nothing is written, so a miss stores nothing.
const TAKE_SCRIPT: &str = r#"
local entry = redis.call('GET', KEYS[1])
if entry then
  redis.call('DEL', KEYS[1])
  return entry
end
entry = redis.call('GET', KEYS[2])
if not entry then
  return false
end
redis.call('DEL', KEYS[2])
if KEYS[3] and redis.call('EXISTS', KEYS[3]) == 1 then
  return false
end
return entry
"#;

/// Set a single-use flag unless a build before digest keys already set its
/// raw-keyed twin. `KEYS[1]` the legacy flag, `KEYS[2]` the digest flag,
/// `ARGV[1]` its TTL in seconds. Returns 1 to the one caller that set it.
const CLAIM_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
if redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[1]) then
  return 1
end
return 0
"#;

/// Replace a client entry by its digest-only form only while it is still
/// exactly the entry that was read, keeping its expiry. `KEYS[1]` the entry,
/// `ARGV[1]` the value read, `ARGV[2]` its digest-only form. A concurrent
/// upgrade (same result) or update (newer metadata) wins, so no reader sees a
/// half-upgraded entry and no field is lost. Returns 1 when it replaced it.
const UPGRADE_CLIENT_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
  return 0
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[2])
end
return 1
"#;

/// Extend a client entry's expiry, and only while it has one. `KEYS[1]` the entry,
/// `ARGV[1]` the lifetime in seconds. `TTL` answers -1 for a key without an expiry (a
/// static client) and -2 for an absent key, and only a positive TTL is extended, so a
/// client that turns static or disappears between a check and the write is never given
/// an expiry. Returns 1 when it extended the entry.
const TOUCH_CLIENT_SCRIPT: &str = r#"
if redis.call('TTL', KEYS[1]) > 0 then
  return redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return 0
"#;

/// Write a client entry, deciding its lifetime on the key as it is. `KEYS[1]` the entry,
/// `ARGV[1]` the value, `ARGV[2]` the lifetime in seconds. `TTL` answers -1 for a key
/// without an expiry, which is a static client and stays that way; every other write, a
/// new key included, gets the full lifetime. One script, so the decision and the write
/// see the same key.
const SET_CLIENT_SCRIPT: &str = r#"
if redis.call('TTL', KEYS[1]) == -1 then
  redis.call('SET', KEYS[1], ARGV[1])
else
  redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
end
return 1
"#;

fn code_key(code: &str) -> String {
    format!("{KV_CODE_DIGEST_PREFIX}/{}", digest(code))
}

fn legacy_code_key(code: &str) -> String {
    format!("{KV_CODE_PREFIX}/{code}")
}

fn session_key(id: &str) -> String {
    format!("{KV_SESSION_DIGEST_PREFIX}/{}", digest(id))
}

fn legacy_session_key(id: &str) -> String {
    format!("{KV_SESSION_PREFIX}/{id}")
}

fn device_code_key(device_code_digest: &str) -> String {
    format!("{KV_DEVICE_CODE_DIGEST_PREFIX}/{device_code_digest}")
}

fn legacy_device_code_key(device_code: &str) -> String {
    format!("{KV_LEGACY_DEVICE_CODE_PREFIX}/{device_code}")
}

fn user_code_key(user_code_digest: &str) -> String {
    format!("{KV_USER_CODE_DIGEST_PREFIX}/{user_code_digest}")
}

fn legacy_user_code_key(user_code: &str) -> String {
    format!("{KV_LEGACY_USER_CODE_PREFIX}/{user_code}")
}

/// The key a looked-up device code's entry is stored under.
fn stored_device_code_key(device_code: &DeviceCodeRef) -> String {
    match &device_code.legacy {
        Some(raw) => legacy_device_code_key(raw),
        None => device_code_key(&device_code.digest),
    }
}

fn caip122_nonce_key(category: &str, nonce: &str) -> String {
    format!(
        "{KV_CAIP122_NONCE_DIGEST_PREFIX}/{category}/{}",
        digest(nonce)
    )
}

fn legacy_caip122_nonce_key(category: &str, nonce: &str) -> String {
    format!("{KV_CAIP122_NONCE_PREFIX}/{category}/{nonce}")
}

fn own_session_key(kind: OwnSession, token: &str) -> String {
    format!("{}/{}", kind.prefix(), digest(token))
}

fn legacy_own_session_key(kind: OwnSession, token: &str) -> String {
    format!("{}/{token}", kind.legacy_prefix())
}

/// The index of a DID's own sessions, keyed by the digest of the canonical
/// DID, so a `did:pkh` address in any case finds the same index and the key
/// carries no DID.
fn own_session_idx_key(did: &str) -> String {
    format!(
        "{KV_OWN_SESSION_IDX_PREFIX}/{}",
        digest(&crate::mxid::canonicalize(did))
    )
}

/// Store an own session and index it under its DID, in one step. `KEYS[1]`
/// the session key, `KEYS[2]` the DID's index; `ARGV[1]` the value, `ARGV[2]`
/// the lifetime in seconds. The index entry's score is the session's expiry
/// (Redis `TIME`, ms); entries already expired are pruned, and the index lives
/// as long as its longest session.
const CREATE_OWN_SESSION: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl_ms = tonumber(ARGV[2]) * 1000
redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl_ms)
redis.call('ZADD', KEYS[2], now + ttl_ms, KEYS[1])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('PTTL', KEYS[2]) < ttl_ms then
  redis.call('PEXPIRE', KEYS[2], ttl_ms)
end
return 1
"#;

/// End every session a DID's index names, and the index. `KEYS[1]` the
/// index. Returns how many sessions were removed.
const REVOKE_OWN_SESSIONS: &str = r#"
local n = 0
for _, key in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
  n = n + redis.call('DEL', key)
end
redis.call('DEL', KEYS[1])
return n
"#;

fn ceremony_key(ceremony: Ceremony, id: &str) -> String {
    format!("{}/{}", ceremony.prefix(), digest(id))
}

fn legacy_ceremony_key(ceremony: Ceremony, id: &str) -> String {
    format!("{}/{id}", ceremony.legacy_prefix())
}

impl RedisClient {
    /// Run [`TAKE_SCRIPT`] over a digest key, its legacy twin and an optional
    /// legacy used-marker.
    async fn take(&self, keys: &[&str]) -> Result<Option<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let mut cmd = bb8_redis::redis::cmd("EVAL");
        cmd.arg(TAKE_SCRIPT).arg(keys.len()).arg(keys);
        cmd.query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to take a single-use entry: {}", e))
    }

    /// Run [`CLAIM_SCRIPT`]: set `flag` for `ttl` seconds unless `legacy_flag`
    /// exists; true for the one caller that set it.
    async fn claim(&self, legacy_flag: &str, flag: &str, ttl: u64) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let won: i64 = bb8_redis::redis::cmd("EVAL")
            .arg(CLAIM_SCRIPT)
            .arg(2)
            .arg(legacy_flag)
            .arg(flag)
            .arg(ttl)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to claim a single-use flag: {}", e))?;
        Ok(won == 1)
    }

    /// The value at a digest key, else at its legacy twin, read in one step:
    /// `(value, found_in_legacy)`.
    async fn get_either(&self, key: &str, legacy_key: &str) -> Result<Option<(String, bool)>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let (current, legacy): (Option<String>, Option<String>) = bb8_redis::redis::cmd("MGET")
            .arg(key)
            .arg(legacy_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to read {}: {}", redact_key(key), e))?;
        Ok(current
            .map(|v| (v, false))
            .or_else(|| legacy.map(|v| (v, true))))
    }

    /// Read a device code's entry by its digest key and, for a raw device code
    /// that may be a legacy one, its `device_codes/{raw}` key. The returned
    /// reference names the layout the entry was found in.
    async fn read_device_code(
        &self,
        device_code_digest: &str,
        raw: Option<&str>,
    ) -> Result<Option<(DeviceCodeRef, DeviceCodeEntry)>> {
        let key = device_code_key(device_code_digest);
        let found = match raw {
            Some(raw) => self.get_either(&key, &legacy_device_code_key(raw)).await?,
            None => self.get_raw(&key).await?.map(|v| (v, false)),
        };
        let Some((value, in_legacy)) = found else {
            return Ok(None);
        };
        let entry = DeviceCodeEntry::from_stored(&value)
            .map_err(|e| anyhow!("Failed to deserialize DeviceCodeEntry: {}", e))?;
        let device_ref = DeviceCodeRef {
            digest: device_code_digest.to_string(),
            legacy: raw.filter(|_| in_legacy).map(str::to_string),
        };
        Ok(Some((device_ref, entry)))
    }

    /// Store the state of a WebAuthn ceremony under the digest of the ceremony
    /// id the client holds, for `ttl_secs`.
    pub async fn put_ceremony_state(
        &self,
        ceremony: Ceremony,
        id: &str,
        state: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        self.set_ex_raw(&ceremony_key(ceremony, id), state, ttl_secs)
            .await
    }

    /// Read and delete a ceremony's state in one step, so a challenge is used
    /// at most once. A ceremony a build before digest keys started (raw id)
    /// is read for its remaining lifetime.
    pub async fn take_ceremony_state(
        &self,
        ceremony: Ceremony,
        id: &str,
    ) -> Result<Option<String>> {
        self.take(&[
            &ceremony_key(ceremony, id),
            &legacy_ceremony_key(ceremony, id),
        ])
        .await
    }

    pub async fn new(url: &Url) -> Result<Self> {
        let manager = RedisConnectionManager::new(url.as_str())
            .context("Could not build Redis connection manager")?;
        let pool = bb8::Pool::builder()
            .build(manager.clone())
            .await
            .context("Could not build Redis pool")?;
        Ok(Self {
            pool,
            lifetime: Default::default(),
            reuse_revokes_grant: false,
        })
    }
}

/// Generic Redis helpers for non-DBClient storage (WebAuthn credentials, challenges, etc.).
impl RedisClient {
    /// Store a key-value pair with a TTL in seconds.
    pub async fn set_ex_raw(&self, key: &str, value: &str, ttl_secs: u64) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        conn.set_ex::<_, _, ()>(key, value, ttl_secs)
            .await
            .map_err(|e| anyhow!("Redis SET EX: {}", e))?;
        Ok(())
    }

    /// Store a key-value pair with no TTL (persistent).
    pub async fn set_raw(&self, key: &str, value: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        conn.set::<_, _, ()>(key, value)
            .await
            .map_err(|e| anyhow!("Redis SET: {}", e))?;
        Ok(())
    }

    /// Get a value by key.
    pub async fn get_raw(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        let val: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| anyhow!("Redis GET: {}", e))?;
        Ok(val)
    }

    /// List keys matching a glob pattern.
    pub async fn keys_raw(&self, pattern: &str) -> Result<Vec<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| anyhow!("Redis KEYS: {}", e))?;
        Ok(keys)
    }

    /// Delete a key.
    pub async fn del_raw(&self, key: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        conn.del::<_, ()>(key)
            .await
            .map_err(|e| anyhow!("Redis DEL: {}", e))?;
        Ok(())
    }

    /// Remaining TTL of a key in seconds: `-1` when it has none, `-2` when it is absent.
    pub async fn ttl_raw(&self, key: &str) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        bb8_redis::redis::cmd("TTL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Redis TTL: {}", e))
    }

    /// Set a key's TTL in seconds. Tests use it to age an entry.
    pub async fn expire_raw(&self, key: &str, ttl_secs: i64) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        conn.expire::<_, ()>(key, ttl_secs)
            .await
            .map_err(|e| anyhow!("Redis EXPIRE: {}", e))
    }

    /// Add `member` to the Redis SET at `key` (idempotent; SADD of an existing
    /// member is a no-op). Mirrors the command-issue pattern of the other raw
    /// helpers so callers stay free of the bb8/redis types.
    pub async fn sadd_raw(&self, key: &str, member: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        conn.sadd::<_, _, ()>(key, member)
            .await
            .map_err(|e| anyhow!("Redis SADD: {}", e))?;
        Ok(())
    }

    /// Remove `member` from the Redis SET at `key` (idempotent; SREM of an absent
    /// member is a no-op). Returns the number of members removed (0 or 1).
    pub async fn srem_raw(&self, key: &str, member: &str) -> Result<usize> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        let removed: usize = conn
            .srem(key, member)
            .await
            .map_err(|e| anyhow!("Redis SREM: {}", e))?;
        Ok(removed)
    }

    /// Return every member of the Redis SET at `key` (empty vec if the key is
    /// absent, which Redis treats as the empty set).
    pub async fn smembers_raw(&self, key: &str) -> Result<Vec<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        let members: Vec<String> = conn
            .smembers(key)
            .await
            .map_err(|e| anyhow!("Redis SMEMBERS: {}", e))?;
        Ok(members)
    }

    /// Revoke (delete) every stored OAuth token for the given Matrix `username`
    /// (localpart) and `device_id`. Returns the number of tokens removed.
    ///
    /// This implements the authorization-server side of MSC4191
    /// `device_delete`: removing the access/refresh tokens makes introspection
    /// report the session inactive, so the device can no longer use the C-S API.
    ///
    /// Matching is keyed on `username` (the localpart `resolve_identity`
    /// resolved for this DID — grandfathered legacy or modern, whichever
    /// Synapse actually has the account under; see the `localpart` module)
    /// rather than the raw DID, so revocation is
    /// robust to address-case differences between the original sign-in DID and
    /// the re-authentication DID.
    ///
    /// Revocation is **atomic and race-free** (S3-3 / H3): a single Lua script
    /// reads the per-`(username, device_id)` index SET, deletes every member token
    /// plus the index itself, and plants a short-lived *device-revoked tombstone*
    /// — all in one Redis round trip (Redis runs Lua single-threaded, so no
    /// concurrent writer can interleave). The tombstone closes the residual
    /// window: a token refresh that *started* before the sweep but completes just
    /// after it consults the tombstone and refuses, so no resurrected token
    /// survives an explicit sign-out.
    ///
    /// A best-effort legacy keyspace scan runs afterwards as a backstop for any
    /// pre-index token (e.g. minted before an upgrade); it never re-creates the
    /// race because the tombstone already blocks new mints.
    pub async fn revoke_device_tokens(&self, username: &str, device_id: &str) -> Result<usize> {
        // The grants of the device first (one atomic script that also plants
        // the tombstone): deleting a grant makes all its tokens inert at once.
        // The legacy index and scan below catch `token/{raw}` entries written
        // before the grant record.
        let revoked_grants = self.revoke_grants_for_device(username, device_id).await?;
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;

        // Atomic: delete every indexed token + the index + set the tombstone in
        // ONE server-side Lua call (Redis runs Lua single-threaded, so no
        // concurrent writer interleaves). Issued via raw EVAL so no extra crate
        // feature is required. KEYS[1] = index set, KEYS[2] = tombstone.
        // ARGV[1] = tombstone TTL.
        const REVOKE_LUA: &str = r#"
            local members = redis.call('SMEMBERS', KEYS[1])
            local n = 0
            for _, k in ipairs(members) do
              n = n + redis.call('DEL', k)
            end
            redis.call('DEL', KEYS[1])
            redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[1]))
            return n
        "#;
        let idx_key = device_token_idx_key(username, device_id);
        let tomb_key = device_tombstone_key(username, device_id);
        let revoked_idx: usize = bb8_redis::redis::cmd("EVAL")
            .arg(REVOKE_LUA)
            .arg(2) // numkeys
            .arg(&idx_key)
            .arg(&tomb_key)
            .arg(TOMBSTONE_TTL_SECS)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("revoke_device_tokens Lua failed: {}", e))?;
        drop(conn);

        // Backstop: catch any token not present in the index (pre-upgrade tokens).
        let revoked_scan = self
            .revoke_tokens_where(|meta| meta.username == username && meta.device_id == device_id)
            .await
            .unwrap_or(0);

        let revoked = revoked_grants + revoked_idx + revoked_scan;
        debug!(
            username,
            device_id, revoked_grants, revoked_idx, revoked_scan, revoked, "revoke_device_tokens"
        );
        Ok(revoked)
    }

    /// Revoke every stored OAuth token for `username` (localpart), across all devices.
    /// Returns the count removed. Used by MSC4191 account_deactivate: after Synapse
    /// deactivates the account, removing all tokens makes introspection report every
    /// session inactive.
    ///
    /// Like [`revoke_device_tokens`](Self::revoke_device_tokens) this keys on
    /// `username` (the localpart `resolve_identity` resolved for this DID —
    /// grandfathered legacy or modern, whichever Synapse actually has the
    /// account under) so it is
    /// robust to address-case differences between sign-in and re-auth DIDs.
    ///
    /// **Race-free (S3-4 / H6, I9):** the script that deletes the user's grants
    /// sets the user epoch in the same atomic step, so a refresh racing the
    /// sweep is refused by the epoch whichever runs first; the callers
    /// `account_deactivate`/`account_erase` also set it via
    /// [`set_user_epoch`](Self::set_user_epoch) before asking Synapse. The
    /// legacy scan loops until a pass finds zero tokens; no legacy token can be
    /// minted any more, so the loop terminates.
    pub async fn revoke_all_user_tokens(&self, username: &str) -> Result<usize> {
        // The user epoch and every grant of the user, in one atomic script:
        // the epoch refuses every grant authenticated until now (I9), wherever
        // it is. The loop below is the backstop for legacy `token/{raw}`
        // entries written before the grant record; an epoch refuses those too
        // (their `iat` is before it), but they are deleted all the same.
        let mut total = self.revoke_grants_for_user(username).await?;
        for _ in 0..5 {
            let n = self
                .revoke_tokens_where(|meta| meta.username == username)
                .await?;
            total += n;
            if n == 0 {
                break;
            }
        }
        debug!(
            "revoke_all_user_tokens: username={} revoked={}",
            username, total
        );
        Ok(total)
    }

    /// Set the user epoch (I9) so every grant of this user authenticated
    /// until now is refused at once by both refresh endpoints and the access
    /// check. Set FIRST, before Synapse is asked and before the
    /// `revoke_all_user_tokens` sweep (which sets it again, later), by
    /// `account_deactivate`/`account_erase` (S3-4 / H6). Replaces the user
    /// tombstone, which also refused sign-ins made after it for 900 s.
    pub async fn set_user_epoch(&self, username: &str) -> Result<()> {
        self.set_epoch(super::grant::EpochScope::User(username))
            .await
            .map(|_| ())
    }

    /// Record, with no TTL, that the account `localpart` of `did` is being
    /// erased. Written BEFORE Synapse is asked to erase, so an erasure that
    /// succeeds always has a marker. Keyed twice, by the localpart Synapse
    /// knows the account under and by the canonical DID the user signs with,
    /// so a later change in how the DID resolves cannot slip past it.
    pub async fn mark_account_erased(&self, localpart: &str, did: &str) -> Result<()> {
        let at = chrono::Utc::now().to_rfc3339();
        self.set_raw(&erased_user_key(localpart), &at).await?;
        self.set_raw(&erased_did_key(did), &at).await
    }

    /// Whether the account `localpart` of `did` carries an erasure marker
    /// (either key). An `Err` means "unknown", and a caller deciding whether an
    /// account may come back must treat it as a refusal.
    pub async fn is_account_erased(&self, localpart: &str, did: &str) -> Result<bool> {
        if self.get_raw(&erased_user_key(localpart)).await?.is_some() {
            return Ok(true);
        }
        Ok(self.get_raw(&erased_did_key(did)).await?.is_some())
    }

    /// Purge a user's WebAuthn identity artifacts so the DID cannot be silently
    /// re-derived after account erasure. Returns the total number of Redis keys
    /// removed (links + credentials).
    ///
    /// Two passes, both best-effort and idempotent:
    ///
    /// (a) **Linked credentials (MUST):** scan `webauthn:link/*`; for each entry
    ///     whose `primary_did` equals `did`, delete the link AND the credential
    ///     it points at (`webauthn:credential/{cred_id}`, where `cred_id` is the
    ///     link key's suffix). This is the path that maps a passkey back to a
    ///     wallet DID, so it is the load-bearing case.
    ///
    /// (b) **Standalone credentials (BEST-EFFORT):** scan `webauthn:credential/*`
    ///     and delete any whose stored passkey derives to this exact `did:key`.
    ///     The P-256 -> `did:key:zDn…` derivation lives in the webauthn layer
    ///     (which owns the webauthn-rs types), so the caller passes a `derive`
    ///     resolver mapping a stored credential JSON to its derived DID; this
    ///     keeps the DB layer free of a webauthn-rs dependency. A resolver that
    ///     always returns `None` cleanly limits the purge to part (a).
    ///
    /// Credentials already removed in pass (a) are skipped in pass (b) (they no
    /// longer exist), so the count never double-counts.
    pub async fn purge_identity<F>(&self, did: &str, derive: F) -> Result<usize>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut purged = 0usize;
        // Accumulate per-key errors instead of `?`-aborting mid-sweep (S3-4): a
        // single Redis hiccup must not leave the purge half-done while the caller
        // still claims "Erased". We complete the whole sweep, then surface a
        // partial failure so the caller can distinguish a clean erase from one
        // where artifacts may remain.
        let mut errors = 0usize;

        // -- (a) Linked credentials: webauthn:link/{cred_id} -> { primary_did } --
        let link_prefix = "webauthn:link/";
        let link_keys = self.keys_raw(&format!("{}*", link_prefix)).await?;
        for link_key in link_keys {
            let raw = match self.get_raw(&link_key).await {
                Ok(Some(v)) => v,
                Ok(None) => continue, // raced with another purge / expiry
                Err(e) => {
                    debug!(
                        "purge_identity: get link {} failed: {}",
                        redact_key(&link_key),
                        e
                    );
                    errors += 1;
                    continue;
                }
            };
            let link: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue, // not a link entry; leave it
            };
            if link.get("primary_did").and_then(|d| d.as_str()) != Some(did) {
                continue;
            }
            // The credential id is the link key's suffix.
            let cred_id = &link_key[link_prefix.len()..];
            let cred_key = format!("webauthn:credential/{}", cred_id);
            match self.get_raw(&cred_key).await {
                Ok(Some(_)) => match self.del_raw(&cred_key).await {
                    Ok(()) => purged += 1,
                    Err(e) => {
                        debug!(
                            "purge_identity: del cred {} failed: {}",
                            redact_key(&cred_key),
                            e
                        );
                        errors += 1;
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    debug!(
                        "purge_identity: get cred {} failed: {}",
                        redact_key(&cred_key),
                        e
                    );
                    errors += 1;
                }
            }
            match self.del_raw(&link_key).await {
                Ok(()) => purged += 1,
                Err(e) => {
                    debug!(
                        "purge_identity: del link {} failed: {}",
                        redact_key(&link_key),
                        e
                    );
                    errors += 1;
                }
            }
            // Keep the by_did reverse index consistent: drop this cred from the
            // DID's set (and the set itself once emptied). Best-effort — the index
            // is advisory, so a failure here must not mark the erase incomplete.
            if let Err(e) = self.index_remove_passkey(did, cred_id).await {
                debug!(
                    "purge_identity: index_remove_passkey {} failed: {}",
                    fingerprint(cred_id),
                    e
                );
            }
            // Delete-through: without this, an erased identity's passkey would
            // survive in aqua-auth's namespace the moment the dual-write flag is
            // on, and erasure would be incomplete. No-op when the flag is off.
            crate::credential_store::mirror_delete(did, cred_id).await;
        }

        // -- (b) Standalone credentials whose passkey derives to this did:key --
        let cred_prefix = "webauthn:credential/";
        let cred_keys = self.keys_raw(&format!("{}*", cred_prefix)).await?;
        for cred_key in cred_keys {
            let raw = match self.get_raw(&cred_key).await {
                Ok(Some(v)) => v,
                Ok(None) => continue, // already removed in pass (a) or expired
                Err(e) => {
                    debug!(
                        "purge_identity: get cred {} failed: {}",
                        redact_key(&cred_key),
                        e
                    );
                    errors += 1;
                    continue;
                }
            };
            if derive(&raw).as_deref() == Some(did) {
                match self.del_raw(&cred_key).await {
                    Ok(()) => purged += 1,
                    Err(e) => {
                        debug!(
                            "purge_identity: del cred {} failed: {}",
                            redact_key(&cred_key),
                            e
                        );
                        errors += 1;
                    }
                }
                // Keep the by_did reverse index consistent (best-effort, advisory).
                let cred_id = &cred_key[cred_prefix.len()..];
                if let Err(e) = self.index_remove_passkey(did, cred_id).await {
                    debug!(
                        "purge_identity: index_remove_passkey {} failed: {}",
                        fingerprint(cred_id),
                        e
                    );
                }
                // Delete-through, as in pass (a).
                crate::credential_store::mirror_delete(did, cred_id).await;
            }
        }

        debug!(
            "purge_identity: did={} purged={} errors={}",
            did, purged, errors
        );
        if errors > 0 {
            return Err(anyhow!(
                "purge_identity completed with {} error(s); {} artifact(s) purged \
                 (some identity artifacts may remain)",
                errors,
                purged
            ));
        }
        Ok(purged)
    }

    // -- webauthn:by_did reverse index ----------------------------------------
    //
    // `webauthn:by_did/{did}` is a Redis SET of the `cred_id_b64` values that
    // resolve to `did` (a derived `did:key` from `register_finish`, or a wallet
    // `primary_did` from `link_finish`). It lets a returning login scope the
    // passkey picker to one DID's keys with a single SMEMBERS instead of a full
    // credential keyspace scan. It is advisory: `get_passkeys_for_did` self-heals
    // from a read-only scan when the index is absent/empty, so a missed update
    // never causes a wrong answer — only a slower one until it back-fills.

    /// SADD `cred_id_b64` into the `webauthn:by_did/{did}` index. Called by
    /// `register_finish` (derived did:key) and `link_finish` (wallet primary_did)
    /// after the credential/link itself is stored. Idempotent.
    pub async fn index_add_passkey(&self, did: &str, cred_id_b64: &str) -> Result<()> {
        self.sadd_raw(
            &format!("{}/{}", KV_WEBAUTHN_BY_DID_PREFIX, did),
            cred_id_b64,
        )
        .await
    }

    /// SREM `cred_id_b64` from the `webauthn:by_did/{did}` index, and DEL the index
    /// key entirely once it is emptied so the keyspace stays clean. Called by
    /// `purge_identity` for every credential/link it removes. Idempotent.
    pub async fn index_remove_passkey(&self, did: &str, cred_id_b64: &str) -> Result<()> {
        let key = format!("{}/{}", KV_WEBAUTHN_BY_DID_PREFIX, did);
        self.srem_raw(&key, cred_id_b64).await?;
        // Drop the index key when it holds nothing, so an emptied DID leaves no
        // dangling SET behind (SMEMBERS of a missing key is the empty set anyway).
        if self.smembers_raw(&key).await?.is_empty() {
            self.del_raw(&key).await?;
        }
        Ok(())
    }

    /// Return the `cred_id_b64` values registered/linked for `did`.
    ///
    /// Fast path: read the `webauthn:by_did/{did}` SET (SMEMBERS). FALLBACK: when
    /// that index is absent/empty, run the read-only twin of `purge_identity`'s two
    /// scans to self-heal —
    ///
    /// (a) every `webauthn:link/{cred_id}` whose stored `primary_did == did`
    ///     (wallet-linked passkeys), and
    /// (b) every standalone `webauthn:credential/{cred_id}` whose stored passkey
    ///     `derive`s to this exact `did:key` (the resolver mirrors
    ///     `purge_identity`'s, keeping the DB layer free of webauthn-rs types).
    ///
    /// Results from the scan are best-effort populated back into the index (SADD)
    /// so the next call hits the fast path. A populate failure is non-fatal: the
    /// scan result is still returned. The fallback makes the index advisory rather
    /// than load-bearing, so a missed `index_add_passkey` cannot lose a passkey.
    ///
    /// Enumeration-safety: this is a server-side helper called only with a DID the
    /// server already resolved (from a valid opaque user-session); it never enables
    /// an unauthenticated caller to enumerate credentials.
    pub async fn get_passkeys_for_did<F>(&self, did: &str, derive: F) -> Result<Vec<String>>
    where
        F: Fn(&str) -> Option<String>,
    {
        let index_key = format!("{}/{}", KV_WEBAUTHN_BY_DID_PREFIX, did);
        let indexed = self.smembers_raw(&index_key).await?;
        if !indexed.is_empty() {
            return Ok(indexed);
        }

        // Index miss: self-heal from a read-only scan (the twin of purge_identity).
        let mut found: Vec<String> = Vec::new();

        // (a) Linked credentials: webauthn:link/{cred_id} -> { primary_did }.
        let link_prefix = "webauthn:link/";
        let link_keys = self.keys_raw(&format!("{}*", link_prefix)).await?;
        for link_key in link_keys {
            let raw = match self.get_raw(&link_key).await {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    debug!(
                        "get_passkeys_for_did: get link {} failed: {}",
                        redact_key(&link_key),
                        e
                    );
                    continue;
                }
            };
            let link: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if link.get("primary_did").and_then(|d| d.as_str()) == Some(did) {
                let cred_id = link_key[link_prefix.len()..].to_string();
                if !found.contains(&cred_id) {
                    found.push(cred_id);
                }
            }
        }

        // (b) Standalone credentials whose passkey derives to this did:key.
        let cred_prefix = "webauthn:credential/";
        let cred_keys = self.keys_raw(&format!("{}*", cred_prefix)).await?;
        for cred_key in cred_keys {
            let raw = match self.get_raw(&cred_key).await {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    debug!(
                        "get_passkeys_for_did: get cred {} failed: {}",
                        redact_key(&cred_key),
                        e
                    );
                    continue;
                }
            };
            if derive(&raw).as_deref() == Some(did) {
                let cred_id = cred_key[cred_prefix.len()..].to_string();
                if !found.contains(&cred_id) {
                    found.push(cred_id);
                }
            }
        }

        // Best-effort back-fill so subsequent calls hit the fast path. Never fatal.
        for cred_id in &found {
            if let Err(e) = self.sadd_raw(&index_key, cred_id).await {
                debug!("get_passkeys_for_did: back-fill SADD failed: {}", e);
                break;
            }
        }

        debug!(
            "get_passkeys_for_did: did={} index_miss scanned={}",
            did,
            found.len()
        );
        Ok(found)
    }

    // -- siwx-oidc's own sessions (`siwx_user`, `acct_session`) -----------------
    //
    // The picker hint's value is just the DID and carries no CSRF (it only scopes
    // the passkey picker, it never authorizes a state change); the account
    // session's value is its JSON. Tokens are OPAQUE (two random UUIDs), so a
    // forged or guessed value is a Redis miss -> None -> usernameless fallback.
    // This is the load-bearing enumeration-safety invariant: the identity hint
    // can never be a client-supplied plaintext DID.

    /// Mint an own session of `kind` bound to `did` with `value`, for
    /// `ttl_secs`, and return the opaque token to Set-Cookie. The entry is
    /// keyed by the token's digest (I1) and indexed under the DID, in one
    /// script, so [`revoke_own_sessions`](Self::revoke_own_sessions) finds it.
    pub async fn create_own_session(
        &self,
        kind: OwnSession,
        did: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<String> {
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let _: i64 = self
            .eval(
                CREATE_OWN_SESSION,
                &[&own_session_key(kind, &token), &own_session_idx_key(did)],
                &[value, &ttl_secs.to_string()],
            )
            .await?;
        Ok(token)
    }

    /// The stored value of an own session, or `None` for an unknown, expired
    /// or forged token. A session a build before Phase 4 stored by its raw
    /// token is read for its remaining lifetime. Two reads, not one `MGET`,
    /// so a fault at either key is an error rather than a miss.
    pub async fn lookup_own_session(
        &self,
        kind: OwnSession,
        token: &str,
    ) -> Result<Option<String>> {
        if let Some(value) = self.get_raw(&own_session_key(kind, token)).await? {
            return Ok(Some(value));
        }
        // TODO(remove with the legacy own-session layout, see `OwnSession`).
        self.get_raw(&legacy_own_session_key(kind, token)).await
    }

    /// End one own session (this browser's), whichever layout it is in. Its
    /// index entry stays until it expires or the DID's sessions are revoked;
    /// it names a key that no longer exists.
    pub async fn end_own_session(&self, kind: OwnSession, token: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;
        let _: i64 = bb8_redis::redis::cmd("DEL")
            .arg(own_session_key(kind, token))
            .arg(legacy_own_session_key(kind, token))
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to end an own session: {}", e))?;
        Ok(())
    }

    /// End every own session of `did`, of both kinds: `logout/all`,
    /// deactivation and erasure. Returns how many entries were removed. The
    /// DID is compared canonically ([`crate::mxid::canonicalize`]), so a
    /// `did:pkh` address signed in with another case is the same user.
    ///
    /// Current sessions go through the DID's index in one script. Sessions a
    /// build before Phase 4 stored by raw token have no index and are found by
    /// a scan of their prefix. TODO(remove with the legacy own-session layout).
    pub async fn revoke_own_sessions(&self, did: &str) -> Result<usize> {
        let mut revoked: i64 = self
            .eval(REVOKE_OWN_SESSIONS, &[&own_session_idx_key(did)], &[])
            .await?;
        let canonical = crate::mxid::canonicalize(did);
        for kind in [OwnSession::PickerHint, OwnSession::Account] {
            for key in self
                .keys_raw(&format!("{}/*", kind.legacy_prefix()))
                .await?
            {
                let Some(value) = self.get_raw(&key).await? else {
                    continue;
                };
                if kind
                    .did_of(&value)
                    .is_some_and(|d| crate::mxid::canonicalize(&d) == canonical)
                {
                    self.del_raw(&key).await?;
                    revoked += 1;
                }
            }
        }
        debug!(revoked, "revoke_own_sessions");
        Ok(revoked as usize)
    }

    /// Mint an opaque login user-session (the `siwx_user` picker hint) bound to
    /// `did` for [`USER_SESSION_LIFETIME`], and return the token to Set-Cookie.
    pub async fn create_user_session(&self, did: &str) -> Result<String> {
        self.create_own_session(OwnSession::PickerHint, did, did, USER_SESSION_LIFETIME)
            .await
    }

    /// Resolve an opaque login user-session token to its DID, or `None` if the
    /// token is unknown/expired (a forged or guessed token lands here -> the caller
    /// falls back to usernameless discoverable login, leaking nothing).
    pub async fn lookup_user_session(&self, token: &str) -> Result<Option<String>> {
        self.lookup_own_session(OwnSession::PickerHint, token).await
    }

    /// Delete an opaque login user-session (the account page's sign-out).
    pub async fn destroy_user_session(&self, token: &str) -> Result<()> {
        self.end_own_session(OwnSession::PickerHint, token).await
    }

    /// Scan the token keyspace (`KV_TOKEN_PREFIX`) and delete every entry whose
    /// [`TokenMetadata`] satisfies `pred`, returning the number removed.
    ///
    /// There is no secondary index on token metadata, so this scans the keyspace.
    /// The volume is bounded (access tokens have a short TTL; refresh tokens are
    /// the only long-lived entries), so a full scan is acceptable. Callers log
    /// the removed count so a large sweep is never silent.
    async fn revoke_tokens_where<F>(&self, pred: F) -> Result<usize>
    where
        F: Fn(&TokenMetadata) -> bool,
    {
        let keys = self.keys_raw(&format!("{}/*", KV_TOKEN_PREFIX)).await?;
        let mut revoked = 0usize;
        for key in keys {
            let raw = match self.get_raw(&key).await? {
                Some(v) => v,
                None => continue, // expired between KEYS and GET
            };
            let meta: TokenMetadata = match serde_json::from_str(&raw) {
                Ok(m) => m,
                Err(_) => continue, // not a token entry / unparseable; leave it
            };
            if pred(&meta) {
                self.del_raw(&key).await?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }
}

impl RedisClient {
    /// [`DBClient::sync_static_clients`] against an explicit tracking set, so a test can
    /// use its own set and never prune the static clients of a running stack.
    async fn sync_static_clients_in(
        &self,
        set_key: &str,
        clients: Vec<(String, ClientEntry)>,
    ) -> Result<usize> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let previous: Vec<String> = conn
            .smembers(set_key)
            .await
            .map_err(|e| anyhow!("Failed to read the static client set: {}", e))?;
        for (id, entry) in &clients {
            let value = serde_json::to_string(entry)
                .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?;
            // Tracked before it is written: a failure between the two commands then leaves a
            // tracked id without a client, which pruning handles, and never a client without
            // a TTL that nothing tracks.
            conn.sadd::<_, _, ()>(set_key, id)
                .await
                .map_err(|e| anyhow!("Failed to record a static client: {}", e))?;
            // A plain SET also clears a TTL that an older build wrote on this key.
            conn.set::<_, _, ()>(format!("{}/{}", KV_CLIENT_PREFIX, id), value)
                .await
                .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        }
        let mut pruned = 0;
        for id in previous
            .iter()
            .filter(|id| !clients.iter().any(|(kept, _)| kept == *id))
        {
            conn.del::<_, ()>(format!("{}/{}", KV_CLIENT_PREFIX, id))
                .await
                .map_err(|e| anyhow!("Failed to delete a removed static client: {}", e))?;
            conn.srem::<_, _, ()>(set_key, id)
                .await
                .map_err(|e| anyhow!("Failed to untrack a removed static client: {}", e))?;
            pruned += 1;
        }
        Ok(pruned)
    }
}

#[async_trait]
impl DBClient for RedisClient {
    async fn server_time_ms(&self) -> Result<i64> {
        self.redis_time_ms().await
    }

    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        let _written: i64 = bb8_redis::redis::cmd("EVAL")
            .arg(SET_CLIENT_SCRIPT)
            .arg(1)
            .arg(format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .arg(
                serde_json::to_string(&client_entry)
                    .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
            )
            .arg(CLIENT_LIFETIME)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        Ok(())
    }

    async fn get_client(&self, client_id: String) -> Result<Option<ClientEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_CLIENT_PREFIX, client_id);
        let stored: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let value: serde_json::Value = serde_json::from_str(&stored)
            .map_err(|e| anyhow!("Failed to deserialize client entry: {}", e))?;
        // A plaintext entry (a build before digest keys wrote it) authenticates
        // as it is: it deserializes into its digests.
        let entry: ClientEntry = serde_json::from_value(value.clone())
            .map_err(|e| anyhow!("Failed to deserialize client entry: {}", e))?;
        // ...and is replaced by its digest-only form on this first read.
        // TODO(remove once no entry a build before Phase 2b wrote can be alive:
        // CLIENT_LIFETIME after the deploy).
        if let Some(upgraded) = client_entry_without_plaintext(&value) {
            let replaced: i64 = bb8_redis::redis::cmd("EVAL")
                .arg(UPGRADE_CLIENT_SCRIPT)
                .arg(1)
                .arg(&key)
                .arg(&stored)
                .arg(upgraded.to_string())
                .query_async(&mut *conn)
                .await
                .map_err(|e| anyhow!("Failed to upgrade a client entry: {}", e))?;
            debug!(client_id = %client_id, replaced, "client entry stored as digests");
        }
        Ok(Some(entry))
    }

    async fn delete_client(&self, client_id: String) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        conn.del::<_, ()>(format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .await
            .map_err(|e| anyhow!("Failed to delete kv: {}", e))?;
        Ok(())
    }

    async fn sync_static_clients(&self, clients: Vec<(String, ClientEntry)>) -> Result<usize> {
        self.sync_static_clients_in(KV_STATIC_CLIENTS_KEY, clients)
            .await
    }

    async fn touch_client(&self, client_id: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let _extended: i64 = bb8_redis::redis::cmd("EVAL")
            .arg(TOUCH_CLIENT_SCRIPT)
            .arg(1)
            .arg(format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .arg(CLIENT_LIFETIME)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to extend a client's lifetime: {}", e))?;
        Ok(())
    }

    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()> {
        let key = code_key(&code);
        let value = serde_json::to_string(&code_entry)
            .map_err(|e| anyhow!("Failed to serialize code entry: {}", e))?;
        self.set_ex_raw(&key, &value, ENTRY_LIFETIME as u64)
            .await
            .map_err(|e| anyhow!("Failed to set code in Redis: {}", e))?;
        debug!(
            "set_code: stored code_fp={} ttl={}s",
            fingerprint(&code),
            ENTRY_LIFETIME
        );
        Ok(())
    }

    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let value = serde_json::to_string(&entry)
            .map_err(|e| anyhow!("Failed to serialize session entry: {}", e))?;
        // A session a build before digest keys started moves to its digest key
        // on its first write, so its id leaves the store then. Nothing else is
        // keyed by the session: its signed-in flag is checked in both layouts.
        bb8_redis::redis::pipe()
            .atomic()
            .set_ex(session_key(&id), value, SESSION_LIFETIME)
            .ignore()
            .del(legacy_session_key(&id))
            .ignore()
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        Ok(())
    }

    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>> {
        match self
            .get_either(&session_key(&id), &legacy_session_key(&id))
            .await?
        {
            Some((e, _)) => Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize session entry: {}", e))?),
            None => Ok(None),
        }
    }

    async fn try_consume_code(&self, code: String) -> Result<Option<CodeEntry>> {
        // One atomic step reads and deletes the entry, so exactly one caller
        // ever receives it and no exchanged code stays in the store. A code the
        // previous build stored (`codes/{raw}`, 300 s) is consumed the same way,
        // and a `codes/{raw}/consumed` marker is what an older build left on a
        // code it had already exchanged (it never deleted the entry); such a
        // code is not handed out again.
        let legacy = legacy_code_key(&code);
        let marker = format!("{legacy}/consumed");
        let raw = self.take(&[&code_key(&code), &legacy, &marker]).await?;
        match raw {
            Some(e) => {
                debug!("try_consume_code: consumed code_fp={}", fingerprint(&code));
                Ok(Some(serde_json::from_str(&e).map_err(|e| {
                    anyhow!("Failed to deserialize code entry: {}", e)
                })?))
            }
            None => {
                debug!(
                    "try_consume_code: unknown or already consumed code_fp={}",
                    fingerprint(&code)
                );
                Ok(None)
            }
        }
    }

    async fn try_mark_session_signed_in(&self, id: String) -> Result<bool> {
        // Atomic: only one sign_in wins the flag, and a session the previous
        // build already signed in (`sessions/{raw}/signed_in`) stays signed in.
        self.claim(
            &format!("{}/signed_in", legacy_session_key(&id)),
            &format!("{}/signed_in", session_key(&id)),
            SESSION_LIFETIME,
        )
        .await
        .map_err(|e| anyhow!("Failed to set the signed_in flag: {}", e))
    }

    async fn try_claim_device_code(&self, device_code: &str) -> Result<bool> {
        // Atomic: SET .../redeemed 1 NX EX <ttl> — only the first poll wins, so
        // exactly one concurrent redemption issues tokens (S3-1 / H9). EX is part
        // of the same atomic SET (not a separate EXPIRE), so the claim cannot
        // leak. The claim is keyed by the digest whatever layout the entry is
        // in, and a claim the previous build made on the raw key counts.
        self.claim(
            &format!("{}/redeemed", legacy_device_code_key(device_code)),
            &format!("{}/redeemed", device_code_key(&digest(device_code))),
            DEVICE_CODE_LIFETIME,
        )
        .await
        .map_err(|e| anyhow!("Failed to claim a device code: {}", e))
    }

    async fn set_token(&self, token: &str, metadata: &TokenMetadata, ttl: u64) -> Result<()> {
        // Every endpoint accepts exactly one kind of token, so an entry without a
        // kind would be classified by lifetime instead of by its writer.
        if metadata.kind.is_none() {
            return Err(anyhow!("refusing to store a token without a kind"));
        }
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_TOKEN_PREFIX, token);
        let value = serde_json::to_string(metadata)
            .map_err(|e| anyhow!("Failed to serialize token metadata: {}", e))?;
        conn.set_ex::<_, _, ()>(&key, &value, ttl)
            .await
            .map_err(|e| anyhow!("Failed to SET EX token: {}", e))?;
        // Maintain the per-(username, device_id) secondary index so revocation is
        // an atomic O(members) delete rather than a racy keyspace scan (S3-3 / H3).
        // Standalone-mode tokens carry an empty device_id and are revoked by the
        // presented token only, so they are not indexed.
        if !metadata.device_id.is_empty() {
            let idx_key = device_token_idx_key(&metadata.username, &metadata.device_id);
            // SADD the token key, then bump the set TTL to outlive its longest
            // member (refresh-token TTL). One round trip via a pipeline-free Lua
            // would be tidier, but two simple commands are fine here and the
            // index is advisory (the legacy scan in revoke_tokens_where remains a
            // backstop).
            conn.sadd::<_, _, ()>(&idx_key, &key)
                .await
                .map_err(|e| anyhow!("Failed to SADD device token index: {}", e))?;
            conn.expire::<_, ()>(&idx_key, REFRESH_TOKEN_TTL as i64)
                .await
                .map_err(|e| anyhow!("Failed to EXPIRE device token index: {}", e))?;
        }
        debug!("set_token: stored key={} ttl={}s", redact_key(&key), ttl);
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<TokenMetadata>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_TOKEN_PREFIX, token);
        let entry: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to GET token: {}", e))?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_str(&e).map_err(|e| {
                anyhow!("Failed to deserialize token metadata: {}", e)
            })?)),
            None => Ok(None),
        }
    }

    async fn delete_token(&self, token: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_TOKEN_PREFIX, token);
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| anyhow!("Failed to DEL token: {}", e))?;
        Ok(())
    }

    // -- RFC 8628 device code storage -----------------------------------------

    async fn set_device_code(
        &self,
        device_code: &str,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()> {
        let key = device_code_key(&digest(device_code));
        let value = serde_json::to_string(entry)
            .map_err(|e| anyhow!("Failed to serialize DeviceCodeEntry: {}", e))?;
        self.set_ex_raw(&key, &value, ttl).await
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<(DeviceCodeRef, DeviceCodeEntry)>> {
        self.read_device_code(&digest(device_code), Some(device_code))
            .await
    }

    async fn update_device_code(
        &self,
        device_code: &DeviceCodeRef,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()> {
        let value = serde_json::to_string(entry)
            .map_err(|e| anyhow!("Failed to serialize DeviceCodeEntry: {}", e))?;
        self.set_ex_raw(&stored_device_code_key(device_code), &value, ttl)
            .await
    }

    async fn delete_device_code(&self, device_code: &DeviceCodeRef) -> Result<()> {
        self.del_raw(&stored_device_code_key(device_code)).await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<(DeviceCodeRef, DeviceCodeEntry)>> {
        let mapping = self
            .get_either(
                &user_code_key(&digest(user_code)),
                &legacy_user_code_key(user_code),
            )
            .await?;
        match mapping {
            // A new mapping holds the device code's digest.
            Some((device_code_digest, false)) => {
                self.read_device_code(&device_code_digest, None).await
            }
            // A legacy mapping holds the raw device code, whose entry is
            // `device_codes/{raw}`. TODO(remove one release after Phase 2b).
            Some((device_code, true)) => {
                self.read_device_code(&digest(&device_code), Some(&device_code))
                    .await
            }
            None => Ok(None),
        }
    }

    async fn set_user_code_mapping(
        &self,
        user_code: &str,
        device_code: &str,
        ttl: u64,
    ) -> Result<()> {
        self.set_ex_raw(
            &user_code_key(&digest(user_code)),
            &digest(device_code),
            ttl,
        )
        .await
    }

    async fn delete_user_code_mapping(&self, entry: &DeviceCodeEntry) -> Result<()> {
        match &entry.legacy_user_code {
            Some(user_code) => self.del_raw(&legacy_user_code_key(user_code)).await,
            None => self.del_raw(&user_code_key(&entry.user_code_digest)).await,
        }
    }

    // -- CAIP-122 server-issued single-use nonce store (C1) -------------------
    //
    // The device-approval (`POST /device`) and account (`POST /account/wallet`)
    // CAIP-122 paths must bind every accepted signature to a fresh, server-issued,
    // single-use nonce so a captured/replayed victim signature cannot approve an
    // attacker's device or drive an account action. This mirrors the login path,
    // which already binds the session nonce. Those two flows have no equivalent
    // session, so the nonce is minted on a dedicated GET (`/device/nonce`,
    // `/account/nonce`) and consumed here.
    //
    // The stored value is the *binding context* the nonce was minted for (the
    // device `user_code` or the account `action`). The consumer checks it, so a
    // nonce minted for one context cannot be redeemed for another (cross-context /
    // operation replay rejected). Single-use is enforced atomically via SETNX on a
    // companion `consumed` flag.

    async fn mint_caip122_nonce(&self, category: &str, binding: &str) -> Result<String> {
        // 16 random bytes hex-encoded (128 bits) — well above the login nonce.
        let nonce: String = {
            let mut bytes = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
            hex::encode(bytes)
        };
        self.set_ex_raw(
            &caip122_nonce_key(category, &nonce),
            binding,
            CAIP122_NONCE_TTL_SECS,
        )
        .await?;
        Ok(nonce)
    }

    async fn try_consume_caip122_nonce(
        &self,
        category: &str,
        nonce: &str,
    ) -> Result<Option<String>> {
        // Atomic: the first caller reads and deletes the entry; a replay finds
        // nothing. A nonce the previous build minted is consumed the same way,
        // unless its `/consumed` flag shows that build already consumed it.
        let legacy = legacy_caip122_nonce_key(category, nonce);
        let marker = format!("{legacy}/consumed");
        self.take(&[&caip122_nonce_key(category, nonce), &legacy, &marker])
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{erased_did_key, erased_user_key};
    use crate::db::tokens::digest;
    use crate::db::{
        Ceremony, CodeEntry, DBClient, DeviceCodeEntry, DeviceCodeStatus, OwnSession, SessionEntry,
        TokenKind, TokenMetadata, KV_CODE_PREFIX,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A globally-unique nonce for test keys on the shared Redis. The nanosecond
    /// clock alone can collide across tests that start in the same instant on
    /// different threads (observed when running only the two `revoke_*` tests as a
    /// pair); a process-wide atomic counter makes every nonce distinct regardless
    /// of scheduling, so tests are isolated for ANY subset, not just the full run.
    fn unique_nonce() -> u128 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Shift the wall-clock left and OR in a monotonically-increasing counter so
        // the suffix is unique even for same-nanosecond callers.
        (base << 20) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF)
    }

    fn token_meta(device_id: &str, username: &str) -> TokenMetadata {
        TokenMetadata {
            username: username.to_string(),
            device_id: device_id.to_string(),
            scope: "openid".to_string(),
            client_id: "c".to_string(),
            iat: 0,
            exp: i64::MAX,
            // did is stored verbatim from sign-in; revocation keys on username,
            // so the did case here intentionally differs from the username.
            did: format!("did:pkh:eip155:1:0X{}", username.to_uppercase()),
            name: "n".to_string(),
            kind: Some(TokenKind::Access),
        }
    }

    /// The store refuses a token entry without a kind: every writer sets one.
    #[tokio::test]
    async fn set_token_refuses_an_entry_without_a_kind() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let token = format!("kindless-{}", unique_nonce());
        let mut meta = token_meta("", "kindless");
        meta.kind = None;
        assert!(
            client.set_token(&token, &meta, 60).await.is_err(),
            "a token without a kind must not be stored"
        );
        assert!(client.get_token(&token).await.unwrap().is_none());
    }

    /// H5: device_delete must revoke ONLY the OAuth session(s) for the targeted
    /// (username, device_id), leaving other devices and other users untouched.
    /// Needs Redis (`crate::test_support::redis`).
    #[tokio::test]
    async fn revoke_device_tokens_removes_only_matching_session() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        // Unique per run so parallel tests / stale entries cannot interfere.
        let nonce = unique_nonce();
        let user = format!("user-{nonce}");
        let other_user = format!("other-{nonce}");
        let d1 = format!("DEV1_{nonce}");
        let d2 = format!("DEV2_{nonce}");
        let (t1, t2, t3) = (
            format!("tok1_{nonce}"),
            format!("tok2_{nonce}"),
            format!("tok3_{nonce}"),
        );

        client
            .set_token(&t1, &token_meta(&d1, &user), 120)
            .await
            .unwrap(); // match
        client
            .set_token(&t2, &token_meta(&d2, &user), 120)
            .await
            .unwrap(); // same user, other device
        client
            .set_token(&t3, &token_meta(&d1, &other_user), 120)
            .await
            .unwrap(); // other user, same device

        let revoked = client.revoke_device_tokens(&user, &d1).await.unwrap();
        assert_eq!(revoked, 1, "exactly the (user, d1) token must be revoked");
        assert!(
            client.get_token(&t1).await.unwrap().is_none(),
            "matching token must be gone"
        );
        assert!(
            client.get_token(&t2).await.unwrap().is_some(),
            "same-user different-device token must remain"
        );
        assert!(
            client.get_token(&t3).await.unwrap().is_some(),
            "different-user same-device token must remain"
        );

        // Best-effort cleanup.
        client.delete_token(&t2).await.ok();
        client.delete_token(&t3).await.ok();
    }

    /// MSC4191 account_deactivate must revoke EVERY OAuth session for the user
    /// (all devices), leaving other users untouched.
    /// Needs Redis (`crate::test_support::redis`).
    #[tokio::test]
    async fn revoke_all_user_tokens_removes_all_user_sessions() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        // Unique per run so parallel tests / stale entries cannot interfere.
        let nonce = unique_nonce();
        let user = format!("user-{nonce}");
        let other_user = format!("other-{nonce}");
        let d1 = format!("DEV1_{nonce}");
        let d2 = format!("DEV2_{nonce}");
        let (t1, t2, t3) = (
            format!("tok1_{nonce}"),
            format!("tok2_{nonce}"),
            format!("tok3_{nonce}"),
        );

        client
            .set_token(&t1, &token_meta(&d1, &user), 120)
            .await
            .unwrap(); // user, device 1
        client
            .set_token(&t2, &token_meta(&d2, &user), 120)
            .await
            .unwrap(); // user, device 2
        client
            .set_token(&t3, &token_meta(&d1, &other_user), 120)
            .await
            .unwrap(); // other user

        let revoked = client.revoke_all_user_tokens(&user).await.unwrap();
        assert_eq!(revoked, 2, "both of the user's tokens must be revoked");
        assert!(
            client.get_token(&t1).await.unwrap().is_none(),
            "user device-1 token must be gone"
        );
        assert!(
            client.get_token(&t2).await.unwrap().is_none(),
            "user device-2 token must be gone"
        );
        assert!(
            client.get_token(&t3).await.unwrap().is_some(),
            "different-user token must remain"
        );

        // Best-effort cleanup.
        client.delete_token(&t3).await.ok();
    }

    /// The erasure marker is durable (no TTL) and found by the localpart OR by
    /// any spelling of the DID that canonicalises to the marked one, and only
    /// for the account it was written for. Needs Redis
    /// (`crate::test_support::redis`).
    #[tokio::test]
    async fn an_erasure_marker_is_durable_and_found_by_localpart_or_canonical_did() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let nonce = unique_nonce();
        let localpart = format!("erased-{nonce}");
        let did = format!("did:pkh:eip155:1:0xAbC{nonce}");
        let other_did = format!("did:pkh:eip155:1:0xdef{nonce}");

        assert!(!client.is_account_erased(&localpart, &did).await.unwrap());
        client.mark_account_erased(&localpart, &did).await.unwrap();

        assert!(client.is_account_erased(&localpart, &did).await.unwrap());
        assert!(
            client
                .is_account_erased("some-other-localpart", &did.to_lowercase())
                .await
                .unwrap(),
            "a did:pkh case variant is the same account and must find the marker"
        );
        assert!(
            client
                .is_account_erased(&localpart, &other_did)
                .await
                .unwrap(),
            "the localpart alone must find the marker"
        );
        assert!(
            !client
                .is_account_erased(&format!("other-{nonce}"), &other_did)
                .await
                .unwrap(),
            "an unrelated account must not read as erased"
        );

        let mut conn = client.pool.get().await.unwrap();
        for key in [erased_user_key(&localpart), erased_did_key(&did)] {
            let ttl: i64 = bb8_redis::redis::cmd("TTL")
                .arg(&key)
                .query_async(&mut *conn)
                .await
                .unwrap();
            assert_eq!(ttl, -1, "{key} must never expire");
        }
        assert!(
            !erased_did_key(&did).contains(&did.to_lowercase()[8..]),
            "the DID must not be stored in cleartext"
        );
        drop(conn);
        client.del_raw(&erased_user_key(&localpart)).await.ok();
        client.del_raw(&erased_did_key(&did)).await.ok();
    }

    /// H4 (part a, MUST): purge_identity must delete the `webauthn:link/*` entry
    /// whose `primary_did` matches the DID AND the credential that link points at,
    /// while leaving links/credentials for OTHER DIDs untouched. Uses a no-op
    /// credential resolver so part (b) does not interfere with the part-(a)
    /// assertion. Needs Redis (`crate::test_support::redis`).
    #[tokio::test]
    async fn purge_identity_removes_linked_credential_for_did() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        let nonce = unique_nonce();
        let did = format!("did:pkh:eip155:1:0xPURGE{nonce}");
        let other_did = format!("did:pkh:eip155:1:0xKEEP{nonce}");
        let cred = format!("cred-{nonce}");
        let other_cred = format!("othercred-{nonce}");

        let link_key = format!("webauthn:link/{cred}");
        let cred_key = format!("webauthn:credential/{cred}");
        let other_link_key = format!("webauthn:link/{other_cred}");
        let other_cred_key = format!("webauthn:credential/{other_cred}");

        // Linked credential for the target DID (must be purged).
        client
            .set_raw(
                &link_key,
                &format!(r#"{{"primary_did":"{did}","label":"linked"}}"#),
            )
            .await
            .unwrap();
        client
            .set_raw(&cred_key, r#"{"stub":"credential"}"#)
            .await
            .unwrap();

        // Linked credential for an unrelated DID (must survive).
        client
            .set_raw(
                &other_link_key,
                &format!(r#"{{"primary_did":"{other_did}","label":"linked"}}"#),
            )
            .await
            .unwrap();
        client
            .set_raw(&other_cred_key, r#"{"stub":"other"}"#)
            .await
            .unwrap();

        // No-op resolver: part (b) finds nothing, so the count reflects part (a) only.
        let purged = client.purge_identity(&did, |_json| None).await.unwrap();
        assert_eq!(purged, 2, "the link AND its credential must be purged");
        assert!(
            client.get_raw(&link_key).await.unwrap().is_none(),
            "matching link must be gone"
        );
        assert!(
            client.get_raw(&cred_key).await.unwrap().is_none(),
            "credential the matching link pointed at must be gone"
        );
        assert!(
            client.get_raw(&other_link_key).await.unwrap().is_some(),
            "unrelated link must remain"
        );
        assert!(
            client.get_raw(&other_cred_key).await.unwrap().is_some(),
            "unrelated credential must remain"
        );

        // Best-effort cleanup of the surviving unrelated keys.
        client.del_raw(&other_link_key).await.ok();
        client.del_raw(&other_cred_key).await.ok();
    }

    /// H4 (part b, BEST-EFFORT): a standalone credential (no link entry) whose
    /// stored passkey derives to the target did:key must also be purged, using
    /// the supplied derivation resolver. A credential deriving to a different
    /// DID must survive. Needs Redis (`crate::test_support::redis`).
    #[tokio::test]
    async fn purge_identity_removes_standalone_credential_by_derived_did() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        let nonce = unique_nonce();
        let did = format!("did:key:zDnPURGE{nonce}");
        let mine = format!("mine-{nonce}");
        let theirs = format!("theirs-{nonce}");
        let mine_key = format!("webauthn:credential/{mine}");
        let theirs_key = format!("webauthn:credential/{theirs}");

        // The stored JSON carries the derived-DID marker the resolver keys on.
        client
            .set_raw(&mine_key, &format!(r#"{{"derives_to":"{did}"}}"#))
            .await
            .unwrap();
        client
            .set_raw(
                &theirs_key,
                &format!(r#"{{"derives_to":"did:key:zDnOTHER{nonce}"}}"#),
            )
            .await
            .unwrap();

        // Resolver maps a credential JSON to its derived did:key.
        let target = did.clone();
        let resolver = |json: &str| {
            let v: serde_json::Value = serde_json::from_str(json).ok()?;
            v.get("derives_to")?.as_str().map(|s| s.to_string())
        };

        let purged = client.purge_identity(&target, resolver).await.unwrap();
        assert_eq!(
            purged, 1,
            "only the credential deriving to the DID is purged"
        );
        assert!(
            client.get_raw(&mine_key).await.unwrap().is_none(),
            "standalone credential deriving to the DID must be gone"
        );
        assert!(
            client.get_raw(&theirs_key).await.unwrap().is_some(),
            "credential deriving to another DID must remain"
        );

        client.del_raw(&theirs_key).await.ok();
    }

    /// H3: `get_passkeys_for_did`'s scan-fallback (cold index) must return EXACTLY
    /// the same set as the maintained index (warm), for a DID that has BOTH a
    /// wallet-linked passkey (`webauthn:link`, primary_did == did) AND a standalone
    /// credential that derives to that same DID. Unrelated link/credential entries
    /// for OTHER DIDs must be excluded from both. Needs Redis
    /// (`crate::test_support::redis`), like the `purge_identity_*` tests.
    #[tokio::test]
    async fn get_passkeys_for_did_scan_fallback_equals_index() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        let nonce = unique_nonce();
        let did = format!("did:pkh:eip155:1:0xWALLET{nonce}");
        let other_did = format!("did:pkh:eip155:1:0xOTHER{nonce}");

        // (1) wallet-linked passkey: link/{linked_cred} -> primary_did == did.
        let linked_cred = format!("linkedcred-{nonce}");
        let link_key = format!("webauthn:link/{linked_cred}");
        let linked_cred_key = format!("webauthn:credential/{linked_cred}");
        client
            .set_raw(
                &link_key,
                &format!(r#"{{"primary_did":"{did}","label":"linked"}}"#),
            )
            .await
            .unwrap();
        // The linked credential's own JSON derives to some unrelated did:key; it is
        // in scope for `did` ONLY via the link, never via derivation.
        client
            .set_raw(
                &linked_cred_key,
                &format!(r#"{{"derives_to":"did:key:zDnLINKED{nonce}"}}"#),
            )
            .await
            .unwrap();

        // (2) standalone passkey: credential/{standalone} derives to `did`.
        let standalone = format!("standalone-{nonce}");
        let standalone_key = format!("webauthn:credential/{standalone}");
        client
            .set_raw(&standalone_key, &format!(r#"{{"derives_to":"{did}"}}"#))
            .await
            .unwrap();

        // (3) unrelated entries for OTHER DIDs (must be excluded from both paths).
        let other_link_cred = format!("otherlink-{nonce}");
        let other_link_key = format!("webauthn:link/{other_link_cred}");
        let other_link_cred_key = format!("webauthn:credential/{other_link_cred}");
        client
            .set_raw(
                &other_link_key,
                &format!(r#"{{"primary_did":"{other_did}","label":"linked"}}"#),
            )
            .await
            .unwrap();
        client
            .set_raw(
                &other_link_cred_key,
                &format!(r#"{{"derives_to":"did:key:zDnELSE{nonce}"}}"#),
            )
            .await
            .unwrap();
        let other_standalone = format!("otherstandalone-{nonce}");
        let other_standalone_key = format!("webauthn:credential/{other_standalone}");
        client
            .set_raw(
                &other_standalone_key,
                &format!(r#"{{"derives_to":"{other_did}"}}"#),
            )
            .await
            .unwrap();

        // Test resolver: mirrors webauthn::derive_did_from_credential_json's role
        // (maps a stored credential JSON to its derived did:key), but reads the
        // test fixture's `derives_to` marker so we exercise pure DB-layer logic
        // with no webauthn-rs dependency.
        let resolver = |json: &str| -> Option<String> {
            let v: serde_json::Value = serde_json::from_str(json).ok()?;
            v.get("derives_to")?.as_str().map(|s| s.to_string())
        };

        // COLD path: no index key exists yet -> get_passkeys_for_did must scan and
        // self-heal. Expect exactly the linked cred + the standalone cred.
        let index_key = format!("{}/{}", super::KV_WEBAUTHN_BY_DID_PREFIX, did);
        client.del_raw(&index_key).await.ok(); // ensure cold
        let mut cold = client.get_passkeys_for_did(&did, resolver).await.unwrap();
        cold.sort();
        let mut expected = vec![linked_cred.clone(), standalone.clone()];
        expected.sort();
        assert_eq!(
            cold, expected,
            "scan fallback must return exactly the linked + standalone creds for the DID"
        );

        // The scan should have back-filled the index, so a WARM read returns the
        // same set directly from SMEMBERS (proving index == scan).
        let mut warm = client.smembers_raw(&index_key).await.unwrap();
        warm.sort();
        assert_eq!(
            warm, expected,
            "back-filled index (SMEMBERS) must equal the scan result"
        );

        // And a second get_passkeys_for_did now takes the fast path with the same
        // answer.
        let mut warm2 = client.get_passkeys_for_did(&did, resolver).await.unwrap();
        warm2.sort();
        assert_eq!(
            warm2, expected,
            "warm index lookup must equal the scan result"
        );

        // Best-effort cleanup.
        for k in [
            &link_key,
            &linked_cred_key,
            &standalone_key,
            &other_link_key,
            &other_link_cred_key,
            &other_standalone_key,
            &index_key,
        ] {
            client.del_raw(k).await.ok();
        }
    }

    /// Opaque login user-session: create -> lookup round-trips the DID; a
    /// forged/guessed token is a miss (None). Needs Redis
    /// (`crate::test_support::redis`).
    #[tokio::test]
    async fn user_session_create_lookup_roundtrip_and_forged_miss() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };

        let nonce = unique_nonce();
        let did = format!("did:key:zDnUSERSESS{nonce}");

        let token = client.create_user_session(&did).await.unwrap();
        assert_eq!(
            client.lookup_user_session(&token).await.unwrap().as_deref(),
            Some(did.as_str()),
            "a valid token must resolve to its DID"
        );

        // A forged token (never minted) must miss -> None (usernameless fallback).
        let forged = format!("forged{nonce}deadbeef");
        assert!(
            client.lookup_user_session(&forged).await.unwrap().is_none(),
            "a forged/guessed token must be a Redis miss -> None"
        );

        // destroy -> subsequent lookup misses.
        client.destroy_user_session(&token).await.unwrap();
        assert!(
            client.lookup_user_session(&token).await.unwrap().is_none(),
            "a destroyed session must no longer resolve"
        );
    }

    /// Own sessions (`siwx_user`, `acct_session`) are keyed by the digest of
    /// the token the browser holds (I1): the digest key holds the value, the
    /// raw token is in no key, and the token resolves through the digest.
    #[tokio::test]
    async fn own_sessions_are_keyed_by_the_digest_of_the_token() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let nonce = unique_nonce();
        let did = format!("did:key:zDnOWNDIGEST{nonce}");
        for (kind, value, prefix, legacy) in [
            (
                OwnSession::PickerHint,
                did.clone(),
                "siwx_user",
                "user:session",
            ),
            (
                OwnSession::Account,
                format!(r#"{{"did":"{did}","csrf":"c","exp":0}}"#),
                "acct_session",
                "account_session",
            ),
        ] {
            let token = client
                .create_own_session(kind, &did, &value, 60)
                .await
                .unwrap();
            assert_eq!(
                client
                    .get_raw(&format!("{prefix}/{}", digest(&token)))
                    .await
                    .unwrap()
                    .as_deref(),
                Some(value.as_str()),
                "{kind:?}: stored under the digest of its token"
            );
            assert!(
                client
                    .get_raw(&format!("{legacy}/{token}"))
                    .await
                    .unwrap()
                    .is_none(),
                "{kind:?}: never under the raw token"
            );
            assert_eq!(
                client.lookup_own_session(kind, &token).await.unwrap(),
                Some(value.clone()),
                "{kind:?}: the token resolves"
            );
            assert!(
                client
                    .lookup_own_session(kind, &digest(&token))
                    .await
                    .unwrap()
                    .is_none(),
                "{kind:?}: the stored digest presented as a token matches nothing"
            );
            client.end_own_session(kind, &token).await.unwrap();
            assert!(
                client
                    .lookup_own_session(kind, &token)
                    .await
                    .unwrap()
                    .is_none(),
                "{kind:?}: an ended session no longer resolves"
            );
        }
    }

    /// An own session a build before Phase 4 wrote (raw-keyed) is read for its
    /// remaining lifetime and ended like a current one.
    #[tokio::test]
    async fn a_legacy_own_session_is_read_and_ended() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let nonce = unique_nonce();
        let did = format!("did:key:zDnOWNLEGACY{nonce}");
        for (kind, legacy) in [
            (OwnSession::PickerHint, "user:session"),
            (OwnSession::Account, "account_session"),
        ] {
            let token = format!("legacy{nonce}{legacy}");
            client
                .set_ex_raw(&format!("{legacy}/{token}"), &did, 60)
                .await
                .unwrap();
            assert_eq!(
                client.lookup_own_session(kind, &token).await.unwrap(),
                Some(did.clone()),
                "{kind:?}: a legacy entry is read"
            );
            client.end_own_session(kind, &token).await.unwrap();
            assert!(
                client
                    .lookup_own_session(kind, &token)
                    .await
                    .unwrap()
                    .is_none(),
                "{kind:?}: ending it removes the legacy entry"
            );
        }
    }

    /// `revoke_own_sessions` ends every own session of the DID, of both kinds
    /// and both layouts, whatever the case of a `did:pkh` address it was minted
    /// with, and no session of another DID.
    #[tokio::test]
    async fn revoking_own_sessions_ends_every_session_of_the_did_and_no_other() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let nonce = unique_nonce();
        let did = format!("did:pkh:eip155:1:0xAbC{nonce:x}");
        let did_folded = did.to_lowercase();
        let other = format!("did:pkh:eip155:1:0xDeF{nonce:x}");
        let account = |d: &str| format!(r#"{{"did":"{d}","csrf":"c","exp":0}}"#);

        let mut mine = Vec::new();
        for d in [&did, &did_folded] {
            let t = client
                .create_own_session(OwnSession::PickerHint, d, d, 60)
                .await
                .unwrap();
            mine.push((OwnSession::PickerHint, t));
            let t = client
                .create_own_session(OwnSession::Account, d, &account(d), 60)
                .await
                .unwrap();
            mine.push((OwnSession::Account, t));
        }
        let legacy_hint = format!("legacyhint{nonce}");
        client
            .set_ex_raw(&format!("user:session/{legacy_hint}"), &did, 60)
            .await
            .unwrap();
        mine.push((OwnSession::PickerHint, legacy_hint));
        let legacy_account = format!("legacyacct{nonce}");
        client
            .set_ex_raw(
                &format!("account_session/{legacy_account}"),
                &account(&did_folded),
                60,
            )
            .await
            .unwrap();
        mine.push((OwnSession::Account, legacy_account));
        let other_hint = client
            .create_own_session(OwnSession::PickerHint, &other, &other, 60)
            .await
            .unwrap();
        let other_legacy = format!("legacyother{nonce}");
        client
            .set_ex_raw(&format!("user:session/{other_legacy}"), &other, 60)
            .await
            .unwrap();

        let revoked = client.revoke_own_sessions(&did).await.unwrap();
        assert_eq!(
            revoked,
            mine.len(),
            "every own session of the DID is revoked"
        );
        for (kind, token) in &mine {
            assert!(
                client
                    .lookup_own_session(*kind, token)
                    .await
                    .unwrap()
                    .is_none(),
                "{kind:?} {token}: revoked"
            );
        }
        for token in [&other_hint, &other_legacy] {
            assert_eq!(
                client
                    .lookup_own_session(OwnSession::PickerHint, token)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(other.as_str()),
                "another DID's session survives"
            );
        }
        client.revoke_own_sessions(&other).await.unwrap();
    }

    fn code_entry(did: &str) -> CodeEntry {
        CodeEntry {
            exchange_count: 0,
            did: did.to_string(),
            nonce: None,
            client_id: "c".to_string(),
            auth_time: chrono::Utc::now(),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            device_id: None,
            localpart: None,
            scope: None,
        }
    }

    /// Consuming an authorization code removes it from the store, so nothing is
    /// left behind that a later reader could take for a live code, and a second
    /// consumer gets nothing. The code is stored only under its digest. Needs
    /// Redis (`crate::test_support::redis`).
    #[tokio::test]
    async fn a_consumed_code_leaves_no_entry() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let code = format!("code-{}", unique_nonce());
        let key = format!("code/{}", digest(&code));
        client
            .set_code(code.clone(), code_entry("did:key:zDnCONSUMED"))
            .await
            .unwrap();
        assert!(
            client.get_raw(&key).await.unwrap().is_some(),
            "setup: the code is stored under its digest"
        );
        assert!(
            client
                .get_raw(&format!("{KV_CODE_PREFIX}/{code}"))
                .await
                .unwrap()
                .is_none(),
            "the code is never a key in the clear"
        );

        let first = client.try_consume_code(code.clone()).await.unwrap();
        assert_eq!(
            first.map(|e| e.did).as_deref(),
            Some("did:key:zDnCONSUMED"),
            "the first consumer gets the entry"
        );
        assert!(
            client.get_raw(&key).await.unwrap().is_none(),
            "a consumed code must leave no {key} entry"
        );
        assert!(
            client.try_consume_code(code).await.unwrap().is_none(),
            "a second consumer gets nothing"
        );
    }

    /// A code that an older build already exchanged (it left a `/consumed`
    /// marker and kept the entry) is not handed out again, and its entry goes.
    #[tokio::test]
    async fn a_code_exchanged_by_an_older_build_is_not_redeemable() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let code = format!("code-old-{}", unique_nonce());
        // The older build stored the code under its raw key.
        let key = format!("{KV_CODE_PREFIX}/{code}");
        client
            .set_ex_raw(
                &key,
                &serde_json::to_string(&code_entry("did:key:zDnOLDBUILD")).unwrap(),
                60,
            )
            .await
            .unwrap();
        client
            .set_ex_raw(&format!("{key}/consumed"), "1", 60)
            .await
            .unwrap();
        assert!(
            client.try_consume_code(code).await.unwrap().is_none(),
            "a code an older build exchanged must not be redeemed again"
        );
        assert!(client.get_raw(&key).await.unwrap().is_none());
    }

    /// Exactly one of many concurrent consumers of one code wins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_consumers_of_one_code_have_exactly_one_winner() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        for round in 0..8 {
            let code = format!("code-race-{round}-{}", unique_nonce());
            client
                .set_code(code.clone(), code_entry("did:key:zDnRACE"))
                .await
                .unwrap();
            let tasks: Vec<_> = (0..16)
                .map(|_| {
                    let client = client.clone();
                    let code = code.clone();
                    tokio::spawn(async move { client.try_consume_code(code).await.unwrap() })
                })
                .collect();
            let mut winners = 0;
            for t in tasks {
                if t.await.unwrap().is_some() {
                    winners += 1;
                }
            }
            assert_eq!(winners, 1, "round {round}: exactly one consumer wins");
        }
    }

    /// Every key and value under the test Redis that contains `needle`.
    async fn stored_anywhere(client: &super::RedisClient, needle: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for key in client.keys_raw("*").await.unwrap() {
            if key.contains(needle) {
                hits.push(key.clone());
            } else if let Ok(Some(v)) = client.get_raw(&key).await {
                if v.contains(needle) {
                    hits.push(format!("value of {key}"));
                }
            }
        }
        hits
    }

    /// A code the previous build stored under its raw key (it lives 300 s) is
    /// consumed exactly once after the upgrade and leaves no entry.
    #[tokio::test]
    async fn a_code_the_previous_build_stored_is_consumed_once() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let code = format!("code-prev-{}", unique_nonce());
        let key = format!("{KV_CODE_PREFIX}/{code}");
        client
            .set_ex_raw(
                &key,
                &serde_json::to_string(&code_entry("did:key:zDnPREV")).unwrap(),
                60,
            )
            .await
            .unwrap();
        let first = client.try_consume_code(code.clone()).await.unwrap();
        assert_eq!(first.map(|e| e.did).as_deref(), Some("did:key:zDnPREV"));
        assert!(client.get_raw(&key).await.unwrap().is_none());
        assert!(client.try_consume_code(code).await.unwrap().is_none());
    }

    /// A stored digest presented as the code finds nothing: the legacy read
    /// uses its own prefix, which nothing writes any more.
    #[tokio::test]
    async fn a_stored_digest_presented_as_a_code_is_not_a_code() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let code = format!("code-digest-{}", unique_nonce());
        client
            .set_code(code.clone(), code_entry("did:key:zDnDIGEST"))
            .await
            .unwrap();
        assert!(client
            .try_consume_code(digest(&code))
            .await
            .unwrap()
            .is_none());
        assert!(client.try_consume_code(code).await.unwrap().is_some());
    }

    fn session_entry(nonce: &str) -> SessionEntry {
        SessionEntry {
            siwe_nonce: nonce.to_string(),
            secret: "s".to_string(),
            signin_count: 0,
            verified_did: None,
            request: None,
        }
    }

    /// A login session is stored only under its digest; its signed-in flag
    /// too, and only the first sign-in wins it.
    #[tokio::test]
    async fn a_session_and_its_signed_in_flag_are_keyed_by_digest() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let id = format!("sess-{}", unique_nonce());
        client
            .set_session(id.clone(), session_entry("n1"))
            .await
            .unwrap();
        let read = client.get_session(id.clone()).await.unwrap().unwrap();
        assert_eq!(read.siwe_nonce, "n1");
        assert!(client
            .get_raw(&format!("session/{}", digest(&id)))
            .await
            .unwrap()
            .is_some());
        assert!(client.try_mark_session_signed_in(id.clone()).await.unwrap());
        assert!(!client.try_mark_session_signed_in(id.clone()).await.unwrap());
        assert!(client
            .get_raw(&format!("session/{}/signed_in", digest(&id)))
            .await
            .unwrap()
            .is_some());
        assert_eq!(stored_anywhere(&client, &id).await, Vec::<String>::new());
    }

    /// A session the previous build started is read in place; its first write
    /// moves it to the digest key; a sign-in that build already made counts.
    #[tokio::test]
    async fn a_session_the_previous_build_started_is_read_moved_and_its_flag_honoured() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let id = format!("sess-prev-{}", unique_nonce());
        let legacy = format!("sessions/{id}");
        let json = serde_json::to_string(&session_entry("old")).unwrap();
        client.set_ex_raw(&legacy, &json, 60).await.unwrap();
        let mut read = client.get_session(id.clone()).await.unwrap().unwrap();
        assert_eq!(read.siwe_nonce, "old");
        read.verified_did = Some("did:key:zDnMOVED".to_string());
        client.set_session(id.clone(), read).await.unwrap();
        assert!(client.get_raw(&legacy).await.unwrap().is_none());
        let moved = client.get_session(id.clone()).await.unwrap().unwrap();
        assert_eq!(moved.verified_did.as_deref(), Some("did:key:zDnMOVED"));

        let signed = format!("sess-signed-{}", unique_nonce());
        client
            .set_ex_raw(&format!("sessions/{signed}/signed_in"), "1", 60)
            .await
            .unwrap();
        assert!(
            !client.try_mark_session_signed_in(signed).await.unwrap(),
            "a session the previous build signed in stays signed in"
        );
    }

    /// Device and user codes are stored only as digests: the entry under the
    /// device code's digest holds the user code's digest, the mapping under the
    /// user code's digest holds the device code's digest. Lookup by either,
    /// update, the redemption claim and deletion all work on that layout.
    #[tokio::test]
    async fn device_and_user_codes_are_stored_only_as_digests() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let device_code = format!("dvc_unit{n}");
        let user_code = format!("UNIT-{n}");
        let entry = DeviceCodeEntry::new(&user_code, "c".to_string(), "openid".to_string(), 0);
        client
            .set_device_code(&device_code, &entry, 60)
            .await
            .unwrap();
        client
            .set_user_code_mapping(&user_code, &device_code, 60)
            .await
            .unwrap();
        assert_eq!(
            stored_anywhere(&client, &device_code).await,
            Vec::<String>::new()
        );
        assert_eq!(
            stored_anywhere(&client, &user_code).await,
            Vec::<String>::new()
        );

        let (by_user, mut found) = client
            .get_device_code_by_user_code(&user_code)
            .await
            .unwrap()
            .expect("found by user code");
        let (by_device, _) = client.get_device_code(&device_code).await.unwrap().unwrap();
        assert_eq!(by_user, by_device, "both lookups name the same entry");
        found.status = DeviceCodeStatus::Approved;
        client
            .update_device_code(&by_user, &found, 60)
            .await
            .unwrap();
        let (_, approved) = client.get_device_code(&device_code).await.unwrap().unwrap();
        assert_eq!(approved.status, DeviceCodeStatus::Approved);
        assert_eq!(approved.user_code_digest, digest(&user_code));

        assert!(client.try_claim_device_code(&device_code).await.unwrap());
        assert!(!client.try_claim_device_code(&device_code).await.unwrap());
        client.delete_device_code(&by_device).await.unwrap();
        client.delete_user_code_mapping(&approved).await.unwrap();
        assert!(client
            .get_device_code(&device_code)
            .await
            .unwrap()
            .is_none());
        assert!(client
            .get_device_code_by_user_code(&user_code)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            stored_anywhere(&client, &device_code).await,
            Vec::<String>::new()
        );
    }

    /// The user code is hashed exactly as presented, as it was matched before:
    /// the server never normalised it (the approval page trims and upper-cases
    /// what the person types), so another spelling is another code.
    #[tokio::test]
    async fn a_user_code_is_hashed_exactly_as_presented() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let device_code = format!("dvc_case{n}");
        let user_code = format!("BCD-FGH{n}");
        let entry = DeviceCodeEntry::new(&user_code, "c".to_string(), "openid".to_string(), 0);
        client
            .set_device_code(&device_code, &entry, 60)
            .await
            .unwrap();
        client
            .set_user_code_mapping(&user_code, &device_code, 60)
            .await
            .unwrap();
        assert!(client
            .get_device_code_by_user_code(&user_code)
            .await
            .unwrap()
            .is_some());
        assert!(client
            .get_device_code_by_user_code(&user_code.to_lowercase())
            .await
            .unwrap()
            .is_none());
    }

    /// A device code the previous build stored (`device_codes/{raw}`, the user
    /// code in the entry, `user_codes/{raw}` -> the raw device code) is found
    /// by either code, updated in place, claimed once (a claim that build made
    /// counts), and deleted with its mapping.
    #[tokio::test]
    async fn a_device_code_the_previous_build_stored_is_used_in_place() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let device_code = format!("dvc_prev{n}");
        let user_code = format!("PREV-{n}");
        let legacy_json = serde_json::json!({
            "user_code": user_code, "client_id": "c", "scope": "openid",
            "status": "Pending", "did": null, "device_id": null, "last_poll": null,
            "created_at": 0,
        })
        .to_string();
        client
            .set_ex_raw(&format!("device_codes/{device_code}"), &legacy_json, 60)
            .await
            .unwrap();
        client
            .set_ex_raw(&format!("user_codes/{user_code}"), &device_code, 60)
            .await
            .unwrap();

        let (r, mut entry) = client
            .get_device_code_by_user_code(&user_code)
            .await
            .unwrap()
            .expect("a legacy user code is found");
        assert_eq!(entry.user_code_digest, digest(&user_code));
        entry.status = DeviceCodeStatus::Approved;
        client.update_device_code(&r, &entry, 60).await.unwrap();
        assert!(
            client
                .get_raw(&format!("device_code/{}", digest(&device_code)))
                .await
                .unwrap()
                .is_none(),
            "a legacy entry is updated where it is"
        );
        let (r2, polled) = client.get_device_code(&device_code).await.unwrap().unwrap();
        assert_eq!(r2, r);
        assert_eq!(polled.status, DeviceCodeStatus::Approved);
        assert!(client.try_claim_device_code(&device_code).await.unwrap());
        client.delete_device_code(&r2).await.unwrap();
        client.delete_user_code_mapping(&polled).await.unwrap();
        assert_eq!(
            stored_anywhere(&client, &device_code).await,
            Vec::<String>::new()
        );
        assert_eq!(
            stored_anywhere(&client, &user_code).await,
            Vec::<String>::new()
        );

        let claimed = format!("dvc_prevclaim{n}");
        client
            .set_ex_raw(&format!("device_codes/{claimed}/redeemed"), "1", 60)
            .await
            .unwrap();
        assert!(
            !client.try_claim_device_code(&claimed).await.unwrap(),
            "a claim the previous build made counts"
        );
    }

    /// An entry exactly as the previous build serialized it deserialises, and
    /// a new entry never serializes the user code.
    #[test]
    fn a_previous_build_device_code_entry_deserialises() {
        let legacy = DeviceCodeEntry::from_stored(
            r#"{"user_code":"ABC-DEF","client_id":"c","scope":"openid","status":"Approved","did":"did:key:zDnX","device_id":null,"last_poll":7,"created_at":1}"#,
        )
        .unwrap();
        assert_eq!(legacy.user_code_digest, digest("ABC-DEF"));
        assert_eq!(legacy.legacy_user_code.as_deref(), Some("ABC-DEF"));
        assert_eq!(legacy.status, DeviceCodeStatus::Approved);
        assert_eq!(legacy.last_poll, Some(7));
        let new = DeviceCodeEntry::new("ABC-DEF", "c".to_string(), "openid".to_string(), 1);
        let json = serde_json::to_string(&new).unwrap();
        assert!(
            !json.contains("ABC-DEF") && !json.contains("\"user_code\""),
            "{json}"
        );
    }

    /// CAIP-122 nonces are stored by digest and used once; a nonce the
    /// previous build minted is used once too, unless it consumed it already.
    #[tokio::test]
    async fn caip122_nonces_are_stored_by_digest_and_used_once() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let cat = format!("unit{}", unique_nonce());
        let nonce = client.mint_caip122_nonce(&cat, "binding").await.unwrap();
        assert_eq!(stored_anywhere(&client, &nonce).await, Vec::<String>::new());
        assert_eq!(
            client
                .try_consume_caip122_nonce(&cat, &nonce)
                .await
                .unwrap()
                .as_deref(),
            Some("binding")
        );
        assert!(client
            .try_consume_caip122_nonce(&cat, &nonce)
            .await
            .unwrap()
            .is_none());

        let old = format!("{:032x}", unique_nonce());
        client
            .set_ex_raw(&format!("caip122_nonce/{cat}/{old}"), "OLD-BINDING", 60)
            .await
            .unwrap();
        assert_eq!(
            client
                .try_consume_caip122_nonce(&cat, &old)
                .await
                .unwrap()
                .as_deref(),
            Some("OLD-BINDING")
        );
        assert!(client
            .try_consume_caip122_nonce(&cat, &old)
            .await
            .unwrap()
            .is_none());
        let spent = format!("{:032x}", unique_nonce());
        client
            .set_ex_raw(&format!("caip122_nonce/{cat}/{spent}"), "SPENT", 60)
            .await
            .unwrap();
        client
            .set_ex_raw(&format!("caip122_nonce/{cat}/{spent}/consumed"), "1", 60)
            .await
            .unwrap();
        assert!(client
            .try_consume_caip122_nonce(&cat, &spent)
            .await
            .unwrap()
            .is_none());
    }

    /// Ceremony state is keyed by the digest of the ceremony id, taken once,
    /// and a ceremony the previous build started is read for its lifetime.
    #[tokio::test]
    async fn ceremony_state_is_digest_keyed_and_taken_once() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        for ceremony in [Ceremony::Challenge, Ceremony::Link] {
            let id = format!("device_passkey_CER-{}", unique_nonce());
            client
                .put_ceremony_state(ceremony, &id, "state", 60)
                .await
                .unwrap();
            assert_eq!(stored_anywhere(&client, &id).await, Vec::<String>::new());
            assert_eq!(
                client
                    .take_ceremony_state(ceremony, &id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("state")
            );
            assert!(client
                .take_ceremony_state(ceremony, &id)
                .await
                .unwrap()
                .is_none());

            let old = format!("old-{}", unique_nonce());
            let legacy = match ceremony {
                Ceremony::Challenge => format!("webauthn:challenge/{old}"),
                Ceremony::Link => format!("webauthn:link_challenge/{old}"),
            };
            client.set_ex_raw(&legacy, "old-state", 60).await.unwrap();
            assert_eq!(
                client
                    .take_ceremony_state(ceremony, &old)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("old-state")
            );
            assert!(client.get_raw(&legacy).await.unwrap().is_none());
        }
    }

    /// A client entry the previous build wrote (plaintext secret and
    /// registration access token), stored with a 1000 s expiry under a fresh id.
    async fn seed_plaintext_client(client: &super::RedisClient) -> (String, String) {
        let id = format!("client-prev-{}", unique_nonce());
        let stored = serde_json::json!({
            "secret": "prev-secret",
            "metadata": openidconnect::core::CoreClientMetadata::new(
                vec![openidconnect::RedirectUrl::new("https://rp.example.org/cb".into()).unwrap()],
                Default::default(),
            ),
            "access_token": "prev-token",
        })
        .to_string();
        client
            .set_ex_raw(&format!("clients/{id}"), &stored, 1000)
            .await
            .unwrap();
        (id, stored)
    }

    async fn pttl(client: &super::RedisClient, key: &str) -> i64 {
        let mut conn = client.pool.get().await.unwrap();
        bb8_redis::redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .unwrap()
    }

    /// The first read of a previous build's client entry authenticates with
    /// the old secret and token and replaces the entry by its digest-only form,
    /// keeping its expiry; later reads change nothing.
    #[tokio::test]
    async fn a_plaintext_client_entry_is_upgraded_on_first_read_keeping_its_expiry() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let (id, stored) = seed_plaintext_client(&client).await;
        let key = format!("clients/{id}");
        let entry = client.get_client(id.clone()).await.unwrap().unwrap();
        assert!(entry.secret_matches("prev-secret"));
        assert!(entry.access_token_matches("prev-token"));
        let upgraded = client.get_raw(&key).await.unwrap().unwrap();
        assert!(!upgraded.contains("prev-secret"), "{upgraded}");
        assert!(!upgraded.contains("prev-token"), "{upgraded}");
        let expected =
            crate::db::client_entry_without_plaintext(&serde_json::from_str(&stored).unwrap())
                .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&upgraded).unwrap(),
            expected
        );
        let ttl = pttl(&client, &key).await;
        assert!(
            ttl > 900_000 && ttl <= 1_000_000,
            "the expiry is kept: {ttl} ms"
        );

        let again = client.get_client(id.clone()).await.unwrap().unwrap();
        assert!(again.secret_matches("prev-secret"));
        assert_eq!(client.get_raw(&key).await.unwrap().unwrap(), upgraded);
        client.del_raw(&key).await.unwrap();
    }

    /// Concurrent first reads of one plaintext entry all authenticate, and
    /// exactly one digest-only entry is left, whoever wrote it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_reads_of_a_plaintext_client_all_authenticate_and_leave_one_digested_entry(
    ) {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let (id, stored) = seed_plaintext_client(&client).await;
        let mut reads = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let (client, id) = (client.clone(), id.clone());
            reads.spawn(async move { client.get_client(id).await });
        }
        while let Some(read) = reads.join_next().await {
            let entry = read
                .unwrap()
                .unwrap()
                .expect("every reader finds the client");
            assert!(entry.secret_matches("prev-secret"));
            assert!(entry.access_token_matches("prev-token"));
        }
        let expected =
            crate::db::client_entry_without_plaintext(&serde_json::from_str(&stored).unwrap())
                .unwrap();
        let key = format!("clients/{id}");
        let left = client.get_raw(&key).await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&left).unwrap(),
            expected
        );
        assert_eq!(
            client.keys_raw(&format!("clients/{id}*")).await.unwrap(),
            vec![key.clone()]
        );
        client.del_raw(&key).await.unwrap();
    }

    /// The upgrade replaces only the entry it read: an entry that changed in
    /// between (an update, or another reader's upgrade) is left as it is, so
    /// no field written meanwhile is lost.
    #[tokio::test]
    async fn an_upgrade_never_overwrites_an_entry_that_changed_since_it_was_read() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let (id, stored) = seed_plaintext_client(&client).await;
        let key = format!("clients/{id}");
        let updated = stored.replace("rp.example.org", "updated.example.org");
        client.set_ex_raw(&key, &updated, 1000).await.unwrap();
        let mut conn = client.pool.get().await.unwrap();
        let replaced: i64 = bb8_redis::redis::cmd("EVAL")
            .arg(super::UPGRADE_CLIENT_SCRIPT)
            .arg(1)
            .arg(&key)
            .arg(&stored)
            .arg("{}")
            .query_async(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(replaced, 0);
        assert_eq!(client.get_raw(&key).await.unwrap().unwrap(), updated);
        client.del_raw(&key).await.unwrap();
    }

    fn lifetime_test_entry_with_secret(secret: &str) -> crate::db::ClientEntry {
        let metadata = crate::db::SiwxClientMetadata::new(
            vec![
                openidconnect::RedirectUrl::new("https://app.example.org/callback".into()).unwrap(),
            ],
            crate::db::LogoutClientMetadata::default(),
        );
        crate::db::ClientEntry::new(secret, metadata, None)
    }

    fn lifetime_test_entry() -> crate::db::ClientEntry {
        lifetime_test_entry_with_secret("not-a-secret-test-fixture")
    }

    /// A static client carries no TTL after start-up, a TTL an older build wrote is
    /// cleared, and a static client removed from the configuration is deleted at the
    /// next sync. Uses its own tracking set, so it can never prune the static clients of
    /// a stack that shares this Redis.
    #[tokio::test]
    async fn static_clients_never_expire() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let set_key = format!("clients:static:test-{n}");
        let kept = format!("static-kept-{n}");
        let removed = format!("static-removed-{n}");
        let kept_key = format!("clients/{kept}");
        let removed_key = format!("clients/{removed}");

        // An older build wrote the kept client with the 30-day lifetime.
        client
            .set_client(kept.clone(), lifetime_test_entry())
            .await
            .unwrap();
        assert!(
            client.ttl_raw(&kept_key).await.unwrap() > 0,
            "precondition: the old write carries a TTL"
        );

        let pruned = client
            .sync_static_clients_in(
                &set_key,
                vec![
                    (kept.clone(), lifetime_test_entry()),
                    (removed.clone(), lifetime_test_entry()),
                ],
            )
            .await
            .unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(
            client.ttl_raw(&kept_key).await.unwrap(),
            -1,
            "a static client must never expire"
        );
        assert_eq!(client.ttl_raw(&removed_key).await.unwrap(), -1);

        // The next start no longer configures `removed`.
        let pruned = client
            .sync_static_clients_in(&set_key, vec![(kept.clone(), lifetime_test_entry())])
            .await
            .unwrap();
        assert_eq!(pruned, 1, "exactly the removed client is pruned");
        assert!(
            client.get_client(removed.clone()).await.unwrap().is_none(),
            "a client removed from default_clients must not stay registered"
        );
        assert!(client.get_client(kept.clone()).await.unwrap().is_some());
        assert_eq!(client.ttl_raw(&kept_key).await.unwrap(), -1);

        client.del_raw(&kept_key).await.ok();
        client.del_raw(&set_key).await.ok();
    }

    #[tokio::test]
    async fn touching_extends_a_dynamic_client_and_never_a_static_one() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let dynamic = format!("dynamic-{n}");
        let dynamic_key = format!("clients/{dynamic}");
        client
            .set_client(dynamic.clone(), lifetime_test_entry())
            .await
            .unwrap();
        client.expire_raw(&dynamic_key, 60).await.unwrap(); // close to its end
        client.touch_client(&dynamic).await.unwrap();
        let ttl = client.ttl_raw(&dynamic_key).await.unwrap();
        assert!(
            ttl > crate::db::CLIENT_LIFETIME as i64 - 60,
            "a used dynamic client gets its full lifetime back, got {ttl}"
        );

        let set_key = format!("clients:static:test-{n}");
        let fixed = format!("static-{n}");
        let fixed_key = format!("clients/{fixed}");
        client
            .sync_static_clients_in(&set_key, vec![(fixed.clone(), lifetime_test_entry())])
            .await
            .unwrap();
        client.touch_client(&fixed).await.unwrap();
        assert_eq!(
            client.ttl_raw(&fixed_key).await.unwrap(),
            -1,
            "touching must never give a static client a TTL"
        );

        let unknown = format!("unknown-{n}");
        client.touch_client(&unknown).await.unwrap();
        assert_eq!(
            client.ttl_raw(&format!("clients/{unknown}")).await.unwrap(),
            -2,
            "touching an unknown id creates nothing"
        );

        for key in [dynamic_key, fixed_key, set_key] {
            client.del_raw(&key).await.ok();
        }
    }

    /// Rewriting a client's entry (a registration-management update) never changes whether
    /// it expires: a static client stays without an expiry, and a dynamic client gets its
    /// full lifetime back, as it does on every other use.
    #[tokio::test]
    async fn rewriting_a_client_keeps_a_static_client_without_expiry() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let n = unique_nonce();
        let set_key = format!("clients:static:test-{n}");
        let fixed = format!("static-{n}");
        let fixed_key = format!("clients/{fixed}");
        client
            .sync_static_clients_in(&set_key, vec![(fixed.clone(), lifetime_test_entry())])
            .await
            .unwrap();

        client
            .set_client(fixed.clone(), lifetime_test_entry_with_secret("rewritten"))
            .await
            .unwrap();
        assert_eq!(
            client.ttl_raw(&fixed_key).await.unwrap(),
            -1,
            "a rewrite must not give a static client an expiry"
        );
        assert!(
            client
                .get_client(fixed)
                .await
                .unwrap()
                .unwrap()
                .secret_matches("rewritten"),
            "the entry itself is replaced"
        );

        let dynamic = format!("dynamic-{n}");
        let dynamic_key = format!("clients/{dynamic}");
        client
            .set_client(dynamic.clone(), lifetime_test_entry())
            .await
            .unwrap();
        client.expire_raw(&dynamic_key, 60).await.unwrap(); // close to its end
        client
            .set_client(dynamic, lifetime_test_entry())
            .await
            .unwrap();
        let ttl = client.ttl_raw(&dynamic_key).await.unwrap();
        assert!(
            ttl > crate::db::CLIENT_LIFETIME as i64 - 60,
            "a rewritten dynamic client gets its full lifetime back, got {ttl}"
        );

        for key in [fixed_key, dynamic_key, set_key] {
            client.del_raw(&key).await.ok();
        }
    }

    /// A static client an earlier build wrote in the clear and without an expiry is
    /// replaced by its digest-only form on its first read, and keeps having no expiry:
    /// the upgrade rewrites the entry in place and must not give it one.
    #[tokio::test]
    async fn an_upgraded_plaintext_static_client_keeps_no_ttl() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let id = format!("plaintext-static-{}", unique_nonce());
        let key = format!("clients/{id}");
        let secret = "not-a-secret-test-fixture";
        let plaintext = serde_json::json!({
            "secret": secret,
            "metadata": {"redirect_uris": ["https://app.example.org/callback"]},
        })
        .to_string();
        client.set_raw(&key, &plaintext).await.unwrap();
        assert_eq!(
            client.ttl_raw(&key).await.unwrap(),
            -1,
            "precondition: a static client has no expiry"
        );

        let entry = client.get_client(id).await.unwrap().unwrap();

        assert!(
            entry.secret_matches(secret),
            "the plaintext entry authenticates"
        );
        let stored = client.get_raw(&key).await.unwrap().unwrap();
        assert!(
            !stored.contains(secret),
            "the first read replaced the entry by its digest-only form: {stored}"
        );
        assert_eq!(
            client.ttl_raw(&key).await.unwrap(),
            -1,
            "the upgrade must not give a static client an expiry"
        );
        client.del_raw(&key).await.ok();
    }
}
