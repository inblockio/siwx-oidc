use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bb8_redis::{
    bb8::{self, Pool},
    redis::AsyncCommands,
    RedisConnectionManager,
};
use tracing::debug;
use url::Url;

use super::*;

/// How long a device-revoked / user-deactivation tombstone lives. It only needs
/// to outlast an in-flight refresh that started before the sweep; a few minutes
/// is ample (access tokens live 5 min). It is also harmless if it lingers: it
/// just makes a refresh refuse, and a fresh sign-in does not consult it.
const TOMBSTONE_TTL_SECS: u64 = 600; // 10 min

#[derive(Clone)]
pub struct RedisClient {
    pool: Pool<RedisConnectionManager>,
}

/// Redis key for the per-`(username, device_id)` token index SET.
fn device_token_idx_key(username: &str, device_id: &str) -> String {
    format!("{}/{}/{}", KV_DEVICE_TOKEN_IDX_PREFIX, username, device_id)
}

/// Redis key for the short-lived device-revoked tombstone.
fn device_tombstone_key(username: &str, device_id: &str) -> String {
    format!("{}/{}/{}", KV_DEVICE_TOMBSTONE_PREFIX, username, device_id)
}

/// Redis key for the per-user deactivation tombstone.
fn user_tombstone_key(username: &str) -> String {
    format!("{}/{}", KV_USER_TOMBSTONE_PREFIX, username)
}

/// Redis key for the short-lived refresh-token rotation grace pointer.
fn rotated_token_key(old_refresh: &str) -> String {
    format!("{}/{}", KV_ROTATED_PREFIX, old_refresh)
}

impl RedisClient {
    pub async fn new(url: &Url) -> Result<Self> {
        let manager = RedisConnectionManager::new(url.as_str())
            .context("Could not build Redis connection manager")?;
        let pool = bb8::Pool::builder()
            .build(manager.clone())
            .await
            .context("Could not build Redis pool")?;
        Ok(Self { pool })
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
    /// Matching is keyed on `username` (the lowercased `did_to_localpart` value,
    /// which is what Synapse uses) rather than the raw DID, so revocation is
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

        let revoked = revoked_idx + revoked_scan;
        debug!(
            "revoke_device_tokens: username={} device_id={} revoked_idx={} revoked_scan={} total={}",
            username, device_id, revoked_idx, revoked_scan, revoked
        );
        Ok(revoked)
    }

    /// Revoke every stored OAuth token for `username` (localpart), across all devices.
    /// Returns the count removed. Used by MSC4191 account_deactivate: after Synapse
    /// deactivates the account, removing all tokens makes introspection report every
    /// session inactive.
    ///
    /// Like [`revoke_device_tokens`](Self::revoke_device_tokens) this keys on
    /// `username` (the lowercased `did_to_localpart` value Synapse uses) so it is
    /// robust to address-case differences between sign-in and re-auth DIDs.
    ///
    /// **Race-free (S3-4 / H6):** the caller (`account_deactivate`/`account_erase`)
    /// plants the per-user deactivation tombstone via
    /// [`mark_user_deactivated`](Self::mark_user_deactivated) BEFORE calling this,
    /// so a concurrent refresh/mint refuses to issue tokens during/after the
    /// sweep. As a defence-in-depth backstop this method also (re)sets the
    /// tombstone itself, then loops the scan until a pass finds zero tokens, so a
    /// writer that slipped in between the tombstone and the first scan is still
    /// cleaned up. No new token can be minted (the refresh path is tombstoned), so
    /// the loop terminates.
    pub async fn revoke_all_user_tokens(&self, username: &str) -> Result<usize> {
        // Defence-in-depth: ensure the tombstone is present even if the caller
        // did not set it (the explicit callers do, before this point).
        self.mark_user_deactivated(username).await?;

        let mut total = 0usize;
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

    /// Plant the per-user deactivation tombstone so any concurrent (or later)
    /// refresh/mint for this user refuses to issue tokens. Set FIRST, before the
    /// `revoke_all_user_tokens` sweep, by `account_deactivate`/`account_erase`
    /// (S3-4 / H6). Idempotent.
    pub async fn mark_user_deactivated(&self, username: &str) -> Result<()> {
        self.set_ex_raw(&user_tombstone_key(username), "1", TOMBSTONE_TTL_SECS)
            .await
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
                    debug!("purge_identity: get link {} failed: {}", link_key, e);
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
                        debug!("purge_identity: del cred {} failed: {}", cred_key, e);
                        errors += 1;
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    debug!("purge_identity: get cred {} failed: {}", cred_key, e);
                    errors += 1;
                }
            }
            match self.del_raw(&link_key).await {
                Ok(()) => purged += 1,
                Err(e) => {
                    debug!("purge_identity: del link {} failed: {}", link_key, e);
                    errors += 1;
                }
            }
            // Keep the by_did reverse index consistent: drop this cred from the
            // DID's set (and the set itself once emptied). Best-effort — the index
            // is advisory, so a failure here must not mark the erase incomplete.
            if let Err(e) = self.index_remove_passkey(did, cred_id).await {
                debug!("purge_identity: index_remove_passkey {} failed: {}", cred_id, e);
            }
        }

        // -- (b) Standalone credentials whose passkey derives to this did:key --
        let cred_prefix = "webauthn:credential/";
        let cred_keys = self.keys_raw(&format!("{}*", cred_prefix)).await?;
        for cred_key in cred_keys {
            let raw = match self.get_raw(&cred_key).await {
                Ok(Some(v)) => v,
                Ok(None) => continue, // already removed in pass (a) or expired
                Err(e) => {
                    debug!("purge_identity: get cred {} failed: {}", cred_key, e);
                    errors += 1;
                    continue;
                }
            };
            if derive(&raw).as_deref() == Some(did) {
                match self.del_raw(&cred_key).await {
                    Ok(()) => purged += 1,
                    Err(e) => {
                        debug!("purge_identity: del cred {} failed: {}", cred_key, e);
                        errors += 1;
                    }
                }
                // Keep the by_did reverse index consistent (best-effort, advisory).
                let cred_id = &cred_key[cred_prefix.len()..];
                if let Err(e) = self.index_remove_passkey(did, cred_id).await {
                    debug!(
                        "purge_identity: index_remove_passkey {} failed: {}",
                        cred_id, e
                    );
                }
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
                    debug!("get_passkeys_for_did: get link {} failed: {}", link_key, e);
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
                    debug!("get_passkeys_for_did: get cred {} failed: {}", cred_key, e);
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

    // -- Opaque login user-session --------------------------------------------
    //
    // Mirrors account.rs's create/lookup_account_session, but generic: the value
    // is just the DID and there is no CSRF (this token only scopes the passkey
    // picker, it never authorizes a state change). The token is OPAQUE (two random
    // UUIDs), so a forged/guessed value is a Redis miss -> None -> usernameless
    // fallback. This is the load-bearing enumeration-safety invariant: the
    // identity hint can never be a client-supplied plaintext DID.

    /// Mint an opaque login user-session bound to `did`, store
    /// `user:session/{token}` -> did with TTL [`USER_SESSION_LIFETIME`], and return
    /// the opaque token to Set-Cookie.
    pub async fn create_user_session(&self, did: &str) -> Result<String> {
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        self.set_ex_raw(
            &format!("{}/{}", KV_USER_SESSION_PREFIX, token),
            did,
            USER_SESSION_LIFETIME,
        )
        .await?;
        Ok(token)
    }

    /// Resolve an opaque login user-session token to its DID, or `None` if the
    /// token is unknown/expired (a forged or guessed token lands here -> the caller
    /// falls back to usernameless discoverable login, leaking nothing).
    pub async fn lookup_user_session(&self, token: &str) -> Result<Option<String>> {
        self.get_raw(&format!("{}/{}", KV_USER_SESSION_PREFIX, token))
            .await
    }

    /// Delete an opaque login user-session (best-effort; used to clear the hint on
    /// explicit "use a different passkey" / sign-out).
    #[allow(dead_code)]
    pub async fn destroy_user_session(&self, token: &str) -> Result<()> {
        self.del_raw(&format!("{}/{}", KV_USER_SESSION_PREFIX, token))
            .await
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

#[async_trait]
impl DBClient for RedisClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        conn.set_ex::<_, _, ()>(
            format!("{}/{}", KV_CLIENT_PREFIX, client_id),
            serde_json::to_string(&client_entry)
                .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
            CLIENT_LIFETIME,
        )
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
        let entry: Option<String> = conn
            .get(format!("{}/{}", KV_CLIENT_PREFIX, client_id))
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if let Some(e) = entry {
            Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize client entry: {}", e))?)
        } else {
            Ok(None)
        }
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

    async fn set_code(&self, code: String, code_entry: CodeEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_CODE_PREFIX, code);
        let value = serde_json::to_string(&code_entry)
            .map_err(|e| anyhow!("Failed to serialize code entry: {}", e))?;
        conn.set_ex::<_, _, ()>(&key, &value, ENTRY_LIFETIME as u64)
            .await
            .map_err(|e| anyhow!("Failed to set code in Redis: {}", e))?;
        debug!("set_code: stored key={} ttl={}s", key, ENTRY_LIFETIME);
        Ok(())
    }

    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let key = format!("{}/{}", KV_CODE_PREFIX, code);
        let entry: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if let Some(e) = entry {
            Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize code entry: {}", e))?)
        } else {
            Ok(None)
        }
    }

    async fn set_session(&self, id: String, entry: SessionEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        conn.set_ex::<_, _, ()>(
            format!("{}/{}", KV_SESSION_PREFIX, id),
            serde_json::to_string(&entry)
                .map_err(|e| anyhow!("Failed to serialize session entry: {}", e))?,
            SESSION_LIFETIME,
        )
        .await
        .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        Ok(())
    }

    async fn get_session(&self, id: String) -> Result<Option<SessionEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let entry: Option<String> = conn
            .get(format!("{}/{}", KV_SESSION_PREFIX, id))
            .await
            .map_err(|e| anyhow!("Failed to get kv: {}", e))?;
        if let Some(e) = entry {
            Ok(serde_json::from_str(&e)
                .map_err(|e| anyhow!("Failed to deserialize session entry: {}", e))?)
        } else {
            Ok(None)
        }
    }

    async fn try_consume_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        let key = format!("{}/{}", KV_CODE_PREFIX, code);

        // Atomic: SETNX on a consumed flag — only one caller wins.
        let consumed_key = format!("{}/consumed", key);
        let was_set: bool = conn
            .set_nx(&consumed_key, "1")
            .await
            .map_err(|e| anyhow!("Failed to SETNX consumed flag: {}", e))?;
        if was_set {
            let _: () = conn
                .expire(&consumed_key, ENTRY_LIFETIME as i64)
                .await
                .unwrap_or(());
        } else {
            debug!("try_consume_code: already consumed key={}", key);
            return Ok(None); // Already consumed by another request
        }

        // Read the code entry (safe: only the winner reaches here).
        let entry: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to get code entry: {}", e))?;
        match entry {
            Some(e) => {
                debug!("try_consume_code: found key={}", key);
                Ok(Some(serde_json::from_str(&e).map_err(|e| {
                    anyhow!("Failed to deserialize code entry: {}", e)
                })?))
            }
            None => {
                debug!("try_consume_code: NOT FOUND key={}", key);
                Ok(None)
            }
        }
    }

    async fn try_mark_session_signed_in(&self, id: String) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        // Atomic: SETNX on a signed-in flag — only one sign_in wins.
        let flag_key = format!("{}/{}/signed_in", KV_SESSION_PREFIX, id);
        let was_set: bool = conn
            .set_nx(&flag_key, "1")
            .await
            .map_err(|e| anyhow!("Failed to SETNX signed_in flag: {}", e))?;
        if was_set {
            let _: () = conn
                .expire(&flag_key, SESSION_LIFETIME as i64)
                .await
                .unwrap_or(());
        }
        Ok(was_set)
    }

    async fn try_claim_device_code(&self, device_code: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        // Atomic: SET .../redeemed 1 NX EX <ttl> — only the first poll wins, so
        // exactly one concurrent redemption issues tokens (S3-1 / H9). EX is part
        // of the same atomic SET (not a separate EXPIRE), so the claim cannot leak.
        let claim_key = format!("device_codes/{}/redeemed", device_code);
        let was_set: Option<String> = bb8_redis::redis::cmd("SET")
            .arg(&claim_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(DEVICE_CODE_LIFETIME)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("Failed to SET NX device-code claim: {}", e))?;
        // Redis returns "OK" when the key was set, nil (None) when NX rejected it.
        Ok(was_set.is_some())
    }

    async fn is_device_revoked(&self, username: &str, device_id: &str) -> Result<bool> {
        Ok(self
            .get_raw(&device_tombstone_key(username, device_id))
            .await?
            .is_some())
    }

    async fn is_user_deactivated(&self, username: &str) -> Result<bool> {
        Ok(self.get_raw(&user_tombstone_key(username)).await?.is_some())
    }

    async fn set_rotated_token(
        &self,
        old_refresh: &str,
        successor: &RotatedToken,
        ttl: u64,
    ) -> Result<()> {
        let value = serde_json::to_string(successor)
            .map_err(|e| anyhow!("Failed to serialize rotated token: {}", e))?;
        self.set_ex_raw(&rotated_token_key(old_refresh), &value, ttl)
            .await
    }

    async fn get_rotated_token(&self, old_refresh: &str) -> Result<Option<RotatedToken>> {
        match self.get_raw(&rotated_token_key(old_refresh)).await? {
            Some(v) => {
                Ok(Some(serde_json::from_str(&v).map_err(|e| {
                    anyhow!("Failed to deserialize rotated token: {}", e)
                })?))
            }
            None => Ok(None),
        }
    }

    // -- Opaque token storage (MSC3861) ----------------------------------------

    async fn set_token(&self, token: &str, metadata: &TokenMetadata, ttl: u64) -> Result<()> {
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
        debug!("set_token: stored key={} ttl={}s", key, ttl);
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
        let key = format!("device_codes/{}", device_code);
        let value = serde_json::to_string(entry)
            .map_err(|e| anyhow!("Failed to serialize DeviceCodeEntry: {}", e))?;
        self.set_ex_raw(&key, &value, ttl).await
    }

    async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>> {
        let key = format!("device_codes/{}", device_code);
        match self.get_raw(&key).await? {
            Some(v) => Ok(Some(serde_json::from_str(&v).map_err(|e| {
                anyhow!("Failed to deserialize DeviceCodeEntry: {}", e)
            })?)),
            None => Ok(None),
        }
    }

    async fn update_device_code(
        &self,
        device_code: &str,
        entry: &DeviceCodeEntry,
        ttl: u64,
    ) -> Result<()> {
        self.set_device_code(device_code, entry, ttl).await
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<()> {
        let key = format!("device_codes/{}", device_code);
        self.del_raw(&key).await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<(String, DeviceCodeEntry)>> {
        let mapping_key = format!("user_codes/{}", user_code);
        let device_code = match self.get_raw(&mapping_key).await? {
            Some(dc) => dc,
            None => return Ok(None),
        };
        match self.get_device_code(&device_code).await? {
            Some(entry) => Ok(Some((device_code, entry))),
            None => Ok(None),
        }
    }

    async fn set_user_code_mapping(
        &self,
        user_code: &str,
        device_code: &str,
        ttl: u64,
    ) -> Result<()> {
        let key = format!("user_codes/{}", user_code);
        self.set_ex_raw(&key, device_code, ttl).await
    }

    async fn delete_user_code_mapping(&self, user_code: &str) -> Result<()> {
        let key = format!("user_codes/{}", user_code);
        self.del_raw(&key).await
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
    // companion `consumed` flag, exactly like `try_consume_code`.

    async fn mint_caip122_nonce(&self, category: &str, binding: &str) -> Result<String> {
        // 16 random bytes hex-encoded (128 bits) — well above the login nonce.
        let nonce: String = {
            let mut bytes = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
            hex::encode(bytes)
        };
        let key = format!("{}/{}/{}", KV_CAIP122_NONCE_PREFIX, category, nonce);
        self.set_ex_raw(&key, binding, CAIP122_NONCE_TTL_SECS)
            .await?;
        Ok(nonce)
    }

    async fn try_consume_caip122_nonce(
        &self,
        category: &str,
        nonce: &str,
    ) -> Result<Option<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {}", e))?;

        let key = format!("{}/{}/{}", KV_CAIP122_NONCE_PREFIX, category, nonce);
        let consumed_key = format!("{}/consumed", key);

        // Atomic: SETNX on the consumed flag — only the first caller wins.
        let was_set: bool = conn
            .set_nx(&consumed_key, "1")
            .await
            .map_err(|e| anyhow!("Failed to SETNX caip122 nonce consumed flag: {}", e))?;
        if was_set {
            let _: () = conn
                .expire(&consumed_key, CAIP122_NONCE_TTL_SECS as i64)
                .await
                .unwrap_or(());
        } else {
            // Already consumed by an earlier request — reject as replay.
            return Ok(None);
        }

        // Winner reads the binding context. A missing value means the nonce never
        // existed or expired (the consumed flag we just set is harmless).
        let binding: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| anyhow!("Failed to read caip122 nonce binding: {}", e))?;
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::RedisClient;
    use crate::db::{DBClient, TokenMetadata};
    use std::sync::atomic::{AtomicU64, Ordering};
    use url::Url;

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
        }
    }

    /// H5: device_delete must revoke ONLY the OAuth session(s) for the targeted
    /// (username, device_id), leaving other devices and other users untouched.
    /// Requires Redis on localhost; skips cleanly if unavailable.
    #[tokio::test]
    async fn revoke_device_tokens_removes_only_matching_session() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
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
    /// Requires Redis on localhost; skips cleanly if unavailable.
    #[tokio::test]
    async fn revoke_all_user_tokens_removes_all_user_sessions() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
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

    /// H4 (part a, MUST): purge_identity must delete the `webauthn:link/*` entry
    /// whose `primary_did` matches the DID AND the credential that link points at,
    /// while leaving links/credentials for OTHER DIDs untouched. Uses a no-op
    /// credential resolver so part (b) does not interfere with the part-(a)
    /// assertion. Requires Redis on localhost; skips cleanly if unavailable.
    #[tokio::test]
    async fn purge_identity_removes_linked_credential_for_did() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
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
    /// DID must survive. Requires Redis on localhost; skips cleanly if absent.
    #[tokio::test]
    async fn purge_identity_removes_standalone_credential_by_derived_did() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return,
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
    /// for OTHER DIDs must be excluded from both. Requires Redis on localhost;
    /// skips cleanly if unavailable. Mirrors the `purge_identity_*` style/gating.
    #[tokio::test]
    async fn get_passkeys_for_did_scan_fallback_equals_index() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
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
    /// forged/guessed token is a miss (None). Requires Redis on localhost; skips
    /// cleanly if unavailable.
    #[tokio::test]
    async fn user_session_create_lookup_roundtrip_and_forged_miss() {
        let client = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return,
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
}
