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

#[derive(Clone)]
pub struct RedisClient {
    pool: Pool<RedisConnectionManager>,
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
    /// There is no secondary index on (username, device_id), so this scans the
    /// token keyspace. The volume is bounded (access tokens have a short TTL;
    /// refresh tokens are the only long-lived entries), so a full scan is
    /// acceptable. The removed count is logged so a large sweep is never silent.
    pub async fn revoke_device_tokens(&self, username: &str, device_id: &str) -> Result<usize> {
        let revoked = self
            .revoke_tokens_where(|meta| meta.username == username && meta.device_id == device_id)
            .await?;
        debug!(
            "revoke_device_tokens: username={} device_id={} revoked={}",
            username, device_id, revoked
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
    pub async fn revoke_all_user_tokens(&self, username: &str) -> Result<usize> {
        let revoked = self
            .revoke_tokens_where(|meta| meta.username == username)
            .await?;
        debug!(
            "revoke_all_user_tokens: username={} revoked={}",
            username, revoked
        );
        Ok(revoked)
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

        // -- (a) Linked credentials: webauthn:link/{cred_id} -> { primary_did } --
        let link_prefix = "webauthn:link/";
        for link_key in self.keys_raw(&format!("{}*", link_prefix)).await? {
            let raw = match self.get_raw(&link_key).await? {
                Some(v) => v,
                None => continue, // raced with another purge / expiry
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
            if self.get_raw(&cred_key).await?.is_some() {
                self.del_raw(&cred_key).await?;
                purged += 1;
            }
            self.del_raw(&link_key).await?;
            purged += 1;
        }

        // -- (b) Standalone credentials whose passkey derives to this did:key --
        let cred_prefix = "webauthn:credential/";
        for cred_key in self.keys_raw(&format!("{}*", cred_prefix)).await? {
            let raw = match self.get_raw(&cred_key).await? {
                Some(v) => v,
                None => continue, // already removed in pass (a) or expired
            };
            if derive(&raw).as_deref() == Some(did) {
                self.del_raw(&cred_key).await?;
                purged += 1;
            }
        }

        debug!("purge_identity: did={} purged={}", did, purged);
        Ok(purged)
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
}

#[cfg(test)]
mod tests {
    use super::RedisClient;
    use crate::db::{DBClient, TokenMetadata};
    use url::Url;

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
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
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
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
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

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
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

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
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
}
