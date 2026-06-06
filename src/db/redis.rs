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
            if meta.username == username && meta.device_id == device_id {
                self.del_raw(&key).await?;
                revoked += 1;
            }
        }
        debug!(
            "revoke_device_tokens: username={} device_id={} revoked={}",
            username, device_id, revoked
        );
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
}
