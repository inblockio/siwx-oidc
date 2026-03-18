use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bb8_redis::{
    bb8::{self, Pool},
    redis::AsyncCommands,
    RedisConnectionManager,
};
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

#[async_trait]
impl DBClient for RedisClient {
    async fn set_client(&self, client_id: String, client_entry: ClientEntry) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;

        conn.set::<_, _, ()>(
            format!("{}/{}", KV_CLIENT_PREFIX, client_id),
            serde_json::to_string(&client_entry)
                .map_err(|e| anyhow!("Failed to serialize client entry: {}", e))?,
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
        conn.set_ex::<_, _, ()>(
            code.to_string(),
            serde_json::to_string(&code_entry)
                .map_err(|e| anyhow!("Failed to serialize code entry: {}", e))?,
            ENTRY_LIFETIME as u64,
        )
        .await
        .map_err(|e| anyhow!("Failed to set kv: {}", e))?;
        Ok(())
    }

    async fn get_code(&self, code: String) -> Result<Option<CodeEntry>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get connection to database: {}", e))?;
        let entry: Option<String> = conn
            .get(code)
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
}
