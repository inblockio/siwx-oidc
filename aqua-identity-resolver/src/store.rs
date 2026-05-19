use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::ResolverError;
use crate::profile::VerifiedProfile;

#[async_trait]
pub trait ClaimStore: Send + Sync {
    async fn upsert(&self, profile: VerifiedProfile) -> Result<(), ResolverError>;
    async fn get(&self, did: &str) -> Result<Option<VerifiedProfile>, ResolverError>;
    async fn remove(&self, did: &str) -> Result<(), ResolverError>;
}

#[derive(Debug, Default)]
pub struct InMemoryClaimStore {
    profiles: RwLock<HashMap<String, VerifiedProfile>>,
}

impl InMemoryClaimStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ClaimStore for InMemoryClaimStore {
    async fn upsert(&self, profile: VerifiedProfile) -> Result<(), ResolverError> {
        let mut map = self.profiles.write().await;
        map.insert(profile.did.clone(), profile);
        Ok(())
    }

    async fn get(&self, did: &str) -> Result<Option<VerifiedProfile>, ResolverError> {
        let map = self.profiles.read().await;
        Ok(map.get(did).cloned())
    }

    async fn remove(&self, did: &str) -> Result<(), ResolverError> {
        let mut map = self.profiles.write().await;
        map.remove(did);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_round_trip() {
        let store = InMemoryClaimStore::new();
        let profile = VerifiedProfile::new("did:key:z6MkTest");

        store.upsert(profile.clone()).await.unwrap();
        let got = store.get("did:key:z6MkTest").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().did, "did:key:z6MkTest");
    }

    #[tokio::test]
    async fn in_memory_remove() {
        let store = InMemoryClaimStore::new();
        store
            .upsert(VerifiedProfile::new("did:key:z6MkTest"))
            .await
            .unwrap();
        store.remove("did:key:z6MkTest").await.unwrap();
        let got = store.get("did:key:z6MkTest").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn in_memory_missing_returns_none() {
        let store = InMemoryClaimStore::new();
        let got = store.get("did:key:nonexistent").await.unwrap();
        assert!(got.is_none());
    }
}
