use std::collections::HashMap;
use std::sync::Arc;

use aqua_rs_sdk::{
    core::VerificationResult,
    schema::{tree::Tree, AquaTreeWrapper},
    Aquafier,
};
use tracing::debug;

use crate::error::ResolverError;
use crate::extract::extract_claims;
use crate::profile::{ExtractedClaim, VerifiedProfile};
use crate::store::ClaimStore;

pub struct AquaIdentityResolver<S: ClaimStore> {
    aquafier: Arc<Aquafier>,
    store: Arc<S>,
}

impl<S: ClaimStore> AquaIdentityResolver<S> {
    pub fn new(aquafier: Arc<Aquafier>, store: Arc<S>) -> Self {
        Self { aquafier, store }
    }

    pub fn with_store(store: Arc<S>) -> Self {
        Self {
            aquafier: Arc::new(Aquafier::new()),
            store,
        }
    }

    pub async fn ingest(&self, tree: Tree) -> Result<Vec<ExtractedClaim>, ResolverError> {
        let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);

        let result = self.aquafier.verify_tree_sync(wrapper, vec![])?;

        if !result.is_valid {
            return Err(ResolverError::VerificationFailed {
                status: result.status.clone(),
            });
        }

        self.apply_claims(&tree, &result).await
    }

    pub async fn ingest_verified(
        &self,
        tree: &Tree,
        result: &VerificationResult,
    ) -> Result<Vec<ExtractedClaim>, ResolverError> {
        if !result.is_valid {
            return Err(ResolverError::VerificationFailed {
                status: result.status.clone(),
            });
        }

        self.apply_claims(tree, result).await
    }

    pub async fn resolve(&self, did: &str) -> Result<Option<VerifiedProfile>, ResolverError> {
        self.store.get(did).await
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    async fn apply_claims(
        &self,
        tree: &Tree,
        result: &VerificationResult,
    ) -> Result<Vec<ExtractedClaim>, ResolverError> {
        let claims = extract_claims(tree, result);

        if claims.is_empty() {
            debug!("no identity claims found in tree");
            return Ok(claims);
        }

        let mut by_did: HashMap<String, Vec<ExtractedClaim>> = HashMap::new();
        for claim in &claims {
            by_did
                .entry(claim.signer_did.clone())
                .or_default()
                .push(claim.clone());
        }

        for (did, did_claims) in by_did {
            let mut profile = self
                .store
                .get(&did)
                .await?
                .unwrap_or_else(|| VerifiedProfile::new(&did));

            for claim in did_claims {
                profile.apply_claim(claim);
            }

            self.store.upsert(profile).await?;
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryClaimStore;

    #[tokio::test]
    async fn resolve_missing_returns_none() {
        let store = Arc::new(InMemoryClaimStore::new());
        let resolver = AquaIdentityResolver::with_store(store);
        let profile = resolver.resolve("did:key:nonexistent").await.unwrap();
        assert!(profile.is_none());
    }

    #[tokio::test]
    async fn ingest_verified_stores_profile() {
        use aqua_rs_sdk::primitives::{HashType, Method, RevisionLink};
        use aqua_rs_sdk::schema::templates::NameClaim;
        use aqua_rs_sdk::schema::{AnyRevision, Object};
        use std::collections::{BTreeMap, HashMap};

        let nc = NameClaim {
            signer_did: "did:key:z6MkTest".into(),
            given_name: "Bob".into(),
            family_name: "Jones".into(),
            middle_name: None,
            name_prefix: None,
            name_suffix: None,
            nickname: None,
            preferred_username: None,
            valid_from: None,
            valid_until: None,
        };

        let obj = Object::genesis_with_template(Method::Scalar, HashType::Sha3_256, nc);
        let obj_value = obj.genericize().unwrap();
        let rev_link = RevisionLink::from_bytes([0xDD; 32]);

        let mut revisions = BTreeMap::new();
        revisions.insert(rev_link.clone(), AnyRevision::Typed(obj_value));

        let tree = Tree {
            revisions,
            file_index: BTreeMap::new(),
        };

        let mut wasm_outputs = HashMap::new();
        wasm_outputs.insert(
            rev_link.to_string(),
            serde_json::json!({ "state": "self_signed", "state_index": 1 }),
        );
        let result = VerificationResult {
            is_valid: true,
            status: "VERIFIED".into(),
            logs: vec![],
            wasm_outputs,
        };

        let store = Arc::new(InMemoryClaimStore::new());
        let resolver = AquaIdentityResolver::with_store(store);

        let claims = resolver.ingest_verified(&tree, &result).await.unwrap();
        assert_eq!(claims.len(), 1);

        let profile = resolver.resolve("did:key:z6MkTest").await.unwrap();
        assert!(profile.is_some());
        let profile = profile.unwrap();
        assert_eq!(profile.display_name.as_deref(), Some("Bob Jones"));
        assert_eq!(profile.claims.len(), 1);
    }

    #[tokio::test]
    async fn ingest_verified_rejects_invalid() {
        use std::collections::BTreeMap;

        let tree = Tree {
            revisions: BTreeMap::new(),
            file_index: BTreeMap::new(),
        };
        let result = VerificationResult {
            is_valid: false,
            status: "HASH_VERIFICATION_FAILED".into(),
            logs: vec![],
            wasm_outputs: HashMap::new(),
        };

        let store = Arc::new(InMemoryClaimStore::new());
        let resolver = AquaIdentityResolver::with_store(store);

        let err = resolver.ingest_verified(&tree, &result).await;
        assert!(err.is_err());
    }
}
