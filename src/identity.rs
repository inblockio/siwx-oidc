use axum::{
    extract::{Json, State},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};

use aqua_identity_resolver::{AquaIdentityResolver, InMemoryClaimStore, Tree};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::oidc::{did_to_localpart, CustomError};
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::RedisClient;

const IDENTITY_DISPLAY_NAME_PREFIX: &str = "identity:display_name";
const IDENTITY_EMAIL_PREFIX: &str = "identity:email";

#[derive(Clone)]
pub struct IdentityState {
    pub resolver: Arc<AquaIdentityResolver<InMemoryClaimStore>>,
    pub redis_client: RedisClient,
    pub synapse_client: Option<Arc<SynapseClient>>,
    pub mas_shared_secret: Option<String>,
}

#[derive(Deserialize)]
pub struct IngestRequest {
    pub tree: serde_json::Value,
}

#[derive(Serialize)]
pub struct IngestResponse {
    pub claims_extracted: usize,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub async fn ingest_claims(
    State(state): State<IdentityState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, CustomError> {
    let secret = state
        .mas_shared_secret
        .as_deref()
        .ok_or_else(|| CustomError::BadRequest("Identity ingestion requires MAS mode".into()))?;

    if !constant_time_eq(auth.token(), secret) {
        return Err(CustomError::Unauthorized("Invalid authorization".into()));
    }

    let tree: Tree = serde_json::from_value(payload.tree)
        .map_err(|e| CustomError::BadRequest(format!("Invalid tree JSON: {}", e)))?;

    let claims = state
        .resolver
        .ingest(tree)
        .await
        .map_err(|e| CustomError::Other(anyhow::anyhow!("Ingestion failed: {}", e)))?;

    if claims.is_empty() {
        return Ok(Json(IngestResponse {
            claims_extracted: 0,
            display_name: None,
            email: None,
        }));
    }

    let signer_did = &claims[0].signer_did;

    let profile = state
        .resolver
        .resolve(signer_did)
        .await
        .map_err(|e| CustomError::Other(anyhow::anyhow!("Profile resolve failed: {}", e)))?;

    let (display_name, email) = if let Some(ref p) = profile {
        (p.display_name.clone(), p.email.clone())
    } else {
        (None, None)
    };

    if let Some(ref name) = display_name {
        if let Err(e) = state
            .redis_client
            .set_raw(
                &format!("{}:{}", IDENTITY_DISPLAY_NAME_PREFIX, signer_did),
                name,
            )
            .await
        {
            warn!("Failed to store identity display name in Redis: {}", e);
        }
    }
    if let Some(ref email_val) = email {
        if let Err(e) = state
            .redis_client
            .set_raw(
                &format!("{}:{}", IDENTITY_EMAIL_PREFIX, signer_did),
                email_val,
            )
            .await
        {
            warn!("Failed to store identity email in Redis: {}", e);
        }
    }

    if let (Some(ref name), Some(ref synapse)) = (&display_name, &state.synapse_client) {
        let localpart = did_to_localpart(signer_did);
        if let Err(e) = synapse.provision_user(&localpart, name).await {
            warn!("Failed to push display name to Synapse: {}", e);
        } else {
            info!(
                "Pushed display name '{}' for {} to Synapse",
                name, signer_did
            );
        }
    }

    Ok(Json(IngestResponse {
        claims_extracted: claims.len(),
        display_name,
        email,
    }))
}
