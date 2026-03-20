//! WebAuthn/passkey ceremony — server-layer authentication (Layer 2).
//!
//! This module handles the full WebAuthn ceremony using the `webauthn-rs` safe API.
//! It does NOT extend `DIDMethod` — see PLAN_webauthn.md for rationale.
//!
//! After successful authentication, the verified DID is stored in the Redis session.
//! `sign_in` reads it from there (server-side, trusted).

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;
use webauthn_rs::prelude::*;

use siwx_oidc::db::RedisClient;

// -- Redis key prefixes for WebAuthn state --

const CHALLENGE_PREFIX: &str = "webauthn:challenge";
const CREDENTIAL_PREFIX: &str = "webauthn:credential";
const CHALLENGE_TTL: u64 = 120; // 2 min

// -- DID derivation from P-256 public key --

/// Multicodec varint for P-256 (0x1200), same as siwx-core/src/key/mod.rs.
const P256_MULTICODEC: &[u8] = &[0x80, 0x24];

/// Derive a `did:key:zDn…` from a P-256 compressed SEC1 public key (33 bytes).
fn did_from_p256_compressed(compressed: &[u8]) -> String {
    let mut bytes = P256_MULTICODEC.to_vec();
    bytes.extend_from_slice(compressed);
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

/// Extract the P-256 public key from a Passkey credential and derive a did:key.
fn did_from_passkey(passkey: &Passkey) -> Result<String> {
    let cose_key = passkey.get_public_key();
    match &cose_key.key {
        COSEKeyType::EC_EC2(ec2) => {
            if ec2.curve != ECDSACurve::SECP256R1 {
                return Err(anyhow!(
                    "WebAuthn credential uses unsupported curve (expected P-256)"
                ));
            }
            // Build compressed SEC1 point: 0x02 (even y) or 0x03 (odd y) + x
            let y_bytes: &[u8] = ec2.y.as_ref();
            let y_is_odd = y_bytes.last().map_or(false, |b| b & 1 == 1);
            let prefix = if y_is_odd { 0x03 } else { 0x02 };
            let mut compressed = vec![prefix];
            compressed.extend_from_slice(ec2.x.as_ref());
            Ok(did_from_p256_compressed(&compressed))
        }
        _ => Err(anyhow!(
            "WebAuthn credential is not EC2/P-256 — cannot derive did:key"
        )),
    }
}

// -- Request/response types for the HTTP API --

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub did: String,
    pub credential_id: String,
}

#[derive(Serialize)]
pub struct AuthenticateFinishResponse {
    pub ok: bool,
    pub did: String,
}

// -- Registration ceremony --

pub async fn register_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    display_name: Option<String>,
) -> Result<CreationChallengeResponse> {
    let user_unique_id = Uuid::new_v4();
    let name = display_name.as_deref().unwrap_or("passkey-user");

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, name, name, None)
        .map_err(|e| anyhow!("WebAuthn registration start failed: {:?}", e))?;

    // Store registration state in Redis (consumed by register_finish).
    let state_json = serde_json::to_string(&reg_state)
        .map_err(|e| anyhow!("Failed to serialize registration state: {}", e))?;
    redis
        .set_ex_raw(
            &format!("{}/{}", CHALLENGE_PREFIX, session_id),
            &state_json,
            CHALLENGE_TTL,
        )
        .await?;

    info!("webauthn register_start: session={}", session_id);
    Ok(ccr)
}

pub async fn register_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<RegisterFinishResponse> {
    // Retrieve and consume the registration state.
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let state_json = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No registration challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize registration state: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow!("WebAuthn registration verification failed: {:?}", e))?;

    let did = did_from_passkey(&passkey)?;
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(passkey.cred_id());

    // Store the credential persistently (no TTL).
    let cred_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize passkey: {}", e))?;
    redis
        .set_raw(
            &format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64),
            &cred_json,
        )
        .await?;

    info!(
        "webauthn register_finish: did={} cred_id={}",
        did, cred_id_b64
    );
    Ok(RegisterFinishResponse {
        did,
        credential_id: cred_id_b64,
    })
}

// -- Authentication ceremony (discoverable / passkeys) --

pub async fn authenticate_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
) -> Result<RequestChallengeResponse> {
    // Discoverable credentials: empty allow list — browser shows all passkeys for this RP.
    let (rcr, auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| anyhow!("WebAuthn auth start failed: {:?}", e))?;

    let state_json = serde_json::to_string(&auth_state)
        .map_err(|e| anyhow!("Failed to serialize auth state: {}", e))?;
    redis
        .set_ex_raw(
            &format!("{}/{}", CHALLENGE_PREFIX, session_id),
            &state_json,
            CHALLENGE_TTL,
        )
        .await?;

    info!("webauthn authenticate_start: session={}", session_id);
    Ok(rcr)
}

pub async fn authenticate_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    auth_response: PublicKeyCredential,
) -> Result<AuthenticateFinishResponse> {
    // Retrieve and consume the authentication state.
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let state_json = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No auth challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let auth_state: DiscoverableAuthentication = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize auth state: {}", e))?;

    // Step 1: Identify which credential the user selected (get cred_id from assertion).
    let (_user_unique_id, cred_id) = webauthn
        .identify_discoverable_authentication(&auth_response)
        .map_err(|e| anyhow!("Failed to identify credential: {:?}", e))?;

    // Step 2: Look up the stored credential from Redis.
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(cred_id);
    if cred_id_b64.is_empty() {
        return Err(anyhow!("Empty credential ID in WebAuthn assertion"));
    }
    let cred_key = format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64);
    let cred_json = redis
        .get_raw(&cred_key)
        .await?
        .ok_or_else(|| anyhow!("Credential not found: {}", cred_id_b64))?;
    let mut passkey: Passkey = serde_json::from_str(&cred_json)
        .map_err(|e| anyhow!("Failed to deserialize credential: {}", e))?;

    // Step 3: Convert to DiscoverableKey and finish the ceremony.
    let dk: DiscoverableKey = (&passkey).into();
    let auth_result = webauthn
        .finish_discoverable_authentication(&auth_response, auth_state, &[dk])
        .map_err(|e| anyhow!("WebAuthn authentication failed: {:?}", e))?;

    let did = did_from_passkey(&passkey)?;

    // Update sign count in stored credential.
    passkey.update_credential(&auth_result);
    let updated_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize updated credential: {}", e))?;
    redis.set_raw(&cred_key, &updated_json).await?;

    // Store verified DID in the session (this is what sign_in reads).
    let session_key = format!("sessions/{}", session_id);
    let session_json = redis
        .get_raw(&session_key)
        .await?
        .ok_or_else(|| anyhow!("Session not found"))?;
    let mut session: siwx_oidc::db::SessionEntry = serde_json::from_str(&session_json)
        .map_err(|e| anyhow!("Failed to deserialize session: {}", e))?;
    session.verified_did = Some(did.clone());
    let updated_session = serde_json::to_string(&session)
        .map_err(|e| anyhow!("Failed to serialize session: {}", e))?;
    redis
        .set_ex_raw(
            &session_key,
            &updated_session,
            siwx_oidc::db::SESSION_LIFETIME,
        )
        .await?;

    info!(
        "webauthn authenticate_finish: did={} cred={}",
        did, cred_id_b64
    );
    Ok(AuthenticateFinishResponse { ok: true, did })
}

/// Build the Webauthn instance from config.
pub fn build_webauthn(
    base_url: &Url,
    rp_id: Option<&str>,
    rp_origin: Option<&str>,
) -> Result<Webauthn> {
    let default_rp_id = base_url
        .host_str()
        .ok_or_else(|| anyhow!("SIWEOIDC_BASE_URL has no host — cannot derive WebAuthn RP ID"))?
        .to_string();
    let rp_id = rp_id.unwrap_or(&default_rp_id);

    let default_origin = base_url.as_str().trim_end_matches('/').to_string();
    let rp_origin = Url::parse(rp_origin.unwrap_or(&default_origin))
        .map_err(|e| anyhow!("Invalid SIWEOIDC_RP_ORIGIN: {}", e))?;

    WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| anyhow!("WebauthnBuilder::new failed (rp_id={}, origin={}): {:?}", rp_id, rp_origin, e))?
        .build()
        .map_err(|e| anyhow!("Webauthn::build failed: {:?}", e))
}
