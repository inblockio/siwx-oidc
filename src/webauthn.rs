//! WebAuthn/passkey ceremony — server-layer authentication (Layer 2).
//!
//! This module handles the full WebAuthn ceremony using the `webauthn-rs` safe API.
//! It does NOT extend `DIDMethod` — see PLAN_webauthn.md for rationale.
//!
//! After successful authentication, the verified DID is stored in the Redis session.
//! `sign_in` reads it from there (server-side, trusted).

use anyhow::{anyhow, Result};
use aqua_auth::{verify_webauthn_assertion, WebAuthnAssertionParams};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{AuthenticatorSelectionCriteria, ResidentKeyRequirement};

use siwx_oidc::db::RedisClient;

// -- Redis key prefixes for WebAuthn state --

const CHALLENGE_PREFIX: &str = "webauthn:challenge";
const CREDENTIAL_PREFIX: &str = "webauthn:credential";
const LINK_PREFIX: &str = "webauthn:link";
const LINK_CHALLENGE_PREFIX: &str = "webauthn:link_challenge";
const CHALLENGE_TTL: u64 = 120; // 2 min

// -- DID derivation from P-256 public key --

/// Multicodec varint for P-256 (0x1200), same as aqua-auth key module.
const P256_MULTICODEC: &[u8] = &[0x80, 0x24];

/// Derive a `did:key:zDn…` from a P-256 compressed SEC1 public key (33 bytes).
fn did_from_p256_compressed(compressed: &[u8]) -> String {
    let mut bytes = P256_MULTICODEC.to_vec();
    bytes.extend_from_slice(compressed);
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

fn compressed_pubkey_from_passkey(passkey: &Passkey) -> Result<Vec<u8>> {
    let cose_key = passkey.get_public_key();
    match &cose_key.key {
        COSEKeyType::EC_EC2(ec2) => {
            if ec2.curve != ECDSACurve::SECP256R1 {
                return Err(anyhow!(
                    "WebAuthn credential uses unsupported curve (expected P-256)"
                ));
            }
            let y_bytes: &[u8] = ec2.y.as_ref();
            let y_is_odd = y_bytes.last().is_some_and(|b| b & 1 == 1);
            let prefix = if y_is_odd { 0x03 } else { 0x02 };
            let mut compressed = vec![prefix];
            compressed.extend_from_slice(ec2.x.as_ref());
            Ok(compressed)
        }
        _ => Err(anyhow!(
            "WebAuthn credential is not EC2/P-256 — cannot derive did:key"
        )),
    }
}

fn did_from_passkey(passkey: &Passkey) -> Result<String> {
    let compressed = compressed_pubkey_from_passkey(passkey)?;
    Ok(did_from_p256_compressed(&compressed))
}

/// Derive the `did:key:zDn…` for a stored WebAuthn credential from its raw JSON
/// (the value stored at `webauthn:credential/{cred_id}`), or `None` if the JSON
/// is not a deserializable P-256 passkey.
///
/// This is the resolver `RedisClient::purge_identity` uses for its best-effort
/// standalone-credential pass: it lets the DB layer stay free of the webauthn-rs
/// types while still reusing the single source of truth for DID derivation.
pub fn derive_did_from_credential_json(cred_json: &str) -> Option<String> {
    let passkey: Passkey = serde_json::from_str(cred_json).ok()?;
    did_from_passkey(&passkey).ok()
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

/// Typed outcome of a failed assertion verification.
///
/// `UnknownCredential` is the single, narrowly-scoped case where the presented
/// credential is not registered on this server (a stale/revoked passkey selected
/// from the platform picker). It is constructed at exactly one site (the Redis
/// credential lookup miss) and carries the base64url credential id so the handler
/// can echo it back to the client for a privacy-safe `signalUnknownCredential`
/// prune. Every OTHER failure mode (expired/decoded challenge, empty id, signature
/// mismatch, missing UV flag, sign-count regression) stays `Other` and keeps its
/// existing 500/internal-error classification. This isolation is load-bearing: a
/// valid passkey must never be signaled for pruning because of a transient or
/// unrelated failure.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The presented credential id is not registered on this server.
    /// Carries the base64url credential id.
    #[error("Credential not found: {0}")]
    UnknownCredential(String),
    /// Any other verification failure (challenge, signature, flags, counter, I/O).
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// -- Account linking (Phase 2) --

/// Stored at `webauthn:link/{cred_id_b64}` — maps a passkey credential to a primary DID.
#[derive(Serialize, Deserialize)]
pub struct LinkEntry {
    pub primary_did: String,
    pub label: String,
}

/// Challenge state for link ceremonies — wraps the registration state with the primary DID.
#[derive(Serialize, Deserialize)]
struct LinkChallengeState {
    reg_state_json: String,
    primary_did: String,
}

#[derive(Serialize)]
pub struct LinkFinishResponse {
    pub credential_id: String,
    pub primary_did: String,
}

/// Upgrade a passkey registration challenge to require a **discoverable (resident)**
/// credential. `webauthn-rs`'s `start_passkey_registration` requests
/// `residentKey: discouraged`, which yields non-discoverable credentials usable only
/// when the server supplies their id in `allowCredentials`. In a usernameless flow
/// that forces enumerating EVERY credential to the browser (a privacy leak + a
/// server-wide passkey picker). Requesting a resident key instead lets the
/// authenticator surface only the user's own passkey, so `authenticate_start` can use
/// an empty `allowCredentials`. (Existing non-resident credentials predate this and
/// must be re-registered to gain discoverability.)
fn require_resident_key(ccr: &mut CreationChallengeResponse) {
    let sel = ccr
        .public_key
        .authenticator_selection
        .get_or_insert_with(AuthenticatorSelectionCriteria::default);
    sel.resident_key = Some(ResidentKeyRequirement::Required);
    sel.require_resident_key = true;
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

    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, name, name, None)
        .map_err(|e| anyhow!("WebAuthn registration start failed: {:?}", e))?;
    require_resident_key(&mut ccr);

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
    // Discoverable (usernameless) authentication: leave `allow_credentials` EMPTY.
    // Credentials are registered as discoverable resident keys (see
    // `require_resident_key`), so the authenticator surfaces only the user's own
    // passkey and `verify_credential` resolves it by raw id. We must NOT enumerate
    // stored credentials here: that leaked every credential id to unauthenticated
    // callers and produced a server-wide passkey picker.
    let (rcr, _auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| anyhow!("WebAuthn auth start failed: {:?}", e))?;

    let challenge_b64 = URL_SAFE_NO_PAD.encode(&*rcr.public_key.challenge);
    redis
        .set_ex_raw(
            &format!("{}/{}", CHALLENGE_PREFIX, session_id),
            &challenge_b64,
            CHALLENGE_TTL,
        )
        .await?;

    info!("webauthn authenticate_start: session={}", session_id);
    Ok(rcr)
}

/// Core WebAuthn assertion verification: challenge retrieval, credential lookup,
/// cryptographic verification, counter update, and DID resolution. Shared by
/// both the OIDC login flow and the device approval flow.
pub async fn verify_credential(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: &PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let challenge_b64 = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No auth challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .map_err(|e| anyhow!("Failed to decode stored challenge: {}", e))?;

    let cred_id_b64 = URL_SAFE_NO_PAD.encode(&*auth_response.raw_id);
    if cred_id_b64.is_empty() {
        return Err(anyhow!("Empty credential ID in WebAuthn assertion").into());
    }
    let cred_key = format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64);
    let cred_json = redis
        .get_raw(&cred_key)
        .await?
        // The ONLY site that yields VerifyError::UnknownCredential. A stale/revoked
        // passkey selected from the picker lands here (lookup precedes signature
        // verification), so this is reachable without a forged signature. Keeping the
        // lookup before verification is load-bearing for the 401-not-500 path.
        .ok_or_else(|| VerifyError::UnknownCredential(cred_id_b64.clone()))?;
    let passkey: Passkey = serde_json::from_str(&cred_json)
        .map_err(|e| anyhow!("Failed to deserialize credential: {}", e))?;

    let compressed_pubkey = compressed_pubkey_from_passkey(&passkey)?;

    let der_sig = &*auth_response.response.signature;
    let sig = Signature::from_der(der_sig)
        .map_err(|e| anyhow!("Failed to DER-decode ECDSA signature: {}", e))?;
    let sig_bytes = sig.to_bytes();

    let params = WebAuthnAssertionParams {
        credential_public_key: &compressed_pubkey,
        authenticator_data: &auth_response.response.authenticator_data,
        client_data_json: &auth_response.response.client_data_json,
        signature: &sig_bytes,
        expected_challenge: &challenge_bytes,
        expected_origin: rp_origin,
        expected_rp_id: rp_id,
    };

    match verify_webauthn_assertion(&params) {
        Ok(true) => {}
        Ok(false) => {
            return Err(anyhow!("WebAuthn assertion signature verification failed").into())
        }
        Err(e) => return Err(anyhow!("WebAuthn assertion verification error: {}", e).into()),
    }

    let flags = auth_response.response.authenticator_data[32];
    if flags & 0x04 == 0 {
        return Err(anyhow!("User Verification flag not set").into());
    }

    let passkey_did = did_from_passkey(&passkey)?;

    let did = match redis
        .get_raw(&format!("{}/{}", LINK_PREFIX, cred_id_b64))
        .await?
    {
        Some(link_json) => {
            let link_entry: LinkEntry = serde_json::from_str(&link_json)
                .map_err(|e| anyhow!("Failed to deserialize link entry: {}", e))?;
            info!(
                "webauthn verify_credential: linked cred={} primary_did={}",
                cred_id_b64, link_entry.primary_did
            );
            link_entry.primary_did
        }
        None => passkey_did,
    };

    let auth_data = &*auth_response.response.authenticator_data;
    if auth_data.len() >= 37 {
        let new_counter =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        let mut passkey_value: serde_json::Value = serde_json::from_str(&cred_json)
            .map_err(|e| anyhow!("Failed to parse stored credential for counter update: {}", e))?;
        if let Some(cred) = passkey_value.get_mut("cred") {
            let stored_counter = cred.get("counter").and_then(|c| c.as_u64()).unwrap_or(0) as u32;
            if (new_counter > 0 || stored_counter > 0) && new_counter < stored_counter {
                return Err(anyhow!(
                    "Sign count regression (stored={}, got={}), possible cloned authenticator",
                    stored_counter,
                    new_counter
                )
                .into());
            }
            cred["counter"] = serde_json::json!(new_counter);
        }
        redis
            .set_raw(
                &cred_key,
                &serde_json::to_string(&passkey_value)
                    .map_err(|e| anyhow!("Failed to serialize credential counter: {}", e))?,
            )
            .await?;
    }

    info!(
        "webauthn verify_credential: did={} cred={}",
        did, cred_id_b64
    );
    Ok(AuthenticateFinishResponse { ok: true, did })
}

/// Full authenticate-finish for the OIDC login flow: verifies the credential
/// AND stores the verified DID in the Redis session (needed by `sign_in`).
pub async fn authenticate_finish(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let resp = verify_credential(redis, session_id, rp_id, rp_origin, &auth_response).await?;

    let session_key = format!("sessions/{}", session_id);
    let session_json = redis
        .get_raw(&session_key)
        .await?
        .ok_or_else(|| anyhow!("Session not found"))?;
    let mut session: siwx_oidc::db::SessionEntry = serde_json::from_str(&session_json)
        .map_err(|e| anyhow!("Failed to deserialize session: {}", e))?;
    session.verified_did = Some(resp.did.clone());
    let updated_session = serde_json::to_string(&session)
        .map_err(|e| anyhow!("Failed to serialize session: {}", e))?;
    redis
        .set_ex_raw(
            &session_key,
            &updated_session,
            siwx_oidc::db::SESSION_LIFETIME,
        )
        .await?;

    Ok(resp)
}

// -- Account linking ceremony (Phase 2) ------------------------------------

pub async fn link_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    primary_did: &str,
    display_name: Option<String>,
) -> Result<CreationChallengeResponse> {
    let user_unique_id = Uuid::new_v4();
    let name = display_name.as_deref().unwrap_or("linked-passkey");

    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, name, name, None)
        .map_err(|e| anyhow!("WebAuthn registration start failed: {:?}", e))?;
    require_resident_key(&mut ccr);

    // Store registration state + primary_did in Redis.
    let reg_state_json = serde_json::to_string(&reg_state)
        .map_err(|e| anyhow!("Failed to serialize registration state: {}", e))?;
    let link_state = LinkChallengeState {
        reg_state_json,
        primary_did: primary_did.to_string(),
    };
    let state_json = serde_json::to_string(&link_state)
        .map_err(|e| anyhow!("Failed to serialize link challenge state: {}", e))?;
    redis
        .set_ex_raw(
            &format!("{}/{}", LINK_CHALLENGE_PREFIX, session_id),
            &state_json,
            CHALLENGE_TTL,
        )
        .await?;

    info!(
        "webauthn link_start: session={} primary_did={}",
        session_id, primary_did
    );
    Ok(ccr)
}

pub async fn link_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<LinkFinishResponse> {
    // Retrieve and consume the link challenge state.
    let challenge_key = format!("{}/{}", LINK_CHALLENGE_PREFIX, session_id);
    let state_json = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No link challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let link_state: LinkChallengeState = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize link challenge state: {}", e))?;
    let reg_state: PasskeyRegistration = serde_json::from_str(&link_state.reg_state_json)
        .map_err(|e| anyhow!("Failed to deserialize registration state: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow!("WebAuthn registration verification failed: {:?}", e))?;

    let cred_id_b64 = URL_SAFE_NO_PAD.encode(passkey.cred_id());

    // Store the credential persistently (same as register_finish).
    let cred_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize passkey: {}", e))?;
    redis
        .set_raw(
            &format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64),
            &cred_json,
        )
        .await?;

    // Store the link mapping: cred_id → primary_did.
    let link_entry = LinkEntry {
        primary_did: link_state.primary_did.clone(),
        label: "linked".to_string(),
    };
    let link_json = serde_json::to_string(&link_entry)
        .map_err(|e| anyhow!("Failed to serialize link entry: {}", e))?;
    redis
        .set_raw(&format!("{}/{}", LINK_PREFIX, cred_id_b64), &link_json)
        .await?;

    info!(
        "webauthn link_finish: cred_id={} primary_did={}",
        cred_id_b64, link_state.primary_did
    );
    Ok(LinkFinishResponse {
        credential_id: cred_id_b64,
        primary_did: link_state.primary_did,
    })
}

pub struct WebauthnConfig {
    pub webauthn: Webauthn,
    pub rp_id: String,
    pub rp_origin: String,
}

/// Build the Webauthn instance from config.
pub fn build_webauthn(
    base_url: &Url,
    rp_id: Option<&str>,
    rp_origin: Option<&str>,
) -> Result<WebauthnConfig> {
    let default_rp_id = base_url
        .host_str()
        .ok_or_else(|| anyhow!("SIWEOIDC_BASE_URL has no host — cannot derive WebAuthn RP ID"))?
        .to_string();
    let resolved_rp_id = rp_id.unwrap_or(&default_rp_id).to_string();

    let default_origin = base_url.as_str().trim_end_matches('/').to_string();
    let resolved_rp_origin = rp_origin
        .unwrap_or(&default_origin)
        .trim_end_matches('/')
        .to_string();
    let rp_origin_url = Url::parse(&resolved_rp_origin)
        .map_err(|e| anyhow!("Invalid SIWEOIDC_RP_ORIGIN: {}", e))?;

    let webauthn = WebauthnBuilder::new(&resolved_rp_id, &rp_origin_url)
        .map_err(|e| {
            anyhow!(
                "WebauthnBuilder::new failed (rp_id={}, origin={}): {:?}",
                resolved_rp_id,
                rp_origin_url,
                e
            )
        })?
        .build()
        .map_err(|e| anyhow!("Webauthn::build failed: {:?}", e))?;

    Ok(WebauthnConfig {
        webauthn,
        rp_id: resolved_rp_id,
        rp_origin: resolved_rp_origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `derive_did_from_credential_json` is the resolver `RedisClient::purge_identity`
    /// uses for its best-effort standalone-credential pass (pass b). It MUST fail
    /// closed: anything that is not a deserializable P-256 passkey returns `None`
    /// (never panics). This is what keeps a webauthn-rs serialization drift from
    /// turning purge into a silent crash; the load-bearing link-based pass (a) is
    /// unaffected, and a drift surfaces as pass (b) returning `None` (covered here),
    /// not as a panic in an erasure request.
    ///
    /// NOTE (residual coverage gap, tracked in the lifecycle audit): the POSITIVE
    /// round-trip (a real serialized webauthn-rs `Passkey` JSON -> stable
    /// `did:key:zDn…`) is exercised only by the ignored e2e webauthn path and the
    /// production read path, not a hermetic fixture, because constructing a valid
    /// `Passkey` needs a software authenticator dependency we deliberately do not add.
    #[test]
    fn derive_did_from_credential_json_fails_closed_on_non_passkey_input() {
        assert_eq!(derive_did_from_credential_json(""), None, "empty input");
        assert_eq!(
            derive_did_from_credential_json("not json at all"),
            None,
            "garbage input"
        );
        assert_eq!(
            derive_did_from_credential_json("{}"),
            None,
            "empty object is not a passkey"
        );
        assert_eq!(
            derive_did_from_credential_json(r#"{"cred":{"unexpected":"shape"}}"#),
            None,
            "wrong-shaped JSON must not panic, must return None"
        );
    }
}
