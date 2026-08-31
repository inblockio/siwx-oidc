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
use tracing::{info, warn};
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{AllowCredentials, AuthenticatorSelectionCriteria, ResidentKeyRequirement};

use siwx_oidc::db::RedisClient;

// -- Redis key prefixes for WebAuthn state --

const CHALLENGE_PREFIX: &str = "webauthn:challenge";
const CREDENTIAL_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_CREDENTIAL_PREFIX;
// The same constant the library's credential-identity resolver and the backfill
// read, so a reader and this writer cannot drift onto different key spellings.
// Ownership of the namespace is unchanged: `link_finish` is still the only
// writer.
const LINK_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_LINK_PREFIX;
const LINK_CHALLENGE_PREFIX: &str = "webauthn:link_challenge";
const CHALLENGE_TTL: u64 = 120; // 2 min

// -- DID derivation from P-256 public key --
//
// Not implemented here. `aqua_auth::p256_compressed_from_passkey` and
// `aqua_auth::did_key_from_p256_compressed` are the same computation, and since
// the `=0.6.1-dev` alignment `Passkey` is literally the same type in both
// crates, so the local copies (a multicodec constant, a COSE -> compressed-SEC1
// extractor, and a base58 encoder) were duplicates rather than an independent
// implementation. Byte-identity is pinned by
// `derivation_is_byte_identical_to_the_pre_0_7_0_local_helpers` below, against
// the values the deleted code produced for the real fixture blob.

/// The compressed (33-byte SEC1) P-256 public key a passkey authenticates with.
fn compressed_pubkey_from_passkey(passkey: &Passkey) -> Result<[u8; 33]> {
    aqua_auth::p256_compressed_from_passkey(passkey).map_err(|e| anyhow!("{}", e))
}

fn did_from_passkey(passkey: &Passkey) -> Result<String> {
    let compressed = compressed_pubkey_from_passkey(passkey)?;
    Ok(aqua_auth::did_key_from_p256_compressed(&compressed))
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

/// Whether `did` resolves to a Matrix identity that does NOT yet exist on this
/// homeserver, i.e. signing in with it would CREATE a brand-new account.
///
/// This is the read-only detector the new-user gate and the account/QR reject
/// paths share: it is exactly `SynapseClient::is_localpart_available(localpart)`,
/// where `localpart` is `oidc::did_to_localpart(did)` (the same lowercasing the
/// provisioning path uses, so the answer matches what `sign_in` would do). It
/// performs no writes, so probing it before any provisioning leaves zero Synapse
/// state behind.
///
/// A free fn taking `&SynapseClient` (rather than a method on `SynapseClient`)
/// because `did_to_localpart` lives in the binary's `oidc` module while
/// `SynapseClient` lives in the `siwx_oidc` library crate; keeping the wrapper
/// here avoids a library->binary dependency.
pub async fn is_new_identity(
    synapse: &crate::synapse_client::SynapseClient,
    did: &str,
) -> Result<bool> {
    let localpart = crate::oidc::did_to_localpart(did);
    synapse.is_localpart_available(&localpart).await
}

/// The error message returned by every server-enforced new-account-creation
/// reject (account re-auth + QR/device approval). New-account creation is
/// permitted ONLY at the login screen, behind the new-user gate; in the
/// account-management and QR/device-approval flows it is impossible.
pub const NEW_IDENTITY_REJECT_MSG: &str =
    "This passkey/wallet is not linked to an existing account. \
     Create an account at sign-in first.";

/// Server-enforced reject for the account + QR/device flows: if a Synapse client
/// is configured AND the authenticated `did` resolves to a NON-existent account
/// (`is_new_identity == true`), return a clear `BadRequest` and provision
/// nothing. Call this AFTER the DID is cryptographically verified but BEFORE any
/// action runs / any device-code entry is mutated.
///
/// Graceful degradation: when `synapse` is `None` the new-identity status cannot
/// be detected, so this is a no-op (the flow's existing `require_synapse` /
/// `server_name` guards already `BadRequest` for the actions that need Synapse).
/// Returning the existing-identity path unchanged keeps `is_new_identity == false`
/// a strict no-op.
pub async fn reject_if_new_identity(
    synapse: Option<&crate::synapse_client::SynapseClient>,
    did: &str,
) -> Result<(), crate::oidc::CustomError> {
    let synapse = match synapse {
        Some(s) => s,
        None => return Ok(()),
    };
    match is_new_identity(synapse, did).await {
        Ok(true) => {
            info!(did = %did, "rejecting new-identity (no existing account) outside login flow");
            Err(crate::oidc::CustomError::BadRequest(
                NEW_IDENTITY_REJECT_MSG.to_string(),
            ))
        }
        Ok(false) => Ok(()),
        // A detection failure (Synapse unreachable) must not silently create an
        // account: fail closed with the same clear message rather than provisioning.
        Err(e) => {
            warn!(did = %did, "new-identity detection failed, rejecting to avoid silent creation: {}", e);
            Err(crate::oidc::CustomError::BadRequest(
                NEW_IDENTITY_REJECT_MSG.to_string(),
            ))
        }
    }
}

/// The error message returned by every server-enforced deactivated-account
/// reject. Deliberately does NOT distinguish "deactivated" from "erased" to the
/// caller: both mean the same thing to the person at the keyboard, and Synapse
/// reports them identically (`is_deactivated == true`) anyway.
pub const DEACTIVATED_REJECT_MSG: &str = "This account has been deactivated and cannot sign in. \
     Contact a server administrator if you believe this is a mistake.";

/// Server-enforced reject for a **deactivated** account.
///
/// # Why this exists
///
/// Deactivation was enforceable nowhere before this gate. Synapse's delegated
/// auth path (`synapse/api/auth/mas.py`, 1.159.0) contains **zero** references
/// to `deactivated` — under MSC3861 Synapse does not own the tokens, so it
/// trusts our introspection response and never consults `users.deactivated`.
/// On our side the Redis tombstone (`DBClient::is_user_deactivated`) is a
/// bounded-TTL race guard for the refresh/mint path (S3-4 / H6), not a durable
/// authority, and nothing consulted it at sign-in. The net effect was that
/// `account_deactivate` and `account_erase` were undone by simply signing in
/// again: `is_localpart_available` reports a deactivated user's localpart as
/// *taken*, so the new-identity gate classified them as a normal returning
/// account and issued a full session.
///
/// Synapse is therefore the authority here, via
/// [`SynapseClient::query_user`](crate::synapse_client::SynapseClient::query_user).
///
/// # Semantics
///
/// * `synapse == None` — no-op. Standalone deployments have no account to
///   deactivate, and this must never 500 a working standalone login.
/// * account exists and `is_deactivated == true` — `Unauthorized`.
/// * account exists and `is_deactivated == false` — `Ok(())`.
/// * account does **not** exist (`query_user` → `None`) — `Ok(())`. That is the
///   new-identity case and belongs to [`reject_if_new_identity`]; conflating the
///   two here would break first-time sign-in, which is legitimate at the login
///   screen.
/// * probe failed — **fails closed** with the same message, matching
///   [`reject_if_new_identity`]. A Synapse outage must not silently re-open
///   access to deactivated accounts.
pub async fn reject_if_deactivated(
    synapse: Option<&crate::synapse_client::SynapseClient>,
    did: &str,
) -> Result<(), crate::oidc::CustomError> {
    let synapse = match synapse {
        Some(s) => s,
        None => return Ok(()),
    };
    let localpart = crate::oidc::did_to_localpart(did);
    match synapse.query_user(&localpart).await {
        Ok(Some(info)) if info.is_deactivated => {
            info!(did = %did, "rejecting sign-in for deactivated account");
            Err(crate::oidc::CustomError::Unauthorized(
                DEACTIVATED_REJECT_MSG.to_string(),
            ))
        }
        // Active account, or no account at all (the new-identity case).
        Ok(_) => Ok(()),
        Err(e) => {
            warn!(did = %did, "deactivation probe failed, rejecting to avoid reviving a deactivated account: {}", e);
            Err(crate::oidc::CustomError::Unauthorized(
                DEACTIVATED_REJECT_MSG.to_string(),
            ))
        }
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

    // Maintain the webauthn:by_did reverse index so a returning login can scope
    // the passkey picker to this DID's keys without a credential keyspace scan.
    // A standalone passkey resolves to its derived did:key. Best-effort: the index
    // is advisory (get_passkeys_for_did self-heals via scan), so a hiccup here must
    // not fail the registration the user just completed.
    if let Err(e) = redis.index_add_passkey(&did, &cred_id_b64).await {
        info!(
            "webauthn register_finish: by_did index update failed: {}",
            e
        );
    }

    // Dual-write into aqua-auth's credential store when it is enabled. A fresh
    // registration is unlinked, so its identity is the derived did:key. No-op
    // when the flag is off, and best-effort when it is on: the legacy write
    // above already succeeded, so the user is not locked out either way.
    siwx_oidc::credential_store::mirror_credential(&cred_id_b64, &cred_json, &did, None).await;

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

/// Begin a WebAuthn assertion ceremony.
///
/// Two paths, selected by `scope_did`:
///
/// * `None` — **discoverable (usernameless)** authentication: `allow_credentials`
///   is left EMPTY. Credentials are registered as discoverable resident keys (see
///   `require_resident_key`), so the authenticator surfaces only the user's own
///   passkey and `verify_credential` resolves it by raw id. We must NOT enumerate
///   stored credentials here: that leaked every credential id to unauthenticated
///   callers and produced a server-wide passkey picker. This is the historical
///   (and still-default) behavior; ALL callers pass `None` until the cookie wiring
///   lands, so the runtime behavior is identical to before.
///
/// * `Some(did)` — **scoped** authentication: `allow_credentials` is set to exactly
///   the credentials that resolve to `did` (its standalone passkeys plus any
///   wallet-linked ones), via `get_passkeys_for_did`. The picker then shows only
///   that account. Enumeration-safety: this path runs ONLY when a caller supplies a
///   DID, and a caller may only do so after resolving it from a VALID opaque
///   user-session token (a forged/guessed token is a Redis miss -> `None` ->
///   usernameless). If the resolved credential set is EMPTY (e.g. a wallet-only DID
///   with no linked passkey), we fall back to leaving `allow_credentials` empty
///   (discoverable) rather than emitting a broken empty picker that would block
///   every key.
///
/// Note: we deliberately do NOT use `start_passkey_authentication` / persist a
/// `PasskeyAuthentication` finish-state. `verify_credential` verifies the assertion
/// MANUALLY (via `aqua_auth::verify_webauthn_assertion`) against the challenge
/// STRING stored in Redis; it never consumes a webauthn-rs finish-state. So for the
/// scoped path we obtain a `RequestChallengeResponse` exactly as the usernameless
/// path does and set `allow_credentials` directly (the shape the pre-discoverable
/// code used). The stored challenge and `verify_credential` are unchanged.
pub async fn authenticate_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    scope_did: Option<&str>,
) -> Result<RequestChallengeResponse> {
    let (mut rcr, _auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| anyhow!("WebAuthn auth start failed: {:?}", e))?;

    if let Some(did) = scope_did {
        // The UNION of the legacy webauthn:by_did index (with its scan
        // self-heal) and, when the flag is on, aqua-auth's did index -- not a
        // preference for one over the other. An EMPTY result is advisory and
        // means usernameless rather than denied, but a PARTIAL result is not:
        // a non-empty allow_credentials restricts the authenticator to exactly
        // that set, so omitting a passkey the backfill has not reached yet
        // locks that device out. See credential_store::list_credential_ids.
        let cred_ids = siwx_oidc::credential_store::list_credential_ids(
            redis,
            did,
            derive_did_from_credential_json,
        )
        .await?;
        // Empty set -> fall back to discoverable (leave allow_credentials empty) so a
        // wallet-only DID does not produce a broken empty picker that blocks all keys.
        if !cred_ids.is_empty() {
            let allow_list: Vec<AllowCredentials> = cred_ids
                .iter()
                .filter_map(|cred_id_b64| {
                    let bytes = URL_SAFE_NO_PAD.decode(cred_id_b64).ok()?;
                    Some(AllowCredentials {
                        type_: "public-key".to_string(),
                        // webauthn-rs-proto 0.6.1-dev types this as a plain
                        // `Vec<u8>` (it was `Base64UrlSafeData` in 0.6.0-dev).
                        // The JSON wire form is unchanged: the field still
                        // serializes as unpadded base64url via `serde_as`.
                        id: bytes,
                        transports: None,
                    })
                })
                .collect();
            rcr.public_key.allow_credentials = allow_list;
            info!(
                "webauthn authenticate_start: session={} scoped did={} creds={}",
                session_id,
                did,
                rcr.public_key.allow_credentials.len()
            );
        } else {
            info!(
                "webauthn authenticate_start: session={} scope did={} resolved 0 creds -> discoverable fallback",
                session_id, did
            );
        }
    }

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
    // Read-through: aqua-auth's credential store first when the flag is on, this
    // namespace on a miss. The fallback is what makes the flag safe to flip
    // before the backfill has run.
    let cred_json = siwx_oidc::credential_store::read_blob(redis, &cred_id_b64)
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
        Ok(false) => return Err(anyhow!("WebAuthn assertion signature verification failed").into()),
        Err(e) => return Err(anyhow!("WebAuthn assertion verification error: {}", e).into()),
    }

    let flags = auth_response.response.authenticator_data[32];
    if flags & 0x04 == 0 {
        return Err(anyhow!("User Verification flag not set").into());
    }

    let passkey_did = did_from_passkey(&passkey)?;

    // A `webauthn:link` entry OVERRIDES the DID derived from the passkey. That
    // rule now lives in one place, `credential_identity`, because the
    // credential-store backfill has to reproduce it exactly: if the two ever
    // disagreed, every linked credential would be stored under one principal and
    // authenticate as another. Read-only; linking is still written only by
    // `link_finish` below.
    let did = siwx_oidc::credential_identity::resolve_credential_identity(
        redis,
        &cred_id_b64,
        &passkey_did,
    )
    .await?
    .did;

    let auth_data = &*auth_response.response.authenticator_data;
    if auth_data.len() >= 37 {
        let new_counter =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        let mut passkey_value: serde_json::Value =
            serde_json::from_str(&cred_json).map_err(|e| {
                anyhow!(
                    "Failed to parse stored credential for counter update: {}",
                    e
                )
            })?;
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
        // Dual-write the counter. aqua-auth keeps it in a sidecar field rather
        // than inside the blob, and its store is monotonic, so a replayed lower
        // value is ignored there exactly as the regression check above rejects
        // it here.
        siwx_oidc::credential_store::mirror_sign_count(&cred_id_b64, new_counter).await;
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

    // Maintain the webauthn:by_did reverse index against the PRIMARY (wallet) DID:
    // a linked passkey resolves to primary_did at verify time, so a returning login
    // scoped to the wallet DID must surface this passkey. Best-effort (advisory).
    if let Err(e) = redis
        .index_add_passkey(&link_state.primary_did, &cred_id_b64)
        .await
    {
        info!("webauthn link_finish: by_did index update failed: {}", e);
    }

    // Dual-write into aqua-auth's credential store when it is enabled, under the
    // PRIMARY did and with the link's label, because that is what
    // `resolve_credential_identity` (and therefore a login) resolves for this
    // credential. Writing the derived did:key here would record a principal the
    // login path never produces. The link entry itself is NOT mirrored: it stays
    // owned by, and readable only from, this namespace.
    siwx_oidc::credential_store::mirror_credential(
        &cred_id_b64,
        &cred_json,
        &link_state.primary_did,
        Some(link_entry.label.clone()),
    )
    .await;

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

    /// Byte-identity across the 0.7.0 helper deletion.
    ///
    /// `compressed_pubkey_from_passkey` and `did_from_passkey` used to be
    /// implemented here (a `P256_MULTICODEC` constant, a COSE -> compressed-SEC1
    /// extractor, a base58 encoder) and now delegate to aqua-auth. The two
    /// values below were produced by the DELETED local implementation against
    /// this exact fixture, so this test fails if the delegation is not
    /// bit-for-bit the same computation.
    ///
    /// The compressed key matters as much as the DID: it is what
    /// `verify_credential` hands to `verify_webauthn_assertion` as
    /// `credential_public_key`, so a single flipped byte would reject every
    /// login rather than merely rename an identity.
    #[test]
    fn derivation_is_byte_identical_to_the_pre_0_7_0_local_helpers() {
        const BLOB: &str = include_str!("../tests/fixtures/passkey_webauthn_rs_0_6_0_dev.json");
        const PRE_0_7_0_COMPRESSED_HEX: &str =
            "02a463503d9518bd64a40f5760b9b3b4cd2c419848896a959109434c4453773da4";
        const PRE_0_7_0_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";

        let passkey: Passkey = serde_json::from_str(BLOB).expect("fixture parses");
        let compressed = compressed_pubkey_from_passkey(&passkey).expect("P-256");
        assert_eq!(compressed.len(), 33, "compressed SEC1 is 33 bytes");
        assert_eq!(
            hex::encode(compressed),
            PRE_0_7_0_COMPRESSED_HEX,
            "the compressed public key must be byte-identical to the deleted local helper"
        );
        assert_eq!(
            did_from_passkey(&passkey).expect("derives"),
            PRE_0_7_0_DID,
            "the derived did:key must be byte-identical to the deleted local helper"
        );
        assert_eq!(
            derive_did_from_credential_json(BLOB).as_deref(),
            Some(PRE_0_7_0_DID),
            "the purge-path resolver must agree too"
        );
    }

    /// The serialized `Passkey` blob written by webauthn-rs **0.6.0-dev** (the
    /// version this crate ran before the `=0.6.1-dev` alignment) must still
    /// deserialize under 0.6.1-dev, and must still derive the same
    /// `did:key:zDn…`. That is what makes the credential store shareable with
    /// aqua-auth/aqua-node/aquafier: a passkey registered by the old binary is
    /// readable by the new one, and both agree on the identity it maps to.
    ///
    /// The fixture is a REAL blob, produced by a full `start_passkey_registration`
    /// /`finish_passkey_registration` ceremony against a `webauthn-authenticator-rs`
    /// SoftToken linked to webauthn-rs 0.6.0-dev, then copied verbatim. It closes the
    /// positive-round-trip coverage gap noted on the test above without adding a
    /// software-authenticator dependency to this crate.
    #[test]
    fn passkey_blob_from_webauthn_rs_060dev_still_deserializes_and_derives_same_did() {
        const BLOB: &str = include_str!("../tests/fixtures/passkey_webauthn_rs_0_6_0_dev.json");
        const EXPECTED_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";
        const EXPECTED_CRED_ID: &str = "437HJ4gJirHMj5bDSeoDN6ODix56R_i5GgCLhqF0L9I";

        let passkey: Passkey = serde_json::from_str(BLOB)
            .expect("a 0.6.0-dev Passkey blob must deserialize under the pinned webauthn-rs");

        assert_eq!(
            URL_SAFE_NO_PAD.encode(passkey.cred_id()),
            EXPECTED_CRED_ID,
            "credential id must be stable across the webauthn-rs bump"
        );
        assert_eq!(
            did_from_passkey(&passkey).expect("P-256 passkey"),
            EXPECTED_DID,
            "did:key derivation must be stable across the webauthn-rs bump"
        );
        assert_eq!(
            derive_did_from_credential_json(BLOB).as_deref(),
            Some(EXPECTED_DID),
            "the purge-path resolver must agree with did_from_passkey"
        );

        // Re-serializing must not rewrite the stored blob: the counter-update
        // path in `verify_credential` writes the value back, so a serialization
        // drift here would silently rewrite every credential on first login.
        let reserialized = serde_json::to_string(&passkey).expect("serialize");
        assert_eq!(
            reserialized.trim(),
            BLOB.trim(),
            "re-serialization must be byte-identical to the 0.6.0-dev blob"
        );
    }

    /// H5 (graceful degradation): when no Synapse client is configured the
    /// account/QR flows cannot detect a new identity, so `reject_if_new_identity`
    /// is a strict no-op (returns Ok). Deterministic, no network: this is the
    /// branch that preserves standalone-deployment behavior. (The other guards in
    /// those flows already BadRequest for the actions that need Synapse.)
    #[tokio::test]
    async fn reject_if_new_identity_is_noop_without_synapse() {
        assert!(
            reject_if_new_identity(None, "did:key:zDnANYTHING")
                .await
                .is_ok(),
            "no Synapse client must be a no-op (cannot detect, do not reject)"
        );
    }

    /// H5 (fail-closed): a Synapse client that is present but UNREACHABLE is a
    /// detection failure. We must NOT fall through and provision a new account; we
    /// reject with the same clear `BadRequest` message. Points at an unroutable
    /// endpoint so the request fails fast without a live Synapse.
    #[tokio::test]
    async fn reject_if_new_identity_fails_closed_on_synapse_error() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable.
        let synapse = crate::synapse_client::SynapseClient::new("http://192.0.2.1:1", "secret");
        let err = reject_if_new_identity(Some(&synapse), "did:key:zDnUNREACHABLE")
            .await
            .expect_err("detection failure must reject, not silently create");
        match err {
            crate::oidc::CustomError::BadRequest(msg) => {
                assert_eq!(msg, NEW_IDENTITY_REJECT_MSG);
            }
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    /// Graceful degradation, mirroring `reject_if_new_identity_is_noop_without_synapse`:
    /// a standalone deployment has no Synapse account to deactivate, so the gate
    /// must be a strict no-op rather than failing closed and breaking every login.
    #[tokio::test]
    async fn reject_if_deactivated_is_noop_without_synapse() {
        assert!(
            reject_if_deactivated(None, "did:key:zDnANYTHING")
                .await
                .is_ok(),
            "no Synapse client must be a no-op (cannot detect, do not reject)"
        );
    }

    /// Fail-closed: a present-but-UNREACHABLE Synapse is a detection failure. It
    /// must NOT fall through to a working session — that is exactly the bypass
    /// this gate exists to close, and a Synapse outage is the moment it would
    /// matter most. Unlike the new-identity gate this surfaces `Unauthorized`,
    /// because the semantic is "you may not sign in", not "your request was bad".
    #[tokio::test]
    async fn reject_if_deactivated_fails_closed_on_synapse_error() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable.
        let synapse = crate::synapse_client::SynapseClient::new("http://192.0.2.1:1", "secret");
        let err = reject_if_deactivated(Some(&synapse), "did:key:zDnUNREACHABLE")
            .await
            .expect_err("probe failure must reject, not revive a deactivated account");
        match err {
            crate::oidc::CustomError::Unauthorized(msg) => {
                assert_eq!(msg, DEACTIVATED_REJECT_MSG);
            }
            other => panic!("expected Unauthorized, got {:?}", other),
        }
    }

    /// The gate reads exactly one field off the MAS wire, so pin the shape of
    /// `MasQueryUserResource.Response` (synapse 1.159.0). Two properties matter:
    /// an ACTIVE user must parse to `is_deactivated == false` (a parse that
    /// defaulted the wrong way would silently lock every user out), and an
    /// unknown extra field must not break parsing on a security path.
    #[test]
    fn mas_user_info_parses_the_synapse_wire_shape() {
        use crate::synapse_client::MasUserInfo;

        let active: MasUserInfo = serde_json::from_str(
            r#"{"user_id":"@alice:example.org","display_name":"Alice","avatar_url":null,
                 "is_suspended":false,"is_deactivated":false}"#,
        )
        .expect("active user must parse");
        assert!(
            !active.is_deactivated,
            "active user must not read as deactivated"
        );
        assert_eq!(active.user_id, "@alice:example.org");

        let gone: MasUserInfo = serde_json::from_str(
            r#"{"user_id":"@bob:example.org","display_name":null,"avatar_url":null,
                 "is_suspended":false,"is_deactivated":true,"future_field":42}"#,
        )
        .expect("unknown fields must not break a security-gate parse");
        assert!(
            gone.is_deactivated,
            "deactivated user must read as deactivated"
        );
    }

    /// H2 (enumeration-safety): a FORGED `siwx_user` cookie token is a Redis miss,
    /// so the handler resolves `scope_did = None` and `authenticate_start` runs the
    /// usernameless (discoverable) path with an EMPTY `allowCredentials` — leaking
    /// zero credential ids. This exercises the exact seam the HTTP handler uses
    /// (`lookup_user_session` -> `authenticate_start(scope_did)`), end to end against
    /// Redis. Requires Redis on localhost; skips cleanly when unavailable.
    #[tokio::test]
    async fn forged_user_cookie_yields_usernameless_empty_allow_credentials() {
        let redis = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
        };

        // A localhost RP is valid for WebauthnBuilder (origin must be https OR
        // localhost); this lets the test build a real Webauthn without TLS.
        let base = Url::parse("http://localhost:8000").unwrap();
        let cfg = build_webauthn(&base, None, None).expect("build webauthn");

        // A forged/guessed token that was never minted -> lookup must miss -> None.
        let nonce = Uuid::new_v4().simple().to_string();
        let forged = format!("forged{nonce}deadbeefcafe");
        let scope_did = redis
            .lookup_user_session(&forged)
            .await
            .expect("lookup must not error");
        assert!(
            scope_did.is_none(),
            "a forged token must be a Redis miss -> None (usernameless fallback)"
        );

        // Drive authenticate_start with the resolved (None) scope: usernameless.
        let session_id = format!("forgedsess{nonce}");
        let rcr = authenticate_start(&cfg.webauthn, &redis, &session_id, scope_did.as_deref())
            .await
            .expect("authenticate_start must succeed");
        assert!(
            rcr.public_key.allow_credentials.is_empty(),
            "forged cookie -> usernameless -> allowCredentials MUST be empty (no enumeration)"
        );
    }

    /// H1/H2 (positive scoping): a VALID `siwx_user` session for DID A makes
    /// `authenticate_start` offer EXACTLY A's credential and NEVER B's. This is the
    /// other half of the forged-cookie test — it proves the scoped path is correct,
    /// not merely safe, and is the server-side twin of the browser two-credential
    /// case. Seeds the `by_did` index directly (the SMEMBERS fast path) so it needs no
    /// real attestation. Requires Redis on localhost; skips cleanly when unavailable.
    #[tokio::test]
    async fn valid_user_session_scopes_allow_credentials_to_its_did_only() {
        let redis = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
        };
        let base = Url::parse("http://localhost:8000").unwrap();
        let cfg = build_webauthn(&base, None, None).expect("build webauthn");

        let nonce = Uuid::new_v4().simple().to_string();
        let did_a = format!("did:key:zDnA{nonce}");
        let did_b = format!("did:key:zDnB{nonce}");
        let cred_a = URL_SAFE_NO_PAD.encode(format!("credA-{nonce}").as_bytes());
        let cred_b = URL_SAFE_NO_PAD.encode(format!("credB-{nonce}").as_bytes());
        redis
            .index_add_passkey(&did_a, &cred_a)
            .await
            .expect("seed A");
        redis
            .index_add_passkey(&did_b, &cred_b)
            .await
            .expect("seed B");

        // Mint the opaque user-session the handler resolves from the siwx_user cookie.
        let token = redis
            .create_user_session(&did_a)
            .await
            .expect("mint session");
        let scope_did = redis.lookup_user_session(&token).await.expect("lookup");
        assert_eq!(scope_did.as_deref(), Some(did_a.as_str()));

        let session_id = format!("scopesess{nonce}");
        let rcr = authenticate_start(&cfg.webauthn, &redis, &session_id, scope_did.as_deref())
            .await
            .expect("authenticate_start");

        let offered: Vec<String> = rcr
            .public_key
            .allow_credentials
            .iter()
            .map(|c| URL_SAFE_NO_PAD.encode(&*c.id))
            .collect();
        assert_eq!(
            offered,
            vec![cred_a.clone()],
            "scoped to A: offer exactly A's credential"
        );
        assert!(
            !offered.contains(&cred_b),
            "B's credential must NEVER be offered when scoped to A"
        );

        // Cleanup so reruns stay isolated (no TTL on by_did / user-session here).
        redis.index_remove_passkey(&did_a, &cred_a).await.ok();
        redis.index_remove_passkey(&did_b, &cred_b).await.ok();
        redis.destroy_user_session(&token).await.ok();
    }
}
