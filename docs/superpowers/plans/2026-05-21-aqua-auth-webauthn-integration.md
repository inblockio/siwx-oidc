# Replace webauthn-rs Assertion Verification with aqua-auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace webauthn-rs's `finish_discoverable_authentication` in the passkey login flow with aqua-auth's lightweight `verify_webauthn_assertion`, reducing the webauthn-rs surface to registration and challenge generation only.

**Architecture:** The `authenticate_finish` function currently delegates assertion verification to webauthn-rs (which deserializes a full state object from Redis). After this change, `authenticate_start` stores only the raw challenge bytes in Redis, and `authenticate_finish` extracts raw fields from the browser's `PublicKeyCredential`, DER-decodes the signature, and calls `aqua_auth::verify_webauthn_assertion` for cryptographic verification. webauthn-rs remains for registration/attestation (`finish_passkey_registration`) and challenge generation (`start_discoverable_authentication`).

**Tech Stack:** Rust, aqua-auth 0.2.0 (webauthn feature), p256 (DER signature decoding), webauthn-rs 0.6.0-dev (retained for registration)

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` | Modify | Enable `webauthn` feature on aqua-auth |
| `src/webauthn.rs` | Modify | Refactor `authenticate_start` (store raw challenge), rewrite `authenticate_finish` (use aqua-auth), extract `compressed_pubkey_from_passkey` helper, add `build_webauthn` resolved-value return |
| `src/axum_lib.rs` | Modify | Add `rp_id`/`rp_origin` to `AppState`, update route handler call |

## Context for the Implementer

### Key types from webauthn-rs-proto (read-only, not modified)

```
PublicKeyCredential {
    id: String,                                    // base64url cred ID
    raw_id: Base64UrlSafeData,                     // raw bytes (Deref<[u8]>)
    response: AuthenticatorAssertionResponseRaw {
        authenticator_data: Base64UrlSafeData,     // raw bytes
        client_data_json: Base64UrlSafeData,       // raw UTF-8 bytes
        signature: Base64UrlSafeData,              // DER-encoded ECDSA
    },
}

RequestChallengeResponse {
    public_key: PublicKeyCredentialRequestOptions {
        challenge: Base64UrlSafeData,              // raw challenge bytes
        rp_id: String,
        ...
    },
}
```

`Base64UrlSafeData` is a newtype around `Vec<u8>` that implements `Deref<Target=[u8]>`.

### aqua-auth API (behind `webauthn` feature)

```rust
pub struct WebAuthnAssertionParams<'a> {
    pub credential_public_key: &'a [u8],   // 33-byte compressed SEC1 P-256
    pub authenticator_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature: &'a [u8],               // 64-byte r||s (NOT DER)
    pub expected_challenge: &'a [u8],
    pub expected_origin: &'a str,
    pub expected_rp_id: &'a str,
}

pub fn verify_webauthn_assertion(params: &WebAuthnAssertionParams) -> Result<bool, CryptoError>;
```

### Browser signature format

Browsers send DER-encoded ECDSA signatures. aqua-auth expects 64-byte r||s. Convert with:
```rust
let sig = p256::ecdsa::Signature::from_der(&der_bytes)?;
let r_s_bytes = sig.to_bytes(); // GenericArray<u8, U64>
```

### Sign count

Bytes [33..37] of `authenticator_data` (big-endian u32). Most sync'd passkeys always report 0 (webauthn-rs docs: "most passkeys lack an internal device activation counter"). We update the counter in the stored Passkey JSON for completeness but do not enforce monotonicity.

---

### Task 1: Enable aqua-auth webauthn feature

**Files:**
- Modify: `Cargo.toml:14`

- [ ] **Step 1: Update the dependency**

In `Cargo.toml`, change line 14 from:
```toml
aqua-auth = { path = "../aqua-auth" }
```
to:
```toml
aqua-auth = { path = "../aqua-auth", features = ["webauthn"] }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --workspace 2>&1 | tail -5`
Expected: no errors (the webauthn module is gated but doesn't conflict)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "feat: enable aqua-auth webauthn feature for assertion verification"
```

---

### Task 2: Refactor build_webauthn to return resolved RP values

**Files:**
- Modify: `src/webauthn.rs:394-414` (the `build_webauthn` function)
- Modify: `src/axum_lib.rs:49-56` (AppState struct)
- Modify: `src/axum_lib.rs:523-544` (startup code)

The `authenticate_finish` function needs the resolved RP ID and origin strings (after defaults are applied). Currently these are computed inside `build_webauthn` and only passed to webauthn-rs. We need to surface them.

- [ ] **Step 1: Change build_webauthn return type**

In `src/webauthn.rs`, replace the `build_webauthn` function (lines 394-414) with:

```rust
pub struct WebauthnConfig {
    pub webauthn: Webauthn,
    pub rp_id: String,
    pub rp_origin: String,
}

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
    let resolved_rp_origin = rp_origin.unwrap_or(&default_origin).to_string();
    let rp_origin_url = Url::parse(&resolved_rp_origin)
        .map_err(|e| anyhow!("Invalid SIWEOIDC_RP_ORIGIN: {}", e))?;

    let webauthn = WebauthnBuilder::new(&resolved_rp_id, &rp_origin_url)
        .map_err(|e| anyhow!("WebauthnBuilder::new failed (rp_id={}, origin={}): {:?}", resolved_rp_id, rp_origin_url, e))?
        .build()
        .map_err(|e| anyhow!("Webauthn::build failed: {:?}", e))?;

    Ok(WebauthnConfig {
        webauthn,
        rp_id: resolved_rp_id,
        rp_origin: resolved_rp_origin,
    })
}
```

- [ ] **Step 2: Add rp_id and rp_origin to AppState**

In `src/axum_lib.rs`, change the `AppState` struct (around line 49-56) from:

```rust
#[derive(Clone)]
struct AppState {
    signing_key: Arc<EcdsaSigningKey>,
    config: config::Config,
    redis_client: RedisClient,
    webauthn: Arc<Webauthn>,
    synapse_client: Option<Arc<SynapseClient>>,
}
```

to:

```rust
#[derive(Clone)]
struct AppState {
    signing_key: Arc<EcdsaSigningKey>,
    config: config::Config,
    redis_client: RedisClient,
    webauthn: Arc<Webauthn>,
    rp_id: String,
    rp_origin: String,
    synapse_client: Option<Arc<SynapseClient>>,
}
```

- [ ] **Step 3: Update startup code to destructure WebauthnConfig**

In `src/axum_lib.rs`, change the startup block (around lines 523-544) from:

```rust
    let webauthn = wa::build_webauthn(
        &config.base_url,
        config.rp_id.as_deref(),
        config.rp_origin.as_deref(),
    )
    .expect("Failed to initialize WebAuthn — check SIWEOIDC_BASE_URL, SIWEOIDC_RP_ID, SIWEOIDC_RP_ORIGIN");
```

to:

```rust
    let wa_config = wa::build_webauthn(
        &config.base_url,
        config.rp_id.as_deref(),
        config.rp_origin.as_deref(),
    )
    .expect("Failed to initialize WebAuthn — check SIWEOIDC_BASE_URL, SIWEOIDC_RP_ID, SIWEOIDC_RP_ORIGIN");
```

And update the `AppState` construction from:

```rust
    let state = AppState {
        signing_key: Arc::new(signing_key),
        config: config.clone(),
        redis_client,
        webauthn: Arc::new(webauthn),
        synapse_client,
    };
```

to:

```rust
    let state = AppState {
        signing_key: Arc::new(signing_key),
        config: config.clone(),
        redis_client,
        webauthn: Arc::new(wa_config.webauthn),
        rp_id: wa_config.rp_id,
        rp_origin: wa_config.rp_origin,
        synapse_client,
    };
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check --workspace 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add src/webauthn.rs src/axum_lib.rs
git commit -m "refactor: surface resolved rp_id/rp_origin from build_webauthn into AppState"
```

---

### Task 3: Simplify authenticate_start to store raw challenge

**Files:**
- Modify: `src/webauthn.rs:179-201` (the `authenticate_start` function)

Currently stores the full serialized `DiscoverableAuthentication` state. After this change, stores only the raw challenge bytes (base64url-encoded) since we no longer need webauthn-rs's state for verification.

- [ ] **Step 1: Rewrite authenticate_start**

In `src/webauthn.rs`, replace the `authenticate_start` function (lines 179-201) with:

```rust
pub async fn authenticate_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
) -> Result<RequestChallengeResponse> {
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
```

Key changes:
- `_auth_state` is discarded (no longer serialized to Redis)
- Only the raw challenge bytes are stored (base64url-encoded string)
- No longer needs `danger-allow-state-serialisation` for auth path

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --workspace 2>&1 | tail -5`
Expected: may show warnings about unused imports (will be cleaned in Task 4)

- [ ] **Step 3: Commit**

```bash
git add src/webauthn.rs
git commit -m "refactor: authenticate_start stores raw challenge bytes instead of full auth state"
```

---

### Task 4: Rewrite authenticate_finish with aqua-auth verification

**Files:**
- Modify: `src/webauthn.rs:1-14` (imports)
- Modify: `src/webauthn.rs:26-60` (DID helpers)
- Modify: `src/webauthn.rs:203-293` (authenticate_finish function)
- Modify: `src/axum_lib.rs:377-393` (route handler)

This is the core change. The function no longer calls webauthn-rs for assertion verification.

- [ ] **Step 1: Update imports in webauthn.rs**

Replace the imports block at the top of `src/webauthn.rs` (lines 1-14) with:

```rust
//! WebAuthn/passkey ceremony — server-layer authentication (Layer 2).
//!
//! Registration uses webauthn-rs (attestation verification).
//! Authentication assertion verification uses aqua-auth's lightweight verifier.

use anyhow::{anyhow, Result};
use aqua_auth::{verify_webauthn_assertion, WebAuthnAssertionParams};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;
use webauthn_rs::prelude::*;

use siwx_oidc::db::RedisClient;
```

- [ ] **Step 2: Extract compressed_pubkey_from_passkey helper**

In `src/webauthn.rs`, replace the DID helper functions (lines 26-60) with:

```rust
// -- DID derivation from P-256 public key --

/// Multicodec varint for P-256 (0x1200), same as aqua-auth key module.
const P256_MULTICODEC: &[u8] = &[0x80, 0x24];

/// Extract the compressed SEC1 P-256 public key (33 bytes) from a Passkey credential.
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

/// Derive a `did:key:zDn…` from a P-256 compressed SEC1 public key (33 bytes).
fn did_from_p256_compressed(compressed: &[u8]) -> String {
    let mut bytes = P256_MULTICODEC.to_vec();
    bytes.extend_from_slice(compressed);
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

/// Extract the P-256 public key from a Passkey credential and derive a did:key.
fn did_from_passkey(passkey: &Passkey) -> Result<String> {
    let compressed = compressed_pubkey_from_passkey(passkey)?;
    Ok(did_from_p256_compressed(&compressed))
}
```

- [ ] **Step 3: Rewrite authenticate_finish**

Replace the `authenticate_finish` function (lines 203-293) with:

```rust
pub async fn authenticate_finish(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: PublicKeyCredential,
) -> Result<AuthenticateFinishResponse> {
    // Retrieve and consume the stored challenge.
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let challenge_b64 = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No auth challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .map_err(|e| anyhow!("Corrupt stored challenge: {}", e))?;

    // Extract credential ID directly from the browser response.
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(&*auth_response.raw_id);
    if cred_id_b64.is_empty() {
        return Err(anyhow!("Empty credential ID in WebAuthn assertion"));
    }

    // Look up the stored credential from Redis.
    let cred_key = format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64);
    let cred_json = redis
        .get_raw(&cred_key)
        .await?
        .ok_or_else(|| anyhow!("Credential not found: {}", cred_id_b64))?;
    let passkey: Passkey = serde_json::from_str(&cred_json)
        .map_err(|e| anyhow!("Failed to deserialize credential: {}", e))?;

    // Extract the compressed P-256 public key for verification.
    let compressed_pubkey = compressed_pubkey_from_passkey(&passkey)?;

    // DER-decode the browser's ECDSA signature to 64-byte r||s.
    let der_sig = &*auth_response.response.signature;
    let sig = Signature::from_der(der_sig)
        .map_err(|e| anyhow!("Invalid DER signature from authenticator: {}", e))?;
    let sig_bytes = sig.to_bytes();

    // Verify the assertion with aqua-auth.
    let params = WebAuthnAssertionParams {
        credential_public_key: &compressed_pubkey,
        authenticator_data: &auth_response.response.authenticator_data,
        client_data_json: &auth_response.response.client_data_json,
        signature: &sig_bytes,
        expected_challenge: &challenge_bytes,
        expected_origin: rp_origin,
        expected_rp_id: rp_id,
    };

    let valid = verify_webauthn_assertion(&params)
        .map_err(|e| anyhow!("WebAuthn assertion verification failed: {}", e))?;
    if !valid {
        return Err(anyhow!("WebAuthn signature verification failed"));
    }

    let passkey_did = did_from_passkey(&passkey)?;

    // Check if this credential is linked to a primary DID (account linking).
    let did = match redis
        .get_raw(&format!("{}/{}", LINK_PREFIX, cred_id_b64))
        .await?
    {
        Some(link_json) => {
            let link_entry: LinkEntry = serde_json::from_str(&link_json)
                .map_err(|e| anyhow!("Failed to deserialize link entry: {}", e))?;
            info!(
                "webauthn authenticate_finish: linked cred={} → primary_did={}",
                cred_id_b64, link_entry.primary_did
            );
            link_entry.primary_did
        }
        None => passkey_did,
    };

    // Update sign count in stored credential (best-effort, not enforced).
    let auth_data = &*auth_response.response.authenticator_data;
    if auth_data.len() >= 37 {
        let new_counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        let mut passkey_value: serde_json::Value = serde_json::from_str(&cred_json)
            .map_err(|e| anyhow!("Failed to parse credential JSON for counter update: {}", e))?;
        if let Some(cred) = passkey_value.get_mut("cred") {
            cred["counter"] = serde_json::json!(new_counter);
        }
        let updated_json = serde_json::to_string(&passkey_value)
            .map_err(|e| anyhow!("Failed to serialize updated credential: {}", e))?;
        redis.set_raw(&cred_key, &updated_json).await?;
    }

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
```

- [ ] **Step 4: Update the route handler in axum_lib.rs**

In `src/axum_lib.rs`, replace the `webauthn_authenticate_finish` handler (lines 377-393) with:

```rust
async fn webauthn_authenticate_finish(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Json(auth_response): Json<PublicKeyCredential>,
) -> Result<Json<wa::AuthenticateFinishResponse>, CustomError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| CustomError::BadRequest("Session cookie not found".to_string()))?;
    let resp = wa::authenticate_finish(
        &state.redis_client,
        session_id,
        &state.rp_id,
        &state.rp_origin,
        auth_response,
    )
    .await?;
    Ok(Json(resp))
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --workspace 2>&1 | tail -10`
Expected: clean compilation, possibly with warnings about unused `DiscoverableAuthentication` import (cleaned up by the glob import)

- [ ] **Step 6: Run aqua-auth tests**

Run: `cargo test -p aqua-auth 2>&1 | tail -10`
Expected: all tests pass (including the 7 webauthn tests)

- [ ] **Step 7: Commit**

```bash
git add src/webauthn.rs src/axum_lib.rs
git commit -m "feat: replace webauthn-rs assertion verification with aqua-auth verify_webauthn_assertion

authenticate_finish now uses aqua-auth's lightweight P-256 verifier instead of
webauthn-rs finish_discoverable_authentication. This reduces the webauthn-rs
surface to registration/attestation and challenge generation only.

Key changes:
- authenticate_start stores raw challenge bytes (not full auth state)
- authenticate_finish extracts raw fields from PublicKeyCredential directly
- DER signature decoded to r||s via p256 crate
- Sign count updated via JSON manipulation (best-effort, not enforced)"
```

---

### Task 5: Build and smoke test

**Files:** None (verification only)

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace 2>&1 | tail -10`
Expected: successful build

- [ ] **Step 2: Run all unit tests**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: all existing tests pass. The server e2e test may skip if no Redis is running (that's fine).

- [ ] **Step 3: Verify Docker build still works**

Run: `docker build -t siwx-oidc-test . 2>&1 | tail -10`
Expected: successful build (the binary includes aqua-auth's webauthn module)

---

### Task 6: Update CLAUDE.md documentation

**Files:**
- Modify: `CLAUDE.md` (the `## WebAuthn/Passkey architecture` section)

- [ ] **Step 1: Update the architecture section**

In `CLAUDE.md`, update the `## WebAuthn/Passkey architecture` section to reflect that assertion verification now uses aqua-auth:

Replace the opening line:
```
**Ceremony module:** `src/webauthn.rs` — uses `webauthn-rs` 0.6.0-dev safe API.
```

with:

```
**Ceremony module:** `src/webauthn.rs` — registration uses `webauthn-rs` 0.6.0-dev safe API;
assertion verification uses `aqua-auth`'s `verify_webauthn_assertion` (P-256, behind `webauthn` feature).
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for aqua-auth assertion verification"
```
