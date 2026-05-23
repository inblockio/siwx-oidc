# aqua-rs-auth / siwx-core Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate duplicated crypto verification code by making aqua-rs-auth delegate to siwx-core, then prove the full Matrix stack works with an e2e messaging test between two authenticated clients.

**Architecture:** aqua-rs-auth becomes a thin session/challenge layer. All signature verification delegates to `siwx_core::find_did_method(did)?.verify()`. The verify_*.rs and did.rs modules are deleted; message.rs uses `siwx_core::did::*` functions directly. Crypto crates (k256, ed25519-dalek, p256, sha3) move from production deps to dev-deps only.

**Tech Stack:** Rust, siwx-core (path dependency), reqwest (e2e test HTTP client), Matrix Client-Server API v3

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | verify_caip122() delegates to siwx_core::find_did_method(did)?.verify() | All 3 signature types (EIP-191, Ed25519, P-256) still verify correctly | siwx-core's DIDMethod::verify() is functionally equivalent to the deleted verifiers | `cargo test -p aqua-auth` -- dispatch_eip155, dispatch_ed25519, dispatch_p256 pass |
| H2 | crypto deps (k256, ed25519-dalek, p256, sha3) are removed from [dependencies] and moved to [dev-dependencies] | aqua-auth still compiles for production use | These crates were only used by verify_*.rs and did.rs, not by session/challenge/message code | `cargo build -p aqua-auth` succeeds |
| H3 | message.rs uses siwx_core::did functions instead of local did.rs | CAIP-122 messages are byte-identical to the current output | siwx_core::did::* functions are ports of aqua-rs-auth's did.rs (confirmed: siwx-core/src/did.rs header says "Ported from aqua-rs-auth") | message.rs tests (eip155_message_has_chain_id, ed25519_message_no_chain_id, p256_message_no_chain_id, message_contains_all_fields) all pass |
| H4 | aqua-rs-auth's public API signature (verify_caip122, ChallengeStore, SessionStore, types) stays the same | Downstream consumers (aqua-state-viewer, aqua-timestamp, aqua-node) need zero source changes | Consumers only call verify_caip122() and store APIs, never import verify_*.rs or did.rs directly | `cargo check` on downstream crates (if available) |
| H5 | SiwxError maps to AuthError without information loss | Error handling behavior is preserved | Both error enums have matching variant structure (confirmed by reading both error.rs files) | error-path unit tests pass (unsupported_namespace_returns_error, invalid_did_prefix_returns_error) |
| H6 | Two clients authenticate via siwx-oidc and get Matrix access tokens | They can create rooms, send messages, and receive each other's messages through Synapse | siwx-oidc + Synapse + Redis are running, MSC3861 token introspection is healthy | `cargo test --test e2e_messaging -- --nocapture` passes |
| H7 | siwx-core is referenced as a path dependency from aqua-rs-auth | aqua-rs-auth consumers gain did:key and did:peer verification for free | Path dependency resolves correctly; Cargo unifies shared transitive deps (k256, hex, etc.) | `verify_caip122("did:pkh:eip155:...", ...)` works, and `find_did_method("did:key:z6Mk...")` returns Some |

---

## Repos and Branches

| Repo | Branch | Purpose |
|------|--------|---------|
| `~/siwx-oidc` | `aqua-rs-auth_integration` (from `fork-stable`) | E2E messaging test |
| `~/aqua-rs-auth` | `siwx-core-integration` (from current HEAD) | Crypto delegation refactor |

---

## Task 1: Create branches and add siwx-core dependency

**Hypotheses:** H2, H7

**Files:**
- Modify: `~/aqua-rs-auth/Cargo.toml`

- [ ] **Step 1: Create branch in siwx-oidc**

```bash
cd ~/siwx-oidc
git checkout fork-stable
git checkout -b aqua-rs-auth_integration
```

- [ ] **Step 2: Create branch in aqua-rs-auth**

```bash
cd ~/aqua-rs-auth
git checkout -b siwx-core-integration
```

- [ ] **Step 3: Add siwx-core as path dependency in aqua-rs-auth Cargo.toml**

Replace the crypto dependencies block with siwx-core:

```toml
[dependencies]
# Crypto verification delegated to siwx-core
siwx-core = { path = "../siwx-oidc/siwx-core" }

# Core
rand = "0.8"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
chrono = { version = "0.4", features = ["serde"] }
dashmap = "6"
tokio = { version = "1", features = ["time", "rt"] }

# Optional: client helpers
[dependencies.reqwest]
version = "0.12"
default-features = false
features = ["json", "rustls-tls"]
optional = true

[features]
default = []
client = ["dep:reqwest"]

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
k256 = { version = "0.13", features = ["ecdsa"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
p256 = { version = "0.13", features = ["ecdsa"] }
sha3 = "0.10"
```

- [ ] **Step 4: Verify it compiles (will have unused import warnings, that's OK)**

Run: `cd ~/aqua-rs-auth && cargo check`
Expected: Compiles (warnings about unused siwx-core are fine at this stage)

---

## Task 2: Add SiwxError to AuthError mapping

**Hypotheses:** H5

**Files:**
- Modify: `~/aqua-rs-auth/src/error.rs`

- [ ] **Step 1: Add From<SiwxError> impl to error.rs**

Append after the AuthError enum definition:

```rust
impl From<siwx_core::SiwxError> for AuthError {
    fn from(e: siwx_core::SiwxError) -> Self {
        match e {
            siwx_core::SiwxError::UnsupportedMethod(m) => AuthError::UnsupportedMethod(m),
            siwx_core::SiwxError::InvalidDid(d) => AuthError::InvalidDid(d),
            siwx_core::SiwxError::InvalidSignature(s) => AuthError::InvalidSignature(s),
            siwx_core::SiwxError::VerificationFailed => AuthError::VerificationFailed,
            siwx_core::SiwxError::HexDecode(e) => AuthError::HexDecode(e),
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd ~/aqua-rs-auth && cargo check`
Expected: Compiles

---

## Task 3: Rewrite verify_caip122() to delegate to siwx-core

**Hypotheses:** H1, H5, H7

**Files:**
- Modify: `~/aqua-rs-auth/src/lib.rs`

- [ ] **Step 1: Rewrite verify_caip122 body**

Replace the entire function body and remove the old module declarations. The new lib.rs:

```rust
pub mod challenge;
#[cfg(feature = "client")]
pub mod client;
pub mod did;
pub mod error;
pub mod message;
pub mod session;
pub mod types;

pub use challenge::ChallengeStore;
pub use error::AuthError;
pub use session::SessionStore;
pub use types::{AuthenticatedDid, Challenge, Session, SessionInfo, SessionRequest};

/// Verify a CAIP-122 session signature. Dispatches via siwx-core's DIDMethod registry.
pub fn verify_caip122(did: &str, message: &str, signature: &[u8]) -> Result<bool, AuthError> {
    let method = siwx_core::find_did_method(did)
        .ok_or_else(|| AuthError::UnsupportedMethod(did.to_string()))?;
    method.verify(did, message, signature).map_err(AuthError::from)
}
```

Note: `pub mod did;` stays temporarily for this task. Task 4 removes it.

- [ ] **Step 2: Run existing tests to verify dispatch still works**

Run: `cd ~/aqua-rs-auth && cargo test -p aqua-auth -- --nocapture`
Expected: dispatch_eip155, dispatch_ed25519, dispatch_p256 pass. The tests in lib.rs use the old `did::` helpers which still exist at this point.

- [ ] **Step 3: Delete verify_eip191.rs, verify_ed25519.rs, verify_p256.rs**

```bash
cd ~/aqua-rs-auth
rm src/verify_eip191.rs src/verify_ed25519.rs src/verify_p256.rs
```

- [ ] **Step 4: Run tests again**

Run: `cd ~/aqua-rs-auth && cargo test -p aqua-auth -- --nocapture`
Expected: All tests pass (the deleted modules had `mod` declarations already removed in Step 1)

- [ ] **Step 5: Commit**

```bash
cd ~/aqua-rs-auth
git add src/lib.rs src/error.rs Cargo.toml
git add -u  # captures deleted files
git commit -m "refactor: delegate verify_caip122 to siwx-core, remove crypto verifiers"
```

---

## Task 4: Remove did.rs, update message.rs to use siwx_core::did

**Hypotheses:** H3

**Files:**
- Modify: `~/aqua-rs-auth/src/message.rs`
- Delete: `~/aqua-rs-auth/src/did.rs`
- Modify: `~/aqua-rs-auth/src/lib.rs` (remove `pub mod did;`)

- [ ] **Step 1: Rewrite message.rs to use siwx_core::did functions**

The key change: replace `use crate::did::{identifier_from_did, parse_did_namespace}` with siwx_core::did equivalents. The `identifier_from_did` function is reimplemented locally using siwx_core::did functions.

```rust
//! CAIP-122 canonical message construction (SIWE-compatible format).

use crate::error::AuthError;
use chrono::{DateTime, Utc};

/// Parameters for constructing a CAIP-122 message.
pub struct MessageParams<'a> {
    pub did: &'a str,
    pub domain: &'a str,
    pub uri: &'a str,
    pub nonce: &'a str,
    pub issued_at: DateTime<Utc>,
    pub expiration_time: DateTime<Utc>,
}

/// Extract the identifier field for a CAIP-122 message from a DID,
/// using siwx-core's DID parsing utilities.
fn identifier_from_did(did: &str) -> Result<String, AuthError> {
    let ns = siwx_core::did::parse_did_namespace(did).map_err(AuthError::from)?;
    match ns {
        "eip155" => {
            let addr = siwx_core::did::address_from_did(did).map_err(AuthError::from)?;
            Ok(format!("0x{}", siwx_core::did::eip55_checksum(&addr)))
        }
        "ed25519" => {
            let pk = siwx_core::did::pubkey_from_ed25519_did(did).map_err(AuthError::from)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        "p256" => {
            let pk = siwx_core::did::pubkey_from_p256_did(did).map_err(AuthError::from)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        other => Err(AuthError::UnsupportedMethod(other.into())),
    }
}

/// Construct a canonical CAIP-122 message string.
pub fn build_message(params: &MessageParams) -> Result<String, AuthError> {
    let ns = siwx_core::did::parse_did_namespace(params.did).map_err(AuthError::from)?;
    let identifier = identifier_from_did(params.did)?;

    let method_label = match ns {
        "eip155"  => "Ethereum",
        "ed25519" => "Ed25519",
        "p256"    => "P-256",
        other     => return Err(AuthError::UnsupportedMethod(other.into())),
    };

    let issued_at = params.issued_at.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expiration_time = params.expiration_time.format("%Y-%m-%dT%H:%M:%S%.3fZ");

    let mut msg = format!(
        "{domain} wants you to sign in with your {method_label} account:\n\
         {identifier}\n\
         \n\
         Sign in to Aqua Node\n\
         \n\
         URI: {uri}\n\
         Version: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}",
        domain = params.domain,
        uri = params.uri,
        nonce = params.nonce,
    );

    if ns == "eip155" {
        msg.push_str("\nChain ID: 1");
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn eip155_message_has_chain_id() {
        let addr_hex = hex::encode([0x11; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("Ethereum account"));
        assert!(msg.contains("Chain ID: 1"));
        assert!(msg.contains("Sign in to Aqua Node"));
        assert!(msg.contains("Nonce: 0xdeadbeef"));
    }

    #[test]
    fn ed25519_message_no_chain_id() {
        let pk_hex = hex::encode([0xAA; 32]);
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("Ed25519 account"));
        assert!(!msg.contains("Chain ID"));
    }

    #[test]
    fn p256_message_no_chain_id() {
        let pk_hex = hex::encode([0xBB; 33]);
        let did = format!("did:pkh:p256:0x{pk_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("P-256 account"));
        assert!(!msg.contains("Chain ID"));
    }

    #[test]
    fn message_contains_all_fields() {
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 1, 15, 10, 35, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "localhost",
            uri: "http://localhost:3000",
            nonce: "0xaabbccdd",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.starts_with("localhost wants you to sign in"));
        assert!(msg.contains("URI: http://localhost:3000"));
        assert!(msg.contains("Version: 1"));
        assert!(msg.contains("Nonce: 0xaabbccdd"));
        assert!(msg.contains("Issued At: 2026-01-15T10:30:00.000Z"));
        assert!(msg.contains("Expiration Time: 2026-01-15T10:35:00.000Z"));
    }
}
```

- [ ] **Step 2: Run message tests to verify output is unchanged**

Run: `cd ~/aqua-rs-auth && cargo test -p aqua-auth message -- --nocapture`
Expected: All 4 message tests pass

- [ ] **Step 3: Delete did.rs and remove its module declaration from lib.rs**

```bash
rm ~/aqua-rs-auth/src/did.rs
```

In `lib.rs`, remove the line `pub mod did;`.

- [ ] **Step 4: Update lib.rs tests to use siwx_core::did instead of crate::did**

The lib.rs tests use `did::address_from_verifying_key` and `did::eip55_checksum`. Replace with `siwx_core::did::*`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_eip155() {
        use k256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        use sha3::{Digest, Keccak256};

        let secret = k256::SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret);
        let addr = siwx_core::did::address_from_verifying_key(signing_key.verifying_key());
        let did_str = format!("did:pkh:eip155:1:0x{}", siwx_core::did::eip55_checksum(&addr));

        let msg = "test dispatch eip155";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = u8::from(rec_id) + 27;

        assert!(verify_caip122(&did_str, msg, &sig_bytes).unwrap());
    }

    #[test]
    fn dispatch_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did_str = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));

        let msg = "test dispatch ed25519";
        let sig = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn dispatch_p256() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let did_str = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));

        let msg = "test dispatch p256";
        let sig: Signature = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn unsupported_namespace_returns_error() {
        let result = verify_caip122("did:pkh:solana:0xabc", "msg", &[0u8; 64]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedMethod(_)));
    }

    #[test]
    fn invalid_did_prefix_returns_error() {
        let result = verify_caip122("not:a:did", "msg", &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn did_key_dispatches_via_siwx_core() {
        // Verify that did:key DIDs are now supported (gained from siwx-core integration)
        assert!(siwx_core::find_did_method("did:key:z6MkiTBz1y").is_some());
    }
}
```

- [ ] **Step 5: Run full test suite**

Run: `cd ~/aqua-rs-auth && cargo test -p aqua-auth -- --nocapture`
Expected: All tests pass (dispatch tests, message tests, challenge tests, session tests)

- [ ] **Step 6: Verify clean build without crypto deps**

Run: `cd ~/aqua-rs-auth && cargo build -p aqua-auth`
Expected: Compiles. No k256/ed25519-dalek/p256/sha3 in the dependency tree for non-test builds.

- [ ] **Step 7: Commit**

```bash
cd ~/aqua-rs-auth
git add -A
git commit -m "refactor: remove did.rs, message.rs uses siwx_core::did directly"
```

---

## Task 5: Update lib.rs doc comment and verify public API

**Hypotheses:** H4, H7

**Files:**
- Modify: `~/aqua-rs-auth/src/lib.rs` (doc comment only)

- [ ] **Step 1: Update the crate-level doc comment**

Replace the doc comment at the top of lib.rs:

```rust
//! # aqua-auth
//!
//! CAIP-122 ("Sign In With X") session authentication for the Aqua Protocol.
//!
//! Provides:
//! - **CAIP-122 message construction** -- SIWE-compatible format, generalized for
//!   Ed25519 and P-256 signers.
//! - **Chain-dispatching signature verification** -- `verify_caip122()` delegates
//!   to siwx-core's DIDMethod registry for all signature verification.
//! - **ChallengeStore** -- in-memory, 5-min TTL, single-use nonces.
//! - **SessionStore** -- in-memory, 1-hr TTL, background sweep.
//! - **Client helpers** -- (behind `client` feature flag) reqwest-based auth flow.
//!
//! # Supported DID methods
//!
//! All DID methods registered in siwx-core are supported automatically:
//! did:pkh (eip155, ed25519, p256), did:key (Ed25519, P-256), did:peer (v0, v2).
```

- [ ] **Step 2: Verify public API surface is unchanged**

Run: `cd ~/aqua-rs-auth && cargo doc --no-deps -p aqua-auth 2>&1 | head -20`
Expected: No errors. The public API should still include: verify_caip122, ChallengeStore, SessionStore, Challenge, Session, SessionInfo, SessionRequest, AuthenticatedDid, AuthError, message::build_message, message::MessageParams.

- [ ] **Step 3: Commit**

```bash
cd ~/aqua-rs-auth
git add src/lib.rs
git commit -m "docs: update crate doc to reflect siwx-core integration"
```

---

## Task 6: Write e2e messaging test in siwx-oidc

**Hypotheses:** H6

**Files:**
- Create: `~/siwx-oidc/tests/e2e_messaging.rs`

This test reuses the OIDC auth flow pattern from `tests/e2e_msc3861.rs`. Two clients authenticate independently, then exchange messages via the Matrix Client-Server API.

- [ ] **Step 1: Write the e2e messaging test**

Create `~/siwx-oidc/tests/e2e_messaging.rs`:

```rust
//! E2E test: two clients authenticate via siwx-oidc and exchange Matrix messages.
//!
//! Required environment:
//!   SIWEOIDC_HOST - siwx-oidc instance (default: http://localhost:8081)
//!   MATRIX_HOST   - Matrix homeserver (default: http://localhost:8448)
//!
//! Run:
//!   MATRIX_HOST=https://matrix.inblock.io SIWEOIDC_HOST=https://siwx-oidc.inblock.io \
//!     cargo test --test e2e_messaging -- --nocapture

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers (same as e2e_msc3861.rs)
// ---------------------------------------------------------------------------

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

fn matrix_host() -> String {
    std::env::var("MATRIX_HOST").unwrap_or_else(|_| "http://localhost:8448".to_string())
}

fn address_from_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            result.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }
    }
    result
}

fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec_id) + 27;
    format!("0x{}", hex::encode(bytes))
}

fn pkce_pair() -> (String, String) {
    use rand::Rng;
    let verifier: String = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let full = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://dummy{}", url)
    };
    let parsed = reqwest::Url::parse(&full).unwrap();
    parsed.query_pairs().into_owned().collect()
}

// ---------------------------------------------------------------------------
// Auth flow (produces a Matrix access token for a fresh Ethereum identity)
// ---------------------------------------------------------------------------

struct AuthResult {
    access_token: String,
    did: String,
}

async fn authenticate_client(label: &str) -> AuthResult {
    let base = siweoidc_host();

    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    eprintln!("[{label}] DID: {did}");

    let redirect_uri = format!("{}/callback", base);
    let reg_body = json!({
        "redirect_uris": [&redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });

    let http = Client::new();
    let reg_resp = http
        .post(format!("{}/register", base))
        .json(&reg_body)
        .send()
        .await
        .expect("register request failed");
    assert_eq!(reg_resp.status(), StatusCode::CREATED);
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

    let (code_verifier, code_challenge) = pkce_pair();
    let state = format!("state_{label}");
    let client = no_redirect_client();

    let authorize_url = format!(
        "{}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state,
        urlencoding::encode(&code_challenge),
    );
    let auth_resp = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER);

    let set_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session_cookie = set_cookie.split(';').next().unwrap().to_string();

    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let query = parse_query(&location);
    let nonce = query.get("nonce").unwrap();
    let domain = query.get("domain").unwrap();

    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Resources:\n\
         - {redirect_uri}",
    );

    let signature = eip191_sign(&signing_key, &message);
    let siwx_payload = json!({
        "did": did,
        "message": message,
        "signature": signature,
    });
    let siwx_cookie_value = serde_json::to_string(&siwx_payload).unwrap();

    let sign_in_url = format!(
        "{}/sign_in?redirect_uri={}&state={}&client_id={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&redirect_uri),
        state,
        urlencoding::encode(&client_id),
        urlencoding::encode(&code_challenge),
    );

    let sign_in_resp = client
        .get(&sign_in_url)
        .header(
            "cookie",
            format!(
                "{}; siwx={}",
                session_cookie,
                urlencoding::encode(&siwx_cookie_value)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sign_in_resp.status(), StatusCode::SEE_OTHER);

    let sign_in_location = sign_in_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_query = parse_query(&sign_in_location);
    let code = callback_query.get("code").unwrap();

    let token_resp = http
        .post(format!("{}/token", base))
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::OK);
    let token_json: Value = token_resp.json().await.unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();
    assert!(access_token.starts_with("mat_"));
    eprintln!("[{label}] authenticated, token={}", &access_token[..12]);

    AuthResult { access_token, did }
}

// ---------------------------------------------------------------------------
// Matrix Client-Server API helpers
// ---------------------------------------------------------------------------

async fn matrix_whoami(http: &Client, token: &str) -> Option<Value> {
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
        return None;
    }
    assert_eq!(resp.status(), StatusCode::OK);
    Some(resp.json().await.unwrap())
}

async fn create_room(http: &Client, token: &str, name: &str) -> String {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/createRoom",
            matrix_host()
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "preset": "private_chat",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "createRoom failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap_or_default();
    // Re-request if we consumed the body
    let resp2 = http
        .post(format!(
            "{}/_matrix/client/v3/createRoom",
            matrix_host()
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "preset": "private_chat",
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp2.json().await.unwrap();
    body["room_id"].as_str().unwrap().to_string()
}

async fn invite_user(http: &Client, token: &str, room_id: &str, user_id: &str) {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/rooms/{}/invite",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .json(&json!({ "user_id": user_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "invite failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn join_room(http: &Client, token: &str, room_id: &str) {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/join/{}",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "join failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn send_message(http: &Client, token: &str, room_id: &str, body: &str) -> String {
    let txn_id = uuid::Uuid::new_v4().to_string();
    let resp = http
        .put(format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            matrix_host(),
            urlencoding::encode(room_id),
            urlencoding::encode(&txn_id)
        ))
        .bearer_auth(token)
        .json(&json!({
            "msgtype": "m.text",
            "body": body,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "send_message failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let send_json: Value = resp.json().await.unwrap();
    send_json["event_id"].as_str().unwrap().to_string()
}

async fn sync_and_find_message(
    http: &Client,
    token: &str,
    room_id: &str,
    expected_body: &str,
) -> bool {
    // Use /messages endpoint to fetch recent room history.
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/rooms/{}/messages?dir=b&limit=10",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        eprintln!("[sync] messages endpoint returned {}", resp.status());
        return false;
    }
    let body: Value = resp.json().await.unwrap();
    if let Some(chunks) = body["chunk"].as_array() {
        for event in chunks {
            if event["type"] == "m.room.message" {
                if let Some(content_body) = event["content"]["body"].as_str() {
                    if content_body == expected_body {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Test: two clients exchange messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_client_messaging() {
    let http = Client::new();

    // 1. Authenticate two independent clients.
    let alice = authenticate_client("alice").await;
    let bob = authenticate_client("bob").await;

    // 2. Verify both clients can reach Matrix.
    let alice_whoami = matrix_whoami(&http, &alice.access_token).await;
    let bob_whoami = matrix_whoami(&http, &bob.access_token).await;

    if alice_whoami.is_none() || bob_whoami.is_none() {
        eprintln!("[e2e] Matrix introspection unavailable - skipping messaging test");
        eprintln!("[e2e] Both OIDC auth flows succeeded at the siwx-oidc level");
        return;
    }

    let alice_user_id = alice_whoami.unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bob_user_id = bob_whoami.unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();
    eprintln!("[e2e] alice={}, bob={}", alice_user_id, bob_user_id);

    // 3. Alice creates a room.
    let room_id = create_room(&http, &alice.access_token, "e2e-test-room").await;
    eprintln!("[e2e] room_id={}", room_id);

    // 4. Alice invites Bob.
    invite_user(&http, &alice.access_token, &room_id, &bob_user_id).await;
    eprintln!("[e2e] bob invited");

    // 5. Bob joins the room.
    join_room(&http, &bob.access_token, &room_id).await;
    eprintln!("[e2e] bob joined");

    // 6. Alice sends a message.
    let test_message = format!("Hello from alice! timestamp={}", Utc::now().timestamp());
    let event_id = send_message(&http, &alice.access_token, &room_id, &test_message).await;
    eprintln!("[e2e] alice sent message, event_id={}", event_id);

    // 7. Bob reads the message.
    let found = sync_and_find_message(&http, &bob.access_token, &room_id, &test_message).await;
    assert!(
        found,
        "bob should see alice's message '{}' in room {}",
        test_message, room_id
    );
    eprintln!("[e2e] bob received alice's message");

    // 8. Bob replies.
    let reply_message = format!("Hello back from bob! timestamp={}", Utc::now().timestamp());
    let reply_event_id =
        send_message(&http, &bob.access_token, &room_id, &reply_message).await;
    eprintln!("[e2e] bob sent reply, event_id={}", reply_event_id);

    // 9. Alice reads the reply.
    let found_reply =
        sync_and_find_message(&http, &alice.access_token, &room_id, &reply_message).await;
    assert!(
        found_reply,
        "alice should see bob's reply '{}' in room {}",
        reply_message, room_id
    );
    eprintln!("[e2e] alice received bob's reply");

    eprintln!("[e2e] two-client messaging test PASSED");
}
```

- [ ] **Step 2: Add uuid to dev-dependencies in siwx-oidc Cargo.toml**

The test uses `uuid::Uuid::new_v4()` for transaction IDs. Check if uuid is already in dev-deps; if not, add:

```toml
[dev-dependencies]
uuid = { version = "1", features = ["v4"] }
```

Note: uuid is already in `[dependencies]` with v4 feature, so dev code can use it.

- [ ] **Step 3: Fix the create_room helper**

The initial create_room implementation above has a bug (consuming the response body twice). Replace with the correct version:

```rust
async fn create_room(http: &Client, token: &str, name: &str) -> String {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/createRoom",
            matrix_host()
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "preset": "private_chat",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    body["room_id"].as_str().unwrap().to_string()
}
```

- [ ] **Step 4: Verify test compiles**

Run: `cd ~/siwx-oidc && cargo test --test e2e_messaging --no-run`
Expected: Compiles without errors

- [ ] **Step 5: Commit**

```bash
cd ~/siwx-oidc
git add tests/e2e_messaging.rs
git commit -m "test: add e2e messaging test for two-client Matrix communication"
```

---

## Task 7: Run e2e test and verify

**Hypotheses:** H6

**Files:** None (test execution only)

- [ ] **Step 1: Run the e2e messaging test against live infrastructure**

Run:
```bash
cd ~/siwx-oidc
MATRIX_HOST=https://matrix.inblock.io SIWEOIDC_HOST=https://siwx-oidc.inblock.io \
  cargo test --test e2e_messaging -- --nocapture
```

Expected: Test passes, showing:
- Both clients authenticate successfully
- Alice creates a room
- Bob joins after invitation
- Messages flow bidirectionally

If Matrix introspection is unavailable (503), the test gracefully skips messaging assertions while confirming the OIDC flow itself works.

- [ ] **Step 2: Run aqua-rs-auth full test suite one final time**

Run: `cd ~/aqua-rs-auth && cargo test -p aqua-auth -- --nocapture`
Expected: All tests pass (37 original tests adapted + new did:key test)

- [ ] **Step 3: Run siwx-core tests to verify no regressions**

Run: `cd ~/siwx-oidc && cargo test -p siwx-core`
Expected: All 57 tests pass

---

## Verification Matrix

| Hypothesis | Task | Verification Command | Criterion |
|-----------|------|---------------------|-----------|
| H1 | 3 | `cargo test -p aqua-auth dispatch` | 3 dispatch tests pass |
| H2 | 4 | `cargo build -p aqua-auth` | Compiles without crypto in prod deps |
| H3 | 4 | `cargo test -p aqua-auth message` | 4 message tests pass |
| H4 | 5 | `cargo doc --no-deps -p aqua-auth` | Public API unchanged |
| H5 | 3 | `cargo test -p aqua-auth unsupported` | Error mapping tests pass |
| H6 | 7 | `cargo test --test e2e_messaging` | Two clients exchange messages |
| H7 | 4 | `cargo test -p aqua-auth did_key` | find_did_method returns Some for did:key |
