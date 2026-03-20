# PLAN: WebAuthn/Passkey Authentication
**Status:** Approved — implementation starting
**Date:** 2026-03-21
**Branch:** `mobile-auth-planning`

---

## Goal

Add passkey (WebAuthn) login to siwx-oidc so mobile and family users can
authenticate without a browser wallet extension, while following the key-based
design patterns of siwx.

## Architecture Decision

WebAuthn is a **server-layer ceremony**, not a DIDMethod extension.

```
Layer 1: siwx-core         — Pure crypto. DIDMethod::verify() = CAIP-122 only. UNCHANGED.
Layer 2: src/webauthn.rs    — Full ceremony via webauthn-rs safe API. NEW.
Layer 3: src/oidc.rs        — sign_in generalized: session.verified_did OR siwx cookie.
```

**Why not extend DIDMethod?** (Research: NIST SP 800-63B, W3C WebAuthn §7.2, webauthn-rs)
- WebAuthn has 17 verification steps; only 2 are cryptographic
- The other 15 require server state (challenge, origin, RP ID, flags, sign count)
- siwx-core is pure/sync/stateless — ceremony checks cannot live there
- webauthn-rs safe API is monolithic by design; splitting crypto from ceremony is unsafe

**DID derivation:** Passkey P-256 public key → `did:key:zDn…` using existing siwx-core
encoding (`key/mod.rs:16` P256_PREFIX + compressed SEC1 point + base58btc).

---

## Components

### Component 1 — WebAuthn Ceremony Module (`src/webauthn.rs`)

**Dependencies:** `webauthn-rs = "0.5"` (safe API, not core)

#### 1.1 Endpoints

```
POST /webauthn/register/start       → creation options + challenge
POST /webauthn/register/finish      → verify attestation, store credential, derive did:key
POST /webauthn/authenticate/start   → request options + challenge
POST /webauthn/authenticate/finish  → verify assertion, store verified_did in session, redirect
```

#### 1.2 Redis Key Schema

```
webauthn:challenge:{session_id}    TTL 60s   — serialized webauthn-rs state (Registration/Authentication)
webauthn:credential:{cred_id_b64}  no TTL    — { did, passkey_json, label }
webauthn:did_creds:{did}           no TTL    — SET of cred_id_b64 (reverse lookup for listing)
```

- `passkey_json`: serialized `webauthn_rs::prelude::Passkey` (contains pubkey, sign_count, etc.)
- `cred_id_b64`: base64url-encoded credential ID (WebAuthn opaque bytes)

#### 1.3 DID Derivation from WebAuthn Credential

After attestation verification, extract the P-256 public key from the credential:

```rust
use siwx_core::key::{P256_PREFIX};

fn did_from_p256_pubkey(compressed_sec1: &[u8]) -> String {
    let mut bytes = P256_PREFIX.to_vec();
    bytes.extend_from_slice(compressed_sec1);  // 33 bytes compressed
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}
```

This produces a deterministic `did:key:zDn…` — same passkey = same DID.

#### 1.4 authenticate_finish Flow

```
1. Deserialize webauthn-rs authentication state from Redis (challenge:{session_id})
2. Call webauthn.finish_passkey_authentication() — full ceremony (all 17 steps)
3. Look up webauthn:credential:{cred_id_b64} → get stored did
4. Update sign_count in stored passkey
5. Store verified_did in SessionEntry (Redis session)
6. Delete challenge from Redis (consumed)
7. Redirect to /sign_in?redirect_uri=…&state=…&client_id=…
```

### Component 2 — SessionEntry Extension (`src/db/mod.rs`)

Add one field:

```rust
pub struct SessionEntry {
    pub siwe_nonce: String,
    pub oidc_nonce: Option<Nonce>,
    pub secret: String,
    pub signin_count: u64,
    pub verified_did: Option<String>,  // NEW: set by ceremony, read by sign_in
}
```

### Component 3 — sign_in Generalization (`src/oidc.rs`)

```rust
pub async fn sign_in(/* ... */) -> Result<Url, CustomError> {
    // ... session validation (unchanged) ...

    let did = if let Some(verified_did) = session_entry.verified_did.as_ref() {
        // Path A: Server-verified ceremony (WebAuthn)
        // DID already verified by authenticate_finish — trusted (stored in Redis)
        info!("sign_in: server-verified did={}", verified_did);
        verified_did.clone()
    } else {
        // Path B: Client-set CAIP-122 cookie (existing wallet flow — unchanged)
        let siwx_cookie = /* read cookie, decode */;
        let did_method = find_did_method(&siwx_cookie.did)?;
        // ... verify signature, same as today ...
        siwx_cookie.did
    };

    // Common path: DID allowlist, nonce check (for CAIP-122), redirect_uri, code issuance
    // ... (existing logic, parameterized by `did`) ...
}
```

**Nonce handling:** For WebAuthn, the challenge IS the session nonce (set during
`/webauthn/authenticate/start`). The nonce check in sign_in is skipped for
server-verified DIDs because the challenge was already verified during the ceremony.
The redirect_uri and DID allowlist checks still apply.

### Component 4 — Config Extension (`src/config.rs`)

```rust
pub rp_id: Option<String>,      // WebAuthn RP ID (defaults to hostname of base_url)
pub rp_origin: Option<String>,  // WebAuthn expected origin (defaults to base_url)
```

Env vars: `SIWEOIDC_RP_ID`, `SIWEOIDC_RP_ORIGIN`.

### Component 5 — Frontend (`js/ui/src/App.svelte`)

Add alongside existing wallet flow:
- "Sign in with passkey" button → `/webauthn/authenticate/start` → `navigator.credentials.get()` → `/webauthn/authenticate/finish`
- "Register a passkey" link → `/webauthn/register/start` → `navigator.credentials.create()` → `/webauthn/register/finish`

### Component 6 — Account Linking (Phase 2)

Allow existing wallet users to link a passkey to their wallet DID.

```
POST /link/webauthn/start    — begin passkey registration (requires authenticated session)
POST /link/webauthn/finish   — store cred_id → primary_did mapping
```

Redis: `webauthn:link:{cred_id_b64}  no TTL  → { primary_did, label }`

Token issuance change: after WebAuthn authentication, check `webauthn:link:{cred_id}`.
If found, substitute `primary_did` as the OIDC `sub` instead of the passkey's `did:key`.

---

## Implementation Order

```
Phase 1 — Foundation (this branch)
  1a. Add webauthn-rs dependency
  1b. Add verified_did to SessionEntry
  1c. Create src/webauthn.rs (register + authenticate endpoints)
  1d. Register routes in axum_lib.rs
  1e. Add RP config to config.rs
  1f. Generalize sign_in for server-verified path
  1g. Add passkey UI to App.svelte
  1h. Test: new user registers passkey → logs in → gets Matrix account

Phase 2 — Account Linking
  2a. Add /link endpoints
  2b. Add webauthn:link Redis schema
  2c. Modify authenticate_finish to check link mappings
  2d. Test: existing MetaMask user links passkey → logs in via passkey → same account

Phase 3 — RFC 8628 Device Authorization Grant (separate branch)
  3a. POST /device_authorization endpoint
  3b. POST /token device_code grant type
  3c. GET /device approval page (with passkey + wallet auth)
  3d. OIDC discovery update
  3e. Verify Element X QR code flow

Phase 4 — MSC4108 (separate repo: siwx-oidc-matrix-server)
  4a. Add msc4108_enabled to homeserver.yaml
  4b. Verify Element X cross-device session transfer
```

---

## Security Invariants

| Invariant | Implementation |
|---|---|
| Single code issuance point | Auth codes only created in `sign_in`. WebAuthn endpoints never issue codes. |
| Server-side trust | `verified_did` stored in Redis session, never in a client cookie. |
| Ceremony completeness | `webauthn-rs` safe API verifies all 17 steps atomically. |
| Challenge binding | WebAuthn challenge = session nonce. Verified in ceremony. 60s TTL. |
| RP ID binding | `rpIdHash` in authenticatorData must match configured RP ID. Browser enforces origin. |
| UV enforcement | `userVerification: "preferred"` in credential request. |
| Sign count | Updated on every assertion. Reject if count regresses (except 0 for synced passkeys). |
| Fail closed | Redis unavailable → reject login. Ceremony failure → reject login. |
| DID allowlist | `sign_in` enforces `supported_did_methods` for ALL paths including server-verified. |

## Open Questions

1. **Recovery:** Passkey-only user loses phone, no cloud sync → new DID → new account.
   Options: backup codes (BIP39), email recovery, accept as sovereign tradeoff. Deferred.
2. **Redis durability:** Credential mappings must survive `--reset`. Use separate named volume.
3. **webauthn-rs version:** Pin to 0.5.x stable. Check passkey/resident key support.
