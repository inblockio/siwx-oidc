# Add a New Authentication Ceremony

Add a new authentication method (e.g. WebAuthn/passkeys, SSH keys, PGP) to siwx-oidc.

## Architecture — Three-Layer Ceremony Model

Authentication ceremonies live in the **server layer** (`src/`), not in `siwx-core`.
The `DIDMethod` trait handles CAIP-122 verification only. New proof ceremonies are
separate server-side modules that produce a verified DID.

```
Layer 1: siwx-core        — Pure crypto. DIDMethod::verify() = CAIP-122 only. DO NOT MODIFY.
Layer 2: src/{ceremony}.rs — Ceremony verification (this skill). Verify proof → store DID in session.
Layer 3: src/oidc.rs       — sign_in reads verified DID from session → issues OIDC auth code.
```

**Key principle:** All ceremonies funnel into `sign_in` as the single OIDC code issuance point.
The normalized output of every ceremony is a verified DID string stored in the Redis session.

## Checklist

### 1. DID derivation — confirm siwx-core support

Before writing any server code, confirm the DID type your ceremony produces is already
supported in siwx-core:

- `did:key:zDn…` (P-256) — for WebAuthn/passkeys. Already in `siwx-core/src/key/mod.rs`.
- `did:key:z6Mk…` (Ed25519) — for SSH Ed25519 keys. Already in `siwx-core/src/key/mod.rs`.
- `did:pkh:eip155:…` — for Ethereum wallets. Already in `siwx-core/src/pkh/`.

If the key type is new, use `/add-did-method` or `/add-cipher-suite` first.

### 2. Add the ceremony module — `src/{ceremony}.rs`

Create a new module with at minimum:

```rust
// src/webauthn.rs (example for WebAuthn)

use siwx_oidc::db::*;

// Registration endpoints (first-time setup)
pub async fn register_start(/* state, session */) -> impl IntoResponse { /* ... */ }
pub async fn register_finish(/* state, session, attestation */) -> impl IntoResponse { /* ... */ }

// Authentication endpoints (login)
pub async fn authenticate_start(/* state, session */) -> impl IntoResponse { /* ... */ }
pub async fn authenticate_finish(/* state, session, assertion */) -> impl IntoResponse {
    // 1. Full ceremony verification (use library's SAFE API, never raw crypto)
    // 2. Derive DID from verified credential's public key
    // 3. Store verified DID in session:
    //      session_entry.verified_did = Some(did);
    //      db.set_session(session_id, session_entry).await?;
    // 4. Redirect to /sign_in (existing endpoint handles code issuance)
}
```

**Security rules for ceremony modules:**
- Use the ceremony library's SAFE/high-level API (e.g. `webauthn-rs`, not `webauthn-rs-core`)
- Never expose raw signature verification as a standalone WebAuthn check
- All ceremony checks must be atomic (rpIdHash, origin, challenge, flags, counter, signature)
- Store the verified DID in Redis session, NOT in a client-side cookie
- Fail closed: if any check fails or Redis is unavailable, reject the login

### 3. Add Redis key schema — `src/db/mod.rs` + `src/db/redis.rs`

Add storage for ceremony-specific state. Example for WebAuthn:

```rust
// In SessionEntry — add optional verified_did field
pub struct SessionEntry {
    pub siwe_nonce: String,
    pub oidc_nonce: Option<Nonce>,
    pub secret: String,
    pub signin_count: u64,
    pub verified_did: Option<String>,  // ← NEW: set by ceremony, read by sign_in
}

// Ceremony-specific keys (e.g. credential storage)
// webauthn:credential:{cred_id}  no TTL  → { did, pubkey, sign_count }
// webauthn:challenge:{session}   TTL 60s → challenge state
```

### 4. Register routes — `src/axum_lib.rs`

```rust
.route("/webauthn/register/start", post(webauthn::register_start))
.route("/webauthn/register/finish", post(webauthn::register_finish))
.route("/webauthn/authenticate/start", post(webauthn::authenticate_start))
.route("/webauthn/authenticate/finish", post(webauthn::authenticate_finish))
```

### 5. Generalize sign_in — `src/oidc.rs`

Add the server-verified path before the existing CAIP-122 cookie path:

```rust
pub async fn sign_in(/* ... */) -> Result<Url, CustomError> {
    // Path A: Server-verified ceremony (WebAuthn, SSH, etc.)
    if let Some(verified_did) = session_entry.verified_did.as_ref() {
        // DID was already verified by the ceremony endpoint
        // Proceed directly to allowlist check + code issuance
        let did = verified_did.clone();
        // ... check allowlist, nonce, redirect_uri, issue code ...
    }
    // Path B: Client-set CAIP-122 cookie (existing wallet flow — unchanged)
    else {
        let siwx_cookie = /* read cookie */;
        let did_method = find_did_method(&siwx_cookie.did)?;
        did_method.verify(&siwx_cookie.did, &siwx_cookie.message, &sig_bytes)?;
        // ... existing flow unchanged ...
    }
}
```

### 6. Add frontend UI — `js/ui/src/App.svelte`

Add a button/section for the new ceremony. For WebAuthn:
- "Sign in with passkey" button → calls `/webauthn/authenticate/start` → `navigator.credentials.get()` → posts to `/webauthn/authenticate/finish`
- "Register a passkey" for first-time setup

### 7. Update config — `src/config.rs`

Add any ceremony-specific config (e.g. `SIWEOIDC_RP_ID` for WebAuthn RP ID).

### 8. Test

```bash
cargo test --bin siwx-oidc  # Server tests (needs Redis)
```

## Security invariants (must hold for ALL ceremonies)

| Invariant | What to check |
|---|---|
| Single code issuance | Auth codes are ONLY created in `sign_in`. Ceremony endpoints NEVER issue codes. |
| Challenge binding | The ceremony challenge MUST match the session nonce. Prevents replay. |
| Server-side trust | Verified DID stored in Redis session, never in a client-side cookie. |
| Fail closed | If Redis or ceremony library fails, reject login. Never silently skip checks. |
| DID allowlist | `sign_in` enforces `supported_did_methods` for ALL paths, including server-verified. |
| No ceremony in siwx-core | Ceremony logic stays in `src/`. The `DIDMethod` trait is not extended. |

## Production checklist

Before shipping a new ceremony:

- [ ] All `.expect()` / `.unwrap()` calls are in startup-only code or replaced with `Result`
- [ ] Input validation: credential IDs, session IDs validated for non-empty before use in Redis keys
- [ ] Server-verified path in `sign_in` enforces both `allowed_did_methods` AND `allowed_pkh_namespaces`
- [ ] Challenge TTLs are set (default 120s) and challenges are consumed (deleted) after use
- [ ] `SIWEOIDC_SUPPORTED_DID_METHODS` includes the DID method the ceremony produces (e.g. `"key"` for passkeys)
- [ ] Redis key prefixes are unique and don't collide with existing prefixes (sessions/, codes/, clients/)
- [ ] Frontend `buildSignInUrl()` passes PKCE params through to `/sign_in`
- [ ] `CLAUDE.md` troubleshooting section updated with ceremony-specific error messages

## References

- NIST SP 800-63B — authenticator verification is a server/verifier responsibility
- W3C WebAuthn L2 §7.2 — 17-step ceremony, only 2 are crypto
- Carl Ellison, "Ceremony Design and Analysis" (IACR 2007/399) — ceremony ≠ crypto
- webauthn-rs safe API — monolithic ceremony verification by design
