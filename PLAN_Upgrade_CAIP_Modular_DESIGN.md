# siwx-oidc v2 — Architecture Design Document

> **Status:** Draft — 2026-03-18
> **Scope:** Clean reimplementation of the CAIP-122 → OIDC bridge with modular cipher support

---

## 1. Problem Statement

We need a bridge that lets agents and users authenticate to legacy Web2 OIDC services (Matrix/Synapse, any OAuth2 RP) using cryptographic proof of key ownership — signed messages verified against arbitrary key material.

The current siwx-oidc fork works but has three structural problems:

1. **Hardcoded cipher knowledge** scattered across 8+ locations in 2 crates — adding a cipher means coordinated edits everywhere.
2. **CAIP namespace conflated with cipher suite** — `"eip155"` means both "Ethereum network" and "secp256k1 + EIP-191 prefix." For non-blockchain use, the abstraction is wrong.
3. **Outdated dependency stack** — RSA JWT signing with a known timing vulnerability (RUSTSEC-2023-0071), openidconnect 3.x, axum 0.4.x.

### Design Goal

**Adding a new cipher suite (e.g. P-384, Ed448, RSA, ML-DSA) should be a single file implementing a single trait, with zero changes to the OIDC server, the headless client, the message format, the DID parser, or the config layer.**

---

## 2. Guiding Principles

- **Cipher-first, chain-optional.** The primary concept is "what algorithm signed this?" not "which blockchain is this from?" Chain IDs are metadata on a cipher suite, not the organizing axis.
- **CAIP-122 compatible, not CAIP-122 limited.** The wire format (message structure, `did:pkh` identifiers) remains CAIP-122 for interoperability with the Web3 ecosystem, but the internal architecture does not assume blockchain.
- **One source of truth.** Message construction, DID parsing, and cipher metadata live in exactly one place. No duplication between server and client.
- **Trait-driven dispatch.** The OIDC layer knows nothing about specific ciphers. It asks a registry "can you verify this namespace?" and gets back a yes/no.
- **Modern dependencies.** EdDSA/ES256 for JWT signing (eliminating RSA). Current versions of axum, openidconnect, tokio.

---

## 3. Crate Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      Workspace                           │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ siwx-core   │  │ siwx-oidc    │  │ siwx-oidc-auth │  │
│  │             │  │ (server)     │  │ (headless      │  │
│  │ Traits      │  │              │  │  client)       │  │
│  │ Types       │  │ Axum routes  │  │                │  │
│  │ Message fmt │  │ OIDC logic   │  │ login() fn     │  │
│  │ DID parsing │  │ JWT signing  │  │                │  │
│  │ Registry    │  │ DB layer     │  │                │  │
│  │             │  │ Config       │  │                │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                │                   │           │
│         │   ┌────────────┴───────────────────┘           │
│         │   │  (both depend on siwx-core)                │
│         │   │                                            │
│  ┌──────┴───┴──────────────────────────────────────────┐ │
│  │              Cipher Suite Modules                   │ │
│  │                                                     │ │
│  │  ┌─────────┐ ┌────────┐ ┌──────┐ ┌──────┐ ┌─────┐ │ │
│  │  │ eip191  │ │ed25519 │ │ p256 │ │ p384 │ │ rsa │ │ │
│  │  │(eip155) │ │        │ │      │ │      │ │     │ │ │
│  │  └─────────┘ └────────┘ └──────┘ └──────┘ └─────┘ │ │
│  │                                                     │ │
│  │  Each: impl CipherSuite + inventory::submit!        │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 3.1 siwx-core

The shared foundation crate. Contains everything both the server and the headless client need — types, traits, message format, DID parsing, cipher registry. **No network code, no OIDC code, no async runtime.**

**Owns:**
- `CipherSuite` trait (the extensibility boundary)
- `SiwxMessage` struct and `to_canonical_message()` (single source of truth)
- `SiwxCookie` struct
- DID parsing (`parse_did()`, `to_did()`)
- Cipher registry (via `inventory`)
- Built-in cipher modules (eip191, ed25519, p256 — and any additional ones)

**Does not own:**
- OIDC protocol logic
- HTTP/transport
- Database/session management
- JWT signing

### 3.2 siwx-oidc (server)

The OIDC Identity Provider. Accepts CAIP-122 sign-in proofs and issues standard OIDC tokens. **Has zero knowledge of specific ciphers** — delegates all verification to `siwx-core`'s registry.

**Owns:**
- OIDC endpoints: `/authorize`, `/token`, `/userinfo`, `/sign_in`, `/.well-known/openid-configuration`, `/jwk`, `/register`
- JWT signing key management (EdDSA or ES256 — not RSA)
- Session and authorization code storage (Redis / Cloudflare KV)
- Configuration
- HTTP routing (Axum)

### 3.3 siwx-oidc-auth (headless client)

Library crate for agents and CLI tools to perform the OIDC authorization-code flow without a browser. **Has zero knowledge of specific ciphers** — caller provides a `sign_fn` closure and a DID string.

**Owns:**
- `login()` function (the full headless flow)
- HTTP client management (reqwest + cookie store)

**Does not own:**
- Signing logic (caller provides it)
- Message construction details (uses `siwx-core::SiwxMessage`)

---

## 4. The CipherSuite Trait

The central extensibility boundary. Every supported cipher implements this trait.

```
CipherSuite
├── namespace()        → &str          // "eip155", "ed25519", "p256", "p384", "rsa"
├── display_label()    → &str          // "Ethereum", "Ed25519", "P-256", "P-384", "RSA"
├── has_chain_id()     → bool          // true only for blockchain namespaces
├── did_segments()     → usize         // 3 = did:pkh:ns:addr, 4 = did:pkh:ns:chain:addr
├── verify(did, message, signature)    → Result<bool>
└── parse_did_parts(did_remainder)     → Result<(address, Option<chain_id>)>
```

### Registration

Cipher suites self-register at compile time using `inventory`:

```
// In the ed25519 module:
inventory::submit! { &Ed25519Suite as &dyn CipherSuite }

// In the server or client — no import of specific ciphers needed:
fn find_suite(namespace: &str) -> Option<&'static dyn CipherSuite> {
    inventory::iter::<&dyn CipherSuite>
        .find(|s| s.namespace() == namespace)
}
```

### What adding a new cipher looks like

One file, one trait impl, one `inventory::submit!` call. Example for P-384:

```
File: siwx-core/src/ciphers/p384.rs

  struct P384Suite;

  impl CipherSuite for P384Suite {
      fn namespace(&self) -> &str { "p384" }
      fn display_label(&self) -> &str { "P-384" }
      fn has_chain_id(&self) -> bool { false }
      fn did_segments(&self) -> usize { 3 }
      fn verify(&self, did, message, signature) -> Result<bool> { ... }
      fn parse_did_parts(&self, remainder) -> Result<(String, Option<String>)> { ... }
  }

  inventory::submit! { &P384Suite as &dyn CipherSuite }
```

No other file changes. The server and client discover it automatically.

### The eip155 Special Case

EIP-155 (Ethereum / secp256k1 + EIP-191) is the only currently-known cipher suite where:
- `has_chain_id()` returns `true`
- `did_segments()` returns `4` (did:pkh:eip155:**chain_id**:address)
- `verify()` internally prepends the EIP-191 `\x19Ethereum Signed Message:\n{len}` prefix before hashing with Keccak256 and doing ecrecover

This is handled entirely inside its `CipherSuite` impl. The OIDC layer sees it as just another namespace with one extra DID segment.

---

## 5. Message Format

The CAIP-122 message format is retained as-is for wire compatibility. The `SiwxMessage` struct lives in `siwx-core` (single definition, no duplication).

```
{domain} wants you to sign in with your {display_label} account:
{address}

{statement}

URI: {uri}
Version: {version}
[Chain ID: {chain_id}]      ← only if cipher.has_chain_id()
Nonce: {nonce}
Issued At: {issued_at}
[Expiration Time: {expiration_time}]
[Not Before: {not_before}]
[Request ID: {request_id}]
[Resources:
- {resource_1}
- {resource_2}]
```

**Key change from v1:** `to_canonical_message()` no longer hardcodes `if namespace == "eip155"`. Instead, it queries the cipher registry:

```
if registry.get(self.namespace)?.has_chain_id() {
    // include Chain ID line
}
```

### DID Format

Retained: `did:pkh:{namespace}[:{chain_id}]:{address}`

- 3-segment (most ciphers): `did:pkh:ed25519:0x{pubkey_hex}`
- 4-segment (eip155-like): `did:pkh:eip155:1:0x{address}`

The segment count is driven by `CipherSuite::did_segments()`. Parsing uses `CipherSuite::parse_did_parts()` to handle namespace-specific address formats.

---

## 6. OIDC Token Signing

### Problem

The current implementation signs OIDC JWTs with RSA (RS256), which is affected by RUSTSEC-2023-0071 (Marvin Attack — timing side-channel on the `rsa` crate). No stable patched version of the `rsa` crate exists.

### Decision: EdDSA (Ed25519) as default, ES256 (P-256) as alternative

| Property | EdDSA (Ed25519) | ES256 (P-256) |
|---|---|---|
| Key size | 32 bytes | 32 bytes |
| Signature size | 64 bytes | 64 bytes |
| Performance | Fastest | Fast |
| OIDC support | `openidconnect` 4.x has EdDSA | Enum present but signing "unsupported" in Core types |
| JWT ecosystem | `jsonwebtoken` 10.x supports it | `jsonwebtoken` 10.x supports it |
| RP compatibility | Most modern RPs accept it | Universal acceptance |

**Primary:** EdDSA (Ed25519) — smallest, fastest, no known side-channel issues, well-supported by `jsonwebtoken` 10.x.

**Fallback:** ES256 (P-256) — if an RP does not support EdDSA (rare but possible with older OAuth2 libraries).

**Configuration:** The server generates or loads a signing key at startup. The algorithm is selected via config (`SIWXOIDC_JWT_ALG=EdDSA` or `ES256`). The JWKS endpoint advertises the corresponding public key.

### Implementation Note

Since `openidconnect` 4.x does not natively support EdDSA/ES256 *signing* in its `Core*` types (only verification), JWT token construction will use `jsonwebtoken` directly. The `openidconnect` crate is still used for OIDC protocol types (metadata, client registration, claims) but not for the signing step itself.

---

## 7. OIDC Flow (unchanged)

The OIDC authorization-code flow is the same as v1. The cipher-agnostic refactoring does not change the protocol.

```
Agent/User                    siwx-oidc                     Relying Party
    │                            │                              │
    │  1. GET /authorize ◄───────┼────── redirect from RP ──────┤
    │         ─────────────────► │                              │
    │  2. ◄── 302 + session     │                              │
    │         cookie + nonce     │                              │
    │                            │                              │
    │  3. Build SiwxMessage      │                              │
    │     Sign with key material │                              │
    │     Set siwe cookie        │                              │
    │                            │                              │
    │  4. GET /sign_in ─────────►│                              │
    │                            │ 5. Lookup cipher suite       │
    │                            │    via registry              │
    │                            │    Verify signature          │
    │                            │    Validate nonce/domain/    │
    │                            │    time/resource binding     │
    │                            │                              │
    │  6. ◄── 302 + auth code   │                              │
    │         ────────────────────────────────────────────────► │
    │                            │  7. POST /token ◄────────────┤
    │                            │     (code exchange)          │
    │                            │  8. ──── ID token (EdDSA) ──►│
    │                            │                              │
    │                            │  9. GET /userinfo ◄──────────┤
    │                            │ 10. ──── {sub: did:pkh:...} ►│
```

Step 5 is the only step that touches cipher-specific logic, and it's a single registry lookup + trait method call.

---

## 8. Database Layer

**Unchanged from v1.** The `DBClient` trait with `set_code`/`get_code`/`set_session`/`get_session`/`set_client`/`get_client` remains. The `CodeEntry` struct stores `namespace: String` and `address: String` — both are opaque strings from the DB layer's perspective.

Two backends:
- **Native:** Redis via `bb8-redis` (upgrade to current version)
- **WASM32:** Cloudflare KV + Durable Objects

No cipher knowledge enters the DB layer.

---

## 9. Configuration

```toml
# siwx-oidc.toml

address = "0.0.0.0"
port = 8000
base_url = "https://auth.example.com"
redis_url = "redis://localhost"

# JWT signing algorithm for OIDC tokens (not the user's signature algorithm)
jwt_alg = "EdDSA"          # or "ES256"
# jwt_private_key_pem = ... # optional; generated at startup if absent

# Which cipher namespaces this server accepts.
# Any namespace with a registered CipherSuite impl is valid.
supported_namespaces = ["eip155", "ed25519", "p256"]

# Legacy / optional
eth_provider = "https://eth.example.com"  # for future ENS resolution
```

**Change from v1:** `rsa_pem` config field replaced by `jwt_alg` + `jwt_private_key_pem`. The signing key type matches the configured algorithm.

**Validation at startup:** The server checks that every entry in `supported_namespaces` has a corresponding `CipherSuite` in the registry. Unknown namespaces cause a startup error with a clear message listing available ciphers.

---

## 10. Dependency Stack

### siwx-core

| Crate | Purpose |
|---|---|
| `inventory` ~0.3 | Compile-time cipher suite registration |
| `serde` + `serde_json` | Message serialization |
| `thiserror` | Error types |
| `hex` | Signature/address encoding |
| `chrono` | Timestamp handling |
| — | (Cipher-specific deps are internal to each module) |

Cipher modules pull in their own crypto deps:
- eip191: `k256`, `sha3`
- ed25519: `ed25519-dalek`
- p256: `p256`
- p384: `p384` (when added)
- rsa: `rsa` (when added — only for *signature verification*, not JWT signing)

### siwx-oidc (server)

| Crate | Version | Purpose |
|---|---|---|
| `siwx-core` | workspace | Traits, types, cipher registry |
| `axum` | ~0.8 | HTTP framework |
| `tokio` | ~1.40 | Async runtime |
| `tower-http` | ~0.6 | CORS, static files, tracing |
| `openidconnect` | ~4.0 | OIDC protocol types (metadata, claims, client registration) |
| `jsonwebtoken` | ~10.3 | JWT signing (EdDSA / ES256) |
| `bb8-redis` | current | Redis connection pool |
| `uuid` | ~1.x | Code/session identifiers |
| `figment` | ~0.10 | Config (TOML + env) |
| `cookie` | current | Session/auth cookies |

### siwx-oidc-auth (headless client)

| Crate | Version | Purpose |
|---|---|---|
| `siwx-core` | workspace | Shared message types, DID parsing |
| `reqwest` | ~0.12 | HTTP client |
| `reqwest_cookie_store` | current | Cookie management |

---

## 11. Target Cipher Suites

Initial release (v2.0):

| Namespace | Algorithm | DID Segments | Chain ID | Crate |
|---|---|---|---|---|
| `eip155` | secp256k1 + EIP-191 prefix + Keccak256 | 4 | Yes | `k256`, `sha3` |
| `ed25519` | Ed25519 | 3 | No | `ed25519-dalek` |
| `p256` | NIST P-256 ECDSA | 3 | No | `p256` |

Planned follow-up (v2.x):

| Namespace | Algorithm | Notes |
|---|---|---|
| `p384` | NIST P-384 ECDSA | Government/enterprise PKI |
| `secp256k1` | Raw secp256k1 (no EIP-191 prefix) | Bitcoin, Nostr — sign raw message hash, no Ethereum wrapping |
| `rsa` | RSA PKCS#1 v1.5 / PSS | SSH keys, enterprise PKI, PGP |
| `ed448` | Ed448-Goldilocks | Higher-security EdDSA |
| `bls12-381` | BLS signatures | Aggregate/threshold signatures |
| `ml-dsa` | ML-DSA (Dilithium) | Post-quantum (NIST FIPS 204) |

Each is a single `CipherSuite` impl + `inventory::submit!` in `siwx-core/src/ciphers/`. No changes to the server or client crates.

---

## 12. Cloudflare Worker Target

The WASM32 deployment target is retained. Architectural considerations:

- `inventory` works in WASM (it uses `ctor` which compiles to wasm-bindgen init functions).
- `jsonwebtoken` with `rust_crypto` feature compiles to WASM (no OpenSSL).
- The `DBClient` trait already has conditional `?Send` for WASM.
- `axum` is replaced by the `worker` crate's request routing on the WASM target (unchanged from v1).

The cipher registry is the same on both targets — `inventory` handles the registration regardless of platform.

---

## 13. Security Model

### Signature Verification (user identity proof)

- Delegated entirely to `CipherSuite::verify()` — each cipher owns its own verification logic.
- The OIDC server trusts the registry: if a cipher is registered and the namespace is in `supported_namespaces`, signatures from it are accepted.
- **Nonce binding:** Server-generated, single-use, stored in Redis with TTL.
- **Domain binding:** Message `domain` field must match server's `base_url`.
- **Resource binding:** `resources[0]` must match the OIDC `redirect_uri`.
- **Time binding:** `expiration_time` and `not_before` enforced server-side.

### JWT Signing (OIDC token issuance)

- EdDSA (Ed25519) or ES256 (P-256) — no RSA. Eliminates RUSTSEC-2023-0071.
- Signing key generated at first startup if not provided via config. Stored on disk or in a secrets manager.
- Key rotation: new key ID (`kid`) per key; old keys remain in JWKS for token verification until TTL expiry.
- Short-lived tokens: ID token expires in 60 seconds, access token (authorization code) expires in 30 seconds.

### Session Management

- Session cookie: `SameSite=Strict`, `HttpOnly`, 5-minute TTL.
- Single-use sign-in: `signin_count` prevents replay within a session.
- Single-use authorization code: `exchange_count` prevents code reuse.

---

## 14. Migration Path from v1

This is a reimplementation, not a patch. But the migration surface is small because the OIDC wire protocol is identical:

1. **RPs (Matrix/Synapse, other OIDC clients):** No change needed. The OIDC endpoints, token format, and `sub` claim (`did:pkh:...`) are the same. The only difference is the JWT signing algorithm (EdDSA instead of RS256) — RPs that fetch JWKS dynamically (which is all spec-compliant RPs) handle this automatically.

2. **Headless clients (siwx-oidc-auth users):** The `login()` API stays the same — `(did, sign_fn, authorize_url) -> Client`. The internal message construction now comes from `siwx-core` instead of a local copy.

3. **Configuration:** `rsa_pem` is replaced by `jwt_alg` + `jwt_private_key_pem`. `SIWEOIDC_*` env prefix remains `SIWXOIDC_*`. `supported_namespaces` format unchanged.

4. **Database:** Schema unchanged — `CodeEntry`, `ClientEntry`, `SessionEntry` are the same structures. Redis data is compatible; no migration needed.

5. **Docker image:** Same base image strategy (muslrust), different dependency versions. Image tag bumps to `v2.0.0`.

---

## 15. What This Design Does NOT Cover

- **Browser/wallet UI** — The JS frontend (WalletConnect/Web3Modal) is a separate concern. It can continue using the `siwe` npm package for EIP-4361 messages and be extended separately for other ciphers.
- **ENS resolution** — Deferred. The `eth_provider` config field is retained but unused. ENS name/avatar resolution can be added as an optional enrichment on the `eip155` cipher suite later.
- **Verifiable Credentials** — Out of scope. This bridge is for proving key ownership, not presenting VCs. OpenID4VP is a separate protocol.
- **SIOP v2** — Not implemented. SIOP v2 inverts the architecture (wallet = OP). Our bridge model (centralized OIDC IdP that verifies signatures) is the correct approach for legacy RPs that don't support SIOP.
- **Token refresh** — OIDC refresh tokens are not implemented (same as v1). Sessions are short-lived by design.

---

## 16. Open Questions

1. **Should cipher modules live in `siwx-core` or in separate crates?** Putting them in `siwx-core` is simpler but means every consumer compiles every cipher's crypto deps. Separate crates (`siwx-cipher-ed25519`, `siwx-cipher-p384`) allow opt-in via Cargo features but add workspace complexity. For 3-5 ciphers, in-crate with feature flags is likely sufficient. For 10+, separate crates may be cleaner.

2. **`did:pkh` vs. `did:key` for non-blockchain ciphers.** `did:pkh` (public key hash) is correct for Ethereum where the address is a hash of the public key. For Ed25519/P-256 where the "address" field is the full public key hex, `did:key` may be more semantically correct. However, `did:pkh` provides a uniform format and is what CAIP-122 specifies. Recommendation: keep `did:pkh` for CAIP-122 compatibility, consider supporting `did:key` as an alternative DID format in a future version.

3. **Namespace naming for raw secp256k1.** `"eip155"` means secp256k1 *with* EIP-191 prefix. Bitcoin/Nostr use secp256k1 *without* EIP-191. Should the raw variant be `"secp256k1"` or follow a CAIP namespace like `"bip122"`? Recommendation: use `"secp256k1"` as the namespace (cipher-first naming), document that `"eip155"` is the Ethereum-specific variant with prefix wrapping.

4. **`openidconnect` 4.x integration depth.** Given that `openidconnect` 4.x doesn't support EdDSA/ES256 *signing* in its Core types, we use it only for protocol types and do JWT signing with `jsonwebtoken`. Should we define custom OIDC types instead of using `openidconnect` at all? Recommendation: keep `openidconnect` for metadata/claims/registration types — they're well-tested and spec-compliant. Only bypass it for the JWT signing step.

---

## 17. Codebase Reality Check — Evaluation Against Current Repository

> **Date:** 2026-03-18
> **Method:** Automated audit of every source file, Cargo.toml, and build artifact in the repository.

This section evaluates each claim in the plan above against the actual state of the codebase at commit `caf9516` (HEAD of `main`).

### 17.1 What the Plan Gets Right

**Problem diagnosis is accurate.** The three structural problems are real and confirmed by code inspection:

- Cipher knowledge *is* scattered across 8+ locations: `oidc.rs:268-270` (DID format hardcodes `"eip155:{}:{}"` with chain_id and checksum address), `oidc.rs:559-580` (`Web3ModalMessage` struct with `chain_id: u64` always present), `oidc.rs:625-637` (signature parsing assumes `[u8; 65]` secp256k1 format), the `siwe` crate dependency, `db/mod.rs:24` (`chain_id: Option<u64>` in `CodeEntry`), and the Svelte frontend's `SiweMessage` construction.
- The `eip155` namespace *is* conflated with secp256k1 — adding ed25519 would require coordinated edits in every location above.

**Dependency assessment is mostly current.** The repo has already upgraded to:
- `axum` 0.8 (done)
- `openidconnect` 4.0 (done)
- `bb8-redis` 0.26, `tokio` 1, `figment` 0.10 (done)

The plan correctly identifies `jsonwebtoken`, `inventory`, `ed25519-dalek`, and `k256`/`sha3` as needed additions.

**Database layer assessment is correct.** The `DBClient` trait is clean and cipher-agnostic *except* for the `CodeEntry.chain_id` field (see issues below).

**OIDC flow description matches** the actual endpoints and protocol in `oidc.rs`.

**Crate architecture (3-crate split) is sound.** Clean boundaries already exist in the code between OIDC logic (`oidc.rs`), config (`config.rs`), DB (`db/`), and HTTP (`axum_lib.rs`).

### 17.2 Issues and Corrections

**1. RSA is already eliminated on the native target — plan overstates the problem.**

The plan's Section 6 describes RSA JWT signing as the current state. In reality, commit `caf9516` ("Replace RSA with ES256 and upgrade all dependencies") already migrated the native server to ES256 (P-256 ECDSA). A complete `EcdsaSigningKey` implementation exists at `oidc.rs:71-130` using the `p256` crate, with raw `r||s` encoding. The `rsa` crate is no longer a dependency.

**However**, `worker_lib.rs` still uses RSA (`RsaPrivateKey::from_pkcs1_pem` at lines 7, 85, 128, 178). This is a divergence the plan does not call out.

**Correction:** Section 6 should acknowledge ES256 as the working baseline. EdDSA should be positioned as an *option*, not a migration from RSA.

**2. The `siwe` crate coupling is deeper than the plan implies.**

The plan describes extracting message construction into `SiwxMessage`. In practice, the current code delegates heavily to `siwe::Message` — not just for verification but also for message parsing and construction via `to_eip4361_message()` at `oidc.rs:558-605`. The `SiwxMessage` abstraction must fully replace:
- `siwe::Message` struct and its field types
- `siwe::eip55` checksum address formatting
- `siwe::Message::verify()` (which bundles EIP-191 prefix, Keccak256 hashing, and secp256k1 ecrecover)

This is a security-critical reimplementation, not a simple extraction. The EIP-4361 message format has strict ordering and whitespace rules that must be reproduced exactly for signature verification to work.

**Correction:** Flag `SiwxMessage` as the highest-risk work item. Consider keeping the `siwe` crate as the internal implementation for the eip155 cipher module rather than reimplementing its message format logic.

**3. `CodeEntry.address` is `alloy::primitives::Address`, not `String`.**

The plan's Section 8 states "The `CodeEntry` struct stores `namespace: String` and `address: String`." The actual definition at `db/mod.rs:17-25` is:

```rust
pub struct CodeEntry {
    pub exchange_count: u8,
    pub address: Address,        // alloy::primitives::Address (20-byte Ethereum type)
    pub nonce: String,
    pub client_id: String,
    pub auth_time: DateTime<Utc>,
    pub chain_id: Option<u64>,   // Ethereum-specific
}
```

Both `address: Address` and `chain_id: Option<u64>` are Ethereum-specific types. Changing these to `address: String` and replacing `chain_id` with `namespace: String` is a **breaking change** for serialized Redis data. Existing sessions/codes will fail to deserialize after the upgrade.

**Correction:** Section 8 should acknowledge this as a breaking DB schema change. Either implement a migration strategy (e.g., flush Redis on upgrade, which is acceptable given the 30s/5min TTLs) or add backwards-compatible deserialization.

**4. `inventory` crate has known WASM fragility.**

The plan's Section 12 claims "`inventory` works in WASM (it uses `ctor` which compiles to wasm-bindgen init functions)." This is optimistic. The `inventory` crate relies on link-time constructor tricks (`#[ctor]`) that are fragile on `wasm32-unknown-unknown`. The `ctor` crate has documented issues with WASM targets where constructors may not execute reliably depending on the linker and runtime.

**Correction:** Replace `inventory` with a manual registry function. A `fn all_suites() -> &'static [&'static dyn CipherSuite]` is ~5 lines of code, works on all targets, and is only marginally less ergonomic. The "zero changes to add a cipher" claim becomes "one line added to the registry function" — still a massive improvement over 8+ file edits.

**5. The headless client (`siwx-oidc-auth`) does not exist — it's greenfield, not a refactor.**

The plan's Section 3.3 and Section 14.2 describe the headless client as if it's being refactored from existing code. No headless client exists in this repository. The only client code is:
- The Svelte UI frontend (`js/ui/`) — browser-based, uses WalletConnect
- The `example/demo/` Yew app — outdated (openidconnect 3.1.1), not a library

**Correction:** Section 3.3 should state this is a new crate. Section 14.2 ("The `login()` API stays the same") is misleading — there is no existing API to maintain compatibility with.

**6. `worker_lib.rs` is significantly diverged — the plan doesn't address this.**

The Cloudflare Worker implementation at `worker_lib.rs` still uses RSA signing and has not been updated to match the ES256 migration in the native server. This file duplicates OIDC logic from `oidc.rs` rather than sharing it, which means the modular refactor needs to either:
- Bring `worker_lib.rs` into parity before the refactor, or
- Accept that the WASM target is broken and fix it as part of the v2 work, or
- Drop WASM support and remove the file

**Correction:** Add a section or pre-requisite step addressing `worker_lib.rs` status. The current plan's Section 12 assumes the worker target is functional; it is not.

**7. Config env prefix is a breaking change that isn't flagged.**

The plan's Section 14.3 states: "`SIWEOIDC_*` env prefix remains `SIWXOIDC_*`." The current code at `axum_lib.rs:256` uses `Env::prefixed("SIWEOIDC_")` (with an 'E'). Changing to `SIWXOIDC_` is a breaking change for all deployed environments.

**Correction:** Either keep `SIWEOIDC_` for backwards compatibility and accept both prefixes, or explicitly flag this as a breaking change requiring environment variable updates in all deployments.

**8. The `alloy` dependency is unaccounted for.**

The current codebase uses `alloy` (version 1) extensively:
- `alloy::primitives::Address` for Ethereum addresses throughout `oidc.rs`
- `alloy::providers` + `alloy::transports::http` for ENS resolution in `resolve_claims()`
- `alloy::signers::local::PrivateKeySigner` in tests

The plan never mentions `alloy`. For the modular architecture, `alloy` should be scoped to the eip155 cipher module only, not pulled into `siwx-core`'s public API. The current `Address` type in `CodeEntry` is the main coupling point.

**Correction:** Add `alloy` to Section 10's dependency list under the eip155 cipher module. Document that `alloy` must not leak into `siwx-core`'s public types.

**9. `jsonwebtoken` integration path with `openidconnect` is underspecified.**

The plan says "JWT token construction will use `jsonwebtoken` directly" but doesn't detail how this interacts with `openidconnect`'s protocol types. The current signing is done through `openidconnect`'s `PrivateSigningKey` trait at `oidc.rs:71-130`, and `CoreIdToken::new()` at `oidc.rs:299` expects this trait. Switching to raw `jsonwebtoken` means reimplementing the ID token construction that `openidconnect` currently handles (claims structure, header, serialization).

**Correction:** Section 6 should specify whether to implement `openidconnect::PrivateSigningKey` for the new key types (keeping the `CoreIdToken::new()` flow) or bypass `openidconnect` for token construction entirely (more work but cleaner separation). The current ES256 implementation already shows how to implement `PrivateSigningKey` — the same pattern can be used for EdDSA.

### 17.3 Feasibility Assessment

| Plan Element | Feasibility | Risk | Notes |
|---|---|---|---|
| Workspace split into 3 crates | High | Low | Clean boundaries already exist |
| `CipherSuite` trait + registry | High | Medium | Use manual registry instead of `inventory` for WASM safety |
| eip155 cipher module | Medium | **High** | Must replicate `siwe` crate internals (EIP-191 prefix, Keccak256, ecrecover). Security-critical. |
| ed25519 / p256 cipher modules | High | Low | Straightforward crypto, well-tested crates |
| EdDSA JWT signing | Medium | Low | ES256 already works; EdDSA is incremental |
| `SiwxMessage` replacing `siwe::Message` | Medium | **High** | Message format correctness is security-critical; strict whitespace/ordering rules |
| Headless client crate | High | Low | Greenfield; no legacy constraints |
| Worker parity | Low | **High** | `worker_lib.rs` is stale (RSA); may need near-rewrite |
| DB schema change (`Address` → `String`) | High | Low | Short TTLs make flush-on-upgrade acceptable |

### 17.4 Recommended Execution Order

Based on the risk assessment, the implementation should proceed in this order:

1. **Pre-requisite: Decide on `worker_lib.rs`.** Fix it, drop it, or mark it as out-of-scope for v2.0. Do not carry stale code through the refactor.

2. **Phase 1: Extract `siwx-core` crate.** Create the workspace, move types and traits. Use a manual cipher registry (not `inventory`). Implement the `CipherSuite` trait with eip155 as the first module — keep the `siwe` crate as the internal implementation initially rather than reimplementing message format logic.

3. **Phase 2: Refactor `siwx-oidc` server.** Make it cipher-agnostic by replacing all hardcoded `eip155`/Ethereum references with registry lookups. Change `CodeEntry` to use `String` types. Keep ES256 as default JWT signing.

4. **Phase 3: Add ed25519 and p256 cipher modules.** These are the proof that the abstraction works. If adding them requires changes outside their own module files, the trait design needs revision.

5. **Phase 4: Create `siwx-oidc-auth` headless client.** Greenfield crate using `siwx-core` types.

6. **Phase 5 (optional): Add EdDSA JWT signing.** Only if there's a concrete RP that needs it. ES256 has universal acceptance.

### 17.5 Current Source File Inventory

For reference, the complete source structure that this plan must transform:

```
src/
├── lib.rs              — Exports `pub mod db`
├── main.rs             — Entry point → axum_lib::main()
├── config.rs           — Config struct (Figment: TOML + env)
├── axum_lib.rs         — Axum server, routes, AppState, ES256 key init
├── oidc.rs             — All OIDC logic: EcdsaSigningKey, endpoints, SIWE verification, DID gen, tests
├── worker_lib.rs       — Cloudflare Worker (STALE: still uses RSA)
└── db/
    ├── mod.rs          — DBClient trait, CodeEntry/ClientEntry/SessionEntry
    ├── redis.rs        — Redis implementation
    └── cf.rs           — Cloudflare KV implementation

js/ui/                  — Svelte frontend (WalletConnect/Wagmi/siwe npm)
example/demo/           — Yew WASM demo (outdated deps)
test/docker-compose.yml — Integration tests (Keycloak + Redis)
```
