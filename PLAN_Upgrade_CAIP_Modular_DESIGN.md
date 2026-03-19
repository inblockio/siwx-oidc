# siwx-oidc v2 — Architecture Design Document

> **Status:** Draft — 2026-03-19 (Second iteration)
> **Scope:** Drop-in replacement for `siwe-oidc` connecting to Matrix/Synapse, extended to modular cipher and DID method support

---

## 1. Problem Statement

We need a bridge that lets agents and users authenticate to legacy Web2 OIDC services (Matrix/Synapse, any OAuth2 RP) using cryptographic proof of key ownership — signed messages verified against arbitrary key material.

The current siwx-oidc fork works but has three structural problems:

1. **Hardcoded cipher knowledge** scattered across 8+ locations in 2 crates — adding a cipher means coordinated edits everywhere.
2. **CAIP namespace conflated with cipher suite** — `"eip155"` means both "Ethereum network" and "secp256k1 + EIP-191 prefix." For non-blockchain use, the abstraction is wrong.
3. **Outdated dependency stack** — RSA JWT signing with a known timing vulnerability (RUSTSEC-2023-0071), openidconnect 3.x, axum 0.4.x.

### Design Goal

**Primary:** A drop-in replacement for `siwe-oidc` that connects to Matrix/Synapse via OpenID Connect, extended to support `did:pkh` with three cipher suites (eip155, Ed25519, P-256) in the first release.

**Secondary:** Adding a new cipher suite or DID method should require exactly one new file plus one line in the registry, with zero changes to the OIDC server, the headless client, the message format, the DID parser, or the config layer.

### Reference Implementation

The companion library `aqua-rs-auth` already contains working, tested implementations of all three v2.0 cipher suites: `verify_eip191.rs` (secp256k1 + EIP-191 + Keccak256), `verify_ed25519.rs`, and `verify_p256.rs`. The `siwx-core` cipher modules are a direct port of these — migration, not reimplementation. This eliminates the security risk of writing new cryptographic verification code from scratch.

---

## 2. Guiding Principles

- **Cipher-first, chain-optional.** The primary concept is "what algorithm signed this?" not "which blockchain is this from?" Chain IDs are metadata on a cipher suite, not the organizing axis.
- **CAIP-122 compatible, not CAIP-122 limited.** The wire format (message structure, `did:pkh` identifiers) remains CAIP-122 for interoperability with the Web3 ecosystem, but the internal architecture does not assume blockchain.
- **One source of truth.** Message construction, DID parsing, and cipher metadata live in exactly one place. No duplication between server and client.
- **Trait-driven dispatch.** The OIDC layer knows nothing about specific ciphers. It asks a registry "can you verify this namespace?" and gets back a yes/no.
- **Modern dependencies.** ES256 for JWT signing (RSA eliminated). Current versions of axum, openidconnect, tokio.
- **Port before inventing.** `aqua-rs-auth` already contains proven cipher implementations for all three v2.0 target suites. Use them directly. Novel code is limited to the trait plumbing; the cryptographic verification logic is not new.

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
- `DIDMethod` trait (the primary extensibility boundary)
- `CipherSuite` trait (the crypto-layer boundary; internal to `did:pkh`)
- `SiwxMessage` struct and `to_canonical_message()` (single source of truth)
- `SiwxCookie` struct
- DID method registry (manual static function — no `inventory`)
- Cipher suite registry (manual static function — no `inventory`)
- Built-in DID method modules (pkh, key, peer)
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

## 4. Extensibility Traits

Two traits form the extensibility boundary, addressing orthogonal concerns:

- **`DIDMethod`** — the *primary* boundary. Controls how to interpret a DID, extract address and chain metadata for CAIP-122 message construction, and dispatch verification. The server only imports `DIDMethod` — it has no knowledge of specific cipher suites.
- **`CipherSuite`** — the *secondary* boundary. Controls the cryptographic primitive for signatures under `did:pkh`. Internal to the `PkhMethod` implementation; not exposed to the server or the headless client.

### 4.1 The DIDMethod Trait

```
DIDMethod
├── method_name()                      → &str                  // "pkh", "key", "peer"
├── supports_did(did)                  → bool                  // quick prefix check
├── display_label(did)                 → Result<String>        // "Ethereum", "Ed25519 Key"
├── address_for_message(did)           → Result<String>        // address line in CAIP-122 message
├── has_chain_id(did)                  → bool                  // whether to include Chain ID line
├── chain_id(did)                      → Result<Option<String>>
├── canonical_subject(did)             → Result<String>        // normalized DID for OIDC sub claim
└── verify(did, canonical_msg, sig)    → Result<bool>
```

#### Registry

DID methods register via a manual static function in `siwx-core` (not `inventory` — see Section 17.2 Issue 4):

```
// siwx-core/src/did_methods/mod.rs

pub fn all_did_methods() -> &'static [&'static dyn DIDMethod] {
    &[
        &PkhMethod,   // did:pkh — all CAIP cipher suites
        &KeyMethod,   // did:key — multicodec-prefixed self-contained keys
        &PeerMethod,  // did:peer — variants 0 and 2 (self-contained)
    ]
}

pub fn find_did_method(did: &str) -> Option<&'static dyn DIDMethod> {
    all_did_methods().iter().copied().find(|m| m.supports_did(did))
}
```

#### What adding a new DID method looks like

One file, one trait impl, one line in `all_did_methods()`. Example: adding `did:peer`:

```
File: siwx-core/src/did_methods/peer.rs

  pub struct PeerMethod;

  impl DIDMethod for PeerMethod {
      fn method_name(&self) -> &str { "peer" }
      fn supports_did(&self, did: &str) -> bool { did.starts_with("did:peer:") }
      fn verify(&self, did, msg, sig) -> Result<bool> { ... }  // dispatch on numalgo prefix
      // ...
  }

  // In siwx-core/src/did_methods/mod.rs — one line added:
  &PeerMethod,
```

No changes to the server, the headless client, the OIDC logic, the message format, the DB layer, or the config.

#### How did:key works

`did:key:z6MkhaXgBZ...` embeds the key type via a multicodec prefix in the multibase-encoded value. The `KeyMethod` impl decodes the prefix to determine the algorithm (`0xed01` = Ed25519, `0x1200` = P-256, `0x1201` = P-384) and dispatches verification to the appropriate crypto primitive internally. No registry lookup outside the method itself.

The OIDC `sub` claim is the full `did:key:...` identifier. The CAIP-122 address line contains the multibase-encoded key (the segment after `did:key:`).

#### How did:peer works

`did:peer` variant 0 (`did:peer:0z6Mk...`) encodes a single inception key — structurally identical to `did:key`. Variant 2 (`did:peer:2...`) encodes multiple keys and services inline. Both are self-contained with no network access required.

Variants 1 and 4 require out-of-band document exchange and are out of scope for v2.0.

### 4.2 The CipherSuite Trait (internal to did:pkh)

Used exclusively inside `PkhMethod`. Not part of the server or headless client public API.

```
CipherSuite  (internal to PkhMethod)
├── namespace()        → &str          // "eip155", "ed25519", "p256", "p384", "rsa"
├── has_chain_id()     → bool          // true only for blockchain namespaces
├── did_segments()     → usize         // 3 = pkh:ns:addr, 4 = pkh:ns:chain:addr
├── verify(did, message, signature)    → Result<bool>
└── parse_did_parts(did_remainder)     → Result<(address, Option<chain_id>)>
```

`PkhMethod` maintains its own internal cipher registry and implements `DIDMethod` by delegating to it:

```
// siwx-core/src/ciphers/mod.rs

pub fn all_cipher_suites() -> &'static [&'static dyn CipherSuite] {
    &[&Eip191Suite, &Ed25519Suite, &P256Suite]
}

fn find_cipher_suite(namespace: &str) -> Option<&'static dyn CipherSuite> {
    all_cipher_suites().iter().copied().find(|s| s.namespace() == namespace)
}
```

#### What adding a new cipher under did:pkh looks like

One file, one trait impl, one line in `all_cipher_suites()`. Example for P-384:

```
File: siwx-core/src/ciphers/p384.rs

  pub struct P384Suite;

  impl CipherSuite for P384Suite {
      fn namespace(&self) -> &str { "p384" }
      fn has_chain_id(&self) -> bool { false }
      fn did_segments(&self) -> usize { 3 }
      fn verify(&self, did, message, signature) -> Result<bool> { ... }
      fn parse_did_parts(&self, remainder) -> Result<(String, Option<String>)> { ... }
  }

  // In all_cipher_suites():
  &[&Eip191Suite, &Ed25519Suite, &P256Suite, &P384Suite]
```

No changes outside the cipher module file.

### 4.3 The eip155 Special Case (unchanged)

EIP-155 is handled entirely inside `Eip191Suite::verify()`, which is internal to `PkhMethod`. The `DIDMethod` layer sees `did:pkh:eip155:1:0x...` as just another DID where `has_chain_id()` returns `true`.

- `has_chain_id()` returns `true`
- `did_segments()` returns `4` (pkh:eip155:**chain_id**:address)
- `verify()` internally prepends the EIP-191 `\x19Ethereum Signed Message:\n{len}` prefix before hashing with Keccak256 and doing ecrecover

### 4.4 Future: Network-Resolved DID Methods (out of scope for v2.0)

`did:web`, `did:webvh`, and `did:keri` require async HTTP resolution before verification. These cannot implement the sync `DIDMethod` trait. The architecture accommodates them via a separate `DIDResolver` trait in `siwx-oidc` (not `siwx-core`):

```
// In siwx-oidc — async, network-capable, NOT in siwx-core

DIDResolver (async)
├── method_name()    → &str
└── resolve(did)     → Future<Result<ResolvedDID>>

ResolvedDID
├── canonical_subject    : String                     // for OIDC sub claim
└── verification_keys    : Vec<(AlgorithmId, Vec<u8>)> // (algorithm, raw public key bytes)
```

After resolution, the server calls the matching `CipherSuite` implementation with the raw key material. The resolution step and the cryptographic verification step are cleanly separated; neither `siwx-core` nor the `DIDMethod` trait is touched to add a new resolver.

`did:webvh` in particular is worth noting: its SCID (Self-Certifying Identifier) component binds the DID to its genesis event hash — this is a sync crypto check that belongs in `siwx-core` as part of the `did:webvh` resolver, providing a meaningful security property even before full log traversal.

**Not implemented in v2.0.** See Section 15.

---

## 5. Message Format

The CAIP-122 message format is retained as-is for wire compatibility. The `SiwxMessage` struct lives in `siwx-core` (single definition, no duplication).

```
{domain} wants you to sign in with your {display_label} account:
{address}

{statement}

URI: {uri}
Version: {version}
[Chain ID: {chain_id}]      ← only if did_method.has_chain_id(did)
Nonce: {nonce}
Issued At: {issued_at}
[Expiration Time: {expiration_time}]
[Not Before: {not_before}]
[Request ID: {request_id}]
[Resources:
- {resource_1}
- {resource_2}]
```

**Key change from v1:** `to_canonical_message()` no longer hardcodes `if namespace == "eip155"`. Instead, it queries the DID method:

```
if did_method.has_chain_id(&self.did)? {
    // include Chain ID line
}
```

### DID Format

The DID format depends on the method. All formats flow through `DIDMethod::canonical_subject()` to produce the normalized string used as the OIDC `sub` claim.

**did:pkh** (CAIP-122 native):
- 3-segment: `did:pkh:ed25519:0x{pubkey_hex}`
- 4-segment (chain-aware): `did:pkh:eip155:1:0x{address}`
- Segment count driven by `CipherSuite::did_segments()` internal to `PkhMethod`

**did:key** (self-contained, ephemeral-friendly):
- `did:key:z{multibase_encoded_multicodec_key}`
- Examples: `did:key:z6Mk...` (Ed25519), `did:key:zDna...` (P-256)

**did:peer** (pairwise, self-contained variants):
- Variant 0: `did:peer:0z6Mk...` (single inception key, same encoding as `did:key`)
- Variant 2: `did:peer:2Ez6Ls...Vz6Mk...` (service + key encoded inline)

### The SiwxCookie: Sign-in Interface Boundary

The sign-in cookie is the interface contract between the client (browser frontend or headless agent) and the `/sign_in` endpoint. This is the most visible breaking change from siwe-oidc.

**Current format — cookie name: `siwe` (siwe-oidc / siwx-oidc v1):**
```
{
  "domain": "example.com",
  "address": "0xABCD...",       ← Ethereum address only
  "chainId": 1,                 ← Ethereum only
  "statement": "...",
  "uri": "https://...",
  "version": "1",
  "nonce": "abc123",
  "issuedAt": "2024-01-01T00:00:00.000Z"
}
+ separate "signature" field: 65-byte secp256k1, 0x-prefixed hex (fixed length)
```

**New format — cookie name: `siwx` (siwx-oidc v2):**
```
{
  "did": "did:pkh:eip155:1:0xABCD...",   ← any supported DID
  "domain": "example.com",
  "statement": "...",
  "uri": "https://...",
  "version": "1",
  "nonce": "abc123",
  "issued_at": "2024-01-01T00:00:00.000Z",
  "expiration_time": null,
  "not_before": null,
  "request_id": null,
  "resources": ["https://..."],
  "signature": "0x..."                    ← variable length; format per cipher
}
```

**Key changes:**
- `address` and `chainId` removed — both are derived from `did` by the server via `DIDMethod`
- `did` field added — server dispatches via `find_did_method(did)` for cipher-agnostic verification
- Cookie renamed `siwe` → `siwx`
- Signature is variable-length: 65 bytes (eip155), 64 bytes (ed25519), DER-or-fixed-64 (p256)

**Frontend impact:** The Svelte/Web3Modal frontend currently sends a `siwe` cookie for Ethereum sign-ins. It must be updated to send a `siwx` cookie with `"did": "did:pkh:eip155:{chainId}:{checksumAddress}"`. Ed25519 and P-256 sign-ins are exclusively for the headless client — not the browser frontend.

---

## 6. OIDC Token Signing

### Current State

The native server (`axum_lib.rs:71-130`) already implements ES256 (P-256 ECDSA) JWT signing via `EcdsaSigningKey` — the `rsa` crate was eliminated in commit `caf9516`. The `worker_lib.rs` Cloudflare target still uses RSA but is dropped from v2.0 scope. **There is no RSA migration needed for the native server.**

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

# Which DID methods this server accepts.
# Any method with a registered DIDMethod impl is valid.
supported_did_methods = ["pkh", "key", "peer"]

# For did:pkh only: which cipher namespaces to accept.
# Any namespace with a registered CipherSuite impl is valid.
supported_pkh_namespaces = ["eip155", "ed25519", "p256"]

# Legacy / optional
eth_provider = "https://eth.example.com"  # for future ENS resolution
```

**Change from v1:** `rsa_pem` config field replaced by `jwt_alg` + `jwt_private_key_pem`. The signing key type matches the configured algorithm.

**Validation at startup:** The server checks that every entry in `supported_did_methods` has a corresponding `DIDMethod` in the registry, and every entry in `supported_pkh_namespaces` has a corresponding `CipherSuite`. Unknown entries cause a startup error with a clear message listing available methods and ciphers.

---

## 10. Dependency Stack

### siwx-core

| Crate | Purpose |
|---|---|
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

## 11. Target DID Methods and Cipher Suites

### DID Methods (v2.0)

| Method | Format | Resolution | Trait | Notes |
|---|---|---|---|---|
| `did:pkh` | `did:pkh:{ns}[:{chain}]:{addr}` | Self-contained | `DIDMethod` (`PkhMethod`) | CAIP-122 native; wraps `CipherSuite` registry |
| `did:key` | `did:key:z{multicodec_key}` | Self-contained | `DIDMethod` (`KeyMethod`) | Key type from multicodec prefix; ideal for ephemeral one-time proofs |
| `did:peer` | `did:peer:{numalgo}...` | Self-contained (v0, v2) | `DIDMethod` (`PeerMethod`) | Pairwise DIDs; v0 identical to `did:key`; v2 multi-key inline |

Planned follow-up (v2.x) — requires async `DIDResolver` in `siwx-oidc`:

| Method | Notes |
|---|---|
| `did:web` | HTTP fetch of DID document at well-known URL |
| `did:webvh` | HTTP fetch + SCID binding + DID log traversal; verifiable key history |
| `did:keri` | Key Event Log via KERI witness network; walled garden infrastructure |

### Cipher Suites under did:pkh (v2.0)

| Namespace | Algorithm | DID Segments | Chain ID | Crate |
|---|---|---|---|---|
| `eip155` | secp256k1 + EIP-191 prefix + Keccak256 | 4 | Yes | `k256`, `sha3` |
| `ed25519` | Ed25519 | 3 | No | `ed25519-dalek` |
| `p256` | NIST P-256 ECDSA | 3 | No | `p256` |

Planned follow-up cipher suites under did:pkh (v2.x):

| Namespace | Algorithm | Notes |
|---|---|---|
| `p384` | NIST P-384 ECDSA | Government/enterprise PKI |
| `secp256k1` | Raw secp256k1 (no EIP-191 prefix) | Bitcoin, Nostr — sign raw message hash, no Ethereum wrapping |
| `rsa` | RSA PKCS#1 v1.5 / PSS | SSH keys, enterprise PKI, PGP |
| `ed448` | Ed448-Goldilocks | Higher-security EdDSA |
| `bls12-381` | BLS signatures | Aggregate/threshold signatures |
| `ml-dsa` | ML-DSA (Dilithium) | Post-quantum (NIST FIPS 204) |

Adding a new DID method: one file + one line in `all_did_methods()`.
Adding a new `did:pkh` cipher: one file + one line in `all_cipher_suites()`.
No changes to the server, the headless client, or any other module in either case.

---

## 12. Cloudflare Worker Target

The WASM32 deployment target is retained. Architectural considerations:

- The DID method and cipher registries are plain `static` slice functions — zero `inventory` / `ctor` tricks. They compile identically on native and WASM32.
- `jsonwebtoken` with `rust_crypto` feature compiles to WASM (no OpenSSL).
- The `DBClient` trait already has conditional `?Send` for WASM.
- `axum` is replaced by the `worker` crate's request routing on the WASM target (unchanged from v1).

The registries work identically on both targets because they are ordinary Rust functions, not link-time constructor magic.

---

## 13. Security Model

### Signature Verification (user identity proof)

- Delegated to `DIDMethod::verify()` — each DID method owns its full verification logic (including any internal cipher dispatch).
- The OIDC server trusts the registry: if a DID method is registered and accepted by config, signatures from it are accepted.
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

## 14. Migration Path: siwe-oidc → siwx-oidc

This is a targeted reimplementation. The OIDC wire protocol is identical; the changes are in the server internals and three specific external-facing points.

### What stays the same

- All HTTP endpoints (same URLs, same parameters, same response shapes)
- JWT signing algorithm: ES256 — already in use in both siwe-oidc and siwx-oidc v1.5
- JWKS endpoint — same P-256 key format; RPs that fetch JWKS dynamically (all spec-compliant RPs) need no changes
- Dynamic client registration, token exchange, userinfo — unchanged
- Redis as the session/code store — same connection config
- Docker image strategy (muslrust base) — image tag bumps to `v2.0.0`

### What changes (breaking)

**1. The `sub` claim format — intentional breaking change.**

| Version | sub claim format |
|---|---|
| siwe-oidc | `eip155:1:0xABCD...` |
| siwx-oidc v1.5 (current) | `eip155:1:0xABCD...` (same) |
| siwx-oidc v2.0 | `did:pkh:eip155:1:0xABCD...` |

This is the correct change — the sub claim should be a proper DID URI, not a bare CAIP namespace string. However it **will break** any RP that stores or compares sub values without going through JWKS-based token verification.

**Matrix/Synapse MAS claim-mapping update required.** The Jinja2 template that extracts the Matrix localpart from `sub` must handle the new format. Example before/after:
```
# Before (siwe-oidc)
{{ sub | split(":") | last }}         → "0xABCD..."

# After (siwx-oidc v2.0)
{{ sub | split(":") | last }}         → "0xABCD..."   ← same result, different split position
{{ sub.split(":")[4] }}               → "0xABCD..."   ← explicit index
```

**2. Sign-in cookie format — affects the JS frontend.**

The cookie name changes from `siwe` to `siwx` and the schema changes (see Section 5). The Svelte/Web3Modal frontend must be updated to send the new format in lockstep with the server deployment.

**3. Configuration field names — additive, one rename.**

| siwe-oidc field | siwx-oidc v2.0 field | Notes |
|---|---|---|
| `signing_key_pem` | `signing_key_pem` | Unchanged |
| `redis_url` | `redis_url` | Unchanged |
| `eth_provider` | `eth_provider` | Unchanged (ENS still deferred) |
| `default_clients` | `default_clients` | Unchanged |
| `require_secret` | `require_secret` | Unchanged |
| — | `supported_did_methods` | New: `["pkh"]` for v2.0 eip155-only, `["pkh", "key"]` to enable did:key |
| — | `supported_pkh_namespaces` | New: `["eip155", "ed25519", "p256"]` |

**Env var prefix:** The current code uses `SIWEOIDC_` prefix. Keep it for backwards compatibility — accept both `SIWEOIDC_` and `SIWXOIDC_` prefixes, or document the rename explicitly for all deployments.

**4. Database schema — flush Redis on upgrade.**

`CodeEntry.address` changes from `alloy::primitives::Address` (Ethereum-specific) to `String`. The serialized Redis entries from v1 will fail to deserialize with the v2 binary. Given the 30-second code TTL and 5-minute session TTL, a rolling restart with a deliberate 5-minute drain window achieves zero downtime without a migration script.

### No headless client migration

`siwx-oidc-auth` is a new crate (Phase 3). There is no existing headless client to migrate. The `aqua-rs-auth` library provides the authentication pattern to model it after.

---

## 15. What This Design Does NOT Cover

- **Browser/wallet UI** — The JS frontend (WalletConnect/Web3Modal) is a separate concern. It can continue using the `siwe` npm package for EIP-4361 messages and be extended separately for other ciphers.
- **ENS resolution** — Deferred. The `eth_provider` config field is retained but unused. ENS name/avatar resolution can be added as an optional enrichment on the `eip155` cipher suite later.
- **Verifiable Credentials** — Out of scope. This bridge is for proving key ownership, not presenting VCs. OpenID4VP is a separate protocol.
- **SIOP v2** — Not implemented. SIOP v2 inverts the architecture (wallet = OP). Our bridge model (centralized OIDC IdP that verifies signatures) is the correct approach for legacy RPs that don't support SIOP.
- **Token refresh** — OIDC refresh tokens are not implemented (same as v1). Sessions are short-lived by design.
- **Network-resolved DID methods** — `did:web`, `did:webvh`, and `did:keri` require async HTTP resolution and cannot implement the sync `DIDMethod` trait. The `DIDResolver` async extension point (Section 4.4) is designed for them but not implemented in v2.0. `did:webvh`'s SCID binding and `did:keri`'s Key Event Log are also out of scope. The three v2.0 DID methods (`did:pkh`, `did:key`, `did:peer`) are sufficient to prove the extensibility architecture; resolvers can be added incrementally without touching core traits.

---

## 16. Open Questions

1. **Should cipher modules live in `siwx-core` or in separate crates?** Putting them in `siwx-core` is simpler but means every consumer compiles every cipher's crypto deps. Separate crates (`siwx-cipher-ed25519`, `siwx-cipher-p384`) allow opt-in via Cargo features but add workspace complexity. For 3-5 ciphers, in-crate with feature flags is likely sufficient. For 10+, separate crates may be cleaner. The same question applies to DID method modules.

2. ~~**`did:pkh` vs. `did:key` for non-blockchain ciphers.**~~ **Resolved.** Both are first-class DID methods in v2.0. `did:pkh` remains the CAIP-122 native path; `did:key` and `did:peer` are supported via the `DIDMethod` trait alongside it. The two-trait model (`DIDMethod` + `CipherSuite`) makes them coexist without compromise.

3. **Namespace naming for raw secp256k1.** `"eip155"` means secp256k1 *with* EIP-191 prefix. Bitcoin/Nostr use secp256k1 *without* EIP-191. Should the raw variant be `"secp256k1"` or follow a CAIP namespace like `"bip122"`? Recommendation: use `"secp256k1"` as the namespace (cipher-first naming), document that `"eip155"` is the Ethereum-specific variant with prefix wrapping.

4. **`openidconnect` 4.x integration depth.** Given that `openidconnect` 4.x doesn't support EdDSA/ES256 *signing* in its Core types, we use it only for protocol types and do JWT signing with `jsonwebtoken`. Should we define custom OIDC types instead of using `openidconnect` at all? Recommendation: keep `openidconnect` for metadata/claims/registration types — they're well-tested and spec-compliant. Only bypass it for the JWT signing step.

5. **CAIP-122 message format for non-pkh DIDs.** The CAIP-122 spec defines the message format for `did:pkh` identifiers. For `did:key` and `did:peer`, the `{address}` line will contain the multibase-encoded public key rather than a blockchain address, and `{display_label}` will reflect the key type (e.g., "Ed25519 Key"). This is a compatible extension but not yet part of any CAIP spec. Recommendation: proceed with the compatible extension for v2.0 and document the deviation; engage CAIP if the extension gains traction.

---

## 17. Codebase Reality Check — Evaluation Against Current Repository

> **Date:** 2026-03-19 (Second iteration — includes aqua-rs-auth cipher audit and siwe-oidc interface analysis)
> **Method:** Automated audit of every source file, Cargo.toml, and build artifact in the repository and its companions.

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

**The ES256 signing implementation is complete and correct.** The `EcdsaSigningKey` struct at `axum_lib.rs:71-130` implements `openidconnect::PrivateSigningKey` using `p256::ecdsa::SigningKey`. This is the correct pattern for JWT signing and requires no changes for v2.0.

**The `aqua-rs-auth` companion library provides production-quality implementations of all three v2.0 cipher suites.** The verify functions are tested, in production use, and map directly to the three `CipherSuite` impls needed:
- `aqua-rs-auth/src/verify_eip191.rs` → `siwx-core/src/ciphers/eip191.rs`
- `aqua-rs-auth/src/verify_ed25519.rs` → `siwx-core/src/ciphers/ed25519.rs`
- `aqua-rs-auth/src/verify_p256.rs` → `siwx-core/src/ciphers/p256.rs`

The Phase 1 cipher work is a port, not an invention. This eliminates the highest-risk item from the previous assessment.

**The siwe-oidc interface is fully characterized.** Env var prefix (`SIWEOIDC_`), endpoint structure, token format, cookie schema, and sub claim format are all known precisely. The migration path can be written concretely.

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

**10. `aqua-rs-auth` contains verified implementations of all three v2.0 cipher suites — risk is lower than assumed.**

The companion library [`aqua-rs-auth`](https://github.com/inblockio/aqua-rs-auth) implements eip191, ed25519, and p256 verification against the same message format (`CAIP-122 / verify_caip122()`). These functions are in production use:
- `verify_eip191::verify()` — EIP-191 prefix + Keccak256 + secp256k1 ecrecover (using `k256` + `sha3`)
- `verify_ed25519::verify()` — ed25519-dalek 2.x signature verification
- `verify_p256::verify()` — P-256 ECDSA, accepts both DER and fixed-size (r‖s) signatures

**Correction:** Downgrade the eip191 cipher module risk from **High** to **Low**. The implementation exists and is tested. The `siwe` crate replacement is straightforward: port the verify function and validate bit-identical output against the siwe crate in a test. Phase 1 carries no novel cryptographic implementation.

**11. The `SiwxCookie` format change is the primary client interface boundary — requires coordinated frontend update.**

The current sign-in uses a `siwe` cookie with Ethereum-specific fields (`address: Address`, `chainId: u64`). The new `siwx` cookie has a `did: String` field and a variable-length hex `signature`. This change must be deployed atomically with the Svelte frontend update — the server cannot accept both formats simultaneously without a versioned endpoint or a transition period.

**Correction:** The frontend (`js/ui/`) must be updated as part of Phase 1, not as a separate concern. Add it explicitly to the Phase 1 checklist. The change is small (swap `address`/`chainId` fields for `did`) but is a hard coordination point.

**12. The sub claim format change is a real breaking change for siwe-oidc → siwx-oidc migration — not acknowledged in the original plan.**

The original plan states "sub claim stays the same." This is wrong on two counts:
1. The current siwx-oidc code (same as siwe-oidc) generates `eip155:{chain_id}:{address}`, not `did:pkh:eip155:{chain_id}:{address}`
2. The v2.0 design calls for `did:pkh:eip155:{chain_id}:{address}`

The change is intentional and correct (the sub should be a proper DID URI), but it will break Matrix/Synapse MAS claim-mapping templates and any RP that stores or equality-checks sub values. **The MAS config must be updated when siwx-oidc v2.0 is deployed.**

**Correction:** Section 14 must explicitly document this as a breaking change, with the MAS template update required.

### 17.3 Feasibility Assessment

| Plan Element | Feasibility | Risk | Notes |
|---|---|---|---|
| Workspace split into 3 crates | High | Low | Clean boundaries already exist |
| `DIDMethod` trait + registry | High | Low | Manual static function; primary extensibility axis; no `inventory` |
| `CipherSuite` trait (internal to did:pkh) | High | Low | Same manual registry pattern; scoped inside `PkhMethod` |
| eip191 cipher module | High | Low | **Revised** — implementation exists in `aqua-rs-auth/src/verify_eip191.rs`; port, not reimplementation |
| ed25519 cipher module | High | Low | Implementation exists in `aqua-rs-auth/src/verify_ed25519.rs`; port |
| p256 cipher module | High | Low | Implementation exists in `aqua-rs-auth/src/verify_p256.rs`; port |
| `did:key` DID method | High | Low | Multicodec prefix decode + delegate to existing Ed25519/P-256 suites |
| `did:peer` DID method (v0, v2) | High | Low | Phase 2+ optional; variant 0 identical to `did:key` |
| EdDSA JWT signing | Medium | Low | ES256 already works; EdDSA is optional — no concrete RP need identified |
| `SiwxMessage` + `SiwxCookie` | Medium | Medium | Message format has strict whitespace/ordering rules; validate against `siwe` crate in test |
| JS frontend cookie update | High | Low | Small change (add `did`, remove `address`/`chainId`); must deploy with server atomically |
| Headless client crate | High | Low | Greenfield; model after `aqua-rs-auth/src/client.rs` adapted for OIDC flow |
| Worker target | — | — | **Dropped from v2.0 scope** — stale RSA; not needed for Matrix/Synapse use case |
| DB schema change (`Address` → `String`) | High | Low | Flush-on-upgrade; 30s/5min TTLs make this safe |
| Sub claim format change | High | Low | One-line code change; requires MAS claim-mapping config update |

### 17.4 Recommended Execution Order (Second Iteration — MVP-First)

> **Driving principle:** The first deliverable is a working drop-in for siwe-oidc on Matrix/Synapse. All architectural work is in service of that goal.

---

**Pre-requisite: Drop `worker_lib.rs`.**

Remove the Cloudflare Worker target from v2.0 scope. The file is stale (RSA signing, logic diverged from the native server) and is not required for the Matrix/Synapse use case. Delete it and the `cf` DB backend. Can be restored in a later release using the same `DIDMethod` registry.

---

**Phase 1 — MVP: `did:pkh` drop-in for siwe-oidc**

*Deliverable: a `siwx-oidc` binary that replaces `siwe-oidc` on Matrix/Synapse, accepting `did:pkh:{eip155,ed25519,p256}` DIDs and signing OIDC tokens with ES256.*

**1.1 — Workspace setup.**
Convert root `Cargo.toml` to a workspace. Create `siwx-core/` and `siwx-oidc/` crates. Move current `src/` → `siwx-oidc/src/`. Confirm the build passes with no logic changes.

**1.2 — Trait definitions in `siwx-core`.**
Define `DIDMethod` (Section 4.1) and `CipherSuite` (Section 4.2) with their manual registries (`all_did_methods()`, `all_cipher_suites()`). No implementations yet — trait + registry stubs only.

**1.3 — Port cipher modules from `aqua-rs-auth`.**

| Source | Destination | Notes |
|---|---|---|
| `aqua-rs-auth/src/verify_eip191.rs` | `siwx-core/src/ciphers/eip191.rs` as `Eip191Suite` | EIP-191 + Keccak256 + ecrecover |
| `aqua-rs-auth/src/verify_ed25519.rs` | `siwx-core/src/ciphers/ed25519.rs` as `Ed25519Suite` | ed25519-dalek 2.x |
| `aqua-rs-auth/src/verify_p256.rs` | `siwx-core/src/ciphers/p256.rs` as `P256Suite` | DER + fixed-size r‖s |

Each file implements `CipherSuite`. Add to `all_cipher_suites()`. Bring `k256`, `sha3`, `ed25519-dalek`, `p256` into `siwx-core/Cargo.toml`. This is a **port of tested code** — no novel cryptographic implementation.

**1.4 — Implement `PkhMethod`.**
`siwx-core/src/did_methods/pkh.rs`. Implements `DIDMethod` by delegating to the cipher registry. Port DID parsing from `aqua-rs-auth/src/did.rs` (address extraction, EIP-55 checksum, chain_id from eip155 DID segment). Add to `all_did_methods()`.

**1.5 — Define `SiwxMessage` and `SiwxCookie`.**
`SiwxMessage` produces the canonical CAIP-122 string via `to_canonical_message()`. `SiwxCookie` is the `/sign_in` wire format (Section 5.1). **Critical test:** `SiwxMessage::to_canonical_message()` must produce bit-identical output to `siwe::Message` for the eip155 case. This test is the correctness gate for removing the `siwe` crate.

**1.6 — Refactor `siwx-oidc` sign_in endpoint.**
Replace `Web3ModalMessage` + `siwe::Message::verify()` with `SiwxCookie` + `find_did_method(did)?.verify()`. Remove `siwe` and `alloy` from `siwx-oidc/Cargo.toml`. Cookie name: `siwe` → `siwx`.

**1.7 — Update the Svelte frontend.**
Update `js/ui/` to send `"did": "did:pkh:eip155:{chainId}:{checksumAddress}"` in the new `siwx` cookie format. Must deploy atomically with the server.

**1.8 — Update `CodeEntry`.**
`address: alloy::primitives::Address` → `address: String`. `chain_id: Option<u64>` → `namespace: String`. DB abstraction layer is unchanged. Flush Redis on upgrade (30s code TTL, 5min session TTL — clean restart with drain window is safe).

**1.9 — Update config and startup validation.**
Add `supported_did_methods` and `supported_pkh_namespaces` to `Config`. Startup validates all configured values against the registry. Decide on env var prefix: keep `SIWEOIDC_` for backwards compatibility or migrate to `SIWXOIDC_`.

**1.10 — Update sub claim.**
Change `resolve_claims()` to return `DIDMethod::canonical_subject(did)` — produces `did:pkh:eip155:{chain_id}:{address}`. Update the Matrix MAS Jinja2 claim-mapping template to handle the new prefix.

**Phase 1 test gate:** All three cipher suites produce valid OIDC tokens. The eip155 flow is behaviorally identical to siwe-oidc (only the sub prefix changes). Integration tests (Keycloak + Redis) pass.

---

**Phase 2 — Prove modularity: `did:key`**

*Deliverable: `did:key` DIDs accepted with zero changes to siwx-oidc server code, DB schema, or OIDC protocol.*

**2.1** — Add `siwx-core/src/did_methods/key.rs`. `KeyMethod` implementing `DIDMethod`. Decodes multicodec prefix (`0xed01` = Ed25519, `0x1200` = P-256) and delegates to the existing cipher suites. `address_for_message()` returns the multibase key string. `has_chain_id()` returns `false`.

**2.2** — Add `&KeyMethod` to `all_did_methods()`. One line.

**2.3** — Add `"key"` to `supported_did_methods` in test/config fixture. One line.

**Proof criteria:** The git diff for Phase 2 touches **only** `siwx-core/src/did_methods/key.rs` (new) + `siwx-core/src/did_methods/mod.rs` (one line) + test fixtures. If any other production file changes, the trait design needs revision.

---

**Phase 3 (Optional) — Headless client: `siwx-oidc-auth`**

Create `siwx-oidc-auth/` crate. Implement `login(did, sign_fn, authorize_url) -> Client` — the OIDC authorization-code flow for agents and CLI tools. Model after `aqua-rs-auth/src/client.rs`'s `authenticate()` function, adapted for the three-legged OIDC flow.

---

**Phase 4+ — Architecture documented, not targeted**

`did:peer`, `did:web`, `did:webvh`, `did:keri`: described in Sections 4.1 and 4.4. Implement on demand. The browser frontend (Svelte/Web3Modal) continues to handle eip155 only; all other ciphers go through the headless client.

### 17.5 Source File Inventory: Current → Target

**Current (v1.5 — monolithic):**
```
src/
├── lib.rs              — Exports `pub mod db`
├── main.rs             — Entry point → axum_lib::main()
├── config.rs           — Config struct (Figment: TOML + env)
├── axum_lib.rs         — Axum server, routes, AppState, ES256 key init
├── oidc.rs             — All OIDC logic: EcdsaSigningKey, endpoints, SIWE verification, DID gen, tests
├── worker_lib.rs       — Cloudflare Worker (STALE → DROPPED in v2.0)
└── db/
    ├── mod.rs          — DBClient trait, CodeEntry/ClientEntry/SessionEntry
    ├── redis.rs        — Redis implementation
    └── cf.rs           — Cloudflare KV (STALE → DROPPED in v2.0)

js/ui/                  — Svelte frontend (WalletConnect/Wagmi/siwe npm → needs siwx cookie update)
test/docker-compose.yml — Integration tests (Keycloak + Redis)
```

**Target (v2.0 — workspace):**
```
Cargo.toml              — Workspace root: members = [siwx-core, siwx-oidc, siwx-oidc-auth]

siwx-core/
└── src/
    ├── lib.rs          — Re-exports traits, types, registries
    ├── message.rs      — SiwxMessage, SiwxCookie, to_canonical_message()
    ├── did_methods/
    │   ├── mod.rs      — DIDMethod trait, all_did_methods(), find_did_method()
    │   ├── pkh.rs      — PkhMethod (wraps CipherSuite registry)   ← Phase 1
    │   └── key.rs      — KeyMethod (multicodec decode)            ← Phase 2
    └── ciphers/
        ├── mod.rs      — CipherSuite trait, all_cipher_suites()
        ├── eip191.rs   — Eip191Suite (ported from aqua-rs-auth)   ← Phase 1
        ├── ed25519.rs  — Ed25519Suite (ported from aqua-rs-auth)  ← Phase 1
        └── p256.rs     — P256Suite (ported from aqua-rs-auth)     ← Phase 1

siwx-oidc/
└── src/
    ├── main.rs         — Entry point
    ├── config.rs       — Config (+ supported_did_methods, supported_pkh_namespaces)
    ├── axum_lib.rs     — Routes, AppState, ES256 key init (minimal changes)
    ├── oidc.rs         — OIDC logic using DIDMethod dispatch (no cipher knowledge)
    └── db/
        ├── mod.rs      — DBClient, CodeEntry (address: String, namespace: String)
        └── redis.rs    — Redis implementation (unchanged)

siwx-oidc-auth/         — Phase 3 (headless client)
└── src/
    └── lib.rs          — login(did, sign_fn, authorize_url) → Client

js/ui/                  — Svelte frontend (siwx cookie format, unchanged eip155 logic)
test/docker-compose.yml — Integration tests (unchanged)

github.com/inblockio/aqua-rs-auth  — Companion library (source of cipher implementations, not a workspace dep)
```
