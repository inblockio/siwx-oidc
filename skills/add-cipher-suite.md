Add a new cipher suite to the did:pkh DID method.

Cipher suites live in aqua-auth (https://github.com/inblockio/aqua-rs-auth, crate
`aqua-auth`), which siwx-oidc pins by git tag. Paths below are relative to an
aqua-auth checkout.

Cipher suites handle crypto verification for specific did:pkh namespaces
(e.g., eip155 for Ethereum, ed25519 for Ed25519 keys). Each suite is one file
+ one line in the registry.

## 1. Create the implementation file

Create `src/pkh/{namespace}.rs` where `{namespace}` matches the did:pkh
namespace (e.g., `eip155`). Suites for a key type that `did:key` also uses sit
next to it instead (`Ed25519Suite` and `P256Suite` are in `src/key/`).

The file must:
- Define a public struct (e.g., `NewSuite`)
- Implement `aqua_auth::CipherSuite` (`src/cipher_suite.rs`) for it
- Include tests: roundtrip verify, wrong-key reject, tampered-message reject

Required trait methods:
```rust
fn namespace(&self) -> &str;           // e.g. "eip155"
fn has_chain_id(&self) -> bool;        // true only for eip155
fn did_segments(&self) -> usize;       // 2 for chain:addr (eip155), 1 for addr-only
fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError>;
fn parse_did_parts(&self, did_remainder: &str) -> Result<(String, Option<String>), CryptoError>;
```

Reference implementations:
- With chain ID: `src/pkh/eip155.rs` (EIP-191 ecrecover)
- Without chain ID: `src/key/ed25519.rs`, `src/key/p256.rs`

DID parsing helpers in `src/did.rs`:
- `parse_did_namespace(did)` — the did:pkh namespace
- `address_from_did(did)` — the 20-byte Ethereum address of an eip155 DID
- `pubkey_from_ed25519_did(did)` / `pubkey_from_p256_did(did)` — type-specific

## 2. Register in pkh/mod.rs

Add `pub mod {namespace};` and `pub use {namespace}::{SuiteStruct};` to
`src/pkh/mod.rs` (or the module the file lives in).

## 3. Register in the cipher suite registry

In `src/cipher_suite.rs`, add to `all_cipher_suites()`:
```rust
use crate::pkh::{SuiteStruct};
// add to the vec:
vec![..., Box::new({SuiteStruct})]
```

## 4. Run tests

```bash
cargo test   # in the aqua-auth checkout
```

Release aqua-auth with a new tag, then bump the `aqua-auth` tag in BOTH
`Cargo.toml` and `siwx-oidc-auth/Cargo.toml` of siwx-oidc.

## 5. Config (server side, in siwx-oidc)

The new namespace is opt-in. Operators add it to `supported_pkh_namespaces`.
Startup validation in `src/axum_lib.rs` checks it against the registry.

## 6. Update documentation

- Add the namespace to the DID methods table in siwx-oidc's `docs/architecture.md`
  and to `README.md` wherever namespaces are listed

## Notes

- `parse_did_parts()` splits the did:pkh remainder (after `did:pkh:{namespace}:`)
  into `(address, Option<chain_id>)`. For eip155: `"1:0xAbc"` → `("0xAbc", Some("eip155:1"))`.
  For chainless suites: `"0xpubkey"` → `("0xpubkey", None)`.
- `verify()` receives the full DID string, the CAIP-122 message text, and raw
  signature bytes. It must extract the public key from the DID and verify.
- Use existing, audited crypto crates (as the current suites do) — do not reinvent crypto.
