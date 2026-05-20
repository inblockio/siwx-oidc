Add a new cipher suite to the did:pkh DID method.

Cipher suites handle crypto verification for specific did:pkh namespaces
(e.g., eip155 for Ethereum, ed25519 for Ed25519 keys). Each suite is one file
+ one line in the registry.

## 1. Create the implementation file

Create `siwx-core/src/pkh/{namespace}.rs` where `{namespace}` matches the
did:pkh namespace (e.g., `eip155`, `ed25519`, `p256`).

The file must:
- Define a public struct (e.g., `NewSuite`)
- Implement `siwx_core::cipher_suite::CipherSuite` for it
- Include tests: roundtrip verify, wrong-key reject, tampered-message reject

Required trait methods:
```rust
fn namespace(&self) -> &str;           // e.g. "eip155"
fn has_chain_id(&self) -> bool;        // true only for eip155
fn did_segments(&self) -> usize;       // 2 for chain:addr (eip155), 1 for addr-only
fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, SiwxError>;
fn parse_did_parts(&self, did_remainder: &str) -> Result<(String, Option<String>), SiwxError>;
```

Reference implementations:
- With chain ID: `siwx-core/src/pkh/eip155.rs` (EIP-191 ecrecover)
- Without chain ID: `siwx-core/src/pkh/ed25519.rs`, `siwx-core/src/pkh/p256.rs`

DID parsing helpers in `siwx-core/src/did.rs`:
- `address_from_did(did, namespace)` — extract address/pubkey from a did:pkh DID
- `pubkey_from_ed25519_did(did)` / `pubkey_from_p256_did(did)` — type-specific

## 2. Register in pkh/mod.rs

Add `pub mod {namespace};` and `pub use {namespace}::{SuiteStruct};` to
`siwx-core/src/pkh/mod.rs`.

## 3. Register in the cipher suite registry

In `siwx-core/src/cipher_suite.rs`, add to `all_cipher_suites()`:
```rust
use crate::pkh::{SuiteStruct};
// add to the vec:
vec![..., Box::new({SuiteStruct})]
```

## 4. Run tests

```bash
cargo test -p siwx-core
```

## 5. Config (server side)

The new namespace is opt-in. Operators add it to `supported_pkh_namespaces`.
Startup validation in `src/axum_lib.rs` checks it against the registry.

## 6. Update documentation

- Add the namespace to the DID scope table in `CLAUDE.md` and `README.md`

## Notes

- `parse_did_parts()` splits the did:pkh remainder (after `did:pkh:{namespace}:`)
  into `(address, Option<chain_id>)`. For eip155: `"1:0xAbc"` → `("0xAbc", Some("eip155:1"))`.
  For chainless suites: `"0xpubkey"` → `("0xpubkey", None)`.
- `verify()` receives the full DID string, the CAIP-122 message text, and raw
  signature bytes. It must extract the public key from the DID and verify.
- Port from aqua-rs-auth when possible — do not reinvent crypto.
