Add a new DID method to siwx-core.

Each DID method is one file + one line in the registry. Follow these steps exactly:

## 1. Create the implementation file

Create `siwx-core/src/{method}/mod.rs` where `{method}` is the DID method name
(e.g., `web`, `key`, `peer`).

The file must:
- Define a public struct (e.g., `WebMethod`)
- Implement `siwx_core::did_method::DIDMethod` for it
- Include `#[cfg(test)] mod tests` with at minimum: roundtrip verify, wrong-key reject, tampered-message reject

Required trait methods:
```rust
fn method_name(&self) -> &str;           // e.g. "web"
fn supports_did(&self, did: &str) -> bool; // default: did.starts_with("did:{method}:")
fn display_label(&self, did: &str) -> Result<String, SiwxError>;
fn address_for_message(&self, did: &str) -> Result<String, SiwxError>;
fn has_chain_id(&self, did: &str) -> bool;
fn chain_id(&self, did: &str) -> Result<Option<String>, SiwxError>;
fn canonical_subject(&self, did: &str) -> Result<String, SiwxError>;
fn verify(&self, did: &str, canonical_msg: &str, signature: &[u8]) -> Result<bool, SiwxError>;
```

Reference implementations:
- Simple (no cipher suites): `siwx-core/src/key/mod.rs` (KeyMethod)
- With cipher suite dispatch: `siwx-core/src/pkh/method.rs` (PkhMethod)
- Shared key decoding: `siwx-core/src/peer/mod.rs` (PeerMethod reuses key module)

## 2. Register in lib.rs

Add `pub mod {method};` to `siwx-core/src/lib.rs`.

## 3. Register in the DID method registry

In `siwx-core/src/did_method.rs`, add to `all_did_methods()`:
```rust
use crate::{method}::{MethodStruct};
// add to the vec:
vec![..., Box::new({MethodStruct})]
```

## 4. Update the registry test

In `siwx-core/src/did_method.rs`, update `all_did_methods_has_pkh_key_peer` test
to also assert the new method name is present, and add a `find_*_returns_some` test.

## 5. Run tests

```bash
cargo test -p siwx-core
```

All existing tests must still pass. The new method's tests must pass too.

## 6. Config (server side)

The new method is opt-in. Operators add it to `supported_did_methods` in config.
No server code changes needed — the allow-list check in `src/oidc.rs::sign_in`
and startup validation in `src/axum_lib.rs` handle it generically.

## 7. Update documentation

- Add the method to the DID scope table in `CLAUDE.md`
- Add it to the table in `README.md`

## Notes

- siwx-core is sync only — no async, no network. If the DID method needs network
  resolution (e.g., did:web, did:webvh), it needs an async DIDResolver trait in the
  server crate, not in siwx-core. See PLAN_Upgrade_CAIP_Modular_DESIGN.md §4.
- Verification must be pure crypto — extract key material from the DID, verify signature.
- `canonical_subject()` should return the full DID string.
