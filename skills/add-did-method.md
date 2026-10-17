Add a new DID method to aqua-auth.

DID methods live in aqua-auth (https://github.com/inblockio/aqua-auth, crate
`aqua-auth`), which siwx-oidc pins by git tag. Paths below are relative to an
aqua-auth checkout. Each DID method is one file + one line in the registry.
Follow these steps exactly:

## 1. Create the implementation file

Create `src/{method}/mod.rs` where `{method}` is the DID method name
(e.g., `web`, `key`, `peer`).

The file must:
- Define a public struct (e.g., `WebMethod`)
- Implement `aqua_auth::DIDMethod` (`src/did_method.rs`) for it
- Include `#[cfg(test)] mod tests` with at minimum: roundtrip verify, wrong-key reject, tampered-message reject

Required trait methods:
```rust
fn method_name(&self) -> &str;           // e.g. "web"
fn supports_did(&self, did: &str) -> bool; // default: did.starts_with("did:{method}:")
fn method_label(&self, did: &str) -> Result<&'static str, CryptoError>;
fn display_label(&self, did: &str) -> Result<String, CryptoError>;
fn address_for_message(&self, did: &str) -> Result<String, CryptoError>;
fn has_chain_id(&self, did: &str) -> bool;
fn chain_id(&self, did: &str) -> Result<Option<String>, CryptoError>;
fn canonical_subject(&self, did: &str) -> Result<String, CryptoError>;
fn verify(&self, did: &str, canonical_msg: &str, signature: &[u8]) -> Result<bool, CryptoError>;
```

Reference implementations:
- Simple (no cipher suites): `src/key/mod.rs` (KeyMethod)
- With cipher suite dispatch: `src/pkh/method.rs` (PkhMethod)
- Shared key decoding: `src/peer/mod.rs` (PeerMethod reuses key module)

## 2. Register in lib.rs

Add `pub mod {method};` (and a `pub use` of the struct) to `src/lib.rs`.

## 3. Register in the DID method registry

In `src/did_method.rs`, add to `all_did_methods()`:
```rust
use crate::{method}::{MethodStruct};
// add to the vec:
vec![..., Box::new({MethodStruct})]
```

## 4. Update the registry test

In `src/did_method.rs`, update `all_did_methods_has_pkh_key_peer` test
to also assert the new method name is present, and add a `find_*_returns_some` test.

## 5. Run tests

```bash
cargo test   # in the aqua-auth checkout
```

All existing tests must still pass. The new method's tests must pass too.
Release aqua-auth with a new tag, then bump the `aqua-auth` tag in BOTH
`Cargo.toml` and `siwx-oidc-auth/Cargo.toml` of siwx-oidc (they must stay equal).

## 6. Config (server side, in siwx-oidc)

The new method is opt-in. Operators add it to `supported_did_methods` in config.
No server code changes needed — the allow-list check in `src/oidc.rs::sign_in`
and startup validation in `src/axum_lib.rs` handle it generically.

## 7. Update documentation

- Add the method to the DID methods table in siwx-oidc's `docs/architecture.md`
- Add it to `README.md` wherever DID methods are listed

## Notes

- `DIDMethod` is sync only — no async, no network. If the DID method needs network
  resolution (e.g., did:web, did:webvh), it needs an async resolver in the
  server crate, not in the `DIDMethod` trait.
- Verification must be pure crypto — extract key material from the DID, verify signature.
- `canonical_subject()` should return the full DID string.
