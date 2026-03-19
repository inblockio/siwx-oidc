# Copilot Instructions — siwx-oidc

## What this is

siwx-oidc is a CAIP-122 to OpenID Connect bridge. Users sign a challenge with
a DID-based key; the server issues standard OIDC tokens. Rust workspace with
three crates.

## Workspace layout

- **siwx-core** — Pure crypto library. Traits: `DIDMethod`, `CipherSuite`. No async.
- **siwx-oidc** (root) — Axum OIDC server with Redis backend.
- **siwx-oidc-auth** — Headless OIDC client library + CLI.

## Key traits

`DIDMethod` (in `siwx-core/src/did_method.rs`): server dispatches on this.
Methods: `method_name()`, `verify(did, msg, sig)`, `canonical_subject(did)`.
Implementations: `PkhMethod`, `KeyMethod`, `PeerMethod`.

`CipherSuite` (in `siwx-core/src/cipher_suite.rs`): internal to did:pkh only.
Methods: `namespace()`, `verify(did, msg, sig)`, `parse_did_parts(remainder)`.
Implementations: `Eip155Suite`, `Ed25519Suite`, `P256Suite`.

## Extension pattern

Adding a DID method: create `siwx-core/src/{method}/mod.rs`, implement
`DIDMethod`, register in `all_did_methods()` in `did_method.rs`. One file, one line.

Adding a cipher suite: create `siwx-core/src/pkh/{namespace}.rs`, implement
`CipherSuite`, register in `all_cipher_suites()`. One file, one line.

## Sign-in flow

1. `GET /authorize` → session cookie + nonce redirect
2. Client signs CAIP-122 message containing nonce
3. `GET /sign_in` with `siwx` cookie → `find_did_method(did).verify()` → code
4. `POST /token` with code → OIDC tokens (ES256)

## Important files

- `src/oidc.rs` — Core OIDC logic (sign_in, token, userinfo, ES256 signing)
- `src/config.rs` — Server config (supported_did_methods, supported_pkh_namespaces)
- `src/axum_lib.rs` — Routes and startup validation
- `siwx-core/src/did_method.rs` — DIDMethod trait and registry
- `siwx-oidc-auth/src/lib.rs` — Headless client (SiwxKey, authenticate())

## Style notes

- siwx-core has no async — all verification is pure crypto
- Errors use `SiwxError` enum in siwx-core, `CustomError` in the server
- Config uses Figment (TOML + env vars with `SIWEOIDC_` prefix)
- `sub` claim is the full DID string (e.g., `did:pkh:eip155:1:0x...`)
- Cookie name is `siwx`, payload is `{ did, message, signature }`
