---
name: siwx-oidc
description: Use when working on siwx-oidc OIDC provider code, debugging authentication flows, understanding CAIP-122 multi-chain identity, extending DID methods, or troubleshooting Matrix integration. Triggers on auth errors, DID method questions, token issues, WebAuthn problems.
---

# siwx-oidc Expert Reference

## Architecture (three layers)

| Layer | Location | Responsibility | Async? |
|-------|----------|---------------|--------|
| 1 | `siwx-core/src/` | Pure crypto: DID parsing, CAIP-122 verification, cipher suites | No (WASM-safe) |
| 2 | `src/{ceremony}.rs` | Auth ceremony verification: CAIP-122 (`oidc.rs`), WebAuthn (`webauthn.rs`) | Yes |
| 3 | `src/oidc.rs` | OIDC token issuance (ES256), client registration, userinfo | Yes |

## Two-trait extensibility model (Layer 1)

| Trait | Visibility | Purpose | Registry |
|-------|-----------|---------|----------|
| `DIDMethod` | Server-facing | DID parsing + CAIP-122 verify dispatch | `all_did_methods()` in `did_method.rs` |
| `CipherSuite` | Internal to `PkhMethod` | Per-namespace crypto (eip155/ed25519/p256) | `all_cipher_suites()` in `cipher_suite.rs` |

The server only imports `DIDMethod`. `CipherSuite` is hidden behind `PkhMethod::verify()` which calls `find_cipher_suite(namespace)`. Registries are manual `Vec<Box<dyn T>>` functions (no `inventory` crate, WASM-unsafe).

## Sign-in flows

**Path A: CAIP-122 (wallet signing)**
1. `GET /authorize` -> session cookie + nonce stored in Redis
2. Frontend builds CAIP-122 message with nonce, wallet signs it, sets `siwx` cookie `{ did, message, signature }`
3. `GET /sign_in` -> `find_did_method(did).verify()` on cookie contents, checks nonce + resources -> auth code
4. `POST /token` -> ID token (ES256 JWT) + access token

**Path B: WebAuthn (passkey)**
1. `GET /authorize` -> session cookie + nonce
2. `POST /webauthn/authenticate/start` -> browser passkey prompt -> `POST /webauthn/authenticate/finish`
3. Verified DID stored in `session.verified_did` (Redis, server-side, trusted)
4. `GET /sign_in` -> reads `verified_did` (no cookie verification needed) -> auth code
5. `POST /token` -> ID token + access token

## MSC3861 Matrix integration

Activated when `mas_shared_secret` is set in config. Changes token issuance from JWTs to opaque tokens.

| Component | Details |
|-----------|---------|
| Access tokens | `mat_` prefix, 300s TTL, 36 chars (4 prefix + 32 base62) |
| Refresh tokens | `mcr_` prefix, 86400s TTL, same format |
| Introspection | `POST /oauth2/introspect` (RFC 7662), Bearer or client_secret_post auth |
| User provisioning | `SynapseClient` calls `/_synapse/mas/provision_user` on first login |
| Device lifecycle | `SIWX_` prefix + UUID fragment; recycled on re-login (delete old, recreate) |
| Cross-signing | `allow_cross_signing_reset` called on first login for new device |
| Compat layer | `/_matrix/client/v3/{login,logout,refresh}` + `POST /oauth2/revoke` |
| Username derivation | `did:pkh`: colons to dashes, lowercased (`did-pkh-eip155-1-0xabc`); `did:key`/`did:peer:0`: base58 body hex-encoded (`did-key-{hex}`, `did-peer-0-{hex}`). Reversed by `localpart_to_did()`. |

## DID method support

| Method | Key types | `sub` claim format | Default |
|--------|-----------|-------------------|---------|
| `did:pkh` | eip155, ed25519, p256 | `did:pkh:eip155:1:0x...` | Yes |
| `did:key` | Ed25519 (`z6Mk`), P-256 (`zDn`) | `did:key:z...` | No (opt-in) |
| `did:peer` | variant 0, variant 2 (V-key) | `did:peer:0z...` | No (opt-in) |

`did:key` uses multibase (base58btc `z` prefix) + multicodec (Ed25519: `0xED01`, P-256: `0x8024`).

## aqua-rs-auth relationship

siwx-core cipher suites (`eip155.rs`, `ed25519.rs`, `p256.rs`) were **ported from** `../aqua-rs-auth/src/verify_*.rs`. The files say "Ported from aqua-rs-auth" in their doc comments. This is a deliberate copy, not a Cargo dependency, because siwx-core must remain `no_std`-compatible, WASM-safe, and have zero non-crypto dependencies. aqua-rs-auth carries async runtime and Aqua-specific types.

## CAIP-122 philosophy

CAIP-122 generalizes SIWE (EIP-4361) to any blockchain. The `sub` claim changed from `eip155:1:0xAddr` (SIWE era) to `did:pkh:eip155:1:0xAddr` because:
- DIDs are the universal identifier namespace (W3C standard)
- `did:pkh` encodes chain + address in a single URI (CAIP-10 wrapped in DID)
- Non-blockchain keys (ed25519, p256) have no chain ID; `did:pkh` handles both uniformly
- `did:key` enables passkey-derived identities without any blockchain dependency

## Key files

| File | Purpose |
|------|---------|
| `siwx-core/src/did_method.rs` | `DIDMethod` trait + `find_did_method()` registry |
| `siwx-core/src/cipher_suite.rs` | `CipherSuite` trait + `find_cipher_suite()` registry |
| `siwx-core/src/pkh/method.rs` | `PkhMethod`: dispatches to cipher suites via namespace |
| `siwx-core/src/key/mod.rs` | `KeyMethod`: multibase/multicodec decode + verify |
| `src/oidc.rs` | OIDC endpoints: authorize, sign_in, token, userinfo |
| `src/introspect.rs` | `POST /oauth2/introspect` (RFC 7662) |
| `src/synapse_client.rs` | `SynapseClient`: provision_user, upsert_device, delete_device |
| `src/compat.rs` | Matrix legacy endpoints + `POST /oauth2/revoke` |
| `src/webauthn.rs` | WebAuthn ceremony: register, authenticate, account linking |
| `src/config.rs` | `Config` struct (env prefix: `SIWEOIDC_`) |
| `src/db/mod.rs` | `DBClient` trait, `CodeEntry`, `SessionEntry`, `TokenMetadata` |

## Common mistakes

1. **Extending `DIDMethod` for WebAuthn** -- Wrong. WebAuthn is a server-layer ceremony, not a DID method. Ceremony verification needs session state (challenge binding, RP ID, origin). Use `src/webauthn.rs` and store `verified_did` in session.
2. **Importing `CipherSuite` in server code** -- Wrong. Only `DIDMethod` is server-visible. `CipherSuite` is internal to `PkhMethod`.
3. **Adding `inventory` crate for auto-registration** -- Breaks WASM. Keep manual `Vec<Box<dyn T>>` registries.
4. **Adding aqua-rs-auth as a Cargo dependency** -- Breaks WASM-safety and adds async runtime. Port the verification function instead.
5. **Forgetting to add `"key"` to `supported_did_methods`** -- Passkeys derive `did:key:zDn...`. Without `"key"` in config, passkey login returns "DID method 'key' is not enabled."
6. **Reversing username to DID with simple dash-to-colon** -- Only valid for `did:pkh`. For `did:key` and `did:peer` localparts (hex-encoded), use `localpart_to_did()` which decodes hex back to base58. Never use `.replace('-', ":")` directly; always call `localpart_to_did()`.
7. **Assuming JWT tokens in MSC3861 mode** -- When `mas_shared_secret` is set, access tokens are opaque (`mat_`), not JWTs. Synapse validates them via introspection, not JWT verification.
8. **Skipping device deletion before recreate** -- Device recycling (`delete_device` then `upsert_device`) is required to flush stale one-time keys from Synapse. Skipping it causes E2EE key mismatches.
