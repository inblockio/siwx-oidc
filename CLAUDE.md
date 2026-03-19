# siwx-oidc — CLAUDE.md

## What this repo is

**siwx-oidc** is a CAIP-122 → OpenID Connect bridge server for general community use.

It allows any service that speaks OpenID Connect to authenticate users by
DID-based cryptographic identity — not just Ethereum addresses. Users sign a
CAIP-122 challenge with their wallet; siwx-oidc issues standard OIDC tokens
(ID token, access token) in return.

It is a modular, multi-DID replacement for
[siwe-oidc](https://github.com/inblockio/siwe-oidc) (Ethereum-only).
The primary deployment target is [Matrix Authentication Service
(MAS)](https://github.com/element-hq/matrix-authentication-service), but any
OIDC relying party can use it.

## Architecture plan

Full design document: [`PLAN_Upgrade_CAIP_Modular_DESIGN.md`](./PLAN_Upgrade_CAIP_Modular_DESIGN.md)

Key decisions:
- **Two-trait model**: `DIDMethod` (primary, server-visible dispatch) +
  `CipherSuite` (secondary, internal to `did:pkh`)
- **Manual registries**: `all_did_methods()` / `all_cipher_suites()` — no
  `inventory` crate (WASM-unsafe)
- **In-repo workspace**: `siwx-core` (lib, no async) + `siwx-oidc` (binary,
  axum server) as Cargo workspace members
- **Cipher suites copied from aqua-rs-auth** — not a crate dependency; all
  transitive deps pulled in directly

## External repos

| Repo | Purpose |
|------|---------|
| `../siwe-oidc` — [github.com/inblockio/siwe-oidc](https://github.com/inblockio/siwe-oidc) | Upstream Ethereum-only OIDC bridge; siwx-oidc is its multi-DID successor |
| `../aqua-rs-auth` — [github.com/inblockio/aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth) | Reference implementation for all three cipher suites (`verify_eip191.rs`, `verify_ed25519.rs`, `verify_p256.rs`). Port files, do not add as dependency. |

## v2.0 DID method scope

| DID Method | Cipher suites | Status |
|-----------|--------------|--------|
| `did:pkh` | eip155, ed25519, p256 | Phase 1 — port from aqua-rs-auth |
| `did:key` | Ed25519, P-256 | Phase 2 — prove modularity |
| `did:peer` | variant 0/2 | Phase 2 |
| `did:web`, `did:webvh`, `did:keri` | — | Architecture only; async resolver needed |

## Breaking changes vs siwe-oidc

1. **`sub` claim**: `eip155:1:0xAddr` → `did:pkh:eip155:1:0xAddr` — Matrix MAS
   claim-mapping template must be updated
2. **Sign-in cookie**: name `siwe` → `siwx`; payload `{ did, message, signature }`
   replaces `{ message: Web3ModalMessage, signature }` — atomic frontend + server deploy
3. **`CodeEntry.address`**: `alloy_primitives::Address` → `String` — flush Redis on upgrade
4. **Config**: adds `supported_did_methods` + `supported_pkh_namespaces`

## Frontend (js/ui/src/App.svelte)

Currently Ethereum-only (Web3Modal + Wagmi + `siwe` npm package).

Phase 1.7 changes are small:
- Cookie name `'siwe'` → `'siwx'`
- Payload: `{ did: "did:pkh:eip155:{chainId}:{address}", message: preparedMessage, signature }`
- `siwe` npm package and Web3Modal stay for Phase 1

Phase 2+ (Ed25519/P-256) needs a different wallet connector — scoped separately.

## Config env vars (native binary)

Prefix: `SIWEOIDC_` (keep for now; rename to `SIWXOIDC_` is a future breaking change)

| Var | Description |
|-----|-------------|
| `SIWEOIDC_ADDRESS` | IP to bind |
| `SIWEOIDC_REDIS_URL` | Redis URL |
| `SIWEOIDC_BASE_URL` | Advertised OIDC issuer URL |
| `SIWEOIDC_SIGNING_KEY_PEM` | PKCS#8 PEM for ES256 signing key (generated if absent) |
