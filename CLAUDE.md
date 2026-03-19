# siwx-oidc — CLAUDE.md

## What this repo is

**siwx-oidc** is a CAIP-122 to OpenID Connect bridge server for general community use.

Users sign a CAIP-122 challenge with their wallet (or a local key); siwx-oidc
issues standard OIDC tokens (ID token, access token) in return. Any OIDC relying
party can use it. The primary deployment target is
[Matrix Authentication Service (MAS)](https://github.com/element-hq/matrix-authentication-service).

Multi-DID successor to [siwe-oidc](https://github.com/inblockio/siwe-oidc) (Ethereum-only).

## File map

```
siwx-core/src/                     ← Pure crypto library (no async, no network)
  lib.rs                            Crate root — re-exports traits
  did_method.rs                     DIDMethod trait + all_did_methods() registry
  cipher_suite.rs                   CipherSuite trait + all_cipher_suites() registry
  did.rs                            DID parsing utilities (address extraction, EIP-55)
  error.rs                          SiwxError enum
  pkh/                              did:pkh — dispatches to cipher suites
    method.rs                         PkhMethod (DIDMethod impl)
    eip155.rs                         EIP-191 ecrecover (Ethereum)
    ed25519.rs                        Ed25519 raw signature verify
    p256.rs                           P-256 ECDSA verify (DER + fixed)
  key/mod.rs                        did:key — multibase/multicodec key decoding
  peer/mod.rs                       did:peer — variant 0 + variant 2 V-key

src/                                ← Axum OIDC server (binary)
  config.rs                          Config struct (supported_did_methods, signing key, etc.)
  axum_lib.rs                        Routes, startup validation, state
  oidc.rs                            OIDC logic: authorize, sign_in, token, userinfo, ES256 key
  db/mod.rs                          DBClient trait, CodeEntry, SessionEntry, ClientEntry
  db/redis.rs                        Redis implementation

siwx-oidc-auth/src/                ← Headless OIDC client (library + CLI)
  lib.rs                             SiwxKey (PEM/hex/generate), authenticate(), AuthTokens
  main.rs                            CLI: --key-file, --print-did, --server

js/ui/src/App.svelte               ← Svelte frontend (Ethereum-only via Web3Modal)
```

## Architecture

**Two-trait extensibility model:**
- `DIDMethod` — primary, server-visible dispatch. The server only sees this trait.
- `CipherSuite` — secondary, internal to `did:pkh`. Never imported by the server.

**Registries** are manual static functions (`all_did_methods()` / `all_cipher_suites()`).
No `inventory` crate (WASM-unsafe).

**Adding a new DID method** = one file + one line in registry. See `/add-did-method`.
**Adding a new cipher suite** = one file + one line in registry. See `/add-cipher-suite`.

**Sign-in flow:**
1. `GET /authorize` → session cookie + nonce
2. Frontend/client builds CAIP-122 message with nonce, signs it
3. `GET /sign_in` with `siwx` cookie → `find_did_method(did).verify()` → auth code
4. `POST /token` → ID token + access token (ES256 signed)

## DID method scope

| DID Method | Key types | Location | Default |
|-----------|-----------|----------|---------|
| `did:pkh` | eip155, ed25519, p256 | `siwx-core/src/pkh/` | Yes |
| `did:key` | Ed25519 (`z6Mk…`), P-256 (`zDn…`) | `siwx-core/src/key/` | No (opt-in) |
| `did:peer` | variant 0, variant 2 | `siwx-core/src/peer/` | No (opt-in) |
| `did:web` | — | Not implemented | Needs async resolver |

## Building and testing

```bash
# Build the full workspace
cargo build --workspace

# Run siwx-core unit tests (57 tests, no Redis needed)
cargo test -p siwx-core

# Run server tests (needs Redis on localhost:6379)
cargo test --bin siwx-oidc

# Run the server (needs Redis)
cargo run

# Run the headless client
cargo run -p siwx-oidc-auth -- --help
```

The siwx-core tests are self-contained (pure crypto). The server e2e test
(`oidc::tests::e2e_flow`) requires a running Redis instance.

## Headless client (siwx-oidc-auth)

Authenticates to a remote siwx-oidc server with a local `did:key` private key.
Server must have `"key"` in `supported_did_methods`.

```bash
# Generate a persistent Ed25519 identity
openssl genpkey -algorithm Ed25519 -out identity.pem

# Print the DID for registration
siwx-oidc-auth --print-did --key-file identity.pem

# Authenticate and get OIDC tokens
siwx-oidc-auth --server https://siwx.example.com \
  --client-id my-service --redirect-uri https://app/callback \
  --key-file identity.pem
```

Key input priority: `--key-file` > `SIWX_KEY_FILE` env > `--key-hex` > generate ephemeral.
PEM format is canonical (PKCS#8, auto-detects Ed25519 vs P-256).

## Config env vars

Prefix: `SIWEOIDC_` (via Figment: `siwe-oidc.toml` or env vars)

| Var | Description | Default |
|-----|-------------|---------|
| `SIWEOIDC_ADDRESS` | IP to bind | `127.0.0.1` |
| `SIWEOIDC_PORT` | Port | `8000` |
| `SIWEOIDC_BASE_URL` | Advertised OIDC issuer URL | `http://127.0.0.1:8000` |
| `SIWEOIDC_REDIS_URL` | Redis URL | `redis://localhost` |
| `SIWEOIDC_SIGNING_KEY_PEM` | PKCS#8 PEM for ES256 signing key | generated |
| `SIWEOIDC_SUPPORTED_DID_METHODS` | DID methods accepted at sign-in | `["pkh"]` |
| `SIWEOIDC_SUPPORTED_PKH_NAMESPACES` | did:pkh namespaces accepted | `["eip155","ed25519","p256"]` |

## Breaking changes vs siwe-oidc

1. `sub` claim: `eip155:1:0xAddr` → `did:pkh:eip155:1:0xAddr`
2. Cookie: `siwe` → `siwx`; payload `{ did, message, signature }`
3. `CodeEntry.address` → `CodeEntry.did` (String) — flush Redis on upgrade
4. Config: adds `supported_did_methods` + `supported_pkh_namespaces`

## External repos

| Repo | Purpose |
|------|---------|
| `../siwe-oidc` | Upstream Ethereum-only predecessor (abandoned) |
| `../aqua-rs-auth` | Reference cipher suites — port files, do not add as dependency |

## Frontend (js/ui/src/App.svelte)

Ethereum-only (Web3Modal + Wagmi + `siwe` npm). Cookie name `'siwx'`, payload
`{ did, message, signature }`. Ed25519/P-256 wallet connectors scoped for later.
