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
  config.rs                          Config struct (supported_did_methods, RP ID, signing key, etc.)
  axum_lib.rs                        Routes, startup validation, state (incl. Webauthn)
  oidc.rs                            OIDC logic: authorize, sign_in, token, userinfo, ES256 key
  webauthn.rs                        WebAuthn ceremony: register + discoverable authenticate
  db/mod.rs                          DBClient trait, CodeEntry, SessionEntry, ClientEntry
  db/redis.rs                        Redis implementation + generic helpers (set_raw, get_raw, etc.)

siwx-oidc-auth/src/                ← Headless OIDC client (library + CLI)
  lib.rs                             SiwxKey (PEM/hex/generate), authenticate(), AuthTokens
  main.rs                            CLI: --key-file, --print-did, --server

js/ui/src/App.svelte               ← Svelte frontend (Ethereum-only via Web3Modal)
```

## Architecture

**Three-layer model:**

```
Layer 1: siwx-core        — Pure crypto library (no async, no network, WASM-safe)
  ├── DIDMethod trait       — DID parsing + CAIP-122 verification dispatch
  ├── CipherSuite trait     — Internal to did:pkh, never imported by server
  └── Registries            — Manual static functions (no inventory crate)

Layer 2: src/{ceremony}.rs — Auth ceremony verification (server-side)
  ├── CAIP-122              — Wallet signing (verified in sign_in via DIDMethod::verify)
  ├── [planned] WebAuthn    — Passkey ceremony (webauthn-rs safe API → verified DID in session)
  └── [planned] RFC 8628    — Device Authorization Grant (device page → approved device code)

Layer 3: src/oidc.rs       — OIDC token issuance (single code issuance point: sign_in)
```

**Key boundary:** siwx-core handles CAIP-122 proof verification only. New authentication
ceremonies (WebAuthn, SSH, PGP) are server-layer modules that produce a verified DID.
The `DIDMethod` trait is NOT extended for non-CAIP-122 proofs. See `/add-auth-ceremony`.

**Why:** NIST SP 800-63B, W3C WebAuthn §7.2, and webauthn-rs all mandate that ceremony
verification (challenge binding, origin checking, RP ID, flags, sign count) lives in the
server layer where session state is available. Crypto alone is necessary but not sufficient.

**Two-trait extensibility model (Layer 1):**
- `DIDMethod` — primary, server-visible dispatch. The server only sees this trait.
- `CipherSuite` — secondary, internal to `did:pkh`. Never imported by the server.

**Registries** are manual static functions (`all_did_methods()` / `all_cipher_suites()`).
No `inventory` crate (WASM-unsafe).

**Adding a new DID method** = one file + one line in registry. See `/add-did-method`.
**Adding a new cipher suite** = one file + one line in registry. See `/add-cipher-suite`.
**Adding a new auth ceremony** = one server module + sign_in generalization. See `/add-auth-ceremony`.

**Sign-in flow (CAIP-122 — existing):**
1. `GET /authorize` → session cookie + nonce
2. Frontend/client builds CAIP-122 message with nonce, signs it
3. `GET /sign_in` with `siwx` cookie → `find_did_method(did).verify()` → auth code
4. `POST /token` → ID token + access token (ES256 signed)

**Sign-in flow (server-verified ceremony — planned):**
1. `GET /authorize` → session cookie + nonce
2. Ceremony endpoint verifies proof (e.g. WebAuthn assertion) → stores verified DID in Redis session
3. Redirect to `GET /sign_in` → reads `session.verified_did` (trusted) → auth code
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
| `SIWEOIDC_RP_ID` | WebAuthn Relying Party ID (domain) | hostname of `BASE_URL` |
| `SIWEOIDC_RP_ORIGIN` | WebAuthn expected origin URL | `BASE_URL` |

**For passkey login:** add `"key"` to `SIWEOIDC_SUPPORTED_DID_METHODS` so the `did:key:zDn…`
DIDs derived from passkeys are accepted by `sign_in`.

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

Two authentication methods on the login page:

1. **Sign-In with Ethereum** — `@wagmi/core` + `injected()` for direct browser wallet
   detection (MetaMask, Brave, Coinbase extension) via EIP-1193. SIWE message built
   with `viem/siwe` (`createSiweMessage`). Cookie name `'siwx'`, payload `{ did, message, signature }`.

2. **Sign-In with Passkey** — Browser WebAuthn API (`navigator.credentials.get()`).
   Calls `/webauthn/authenticate/start` → browser passkey prompt → `/webauthn/authenticate/finish`.
   No cookie involved — verified DID stored server-side in Redis session.
   "Register a new passkey" link for first-time users.

3. **Link Passkey to Wallet** — After wallet sign-in, user is offered "Link a passkey
   for future logins?" before redirecting. Calls `/link/webauthn/start` → browser
   creates passkey → `/link/webauthn/finish`. Future passkey logins produce the wallet DID.

## Deployment (Docker)

```bash
# Build locally
docker build -t ghcr.io/inblockio/siwx-oidc:latest .

# Image is ~18MB (Alpine + static musl binary + frontend assets)
# CI publishes to GHCR on push to main (see .github/workflows/docker.yml)
```

Matrix Synapse deployment: see `../siwx-oidc-matrix-server` (branch `siwx`).
Run `/deploy-check` for the full pre-deployment checklist.

## WebAuthn/Passkey architecture

**Ceremony module:** `src/webauthn.rs` — uses `webauthn-rs` 0.6.0-dev safe API.
**DID derivation:** Passkey P-256 pubkey → compressed SEC1 → `did:key:zDn…` (same
encoding as `siwx-core/src/key/mod.rs`).

**Redis keys:**
```
webauthn:challenge/{session_id}        TTL 120s  — ceremony state (register or auth)
webauthn:credential/{cred_id_b64}      no TTL    — stored Passkey (JSON-serialized)
webauthn:link/{cred_id_b64}            no TTL    — { primary_did, label } (account linking)
webauthn:link_challenge/{session_id}   TTL 120s  — link ceremony state (reg_state + primary_did)
```

**Endpoints:**
```
POST /webauthn/register/start       — returns CreationChallengeResponse
POST /webauthn/register/finish      — verifies attestation, stores credential
POST /webauthn/authenticate/start   — returns RequestChallengeResponse (discoverable)
POST /webauthn/authenticate/finish  — verifies assertion, stores verified_did in session
POST /link/webauthn/start           — begin passkey registration (verifies siwx cookie for DID ownership)
POST /link/webauthn/finish          — verifies attestation, stores credential + link mapping
```

**Account linking (Phase 2):** Wallet users can link a passkey to their existing DID.
After linking, authenticating with that passkey produces the wallet's DID (not a new `did:key`).
The `/link/webauthn/start` endpoint verifies the `siwx` cookie's CAIP-122 signature to prove
DID ownership before creating the link. `authenticate_finish` checks `webauthn:link/{cred_id}`
and substitutes `primary_did` if a mapping exists.

## Troubleshooting

### WebAuthn passkey login fails

1. **"DID method 'key' is not enabled on this server"** → add `"key"` to
   `SIWEOIDC_SUPPORTED_DID_METHODS` (passkeys derive `did:key:zDn…`).

2. **"No registration challenge found (expired or already used)"** → challenge has
   120s TTL. User took too long or page was refreshed. Retry from the start.

3. **"WebAuthn registration/auth start failed"** → check `SIWEOIDC_BASE_URL` has a
   valid hostname (used as RP ID). If behind a reverse proxy, set `SIWEOIDC_RP_ID`
   and `SIWEOIDC_RP_ORIGIN` explicitly.

4. **Browser shows no passkeys / "NotAllowedError"** → RP ID mismatch. The browser
   will only offer passkeys registered for the exact RP ID domain. Check that the
   domain users see in the browser matches `SIWEOIDC_RP_ID`.

5. **"Credential not found" after selecting a passkey** → credential was stored on a
   different Redis instance, or Redis was flushed. Credential keys have no TTL but
   are lost on `--reset`. Check `redis-cli KEYS 'webauthn:credential/*'`.

6. **"Session not found"** → session expired (300s TTL) between authenticate_finish
   and sign_in redirect. Check for network/proxy delays.

### CAIP-122 wallet login fails

Run `/debug-oidc` for the full OIDC flow debugging checklist.

Common issues:
- **"Nonce mismatch"** → session cookie expired between authorize and sign_in.
- **"Signature verification failed"** → DID in cookie doesn't match the signing key.
- **"Missing or mismatched resource"** → redirect_uri not in CAIP-122 resources array.

### Redis inspection

```bash
# List all WebAuthn credentials
redis-cli KEYS 'webauthn:credential/*'

# Inspect a specific credential
redis-cli GET 'webauthn:credential/{cred_id_b64}'

# List active challenges
redis-cli KEYS 'webauthn:challenge/*'

# List active sessions
redis-cli KEYS 'sessions/*'

# Check if a session has a verified_did
redis-cli GET 'sessions/{session_id}' | python3 -m json.tool
```

## Claude Code skills

| Skill | Purpose |
|-------|---------|
| `/add-did-method` | Add a new DID method to siwx-core (Layer 1) |
| `/add-cipher-suite` | Add a new cipher suite to did:pkh (Layer 1) |
| `/add-auth-ceremony` | Add a new auth ceremony to the server (Layer 2) |
| `/docker-build` | Build, test, push Docker image |
| `/deploy-check` | Pre-deployment checklist for Matrix |
| `/debug-oidc` | Debug OIDC authentication flow issues |
