# siwx-oidc — CLAUDE.md

## What this repo is

**siwx-oidc** is a CAIP-122 to OpenID Connect bridge server for general community use.

Users sign a CAIP-122 challenge with their wallet (or a local key); siwx-oidc
issues standard OIDC tokens (ID token, access token) in return. Any OIDC relying
party can use it. The primary deployment target is Matrix Synapse, where siwx-oidc
**replaces MAS entirely** via MSC3861 (delegated auth with shared secret, token
introspection, user/device provisioning).

Multi-DID successor to [siwe-oidc](https://github.com/inblockio/siwe-oidc) (Ethereum-only).

## File map

```
src/                                ← Axum OIDC server (binary)
  config.rs                          Config struct (supported_did_methods, RP ID, signing key, etc.)
  axum_lib.rs                        Routes, startup validation, state (incl. Webauthn)
  oidc.rs                            OIDC logic: authorize, sign_in, token, userinfo, ES256 key
  device_auth.rs                     RFC 8628 Device Authorization Grant (device_code, approval page)
  account.rs                         MSC4191/MSC4312: account mgmt page + actions (profile, devices_list,
                                     device_view, device_delete, cross_signing_reset + session_* aliases).
                                     SUPPORTED_ACTIONS is the single source of truth (drives discovery +
                                     dispatch); canonical_action() normalizes session_*→device_*.
  synapse_client.rs                  Synapse MAS + admin-API client: provision/upsert/cross_signing_reset,
                                     and list_devices/get_device/delete_device (admin_token = MAS secret).
  webauthn.rs                        WebAuthn ceremony: register + discoverable authenticate
  db/mod.rs                          DBClient trait, CodeEntry, SessionEntry, ClientEntry, DeviceCodeEntry
  db/redis.rs                        Redis impl + helpers; revoke_device_tokens(did, device_id) revokes
                                     an OAuth session (MSC4191 device_delete -> introspection inactive)

siwx-oidc-auth/src/                ← Headless OIDC client (library + CLI)
  lib.rs                             SiwxKey (PEM/hex/generate), authenticate(), refresh(), AuthTokens
  main.rs                            CLI: --key-file, --print-did, --server, --refresh-token

js/ui/src/App.svelte               ← Svelte frontend (Ethereum-only via Web3Modal)
```

## Architecture

**Three-layer model:**

```
Layer 1: aqua-auth         — Crypto library (external crate, pure core + optional HTTP layer)
  ├── DIDMethod trait       — DID parsing + CAIP-122 verification dispatch
  ├── CipherSuite trait     — Internal to did:pkh, never imported by server
  └── Registries            — Manual static functions (no inventory crate)

Layer 2: src/{ceremony}.rs — Auth ceremony verification (server-side)
  ├── CAIP-122              — Wallet signing (verified in sign_in via DIDMethod::verify)
  ├── WebAuthn              — Passkey ceremony (webauthn-rs safe API, verified DID in session)
  └── RFC 8628              — Device Authorization Grant (device_auth.rs, approval page + polling)

Layer 3: src/oidc.rs       — OIDC token issuance (sign_in + device_code grant)
```

**Key boundary:** aqua-auth handles CAIP-122 proof verification only. New authentication
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

**Sign-in flow (server-verified ceremony, e.g. WebAuthn passkey):**
1. `GET /authorize` → session cookie + nonce
2. Ceremony endpoint verifies proof (WebAuthn assertion) → stores verified DID in Redis session
3. Redirect to `GET /sign_in` → reads `session.verified_did` (trusted) → auth code
4. `POST /token` → ID token + access token (ES256 signed)

**Device code flow (RFC 8628, for Element X QR code login):**
1. `POST /device_authorization` → device_code + user_code + verification_uri
2. Device polls `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
3. User opens `/device?user_code=XXX-XXX`, authenticates with wallet/passkey
4. Approval updates device code status → next poll returns tokens + provisions Synapse device

## Token model

Both standalone and MSC3861 modes use the same token storage model (`TokenMetadata`
in Redis via `set_token`/`get_token`). The only differences are token prefixes and
scope format.

| Aspect | MSC3861 mode | Standalone mode |
|--------|-------------|-----------------|
| Access token prefix | `mat_` | (none) |
| Refresh token prefix | `mcr_` | (none) |
| Scope format | `openid urn:matrix:client:api:* urn:matrix:client:device:{id}` | `openid profile` |
| Access token TTL | 300s | 300s |
| Refresh token TTL | 7776000s (90d) | 7776000s (90d) |
| Introspection | Active (`/oauth2/introspect`) | Not available |
| Device ID | Synapse-managed `SIWX_{uuid}` | Empty string (no Synapse) |

**Token lifecycle:**
1. `POST /token` (grant_type=authorization_code) creates both access and refresh
   `TokenMetadata` entries in Redis. The authorization code (`CodeEntry`) is consumed.
2. `POST /token` (grant_type=refresh_token) rotates both tokens: new access + new
   refresh, old refresh deleted. `device_id` is preserved across rotations.
3. `POST /token` (grant_type=device_code) provisions Synapse device, issues tokens,
   cleans up device code and user code entries.
4. `userinfo` resolves tokens via `get_token` first (covers both modes), then falls
   back to `get_code` for backward compatibility with pre-refresh-token deployments.

**Client library (`siwx-oidc-auth`):**
- `authenticate()` returns `AuthTokens` with `refresh_token: Option<String>` populated
- `refresh()` exchanges a refresh token for new tokens via `POST /token`
- `authenticate_device_flow()` polls device code grant until approved
- CLI: `--refresh-token <value>` calls `refresh()` instead of `authenticate()`
- CLI: `--device-flow` uses RFC 8628 (no local key needed)

**Deploy note:** Redis flush recommended when upgrading from pre-refresh-token
deployments (standalone mode token storage changed from `CodeEntry` to `TokenMetadata`).
Existing sessions via the legacy `get_code` path still work as a fallback.

## DID method scope

| DID Method | Key types | Location | Default |
|-----------|-----------|----------|---------|
| `did:pkh` | eip155, ed25519, p256 | `aqua-auth` (pkh module) | Yes |
| `did:key` | Ed25519 (`z6Mk…`), P-256 (`zDn…`) | `aqua-auth` (key module) | No (opt-in) |
| `did:peer` | variant 0, variant 2 | `aqua-auth` (peer module) | No (opt-in) |
| `did:web` | — | Not implemented | Needs async resolver |

## Building and testing

```bash
# Build the full workspace
cargo build --workspace

# Run aqua-auth crypto tests (83 tests incl. webauthn, no Redis needed)
cd ../aqua-auth && cargo test --features webauthn && cd -

# Run server tests (needs Redis on localhost:6379)
cargo test --bin siwx-oidc

# Run the server (needs Redis)
cargo run

# Run the headless client
cargo run -p siwx-oidc-auth -- --help
```

The aqua-auth tests are self-contained (pure crypto). The server e2e test
(`oidc::tests::e2e_flow`) requires a running Redis instance.

## E2E & Security Test Harness (audit 2026-06-14)

This is the complete, self-contained recipe to re-run **everything** from the
2026-06-14 resilience/security audit. Each item lists the EXACT command. Unless
noted, run from the repo root (`~/siwx-oidc`) with the mock stack up.

### Audit documents (read these first)

- **Requirement map + hazard register:** `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`
  — every wallet/WebAuthn/device flow as falsifiable if-then hypotheses (R-A1…R-K2)
  plus the race/cleanup hazard register **H1…H14** that drove the suites.
- **Morning summary:** `docs/audits/2026-06-14-OVERNIGHT-SUMMARY.md` — what landed,
  commit index, owner-decision queue, how-to-run.
- **Security review** (on the security branch, `~/siwx-oidc-sec`):
  `docs/audits/2026-06-14-siwx-oidc-security-review.md` (consolidated, C1/C2 + H-a…H-i)
  and the breaking-fix spec `docs/audits/2026-06-14-remediation-spec-criticals.md`.

### Mock stack (Redis + Synapse mock + siwx-oidc, all podman)

```bash
bash e2e/up.sh      # builds the debug binary, starts 3 containers, waits for /health
bash e2e/down.sh    # tear down
```

Containers (host sandbox reaps host-bound listeners, so every listener is
containerised; `ubuntu:rolling` matches host glibc 2.43 so the native debug binary
runs as-is):

| Container | Port (127.0.0.1) | Role |
|---|---|---|
| `siwx-e2e-redis` | 6379 | session/token/credential store |
| `siwx-e2e-mock`  | 8090 | Synapse admin/MAS mock (Bearer `testsecret`) |
| `siwx-e2e-oidc`  | 8080 | siwx-oidc provider (audited local debug binary) |

**Synapse mock (`e2e/synapse_mock.py`)** — faithful in-memory mock of the Synapse
admin/MAS endpoints siwx-oidc calls, with test hooks used by the race suite:

| Hook | Purpose |
|---|---|
| `POST /__reset` | clear all state (devices, call log, armed faults, secret) |
| `POST /__seed_device {mxid, device_id}` | pre-create a device for a user |
| `GET /__state` | dump devices + per-call ordering log; now also exposes `effective_deletes` accounting + currently-armed faults |
| `POST /__fail {endpoint, mode}` | fault injection — `mode` = `500` \| `timeout` \| `off` for e.g. `delete_device` (drives H14 / Synapse-unreachable tests) |
| `POST /__set_secret` | rotate the admin/MAS shared secret at runtime |

### One-shot pipeline

```bash
bash e2e/run-all.sh
```
Stages: (1) bring up stack → (2) `cargo test --bin siwx-oidc` (unit) →
(3) HTTP-level account E2E (`e2e_account_management`) → (4) legacy CS-API
device-delete probe (`e2e/legacy-cs-api-probe.sh`) → (5) headless browser E2E
(`e2e/browser/run.sh`).

### Rust suites (run with the mock stack up)

```bash
# Unit tests (needs Redis on :6379)
cargo test --bin siwx-oidc

# HTTP-level account-management E2E (real EIP-191 wallet sigs + account session)
cargo test --test e2e_account_management -- --ignored --test-threads=1

# Race / teardown deterministic interleavings (mock + Redis, forced ordering)
cargo test --test e2e_race_teardown -- --ignored --test-threads=1
```

`e2e_race_teardown` contains the **H1/H2/H4/H8/H10/H12/H14 guards** (revoke≠delete,
no device-id recycling, concurrent-delete crosstalk, single auth-code winner,
post-terminal-action session death, targeted delete, Synapse-failure-not-500) AND
the **un-gated H3/H6/H9 race-regression guards** — these were the original bug
reproducers (device_delete TOCTOU + KEYS-scan revoke racing refresh; deactivate's
non-atomic sweep letting refresh resurrect access; device-code Approved branch
double-redemption). After the fixes landed they run **unconditionally** as permanent
regression guards.

```bash
# C1/C2 OAuth/auth-binding negative tests (the safe-subset fixes, commit 6e16b47)
cargo test --test e2e_oauth_binding -- --ignored --test-threads=1
```
`e2e_oauth_binding` (security branch) is the C1/C2 negative suite: expired login
CAIP-122 signature rejected, mismatched `client_id` at `/token` rejected, unregistered
`redirect_uri` at `/sign_in` rejected (no code leaked), and `plain`-PKCE rejected
(at `/authorize` and `/token`).

### Browser suite (Playwright in a container)

```bash
bash e2e/browser/run.sh      # runs in mcr.microsoft.com/playwright on host network
```
Drives the real DOM with a mock `window.ethereum` (real `ethers` EIP-191 signing) +
CDP **WebAuthn virtual authenticator**. Helpers: `e2e/browser/wallet-helper.mjs`,
`e2e/browser/webauthn-helper.mjs`. Specs:

- `account.spec.mjs` — one re-auth covers a whole account session; device sign-out
  deletes the Synapse device + revokes tokens; erase runs `deactivate(erase=true)`;
  legacy in-client delete endpoints; legible admin-token rejection.
- `device-lifecycle.spec.mjs` — passkey register→login→token; one-re-auth-covers-many;
  base64 `device_view`; **H13** erase purges WebAuthn creds from Redis; **H11**
  challenge session-binding; CSRF (R-G8); cross-signing-reset (R-G4).

### Live suites vs a REAL homeserver

Run against a real Synapse (see the REAL stack recipe below):

```bash
SIWEOIDC_HOST=http://localhost:8081 MATRIX_HOST=http://localhost:8448 \
  cargo test --test e2e_msc3861 -- --ignored --test-threads=1
SIWEOIDC_HOST=http://localhost:8081 MATRIX_HOST=http://localhost:8448 \
  cargo test --test e2e_session_teardown -- --ignored --test-threads=1
SIWEOIDC_HOST=http://localhost:8081 MATRIX_HOST=http://localhost:8448 \
  cargo test --test e2e_msc4191_live -- --ignored --test-threads=1
SIWEOIDC_HOST=http://localhost:8081 MATRIX_HOST=http://localhost:8448 \
  cargo test --test e2e_messaging -- --ignored --test-threads=1
```

**Known follow-up:** `e2e_session_teardown` asserts `whoami == 401` *immediately*
after revocation and can fail on Synapse's ~120s introspection cache (siwx-oidc
revokes instantly per logs; a sibling polling test flips 200→401 at exactly t+120s).
It should **poll** past the cache rather than assert immediately.

### REAL stack recipe (Synapse + Redis + siwx-oidc via MSC3861)

Full reproducible detail (containers, secrets, the issuer split-horizon trick,
smoke-test output): `/tmp/track2-real-stack.md`. Summary:

1. `git clone https://github.com/inblockio/siwx-oidc-matrix-server`
   (into `~/siwx-oidc-matrix-server`, OUTSIDE this repo).
2. No `docker compose` on this box — the `docker-compose.local.yml` stack is
   translated into individual `podman run` commands on a dedicated bridge network
   `siwx-real-net` (for inter-container DNS).
3. **Issuer split-horizon trick:** the live tests reach the OIDC issuer at
   `http://localhost:8081`, but Synapse-in-container cannot reach `localhost`. Use
   Synapse `experimental_features.msc3861.issuer_metadata` to advertise the **public**
   issuer (`http://localhost:8081`) to clients while pointing
   `introspection_endpoint` at the **internal** docker address
   (`http://siwx-real-oidc:8081/oauth2/introspect`). siwx-oidc reaches Synapse for
   provisioning via `SIWEOIDC_SYNAPSE_ENDPOINT=http://siwx-real-synapse:8008`.
4. Containers: `siwx-real-redis` (net-internal), `siwx-real-oidc` (`127.0.0.1:8081`,
   runs the audited local debug binary mounted read-only — `podman restart` after a
   rebuild), `siwx-real-synapse` (`127.0.0.1:8448`).
5. **Teardown:**
   `podman rm -f siwx-real-redis siwx-real-oidc siwx-real-synapse && podman network rm siwx-real-net`
   (add `podman volume rm siwx-real-matrix-data && podman rmi localhost/siwx-real-synapse:local` for a full clean).

Never touch `aqua-agent-*` (production) or `siwx-e2e-*` (mock stack) containers.

### REAL E2EE messaging regression + edge route

The plaintext two-client messaging regression (`e2e_messaging::two_client_messaging`)
proves provisioning + delivery. A true **E2EE** two-client test needs a Matrix crypto
client, so it runs via the **aqua-matrix-connector** (`~/aqua-matrix-agent`, matrix-sdk
e2e) logging in through siwx-oidc. Full writeup + evidence:
`docs/audits/2026-06-14-e2ee-regression.md` (R-K1 encrypted bidirectional decrypt +
R-K2 device-sign-out survivability, both PASS). Connector test delta (test-only) is
kept as a patch at `docs/audits/patches/e2ee-connector-localstack.patch`.

**The edge route (why it is needed).** Under MSC3861 Synapse **disables its native
CS-API logout / device-management endpoints** (`404 "Unrecognized request"`); those
are **owned by siwx-oidc** (`src/compat.rs`: `login_flows`/`logout`/`logout_all`/
`delete_device`/`delete_devices`/`refresh`). So matrix-sdk's native
`client.matrix_auth().logout()` (the deployed in-client "Sign out this session" path)
404s against a bare Synapse. PROD forwards those paths to siwx-oidc with a Caddy
method-route on `matrix.inblock.io`. The local real stack mirrors that with a
`siwx-real-caddy` edge (`e2e/real-stack/Caddyfile`, brought up by
`e2e/real-stack-edge.sh`) on `http://localhost:8450`, routing the six owned paths →
`siwx-real-oidc:8081` and everything else → `siwx-real-synapse:8008`. The connector
points its homeserver at the **edge**, so native sign-out reaches siwx-oidc through the
real client → edge → siwx-oidc path (no direct-to-:8081 workaround).

**Exact run commands** (real stack up → add edge → run the connector E2EE test via the
regression worktree; localhost only):

```bash
# 1) real stack up (see recipe above); then add the prod-mirroring edge:
cd ~/siwx-oidc
bash e2e/real-stack-edge.sh up        # siwx-real-caddy on :8450
bash e2e/real-stack-edge.sh verify    # POST /logout: direct-Synapse 404 vs edge 200

# 2) connector regression worktree (concurrent agent owns the main tree):
git -C ~/aqua-matrix-agent worktree add ~/aqua-matrix-agent-e2ee regression/local-e2ee-track2
cd ~/aqua-matrix-agent-e2ee
git apply ~/siwx-oidc/docs/audits/patches/e2ee-connector-localstack.patch || true
cargo build --test e2e --features e2e
mkdir -p /tmp/rk-e2ee/keys
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/a.pem --print-did
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/b.pem --print-did

# 3) R-K1 (encrypted bidirectional decrypt) — client points at the EDGE :8450:
SIWX_E2E_SIWX_URL=http://localhost:8081 SIWX_E2E_MATRIX_URL=http://localhost:8450 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/a.pem SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store \
cargo test --test e2e --features e2e e2ee_bidirectional_messaging -- --nocapture --test-threads=1

# 4) R-K2 (NATIVE matrix-sdk logout → edge → siwx-oidc; fresh keys+store, full-life tokens):
SIWX_E2E_RUN_RK2=1 SIWX_E2E_SIWX_URL=http://localhost:8081 SIWX_E2E_MATRIX_URL=http://localhost:8450 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/rk2-a.pem SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/rk2-b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store-rk2 \
cargo test --test e2e --features e2e e2ee_device_logout_history_survives -- --nocapture --test-threads=1

# teardown the edge when done (leaves the real stack up):
bash ~/siwx-oidc/e2e/real-stack-edge.sh down
```

Gotchas: keep R-K1 / R-K2 on SEPARATE store roots + identities (the crypto store binds
to (homeserver, device_id); reusing a store across homeserver URLs collides server-side
one-time keys → all events `[unable to decrypt]`). R-K2's native `logout()` invalidates
B's session client-side immediately, so never sync B after logout. Do not touch
`~/aqua-matrix-agent`'s working tree — use the worktree.

## Headless client (siwx-oidc-auth)

Two authentication modes:

**Authorization code flow** (local signing key, server needs `"key"` in `supported_did_methods`):

```bash
# Generate a persistent Ed25519 identity
openssl genpkey -algorithm Ed25519 -out identity.pem

# Print the DID for registration
siwx-oidc-auth --print-did --key-file identity.pem

# Authenticate and get OIDC tokens (includes refresh_token)
siwx-oidc-auth --server https://siwx.example.com \
  --client-id my-service --redirect-uri https://app/callback \
  --key-file identity.pem

# Refresh tokens without re-authenticating (no --redirect-uri needed)
siwx-oidc-auth --server https://siwx.example.com \
  --client-id my-service --refresh-token "<refresh_token_value>" \
  --key-file identity.pem
```

Key input priority: `--key-file` > `SIWX_KEY_FILE` env > `--key-hex` > generate ephemeral.
PEM format is canonical (PKCS#8, auto-detects Ed25519 vs P-256).

**Refresh tokens:** Both standalone and MSC3861 modes issue refresh tokens with a TTL
of **90 days** (`REFRESH_TOKEN_TTL = 7_776_000` s) — intentional.
The `refresh()` library function and `--refresh-token` CLI flag exchange a refresh
token for new access + refresh tokens without repeating the full CAIP-122 sign-in.
The server rotates the refresh token on each use (old token is deleted).

**Device flow** (RFC 8628, no local key needed; user approves on another device):

```bash
# For headless servers, CI, or machines without a browser/wallet
siwx-oidc-auth --device-flow \
  --server https://siwx.example.com \
  --client-id my-service
```

Prints a user code and verification URL to stderr, polls until approved.
The resulting tokens are associated with whatever DID the approving user
authenticates with (wallet or passkey).

**Identity ownership:** The two modes produce different identity models:

| Mode | Identity owner | DID type | Use case |
|------|---------------|----------|----------|
| Auth code (`--key-file`) | The machine itself | `did:key:z6Mk...` (Ed25519) or `did:key:zDn...` (P-256) | Service accounts, bots, autonomous agents |
| Device flow (`--device-flow`) | The human who approves | `did:pkh:eip155:1:0x...` (wallet) or `did:key:zDn...` (passkey) | CI, headless SSH, shared servers |

The device flow does NOT give the machine its own DID. The approving user's
DID is embedded in the tokens. If they approve with MetaMask, the session runs
under their `did:pkh:eip155:...`; if they approve with a passkey, it runs under
their `did:key:zDn...` (or linked wallet DID).

**Device flow examples:**

```bash
# CI pipeline: prints approval URL in CI log, engineer approves on phone
siwx-oidc-auth --device-flow \
  --server https://siwx.example.com --client-id ci-bot

# Remote SSH session: no browser available
siwx-oidc-auth --device-flow \
  --server https://siwx.example.com --client-id my-app

# Pipe access token directly to a file
siwx-oidc-auth --device-flow \
  --server https://siwx.example.com --client-id agent \
  | jq -r .access_token > /tmp/matrix-token
```

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
| `SIWEOIDC_LOG_FORMAT` | Log output format | `pretty` (or `json`) |
| `SIWEOIDC_MATRIX_SERVER_NAME` | Matrix server_name for cross-signing checks | (none) |
| `SIWEOIDC_ACCOUNT_MANAGEMENT_URI` | MSC4191 account management URL (override) | `{base_url}/account` |

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
| `../aqua-auth` | Crypto layer (aqua-auth 0.2.0) providing DIDMethod/CipherSuite traits. Workspace dependency. |

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

**Deploy model:** Code on dev machine, push to GitHub, CI builds Docker images to GHCR,
server pulls and runs them. No repos or builds on the server.

```bash
# CI publishes to GHCR on push to main (see .github/workflows/docker.yml)
# Image is ~18MB (Alpine + static musl binary + frontend assets)
```

**Production server:** `deploy@142.93.168.4` (`agentic.inblock.io`)
- Stack directory: `/home/deploy/matrix/stack/` (docker-compose.yml + .env only)
- **Deploys are MANUAL, not automatic.** A `matrix-watchtower-1` container exists but runs
  with `WATCHTOWER_SCOPE=matrix` and the only container carrying that scope label is
  watchtower ITSELF, so it updates nothing in the stack (verified 2026-06-12). A push to
  `main` builds and publishes `ghcr.io/inblockio/siwx-oidc:main` via CI, but it does NOT
  reach prod until someone runs, on the server:
  `cd /home/deploy/matrix/stack && docker compose pull siwx-oidc && docker compose up -d siwx-oidc`.
  (Do not trust the old "watchtower auto-deploys within 5 min" claim.)
- Caddy reverse proxy in portal stack (`portal-caddy-1`, config at `/home/portal/portal/Caddyfile`)

**CORS rule:** Caddy must strip siwx-oidc's upstream CORS headers (`header_down
-Access-Control-Allow-Origin` in `reverse_proxy` blocks). Without this, dual ACAO
headers cause silent OIDC failures. See `Caddyfile.local` `(strip_upstream_cors)` snippet.

Matrix Synapse deployment: see `../siwx-oidc-matrix-server`.
Run `/deploy-check` for the full pre-deployment checklist.

### MSC3861 device lifecycle

**Provisioning at sign-in (no recycling):** Sign-in does NOT delete devices. Each
login provisions a fresh `SIWX_{uuid}` via an idempotent `upsert_device`
(`oidc::provision_synapse_device`); it never deletes-then-reuses a device id.
The device_code grant (QR login) uses `provision_synapse_device_additive`, which
likewise upserts without deleting existing devices: if the client supplies a
device_id in the scope (`urn:matrix:client:device:XXX` or
`urn:matrix:org.matrix.msc2967.client:device:XXX`) that exact id is provisioned,
otherwise a `SIWX_{uuid}` is generated. The token response includes the scope so
clients can discover the provisioned device_id. `allow_cross_signing_reset`
fires unconditionally on sign-in.

**Session teardown (logout / revoke / logout-all):** Teardown always revokes the
*ending* session's OAuth tokens. Whether it also deletes the Synapse device is
gated by `compat::TeardownPolicy`, which keys on the caller's intent, NOT on the
transport: an explicit sign-out deletes; bare token hygiene does not. Deleting a
device that is ending is distinct from recycling and is safe (the id is never
reused), so it does not hit the stale-signature problem below. All teardown is
best-effort, idempotent, and never returns 500; with no Synapse client /
`server_name` it degrades to Redis-only token revocation. Revocation keys on
`TokenMetadata.username` (the lowercased localpart), not the raw DID. Implemented
in `src/compat.rs`:

| Endpoint | Handler | Policy | Synapse side effect | Token side effect |
|----------|---------|--------|---------------------|-------------------|
| `POST /oauth2/revoke` (RFC 7009) | `compat::revoke` | `TokensOnly` | none (never deletes the device) | `revoke_device_tokens(username, device_id)` (access + paired refresh) |
| `POST /_matrix/client/v3/logout` | `compat::logout` | `DeleteDevice` | `delete_device` for the bearer token's session | same token revoke as revoke |
| `POST /_matrix/client/v3/logout/all` | `compat::logout_all` | n/a (bulk) | `list_devices` then `delete_device` for EACH device (best-effort per device) | `revoke_all_user_tokens(username)` |

**Revoke must not delete the device (2026-06-12 login incident).** RFC 7009
`/oauth2/revoke` is token hygiene: clients fire it on token rotation and on dialog
dismissals. Deleting the Synapse device there raced in-flight key uploads and
wedged users' cross-signing identity (amplifier B of the incident). Device
deletion is therefore restricted to explicit-intent paths: `compat::logout` and
the MSC4191 `device_delete` / `session_end` actions in `account.rs`.

`logout/all` is session invalidation, NOT account deactivation: it never calls
`deactivate_user`, so the account stays active and the user can sign in again.
(Account deactivation lives in `account.rs` under
`/account?action=org.matrix.account_deactivate`.) Single-session `logout` deletes
only the ending session's device; `revoke` deletes nothing; sign-in is unchanged.

**Why no recycling:** Synapse's `delete_device` (MAS API) does not remove cross-signing
signatures, and its signature-upload handler skips new uploads when a stale one exists.
Recycling a device_id with new keys creates unrecoverable verification failures.
Deleting a device that is *ending* (in teardown above) is safe precisely because the
id is not reused.
See `../siwx-oidc-matrix-server/docs/2026-05-19-device-verification-analysis.md`.

## WebAuthn/Passkey architecture

**Ceremony module:** `src/webauthn.rs` — registration uses `webauthn-rs` 0.6.0-dev safe API;
assertion verification uses `aqua-auth`'s `verify_webauthn_assertion` (P-256, behind `webauthn` feature).
**DID derivation:** Passkey P-256 pubkey → compressed SEC1 → `did:key:zDn…` (same
encoding as aqua-auth's key module).

**Redis keys:**
```
webauthn:challenge/{session_id}        TTL 120s  — ceremony state (register or auth)
webauthn:credential/{cred_id_b64}      no TTL    — stored Passkey (JSON-serialized)
webauthn:link/{cred_id_b64}            no TTL    — { primary_did, label } (account linking)
webauthn:link_challenge/{session_id}   TTL 120s  — link ceremony state (reg_state + primary_did)
device_codes/{device_code}             TTL 1800s — DeviceCodeEntry (RFC 8628)
user_codes/{user_code}                 TTL 1800s — reverse lookup to device_code
```

**Endpoints:**
```
POST /webauthn/register/start       — returns CreationChallengeResponse
POST /webauthn/register/finish      — verifies attestation, stores credential
POST /webauthn/authenticate/start   — returns RequestChallengeResponse (discoverable)
POST /webauthn/authenticate/finish  — verifies assertion, stores verified_did in session
POST /link/webauthn/start           — begin passkey registration (verifies siwx cookie for DID ownership)
POST /link/webauthn/finish          — verifies attestation, stores credential + link mapping
POST /device_authorization          — RFC 8628: returns device_code + user_code + verification_uri
GET  /device                        — approval page (user authenticates and approves device login)
POST /device                        — process approval (wallet CAIP-122 signature)
GET  /device/verify                 — check if user_code is valid and pending
POST /device/passkey/start          — start passkey auth for device approval
POST /device/passkey/finish         — finish passkey auth and approve device
GET  /account                       — MSC4191 account management page
POST /account/wallet                — wallet re-auth for account action (MSC4312)
POST /account/passkey/start         — start passkey auth for account action
POST /account/passkey/finish        — finish passkey auth for account action
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

5. **Selecting a stale/revoked passkey** → the credential was stored on a different
   Redis instance, Redis was flushed (`--reset`; credential keys have no TTL but are
   not persisted), or the credential was revoked/erased. Check
   `redis-cli KEYS 'webauthn:credential/*'`.

   **Behavior (since 2026-06-16):** the unknown-credential case is no longer a raw
   500. `verify_credential` returns the typed `VerifyError::UnknownCredential` (the
   *only* failure mode that does so; the other five stay 500/Other), which the
   handlers render as **HTTP 401** with a machine-readable body
   `{"error":"unknown_credential","credential_id":"<b64url>","message":...}`, logged
   as `unknown_credential` (not `internal_error`). The frontends key on that
   discriminator to (a) show an actionable message and (b) best-effort, feature-
   detected, call `PublicKeyCredential.signalUnknownCredential({rpId, credentialId})`
   so the platform prunes the stale key from the picker next time. This is privacy-
   safe: we only ever signal an id the client just presented, never enumerate stored
   credentials. Support is partial (recent Chrome/Safari), so it is a progressive
   enhancement; the 401 + message is the guaranteed floor on every browser. The
   signal fires ONLY on the discriminator, never on signature/challenge/counter
   failures, so a valid passkey is never pruned.

   **Migration (pre-2026-06-15 credentials):** the discoverable fix requires resident
   keys only for NEW registrations. A passkey registered before that fix may not be
   resident/discoverable and so may not surface in the picker (or may resolve but no
   longer match). There is no server-side migration (the server cannot reach a
   credential it never stored as resident). Re-enrollment path: sign in another way
   (wallet) and register a fresh passkey via "Link a passkey", or register a new one
   on the login page. The unknown-credential message points the user here.

   **Held in reserve (not implemented):** `signalAllAcceptedCredentials` (needs a user
   handle / identity scope) and identifier-first `allowCredentials` (a hard pre-
   filtered picker, but it costs the usernameless flow). Use these only if hard
   prevention is ever required; `signalUnknownCredential` keeps usernameless intact.

6. **"Session not found"** → session expired (300s TTL) between authenticate_finish
   and sign_in redirect. Check for network/proxy delays.

### QR code login (Element X) succeeds but then fails

**Symptom:** The device approval page shows "Device approved", siwx-oidc logs
confirm tokens were issued, but Element X shows a login failure after ~30-60s.

**Root cause:** The user's Element Web session has no Secure Backup (cross-signing
keys). MSC4108 Phase 4 requires Element Web to transfer cross-signing private keys
to Element X via the rendezvous channel. Without cross-signing, Element Web has
nothing to transfer, the rendezvous session expires, and Element X aborts.

**Fix:** Set up Secure Backup in Element Web **before** using QR code login:
1. Log in to Element Web with wallet or passkey
2. Go to Settings > Security & Privacy > Set up Secure Backup
3. Complete the key backup setup
4. Then use "Link new device" to add Element X

**Pre-flight warning:** When `SIWEOIDC_MATRIX_SERVER_NAME` is configured, the
device approval page checks for cross-signing keys and warns the user if they
are missing. Set this env var to the Matrix server_name (e.g. `matrix.inblock.io`).

**Cross-signing auto-bootstrap (investigated 2026-05-23):** MAS contains zero
cross-signing code. First-time cross-signing key upload is handled by Synapse
via MSC3967 (stable since spec v1.11, Synapse >= 1.110.0), which skips UIA
entirely when the user has no existing cross-signing keys. This works
identically for any OIDC provider, including siwx-oidc.

Element Web had a `freshLogin` detection bug (PR #30141, merged June 2025)
where OIDC delegate logins were treated as session restorations
(`freshLogin=false`), causing it to skip `bootstrapCrossSigning()` entirely.
With the fix and correct `.well-known` `m.authentication` configuration
(MSC2965), auto-bootstrap should work without manual Secure Backup setup.

**Prerequisites for auto-bootstrap:**
1. Synapse >= 1.110.0 (MSC3967 stable)
2. `.well-known/matrix/client` includes `m.authentication` pointing to siwx-oidc
3. Element Web version includes freshLogin fix (PR #30141, June 2025)

**For cross-signing key RESET** (not first-time): siwx-oidc calls
`allow_cross_signing_reset` on every login (both provisioning modes), and
also provides a spec-compliant account management page at `/account`
(MSC4191 + MSC4312). When Element Web encounters a cross-signing reset
needing user confirmation, it reads `account_management_uri` from OIDC
discovery and opens `/account?action=org.matrix.cross_signing_reset`.
The user re-authenticates (wallet or passkey), siwx-oidc calls
`allow_cross_signing_reset`, and Element Web retries the upload.

### MSC4191 account management (full action set)

`/account` handles the full MSC4191 deep-link contract
(`/account?action=<action>[&device_id=<id>]`), not just cross-signing reset:

| Action (`device_*` + `session_*` alias) | Effect |
|---|---|
| `profile` | Show the user's identity (DID + Matrix ID) |
| `devices_list` / `sessions_list` | List the user's Synapse devices |
| `device_view` / `session_view` | Show one device's details (needs `device_id`) |
| `device_delete` / `session_end` | Sign a device out (needs `device_id`) |
| `cross_signing_reset` | Allow cross-signing reset (MSC4312) |
| `account_deactivate` | Deactivate the account (Synapse admin `deactivate`, `erase:false`, reversible by admin / `account_reactivate`) + revoke ALL the user's tokens |
| `account_erase` | GDPR erasure: Synapse admin `deactivate` with `erase:true` (purges profile, media, room memberships) + revoke ALL tokens + `RedisClient::purge_identity` (deletes the DID's WebAuthn `credential`/`link` artifacts). Irreversible |
| `account_reactivate` | Restore an `erase:false`-deactivated account (Synapse admin `PUT users {deactivated:false}`). Self-service feasibility under MSC3861 is **unverified** (admin PUT may reject without a local password); fails closed with a clear "ask an admin" message |

**Bare/empty-action landing = account-home menu.** `GET /account` with NO `action`
param (or an empty one) renders a navigation menu (links to `profile`,
`devices_list`, and a danger-styled `account_deactivate`), NOT the dead-end
re-auth buttons. This is required because Element Web's generic "Manage account"
opens the bare `account_management_uri` with no action; previously the re-auth
then POSTed `action:""` and got `400 "Unsupported action: "`. The menu is the
only path an Element Web user has to reach deactivation (Element Web suppresses
its in-app deactivate for externally-managed accounts). Element-X is unaffected
(it deep-links specific actions). The POST handlers now distinguish an empty
action (`400 "Missing action"`) from a truly unknown one
(`400 "Unsupported action: {x}"`) via `parse_action`.

**Account deactivation is irreversible.** `/account?action=org.matrix.account_deactivate`
shows a permanent-deactivation confirmation (a "cannot be undone" warning +
`#confirm-deactivate` checkbox gating the auth buttons) before re-auth. The
checkbox is UX friction only; the real authorization is the wallet/passkey
signature (same model as `device_delete`). On success `execute_action` calls
`SynapseClient::deactivate_user` then `RedisClient::revoke_all_user_tokens` and
returns `ActionOutcome::Deactivated`. Like the other device actions it requires
`SIWEOIDC_MATRIX_SERVER_NAME` + a Synapse client (clear `BadRequest`, never 500,
when absent).

**Account erasure (`account_erase`) is irreversible GDPR deletion.**
`/account?action=org.matrix.account_erase` shows a stronger, danger-styled
confirmation than deactivate ("permanently deletes your profile, media, and room
memberships", a `#confirm-erase` checkbox gating the auth buttons). On success
`execute_action` calls `SynapseClient::deactivate_user(.., erase = true)`, then
best-effort `revoke_all_user_tokens` and best-effort
`RedisClient::purge_identity(did)` (which deletes the DID's `webauthn:link/*`
mappings + their credentials, and standalone `webauthn:credential/*` whose stored
P-256 passkey derives to that `did:key` via
`webauthn::derive_did_from_credential_json`). Returns `ActionOutcome::Erased`.
Erasure removes the WebAuthn artifacts so the DID cannot be silently re-derived
from a leftover passkey.

**Reactivation (`account_reactivate`) is verified working under MSC3861.**
`SynapseClient::reactivate_user` issues admin `PUT /_synapse/admin/v2/users/{mxid}`
with `{"deactivated": false}`; it is valid only for `erase:false` deactivations
(an erased account cannot be restored). Live probe (2026-06-10, prod
agentic.inblock.io, throwaway user): the PUT succeeds with HTTP 200 and the
account comes back `deactivated: false`; no local password is demanded as long
as no `password` key is sent. The action still fails closed on genuine errors
(erased account, Synapse unreachable): a clear `BadRequest` telling the user to
ask a server admin, never a 500. See the doc comment on
`SynapseClient::reactivate_user` and `scripts/verify-lifecycle-live.sh` section 3.

**Model:** the page is stateless; each action re-authenticates (wallet CAIP-122
or passkey), proving the DID, then runs the action and returns a `kind`-tagged
`ActionOutcome` the page JS renders. The advertised set lives in **one place**
(`account::SUPPORTED_ACTIONS`), consumed by `oidc::provider_metadata_value`;
**Synapse forwards it verbatim** to `/_matrix/client/v1/auth_metadata` (verified
live), so no matrix-server change is needed to advertise new actions.

**Device source of truth = Synapse.** `devices_list`/`device_view` call the
Synapse **admin API** (`GET /_synapse/admin/v2/users/{mxid}/devices`) using the
MAS shared secret (which `matrix_server.sh` also sets as `admin_token`).
`device_delete` deletes the Synapse device **and** calls
`RedisClient::revoke_device_tokens` to revoke the OAuth session (introspection
then reports it inactive). Device actions require `SIWEOIDC_MATRIX_SERVER_NAME`
and a Synapse client; without them they return a clear `BadRequest` (standalone
deployments degrade, never 500). Live AC check:
`cargo test --test e2e_msc3861 msc4191_metadata -- --ignored`.

**For QR code login specifically:** even with auto-bootstrap working, the
approving device must have cross-signing private keys in Secure Backup so
it can transfer them via the MSC4108 rendezvous channel. If no Secure Backup
exists, the QR login will fail after approval.

Run `/cross-signing-bootstrap-and-debug` for the full diagnostic flowchart.

**Diagnostic:** Check Synapse logs for `has no master cross-signing key` warnings
during device provisioning. Check siwx-oidc logs for `device approval: user has
no cross-signing keys` warnings. Check browser console for `bootstrapCrossSigning`
calls and `keys/device_signing/upload` requests during login.

### Element X mobile passkey-first login (RESOLVED 2026-05-25)

**Goal:** End-to-end passkey-first login on Element X mobile (Android/iOS). User enters
homeserver, registers passkey with biometric, lands in working E2EE session. No wallet,
no seed phrase, no manual verification prompt.

**Status: iOS WORKING, Android OPEN.** iOS Element X passkey-first login works
end-to-end. Android Element X does not work yet (under investigation).

**Root cause was wrong server input, not an SDK bug.** Two OIDC discovery divergences
from MAS caused the matrix-rust-sdk to silently fail cross-signing bootstrap. The SDK's
`bootstrap_cross_signing_if_needed(None)` never reached the `keys/device_signing/upload`
call because earlier steps failed due to missing metadata, and the error was swallowed:
`error!("Couldn't bootstrap cross signing {e:?}")`.

**Fixes deployed (2026-05-25):**

| Fix | Endpoint | Value |
|-----|----------|-------|
| `prompt_values_supported` | OIDC discovery (`axum_lib.rs`) | `["login", "create"]` |
| `m.authentication.account` | `.well-known/matrix/client` (Caddyfile) | `https://siwx-oidc.inblock.io/account` |

**Investigation timeline (2026-05-24):**
1. Symptom: passkey auth succeeds, then "Can't confirm your digital identity," reset fails
2. Validated: Element Web passkey login works perfectly with same server (server code correct)
3. Validated: QR code login works when cross-signing already set up (token/introspect/scope correct)
4. Synapse logs confirmed: Element X never calls `keys/device_signing/upload`
5. SDK source analysis confirmed: code path supports MSC3967 with `auth: None` (not a hard blocker)
6. Live comparison against MAS found two missing fields in OIDC discovery / .well-known
7. Fixes deployed, Element X passkey-first login works end-to-end

**Lesson learned:** The matrix-rust-sdk silently swallows cross-signing bootstrap errors.
When the SDK encounters unexpected/missing OIDC metadata, the bootstrap task fails before
reaching the key upload HTTP call, and the error is logged at `error!` level with no retry
or user-visible feedback. Always diff OIDC discovery and `.well-known` responses against
MAS when debugging Element X issues.

**Upstream context (still relevant for awareness):**
- [matrix-rust-sdk #1641](https://github.com/matrix-org/matrix-rust-sdk/issues/1641):
  silent bootstrap failure, no retry/recovery. OPEN since 2023.
- [element-meta #2410](https://github.com/element-hq/element-meta/issues/2410):
  richvdh: "no further attempt to publish public keys, account is totally broken."
- These upstream issues mean any future OIDC metadata regression could silently break
  Element X again with no user-visible error. Keep MAS parity as a deployment check.

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

# List active device codes (RFC 8628)
redis-cli KEYS 'device_codes/*'

# Inspect a device code status
redis-cli GET 'device_codes/{device_code}' | python3 -m json.tool

# List active user codes
redis-cli KEYS 'user_codes/*'
```

## Logging conventions

**Subscriber:** Initialized in `axum_lib.rs::main()` with `EnvFilter`. Default filter:
`siwx_oidc=info,tower_http=info,warn`. Override with `RUST_LOG` env var.

**Format:** Set `SIWEOIDC_LOG_FORMAT=json` for structured JSON output (container log
aggregation). Default: human-readable (`pretty`).

**Level guidelines for new modules:**

| Level | Use for | Examples |
|-------|---------|---------|
| `error!` | Unrecoverable failures that halt a request or corrupt state | Signing key load failure, Redis pool exhausted |
| `warn!` | Recoverable errors, unexpected but handled conditions | Synapse API failure (best-effort), invalid client input, auth failures |
| `info!` | Significant state changes, request lifecycle events | Sign-in success, ceremony start/finish, server startup |
| `debug!` | Internal details useful during development | Redis key operations, token metadata, ENS resolution attempts |

**Rules:**
- aqua-auth: NO logging (pure library, no tracing dependency)
- Never log secrets, tokens, cookies, or signing key material
- Use structured fields (`info!(did = %did, "sign_in success")`) not string interpolation
- Error paths: prefer logging at the boundary (`CustomError::into_response`) over scattering
  `warn!` calls through business logic
- Modules that bypass `CustomError` (introspect, compat) must log their own errors

## MSC3861 compliance (resolved 2026-05-19)

Audit document: `docs/audit/msc3861-compliance-audit.md` (2026-05-19)
Implementation plan: `docs/superpowers/plans/2026-05-19-msc3861-compliance.md`

All 6 items fixed in branch `msc3861-compliance`. Deploy note: **Redis flush required**
(TokenMetadata schema changed, `did` and `name` fields are now required).

## Skills (`skills/`)

Skill files live at the repo root in `skills/` (visible to all users).
Claude Code discovers them via symlinks in `.claude/commands/` (invoke with `/skill-name`).

| Skill | Purpose |
|-------|---------|
| `/add-did-method` | Add a new DID method to aqua-auth (Layer 1) |
| `/add-cipher-suite` | Add a new cipher suite to did:pkh in aqua-auth (Layer 1) |
| `/add-auth-ceremony` | Add a new auth ceremony to the server (Layer 2) |
| `/authenticate-siwe-matrix` | End-to-end auth flow: Element Web to siwx-oidc to Synapse |
| `/debug-oidc` | Debug OIDC authentication flow issues |
| `/deploy-check` | Pre-deployment checklist for Matrix |
| `/element-x-qr-code-specialist` | Element X QR code login setup, implementation, and troubleshooting |
| `/cross-signing-bootstrap-and-debug` | Cross-signing bootstrap, debug, and MSC3967/4312/4191 reference |
| `/docker-build` | Build, test, push Docker image |
