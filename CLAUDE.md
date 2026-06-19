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
| Refresh token TTL | 86400s (24h) | 86400s (24h) |
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

**Refresh tokens:** Both standalone and MSC3861 modes issue refresh tokens (24h TTL).
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
webauthn:by_did/{did}                  no TTL    — SET of cred_id_b64 for this DID (reverse index)
user:session/{token}                   TTL 30d   — opaque login user-session: token -> DID
device_codes/{device_code}             TTL 1800s — DeviceCodeEntry (RFC 8628)
user_codes/{user_code}                 TTL 1800s — reverse lookup to device_code
```

**`webauthn:by_did/{did}` reverse index (passkey-picker scoping).** A Redis SET of
the `cred_id_b64` values that resolve to a DID, maintained at `register_finish`
(under the derived `did:key`) and `link_finish` (under the wallet `primary_did`),
and pruned by `purge_identity`. It backs `get_passkeys_for_did(did)`, which returns
exactly that DID's credentials (its standalone passkeys plus any wallet-linked
ones). The index is **advisory**: on a cold/missing index `get_passkeys_for_did`
self-heals by SCANning the credential keyspace and back-filling the SET (verified by
`get_passkeys_for_did_scan_fallback_equals_index`), so a missed `index_add_passkey`
can never lose a passkey — it only costs one scan. A best-effort index-update failure
never fails the registration/link the user just completed.

**`user:session/{token}` opaque login user-session (identity hint).** Mirrors the
`acct_session` pattern: a random opaque `token` -> DID, with a 30-day TTL. It is the
identity hint that scopes the passkey picker (see below). The DID lives ONLY in
Redis; the token is opaque, so a forged/guessed value is a Redis miss -> usernameless
fallback. Minted at `sign_in` (after the new-user gate is cleared) and at account
re-auth; resolved at `authenticate_start`.

**Endpoints:**
```
POST /webauthn/register/start       — returns CreationChallengeResponse
POST /webauthn/register/finish      — verifies attestation, stores credential
POST /webauthn/authenticate/start   — RequestChallengeResponse, scoped by siwx_user cookie (see below)
POST /webauthn/authenticate/finish  — verifies assertion, stores verified_did + reports new_user gate
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

### Passkey-picker scoping (`siwx_user` cookie) — 2026-06-18

Usernameless/discoverable login sends an EMPTY `allowCredentials`, so the OS passkey
picker shows EVERY resident passkey for the RP. To show only the relevant account
for a returning user, `/webauthn/authenticate/start` scopes `allowCredentials` to the
caller's DID — but ONLY when the caller proves identity with an opaque server token,
never a client-supplied identifier (that would re-open the credential-enumeration leak
the discoverable fix closed).

- **`siwx_user` cookie** (`USER_SESSION_COOKIE` in `axum_lib.rs`): an OPAQUE token,
  `Path=/` (so it reaches login-time `authenticate_start`), `HttpOnly; SameSite=Strict`,
  `Secure` on https, `Max-Age` = `USER_SESSION_LIFETIME` (30d). Its value is the token
  only; the DID lives solely at `user:session/{token}` in Redis. Distinct from the
  `acct_session` cookie (`Path=/account`). Minted at `sign_in` (after the new-user gate
  is cleared) and at account re-auth.
- **Scoping:** `authenticate_start` reads `siwx_user` -> `lookup_user_session(token)`
  -> DID -> `get_passkeys_for_did(did)` -> `allowCredentials` = exactly that DID's
  credentials. The response is a wrapper around `RequestChallengeResponse`:
  `{ publicKey..., detected_mxid }` (the `publicKey` fields stay flattened at
  the top level so the frontend is unchanged); `detected_mxid` = `@localpart:server`
  is present ONLY when scoped, else absent/null.
- **No server-side method prediction (rolled back 2026-06-19):** the offer is scoped
  by *identity* only (`allowCredentials`). The login `authenticate_start` does NOT
  emit a `methods` hint and the frontend does NOT grey out a button from one. Wallet
  availability is detected locally (is an EIP-1193 provider injected?); passkeys roam
  across devices/transports, so reachability is resolved live by the ceremony and the
  passkey button is always offered, falling open with a friendly message if no key is
  present. (Removed: `webauthn::methods_for_did` / `MethodsForDid`, the response
  `methods` field, and the App.svelte `disabled` grey-out clauses.) See
  `docs/design/2026-06-19-passkey-offer-scoping-minimal-behavior.md`.
- **Empty scope set:** a wallet-only DID (no linked passkey) resolves to zero creds;
  `authenticate_start` falls back to leaving `allowCredentials` empty (discoverable)
  rather than emitting a broken empty picker that blocks every key.
- **Escape hatch ("use a different passkey"):** body `{"all": true}` OR `?all=1` forces
  usernameless (empty `allowCredentials`) even with a valid cookie.
- **Enumeration-safety invariant:** a forged/guessed/expired `siwx_user` is a Redis
  miss -> `scope_did = None` -> usernameless, leaking ZERO credential ids and a null
  `detected_mxid`. The identity hint can never be a plaintext DID or free-form id.
  (`get_passkeys_for_did` is server-side; it never echoes cred ids to an unscoped
  caller.)

### New-account creation policy (login-only gate) — 2026-06-18

Authenticating with an unrecognised passkey/wallet resolves a DID whose Matrix
localpart is unprovisioned, so `sign_in` would silently CREATE a brand-new account.
"New" is detected read-only, BEFORE any Synapse write, via
`is_new_identity(did)` = `SynapseClient::is_localpart_available(did_to_localpart(did))`.
Creating a new identity is permitted **ONLY at the login screen**; the account and
QR/device flows hard-REJECT it:

| Flow | New identity (`is_localpart_available == true`) |
|------|--------------------------------------------------|
| Login (`/webauthn/authenticate/finish`, wallet `/sign_in`) | **GATE:** `finish` returns `{ok, did, new_user:true, mxid}` and does NOT provision. The browser shows a confirm/cancel gate; provisioning happens only at `/sign_in` AFTER confirm. Cancel = no `/sign_in` = zero Synapse state. |
| Account re-auth (`/account/passkey/finish`, `/account/wallet`) | **REJECT:** `reject_if_new_identity` -> `400` with `NEW_IDENTITY_REJECT_MSG` ("not linked to an existing account. Create an account at sign-in first."). Nothing provisioned. |
| QR / device approval (`/device/passkey/finish`, `/device` wallet) | **REJECT:** same `400`, BEFORE `entry.did` is set, so the token grant never provisions. |

`reject_if_new_identity` fails **closed**: if detection itself fails (Synapse
unreachable) it rejects with the same message rather than risk a silent creation. It
is a strict no-op when no Synapse client is configured (standalone deployments
degrade, never 500). `login_finish` only reports `new_user`/`mxid` when a Synapse
client + `server_name` are configured (else `new_user:false`, behaves as before).

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

   **Behavior (since 2026-06-18):** the unknown-credential case is no longer a raw
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

   **Migration (pre-discoverable-fix credentials):** the discoverable fix requires
   resident keys only for NEW registrations, and removes the credential enumeration
   that `authenticate_start` previously did. A passkey registered before that fix may
   not be resident/discoverable and so may not surface in the picker (or may resolve
   but no longer match). There is no server-side migration (the server cannot reach a
   credential it never stored as resident). Re-enrollment path: sign in another way
   (wallet) and register a fresh passkey via "Link a passkey", or register a new one
   on the login page. The unknown-credential message points the user here.

   **Returning-user picker scoping (since 2026-06-18):** `authenticate_start` now
   scopes `allowCredentials` to the returning user's DID when a valid opaque
   `siwx_user` cookie is present, WITHOUT costing the usernameless flow (no cookie ->
   empty `allowCredentials` as before; escape hatch `{"all":true}`/`?all=1` forces
   usernameless on demand). See "Passkey-picker scoping" above. A stale/scoped key
   still falls through to the `signalUnknownCredential` prune below.

   **Held in reserve (not implemented):** `signalAllAcceptedCredentials` (needs a user
   handle / identity scope). The cookie-scoping above is the safe form of an
   identifier-first picker (opaque token only, escape hatch preserved);
   `signalUnknownCredential` keeps usernameless intact.

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

**No more approval-time pre-flight warning (false positive REMOVED 2026-06-18).**
The device approval page USED to probe the published cross-signing master key (via
`keys/query`) at approval time and warn "no Secure Backup" when it was absent. That
check raced the client's first-time cross-signing bootstrap
(`keys/device_signing/upload`) and mislabelled a still-publishing or in-flux master
key as missing — a confirmed false positive that fired for healthy users. It is
removed: `check_cross_signing` / `CROSS_SIGNING_WARNING` are gone from
`device_auth.rs`, and `DeviceApproveResponse.warning` is now always `None`/absent on
the approve path (covered by the browser e2e `H9`). The real MSC4108 prerequisite
(cross-signing PRIVATE keys on the SENDING device) is not observable server-side;
Element Web's force-first-device-recovery patch enforces it. `SIWEOIDC_MATRIX_SERVER_NAME`
is still used elsewhere (account/device admin-API actions); it no longer drives an
approval-time warning.

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
