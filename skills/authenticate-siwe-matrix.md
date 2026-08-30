End-to-end authentication flow reference: Element Web to siwx-oidc to Matrix Synapse.

Use when tracing, debugging, or explaining the authentication flow. Covers both wallet (CAIP-122) and passkey (WebAuthn) paths through OIDC delegated auth.

**Key fact:** siwx-oidc **replaces MAS entirely**. It is not an upstream IdP behind MAS. Synapse delegates auth to siwx-oidc directly.

**Key fact 2 (the config key changed):** the delegation is configured with
`matrix_authentication_service` on Synapse >= 1.157 (dev-staging runs 1.159.0) and with
`experimental_features.msc3861` on <= 1.156 (prod still runs 1.154.0). The `msc3861`
key was **removed** in 1.157.0 and now crashes Synapse on startup. "MSC3861" still
names the *protocol* and siwx-oidc's internal token mode; it is no longer the name of
a Synapse setting on current versions. See "Synapse delegated-auth config" below.

## Service Topology

```
Element Web  -->  siwx-oidc  <-->  Redis
                     |
                     v
               Matrix Synapse
```

Four containers (`docker-compose.yml` in `../siwx-oidc-matrix-server`):
- **element-web** (nginx + injected JS shims)
- **siwx-oidc** (Axum OIDC server)
- **redis** (session, code, token, credential storage)
- **matrix_synapse** (homeserver, OIDC delegated auth — `matrix_authentication_service` on >= 1.157)

## Two Authentication Paths

Both converge at `GET /sign_in` and produce an authorization code:

| Path | Proof type | DID format | Trust model |
|------|-----------|------------|-------------|
| **Wallet** | Client-set `siwx` cookie with CAIP-122 signed message | `did:pkh:eip155:{chainId}:{address}` | Untrusted cookie; server verifies signature |
| **Passkey** | Server-verified WebAuthn ceremony | `did:key:zDn...` (P-256) | Trusted `verified_did` in Redis session |

---

## Wallet Flow (CAIP-122/SIWE)

### Step 1: Element Web initiates OIDC

Injected JS shims in Element Web (`siwx-gate.js`, `siwx-redirect.js`):

1. `siwx-gate.js` checks `localStorage.mx_access_token`. If absent and no `?code=`, blocks Element boot.
2. `siwx-redirect.js`:
   - Dynamic client registration: `POST /register` (auth method `none`, grants `authorization_code` + `refresh_token`)
   - PKCE: generates `code_verifier`, computes S256 `code_challenge`
   - Stores `code_verifier`, `state`, `client_id` in `sessionStorage`
   - Redirects to `GET /authorize`

### Step 2: /authorize creates session

**`src/oidc.rs:authorize`**

- Validates `client_id`, `redirect_uri`, requires `state` and `openid` scope
- Creates `SessionEntry` in Redis (300s TTL): `{ siwe_nonce, oidc_nonce, signin_count: 0, verified_did: None }`
- Sets `session` cookie (HttpOnly, SameSite=Strict)
- Redirects to login page with `nonce`, `domain`, `redirect_uri`, `state`, `client_id`, PKCE params

### Step 3: User signs CAIP-122 message

**`js/ui/src/App.svelte`**

- `@wagmi/core` + `injected()` connects to browser wallet (MetaMask, Brave, etc.)
- Builds EIP-4361 message via `viem/siwe::createSiweMessage` using the `nonce` from step 2
- Wallet signs (EIP-191 personal_sign)
- Sets `siwx` cookie: `{ did: "did:pkh:eip155:{chainId}:{addr}", message, signature }`
- Optional: offers passkey linking before redirect
- Redirects to `GET /sign_in`

### Step 4: /sign_in verifies and provisions

**`src/oidc.rs:sign_in`**

1. Loads session from Redis, atomically marks signed-in (prevents double sign-in)
2. **CAIP-122 path** (no `verified_did` in session):
   - Reads `siwx` cookie, checks DID method + namespace against config allowlists
   - Verifies signature: `did_method.verify(&did, &message, &sig_bytes)`
   - Checks nonce matches `session.siwe_nonce`
   - Checks `redirect_uri` in CAIP-122 `Resources:` section
3. **Synapse device lifecycle** (if `SIWEOIDC_SYNAPSE_ENDPOINT` + `MAS_SHARED_SECRET` configured):
   - **Never deletes** existing devices on sign-in (no recycle of device IDs)
   - Generates `SIWX_{uuid8}` device ID when the client did not propose one in scope
   - Provisions user via `/_synapse/mas/provision_user` if localpart free
   - Creates/upserts device via `/_synapse/mas/upsert_device`
   - **Best-effort** `POST /_synapse/mas/allow_cross_signing_reset` after every login
     provision (product 3B): arms a short Synapse window so a half-reset client can
     republish public cross-signing keys; failures are logged and do **not** fail sign-in
   - Localpart: DID with colons replaced by dashes, lowercased
4. Creates `CodeEntry` in Redis (UUID key, 300s TTL)
5. Redirects to `redirect_uri?code={uuid}&state={state}`

### Step 5: Token exchange

**`siwx-callback.js`** (injected in Element Web):

1. `siwx-gate.js` detects `?code=`, loads only `siwx-callback.js`
2. Validates `state` matches sessionStorage
3. `POST /token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`

**`src/oidc.rs:token_authorization_code`**:

1. Atomically consumes code (`try_consume_code`)
2. Validates PKCE: SHA-256(code_verifier) == stored code_challenge
3. **MSC3861 mode**: issues opaque tokens stored in Redis:
   - Access: `mat_{32 base62}` (300s TTL)
   - Refresh: `mcr_{32 base62}` (7_776_000s TTL / 90 days)
   - `TokenMetadata`: `{ username, device_id, scope, client_id, iat, exp, did, name }`
   - Scope: `openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}`
4. Signs ES256 ID token: `sub`=DID, `preferred_username`=DID, `name`=ENS name or DID
5. Returns `{ access_token, token_type, id_token, expires_in, refresh_token }`

### Step 6: Element Web session

**`siwx-callback.js`** continues:

1. `GET /_matrix/client/v3/account/whoami` with Bearer token (Synapse introspects it)
2. Stores `mx_access_token`, `mx_user_id`, `mx_device_id`, `mx_hs_url`, OIDC metadata in localStorage
3. Reloads; `siwx-gate.js` sees token; Element boots normally

### Step 7: Ongoing token validation

**`src/introspect.rs:introspect`**

Every Matrix API call: Synapse sends `POST /oauth2/introspect` with `token={mat_...}` and shared secret (Bearer or client_secret_post). Returns `{ active, username, device_id, scope, sub, name, ... }` or `{ active: false }`.

### Step 8: Token refresh

**OIDC** (`POST /token`, `grant_type=refresh_token`): rotates both access and refresh tokens.
**Matrix compat** (`POST /_matrix/client/v3/refresh`): same logic, Matrix JSON format.

---

## Passkey Flow (WebAuthn)

Steps 1-2 identical. Then:

### Step 3b: WebAuthn ceremony

**`src/webauthn.rs`**

1. `POST /webauthn/authenticate/start`: discoverable auth (empty allow list), stores state in Redis (120s TTL)
2. Browser prompts passkey selection
3. `POST /webauthn/authenticate/finish`:
   - Loads credential from `webauthn:credential/{cred_id_b64}`
   - Verifies assertion via `webauthn-rs`
   - Derives DID: P-256 pubkey -> compressed SEC1 -> multicodec `0x8024` -> base58 -> `did:key:zDn...`
   - Checks `webauthn:link/{cred_id}` for account linking (substitutes `primary_did` if linked)
   - **Stores `verified_did` in Redis session** (trusted)
4. Frontend redirects to `GET /sign_in`

### Step 4b: /sign_in trusts verified_did

When `session.verified_did` is set, `sign_in` skips CAIP-122 cookie verification entirely (server-verified). Proceeds to device lifecycle and code issuance.

Steps 5-8 identical.

---

## Redis Key Map

| Pattern | TTL | Purpose |
|---------|-----|---------|
| `sessions/{uuid}` | 300s | Session (siwe_nonce, verified_did, signin_count) |
| `codes/{uuid}` | 300s | Auth code (did, client_id, code_challenge, device_id) |
| `token/{mat_...}` | 300s | Access token metadata |
| `token/{mcr_...}` | 7776000s (90d) | Refresh token metadata |
| `clients/{uuid}` | 30d | Client registration |
| `webauthn:challenge/{session_id}` | 120s | Ceremony state |
| `webauthn:credential/{cred_id_b64}` | none | Stored passkey |
| `webauthn:link/{cred_id_b64}` | none | Account linking map |

## Synapse delegated-auth config (VERSION-DEPENDENT — read before copying)

Written by `entrypoints/matrix_server.sh`. **The config key changed in Synapse 1.157.0.**
Check the homeserver version before applying either block.

### Synapse >= 1.157 — stable `matrix_authentication_service` (dev-staging: 1.159.0)

```yaml
matrix_authentication_service:
  enabled: true
  endpoint: ${SIWEOIDC_INTERNAL_URL:-$SIWEOIDC_BASE_URL}
  secret: ${MAS_SHARED_SECRET}

experimental_features:
  msc4108_enabled: true      # QR login (2024/ECIES) — see /element-x-qr-code-specialist
  msc4143_enabled: true      # MatrixRTC
  msc3266_enabled: true
  msc4222_enabled: true
```

`issuer`, `account_management_url`, `client_id`, `client_secret` and `admin_token`
have **no equivalent here**. Synapse discovers all of that itself by fetching
siwx-oidc's OIDC metadata from `endpoint` — `api/auth/mas.py::auth_metadata()` is
`self._server_metadata.get()`, which does `get_json(self._metadata_url)`.

### Synapse <= 1.156 — legacy `experimental_features.msc3861` (prod today: 1.154.0)

```yaml
experimental_features:
  msc3861:
    enabled: true
    issuer: ${SIWEOIDC_BASE_URL}
    account_management_url: ${SIWEOIDC_BASE_URL}
    client_id: "0000000000000000000SYNAPSE"
    client_secret: ${MAS_SHARED_SECRET}
    admin_token: ${MAS_SHARED_SECRET}
```

**Never carry this block onto 1.157+.** It is a hard startup failure, not a warning
(verified locally against the 1.159.0 image, 2026-08-30):

```
Error in configuration at 'experimental.msc3861':
  experimental_features.msc3861 was removed. Use the matrix_authentication_service
  configuration instead.
```

Process exit code **1** — the container crash-loops. `matrix_server.sh` therefore runs
`yq -i "del(.experimental_features.msc3861)"` before writing the new block.

Synapse 1.154.0 **already** understands `matrix_authentication_service`, so migrating
the config forward does not require the image bump, and a 1.159 -> 1.154 image
rollback does not lose auth.

### Reaching the Synapse admin API = a SECOND credential (changed in 1.157)

The MAS shared secret is **not** an admin credential on 1.157+.

| Credential | Accepted on |
|---|---|
| `MAS_SHARED_SECRET` | `/_synapse/mas/*` only — provision, upsert/delete device, deactivate, cross-signing reset |
| Short-TTL minted `urn:synapse:admin:*` token | `/_synapse/admin/*` — device listing, media/retention admin |

Synapse 1.157 deleted the `admin_token` shim that let the raw shared secret reach
`/_synapse/admin/*`; those routes now answer 401 for it. siwx-oidc mints itself an
admin-scoped token on demand at `POST /oauth2/admin_token` (authenticated by the
shared secret) — see `src/admin_token.rs`. `is_server_admin()` in 1.159 is literally
`"urn:synapse:admin:*" in requester.scope`, and that scope comes verbatim from
siwx-oidc's own introspection response. The minted scope must carry **both**
`urn:matrix:client:api:*` and `urn:synapse:admin:*`, or Synapse rejects the token
before it ever looks at the admin scope.

## Logout / Revocation

Policy is **intent-based** (`compat::TeardownPolicy`), not transport-based:

| Endpoint | Device | Tokens |
|----------|--------|--------|
| `POST /oauth2/revoke` (RFC 7009) | **Keep** (TokensOnly) | Revoke access + paired refresh |
| `POST /_matrix/client/v3/logout` | **Delete** ending session device | Revoke that session's tokens |
| `POST /_matrix/client/v3/logout/all` | Delete each device (best-effort) | Revoke all user tokens |

Revoke must **not** delete the device (2026-06-12 incident). Under MSC3861 these CS-API paths are owned by siwx-oidc and must be edge-routed from the homeserver hostname.

## Common Failure Points

| Symptom | Likely cause | Where to check |
|---------|-------------|----------------|
| Element error before wallet prompt | `siwx-gate.js` not injected | `element_entrypoint.sh` |
| "Nonce mismatch" | Session expired (300s) | `oidc.rs:sign_in` |
| "Signature verification failed" | DID/key mismatch | `oidc.rs:sign_in` |
| "DID method 'key' not enabled" | Missing `"key"` in `SUPPORTED_DID_METHODS` | `config.rs` |
| 401 on whoami | Shared secret mismatch | `introspect.rs` |
| User not in Synapse | `provision_user` failed | `synapse_client.rs` |
| "code_verifier mismatch" | PKCE failure | `oidc.rs:token_authorization_code` |
| Repeated `401 "Unrecognised client id"` every ~10s | Element's native MSC3861 OIDC running alongside custom scripts; `document.write()` in gate does not prevent `bundle.js` from loading | Server logs (two concurrent `/authorize` flows), `siwx-gate.js` |
| Login succeeds on server but Element shows error or loops | Auth code consumed by wrong handler; Element's native OIDC and `siwx-callback.js` race to exchange the single-use code | Browser console, `siwx-callback.js` vs Element bundle |
| Constant `401` log noise after redeploy | Element caches stale `client_id` in localStorage; invalidated by Redis wipe on redeploy | Element localStorage, Redis `clients/` keys |
