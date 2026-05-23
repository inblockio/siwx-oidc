# RFC 8628 Device Authorization Grant for siwx-oidc

**Date:** 2026-05-23
**Branch:** `element-x-support` (both `siwx-oidc` and `siwx-oidc-matrix-server`)
**Skill:** `/element-x-qr-code-specialist` (setup/troubleshooting reference)
**Protocol spec:** `docs/element-x-qr-code-protocol-spec.md`
**Phase:** 3 of PLAN_webauthn.md
**Goal:** Element X mobile can scan a QR code on desktop Element Web and bind a new session to the same Ethereum wallet account.

---

## Context

siwx-oidc is a CAIP-122-to-OIDC bridge that replaces MAS entirely for Matrix Synapse
via MSC3861 delegated auth. Users log in with Ethereum wallets or passkeys. The server
currently supports two OAuth2 grant types: `authorization_code` and `refresh_token`.

Element X mobile supports QR code login via MSC4108, which requires the OIDC provider
to implement RFC 8628 (Device Authorization Grant). This is the missing piece: once
siwx-oidc supports the device code grant, Element X can scan a QR code displayed by
Element Web and obtain tokens for the same account.

The 2024 version of MSC4108 (ECIES encryption) is the one compatible with siwx-oidc's
`experimental_features.msc3861` config. The 2025 version (MSC4388/HPKE) requires the
`matrix_authentication_service` block and is NOT compatible.

---

## Architecture (what exists, what's new)

```
Existing (working):
  Element Web → GET /authorize → sign CAIP-122 → GET /sign_in → POST /token
  (authorization_code grant, PKCE, opaque mat_/mcr_ tokens, Synapse device lifecycle)

New (this plan):
  Element X → POST /device_authorization → get device_code + user_code
  Element X → poll POST /token (device_code grant) → wait for approval
  Desktop user → GET /device?user_code=... → approve with wallet/passkey
  → device_code status flips to approved → Element X gets tokens
```

The device code grant reuses the existing token issuance infrastructure: opaque tokens,
`TokenMetadata`, Synapse device provisioning, and introspection. The only new code is
the device authorization endpoint, the approval page, and the token grant type handler.

---

## Acceptance Criteria

1. `POST /device_authorization` returns `device_code`, `user_code`, `verification_uri`,
   `verification_uri_complete`, `expires_in`, `interval`
2. `GET /device` serves an approval page; `POST /device` accepts wallet/passkey proof
3. `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` returns
   tokens when approved, `authorization_pending` while waiting, `access_denied` on denial,
   `expired_token` on timeout, `slow_down` on fast polling
4. `/.well-known/openid-configuration` advertises `device_authorization_endpoint` and
   `urn:ietf:params:oauth:grant-type:device_code` in `grant_types_supported`
5. Synapse `msc4108_enabled: true` is set in the matrix server entrypoint
6. Reverse proxy passes rendezvous endpoints to Synapse
7. End-to-end: Element Web "Link new device" -> Element X scans QR -> approval ->
   Element X logged in with same DID, E2EE keys transferred

---

## Implementation Plan

### Phase 3a: Data model + Redis schema

**New struct: `DeviceCodeEntry`**

Add to `src/db/mod.rs` after `TokenMetadata` (line ~82):

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceCodeEntry {
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub status: DeviceCodeStatus,
    pub did: Option<String>,        // Set when approved
    pub device_id: Option<String>,  // Set when approved
    pub last_poll: Option<i64>,     // Unix timestamp, for slow_down detection
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
}
```

**New DBClient trait methods** (add to trait in `src/db/mod.rs` line ~84):

```rust
async fn set_device_code(&self, device_code: &str, entry: &DeviceCodeEntry, ttl: u64) -> Result<()>;
async fn get_device_code(&self, device_code: &str) -> Result<Option<DeviceCodeEntry>>;
async fn update_device_code(&self, device_code: &str, entry: &DeviceCodeEntry, ttl: u64) -> Result<()>;
async fn delete_device_code(&self, device_code: &str) -> Result<()>;
async fn get_device_code_by_user_code(&self, user_code: &str) -> Result<Option<(String, DeviceCodeEntry)>>;
async fn set_user_code_mapping(&self, user_code: &str, device_code: &str, ttl: u64) -> Result<()>;
async fn delete_user_code_mapping(&self, user_code: &str) -> Result<()>;
```

**Redis implementation** (add to `src/db/redis.rs`):

Key patterns:
- `device_codes/{device_code}` with TTL = `expires_in` (default 1800s)
- `user_codes/{user_code}` with TTL = `expires_in` (reverse lookup, stores device_code string)

Constants to add to `src/db/mod.rs`:
```rust
pub const DEVICE_CODE_LIFETIME: u64 = 1800;  // 30 minutes
pub const DEVICE_CODE_INTERVAL: u64 = 5;     // minimum polling interval
```

**Test:** Unit test for DeviceCodeEntry serialization roundtrip.

---

### Phase 3b: Device authorization endpoint

**New file: `src/device_auth.rs`**

**Endpoint: `POST /device_authorization`**

```rust
#[derive(Deserialize)]
pub struct DeviceAuthRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub async fn device_authorization(
    State(state): State<AppState>,
    Form(form): Form<DeviceAuthRequest>,
) -> Result<Json<DeviceAuthResponse>, CustomError>
```

Logic:
1. Validate `client_id` exists in Redis (`db_client.get_client()`)
2. Generate `device_code`: reuse `generate_opaque_token("dvc_")` pattern from `introspect.rs:32`
3. Generate `user_code`: 8-char base-20 (`BCDFGHJKLMNPQRSTVWXZ`), hyphenated as `XXXX-XXXX`
4. Parse scope (default `"openid"`)
5. Store `DeviceCodeEntry` in Redis with TTL
6. Store user_code -> device_code mapping in Redis with same TTL
7. Return `DeviceAuthResponse`

**user_code generation:**
```rust
fn generate_user_code() -> String {
    const CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut rng = thread_rng();
    let code: String = (0..8).map(|_| CHARSET[rng.gen_range(0..20)] as char).collect();
    format!("{}-{}", &code[..4], &code[4..])
}
```

**Router** (add to `src/axum_lib.rs` line ~570):
```rust
.route("/device_authorization", post(device_auth::device_authorization))
```

**Tests:**
- `device_authorization` returns valid response with all required fields
- Invalid `client_id` returns 400
- `user_code` format matches `XXXX-XXXX` pattern

---

### Phase 3c: Approval page (`GET/POST /device`)

**Endpoint: `GET /device`** (serves HTML approval page)

The approval page must let the user authenticate with their wallet or passkey, then
approve the device login. Two approaches:

**Option A (recommended): Minimal standalone HTML page**

Serve a small HTML page from `js/ui/public/device.html` (or inline in the Rust handler)
that:
1. Reads `user_code` from query string (or prompts user to enter it)
2. Displays: "A device wants to sign in. Code: XXXX-XXXX"
3. Offers wallet sign-in (reuse the CAIP-122 flow) or passkey
4. On successful auth, POSTs to `/device` with the proof + user_code

**Option B: Redirect-based (simpler but less elegant)**

Redirect to the existing `/authorize` flow with a special `device_user_code` parameter.
After sign_in completes, instead of redirecting to the client, approve the device code.

**Recommended: Option A** for cleaner separation. The page can be minimal since it only
needs to verify identity, not complete an OIDC flow.

**Endpoint: `POST /device`** (processes approval)

```rust
#[derive(Deserialize)]
pub struct DeviceApproveRequest {
    pub user_code: String,
    pub did: String,
    pub message: String,
    pub signature: String,
    // OR for passkey:
    pub verified_did: Option<String>,
    pub action: String,  // "approve" or "deny"
}

pub async fn device_approve(
    State(state): State<AppState>,
    Form(form): Form<DeviceApproveRequest>,
) -> Result<Html<String>, CustomError>
```

Logic:
1. Look up `user_code` -> `device_code` mapping
2. Look up `DeviceCodeEntry`
3. Verify the authentication proof (CAIP-122 signature or WebAuthn)
4. If `action == "approve"`: set status to `Approved`, store DID
5. If `action == "deny"`: set status to `Denied`
6. Return confirmation HTML

**Alternative: WebAuthn approval flow**

For passkey approval, the page would need to call `/webauthn/authenticate/start` and
`/webauthn/authenticate/finish` first (existing endpoints), then POST to `/device`
with the `verified_did` from the session. This reuses the existing WebAuthn ceremony
infrastructure.

**Router** (add to `src/axum_lib.rs`):
```rust
.route("/device", get(device_auth::device_page).post(device_auth::device_approve))
```

**Tests:**
- Approval with valid user_code + signature sets status to `Approved`
- Denial sets status to `Denied`
- Invalid user_code returns 404
- Expired user_code returns 400
- Invalid signature returns 401

---

### Phase 3d: Token endpoint extension (device_code grant)

**Modify: `src/oidc.rs`**

`CoreGrantType` from `openidconnect 4.0.1` already has a first-class `DeviceCode` variant
that deserializes from `"urn:ietf:params:oauth:grant-type:device_code"`. No `Extension`
matching needed. Just add `CoreGrantType::DeviceCode => { ... }` to the match.

**New fields in `TokenForm`** (add to struct at `oidc.rs:366`):
```rust
pub device_code: Option<String>,  // For device_code grant
```

**New function: `token_device_code()`**

```rust
async fn token_device_code(
    form: &TokenForm,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
    synapse_client: &Option<Arc<SynapseClient>>,
) -> Result<CoreTokenResponse, CustomError>
```

Logic:
1. Require `device_code` and `client_id` in form
2. Look up `DeviceCodeEntry` in Redis
3. Validate `client_id` matches
4. Check rate limiting: if `last_poll` is less than `interval` seconds ago, return
   `slow_down` error and update `last_poll`
5. Update `last_poll` timestamp
6. Match on status:
   - `Pending`: return 400 `{"error": "authorization_pending", "error_description": "..."}`
   - `Denied`: delete device code, return 400 `{"error": "access_denied", "error_description": "..."}`
   - `Approved`: proceed to token issuance
7. On approval:
   - Extract DID from `DeviceCodeEntry`
   - Run Synapse device lifecycle (reuse code from `sign_in`):
     - `delete_device` (old device if exists)
     - Generate `SIWX_{uuid8}` device ID
     - `provision_user` (if new)
     - `upsert_device`
     - `allow_cross_signing_reset`
   - Generate opaque access token (`mat_`) and refresh token (`mcr_`)
   - Store `TokenMetadata` in Redis
   - Sign ES256 ID token
   - Delete device code and user code from Redis
   - Return token response

**Error responses** (RFC 8628 Section 3.5):

RFC 8628 error codes (`authorization_pending`, `slow_down`, `expired_token`) are not
standard OAuth2 error types. Use `CoreErrorResponseType::Extension(s)` for these:

```rust
fn device_code_error(error: &str, description: &str) -> CustomError {
    CustomError::BadRequestToken(TokenError {
        error: CoreErrorResponseType::Extension(error.to_string()),
        error_description: description.to_string(),
    })
}
```

`CoreErrorResponseType` has an `Extension(String)` variant. The `BadRequestToken` error
handler in `axum_lib.rs:78` serializes it as `{"error": "...", "error_description": "..."}`,
which is exactly the format RFC 8628 requires.

**Integration with token() dispatcher** (modify `oidc.rs:385-398`):

```rust
match form.grant_type {
    CoreGrantType::AuthorizationCode => { ... },
    CoreGrantType::RefreshToken => { ... },
    CoreGrantType::DeviceCode => {
        token_device_code(&form, signing_key, config, db_client, synapse_client).await
    },
    _ => Err(CustomError::BadRequestToken(TokenError { ... })),
}
```

**Refactor: extract Synapse device lifecycle**

The device provisioning logic in `sign_in()` (lines 1108-1155) should be extracted into
a shared function so both `sign_in` and `token_device_code` can use it:

```rust
pub async fn provision_synapse_device(
    did: &str,
    synapse_client: &SynapseClient,
    db_client: &DBClientType,
) -> Result<(String, String), CustomError>  // Returns (device_id, localpart)
```

This function:
1. Computes localpart from DID (replace colons with dashes, lowercase)
2. Deletes old device if exists
3. Generates new `SIWX_{uuid8}` device ID
4. Provisions user if new
5. Upserts device
6. Calls `allow_cross_signing_reset`
7. Stores device ID mapping
8. Returns `(device_id, localpart)`

**Tests:**
- `authorization_pending` response when status is `Pending`
- `access_denied` response when status is `Denied`
- `expired_token` response when device code is expired (not found in Redis)
- `slow_down` response when polling too fast
- Successful token issuance when status is `Approved`
- Token response includes `access_token`, `refresh_token`, `id_token`
- Token introspection works for device-code-issued tokens
- Synapse device provisioning is called on approval

---

### Phase 3e: OIDC Discovery update

**Modify: `src/axum_lib.rs` lines 126-140**

In `provider_metadata()`, update the JSON additions:

```rust
// Line 136: add device_code to grant_types
j["grant_types_supported"] = json!([
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
]);

// Add new field:
j["device_authorization_endpoint"] = json!(format!("{}/device_authorization", base_url));
```

**Test:**
- `GET /.well-known/openid-configuration` includes `device_authorization_endpoint`
- `grant_types_supported` includes all three grant types

---

### Phase 3f: Synapse MSC4108 config (siwx-oidc-matrix-server repo)

**Modify: `entrypoints/matrix_server.sh`**

Add after the existing MSC3861 config block (after line ~27):

```bash
# Enable QR code login rendezvous server (MSC4108)
yq -i ".experimental_features.msc4108_enabled = true" /data/homeserver.yaml
```

**Modify: `Caddyfile.local`** (and production Caddyfile if separate)

Add explicit rendezvous routes before the catch-all handle block:

```caddyfile
handle /_matrix/client/unstable/org.matrix.msc4108/* {
    reverse_proxy matrix_synapse:8080
}
handle /_synapse/client/rendezvous/* {
    reverse_proxy matrix_synapse:8080
}
```

**Verify:** After restarting Synapse:
```bash
curl -s https://{MATRIX_HOST}/_matrix/client/versions | jq '.unstable_features["org.matrix.msc4108"]'
# Expected: true
```

---

### Phase 3g: End-to-end integration test

**Manual test protocol:**

1. Deploy updated siwx-oidc + Synapse with MSC4108
2. Log in to Element Web with Ethereum wallet (existing flow)
3. Go to Settings > Sessions > "Link new device"
4. Verify QR code appears
5. Open Element X on mobile, tap "Sign in with QR code"
6. Scan QR code
7. Verify two-digit CheckCode appears on Element X
8. Enter CheckCode on desktop
9. Desktop opens `/device` approval page
10. Approve with MetaMask signature
11. Element X completes login
12. Verify:
    - Same DID/username on both devices
    - E2EE messages readable on Element X
    - Encrypted messages sent from Element X readable on desktop
    - Token introspection works for Element X's token
    - Refresh token rotation works

**Automated test** (if Redis is available):

Add an integration test in `src/oidc.rs` (alongside existing `e2e_flow` test):

```rust
#[tokio::test]
#[ignore] // Requires Redis
async fn device_code_flow() {
    // 1. Register client
    // 2. POST /device_authorization -> get device_code, user_code
    // 3. Poll POST /token -> expect authorization_pending
    // 4. Approve via POST /device (simulate wallet signature)
    // 5. Poll POST /token -> expect success
    // 6. Verify token metadata
    // 7. Verify introspection
}
```

---

## Code References (exact locations)

| What | File | Line(s) |
|------|------|---------|
| Token function (dispatcher) | `src/oidc.rs` | 378-398 |
| TokenForm struct | `src/oidc.rs` | 366-376 |
| token_authorization_code() | `src/oidc.rs` | 480-674 |
| token_refresh() | `src/oidc.rs` | 400-478 |
| CustomError enum | `src/oidc.rs` | 146-162 |
| TokenError struct | `src/oidc.rs` | 140-144 |
| OIDC paths (constants) | `src/oidc.rs` | 61-70 |
| Provider metadata handler | `src/axum_lib.rs` | 126-140 |
| grant_types_supported | `src/axum_lib.rs` | 136 |
| Router registration | `src/axum_lib.rs` | 558-611 |
| AppState struct | `src/axum_lib.rs` | 49-58 |
| Token handler (axum) | `src/axum_lib.rs` | 142-185 |
| Error response conversion | `src/axum_lib.rs` | 78-117 |
| Config struct | `src/config.rs` | 8-48 |
| Config loading (Figment) | `src/axum_lib.rs` | 452-456 |
| DBClient trait | `src/db/mod.rs` | 84-117 |
| CodeEntry struct | `src/db/mod.rs` | 26-42 |
| SessionEntry struct | `src/db/mod.rs` | 52-61 |
| TokenMetadata struct | `src/db/mod.rs` | 64-82 |
| TTL constants | `src/db/mod.rs` | 15-23 |
| Redis set_ex_raw | `src/db/redis.rs` | 33-43 |
| Redis set_raw | `src/db/redis.rs` | 46-56 |
| Redis key prefixes | `src/db/redis.rs` | 142, 179, 281, 324 |
| generate_opaque_token() | `src/introspect.rs` | 32-38 |
| Introspect endpoint | `src/introspect.rs` | 67-125 |
| SynapseClient methods | `src/synapse_client.rs` | provision_user, upsert_device, delete_device |
| Device lifecycle in sign_in | `src/oidc.rs` | 1108-1155 |
| Device ID generation | `src/oidc.rs` | 1123 |
| PLAN_webauthn Phase 3 | `PLAN_webauthn.md` | 182-187 |

## Dependencies

No new crate dependencies required. All cryptographic primitives, Redis operations,
and HTTP framework features needed are already available in the workspace.

**Confirmed:** `openidconnect 4.0.1`'s `CoreGrantType` enum has a first-class `DeviceCode`
variant that deserializes from `"urn:ietf:params:oauth:grant-type:device_code"`. No
workarounds needed. `CoreErrorResponseType` has `Extension(String)` for RFC 8628 error
codes (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`).

## Boundary Conditions

- **DO NOT** implement MSC4388 (2025 rendezvous); it requires `matrix_authentication_service`
  config which is incompatible with the current `msc3861` setup
- **DO NOT** add `msc4108_delegation_endpoint` and `msc4108_enabled` simultaneously
  (Synapse raises ConfigError)
- **DO NOT** build Docker images locally (use CI); the machine is resource-constrained
- The approval page (`/device`) must serve from the same origin as `SIWEOIDC_BASE_URL`
  for cookie/CORS to work
- Rendezvous sessions are in-memory in Synapse (lost on restart, capacity 100, TTL 60s)
- User codes must avoid vowels to prevent forming offensive words (base-20 charset)
- Device codes must be high-entropy (32+ chars) since they are not displayed to users

## Execution Order

```
3a (data model) ──→ 3b (device_auth endpoint) ──→ 3d (token extension)
                                                        |
                ──→ 3c (approval page) ─────────────────┘
                                                        |
                ──→ 3e (OIDC discovery) ────────────────┘
                                                        |
                ──→ 3f (Synapse config) ────────────────→ 3g (e2e test)
```

3a must be first (others depend on it). 3b, 3c, 3e, 3f can be parallelized after 3a.
3d depends on 3b and 3c. 3g is the final integration test.

## Refactoring Note

The Synapse device lifecycle code in `sign_in()` (lines 1108-1155 of `oidc.rs`) should
be extracted into a shared `provision_synapse_device()` function during Phase 3d. Both
`sign_in` and `token_device_code` need identical provisioning logic. This is a clean
refactor that reduces duplication and makes the code more maintainable.
