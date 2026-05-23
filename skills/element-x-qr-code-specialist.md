Element X QR code login specialist for siwx-oidc + Synapse + Element X mobile.

Use when setting up, debugging, or implementing QR code login between a desktop
Ethereum wallet session and Element X mobile. Covers RFC 8628 (Device Authorization
Grant), MSC4108 (QR code sign-in), MSC4341 (Matrix device code grant), and the
rendezvous channel.

For detailed protocol specifications, see `docs/element-x-qr-code-protocol-spec.md`.

---

## Architecture Overview

```
Element X (mobile)                    Element Web (desktop, logged in)
     |                                       |
     |-- scan QR code <-- display QR code ---|
     |                                       |
     |===== encrypted rendezvous channel ====|  (via Synapse rendezvous server)
     |                                       |
     |-- POST /device_authorization -------->|  siwx-oidc
     |   (get device_code + user_code)       |
     |                                       |
     |-- send verification_uri via channel ->|
     |                                       |-- open /device page in browser
     |                                       |-- user approves (wallet/passkey)
     |                                       |
     |-- poll POST /token ------------------>|  siwx-oidc
     |   (until approved)                    |
     |                                       |
     |<======= E2EE secrets transfer =======|  (cross-signing keys via channel)
     |                                       |
     v                                       v
  Logged in on Element X               Session bound to same DID
  with same account + E2EE
```

### Components

| Component | Role | Where |
|-----------|------|-------|
| **Element X** (iOS/Android) | New device, scans QR, polls for token | Mobile app |
| **Element Web** (desktop) | Existing device, displays QR, approves login, sends E2EE keys | Browser |
| **Synapse** | Homeserver + built-in rendezvous server (in-memory) | `siwx-oidc-matrix-server` |
| **siwx-oidc** | OIDC provider, issues tokens via RFC 8628 device grant | `siwx-oidc` repo |
| **Redis** | Session, token, device code storage | `siwx-oidc-matrix-server` |

### Protocol Stack

| Layer | Protocol | Purpose | Status |
|-------|----------|---------|--------|
| Transport | MSC4108 rendezvous (2024 version) | Encrypted device-to-device relay via Synapse | Built into Synapse >= 1.106.0 |
| Auth | RFC 8628 / MSC4341 | Device Authorization Grant | Implemented in siwx-oidc |
| Tokens | MSC3861 | OIDC delegated auth, token introspection | Already implemented |
| E2EE | MSC4108 Phase 4 | Cross-signing key transfer via rendezvous | Handled by Element clients |

---

## Version Compatibility (CRITICAL)

There are two versions of MSC4108. **siwx-oidc must use the 2024 version.**

| Version | Encryption | Synapse config | Compatible with msc3861? |
|---------|------------|----------------|--------------------------|
| **2024** | ECIES | `experimental_features.msc4108_enabled: true` | YES |
| 2025 | HPKE | `experimental_features.msc4388_mode` | NO (requires `matrix_authentication_service` block) |

The 2025 version (MSC4388) requires the `matrix_authentication_service` config block,
which is the stable MAS integration. siwx-oidc uses `experimental_features.msc3861`,
so only the 2024 version works.

---

## Implementation Status

| Component | Status | Blocker? |
|-----------|--------|----------|
| Synapse rendezvous server | Available (>= 1.106.0, current is 1.153.0+) | No |
| Synapse `msc4108_enabled` config | Deployed | No |
| Reverse proxy (Caddy) | Works | No |
| siwx-oidc: `POST /device_authorization` | Implemented | No |
| siwx-oidc: `POST /token` device_code grant | Implemented (honors client device_id from scope) | No |
| siwx-oidc: `GET /device` approval page | Implemented (wallet + passkey) | No |
| siwx-oidc: OIDC discovery update | Implemented | No |
| Element Web: "Link new device" UI | Available in production Element Web | No |
| Element X: QR code scanning | Available in production Element X | No |

---

## Setup Guide

### Prerequisites

- Synapse >= 1.106.0 (current `matrixdotorg/synapse:latest` satisfies this)
- siwx-oidc with RFC 8628 implemented (Phase 3 of PLAN_webauthn.md)
- Element Web with "Link new device" feature (production Element Web has this)
- Element X mobile app (production iOS/Android)
- Working MSC3861 delegated auth (already deployed)

### Step 1: Enable MSC4108 in Synapse (siwx-oidc-matrix-server repo)

Edit `entrypoints/matrix_server.sh`, add after the existing MSC3861 config block:

```bash
# Enable QR code login rendezvous server (MSC4108 2024 version)
yq -i ".experimental_features.msc4108_enabled = true" /data/homeserver.yaml
```

This enables:
- `POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous` (create session)
- `GET/PUT/DELETE /_synapse/client/rendezvous/{session_id}` (session management)
- `org.matrix.msc4108: true` in `GET /_matrix/client/versions`

The rendezvous server is in-memory with these defaults:
- 100 concurrent sessions
- 4KB max payload per message
- 60s session TTL
- 60s eviction interval

### Step 2: Verify reverse proxy passes rendezvous endpoints

In `Caddyfile.local` (or production Caddyfile), ensure the rendezvous paths reach
Synapse without compression mangling ETags. The existing catch-all `handle` block
should work, but for safety, add explicit blocks BEFORE the catch-all:

```caddyfile
handle /_matrix/client/unstable/org.matrix.msc4108/* {
    reverse_proxy matrix_synapse:8080
}
handle /_synapse/client/rendezvous/* {
    reverse_proxy matrix_synapse:8080
}
```

**ETag warning:** If Caddy's `encode zstd gzip` directive is applied to these paths,
it can alter ETags and break the rendezvous protocol's sequence_token compare-and-swap.
Either exclude these paths from compression or verify ETags pass through unmodified.

### Step 3: Implement RFC 8628 in siwx-oidc (the blocker)

See "Implementation Guide" section below for full details.

### Step 4: Update OIDC Discovery

In `src/oidc.rs`, update the `openid-configuration` response to include:

```json
{
  "device_authorization_endpoint": "{base_url}/device_authorization",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ]
}
```

### Step 5: Configure Element Web

Element Web needs to know the homeserver supports QR login. This is automatic when
Synapse advertises `org.matrix.msc4108: true` in `/versions`. No Element Web config
changes needed.

The "Link new device" option appears in the user menu (Security & Privacy or All
Settings > Sessions).

### Step 6: Test the flow

1. Log in to Element Web via Ethereum wallet (existing flow)
2. Go to Settings > Sessions > "Link new device" (or equivalent menu item)
3. Element Web displays a QR code
4. Open Element X on mobile, tap "Sign in with QR code"
5. Scan the QR code displayed on desktop
6. Element X shows a two-digit verification code
7. Enter the code on the desktop prompt
8. Desktop opens the siwx-oidc `/device` approval page
9. Approve with wallet signature or passkey
10. Element X completes login, receives E2EE keys
11. Verify Element X shows the same account, can read encrypted messages

---

## Configuration Reference

### siwx-oidc environment variables (new for RFC 8628)

| Var | Description | Default |
|-----|-------------|---------|
| `SIWEOIDC_DEVICE_CODE_EXPIRY` | Device code lifetime in seconds | `1800` (30 min) |
| `SIWEOIDC_DEVICE_CODE_INTERVAL` | Minimum polling interval in seconds | `5` |
| `SIWEOIDC_USER_CODE_LENGTH` | User code length (characters) | `6` |
| `SIWEOIDC_USER_CODE_CHARSET` | Character set for user codes | `BCDFGHJKLMNPQRSTVWXZ` (base-20, no vowels) |

### Synapse homeserver.yaml

```yaml
experimental_features:
  msc3861:
    enabled: true
    issuer: ${SIWEOIDC_BASE_URL}
    account_management_url: ${SIWEOIDC_BASE_URL}
    client_id: "0000000000000000000SYNAPSE"
    client_secret: ${MAS_SHARED_SECRET}
    admin_token: ${MAS_SHARED_SECRET}

  # QR code login (MSC4108 2024 version)
  msc4108_enabled: true
```

DO NOT set both `msc4108_enabled` and `msc4108_delegation_endpoint` (Synapse raises
ConfigError). Use `msc4108_delegation_endpoint` only if running a separate rendezvous
server (not needed; Synapse has one built in).

DO NOT set `msc4388_mode` (2025 version; incompatible with msc3861).

### Redis keys (new for RFC 8628)

| Key pattern | TTL | Content |
|-------------|-----|---------|
| `device_code:{code}` | `expires_in` | `{ user_code, client_id, scope, status, did, device_id }` |
| `user_code:{code}` | `expires_in` | `{ device_code }` (reverse lookup for approval page) |

Status: `pending` -> `approved` (with DID) or `denied`

---

## Implementation Guide: RFC 8628 in siwx-oidc

### New files

| File | Purpose |
|------|---------|
| `src/device_auth.rs` | Device authorization endpoint + approval page |

### Endpoint 1: POST /device_authorization

Accept: `application/x-www-form-urlencoded`

Parameters:
- `client_id` (required): registered client
- `scope` (optional): defaults to `openid`

Logic:
1. Validate client_id exists in Redis
2. Generate high-entropy `device_code` (32+ bytes, base62)
3. Generate human-readable `user_code` (6 chars, base-20: `BCDFGHJKLMNPQRSTVWXZ`, hyphenated: `WDJ-BMJ`)
4. Store `device_code:{code}` in Redis with TTL = `expires_in`
5. Store `user_code:{code}` in Redis with TTL = `expires_in` (reverse lookup)
6. Return JSON response

Response:
```json
{
  "device_code": "...",
  "user_code": "WDJ-BMJ",
  "verification_uri": "{base_url}/device",
  "verification_uri_complete": "{base_url}/device?user_code=WDJ-BMJ",
  "expires_in": 1800,
  "interval": 5
}
```

### Endpoint 2: GET /device (approval page)

An HTML page where the logged-in user approves the device login. This page reuses
the existing wallet/passkey auth UI.

Flow:
1. If `user_code` in query string, pre-fill it
2. User authenticates (wallet CAIP-122 signature or WebAuthn passkey)
3. Server verifies the authentication proof
4. Server looks up `user_code:{code}` to find the `device_code`
5. Server updates `device_code:{code}` status to `approved`, stores verified DID
6. Page shows "Device approved" confirmation

The approval page must verify the user's identity. It can use the same authentication
methods as the main login page (wallet or passkey).

### Endpoint 3: POST /token (device_code grant extension)

Add a new match arm for `grant_type=urn:ietf:params:oauth:grant-type:device_code`:

Parameters:
- `grant_type`: `urn:ietf:params:oauth:grant-type:device_code`
- `device_code`: the device code
- `client_id`: must match the original request

Logic:
1. Look up `device_code:{code}` in Redis
2. Validate `client_id` matches
3. Check status:
   - `pending`: return 400 `{ "error": "authorization_pending" }`
   - `denied`: return 400 `{ "error": "access_denied" }`, delete code
   - `approved`: proceed to token issuance, delete code
4. On approval:
   - Read DID from device_code entry
   - Run Synapse device lifecycle (same as sign_in: provision user, upsert device)
   - Issue opaque access token (`mat_...`) and refresh token (`mcr_...`)
   - Sign ES256 ID token with DID as `sub`
   - Return standard token response

Rate limiting: track last poll time per device_code. If polling faster than `interval`,
return 400 `{ "error": "slow_down" }`.

### OIDC Discovery update

In `src/oidc.rs`, update the `/.well-known/openid-configuration` response:

Add `"device_authorization_endpoint"` field and `"urn:ietf:params:oauth:grant-type:device_code"`
to `grant_types_supported`.

### Router update

In `src/axum_lib.rs`, add routes:

```rust
.route("/device_authorization", post(device_auth::device_authorization))
.route("/device", get(device_auth::device_page).post(device_auth::device_approve))
```

---

## Troubleshooting

### QR code does not appear in Element Web

| Check | How | Fix |
|-------|-----|-----|
| MSC4108 enabled in Synapse | `curl -s https://{MATRIX_HOST}/_matrix/client/versions \| jq '.unstable_features["org.matrix.msc4108"]'` | Must return `true`. Add `msc4108_enabled: true` to homeserver.yaml |
| Element Web version | Check Element Web version in Settings > Help & About | Must be recent enough to support MSC4108 (v1.11.84+ removed old MSC3906, uses MSC4108) |
| "Link new device" menu item | Settings > Sessions (or Security & Privacy) | If missing, Element Web may not detect MSC4108 support from Synapse |

### QR code scans but Element X shows error

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Unsupported protocol" | OIDC provider doesn't advertise device_code grant | Add `device_authorization_endpoint` and `urn:ietf:params:oauth:grant-type:device_code` to OIDC discovery |
| "Connection failed" | Rendezvous session expired (60s) | Retry; ensure network latency is low |
| "Rendezvous server not available" | Rendezvous endpoint not reachable | Check reverse proxy passes `/_matrix/client/unstable/org.matrix.msc4108/*` and `/_synapse/client/rendezvous/*` to Synapse |
| "Verification code mismatch" | MITM or user error | Retry from scratch |

### Device authorization fails

| Symptom | Cause | Fix |
|---------|-------|-----|
| 404 on `/device_authorization` | Endpoint not implemented | Implement RFC 8628 in siwx-oidc (Phase 3) |
| "Invalid client_id" | Client not registered | Element X must register via dynamic client registration first |
| "Unsupported grant type" | Token endpoint doesn't handle device_code | Add device_code grant to token handler |

### Approval page issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Approval page shows but wallet doesn't connect | Same-origin issues with wallet extension | Ensure `/device` page is served from `SIWEOIDC_BASE_URL` |
| "User code expired" | 30-minute TTL exceeded | Retry QR flow from scratch |
| "User code not found" | Redis flushed or wrong instance | Check `redis-cli KEYS 'user_code:*'` |

### Token polling fails

| Symptom | Cause | Fix |
|---------|-------|-----|
| Stuck on `authorization_pending` forever | User never approved on desktop | Check desktop browser opened the approval page |
| `expired_token` | Device code expired (30 min default) | Retry from scratch |
| `access_denied` | User explicitly denied | User must approve; check if correct account |
| `slow_down` | Polling faster than interval | Client should increase interval by 5s (Element X handles this) |

### E2EE key transfer fails

| Symptom | Cause | Fix |
|---------|-------|-----|
| Element X logged in but can't read encrypted messages | E2EE secrets not transferred | Check that existing device has cross-signing keys. Verify rendezvous channel stayed open long enough for Phase 4 |
| "Device not verified" on other devices | Self-signing failed | Element X should automatically self-sign during key upload. Check Synapse logs for `keys/upload` errors |
| "Unable to verify session" | Cross-signing reset needed | Run `allow_cross_signing_reset` (siwx-oidc does this during device provisioning) |

### Rendezvous channel issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| 409 `M_CONCURRENT_WRITE` | Sequence token mismatch | Client retries with fresh GET. Usually transient. |
| Sessions lost after Synapse restart | Rendezvous is in-memory only | Expected behavior; user must retry QR flow |
| "Capacity exceeded" | More than 100 concurrent rendezvous sessions | Unusual; check for leaked sessions or DoS |

### Reverse proxy ETag issues

If QR login works locally but fails behind Caddy/nginx:

```bash
# Test ETag preservation
curl -v -X POST "https://{MATRIX_HOST}/_matrix/client/unstable/org.matrix.msc4108/rendezvous" \
  -H "Content-Type: application/json" -d '{"data":""}' 2>&1 | grep -i etag

# Should see an ETag header in the response
# If missing or modified, disable compression for rendezvous paths
```

### Redis inspection for device codes

```bash
# List active device codes
redis-cli KEYS 'device_code:*'

# Inspect a device code
redis-cli GET 'device_code:{code}'

# List active user codes
redis-cli KEYS 'user_code:*'

# Check device code status
redis-cli GET 'device_code:{code}' | python3 -m json.tool
# Look for: "status": "pending" | "approved" | "denied"
```

### Diagnostic checklist

Run this sequence to verify the full stack:

```bash
# 1. Check Synapse supports MSC4108
curl -s "https://{MATRIX_HOST}/_matrix/client/versions" | \
  jq '.unstable_features["org.matrix.msc4108"]'
# Expected: true

# 2. Check OIDC discovery advertises device_code grant
curl -s "https://{SIWEOIDC_HOST}/.well-known/openid-configuration" | \
  jq '.grant_types_supported'
# Expected: includes "urn:ietf:params:oauth:grant-type:device_code"

# 3. Check device_authorization_endpoint is present
curl -s "https://{SIWEOIDC_HOST}/.well-known/openid-configuration" | \
  jq '.device_authorization_endpoint'
# Expected: "https://{SIWEOIDC_HOST}/device_authorization"

# 4. Test rendezvous endpoint
curl -s -X POST "https://{MATRIX_HOST}/_matrix/client/unstable/org.matrix.msc4108/rendezvous" \
  -H "Content-Type: application/json" -d '{"data":""}' | python3 -m json.tool
# Expected: { "id": "...", "sequence_token": "...", "expires_in_ms": ... }

# 5. Test device authorization endpoint
curl -s -X POST "https://{SIWEOIDC_HOST}/device_authorization" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=test&scope=openid" | python3 -m json.tool
# Expected: { "device_code": "...", "user_code": "...", ... }

# 6. Check Synapse logs for rendezvous activity
docker compose logs matrix_synapse 2>&1 | grep -i rendezvous | tail -10

# 7. Check siwx-oidc logs for device auth activity
docker compose logs siwx-oidc 2>&1 | grep -i device | tail -10
```

---

## User Flow Summary (for end users)

### First time: Desktop Ethereum login

1. Open Element Web in browser with MetaMask
2. Sign in with Ethereum wallet (existing CAIP-122 flow)
3. Account created with DID-based username

### Adding Element X mobile

1. On desktop Element Web: go to Settings > Sessions > "Link new device"
2. QR code appears on screen
3. On Element X mobile: tap "Sign in with QR code" on login screen
4. Point phone camera at desktop QR code
5. Element X shows a two-digit code (e.g., "42")
6. Enter "42" on the desktop prompt
7. Desktop opens approval page; approve with MetaMask signature
8. Element X completes login automatically
9. Encrypted messages are accessible on mobile

### Result

Both devices share the same Matrix account (same DID, same cross-signing identity).
The mobile device has its own device ID (`SIWX_{uuid}`) but is cross-signed by the
desktop device's keys, making it trusted in E2EE rooms.
