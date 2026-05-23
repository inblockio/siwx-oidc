# Element X QR Code Login: Protocol Specification Reference

Detailed protocol specifications for MSC4108, MSC4388, MSC4341, and RFC 8628 as they
apply to siwx-oidc + Synapse + Element X QR code login.

## MSC Architecture (Three MSCs)

| MSC | Purpose | Status (as of 2026-05) | Spec version |
|-----|---------|------------------------|--------------|
| MSC4108 | Overall QR code sign-in + E2EE setup flow | PR open, rework in progress | -- |
| MSC4341 | RFC 8628 Device Authorization Grant for Matrix | Merged into Matrix v1.18 | Stable |
| MSC4388 | Secure out-of-band rendezvous channel (HPKE) | PR open, split from MSC4108 | Unstable |

Superseded MSCs (removed from Element Web v1.11.84):
- MSC3886 (simple rendezvous) -- replaced by MSC4388
- MSC3903 (X25519 ECDH secure channel) -- replaced by MSC4388
- MSC3906 (sign-in + E2EE via QR) -- replaced by MSC4108

## Two Versions of MSC4108

### 2024 Version (ECIES, compatible with msc3861)

- Discovery: `unstable_features.org.matrix.msc4108 = true` in `GET /_matrix/client/versions`
- Encryption: ECIES
- Synapse config: `experimental_features.msc4108_enabled: true`
- Compatible with: `experimental_features.msc3861` (what siwx-oidc uses)
- First available: Synapse 1.106.0 (2024-04-30)
- Rendezvous endpoints:
  - `POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous` (create session)
  - `GET/PUT/DELETE /_synapse/client/rendezvous/{session_id}` (session management)

### 2025 Version (HPKE, requires matrix_authentication_service)

- Discovery: `GET /_matrix/client/v1/rendezvous`
- Encryption: HPKE (RFC 9180)
- Synapse config: `experimental_features.msc4388_mode: "open"` or `"authenticated"`
- Requires: `matrix_authentication_service` config block (NOT compatible with `msc3861`)
- Rendezvous endpoints:
  - `POST /_matrix/client/unstable/io.element.msc4388/rendezvous`
  - `GET/PUT/DELETE /_matrix/client/unstable/io.element.msc4388/rendezvous/{id}`

**siwx-oidc must use the 2024 version.** The 2025 version requires the
`matrix_authentication_service` config block, which is incompatible with siwx-oidc's
`experimental_features.msc3861` approach.

## Complete QR Code Login Flow (MSC4108 2024 + RFC 8628)

### Actors

- **Existing device (E):** Desktop browser, already logged in via Ethereum wallet
- **New device (N):** Element X mobile app, wants to log in
- **Synapse:** Homeserver with MSC4108 rendezvous server built in
- **siwx-oidc:** OIDC provider (must implement RFC 8628)

### Phase 1: Secure Channel Establishment

```
E: Generate ephemeral Curve25519 keypair (Ep, Es)
E: POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous
   -> { id, sequence_token, expires_in_ms }
E: Display QR code containing:
   - Ephemeral public key (Ep, 32 bytes)
   - Rendezvous session ID
   - Homeserver base URL
   - Intent byte (0x01 = existing device scanning)

N: Scan QR code, extract Ep, rendezvous ID, base URL
N: Generate ephemeral Curve25519 keypair (Np, Ns)
N: Compute SharedSecret = ECDH(Ns, Ep)
N: Encrypt "MATRIX_QR_CODE_LOGIN_INITIATE" -> LoginInitiateMessage
N: PUT /_synapse/client/rendezvous/{id} with LoginInitiateMessage

E: GET /_synapse/client/rendezvous/{id} -> LoginInitiateMessage
E: Compute SharedSecret = ECDH(Es, Np)
E: Decrypt and verify "MATRIX_QR_CODE_LOGIN_INITIATE"
E: Encrypt "MATRIX_QR_CODE_LOGIN_OK" -> LoginOkMessage
E: PUT /_synapse/client/rendezvous/{id} with LoginOkMessage

N: GET /_synapse/client/rendezvous/{id} -> LoginOkMessage
N: Decrypt and verify "MATRIX_QR_CODE_LOGIN_OK"
N: Compute CheckCode (two-digit: first digit 1-9, second digit 0-9)
N: Display: "Enter code XY on your other device"

E: Compute same CheckCode independently
E: Prompt user to enter the code displayed on N
E: User enters code -> verified if match
```

### Phase 2: Login Protocol Negotiation

```
N: GET /_matrix/client/v1/auth_metadata (from base URL in QR)
   -> Verify grant_types_supported includes device_code
   -> Get device_authorization_endpoint

N: POST {device_authorization_endpoint}
   client_id={client_id}&scope=openid+urn:matrix:client:api:*+urn:matrix:client:device:{DEVICE_ID}
   -> { device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval }

N: Send via rendezvous (encrypted):
   {
     "type": "m.login.protocol",
     "protocol": "device_authorization_grant",
     "device_authorization_grant": {
       "verification_uri": "https://siwx-oidc.example.com/device",
       "verification_uri_complete": "https://siwx-oidc.example.com/device?user_code=123456"
     },
     "device_id": "ABCDEFGH"
   }
```

### Phase 3: User Consent and Token Acquisition

```
E: Receive m.login.protocol via rendezvous
E: Verify device_id does not already exist: GET /_matrix/client/v3/devices/{device_id} -> 404
E: Open verification_uri_complete in system browser
E: Send via rendezvous: { "type": "m.login.protocol_accepted" }

   --- User approves on the /device page (wallet signature or passkey) ---

N: Poll POST /token with grant_type=urn:ietf:params:oauth:grant-type:device_code
   -> authorization_pending (keep polling at interval)
   -> 200 { access_token, refresh_token, id_token, expires_in }

N: Send via rendezvous: { "type": "m.login.success" }
```

### Phase 4: E2EE Secret Sharing

```
E: Verify device exists: GET /_matrix/client/v3/devices/{device_id} -> 200

E: Send via rendezvous (encrypted):
   {
     "type": "m.login.secrets",
     "cross_signing": {
       "master_key": "<base64>",
       "self_signing_key": "<base64>",
       "user_signing_key": "<base64>"
     },
     "backup": {
       "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
       "key": "<base64>",
       "backup_version": "1"
     }
   }

N: Store secrets, generate cross-signing signature
N: POST /_matrix/client/v3/keys/upload (device keys + self-signature, atomic)
```

## QR Code Binary Format (MSC4108 2024)

Binary-mode QR code, error correction level Q:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 6 bytes | ASCII `MATRIX` (stable) or prefix for unstable |
| 6 | 1 byte | Type: `0x03` |
| 7 | 1 byte | Intent: `0x00` = new device, `0x01` = existing device |
| 8 | 32 bytes | Ephemeral Curve25519 public key (raw bytes) |
| 40 | 2 bytes | Rendezvous ID length (big-endian uint16) |
| 42 | variable | Rendezvous session ID (UTF-8) |
| varies | 2 bytes | Base URL length (big-endian uint16) |
| varies | variable | Homeserver base URL (UTF-8) |

## RFC 8628 Device Authorization Grant

### Endpoints Required in siwx-oidc

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/device_authorization` | POST | Device requests codes |
| `/device` | GET/POST | User-facing approval page |
| `/token` | POST | Extended with `device_code` grant type |

### Device Authorization Request

```http
POST /device_authorization HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&scope=openid+urn:matrix:client:api:*+urn:matrix:client:device:{DEVICE_ID}
```

### Device Authorization Response

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://siwx-oidc.example.com/device",
  "verification_uri_complete": "https://siwx-oidc.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}
```

### Token Endpoint Extension

Request:
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id={client_id}
```

Polling responses:

| HTTP | Error code | Meaning | Client action |
|------|------------|---------|---------------|
| 400 | `authorization_pending` | User has not yet approved | Continue polling |
| 400 | `slow_down` | Polling too fast | Increase interval by 5s |
| 400 | `access_denied` | User denied | Stop, show error |
| 400 | `expired_token` | Device code expired | Stop, restart flow |
| 200 | -- | Success | Use tokens |

### OIDC Discovery Additions

```json
{
  "device_authorization_endpoint": "https://siwx-oidc.example.com/device_authorization",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ]
}
```

### Redis Keys (proposed schema for siwx-oidc)

| Key pattern | TTL | Content |
|-------------|-----|---------|
| `device_code:{code}` | `expires_in` | `{ user_code, client_id, scope, status, did, device_id }` |
| `user_code:{code}` | `expires_in` | `{ device_code }` (reverse lookup) |

Status values: `pending`, `approved`, `denied`

### Approval Page (/device)

The approval page is where siwx-oidc's unique value shows: instead of username/password,
the user approves with their Ethereum wallet (CAIP-122 signature) or passkey (WebAuthn).

Flow:
1. User visits `/device` (from `verification_uri_complete`)
2. Page shows: "A device wants to log in. Code: WDJB-MJHT. Approve with your wallet?"
3. User signs with MetaMask or uses passkey
4. Server verifies signature/ceremony, marks `device_code` status as `approved`
5. Server stores the verified DID in the device_code entry
6. Next poll from Element X at `/token` returns tokens

### Rendezvous Channel Properties (built into Synapse)

- In-memory storage (not persistent across restarts)
- Capacity: 100 concurrent sessions
- Max payload: 4096 bytes per message
- Session TTL: 60 seconds
- No worker support (main process only)
- Concurrency control via `sequence_token` (compare-and-swap, 409 on mismatch)

## Rendezvous Message Types

| Message | Sender | Purpose |
|---------|--------|---------|
| `m.login.protocols` | Existing device | Announce available protocols + base URL |
| `m.login.protocol` | New device | Choose protocol, send verification URIs + device_id |
| `m.login.protocol_accepted` | Existing device | Acknowledge, browser opened |
| `m.login.success` | New device | Token obtained |
| `m.login.declined` | New device | User denied |
| `m.login.failure` | Either | Error (see reason codes below) |
| `m.login.secrets` | Existing device | Cross-signing + backup keys |

Failure reasons: `authorization_expired`, `device_already_exists`, `device_not_found`,
`unexpected_message_received`, `unsupported_protocol`, `user_cancelled`,
`unable_to_open_verification_uri`

## Security Model

Threat model defends against:
- **Dolev-Yao attacker** (full network control without QR access): cannot derive shared
  secret without scanning the QR code
- **Shoulder-surfing attacker** (can scan QR): thwarted at CheckCode step; attacker
  cannot complete the two-digit verification
- **Malicious rendezvous server**: AAD binding prevents payload substitution

CheckCode: two digits (first 1-9, second 0-9) = 90 possibilities. Sufficient for MITM
detection given physical proximity requirement.

## Sources

- [MSC4108](https://github.com/matrix-org/matrix-spec-proposals/pull/4108)
- [MSC4341](https://github.com/matrix-org/matrix-spec-proposals/pull/4341) (merged, Matrix v1.18)
- [MSC4388](https://github.com/matrix-org/matrix-spec-proposals/pull/4388)
- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- [Synapse MSC4108 tracking](https://github.com/element-hq/synapse/issues/19434)
- [Are We OIDC Yet](https://areweoidcyet.com/client-implementation-guide/device-code-grant/)
- [MAS device-code-grant.sh](https://github.com/element-hq/matrix-authentication-service/blob/main/misc/device-code-grant.sh)
