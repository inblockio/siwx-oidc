# siwx-oidc MSC3861 Compliance Audit

## Executive Summary

siwx-oidc implements MSC3861 and **replaces Matrix Authentication Service (MAS) entirely**. Synapse delegates all authentication to siwx-oidc via a shared secret. There is no MAS instance in the deployment.

The core MSC3861 contract is solid. All critical endpoints are implemented and functional. Two high-severity gaps exist that block native Element OIDC support. Several medium and low-severity items are documented for future improvement.

## Architecture: How It Works

```
Element Web / Element X
    |
    |  OIDC: siwx-oidc IS the OIDC Provider (issuer)
    v
siwx-oidc (Axum server + Redis)
    |
    |  MSC3861 admin API (shared secret auth)
    v
Synapse homeserver
```

**Key insight:** siwx-oidc is not an upstream IdP behind MAS. It implements the same MSC3861 contract MAS does. From Synapse's perspective, siwx-oidc and MAS are interchangeable.

**Why this design:** MAS has no wallet/DID support and none is planned. Rather than chaining two OIDC hops (Element to MAS to siwx-oidc), siwx-oidc implements the MSC3861 contract directly, cutting out the middleman.

### MSC3861 Mode Activation

When `SIWEOIDC_MAS_SHARED_SECRET` is set, the server switches to MSC3861 mode:

- Token issuance produces opaque `mat_`/`mcr_` tokens (not JWTs)
- Matrix-specific scopes are injected into tokens
- Synapse provisioning calls are made during sign-in
- The `/oauth2/introspect` endpoint becomes active

Without the shared secret, siwx-oidc acts as a plain OIDC provider with JWT tokens.

### Sign-in Flow (MSC3861 Mode)

1. Element does OIDC discovery against siwx-oidc (the issuer URL in Synapse config)
2. Element redirects to siwx-oidc's `/authorize`
3. User signs with wallet (CAIP-122) or passkey (WebAuthn) on the login page
4. siwx-oidc calls `/_synapse/mas/provision_user` and `/_synapse/mas/upsert_device`
5. siwx-oidc issues opaque `mat_` access token and `mcr_` refresh token
6. Element uses the `mat_` token with Synapse for all API calls
7. Synapse calls `POST /oauth2/introspect` on siwx-oidc to validate each request

## Implemented Features

### OIDC Endpoints

| Endpoint | Method | File | Status |
|---|---|---|---|
| `/.well-known/openid-configuration` | GET | `oidc.rs:171-236` | Complete |
| `/authorize` | GET | `oidc.rs:675-820` | Complete |
| `/sign_in` | GET | `oidc.rs:947-1158` | Complete |
| `/token` | POST | `oidc.rs:378-654` | Complete |
| `/userinfo` | GET/POST | `oidc.rs:1287-1360` | Complete |
| `/jwk` | GET | `oidc.rs:166-169` | Complete |
| `/register` | POST | `oidc.rs:1167-1216` | Complete |

### MSC3861-Specific Endpoints

| Endpoint | Method | File | Purpose |
|---|---|---|---|
| `/oauth2/introspect` | POST | `introspect.rs:67-119` | Token validation for Synapse |
| `/oauth2/revoke` | POST | `compat.rs:53-62` | Token revocation (RFC 7009) |

### Matrix Legacy Compat Endpoints

| Endpoint | Method | File | Purpose |
|---|---|---|---|
| `/_matrix/client/v3/login` | GET | `compat.rs:66-76` | Login flows discovery |
| `/_matrix/client/v3/logout` | POST | `compat.rs:80-91` | Session logout |
| `/_matrix/client/v3/refresh` | POST | `compat.rs:95-188` | Token refresh (Matrix format) |

### Synapse Admin API Calls (outbound)

| Endpoint Called | File | Purpose |
|---|---|---|
| `/_synapse/mas/provision_user` | `synapse_client.rs:37-58` | Create or update Matrix user |
| `/_synapse/mas/upsert_device` | `synapse_client.rs:63-94` | Create or update device |
| `/_synapse/mas/delete_device` | `synapse_client.rs:97-118` | Delete a device |
| `/_synapse/mas/allow_cross_signing_reset` | `synapse_client.rs:121-139` | Allow key reset on next login |
| `/_synapse/mas/is_localpart_available` | `synapse_client.rs:146-174` | Check username availability |
| `/_synapse/mas/sync_devices` | `synapse_client.rs:179-200` | Sync full device list (dead code) |

### Token Format (MSC3861 Mode)

| Token Type | Prefix | Length | Storage | TTL |
|---|---|---|---|---|
| Access token | `mat_` | 36 chars | Redis | 300s (5 min) |
| Refresh token | `mcr_` | 36 chars | Redis | 86400s (24h) |

Scopes embedded in tokens: `openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:{device_id}`

## Gap Analysis

### HIGH Severity

**1. `/authorize` rejects Matrix-specific scopes**

- Location: `oidc.rs:758-760`
- The authorize endpoint validates requested scopes against `[openid, profile]` and rejects anything else. Native OIDC Matrix clients (Element X, oidc-client-ts apps) request `urn:matrix:org.matrix.msc2967.client:api:*` as a scope, which gets rejected.
- Current workaround: The deployment uses a custom JavaScript gate (`siwx-redirect.js`) that only requests `scope=openid profile`, bypassing Element's built-in OIDC flow.
- Impact: Blocks native Element X OIDC support. The custom JS gate is a fragile workaround.
- Fix: Accept and pass through Matrix scopes, or silently ignore unknown scopes per RFC 6749 Section 3.3.

**2. Discovery metadata mismatch for introspection auth**

- Location: `axum_lib.rs:110`
- Discovery advertises `introspection_endpoint_auth_methods_supported: ["bearer"]`, but the Synapse deployment is configured with `client_secret_post`. The introspect endpoint code (`introspect.rs:78-84`) actually accepts both methods, so it works in practice.
- Impact: Spec violation. If Synapse ever validates discovery metadata, this breaks silently.
- Fix: Change discovery to `["client_secret_post", "bearer"]`.

### MEDIUM Severity

**3. `sub` claim inconsistency between ID token and introspection**

- ID token `sub` = full DID (e.g., `did:pkh:eip155:1:0xAbc...`)
- Introspection `sub` = localpart (e.g., `did-pkh-eip155-1-0xabc...`)
- These are different values for the same user. Works because Synapse binds the external_id on first use, but it violates the OIDC spec requirement that `sub` be consistent across endpoints.

**4. No `name` field in introspection response**

- Location: `introspect.rs:104-115`
- Newer Synapse versions read `name` from introspection to update display names dynamically. Without it, display names are only set during initial `provision_user` and never update afterward (e.g., if a user's ENS name changes).

**5. Only unstable Matrix scopes issued**

- Location: `oidc.rs:579-581`
- Tokens contain `urn:matrix:org.matrix.msc2967.client:...` (unstable MSC prefix). The stable versions are `urn:matrix:client:...`. Synapse 1.152 accepts both, but future Synapse versions may deprecate unstable scopes.

**6. `sync_devices` is dead code**

- Location: `synapse_client.rs:179-200`
- The method exists but is never called. The sign-in flow uses individual `upsert_device` calls. Not a bug, but unused code that should be either wired up or removed.

### LOW Severity

**7. No `/_matrix/client/v3/logout/all`**: Cannot revoke all sessions for a user at once. Only individual session logout is supported.

**8. No `delete_user` / `reactivate_user`**: Account deactivation is not supported. Not needed for current deployment but required for full user lifecycle management.

**9. No `account_management_url` in OIDC discovery**: MSC2965 specifies this field. Currently handled at the Synapse deployment level via `homeserver.yaml`, not by siwx-oidc.

**10. Token revocation does not delete Synapse devices**: `POST /oauth2/revoke` and `/v3/logout` delete the token from Redis but do not call `/_synapse/mas/delete_device`. Stale devices may appear in Synapse's device list until the next login (when the device is recycled).

**11. Display name is raw DID**: `provision_user` sets the display name to the full DID string. ENS names are resolved for OIDC claims but not passed to Synapse provisioning.

**12. 5-minute access token TTL**: Aggressive TTL means frequent refresh cycles. The custom JS gate does not implement automatic token refresh, so sessions may silently break after 5 minutes if refresh is not handled.

## Configuration Reference

| Variable | MSC3861 Role |
|---|---|
| `SIWEOIDC_MAS_SHARED_SECRET` | Enables MSC3861 mode. Must match Synapse's `auth_service` config. |
| `SIWEOIDC_BASE_URL` | Advertised as the OIDC issuer URL. Synapse resolves discovery from this. |
| Synapse `experimental_features.msc3861` | Must be enabled in Synapse for delegated auth. |
| Synapse `auth_service.issuer` | Must point to siwx-oidc's `BASE_URL`. |
| Synapse `auth_service.introspection_endpoint` | Must point to `/oauth2/introspect`. |

## Key Source Files

| File | Responsibility |
|---|---|
| `src/oidc.rs` | OIDC protocol logic: authorize, sign_in, token, userinfo |
| `src/introspect.rs` | MSC3861 token introspection (RFC 7662) |
| `src/compat.rs` | Matrix legacy endpoints and OAuth2 revocation |
| `src/synapse_client.rs` | Outbound calls to Synapse `/_synapse/mas/` admin API |
| `src/config.rs` | Configuration struct including `mas_shared_secret` |
| `src/axum_lib.rs` | Route registration and server startup |

## Recommendations

1. **Fix scope validation** at `/authorize` to unblock native Element OIDC (HIGH, enables Element X)
2. **Fix discovery metadata** for introspection auth methods (HIGH, 1-line fix)
3. **Align `sub` claim** between ID token and introspection (MEDIUM, prevents future breakage)
4. **Add `name` to introspection** response (MEDIUM, enables display name updates)
5. **Migrate to stable Matrix scopes** (MEDIUM, future-proofing)
6. **Remove or wire up `sync_devices`** (LOW, code hygiene)
