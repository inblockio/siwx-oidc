Debug an OIDC authentication flow issue in siwx-oidc.

When the user reports a sign-in problem, work through these diagnostic steps.

## 1. Identify the failure point

The OIDC flow has 4 stages. Ask the user where it fails, or check logs:

| Stage | Endpoint | What happens | Common errors |
|-------|----------|-------------|---------------|
| 1 | `GET /authorize` | Returns session cookie + redirects to frontend | Missing/invalid client_id, redirect_uri not registered |
| 2 | Frontend | User signs CAIP-122 message, sets `siwx` cookie | No wallet detected, user rejects signature, wrong nonce |
| 3 | `GET /sign_in` | Verifies signature, issues auth code | Invalid signature, DID method not supported, expired nonce |
| 4 | `POST /token` | Exchanges code for ID + access tokens | Code expired/already used, invalid client_secret |

## 2. Check server logs

```bash
# If running via docker compose
docker compose logs siwx-oidc --tail 50

# If running locally with debug logging
RUST_LOG=siwx_oidc=debug,tower_http=debug cargo run

# For full trace-level output (very verbose)
RUST_LOG=siwx_oidc=trace,tower_http=trace cargo run

# For JSON output (useful for piping to jq)
SIWXOIDC_LOG_FORMAT=json RUST_LOG=siwx_oidc=debug cargo run 2>&1 | jq .
```

Key log targets:
- `siwx_oidc::oidc` -- sign-in, token, authorize, ENS resolution
- `siwx_oidc::webauthn` -- passkey ceremonies
- `siwx_oidc::axum_lib` -- startup, request/response lifecycle, error responses
- `siwx_oidc::introspect` -- token introspection for Synapse
- `siwx_oidc::compat` -- Matrix compat endpoints (revoke, refresh, logout)
- `siwx_oidc::synapse_client` -- Synapse provisioning API calls
- `tower_http` -- HTTP request/response traces

## 3. Check OIDC discovery

```bash
curl -s http://localhost:8000/.well-known/openid-configuration | python3 -m json.tool
```

Verify:
- `issuer` matches `SIWXOIDC_BASE_URL` (legacy name `SIWEOIDC_BASE_URL`)
- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` are present
- `jwks_uri` is accessible

## 4. Check JWKS

```bash
curl -s http://localhost:8000/jwk | python3 -m json.tool
```

Should return a JWK set with the live ES256 key (plus any retired public keys). The
`kid` is derived from the key; if it changes after every restart, no signing key is
configured and an ephemeral one is generated (see docs/configuration.md).

## 5. Check registered clients

```bash
# Needs the client's registration access token (returned by POST /register)
curl -s http://localhost:8000/client/{client_id} \
  -H "Authorization: Bearer {registration_access_token}" | python3 -m json.tool

# Or read it straight from Redis (it holds the digests of the secret and the
# registration access token, never the values)
redis-cli GET 'clients/{client_id}' | python3 -m json.tool
```

Verify the client exists and `redirect_uris` includes the callback URL being used.

## 6. Check cookie content

In the browser devtools → Application → Cookies, look for the `siwx` cookie.
It should contain JSON: `{ "did": "did:pkh:...", "message": "...", "signature": "0x..." }`.

Common cookie issues:
- Cookie not set: frontend JS error, check browser console
- Cookie `sameSite: Strict` blocks cross-origin: issuer and relying party on different domains
- Cookie too large: some browsers limit cookie size

## 7. Verify signature manually

If the server rejects a signature, test the DID method directly:
```bash
cargo test   # in an aqua-auth checkout, at the tag siwx-oidc pins
```

For specific DID verification, check in aqua-auth (https://github.com/inblockio/aqua-rs-auth):
- `src/pkh/eip155.rs` — Ethereum (EIP-191)
- `src/key/ed25519.rs` — Ed25519
- `src/key/p256.rs` — P-256 ECDSA
- `src/key/mod.rs` — did:key
- `src/peer/mod.rs` — did:peer

## 8. Check supported methods config

```bash
# What DID methods does the server accept?
grep supported_did_methods siwx-oidc.toml siwe-oidc.toml
# Env var override (SIWXOIDC_ wins over the legacy SIWEOIDC_):
echo $SIWXOIDC_SUPPORTED_DID_METHODS $SIWEOIDC_SUPPORTED_DID_METHODS

# What pkh namespaces?
grep supported_pkh_namespaces siwx-oidc.toml siwe-oidc.toml
echo $SIWXOIDC_SUPPORTED_PKH_NAMESPACES $SIWEOIDC_SUPPORTED_PKH_NAMESPACES
```

Default: `supported_did_methods = ["pkh", "key"]`, `supported_pkh_namespaces = ["eip155", "ed25519", "p256"]`.

## 9. Test with headless client

Bypass the frontend entirely using siwx-oidc-auth:
```bash
# Server must have "key" in supported_did_methods
cargo run -p siwx-oidc-auth -- \
  --server http://localhost:8000 \
  --client-id {client_id} \
  --redirect-uri {redirect_uri}
```

This tests the full OIDC flow without a browser/wallet.

## 10. Redis connectivity

```bash
redis-cli -u redis://localhost ping   # should return PONG
redis-cli -u redis://localhost keys '*'  # check stored sessions/codes
```
