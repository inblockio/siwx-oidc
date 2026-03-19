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
RUST_LOG=siwx_oidc=debug,tower_http=trace cargo run
```

## 3. Check OIDC discovery

```bash
curl -s http://localhost:8000/.well-known/openid-configuration | python3 -m json.tool
```

Verify:
- `issuer` matches `SIWEOIDC_BASE_URL`
- `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` are present
- `jwks_uri` is accessible

## 4. Check JWKS

```bash
curl -s http://localhost:8000/jwks | python3 -m json.tool
```

Should return a JWK set with an ES256 key. If empty, the signing key failed to load.

## 5. Check registered clients

```bash
curl -s http://localhost:8000/client/{client_id} | python3 -m json.tool
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
cargo test -p siwx-core
```

For specific DID verification, check:
- `siwx-core/src/pkh/eip155.rs` — Ethereum (EIP-191)
- `siwx-core/src/pkh/ed25519.rs` — Ed25519
- `siwx-core/src/pkh/p256.rs` — P-256 ECDSA
- `siwx-core/src/key/mod.rs` — did:key
- `siwx-core/src/peer/mod.rs` — did:peer

## 8. Check supported methods config

```bash
# What DID methods does the server accept?
grep supported_did_methods siwe-oidc.toml
# Env var override:
echo $SIWEOIDC_SUPPORTED_DID_METHODS

# What pkh namespaces?
grep supported_pkh_namespaces siwe-oidc.toml
echo $SIWEOIDC_SUPPORTED_PKH_NAMESPACES
```

Default: `supported_did_methods = ["pkh"]`, `supported_pkh_namespaces = ["eip155", "ed25519", "p256"]`.

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
