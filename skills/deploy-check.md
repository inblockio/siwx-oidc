Pre-deployment checklist for siwx-oidc with Matrix Synapse.

Run through this checklist to verify everything is ready after deploying
to the production server (`deploy@142.93.168.4`).

## Deploy model

Code on dev machine, push to GitHub, CI builds Docker images to GHCR.
**Deploys are MANUAL** (verified 2026-06-12): the watchtower container is scoped
to `matrix` but nothing else carries that scope label, so it updates NOTHING.
After CI publishes, someone must run on the server:
`cd /home/deploy/matrix/stack && docker compose pull siwx-oidc && docker compose up -d siwx-oidc`.

**No repos or builds on the server.** Server has only `docker-compose.yml` + `.env`
at `/home/deploy/matrix/stack/`.

## 1. CI status

Verify CI built and pushed images successfully:
```bash
# siwx-oidc (OIDC server)
gh run list -R inblockio/siwx-oidc --limit 3

# siwx-oidc-matrix-server (Synapse + Element Web)
gh run list -R inblockio/siwx-oidc-matrix-server --limit 3
```

## 2. Server container status

```bash
ssh deploy@142.93.168.4 "cd /home/deploy/matrix/stack && docker compose ps"
```

All 5 services should be healthy: matrix_synapse, siwx-oidc, redis, element-web, watchtower.

## 3. OIDC and Synapse verification

```bash
ssh deploy@142.93.168.4 "
  # OIDC discovery
  curl -s https://siwx-oidc.inblock.io/.well-known/openid-configuration | python3 -m json.tool

  # Synapse reachable
  curl -s https://matrix.inblock.io/_matrix/client/versions | python3 -m json.tool

  # Login flows (should show m.login.sso only, no password)
  curl -s https://matrix.inblock.io/_matrix/client/v3/login | python3 -m json.tool

  # MSC4108 QR code login enabled
  curl -s https://matrix.inblock.io/_matrix/client/versions | python3 -c 'import json,sys; print(\"msc4108:\", json.load(sys.stdin)[\"unstable_features\"].get(\"org.matrix.msc4108\"))'
"
```

## 4. MSC3861 auth_metadata guard

Synapse forwards `experimental_features.msc3861.issuer_metadata` VERBATIM to
browsers via `GET /_matrix/client/v1/auth_metadata`; if it is missing capability
fields (`response_types_supported`, `grant_types_supported`,
`code_challenge_methods_supported`) or contains non-public endpoint URLs,
matrix-js-sdk rejects the issuer and Element Web silently falls back to the
legacy `/login/sso/redirect` route. That route 404s under MSC3861 (siwx-oidc
has no MAS compat shim), so any auth_metadata regression is a total, silent
login dead-end — this check fails loudly instead.

```bash
scripts/check-auth-metadata.sh https://matrix.inblock.io https://siwx-oidc.inblock.io/
```

Must end with `== PASS ... ==` (exit 0). The 404 WARNING for the legacy SSO
route is expected and informational.

## 5. CORS verification

siwx-oidc's tower_http CorsLayer and Caddy both emit CORS headers. Caddy must
strip siwx-oidc's headers to avoid dual Access-Control-Allow-Origin (browsers reject it).

```bash
ssh deploy@142.93.168.4 "curl -sI https://siwx-oidc.inblock.io/.well-known/openid-configuration \
  -H 'Origin: https://element.inblock.io' | grep -i access-control-allow-origin"
# Must show exactly ONE line: Access-Control-Allow-Origin: https://element.inblock.io
```

If two lines appear, update `/home/portal/portal/Caddyfile` to add `header_down
-Access-Control-Allow-Origin` in the siwx-oidc reverse_proxy block. See Caddyfile.local
`(strip_upstream_cors)` snippet.

## 6. DNS records

Two domains needed:
- **matrix.inblock.io** — Synapse homeserver
- **siwx-oidc.inblock.io** — OIDC provider
- **element.inblock.io** — Element Web client

All point to `142.93.168.4`. Caddy handles TLS via Let's Encrypt.

## 7. Manual deploy (watchtower is a NO-OP)

Watchtower runs scoped to `com.centurylinklabs.watchtower.scope=matrix`, but the
only container carrying that label is watchtower itself — it deploys nothing
(verified 2026-06-12; see CLAUDE.md "Deployment"). Pull and restart manually:

```bash
ssh deploy@142.93.168.4 "cd /home/deploy/matrix/stack && docker compose pull siwx-oidc && docker compose up -d siwx-oidc"
```

## 8. Login test

1. Open `https://element.inblock.io` in incognito (clear localStorage)
2. Should see "Connecting wallet..." splash (siwx-gate.js blocks Element)
3. MetaMask prompts to sign CAIP-122 message
4. After signing, redirected back with `?code=`, token exchange completes
5. Element loads with DID-based username

For passkey login: register a passkey first, then use "Sign in with Passkey".

## Common issues

- **Element shows #/welcome instead of wallet prompt**: CORS issue (dual ACAO headers, see step 5) or an auth_metadata regression sent Element down the legacy SSO 404 route (see step 4).
- **Watchtower crash-looping**: Needs `DOCKER_API_VERSION: "1.40"` in environment.
- **"DID method 'key' not enabled"**: Add `"key"` to `SIWEOIDC_SUPPORTED_DID_METHODS` in .env.
- **Stale client_id 401 loops**: Element caches client_id; siwx-redirect.js now always registers fresh.
- **QR code greyed out**: Check `msc4108_enabled: true` in Synapse config (see step 3).
