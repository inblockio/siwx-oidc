Pre-deployment checklist for siwx-oidc with Matrix Synapse.

Run through this checklist to verify everything is ready after deploying
to the production server (`deploy@142.93.168.4`).

## Deploy model

Code on dev machine, push to GitHub, CI builds Docker images to GHCR,
Watchtower on the server auto-pulls new images every 5 minutes.

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

## 4. CORS verification

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

## 5. DNS records

Two domains needed:
- **matrix.inblock.io** — Synapse homeserver
- **siwx-oidc.inblock.io** — OIDC provider
- **element.inblock.io** — Element Web client

All point to `142.93.168.4`. Caddy handles TLS via Let's Encrypt.

## 6. Watchtower auto-deploy

```bash
ssh deploy@142.93.168.4 "cd /home/deploy/matrix/stack && docker compose logs watchtower --tail 5"
```

Should show polling every 300s. Watchtower is scoped to containers labeled
`com.centurylinklabs.watchtower.scope=matrix`.

## 7. Login test

1. Open `https://element.inblock.io` in incognito (clear localStorage)
2. Should see "Connecting wallet..." splash (siwx-gate.js blocks Element)
3. MetaMask prompts to sign CAIP-122 message
4. After signing, redirected back with `?code=`, token exchange completes
5. Element loads with DID-based username

For passkey login: register a passkey first, then use "Sign in with Passkey".

## Common issues

- **Element shows #/welcome instead of wallet prompt**: CORS issue (dual ACAO headers). See step 4.
- **Watchtower crash-looping**: Needs `DOCKER_API_VERSION: "1.40"` in environment.
- **"DID method 'key' not enabled"**: Add `"key"` to `SIWEOIDC_SUPPORTED_DID_METHODS` in .env.
- **Stale client_id 401 loops**: Element caches client_id; siwx-redirect.js now always registers fresh.
- **QR code greyed out**: Check `msc4108_enabled: true` in Synapse config (see step 3).
