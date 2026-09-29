Pre-deployment checklist for siwx-oidc with Matrix Synapse.

Run through this checklist after deploying siwx-oidc in front of a Synapse
homeserver (siwx-oidc as the auth service in Synapse's `matrix_authentication_service`
integration). It is written for a Docker Compose
deployment behind a Caddy reverse proxy, but the checks are HTTP-level and
apply to any setup.

Set these once for your deployment; every command below uses them:

```bash
MATRIX=https://matrix.example.org        # homeserver public base URL
OIDC=https://siwx-oidc.example.org       # siwx-oidc issuer (SIWXOIDC_BASE_URL)
ELEMENT=https://element.example.org      # Element Web origin (if you serve it)
```

## Deploy model

Code on a dev machine, push to GitHub, CI builds Docker images to GHCR
(`ghcr.io/inblockio/siwx-oidc`). Publishing an image deploys nothing by itself:
after CI publishes, pull and recreate the container on your host (step 7).

## 1. CI status

Verify CI built and pushed images successfully:
```bash
# siwx-oidc (OIDC server)
gh run list -R inblockio/siwx-oidc --limit 3

# siwx-oidc-matrix-server (Synapse + Element Web)
gh run list -R inblockio/siwx-oidc-matrix-server --limit 3
```

## 2. Server container status

On the deployment host, in the compose stack directory:

```bash
docker compose ps
```

Every service should be healthy — at minimum Synapse, siwx-oidc and Redis, plus
Element Web if you serve it.

## 3. OIDC and Synapse verification

```bash
# OIDC discovery
curl -s "$OIDC/.well-known/openid-configuration" | python3 -m json.tool

# Synapse reachable
curl -s "$MATRIX/_matrix/client/versions" | python3 -m json.tool

# Login flows (should show m.login.sso only, no password)
curl -s "$MATRIX/_matrix/client/v3/login" | python3 -m json.tool

# MSC4108 QR code login enabled
curl -s "$MATRIX/_matrix/client/versions" | python3 -c 'import json,sys; print("msc4108:", json.load(sys.stdin)["unstable_features"].get("org.matrix.msc4108"))'
```

## 4. auth_metadata guard

Synapse republishes siwx-oidc's OIDC metadata to browsers via
`GET /_matrix/client/v1/auth_metadata`. If it is missing capability fields
(`response_types_supported`, `grant_types_supported`,
`code_challenge_methods_supported`) or contains non-public endpoint URLs,
matrix-js-sdk rejects the issuer and Element Web silently falls back to the
legacy `/login/sso/redirect` route. That route 404s under delegated auth
(siwx-oidc has no MAS compat shim), so any auth_metadata regression is a total,
silent login dead-end — this check fails loudly instead.

**Where that metadata comes from is version-dependent** — it changes what you fix
when the check fails:

| Synapse | Source of `auth_metadata` |
|---|---|
| >= 1.157 | **Fetched live over HTTP** from `matrix_authentication_service.endpoint`. `api/auth/mas.py::auth_metadata()` is `self._server_metadata.get()` -> `get_json(self._metadata_url)`. There is no `issuer_metadata` config key; grep of the 1.159.0 tree finds zero occurrences. Fix regressions in **siwx-oidc's `/.well-known/openid-configuration`**, then let Synapse's metadata cache expire. |
| <= 1.156 (historical) | With the old `experimental_features.msc3861` block (removed in 1.157.0): forwarded **verbatim** from its `issuer_metadata` config blob, when set. Fix regressions in the **homeserver.yaml blob**. |

Either way the guard script below asserts the same public contract, so it is valid
against both.

```bash
scripts/check-auth-metadata.sh "$MATRIX" "$OIDC/"
```

Must end with `== PASS ... ==` (exit 0). The 404 WARNING for the legacy SSO
route is expected and informational.

## 5. CORS verification

siwx-oidc's tower_http CorsLayer and Caddy both emit CORS headers. Caddy must
strip siwx-oidc's headers to avoid dual Access-Control-Allow-Origin (browsers reject it).

```bash
curl -sI "$OIDC/.well-known/openid-configuration" \
  -H "Origin: $ELEMENT" | grep -i access-control-allow-origin
# Must show exactly ONE line: Access-Control-Allow-Origin: <your Element origin>
```

If two lines appear, add `header_down -Access-Control-Allow-Origin` to the
siwx-oidc `reverse_proxy` block of your Caddyfile. See the `(strip_upstream_cors)`
snippet in `Caddyfile.local` (siwx-oidc-matrix-server).

## 6. DNS records

Three hostnames are needed (names are yours to choose):
- **homeserver** (`$MATRIX`) — Synapse
- **OIDC provider** (`$OIDC`) — siwx-oidc
- **Element Web** (`$ELEMENT`) — the web client, if you serve it

All point at the reverse proxy host. Caddy handles TLS via Let's Encrypt.

## 7. Roll out the new image

After CI publishes, pull and recreate siwx-oidc on the deployment host, in the
compose stack directory:

```bash
docker compose pull siwx-oidc && docker compose up -d siwx-oidc
```

If you run an auto-updater such as watchtower, verify it actually watches the
siwx-oidc container before relying on it: a watchtower started with a scope
(`com.centurylinklabs.watchtower.scope=…`) only updates containers carrying that
same scope label, and updates nothing at all when only watchtower itself carries it.

## 8. Login test

1. Open `$ELEMENT` in incognito (clear localStorage)
2. Should see "Connecting wallet..." splash (siwx-gate.js blocks Element)
3. MetaMask prompts to sign CAIP-122 message
4. After signing, redirected back with `?code=`, token exchange completes
5. Element loads with the account's Matrix ID (derived from the DID) and a generated display name

For passkey login: register a passkey first, then use "Sign in with Passkey".

## Common issues

- **Element shows #/welcome instead of wallet prompt**: CORS issue (dual ACAO headers, see step 5) or an auth_metadata regression sent Element down the legacy SSO 404 route (see step 4).
- **Watchtower crash-looping**: Needs `DOCKER_API_VERSION: "1.40"` in environment.
- **"DID method 'key' not enabled"**: `supported_did_methods` was overridden without `"key"`; add it back to `SIWXOIDC_SUPPORTED_DID_METHODS` (default `["pkh", "key"]`).
- **Stale client_id 401 loops**: Element caches client_id; siwx-redirect.js now always registers fresh.
- **QR code greyed out**: Check `msc4108_enabled: true` in Synapse config (see step 3).
