Pre-deployment checklist for siwx-oidc with Matrix Synapse.

Run through this checklist to verify everything is ready before deploying
to a production server.

## 1. Docker image availability

Verify the GHCR image exists and is pullable:
```bash
docker pull ghcr.io/inblockio/siwx-oidc:latest
```

If it fails, check:
- Is the package public? https://github.com/orgs/inblockio/packages
- Is the latest CI green? https://github.com/inblockio/siwx-oidc/actions

## 2. Matrix server repo state

Check the siwx-oidc-matrix-server repo is on the `siwx` branch:
```bash
cd ../siwx-oidc-matrix-server
git branch --show-current  # should be: siwx
git log --oneline -3
```

## 3. Required DNS records

Two domains needed (can be subdomains):
- **MATRIX_HOST** (e.g., `matrix.example.com`) — for Synapse
- **SIWEOIDC_HOST** (e.g., `siwx-oidc.example.com`) — for the OIDC provider

Both must have A/AAAA records pointing to the server. The nginx-proxy + acme-companion
handle TLS certificate provisioning automatically via Let's Encrypt.

For Matrix federation, also set up:
- `_matrix._tcp.{MATRIX_HOST}` SRV record → port 8448
- OR `.well-known/matrix/server` on the domain

## 4. Required ports

Verify these ports are open on the server firewall:
- **80** — HTTP (Let's Encrypt ACME challenges)
- **443** — HTTPS (nginx proxy)
- **8448** — Matrix federation (direct, not proxied)

## 5. Signing key

The `start-matrix.sh` script auto-generates a persistent ES256 signing key in
`siwx-oidc-config/siwe-oidc.toml` on first run. This key is mounted read-only
into the siwx-oidc container.

If redeploying to a new server, copy `siwx-oidc-config/` from the old server
to preserve the signing key (otherwise all existing tokens are invalidated).

## 6. Service startup order

The docker-compose enforces:
```
Redis (healthy) → siwx-oidc (healthy) → Synapse
                  nginx-proxy → letsencrypt
```

siwx-oidc health check: `GET /.well-known/openid-configuration`
Redis health check: `redis-cli ping`

## 7. Post-deployment verification

After `start-matrix.sh` completes:
```bash
# Check all services are running
docker compose ps

# Check siwx-oidc OIDC discovery
curl -s https://{SIWEOIDC_HOST}/.well-known/openid-configuration | python3 -m json.tool

# Check Synapse is reachable
curl -s https://{MATRIX_HOST}/_matrix/client/versions | python3 -m json.tool

# Check OIDC integration (should list siwx-oidc as login provider)
curl -s https://{MATRIX_HOST}/_matrix/client/r0/login | python3 -m json.tool
```

## 8. First login test

1. Open `https://{MATRIX_HOST}` in a browser with MetaMask installed
2. Click "Sign in" → should show siwx-oidc as an option
3. Click siwx-oidc → redirected to `https://{SIWEOIDC_HOST}/authorize`
4. MetaMask prompts to sign → approve → redirected back to Matrix
5. Matrix creates account with DID-based username

## Common issues

- **"Server needs to restart 3-5 times"**: This is expected on first boot — Synapse needs TLS certs from Let's Encrypt, which requires the proxy to be running first. Wait ~2 minutes.
- **OIDC discovery fails**: Check that siwx-oidc can reach Redis (`docker compose logs siwx-oidc`)
- **Synapse can't reach siwx-oidc issuer**: The OIDC issuer URL (`SIWEOIDC_BASE_URL`) must be reachable from inside the Synapse container. If using Docker networking, use the external HTTPS URL (not internal Docker hostname).
- **"No wallet detected"**: User needs a browser wallet extension (MetaMask, Brave Wallet, Coinbase). Mobile wallets via QR code are not supported — mobile users should use the headless `siwx-oidc-auth` CLI with `did:key`.
