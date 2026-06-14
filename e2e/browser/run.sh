#!/usr/bin/env bash
# Run the headless browser E2E inside the official Playwright container (bundled
# Chromium + node), on the host network so it can reach the live stack on
# localhost:8080 (siwx-oidc) and :8090 (Synapse mock). Run e2e/up.sh first.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG=mcr.microsoft.com/playwright:v1.50.1-noble

exec podman run --rm --network host --userns=keep-id \
  -v "$DIR:/work:z" -w /work \
  -e HOME=/tmp \
  -e SIWEOIDC_HOST="${SIWEOIDC_HOST:-http://localhost:8080}" \
  -e SYNAPSE_MOCK="${SYNAPSE_MOCK:-http://localhost:8090}" \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e npm_config_cache=/tmp/.npm \
  "$IMG" \
  bash -lc 'npm install --no-audit --no-fund --silent && npx playwright test'
