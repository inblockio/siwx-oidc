#!/usr/bin/env bash
# Run the headless browser E2E inside the official Playwright container (bundled
# Chromium + node), on the host network so it can reach the live stack.
# Run e2e/up.sh first. Default SIWEOIDC_HOST is :18080 (see e2e/env.sh).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$DIR/../env.sh"
IMG=mcr.microsoft.com/playwright:v1.50.1-noble

exec podman run --rm --network host --userns=keep-id \
  -v "$DIR:/work:z" -w /work \
  -e HOME=/tmp \
  -e SIWEOIDC_HOST="${SIWEOIDC_HOST:-$SIWEOIDC_BASE_URL}" \
  -e SYNAPSE_MOCK="${SYNAPSE_MOCK:-http://localhost:${SYNAPSE_MOCK_PORT}}" \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e npm_config_cache=/tmp/.npm \
  "$IMG" \
  bash -lc 'npm install --no-audit --no-fund --silent && npx playwright test "$@"' _ "$@"
