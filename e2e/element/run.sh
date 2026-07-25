#!/usr/bin/env bash
# Run Element Web Playwright specs against the live compose.local stack.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG=mcr.microsoft.com/playwright:v1.50.1-noble

# Mount whole e2e/ so ../browser imports resolve inside the container.
E2E_ROOT="$(cd "$DIR/.." && pwd)"
exec podman run --rm --network host --userns=keep-id \
  -v "$E2E_ROOT:/e2e:z" \
  -w /e2e/element \
  -e HOME=/tmp \
  -e ELEMENT_URL="${ELEMENT_URL:-http://localhost:8088}" \
  -e MATRIX_URL="${MATRIX_URL:-http://localhost:8080}" \
  -e SIWX_URL="${SIWX_URL:-http://localhost:8081}" \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e npm_config_cache=/tmp/.npm \
  "$IMG" \
  bash -lc 'npm install --no-audit --no-fund --silent && npx playwright test "$@"' _ "$@"
