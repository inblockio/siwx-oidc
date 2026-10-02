#!/usr/bin/env bash
# Run Element Web Playwright specs against the live compose.local stack.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# Host ports/URLs of the stack stack-up.sh brings up (one source: stack-env.sh).
# shellcheck disable=SC1091
. "$DIR/stack-env.sh"
IMG=mcr.microsoft.com/playwright:v1.62.1-noble

# Mount whole e2e/ so ../browser imports resolve inside the container.
E2E_ROOT="$(cd "$DIR/.." && pwd)"
exec podman run --rm --network host --userns=keep-id \
  -v "$E2E_ROOT:/e2e:z" \
  -w /e2e/element \
  -e HOME=/tmp \
  -e ELEMENT_URL="${ELEMENT_URL:-$E2E_ELEMENT_URL}" \
  -e MATRIX_URL="${MATRIX_URL:-$E2E_MATRIX_URL}" \
  -e SIWX_URL="${SIWX_URL:-$E2E_SIWX_URL}" \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e npm_config_cache=/tmp/.npm \
  "$IMG" \
  bash -lc 'npm install --no-audit --no-fund --silent && npx playwright test "$@"' _ "$@"
