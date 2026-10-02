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

# Runs inside the container, as the host user (--userns=keep-id), so every
# node_modules is built by the same node/npm that runs Playwright, never by the
# host's. Every spec imports ../browser/wallet-helper.mjs,
# which resolves `ethers` from e2e/browser/node_modules (the element/ one is not
# on its resolution path), so that tree has to exist too. e2e/browser has no
# committed lockfile (e2e/.gitignore), so its install is pinned by the exact
# versions in its package.json. npm writes node_modules/.package-lock.json on
# every install: missing, or older than package.json, means install; otherwise skip.
IN_CONTAINER='
set -e
if [ ! -f /e2e/browser/node_modules/.package-lock.json ] \
   || [ /e2e/browser/package.json -nt /e2e/browser/node_modules/.package-lock.json ]; then
  echo "[run.sh] installing e2e/browser dependencies" >&2
  (cd /e2e/browser && npm install --no-audit --no-fund --silent)
else
  echo "[run.sh] e2e/browser dependencies up to date, skipping install" >&2
fi
npm install --no-audit --no-fund --silent
npx playwright test "$@"
'
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
  bash -lc "$IN_CONTAINER" _ "$@"
