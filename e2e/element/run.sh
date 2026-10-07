#!/usr/bin/env bash
# Run Element Web Playwright specs against the live compose.local stack.
#
# Optional, all passed through to the container when set:
#   CTRF_OUTPUT       host path of a CTRF JSON report to write (playwright-ctrf-json-reporter);
#                     its directory is mounted at the same path inside the container
#   CTRF_OUTPUT_DIR   host directory for the CTRF report (file name ctrf-report.json)
#   QUALIFY_STATE_DIR host directory a continuity suite keeps its state in (ew-upgrade-*),
#                     mounted at the same path
#   E2E_STRICT_SKIPS, T2_* and MAS_SHARED_SECRET are passed through unchanged.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG=mcr.microsoft.com/playwright:v1.62.1-noble

# Mount whole e2e/ so ../browser imports resolve inside the container.
E2E_ROOT="$(cd "$DIR/.." && pwd)"

extra=()
mount_same() { # mount a host directory at the same path inside the container
  mkdir -p "$1"
  extra+=(-v "$1:$1:z")
}
if [ -n "${CTRF_OUTPUT:-}" ]; then
  case "$CTRF_OUTPUT" in /*) ;; *) echo "run.sh: CTRF_OUTPUT must be an absolute path" >&2; exit 2 ;; esac
  mount_same "$(dirname "$CTRF_OUTPUT")"
  extra+=(-e "CTRF_OUTPUT=$CTRF_OUTPUT")
fi
if [ -n "${CTRF_OUTPUT_DIR:-}" ]; then
  case "$CTRF_OUTPUT_DIR" in /*) ;; *) echo "run.sh: CTRF_OUTPUT_DIR must be an absolute path" >&2; exit 2 ;; esac
  mount_same "$CTRF_OUTPUT_DIR"
  extra+=(-e "CTRF_OUTPUT_DIR=$CTRF_OUTPUT_DIR")
fi
if [ -n "${QUALIFY_STATE_DIR:-}" ]; then
  case "$QUALIFY_STATE_DIR" in /*) ;; *) echo "run.sh: QUALIFY_STATE_DIR must be an absolute path" >&2; exit 2 ;; esac
  mount_same "$QUALIFY_STATE_DIR"
  extra+=(-e "QUALIFY_STATE_DIR=$QUALIFY_STATE_DIR")
fi
# Names only: podman reads each value from this environment, so no value is on a command line.
for v in $(compgen -e | grep -E '^(T2_[A-Z0-9_]+|E2E_STRICT_SKIPS|MAS_SHARED_SECRET)$' || true); do
  extra+=(-e "$v")
done

exec podman run --rm --network host --userns=keep-id \
  -v "$E2E_ROOT:/e2e:z" \
  "${extra[@]}" \
  -w /e2e/element \
  -e HOME=/tmp \
  -e ELEMENT_URL="${ELEMENT_URL:-http://localhost:28088}" \
  -e MATRIX_URL="${MATRIX_URL:-http://localhost:28080}" \
  -e SIWX_URL="${SIWX_URL:-http://localhost:28081}" \
  -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -e npm_config_cache=/tmp/.npm \
  "$IMG" \
  bash -lc '
    # The specs import ../browser/*-helper.mjs, which need that suite'"'"'s own dependencies.
    if [ ! -d ../browser/node_modules/ethers ]; then
      (cd ../browser && npm install --no-audit --no-fund --silent)
    fi
    npm install --no-audit --no-fund --silent && npx playwright test "$@"' _ "$@"
