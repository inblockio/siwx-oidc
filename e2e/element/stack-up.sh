#!/usr/bin/env bash
# Bring up the local Element + Synapse + siwx-oidc stack for EW-* Playwright.
# Uses siwx-oidc-matrix-server/docker-compose.local.yml (sibling of this repo).
set -euo pipefail
# Compose project, host ports and URLs: one source for stack-up/down, t5 and run.sh.
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/stack-env.sh"
SIWX_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MS_REPO="${MATRIX_SERVER_REPO:-$(cd "$SIWX_REPO/../siwx-oidc-matrix-server" && pwd)}"

if [ ! -f "$MS_REPO/docker-compose.local.yml" ]; then
  echo "matrix-server repo not found at $MS_REPO" >&2
  exit 1
fi

cd "$MS_REPO"
if [ ! -f .env.local ]; then
  echo "missing $MS_REPO/.env.local — generate secrets (see docker-compose.local.yml header)" >&2
  exit 1
fi

# Prefer docker compose; fall back to docker-compose / podman-compose. Always
# `-p`: never let compose derive the project from the directory name (stack-env.sh).
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -p "$E2E_COMPOSE_PROJECT" -f docker-compose.local.yml --env-file .env.local)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -p "$E2E_COMPOSE_PROJECT" -f docker-compose.local.yml --env-file .env.local)
elif command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose -p "$E2E_COMPOSE_PROJECT" -f docker-compose.local.yml --env-file .env.local)
else
  echo "no docker compose / podman-compose found" >&2
  exit 1
fi

echo "[stack-up] building + starting Element stack, compose project ${E2E_COMPOSE_PROJECT} (siwx build context: $SIWX_REPO) ..."
"${COMPOSE[@]}" up --build -d

# Host ports come from stack-env.sh, the same values compose was started with
# and run.sh hands to the specs (never re-read from .env.local here).
MATRIX_P="$E2E_MATRIX_PORT"
SIWX_P="$E2E_SIWX_PORT"
ELEM_P="$E2E_ELEMENT_PORT"

echo "[stack-up] waiting for health (matrix :${MATRIX_P} siwx :${SIWX_P} element :${ELEM_P}) ..."
for i in $(seq 1 90); do
  ok=0
  curl -sf "http://localhost:${SIWX_P}/health" >/dev/null 2>&1 && \
  curl -sf "http://localhost:${MATRIX_P}/_matrix/client/versions" >/dev/null 2>&1 && \
  curl -sf "http://localhost:${ELEM_P}/" >/dev/null 2>&1 && ok=1
  if [ "$ok" = "1" ]; then
    echo "[stack-up] ready: Element :${ELEM_P}  Matrix :${MATRIX_P}  siwx :${SIWX_P}"
    exit 0
  fi
  sleep 2
done
echo "[stack-up] timed out waiting for health" >&2
"${COMPOSE[@]}" ps >&2 || true
exit 1
