#!/usr/bin/env bash
# Bring up the local Element + Synapse + siwx-oidc stack for EW-* Playwright.
# Uses siwx-oidc-matrix-server/docker-compose.local.yml (sibling of this repo).
set -euo pipefail
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

# Prefer docker compose; fall back to docker-compose / podman-compose.
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -f docker-compose.local.yml --env-file .env.local)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f docker-compose.local.yml --env-file .env.local)
elif command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose -f docker-compose.local.yml --env-file .env.local)
else
  echo "no docker compose / podman-compose found" >&2
  exit 1
fi

echo "[stack-up] building + starting Element stack (siwx build context: $SIWX_REPO) ..."
"${COMPOSE[@]}" up --build -d

# Host ports (read from .env.local via already-exported compose env, or defaults
# that avoid portal-e2e on :8080).
set -a; # shellcheck disable=SC1091
. .env.local
set +a
MATRIX_P="${MATRIX_HOST_PORT:-28080}"
SIWX_P="${SIWEOIDC_HOST_PORT:-28081}"
ELEM_P="${CLIENT_HOST_PORT:-28088}"

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
