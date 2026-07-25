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

echo "[stack-up] waiting for health ..."
for i in $(seq 1 90); do
  ok=0
  curl -sf http://localhost:8081/health >/dev/null 2>&1 && \
  curl -sf http://localhost:8080/_matrix/client/versions >/dev/null 2>&1 && \
  curl -sf http://localhost:8088/ >/dev/null 2>&1 && ok=1
  if [ "$ok" = "1" ]; then
    echo "[stack-up] ready: Element :8088  Matrix :8080  siwx :8081"
    exit 0
  fi
  sleep 2
done
echo "[stack-up] timed out waiting for health" >&2
"${COMPOSE[@]}" ps >&2 || true
exit 1
