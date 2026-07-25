#!/usr/bin/env bash
set -euo pipefail
SIWX_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MS_REPO="${MATRIX_SERVER_REPO:-$(cd "$SIWX_REPO/../siwx-oidc-matrix-server" && pwd)}"
cd "$MS_REPO"
if docker compose version >/dev/null 2>&1; then
  docker compose -f docker-compose.local.yml --env-file .env.local down
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose -f docker-compose.local.yml --env-file .env.local down
else
  podman-compose -f docker-compose.local.yml --env-file .env.local down
fi
echo "[stack-down] done"
