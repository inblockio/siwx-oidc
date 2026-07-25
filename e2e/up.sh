#!/usr/bin/env bash
# Bring up the local E2E stack: Redis + Synapse mock + siwx-oidc, all in podman
# (the host sandbox reaps host processes that bind a listening socket, so every
# listener runs in a container; ubuntu:rolling matches the host glibc 2.43 so the
# natively-built debug binary runs as-is).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
# shellcheck disable=SC1091
source "$REPO/e2e/env.sh"

cargo build --bin siwx-oidc

podman rm -f siwx-e2e-redis siwx-e2e-mock siwx-e2e-oidc >/dev/null 2>&1 || true

podman run -d --name siwx-e2e-redis -p 127.0.0.1:6379:6379 \
  docker.io/library/redis:7-alpine >/dev/null

podman run -d --name siwx-e2e-mock --network host \
  -v "$REPO/e2e:/app:ro" \
  -e SYNAPSE_MOCK_SECRET="$SYNAPSE_MOCK_SECRET" -e SYNAPSE_MOCK_PORT="$SYNAPSE_MOCK_PORT" \
  docker.io/library/python:3-alpine python /app/synapse_mock.py >/dev/null

podman run -d --name siwx-e2e-oidc --network host -w /app -v "$REPO:/app:z" \
  -e SIWEOIDC_ADDRESS="$SIWEOIDC_ADDRESS" -e SIWEOIDC_PORT="$SIWEOIDC_PORT" \
  -e SIWEOIDC_BASE_URL="$SIWEOIDC_BASE_URL" \
  -e SIWEOIDC_REDIS_URL="$SIWEOIDC_REDIS_URL" \
  -e SIWEOIDC_MAS_SHARED_SECRET="$SIWEOIDC_MAS_SHARED_SECRET" \
  -e SIWEOIDC_SYNAPSE_ENDPOINT="$SIWEOIDC_SYNAPSE_ENDPOINT" \
  -e SIWEOIDC_MATRIX_SERVER_NAME="$SIWEOIDC_MATRIX_SERVER_NAME" \
  -e SIWEOIDC_REQUIRE_SECRET="$SIWEOIDC_REQUIRE_SECRET" \
  -e RUST_LOG="$RUST_LOG" \
  docker.io/library/ubuntu:rolling /app/target/debug/siwx-oidc >/dev/null

for i in $(seq 1 60); do
  if curl -sf "${SIWEOIDC_BASE_URL}/health" >/dev/null 2>&1; then
    echo "stack up (${SIWEOIDC_BASE_URL})"
    exit 0
  fi
  sleep 0.5
done
echo "siwx-oidc did not become healthy on ${SIWEOIDC_BASE_URL}" >&2
podman logs siwx-e2e-oidc | tail -20 >&2
exit 1
