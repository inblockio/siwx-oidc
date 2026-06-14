#!/usr/bin/env bash
# Bring up the local E2E stack: Redis + Synapse mock + siwx-oidc, all in podman
# (the host sandbox reaps host processes that bind a listening socket, so every
# listener runs in a container; ubuntu:rolling matches the host glibc 2.43 so the
# natively-built debug binary runs as-is).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

cargo build --bin siwx-oidc

podman rm -f siwx-e2e-redis siwx-e2e-mock siwx-e2e-oidc >/dev/null 2>&1 || true

podman run -d --name siwx-e2e-redis -p 127.0.0.1:6379:6379 \
  docker.io/library/redis:7-alpine >/dev/null

podman run -d --name siwx-e2e-mock --network host \
  -v "$REPO/e2e:/app:ro" \
  -e SYNAPSE_MOCK_SECRET=testsecret -e SYNAPSE_MOCK_PORT=8090 \
  docker.io/library/python:3-alpine python /app/synapse_mock.py >/dev/null

podman run -d --name siwx-e2e-oidc --network host -w /app -v "$REPO:/app:z" \
  -e SIWEOIDC_ADDRESS=127.0.0.1 -e SIWEOIDC_PORT=8080 \
  -e SIWEOIDC_BASE_URL=http://localhost:8080 \
  -e SIWEOIDC_REDIS_URL=redis://localhost:6379 \
  -e SIWEOIDC_MAS_SHARED_SECRET=testsecret \
  -e SIWEOIDC_SYNAPSE_ENDPOINT=http://localhost:8090 \
  -e SIWEOIDC_MATRIX_SERVER_NAME=matrix.test \
  -e SIWEOIDC_REQUIRE_SECRET=false \
  -e RUST_LOG=siwx_oidc=info,tower_http=warn,warn \
  docker.io/library/ubuntu:rolling /app/target/debug/siwx-oidc >/dev/null

for i in $(seq 1 60); do
  if curl -sf http://localhost:8080/health >/dev/null 2>&1; then echo "stack up"; exit 0; fi
  sleep 0.5
done
echo "siwx-oidc did not become healthy" >&2; podman logs siwx-e2e-oidc | tail -20 >&2; exit 1
