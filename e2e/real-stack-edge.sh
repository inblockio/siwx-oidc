#!/usr/bin/env bash
# Add a prod-like Caddy edge in front of the LOCAL REAL stack (siwx-real-*).
#
# WHY: under MSC3861, Synapse disables its native CS-API logout / device
# management endpoints (404 "Unrecognized request"). Those are owned by siwx-oidc
# (src/compat.rs). Production routes them to siwx-oidc with a Caddy method-route on
# matrix.inblock.io. The bare local real stack has no edge, so a matrix-sdk
# client's native `matrix_auth().logout()` 404s. This script stands up an edge
# container (siwx-real-caddy) that mirrors the prod route split, so a client can
# point its homeserver at the edge and have native device sign-out reach siwx-oidc.
#
# Prereq: the real stack must already be up (see /tmp/track2-real-stack.md):
#   siwx-real-oidc (8081), siwx-real-synapse (8008 internal), siwx-real-redis,
#   all on the podman network `siwx-real-net`.
#
# Edge endpoint (host): http://localhost:8450
#
# Usage:
#   bash e2e/real-stack-edge.sh up      # start/replace the edge (default)
#   bash e2e/real-stack-edge.sh down    # remove the edge container
#   bash e2e/real-stack-edge.sh verify  # probe native logout 404→via-edge
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NET="siwx-real-net"
EDGE_NAME="siwx-real-caddy"
EDGE_PORT="8450"
CADDYFILE="$REPO/e2e/real-stack/Caddyfile"
ACTION="${1:-up}"

require_stack() {
  for c in siwx-real-oidc siwx-real-synapse; do
    if ! podman container exists "$c"; then
      echo "ERROR: $c is not running. Bring up the real stack first (see /tmp/track2-real-stack.md)." >&2
      exit 1
    fi
  done
  if ! podman network exists "$NET"; then
    echo "ERROR: podman network $NET is missing. Bring up the real stack first." >&2
    exit 1
  fi
}

case "$ACTION" in
  up)
    require_stack
    podman rm -f "$EDGE_NAME" >/dev/null 2>&1 || true
    podman run -d --name "$EDGE_NAME" --network "$NET" \
      -p "127.0.0.1:${EDGE_PORT}:${EDGE_PORT}" \
      -v "$CADDYFILE:/etc/caddy/Caddyfile:ro,z" \
      docker.io/library/caddy:2-alpine >/dev/null

    # Wait for the edge to answer (well-known is served by the edge itself).
    for i in $(seq 1 60); do
      if curl -sf "http://localhost:${EDGE_PORT}/.well-known/matrix/client" >/dev/null 2>&1; then
        echo "edge up: http://localhost:${EDGE_PORT}  (container ${EDGE_NAME} on ${NET})"
        echo "routes login/logout/logout-all/refresh/devices/delete_devices -> siwx-real-oidc:8081"
        echo "routes everything else -> siwx-real-synapse:8008"
        exit 0
      fi
      sleep 0.5
    done
    echo "edge did not become healthy" >&2
    podman logs "$EDGE_NAME" 2>&1 | tail -20 >&2
    exit 1
    ;;

  down)
    podman rm -f "$EDGE_NAME" >/dev/null 2>&1 || true
    echo "edge removed: ${EDGE_NAME}"
    ;;

  verify)
    # Demonstrate the before/after: Synapse's native CS-API logout 404s under
    # MSC3861; the SAME path through the edge reaches siwx-oidc and returns 200.
    echo "== direct to Synapse (127.0.0.1:8448) — expect 404 under MSC3861 =="
    curl -s -o /dev/null -w "POST /_matrix/client/v3/logout -> HTTP %{http_code}\n" \
      -X POST http://localhost:8448/_matrix/client/v3/logout \
      -H 'Authorization: Bearer invalid_token_probe' -H 'Content-Type: application/json' -d '{}'
    echo "== through the edge (127.0.0.1:${EDGE_PORT}) — expect 200 (siwx-oidc compat::logout) =="
    curl -s -o /dev/null -w "POST /_matrix/client/v3/logout -> HTTP %{http_code}\n" \
      -X POST "http://localhost:${EDGE_PORT}/_matrix/client/v3/logout" \
      -H 'Authorization: Bearer invalid_token_probe' -H 'Content-Type: application/json' -d '{}'
    # login flows discovery (GET) also moves to siwx-oidc through the edge.
    echo "== login-flows discovery through the edge — expect 200 with m.login.sso =="
    curl -s -o /dev/null -w "GET  /_matrix/client/v3/login  -> HTTP %{http_code}\n" \
      "http://localhost:${EDGE_PORT}/_matrix/client/v3/login"
    ;;

  *)
    echo "usage: $0 {up|down|verify}" >&2
    exit 2
    ;;
esac
