#!/usr/bin/env bash
# Tear down the local E2E stack.
podman rm -f siwx-e2e-redis siwx-e2e-mock siwx-e2e-oidc >/dev/null 2>&1 || true

# The Redis data volume is NOT removed by default: it is the durable session
# state (WebAuthn credentials, device codes, refresh tokens) that up.sh's
# named-volume fix exists to protect across routine stack recycles. Only an
# explicit --purge wipes it.
if [ "${1:-}" = "--purge" ]; then
  podman volume rm -f siwx-e2e-redis-data >/dev/null 2>&1 || true
  echo "stack down (volume purged)"
else
  echo "stack down"
fi
