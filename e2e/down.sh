#!/usr/bin/env bash
# Tear down the local E2E stack.
podman rm -f siwx-e2e-redis siwx-e2e-mock siwx-e2e-oidc >/dev/null 2>&1 || true
echo "stack down"
