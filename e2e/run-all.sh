#!/usr/bin/env bash
# Full account-management E2E: stack up, then unit tests + HTTP-level Rust E2E +
# legacy CS-API probe + headless browser E2E (wallet + passkey).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
cd "$REPO"

echo "== 1/5  bring up stack (Redis + Synapse mock + siwx-oidc) =="
bash e2e/up.sh

echo "== 2/5  unit tests (cargo test --bin siwx-oidc) =="
cargo test --bin siwx-oidc

echo "== 3/5  HTTP-level account E2E (real wallet signatures + session) =="
cargo test --test e2e_account_management -- --ignored --test-threads=1

echo "== 4/5  legacy CS-API device-delete probe =="
bash e2e/legacy-cs-api-probe.sh

echo "== 5/5  headless browser E2E (mock wallet + WebAuthn virtual authenticator) =="
bash e2e/browser/run.sh

echo
echo "ALL ACCOUNT-MANAGEMENT E2E GREEN"
