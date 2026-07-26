#!/usr/bin/env bash
# T5 (H-D1): restart-survival e2e leg — host driver.
#
# Plan: docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md
# H-D1: "If session state survives a full stack restart (durable AOF, named
# volume, verified replay), then a client holding a valid refresh token stays
# logged in with the SAME device_id; zero new device provisions."
#
# Four phases, run from the HOST (not inside the Playwright container, unlike
# the specs themselves):
#   1. capture pre-restart session state           (ew-restart-capture.spec.mjs)
#   2. restart the WHOLE local stack                (docker-compose restart)
#   3. poll for health before touching the stack again
#   4. post-restart assertions                      (ew-restart-assert.spec.mjs)
#
# The two spec files talk to each other only through
# e2e/element/test-results/t5-state.json, which lives on the host disk (inside
# the `/e2e` tree run.sh bind-mounts into the container) and therefore survives
# both the container exiting between phases 1 and 4 AND the stack restart.
set -euo pipefail

# Overridable like stack-up.sh's MATRIX_SERVER_REPO, but defaulting to the
# real path (NOT a sibling-relative guess): this script is authored to run
# from inside a worktree (e.g. /home/waldknoten-01/wt/siwx-durability), where
# "../siwx-oidc-matrix-server" would resolve next to the WORKTREE instead of
# the real matrix-server checkout.
MS_REPO="${MATRIX_SERVER_REPO:-/home/waldknoten-01/siwx-oidc-matrix-server}"
SIWX_REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # e2e/element -> repo root
ELEMENT_DIR="$SIWX_REPO_DIR/e2e/element"

SIWX_URL="${SIWX_URL:-http://localhost:28081}"
MATRIX_URL="${MATRIX_URL:-http://localhost:28080}"
ELEMENT_URL="${ELEMENT_URL:-http://localhost:28088}"

if [ ! -d "$MS_REPO" ]; then
  echo "[t5] matrix-server repo not found at $MS_REPO" >&2
  exit 1
fi
if [ ! -f "$MS_REPO/.env.local" ]; then
  echo "[t5] missing $MS_REPO/.env.local — cannot restart the stack safely" >&2
  exit 1
fi

# The compose command MUST be exactly this, including --env-file. Omitting
# --env-file resolves SIWEOIDC_SIGNING_KEY_PEM (and other secrets sourced from
# .env.local) to empty, which panics siwx-oidc at startup — a real incident on
# this lab. Do not "simplify" this to a bare `-f docker-compose.local.yml`.
COMPOSE=(docker-compose -f docker-compose.local.yml --env-file .env.local)

cd "$MS_REPO"

echo "[t5] phase 1/4: capture pre-restart state (ew-restart-capture.spec.mjs)"
bash "$ELEMENT_DIR/run.sh" ew-restart-capture.spec.mjs

echo "[t5] phase 2/4: restarting the whole stack"
echo "[t5]   cwd=$MS_REPO cmd=${COMPOSE[*]} restart"
# Seconds, NOT `date +%s%3N`. This box ships uutils coreutils 0.8.0, whose `date`
# ignores the %3N width modifier and emits `%s` followed by FULL nanoseconds --
# `date +%s%3N` returns a 19-digit value, and the resulting arithmetic printed
# "1176248s" for a ~10s restart. Second resolution is all this log needs, and a
# wrong number in a harness log is worse than a coarse one.
restart_start_s=$(date +%s)
# `restart`, never `down`/`rm`/`-v`. Those would remove (or risk removing) the
# NAMED `redis_data` volume (docker-compose.local.yml, AOF-backed:
# `redis-server --appendonly yes`) — destroying it would invalidate the whole
# H-D1 test (there would be nothing left to prove "survived") and lose
# whatever else is in the lab's Redis.
"${COMPOSE[@]}" restart
restart_cmd_s=$(date +%s)
echo "[t5]   compose restart command returned after $(( restart_cmd_s - restart_start_s ))s"

echo "[t5] phase 3/4: waiting for health (siwx, matrix, element) — up to 180s"
health_deadline=$((SECONDS + 180))
healthy=0
while [ "$SECONDS" -lt "$health_deadline" ]; do
  ok=1
  curl -sf "${SIWX_URL}/.well-known/openid-configuration" >/dev/null 2>&1 || ok=0
  curl -sf "${MATRIX_URL}/_matrix/client/versions" >/dev/null 2>&1 || ok=0
  curl -sf "${ELEMENT_URL}/" >/dev/null 2>&1 || ok=0
  if [ "$ok" = "1" ]; then
    healthy=1
    break
  fi
  sleep 2
done

restart_end_s=$(date +%s)
elapsed_s=$(( restart_end_s - restart_start_s ))
# This number is the one the assert phase's 240s access-token conditional
# (ew-restart-assert.spec.mjs, leg D) is reasoned against — printed here so a
# human/orchestrator reading this log can correlate the two independently
# (the two processes do not share this value programmatically; the assert
# spec recomputes elapsed-since-capture itself from t5-state.json).
echo "[t5]   elapsed restart-to-healthy: ${elapsed_s}s"

if [ "$healthy" != "1" ]; then
  echo "[t5] FAILED: stack did not become healthy within 180s of the restart" >&2
  "${COMPOSE[@]}" ps >&2 || true
  exit 1
fi
echo "[t5]   healthy: siwx=${SIWX_URL} matrix=${MATRIX_URL} element=${ELEMENT_URL}"

echo "[t5] phase 4/4: post-restart assertions (ew-restart-assert.spec.mjs)"
bash "$ELEMENT_DIR/run.sh" ew-restart-assert.spec.mjs

echo "[t5] DONE — restart-to-healthy took ${elapsed_s}s"
