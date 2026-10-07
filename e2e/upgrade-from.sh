#!/usr/bin/env bash
# Mock upgrade from a previous siwx-oidc image to the build under test, Redis kept.
#
#   bash e2e/upgrade-from.sh <old-image> [<new>]
#
# <old-image>  the image to upgrade FROM, by full reference (prefer a digest:
#              registry/name@sha256:...). Also UPGRADE_OLD_IMAGE.
# <new>        the build to upgrade TO: a path to a siwx-oidc binary (run in
#              ubuntu:rolling, like e2e/up.sh), or an image reference. Also
#              UPGRADE_NEW. Default: `cargo build --bin siwx-oidc` of this tree.
#
# It starts a private stack (Redis without persistence, the Synapse mock of this
# tree, the OLD siwx-oidc), runs the mint stages, replaces ONLY siwx-oidc with the
# NEW build (same Redis, same mock, same configuration), runs the check stages,
# and tears the stack down. The suites, all from this tree:
#
#   R1  tests/e2e_race_teardown.rs legacy_tokens_keep_working_after_the_upgrade
#       (E2E_R1_STAGE=mint|check): legacy access and refresh tokens at both
#       refresh endpoints.
#   R2  tests/e2e_race_teardown.rs in_flight_codes_and_sessions_survive_the_upgrade
#       (E2E_R2_STAGE=mint|check): codes, login sessions, device codes and client
#       registrations in flight.
#   T1  siwx-oidc-auth/tests/live_upgrade.rs (QUALIFY_STAGE=mint|check|cleanup)
#       with the mock as the homeserver: it forwards the two client-server routes
#       an edge sends to siwx-oidc (refresh, device deletion), as a deployment does.
#   T4  (only with UPGRADE_SOAK_SECS > 0) siwx-oidc-auth/examples/soak.rs, started
#       on the OLD build and held across the switch, which then leaves siwx-oidc
#       down for UPGRADE_SWAP_GAP_SECS (default 20) to model a recreate.
#
# Every check stage must run within 300 s of its mint (legacy access tokens and
# in-flight codes live that long), so the test binaries are built first.
#
# Environment (all optional):
#   UPGRADE_OIDC_PORT (18391), UPGRADE_MOCK_PORT (18390), UPGRADE_REDIS_PORT (16390)
#   UPGRADE_RUN_DIR   evidence directory (default ~/.cache/siwx-oidc-upgrade-from/<UTC time>);
#                     it holds local test credentials of this throwaway stack: mode 0700
#   UPGRADE_SOAK_SECS run T4 for that long (0 = not at all; 480 or more to see the switch)
#   UPGRADE_SOAK_SESSIONS (5)
#   UPGRADE_SWAP_GAP_SECS (20 with the soak, else 0)
#   UPGRADE_KEEP=1    leave the stack running at the end
#
# Exit status: 0 when every stage passed, 1 otherwise. The summary names the old
# image with its revision label and the new build with its revision.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

OLD="${1:-${UPGRADE_OLD_IMAGE:-}}"
NEW="${2:-${UPGRADE_NEW:-}}"
if [ -z "$OLD" ]; then
  echo "usage: $0 <old-image> [<new-binary-or-image>]  (or UPGRADE_OLD_IMAGE / UPGRADE_NEW)" >&2
  exit 2
fi

OIDC_PORT="${UPGRADE_OIDC_PORT:-18391}"
MOCK_PORT="${UPGRADE_MOCK_PORT:-18390}"
REDIS_PORT="${UPGRADE_REDIS_PORT:-16390}"
SOAK_SECS="${UPGRADE_SOAK_SECS:-0}"
SOAK_SESSIONS="${UPGRADE_SOAK_SESSIONS:-5}"
if [ "$SOAK_SECS" -gt 0 ]; then GAP_DEFAULT=20; else GAP_DEFAULT=0; fi
GAP="${UPGRADE_SWAP_GAP_SECS:-$GAP_DEFAULT}"
RUN_DIR="${UPGRADE_RUN_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/siwx-oidc-upgrade-from/$(date -u +%Y%m%dT%H%M%SZ)}"
P=siwx-upgrade
BASE="http://localhost:${OIDC_PORT}"
MOCK="http://localhost:${MOCK_PORT}"

mkdir -p "$RUN_DIR" && chmod 700 "$RUN_DIR"
STATE_DIR="$RUN_DIR/t1-state"
SUMMARY="$RUN_DIR/summary.txt"
: >"$SUMMARY"
say() { echo "$*" | tee -a "$SUMMARY"; }

teardown() {
  [ -n "${SOAK_PID:-}" ] && kill "$SOAK_PID" 2>/dev/null
  if [ "${UPGRADE_KEEP:-0}" != "1" ]; then
    podman rm -f "$P-oidc" "$P-mock" "$P-redis" >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

for port in "$OIDC_PORT" "$MOCK_PORT" "$REDIS_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is in use: set UPGRADE_*_PORT" >&2
    exit 2
  fi
done

# -- the builds ----------------------------------------------------------------
podman image exists "$OLD" || podman pull "$OLD" >/dev/null || { echo "cannot pull $OLD" >&2; exit 2; }
OLD_REV="$(podman image inspect "$OLD" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null)"
if [ -z "$NEW" ]; then
  cargo build --bin siwx-oidc || exit 2
  NEW="$REPO/target/debug/siwx-oidc"
fi
if [ -f "$NEW" ]; then
  NEW_KIND=binary
  NEW="$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")"
  NEW_REV="$(git -C "$REPO" rev-parse HEAD)$(git -C "$REPO" diff --quiet HEAD -- src Cargo.toml Cargo.lock || echo '-dirty')"
else
  NEW_KIND=image
  podman image exists "$NEW" || podman pull "$NEW" >/dev/null || { echo "cannot pull $NEW" >&2; exit 2; }
  NEW_REV="$(podman image inspect "$NEW" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null)"
fi
TESTS_REV="$(git -C "$REPO" rev-parse HEAD)$(git -C "$REPO" diff --quiet HEAD || echo '-dirty')"
say "old:   $OLD (revision ${OLD_REV:-unlabelled})"
say "new:   $NEW_KIND $NEW (revision ${NEW_REV:-unlabelled})"
say "tests: $REPO at $TESTS_REV"
say "run:   $RUN_DIR"

cargo test --test e2e_race_teardown --no-run >/dev/null 2>&1 || { echo "building the R1/R2 tests failed" >&2; exit 2; }
cargo test -p siwx-oidc-auth --test live_upgrade --no-run >/dev/null 2>&1 || { echo "building T1 failed" >&2; exit 2; }
if [ "$SOAK_SECS" -gt 0 ]; then
  cargo build -p siwx-oidc-auth --example soak >/dev/null 2>&1 || { echo "building T4 failed" >&2; exit 2; }
fi

# -- the stack -----------------------------------------------------------------
OIDC_ENV=(
  -e SIWXOIDC_ADDRESS=127.0.0.1 -e SIWEOIDC_ADDRESS=127.0.0.1
  -e SIWEOIDC_PORT="$OIDC_PORT" -e SIWEOIDC_BASE_URL="$BASE"
  -e SIWEOIDC_REDIS_URL="redis://localhost:${REDIS_PORT}"
  -e SIWEOIDC_MAS_SHARED_SECRET=testsecret
  -e SIWEOIDC_SYNAPSE_ENDPOINT="$MOCK"
  -e SIWEOIDC_MATRIX_SERVER_NAME=matrix.test
  -e SIWEOIDC_REQUIRE_SECRET=false
  -e RUST_LOG=siwx_oidc=info,tower_http=warn,warn
)

wait_health() {
  for _ in $(seq 1 120); do
    curl -sf "$BASE/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "siwx-oidc did not become healthy on $BASE" >&2
  podman logs "$P-oidc" 2>&1 | tail -20 >&2
  return 1
}

start_oidc() { # <binary-or-image> <kind>
  if [ "$2" = binary ]; then
    podman run -d --name "$P-oidc" --network host -w /app -v "$REPO:/app:ro,z" \
      -v "$1:/usr/local/bin/siwx-oidc-under-test:ro,z" "${OIDC_ENV[@]}" \
      docker.io/library/ubuntu:rolling /usr/local/bin/siwx-oidc-under-test >/dev/null
  else
    podman run -d --name "$P-oidc" --network host "${OIDC_ENV[@]}" "$1" >/dev/null
  fi
}

prefix_counts() { # key prefixes only, never a key name
  podman exec "$P-redis" redis-cli --scan | sed -E 's#/.*##' | sort | uniq -c
}

podman rm -f "$P-oidc" "$P-mock" "$P-redis" >/dev/null 2>&1 || true
podman run -d --name "$P-redis" -p "127.0.0.1:${REDIS_PORT}:6379" \
  docker.io/library/redis:7-alpine redis-server --save '' --appendonly no >/dev/null || exit 2
for _ in $(seq 1 60); do
  podman exec "$P-redis" redis-cli ping 2>/dev/null | grep -q PONG && break
  sleep 0.5
done
podman run -d --name "$P-mock" --network host -v "$REPO/e2e:/app:ro,z" \
  -e SYNAPSE_MOCK_SECRET=testsecret -e SYNAPSE_MOCK_PORT="$MOCK_PORT" \
  -e SYNAPSE_MOCK_SERVER_NAME=matrix.test -e SYNAPSE_MOCK_OIDC_BASE="$BASE" \
  docker.io/library/python:3-alpine python /app/synapse_mock.py >/dev/null || exit 2
for _ in $(seq 1 60); do
  curl -sf "$MOCK/health" >/dev/null 2>&1 && break
  sleep 0.5
done
start_oidc "$OLD" image && wait_health || exit 1

export SIWEOIDC_HOST="$BASE" SYNAPSE_MOCK="$MOCK" E2E_REDIS_URL="redis://localhost:${REDIS_PORT}"
export E2E_STRICT_SKIPS=1 E2E_R1_SESSIONS="$RUN_DIR/r1.json" E2E_R2_FILE="$RUN_DIR/r2.json"
export SIWX_SERVER="$BASE" SIWX_HOMESERVER="$MOCK" QUALIFY_STATE_DIR="$STATE_DIR"
umask 077

declare -A RESULT
stage() { # <name> <log> <command...>
  local name="$1" log="$RUN_DIR/$2.log"; shift 2
  local t0=$SECONDS
  "$@" >"$log" 2>&1
  local rc=$?
  RESULT[$name]=$rc
  say "$(printf '%-14s %s  (%3d s)  %s' "$name" "$([ $rc -eq 0 ] && echo PASS || echo FAIL)" $((SECONDS - t0)) "$log")"
  return $rc
}
race() { # <stage> -- runs R1 and R2 in one test binary
  E2E_R1_STAGE="$1" E2E_R2_STAGE="$1" cargo test --test e2e_race_teardown -- --ignored --exact \
    --test-threads=1 legacy_tokens_keep_working_after_the_upgrade \
    in_flight_codes_and_sessions_survive_the_upgrade
}
t1() { # <stage>
  QUALIFY_STAGE="$1" cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture "$1_"
}

# -- mint on the old build -----------------------------------------------------
stage r1r2-mint r1r2-mint race mint
stage t1-mint t1-mint t1 mint
prefix_counts >"$RUN_DIR/keys-after-mint.txt"
if [ "$SOAK_SECS" -gt 0 ]; then
  "$REPO/target/debug/examples/soak" --sessions "$SOAK_SESSIONS" --duration "$SOAK_SECS" \
    >"$RUN_DIR/t4-soak.jsonl" 2>"$RUN_DIR/t4-soak.log" &
  SOAK_PID=$!
  for _ in $(seq 1 120); do grep -q 'sessions signed in' "$RUN_DIR/t4-soak.log" && break; sleep 0.5; done
fi

# -- the switch: only siwx-oidc, Redis and the mock kept ---------------------
podman logs "$P-oidc" >"$RUN_DIR/oidc-old.log" 2>&1
podman rm -f "$P-oidc" >/dev/null
sleep "$GAP"
start_oidc "$NEW" "$NEW_KIND" && wait_health || exit 1
say "switch: old -> new, siwx-oidc down for ~${GAP} s"

# -- check on the new build ----------------------------------------------------
stage r1r2-check r1r2-check race check
stage t1-check t1-check t1 check
stage t1-cleanup t1-cleanup t1 cleanup
if [ -n "${SOAK_PID:-}" ]; then
  wait "$SOAK_PID"
  RESULT[t4-soak]=$?
  SOAK_PID=
  say "$(printf '%-14s %s  %s' t4-soak "$([ "${RESULT[t4-soak]}" -eq 0 ] && echo PASS || echo FAIL)" "$RUN_DIR/t4-soak.jsonl")"
  tail -1 "$RUN_DIR/t4-soak.jsonl" | tee -a "$SUMMARY"
fi
prefix_counts >"$RUN_DIR/keys-after-check.txt"
podman logs "$P-oidc" >"$RUN_DIR/oidc-new.log" 2>&1

failed=0
for name in "${!RESULT[@]}"; do [ "${RESULT[$name]}" -eq 0 ] || failed=1; done
if [ $failed -eq 0 ]; then say "UPGRADE PASS"; else say "UPGRADE FAIL"; fi
exit $failed
