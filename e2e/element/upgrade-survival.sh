#!/usr/bin/env bash
# T2: Element Web upgrade continuity across a siwx-oidc image switch (host driver).
#
# Derived from t5-restart-survival.sh. Where T5 restarts the whole stack, T2 replaces ONLY the
# siwx-oidc image (baseline -> candidate) and keeps Redis, Synapse, Element Web and the edge
# running, which is what a production promotion of siwx-oidc does:
#
#   mint    the running siwx-oidc must be BASELINE_IMAGE; ew-upgrade-capture.spec.mjs signs a
#           user in through Element in a persistent browser profile, with recovery key,
#           an encrypted room shared with a second user, a second device and a passkey account
#   switch  `up -d --no-deps siwx-oidc` with SIWX_OIDC_IMAGE_REF=CANDIDATE_IMAGE on the lab
#           compose project; health; the candidate runs; every other service kept its StartedAt
#   check   the running siwx-oidc must be CANDIDATE_IMAGE; ew-upgrade-assert.spec.mjs reopens
#           the profile and checks what a user would notice (see that file's header)
#
# QUALIFY_STAGE selects mint, switch, check, or all three (default). The pre-prod qualification
# driver runs mint, switches with its own `component` step, then runs check.
#
# Required:
#   ELEMENT_URL MATRIX_URL SIWX_URL   the lab's three public URLs (no defaults)
#   QUALIFY_STATE_DIR                 absolute, mode 700, under ~/.cache; must not hold a profile
#                                     yet when mint runs (browser profile, state, passkey: secrets
#                                     of throwaway lab accounts)
#   BASELINE_IMAGE CANDIDATE_IMAGE    siwx-oidc image references (name@sha256:digest)
# For switch (and a T2_NEGATIVE control), the lab's compose project:
#   LAB_COMPOSE_DIR                   siwx-oidc-matrix-server checkout (docker-compose.local.yml
#                                     + docker-compose.qualify.yml)
#   LAB_PROJECT                       compose project name (always explicit)
#   LAB_ENV_FILE                      the lab's env file (path relative to LAB_COMPOSE_DIR or absolute)
#   REDIS_IMAGE_REF SYNAPSE_IMAGE_REF ELEMENT_IMAGE_REF   the overlay refuses to run without them
# Optional:
#   CTRF_OUTPUT       merged CTRF report (default $QUALIFY_STATE_DIR/ctrf/ctrf-report.json); the
#                     per-phase reports land next to it as t2-capture.ctrf.json, t2-assert.ctrf.json
#   T2_REFRESH_WAIT_S how long the assert waits for Element's token refresh (default 420)
#   T2_MAX_STATE_AGE_S the capture state's window (default 3600)
#   T2_NEGATIVE=flush-redis   negative control: FLUSHALL the lab's Redis between switch and
#                     check. The check MUST then fail; this driver exits with the check's status.
#
# The driver creates throwaway accounts on the target and deactivates them at the end of check
# (EW-UZ), or right away when mint fails.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
STAGE="${QUALIFY_STAGE:-all}"
case "$STAGE" in mint|switch|check|all) ;; *) echo "[t2] QUALIFY_STAGE must be mint, switch, check or all" >&2; exit 2 ;; esac

need() { for v in "$@"; do [ -n "${!v:-}" ] || { echo "[t2] $v is not set" >&2; exit 2; }; done; }
need ELEMENT_URL MATRIX_URL SIWX_URL QUALIFY_STATE_DIR BASELINE_IMAGE CANDIDATE_IMAGE
case "$QUALIFY_STATE_DIR" in /*) ;; *) echo "[t2] QUALIFY_STATE_DIR must be absolute" >&2; exit 2 ;; esac
for v in BASELINE_IMAGE CANDIDATE_IMAGE; do
  case "${!v}" in *@sha256:*) ;; *) echo "[t2] $v must be pinned by digest (name@sha256:...)" >&2; exit 2 ;; esac
done
[ "$BASELINE_IMAGE" != "$CANDIDATE_IMAGE" ] || { echo "[t2] BASELINE_IMAGE and CANDIDATE_IMAGE are the same" >&2; exit 2; }
mkdir -p "$QUALIFY_STATE_DIR"
chmod 700 "$QUALIFY_STATE_DIR"
export ELEMENT_URL MATRIX_URL SIWX_URL QUALIFY_STATE_DIR

CTRF_OUTPUT="${CTRF_OUTPUT:-$QUALIFY_STATE_DIR/ctrf/ctrf-report.json}"
CTRF_DIR="$(dirname "$CTRF_OUTPUT")"
mkdir -p "$CTRF_DIR"
STEPS="$CTRF_DIR/t2-driver-steps.tsv"   # name<TAB>passed|failed<TAB>ms<TAB>message
[ "$STAGE" = "check" ] || : > "$STEPS"
touch "$STEPS"

lab_needed=0
{ [ "$STAGE" = "switch" ] || [ "$STAGE" = "all" ] || [ -n "${T2_NEGATIVE:-}" ]; } && lab_needed=1
COMPOSE=()
if [ "$lab_needed" = "1" ] || [ -n "${LAB_PROJECT:-}" ]; then
  need LAB_COMPOSE_DIR LAB_PROJECT LAB_ENV_FILE REDIS_IMAGE_REF SYNAPSE_IMAGE_REF ELEMENT_IMAGE_REF
  [ -f "$LAB_COMPOSE_DIR/docker-compose.qualify.yml" ] || { echo "[t2] no docker-compose.qualify.yml in $LAB_COMPOSE_DIR" >&2; exit 2; }
  export REDIS_IMAGE_REF SYNAPSE_IMAGE_REF ELEMENT_IMAGE_REF
  COMPOSE=(docker compose -p "$LAB_PROJECT" -f docker-compose.local.yml -f docker-compose.qualify.yml --env-file "$LAB_ENV_FILE")
fi

# Compose with the given siwx-oidc image; never prints the interpolated configuration.
compose() { (cd "$LAB_COMPOSE_DIR" && SIWX_OIDC_IMAGE_REF="$1" "${COMPOSE[@]}" "${@:2}"); }
cid_of() { compose "$1" ps -q "$2" | head -1; }
image_id() { docker image inspect -f '{{.Id}}' "$1" 2>/dev/null | sed 's/^sha256://'; }
running_image_id() { docker inspect -f '{{.Image}}' "$1" 2>/dev/null | sed 's/^sha256://'; }
label_rev() { docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null; }
now_ms() { echo $(( $(date +%s) * 1000 )); }   # seconds resolution (see t5-restart-survival.sh)
step() { # name status started_ms message
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(( $(now_ms) - $3 ))" "$4" >> "$STEPS"
  echo "[t2] $2: $1${4:+ ($4)}"
}

# The siwx-oidc the lab runs must be $1 (an image ref); resolved by service, never by name.
expect_running() { # ref label
  local t0 cid want got
  t0=$(now_ms)
  if [ "${#COMPOSE[@]}" -eq 0 ]; then
    step "driver: siwx-oidc runs the $2 image" skipped "$t0" "LAB_PROJECT not set: the caller switches and checks the image"
    return 0
  fi
  cid=$(cid_of "$1" siwx-oidc)
  want=$(image_id "$1")
  got=$( [ -n "$cid" ] && running_image_id "$cid" || true)
  if [ -n "$cid" ] && [ -n "$want" ] && [ "$want" = "$got" ]; then
    step "driver: siwx-oidc runs the $2 image" passed "$t0" "revision $(label_rev "$cid")"
  else
    step "driver: siwx-oidc runs the $2 image" failed "$t0" "running image ${got:-none}, expected ${want:-unknown}"
    return 1
  fi
}

run_spec() { # spec ctrf-file [args...]
  local spec="$1" out="$2"; shift 2
  CTRF_OUTPUT="$out" bash "$DIR/run.sh" "$spec" "$@"
}

merge_ctrf() {
  python3 - "$CTRF_OUTPUT" "$STEPS" "$CTRF_DIR/t2-capture.ctrf.json" "$CTRF_DIR/t2-assert.ctrf.json" <<'PY'
import json, os, sys, time
out, steps, *parts = sys.argv[1:]
tests, start, stop, tool = [], None, None, {"name": "playwright"}
for p in parts:
    if not os.path.exists(p):
        continue
    r = json.load(open(p))["results"]
    tool = r.get("tool", tool)
    tests += r["tests"]
    s = r["summary"]
    start = s["start"] if start is None else min(start, s["start"])
    stop = s["stop"] if stop is None else max(stop, s["stop"])
for line in open(steps):
    name, status, ms, msg = (line.rstrip("\n").split("\t") + [""])[:4]
    t = {"name": name, "status": status, "duration": int(ms), "suite": "upgrade-survival.sh"}
    if msg:
        t["message"] = msg
    tests.append(t)
now = int(time.time() * 1000)
summary = {k: sum(1 for t in tests if t["status"] == k) for k in ("passed", "failed", "skipped", "pending", "other")}
summary.update(tests=len(tests), start=start or now, stop=stop or now)
json.dump({"results": {"tool": tool, "summary": summary, "tests": tests,
           "environment": {"appName": "siwx-oidc e2e/element T2 upgrade-survival"}}},
          open(out, "w"), indent=2)
print(f"[t2] CTRF {out}: " + ", ".join(f"{k} {summary[k]}" for k in ("tests", "passed", "failed", "skipped")))
PY
}
trap merge_ctrf EXIT

T_START=$(date +%s)

# ------------------------------------------------------------------ mint
if [ "$STAGE" = "mint" ] || [ "$STAGE" = "all" ]; then
  expect_running "$BASELINE_IMAGE" baseline
  echo "[t2] mint: ew-upgrade-capture.spec.mjs on the baseline"
  t=$(date +%s)
  if ! run_spec ew-upgrade-capture.spec.mjs "$CTRF_DIR/t2-capture.ctrf.json"; then
    echo "[t2] mint FAILED after $(( $(date +%s) - t ))s; deactivating what it created" >&2
    T2_CLEANUP_ONLY=1 run_spec ew-upgrade-assert.spec.mjs "$CTRF_DIR/t2-cleanup.ctrf.json" --grep 'EW-UZ' || true
    exit 1
  fi
  echo "[t2] mint took $(( $(date +%s) - t ))s"
fi

# ------------------------------------------------------------------ switch
if [ "$STAGE" = "switch" ] || [ "$STAGE" = "all" ]; then
  expect_running "$BASELINE_IMAGE" baseline
  t0=$(now_ms)
  declare -A started=()
  others=$(compose "$BASELINE_IMAGE" ps --services | grep -vx 'siwx-oidc' || true)
  for s in $others; do started[$s]=$(docker inspect -f '{{.State.StartedAt}}' "$(cid_of "$BASELINE_IMAGE" "$s")"); done
  echo "[t2] switch: up -d --no-deps siwx-oidc -> candidate (kept: $(echo $others | tr '\n' ' '))"
  t=$(date +%s)
  compose "$CANDIDATE_IMAGE" up -d --no-deps siwx-oidc
  healthy=0
  for _ in $(seq 1 90); do
    cid=$(cid_of "$CANDIDATE_IMAGE" siwx-oidc)
    h=$( [ -n "$cid" ] && docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)
    if [ "$h" = "healthy" ] && curl -sf "${SIWX_URL}/.well-known/openid-configuration" >/dev/null; then healthy=1; break; fi
    sleep 2
  done
  echo "[t2] switch-to-healthy took $(( $(date +%s) - t ))s"
  if [ "$healthy" = "1" ]; then
    step "driver: the candidate siwx-oidc is healthy after up -d --no-deps" passed "$t0" ""
  else
    step "driver: the candidate siwx-oidc is healthy after up -d --no-deps" failed "$t0" "not healthy within 180 s"
    exit 1
  fi
  expect_running "$CANDIDATE_IMAGE" candidate
  t0=$(now_ms)
  moved=""
  for s in $others; do
    now=$(docker inspect -f '{{.State.StartedAt}}' "$(cid_of "$CANDIDATE_IMAGE" "$s")" 2>/dev/null || echo gone)
    [ "$now" = "${started[$s]}" ] || moved="$moved $s"
  done
  if [ -z "$moved" ]; then
    step "driver: every other service kept running (StartedAt unchanged)" passed "$t0" "$(echo $others | tr '\n' ' ')"
  else
    step "driver: every other service kept running (StartedAt unchanged)" failed "$t0" "restarted:$moved"
    exit 1
  fi
fi

# ------------------------------------------------------------------ check
if [ "$STAGE" = "check" ] || [ "$STAGE" = "all" ]; then
  expect_running "$CANDIDATE_IMAGE" candidate
  if [ "${T2_NEGATIVE:-}" = "flush-redis" ]; then
    t0=$(now_ms)
    rcid=$(cid_of "$CANDIDATE_IMAGE" redis)
    [ -n "$rcid" ] || { echo "[t2] no redis container in project $LAB_PROJECT" >&2; exit 2; }
    docker exec "$rcid" redis-cli FLUSHALL >/dev/null
    step "driver: NEGATIVE CONTROL: the lab's Redis was flushed before the check" passed "$t0" "the check below must fail"
  elif [ -n "${T2_NEGATIVE:-}" ]; then
    echo "[t2] unknown T2_NEGATIVE=${T2_NEGATIVE}" >&2; exit 2
  fi
  echo "[t2] check: ew-upgrade-assert.spec.mjs on the candidate"
  t=$(date +%s)
  rc=0
  run_spec ew-upgrade-assert.spec.mjs "$CTRF_DIR/t2-assert.ctrf.json" || rc=$?
  echo "[t2] check took $(( $(date +%s) - t ))s (exit $rc)"
  echo "[t2] DONE in $(( $(date +%s) - T_START ))s"
  exit "$rc"
fi
echo "[t2] DONE ($STAGE) in $(( $(date +%s) - T_START ))s"
