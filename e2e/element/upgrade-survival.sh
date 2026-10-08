#!/usr/bin/env bash
# T2: Element Web upgrade continuity across an image switch (host driver).
#
# Derived from t5-restart-survival.sh. Where T5 restarts the whole stack, T2 replaces ONE image
# and keeps every other service running, which is what a production promotion of that component
# does. T2_SWAP picks it:
#
#   siwx-oidc (default)  replace ONLY siwx-oidc (baseline -> candidate); Redis, Synapse, Element
#                        Web and the edge keep running. The stages below.
#   element-web (T2-EW)  replace ONLY element-web (ELEMENT_BASELINE_IMAGE -> ELEMENT_CANDIDATE_IMAGE);
#                        Redis, siwx-oidc, Synapse and the edge keep running. mint runs
#                        ew-upgrade-ew-capture.spec.mjs, check ew-upgrade-ew-assert.spec.mjs: the
#                        session, the device and the browser EventIndex (siwx-oidc-matrix-server
#                        patches/element-web entry 6) must survive the switch.
#
# T2_DIRECTION=rollback runs the same stages from the candidate to the baseline (the rollback
# drill): mint expects the candidate, switch goes to the baseline, check expects the baseline.
# Default upgrade (baseline -> candidate).
#
# Stages, as T2_SWAP=siwx-oidc runs them:
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
#                                     (T2_SWAP=element-web: ELEMENT_BASELINE_IMAGE and
#                                     ELEMENT_CANDIDATE_IMAGE, the two element-web images, instead)
# For switch (and a T2_NEGATIVE=flush-redis control), the lab's compose project:
#   LAB_COMPOSE_DIR                   siwx-oidc-matrix-server checkout (docker-compose.local.yml
#                                     + docker-compose.qualify.yml)
#   LAB_PROJECT                       compose project name (always explicit)
#   LAB_ENV_FILE                      the lab's env file (path relative to LAB_COMPOSE_DIR or absolute)
#   REDIS_IMAGE_REF SYNAPSE_IMAGE_REF ELEMENT_IMAGE_REF   the overlay refuses to run without them
#                                     (T2_SWAP=element-web: SIWX_OIDC_IMAGE_REF instead of
#                                     ELEMENT_IMAGE_REF, which the switch sets)
# Optional:
#   CTRF_OUTPUT       merged CTRF report (default $QUALIFY_STATE_DIR/ctrf/ctrf-report.json); the
#                     per-phase reports land next to it as t2-capture.ctrf.json, t2-assert.ctrf.json
#   T2_REFRESH_WAIT_S how long the assert waits for Element's token refresh (default 420)
#   T2_MAX_STATE_AGE_S the capture state's window (default 3600)
#   T2_NEGATIVE=flush-redis   negative control: FLUSHALL the lab's Redis between switch and
#                     check. The check MUST then fail; this driver exits with the check's status.
#   T2_NEGATIVE=drop-eventindex   (T2_SWAP=element-web) negative control: the check deletes the
#                     profile's element-eventindex IndexedDB database before it opens Element;
#                     EW-EA3 (the index was not reset) MUST then fail.
#
# The driver creates throwaway accounts on the target and deactivates them at the end of check
# (EW-UZ; EW-EZ for the Element Web swap), or right away when mint fails.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
STAGE="${QUALIFY_STAGE:-all}"
case "$STAGE" in mint|switch|check|all) ;; *) echo "[t2] QUALIFY_STAGE must be mint, switch, check or all" >&2; exit 2 ;; esac

need() { for v in "$@"; do [ -n "${!v:-}" ] || { echo "[t2] $v is not set" >&2; exit 2; }; done; }

# What is swapped: the compose service, the variable its image comes from, the two images, the
# spec pair, the image variables the lab still needs from the environment, its negative control.
SWAP="${T2_SWAP:-siwx-oidc}"
case "$SWAP" in
  siwx-oidc)
    SERVICE=siwx-oidc; SWITCH_VAR=SIWX_OIDC_IMAGE_REF; BASE_VAR=BASELINE_IMAGE; CAND_VAR=CANDIDATE_IMAGE
    CAPTURE_SPEC=ew-upgrade-capture.spec.mjs; ASSERT_SPEC=ew-upgrade-assert.spec.mjs; CLEANUP_GREP='EW-UZ'
    KEPT_VARS=(REDIS_IMAGE_REF SYNAPSE_IMAGE_REF ELEMENT_IMAGE_REF); NEGATIVE=flush-redis ;;
  element-web)
    SERVICE=element-web; SWITCH_VAR=ELEMENT_IMAGE_REF; BASE_VAR=ELEMENT_BASELINE_IMAGE; CAND_VAR=ELEMENT_CANDIDATE_IMAGE
    CAPTURE_SPEC=ew-upgrade-ew-capture.spec.mjs; ASSERT_SPEC=ew-upgrade-ew-assert.spec.mjs; CLEANUP_GREP='EW-EZ'
    KEPT_VARS=(REDIS_IMAGE_REF SYNAPSE_IMAGE_REF SIWX_OIDC_IMAGE_REF); NEGATIVE=drop-eventindex ;;
  *) echo "[t2] T2_SWAP must be siwx-oidc or element-web" >&2; exit 2 ;;
esac
if [ -n "${T2_NEGATIVE:-}" ] && [ "$T2_NEGATIVE" != "$NEGATIVE" ]; then
  echo "[t2] T2_NEGATIVE=$T2_NEGATIVE is not the control of T2_SWAP=$SWAP (that is $NEGATIVE)" >&2; exit 2
fi

need ELEMENT_URL MATRIX_URL SIWX_URL QUALIFY_STATE_DIR "$BASE_VAR" "$CAND_VAR"
case "$QUALIFY_STATE_DIR" in /*) ;; *) echo "[t2] QUALIFY_STATE_DIR must be absolute" >&2; exit 2 ;; esac
for v in "$BASE_VAR" "$CAND_VAR"; do
  case "${!v}" in *@sha256:*) ;; *) echo "[t2] $v must be pinned by digest (name@sha256:...)" >&2; exit 2 ;; esac
done
BASELINE_IMAGE="${!BASE_VAR}"; CANDIDATE_IMAGE="${!CAND_VAR}"
[ "$BASELINE_IMAGE" != "$CANDIDATE_IMAGE" ] || { echo "[t2] $BASE_VAR and $CAND_VAR are the same" >&2; exit 2; }

# Direction: FROM is what mint expects and the switch leaves, TO what the switch installs.
case "${T2_DIRECTION:-upgrade}" in
  upgrade)  FROM_IMAGE="$BASELINE_IMAGE"; FROM_LABEL=baseline; TO_IMAGE="$CANDIDATE_IMAGE"; TO_LABEL=candidate ;;
  rollback) FROM_IMAGE="$CANDIDATE_IMAGE"; FROM_LABEL=candidate; TO_IMAGE="$BASELINE_IMAGE"; TO_LABEL=baseline ;;
  *) echo "[t2] T2_DIRECTION must be upgrade or rollback" >&2; exit 2 ;;
esac
echo "[t2] swap $SERVICE, ${T2_DIRECTION:-upgrade}: $FROM_LABEL -> $TO_LABEL${T2_NEGATIVE:+, NEGATIVE CONTROL $T2_NEGATIVE}"
mkdir -p "$QUALIFY_STATE_DIR"
chmod 700 "$QUALIFY_STATE_DIR"
export ELEMENT_URL MATRIX_URL SIWX_URL QUALIFY_STATE_DIR

CTRF_OUTPUT="${CTRF_OUTPUT:-$QUALIFY_STATE_DIR/ctrf/ctrf-report.json}"
CTRF_DIR="$(dirname "$CTRF_OUTPUT")"
mkdir -p "$CTRF_DIR"
STEPS="$CTRF_DIR/t2-driver-steps.tsv"   # name<TAB>passed|failed<TAB>ms<TAB>message
# A new run starts with mint; switch and check append to its steps.
case "$STAGE" in
  mint|all) : > "$STEPS"; rm -f "$CTRF_DIR"/t2-capture.ctrf.json "$CTRF_DIR"/t2-assert.ctrf.json "$CTRF_DIR"/t2-cleanup.ctrf.json ;;
esac
touch "$STEPS"

lab_needed=0
{ [ "$STAGE" = "switch" ] || [ "$STAGE" = "all" ] || [ "${T2_NEGATIVE:-}" = "flush-redis" ]; } && lab_needed=1
COMPOSE=()
if [ "$lab_needed" = "1" ] || [ -n "${LAB_PROJECT:-}" ]; then
  need LAB_COMPOSE_DIR LAB_PROJECT LAB_ENV_FILE "${KEPT_VARS[@]}"
  # The overlay can only check that a reference is set; a tag could move under the rehearsal.
  for v in "${KEPT_VARS[@]}"; do
    case "${!v}" in *@sha256:*) ;; *) echo "[t2] $v must be pinned by digest (name@sha256:...)" >&2; exit 2 ;; esac
  done
  [ -f "$LAB_COMPOSE_DIR/docker-compose.qualify.yml" ] || { echo "[t2] no docker-compose.qualify.yml in $LAB_COMPOSE_DIR" >&2; exit 2; }
  export "${KEPT_VARS[@]}"
  COMPOSE=(docker compose -p "$LAB_PROJECT" -f docker-compose.local.yml -f docker-compose.qualify.yml --env-file "$LAB_ENV_FILE")
fi

# Compose with the given image for the swapped service; never prints the interpolated configuration.
compose() { (cd "$LAB_COMPOSE_DIR" && env "$SWITCH_VAR=$1" "${COMPOSE[@]}" "${@:2}"); }
cid_of() { compose "$1" ps -q "$2" | head -1; }
image_id() { docker image inspect -f '{{.Id}}' "$1" 2>/dev/null | sed 's/^sha256://'; }
running_image_id() { docker inspect -f '{{.Image}}' "$1" 2>/dev/null | sed 's/^sha256://'; }
label_rev() { docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null; }
now_ms() { echo $(( $(date +%s) * 1000 )); }   # seconds resolution (see t5-restart-survival.sh)
step() { # name status started_ms message
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(( $(now_ms) - $3 ))" "$4" >> "$STEPS"
  echo "[t2] $2: $1${4:+ ($4)}"
}

# The swapped service the lab runs must be $1 (an image ref); resolved by service, never by name.
expect_running() { # ref label stage
  local t0 cid want got
  t0=$(now_ms)
  if [ "${#COMPOSE[@]}" -eq 0 ]; then
    step "driver ($3): $SERVICE runs the $2 image" skipped "$t0" "LAB_PROJECT not set: the caller switches and checks the image"
    return 0
  fi
  cid=$(cid_of "$1" "$SERVICE")
  want=$(image_id "$1")
  got=$( [ -n "$cid" ] && running_image_id "$cid" || true)
  if [ -n "$cid" ] && [ -n "$want" ] && [ "$want" = "$got" ]; then
    step "driver ($3): $SERVICE runs the $2 image" passed "$t0" "revision $(label_rev "$cid")"
  else
    step "driver ($3): $SERVICE runs the $2 image" failed "$t0" "running image ${got:-none}, expected ${want:-unknown}"
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
  expect_running "$FROM_IMAGE" "$FROM_LABEL" mint
  echo "[t2] mint: $CAPTURE_SPEC on the $FROM_LABEL"
  t=$(date +%s)
  if ! run_spec "$CAPTURE_SPEC" "$CTRF_DIR/t2-capture.ctrf.json"; then
    echo "[t2] mint FAILED after $(( $(date +%s) - t ))s; deactivating what it created" >&2
    T2_CLEANUP_ONLY=1 run_spec "$ASSERT_SPEC" "$CTRF_DIR/t2-cleanup.ctrf.json" --grep "$CLEANUP_GREP" || true
    exit 1
  fi
  echo "[t2] mint took $(( $(date +%s) - t ))s"
fi

# ------------------------------------------------------------------ switch
if [ "$STAGE" = "switch" ] || [ "$STAGE" = "all" ]; then
  expect_running "$FROM_IMAGE" "$FROM_LABEL" "switch, before"
  t0=$(now_ms)
  declare -A started=()
  others=$(compose "$FROM_IMAGE" ps --services | grep -vx "$SERVICE" || true)
  for s in $others; do started[$s]=$(docker inspect -f '{{.State.StartedAt}}' "$(cid_of "$FROM_IMAGE" "$s")"); done
  echo "[t2] switch: up -d --no-deps $SERVICE -> $TO_LABEL (kept: $(echo $others | tr '\n' ' '))"
  t=$(date +%s)
  compose "$TO_IMAGE" up -d --no-deps "$SERVICE"
  # Healthy by the container's healthcheck, and serving: siwx-oidc its discovery, Element its /version.
  case "$SERVICE" in siwx-oidc) probe="${SIWX_URL}/.well-known/openid-configuration" ;; *) probe="${ELEMENT_URL}/version" ;; esac
  healthy=0
  for _ in $(seq 1 90); do
    cid=$(cid_of "$TO_IMAGE" "$SERVICE")
    h=$( [ -n "$cid" ] && docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)
    if [ "$h" = "healthy" ] && curl -sf "$probe" >/dev/null; then healthy=1; break; fi
    sleep 2
  done
  echo "[t2] switch-to-healthy took $(( $(date +%s) - t ))s"
  if [ "$healthy" = "1" ]; then
    step "driver (switch): the $TO_LABEL $SERVICE is healthy after up -d --no-deps" passed "$t0" ""
  else
    step "driver (switch): the $TO_LABEL $SERVICE is healthy after up -d --no-deps" failed "$t0" "not healthy within 180 s"
    exit 1
  fi
  expect_running "$TO_IMAGE" "$TO_LABEL" "switch, after"
  t0=$(now_ms)
  moved=""
  for s in $others; do
    now=$(docker inspect -f '{{.State.StartedAt}}' "$(cid_of "$TO_IMAGE" "$s")" 2>/dev/null || echo gone)
    [ "$now" = "${started[$s]}" ] || moved="$moved $s"
  done
  if [ -z "$moved" ]; then
    step "driver (switch): every other service kept running (StartedAt unchanged)" passed "$t0" "$(echo $others | tr '\n' ' ')"
  else
    step "driver (switch): every other service kept running (StartedAt unchanged)" failed "$t0" "restarted:$moved"
    exit 1
  fi
fi

# ------------------------------------------------------------------ check
if [ "$STAGE" = "check" ] || [ "$STAGE" = "all" ]; then
  expect_running "$TO_IMAGE" "$TO_LABEL" check
  if [ "${T2_NEGATIVE:-}" = "flush-redis" ]; then
    t0=$(now_ms)
    rcid=$(cid_of "$TO_IMAGE" redis)
    [ -n "$rcid" ] || { echo "[t2] no redis container in project $LAB_PROJECT" >&2; exit 2; }
    docker exec "$rcid" redis-cli FLUSHALL >/dev/null
    step "driver (check): NEGATIVE CONTROL: the lab's Redis was flushed before the check" passed "$t0" "the check below must fail"
  elif [ "${T2_NEGATIVE:-}" = "drop-eventindex" ]; then
    # Done by the assert spec (it needs the browser profile); T2_NEGATIVE reaches it through run.sh.
    step "driver (check): NEGATIVE CONTROL: the check deletes the profile's element-eventindex database first" passed "$(now_ms)" "EW-EA3 below must fail"
  fi
  echo "[t2] check: $ASSERT_SPEC on the $TO_LABEL"
  t=$(date +%s)
  rc=0
  run_spec "$ASSERT_SPEC" "$CTRF_DIR/t2-assert.ctrf.json" || rc=$?
  echo "[t2] check took $(( $(date +%s) - t ))s (exit $rc)"
  echo "[t2] DONE in $(( $(date +%s) - T_START ))s"
  exit "$rc"
fi
echo "[t2] DONE ($STAGE) in $(( $(date +%s) - T_START ))s"
