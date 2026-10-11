#!/usr/bin/env bash
#
# dev-stack-guest-smoke.sh
#
# Minimal smoke run for a guest-enabled dev stack (docs/guest-portal.md, "Smoke run").
# It runs, in order:
#   1. scripts/check-guest-posture.sh <issuer>
#   2. scripts/check-guest-proxy.sh   <issuer> [<direct-upstream>]
#   3. a peek with a bogus invite, expecting the documented 404 {"error":"invalid_link"}
# and exits 1 if any of them failed.
#
# It changes no state (see the two checks for what they send) and needs no secret. It
# does NOT run the level-L suites that need a live Synapse with the policy module, lk-jwt
# and LiveKit (ST-14, ST-18, ST-21, ST-34, SP-7); those belong to the operations
# repository's stack. Acceptance A1 to A8 of the guide say how to verify each by hand.
#
# USAGE:
#   scripts/dev-stack-guest-smoke.sh <issuer-base-url> [<direct-upstream-url>]
#   scripts/dev-stack-guest-smoke.sh http://localhost:18480

set -u

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <issuer-base-url> [<direct-upstream-url>]" >&2
    exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="${1%/}"
rc=0

echo "### 1/3 posture"
"$HERE/check-guest-posture.sh" "$BASE" on || rc=1
echo
echo "### 2/3 proxy"
"$HERE/check-guest-proxy.sh" "$BASE" ${2:+"$2"} || rc=1
echo
echo "### 3/3 peek with a bogus invite"
code="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' -X POST "$BASE/guest/peek" \
    -H 'Content-Type: application/json' -H "Origin: $(printf '%s' "$BASE" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')" \
    --data '{"invite_id":"AAAAAAAAAAAAAAAA","secret":"gi_00000000000000000000000000000000"}')" || code=000
body="$(curl -sS -m 15 -X POST "$BASE/guest/peek" \
    -H 'Content-Type: application/json' -H "Origin: $(printf '%s' "$BASE" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')" \
    --data '{"invite_id":"AAAAAAAAAAAAAAAA","secret":"gi_00000000000000000000000000000000"}')" || body=""
if [ "$code" = 404 ] && printf '%s' "$body" | grep -q '"invalid_link"'; then
    echo "PASS: bogus peek answers 404 invalid_link"
else
    echo "FAIL: bogus peek answered $code $body (want 404 invalid_link)"
    rc=1
fi
echo
[ "$rc" -eq 0 ] && echo "SMOKE: OK" || echo "SMOKE: FAILED"
exit "$rc"
