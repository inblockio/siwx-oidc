#!/usr/bin/env bash
#
# verify-lifecycle-live.sh
#
# Live verification of the 2026-06-09 Synapse lifecycle features against a DEPLOYED
# siwx-oidc + Synapse, confirming the assumptions that could not be verified locally
# (no live Synapse on the dev box). Pairs with the ignored e2e tests
# (tests/e2e_session_teardown.rs, tests/e2e_msc3861.rs).
#
# Features under test:
#   F1  logout / revoke delete the Synapse device (not just the Redis token)
#   F2  POST /_matrix/client/v3/logout/all (revoke all tokens + delete all devices,
#       never deactivate)
#   F3  account_erase (erase:true + token revoke + WebAuthn identity purge) and
#       account_reactivate (admin PUT deactivated:false; MSC3861 feasibility UNKNOWN)
#
# WHAT RUNS WHEN:
#   * Sections 1-2 (read-only) always run: discovery/metadata advertising + route wiring.
#   * Section 3 (REACTIVATION PROBE) and Section 5 (ERASURE) are DESTRUCTIVE on a
#     throwaway user and only run with CONFIRM_DESTRUCTIVE=1 + TEST_LOCALPART set.
#   * Section 4 (end-to-end logout teardown) runs only if you supply USER_TOKEN.
#
# SECRETS: the Synapse admin token (== the MAS shared secret) is read from $ADMIN_TOKEN
# and is NEVER printed. Run this on the server (or a host that already holds the secret).
#
# USAGE (run on the server, where the admin secret lives):
#   export ISSUER=https://siwx-oidc.inblock.io
#   export MATRIX=https://matrix.inblock.io
#   export SERVER_NAME=inblock.io                 # the Matrix server_name (mxid domain)
#   export ADMIN_TOKEN="$(grep -oP 'shared_secret:\s*\K\S+' /path/to/mas/config)"  # do not echo it
#   # read-only checks:
#   ./verify-lifecycle-live.sh
#   # + the reactivation feasibility probe + erasure on a THROWAWAY user:
#   export TEST_LOCALPART=did-pkh-eip155-1-0xdeadbeef...   # a disposable account localpart
#   CONFIRM_DESTRUCTIVE=1 ./verify-lifecycle-live.sh
#   # + end-to-end OIDC-layer logout teardown (paste a real access token, e.g. from
#   #   Element devtools, that belongs to TEST_LOCALPART):
#   USER_TOKEN="mat_..." CONFIRM_DESTRUCTIVE=1 ./verify-lifecycle-live.sh

set -uo pipefail

# --- config ---------------------------------------------------------------
ISSUER="${ISSUER:-https://siwx-oidc.inblock.io}"
MATRIX="${MATRIX:-https://matrix.inblock.io}"
SERVER_NAME="${SERVER_NAME:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
TEST_LOCALPART="${TEST_LOCALPART:-}"
USER_TOKEN="${USER_TOKEN:-}"
CONFIRM_DESTRUCTIVE="${CONFIRM_DESTRUCTIVE:-0}"

command -v curl >/dev/null || { echo "need curl"; exit 2; }
command -v jq   >/dev/null || { echo "need jq";   exit 2; }

PASS=0 FAIL=0 SKIP=0
green() { printf '\033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
red()   { printf '\033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip()  { printf '\033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
hdr()   { printf '\n=== %s ===\n' "$1"; }

# curl returning "BODY<newline>HTTP_STATUS"; admin auth added only if ADMIN_TOKEN set.
admin_curl() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "Authorization: Bearer ${ADMIN_TOKEN}" -w $'\n%{http_code}')
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "${MATRIX}${path}" 2>/dev/null
}
mxid() { printf '@%s:%s' "$1" "$SERVER_NAME"; }

# --- 1. discovery / metadata advertising (read-only) ----------------------
hdr "1. New actions advertised (OIDC discovery + Synapse auth_metadata)"
check_actions() { # url label
  local doc; doc="$(curl -sS "$1" 2>/dev/null)" || { red "$2 unreachable ($1)"; return; }
  local acts; acts="$(jq -r '.account_management_actions_supported // [] | join(",")' <<<"$doc" 2>/dev/null)"
  for want in org.matrix.account_erase org.matrix.account_reactivate org.matrix.account_deactivate; do
    if grep -q "$want" <<<"$acts"; then green "$2 advertises $want"; else red "$2 MISSING $want (got: $acts)"; fi
  done
}
check_actions "${ISSUER}/.well-known/openid-configuration" "OIDC discovery"
check_actions "${MATRIX}/_matrix/client/v1/auth_metadata"   "Synapse auth_metadata"

# --- 2. teardown routes wired (read-only; idempotent no-op) ----------------
hdr "2. Teardown routes exist (expect 200, NOT 404, on an empty/invalid request)"
route_probe() { # method path label
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -X "$1" "${ISSUER}$2" 2>/dev/null)"
  case "$code" in
    200|204) green "$3 -> $code (wired, idempotent no-op)";;
    404)     red   "$3 -> 404 (ROUTE MISSING)";;
    *)       green "$3 -> $code (wired; non-404)";;
  esac
}
route_probe POST /_matrix/client/v3/logout      "logout"
route_probe POST /_matrix/client/v3/logout/all  "logout/all"
route_probe POST /oauth2/revoke                 "revoke"   # form endpoint; non-404 = wired

# --- 3. REACTIVATION feasibility probe under MSC3861 (DESTRUCTIVE) ---------
# This is the key unverified assumption: does Synapse admin reactivation
# (PUT users {deactivated:false}) actually work when MAS owns auth?
hdr "3. Reactivation feasibility under MSC3861 (DESTRUCTIVE, throwaway user)"
if [ "$CONFIRM_DESTRUCTIVE" != 1 ] || [ -z "$ADMIN_TOKEN" ] || [ -z "$SERVER_NAME" ] || [ -z "$TEST_LOCALPART" ]; then
  skip "reactivation probe (needs CONFIRM_DESTRUCTIVE=1 + ADMIN_TOKEN + SERVER_NAME + TEST_LOCALPART)"
else
  ID="$(mxid "$TEST_LOCALPART")"
  echo "  target (throwaway): $ID"
  # baseline
  base="$(admin_curl GET "/_synapse/admin/v2/users/$(jq -rn --arg s "$ID" '$s|@uri')")"
  echo "  baseline deactivated=$(jq -r '.deactivated // "?"' <<<"${base%$'\n'*}" 2>/dev/null)"
  # deactivate erase:false
  admin_curl POST "/_synapse/admin/v1/deactivate/$(jq -rn --arg s "$ID" '$s|@uri')" '{"erase": false}' >/dev/null
  after_de="$(admin_curl GET "/_synapse/admin/v2/users/$(jq -rn --arg s "$ID" '$s|@uri')")"
  if [ "$(jq -r '.deactivated' <<<"${after_de%$'\n'*}" 2>/dev/null)" = true ]; then
    green "deactivate(erase:false) -> user deactivated"
  else red "deactivate did not set deactivated:true"; fi
  # the probe: reactivate
  rea="$(admin_curl PUT "/_synapse/admin/v2/users/$(jq -rn --arg s "$ID" '$s|@uri')" '{"deactivated": false}')"
  rea_code="${rea##*$'\n'}"; rea_body="${rea%$'\n'*}"
  echo "  reactivate PUT -> HTTP $rea_code; body: $(head -c 300 <<<"$rea_body")"
  after_re="$(admin_curl GET "/_synapse/admin/v2/users/$(jq -rn --arg s "$ID" '$s|@uri')")"
  if [ "$(jq -r '.deactivated' <<<"${after_re%$'\n'*}" 2>/dev/null)" = false ]; then
    green "REACTIVATION SUPPORTED under MSC3861 (keep org.matrix.account_reactivate advertised)"
  else
    red  "REACTIVATION BLOCKED under MSC3861 (HTTP $rea_code) -> drop account_reactivate from SUPPORTED_ACTIONS or keep ask-admin message; user '$ID' is left DEACTIVATED"
  fi
fi

# --- 4. End-to-end logout teardown through the OIDC layer (needs USER_TOKEN) -
hdr "4. logout / logout-all delete the Synapse device (end-to-end, needs USER_TOKEN)"
if [ -z "$USER_TOKEN" ] || [ -z "$ADMIN_TOKEN" ] || [ -z "$SERVER_NAME" ] || [ -z "$TEST_LOCALPART" ]; then
  skip "OIDC-layer teardown (needs USER_TOKEN + ADMIN_TOKEN + SERVER_NAME + TEST_LOCALPART for the token's user)"
else
  ID="$(mxid "$TEST_LOCALPART")"; ENC="$(jq -rn --arg s "$ID" '$s|@uri')"
  before="$(admin_curl GET "/_synapse/admin/v2/users/${ENC}/devices")"
  n_before="$(jq -r '.total // (.devices|length)' <<<"${before%$'\n'*}" 2>/dev/null)"
  echo "  devices before: ${n_before}"
  # single-session logout
  curl -sS -o /dev/null -X POST -H "Authorization: Bearer ${USER_TOKEN}" "${ISSUER}/_matrix/client/v3/logout"
  after="$(admin_curl GET "/_synapse/admin/v2/users/${ENC}/devices")"
  n_after="$(jq -r '.total // (.devices|length)' <<<"${after%$'\n'*}" 2>/dev/null)"
  echo "  devices after logout: ${n_after}"
  if [ "${n_after:-x}" -lt "${n_before:-0}" ] 2>/dev/null; then
    green "logout removed the session's Synapse device (${n_before} -> ${n_after})"
  else
    red "logout did not remove a Synapse device (check SIWEOIDC_MATRIX_SERVER_NAME is set on the server)"
  fi
  echo "  NOTE: to test logout/all, log in 2+ sessions, then:"
  echo "        curl -X POST -H 'Authorization: Bearer <tok>' ${ISSUER}/_matrix/client/v3/logout/all"
  echo "        then GET admin .../devices -> expect 0, and confirm you can still sign in (account active)."
fi

# --- 5. Erasure (DESTRUCTIVE) ---------------------------------------------
hdr "5. account_erase: erase:true purges profile (DESTRUCTIVE, irreversible)"
if [ "$CONFIRM_DESTRUCTIVE" != 1 ] || [ -z "$ADMIN_TOKEN" ] || [ -z "$SERVER_NAME" ] || [ -z "$TEST_LOCALPART" ]; then
  skip "erasure check (needs CONFIRM_DESTRUCTIVE=1 + ADMIN_TOKEN + SERVER_NAME + TEST_LOCALPART)"
else
  ID="$(mxid "$TEST_LOCALPART")"; ENC="$(jq -rn --arg s "$ID" '$s|@uri')"
  admin_curl POST "/_synapse/admin/v1/deactivate/${ENC}" '{"erase": true}' >/dev/null
  u="$(admin_curl GET "/_synapse/admin/v2/users/${ENC}")"
  dn="$(jq -r '.displayname // ""' <<<"${u%$'\n'*}" 2>/dev/null)"
  if [ -z "$dn" ] || [ "$dn" = null ]; then green "erase:true cleared the display name / profile"; else red "profile still present after erase (displayname='$dn')"; fi
  echo "  (the siwx-oidc account_erase action also revokes all tokens + purges webauthn:link/credential for the DID;"
  echo "   verify with: redis-cli KEYS 'webauthn:link/*' / 'token/*' before+after the /account erase action.)"
fi

# --- summary --------------------------------------------------------------
hdr "summary"
printf 'PASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
