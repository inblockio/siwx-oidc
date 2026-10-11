#!/usr/bin/env bash
#
# check-guest-posture.sh
#
# Deployment posture check for siwx-oidc guest mode. It probes a RUNNING issuer
# over HTTP and prints one PASS / FAIL / SKIP line per check; it exits 1 when
# any check FAILed, 0 otherwise. See docs/guest-portal.md (acceptance A1..A8).
#
# What it proves (the app half of GP-SEC-04, 30, 39, 40, 41):
#   1. Guest flag state: an unknown /guest path answers 404 (on) or 503
#      guest_unavailable (off). With the flag off, the checks that need guest
#      mode on are reported SKIP; the shell's own headers are still checked.
#   2. GP-SEC-39 security headers on every guest response, errors included.
#   3. A POST without a provably same-origin Origin / Sec-Fetch-Site is refused
#      403; a non-JSON POST is 415; a body over 4 KiB is 413 (claim/finish: 16 KiB).
#   4. The routes a guest's browser calls answer no CORS; the Bearer routes
#      answer exactly "Access-Control-Allow-Origin: *" and no credentials.
#   5. The helper pages (/guest/continue, join, ended, claim) are served from the
#      issuer origin with a CSP that has no 'unsafe-inline' for scripts, and the
#      HTML has no inline <script> body, no on*= handler and no javascript: URL.
#   6. Host and guest-Bearer routes refuse an anonymous request.
#   7. Discovery names this issuer.
#
# What it does NOT prove (no HTTP probe can; see the guide's checklist): the
# Synapse configuration (user_types, policy module, federation, auto_join_rooms,
# publishRooms), Redis persistence, proxy rate limits (check-guest-proxy.sh), log
# retention.
#
# Read-only: it sends GETs and a handful of POSTs carrying a made-up invite id
# and no valid secret. Nothing is created. Each bogus peek that reaches the
# handler is one counted `guest_refused` audit event (see refusal_burst).
# No credentials, tokens or secrets are needed, read or printed.
#
# Dependencies: bash, curl, grep, sed, tr, head.
#
# USAGE:
#   scripts/check-guest-posture.sh <issuer-base-url> [on|off]
#   scripts/check-guest-posture.sh https://id.example.org
#   scripts/check-guest-posture.sh http://localhost:18480 off
# The optional second argument states the flag you EXPECT; a mismatch FAILs.

set -u

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <issuer-base-url> [on|off]" >&2
    exit 2
fi
BASE="${1%/}"
EXPECT="${2:-}"
case "$EXPECT" in "" | on | off) ;; *)
    echo "usage: $0 <issuer-base-url> [on|off]" >&2
    exit 2
    ;;
esac
# The Origin a same-origin browser sends: scheme://host[:port] of the base URL.
ORIGIN="$(printf '%s' "$BASE" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')"
EVIL="https://evil.example.org"
FAKE_ID="AAAAAAAAAAAAAAAA"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
H="$TMP/h"
B="$TMP/b"

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $*"; }

# req METHOD PATH [curl args...]  ->  CODE, headers in $H (CR stripped), body in $B
req() {
    local method="$1" path="$2"
    shift 2
    : >"$H"
    : >"$B"
    CODE="$(curl -sS -m 15 -X "$method" -D "$H" -o "$B" -w '%{http_code}' -H 'Expect:' "$@" "$BASE$path" 2>/dev/null)" || CODE=000
    tr -d '\r' <"$H" >"$H.n" && mv "$H.n" "$H"
}
# hdr NAME -> every value of that response header, one per line
hdr() { grep -i "^$1:" "$H" | sed -E 's/^[^:]*:[[:space:]]*//'; }
has_hdr() { grep -qi "^$1:" "$H"; }
# bodycode -> the "error" field of a JSON error body
bodycode() { sed -nE 's/.*"error"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$B" | head -n 1; }
# post_json PATH ORIGIN-OR-"-" [extra curl args]: JSON POST with a made-up invite
post_json() {
    local path="$1" origin="$2"
    shift 2
    local args=(-H 'Content-Type: application/json' --data "{\"invite_id\":\"$FAKE_ID\",\"secret\":\"gi_00000000000000000000000000000000\"}")
    [ "$origin" != "-" ] && args+=(-H "Origin: $origin")
    req POST "$path" "${args[@]}" "$@"
}

# GP-SEC-39 on the response currently in $H.
check_security_headers() {
    local what="$1" csp bad=""
    csp="$(hdr content-security-policy | head -n 1)"
    case "$csp" in *"default-src 'self'"*) ;; *) bad="$bad CSP.default-src" ;; esac
    case "$csp" in *"script-src 'self'"*) ;; *) bad="$bad CSP.script-src" ;; esac
    case "$csp" in *"frame-ancestors 'none'"*) ;; *) bad="$bad CSP.frame-ancestors" ;; esac
    case "$csp" in *"base-uri 'none'"*) ;; *) bad="$bad CSP.base-uri" ;; esac
    hdr x-frame-options | grep -qix 'DENY' || bad="$bad X-Frame-Options"
    hdr referrer-policy | grep -qix 'no-referrer' || bad="$bad Referrer-Policy"
    hdr x-content-type-options | grep -qix 'nosniff' || bad="$bad X-Content-Type-Options"
    hdr cache-control | grep -qi 'no-store' || bad="$bad Cache-Control"
    if [ -z "$bad" ]; then
        pass "security headers (GP-SEC-39) on $what"
    else
        fail "security headers missing or wrong on $what:$bad"
    fi
}

echo "== guest mode posture =="
echo "issuer: $BASE   origin: $ORIGIN"

# --- 1. flag state -----------------------------------------------------------
req GET "/guest/posture-probe-$$"
STATE=""
case "$CODE:$(bodycode)" in
    404:not_found) STATE=on ;;
    503:guest_unavailable) STATE=off ;;
esac
if [ -z "$STATE" ]; then
    fail "guest flag state: /guest/<unknown> answered $CODE $(bodycode) (want 404 not_found when on, 503 guest_unavailable when off); is this a siwx-oidc issuer?"
    echo
    echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 1
fi
echo "guest flag detected: $STATE"
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$STATE" ]; then
    fail "guest flag is $STATE, expected $EXPECT"
else
    pass "guest flag is $STATE${EXPECT:+ (as expected)}"
fi
check_security_headers "the /guest ${STATE} shell ($CODE)"
if has_hdr access-control-allow-origin; then
    fail "the /guest shell answers Access-Control-Allow-Origin (guest routes sit outside the global CORS layer)"
else
    pass "no Access-Control-Allow-Origin on the /guest shell"
fi

if [ "$STATE" = off ]; then
    for what in \
        "same-origin check on POST (403 forbidden_origin)" \
        "JSON-only POST (415)" \
        "body caps (413)" \
        "no CORS on the cookie routes; * only on the Bearer routes" \
        "helper pages: CSP and no inline script" \
        "host and guest Bearer routes refuse anonymous callers" \
        "peek of an unknown invite answers invalid_link"; do
        skip "$what (guest mode is off)"
    done
else
    # --- 3. peek of a bogus invite: the documented error ----------------------
    post_json /guest/peek "$ORIGIN"
    KILL=0
    if [ "$CODE" = 404 ] && [ "$(bodycode)" = invalid_link ]; then
        pass "peek of an unknown invite answers 404 invalid_link"
        check_security_headers "POST /guest/peek (404)"
    elif [ "$CODE" = 503 ] && [ "$(bodycode)" = disabled ]; then
        KILL=1
        skip "peek of an unknown invite: the kill switch is engaged (503 disabled; guest:control disabled)"
    else
        fail "peek of an unknown invite answered $CODE $(bodycode) (want 404 invalid_link); a public origin different from base_url would show here as 403 forbidden_origin"
    fi

    # --- 3. same-origin check -------------------------------------------------
    post_json /guest/peek "$EVIL"
    if [ "$CODE" = 403 ] && [ "$(bodycode)" = forbidden_origin ]; then
        pass "POST /guest/peek with a foreign Origin is refused 403 forbidden_origin"
        check_security_headers "the 403 forbidden_origin response"
    else
        fail "POST /guest/peek with Origin: $EVIL answered $CODE $(bodycode) (want 403 forbidden_origin)"
    fi
    post_json /guest/peek - -H 'Sec-Fetch-Site: cross-site'
    if [ "$CODE" = 403 ]; then
        pass "POST /guest/peek with Sec-Fetch-Site: cross-site is refused 403"
    else
        fail "POST /guest/peek with Sec-Fetch-Site: cross-site answered $CODE (want 403)"
    fi
    post_json /guest/peek -
    if [ "$CODE" = 403 ]; then
        pass "POST /guest/peek with neither Origin nor Sec-Fetch-Site is refused 403"
    else
        fail "POST /guest/peek with no Origin and no Sec-Fetch-Site answered $CODE (want 403)"
    fi
    post_json /guest/redeem "$ORIGIN" -H 'Sec-Fetch-Site: same-site'
    if [ "$CODE" = 403 ]; then
        pass "POST /guest/redeem with Sec-Fetch-Site: same-site is refused 403 (a sibling origin is not the issuer)"
    else
        fail "POST /guest/redeem with Sec-Fetch-Site: same-site answered $CODE (want 403)"
    fi

    # --- 3. JSON only, body caps ---------------------------------------------
    req POST /guest/peek -H "Origin: $ORIGIN" -H 'Content-Type: text/plain' --data 'x=1'
    if [ "$CODE" = 415 ]; then
        pass "non-JSON POST /guest/peek is refused 415"
    else
        fail "text/plain POST /guest/peek answered $CODE (want 415)"
    fi
    req POST /guest/peek -H "Origin: $ORIGIN" --data 'x=1'
    if [ "$CODE" = 415 ]; then
        pass "form-encoded POST /guest/peek is refused 415"
    else
        fail "form POST /guest/peek answered $CODE (want 415)"
    fi
    printf '{"invite_id":"%s"}' "$(head -c 5000 /dev/zero | tr '\0' a)" >"$TMP/5k.json"
    req POST /guest/peek -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/5k.json"
    if [ "$CODE" = 413 ]; then
        pass "a 5 KiB body on /guest/peek is refused 413"
    else
        fail "a 5 KiB body on /guest/peek answered $CODE (want 413; the cap is 4 KiB)"
    fi
    printf '{"x":"%s"}' "$(head -c 17000 /dev/zero | tr '\0' a)" >"$TMP/17k.json"
    req POST /guest/claim/finish -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/17k.json"
    if [ "$CODE" = 413 ]; then
        pass "a 17 KiB body on /guest/claim/finish is refused 413"
    else
        fail "a 17 KiB body on /guest/claim/finish answered $CODE (want 413; the cap is 16 KiB)"
    fi
    req POST /guest/claim/finish -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/5k.json"
    if [ "$CODE" != 413 ]; then
        pass "a 5 KiB body on /guest/claim/finish passes the size gate (answered $CODE; its own cap is 16 KiB)"
    else
        fail "a 5 KiB body on /guest/claim/finish was refused 413 (the claim route must accept up to 16 KiB)"
    fi

    # --- 4. CORS --------------------------------------------------------------
    cors_bad=""
    for p in "GET /guest/ended" "GET /guest/claim" "GET /guest/continue" "GET /guest/resume" "GET /guest/join/$FAKE_ID" "GET /guest/assets/join.js"; do
        req "${p%% *}" "${p#* }" -H "Origin: $EVIL"
        has_hdr access-control-allow-origin && cors_bad="$cors_bad ${p#* }"
    done
    post_json /guest/peek "$EVIL"
    has_hdr access-control-allow-origin && cors_bad="$cors_bad POST:/guest/peek(403)"
    post_json /guest/redeem "$ORIGIN"
    has_hdr access-control-allow-origin && cors_bad="$cors_bad POST:/guest/redeem"
    req OPTIONS /guest/peek -H "Origin: $EVIL" -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
    has_hdr access-control-allow-origin && cors_bad="$cors_bad OPTIONS:/guest/peek"
    if [ -z "$cors_bad" ]; then
        pass "no Access-Control-Allow-Origin on the cookie and no-credential routes (incl. a preflight)"
    else
        fail "Access-Control-Allow-Origin on cookie-group routes:$cors_bad"
    fi
    req GET /guest/invites -H "Origin: $EVIL"
    acao="$(hdr access-control-allow-origin)"
    if [ "$acao" = "*" ] && ! has_hdr access-control-allow-credentials; then
        pass "Bearer routes answer Access-Control-Allow-Origin: * without credentials"
    else
        fail "GET /guest/invites ACAO='$acao', Allow-Credentials present=$(has_hdr access-control-allow-credentials && echo yes || echo no) (want '*' and no credentials)"
    fi

    # --- 5. helper pages ------------------------------------------------------
    for page in /guest/continue "/guest/join/$FAKE_ID" /guest/ended /guest/claim; do
        req GET "$page"
        if [ "$CODE" != 200 ]; then
            fail "helper page $page answered $CODE (want 200)"
            continue
        fi
        if ! hdr content-type | grep -qi '^text/html'; then
            fail "helper page $page content-type is '$(hdr content-type)' (want text/html)"
            continue
        fi
        check_security_headers "helper page $page"
        csp="$(hdr content-security-policy | head -n 1)"
        sp="$(printf '%s' "$csp" | tr ';' '\n' | sed -E 's/^[[:space:]]+//' | grep -E "^(script-src|default-src)" | tr '\n' ' ')"
        if printf '%s' "$sp" | grep -qE "unsafe-inline|unsafe-eval|data:|https?:|\*"; then
            fail "helper page $page CSP lets scripts load from somewhere other than 'self': $sp"
        else
            pass "helper page $page CSP script sources are 'self' only (no 'unsafe-inline')"
        fi
        flat="$(tr '\n' ' ' <"$B")"
        n_open="$(printf '%s' "$flat" | grep -oiE '<script' | wc -l | tr -d ' ')"
        inline=0
        srcs=""
        while IFS= read -r tag; do
            [ -z "$tag" ] && continue
            if ! printf '%s' "$tag" | grep -qiE '^<script[^>]*[[:space:]]src="[^"]+"[^>]*></script>$'; then
                inline=$((inline + 1))
            else
                srcs="$srcs $(printf '%s' "$tag" | sed -E 's/.*[[:space:]]src="([^"]*)".*/\1/')"
            fi
        done < <(printf '%s' "$flat" | grep -oiE '<script[^>]*>[^<]*</script>')
        n_tags="$(printf '%s' "$flat" | grep -oiE '<script[^>]*>[^<]*</script>' | wc -l | tr -d ' ')"
        if [ "$n_open" != "$n_tags" ] || [ "$inline" -gt 0 ]; then
            fail "helper page $page has an inline <script> (open tags $n_open, well-formed $n_tags, inline $inline)"
        elif printf '%s' "$flat" | grep -qiE '<[a-z][^>]*[[:space:]]on[a-z]+[[:space:]]*=|javascript:'; then
            fail "helper page $page has an inline event handler or a javascript: URL"
        else
            pass "helper page $page has no inline script (scripts: ${srcs:- none})"
        fi
        for s in $srcs; do
            case "$s" in
                //*) fail "helper page $page loads a script from another origin: $s" ;;
                /*) ;;
                "$BASE"/* | "$ORIGIN"/*) s="${s#"$ORIGIN"}" ;;
                *) fail "helper page $page loads a script from another origin: $s"; continue ;;
            esac
            req GET "$s"
            if [ "$CODE" = 200 ] && hdr content-type | grep -qi 'javascript' && hdr x-content-type-options | grep -qix nosniff; then
                pass "script $s is served from the issuer origin as JavaScript with nosniff"
            else
                fail "script $s answered $CODE content-type '$(hdr content-type)' (want 200 text/javascript + nosniff)"
            fi
        done
    done

    # --- 6. anonymous callers -------------------------------------------------
    bad=""
    for p in "GET /guest/invites" "GET /guest/context"; do
        req "${p%% *}" "${p#* }"
        case "$CODE" in 401 | 403) ;; *) bad="$bad ${p#* }=$CODE" ;; esac
    done
    post_json /guest/invites "$ORIGIN"
    case "$CODE" in 401 | 403) ;; *) bad="$bad POST:/guest/invites=$CODE" ;; esac
    post_json /guest/meetings/end "$ORIGIN"
    case "$CODE" in 401 | 403) ;; *) bad="$bad POST:/guest/meetings/end=$CODE" ;; esac
    if [ -z "$bad" ]; then
        pass "host and guest Bearer routes refuse an anonymous caller (401/403)"
    else
        fail "an anonymous caller was not refused (want 401/403):$bad"
    fi
    [ "$KILL" = 1 ] && skip "kill switch engaged: peek/redeem checks above ran against the 503 shell"
fi

# --- 7. discovery ---------------------------------------------------------------
req GET /.well-known/openid-configuration
if [ "$CODE" = 200 ]; then
    iss="$(sed -nE 's/.*"issuer"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$B" | head -n 1)"
    if [ "${iss%/}" = "$BASE" ]; then
        pass "discovery issuer is $iss (the origin the guest pages are served from)"
    else
        fail "discovery issuer is '$iss', the probed base is '$BASE' (base_url and the public URL must agree)"
    fi
else
    fail "GET /.well-known/openid-configuration answered $CODE"
fi

echo
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
