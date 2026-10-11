#!/usr/bin/env bash
#
# check-guest-proxy.sh
#
# Deployment check for the reverse proxy in front of a guest-enabled siwx-oidc
# (GP-SEC-04, ST-04, prerequisite P6 of docs/guest-portal.md). It probes the PUBLIC
# URL, and optionally the direct upstream URL, and prints one PASS / FAIL / SKIP
# line per check; it exits 1 when any check FAILed, 0 otherwise.
#
# What it proves:
#   1. The public origin is the issuer's base_url: a same-origin POST is accepted
#      by the app (404 invalid_link, not 403 forbidden_origin).
#   2. The GP-SEC-39 headers survive the proxy on /guest responses, and the proxy
#      does not replace Cache-Control: no-store (no caching of /guest, no Age).
#   3. CORS: the cookie and no-credential routes carry no Access-Control-Allow-
#      Origin through the proxy (the proxy must neither add nor keep one); the
#      Bearer routes carry exactly ONE ACAO value, "*" (a proxy that adds its own
#      next to the app's gives two values, which browsers reject). The house rule
#      is: strip the upstream ACAO in the reverse_proxy block and set one at the proxy.
#   4. HSTS on https; plain http redirects to https (or is closed).
#   5. The proxy does not raise the app's body caps (4 KiB; 16 KiB on claim/finish;
#      a 1 MiB body is refused, not forwarded or timed out).
#   6. With the direct upstream URL: status and security headers match the proxy's.
#   7. Optional, needs a value you capture yourself (it is a secret, never fetched here):
#      the guest cookie's attributes survive. Redeem an invite in a browser or with
#      curl, then run with GUEST_SET_COOKIE='<the whole Set-Cookie header value>'.
#      The cookie value is never printed.
#   8. Optional, OFF by default because it is noisy and trips the limiter for real
#      users behind the same address: CHECK_RATE_LIMIT=1 sends 25 bogus redeems and
#      expects a 429 (ST-04: 15 redeems, 429 after the burst).
#
# Read-only: GETs and POSTs with a made-up invite id and no valid secret; nothing is
# created. No secrets are needed, read or printed. Dependencies: bash, curl, grep,
# sed, tr, head.
#
# USAGE:
#   scripts/check-guest-proxy.sh <public-base-url> [<direct-upstream-url>]
#   scripts/check-guest-proxy.sh https://id.example.org http://127.0.0.1:8080
#   GUEST_SET_COOKIE='__Host-guest_session=...; Secure; ...' scripts/check-guest-proxy.sh https://id.example.org
#   CHECK_RATE_LIMIT=1 scripts/check-guest-proxy.sh https://id.example.org

set -u

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <public-base-url> [<direct-upstream-url>]" >&2
    exit 2
fi
PUBLIC="${1%/}"
DIRECT="${2:-}"
DIRECT="${DIRECT%/}"
ORIGIN="$(printf '%s' "$PUBLIC" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')"
SCHEME="${PUBLIC%%://*}"
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

# req BASE METHOD PATH [curl args...]  ->  CODE, headers in $H (CR stripped), body in $B
req() {
    local base="$1" method="$2" path="$3"
    shift 3
    : >"$H"
    : >"$B"
    CODE="$(curl -sS -m 20 -X "$method" -D "$H" -o "$B" -w '%{http_code}' -H 'Expect:' "$@" "$base$path" 2>/dev/null)" || CODE=000
    tr -d '\r' <"$H" >"$H.n" && mv "$H.n" "$H"
}
hdr() { grep -i "^$1:" "$H" | sed -E 's/^[^:]*:[[:space:]]*//'; }
has_hdr() { grep -qi "^$1:" "$H"; }
count_hdr() { grep -ci "^$1:" "$H"; }
bodycode() { sed -nE 's/.*"error"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$B" | head -n 1; }
post_json() {
    local base="$1" path="$2" origin="$3"
    shift 3
    local args=(-H 'Content-Type: application/json' --data "{\"invite_id\":\"$FAKE_ID\",\"secret\":\"gi_00000000000000000000000000000000\"}")
    [ "$origin" != "-" ] && args+=(-H "Origin: $origin")
    req "$base" POST "$path" "${args[@]}" "$@"
}
# The header set the app owns, as one comparable string.
sec_sig() {
    for n in content-security-policy x-frame-options referrer-policy x-content-type-options cache-control; do
        printf '%s=%s;' "$n" "$(hdr "$n" | head -n 1)"
    done
}

echo "== guest reverse-proxy check =="
echo "public: $PUBLIC${DIRECT:+   direct upstream: $DIRECT}"

# --- guest mode must be on, or there is nothing to check ---------------------------
req "$PUBLIC" GET "/guest/proxy-probe-$$"
if [ "$CODE" = 503 ] && [ "$(bodycode)" = guest_unavailable ]; then
    echo "guest mode is OFF behind this URL (503 guest_unavailable): the proxy checks that need guest routes are SKIPped"
    skip "guest mode is off; run scripts/check-guest-posture.sh first, enable it, then repeat this check"
    echo
    echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 0
elif [ "$CODE" != 404 ] || [ "$(bodycode)" != not_found ]; then
    fail "GET /guest/<unknown> through the public URL answered $CODE '$(bodycode)' (want the app's 404 not_found): is the proxy routing /guest to siwx-oidc?"
    echo
    echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 1
fi
pass "/guest is routed to a guest-enabled siwx-oidc (404 not_found for an unknown path)"

# --- 1. public origin == base_url -------------------------------------------------
post_json "$PUBLIC" /guest/peek "$ORIGIN"
if [ "$CODE" = 404 ] && [ "$(bodycode)" = invalid_link ]; then
    pass "a same-origin POST through the proxy reaches the handler (404 invalid_link): public origin equals base_url"
elif [ "$CODE" = 403 ]; then
    fail "a same-origin POST (Origin: $ORIGIN) was refused 403 forbidden_origin: base_url differs from the public origin, or the proxy rewrites Origin"
elif [ "$CODE" = 429 ]; then
    skip "peek answered 429 (the proxy limiter is already engaged); the checks that need a handler answer may fail"
else
    fail "a same-origin POST /guest/peek answered $CODE '$(bodycode)' (want 404 invalid_link)"
fi

# --- 2. headers, caching -----------------------------------------------------------
for p in "GET /guest/join/$FAKE_ID" "GET /guest/ended" "GET /guest/assets/join.js" "GET /guest/proxy-probe-$$"; do
    req "$PUBLIC" "${p%% *}" "${p#* }"
    bad=""
    hdr content-security-policy | grep -q "script-src 'self'" || bad="$bad CSP"
    hdr x-frame-options | grep -qix DENY || bad="$bad X-Frame-Options"
    hdr x-content-type-options | grep -qix nosniff || bad="$bad nosniff"
    hdr referrer-policy | grep -qix no-referrer || bad="$bad Referrer-Policy"
    hdr cache-control | grep -qi no-store || bad="$bad Cache-Control"
    has_hdr age && bad="$bad Age(cache hit)"
    hdr cache-control | grep -qiE 'public|max-age=[1-9]|s-maxage' && bad="$bad Cache-Control-allows-caching"
    if [ -z "$bad" ]; then
        pass "${p#* }: security headers intact, Cache-Control no-store, not cached"
    else
        fail "${p#* }: through the proxy:$bad"
    fi
done
post_json "$PUBLIC" /guest/peek "$ORIGIN"
if hdr cache-control | grep -qi no-store && ! has_hdr age; then
    pass "POST /guest/peek: Cache-Control no-store"
else
    fail "POST /guest/peek: Cache-Control is '$(hdr cache-control)'"
fi

# --- 3. CORS ----------------------------------------------------------------------
bad=""
for p in "GET /guest/ended" "GET /guest/claim" "GET /guest/continue" "GET /guest/resume" "GET /guest/join/$FAKE_ID" "GET /guest/assets/join.js"; do
    req "$PUBLIC" "${p%% *}" "${p#* }" -H "Origin: $EVIL"
    has_hdr access-control-allow-origin && bad="$bad ${p#* }"
done
post_json "$PUBLIC" /guest/peek "$EVIL"
has_hdr access-control-allow-origin && bad="$bad POST:/guest/peek(403)"
post_json "$PUBLIC" /guest/redeem "$ORIGIN"
has_hdr access-control-allow-origin && bad="$bad POST:/guest/redeem"
req "$PUBLIC" OPTIONS /guest/peek -H "Origin: $EVIL" -H 'Access-Control-Request-Method: POST'
has_hdr access-control-allow-origin && bad="$bad OPTIONS:/guest/peek"
if [ -z "$bad" ]; then
    pass "no Access-Control-Allow-Origin on the cookie routes through the proxy (not added, not kept)"
else
    fail "Access-Control-Allow-Origin on cookie routes through the proxy:$bad (strip it in the reverse_proxy block)"
fi
req "$PUBLIC" GET /guest/invites -H "Origin: $EVIL"
n="$(count_hdr access-control-allow-origin)"
v="$(hdr access-control-allow-origin | head -n 1)"
if [ "$n" = 1 ] && [ "$v" = "*" ] && ! has_hdr access-control-allow-credentials; then
    pass "Bearer routes carry exactly one Access-Control-Allow-Origin: * and no credentials"
elif [ "$n" -gt 1 ]; then
    fail "GET /guest/invites carries $n Access-Control-Allow-Origin headers (proxy added its own next to the app's; strip the upstream one)"
else
    fail "GET /guest/invites ACAO count=$n value='$v' (want one '*', no credentials)"
fi

# --- 4. HSTS, plain http ----------------------------------------------------------
if [ "$SCHEME" = https ]; then
    req "$PUBLIC" GET /guest/ended
    sts="$(hdr strict-transport-security | head -n 1)"
    age="$(printf '%s' "$sts" | sed -nE 's/.*max-age=([0-9]+).*/\1/p')"
    if [ -n "$age" ] && [ "$age" -ge 15552000 ]; then
        pass "HSTS on /guest/ended: $sts"
    else
        fail "HSTS missing or max-age under 15552000 on /guest/ended (got '$sts')"
    fi
    plain="http://${PUBLIC#https://}"
    : >"$H"
    c="$(curl -sS -m 8 -o /dev/null -D "$H" -w '%{http_code}' "$plain/guest/ended" 2>/dev/null)" || c=000
    tr -d '\r' <"$H" >"$H.n" && mv "$H.n" "$H"
    case "$c" in
        301 | 302 | 307 | 308)
            if hdr location | grep -qi '^https://'; then
                pass "plain http /guest/ended redirects to https ($c)"
            else
                fail "plain http redirects ($c) to '$(hdr location)', not https"
            fi
            ;;
        000) pass "plain http is not served (connection refused or closed)" ;;
        *) fail "plain http /guest/ended answered $c without redirecting to https" ;;
    esac
else
    skip "HSTS and http->https redirect (the public URL is $SCHEME, a development setup)"
fi

# --- 5. body caps -----------------------------------------------------------------
printf '{"invite_id":"%s"}' "$(head -c 5000 /dev/zero | tr '\0' a)" >"$TMP/5k.json"
printf '{"x":"%s"}' "$(head -c 17000 /dev/zero | tr '\0' a)" >"$TMP/17k.json"
printf '{"x":"%s"}' "$(head -c 1048576 /dev/zero | tr '\0' a)" >"$TMP/1m.json"
req "$PUBLIC" POST /guest/peek -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/5k.json"
if [ "$CODE" = 413 ]; then
    pass "a 5 KiB body on /guest/peek is refused 413 through the proxy"
else
    fail "a 5 KiB body on /guest/peek answered $CODE (want 413: the proxy raised or hides the app's 4 KiB cap)"
fi
req "$PUBLIC" POST /guest/claim/finish -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/17k.json"
if [ "$CODE" = 413 ]; then
    pass "a 17 KiB body on /guest/claim/finish is refused 413 through the proxy"
else
    fail "a 17 KiB body on /guest/claim/finish answered $CODE (want 413)"
fi
req "$PUBLIC" POST /guest/claim/finish -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/5k.json"
if [ "$CODE" != 413 ]; then
    pass "a 5 KiB body on /guest/claim/finish is not refused for size ($CODE): the proxy cap is not below the app's 16 KiB"
else
    fail "a 5 KiB body on /guest/claim/finish was refused 413: the proxy cap is below the app's 16 KiB (a WebAuthn attestation needs it)"
fi
req "$PUBLIC" POST /guest/peek -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data-binary "@$TMP/1m.json"
case "$CODE" in
    413 | 400) pass "a 1 MiB body on /guest/peek is refused ($CODE)" ;;
    000) pass "a 1 MiB body on /guest/peek was cut off by the proxy or the app (connection closed)" ;;
    *) fail "a 1 MiB body on /guest/peek answered $CODE (want 413)" ;;
esac

# --- 6. direct upstream comparison -------------------------------------------------
if [ -n "$DIRECT" ]; then
    for p in "GET /guest/join/$FAKE_ID" "GET /guest/ended" "GET /guest/proxy-probe-$$"; do
        req "$PUBLIC" "${p%% *}" "${p#* }"
        pc="$CODE"
        psig="$(sec_sig)"
        req "$DIRECT" "${p%% *}" "${p#* }"
        dc="$CODE"
        dsig="$(sec_sig)"
        if [ "$pc" = "$dc" ] && [ "$psig" = "$dsig" ]; then
            pass "${p#* }: the proxy passes status $pc and the app's security headers unchanged"
        else
            fail "${p#* }: proxy $pc vs direct $dc; headers differ: proxy[$psig] direct[$dsig]"
        fi
    done
    req "$DIRECT" GET /guest/ended -H "Origin: $EVIL"
    if has_hdr access-control-allow-origin; then
        fail "the DIRECT upstream answers ACAO on a cookie route; fix the app before the proxy"
    else
        pass "the direct upstream answers no ACAO on a cookie route (so any ACAO seen publicly is the proxy's)"
    fi
else
    skip "direct upstream comparison (no <direct-upstream-url> given)"
fi

# --- 7. cookie attributes -----------------------------------------------------------
if [ -n "${GUEST_SET_COOKIE:-}" ]; then
    c="$GUEST_SET_COOKIE"
    bad=""
    case "$c" in "__Host-guest_session="*) ;; *) bad="$bad name(want __Host-guest_session)" ;; esac
    printf '%s' "$c" | grep -qi ';[[:space:]]*Secure' || bad="$bad Secure"
    printf '%s' "$c" | grep -qi ';[[:space:]]*HttpOnly' || bad="$bad HttpOnly"
    printf '%s' "$c" | grep -qi ';[[:space:]]*Path=/\(;\|$\)' || bad="$bad Path=/"
    printf '%s' "$c" | grep -qi ';[[:space:]]*SameSite=Lax' || bad="$bad SameSite=Lax"
    printf '%s' "$c" | grep -qi ';[[:space:]]*Domain=' && bad="$bad Domain-present"
    if [ -z "$bad" ]; then
        pass "guest cookie attributes (value not shown): __Host- prefix, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain"
    else
        fail "guest cookie attributes wrong:$bad"
    fi
else
    skip "guest cookie attributes (the Set-Cookie comes only from a successful redeem, which needs an invite secret; pass GUEST_SET_COOKIE to check one)"
fi

# --- 8. rate limit ------------------------------------------------------------------
if [ "${CHECK_RATE_LIMIT:-}" = 1 ]; then
    got=0
    i=0
    while [ "$i" -lt 25 ]; do
        post_json "$PUBLIC" /guest/redeem "$ORIGIN"
        [ "$CODE" = 429 ] && got=$((got + 1))
        i=$((i + 1))
    done
    if [ "$got" -gt 0 ]; then
        pass "POST /guest/redeem is rate limited by the proxy (429 on $got of 25 requests)"
    else
        fail "25 redeems from one address, no 429: the proxy does not rate-limit the mint path (P6)"
    fi
else
    skip "rate limits (P6, ST-04): set CHECK_RATE_LIMIT=1 to send 25 bogus redeems; it trips the limiter for real users behind the same address for several minutes"
fi

echo
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
