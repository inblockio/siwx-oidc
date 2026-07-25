#!/usr/bin/env bash
#
# check-auth-metadata.sh
#
# Deploy-time guard against MSC3861 auth_metadata regressions.
#
# Synapse forwards experimental_features.msc3861.issuer_metadata VERBATIM to
# browsers via GET /_matrix/client/v1/auth_metadata. If that metadata is
# incomplete (missing response_types_supported / grant_types_supported /
# code_challenge_methods_supported) or contains non-public (docker-internal)
# endpoint URLs, matrix-js-sdk rejects the issuer ("Issuer configuration not
# valid"), Element Web silently falls back to the legacy /login/sso/redirect
# route, and that route 404s under MSC3861 (siwx-oidc ships no MAS compat
# shim) — a total, SILENT login dead-end. This happened in the local Element
# lab (endpoints-only dict with internal docker URLs, fixed 2026-07-25); prod
# also sets sso_redirect_options.immediate, so any future regression there is
# an outage. See docs/2026-07-25-HANDOVER-phase2-session-onboarding.md §14.
#
# Checks (FAILURES — any one makes the script exit non-zero):
#   a. response_types_supported contains "code"
#   b. grant_types_supported contains "authorization_code" AND "refresh_token"
#   c. code_challenge_methods_supported contains "S256"
#   d. every *_endpoint URL and jwks_uri — EXCEPT introspection_endpoint,
#      which is legitimately server-internal (Synapse-only) in lab setups —
#      is an absolute http(s) URL whose host is browser-resolvable (contains
#      a dot, or is "localhost"; a bare docker service name like "siwx-oidc"
#      fails). With [expected-issuer], those URLs must also start with the
#      expected issuer's origin.
#   e. (WARNING only) probes the legacy /login/sso/redirect fallback, which
#      404s under MSC3861 — Element only avoids that dead-end while the
#      metadata above validates.
#
# Dependencies: curl + python3 only.
#
# USAGE:
#   scripts/check-auth-metadata.sh <matrix-base-url> [expected-issuer]
#   scripts/check-auth-metadata.sh https://matrix.inblock.io https://siwx-oidc.inblock.io/
#   scripts/check-auth-metadata.sh http://localhost:28080 http://localhost:28081/

set -uo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <matrix-base-url> [expected-issuer]" >&2
    exit 2
fi

BASE="${1%/}"
EXPECTED_ISSUER="${2:-}"
META_URL="$BASE/_matrix/client/v1/auth_metadata"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "== MSC3861 auth_metadata guard =="
echo "GET $META_URL"

HTTP_CODE="$(curl -sS --max-time 15 -o "$TMP" -w '%{http_code}' "$META_URL")" || {
    echo "FAIL: could not fetch $META_URL (curl error)" >&2
    exit 1
}
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: $META_URL returned HTTP $HTTP_CODE (expected 200)." >&2
    echo "      Without valid auth_metadata, Element falls back to legacy SSO and dead-ends." >&2
    exit 1
fi

python3 - "$TMP" "$EXPECTED_ISSUER" <<'PYEOF'
import json, sys
from urllib.parse import urlparse

path, expected_issuer = sys.argv[1], sys.argv[2]

try:
    with open(path) as f:
        meta = json.load(f)
except json.JSONDecodeError as e:
    print(f"FAIL: auth_metadata is not valid JSON: {e}")
    sys.exit(1)

violations = []


def contains(field, *required):
    values = meta.get(field)
    if not isinstance(values, list):
        violations.append(
            f"{field} is missing or not a list (got {values!r}) — "
            f"matrix-js-sdk rejects the issuer without it"
        )
        return
    for r in required:
        if r not in values:
            violations.append(
                f'{field} must contain "{r}" (got {values!r})'
            )


# a–c: the capability fields matrix-js-sdk validates before trusting the issuer.
contains("response_types_supported", "code")
contains("grant_types_supported", "authorization_code", "refresh_token")
contains("code_challenge_methods_supported", "S256")

# d: browser-facing URLs must be public. introspection_endpoint is exempt:
# only Synapse calls it, so a docker-internal URL there is legitimate.
issuer_origin = None
if expected_issuer:
    p = urlparse(expected_issuer)
    issuer_origin = f"{p.scheme}://{p.netloc}"

url_keys = sorted(
    k for k in meta
    if (k == "jwks_uri" or k.endswith("_endpoint")) and k != "introspection_endpoint"
)
for key in url_keys:
    url = meta[key]
    if not isinstance(url, str):
        violations.append(f"{key} is not a string (got {url!r})")
        continue
    p = urlparse(url)
    host = p.hostname
    if p.scheme not in ("http", "https") or not host:
        violations.append(f"{key} = {url!r} is not an absolute http(s) URL")
        continue
    if "." not in host and host != "localhost":
        violations.append(
            f"{key} = {url!r} has a docker-internal hostname ({host!r}) — "
            f"browsers cannot resolve it, so matrix-js-sdk issuer validation fails"
        )
        continue
    if issuer_origin and not (url == issuer_origin or url.startswith(issuer_origin + "/")):
        violations.append(
            f"{key} = {url!r} does not start with the expected issuer origin {issuer_origin!r}"
        )

if violations:
    for v in violations:
        print(f"FAIL: {v}")
    print(f"\n{len(violations)} violation(s). matrix-js-sdk will reject this issuer, "
          f"Element will silently fall back to legacy /login/sso/redirect, and that "
          f"route 404s under MSC3861 — a silent login dead-end.")
    sys.exit(1)

print(f"PASS: issuer = {meta.get('issuer')!r}")
print( 'PASS: response_types_supported contains "code"')
print( 'PASS: grant_types_supported contains "authorization_code" + "refresh_token"')
print( 'PASS: code_challenge_methods_supported contains "S256"')
print(f"PASS: {len(url_keys)} browser-facing URL(s) public"
      + (f" and on issuer origin {issuer_origin}" if issuer_origin else "")
      + f" ({', '.join(url_keys)}; introspection_endpoint exempt)")
PYEOF
RESULT=$?

# e: the legacy fallback Element uses when auth_metadata does NOT validate.
LEGACY_URL="$BASE/_matrix/client/v3/login/sso/redirect?redirectUrl=https://example.com/"
LEGACY_CODE="$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "$LEGACY_URL" || echo 'unreachable')"
if [ "$LEGACY_CODE" = "404" ]; then
    echo "WARN: legacy /login/sso/redirect returns 404 (expected under MSC3861 — no MAS compat shim)."
    echo "      Element only avoids this dead-end route while auth_metadata validates; any"
    echo "      metadata regression above turns into a silent total login outage."
else
    echo "WARN: legacy /login/sso/redirect returned HTTP $LEGACY_CODE (not the expected 404)."
    echo "      If a compat shim now answers this route, re-evaluate this guard's assumptions."
fi

if [ "$RESULT" -eq 0 ]; then
    echo "== PASS: auth_metadata at $BASE is safe for matrix-js-sdk issuer validation =="
fi
exit "$RESULT"
