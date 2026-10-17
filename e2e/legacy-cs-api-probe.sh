#!/usr/bin/env bash
# Probe the legacy CS-API device-delete wiring (what an in-client session manager
# calls) against the live stack. Seeds two bearer tokens directly in Redis so each
# resolves to a user, then exercises DELETE /devices/{id} + /delete_devices:
#   - a grant's access token, in the layout the server writes (`grant/{id}` plus
#     `at/{sha256(token)}`, see docs/architecture.md), for the single delete;
#   - a legacy access entry `token/{raw}` as builds before the grant record wrote
#     it (no `kind`; a lifetime of at most 900 s makes it an access token), for the
#     bulk delete: the read fallback that keeps such tokens working until they expire.
# REDIS_CONTAINER names the stack's Redis container (default: e2e/up.sh's).
set -euo pipefail
B=${SIWEOIDC_HOST:-http://localhost:8080}
M=${SYNAPSE_MOCK:-http://localhost:8090}
R=${REDIS_CONTAINER:-siwx-e2e-redis}
MX='@legacyuser:matrix.test'
rcli() { podman exec "$R" redis-cli "$@"; }
sha256() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
random62() { head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }

curl -sf -X POST "$M/__reset" >/dev/null
for d in SIWX_legacy_target SIWX_bulk_1 SIWX_bulk_2; do
  curl -sf -X POST "$M/__seed_device" -H 'Content-Type: application/json' \
    -d "{\"user_id\":\"$MX\",\"device_id\":\"$d\"}" >/dev/null
done
NOW=$(rcli TIME | head -1)

# A grant with no refresh token and its access token.
GRANT=$(sha256 "probe-handle-$(random62)")
GRANT_TOKEN="mat_$(random62)"
rcli HSET "grant/$GRANT" kind matrix_device username legacyuser \
  did 'did:pkh:eip155:1:0xLEGACY' client_id c confidential 0 device_id SIWX_self \
  scope 'openid urn:matrix:client:api:* urn:matrix:client:device:SIWX_self' name n \
  auth_time "$NOW" access_ttl 300 inactivity_secs 300 last_used "$NOW" generation 0 \
  current_rt '' previous_rt '' successor_used 1 >/dev/null
rcli EXPIRE "grant/$GRANT" 300 >/dev/null
rcli HSET "at/$(sha256 "$GRANT_TOKEN")" grant "$GRANT" generation 0 kind access \
  iat "$NOW" exp "$((NOW + 300))" >/dev/null
rcli EXPIRE "at/$(sha256 "$GRANT_TOKEN")" 300 >/dev/null

# A legacy access entry.
LEGACY_TOKEN="mat_$(random62)"
LEGACY='{"username":"legacyuser","device_id":"SIWX_self","scope":"openid","client_id":"c","iat":'"$NOW"',"exp":'"$((NOW + 300))"',"did":"did:pkh:eip155:1:0xLEGACY","name":"n"}'
rcli SET "token/$LEGACY_TOKEN" "$LEGACY" EX 300 >/dev/null

code1=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/_matrix/client/v3/devices/SIWX_legacy_target" -H "Authorization: Bearer $GRANT_TOKEN")
code2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/_matrix/client/v3/delete_devices" -H "Authorization: Bearer $LEGACY_TOKEN" -H 'Content-Type: application/json' -d '{"devices":["SIWX_bulk_1","SIWX_bulk_2"]}')
code3=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/_matrix/client/v3/devices/SIWX_x" -H 'Authorization: Bearer nope')
remaining=$(curl -sf "$M/__state" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["devices"].get("'"$MX"'",[])))')

echo "DELETE one (grant bearer)   -> $code1 (want 200)"
echo "POST bulk (legacy bearer)   -> $code2 (want 200)"
echo "bad bearer                  -> $code3 (want 401)"
echo "devices left                -> $remaining (want 0)"
[ "$code1" = 200 ] && [ "$code2" = 200 ] && [ "$code3" = 401 ] && [ "$remaining" = 0 ] \
  && echo "LEGACY CS-API PROBE: PASS" || { echo "LEGACY CS-API PROBE: FAIL"; exit 1; }
