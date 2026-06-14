#!/usr/bin/env bash
# Probe the legacy CS-API device-delete wiring (what an in-client session manager
# calls) against the live stack. Seeds a bearer token directly in Redis so the
# bearer resolves to a user, then exercises DELETE /devices/{id} + /delete_devices.
set -euo pipefail
B=${SIWEOIDC_HOST:-http://localhost:8080}
M=${SYNAPSE_MOCK:-http://localhost:8090}
MX='@legacyuser:matrix.test'

curl -sf -X POST "$M/__reset" >/dev/null
for d in SIWX_legacy_target SIWX_bulk_1 SIWX_bulk_2; do
  curl -sf -X POST "$M/__seed_device" -H 'Content-Type: application/json' \
    -d "{\"user_id\":\"$MX\",\"device_id\":\"$d\"}" >/dev/null
done
TOK='{"username":"legacyuser","device_id":"SIWX_self","scope":"openid","client_id":"c","iat":0,"exp":9999999999,"did":"did:pkh:eip155:1:0xLEGACY","name":"n"}'
podman exec siwx-e2e-redis redis-cli SET 'token/legacybearer' "$TOK" >/dev/null

code1=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/_matrix/client/v3/devices/SIWX_legacy_target" -H 'Authorization: Bearer legacybearer')
code2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/_matrix/client/v3/delete_devices" -H 'Authorization: Bearer legacybearer' -H 'Content-Type: application/json' -d '{"devices":["SIWX_bulk_1","SIWX_bulk_2"]}')
code3=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/_matrix/client/v3/devices/SIWX_x" -H 'Authorization: Bearer nope')
remaining=$(curl -sf "$M/__state" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["devices"].get("'"$MX"'",[])))')

echo "DELETE one      -> $code1 (want 200)"
echo "POST bulk       -> $code2 (want 200)"
echo "bad bearer      -> $code3 (want 401)"
echo "devices left    -> $remaining (want 0)"
[ "$code1" = 200 ] && [ "$code2" = 200 ] && [ "$code3" = 401 ] && [ "$remaining" = 0 ] \
  && echo "LEGACY CS-API PROBE: PASS" || { echo "LEGACY CS-API PROBE: FAIL"; exit 1; }
