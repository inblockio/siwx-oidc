#!/usr/bin/env bash
# Local shared-RP-ID e2e stack. Hostnames under *.inblock.localhost (Chromium
# resolves *.localhost to loopback itself: no /etc/hosts edits). All listeners in
# podman on the host network.
set -euo pipefail
SIWX="${SIWX:-$(cd "$(dirname "$0")/.." && pwd)}"
AQF="${AQF:-$(cd "$(dirname "$0")/../../aquafier-rs" && pwd)}"
C="${SRP_DATA:-$HOME/.cache/shared-rp-id}"
podman rm -f srp-pg srp-siwx-legacy srp-siwx-shared srp-aqf >/dev/null 2>&1 || true
podman run -d --name srp-pg -p 127.0.0.1:55432:5432 -e POSTGRES_DB=aqf -e POSTGRES_USER=aqf -e POSTGRES_PASSWORD=aqf docker.io/library/postgres:17 >/dev/null
common=( -e SIWEOIDC_ADDRESS=127.0.0.1 -e SIWEOIDC_REDIS_URL=redis://localhost:6379
  -e SIWEOIDC_REQUIRE_SECRET=false -e 'SIWEOIDC_SUPPORTED_DID_METHODS=[pkh,key]'
  -e AQUA_WEBAUTHN_REDIS_URL=redis://localhost:6379 -e RUST_LOG=siwx_oidc=info,warn )
# L: the pre-change configuration (RP ID = its own host), port 18290.
podman run -d --name srp-siwx-legacy --network host -w /app -v "$SIWX:/app:z" "${common[@]}" \
  -e SIWEOIDC_PORT=18290 -e SIWEOIDC_BASE_URL=http://siwx-oidc.inblock.localhost:18290 \
  docker.io/library/ubuntu:rolling /app/target/debug/siwx-oidc >/dev/null
# S: shared RP ID, legacy = its own host (default), port 18291.
podman run -d --name srp-siwx-shared --network host -w /app -v "$SIWX:/app:z" "${common[@]}" \
  -e SIWEOIDC_PORT=18291 -e SIWEOIDC_BASE_URL=http://siwx-oidc.inblock.localhost:18291 \
  -e SIWEOIDC_RP_ID=inblock.localhost \
  docker.io/library/ubuntu:rolling /app/target/debug/siwx-oidc >/dev/null
for i in $(seq 1 60); do pg_ok=$(podman exec srp-pg pg_isready -U aqf -d aqf >/dev/null 2>&1 && echo y || echo n); [ "$pg_ok" = y ] && break; sleep 0.5; done
rm -rf "$C/aqf" && mkdir -p "$C/aqf/fjall" "$C/aqf/keys"
cat > "$C/aqf/aquafier.toml" <<TOML
host = "127.0.0.1"
port = 3291
storage_path = "/data/fjall"
keys_path = "/data/keys"
witness_method = "tsa"
database_url = "postgres://aqf:aqf@127.0.0.1:55432/aqf"
TOML
# A: aquafier on aquafire.inblock.localhost with the shared RP ID and the SHARED
# aqua-auth credential store (the same Redis siwx-oidc dual-writes into). Legacy
# RP off (the shared store records no per-credential RP ID).
podman run -d --name srp-aqf --network host -w /app -v "$AQF:/app:z" -v "$C/aqf:/data:z" \
  -e AQUAFIER_CONFIG=/data/aquafier.toml -e APP_URL=http://aquafire.inblock.localhost:3291 \
  -e AQUAFIER_WEBAUTHN_ORIGIN=http://aquafire.inblock.localhost:3291 \
  -e AQUAFIER_WEBAUTHN_RP_ID=inblock.localhost -e AQUAFIER_WEBAUTHN_LEGACY_RP_ID=inblock.localhost \
  -e AQUA_WEBAUTHN_REDIS_URL=redis://localhost:6379 -e RUST_LOG=info \
  docker.io/library/ubuntu:rolling /app/target/debug/aquafier >/dev/null
for u in http://127.0.0.1:18290/health http://127.0.0.1:18291/health http://127.0.0.1:3291/status; do
  for i in $(seq 1 90); do curl -sf -o /dev/null "$u" && { echo "up $u"; break; }; sleep 1; done
done
