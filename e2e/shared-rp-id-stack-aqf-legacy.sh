#!/usr/bin/env bash
# Two aquafier instances on ONE Postgres, Postgres credential store (no shared
# Redis): A1 = pre-change config (RP ID derived from its host), A2 = shared RP ID
# with the default legacy RP ID (= the derived host).
set -euo pipefail
AQF="${AQF:-$(cd "$(dirname "$0")/../../aquafier-rs" && pwd)}"
C="${SRP_DATA:-$HOME/.cache/shared-rp-id}"
podman rm -f srp-aqf1 srp-aqf2 >/dev/null 2>&1 || true
podman exec srp-pg psql -U aqf -d aqf -c "DROP DATABASE IF EXISTS aqfl" -c "CREATE DATABASE aqfl" >/dev/null
for n in 1 2; do
  rm -rf "$C/aqf$n" && mkdir -p "$C/aqf$n/fjall" "$C/aqf$n/keys"
  cat > "$C/aqf$n/aquafier.toml" <<TOML
host = "127.0.0.1"
port = 329$((n+1))
storage_path = "/data/fjall"
keys_path = "/data/keys"
witness_method = "tsa"
database_url = "postgres://aqf:aqf@127.0.0.1:55432/aqfl"
TOML
done
podman run -d --name srp-aqf1 --network host -w /app -v "$AQF:/app:z" -v "$C/aqf1:/data:z" \
  -e AQUAFIER_CONFIG=/data/aquafier.toml -e APP_URL=http://aquafire.inblock.localhost:3292 \
  -e RUST_LOG=info docker.io/library/ubuntu:rolling /app/target/debug/aquafier >/dev/null
for i in $(seq 1 90); do curl -sf -o /dev/null http://127.0.0.1:3292/status && break; sleep 1; done
podman run -d --name srp-aqf2 --network host -w /app -v "$AQF:/app:z" -v "$C/aqf2:/data:z" \
  -e AQUAFIER_CONFIG=/data/aquafier.toml -e APP_URL=http://aquafire.inblock.localhost:3293 \
  -e AQUAFIER_WEBAUTHN_ORIGIN=http://aquafire.inblock.localhost:3293 \
  -e AQUAFIER_WEBAUTHN_RP_ID=inblock.localhost -e RUST_LOG=info \
  docker.io/library/ubuntu:rolling /app/target/debug/aquafier >/dev/null
for i in $(seq 1 90); do curl -sf -o /dev/null http://127.0.0.1:3293/status && { echo up; break; }; sleep 1; done
# Test-only: make every credential A1 registers look like a pre-migration-037
# row (rp_id NULL), i.e. what the pre-change binary stored.
podman exec -i srp-pg psql -U aqf -d aqfl -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE OR REPLACE FUNCTION srp_null_legacy_rp() RETURNS trigger AS $$
BEGIN
  IF NEW.rp_id = 'aquafire.inblock.localhost' THEN NEW.rp_id := NULL; END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS srp_null_legacy_rp ON webauthn_credentials;
CREATE TRIGGER srp_null_legacy_rp BEFORE INSERT ON webauthn_credentials
  FOR EACH ROW EXECUTE FUNCTION srp_null_legacy_rp();
SQL
