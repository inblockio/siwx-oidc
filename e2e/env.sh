# Shared env for the local E2E stack. `source` this.
#
# Default SIWEOIDC_PORT is 18080 (not 8080): this machine often has portal-e2e
# bound on :8080. Override with SIWEOIDC_PORT / SIWEOIDC_BASE_URL if needed.
export SIWEOIDC_ADDRESS=127.0.0.1
export SIWEOIDC_PORT="${SIWEOIDC_PORT:-18080}"
export SIWEOIDC_BASE_URL="${SIWEOIDC_BASE_URL:-http://localhost:${SIWEOIDC_PORT}}"
export SIWEOIDC_REDIS_URL="${SIWEOIDC_REDIS_URL:-redis://localhost:6379}"
export SIWEOIDC_MAS_SHARED_SECRET="${SIWEOIDC_MAS_SHARED_SECRET:-testsecret}"
export SIWEOIDC_SYNAPSE_ENDPOINT="${SIWEOIDC_SYNAPSE_ENDPOINT:-http://localhost:8090}"
export SIWEOIDC_MATRIX_SERVER_NAME="${SIWEOIDC_MATRIX_SERVER_NAME:-matrix.test}"
export SIWEOIDC_REQUIRE_SECRET=false
export SIWEOIDC_LOG_FORMAT=pretty
export RUST_LOG="${RUST_LOG:-siwx_oidc=info,tower_http=warn,warn}"
export SYNAPSE_MOCK_SECRET="${SYNAPSE_MOCK_SECRET:-testsecret}"
export SYNAPSE_MOCK_PORT="${SYNAPSE_MOCK_PORT:-8090}"
