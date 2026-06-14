# Shared env for the local E2E stack. `source` this.
export SIWEOIDC_ADDRESS=127.0.0.1
export SIWEOIDC_PORT=8080
export SIWEOIDC_BASE_URL=http://localhost:8080
export SIWEOIDC_REDIS_URL=redis://localhost:6379
export SIWEOIDC_MAS_SHARED_SECRET=testsecret
export SIWEOIDC_SYNAPSE_ENDPOINT=http://localhost:8090
export SIWEOIDC_MATRIX_SERVER_NAME=matrix.test
export SIWEOIDC_REQUIRE_SECRET=false
export SIWEOIDC_LOG_FORMAT=pretty
export RUST_LOG=siwx_oidc=info,tower_http=warn,warn
export SYNAPSE_MOCK_SECRET=testsecret
export SYNAPSE_MOCK_PORT=8090
