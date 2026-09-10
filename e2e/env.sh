# Shared env for the local E2E stack. `source` this.
#
# Default SIWEOIDC_PORT is 18080 (not 8080): this machine often has portal-e2e
# bound on :8080. Override with SIWEOIDC_PORT / SIWEOIDC_BASE_URL if needed.
export SIWEOIDC_ADDRESS=127.0.0.1
export SIWEOIDC_PORT="${SIWEOIDC_PORT:-18080}"
export SIWEOIDC_BASE_URL="${SIWEOIDC_BASE_URL:-http://localhost:${SIWEOIDC_PORT}}"
# Redis host port is separated out because up.sh must PUBLISH it, and the
# default 6379 is regularly already taken on this machine (the e2e-harness stack
# and assorted one-off redis containers). A hardcoded bind made the whole mock
# stack un-startable alongside them, which is a real reason these suites went
# unrun for two structural refactors (audit finding D12).
export SIWEOIDC_REDIS_PORT="${SIWEOIDC_REDIS_PORT:-6379}"
export SIWEOIDC_REDIS_URL="${SIWEOIDC_REDIS_URL:-redis://localhost:${SIWEOIDC_REDIS_PORT}}"
export SIWEOIDC_MAS_SHARED_SECRET="${SIWEOIDC_MAS_SHARED_SECRET:-testsecret}"
export SIWEOIDC_SYNAPSE_ENDPOINT="${SIWEOIDC_SYNAPSE_ENDPOINT:-http://localhost:8090}"
export SIWEOIDC_MATRIX_SERVER_NAME="${SIWEOIDC_MATRIX_SERVER_NAME:-matrix.test}"
export SIWEOIDC_REQUIRE_SECRET=false
export SIWEOIDC_LOG_FORMAT=pretty
export RUST_LOG="${RUST_LOG:-siwx_oidc=info,tower_http=warn,warn}"
export SYNAPSE_MOCK_SECRET="${SYNAPSE_MOCK_SECRET:-testsecret}"
export SYNAPSE_MOCK_PORT="${SYNAPSE_MOCK_PORT:-8090}"
# The mock keys its device/lifecycle/profile state on `@localpart:server`, so it
# must agree with SIWEOIDC_MATRIX_SERVER_NAME: the MAS wire format is
# localpart-scoped, and the mock is the side that rebuilds the mxid.
export SYNAPSE_MOCK_SERVER_NAME="${SYNAPSE_MOCK_SERVER_NAME:-$SIWEOIDC_MATRIX_SERVER_NAME}"
# Since the Synapse 1.157 port the mock's ADMIN surface validates the minted
# `msa_` token by really introspecting it at siwx-oidc, exactly as Synapse's
# MasDelegatedAuth does. Without this the mock cannot authorise ANY admin call
# (deliberately: it refuses rather than rubber-stamping). See e2e/synapse_mock.py.
export SYNAPSE_MOCK_OIDC_BASE="${SYNAPSE_MOCK_OIDC_BASE:-$SIWEOIDC_BASE_URL}"
