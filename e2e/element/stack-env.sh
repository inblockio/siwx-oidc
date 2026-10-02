# Single source of truth for the Element e2e stack: compose project name, host
# ports and URLs. `source` this from stack-up.sh, stack-down.sh,
# t5-restart-survival.sh and run.sh; do not execute it.
#
# Compose project. Without `-p`, compose names the project after the directory
# of docker-compose.local.yml, i.e. "siwx-oidc-matrix-server". On a shared host
# that is the project of every other checkout's stack, so `up`/`down` would
# recreate or remove THEIR containers, volumes and network. A dedicated default
# keeps this harness's containers (siwx-e2e-element-<service>-N), volumes and
# network its own. Set E2E_COMPOSE_PROJECT to run a second, independent copy.
E2E_COMPOSE_PROJECT="${E2E_COMPOSE_PROJECT:-siwx-e2e-element}"

# Host ports. 28080/28081/28088 are the lab defaults the specs have always used
# (portal-e2e owns :8080 on the lab hosts, see helpers/element.mjs); the
# compose.local defaults 8080/8081/8088 stay reachable by overriding these.
E2E_MATRIX_PORT="${E2E_MATRIX_PORT:-28080}"
E2E_SIWX_PORT="${E2E_SIWX_PORT:-28081}"
E2E_ELEMENT_PORT="${E2E_ELEMENT_PORT:-28088}"

E2E_MATRIX_URL="http://localhost:${E2E_MATRIX_PORT}"
E2E_SIWX_URL="http://localhost:${E2E_SIWX_PORT}"
E2E_ELEMENT_URL="http://localhost:${E2E_ELEMENT_PORT}"

# What compose publishes and advertises (.well-known, OIDC issuer) must equal
# what stack-up.sh waits on and run.sh points the specs at. Compose lets the
# calling environment beat --env-file, so exporting these pins the stack to the
# ports above even when .env.local carries other (or stale) values.
export MATRIX_HOST_PORT="$E2E_MATRIX_PORT"
export SIWEOIDC_HOST_PORT="$E2E_SIWX_PORT"
export CLIENT_HOST_PORT="$E2E_ELEMENT_PORT"
export MATRIX_BASE_URL="$E2E_MATRIX_URL"
export SIWEOIDC_BASE_URL="$E2E_SIWX_URL"
export SIWEOIDC_HOST="localhost:${E2E_SIWX_PORT}"
