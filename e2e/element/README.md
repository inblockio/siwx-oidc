# Element Web Playwright suite (Phase 2.0)

Drives a **real Element Web** instance against local Synapse + siwx-oidc (MSC3861).

## Stack

Bring it up from this repo (the scripts expect `siwx-oidc-matrix-server` as a sibling
checkout, with its gitignored `.env.local`):

```bash
bash e2e/element/stack-up.sh
bash e2e/element/run.sh [spec ...]
bash e2e/element/stack-down.sh
```

`run.sh` runs Playwright in the `mcr.microsoft.com/playwright` container (host network,
`--userns=keep-id`, all of `e2e/` mounted at `/e2e`) and installs the npm dependencies
there, so nothing needs installing by hand on a fresh checkout. `e2e/element`'s are
installed from its committed lockfile. `e2e/browser`'s are installed too, because every
spec imports `../browser/wallet-helper.mjs`, which needs `ethers` from
`e2e/browser/node_modules`; that install is skipped while `node_modules/.package-lock.json`
is newer than `e2e/browser/package.json` (that package has no committed lockfile, its
direct dependencies are pinned to exact versions).

`stack-up.sh`, `stack-down.sh`, `t5-restart-survival.sh` and `run.sh` all source
[`stack-env.sh`](stack-env.sh), the single source for the compose project and the host
ports, so the stack `stack-up.sh` starts is the stack `run.sh` tests:

| Variable | Default | Meaning |
|----------|---------|---------|
| `E2E_COMPOSE_PROJECT` | `siwx-e2e-element` | Compose project (`-p`) for every compose call. Containers are named `<project>-<service>-N`, volumes and the network carry the same prefix. |
| `E2E_ELEMENT_PORT` | `28088` | Host port of Element Web. |
| `E2E_MATRIX_PORT` | `28080` | Host port of the Matrix edge (Synapse). |
| `E2E_SIWX_PORT` | `28081` | Host port of siwx-oidc. |
| `ELEMENT_URL`, `MATRIX_URL`, `SIWX_URL` | `http://localhost:<port above>` | Read by `run.sh` and the specs. Set only to point the specs at a stack that is not the one `stack-up.sh` started. |

Why a dedicated project: without `-p`, compose names the project after the directory of
`docker-compose.local.yml`, `siwx-oidc-matrix-server`. On a host where other people run
that checkout's stack, `up` and `down` would then recreate or remove their containers,
volumes and images. The scripts never rely on that default. Set `E2E_COMPOSE_PROJECT` to
run a second copy next to the first (give it different ports too).

The ports are exported to compose as `MATRIX_HOST_PORT`, `SIWEOIDC_HOST_PORT`,
`CLIENT_HOST_PORT` and the matching `*_BASE_URL` / `SIWEOIDC_HOST` values. Compose lets the
calling environment beat `--env-file`, so the ports in `stack-env.sh` win over whatever
`.env.local` says. The lab defaults 28080/28081/28088 keep clear of other stacks on
:8080/:8081/:8088; use `E2E_*_PORT=8080 ...` for the compose.local defaults.

Running `docker compose -f docker-compose.local.yml --env-file .env.local up --build -d`
by hand in `siwx-oidc-matrix-server` uses the compose.local defaults (Element :8088,
Matrix :8080, siwx :8081) and the directory project; pass `-p` and the ports yourself, or
use the scripts.

## Specs (EW-* IDs from the audited plan)

| Spec file | Coverage |
|-----------|----------|
| `ew-login.spec.mjs` | EW-L1 wallet login via Element OIDC |
| `ew-sessions.spec.mjs` | EW-S1–S4 manage sessions / remove device / logout |
| `ew-crypto.spec.mjs` | EW-X1–X2 bootstrap / reset (as far as UI allows) |
| `ew-device-link.spec.mjs` | EW-D1 device-code / link new device |
| `ew-passkey.spec.mjs` | EW-P1–P3 passkey OIDC login: new-user gate, returning-user scoped picker + multi-device, synced passkey in a second context |
| `ew-clickpath.spec.mjs` | EW-C1–C3 REAL Element DOM: SSO click-login through the siwx UI + Secure Backup wizard, Settings→Sessions sign-out (teardown policy), Manage-account deep-link |
| `ew-verify-sas.spec.mjs` | EW-V1 R4/AC4 proof: a second session is cross-signed by SAS/emoji driven from a live first session (Settings→Sessions→"Verify session"), with a positive tripwire asserting **no recovery phrase** was typed and no 4S entry surface appeared during the SAS leg |
| `ew-sw-media-auth.spec.mjs` | SW-1..3: Element's service worker keeps authenticated media working when its `/versions` check hits an expired token (401, anonymous retry), a transient 5xx (never cached), or a media 401 while the app refreshes (one bounded retry). Covers siwx-oidc-matrix-server `patches/element-web` entries 9 and 10. `EW_SW_OVERRIDE=<stock sw.js>` serves the unpatched worker through `helpers/stock-sw-proxy.mjs`; every leg must then fail. |
| `ew-encrypted-search.spec.mjs` | UX1–UX8: search in encrypted rooms through the browser EventIndex (siwx-oidc-matrix-server `patches/element-web` entry 6, `browser-eventindex.patch`): the room-info search finds a freshly sent message, an `m.replace` moves the hit to the new body under the original event id, the index survives a reload, sign-out leaves no plaintext in the Element origin's storage, and a second account on the same browser profile cannot find the first one's message. Needs `features.feature_web_event_index: true` in the target's `config.json`; `beforeAll` fails naming the key otherwise. |

## Helpers

- `helpers/element.mjs` — open Element, wait for room list / login
- `helpers/identity.mjs`: what a fresh account's Matrix ID must look like (`expectOpaqueMxid`: 16 base36 characters on the lab server_name) and `expectDidBinding` (the wallet's DID resolves to that MXID through siwx `GET /resolve` in both directions and through the account's `io.inblock.did` profile field). Specs must not compute an expected MXID from a DID.
- Reuses `../browser/wallet-helper.mjs` and `webauthn-helper.mjs` for OIDC redirect origin

## Notes

- Element OIDC redirects land on siwx (`SIWX_URL`, host port `E2E_SIWX_PORT`); mock wallet must be injected on **both** Element and siwx origins when needed.
- Device delete/logout need the Caddy MSC3861 edge routes (logout/all, devices/*) on the Matrix edge port (`E2E_MATRIX_PORT`).
