# Element Web Playwright suite (Phase 2.0)

Drives a **real Element Web** instance against local Synapse + siwx-oidc (MSC3861).

## Stack

Bring up from `siwx-oidc-matrix-server` (sibling repo):

```bash
# From siwx-oidc-matrix-server (needs ../siwx-oidc build context)
docker compose -f docker-compose.local.yml --env-file .env.local up --build -d
# Element:  http://localhost:8088
# Matrix:   http://localhost:8080
# siwx:     http://localhost:8081
```

Or from this repo:

```bash
bash e2e/element/stack-up.sh
bash e2e/element/run.sh
bash e2e/element/stack-down.sh
```

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

## Helpers

- `helpers/element.mjs` — open Element, wait for room list / login
- Reuses `../browser/wallet-helper.mjs` and `webauthn-helper.mjs` for OIDC redirect origin

## Notes

- Element OIDC redirects land on `http://localhost:8081` (siwx); mock wallet must be injected on **both** Element and siwx origins when needed.
- Device delete/logout need the Caddy MSC3861 edge routes (logout/all, devices/*) on `:8080`.
