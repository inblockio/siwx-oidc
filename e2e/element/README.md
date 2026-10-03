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
| `ew-sw-media-auth.spec.mjs` | SW-1..3: Element's service worker keeps authenticated media working when its `/versions` check hits an expired token (401, anonymous retry), a transient 5xx (never cached), or a media 401 while the app refreshes (one bounded retry). Covers siwx-oidc-matrix-server `patches/element-web` entries 9 and 10. `EW_SW_OVERRIDE=<stock sw.js>` serves the unpatched worker through `helpers/stock-sw-proxy.mjs`; every leg must then fail. |
| `ew-encrypted-search.spec.mjs` | UX1–UX8: search in encrypted rooms through the browser EventIndex (siwx-oidc-matrix-server `patches/element-web` entry 6, `browser-eventindex.patch`): the room-info search finds a freshly sent message, an `m.replace` moves the hit to the new body under the original event id, the index survives a reload, sign-out leaves no plaintext in the Element origin's storage, and a second account on the same browser profile cannot find the first one's message. Needs `features.feature_web_event_index: true` in the target's `config.json`; `beforeAll` fails naming the key otherwise. |
| `ew-copy-markdown.spec.mjs` | CM1-CM4: the message context menu's "Copy Markdown" entry (siwx-oidc-matrix-server#24) in an encrypted room: it sits directly above "Pin" (CM1), copies an edited HTML message as exact CommonMark + GFM through the clipboard (CM2), is absent on an `m.image` (CM3), and escapes Markdown and HTML metacharacters of a message with no HTML (CM4). Grants `clipboard-read`/`clipboard-write` to the browser context. Run against an Element without the entry, CM1, CM2 and CM4 must fail on the missing "Copy Markdown" menu item. |

## Helpers

- `helpers/element.mjs` — open Element, wait for room list / login
- Reuses `../browser/wallet-helper.mjs` and `webauthn-helper.mjs` for OIDC redirect origin

## Notes

- Element OIDC redirects land on `http://localhost:8081` (siwx); mock wallet must be injected on **both** Element and siwx origins when needed.
- Device delete/logout need the Caddy MSC3861 edge routes (logout/all, devices/*) on `:8080`.
