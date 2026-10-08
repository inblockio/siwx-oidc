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

`run.sh` runs the specs in the Playwright container. With `CTRF_OUTPUT` (a file) or
`CTRF_OUTPUT_DIR` (a directory, file `ctrf-report.json`) set to an absolute host path it also
writes a CTRF report through `playwright-ctrf-json-reporter`, mounting that location into the
container at the same path; `QUALIFY_STATE_DIR` is mounted the same way, and `T2_*`, `EW_*`,
`E2E_STRICT_SKIPS` and `MAS_SHARED_SECRET` are passed through by name. Other arguments go to
`playwright test` unchanged (spec files, `--grep`, `--list`).

### Upgrade continuity (T2, T2-EW)

`upgrade-survival.sh` captures a signed-in Element Web user on the baseline image, switches only
one service to the candidate, and checks the same browser profile afterwards. `T2_SWAP` picks the
service: `siwx-oidc` (default; `ew-upgrade-capture.spec.mjs`, `ew-upgrade-assert.spec.mjs`) or
`element-web` (T2-EW; `ew-upgrade-ew-capture.spec.mjs`, `ew-upgrade-ew-assert.spec.mjs`: session,
device and the browser EventIndex of patch entry 6 across an Element image switch).
`T2_DIRECTION=rollback` runs candidate -> baseline. It runs on the lab pinned by digest
(siwx-oidc-matrix-server `docker-compose.qualify.yml`); commands, variables and the negative
controls are in [../README.md](../README.md#element-web-upgrade-continuity-elementupgrade-survivalsh).
A plain run of the whole suite leaves these pairs out: they run only with `QUALIFY_STATE_DIR` set.

## Patch legs: tags and the promotion selection

Element Web is promoted with the vendored patches of siwx-oidc-matrix-server
`patches/element-web/` (numbered registry entries in that directory's README) and the runtime
deltas of `dockerfiles/Dockerfile.element` and `config/`. A test that exercises one of them
carries a Playwright tag naming it, so a promotion runs exactly those legs and never re-runs
upstream behaviour or the integration specs:

- `@ew-p<N>`: the test exercises patch registry entry N (a test may carry several);
- `@ew-delta-<name>`: the test exercises a runtime or config delta, `<name>` naming it
  (`theme-overrides`: `config/element-theme-overrides.css`).

Tags are test metadata (`test(title, { tag }, fn)`), not part of the title: CTRF reports keep the
same test names and list the tags separately. Today's legs:

| Tag | Tests (spec file) |
|---|---|
| `@ew-p1` force-first-device-recovery | EW-C1 (clickpath), EW-J1, EW-J2, EW-J4, EW-J5 (journey-exits), EW-L1b (login), EW-R1 (journey-reset-after-no-recovery), EW-R1-0, EW-R1-1 (recovery-entry), EW-U3P-0 (u3prime-no-forced-reset). Untagged: EW-U3P-1, EW-U3P-2 (inconclusive on every build; see the spec) |
| `@ew-p2` setup-encryption-busy-wedge | EW-V1 (verify-sas, its assertion 8), H3-C (h3-second-device-walk), EW-R1-2 (recovery-entry) and EW-D1 (journey-add-device), which assert the ceremony never sits in the zero-control `Phase.Busy` wedge |
| `@ew-p3` honest-qr-disabled-reason | PH-0, PH-1 (patch-honesty) |
| `@ew-p4` offer-verify-current-session | PH-0, PH-2 (patch-honesty) |
| `@ew-p6` browser-eventindex | UX1-UX8 (encrypted-search); T2-EW's EW-EA3 to EW-EA7 judge the same patch across an image switch (driver only, see above) |
| `@ew-p7` show-attested-did | EW-DID1, EW-DID2 (attested-did) |
| `@ew-p8` resolve-did-search | EW-U5, EW-UA6 (the T2 pair, so only under `upgrade-survival.sh`) |
| `@ew-p9` sw-versions-no-cache-on-error | SW-1, SW-2 (sw-media-auth) |
| `@ew-p10` sw-media-401-token-retry | SW-3 (sw-media-auth) |
| `@ew-p11` copy-markdown | CM1-CM7 (copy-markdown; CM3, "absent on media", passes on a build without the entry by design) |
| `@ew-delta-theme-overrides` | EW-MX25 (attested-did) |

Entry 5 (auto-approve-check-code) has no leg: it needs a second MSC4108 client.

The selection, on a lab whose Element runs the build under test (the T2 pairs stay out because
`QUALIFY_STATE_DIR` is unset; list the spec files so nothing else is even loaded):

```bash
./run.sh --grep '@ew-p|@ew-delta' \
  ew-attested-did.spec.mjs ew-clickpath.spec.mjs ew-copy-markdown.spec.mjs ew-encrypted-search.spec.mjs \
  ew-h3-second-device-walk.spec.mjs ew-journey-add-device.spec.mjs ew-journey-exits.spec.mjs \
  ew-journey-reset-after-no-recovery.spec.mjs ew-login.spec.mjs ew-patch-honesty.spec.mjs \
  ew-recovery-entry.spec.mjs ew-sw-media-auth.spec.mjs ew-u3prime-no-forced-reset.spec.mjs ew-verify-sas.spec.mjs
./run.sh --grep '@ew-p1\b' ...     # one entry: \b, or @ew-p1 also selects @ew-p10 and @ew-p11
./run.sh --list --grep '@ew-p|@ew-delta' ...   # what would run
```

`run.sh` hands its arguments to `playwright test` unchanged and passes every `EW_*` variable
through (an absolute file path in one, such as `EW_THEME_OVERRIDES_CSS` or `EW_SW_OVERRIDE`, has
its directory mounted read-only at the same path). On the build a promotion starts from, the legs
of entries the candidate adds or changes are expected to fail (they test what is not there yet);
on the candidate, no patch leg may fail.

Negative controls of the newer legs: `EW_DID_NEGATIVE=hide-field` (EW-DID1 and EW-DID2 must
fail: the browser's reads of the DID profile field answer 404); EW-MX25 fails on the
theme-overrides CSS served before the #25 fix, and `EW_THEME_OVERRIDES_CSS=<file>` judges a CSS
file before an image carries it; T2-EW's `T2_NEGATIVE=drop-eventindex` (EW-EA3 must fail).

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
| `ew-upgrade-capture.spec.mjs`, `ew-upgrade-assert.spec.mjs` | EW-U1..U6 / EW-UA1..UA10, EW-UZ: T2 upgrade continuity, driven by `upgrade-survival.sh` (see above) |
| `ew-attested-did.spec.mjs` | EW-DID1, EW-DID2: the provider-attested DID (siwx-oidc-matrix-server `patches/element-web` entry 7, `show-attested-did.patch`) after a fresh wallet sign-in, whose binding siwx-oidc publishes into the account's `io.inblock.did` profile field: the user-info panel shows a "DID" row directly under the MXID, abbreviated from the wallet's `did:pkh:eip155:1:0` prefix, and its copy button copies the full DID (EW-DID1); Settings > Account shows the full DID in a "DID" row whose copy button copies it (EW-DID2). EW-MX25 (siwx-oidc-matrix-server#25, `config/element-theme-overrides.css`): in the user-info panel the MXID's copy button sits within -1..8 px of the right edge of the MXID's last line, on that line, and the MXID with its button is centred within 4 px in the profile column. `EW_THEME_OVERRIDES_CSS=<file>` serves that file as the theme overrides (and checks the page applied it rule for rule); `EW_DID_NEGATIVE=hide-field` answers the browser's DID profile reads with 404, and EW-DID1 and EW-DID2 must then fail. Grants `clipboard-read`/`clipboard-write`. |
| `ew-upgrade-ew-capture.spec.mjs`, `ew-upgrade-ew-assert.spec.mjs` | EW-EC1..EC4 / EW-EA1..EA7, EW-EZ: T2-EW, continuity across an Element Web image switch (session, device, the browser EventIndex not reset), driven by `upgrade-survival.sh` with `T2_SWAP=element-web` |
| `ew-copy-markdown.spec.mjs` | CM1-CM7: the message context menu's "Copy Markdown" entry (siwx-oidc-matrix-server#24) in an encrypted room: it sits directly above "Pin" (CM1), copies an edited HTML message as exact CommonMark + GFM through the clipboard (CM2), is absent on an `m.image` (CM3), escapes Markdown and HTML metacharacters of a message with raw HTML and no formatted body (CM4), copies Markdown typed into the real composer (pasted, sent with Enter) back exactly as typed, GFM table, task list and soft line breaks included (CM5), and does the same for content Element did not compose: a Rust SDK message whose `formatted_body` is ruma's real `text_markdown` rendering (CM6) and a bot's plain `body` with no HTML (CM7), both sent from the test account because the rule reads the event content only, never the sender. Grants `clipboard-read`/`clipboard-write` to the browser context. Run against an Element without the entry, CM1, CM2, CM4, CM5, CM6 and CM7 must fail on the missing "Copy Markdown" menu item; against one whose entry only converts the displayed HTML, CM5, CM6 and CM7 fail on the clipboard comparison. |

## Helpers

- `helpers/element.mjs` — open Element, wait for room list / login
- Reuses `../browser/wallet-helper.mjs` and `webauthn-helper.mjs` for OIDC redirect origin

## Notes

- Element OIDC redirects land on `http://localhost:8081` (siwx); mock wallet must be injected on **both** Element and siwx origins when needed.
- Device delete/logout need the Caddy MSC3861 edge routes (logout/all, devices/*) on `:8080`.
