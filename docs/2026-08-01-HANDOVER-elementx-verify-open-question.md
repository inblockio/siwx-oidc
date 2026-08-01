# HANDOVER — Element X ↔ Element Web verification: the open question

**Date:** 2026-08-01 **Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`)
**Companion:** `siwx-oidc-matrix-server` branch `fix/4s-tombstone-probe`

> **Read this first, and read it instead of the 30-file audit corpus.** That corpus is FROZEN as
> reference by owner decision — do not grow it. The deliverable is walked user journeys, not models.

---

## 1. The open question

> "Is it expected that when signing in with Element X, *verify with other device* does not work if
> the other device is Element Web?"

**Answer: no, not expected, and not a siwx-oidc fault by design.** Interactive verification
(SAS/emoji) is pure Matrix to-device traffic between two sessions of the same user. siwx-oidc has no
role in it — not proxied, not gated by MSC3861.

**But it is the one path never proven at any layer.** All existing proof is Element Web ↔ Element
Web. There is no second Matrix client in the lab.

### Three candidates, in order of likelihood

| # | Candidate | Status |
|---|---|---|
| 1 | **Busy-wedge fix not deployed.** `6c23298` + `cd17c90` are still absent from prod (verified 2026-08-01: marker `cross-signing not ready 10s after verification` ABSENT from prod's `element-web-app.js`). That bug lets verification succeed cryptographically while Element Web's view sits in `Phase.Busy` with ZERO buttons — indistinguishable from "it didn't work". **Caveat:** observed on the device *being verified*; if Element Web is the verifier it may not be in that path. Strong candidate, NOT a conclusion. |
| 2 | **Cross-client method mismatch.** Element X may offer only QR-scan; Element Web can display a reciprocate QR but cannot scan one. Unverified — the `m.sas.v1` / `m.qr_code.show.v1` markers were ABSENT from prod's app chunk, but that is INCONCLUSIVE (they likely live in another chunk; an identical mistake was already made once this session with `accessSecretStorage: resetting 4S`, which lives in `init.js`). |
| 3 | **Version gap** — see §3. |

### The symptom discriminates — ask the owner which they see

- Element Web never prompts → to-device delivery / not syncing
- Both show emoji, confirm, then Element Web hangs with no buttons → candidate 1; deploy fixes it
- Element X offers only "scan a QR", Element Web shows none → candidate 2
- "Not supported by your account provider" → NOT this; `response_modes_supported` now ships

---

## 2. Prod state, re-verified 2026-08-01 (supersedes the 07-26 readings)

| Fact | Value | Method |
|---|---|---|
| `response_modes_supported` | **`["query","fragment"]`** — G3 CLOSED, fix shipped | live discovery fetch |
| Prod Element | **1.12.24** | `https://element.inblock.io/version` |
| forced-recovery patch | PRESENT | bundle grep |
| 4S raw-GET probe (`00e76f4`+) | **PRESENT** | bundle grep |
| Busy-wedge fix | **ABSENT** | bundle grep |

**Bundle-grep discipline:** fetch `element-web-app.js` from `bundles/<hash>/`, NOT `bundle.js` (a 27 KB
webpack runtime). Verify which chunk holds a marker before concluding anything from its absence, and
use a known-present control marker.

---

## 3. The grounding gap that matters most

**Prod runs Element 1.12.24. The lab pins `ARG ELEMENT_WEB_TAG=v1.12.20`.** Every one of the 231
green tests ran against 1.12.20. Independently worth fixing regardless of the question above.

---

## 4. What is done and committed

siwx-oidc (`~/wt/siwx-durability`): `f39cda1` `d2b7ecf` `062e76f` `a69947c` `b3c7dd5`
matrix-server (`fix/4s-tombstone-probe`): `1de0906`

- **Owner-reported prod failure ROOT CAUSED AND FIXED.** js-sdk cannot delete account data, so
  `setDefaultKeyId(null)` writes `{}`; both vendored probes did `.then(() => true)` and never read
  the body, so a 200 carrying `{}` read as "4S exists". Fixed to `!!r?.key`. Verified: reset now
  re-fires the wizard, mints a new recovery key, backup v3, reaches the app shell.
- **Passkey registration dead action FIXED** (`chained` param; the re-entrancy guard made the
  auto-sign-in a guaranteed no-op since `edff2b2`).
- **Journey walks** J1–J5, passkey, add-device, reset-after-no-recovery, H3 second-device.
- **`EW-Q1-c` was a TEST bug** (a `page.goto('#/settings/sessions')` no-op plus a too-narrow QR
  selector), not a feature gap.

**Verification state: 231 green, 0 red** (Element 53 · Browser 26 · Rust integration 28 · unit 123).
Caveat: the Rust/browser suites ran against the `siwx-e2e-*` mock stack, which was NOT rebuilt — they
may exercise older `src/`. The Element lab WAS rebuilt from this worktree.

---

## 5. Do not ship

`honest-qr-disabled-reason.patch`, `offer-verify-current-session.patch`, and the modified
`Dockerfile.element` — uncommitted, never CI-built, one calls an undefined i18n key.

**Deploy order is non-negotiable: siwx-oidc → verify → element-web `--no-deps`.** Prod siwx-oidc had
ZERO `allow_cross_signing_reset` calls (`git show db79e75:src/oidc.rs | grep -c` → 0); `CLAUDE.md`'s
claim that it "fires unconditionally on sign-in" is stale. Redis needs no flush (`TokenMetadata`
byte-identical).

---

## 6. The lesson this session actually paid for

**Five times a green test turned out to assert nothing**, and each looked exactly like a product
defect: sampling around a helper that did the work internally; reading a token from a place it isn't
stored; stopping at a confirmation dialog and calling it a destination; clicking `.first()` when two
dialogs stack so the click hit an obscured button; a `page.goto` that dispatched nothing.

Every one was caught by carrying the walk one step further — never by reasoning about it. Before
reporting anything green, state what would have to break to turn it red.
