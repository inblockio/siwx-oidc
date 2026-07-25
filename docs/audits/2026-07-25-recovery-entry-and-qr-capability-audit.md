# Recovery-phrase entry & QR second-device login — capability audit

**Date:** 2026-07-25
**Worktree:** `/home/waldknoten-01/wt/siwx-durability`, branch `feat/session-durability-marathon`, base `main` @ `d21329e`
**Method:** `/logic-model` (CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY CONDITIONS)
**Scope:** evaluation + test authoring. **No container was started, stopped, restarted or removed.**
All live evidence is read-only HTTP `GET` against a lab a sibling agent owns.

> **Labelling contract.** **VERIFIED** = backed by a `file:line`, a commit, a config path, or a
> read-only probe reproduced here. **ASSUMED** = a plausible link in the chain that was *not*
> tested; every one is in the assumptions register (§6) with the test that settles it.
>
> **The Playwright specs delivered alongside this document were NOT executed.** The lab is
> sibling-owned this session and running an image that does not correspond to this worktree
> (§2.3). Nothing below should be read as "the tests passed".

---

## 0. Verdict up front

| Capability | Complete? | Where it breaks |
|---|---|---|
| **1 — "Enter recovery phrase" available in every context that needs it** | **NO** | The vendored patch fix removes the *reload* gate but does **not** restore recovery-key entry in the contexts where the gate must legitimately fire. The entry button is gated on a condition (`m.cross_signing.master` stored in 4S) that **nothing in the forced wizard verifies**. |
| **2 — QR / device-code login with a second device** | **NO (unproven, not broken)** | siwx-oidc's RFC 8628 half is correct and proven. Everything past token issuance — rendezvous payload transit, Element's QR affordance actually engaging, the new device not then demanding a phrase — has **never been demonstrated at any layer**. |

**The single most important new finding in this audit** (§3.3): the root cause recorded for the
P0 "no recovery-key field" finding (F16) is **incompatible with the shipped code**. F16 was
attributed to the same local-cache re-hydration timing that caused the gate to fire. It cannot
be: the button's gate reads the **server**, not the local cache. The two are different bugs, and
the merged patch fixes only one of them.

---

## 1. CONTEXT

### 1.1 The requirement

`docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md:105-106` (**R5**, **R6**):

> R5 — User adds a phone, **nothing else signed in** → Recovery phrase — **must remain, and must be enterable**
> R6 — User lost every device → Recovery phrase — **must remain, and must be enterable**

R5/R6 are *negative* requirements: the phrase must still be demanded. The audit question is the
second clause — **enterable**. Plan line 111 states plainly: *"and must be enterable" is not
pedantry — it is currently FALSE (F16)*.

### 1.2 What changed since F16 was recorded

The reload verify-gate was root-caused to this deployment's **own vendored Element patch**, and
two fixes are merged to `main` of `/home/waldknoten-01/siwx-oidc-matrix-server`:

| Commit | Change | Status |
|---|---|---|
| `9ec414d` | `shouldForceVerification` widened: `!crossSigningReady \|\| !(secretStorageReady \|\| hasServer4S)`, with `hasServer4S = client.secretStorage.hasKey()` | superseded |
| `b7e594f` | its own assumption A1 falsified — `hasKey()` reads the **local** cache, as cold as `isSecretStorageReady()`. Replaced with a direct server fetch: `getAccountDataFromServer("m.secret_storage.default_key")` | **current** |

Patch file: `/home/waldknoten-01/siwx-oidc-matrix-server/patches/element-web/force-first-device-recovery.patch`
(VERIFIED, read in full). Two hunks against `apps/web/src/components/structures/MatrixChat.tsx`
at pristine `v1.12.20`, plus two `en_EN.json` strings.

**Hunk 1** (patch:41-46) — the gate condition:

```ts
const secretStorageReady = await crypto?.isSecretStorageReady();
const hasServer4S =
    !secretStorageReady &&
    !!(await client.getAccountDataFromServer("m.secret_storage.default_key").catch(() => null));
return !crossSigningReady || !(secretStorageReady || hasServer4S);
```

**Hunk 2** (patch:50-113) — the forced recovery-creation loop in
`onCompleteSecurityE2eSetupFinished`:

```ts
const hasExisting4S = await cli.secretStorage.hasKey();
await accessSecretStorage(async () => {}, { forceReset: !hasExisting4S });
recoverySetUp = !(await this.shouldForceVerification());
```
…with a `QuestionDialog` (Retry / Sign out) on failure; any dismissal dispatches `logout`.

### 1.3 What is actually running in the lab

VERIFIED by read-only HTTP against the sibling-owned lab, 2026-07-25:

| Probe | Result |
|---|---|
| `GET :28088/version` | `1.12.20` |
| `GET :28088/bundles/444e87b816763490ca35/element-web-app.js` | contains `Forced recovery-key setup was not completed`, `force_recovery_setup_title`, `force_recovery_setup_description`, `getAccountDataFromServer`, `m.secret_storage.default_key` |

> **The running lab Element IS the `b7e594f` patched build.** The merged fix is deployed in the
> lab. (It is *not* in the `siwx-oidc` repo — the patch lives in the sibling `matrix-server`
> repo.)

---

## 2. GOAL, INPUTS, and the environment divergence

### 2.1 Goal (one sentence)

> Enumerate every context in which a user can be asked to prove identity or recover encryption,
> state per context whether a recovery-phrase **entry** path exists with cited evidence, do the
> same proven/unproven/broken split for QR second-device login, and deliver Playwright specs that
> would settle each.

**Acceptance criterion:** a context×path table where every row is VERIFIED or explicitly ASSUMED;
a Capability-2 table that separates *siwx-oidc's part works* from *the end-to-end flow works*;
and two executable specs that fail honestly rather than pass vacuously.

### 2.2 Inputs consumed

| Class | Item |
|---|---|
| Patch | `siwx-oidc-matrix-server/patches/element-web/force-first-device-recovery.patch`; commits `9ec414d`, `b7e594f` |
| Element source | `~/.cache/f2-patch-check/element-web` @ tag `v1.12.20` (git object store; `SetupEncryptionBody.tsx`, `SetupEncryptionStore.ts`, `CompleteSecurity.tsx`, `AccessSecretStorageDialog.tsx`, `CreateSecretStorageDialog.tsx`, `en_EN.json`) |
| Shipped js-sdk | matrix-js-sdk **41.6.0** — read from the **live lab bundle** (chunk `6065.js`), not from source |
| Synapse | image overlay `…/overlay/1513dc6dfd13…/diff/…/synapse/rest/client/rendezvous.py` (read-only) |
| siwx-oidc | `src/oidc.rs`, `src/device_auth.rs`, `src/account.rs` @ `d21329e` |
| Tests | `e2e/element/*.spec.mjs`, `e2e/element/helpers/*`, `e2e/browser/wallet-helper.mjs` |
| Prior art | `docs/audits/2026-07-25-verify-with-other-device-gap-evaluation.md`; `…-AUDITED-PROPOSAL.md:456`; the durability plan |

### 2.3 Environment divergence — the lab is NOT this worktree

VERIFIED, and it invalidates any inference from lab behaviour to `main`:

| Fact | Evidence |
|---|---|
| Live lab `GET :28080/_matrix/client/v1/auth_metadata` returns `response_modes_supported: ["query","fragment"]` | read-only probe |
| `main` @ `d21329e` does **not** emit that field | `grep -n response_modes_supported src/oidc.rs` → 0 hits; `git log -S response_modes_supported -- src/oidc.rs` → no commit |

> The running `siwx-oidc` image is built from a sibling's unmerged branch. **G3 from the prior
> audit is fixed in the running image only.** A build from `main` regresses it. This is a live
> risk, not a hypothetical (§7, our-code item 1).

---

## 3. CAPABILITY 1 — recovery-phrase entry

### 3.1 The exact affordance and its gate (VERIFIED)

`apps/web/src/components/structures/auth/SetupEncryptionBody.tsx` @ `v1.12.20`, `Phase.Intro`:

```tsx
let verifyButton;         if (store.hasDevicesToVerifyAgainst) { … "Use another device" … }
let useRecoveryKeyButton; if (store.keyInfo)                   { … "Use recovery key"   … }
let signOutButton;        if (this.props.allowLogout)          { … "Sign out"           … }
// always rendered:
<Button kind="secondary" onClick={this.onCantConfirmClick}>{_t("encryption|verification|cant_confirm")}</Button>
```

- `onCantConfirmClick` (`SetupEncryptionBody.tsx:130-141`) → `Modal.createDialog(ResetIdentityDialog, …)`
  — **this is the destructive exit.** String: `"Can't confirm?"`.
- `CompleteSecurity.tsx` passes `allowLogout={true}` and, because `force_verification: true`
  (`config/element-config.json:10`, VERIFIED live at `:28088/config.json`), **suppresses the skip
  (X) button**.

So the gate's complete exit set is: **Use another device** (conditional) · **Use recovery key**
(conditional) · **Can't confirm? → reset** (always) · **Sign out** (always).

F16's "only exits are 'Use another device' or destructive RESET" is therefore exactly:
`store.keyInfo === null`.

### 3.2 What `keyInfo` is (VERIFIED)

`apps/web/src/stores/SetupEncryptionStore.ts:90-100`:

```ts
public async fetchKeyInfo(): Promise<void> {
    const keys = await cli.secretStorage.isStored("m.cross_signing.master");
    if (keys === null || Object.keys(keys).length === 0) { this.keyId = null; this.keyInfo = null; }
    else { this.keyId = Object.keys(keys)[0]; this.keyInfo = keys[this.keyId]; }
```

And the **shipped** matrix-js-sdk 41.6.0 implementation, extracted verbatim from the live lab
bundle (`:28088/bundles/444e87b816763490ca35/6065.js`):

```js
async isStored(e){
  const t = await this.accountDataAdapter.getAccountDataFromServer(e);
  if (null == t || !t.encrypted) return null;
  for (const e of Object.keys(t.encrypted)) {
    const r = await this.accountDataAdapter.getAccountDataFromServer(`m.secret_storage.key.${e}`);
    …
```

> **`isStored` is a SERVER read** — the same `getAccountDataFromServer` API that `b7e594f`
> deliberately switched to *because* it bypasses the cold local cache.

### 3.3 The consequence — F16's recorded root cause is incompatible with the code

The audited proposal attributes the whole reload finding to one mechanism: local account_data is
cold on restore, so readiness checks read false. That correctly explains **why the gate fired**.
It **cannot** explain **why the recovery-key button was absent**, because that button's gate does
not read the local cache.

Given the shipped code, `keyInfo === null` has exactly one remaining explanation:

> **`m.cross_signing.master` was not present, as an `encrypted` account_data event, on the
> server at gate time.** i.e. a 4S default key existed (and the megolm backup existed), but the
> **cross-signing master private key was never encrypted into 4S**.

The evidence originally cited against this — *"the 4S/backup setup had fully succeeded and the
backup still exists at gate time"*, with `room_keys/version` returning 200 — does **not** rule it
out. `room_keys/version` is the **megolm message-key backup** version. It is a different artifact
from `m.cross_signing.master` in account_data. A deployment can have the former and not the
latter, and in that state Element is *correct* to withhold the recovery-key button: there is
nothing under that key for the phrase to unlock.

**Why this matters for the merged fix.** `b7e594f` makes the *reload* gate stop firing. It does
nothing about `keyInfo`. If the diagnosis above holds, the fix **masks the symptom in one context
and leaves R5/R6 exactly as broken as F16 described**, because R5/R6 are precisely the contexts
where the gate must still fire. The fix's own success criterion,
`recoverySetUp = !(await this.shouldForceVerification())`, checks only that a 4S **default key**
exists — never that the cross-signing master is stored under it. That is the gap.

**Status: ASSUMED-with-strong-mechanism, not VERIFIED.** It is falsifiable in one assertion, and
that assertion is leg **R1-0** of the delivered spec (§5.1).

### 3.4 Context × recovery-path table

| # | Context | Verify-gate fires? | Recovery-phrase **entry** path | Status |
|---|---|---|---|---|
| **C1** | First login, brand-new account, first device | No gate — the patch's hunk-2 loop forces recovery **creation** | N/A (creation, not entry) | **VERIFIED present.** But nothing asserts the created 4S actually stores `m.cross_signing.master` — this is the root dependency of every row below |
| **C2** | Reload / session restore, 4S exists server-side | **No**, after `b7e594f` (`hasServer4S` short-circuits) | N/A | **Fixed in patch (VERIFIED in source + in the running bundle); runtime behaviour UNVERIFIED** — spec leg R1-1 |
| **C3** | Reload where the server 4S probe fails (network blip) | **Yes** — `.catch(() => null)` fails toward enforcing | `keyInfo` gate → same as C5 | **UNDEFINED if `keyInfo` is null.** A transient error re-creates the whole F16 trap. Newly identified here |
| **C4** | New device, **live verified session exists** | Yes | "Use another device" **and** "Use recovery key" (iff `keyInfo`) | **UNPROVEN** — prior audit C8: never demonstrated at any layer. This is R4 |
| **C5** | **New device, NO live session** | Yes | **ONLY** "Use recovery key" (iff `keyInfo`) | **THE CRITICAL ROW — R5/R6.** If `keyInfo` is null the only exits are `Can't confirm? → ResetIdentityDialog` and `Sign out`. Both are destructive or abandonment. **Undefined user state** — spec leg R1-2 |
| **C6** | Post-reset (`ResetIdentityDialog` completed) | Re-enters C1 | creation again | **UNPROVEN** |
| **C7** | Device approval — siwx `/device` | n/a | **None, by design** | **CORRECT.** This is CAIP-122 / passkey *identity* proof, not E2EE recovery. `src/device_auth.rs:1021,1064` reject new identities before `entry.did` is set. A recovery phrase here would be a category error |
| **C8** | Account re-auth — siwx `/account` | n/a | **None, by design** | **CORRECT.** Same reasoning; `src/account.rs:255-268` `SUPPORTED_ACTIONS` |
| **C9** | In-app Settings → Encryption, live session | n/a | `ChangeRecoveryKey.tsx` exists in the build | **UNPROVEN**, and not the gate — irrelevant to R5/R6 (needs a working session already) |

**Contexts where the only exits remain "use another device" or destructive reset: C3 and C5**
(and C4 degrades to C5 whenever the other device is not actually verifiable). C5 is the worst,
because by construction "use another device" is unavailable there — leaving **reset or sign out
as the only exits**, which is the definition of an undefined user state for R5/R6.

---

## 4. CAPABILITY 2 — QR / device-code second-device login

### 4.1 Proven / unproven / broken

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | OP advertises the device-code grant + `device_authorization_endpoint` | **PROVEN** | `src/oidc.rs:289-295`; live lab `auth_metadata` → `grant_types_supported` includes `urn:ietf:params:oauth:grant-type:device_code`, `device_authorization_endpoint: …/device_authorization` |
| 2 | RFC 8628: `device_authorization` → `authorization_pending` → wallet approve → `mat_`/`mcr_` → whoami on the linked `device_id` | **PROVEN** | `e2e/element/ew-device-link.spec.mjs:39-131` (EW-D1) |
| 3 | `verification_uri_complete` is returned (what MSC4108's existing device needs) | **PROVEN** | `src/device_auth.rs:56-62` |
| 4 | New-identity rejection on the QR path, before any provisioning | **PROVEN** | `src/device_auth.rs:1021,1064` |
| 5 | Approval fabricates no crypto claim; the Q2 dead-end stays externally detectable | **PROVEN** | EW-D2, `ew-device-link.spec.mjs:160-229`, esp. `:202` |
| 6 | MSC4108 rendezvous enabled, advertised, edge-routed | **PROVEN (config + live)** | `matrix_server.sh:78`; overlay `rest/client/rendezvous.py:122-124`; live `unstable_features["org.matrix.msc4108"] = true` |
| 7 | The rendezvous POST needs no token (a not-yet-logged-in device can open a channel) | **PROVEN** | overlay `rendezvous.py:59-68` — `MSC4108RendezvousServlet.on_POST` has **no** `auth.get_user_by_req`, in explicit contrast to the MSC4388 servlets at `:80-95` which do |
| 8 | Element's "Show QR code" is **enabled** and clicking it opens a **real** rendezvous session | **UNPROVEN** | gate `shouldShowQrForLinkNewDevice` evaluated all-true (prior audit §4.2.3) — but "the gate would pass" ≠ "the button works". Zero tests |
| 9 | The rendezvous channel carries a **>512-byte** payload with `If-Match` **through Caddy** | **UNPROVEN — and suspected broken (H-V4)** | `Caddyfile.local:89` comments *"(no compression to preserve ETags)"* but there is **no `encode off`**; site-level `encode zstd gzip` at `:30` covers the block. Live: Caddy gzips Synapse responses on that vhost |
| 10 | A second party can read what Element published to the channel | **UNPROVEN** | — |
| 11 | The new device, having received secrets, does **not** then demand a recovery key | **UNPROVEN (A1)** | the vendored patch is itself the code that could demand one |
| 12 | Approver lacks cross-signing **private** keys → tokens issue, client dies 30–60 s later | **KNOWN FAILURE MODE (Q2), correctly surfaced, not fixed** | `src/device_auth.rs:853-859`: the approval-time pre-flight was **removed** as a confirmed false positive; the real prerequisite is *not observable server-side*. EW-D2 asserts the dead-end is detectable via `keys/query` |
| 13 | `response_modes_supported` present | **BROKEN ON `main`** | §2.3 — live lab has it, `main` @ `d21329e` does not. On matrix-js-sdk ≥ 42 its absence fails issuer validation, and because `isSignInWithQRAvailable()` returns `false` on any validation throw, it *silently* disables QR device-link and mislabels it "Not supported by your account provider" |

### 4.2 The distinction the owner asked for

> **siwx-oidc's part works.** Rows 1–5 are proven by tests that exist and pass. The RFC 8628 half
> is complete, honest about what it cannot observe, and correctly refuses to fabricate a crypto
> claim.
>
> **The end-to-end flow is not proven to work, and one link is suspected broken.** Every row from
> 8 onward is post-token. Nothing has ever demonstrated that a second device completes MSC4108
> Phase 4 in this deployment. Row 9 (H-V4) is the highest-value open item because its symptom
> signature — *approval succeeds, tokens issue, logs look clean, client dies 30–60 s later* — is
> **indistinguishable from Q2**, so today's attribution of every such report to "the approver had
> no cross-signing keys" is not safe.

Row 12 is a genuine, documented, **unfixable-server-side** failure mode, not a defect in our
code. The correct posture — already taken — is detectability plus client-side enforcement, not a
server-side pre-flight (which was tried and was a confirmed false positive).

---

## 5. Delivered specs (NOT EXECUTED)

New files only; no shared helper was modified.

### 5.1 `e2e/element/ew-recovery-entry.spec.mjs` — **EW-R1**

| Leg | Context | Asserts |
|---|---|---|
| **R1-0** | C1 | After the mandatory first-device wizard, `m.cross_signing.master` **is** stored in 4S — read from the **server**, the same predicate the button gate uses. **This single assertion settles §3.3.** On failure it prints the discriminator: default-key present? backup version present? master present? |
| **R1-1** | C2 | Reload either restores straight to `.mx_MatrixChat` (the `b7e594f` outcome) **or**, if the gate fires, "Use recovery key" is present **and entering the captured key completes**. No third outcome is accepted |
| **R1-2** | **C5** | The R5/R6 case. Bootstrap + capture key in context A, delete A's device via MSC4191 so no verified session survives, log in fresh in context B → the gate **must** fire → "Use recovery key" **must** be present → clicking it and typing the real key **must** reach the app. Also asserts the destructive exits are not the only ones |
| **R1-3** | C4 | With a live session present, at least one **non-destructive** exit exists, and records which |

Each leg reads `window.mxSetupEncryptionStore` (VERIFIED exposed — `SetupEncryptionStore.sharedInstance()`
assigns it; 1 occurrence in the live app chunk) to report `keyInfo` / `hasDevicesToVerifyAgainst`
in the failure message, so a red test names the failing conjunct instead of just "button missing".

### 5.2 `e2e/element/ew-qr-second-device.spec.mjs` — **EW-Q1**

| Leg | Asserts |
|---|---|
| **Q1-a** | **H-V4 falsification.** Open a rendezvous session through the edge, then `PUT` a **>512-byte** body with `If-Match: <etag>` and `Accept-Encoding: gzip`. Must be accepted (2xx). A `412` is the H-V4 confirmation and the message reports the observed `ETag` / `Content-Encoding` |
| **Q1-b** | **Second party reads what was written.** A separate HTTP client `GET`s the channel and must receive byte-identical content, then long-polls with `If-None-Match` and must observe the update. This is row 10 |
| **Q1-c** | **Element really engages the rendezvous.** Real DOM: log in, open Settings → Sessions, assert "Show QR code" is **enabled** (not the "Not supported by your account provider" state), click it, and require that a real `POST …/org.matrix.msc4108/rendezvous` was observed on the wire **and** a QR rendered. This is row 8 |
| **Q1-d** | **Metadata guard.** `response_modes_supported ⊇ {query, fragment}` — the row-13 regression guard, which fails today against any build from `main` |

---

## 6. Assumptions register

| ID | Assumption | Status | Test that settles it |
|---|---|---|---|
| **B1** | `keyInfo === null` at F16 time was caused by `m.cross_signing.master` not being stored in 4S (not by cache timing, which §3.2 rules out) | **ASSUMED** — mechanism VERIFIED, occurrence not | **EW-R1 leg R1-0** |
| **B2** | The forced-wizard loop's success check (`!shouldForceVerification()`) can return true while `m.cross_signing.master` is unstored | **ASSUMED** — follows from reading both predicates; the gate checks `m.secret_storage.default_key`, the button checks `m.cross_signing.master` | R1-0 + R1-2 |
| **B3** | On a new device of an existing 4S user, Element routes to `COMPLETE_SECURITY` (`SetupEncryptionBody`) rather than the patch's `E2E_SETUP` path | **ASSUMED** — `crossSigningReady` is false on a new device, which selects `COMPLETE_SECURITY` | R1-2 reaching `.mx_CompleteSecurityBody` |
| **B4** | Deleting the bootstrap device via MSC4191 `org.matrix.device_delete` leaves **no** device satisfying `signedByOwner`, so `hasDevicesToVerifyAgainst` is false in R1-2 | **ASSUMED** | R1-2 reports the observed value |
| **B5** | `SetupEncryptionStore.hasDevicesToVerifyAgainst` counts the **current** device (no self-exclusion), so "Use another device" can render with no other device | **Source VERIFIED** (`SetupEncryptionStore.ts:104-119`); consequence **INFERRED** (prior audit A7) | R1-2/R1-3 report it |
| **B6** | Caddy's `encode` weakens ETags on compressed rendezvous responses, breaking `If-Match` | **ASSUMED** (prior audit A4 / H-V4) | **EW-Q1 leg Q1-a** |
| **B7** | Element Web writes `mx_access_token` to `localStorage` under OIDC | **ASSUMED** — the shared helper `element-login.mjs:62-68` reads it but only hard-fails on `user_id`/`device_id`. The spec falls back to a fresh OIDC token for the same DID | spec self-reports which path it used |
| **B8** | Synapse's MSC4108 rendezvous accepts `text/plain` bodies up to 4 KB with `ETag`/`If-Match` semantics | **REPO/SPEC-SOURCED** — the handler is Rust (`synapse_rust/rendezvous.pyi`) and unreadable from the overlay; `max_content_length = 4 KB` per the prior audit | Q1-a's own response codes |
| **B9** | The lab is representative of prod for Capability 1 | **VERIFIED for Element** (same 1.12.20, same `config.json`, patched build confirmed in the bundle) | — |
| **B10** | The lab is representative of `main` for Capability 2 | **REFUTED** (§2.3) — the running siwx image emits `response_modes_supported`; `main` does not | `grep` on `main` |

---

## 7. Remediation, split by owner

### 7.1 OUR CODE — `siwx-oidc` (this repo)

| P | Item | Detail |
|---|---|---|
| **P1** | Land `response_modes_supported: ["query","fragment"]` in `src/oidc.rs::provider_metadata_value` **and** honour `response_mode=fragment` delivery in `sign_in` — **together, never metadata-only** | It is live in the lab image but **absent from `main`** (§2.3). Any build from `main` regresses it. Blocks Element ≥ 1.12.24 login *and* silently disables QR device-link |
| **P3** | Add the rendezvous route to `e2e/real-stack/Caddyfile` and `Caddyfile.e2e`, or document that those harnesses structurally cannot exercise QR | Prior audit §4.1 sub-finding; today only the Element lab can ever run leg Q1-a/b |
| — | **No change needed to the RFC 8628 half.** | Rows 1–5 are correct and proven. Do **not** re-introduce an approval-time cross-signing pre-flight — it was a confirmed false positive (`src/device_auth.rs:853-859`) |

### 7.2 OUR VENDORED ELEMENT PATCH — `siwx-oidc-matrix-server/patches/element-web/`

| P | Item | Detail |
|---|---|---|
| **P0** | **Make the forced wizard's success condition match the button's gate.** Today hunk 2 accepts `!shouldForceVerification()`, which only proves a 4S **default key** exists. Add: `await cli.secretStorage.isStored("m.cross_signing.master")` must be non-null before `recoverySetUp = true` | This is the *direct* fix for R5/R6. Without it the wizard can report success while leaving every future gate with no recovery-key button (§3.3). **Gate this on EW-R1 leg R1-0 first** — if R1-0 is green the premise is refuted and this item drops |
| **P1** | Bound the `hasServer4S` failure path. `.catch(() => null)` fails toward enforcing, so one transient error on the account_data GET during restore re-creates the full F16 trap (context **C3**) | Add a short bounded retry before falling through to enforcement. Keep failing *toward* enforcement as the terminal behaviour — that part is correct |
| **P2** | Re-verify patch applicability on any Element bump | The patch targets `v1.12.20` `MatrixChat.tsx`; the audited proposal already notes it likely will not apply to 1.12.24, which is separately blocked by row 13 |
| — | The Retry/Sign-out escape hatch is correct and should be kept | It prevents stranding on the inert setup screen |

### 7.3 UPSTREAM — `element-hq/element-web` / `matrix-js-sdk`

| P | Item | Detail |
|---|---|---|
| **P1** | `SetupEncryptionBody` offers **no** recovery-key entry when `keyInfo` is null even though a 4S default key exists server-side. The user holds a recovery key Element will not let them use, and the only remaining exits are destructive | **Do not file until EW-R1 leg R1-0 has produced the evidence.** If R1-0 shows `m.cross_signing.master` genuinely unstored, the *upstream* bug is narrower: the gate should distinguish "no 4S at all" from "4S exists but this secret isn't in it" and say so, rather than silently withholding the button |
| **P2** | `SetupEncryptionStore.hasDevicesToVerifyAgainst` has no self-exclusion (`SetupEncryptionStore.ts:104-119`), so "Use another device" can render for a user with no other device — an exit that cannot complete | Prior audit A7 / B5 here |
| **P3** | matrix-rust-sdk / matrix-js-sdk swallow cross-signing bootstrap errors ([matrix-rust-sdk#1641](https://github.com/matrix-org/matrix-rust-sdk/issues/1641)) | Long-standing; keeps any OIDC-metadata regression silent |

### 7.4 OPS — `siwx-oidc-matrix-server` edge

| P | Item | Detail |
|---|---|---|
| **P1** | Implement the `encode off` that the rendezvous Caddy block **already claims in a comment** (`Caddyfile.local:89`, `Caddyfile.production:54-60`) | The comment/behaviour divergence is a defect regardless of whether H-V4 confirms. Run **EW-Q1 leg Q1-a** first to know which |

---

## 8. BOUNDARY CONDITIONS

**Invariants respected.** I1/I1a (no server-derivable key material) is untouched — nothing here
proposes the server obtaining 4S or cross-signing secrets; C7/C8 confirm the siwx-side re-auth
paths deliberately have no recovery-phrase entry. R5/R6 stay negative requirements: EW-R1 asserts
the phrase is **demanded** *and* **enterable**, never that it can be skipped.

**Exclusions.** No container lifecycle operations. No modification of
`/home/waldknoten-01/siwx-oidc` or of `e2e/element/helpers/*`. No fix applied to the vendored
patch (that repo is out of this worktree's scope; §7.2 is a routed recommendation). No Element
upgrade. No prod probe.

**Loop exit.** Each row of §3.4 and §4.1 is either VERIFIED, or has a named spec leg that would
settle it. The two rows that cannot be settled here at all — B8 (Rust handler unreadable) and
Element X on real hardware — are recorded as such.

**Top risk.** If §3.3's diagnosis is right and P0 (§7.2) is not done, the merged `b7e594f` fix
will read as "the P0 finding is closed" because the *reload* symptom disappears — while R5/R6,
the case the requirement actually protects, stays broken and is now harder to see.
