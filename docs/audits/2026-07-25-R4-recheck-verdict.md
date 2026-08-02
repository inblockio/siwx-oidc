# R4 adversarial re-check — ADOPT / DISREGARD verdict

**Date:** 2026-07-25
**Branch:** `phase2/session-onboarding-lab`
**Method:** `/logic-model` (CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY CONDITIONS)
**Scope:** re-check of a single requirement, **R4**. Evaluation only. No source, config, plan, or
prior audit document was modified; this file is the only artifact written. No container was
started, stopped, or restarted. All live evidence is idempotent read-only `GET`.
**Subject under test:** `docs/audits/2026-07-25-verify-with-other-device-gap-evaluation.md`
(hereafter "the prior audit"). Its conclusions were tested, not trusted.

> **Labelling contract:** **VERIFIED** = file:line, upstream source at a pinned tag, or a live
> read-only probe reproduced here. **INFERRED** = follows from VERIFIED facts by a stated
> argument, not itself observed. **ASSUMED** = a link I did not test; every one appears in §6.

---

## 0. Verdict up front

> ### **ADOPT-MODIFIED**
> **Adopt R4 narrowed to the SAS/emoji half, reclassified from a *build* task to a *proof* task
> (T11 / AC4). Defer the QR half. De-prioritise the whole of R4 below landing the already-written
> vendored-patch fix `9ec414d`.**

Three findings drive this, and each **materially changes** the prior audit's picture:

* **F1 — R4's emoji half is capability-complete today, and the prior audit missed the entry point
  that proves it.** Element Web 1.12.20 has a **second, independent** SAS trigger — Settings →
  Sessions → *(unverified session)* → **"Verify session"** — gated **only** on
  `isCurrentDeviceVerified && userId` (`useOwnDevices.ts:184-191`). It is **not** gated on
  `isCrossSigningReady`, **not** on 4S, **not** on `exportSecretsBundle`, **not** on MSC4108, and
  **not** on any OIDC metadata. It does not touch `SetupEncryptionStore` at all. Every blocker the
  prior audit put against R4 (its C5, C6) applies to the **QR half only**. **R4-via-SAS lacks
  proof, not capability** — a completely different verdict from "R4 is unreachable".

* **F2 — the reload verify-gate that the prior audit made load-bearing for R4 is OUR OWN BUG, and
  the fix is already written.** The proposal's own status table
  (`…AUDITED-PROPOSAL.md:456`, FINDING 2) records it root-caused on 2026-07-25: the gate **does not
  reproduce on any vanilla Element**; it is introduced by
  `siwx-oidc-matrix-server/patches/element-web/force-first-device-recovery.patch`. A fix
  (`9ec414d`, adds a server-side `hasServer4S` term) is **committed on branch
  `fix/finding2-restore-gate` but is NOT on `main` and is NOT deployed**. This **falsifies the
  premise handed to this re-check** that R4 is "one of only two non-destructive exits" from that
  gate: the gate is self-inflicted and removable for less work than R4.

* **F3 — `response_modes_supported` is genuinely absent, is genuinely latent (not present-tense),
  and the prior audit *understated* it.** It is a **two-part** fix, not one field; advertising the
  field alone makes Element ≥ 1.12.24 strictly worse. The prior audit's assumption **A5 is now
  independently VERIFIED** from matrix-js-sdk v42.0.0 source.

**Net:** the prior audit's *direction* (a real gap exists; the suspected cause — missing
rendezvous — is refuted) survives. Its *R4 conclusion* — "R4 does not currently hold… fails on C5
whenever the desktop has been reloaded" — is **REFUTED for the SAS half** and **sustained for the
QR half**. R4 is roughly 90% proof-debt and 10% engineering.

---

## 1. CONTEXT

| Component | State | Evidence |
|---|---|---|
| Element Web | **v1.12.20**, source-built from upstream tag, one vendored patch | `siwx-oidc-matrix-server/dockerfiles/Dockerfile.element:17` `ARG ELEMENT_WEB_TAG=v1.12.20`; live `GET https://element.inblock.io/version` → `1.12.20` |
| matrix-js-sdk | **41.6.0**, exact pin (not a range) | element-web `apps/web/package.json:84` @ tag v1.12.20 |
| Element config (prod, live) | `force_verification: true`, `sso_redirect_options: {immediate: true}`, no QR-related labs flag | live `GET https://element.inblock.io/config.json` |
| Synapse | MSC3861 delegated auth; `msc4108_enabled`; advertises spec ≤ `v1.12` | live `GET /_matrix/client/versions`; image overlay read-only |
| Vendored patch | `force-first-device-recovery.patch`; **main** has the buggy restore gate, **`fix/finding2-restore-gate`** has the fix | `git show main:patches/…` vs working tree; `git log` |
| siwx-oidc | CAIP-122 → OIDC bridge; owns the RFC 8628 half of QR only | `src/oidc.rs`, `src/device_auth.rs` |

**R4 as written** (`docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md:102`):

> *"User adds a phone, desktop still signed in." Today: recovery phrase. Required: QR / emoji
> verify from the desktop, **no phrase typed**.*

Backed by `H-D8` (line 153), workstream W3 (T10–T12, lines 253–269), acceptance criterion `AC4`
(line 301). Note R4 is a **disjunction** — "QR **/** emoji". The prior audit evaluated the
conjunction of everything both halves need and concluded failure; that is the central methodological
error corrected here.

---

## 2. GOAL

> Determine whether R4 is achievable **today** — separately for its emoji/SAS half and its QR half —
> attribute each residual blocker to an owner, and return ADOPT / DISREGARD / ADOPT-MODIFIED.

**Acceptance criterion:** a per-half reachability verdict where every causal link is either
VERIFIED (file:line / pinned upstream source / live probe) or explicitly registered as
ASSUMED, plus an attribution table and a statement of the user-visible behaviour R4 buys.

**Out of scope:** implementing anything; Element X mobile on real hardware; H-V4 (the Caddy
ETag/compression hypothesis) — inherited as OPEN from the prior audit, QR-only, not re-litigated.

---

## 3. INPUTS

| Class | Item | Consumed by |
|---|---|---|
| siwx-oidc code | `src/oidc.rs:201-266` (`metadata`), `:277-308` (`provider_metadata_value`) | W2 |
| Crate source | `openidconnect-4.0.1/src/discovery/mod.rs:55-90`, `:191`, `:233` | W2 |
| Synapse (image overlay, RO) | `rest/__init__.py:114`, `rest/client/sendtodevice.py:84-85`, `rest/client/keys.py:671-679`, `rest/client/sync.py` | W1 |
| Element Web v1.12.20 (upstream tag) | `LoginWithQRSection.tsx`, `SessionManagerTab.tsx`, `useOwnDevices.ts`, `SetupEncryptionStore.ts`, `SetupEncryptionBody.tsx`, `DeviceVerificationStatusCard.tsx`, `MatrixClientPeg.ts` | W3 |
| matrix-js-sdk 41.6.0 / 42.0.0 | `rust-crypto/rust-crypto.ts`, `crypto-api/index.ts`, `rendezvous/index.ts`, `oidc/validate.ts` (41) / `oauth/discover.ts` (42) | W2, W3 |
| matrix-server repo | `patches/element-web/force-first-device-recovery.patch` (+ git history), `dockerfiles/Dockerfile.element` | W4 |
| Repo docs | `…AUDITED-PROPOSAL.md:456` (FINDING 2, FINDING 3); `docs/audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md` | W2, W4 |
| Tests | `src/`, `tests/`, `e2e/` (full grep); `e2e/element/ew-login.spec.mjs:135-137` | W5 |
| Live (RO GET) | `siwx-oidc.inblock.io`, `matrix.inblock.io`, `element.inblock.io` | W1, W2 |

---

## 4. ACTIVITIES → OUTPUTS (evidence)

### 4.1 W1 — Does the SAS transport exist under MSC3861? **YES, unconditionally**

**H-R1:** *IF Synapse withholds to-device or key-signature endpoints under MSC3861, THEN SAS is
impossible regardless of client support.* — Antecedent **FALSE**.

| Surface | MSC3861 gating | Evidence |
|---|---|---|
| `sendtodevice.register_servlets` in the unconditional servlet group | none | `rest/__init__.py:114` (flat list, no conditional) |
| `SendToDeviceRestServlet` registration | none | `rest/client/sendtodevice.py:84-85` — `register_servlets` body is one unconditional line |
| `/keys/query`, `/keys/upload`, `/keys/signatures/upload`, `/keys/device_signing/upload` | none | `rest/client/keys.py:671-679` — all six servlets registered unconditionally; the only `msc3861` references in the file are at `:572,576`, and they **relax UIA**, never remove a servlet |
| `/sync` (carries `to_device`) | none | `grep msc3861\|delegat rest/client/sync.py` → **zero hits** |

**Live read-only probes, prod (`matrix.inblock.io`).** Discriminator: a registered POST-only
servlet answers **405 `M_UNRECOGNIZED`**; an unrouted path answers **404 `M_UNRECOGNIZED`**.

```
/_matrix/client/v3/sendToDevice/m.key.verification.request/txn1  → 405   (registered)
/_matrix/client/v3/keys/signatures/upload                        → 405   (registered)
/_matrix/client/v3/keys/query                                    → 405   (registered)
/_matrix/client/v3/sync                                          → 401 M_MISSING_TOKEN (reachable, authed)
/_matrix/client/unstable/org.matrix.definitely_not_a_thing/xyz   → 404   (control)
/_matrix/client/versions  unstable_features["org.matrix.msc4108"] = true ; io.element.msc4388 absent
```

Synapse's own errcodes come back, so the Caddy edge is not shadowing these paths.

> **FINDING W1 (VERIFIED): the entire SAS transport — to-device, key query, cross-signing
> *signature* upload, and sync delivery — is served unconditionally under MSC3861 in production.
> siwx-oidc is not in this path at all.** Independently reproduces the prior audit §4.3, and
> extends it: the prior audit did not probe `/keys/signatures/upload`, which is the endpoint the
> *verifier* uses to publish its signature of the new device — the one that actually makes the
> second device "verified".

### 4.2 W2 — `response_modes_supported`: absent, latent, and a two-part fix

**Absence — VERIFIED three independent ways:**

1. `src/oidc.rs:201-266` (`metadata`) never calls `.set_response_modes_supported(…)`.
2. `openidconnect-4.0.1/src/discovery/mod.rs:191` initialises `response_modes_supported: None`;
   the field is `Option<Vec<RM>>` (`:72`) and the only writer is the builder at `:233`. Absent ⇒
   omitted from the serialised document.
3. `src/oidc.rs:277-308` (`provider_metadata_value`) injects nine extension keys and **not** this one.
4. **Live prod** `GET https://siwx-oidc.inblock.io/.well-known/openid-configuration` → HTTP 200,
   24 keys, `response_modes_supported` **not among them**.

**Latency — VERIFIED, it is NOT a present-tense bug:**

| Element Web tag | matrix-js-sdk | validates `response_modes_supported`? |
|---|---|---|
| **v1.12.20 (deployed)** | **41.6.0** | **No** — `grep` over the whole 41.6.0 package (src + lib + maps) = **0 hits**. Validator is `src/oidc/validate.ts::validateAuthMetadata`; the field is not among its predicates |
| v1.12.21 / .22 / .23 | 41.7.0 / 41.8.0 / 41.9.0 | No (41.9.0 also 0 hits) |
| **v1.12.24** | **42.0.0** | **Yes — hard requirement** |

matrix-js-sdk **v42.0.0** `src/oauth/discover.ts::isValidAuthMetadata` (verbatim, relevant lines):

```ts
requiredArrayValue(authMetadata, "response_modes_supported", "query") &&
requiredArrayValue(authMetadata, "response_modes_supported", "fragment") &&
```

`requiredArrayValue` (`src/@types/type-guards.ts`) fails identically for a missing field and a
wrong one. Its single caller `MatrixClient.getAuthMetadata()` (`src/client.ts:8896-8908`)
`throw new Error(OAuth2Error.OpSupport)` on invalid. Upstream's own test
`spec/unit/oauth/discover.spec.ts` includes the `["response_modes_supported", ["code","missing fragment"]]`
→ falsy case.

**Field-by-field check of the live prod document against v42's validator:
`response_modes_supported` is the ONLY failing predicate.** Everything else passes, including
v42's *new* requirements (`registration_endpoint` promoted to required-string;
`grant_types_supported` must now contain `refresh_token` — prod has it).

**The prior audit UNDERSTATED this.** Its recommendation #4 is "add
`response_modes_supported: ["query","fragment"]`". Doing only that is **actively harmful**:

* v42 hardcodes `response_mode=fragment` in Element (`apps/web/src/utils/oauth/authorize.ts`
  @ v1.12.24: `const RESPONSE_MODE = "fragment";`) and reads `code`/`state` **only** from the
  fragment (`apps/web/src/vector/url_utils.ts` @ v1.12.24: `oauth2: { keys: ["code","state"],
  location: "fragment" }`).
* **The query fallback was deleted.** ≤ v1.12.23 had *both* `oidc_fragment` and `oidc_query`
  groups and negotiated from metadata
  (`responseMode: delegatedAuthConfig.response_modes_supported?.includes("fragment") ? "fragment" : "query"`).
  That negotiation is why omitting the field has been harmless — it silently selected `query`.
* siwx `sign_in` emits `?code=…&state=…` only. Advertising `fragment` without honouring it
  converts a clean validation failure into a bounce loop.

This is exactly what this repo already records at
`docs/audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md:34-45` and FINDING 3
(`…AUDITED-PROPOSAL.md:457`), with a deploy guard `scripts/check-auth-metadata.sh` WARNing until
fixed. **Prior audit assumption A5 → now independently VERIFIED** from v42 source (the prior
auditor could not fetch it; the repo is `matrix-org/matrix-js-sdk` — `element-hq/matrix-js-sdk` 404s).

**Relevance to R4:** QR half only, and only after an Element upgrade. On v42, validation throws →
`isSignInWithQRAvailable` swallows it (§4.3) → QR degrades to "not supported". But login itself
breaks first, so QR is moot. **Zero relevance to the SAS half.**

### 4.3 W3 — The Element gates: QR gate CONFIRMED, reload-durability claim PARTIALLY REFUTED

**The QR gate — VERIFIED verbatim** (`apps/web/src/components/views/settings/devices/LoginWithQRSection.tsx:26-30`, tag v1.12.20):

```ts
export async function shouldShowQrForLinkNewDevice(cli: MatrixClient, isCrossSigningReady: boolean): Promise<boolean> {
    const doesServerHaveSupport = await isSignInWithQRAvailable(cli);
    return doesServerHaveSupport && !!cli.getCrypto()?.exportSecretsBundle && isCrossSigningReady;
}
```

`isCrossSigningReady` **is** the third conjunct. Source: `SessionManagerTab.tsx:165-168`
`useAsyncMemo(async () => matrixClient.getCrypto()?.isCrossSigningReady() ?? false, [matrixClient])`,
passed at `:274`. False ⇒ button **rendered but `disabled`** plus the text
`settings|sessions|sign_in_with_qr_unsupported` = **"Not supported by your account provider"**
(`LoginWithQRSection.tsx:44-48`). Prior audit §4.2.3 — **CONFIRMED**.

**Three corrections the prior audit did not have:**

1. **The `exportSecretsBundle` conjunct is a no-op.** It is optional on the `CryptoApi` *interface*
   (`crypto-api/index.ts:718-720`) but an unconditional method on `RustCrypto`
   (`rust-crypto.ts:1512-1519`) with no feature flag. Element 1.12.x is rust-crypto-only, so it is
   always `true`. The gate reduces to `isSignInWithQRAvailable && isCrossSigningReady`.
2. **The disabled state flashes on every tab open.** `SessionManagerTab`'s `useAsyncMemo` is called
   with **no `initialValue`**, so it starts `undefined` and is coerced by `!!` at
   `LoginWithQRSection.tsx:35`. "Not supported by your account provider" is therefore transiently
   visible even in a perfectly healthy session. **Any screenshot-based or fast-assertion audit can
   misread this as a permanent failure.** Registered as a methodological caution.
3. **"`isCrossSigningReady` is false after reload" — PARTIALLY REFUTED.** Actual implementation,
   matrix-js-sdk 41.6.0 `src/rust-crypto/rust-crypto.ts:777-789`:

   ```ts
   public async isCrossSigningReady(): Promise<boolean> {
       const { privateKeysInSecretStorage, privateKeysCachedLocally } = await this.getCrossSigningStatus();
       const hasKeysInCache = Boolean(privateKeysCachedLocally.masterKey) &&
           Boolean(privateKeysCachedLocally.selfSigningKey) && Boolean(privateKeysCachedLocally.userSigningKey);
       const identity = await this.getOwnIdentity();
       return !!identity?.isVerified() && (hasKeysInCache || privateKeysInSecretStorage);
   }
   ```

   The local cache is the **rust IndexedDB crypto store, which survives an ordinary page reload
   (F5)**; and `privateKeysInSecretStorage` is a **server-side** check
   (`secretStorageContainsCrossSigningKeys`), true whenever working 4S exists. So false-after-reload
   is **not** a generic property of reload — it requires the crypto store to *also* be lost (fresh
   login / new `device_id` / cleared site data / private window) **and** no usable 4S. The prior
   audit's G2 is real but **narrower than stated**.

### 4.4 W3 (cont.) — **THE DECIDING QUESTION: is R4 reachable via SAS today?**

**H-R2:** *IF Element Web offers a SAS trigger that is not gated on `isCrossSigningReady`, 4S,
`exportSecretsBundle`, MSC4108, or OIDC metadata, THEN R4's emoji half is reachable today and
every blocker the prior audit named applies to the QR half only.* — Antecedent **TRUE**.

**SAS is configured.** `apps/web/src/MatrixClientPeg.ts:434-438`:

```ts
verificationMethods: [VerificationMethod.Sas, VerificationMethod.ShowQrCode, VerificationMethod.Reciprocate],
```

`VerificationRequestDialog.tsx:120-128` switches on `request.chosenMethod` and handles
`VerificationMethod.Sas` → `verification_dialog_title_compare_emojis`. **`m.sas.v1` emoji between
two same-user sessions is available.**

**Entry point E1 — from the NEW device** (this is the one the prior audit examined).
`SetupEncryptionBody.tsx` `Phase.Intro` → "Use another device" (gated `store.hasDevicesToVerifyAgainst`)
→ `onVerifyClick` (`:100-118`) → `cli.getCrypto()!.requestOwnUserVerification()` → `VerificationRequestDialog`.

**Entry point E2 — from the HEALTHY DESKTOP. This is the finding that changes the verdict, and the
prior audit does not mention it.** Full chain at tag v1.12.20:

| Step | File:line | What |
|---|---|---|
| 1 | `SessionManagerTab.tsx:204-221` | `onTriggerDeviceVerification(deviceId)` → `requestDeviceVerification(deviceId)` → `Modal.createDialog(VerificationRequestDialog, …)` |
| 2 | `SessionManagerTab.tsx:318-320` | passed down as `onRequestDeviceVerification` |
| 3 | `FilteredDeviceList.tsx:227` → `DeviceDetails.tsx:125` | forwarded as `onVerifyDevice` |
| 4 | `DeviceVerificationStatusCard.tsx:84-91` | renders **"Verify session"** when `device.isVerified === false && !!onVerifyDevice` |

**The gate** — `apps/web/src/components/views/settings/devices/useOwnDevices.ts:184-191`:

```ts
const isCurrentDeviceVerified = !!devices[currentDeviceId]?.isVerified;

const requestDeviceVerification =
    isCurrentDeviceVerified && userId
        ? async (deviceId) => await matrixClient.getCrypto()!.requestDeviceVerification(userId, deviceId)
        : undefined;
```

> **FINDING W3 (VERIFIED): E2 is gated ONLY on (a) the current device being verified and (b) a
> userId. NOT on `isCrossSigningReady()`. NOT on 4S / `keyInfo`. NOT on `exportSecretsBundle`.
> NOT on `doesServerSupportUnstableFeature("org.matrix.msc4108")`. NOT on the device-code grant.
> NOT on any OP metadata field. It never touches `SetupEncryptionStore`.**
>
> **Every blocker in the prior audit's R4 conjunction — its C2 (rendezvous), C3 (device-code
> grant), C5 (`isCrossSigningReady`), C6 (rendezvous payload), and the whole of G3
> (`response_modes_supported`) and H-V4 (Caddy ETags) — is inert on this path.**

**Does the vendored patch then demand a phrase (prior audit's A1, "the single most load-bearing
unknown for R4")? — RESOLVED at code level: NO.**
Working-tree patch, `shouldForceVerification`:

```
return !crossSigningReady || !(secretStorageReady || hasServer4S);
```

with `hasServer4S = await client.secretStorage.hasKey().catch(() => false)` (server-side default
key in account_data). After a successful SAS on device B: `crossSigningReady` is true
(`identity.isVerified()` now holds; `privateKeysInSecretStorage` is server-side true, and gossiped
keys populate the local cache), and `hasServer4S` is true. ⇒ `shouldForceVerification()` is
**false** ⇒ `onCompleteSecurityE2eSetupFinished` falls straight through to `onShowPostLoginScreen()`
without entering the `accessSecretStorage` loop. **No phrase typed.** The patch's own comment states
this design intent verbatim: *"a restore — or a new device of an existing user whose 4S lives
server-side — is never gated here."*

**Caveat, and it is the reason this is a proof task and not a closed one:** the *deployed* patch is
`main`'s, which lacks `hasServer4S` (§4.5). On `main`'s version the post-SAS predicate is
`!crossSigningReady || !secretStorageReady`, and `secretStorageReady` is the term subject to the
account_data hydration race. **INFERRED:** post-SAS this is likely benign (account_data is long
hydrated by then, unlike at restore), but it is not observed. See A1'.

**R4-via-SAS causal chain, end to end:**

| Link | Claim | Status |
|---|---|---|
| L1 | Synapse serves to-device + `/keys/signatures/upload` + sync under MSC3861 | **VERIFIED** (§4.1, source + live) |
| L2 | Element configures `VerificationMethod.Sas` | **VERIFIED** (`MatrixClientPeg.ts:434-438`) |
| L3 | Two SAS entry points exist; E2 is ungated by anything R4-blocking | **VERIFIED** (§4.4) |
| L4 | Both sessions exist as distinct Synapse devices | **VERIFIED** — siwx `provision_synapse_device_additive`, never delete-then-reuse (CLAUDE.md contract); EW-D1 proves distinct `device_id` end-to-end |
| L5 | Post-SAS the patched gate does not demand a phrase | **VERIFIED on the fixed patch; INFERRED on `main`'s deployed patch** (A1') |
| L6 | Somebody has demonstrated L1–L5 at least once | **FALSE** (§4.6) |

### 4.5 W4 — The reload gate is ours, and the fix is written but unshipped

The prior audit made the reload gate load-bearing for R4 (its G2) and attributed the durability
defect to **Element Web**. That attribution is **wrong**, and this repo already knows it.

`…AUDITED-PROPOSAL.md:456` (FINDING 2, root-caused 2026-07-25, parallel-container matrix across
vanilla 1.12.20 **and** 1.12.24, with and without backup):

> *the gate does NOT reproduce on ANY vanilla Element — it is introduced by our vendored
> `force-first-device-recovery.patch`, whose extended `shouldForceVerification`
> (`!crossSigningReady || !secretStorageReady`) also runs on session RESTORE, where secret-storage
> readiness transiently reads false before account_data re-hydrates. "Upgrade fixes it" = FALSE;
> NO upstream report warranted. **Fix belongs in the vendored patch.***

**Shipping status — VERIFIED by git:**

| Ref | Patch predicate | Deployed? |
|---|---|---|
| `main` (`51923fa`) | `!crossSigningReady \|\| !secretStorageReady` | **Yes — this is what prod runs** |
| `fix/finding2-restore-gate` (`9ec414d`, "stop gating session restore on transient 4S readiness") | `!crossSigningReady \|\| !(secretStorageReady \|\| hasServer4S)` | **No** — branch only; `git branch --contains 9ec414d` lists that branch alone; Element image not rebuilt |

**INFERRED (strongly supported) — the "no recovery-key entry field" P0 is the SAME bug.**
`SetupEncryptionBody`'s "Use recovery key" button is gated on `store.keyInfo`
(`SetupEncryptionBody.tsx:183`), and `keyInfo = await cli.secretStorage.isStored("m.cross_signing.master")`
(`SetupEncryptionStore.ts:94`) — **also derived from account_data**. The single hydration race that
makes `secretStorageReady` false (firing the gate) makes `keyInfo` false (removing the recovery-key
exit) at the same instant. That explains the otherwise-contradictory observation in the plan that
4S had "fully succeeded and the backup still exists at gate time" yet no recovery-key path was
offered. One root cause, one fix.

**REFUTATION of a claim in the plan's framing.** The plan (line ~117) and this re-check's brief
state the gate's "only exits are 'Use another device' and destructive RESET". The reset button is
**unconditional**, not `keyInfo`-gated — `SetupEncryptionBody.tsx:217-219`:

```tsx
<Button kind="secondary" onClick={this.onCantConfirmClick}>{_t("encryption|verification|cant_confirm")}</Button>
```

and its string is **"Can't confirm?"**, not "Proceed with reset". So the user is never *dead-ended*;
they are offered a destructive-only choice. Minor, but the plan's wording overstates the trap.

**Also VERIFIED, prior audit A7 → now source-confirmed:** `SetupEncryptionStore.ts:104-119`
contains **no** `getDeviceId()` comparison — only `dehydrated` and missing-identity-key exclusions.
The code comment says "any *other* verified devices"; the code does not implement "other". So
"Use another device" can render for a single-device user and wait on a peer that will never answer.
Upstream Element's bug; no upstream issue found filed for it.

### 4.6 W5 — Proof: independently re-confirmed at **zero**

Case-insensitive grep across `src/`, `tests/`, `e2e/` (excluding `node_modules`, `test-results`) for
`m\.key\.verification | sendToDevice | to_device | secret\.send | requestOwnUserVerification |
startVerification | verificationRequest | emoji`:

```
=== COUNT === 0
```

**Independently reproduces the prior audit's G1.** The closest any spec gets is `EW-L1b`
(`e2e/element/ew-login.spec.mjs:135-137`), which asserts the buttons `/use another device/i` and
`/remove this device/i` are **visible** after reload and never clicks either. Notably it does *not*
assert that "Use recovery key" is absent — the plan's P0 wording is a human observation, not a
test assertion. No spec anywhere references "Verify session" or the session-list verification
affordance (E2), so **the one entry point that makes R4 reachable has never been touched by a test.**

---

## 5. Attribution table

| # | Blocker | Half affected | Owner | Present-tense? | Fix state |
|---|---|---|---|---|---|
| B1 | **No test proves R4 at any layer** | both | **siwx-oidc (this repo)** | **Yes** | Specified as T11 / AC4 / H-D8; not written |
| B2 | Reload verify-gate fires on session restore | neither directly — but it is what made the prior audit judge R4 unreachable | **siwx-oidc-matrix-server (our vendored patch)** — explicitly **not** upstream Element | **Yes, in prod** | **Fix committed** `9ec414d` on `fix/finding2-restore-gate`; not on `main`, not deployed |
| B3 | No recovery-key entry at that gate | neither | **same vendored patch** (INFERRED: same account_data race kills `keyInfo`) | **Yes, in prod** | Same fix as B2 |
| B4 | `response_modes_supported` absent **+** no `response_mode=fragment` delivery | QR (and login) | **siwx-oidc** | **No — latent.** js-sdk 41.6.0 (deployed) has 0 references | Documented (`…v42-oauth-compat-finding.md`); guard `scripts/check-auth-metadata.sh` WARNs; deploy pin "do not bump past 1.12.23" |
| B5 | `isCrossSigningReady` greys out "Show QR code" | QR only | **upstream Element — and it is CORRECT** | conditional | Not a defect: QR *transfers secrets*, so requiring the sender to hold them is right. Only the *label* is misleading |
| B6 | `hasDevicesToVerifyAgainst` counts the current device | neither (cosmetic) | **upstream Element** | Yes | No upstream issue filed |
| B7 | MSC4388 structurally unavailable (needs stable MAS) | QR, future | **upstream / architectural** | No | Out of our control |
| B8 | H-V4: Caddy compression may weaken rendezvous ETags | QR only | **matrix-server ops** | Unknown | Unproven; falsification test specified in prior audit §4.7 |

**The decisive attribution reading:** the two blockers that hurt a real user *today* are **B2/B3**,
both **ours**, both fixed by one unmerged commit — and **neither is R4**. Of R4's own residue, the
SAS half is **B1 alone** (pure proof debt, fully in our control, one test) and the QR half carries
B4 (ours, latent), B5 (upstream, correct-by-design), B7, B8.

---

## 6. Assumptions register

| ID | Assumption | Status | Test that settles it |
|---|---|---|---|
| **A1'** | On `main`'s *deployed* patch (no `hasServer4S`), a post-SAS device B has `secretStorageReady === true`, so no phrase is demanded. Supersedes the prior audit's A1, which is **resolved at code level on the fixed patch** (§4.4). | **INFERRED** — account_data is hydrated by the time SAS completes, unlike at restore | The T11 two-context Playwright leg, run against the **deployed** patch |
| **A2'** | `device.isVerified === false` is true for the new session B in the desktop's session list, so "Verify session" renders (E2's trigger condition). | **ASSUMED** — follows from B being freshly provisioned and uncross-signed, but not observed | T11: assert the `verification-status-button-{device_id}` testid is present |
| **A3'** | `isCurrentDeviceVerified` is true on the healthy desktop A, so `requestDeviceVerification` is defined (E2's gate). | **ASSUMED** — true for any cross-signed session; the same condition R4 already presumes ("desktop still signed in" and healthy) | T11: assert the button exists before clicking |
| **A4'** | SAS completes when the *verifier* holds the SSK private key. | **ASSUMED** — the normal case; the degraded case (verifier without SSK) is out of R4's scope | T11 happy path |
| **A5'** | Secret gossiping (`m.secret.send`) delivers message-history keys to B after SAS, so B is not merely cross-signed but actually usable. | **ASSUMED** — transport verified (§4.1), delivery not observed | T11: assert B can decrypt a pre-existing message |
| **A6'** | The built prod Element image corresponds to `main`'s patch (not a stale build carrying something else). | **ASSUMED** — `git show main:` is VERIFIED; image provenance is not | `docker image inspect` / rebuild-hash on the prod host |
| **A7'** | The `keyInfo` hydration race (B3) is the cause of the missing recovery-key button. | **INFERRED** — both terms derive from account_data and the race is root-caused for one of them | Land `9ec414d`, reload, assert "Use recovery key" renders |
| **A8'** | H-V4 (Caddy ETag weakening on rendezvous). | **ASSUMED**, inherited unchanged | Prior audit §4.7 falsification test |
| — | `response_modes_supported` hard requirement in js-sdk v42 (prior audit **A5**) | **PROMOTED: ASSUMED → VERIFIED** from `matrix-js-sdk@42.0.0/src/oauth/discover.ts` | — |
| — | Post-SAS the vendored patch does not demand a phrase (prior audit **A1**) | **PROMOTED: ASSUMED → VERIFIED at code level** on the fixed patch (§4.4) | — |
| — | `hasDevicesToVerifyAgainst` self-inclusion (prior audit **A7**) | **PROMOTED: INFERRED → source-VERIFIED** | — |

---

## 7. BOUNDARY CONDITIONS — R4's conjunction, re-scored per half

The prior audit scored one conjunction C1–C8 across both halves and failed R4. Split correctly:

| # | Condition | **SAS half** | **QR half** |
|---|---|---|---|
| C1 | Synapse serves to-device + key endpoints under MSC3861 | **TRUE** (§4.1) | TRUE |
| C2 | MSC4108 rendezvous enabled, advertised, edge-reachable | **N/A — not used** | TRUE (prior audit §4.1, live-reconfirmed `msc4108: true`) |
| C3 | OP advertises device-code grant + `verification_uri_complete` | **N/A — not used** | TRUE |
| C4 | Existing device's client offers the affordance | **TRUE — two entry points** (§4.4) | TRUE, but see C5 |
| C5 | Verifier is `isCrossSigningReady` at the moment of verifying | **N/A — E2 is not gated on it** (§4.4) | **NOT RELIABLY TRUE** (§4.3) |
| C6 | Rendezvous channel carries the payload end to end | **N/A** | **UNVERIFIED**; H-V4 open |
| C7 | New device does not then demand a recovery key | **VERIFIED on the fixed patch, INFERRED on the deployed one** (A1') | same |
| C8 | Demonstrated at least once | **FALSE** (§4.6) | **FALSE** |
| C9 | OP metadata survives client validation | **N/A** | TRUE on 41.6.0; **FALSE from js-sdk 42** (§4.2) |

> **SAS half: fails on C8 alone**, with C7 at INFERRED on the deployed build. That is proof debt.
> **QR half: fails on C5 conditionally, C6 unverified, C8 unconditionally, C9 on any upgrade.**
> That is engineering debt spread across three owners.
>
> **R4 as a disjunction ("QR **/** emoji") is therefore reachable today via its emoji arm.** The
> prior audit's blanket "R4 does not currently hold" is **correct only in the narrow sense that
> nothing has demonstrated it**, and **incorrect** in the sense its own C5/C6 reasoning implies
> (that the desktop cannot serve as verifier). It can — just not via QR.

---

## 8. VERDICT

### 8.1 Decision: **ADOPT-MODIFIED**

**Modification, stated precisely:**

1. **Adopt R4 narrowed to the SAS/emoji arm, reclassified from a build task to a PROOF task.**
   Deliverable is `T11` / `AC4` exactly as already specified in the durability plan (line 266,
   line 301): a two-context Playwright leg — login A → wizard → login B → **verify B from A via
   Settings → Sessions → "Verify session"** (entry point E2, *not* only the SetupEncryption
   "Use another device" path the plan implies) → assert B cross-signed, B can decrypt history,
   and **zero 4S prompts fired**. Resolves C7/C8 and assumptions A1'–A5' in one run.
2. **Defer the QR arm** from R4's acceptance criterion. Track it separately against B4/B5/B8. It
   costs nothing to defer: Element is pinned at 1.12.20 and the deploy guard already forbids
   bumping past 1.12.23.
3. **Sequence R4 *below* landing `9ec414d`.** The `fix/finding2-restore-gate` merge + Element image
   rebuild is a smaller change that fixes a bug users hit **today in production**, and it is a
   precondition for T11 producing an interpretable result — exactly the same "hard gate" logic the
   plan already applies to W3 (line 255).
4. **Amend R4's "Today: recovery phrase" cell.** It is not established that the phrase is required
   today; it is established that nobody has checked. The honest cell is *"Today: unproven —
   capability present via SAS, never demonstrated."*

### 8.2 Which user-visible product behaviour does R4 buy?

**Concretely:** a user whose desktop is signed in adds a phone. Instead of hunting for a
48-character recovery phrase they stored months ago, they compare seven emoji between the two
screens. The phone becomes E2EE-verified, receives the cross-signing private keys and message-history
keys by gossip, and can read existing conversations.

**Why that matters beyond convenience:** it is the **only** path that works for a user who still has
a live session but **cannot find their recovery key** — which, per the prod "verify session loop /
half-reset" forensics, is the population that has been driven into destructive identity resets.
Today that capability exists in the build and **no one on the team can honestly claim it, detect a
regression in it, or point to a run that exercised it.** FINDING 2 is the proof of that cost: the
team shipped a vendored patch that degraded an adjacent verification path and only discovered it
weeks later, in production, by accident.

### 8.3 Is it worth the work, given the attribution split?

**For the SAS arm: yes, decisively.** The residue is **B1 and nothing else** — one blocker, owned
entirely by this repo, discharged by one test. Roughly 90% of R4's user value is unlocked by
*proving what already works*. There is no cheaper high-confidence item in the plan.

**For the QR arm: no, not now.** Its blockers are split across upstream Element (B5 — and B5 is
*correct behaviour*, not a defect: a device that cannot access its own secrets genuinely must not
offer to transfer them), a latent metadata issue that only bites on an upgrade the deploy guard
already forbids (B4), an architectural dead end (B7), and an unproven infrastructure hypothesis
(B8). Spending R4's budget there buys a capability that cannot be exercised until an Element
upgrade that is itself blocked.

### 8.4 If R4 were disregarded, what is left for a reloaded single-device user?

**The question contains a false premise, and correcting it is this re-check's most actionable
output.** R4 requires a second live session **by definition** — it does nothing whatsoever for a
single-device user. R4 was never that user's exit, so disregarding R4 takes nothing from them.

What that user actually needs, in order:

1. **Land `9ec414d`** (merge `fix/finding2-restore-gate` → main, rebuild the Element image, deploy).
   The gate should never fire on session restore in the first place — it does not on any vanilla
   Element. This removes the trap rather than furnishing it with a better exit.
2. **Confirm the recovery-key exit returns** once the gate stops racing account_data (A7'). If
   `keyInfo` hydrates, "Use recovery key" renders and the non-destructive exit R5/R6 depend on is
   restored — which is the *actual* fix for "must remain, **and must be enterable**".
3. **Note that the trap is less absolute than documented:** the "Can't confirm?" reset button is
   unconditional (§4.5), so the user always has *an* action — it is simply a destructive one.

**Therefore the plan's stated dependency — "R4 and the verify-with-other-device evaluation are
load-bearing for R5/R6" — does not survive this re-check.** R5/R6's real dependency is B2/B3, a
merge that is already written. R4 and R5/R6 are adjacent, not coupled.

---

## 9. Invariants respected

- No source, config, plan, or prior-audit document modified; this file is the only artifact written.
- No container started, stopped, or restarted. All live evidence is idempotent read-only `GET`;
  no rendezvous session was created, on prod or in the lab.
- Synapse image overlay read only. Both git repositories left on their existing branches with
  working trees untouched (`git status` unchanged).
- Upstream source read at pinned tags/versions (element-web `v1.12.20`, matrix-js-sdk `41.6.0` /
  `42.0.0`); downloads confined to the session scratchpad and cleaned up.
