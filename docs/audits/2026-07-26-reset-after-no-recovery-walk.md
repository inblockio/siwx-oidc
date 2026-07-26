# Reset-after-no-recovery: the reported prod failure, walked in the lab

**Date:** 2026-07-26
**Spec:** `e2e/element/ew-journey-reset-after-no-recovery.spec.mjs` (EW-R1)
**Run with:** `bash e2e/element/run.sh ew-journey-reset-after-no-recovery`
**Stack:** lab compose (`Element :28088`, `Synapse :28080`, `siwx-oidc :28081`), Element Web
v1.12.20 built from source with the vendored patches.

## The report

> "login, do not complete setting up your recovery key, log out, login (do NOT use the
> recovery key but reset the identity). This is expected to lead into the session without
> past messages (not decryptable) but with the option to now get new recovery keys.
> **On prod this leads to the user not being able to get into the session.**"

## Verdict

**The symptom does NOT reproduce in the lab.** The user reaches the app shell.

But the reason they reach it is **not** the reason the design intends. They get in because
the forced-recovery mandate is **silently defeated by a probe bug** after any identity
reset: `resetEncryption` leaves `m.secret_storage.default_key` present-but-**empty**
(`{}`), and the vendored gate checks only the HTTP status of that account-data event,
never its body. So the gate concludes "4S exists" for a user who has none.

The owner's expected outcome is therefore produced **by accident**. A user who takes this
path in the lab lands in the session with **no recovery key at all**, nothing blocks them,
and — separately measured — they are **not reliably offered** a way to get new recovery
keys (see the open finding below). So of the owner's two expectations, "gets into the
session" holds and "with the option to now get new recovery keys" does not hold
dependably.

## Screen-by-screen walk (measured, lab, 2026-07-26)

Every row below is a screen a real Chromium reached, recorded by `helpers/journey.mjs`
(`settle` polls before judging; a control counts only if visible, not `disabled`, and not
`aria-disabled`). Reproduced identically across four runs.

| # | Screen | Headings | Enabled controls |
|---|---|---|---|
| 1 | siwx login | `Sign in` | Sign in with Ethereum, Sign in with Passkey, Create one |
| 2 | post-signature | `Wallet verified` | Link a passkey, **Skip for now** |
| 3 | forced recovery wizard | `Setting up keys`, `Set up Secure Backup` | **Cancel**, Continue |
| 4 | cancel confirmation | `Setting up keys`, `Are you sure?` | **Cancel**, Go back |
| 5 | recovery-required dialog | `Setting up keys`, `Set up recovery to continue` | **Logout**, Retry, Close dialog |
| 6 | after Logout | `Welcome to inblock.io Chat` | Sign in, Create account |
| 7 | re-login landing → siwx | `Sign in` | (as row 1) |
| 8 | post-signature | `Wallet verified` | Link a passkey, **Skip for now** |
| **9** | **THE GATE** | `Confirm your digital identity` | Learn more, Use another device, **Can't confirm?**, Remove this device |
| 10 | reset confirmation | `Are you sure you want to reset your digital identity?` | **Continue**, Cancel |
| 11 | destination | **APP SHELL** + home-surface nag | (app chrome) |

Row 9 is the answer to the first question asked: **"Use recovery key" is ABSENT.** On this
path reset genuinely is the only forward exit. ("Remove this device" is
`action|sign_out` — a way out, not a way on.)

### Server-side state

Read over the CS API with a token minted independently of the browser session, so nothing
depends on what Element did or did not persist locally.

| | after cancel + logout | after reset |
|---|---|---|
| `m.secret_storage.default_key` | **404 `M_NOT_FOUND`** | **200 `{}`** |
| real 4S (content names a key) | no | **no** |
| cross-signing master key published | yes | yes |
| megolm backup version | `1` | **`2`** (old one deleted, new one created) |
| devices with published E2EE keys | 1 (the logged-out one) | 2 |

## Hypotheses

| | Claim | Result |
|---|---|---|
| **H1** | Re-login fires the forced gate (`!crossSigningReady \|\| !(secretStorageReady \|\| hasServer4S)`) | **CONFIRMED** — row 9 |
| **H2** | "Use recovery key" is absent at that gate, so reset is the only exit | **CONFIRMED** — row 9 |
| **H3** | After reset the forced-recovery loop re-fires and traps the user | **FALSIFIED** — row 11 |

H2's mechanism, for the record: `SetupEncryptionBody` renders that button only
`if (store.keyInfo)` (v1.12.20 `apps/web/src/components/structures/auth/SetupEncryptionBody.tsx:182-189`),
and `keyInfo` comes from `secretStorage.isStored("m.cross_signing.master")`
(`apps/web/src/stores/SetupEncryptionStore.ts:91-102`), which is null when no 4S ever
existed. This is **not** in tension with EW-J3, which saw the button present: that account
**had** 4S. Different precondition, different gate.

## Root cause of H3's falsification

Three code facts, each cited:

1. `resetEncryption` never creates new 4S. It deletes the old one and stops.
   matrix-js-sdk v41.6.0 `src/rust-crypto/rust-crypto.ts:1570-1592`: delete dehydrated
   device → `deleteAllKeyBackupVersions()` → `deleteSecretStorage()` →
   `bootstrapCrossSigning({setupNewCrossSigning:true})` → `resetKeyBackup()`. No
   `bootstrapSecretStorage`.

2. "Deleting" the default key **writes an empty object**. `deleteSecretStorage()` ends in
   `setDefaultKeyId(null)` (`rust-crypto.ts:1609`), and `setDefaultKeyId`
   (`src/secret-storage.ts:373-397`) does
   `const newValue = keyId === null ? {} : { key: keyId }` followed by
   `setAccountData("m.secret_storage.default_key", newValue)`. Its own comment says why:
   the spec "doesn't specify how to delete the default key; we do it by setting the
   account data to an empty object." Matrix has no account-data deletion. **A GET
   therefore returns HTTP 200 for a user with no recovery key.**

3. The vendored gate reads the status, not the body.
   `patches/element-web/force-first-device-recovery.patch` (MatrixChat.tsx, hunk 1):
   ```
   client.http.authedRequest("GET", "/user/.../account_data/m.secret_storage.default_key")
       .then(() => true)
       .catch(() => false)
   ```
   After reset that resolves → `hasServer4S = true` →
   `!crossSigningReady || !(secretStorageReady || hasServer4S)` = `false || !(false||true)`
   = **false**. `onCompleteSecurityE2eSetupFinished` skips its `while (!recoverySetUp)`
   loop entirely and calls `onShowPostLoginScreen()`.

Measured confirmation, from the spec's own log line:
`default_key=200:{} patchProbeSees4S=true has4S=false`. The divergence between what the
patch's probe concludes and what is true is reported explicitly on every run.

## Is the user offered new recovery keys afterwards? — OPEN FINDING: not reliably

**No, not dependably.** This is the weakest part of the outcome and it is worth stating
plainly, because it is the half of the owner's expectation the lab does **not** deliver.

Measured across six runs of the identical walk, polling the landing surface for up to
45 s for any of *back up your chats / set up recovery / set up secure backup / turn on
backup / recovery key*:

| run | landing nag | recovery offer surfaced |
|---|---|---|
| 2 | `Back up your chats` | yes |
| 3 | `Back up your chats` | yes |
| 4 | `You have unverified sessions` | no |
| 5 | `You have unverified sessions` | **no, after 46 s of polling** |
| 6 | `Back up your chats` | yes (within 2 ms) |
| 7 | `You have unverified sessions` | **no, after 46 s of polling** |

Element's home surface rotates its nags, so the recovery offer is a **coin flip, not a
guarantee** — 3 of 6 on an identical walk. When it loses, 45 s of polling finds nothing.
(The spec stays green on both sides of the flip, by design; runs 6 and 7 landed on
opposite sides and both passed.) Scope of the claim: this measures what is offered on the surface the user
lands on, without navigating. A recovery route still exists in Settings — nothing
proactively points them at it, and nothing tells them they currently have no recovery key.

The spec therefore **records this rather than asserting it** (`[FINDING] R1
recovery-offer-after-reset`). Asserting a race yields a flaky-red test, and flaky tests get
deleted, which would lose the finding; the deterministic facts around it are asserted.

Two related process notes, recorded because both were near-misses:

- The first version of this probe **sampled once** at landing and so passed and failed on
  identical product behaviour — the same single-sample defect `helpers/journey.mjs` exists
  to prevent. It now polls.
- The first version of the 4S probe checked only `status === 200` and reported
  `has4S: true` for the empty `{}` key — a check that could not fail, on exactly the state
  this walk exists to detect. Reading the body is what exposed the root cause below.

## Second finding (recorded, not the reported bug)

**"Use another device" at the gate points at a device that no longer has a session.**
Measured: after Logout the logged-out Element device still appears in `/keys/query` with
published E2EE keys, so it still satisfies `hasDevicesToVerifyAgainst`
(`SetupEncryptionStore.ts:104-119`) and the button is offered. *Inferred* (not measured
here): under OIDC-native logout Element revokes at the OP via `/oauth2/revoke`, which is
`TeardownPolicy::TokensOnly` in `src/compat.rs` and by design never deletes the Synapse
device. A user who takes that offer is waiting on a session that cannot answer.

## Lab vs production

The lab is **ahead** of prod, so "green here" is not "fine there". Measured delta:

- `https://element.inblock.io/i18n/en_EN.751084b.json` and the lab's are **byte-identical**
  (sha256 `3dab952d744a795e4a5e6f7fefbd4dda4b2ff586439196f5f7253a85d5752b40`).
- That file **contains** `"Set up recovery to continue"` → **prod carries the
  force-first-device-recovery patch**, including the status-only 4S probe above.
- It does **not** contain `"Verify your current session first."` → neither deployment
  carries the unpushed `offer-verify-current-session` patch.

*Inferred, not measured:* `siwx-oidc-matrix-server` is `ahead 2` of `origin/main`, and both
commits (`6c23298`, `cd17c90`) are the SetupEncryptionStore Busy-wedge fix. Neither touches
this path — the wedge lives in `usePassPhrase` (the "Use recovery key" unlock, a button
**absent** at this gate) and in `onVerificationRequestChange` (after a SAS, which does not
occur here). **So the known lab/prod delta does not explain the reported prod failure.**

### Leading hypothesis for prod — NOT measured

Prod deploys are manual (`CLAUDE.md`), so prod may run an Element image older than
`origin/main`. If prod predates commit `00e76f4` ("raw authed GET for both 4S probes"),
`shouldForceVerification` used `getAccountDataFromServer`, which short-circuits to the
**local** account-data cache. Then, after a reset:

- `hasServer4S` can read **false** (cold cache) → `shouldForceVerification` = **true** →
  the `while (!recoverySetUp)` loop fires; but
- inside the loop, `hasExisting4S` uses a raw GET with
  `.catch(e => e?.errcode !== "M_NOT_FOUND")`, and the emptied key returns **200** → **true**
  → `accessSecretStorage(..., { forceReset: false })` tries to **UNLOCK 4S that does not
  exist**. That cannot succeed, so `recoverySetUp` stays false and the user is returned to
  `Set up recovery to continue` [Retry / Logout] — **forever**.

That is exactly "not being able to get into the session", and it is built entirely from
the pushed source. The trap needs the two probes to **disagree**; since `00e76f4` both use
the same raw GET, so they agree and the trap cannot form — which is why the lab gets in.

**Next step to settle it:** determine which Element image prod actually runs, then walk
this same path against it. Do not treat the hypothesis as established until then.

## What would make EW-R1 go red

Stated explicitly, because a green test that asserts nothing is the failure mode this work
exists to avoid:

- any screen with no app shell and no enabled control (`assertExit`, 11 screens)
- preconditions evaporating: no Cancel in the wizard, no Logout in the recovery dialog, or
  4S already present after cancel+logout
- re-login landing in the app shell (H1 falsified)
- "Use recovery key" appearing at the gate (H2 pin)
- no "Can't confirm?" at the gate, or no "Continue" in the reset confirmation
- the post-reset driver returning `LOOP` (same screen 4 passes running),
  `NO_FORWARD_CONTROL`, or `MAX_STEPS` → **the reported prod symptom**
- the pinned `{has4S:false, patchProbeSees4S:true}` changing in either direction — this is
  the root-cause divergence itself, so it goes red whether the probe gets fixed or reset
  starts creating 4S

What will **not** turn it red, by deliberate choice: the recovery-offer measurement above.
It is a genuine 3-of-5 race in the product, so asserting it would be asserting a coin flip.
It is logged as `[FINDING]` on every run and carried in this document instead.

**Verified by mutation, not by assertion.** Replacing the single click on the reset
confirmation's `Continue` with `Cancel` produced a red run with driver outcome
`NO_FORWARD_CONTROL` and the message *"PROD SYMPTOM REPRODUCED — after resetting the
identity the user never reached the app shell"*. The terminal assertion is reached and
load-bearing on real data. Separately, the body-aware 4S probe flipped `has4S` from `true`
(status-only) to `false` (body-aware) on the same product state, which is what exposed the
root cause above.
