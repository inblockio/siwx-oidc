# The verify-gate trap: root cause SETTLED by measurement (2026-07-25)

**Status:** root cause proven with DOM + live-predicate evidence. **Fix specified but NOT
merged** — it cannot be validated in this session without rebuilding the shared lab image.

This supersedes both earlier explanations. Read this before touching
`patches/element-web/force-first-device-recovery.patch` again.

---

## 1. What was believed, and why both accounts were wrong

| | Account 1 (`9ec414d`, `b7e594f` — **merged**) | Account 2 (proposed P0 — **withdrawn**) |
|---|---|---|
| Claim | Cold local `account_data` cache makes the 4S readiness probe read false on restore | 4S exists but `m.cross_signing.master` was never encrypted into it |
| Fix shipped/proposed | Replace the 4S probe with a server fetch | Assert `isStored("m.cross_signing.master")` in the wizard's success condition |
| Verdict | **Right mechanism, incomplete: fixed only one of the two cold inputs** | **REFUTED** — `EW-R1-0` passes; the master *is* stored |

Account 2 died on a single measurement. `EW-R1-0` ("after the mandatory first-device wizard,
the cross-signing master IS stored in 4S") **passes**. Gating that P0 on measurement instead of
shipping it saved a third unvalidated patch built on a false premise.

## 2. What is actually happening (measured)

`e2e/element/ew-reload-state-probe.spec.mjs`, sampled at 5/15/30/60/120s after a reload.
**Identical at every sample — this is a stable terminal state, not a transient:**

```
phase = 1 (Intro)          .mx_CompleteSecurityBody present
heading  "Confirm your digital identity"
buttons  ["Use another device", "Can't confirm?", "Remove this device"]
inputs   0
crypto   crossSigningReady=true  secretStorageReady=true  keyId=present
```

The crypto is **fully hydrated and healthy** while the gate is still on screen. Evaluating the
patched predicate against that state:

```
!crossSigningReady || !(secretStorageReady || hasServer4S)
= !true || !(true || …)
= false          → the gate should NOT be showing
```

So the gate is rendering a decision taken **seconds earlier, against cold state**, and nothing
ever re-evaluates it.

Live-predicate check at gate time, same page:

```json
{ "isStored_master": ["34Qa0SYzjJdnQUABjdyiFQtQPqHV3RHB"],
  "defaultKeyId":    "34Qa0SYzjJdnQUABjdyiFQtQPqHV3RHB",
  "storePhase":      1,
  "storeKeyInfo":    null }
```

**The predicate returns a valid key; the store's cached `keyInfo` is `null`.** That is the whole
bug, stated in four lines of JSON.

## 3. Root cause

`SetupEncryptionStore` computes its state **once**, during early boot while crypto and
`account_data` are still cold, and **never recomputes**. Two inputs are false-then-true:

1. `isCrossSigningReady()` — false at t≈0, true by t≈5s. **`b7e594f` never addressed this one.**
   It fixed only the 4S half of the predicate, which is why the merged patch did not work.
2. `keyInfo` ← `isStored("m.cross_signing.master")` — null when sampled cold, valid afterwards.

**One bug, three symptoms:**

| Symptom | Where observed |
|---|---|
| Gate fires on reload despite a healthy, ready session | `EW-R1-1` (fails), probe |
| No "Use recovery key" button / no input, so **R5/R6 has no non-destructive exit** | probe: `storeKeyInfo: null` vs live non-null |
| Post-SAS `Phase.Busy` dead-end with zero buttons; one reload clears it | `EW-V1` assertion 8 |

The third is the same pathology in a different phase: state sampled at the wrong instant, never
re-derived.

## 4. R5/R6 impact — proven, not inferred

With no second device the exits are exactly:

- **"Use another device"** — unavailable by construction (that is the R5 premise).
- **"Can't confirm?"** → `ResetIdentityDialog` — **destructive**.
- **"Remove this device"** — sign out.

A user holding a valid recovery key is **never offered anywhere to type it**, even though the
master is in 4S and the key would work. R5/R6's "must be enterable" is **FALSE**, and the cause
is stale UI state rather than a missing capability.

## 5. The fix

Because the predicate is correct and only the cached state is stale, **recomputation after
hydration is sufficient. Do not change the predicate.**

**Fix A — ours, actionable now (`force-first-device-recovery.patch`).** Do not take the
force-verification decision until the client has hydrated. Today it is sampled during boot and
frozen. Deferring it until initial sync completes removes the false gate entirely, which is the
common trap.

**Fix B — upstream Element (`SetupEncryptionStore`).** Recompute `keyInfo` (and re-derive the
phase) when crypto/account_data hydrate, so that when the gate *legitimately* fires the
recovery-key exit is offered. Fix A alone leaves this latent for genuine new devices.

**Explicitly rejected:** asserting `isStored("m.cross_signing.master")` in the wizard's success
condition (Account 2's P0). `EW-R1-0` shows the master is already stored, so this would gate on
a condition that is already true — no effect on the bug, and an unsatisfiable variant would loop
users through Retry/Sign-out.

## 6. Why the fix is not merged

Writing it is easy; validating it is not. There is no element-web checkout locally, the image
builds in CI, and the running lab image was built from `siwx-oidc-matrix-server` branch
`fix/finding2-restore-gate` by a **parallel session that is actively using it** — rebuilding
would restart their stack.

Merging an unvalidated Element patch is exactly what produced this situation: `9ec414d` was
falsified by its own `EW-L1b` run, `b7e594f` was merged with no post-fix run at all, and the
probe above shows the trap still open. A third blind patch is not the answer.

**Validation procedure (run before merging Fix A):**

1. Rebuild the Element image from the patched branch (`dockerfiles/Dockerfile.element`),
   coordinating with whoever owns the lab.
2. `bash e2e/element/run.sh ew-reload-state-probe` — expect `storeKeyInfo` **non-null** and
   `.mx_CompleteSecurityBody` **absent** after reload.
3. `bash e2e/element/run.sh ew-recovery-entry` — expect `EW-R1-1` and `EW-R1-2` to flip green.
4. `bash e2e/element/run.sh ew-verify-sas` — expect assertion 8 to flip green; if it does not,
   Fix B is required as well and that is the discriminator.

## 7. Standing caveat (A15)

The lab image emits `response_modes_supported`, which is **absent from `main` @ `d21329e`**. The
lab is not representative of main. Every conclusion here concerns Element-side state and is
unaffected by that delta, but any siwx-oidc-side conclusion drawn on this lab is not.

## 8. What survives from the merged commits

- `9ec414d` + `b7e594f` — **incomplete, not harmful.** They make the predicate strictly more
  accurate; they simply do not address the `isCrossSigningReady` cold read. Keep.
- `cb75cce` (never `forceReset` on a cold-cache probe) — **independently correct and
  unaffected.** Never take an irreversible branch on an indeterminate probe, regardless of which
  account explains the gate.
