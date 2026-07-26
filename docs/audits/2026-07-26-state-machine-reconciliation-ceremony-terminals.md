# State-machine reconciliation: the ceremony-view terminals were never named

**Date:** 2026-07-26
**Trigger:** EW-R1-2, the last open defect, turned out to be a harness gap. Reconciling that
result against the state-machine definitions explains *why it took a session to find*, and
names the gap that made a success indistinguishable from a trap.

---

## 1. What was measured

Instrumented run of `EW-R1-2` (new device, no other verified session), 10 samples from ~3s to
~30s after the recovery phrase is accepted. **Identical at every sample:**

```
phase = 3 (Done)          .mx_CompleteSecurityBody present, .mx_MatrixChat absent
heading  "Device verified"
buttons  ["Done"]
crypto   crossSigningReady=true  secretStorageReady=true  keyId=present
keyInfo  {algorithm: m.secret_storage.v1.aes-hmac-sha2, iv…, mac…}
```

Both candidate causes are refuted. The phase is **not** stuck at `Busy`; the crypto is **not**
cold. The ceremony succeeded, the cryptographic identity was genuinely restored, and Element
terminated on a **confirmation screen awaiting user acknowledgement**. The app shell cannot
render until "Done" is clicked, and the test never clicked it.

| Suite | Before | After |
|---|---|---|
| `EW-R1-2` | FAIL (3.6m timeout) | **PASS (12.2s)** |
| `ew-recovery-entry` (all 4) | 3 pass / 1 fail | **4 passed (29.4s)** |
| `ew-verify-sas` (incl. assertion 8) | assertion 8 RED | **1 passed (22.0s)** |

`EW-V1` assertion 8 going green is the independent result: it was the only watcher on the
post-SAS dead end, it failed on three consecutive runs, and it passes on an image containing
Fix B. That is Fix B **validated** by the standing rule — a diagnosis is not a fix until a test
that failed now passes.

## 2. Requirement status

| | Requirement | Status |
|---|---|---|
| R4 | Add a device, verify from a live one | **PROVEN** (`EW-V1`, incl. the view transition) |
| R5/R6 | Recovery phrase required **and** enterable | **SATISFIED** — demanded, enterable, accepted, identity restored, user reaches the app |

## 3. The gap: the map stops at the server boundary

`2026-07-25-session-onboarding-state-machine-map.md` §M4 ("Cross-signing + Secure Backup — THE
machine with undefined states") enumerates:

- **public** (Synapse): `XS_Absent`, `XS_Present`, `XS_ResetArmed`, `XS_ResetArmedIneffective`,
  `XS_UploadRejected`, `T_XS_OK`, `T_XS_HalfReset`, `T_XS_HonestFail`
- **private / 4S**: `S4_Absent`, `S4_Present`, `S4_Rotated`, `Backup_Vn`, `Backup_Deleted`

Its transition table has the row:

> `XS_Present` | unlock with recovery key | **stay `XS_Present`, secrets local** | wrong key → client-local fail

That is where the model ends. "Secrets local" is a correct statement about *crypto* and says
nothing about what the **user sees or must do next** — and R5/R6 are requirements about exactly
that. The Element client runs its own state machine (`SetupEncryptionStore.Phase`) whose
terminals decide whether the user reaches the app, and **no state in the map corresponds to any
of them**.

This is not an outside-scope omission. The map's own §0 completeness criteria say so:

1. *"each state is observable (Redis key, Synapse row, **client UI**, or log field)"* — client UI
   is explicitly in scope.
3. *"**Terminals only** — every path ends in a named terminal: `OK_*` / `FAIL_*` / `RECOVER_*`
   (**user can act**)"*.

By its own definition, M4 is incomplete precisely at the boundary where the product goals live.

## 4. Why the omission was expensive

The two client terminals present **identically** at the level the tests asserted at — "the app
shell never renders" — while being opposite in kind:

| | `EW-R1-2` | `EW-V1` assertion 8 |
|---|---|---|
| Phase | `3 (Done)` | `2 (Busy)` |
| Screen | "Device verified" | "Verify this device" |
| Buttons | `["Done"]` | **zero** |
| Crypto | healthy | healthy |
| Kind | **valid** OK terminal, user can act | **invalid** — user cannot act; only escape is reload |
| Correct response | click it (harness gap) | fix the transition (Fix B) |

Because neither was named, a **succeeding** flow and a **wedged** flow were the same observation.
That is what produced the conflation in the SETTLED doc ("EW-R1-2 and EW-V1 assertion 8 are the
same bug") — refuted here — and what made two earlier guesses look plausible. The discriminator
that finally settled it (`phase` + **button count**) is exactly the state label the map lacked.

## 5. Proposed addition — M4c, ceremony view (client)

Naming these makes the invariant mechanically checkable instead of a judgement call.

| State | Meaning | Observable | Kind |
|---|---|---|---|
| `C_Gate` | identity-confirmation gate on screen | `phase=1 (Intro)`, `.mx_CompleteSecurityBody` | transient |
| `C_Working` | ceremony in flight | `phase=2 (Busy)` **with** ≥1 button | transient |
| `T_C_OkAwaitAck` | ceremony succeeded, awaiting acknowledgement | `phase=3 (Done)`, "Device verified", buttons `["Done"]` | **OK terminal** |
| `T_C_App` | user acknowledged, app shell rendered | `.mx_MatrixChat` | **OK terminal** |
| `T_C_Wedged` | success with no way forward | `phase=2 (Busy)` stable **with zero buttons**, crypto healthy | **VIOLATION of §0 crit. 3** |
| `T_C_ResetOffered` | destructive branch offered | `phase=6 (ConfirmReset)` | terminal, destructive |

**The invariant worth enforcing:** no terminal may have zero user-actionable controls while the
underlying crypto is healthy. `T_C_Wedged` is the name for violating it; Fix B removes the two
known ways to reach it; `EW-V1` assertion 8 and `EW-R1-2` are its watchers.

**Product-goal translation.** R5/R6 is precisely: *for a user holding only a recovery phrase and
no other session, a non-destructive path must exist from `C_Gate` to `T_C_App`.* Measured, it
now does. The UX goals are the user-visible projection of these terminals — which is why the
terminals have to be in the model for the goals to be checkable.

## 6. Actions

- [ ] Add §M4c to the state-machine map; update the transition row for "unlock with recovery
      key" to continue into `T_C_OkAwaitAck → T_C_App` instead of ending at "secrets local".
- [ ] Add the M4c rows to the 72-state coverage matrix with their watchers.
- [ ] Keep `EW-V1` assertion 8 and `EW-R1-2` — they are the only watchers on `T_C_Wedged`.
- [ ] Open: whether `cd17c90`'s `usePassphrase` else-branch ever fires. Both Fix B halves are
      confirmed **present in the running bundle** (grepped the built asset; an earlier reading
      from image timestamps was wrong), but the first sample at 3s already showed `Done`, so the
      `if` branch may have succeeded outright and the poll may be unexercised.
