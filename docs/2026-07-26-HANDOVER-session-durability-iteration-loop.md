# HANDOVER — session durability & onboarding: the iteration loop

**Date:** 2026-07-26
**Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`), rebased on `main` @ `7b9cec0`
**Companion repo:** `siwx-oidc-matrix-server` `main` @ `cd17c90`
**Method:** `/logic-model` to plan → `/process-pipeline` to execute → **deploy to the real lab** → test → audit → remediate → repeat.

This document is the **method**, not just the state. The state is a snapshot; the loop is what
produced it and what should continue. Read §1 before resuming work — it is the part that would
have saved this session several hours.

---

## 1. What this session actually taught (read first)

Four findings this session were **wrong on first diagnosis**. Every one was caught the same way:
by a measurement that contradicted a story. The loop below exists to force that contradiction
early rather than after a patch ships.

### L1 — Measure, don't infer. An inference that fits the evidence is not evidence.

| Claim | How it was reached | Outcome |
|---|---|---|
| "A 2s Redis blip kills sessions" (R3) | Read the code, reasoned forward | **Refuted** — bb8 defaults absorb it |
| "4S exists but the master was never stored" | Inferred from a null `keyInfo` | **Refuted** by `EW-R1-0` in one run |
| "`isCrossSigningReady` is the cold input" | Measured it `true` at +5s, reasoned *backwards* | **Refuted** — the 4S probe never issued HTTP at all |
| "The verify gate traps single-device users" | Inferred from a 120s timeout | **Refuted** — harness bug (see L2) |

The one that held (`getAccountDataFromServer` short-circuits to the local store) was found by
**observing the absence of an HTTP request on the wire**. That is the standard. Before proposing
a predicate change, ask: *did I see this, or did I derive it?*

### L2 — Harness bugs present as product defects. Assume it twice before believing a trap.

Two of them this session, both indistinguishable from a real dead end:

1. `injectMockWallet` called twice on one page → `__ethSign has been already registered` → all
   four `EW-R1` tests failed identically.
2. Element under OIDC never persists `mx_access_token` (only the boolean `mx_has_access_token`;
   the token lives pickled in IndexedDB). So `tokenForUser()` always fell through to a headless
   login that **navigated the Element tab to the siwx origin** — the later `page.reload()`
   reloaded *siwx*, no Element locator could match, and the 120s timeout read exactly like
   "trapped with no app and no gate."

**Both were caught only because an independent probe disagreed with the spec.** That is the
detector. When a spec reports a dramatic user-facing failure, write the smallest possible probe
that reproduces the *same scenario by a different path* before writing it up.

### L3 — Never merge an unvalidated patch into this area.

`9ec414d` was falsified by its own `EW-L1b` run. `b7e594f` was merged with **no post-fix run at
all** and the trap was still open. Both were reasonable-looking and both were wrong. The rule
that broke the cycle: **a diagnosis is not a fix until a test that failed now passes.**

### L4 — Fail-open vs fail-closed is per-call-site, and the destructive branch never wins on uncertainty.

The same probe needs *opposite* fallbacks depending on what the answer triggers:

| Site | Indeterminate result should mean | Why |
|---|---|---|
| Restore gate | enforce the wizard | inconvenient, fully recoverable |
| `forceReset` | assume 4S EXISTS, unlock | the other branch destroys message history |
| Revocation recheck, **pre**-mint | retryable 503, destroy nothing | client still holds a usable token |
| Revocation recheck, **post**-mint | commit | the old token is already gone; rollback = unrecoverable sign-out |

Encoded as invariant **I8** and as `RevocationState` (`Revoked` / `Live` / `Indeterminate`), so
the policy lives in one place and cannot drift across the four call sites.

### L5 — Mechanical guards catch what review does not.

- A `const` assertion tying `TOMBSTONE_TTL_SECS` to `2 * ACCESS_TOKEN_TTL` **fired on its first
  compile**: the margin was exactly **zero** (600 == 600), not positive. A human had asserted the
  strict inequality held.
- `scripts/check-patch-hunks.py` caught a stale `@@` header twice, including once for its author.
- **Generate patches by diffing real source in a scratch repo, then `git apply --check`.** Hand-
  authoring diff hunks for a file you cannot compile is how silent corruption enters.

### L6 — Judge a test by what it asserts, not by its name.

`EW-D1` is pure HTTP/OIDC with no crypto. `EW-L1b` asserted two buttons `toBeVisible()` and never
clicked them. `EW-X2` accepted `completed|reset_unconfirmed`, so it could not discriminate. Name-
only coverage is **uncovered**, and the coverage matrix must say so.

### L7 — Do not delete a failing assertion to get green.

`EW-V1` assertion 8 was kept red for most of the session precisely because it was the **only**
watcher on the post-SAS dead end — and it later became the discriminator that proved Fix B worked.
Split into proof + sentinel if you need a green signal; never delete.

### L8 — Operational discipline

- **The lab may not be representative of `main`** (A15). Check what the running image was built
  from before drawing conclusions from it.
- Bring the lab up **only** as `docker-compose -f docker-compose.local.yml --env-file .env.local`.
  Omitting `--env-file` resolves `SIWEOIDC_SIGNING_KEY_PEM` to empty and panics siwx-oidc at
  startup. (Done once this session; recovered in one step.)
- Never `podman rm -f` fixed-name containers while another session may own them. Use a worktree
  and, if needed, a separate compose project.
- Memory governance is load-bearing: a denied subagent spawn means run inline, not retry.

---

## 2. The loop

```
        ┌────────────────────────────────────────────────────────────┐
        │                                                            │
        ▼                                                            │
  ① PLAN            /logic-model                                     │
     CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY          │
     Output: hypothesis register. Every row is falsifiable and        │
     carries THE COMMAND that decides it.                             │
        │                                                            │
        ▼                                                            │
  ② MEASURE  ← the gate this session was missing                     │
     Before writing any fix: run the cheapest probe that              │
     DISCRIMINATES the candidate causes. If two stories fit the       │
     evidence, you do not yet have a cause.                           │
        │                                                            │
        ▼                                                            │
  ③ EXECUTE         /process-pipeline                                │
     Worktree isolation. Subagents for parallel, disjoint files.      │
     One commit per finding, message states what was NOT verified.    │
        │                                                            │
        ▼                                                            │
  ④ DEPLOY to the REAL lab                                           │
     Build the image, restart, confirm healthy. A fix that has not    │
     run against real Synapse + real Element is a hypothesis.         │
        │                                                            │
        ▼                                                            │
  ⑤ TEST                                                             │
     Run the suite that was RED. Green here is the only thing that    │
     converts a diagnosis into a fix.                                 │
        │                                                            │
        ▼                                                            │
  ⑥ AUDIT                                                            │
     Hypothesis trace: every Confirmed cites a command actually run;  │
     every Violated has a root cause; every Untested is a flagged     │
     gap. Then acceptance criteria.                                   │
        │                                                            │
        └──────────── ⑦ REMEDIATE, and loop ────────────────────────┘

  Exit: every requirement Met with cited evidence, or explicitly
  accepted as a gap by the owner. AC5 (recovery phrase required AND
  enterable with no live session) cannot be waived.
```

**Step ② is the addition.** The original loop went plan → implement → test. Inserting an explicit
measurement gate between diagnosis and patch is what would have prevented Fix A, the withdrawn P0,
and two phantom defects.

---

## 3. State at handover

### Landed and validated — `siwx-oidc`, 11 commits

Build clean. **24 lib + 123 bin + 26 browser E2E green.**

| Commit | What |
|---|---|
| `dd34e3f` | `RevocationState` 3-state probe at 4 sites; pre-mint 503 vs post-mint commit; `introspect` pinned to never return `active:false` on a store error |
| `8d6ee86` `95703ac` `845184d` `b78c9af` | Amendment log A1–A15, 72-state coverage matrix, recovery/QR audit, the A14 open-P0 record |
| `f9b39f5` | **EW-V1** — SAS/emoji verification proven, zero recovery-phrase surfaces |
| `97c5927` `2684c87` `758532d` | Reload probe; both harness fixes; corrected root cause |
| `cee3747` | Root-cause doc (with its own §3 marked wrong and superseded) |
| `d0219b3` | **CI runs the browser E2E suite** |

### Landed — `siwx-oidc-matrix-server` main

`cb75cce` forceReset data-loss fix · `1259f0b` ops breadcrumb · `00e76f4` v4 raw authed GET ·
`6c23298` + `cd17c90` **Fix B** (bounded poll at both `Phase.Busy` race sites).

### Requirement status

| | Requirement | Status |
|---|---|---|
| R1 | Restart → nobody notices | Code landed; **restart-survival leg not yet run** |
| R2 | Refresh race survives | Grace on main, **not deployed** |
| R3 | Redis blip survives | **Narrowed and landed**; premise refuted, real defect fixed |
| R4 | Add a device, verify from a live one | **PROVEN** — EW-V1 green in 21.2s |
| R5/R6 | Phrase required **and enterable** | **PARTIAL** — see §4 |

---

## 4. The one open defect, and exactly how to close it

`EW-R1-2` — new device, no other verified session.

**Progressed:** the gate appears, "Use recovery key" is **visible**, and it **accepts the phrase**.
R5/R6's *enterable* half is satisfied.
**Still failing:** `.mx_MatrixChat` never renders afterwards.

**Do not guess the cause.** Two prior guesses in this exact area were wrong. Next action is a
single measurement:

1. Instrument the point immediately after the phrase is accepted in
   `e2e/element/ew-recovery-entry.spec.mjs` (EW-R1-2) — dump `mxSetupEncryptionStore.phase`,
   `isCrossSigningReady()`, `getCrossSigningKeyId()`, and visible buttons, sampled over ~30s.
   `ew-reload-state-probe.spec.mjs` already has a reusable `snapshot()` for this.
2. The result discriminates:
   - **phase stuck at 2 (Busy) with healthy crypto** → still a transition bug; Fix B's poll is not
     reaching this path (check whether `accessSecretStorage` resolved at all).
   - **crypto not ready** → the unlock genuinely fails; a different defect entirely.
3. Only then patch, then rebuild, then re-run `ew-recovery-entry`.

---

## 5. Also open

- **`e2e/element` has no CI enforcement.** `d0219b3` covers `e2e/browser` only; the Element suite
  needs a real Synapse + Element + Caddy, i.e. a cross-repo harness. C-0 is narrowed, not closed.
- **`H-D5` baseline is contradictory** — ~548/72h (map §1.4) vs ~7/4d back-solved from the same
  source. Needs a prod log read, which the plan gates on owner go-ahead. The hypothesis cannot be
  evaluated until reconciled.
- **`EW-V1` has a glare flake:** occasionally both contexts click "Start", producing
  `m.key.verification.cancel` ×2 and a cancelled ceremony. Not a product defect; the click
  orchestration needs a lock.
- **R1's restart-survival leg (T5)** was never run.
- **`response_modes_supported`** landed on main via Finding 3; it is an Element-upgrade gate, not
  a live bug (deployed js-sdk 41.6.0 has zero references).
- **Nothing deployed.** Decision 2 holds: prod release only after the final audit.

---

## 6. Commands

```bash
# Lab — ALWAYS with --env-file
cd ~/siwx-oidc-matrix-server
docker-compose -f docker-compose.local.yml --env-file .env.local build element-web
docker-compose -f docker-compose.local.yml --env-file .env.local up -d element-web

# Suites
cd ~/wt/siwx-durability
bash e2e/element/run.sh ew-verify-sas          # R4 proof
bash e2e/element/run.sh ew-recovery-entry      # R5/R6
bash e2e/element/run.sh ew-reload-state-probe  # diagnostic
bash e2e/browser/run.sh                        # 26 tests, ~13s
cargo test --lib && cargo test --bin siwx-oidc

# Guards
python3 scripts/check-patch-hunks.py           # in siwx-oidc-matrix-server
~/bin/resource-guard.sh verdict                # before any subagent fan-out
```

**Patch authoring:** clone the file from `element-hq/element-web` at the pinned tag into a scratch
git repo at its real path, edit, `git diff`, `git apply --check`. Never hand-author hunks.

---

## 7. Reading order for whoever picks this up

1. This document, §1.
2. `docs/audits/2026-07-25-verify-gate-root-cause-SETTLED.md` — including the UPDATE section that
   marks its own §3 wrong. The correction is the useful part.
3. `docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md` — amendment log
   A1–A15 supersedes the body wherever they disagree.
4. `docs/audits/2026-07-25-state-machine-coverage-matrix.md` — 72 states, with the orchestrator
   verification pass appended.
