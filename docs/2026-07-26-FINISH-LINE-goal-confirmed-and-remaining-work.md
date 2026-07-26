# FINISH LINE — confirmed goal, and the bounded work that closes this marathon

**Date:** 2026-07-26 (third artifact of the day; supersedes the *planning* sections of
`2026-07-26-HANDOVER-state-machine-first-behavior-audit.md`, whose §1 governing idea, §5 commands
and §6 traps remain authoritative)
**Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`)
**Companion:** `siwx-oidc-matrix-server` `main` @ `cd17c90`
**Status of this document:** goal and scope **confirmed by the owner**; §4 is the execution contract.

---

## 1. The confirmed goal

> **Every terminal state a real user can reach in onboarding and session management is *named*,
> *honest*, *exit-bearing*, and *guarded by a test that runs without a human* — with the
> irreversible ones unreachable by default.**

"A complete state machine with no open states in the UX" is not directly falsifiable over a
72-state machine that spans a client we do not own. The four properties are, and each already has a
named breach class in the register:

| Property | Meaning | Breach is named | Invariant |
|---|---|---|---|
| **Named** | the state exists in the map, distinct from its neighbours | U10 (`T_C_Wedged` was indistinguishable from `T_C_OkAwaitAck`) | M4c's reason to exist |
| **Honest** | the UI never asserts an effect it has not confirmed | U1 (success banner, no-op grant), U5 (false "not supported by your provider") | **I4** |
| **Exit-bearing** | no terminal presents zero user-actionable controls while crypto is healthy | `T_C_Wedged` | **I-C1** |
| **Watched** | a test asserts it, and that test runs without a human | **all of it** | **C-0** |

**Definition of done (loop exit).** Every state in coverage-matrix §5 marked Uncovered is either
covered or explicitly accepted with a named terminal and a runbook. `U3′`, `U6` and `Q1` cannot be
waived. No terminal breaches I4 or I-C1. Guarding meets the §2.3 bar.

---

## 2. Scope, decided

### 2.1 Surface = both repos, bounded

siwx-oidc **plus** the vendored Element Web patches in `~/siwx-oidc-matrix-server`, patching Element
**only where a state is destructive or lying**. Everything else gets a named terminal plus a runbook
and is filed upstream. Rationale: the data-loss states (U3′, U4) and the lying states (U5) live in
the client, so a siwx-oidc-only scope would make "production-ready UX" untrue.

### 2.2 Release = hold everything until the final audit

Decision 2 stands. The recommendation to ship the recoverable-harm fixes early (refresh grace, reset
honesty, `RevocationState`) was **considered and declined by the owner.**

**Consequence, stated plainly so it is not lost:** the audit is now the critical path to relieving
live production harm. Prod runs `sha-db79e75` — the lying reset is reachable by every user today,
and every Redis blip still wipes a crypto store, which is the mechanism that feeds users into the
destructive gates. Holding the release does not hold risk constant; it accrues. Therefore **audit
scope must stay bounded** and §4 is deliberately finite. Anything not in §4 is out.

### 2.3 Guarding bar = pragmatic

- Promote the mock-stack-capable Rust `#[ignore]` tests into CI (matrix: "cheaper than any item above").
- Write the missing destructive-path lab tests.
- `e2e/element` becomes a **mandatory pre-deploy gate**, not per-commit.
- Full cross-repo Element CI (real Synapse + Element + Caddy) is **out of scope**. C-0 is therefore
  narrowed, not closed, and every "Covered" verdict outside CI keeps meaning *"a test genuinely
  asserts this"*, not *"this is guarded"*. That wording stays in the matrix.

---

## 3. The ordering document is stale — re-adjudicated 2026-07-26

Coverage-matrix **§8 (Prioritized Gap List)** was authored 2026-07-25 and is the document the
backlog was being drawn from. **Three of its five entries have since closed.** Using it as-is would
have spent the remaining marathon on already-solved problems.

| §8 | Gap | Status as written (07-25) | **Status now (07-26)** | Evidence |
|---|---|---|---|---|
| **#1** | U3′ — `forceReset` on a cold-cache probe | Critical, silent, irreversible | **CLOSED in code — UNWATCHED** | `cb75cce` + `00e76f4`: discriminator is a raw authed GET; fallback is `.catch(e => e?.errcode !== "M_NOT_FOUND")` → indeterminate resolves to *4S exists* → **unlock**. This is exactly the corollary invariant ("fail toward unlock, never reset"). **No test exists** — grep across `e2e/` hits only `node_modules` |
| **#2** | U6 — no recovery-key entry at the verify gate | Critical, stuck-with-no-exit | **CLOSED in code — validation run not recorded** | `patch(v4)` `00e76f4`; matrix §6.3 status correction. The EW-L1b run against a post-`00e76f4` image is still absent from both repos |
| **#3** | Q1 / `T_NewDeviceOK` never demonstrated; SAS zero coverage | High reach, missing evidence | **CLOSED — demonstrated and watched** | `EW-V1`: *"second session cross-signed by SAS/emoji from a live first session — no recovery phrase"*, three browser contexts (`ctxA`/`ctxB`/`ctxO`). This is precisely the two-context leg §8 asked for. Handover §2 already records R4 as PROVEN |
| **#4** | U9 — infra fault ⇒ hard logout | Very high reach, recoverable | **OPEN** — code-closed on branch (`dd34e3f`), unproven by e2e, undeployed | — |
| **#5** | U1 — prod runs the lying reset | Deployment gap | **OPEN** — deployment only; fix is on `main` | — |

**What this means for the marathon.** The remaining work is predominantly **guarding and
totality**, not correctness. Correctness has largely landed; it is simply unwitnessed and unshipped.
That is a much smaller finish than the gap list implied.

Genuinely-open correctness reduces to **U2, U4, U5, U7** (all client-side or alerting) plus the one
structural totality hole, **T-M4**.

---

## 4. The execution contract

Ordered by dependency, not by wish. Phase A unblocks the backlog; Phase B guards what already
landed; Phase C closes the four remaining open states; Phase D ends the marathon.

### Phase A — Reconcile and complete the map

| # | Work | Why it is first |
|---|---|---|
| **A1** | Fold §3's re-adjudication into coverage-matrix §8 as a dated addendum (do **not** rewrite §8 in place — it is pinned to `dd34e3f` and rewriting falsifies its provenance contract, the same reason M4c was appended as §5.9) | The backlog is drawn from §8; it is stale on 3/5 entries |
| **A2** | **Close T-M4: M4's private half.** `S4_*` and `Backup_*` are declared states with no transition table, no events, no terminals. Six of the sixteen uncovered states live here. Define transitions and terminals for the three named user-reachable events with no defined answer: `4S_key_rotated_while_master_stale`, `backup_deleted_with_XS_present`, `recovery_key_lost_with_no_second_device` | The map is not total; "complete state machine" is false until it is. U2 and U4 both live in this half and cannot be specified against an undefined machine |

### Phase B — Guard what already landed

| # | Work | Closes |
|---|---|---|
| **B1** | **`C_Working` watcher.** Assert the discriminator directly: healthy transient `Busy` (**≥1 button**) vs `T_C_Wedged` (**zero buttons**). Nothing states this, and invariant **I-C1 rests entirely on it** | matrix §5.9 `C_Working` Uncovered |
| **B2** | **U3′ regression.** Blip the 4S probe; assert **no new default key is minted** and the existing recovery key survives | §8 #1 unwatched |
| **B3** | **U6 validation.** Run EW-L1b against an image built from `00e76f4`; record the result in both repos | §8 #2 unrecorded |
| **B4** | **U9 / T4 fault injection.** Pause Redis → assert **5xx** (not 401) on `/oauth2/introspect`, `/token` refresh, `compat::refresh`; restore → the same refresh token still works. Must not weaken `dd34e3f`'s three regression guards (**I8**) | §8 #4 unproven |
| **B5** | Promote mock-stack-capable Rust `#[ignore]` tests into CI; add the `e2e/element` pre-deploy gate script | C-0 (narrowed) |

### Phase C — Close the four remaining open states

| # | Work | State |
|---|---|---|
| **C1** | Truthful disabled-reason for QR — replace "Not supported by your account provider" (false; the OP supports it) with the real cause plus a route to the fix | **U5** |
| **C2** | Offer an unverified current device *some* way to initiate verification. Correct-by-design that it cannot vouch for itself; the undefined part is that no alternative is offered | **U7** |
| **C3** | `T_XS_HalfReset`: constructor test, defined recovery transition, and the N×401 alert (plan P4, unwritten) | **U2** |
| **C4** | Prefer-unlock-over-reset product guard. `ResetIdentityDialog` currently offers the destructive branch *more readily* precisely when the user has least to fall back on | **U4** |

> **C1+C2 are the high-value pair.** U5+U6+U7 compose into *"reset is the only visible exit"* — and
> the reset is the destructive one. U6 is now closed, so C1+C2 break that composition.

### Phase D — Final audit and release

| # | Work |
|---|---|
| **D1** | The four-column audit pass across M0–M5 **plus M4c**: per terminal — *is it named, is it reachable, does the user have an action, is a test watching it?* This is the artifact that certifies §1 |
| **D2** | Owner-gated prod reads (§5) |
| **D3** | Release |

---

## 5. Owner-gated — do not run unprompted

- **H-D5 baseline is self-contradictory:** ~548 `invalid_grant`/72h (map §1.4) vs ~7/4d back-solved
  from the same source. Needs a prod log read; the hypothesis cannot be evaluated until reconciled.
- **T7 / H-D6:** whether prod's stored tokens already carry the current `TokenMetadata` shape
  (`did`, `name`). If that read FAILS, the dual-read migration becomes mandatory and the
  "flush is stale" decision re-opens.
- **Whether the RUNNING prod container matches `docker-compose.yml`.** Repo config is durable
  (named `redis_data`, F9); running state unverified. T6 fixed the *labs*, not prod.
- **B10:** that prod is still `sha-db79e75` is **ASSUMED**, carried from the map, never re-probed.
- **Deployment** of everything on this branch.

---

## 6. Invariants this plan must not be used to weaken

- **I4** — never render success when the effect is unconfirmed. Phase D's deploy is not a licence to
  relax `reset_outcome`.
- **I1 / I1a** — verification is never shortcut. C1–C4 close gaps by making the *client's*
  affordances honest, never by having the server vouch for a device or derive key material.
- **I8** — fail open only on indistinguishable I/O errors, never on a definite tombstone. B4's
  harness must not weaken `dd34e3f`'s guards to go green.
- **I-C1** — no terminal may present zero user-actionable controls while crypto is healthy.
- **U3′'s corollary** — "fail toward enforcement" is safe for a **gate** and unsafe for a
  **destructive action**. Any future patch reaching `accessSecretStorage(..., {forceReset})` must
  fail toward **unlock**.

**Do not delete `EW-V1` assertion 8 or `EW-R1-2` to get a green suite.** They are the only watchers
on `T_C_Wedged` (U10).

---

## 7. Discoverability defect found this session

The 2026-07-26 handover referenced `docs/2026-07-26-HANDOVER-...md`, which **does not exist** at the
primary working directory `/home/waldknoten-01/siwx-oidc` — that checkout sits on
`fix/finding3-fragment-response-mode`, ~20 commits behind. All marathon work is in the worktree
`~/wt/siwx-durability`. A fresh session reading the default path concludes the work was never done.

**Rule for future handovers:** state the worktree path and branch in the first two lines, and verify
with `git log --all --oneline` before concluding a referenced document is missing.
