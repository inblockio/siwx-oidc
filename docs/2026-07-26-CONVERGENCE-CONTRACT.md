# CONVERGENCE CONTRACT — how this marathon terminates

**Date:** 2026-07-26 **Branch:** `feat/session-durability-marathon` (worktree `~/wt/siwx-durability`)
**Status:** owner-confirmed. This supersedes the *planning* half of
`2026-07-26-FINISH-LINE-goal-confirmed-and-remaining-work.md`; its §1 goal and §5 owner-gated list stand.

---

## 1. The problem this fixes, measured

| | Session start | After a productive session |
|---|---|---|
| States in the machine | 72 | **~89** |
| Uncovered rows | 16 | **21** |
| Registered assumptions | 11 | **20** |
| Documents a session must read | — | **30 files / 9,086 lines** |
| Of those, carrying corrections or supersessions | — | **14 (47%)** |

That session closed four real things (U3′ watched, `C_Working` asserted, F-1 fixed, 28 tests
promoted) **and the uncovered count still rose.**

**The method diverges.** Each pass adds states and assumptions faster than it closes them. A loop
whose backlog grows per iteration has no exit — it is drift, not iteration. Everything below exists
to invert that slope and make the inversion *measurable*.

---

## 2. Four structural gaps

| | Gap | Evidence it is real |
|---|---|---|
| **A** | **No single source of current truth.** Append-never-rewrite is right for provenance and produced a corpus where nothing states what is true *now*. | The ordering document (matrix §8) was **stale on 3 of its 5 entries**; found only by hand re-adjudication. |
| **B** | **Coverage is asserted by humans, not emitted by runs.** "Covered" means someone read a spec and judged it. | **EW-Q1-c carried a coverage verdict having never once been executed.** Its own audit says the specs "were NOT executed". |
| **C** | **The boundary floats**, so the target is unbounded — scope is set by a client we do not own, and an upgrade silently invalidates verdicts pinned to v1.12.20. | ~17 new states appeared in one pass, all from client behaviour. |
| **D** | **The loop has no exit predicate.** Deploy is gated on "the final audit", which is not defined as anything checkable. | The state-machine effort has no terminal state — the exact defect it exists to eliminate. |

---

## 3. Decisions (owner-confirmed 2026-07-26)

### 3.1 Strategy: ATTENUATE, don't only amplify

Every prior pass amplified controller variety — more tests, more agents, more documents. Ashby
permits the other direction: reduce the *problem's* variety.

**U3′, U4, U5, U6, U7 are not five defects. They are five symptoms of one product decision:** reset
is offered readily and is destructive. A2 established the decisive fact — **once the master key is
published, deleting the message-key backup buys nothing; it is pure loss** — and Element bundles
that DELETE as reset's *opening* move.

Decomposing `reset_identity` (unlock-first; never bundle the DELETE; preview destruction before any
irreversible step) makes a cluster of undefined states **unreachable rather than covered**.

> **Deleting a state is cheaper than testing it, and unlike a test it cannot rot.**

### 3.2 The matrix becomes a BUILD PRODUCT, not a document

Coverage is **emitted by the run**, never hand-asserted. An unexecuted spec then self-reports as
uncovered instead of silently claiming coverage.

### 3.3 Exit predicate — the marathon's terminal state

Converged ⟺ **all five**, each checkable:

1. The ledger is **generated from run output**, not written by hand.
2. **Zero OWNED states unwatched.**
3. **Zero I1 / I4 / I-C1 breaches.**
4. The **accepted set is enumerated and signed off by the owner** — never "everything else".
5. The boundary is **pinned**: certified against Element @ a named commit. An upgrade is an explicit
   re-certification event, not a silent invalidation.

**Falsifiable test that this contract worked:** the uncovered count must **strictly decrease every
pass**. It rose 16 → 21. If it rises again after this, the diagnosis was wrong and must be redone,
not explained away.

---

## 4. Schema (normative — both tracks build against this)

### 4.1 State alphabet — `docs/state-machine/states.yaml`

The single machine-readable declaration of the state space. Hand-maintained; the ONLY hand-maintained
artifact in the loop.

```yaml
- id: T_C_Wedged            # unique; matches the map's name exactly
  machine: M4c              # M0 | M1a | M1b | M1c | M2 | M3 | M4 | M4c | M5
  kind: terminal            # state | terminal
  ownership: OBSERVED       # OWNED | OBSERVED | OUT   (see 4.3)
  observable: "phase==2 and zero actionable controls in the ceremony surface"
  invariant: I-C1           # optional; the invariant this state breaches or upholds
  source: "map §M4c"        # provenance
```

### 4.2 Coverage marker — emitted by tests, parsed by the collector

One line on stdout, from any language, no framework coupling:

```
##STATE##{"id":"T_C_Wedged","spec":"ew-verify-sas.spec.mjs","mode":"asserted"}
```

`mode`: `asserted` (a failing assertion guards it) | `observed` (sampled//logged only — NOT coverage).

The distinction is load-bearing: `T_C_OkAwaitAck` was *observed* for a long time while being
*unasserted*, and that is exactly how it was mistaken for a trap.

### 4.3 Ownership — the frozen boundary (gap C)

| Ownership | Meaning | Bar |
|---|---|---|
| **OWNED** | siwx-oidc's own machines: M0–M3, server half of M4 | MUST be total **and** watched by an asserted marker. Blocks the exit predicate. |
| **OBSERVED** | Client (Element / matrix-js-sdk) states we name and test but do not own | SHOULD be watched; a gap is acceptable **only** if it appears in the signed-off accepted set. |
| **OUT** | Upstream behaviour we neither own nor test | MUST have a named terminal + runbook. Never silently absent. |

---

## 5. Tracks

| | Track | Produces | Depends on |
|---|---|---|---|
| **L1** | Ledger instrument | emitter helpers (JS + Rust), `scripts/build-state-ledger.py`, generated `docs/audits/STATE-LEDGER.md` marked DO-NOT-EDIT | §4 schema only |
| **L2** | State alphabet | `docs/state-machine/states.yaml` — every state from map + matrix + M4c + M4-private-half, classified by ownership | §4 schema only |
| **L3** | Attenuation | reset decomposition design + Element patch: unlock-first, no bundled DELETE, destruction preview | A2's finding |
| **L4** | Boundary pin | certified-against commit recorded; re-certification procedure | L2 |

L1 and L2 are parallel by construction — both build only against §4.

---

## 6. Invariants this contract must not be used to weaken

- **I1 / I1a** — verification is never shortcut. Attenuation makes the *client's* affordances
  non-destructive; it must never have the server vouch for a device or derive key material.
- **I4** — never render success when the effect is unconfirmed.
- **I8** — fail open only on indistinguishable I/O errors, never on a definite tombstone.
- **I-C1** — no terminal may present zero user-actionable controls while crypto is healthy.
- **U3′ corollary** — fail toward *enforcement* for a gate, toward *unlock* for a destructive action.
- **Generated means generated.** If the ledger is ever hand-edited to go green, gap B is back and
  every verdict in it is void.
