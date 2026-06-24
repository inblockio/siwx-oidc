# Cross-signing-reset fix — Logic Model + Execution Plan

**Date:** 2026-06-24
**Branch:** `investigate/grace-deploy-device-verify-20260624`
**Bug doc:** `docs/audits/2026-06-24-grace-deploy-device-verify-forensics.md` (root cause @ f721f7f)

## The bug (one paragraph)
siwx-oidc renders a "Encryption keys reset" SUCCESS banner (`src/account.rs:374` `ActionOutcome::Completed` + `:1609`) decoupled from whether the reset grant is effective. Its lever is `POST /_synapse/mas/allow_cross_signing_reset` (`src/synapse_client.rs:130`), which arms a 10-min, per-user, **master-row-scoped** UIA-bypass window via Synapse `UPDATE e2e_cross_signing_keys SET updatable_without_uia_before_ms WHERE keytype='master'`. In a destructive reset with **no currently-published master**, that `UPDATE` matches 0 rows (no-op) → window never planted → `POST /keys/device_signing/upload` still 401s (Synapse gate `keys.py:403`) → but the MAS push returned 2xx so siwx-oidc shows success (`synapse_client.rs:141-147` only checks its own HTTP status). Result: a stranded half-reset identity.

## GOAL
Make the reauth honest+effective and prove it end-to-end on the local hermetic harness.
**Acceptance:** destructive-reset leg = success-banner-but-401 pre-fix; post-fix never a false success (true success OR truthful failure+guidance); wired into `e2e-harness/run.sh`; fixed siwx-oidc running on `siwx-e2eh-*`, no regressions.
**Out of scope:** prod deploy; forking upstream Synapse (unless the spike proves it the only path + operator approves); the Element-Web 401-follow client fix.

## Hypothesis register

| ID | If | Then | Verification |
|----|-----|------|-------------|
| H1 | I drive a destructive cross-signing reset for a test identity on the e2eh stack + call the reset reauth | the bug reproduces locally: `device_signing/upload` 401s after the reauth reports success | harness repro script: observe banner=success + upload HTTP 401 |
| H2 | I probe `allow_cross_signing_reset` against the e2eh Synapse with/without a published master row | the real contract is known: whether a window can be armed effectively with no master row | inspect `e2e_cross_signing_keys` row + rowcount + subsequent upload status |
| H3 | siwx-oidc reads back grant effectiveness (window-in-future on the gated row / typed MAS result) before rendering success | success is impossible unless the next upload will be honored | code path: `Completed` only when effectiveness confirmed |
| H4 | (if H2 says fixable) siwx-oidc arms the no-master case correctly / reorders | the destructive-reset upload returns 200 post-reauth | leg B upload → 200 |
| H4' | (if H2 says NOT fixable in siwx-oidc) siwx-oidc returns a truthful non-success + guidance | user sees an honest failure, never a false success | leg B outcome != Completed; clear guidance |
| H5 | new e2e test (legs A/B/C) runs against real Synapse, wired into run.sh | RED on pre-fix binary, GREEN on post-fix | `run.sh` test result pre vs post |
| H6 | fixed siwx-oidc built + swapped into e2eh stack | stack healthy on the fixed binary; `run.sh` full green, no regressions | `podman ps` healthy + run.sh full |

## Activity chain (PERT/CPM)
1. **B0 SPIKE (gate):** repro + probe real Synapse contract (H1,H2). Resolves fix-shape (H4 vs H4').
2. **B1 FIX (siwx-oidc):** truthful-success gating (H3) + no-master handling (H4 or H4') + mixed-case-DID guard.
3. **B2 TEST:** real-Synapse e2e legs A/B/C wired into harness (H5). Can develop in parallel with B1.
4. **B3 DEPLOY-LOCAL:** build fixed siwx-oidc, swap into e2eh stack (H6).
5. **B4 VALIDATE:** run.sh full on fixed local stack (H5,H6), green twice.

## Boundary conditions
- **Invariants:** never touch prod; **never render success when the grant is ineffective** (honesty fix is non-negotiable); no Synapse fork without spike-proof + operator approval; reuse the harness.
- **Assumptions:** e2eh real Synapse gates cross-signing like prod (note version); the MAS allow endpoint exists in the e2eh Synapse; siwx-oidc can be rebuilt + swapped into the e2eh stack.
- **Top risks:** (1) no-master functional fix needs an upstream Synapse change → land H4' (truthful failure) — still kills the silent lie; (2) e2eh Synapse ≠ prod version → honesty fix is version-robust; (3) destructive-leg repro needs Element's exact key sequence.
- **Convergence:** B4 green twice; the destructive-reset leg behaves correctly (true success or honest failure).
