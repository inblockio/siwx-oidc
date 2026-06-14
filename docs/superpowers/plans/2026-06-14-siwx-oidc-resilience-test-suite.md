# Plan — siwx-oidc Resilience & Correctness Test Suite (R2)

**Branch:** `audit/siwx-oidc-functional-harness`
**Date:** 2026-06-14
**Hypothesis register:** see `docs/audits/2026-06-14-siwx-oidc-requirement-map.md` (R-A1..R-K2 + H1..H14). That file is the immutable register for this pipeline.
**Plan-confirmation:** user pre-authorized autonomous overnight execution; treated as confirmed, presented for review in the morning summary.

## Baseline (established 2026-06-14)
- GREEN against mock/Redis: unit (`cargo test --bin`), `e2e_account_management`, `legacy-cs-api-probe`, Playwright `account.spec.mjs`.
- Live-only suites (`e2e_msc3861`, `e2e_session_teardown`, `e2e_msc4191_live`, `e2e_messaging`) require a real Synapse (`MATRIX_HOST`) — baseline FAILs are expected absent a homeserver, not regressions. Track 2 stands up a real stack for these.

## Strategy
Race/cleanup hazards are tested **deterministically at the provider+mock+Redis level** (forced interleavings via concurrent reqwest tasks; a real Synapse gives non-deterministic timing). UI-path requirements are tested in Playwright. Real Synapse-side + E2EE messaging is validated separately (Track 2 / R4).

---

### Task F1: Rust race & teardown suite + mock observability
**Hypotheses:** H1,H2,H3,H4,H6,H8,H9,H10,H12,H14 · R-A2,R-F1,R-F2,R-F3,R-F4,R-F5,R-G3,R-G5,R-G9,R-H2,R-H3,R-I1
**Files:** Create `tests/e2e_race_teardown.rs`; extend `e2e/synapse_mock.py` (call-log already present; add per-call detail + a `/__fail` toggle to simulate Synapse-unreachable for H14; ensure DELETE-device and revoke calls are individually observable). Owns ALL mock changes.
**Done when:** new suite green against the mock stack; each test asserts the Synapse-side call pattern (e.g. revoke ⇒ no DELETE; logout ⇒ DELETE; concurrent deletes ⇒ exactly-once / idempotent, no 500, tokens revoked). Commit on the functional branch.

### Task F2: Browser device-lifecycle suite (builds on F1's mock)
**Hypotheses:** H5,H11,H13 · R-A1,R-C1,R-C2,R-G1,R-G2,R-G4,R-G6,R-G8,R-G10
**Files:** Create `e2e/browser/device-lifecycle.spec.mjs` (+ extract reusable `wallet-helper.mjs`/`webauthn-helper.mjs` from `account.spec.mjs`). Uses CDP virtual authenticator for real passkey register/erase (covers credential-purge H13 + challenge-replay H11 + erase-vs-login H5 at the UI/provider boundary).
**Done when:** new specs green via `e2e/browser/run.sh`; cross-signing-reset + base64 device_view + erase-purge observable in mock `/__state`. Commit.

### Task F3 (Track 2 / R4): Real-Synapse live suites + messaging regression
**Hypotheses:** R-A3,R-A4,R-E4,R-I2,R-I3,R-J1,R-J2,R-K1,R-K2 + live confirmation of H1/H2/H7
**Depends on:** real stack from the bringup agent. Run `e2e_msc3861`, `e2e_session_teardown`, `e2e_msc4191_live`, `e2e_messaging` against it. Record real Synapse-side outcomes. If stack BLOCKED, fall back to documented blocker + the `src/compat.rs` unit coverage note.

---

## Audit (Phase 3)
Layer 1 hypothesis trace (every Confirmed cites a run command + output); Layer 2 acceptance-criteria check. Gaps → targeted remediation. Consolidated into the morning summary.
