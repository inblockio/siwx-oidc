# Passkey offer-scoping — audit (hypothesis trace + acceptance criteria)

**Branch:** `feat/passkey-offer-scoping` (worktree `~/siwx-oidc-passkey-scope`), base `a074795`.
**Verified:** 2026-06-19. Plan: `2026-06-19-passkey-offer-scoping-token-derived-CORRECTED.md`.

## Evidence base
- Unit: `cargo test --bin siwx-oidc` → **107 passed, 0 failed** (Redis on :6379).
- Browser: `bash e2e/browser/run.sh` → **24 passed** (mock stack from this worktree,
  `SIWEOIDC_MATRIX_SERVER_NAME=matrix.test`).
- Build: `cargo build --workspace` green; `cargo build --bin siwx-oidc` → **0 warnings**.

## Layer 1 — Hypothesis trace

| ID | Status | Evidence |
|----|--------|----------|
| H1 device scoped by cookie DID | **Confirmed** | browser `device: siwx_user cookie scopes /device/passkey/start…` (#17): scoped→`allowCredentials==[A.credId]`, `not contain B`; unit `valid_user_session_scopes_allow_credentials_to_its_did_only` |
| H2 account scoped by cookie DID | **Confirmed** | browser `account: siwx_user cookie scopes /account/passkey/start…` (#16): scoped→`[A.credId]`, `detected_mxid==@a:matrix.test` |
| H3 degrade-open (absent/forged/`all`) | **Confirmed** | browser #16/#17 (no cookie→`[]`, `all:true`→`[]`); unit `forged_user_cookie…→empty`, `user_session_token_reads_cookie_and_honors_escape_hatch`, `payload_force_all…literal_true`. No 500 path (all helpers return `Option`, never `Err`). |
| H4 wallet-only DID → empty→discoverable | **Confirmed** | pre-existing `authenticate_start` empty-set fallback (webauthn.rs:364-390), unchanged; covered by login scoping test path |
| H5 escape affordance reachable | **Confirmed** | browser escape sub-cases (#16/#17 `all:true`→usernameless); frontend `renderPasskeyScope`→`authPasskey(true)`/`approvePasskey(true)` |
| H6 offer ≠ authorization | **Confirmed** | verify_credential + reject_if_new_identity handlers untouched (diff shows no change); browser H5 account/device reject tests (#19/#20) still pass; H9 (#21) passes |
| H7 frontend consumes populated allowCredentials | **Confirmed** | existing base64→buffer map unchanged; browser account/device ceremonies (account.spec #4, device-lifecycle) still pass |

## Layer 2 — Acceptance criteria

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| AC1 | `/account/passkey/start`: valid cookie→creds+mxid; none/forged→empty | **Yes** | browser #16; unit |
| AC2 | `/device/passkey/start`: same | **Yes** | browser #17 |
| AC3 | two-credential — scoped to A, B not offered; escape→all | **Yes** | browser #16/#17 (`not.toContain(b.credId)` + escape); unit `…to_its_did_only` |
| AC4 | login behavior unchanged | **Yes** | browser #15 (login H1/H11/H2) green; login handler untouched in diff |
| AC5 | build + tests green, no new warnings | **Yes** | 107 unit + 24 browser; workspace build; 0 warnings |
| AC6 | degrade-open — no 500 on cookie/token/index issue | **Yes** | helpers are total (`Option`), `lookup_user_session(...).ok().flatten()` swallows errors; browser/unit degrade cases |

## Adversarial review outcome
Independent 4-lens review (security/degrade-open, server correctness, frontend/XSS,
test adequacy) of the 659-line diff with refute-by-default verification:
**3 raw findings → 2 verified, both LOW (test-coverage gaps; production code correct).
No security, correctness, or degrade-open defect found. Both gaps now CLOSED:**

| # | Finding | Resolution |
|---|---------|------------|
| 1 | Degrade-open on a Redis *error* (vs. a miss) — the load-bearing `.ok().flatten()` in `user_session_scope_did` — was untested; a refactor to `?` would 500 with every test still green. | Added `user_session_scope_did_degrades_open_on_redis_error` (axum_lib.rs): forces a fast `WRONGTYPE` GET error on the `user:session/{token}` key and asserts the handler returns `None`, never propagates. **Pass** (108 unit). |
| 2 | The served-frontend affordance (escape button, `detected_mxid` display) had no DOM-level test, only JSON-contract; the duplicated account/device `renderPasskeyScope` could drift unnoticed. | Added `account DOM:…` (presence + escape re-issues `{"all":true}` + hide) and `device DOM:…` (presence) to `passkey-scoping.spec.mjs`. **Pass** (26 browser). |

Final: **108 unit + 26 browser** green; `cargo build --workspace` clean; **0 warnings**.

## Out of scope / recommended follow-ups
- `id_token_hint` (AccountPageQuery, `#[allow(dead_code)]`) is genuinely dead and cannot
  carry identity without a client change; removable as a separate mechanical cleanup
  (touches ~15 test sites) — intentionally NOT bundled here.
- Wallet grey-out: left reverted (a074795), per the design's "resolve live, not predict".
