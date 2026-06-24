# Plan: refresh-token grace window (fix Element-X mobile sign-out)

**Branch:** `fix/refresh-token-grace` (worktree `~/siwx-oidc-grace`, based on `origin/main` @ a074795)
**Findings:** `docs/audits/2026-06-23-elementx-refresh-rotation-signout.md`
**Goal (one sentence):** Tolerate replay of a just-rotated refresh token by returning the
already-minted successor within a bounded grace window, so a lost rotation response no longer
signs Element-X out.

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | the old refresh token is hard-deleted on rotation with no grace (oidc.rs `token_refresh`, compat.rs `refresh`) | replaying a just-rotated refresh token yields `invalid_grant` / `M_UNKNOWN_TOKEN` | matrix-rust-sdk presents the old token on retry after a lost response | reproducer RED on current code: `RUN_REPRO=1 cargo test --test e2e_race_teardown refresh_grace -- --ignored --nocapture` |
| H2 | on rotation we write a bounded grace pointer (old_rt -> {new_access,new_refresh,access_exp}, TTL=`REFRESH_GRACE_TTL`) and return it on replay | a replay within the window returns 200 with an ACTIVE successor access token | grace TTL <= access TTL so the stored access token is still valid on replay | reproducer GREEN after fix; replayed access token introspects active |
| H3 | the grace pointer is keyed only on genuinely-rotated tokens with a short TTL | a never-issued / unknown refresh token is still rejected (no blanket-accept) | grace lookup only succeeds for tokens we actually rotated | negative assertion: random token -> `invalid_grant` (GREEN) |
| H4 | both the OAuth `/token` path and the compat `/_matrix/client/v3/refresh` path use the shared store-layer grace mechanism | both tolerate replay identically | both handlers reachable in the e2e stack | reproducer exercises both endpoints, both GREEN |
| H5 | the grace store is additive (new `token_rotated/*` key namespace; no `TokenMetadata` change) | existing token/introspection/revocation behavior is unchanged; no Redis migration | nothing else reads/writes the new prefix | existing suite GREEN: `cargo test --bin siwx-oidc`; `cargo test --test e2e_race_teardown -- --ignored` (incl. H3/H6/H9 guards) |
| H6 | the grace pointer is written ONLY after the existing H3/H6 check-mint-recheck rollback passes | the grace pointer never resolves to rolled-back (revoked) tokens | the recheck still runs before grace write | a refresh whose device is torn down mid-rotation does not become replayable (covered by existing teardown guards staying GREEN) |

**Boundary conditions (what must NOT happen):**
- MUST NOT widen refresh-token lifetime or weaken rotation. Grace is bounded (<= 60s); the old
  token is still removed as a valid refresh credential; expired/unknown tokens still rejected.
- MUST NOT change the `TokenMetadata` schema (no Redis flush on deploy).
- MUST NOT introduce a 500 path. Grace read/write are best-effort; failure falls through to the
  existing `invalid_grant`/`M_UNKNOWN_TOKEN`, never 500.
- MUST NOT log token values.
- MUST NOT touch prod. Code + local e2e only; deploy is a separate, owner-gated step.
- MUST NOT regress the existing H1/H2/H3/H6/H8/H9 race + teardown guards.

---

## Tasks

### Task 1: Grace store layer
**Hypotheses:** H2, H3, H5
**Files:** `src/db/mod.rs` (struct + constants + trait methods), `src/db/redis.rs` (impl)
- [ ] `RotatedToken { access_token, refresh_token, access_exp }` (Serialize/Deserialize)
- [ ] `const KV_ROTATED_PREFIX = "token_rotated"`, `pub const REFRESH_GRACE_TTL: u64 = 60`
- [ ] Trait: `set_rotated_token(&self, old_refresh, &RotatedToken, ttl)`, `get_rotated_token(&self, old_refresh) -> Option<RotatedToken>`
- [ ] Redis impl mirroring `is_device_revoked` style (via `set_ex_raw` / `get_raw`)

### Task 2: Wire grace into both refresh handlers
**Hypotheses:** H1, H4, H6
**Files:** `src/oidc.rs` (`token_refresh`), `src/compat.rs` (`refresh`)
- [ ] On `get_token == None`: check `get_rotated_token`; if present, return the successor pair
      (replay), else the existing `invalid_grant` / `M_UNKNOWN_TOKEN`
- [ ] On committed success (AFTER the check-mint-recheck rollback), write the grace pointer for
      the just-presented refresh token; keep the existing delete of the old token
- [ ] `expires_in` on replay computed from `access_exp - now` (>= 0)

### Task 3: Reproducer test
**Hypotheses:** H1, H2, H3, H4
**Files:** `tests/e2e_race_teardown.rs`
- [ ] `refresh_grace_window_tolerates_replay` (OAuth `/token`): login -> refresh (rotate) ->
      replay OLD rt -> assert 200 + active access token; replay twice (idempotent)
- [ ] negative: a random/never-issued refresh token -> `invalid_grant`
- [ ] compat sibling on `/_matrix/client/v3/refresh` (replay OLD rt -> 200)

### Task 4: Verify RED -> GREEN + regression
**Hypotheses:** all
**Files:** (none; verification)
- [ ] `bash e2e/up.sh`; run new test on UNFIXED binary -> RED
- [ ] apply Tasks 1-2; rebuild + restart oidc container; run new test -> GREEN
- [ ] `cargo test --bin siwx-oidc` + `cargo test --test e2e_race_teardown -- --ignored` -> GREEN (no regression)

---

## Execution strategy

Inline, sequential (the change is small and tightly coupled; subagent fan-out overhead is not
warranted, and memory governance favors restraint). A final independent audit pass checks the
hypothesis trace and acceptance criteria before any deploy discussion.
