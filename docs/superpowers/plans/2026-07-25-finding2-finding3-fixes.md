# Plan: Fix Finding 2 (restore-gate in vendored patch) + Finding 3 (fragment response mode)

**Date:** 2026-07-25
**Process:** process-pipeline (logic-model → subagent execution → hypothesis-traced audit)
**Findings source:** `2026-07-25-session-onboarding-AUDITED-PROPOSAL.md` §13 (FINDING 2/3),
`docs/audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md` (+ evidence spec).

---

## Logic model (list mode)

**Shared CONTEXT:** Both findings were empirically root-caused on 2026-07-25 with
parallel-container evidence. Element lab (28080/28081/28088) runs the patched
1.12.20 build + branch-tip siwx. Both repos' mains already contain the Phase-2
merge; work happens on fix branches off main. No prod deploy.

### F2 — vendored patch gates on session restore

- **GOAL:** A merely-reloaded, previously-set-up session never sees the
  "Confirm your digital identity" gate; a genuinely new first device is still
  forced through recovery-key setup.
- **INPUTS:** `patches/element-web/force-first-device-recovery.patch`
  (matrix-server), lab element-web image build, EW-L1b/EW-C1 specs.
- **CAUSAL CHAIN:** patch's `shouldForceVerification` returns
  `!crossSigningReady || !secretStorageReady`; on restore
  `isSecretStorageReady()` is transiently false → gate. The mandate is "a
  recoverable identity EXISTS", and server-side 4S existence
  (`client.secretStorage.hasKey()`) is the truth for that → widening the
  satisfied-condition to `secretStorageReady || hasKey()` removes the restore
  gate without weakening first-login enforcement (a new user has no 4S
  anywhere → still forced).
- **BOUNDARY CONDITIONS (must NOT happen):** first-login wizard skipped for
  genuinely-new users; retry/sign-out escape dialog removed; patch fails to
  apply to the pinned v1.12.20; existing-user-new-device flow trapped.

### F3 — fragment response mode in siwx-oidc

- **GOAL:** matrix-js-sdk v42 (Element ≥ 1.12.24) validates the issuer and
  completes login: metadata advertises `response_modes_supported:
  ["query","fragment"]` AND `sign_in` delivers `#code=…&state=…` when
  `response_mode=fragment` was requested. Default (absent param) stays query —
  all existing clients/tests unchanged.
- **INPUTS:** `src/oidc.rs` (`AuthorizeParams`, `authorize`,
  `provider_metadata_value`, `sign_in` + its `SignInParams`),
  `js/ui/src/App.svelte` (`buildSignInUrl` pass-through), evidence spec for the
  no-shim v1.12.24 repro.
- **CAUSAL CHAIN:** authorize accepts+validates `response_mode`, forwards it on
  the 303 to the login SPA; SPA passes it through to `/sign_in`; `sign_in`
  formats the redirect Location with fragment instead of query when requested;
  metadata advertises both modes → js-sdk v42 `isValidAuthMetadata` passes →
  OIDC-native login, no legacy-SSO fallback.
- **BOUNDARY CONDITIONS (must NOT happen):** advertising fragment without
  honoring it (strictly worse for v42); default query behavior changed
  (breaks 26 mock + headless helpers); `response_mode` values outside
  {query, fragment} silently accepted; fragment emission on non-authorize
  flows (device-code/account are not redirect flows — untouched).

---

## Hypothesis register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | The patch treats server-side 4S existence (`secretStorage.hasKey()`) as satisfying the recoverable-identity mandate | Reload of a set-up session restores to the app shell with NO gate | **A1:** `hasKey()` is truthy at the restore-time evaluation point (if falsified → fallback: defer the 4S half of the check until first sync PREPARED) | Rebuild lab element-web; EW-L1b (tightened: chat-restore REQUIRED, gate = failure) green |
| H2 | The fix only widens the satisfied-condition | First-login enforcement intact: fresh user still walked through recovery-key wizard; retry/sign-out escape unchanged | Patch still applies to pinned v1.12.20 | EW-C1 green (wizard branch actually taken — assert wizard seen), full Element suite green |
| H3 | Metadata advertises query+fragment AND sign_in honors fragment | Vanilla Element 1.12.24 (js-sdk v42) completes OIDC-native login with ZERO shims | v42 needs no other missing fields (agent verified scope/DCR/token OK once shimmed) | Parallel `vectorim/element-web:v1.12.24` on :28089 → click-login lands in app; 0 legacy-SSO hits |
| H4 | authorize forwards `response_mode` to the SPA and App.svelte passes it to `/sign_in`; absent → query | Real UI flow delivers fragment only when requested; every existing query-path consumer unchanged | SPA rebuild lands in lab image | Mock suite 26 green (query default); unit tests for both formats |
| H5 | Element 1.12.20 (patched lab) requests fragment and now RECEIVES fragment | Lab click-paths still green (old js-sdk parses the fragment it asked for) | — | Element suite 17 green after lab siwx rebuild |
| H6 | authorize validates response_mode strictly | Unsupported values → 400 invalid_request; fragment Location formatted `redirect#code=…&state=…` (no query residue) | — | New unit tests in `oidc::tests` |

---

## Tasks

### Task 1 (F3-server): response_mode in oidc.rs  — **Hypotheses:** H3, H4, H6
**Repo:** siwx-oidc, branch `fix/finding3-fragment-response-mode` off `main`.
**Files:** `src/oidc.rs` (AuthorizeParams + authorize + sign_in + SignInParams + provider_metadata_value), unit tests in `oidc::tests`.
- [ ] `AuthorizeParams.response_mode: Option<String>`; validate ∈ {"query","fragment"} else 400 invalid_request
- [ ] authorize 303 to SPA carries `response_mode` when non-default
- [ ] sign_in reads `response_mode` (query param, same round-trip as PKCE); fragment → `Location: {redirect_uri}#code=…&state=…`; default query unchanged
- [ ] `provider_metadata_value`: `response_modes_supported: ["query","fragment"]`
- [ ] Unit tests: metadata field; authorize reject bad mode; sign_in fragment + query formats
- [ ] `cargo test --bin siwx-oidc` green (Redis on :6379)

### Task 2 (F3-UI): App.svelte pass-through — **Hypotheses:** H4
**Repo:** siwx-oidc, same branch.
**Files:** `js/ui/src/App.svelte`.
- [ ] Read `response_mode` from URL params; append to `buildSignInUrl()` when present (mirror `oidc_nonce_param` pattern)

### Task 3 (F2): fix vendored patch — **Hypotheses:** H1, H2
**Repo:** siwx-oidc-matrix-server, branch `fix/finding2-restore-gate` off `main`.
**Files:** `patches/element-web/force-first-device-recovery.patch`.
- [ ] `shouldForceVerification`: `return !crossSigningReady || !(secretStorageReady || hasServer4S)` where `hasServer4S = await client.secretStorage.hasKey().catch(() => false)`; comment explains restore semantics
- [ ] Keep the retry/sign-out loop hunk unchanged
- [ ] Verify the patch applies cleanly at v1.12.20 (dry-run in the Docker build or `git apply --check` against a fetched tree)
- [ ] Fallback if A1 falsified during validation: defer the 4S half until first sync PREPARED

### Task 4 (validation, serial — orchestrator): rebuild + suites — **Hypotheses:** H1–H6
- [ ] Rebuild lab siwx container (F3 branch) and element-web image (F2 branch)
- [ ] Tighten EW-L1b: gate branch becomes a FAILURE (crypto restore REQUIRED); assert EW-C1 wizard actually seen
- [ ] Mock suite 26 green; Element suite green; vanilla 1.12.24 no-shim login green on :28089 (throwaway container)
- [ ] Guard note: `check-auth-metadata.sh` WARN stays until PROD deploys the F3 fix, then flip to FAIL (documented, not flipped now)

### Task 5 (audit + docs) — all hypotheses
- [ ] Hypothesis trace + acceptance criteria tables; update FINDING 2/3 rows to Fixed; update jssdk-v42 audit doc status
- [ ] Commits on both fix branches; NO merge to main and NO deploy until audit reviewed

## Acceptance criteria

| # | Criterion |
|---|-----------|
| AC1 | Reload of a set-up session on the patched lab build restores to the app with no identity gate (EW-L1b tightened, green) |
| AC2 | Fresh first login still forces recovery-key setup (EW-C1 wizard branch exercised, green) |
| AC3 | Vanilla Element 1.12.24 logs in against fixed siwx with zero shims (parallel :28089) |
| AC4 | All pre-existing suites green on the fixed code: 115+ unit, 26 mock, Element suite |
| AC5 | Metadata advertises both response modes; unsupported mode → 400 |
