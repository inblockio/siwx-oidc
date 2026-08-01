# provision_user hardening: loud failure + self-healing retry

**Status:** EXECUTING (gate satisfied by explicit user directive, 2026-08-01)
**Origin:** 2026-08-01 dev incident — account `0x4b23…` was created half-provisioned (Synapse `users` row, no `profiles` row) because `provision_user` failed transiently at first sign-in, was logged at `warn!` and never retried; upstream Synapse bug #19702 (500 on profile write for row-less accounts, present in 1.154.0) then made the account permanently unable to set a displayname. 59/60 dev accounts and all active prod accounts are healthy — this closes the "silent half-provision" half of the problem; the Synapse-side half closes when upstream fixes #19702 and the pinned image is bumped.

## Goal (one sentence)
A `provision_user` failure at first sign-in is logged at `error!`, and any existing account whose Synapse profile row is missing is re-provisioned automatically at its next sign-in — without ever overwriting a user-set (or deliberately cleared) displayname and without ever failing sign-in.

## Design
In `oidc::provision_synapse_device` (src/oidc.rs:1597-1605):
- `Ok(true)` branch: `provision_user` failure → `error!` with structured fields (`did`, `error`), message stating the account may now be half-provisioned and will be retried at next login.
- `Ok(false)` branch (account exists): best-effort self-heal — new `SynapseClient::has_profile_row(localpart, server_name)`:
  `GET {endpoint}/_matrix/client/v3/profile/@{localpart}:{server_name}` (unauthenticated client API).
  - HTTP 200 → row exists → do nothing (this is why a customized OR cleared displayname is never touched: a row with null displayname still returns 200).
  - 404 (no-row: `M_UNKNOWN "No row found"` / `M_NOT_FOUND`) → `warn!` + re-run `provision_user` (the MAS upsert; sets displayname = DID exactly as first-time provisioning would). Retry failure → `error!`.
  - transport/other error → `warn!`, continue (never fail sign-in; same best-effort discipline as the surrounding code).
- `server_name` is not currently available in `provision_synapse_device` — add a `server_name: Option<&str>` parameter (mirrors the existing `has_cross_signing_keys(localpart, server_name)` precedent) and thread `config.matrix_server_name` through the call sites. `None` → skip the heal check (standalone deployments degrade to current behavior, never 500).
- If `provision_synapse_device_additive` (device-code grant) contains the same availability/provision match, apply the identical pattern there (QR login is an equally valid heal point); otherwise leave it and note why.

## Hypothesis register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| P1 | provision_user fails at first sign-in | an `error!` line with did+error fields appears | logging conventions per CLAUDE.md | code review + `grep -n 'error!' src/oidc.rs`; live-forcing a failure is not practical — accepted as review-verified |
| P2 | an existing account lacks its profiles row at sign-in | next sign-in re-runs provision_user and the row is restored | MAS `/provision_user` is an idempotent upsert (proven: it is called freely for new users; MAS semantics) | **dev live test:** throwaway did:key login → delete its `profiles` row via sqlite → re-login → row back with displayname=DID, heal log line present. **RESULT (2026-08-02): PARTIAL.** Detection is confirmed live (the missing row is correctly identified and the retry fires). The retry's own `provision_user` (MAS `set_displayname`) 500s on Synapse 1.154.0 — it hits the SAME upstream `_check_profile_size` crash (element-hq/synapse#19702) that produced the half-provisioned account in the first place, traced live to `profile_handler.set_displayname -> profile.py:354`. So the row is not actually restored on this Synapse version; the heal is correctly wired but inert until the deployment's pinned Synapse image is bumped past the upstream fix. First-time provisioning (registration) is unaffected because it creates the row before ever calling `set_displayname`. |
| P3 | an account has a healthy (or deliberately cleared) profile | sign-in changes nothing about its profile | 200-vs-404 discriminator is correct (row with null displayname → 200) | dev: normal re-login of the throwaway (row present) → profile GET unchanged, no provision_user call in logs. **RESULT (2026-08-02): PREMISE FALSIFIED, FIXED.** The "any 404 = absent" assumption was wrong on Synapse 1.154.0: a row that exists but is empty (displayname AND avatar_url both null) ALSO 404s (`errcode: M_NOT_FOUND`, `"Profile was not found"`), distinct from a truly absent row (`errcode: M_UNKNOWN`, `"No row found"`). The original code read both as absent and re-ran `provision_user`, which CLOBBERED a deliberately-cleared displayname back to the DID (observed live). Fixed by discriminating on `errcode` (`M_UNKNOWN` = absent = heal; everything else, including unparseable bodies, = present = fail-safe, do not heal) via a new pure `profile_404_means_row_absent` with unit tests for all four measured/edge shapes. See "Remediation (2026-08-02)" below. |
| P4 | Synapse client or server_name is unconfigured | behavior identical to today (no check, no 500) | `Option` threading correct | `cargo build` + code review of `None` paths |
| P5 | the change compiles and existing tests still pass | no regression | Redis reachable for `--bin siwx-oidc` tests (throwaway container OK) | `cargo build --workspace` + `cargo clippy` + `cargo test --bin siwx-oidc` (or documented skip) |

## Tasks
### T1 — implement (sonnet subagent, worktree ~/wt/siwx-provision-retry)
**Hypotheses:** P1, P2, P3, P4, P5 — Files: `src/synapse_client.rs` (new `has_profile_row`), `src/oidc.rs` (branch logic + signature), call sites of `provision_synapse_device` (thread server_name), `CLAUDE.md` (token-model/provisioning note if it documents the old behavior).
### T2 — dev-staging live validation
**Hypotheses:** P2, P3 — merge branch → dev CD, then the delete-row/re-login heal test with a throwaway did:key; clean up the throwaway (deactivate).

## Boundary conditions
- Never fail sign-in from any new path (best-effort everywhere).
- Never call provision_user for an account whose profile GET returns 200 (displayname-clobber guard).
- Prod untouched. Dev throwaway account deactivated afterwards.
- Worktree only; ~/siwx-oidc checkout (branch fix/finding3-fragment-response-mode) untouched.

## Remediation (2026-08-02)

Live validation on dev (Synapse 1.154.0) falsified P2 and P3's premises. Findings and fixes:

1. **Discriminator bug (P3, clobber, FIXED).** A profile row with both `displayname` and `avatar_url` null 404s with `errcode: M_NOT_FOUND` ("Profile was not found") — a row that EXISTS. A truly absent row 404s with `errcode: M_UNKNOWN` ("No row found"). The original `has_profile_row` treated any 404 as absent, so it re-ran `provision_user` against a present-but-empty profile and clobbered a deliberately-cleared displayname back to the DID (observed live). Fixed: `has_profile_row` now reads the 404 body and defers to a new pure function `profile_404_means_row_absent(body: &str) -> bool` (`src/synapse_client.rs`), gated on `errcode` alone (`M_UNKNOWN` → absent/heal; `M_NOT_FOUND` or anything unparseable/unrecognized → present/fail-safe, do not heal). `errcode` is primary because Synapse's human-readable `error` strings carry no stability contract. Six unit tests cover the measured shapes plus edge cases (empty body, garbage JSON, `M_UNKNOWN` with unexpected error text, missing `errcode`).
2. **Repair is inert on affected Synapse versions (P2, PARTIAL, expected).** The heal's repair call (`provision_user` → MAS `set_displayname`) itself 500s on a row-less account on Synapse 1.154.0 — it hits the same upstream `_check_profile_size` crash (element-hq/synapse#19702) this whole feature targets. Traced live: `synapse/rest/synapse/mas/users.py` → `profile_handler.set_displayname` → `profile.py:354`. Detection (the `has_profile_row` check + the decision to retry) is correct and confirmed live; the retry's own write is blocked upstream. The `error!` line per affected login is intentional observability, not a new bug, and the heal self-activates with no further code change once the deployment bumps its pinned Synapse image past the fix. First-time provisioning (registration) is unaffected — it creates the row before ever calling `set_displayname`.
3. **New risk: GDPR erasure interplay (documented, accepted).** A GDPR-erased account's purged profile row also reads as `M_UNKNOWN`/absent by this discriminator. If an erased account (`account::execute_action`'s `org.matrix.account_erase`) ever completed sign-in again, the heal would resurrect a bare profile row (`displayname = DID`). Accepted: this reveals nothing beyond the mxid the caller already presented to authenticate. Documented on the heal branch in `src/oidc.rs` and on `SynapseClient::has_profile_row`'s doc comment, cross-referencing `account_erase`.

Files touched in this round: `src/synapse_client.rs` (corrected `has_profile_row`, new `profile_404_means_row_absent` + 6 unit tests, updated doc table), `src/oidc.rs` (comment block on the heal branch covering the inert-repair and erasure notes, updated `provision_synapse_device` doc comment), `CLAUDE.md` (aligned provisioning note), this plan doc.
