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
| P2 | an existing account lacks its profiles row at sign-in | next sign-in re-runs provision_user and the row is restored | MAS `/provision_user` is an idempotent upsert (proven: it is called freely for new users; MAS semantics) | **dev live test:** throwaway did:key login → delete its `profiles` row via sqlite → re-login → row back with displayname=DID, heal log line present |
| P3 | an account has a healthy (or deliberately cleared) profile | sign-in changes nothing about its profile | 200-vs-404 discriminator is correct (row with null displayname → 200) | dev: normal re-login of the throwaway (row present) → profile GET unchanged, no provision_user call in logs |
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
