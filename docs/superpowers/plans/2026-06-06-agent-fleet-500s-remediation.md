# Agent-Fleet 500s Remediation Plan (2026-06-06)

Process-pipeline run. Goal: make the `aqua-matrix-agent` fleet work end-to-end
(zero Synapse 500s on event send), each agent reusing one stable Matrix device,
proven by two agents exchanging encrypted messages.

## Logic Model

- **CONTEXT:** Production `siwx-oidc` runs stale image rev `2b921ab` (deletes the
  Matrix device + resets cross-signing on every login). HEAD `5fa73f2` already fixes
  this (idempotent upsert `provision_synapse_device`, no `delete_device`, no per-login
  reset). The fixed image is already in GHCR as `:main` (= rev `5fa73f2`). It never
  auto-deployed because the `siwx-oidc` service carries no `watchtower.scope=matrix`
  label, so the scoped Watchtower never saw it. The agent fleet is
  `/home/system-001/aqua-matrix-agent`; it calls `siwx_oidc_auth::authenticate()` with
  a hardcoded `scope = "openid profile"` (no device URN), so the server mints a fresh
  `SIWX_<uuid>` device every login. The server's auth-code path ALREADY honors
  `urn:matrix:client:device:<id>` from the session scope (`oidc.rs` `sign_in`), so the
  only gap for stable devices is in the client + fleet.
- **GOAL:** see above (one sentence).
- **INPUTS:** `siwx-oidc-auth/src/{lib,main}.rs`; `aqua-matrix-agent/crates/*`;
  `siwx-oidc-matrix-server/{deploy.sh,docker-compose.yml}`; SSH `deploy@agentic.inblock.io`
  (`~/.ssh/id_ed25519`); live `siwx-oidc.inblock.io` + `matrix.inblock.io`; GHCR.
- **OUTPUTS vs OUTCOMES:** writing the device_id param is an output; an agent reusing one
  device across logins with no 500 is the outcome. Verify outcomes, not outputs.
- **BOUNDARY CONDITIONS:**
  - Invariants: no secrets in model context; no local Docker builds (CI/GHCR only); branch
    per code change (main protected for code); idempotent/additive provisioning only;
    never break cross-signing for real users.
  - Exclusions: not touching OIDC/CAIP-122 protocol, not Element X/mobile, not E2EE protocol.
  - Assumptions: SSH works (confirmed); GHCR `:main` is the fixed digest (confirmed);
    live servers reachable for E2E; agent identities (`agent.pem`, `agent-b.pem`) are valid
    homeserver users.
  - Top risks: (R1) pruning the ~405 stale rows breaks cross-signing if they are not truly
    junk -> investigate, default to NOT pruning; (R2) deploy regression/downtime -> siwx-oidc
    only restart, verify health+rev, rollback path `:sha-2b921ab`; (R3) E2E fails for
    environmental reasons -> diagnose, never claim success without green output.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | prod siwx-oidc upgraded to `5fa73f2` | logins no longer delete the agent's Matrix device (idempotent upsert) | image label reflects source; no other delete path | `docker inspect` label == `5fa73f2`; device row persists across two logins |
| H2 | running rev is `5fa73f2` | a fresh agent login can `/send` with no 500 (device row persists, no FK violation) | Synapse schema FK is the only blocker | E2E send returns 200; row appears in `event_txn_id_device_id`; no 500 in access log |
| H3 | client sends scope with `urn:matrix:client:device:<id>` | server provisions THAT device_id, not a fresh `SIWX_<uuid>` | server scope allowlist accepts the URN (confirmed in `oidc.rs`) | unit: scope string correct; integration: `whoami` device == pinned id |
| H4 | `aqua-matrix-agent` threads a stable per-agent device_id through `authenticate()` | the agent reuses ONE device_id across logins | client param wired; cache not overriding it | login twice; assert device_id equal both times == configured id |
| H5 | two agents authenticate post-fix and exchange encrypted DMs | both decrypt each other's messages with no send error | identities valid; live servers up | `cargo test --test e2e --features e2e` (`e2ee_bidirectional_messaging`) passes |
| H6 | `siwx-oidc` service gets `com.centurylinklabs.watchtower.scope=matrix` label | Watchtower scans + auto-pulls future images | scope value matches Watchtower env (`matrix`) | after redeploy, watchtower `Scanned>=2`; in-scope |
| H7 | production fleet restarted (re-login) after deploy + stable device_id | live tokens bind to a durable, stable device; sends stop 500ing | we can locate + restart the fleet | fleet `/send` returns 200; device_id stable across restarts |
| H8 | the ~405 `master/self_signing/user_signing` rows are provably junk (no live user depends on them) | pruning the junk subset does not break cross-signing | DB backup taken; rows independently verified | schema + per-user analysis; reversible delete with backup; ELSE skip + document |
| H9 | `ci.yml` is red on the merge commit | a real test/lint/fmt failure exists on main (or it is environmental) | reproducible locally | run `cargo test/clippy/fmt`; identify root cause |

## Tasks (staged: mitigate -> harden -> prove -> cleanup)

- T1 [H1,H2] Deploy fixed siwx-oidc to prod (pull+restart `siwx-oidc` only); verify rev `5fa73f2`, health.
- T2 [H2,H5] Immediate post-deploy verification: run two-agent E2E test against prod; confirm sends work (no 500).
- T3 [H3] Add stable device_id capability to `siwx-oidc-auth` client (param + `--device-id` CLI), TDD. Branch.
- T4 [H4] Thread a stable per-agent device_id through `aqua-matrix-agent` (`AgentConfig` -> `authenticate()`). Branch.
- T5 [H7] Locate the running production fleet; re-login (restart) so tokens bind to durable, stable devices.
- T6 [H4,H5] Final verification: E2E test run twice asserting device_id stability + bidirectional decrypt.
- T7 [H6] Fix the missing Watchtower scope label in `siwx-oidc-matrix-server/docker-compose.yml`; redeploy once. Branch.
- T8 [H9] Investigate + fix (or explain) the red `ci.yml`. Branch if a code fix is needed.
- T9 [-] Doc: update stale CLAUDE.md "MSC3861 device lifecycle" section to match HEAD (docs -> main directly).
- T10 [H8] OPTIONAL/RISKY: investigate the ~405 stale rows; prune only if provably safe + reversible, else document + skip.

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|----------|-----------|
| AC1 | prod runs rev `5fa73f2`, not `2b921ab` | H1 |
| AC2 | a login no longer deletes the agent device (persists across logins) | H1 |
| AC3 | agent reuses one stable device_id across logins | H3, H4 |
| AC4 | two agents exchange encrypted messages bidirectionally, no `/send` 500 | H2, H5 |
| AC5 | future deploys auto-apply (Watchtower watches siwx-oidc) | H6 |
| AC6 | (optional) ~405 stale rows pruned safely OR documented safe-to-leave | H8 |
