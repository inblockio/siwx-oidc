# Synapse Lifecycle: Logout/Revoke Teardown, Bulk Sign-Out, Erase + Reactivate (2026-06-09)

Process-pipeline run. Three Synapse-side lifecycle features for siwx-oidc (the MSC3861
AS that replaces MAS). Backbone for secure agent-to-agent communication, so correctness
and clean teardown matter more than brevity.

## Logic Model

### Shared CONTEXT (code-verified 2026-06-09, not from stale docs)

- `compat.rs` is currently **Synapse-agnostic**: `revoke` (`src/compat.rs:45-53`) and
  `logout` (`src/compat.rs:71-81`) only call `redis_client.delete_token`. `CompatState`
  (`src/compat.rs:23-26`) holds **only** `redis_client`, so they *structurally cannot*
  reach Synapse. CLAUDE.md's claim that "both handlers call `delete_device`" is **stale
  aspiration**, contradicted by the code and by `docs/audit/msc3861-compliance-audit.md`
  gap #10.
- **All primitives for full teardown already exist:** `SynapseClient::delete_device`
  / `list_devices` / `get_device` / `deactivate_user` (`src/synapse_client.rs`),
  `RedisClient::revoke_device_tokens` / `revoke_all_user_tokens`
  (`src/db/redis.rs:115,134`), `DBClient::get_token` (maps a bearer/refresh token to
  `TokenMetadata{username, device_id, did, ...}`). The account-page `DeviceDelete`
  (`src/account.rs:259-298`) and `AccountDeactivate` (`src/account.rs:299-320`) branches
  are the proven two-phase teardown template (Synapse admin call → best-effort Redis
  revoke), with `require_synapse` / `require_server_name` graceful-degradation guards.
- **Load-bearing constraint (cross-signing):** Synapse `delete_device` does NOT remove
  rows from `e2e_cross_signing_signatures`. *Clean one-time deletion is SAFE; recycling a
  device_id with new keys is UNRECOVERABLE.* Source:
  `../siwx-oidc-matrix-server/docs/2026-05-19-device-verification-analysis.md:12-14,133-138`.
- **Do not reintroduce per-login deletion.** `docs/superpowers/plans/2026-06-06-agent-fleet-500s-remediation.md`
  records that per-login `delete_device` was *deliberately removed* (it deleted stable-device
  agents' devices and caused 500s / device churn). `provision_synapse_device` is now a
  plain idempotent upsert. **Feature 1 is logout-TIME deletion (an ending session), which
  is clean deletion, NOT per-login deletion and NOT recycling.** `oidc.rs` sign-in is
  out of scope and must not be touched.
- **Deactivation (`erase:false`) is DONE** end-to-end via `account.rs::AccountDeactivate`,
  advertised through `SUPPORTED_ACTIONS` (`src/account.rs:113-124`), dispatched via
  `canonical_action` (`src/account.rs:128-138`).
- **Environment:** Redis is up on `127.0.0.1:6379` (unit + Redis tests runnable). No live
  Synapse locally → Synapse-touching paths verified by unit/contract tests + honest
  documentation of what needs a live homeserver.

### GOAL

Give siwx-oidc full, AS-grade Synapse session/account lifecycle: logout & revoke tear down
the Synapse device (not just the Redis token); a working "sign out everywhere"; and
self-service erasure (`erase:true` + Redis identity purge) and reactivation — all degrading
gracefully when no Synapse is configured, never 500, never recycling a device_id.

### INPUTS

`src/compat.rs`, `src/axum_lib.rs` (CompatState construction `:710-712`, router `:769-786`),
`src/synapse_client.rs`, `src/account.rs`, `src/db/redis.rs`, `src/db/mod.rs`;
test files `tests/e2e_msc3861.rs`, in-module `#[cfg(test)]` in `account.rs`/`synapse_client.rs`;
constraint docs above. Confirmed design decisions (user, 2026-06-09): logout/all =
tokens + delete all devices; erasure = self-service + purge webauthn cred/link; reactivation
= self-service, verify MSC3861 feasibility; revoke index = leave scan, document.

### OUTPUTS vs OUTCOMES

Writing handlers/methods is an output. The **outcomes**: after logout/revoke the Synapse
device row is gone and the session is inactive; after `/logout/all` every device + token
for the user is gone but the account stays active; after erase the account+profile+identity
artifacts are gone; after reactivate an `erase:false` account is usable again (or the
MSC3861 limitation is documented). Verify outcomes.

### BOUNDARY CONDITIONS

- **Invariants:** branch per feature, merged to local `main` only when its tests pass
  (push/PR needs explicit ask); no local Docker image builds; idempotent, best-effort
  teardown that never 500s and never reintroduces per-login deletion or device recycling;
  no secrets in logs/model context; revocation keyed on `username` (lowercased localpart),
  not raw DID.
- **Exclusions:** not touching `oidc.rs` sign-in / CAIP-122 / WebAuthn ceremony verification
  / OIDC token issuance; not building the username→token secondary index (documented as a
  TODO); not Element X / mobile.
- **Assumptions:** `get_token` reliably maps a live bearer→`TokenMetadata`; `delete_device`
  / `deactivate_user(erase=true)` / admin `PUT users {deactivated:false}` behave per the
  Synapse admin API; webauthn link/credential keys are enumerable by DID (derive did:key
  from stored P-256 pubkey, match `primary_did` on links).
- **Top risks:** (R1) reactivation may be constrained under MSC3861 (MAS owns auth) →
  verify, document honestly, never fake success. (R2) erase:true is irreversible → strong
  confirm gating, self-service only behind wallet/passkey proof. (R3) a revoked/expired
  token returns `None` from `get_token` → teardown must be idempotent for the already-gone
  case. (R4) two parallel worktrees double cargo compile load → acceptable; files are
  disjoint so no merge conflict.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | `CompatState` gains `Option<Arc<SynapseClient>>` + `server_name`, and `logout`/`revoke` look up `TokenMetadata` via `get_token` then call `delete_device` + `revoke_device_tokens` | logging out removes the Synapse device record and revokes the session's tokens, while staying idempotent and returning 200 | `get_token`→{username,device_id}; `delete_device` is the right admin call | unit/contract test: token→logout asserts `delete_device(username,device_id)` invoked + `revoke_device_tokens` called; `None` path still 200 |
| H2 | teardown only ever *deletes* (never recycles) a device_id, and sign-in (`oidc.rs`) is untouched | cross-signing is not broken (no stale-signature-over-recycled-id state) | sign-in still mints a fresh uuid each login | confirm no diff to `oidc.rs`; document the safety argument; existing sign-in tests green |
| H3 | `POST /_matrix/client/v3/logout/all` resolves bearer→username, `list_devices`→`delete_device` loop, then `revoke_all_user_tokens`, and never calls `deactivate_user` | all the user's sessions end and all devices are removed, but the account stays active | `list_devices` returns the full set; revoke scans correctly | contract test: 2 sessions → logout/all → both tokens revoked + delete_device called per device + NO deactivate_user; account still active |
| H4 | `deactivate_user` is parameterized with `erase`, and an `AccountErase` action passes `erase=true`, revokes all tokens, and purges webauthn `credential`/`link` entries for the DID | the Synapse account is erased, all tokens revoked, and the DID's passkey/link mappings removed (DID not silently re-derivable) | Synapse honors `erase:true` on admin v1 deactivate; link entries enumerable by `primary_did`; credential→did:key derivable | unit test: erase path calls deactivate with `erase:true` + `purge_identity`; redis test (live Redis): seed link/cred for DID, erase, assert gone |
| H5 | `SynapseClient::reactivate_user` (admin `PUT /_synapse/admin/v2/users/{mxid}` `{deactivated:false}`) is callable under MSC3861, and `Action::Reactivate` invokes it (erase:false only) | an `erase:false`-deactivated account becomes usable again after wallet/passkey re-auth | admin PUT works under MSC3861/MAS | contract test for the call shape; **feasibility probe** against admin API semantics — if MSC3861 blocks it, document the constraint as a verified negative result (do NOT claim success) |
| H6 | `account_erase` + `account_reactivate` are added to `SUPPORTED_ACTIONS` + `canonical_action` + `execute_action` + `ActionOutcome`, and the bare `/account` menu links them | they are advertised in OIDC discovery, dispatchable through the existing re-auth handlers, and reachable from the account-home menu | single-source-of-truth registry pattern holds | unit tests: `SUPPORTED_ACTIONS` contains both; `canonical_action` maps them; account_page renders menu + per-action confirm; `msc4191_metadata` ignored-test still green |
| H7 | `synapse_client` or `server_name` is absent | every new endpoint/action degrades to Redis-only (handlers) or clear `BadRequest` (actions) and never 500 | guard pattern reused from `account.rs` | unit tests with `synapse=None` for each new path |
| H8 | all changes land and merge | `cargo build --workspace`, `cargo fmt --all --check`, `cargo clippy`, `cargo test --bin siwx-oidc` stay green | no unrelated breakage | run all four; capture output |

## Decomposition (branch per feature, parallel worktrees, merged to main)

| Sub-goal | Branch | Hyps | Type | Model | Deps | Isolation |
|---|---|---|---|---|---|---|
| **F1+F2** Synapse-aware `CompatState`; logout/revoke device teardown; `POST /logout/all` (tokens + all devices) | `feat/synapse-session-teardown` | H1,H2,H3,H7,H8 | impl+test | opus | none | worktree A |
| **F3** `erase` param + `reactivate_user` on `SynapseClient`; `AccountErase`+`Reactivate` actions; `purge_identity` (webauthn cred/link); account-menu UI | `feat/account-lifecycle-erase-reactivate` | H4,H5,H6,H7,H8 | impl+test | opus | none | worktree B |

**Why these two groupings:** F1 and F2 both rewrite `CompatState` + `compat.rs` + the
router → same files, so one branch (avoids self-conflict). F3 touches a *disjoint* file
set (`synapse_client.rs`, `account.rs`, `db/redis.rs`) — **zero file overlap with F1+F2**,
so the two branches run fully in parallel with no merge conflict. Each agent does TDD
(red→green→refactor), commits in coherent stages, and runs `build`+`fmt`+`clippy`+unit
tests before reporting. An independent adversarial-verify agent then reviews each committed
diff against its hypotheses before I merge.

## Tasks

### Task F1+F2 — branch `feat/synapse-session-teardown`
**Hypotheses:** H1, H2, H3, H7, H8
- [ ] Add `synapse_client: Option<Arc<SynapseClient>>` + `server_name: Option<String>` to `CompatState`; wire from `AppState` at `axum_lib.rs:710-712`.
- [ ] `compat::logout`: `get_token(bearer)` → `delete_device(username,device_id,server)` best-effort → `revoke_device_tokens(username,device_id)`; idempotent on `None`; degrade to Redis-only when no Synapse; always 200 `{}`.
- [ ] `compat::revoke`: same teardown keyed off `get_token(form.token)`; idempotent; always 200 (RFC 7009).
- [ ] New `compat::logout_all`: `get_token(bearer)` → `list_devices` → `delete_device` loop (best-effort) → `revoke_all_user_tokens`; never `deactivate_user`; 200 `{}`.
- [ ] Route `POST /_matrix/client/v3/logout/all` → `compat::logout_all` with `compat_state`.
- [ ] Tests: device-teardown invoked on logout/revoke; logout/all deletes all + no deactivate; graceful degradation (synapse=None); idempotent already-gone token.
- [ ] Verify: `cargo build --workspace`, `cargo fmt --all --check`, `cargo clippy`, `cargo test --bin siwx-oidc`.

### Task F3 — branch `feat/account-lifecycle-erase-reactivate`
**Hypotheses:** H4, H5, H6, H7, H8
- [ ] `SynapseClient::deactivate_user(localpart, server_name, erase: bool)` — parameterize the hardcoded `erase:false`; update the `AccountDeactivate` caller to pass `false`.
- [ ] `SynapseClient::reactivate_user(localpart, server_name)` — admin `PUT /_synapse/admin/v2/users/{mxid}` `{deactivated:false}`; probe MSC3861 feasibility, document the finding.
- [ ] `RedisClient::purge_identity(did)` — delete `webauthn:link/*` where `primary_did==did` (+ the linked credential), and `webauthn:credential/*` whose derived `did:key` == did.
- [ ] `Action::AccountErase` → `deactivate_user(.., erase=true)` + `revoke_all_user_tokens` + `purge_identity` → `ActionOutcome::Erased`.
- [ ] `Action::Reactivate` → `reactivate_user` → `ActionOutcome::Reactivated` (erase:false only).
- [ ] Register `org.matrix.account_erase` + `org.matrix.account_reactivate` in `SUPPORTED_ACTIONS` + `canonical_action`; add `Erased`/`Reactivated` to `ActionOutcome`.
- [ ] Account page: account-home menu links for erase (danger, "irreversible / deletes all data" confirm, stronger than deactivate) + reactivate; per-action confirm + outcome JS.
- [ ] Tests: erase calls deactivate `erase:true` + purge; purge_identity removes seeded link/cred (live Redis); SUPPORTED_ACTIONS/canonical_action mapping; page render; graceful degradation; `msc4191_metadata` ignored-test still green.
- [ ] Verify: `cargo build --workspace`, `cargo fmt --all --check`, `cargo clippy`, `cargo test --bin siwx-oidc`.

## Acceptance Criteria

| # | Criterion | Hyps |
|---|----------|------|
| AC1 | logout & revoke delete the Synapse device (not just the Redis token), idempotent, 200, graceful without Synapse | H1,H2,H7 |
| AC2 | `POST /_matrix/client/v3/logout/all` revokes all tokens + deletes all devices, does NOT deactivate, account stays active | H3,H7 |
| AC3 | self-service erasure: `erase:true` + all tokens revoked + webauthn identity purged | H4,H7 |
| AC4 | self-service reactivation works for `erase:false` accounts, OR the MSC3861 constraint is documented as a verified negative result | H5,H7 |
| AC5 | erase + reactivate advertised, dispatchable, and reachable from the account-home menu; metadata test green | H6 |
| AC6 | no regression: build + fmt + clippy + unit tests green on merged `main` | H8 |
| AC7 | stale CLAUDE.md "MSC3861 device lifecycle" text reconciled to the now-true behavior | H1,H2 |
