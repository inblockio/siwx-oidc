# Plan: Implement MSC4191 account-management deep links (issue #5)

**Date:** 2026-06-07
**Branch:** `feature/msc4191-account-management`
**Issue:** inblockio/siwx-oidc#5 — "Feat: Siwx oidc msc4191 account management"

---

## Logic Model

### CONTEXT (verified by direct reading + live probes)

- `siwx-oidc` is the Matrix OAuth 2.0 authorization server (MSC3861 delegated auth for Synapse).
- **MSC4191 scaffolding already exists** and only `org.matrix.cross_signing_reset` is implemented:
  - `src/account.rs` — `/account` page using a **per-action re-auth model** (user proves DID via
    wallet CAIP-122 *or* passkey, then `execute_action` runs). No persistent login session.
  - `src/config.rs:55` — `account_management_uri: Option<Url>` (defaults to `{base_url}/account`).
  - `src/axum_lib.rs:150-159` — `provider_metadata` injects `account_management_uri` and
    `account_management_actions_supported` (currently `["org.matrix.cross_signing_reset"]`).
- **Propagation VERIFIED live:** `GET https://matrix.inblock.io/_matrix/client/v1/auth_metadata`
  returns `account_management_uri` + `account_management_actions_supported` **verbatim** from our
  OIDC discovery (`https://siwx-oidc.inblock.io/.well-known/openid-configuration`). Synapse forwards
  the document; **editing siwx-oidc alone satisfies AC1**. No matrix-server repo change required.
- **Device source of truth = Synapse.** `entrypoints/matrix_server.sh:27` sets
  `msc3861.admin_token = MAS_SHARED_SECRET`, so siwx-oidc's `mas_shared_secret` is also a Synapse
  **Admin API** bearer token → we can enumerate/delete devices via `/_synapse/admin/v2/...`.
- **Token store:** Redis `token/{token}` → `TokenMetadata { username, device_id, did, scope, ... }`.
  No secondary index; `RedisClient::keys_raw(pattern)` (KEYS) is available for a device_id reverse scan.
  Per CLAUDE.md token model + `introspect.rs`, `TokenMetadata.device_id` **is** the Matrix device_id.
- `did_to_localpart(did) = did.replace(':', "-").to_lowercase()` (`oidc.rs:1156`, `pub(crate)`).
- Tests: `cargo test` (needs Redis) runs module unit tests; `tests/e2e_msc3861.rs` is live/env-gated
  (manual). CI (`.github/workflows/ci.yml`): `cargo build`, `cargo clippy`, `cargo fmt --check`, `cargo test`.

### GOAL (one sentence)

Implement the full MSC4191 deep-link action set in siwx-oidc — `profile`, `devices_list`,
`device_view`, `device_delete` (plus the `session_*` aliases and the existing `cross_signing_reset`) —
so Matrix clients open `/account?action=…[&device_id=…]` without "Unsupported action", with every
implemented action advertised in metadata and device sign-out actually revoking the OAuth session.

### INPUTS → ACTIVITIES (files to change)

| Input file | Activity |
|---|---|
| `src/account.rs` | `Action` enum + `canonical_action()` (alias normalization) + `SUPPORTED_ACTIONS` (single source of truth); `execute_action` returns typed `ActionOutcome`; thread `device_id`; page render + JS render outcomes |
| `src/synapse_client.rs` | `DeviceInfo`, `list_devices`, `get_device`, `delete_device` via Synapse Admin API (`mas_shared_secret` bearer) |
| `src/db/redis.rs` | `revoke_device_tokens(did, device_id) -> usize` (scan `token/*`, delete matching) |
| `src/axum_lib.rs` | metadata actions array sourced from `account::SUPPORTED_ACTIONS`; account handlers thread `device_id` + redis + `matrix_server_name` + synapse |
| `src/oidc.rs` | extract a **testable** metadata builder so AC1 is unit-tested (no behaviour change) |

### BOUNDARY CONDITIONS

**Out of scope:** profile *editing* (read-only identity view for v1); `id_token_hint` silent SSO
(always re-auth, matching existing flow); any change to the `siwx-oidc-matrix-server` repo;
device management in standalone mode (no Synapse) — degrade with a clear message.

**Invariants:** existing `cross_signing_reset` flow unchanged; standalone mode (no Synapse / no
`matrix_server_name`) never panics; `cargo fmt`/`clippy`/`test` green; no secrets logged; **one**
canonical action list shared between the implementation and the advertised metadata.

**Top risks:**
1. Synapse Admin API rejects `mas_shared_secret` as admin bearer (mitigation: entrypoint sets
   `admin_token=MAS_SHARED_SECRET`; verified by config — final confirm is the manual live e2e).
2. Cross-user device access (mitigation: Admin queries are scoped to the **authenticated** user's
   mxid; revocation only deletes tokens whose `did` matches the authed DID **and** device_id matches).
3. KEYS scan cost for revocation (acceptable at this scale; documented, no silent cap — `log` count).
4. Re-auth replay (no server nonce) — pre-existing for the equally-destructive `cross_signing_reset`;
   accepted as-is, noted, not widened.

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | We expand `account_management_actions_supported` to the full superset, sourced from `account::SUPPORTED_ACTIONS` | OIDC discovery **and** Synapse `auth_metadata` advertise all actions (AC1) | Synapse forwards verbatim (**verified live**) | Unit test on extracted metadata builder asserts array ⊇ {profile, devices_list, device_view, device_delete, cross_signing_reset, sessions_list, session_view, session_end}; manual live `curl auth_metadata` post-deploy |
| H2 | `canonical_action()` maps `session_*`→`device_*` and the supported set is one shared const | Aliases behave identically; advertised set == implemented set | — | Unit: `canonical_action("org.matrix.session_view")==DeviceView`, etc.; `SUPPORTED_ACTIONS` contains both generations |
| H3 | The page + wallet/passkey POST endpoints thread `device_id` (query→request→`execute_action`) | `device_view`/`device_delete` receive their target device | — | Unit: `account_page` embeds `data-device-id`; request structs deserialize `device_id`; handler passes it through |
| H4 | `SynapseClient::list_devices`/`get_device` call `GET /_synapse/admin/v2/users/{mxid}/devices` with `mas_shared_secret` bearer | `devices_list`/`device_view` return the user's real devices | `admin_token == mas_shared_secret` grants Admin API | Unit: mxid + URL construction, encoding, trailing-slash; live e2e (manual) |
| H5 | `device_delete` (a) deletes the Synapse device via Admin API **and** (b) `revoke_device_tokens(did, device_id)` deletes matching Redis tokens | The device's OAuth session is revoked → introspection inactive (AC3) | `TokenMetadata.device_id == Matrix device_id` | Unit (Redis): seed tokens, revoke by device_id, assert matching gone + others intact; live e2e introspect `{active:false}` (manual) |
| H6 | Foreign/missing `device_id` and unknown actions return `BadRequest`/friendly responses | No 500/panic on bad input | — | Unit: foreign device_id→not-found error; unknown action→BadRequest; `device_view` without device_id→BadRequest |
| H7 | Device actions detect absent `synapse_client`/`matrix_server_name` and return a clear error | Standalone mode + existing `cross_signing_reset` preserved | — | Unit: execute returns clear `BadRequest` when Synapse absent; all existing `account.rs` tests still pass |
| H8 | The page JS renders each `ActionOutcome` (`devices`, `device`, `profile`, `deleted`, `completed`) | `device_view` shows detail with no "Unsupported action" (AC2) | — | Unit: page/JS contains render hooks + per-action titles; manual browser screenshot (boundary: live) |

---

## Tasks (staged TDD on the branch)

> **Execution strategy:** the change is one tightly-coupled feature spanning shared types across
> `account.rs`/`axum_lib.rs`/`synapse_client.rs`; parallel worktrees would only create merge
> conflicts (parallelism was already spent on exploration). Execute as **sequential red-green-refactor
> stages on the branch**, one commit per stage. Dependency order: T1 → (T2 ∥ T3) → T4 → T5 → T6.

### Task 1: Action model + metadata (single source of truth)
**Hypotheses:** H1, H2
- [ ] `account.rs`: `Action` enum {Profile, DevicesList, DeviceView, DeviceDelete, CrossSigningReset}; `canonical_action(&str)->Option<Action>` (incl. `session_*` aliases); `pub const SUPPORTED_ACTIONS: &[&str]` (full superset, both generations).
- [ ] `oidc.rs`: extract `pub fn provider_metadata_json(base_url, account_management_uri: Option<&Url>) -> Result<Value>` containing all current custom-field augmentation; `axum_lib::provider_metadata` becomes a thin wrapper. Source the actions array from `account::SUPPORTED_ACTIONS`.
- [ ] Tests (red→green): metadata builder includes all four real actions + aliases + cross_signing_reset; `canonical_action` alias mapping; `SUPPORTED_ACTIONS` membership.
- Commit: `feat(account): MSC4191 action model + advertise full action set in metadata`

### Task 2: Synapse Admin API device methods
**Hypotheses:** H4, H5
- [ ] `synapse_client.rs`: `DeviceInfo { device_id, display_name, last_seen_ts, last_seen_ip }` (serde, tolerant of nulls); `list_devices(localpart, server_name)->Vec<DeviceInfo>`; `get_device(localpart, device_id, server_name)->Option<DeviceInfo>`; `delete_device(localpart, device_id, server_name)`. mxid `@{localpart}:{server_name}`, URL-encoded; `mas_shared_secret` bearer.
- [ ] Tests: mxid/URL construction + encoding; trailing-slash handling (no network).
- Commit: `feat(synapse): admin-API device list/get/delete for MSC4191`

### Task 3: Redis OAuth-session revocation by device
**Hypotheses:** H5
- [ ] `db/redis.rs`: `revoke_device_tokens(&self, did: &str, device_id: &str) -> Result<usize>` — `keys_raw("token/*")`, deserialize, delete where `did==` && `device_id==`; return count; `log`/`debug` the count (no silent cap).
- [ ] Test (Redis): seed matching + non-matching tokens, revoke, assert only matching removed, count correct.
- Commit: `feat(db): revoke_device_tokens — revoke OAuth session by device_id`

### Task 4: Account action routing + outcomes
**Hypotheses:** H3, H5, H6, H7
- [ ] `account.rs`: `#[serde(tag="kind")] enum ActionOutcome { Completed, Profile{…}, Devices{devices}, Device{device}, Deleted{device_id} }`; `execute_action(action, device_id, did, synapse, redis, server_name) -> Result<ActionOutcome>` implementing all actions; `AccountWalletRequest`/passkey-finish gain optional `device_id`; both return `{status, action, result}`.
- [ ] `axum_lib.rs`: account handlers thread `device_id` + `redis_client` + `matrix_server_name`.
- [ ] Error paths: missing device_id (view/delete)→BadRequest; foreign device_id→not-found; unknown action→BadRequest; no Synapse / no server_name→clear BadRequest.
- [ ] Tests: alias dispatch; missing/foreign device_id; unknown action; Synapse-absent.
- Commit: `feat(account): route profile/devices_list/device_view/device_delete (+aliases)`

### Task 5: Account page render + client JS
**Hypotheses:** H8
- [ ] `account.rs` `account_page`: per-action title/subtitle; embed `data-device-id`; JS renders each `ActionOutcome` kind (device list with per-device "Manage"→`device_view` link; device detail with "Sign out this device"→`device_delete`; profile identity; deleted confirmation + "Back to devices"); generalize the hard-coded "Encryption keys reset" terminal.
- [ ] Tests: page embeds `data-device-id`; contains render hooks + correct titles for each action; XSS sanitization retained for device_id.
- Commit: `feat(account): render MSC4191 outcomes (devices, detail, profile, signed-out)`

### Task 6: Verify + audit
- [ ] `cargo fmt --check`, `cargo clippy` (warnings clean), `cargo build`, `cargo test` (Redis up via `test/docker-compose.yml`).
- [ ] Update `tests/e2e_msc3861.rs` with manual (env-gated) MSC4191 assertions (metadata array; device_view; revoke→introspect inactive).
- [ ] Phase 3 audit: hypothesis trace (evidence per H) + acceptance-criteria table. Merge to local `main` if green.

### Acceptance criteria → hypotheses
| # | Criterion | Hypotheses |
|---|---|---|
| AC1 | Metadata advertises uri + actions ⊇ {device_view, device_delete, devices_list, profile} (+ session_* aliases) | H1, H2 |
| AC2 | Element "Manage this session" opens device detail, no "Unsupported action" | H2, H3, H4, H8 |
| AC3 | Signing a device out revokes its access (C-S API rejected) | H5 |
