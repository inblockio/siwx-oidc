# MSC4191 account management: Element Web fix + real account deactivation

Date: 2026-06-07
Branch: `fix/msc4191-account-menu-deactivate`
Repo: `~/siwx-oidc`

## Context

The `/account` page reads `ACTION` from the `?action=` query param and the wallet/passkey
buttons POST that string to `/account/wallet`, which validates via `canonical_action()`
BEFORE the signature (`src/account.rs:290-291`). Element Web's generic "Manage account"
opens the bare `account_management_uri` with NO action param, so the page renders but the
re-auth POSTs `action:""` -> `canonical_action("")` -> `None` -> `400 "Unsupported action: "`.
Element-X works because it deep-links specific supported actions. A live production probe
confirmed only `action:""` and `action:"org.matrix.account_deactivate"` yield "Unsupported action:".

## Goal

Make MSC4191 account management work in Element Web (fix the bare/empty-action dead end with
a proper account-home menu), and implement real account deactivation for
`org.matrix.account_deactivate`, without regressing the 8 existing actions or Element-X.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | the bare/empty-action `/account` renders a navigation menu (links to profile, devices_list, account_deactivate) instead of dead-end auth buttons | Element Web's "Manage account" (bare URI) yields a usable page and never POSTs an empty action -> no 400 | Element Web opens the bare account_management_uri | unit test: `account_page("")` contains menu hrefs and no wallet POST button; live `GET /account` HTML contains the menu |
| H2 | an empty-action POST returns "Missing action" (not "Unsupported action: ") | a stray empty POST is clearly diagnosable | n/a | unit test on action parsing for `""`; live `POST /account/wallet {action:""}` body == "Missing action" |
| H3 | `org.matrix.account_deactivate` is added to `SUPPORTED_ACTIONS` and `canonical_action` | OIDC discovery advertises it and POST handlers accept it (validation passes through to signature) | discovery reads `SUPPORTED_ACTIONS` (oidc.rs:281-282) | `supported_actions_cover_acceptance_criteria` green; live discovery includes it; live POST with dummy sig -> "Verification error" not "Unsupported action" |
| H4 | `execute_action(AccountDeactivate)` calls `synapse.deactivate_user` + `revoke_all_user_tokens` | a re-authenticated user is deactivated in Synapse and all their tokens revoked | MAS shared secret doubles as admin_token; `/_synapse/admin/v1/deactivate/{mxid}` available | unit tests: `deactivate_user` URL/mxid encoding, `revoke_all_user_tokens` removes all the user's tokens (Redis-gated). NOT run against prod |
| H5 | deactivation requires synapse + server_name via `require_synapse`/`require_server_name` | standalone (no-Synapse) deployments return a clear BadRequest, never 500 | n/a | unit test: `execute_action(AccountDeactivate, synapse=None)` -> BadRequest |
| H6 | the `GET /account?action=org.matrix.account_deactivate` page shows a permanent-deactivation confirmation gating the auth buttons | users get an explicit irreversible-action warning before re-auth | n/a | unit test: page contains "permanently"/"cannot be undone" + confirm gate; live GET |
| H7 | the change does not alter the 8 existing actions' dispatch/rendering | no regression to existing actions / login / Element-X | n/a | existing account.rs + oidc tests pass; live probe of existing actions still yields "Verification error" not "Unsupported action" |

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|-----------|-----------|
| AC1 | Bare `/account` (no action) renders a working account-home menu; Element Web "Manage account" no longer dead-ends | H1 |
| AC2 | OIDC discovery `account_management_actions_supported` includes `org.matrix.account_deactivate` | H3 |
| AC3 | `/account?action=org.matrix.account_deactivate` shows the permanent-deactivation confirmation | H6 |
| AC4 | `POST /account/wallet` with `account_deactivate` passes action validation; real deactivation wired to Synapse admin API + token revocation | H3, H4 |
| AC5 | Empty-action POST returns "Missing action" | H2 |
| AC6 | No regression to the 8 existing actions / login / Element-X | H7, H5 |
| AC7 | Build + clippy + fmt + test suite green | all |

## Design (single source of truth preserved)

- `Action::AccountDeactivate` added to the enum; `canonical_action` maps `org.matrix.account_deactivate`.
- `SUPPORTED_ACTIONS` gains `"org.matrix.account_deactivate"` (auto-advertised via oidc.rs:281-282).
- `ActionOutcome::Deactivated` (kind `"deactivated"`) -> terminal "Your account has been deactivated".
- `execute_action(AccountDeactivate)`: `require_synapse` + `require_server_name` -> `synapse.deactivate_user(localpart, server)` -> `db.revoke_all_user_tokens(localpart)` -> `Deactivated`.
- `synapse_client::deactivate_user`: `POST /_synapse/admin/v1/deactivate/{mxid}` `{"erase": false}` (mirrors `delete_device`).
- `redis::revoke_all_user_tokens(username)`: scan token keyspace, delete every entry whose `username` matches (refactor shared with `revoke_device_tokens` via a predicate helper for DRY).
- `account_page`: action-keyed auth-section. Empty action -> menu (links only). `account_deactivate` -> danger warning + confirm-checkbox-gated auth buttons. Other actions -> unchanged.
- Both POST handlers: empty action -> "Missing action"; unknown -> "Unsupported action: {x}" (factor a small `parse_action` helper).

## Boundary conditions

- Irreversible: tests must NOT call real deactivation against production. Redis/Synapse calls are unit-tested with mocks/encoding checks only.
- No em dashes in code or comments.
- Keep `SUPPORTED_ACTIONS` as the single source of truth for both discovery and dispatch.
