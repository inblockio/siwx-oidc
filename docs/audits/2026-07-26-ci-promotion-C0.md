# CI promotion of the `#[ignore]` Rust integration suite (audit finding C-0)

**Date:** 2026-07-26
**Branch:** `feat/session-durability-marathon`
**Plan item:** B5 — "promote a subset of the ignored integration tests" (the
cross-cutting recommendation in the coverage matrix, cheaper than any per-feature item)
**Scope:** `.github/workflows/ci.yml`, `tests/*.rs` (classification only — no test source was modified)

---

## 1. Problem

Before this change CI ran:

| Job | What it covered |
|---|---|
| `build` | `cargo build`, `clippy`, `fmt`, `cargo test` (unit tests; Redis service only) |
| `browser-e2e` | the `e2e/browser` Playwright suite (Redis + `synapse_mock.py` + siwx-oidc) |

Meanwhile **all 43 `#[ignore]` tests in `tests/*.rs` ran nowhere automatically.**
Those 43 tests are the only protocol-level (HTTP wire) guards the repo has for
session teardown, OAuth/CAIP-122 signature binding, the race/teardown hazard
register H1–H14, and MSC4191 account management. Every assertion in them was a
manual, point-in-time claim with zero regression protection.

`grep -c '#\[ignore' tests/*.rs` reports 46; three of those hits are prose inside
doc comments (`e2e_session_teardown.rs:13`, `e2e_race_teardown.rs:11` and `:1459`).
The real attribute count is 43 (`grep -h '^#\[ignore' tests/*.rs | wc -l`).

---

## 2. Classification of all 43 tests

Categories requested: **(a)** nothing beyond Redis, **(b)** the mock Synapse stack,
**(c)** a REAL Synapse (not promotable), **(d)** a browser.

**Category (a) is empty, and (d) is empty.** Every one of the 43 drives siwx-oidc
over HTTP, so all of them need a live siwx-oidc listener — Redis alone is never
sufficient. None of them drive a browser (that is the Playwright suite's job).
The split is therefore entirely (b) vs (c).

The discriminator is objective: **(c) is exactly the set of tests that call a
`/_matrix/client/...` Client-Server endpoint on `MATRIX_HOST`.** `e2e/synapse_mock.py`
implements only `/_synapse/admin/*`, `/_synapse/mas/*` and its own `/__*` test
helpers, and 404s everything else (`do_GET`/`do_POST` fallthrough). The three
category-(b) files contain **zero** `matrix_host` / `MATRIX_HOST` references.

### (b) Mock stack — 28 tests, 25 promoted

| # | Test | File | Status |
|---|---|---|---|
| 1 | `wallet_single_reauth_covers_list_delete_profile` | `e2e_account_management.rs` | PROMOTED |
| 2 | `wallet_erase_runs_erasure_and_clears_session` | `e2e_account_management.rs` | PROMOTED |
| 3 | `account_action_without_session_is_unauthorized` | `e2e_account_management.rs` | PROMOTED |
| 4 | `account_action_csrf_mismatch_is_unauthorized` | `e2e_account_management.rs` | PROMOTED |
| 5 | `admin_token_rejection_is_legible_not_a_500_or_notfound` | `e2e_account_management.rs` | PROMOTED |
| 6 | `expired_login_signature_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 7 | `mismatched_client_id_at_token_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 8 | `unregistered_redirect_uri_at_sign_in_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 9 | `plain_pkce_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 10 | `authorize_without_pkce_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 11 | `device_approval_without_server_nonce_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 12 | `device_approval_cross_user_code_nonce_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 13 | `account_action_without_server_nonce_is_rejected` | `e2e_oauth_binding.rs` | PROMOTED |
| 14 | `account_action_operation_binding_is_enforced` | `e2e_oauth_binding.rs` | PROMOTED |
| 15 | **`device_approval_replay_is_rejected_fresh_succeeds`** | `e2e_oauth_binding.rs` | **RED — skipped (F-1)** |
| 16 | **`account_action_nonce_replay_is_rejected`** | `e2e_oauth_binding.rs` | **RED — skipped (F-1)** |
| 17 | `h1_revoke_does_not_delete_device_but_logout_does` | `e2e_race_teardown.rs` | PROMOTED |
| 18 | `h2_sequential_signins_mint_distinct_device_ids` | `e2e_race_teardown.rs` | PROMOTED |
| 19 | `rf2_rf3_rf4_introspection_active_inactive_and_auth` | `e2e_race_teardown.rs` | PROMOTED |
| 20 | `h8_concurrent_auth_code_exchange_exactly_one_wins` | `e2e_race_teardown.rs` | PROMOTED |
| 21 | `h12_device_delete_targets_only_requested_device` | `e2e_race_teardown.rs` | PROMOTED |
| 22 | `h4_concurrent_delete_different_devices_no_crosstalk` | `e2e_race_teardown.rs` | PROMOTED |
| 23 | `h10_session_cannot_act_after_terminal_action` | `e2e_race_teardown.rs` | PROMOTED |
| 24 | `h14_synapse_delete_failure_is_surfaced_not_500` | `e2e_race_teardown.rs` | PROMOTED |
| 25 | `h3_concurrent_same_device_delete_revokes_all_tokens` | `e2e_race_teardown.rs` | PROMOTED |
| 26 | `h6_deactivate_racing_refresh_no_resurrection` | `e2e_race_teardown.rs` | PROMOTED |
| 27 | `refresh_grace_window_tolerates_replay` | `e2e_race_teardown.rs` | PROMOTED |
| 28 | **`h9_device_code_approved_no_double_redemption`** | `e2e_race_teardown.rs` | **RED — skipped (F-1)** |

### (c) Real Synapse — 15 tests, none promotable

| # | Test | File | Blocking dependency |
|---|---|---|---|
| 29 | `device_code_grant_end_to_end` | `e2e_device_code.rs` | `GET {matrix}/_matrix/client/v3/devices` |
| 30 | `two_client_messaging` | `e2e_messaging.rs` | `createRoom`, `/send`, `/sync` — real rooms + federation-free homeserver |
| 31 | `full_lifecycle` | `e2e_msc3861.rs` | `/_matrix/client/v3/account/whoami` |
| 32 | `refresh_token_flow` | `e2e_msc3861.rs` | `whoami` after rotation |
| 33 | `returning_user_new_device` | `e2e_msc3861.rs` | `/_matrix/client/v3/devices` |
| 34 | `msc4191_metadata_advertised_and_forwarded` | `e2e_msc3861.rs` | `GET {matrix}/_matrix/client/v1/auth_metadata` |
| 35 | `msc4191_device_management_live` | `e2e_msc4191_live.rs` | `whoami` + live device admin |
| 36 | `msc4191_account_menu_and_deactivate_page_live` | `e2e_msc4191_live.rs` | live account lifecycle |
| 37 | `cross_signing_reset_round_trip_live` | `e2e_msc4191_live.rs` | `POST {matrix}/_matrix/client/v3/keys/device_signing/upload` |
| 38 | `cross_signing_reset_leg_a_roundtrip_completed_live` | `e2e_msc4191_live.rs` | same |
| 39 | `cross_signing_reset_stale_window_wedge_live` | `e2e_msc4191_live.rs` | same |
| 40 | `cross_signing_reset_no_master_completed_live` | `e2e_msc4191_live.rs` | same |
| 41 | `logout_deletes_ending_session_device` | `e2e_session_teardown.rs` | Synapse-side device deletion, verified via `{matrix}/_matrix/client/v3/devices` |
| 42 | `revoke_deletes_session_device` | `e2e_session_teardown.rs` | same |
| 43 | `logout_all_invalidates_all_sessions_without_deactivating` | `e2e_session_teardown.rs` | same |

Note on #34: step 1 (siwx-oidc's own discovery doc) *would* run against the mock
stack, but step 2 asserts Synapse forwards the action list verbatim to
`/_matrix/client/v1/auth_metadata`. The test's own comment says *"Left honestly red
rather than weakened: do NOT relax step 2 to make it pass."* Splitting it to harvest
step 1 was rejected — that is exactly the weakening the comment forbids.

---

## 3. What was changed

A new CI job, **`rust-e2e-mock`**, standing up the same self-contained stack
`browser-e2e` uses (Redis service + `e2e/synapse_mock.py` + the debug siwx-oidc
binary), then running three steps:

```
cargo test --test e2e_account_management -- --ignored --test-threads=1
cargo test --test e2e_oauth_binding      -- --ignored --test-threads=1 \
    --skip device_approval_replay_is_rejected_fresh_succeeds \
    --skip account_action_nonce_replay_is_rejected
cargo test --test e2e_race_teardown      -- --ignored --test-threads=1 \
    --skip h9_device_code_approved_no_double_redemption
```

Two deliberate design decisions:

**`#[ignore]` was NOT removed from any test.** The brief allowed removing it where
"clearly correct for a test that needs nothing but Redis" — no such test exists.
All 43 need a live siwx-oidc HTTP listener, and the `build` job runs a plain
`cargo test` with Redis but no listener. Un-ignoring anything would break `build`.
Explicit `-- --ignored` in a job that owns the stack is the correct lever.

**A separate job rather than extra steps on `browser-e2e`.** Both suites reset the
Synapse mock (`POST /__reset`) as their isolation mechanism, so sharing one stack
couples them; a separate job also gives independent failure attribution. Cost is
one extra stack bring-up, mostly absorbed by `Swatinem/rust-cache`.

**`--test-threads=1` is required, not a tuning choice** — it is the documented
contract in each file's header. These tests share one stack and reset global mock
state, so parallel execution makes them clobber each other.

---

## 4. Finding F-1: three tests carry a stale precondition (server is correct, tests are wrong)

**Do not "fix" these by relaxing the assertion.** The server behaviour is correct
and documented; the tests were never updated when the new-account gate landed.

Three tests fail against the mock stack. All three share one root cause, confirmed
from the server log rather than inferred:

```
INFO siwx_oidc::webauthn: rejecting new-identity (no existing account) outside login flow
     did=did:pkh:eip155:1:0x66f21a751d1734aE24f90791c4B028e7C741fCaA
WARN siwx_oidc::axum_lib: bad_request
     error=This passkey/wallet is not linked to an existing account. Create an account at sign-in first.
INFO siwx_oidc::axum_lib: response status=400
```

Each test generates a **fresh random wallet that has never signed in**, then asserts
that a correctly-nonced account action or device approval returns 200:

- `account_action_nonce_replay_is_rejected` → `POST /account/wallet` (`org.matrix.profile`)
- `device_approval_replay_is_rejected_fresh_succeeds` → `POST /device` (`action: approve`)
- `h9_device_code_approved_no_double_redemption` → `POST /device` (`action: approve`)

But `reject_if_new_identity` bars an unprovisioned identity from precisely those two
paths — per CLAUDE.md, new accounts may be created **only at the login screen**;
account re-auth and QR/device approval hard-REJECT with 400. The mock models this
faithfully: `is_localpart_available` answers from an `EXISTING_USERS` set that a
wallet only joins when provisioned, seeded via `__seed_device`, or seeded via
`__seed_user`. A fresh wallet is in none of those, so the gate fires — correctly.

**The three failing tests never seed their identity. The five
`e2e_account_management.rs` tests, which do call `mock_seed_device` first, all pass.**

Independent corroboration: the Playwright suite already got this right.
`e2e/browser/passkey-scoping.spec.mjs`, test `H9: device approval for an EXISTING
user has no Secure-Backup warning`, does the same wallet device approval and passes
— because it first calls `mockSeedUser(didToLocalpart(w.did))` under the comment
*"An EXISTING wallet account: mark its localpart taken so the new-identity gate does
NOT reject (this is a returning user linking a new device via QR)."*

**Suggested fix (not applied here — out of scope for B5, and applying it would mean
editing tests to make CI green):** add a `__seed_user` call for the wallet's
localpart before the first action in each of the three tests, mirroring the browser
suite. That restores the intended precondition (a *returning* user) without touching
a single assertion. Once done, the three `--skip` flags in `ci.yml` should be
deleted and this finding closed.

---

## 5. Verification actually performed

Environment: local isolated stack on this dev box — siwx-oidc `:19080`, Synapse mock
`:19090`, Redis DB **9** on `:6379`. Deliberately separate ports and a separate Redis
DB from the stack already running on `:18080`/`:8090`/DB 0, so nothing in flight was
disturbed. `e2e/element` was never invoked.

**`cargo build --workspace`: PASS** (`Finished dev profile ... in 29.01s`).

Full-file runs, no skips — establishing the red set:

| Suite | Result |
|---|---|
| `e2e_account_management` | `ok. 5 passed; 0 failed` |
| `e2e_oauth_binding` | `FAILED. 9 passed; 2 failed` |
| `e2e_race_teardown` | `FAILED. 11 passed; 1 failed` |

The exact command set now in `ci.yml`, run three times:

| Run | account_mgmt | oauth_binding | race_teardown |
|---|---|---|---|
| 1 (warm) | ok 5/0 (0.14s) | ok 9/0, 2 filtered (0.58s) | ok 11/0, 1 filtered (97.70s) |
| 2 (warm) | ok 5/0 (0.17s) | ok 9/0, 2 filtered (0.60s) | ok 11/0, 1 filtered (89.19s) |
| 3 (**cold**: flushed Redis DB, restarted mock + siwx-oidc) | ok 5/0 (0.10s) | ok 9/0 (0.59s) | ok 11/0 (44.42s) |

**25/25 promoted tests green on three consecutive runs, including one from a
completely cold stack. No flakiness observed** across the race suite's ~40 barrier-
synchronised concurrent rounds. Wall clock for the job's three test steps is ~45–100s,
dominated by `e2e_race_teardown`'s multi-round race loops.

`ci.yml` was parsed with `yaml.safe_load` — valid; jobs `build` (7 steps),
`rust-e2e-mock` (11), `browser-e2e` (11).

Not run: the `e2e/browser` Playwright suite (already in CI, unchanged by this work)
and `e2e/element` (explicitly out of bounds — shared singleton).

---

## 6. Residual coverage gap — what is still NOT regressed by default

Being plain about it, since a green CI is now easy to over-read:

**1. Everything requiring a real Synapse (15 tests) remains completely unguarded.**
No CI job anywhere in this repo starts a real homeserver. Concretely un-regressed:

- **The cross-signing reset state machine — all four legs** (`cross_signing_reset_*`,
  #37–40). This is the exact area of the 2026-06-12 login incident, including the
  stale-signature wedge window. It has *zero* automated coverage of any kind.
- **Synapse-side teardown side effects** (#41–43): that logout actually deletes the
  ending device, that revoke actually does *not*, and that `logout/all` clears every
  device without deactivating. The mock-level analogue `h1` is promoted and does
  guard the call-log shape, but nothing proves real Synapse honours it.
- **Token validity against a homeserver** (#29–33): that an issued `mat_` token is
  accepted by Synapse via MSC3861 introspection, survives rotation, and provisions a
  usable device. Mock tests prove siwx-oidc's half of the contract only.
- **MSC4191 metadata forwarding** (#34): that Synapse re-exposes
  `account_management_actions_supported` verbatim at `/_matrix/client/v1/auth_metadata`.
  A drift here is invisible to CI and is precisely the class of OIDC-metadata
  divergence that silently broke Element X in May (see CLAUDE.md).

**2. Three mock-level behaviours are skipped pending F-1**, of which one is a genuine
functional gap in the *Rust* suite: the RFC 8628 **device-approval success path** is
now asserted by no promoted Rust test (the other three `device_approval_*` tests all
assert rejection). Mitigation: the browser job's `H9` does cover a successful wallet
device approval end to end, so this path is not wholly unguarded — but the
double-redemption race that `h9_device_code_approved_no_double_redemption` exists to
catch (at most one token minted per device code, over 8 concurrent rounds) **is** now
unguarded. That is the most consequential single item F-1 leaves open.

**3. `e2e/element` remains outside CI entirely** — unchanged by this work, and still
tracked separately as a cross-repo harness (it needs a real Synapse, Element Web and
the Caddy edge from `../siwx-oidc-matrix-server`).

### Honest summary

C-0 is **narrowed, not closed**. What is now regression-guarded by default is
siwx-oidc's *own* protocol surface against a mock homeserver: OAuth/PKCE/redirect
binding, CAIP-122 signature freshness and nonce single-use, account-session CSRF and
fail-closed auth, the H1–H14 device/token race and teardown hazards, refresh-token
rotation with its grace window, and MSC4191 account actions. What remains unguarded
is every claim that depends on a **real Synapse agreeing** — above all the
cross-signing reset machinery. Closing that requires standing up a real homeserver in
CI, which is materially more expensive than this item and should stay a separate
plan item.

---

## ADDENDUM — 2026-07-26, F-1 CLOSED (orchestrator)

**F-1 is fixed, so the counts above are superseded: 28/43 promoted, zero skipped.**

The diagnosis in §4 was correct and is what made the fix a two-line change: the
server was right and the three tests were wrong. Each generated a fresh wallet
that had never signed in, then asserted a 200 from a path that `reject_if_new_identity`
correctly 400s (`src/webauthn.rs:134`, `rejecting new-identity (no existing account)
outside login flow`). Creating a Matrix identity is permitted **only** at the login
screen; device approval and account actions are not that screen.

**Fix applied** — a `mock_seed_user` helper in each file, posting the wallet's
localpart to the mock's `__seed_user`, called before the action under test:

| Test | File | Note |
|---|---|---|
| `device_approval_replay_is_rejected_fresh_succeeds` | `tests/e2e_oauth_binding.rs` | seeded after `new_wallet()` |
| `account_action_nonce_replay_is_rejected` | `tests/e2e_oauth_binding.rs` | seeded after `new_wallet()` |
| `h9_device_code_approved_no_double_redemption` | `tests/e2e_race_teardown.rs` | seeded **after** `mock_reset`, which clears the existing-user set |

This models the RETURNING user the tests always meant to exercise. **No assertion
was relaxed** — the replay-rejection and double-redemption assertions are untouched,
and the new-identity gate itself is unchanged. This mirrors what the Playwright suite
already did (`mockSeedUser` in `passkey-scoping.spec.mjs`, test `H9`).

**Verified against the live mock stack** (`SIWEOIDC_HOST=http://localhost:18080`,
`SYNAPSE_MOCK=http://localhost:8090` — note :8080 is a *different* container's
rootlessport, not siwx-oidc):

```
e2e_oauth_binding      11 passed; 0 failed
e2e_race_teardown      12 passed; 0 failed   (84.67s)
e2e_account_management  5 passed; 0 failed
```

The `--skip` flags are removed from `ci.yml` and the job comment no longer describes
a skip. **`h9` is back under guard** — §5's "most consequential single item F-1
leaves open" is closed. The residual gap is now exactly the 15 real-Synapse tests,
including all four cross-signing-reset legs, which remain unguarded by anything.
