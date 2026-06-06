# MSC4191 `org.matrix.profile` Account-Management Action — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make siwx-oidc handle the MSC4191 `org.matrix.profile` deep-link action so Element X "Manage profile" stops returning `Unsupported action: org.matrix.profile`, and advertise it in OIDC discovery — driven by a single source-of-truth action list.

**Architecture:** The `/account` page and re-auth handlers (`account.rs`) and the OIDC discovery metadata (`axum_lib.rs`) currently maintain the supported-action list in **two** places, which drift (the root cause of issue #4: `org.matrix.profile` is in neither). Collapse them to one `pub const SUPPORTED_ACTIONS` in `account.rs` that both the handlers and the metadata endpoint consume. Add `org.matrix.profile` as a non-Synapse, read-only "reveal your DID identity" action that reuses the existing wallet/passkey re-auth plumbing.

**Tech Stack:** Rust, Axum, serde/serde_json, webauthn-rs, aqua-auth (CAIP-122), inline HTML/CSS/JS in `account.rs`.

**Issue:** inblockio/siwx-oidc#4 (also advances #5, which remains out of scope here).

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | `SUPPORTED_ACTIONS` is the single source in `account.rs` and both `is_supported_action` and the metadata handler derive from it | Advertised list and enforced list cannot drift | serde_json serializes `&[&str]` as a JSON array | `cargo test --bin siwx-oidc account::` + grep shows `axum_lib.rs` references `account::SUPPORTED_ACTIONS` |
| H2 | `org.matrix.profile` is added to `SUPPORTED_ACTIONS` | OIDC discovery `account_management_actions_supported` contains `org.matrix.profile` | discovery doc is the contract Synapse re-exposes via MSC2965 | unit test asserts `SUPPORTED_ACTIONS` contains profile + cross_signing_reset |
| H3 | `execute_action` has an `ACTION_PROFILE => Ok(())` arm requiring no Synapse | Re-auth for profile succeeds with no `Unsupported action` and no Synapse client | profile is a read-only identity view, no homeserver call needed | `#[tokio::test]` `execute_action(profile, did, None).await == Ok` |
| H4 | `account_page` has a dedicated profile branch | `GET /account?action=org.matrix.profile` renders an identity view, not the generic "Authenticate to continue" nor an error | inline HTML render path unchanged | unit test `account_page_renders_profile` |
| H5 | `account_wallet`/`account_passkey_finish` echo the verified DID in `AccountActionResponse.did`, and the JS shows it for profile | A user who verifies sees their DID | DID is the user's own, echoing is not a leak | struct serialization unit test + code review of JS branch |
| H6 | profile is advertised AND handled server-side | Element X "Manage profile" stops returning `Unsupported action: org.matrix.profile` | Element X reads `account_management_actions_supported`; Synapse/Caddy re-expose discovery correctly | server-contract tests pass; live Element X check is a deployment boundary (cannot run here) |

---

## Acceptance Criteria

| # | Criterion | Verifies |
|---|-----------|----------|
| AC1 | `GET /account?action=org.matrix.profile` presents a profile/identity view and never yields `Unsupported action` | H3, H4 |
| AC2 | OIDC discovery `account_management_actions_supported` includes `org.matrix.profile` | H1, H2 |
| AC3 | Advertised and enforced action lists share one source (no drift) | H1 |
| AC4 | All pre-existing `account.rs` and `oidc.rs` tests still pass (no regression to cross_signing_reset) | regression |

---

## Boundary Conditions

**Out of scope (do NOT implement here):**
- `org.matrix.device_view` / `device_delete` / `devices_list` and the `session_*` aliases — these need device enumeration and are issue #5.
- ENS resolution / display-name in the profile view (extra async dependency; defer).
- Editing profile (display name / avatar) — those live in Synapse / the Matrix client, not in siwx-oidc.
- `device_id` query-param handling on `/account` (profile needs none).
- Synapse `homeserver.yaml` / Caddy re-exposure of `auth_metadata` — a deployment verification, not code in this repo.

**Invariants:**
- The `org.matrix.cross_signing_reset` flow, its UI copy, and its tests must remain unchanged in behavior.
- `AccountActionResponse.did` is additive and must not break the existing cross_signing_reset JS (which ignores the body).
- Only advertise actions we actually implement (advertising an unhandled action would re-create this exact bug).

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/account.rs` | Action constants, `is_supported_action`, `execute_action`, response type, page render, JS | Modify |
| `src/axum_lib.rs` | OIDC discovery `provider_metadata` handler | Modify (1 line) |

---

## Task 1: Single source of truth for supported actions

**Files:**
- Modify: `src/account.rs:49-55` (constants + `is_supported_action`)
- Test: `src/account.rs` (tests module)

- [ ] **Step 1: Write the failing test** (add to `mod tests`)

```rust
#[test]
fn supported_actions_single_source() {
    assert!(SUPPORTED_ACTIONS.contains(&ACTION_PROFILE));
    assert!(SUPPORTED_ACTIONS.contains(&ACTION_CROSS_SIGNING_RESET));
    // Every advertised action must be enforced as supported.
    for a in SUPPORTED_ACTIONS {
        assert!(is_supported_action(a), "advertised but unsupported: {a}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin siwx-oidc account::tests::supported_actions_single_source`
Expected: FAIL — `ACTION_PROFILE` / `SUPPORTED_ACTIONS` not defined.

- [ ] **Step 3: Replace the constants + validator** (`src/account.rs`, the `-- Supported actions --` section)

```rust
// -- Supported actions --------------------------------------------------------

pub const ACTION_PROFILE: &str = "org.matrix.profile";
pub const ACTION_CROSS_SIGNING_RESET: &str = "org.matrix.cross_signing_reset";

/// Single source of truth for the MSC4191 account-management actions this
/// server implements. Advertised verbatim in OIDC discovery
/// (`account_management_actions_supported`, see `axum_lib::provider_metadata`)
/// AND enforced by the account action handlers. Keeping advertisement and
/// enforcement on the same list makes them impossible to drift — the drift
/// between them was the root cause of issue #4.
pub const SUPPORTED_ACTIONS: &[&str] = &[ACTION_PROFILE, ACTION_CROSS_SIGNING_RESET];

fn is_supported_action(action: &str) -> bool {
    SUPPORTED_ACTIONS.contains(&action)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin siwx-oidc account::tests::supported_actions_single_source`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "refactor(account): single source of truth for MSC4191 supported actions"
```

---

## Task 2: `execute_action` handles `org.matrix.profile` (no Synapse)

**Files:**
- Modify: `src/account.rs:67-95` (`execute_action`)
- Test: `src/account.rs` (tests module)

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn execute_action_profile_is_noop_without_synapse() {
    // profile is a read-only identity view: it must succeed with no Synapse client.
    let r = execute_action(ACTION_PROFILE, "did:pkh:eip155:1:0xabc", None).await;
    assert!(r.is_ok(), "profile action must succeed without Synapse");
}

#[tokio::test]
async fn execute_action_rejects_unknown() {
    let r = execute_action("org.matrix.device_view", "did:pkh:eip155:1:0xabc", None).await;
    assert!(r.is_err(), "unimplemented actions must still be rejected");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin siwx-oidc account::tests::execute_action_profile`
Expected: FAIL — profile falls through to the `_ => Unsupported action` arm.

- [ ] **Step 3: Add the profile arm** (in `execute_action`, before the `_ =>` fallback)

```rust
        ACTION_PROFILE => {
            // Read-only identity view: re-auth already proved DID ownership in the
            // caller; there is no server-side mutable profile to change. The caller
            // echoes the verified DID back to the page for display.
            info!(did = %did, "profile viewed via account management page");
            Ok(())
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin siwx-oidc account::tests::execute_action`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "feat(account): handle org.matrix.profile as a no-op identity action"
```

---

## Task 3: Echo verified DID in the action response

**Files:**
- Modify: `src/account.rs:43-47` (`AccountActionResponse`), `:140-144` (`account_wallet` return), `:173-177` (`account_passkey_finish` return)
- Test: `src/account.rs` (tests module)

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn action_response_serializes_did_and_omits_when_absent() {
    let with = AccountActionResponse {
        status: "completed".into(),
        action: ACTION_PROFILE.into(),
        did: Some("did:pkh:eip155:1:0xabc".into()),
    };
    let j = serde_json::to_string(&with).unwrap();
    assert!(j.contains("did:pkh:eip155:1:0xabc"));

    let without = AccountActionResponse {
        status: "completed".into(),
        action: ACTION_CROSS_SIGNING_RESET.into(),
        did: None,
    };
    let j2 = serde_json::to_string(&without).unwrap();
    assert!(!j2.contains("\"did\""), "did must be omitted when None");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin siwx-oidc account::tests::action_response_serializes`
Expected: FAIL — `AccountActionResponse` has no `did` field.

- [ ] **Step 3: Add the field and populate it**

In the struct:

```rust
#[derive(Serialize)]
pub struct AccountActionResponse {
    pub status: String,
    pub action: String,
    /// The verified DID, echoed back so a read-only action (e.g. profile) can
    /// display the caller's identity. Omitted for actions that don't need it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}
```

In `account_wallet`, replace the success return:

```rust
    execute_action(&req.action, &req.did, synapse_client).await?;

    Ok(AccountActionResponse {
        status: "completed".to_string(),
        did: Some(req.did.clone()),
        action: req.action,
    })
```

In `account_passkey_finish`, replace the success return:

```rust
    execute_action(&req.action, &resp.did, synapse_client).await?;

    Ok(AccountActionResponse {
        status: "completed".to_string(),
        did: Some(resp.did),
        action: req.action,
    })
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin siwx-oidc account::tests::action_response_serializes`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "feat(account): echo verified DID in account action response"
```

---

## Task 4: Profile branch in the rendered page

**Files:**
- Modify: `src/account.rs:189-199` (title/subtitle selection in `account_page`)
- Test: `src/account.rs` (tests module)

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn account_page_renders_profile() {
    let html = account_page(
        AccountPageQuery {
            action: Some("org.matrix.profile".to_string()),
            id_token_hint: None,
        },
        "https://siwx.example.com",
    )
    .0;
    assert!(html.contains("Your identity"));
    assert!(html.contains(r#"data-action="org.matrix.profile""#));
    // Must NOT fall through to the generic "Authenticate to continue" copy.
    assert!(!html.contains("Account action"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin siwx-oidc account::tests::account_page_renders_profile`
Expected: FAIL — profile currently hits the generic `else` branch ("Account action").

- [ ] **Step 3: Add the profile branch** (in the `let (title, subtitle) = ...` chain)

```rust
    let (title, subtitle) = if action == ACTION_CROSS_SIGNING_RESET {
        (
            "Reset encryption keys",
            "Authenticate to confirm resetting your cross-signing keys. \
             This allows your client to set up new encryption keys.",
        )
    } else if action == ACTION_PROFILE {
        (
            "Your identity",
            "Verify with your wallet or passkey to view the decentralized \
             identity (DID) linked to this account.",
        )
    } else if action.is_empty() {
        ("Account", "Manage your account settings.")
    } else {
        ("Account action", "Authenticate to continue.")
    };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin siwx-oidc account::tests::account_page_renders_profile`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "feat(account): render identity view for org.matrix.profile action"
```

---

## Task 5: Action-aware success message in the page JS

**Files:**
- Modify: `src/account.rs` `ACCOUNT_PAGE_JS` — `authWallet` success branch (~line 523) and `authPasskey` success branch (~line 575)

- [ ] **Step 1: Update `authWallet` success handling**

Replace the `if (r.ok) { ... } else { ... }` block in `authWallet`:

```javascript
    if (r.ok) {
      if (ACTION === 'org.matrix.profile') {
        const data = await r.json().catch(() => ({}));
        showTerminal('Your identity', data.did || 'Verified.');
      } else {
        showTerminal('Encryption keys reset', 'Your client can now set up new encryption keys. You can close this page.');
      }
    } else {
      const t = await r.text();
      showStatus(t || 'Action failed.');
    }
```

- [ ] **Step 2: Update `authPasskey` success handling**

Replace the `if (finishR.ok) { ... } else { ... }` block in `authPasskey`:

```javascript
    if (finishR.ok) {
      if (ACTION === 'org.matrix.profile') {
        const data = await finishR.json().catch(() => ({}));
        showTerminal('Your identity', data.did || 'Verified.');
      } else {
        showTerminal('Encryption keys reset', 'Your client can now set up new encryption keys. You can close this page.');
      }
    } else {
      const t = await finishR.text();
      showStatus(t || 'Passkey authentication failed.');
    }
```

- [ ] **Step 3: Add a render-assertion test** (the JS is a static string, so assert its presence)

```rust
#[test]
fn account_page_js_shows_did_for_profile() {
    let html = account_page(
        AccountPageQuery { action: Some("org.matrix.profile".to_string()), id_token_hint: None },
        "https://siwx.example.com",
    )
    .0;
    assert!(html.contains("ACTION === 'org.matrix.profile'"));
    assert!(html.contains("data.did"));
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --bin siwx-oidc account::tests`
Expected: PASS (all account tests).

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "feat(account): show verified DID after profile re-auth in page JS"
```

---

## Task 6: Advertise the single-source action list in OIDC discovery

**Files:**
- Modify: `src/axum_lib.rs:158-159` (`provider_metadata`)

- [ ] **Step 1: Replace the hardcoded array**

```rust
    value["account_management_actions_supported"] =
        serde_json::json!(account::SUPPORTED_ACTIONS);
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build --bin siwx-oidc`
Expected: clean compile (`account` is already imported at `axum_lib.rs:37`).

- [ ] **Step 3: Verify the wiring**

Run: `grep -n "account_management_actions_supported" src/axum_lib.rs`
Expected: the line now references `account::SUPPORTED_ACTIONS`, no literal `"org.matrix.cross_signing_reset"` array remains.

- [ ] **Step 4: Commit**

```bash
git add src/axum_lib.rs
git commit -m "fix(oidc): advertise org.matrix.profile via single-source action list (issue #4)"
```

---

## Task 7: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build the whole workspace**

Run: `cargo build --workspace`
Expected: clean.

- [ ] **Step 2: Run the binary's unit tests that need no Redis**

Run: `cargo test --bin siwx-oidc account::`
Expected: all account tests PASS.

- [ ] **Step 3: Run the metadata test (no Redis)**

Run: `cargo test --bin siwx-oidc oidc::tests::discovery_metadata`
Expected: PASS (no regression to base discovery doc).

- [ ] **Step 4: Clippy on the binary**

Run: `cargo clippy --bin siwx-oidc -- -D warnings`
Expected: no new warnings.

- [ ] **Step 5: rustfmt**

Run: `cargo fmt --all && git diff --stat`
Expected: no churn beyond touched files.

---

## Self-Review notes

- **Spec coverage:** AC1 → Tasks 2+4; AC2 → Tasks 1+6; AC3 → Tasks 1+6; AC4 → Task 7.
- **Type consistency:** `ACTION_PROFILE`, `ACTION_CROSS_SIGNING_RESET`, `SUPPORTED_ACTIONS`, `AccountActionResponse.did` used consistently across Tasks 1-6.
- **No placeholders:** every code step shows full code.
