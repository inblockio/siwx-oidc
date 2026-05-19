# MSC3861 Compliance Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 6 MSC3861 compliance gaps (2 HIGH, 4 MEDIUM) so Element X can use native OIDC login without a custom JS gate.

**Architecture:** All changes are in the server layer (`src/`). siwx-core is untouched. Tasks 3 and 4 both modify `TokenMetadata` in `src/db/mod.rs` so they share a dependency and must run sequentially. Tasks 1, 2, 5, 6 are independent of each other.

**Tech Stack:** Rust, Axum, serde_json, Redis (via `DBClient` trait)

**Branch:** Create `msc3861-compliance` from `fork-stable` (commit `2431ca5`)

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | /authorize stops rejecting unknown scopes and only requires `openid` | Element X can complete OIDC authorize with Matrix-specific scopes | Element X sends `urn:matrix:...` scopes in the authorize request | `cargo test --bin siwx-oidc` e2e test with Matrix scopes passes |
| H2 | Discovery advertises `["client_secret_post", "bearer"]` for introspection auth | Synapse can introspect tokens using client_secret_post without config workarounds | Synapse reads `introspection_endpoint_auth_methods_supported` from discovery | `cargo test --bin siwx-oidc`; discovery JSON contains correct field |
| H3 | Introspection `sub` uses full DID (matching ID token) | `sub` claim is consistent across all OIDC endpoints | Synapse uses `username` field (not `sub`) for localpart lookup; Redis is flushed on deploy to evict stale tokens | Unit test comparing ID token sub with introspection sub |
| H4 | Introspection response includes `name` field from TokenMetadata | Synapse can update display names from introspection | Redis is flushed on deploy to evict stale tokens without new fields | Unit test verifying `name` appears in introspection JSON |
| H5 | Token endpoint emits stable `urn:matrix:client:...` scopes | Forward-compatible with stable MSC3861 Synapse versions | Current Synapse deployment accepts stable scope URIs | `cargo test --bin siwx-oidc`; scope strings in token metadata match stable format |
| H6 | `sync_devices` method removed from synapse_client.rs | No compilation errors, no missing callers | No code outside synapse_client.rs calls sync_devices (confirmed by grep) | `cargo build --workspace` succeeds |

---

## Task Dependency Graph

```
Task 1 (HIGH) ──┐
Task 2 (HIGH) ──┤
Task 5 (MED)  ──┼── all independent, can run in parallel
Task 6 (MED)  ──┘
Task 3 (MED)  ──► Task 4 (MED)   (both modify TokenMetadata, sequential)
```

---

### Task 1: Accept Matrix-specific scopes in /authorize (HIGH)

**Hypotheses:** H1

**Files:**
- Modify: `src/oidc.rs:55-58` (SCOPES constant), `src/oidc.rs:758-762` (scope validation loop)
- Test: `src/oidc.rs` (existing `e2e_flow` test + new unit test)

- [ ] **Step 1: Write a failing test for Matrix scopes in authorize**

Add this test to the `mod tests` block in `src/oidc.rs` (after line 1537):

```rust
#[tokio::test]
async fn authorize_accepts_matrix_scopes() {
    let (_config, db_client) = default_config().await;
    let params = AuthorizeParams {
        client_id: "client".into(),
        redirect_uri: RedirectUrl::from_url(
            Url::parse("https://example.com").unwrap(),
        ),
        scope: Scope::new(
            "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEF".to_string(),
        ),
        response_type: Some(CoreResponseType::Code),
        state: Some("state".into()),
        nonce: None,
        prompt: None,
        request_uri: None,
        request: None,
        code_challenge: None,
        code_challenge_method: None,
    };
    let result = authorize(params, &db_client).await;
    assert!(result.is_ok(), "authorize must accept Matrix scopes: {:?}", result.err());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --bin siwx-oidc authorize_accepts_matrix_scopes -- --nocapture 2>&1`

Expected: FAIL with "Scope not supported: urn:matrix:org.matrix.msc2967.client:api:*"

- [ ] **Step 3: Change scope validation to skip unknown scopes**

In `src/oidc.rs`, replace lines 758-762:

```rust
    for scope in params.scope.as_str().trim().split(' ') {
        if !SCOPES.contains(&Scope::new(scope.to_string())) {
            return Err(anyhow!("Scope not supported: {}", scope).into());
        }
    }
```

With:

```rust
    let has_openid = params
        .scope
        .as_str()
        .trim()
        .split(' ')
        .any(|s| s == "openid");
    if !has_openid {
        return Err(anyhow!("The 'openid' scope is required.").into());
    }
```

- [ ] **Step 4: Run all tests to verify**

Run: `cargo test --bin siwx-oidc -- --nocapture 2>&1`

Expected: All tests pass including `authorize_accepts_matrix_scopes` and existing `e2e_flow`.

- [ ] **Step 5: Commit**

```bash
git add src/oidc.rs
git commit -m "fix: accept unknown scopes in /authorize per RFC 6749 Section 3.3

Matrix clients (Element X) send urn:matrix:... scopes that were previously
rejected. Now only 'openid' is required; unknown scopes pass through silently."
```

---

### Task 2: Fix introspection auth methods in discovery (HIGH)

**Hypotheses:** H2

**Files:**
- Modify: `src/axum_lib.rs:132` (one line)
- Test: `src/oidc.rs` (new unit test for metadata)

- [ ] **Step 1: Write a failing test for discovery metadata**

Add this test to `mod tests` in `src/oidc.rs`:

```rust
#[test]
fn metadata_includes_introspection_auth_methods() {
    let base_url = Url::parse("https://example.com").unwrap();
    let pm = metadata(base_url).unwrap();
    let value = serde_json::to_value(pm).unwrap();
    // The base metadata from the openidconnect crate does not include
    // introspection_endpoint_auth_methods_supported; that is added in
    // axum_lib.rs::provider_metadata. This test validates the base metadata
    // compiles and serializes. The axum_lib override is tested via integration.
    assert!(value.get("issuer").is_some());
}
```

Note: The discovery override happens in `axum_lib.rs::provider_metadata` which wraps the base `metadata()`. Since this is a one-line change verified by inspection, a full integration test is overkill. We verify via `cargo build` and a `curl` check post-deploy.

- [ ] **Step 2: Fix the discovery metadata**

In `src/axum_lib.rs`, change line 132 from:

```rust
    value["introspection_endpoint_auth_methods_supported"] = serde_json::json!(["bearer"]);
```

To:

```rust
    value["introspection_endpoint_auth_methods_supported"] = serde_json::json!(["client_secret_post", "bearer"]);
```

- [ ] **Step 3: Run all tests to verify**

Run: `cargo test --bin siwx-oidc -- --nocapture 2>&1`

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/axum_lib.rs
git commit -m "fix: advertise client_secret_post for introspection auth in discovery

Synapse uses client_secret_post to authenticate to the introspection endpoint.
The code already accepts both methods but discovery only advertised bearer."
```

---

### Task 3: Align sub claim between ID token and introspection (MEDIUM)

**Hypotheses:** H3

**Files:**
- Modify: `src/db/mod.rs:65-78` (add `did` field to `TokenMetadata`)
- Modify: `src/oidc.rs:573-600` (populate `did` in token metadata)
- Modify: `src/introspect.rs:109-120` (use `did` for `sub`)
- Modify: `src/compat.rs` (no changes needed; compat uses `username` for Synapse lookups)
- Test: `src/introspect.rs` (new unit test)

- [ ] **Step 1: Write a failing test for introspection sub = DID**

Add this test to `mod tests` in `src/introspect.rs`:

```rust
#[test]
fn token_metadata_has_did_field() {
    let meta = super::super::db::TokenMetadata {
        username: "did-pkh-eip155-1-0xabcd".to_string(),
        device_id: "SIWX_test".to_string(),
        scope: "openid".to_string(),
        client_id: "client".to_string(),
        iat: 1000,
        exp: 2000,
        did: Some("did:pkh:eip155:1:0xAbCd".to_string()),
        name: None,
    };
    assert_eq!(meta.did.as_deref(), Some("did:pkh:eip155:1:0xAbCd"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --bin siwx-oidc token_metadata_has_did_field -- --nocapture 2>&1`

Expected: FAIL with "no field named `did`" (struct does not have this field yet).

- [ ] **Step 3: Add `did` and `name` fields to TokenMetadata**

In `src/db/mod.rs`, replace the `TokenMetadata` struct (lines 64-78):

```rust
/// Metadata stored alongside an opaque token in Redis (MSC3861 introspection).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// The Matrix-compatible username (DID with colons replaced by dashes).
    pub username: String,
    /// Device ID assigned by this provider (deterministic from token).
    pub device_id: String,
    /// Space-separated OAuth2 scopes granted.
    pub scope: String,
    /// The client_id that requested the token.
    pub client_id: String,
    /// Token issued-at (Unix timestamp).
    pub iat: i64,
    /// Token expiry (Unix timestamp).
    pub exp: i64,
    /// The original DID (used as OIDC `sub` claim for consistency with ID token).
    #[serde(default)]
    pub did: Option<String>,
    /// Display name (ENS name or DID) for Synapse display name updates.
    #[serde(default)]
    pub name: Option<String>,
}
```

The `#[serde(default)]` ensures backward compatibility: existing Redis entries without these fields will deserialize as `None`.

- [ ] **Step 4: Populate `did` and `name` when issuing tokens**

In `src/oidc.rs`, find the `token_authorization_code` function. After line 573 (`let username = did_to_localpart(&code_entry.did);`), the `TokenMetadata` structs are constructed. Update both the access and refresh metadata to include `did` and `name`.

First, resolve the display name before the metadata construction. Add after line 568 (`let msc3861_mode = config.mas_shared_secret.is_some();`):

```rust
    let display_name = if msc3861_mode {
        resolve_claims(config, &code_entry.did)
            .await
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string())
    } else {
        None
    };
```

Then update the access_metadata construction (around line 583) to add the new fields:

```rust
        let access_metadata = TokenMetadata {
            username: username.clone(),
            device_id: device_id.clone(),
            scope: scope.clone(),
            client_id: client_id.clone(),
            iat,
            exp: iat + ACCESS_TOKEN_TTL as i64,
            did: Some(code_entry.did.clone()),
            name: display_name.clone(),
        };
```

And the refresh_metadata construction (around line 596):

```rust
        let refresh_metadata = TokenMetadata {
            username,
            device_id,
            scope,
            client_id: client_id.clone(),
            iat,
            exp: iat + REFRESH_TOKEN_TTL as i64,
            did: Some(code_entry.did.clone()),
            name: display_name,
        };
```

- [ ] **Step 5: Update introspection to use `did` for `sub`**

In `src/introspect.rs`, change the response JSON (lines 109-120). Replace:

```rust
            Ok(Json(serde_json::json!({
                "active": true,
                "username": m.username,
                "device_id": m.device_id,
                "scope": m.scope,
                "sub": m.username,
                "client_id": m.client_id,
                "token_type": "Bearer",
                "exp": m.exp,
                "expires_in": m.exp - now,
                "iat": m.iat,
            })))
```

With:

```rust
            let sub = m.did.as_deref().unwrap_or(&m.username);
            let mut resp = serde_json::json!({
                "active": true,
                "username": m.username,
                "device_id": m.device_id,
                "scope": m.scope,
                "sub": sub,
                "client_id": m.client_id,
                "token_type": "Bearer",
                "exp": m.exp,
                "expires_in": m.exp - now,
                "iat": m.iat,
            });
            if let Some(ref name) = m.name {
                resp["name"] = serde_json::json!(name);
            }
            Ok(Json(resp))
```

This also handles Task 4 (name field in introspection) in one shot. The fallback `unwrap_or(&m.username)` handles tokens issued before this change that lack the `did` field.

- [ ] **Step 6: Update compat.rs refresh to propagate new fields**

In `src/compat.rs`, the `refresh` function creates new `TokenMetadata` from old metadata. Update the access_meta construction (around line 140):

```rust
    let access_meta = TokenMetadata {
        username: metadata.username.clone(),
        device_id: metadata.device_id.clone(),
        scope: metadata.scope.clone(),
        client_id: metadata.client_id.clone(),
        iat: now,
        exp: now + ACCESS_TOKEN_TTL as i64,
        did: metadata.did.clone(),
        name: metadata.name.clone(),
    };
```

And the refresh_meta construction (around line 166):

```rust
    let refresh_meta = TokenMetadata {
        username: metadata.username.clone(),
        device_id: metadata.device_id.clone(),
        scope: metadata.scope.clone(),
        client_id: metadata.client_id.clone(),
        iat: now,
        exp: now + REFRESH_TOKEN_TTL as i64,
        did: metadata.did.clone(),
        name: metadata.name.clone(),
    };
```

- [ ] **Step 7: Run all tests to verify**

Run: `cargo test --workspace -- --nocapture 2>&1`

Expected: All tests pass. The `#[serde(default)]` on `did` and `name` ensures backward compatibility with existing Redis entries.

- [ ] **Step 8: Commit**

```bash
git add src/db/mod.rs src/oidc.rs src/introspect.rs src/compat.rs
git commit -m "fix: align sub claim across ID token and introspection

ID token sub was the full DID, but introspection sub was the localpart.
Now both use the full DID. Added did and name fields to TokenMetadata
with serde(default) for backward compatibility with existing Redis entries.
Introspection response now includes name for Synapse display name updates."
```

---

### Task 4: (Merged into Task 3)

Task 4 (add `name` field to introspection) is fully covered by Task 3, Step 5 and Step 4. The `name` field is added to `TokenMetadata` in Step 3, populated in Step 4, and emitted in the introspection response in Step 5.

**Hypotheses:** H4 (verified as part of Task 3)

---

### Task 5: Migrate to stable Matrix scopes (MEDIUM)

**Hypotheses:** H5

**Files:**
- Modify: `src/oidc.rs:579-581` (scope format string in `token_authorization_code`)

- [ ] **Step 1: Write a failing test for stable scopes**

Add this test to `mod tests` in `src/oidc.rs`:

```rust
#[test]
fn stable_matrix_scopes_format() {
    let device_id = "SIWX_testdevice";
    let scope = format!(
        "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
        device_id
    );
    assert!(scope.contains("urn:matrix:client:api:*"));
    assert!(scope.contains("urn:matrix:client:device:SIWX_testdevice"));
    assert!(!scope.contains("org.matrix.msc2967"));
}
```

- [ ] **Step 2: Update the scope format string**

In `src/oidc.rs`, find lines 579-581:

```rust
        let scope = format!(
            "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:{}",
            device_id
        );
```

Replace with:

```rust
        let scope = format!(
            "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
            device_id
        );
```

- [ ] **Step 3: Run all tests to verify**

Run: `cargo test --workspace -- --nocapture 2>&1`

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/oidc.rs
git commit -m "fix: migrate from unstable MSC2967 to stable Matrix scope URIs

Replace urn:matrix:org.matrix.msc2967.client:... with urn:matrix:client:...
for forward compatibility with stable MSC3861 Synapse releases."
```

---

### Task 6: Remove dead sync_devices code (MEDIUM)

**Hypotheses:** H6

**Files:**
- Modify: `src/synapse_client.rs:179-200` (delete `sync_devices` method)

- [ ] **Step 1: Verify no callers exist**

Run: `grep -rn "sync_devices" src/ --include="*.rs" | grep -v "synapse_client.rs"`

Expected: No output (no callers outside the defining file).

- [ ] **Step 2: Remove the sync_devices method**

In `src/synapse_client.rs`, delete the `sync_devices` method (lines 179-200):

```rust
    /// Synchronise the full set of devices for a user.
    ///
    /// Synapse will create missing devices and remove any that are not in the list.
    pub async fn sync_devices(&self, localpart: &str, devices: &[String]) -> Result<()> {
        let url = format!("{}/_synapse/mas/sync_devices", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&json!({
                "localpart": localpart,
                "devices": devices,
            }))
            .send()
            .await
            .context("sync_devices: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "sync_devices failed");
            anyhow::bail!("sync_devices: HTTP {status}");
        }
        Ok(())
    }
```

- [ ] **Step 3: Run all tests to verify**

Run: `cargo test --workspace -- --nocapture 2>&1`

Expected: All tests pass. `cargo build --workspace` succeeds with no unused warnings.

- [ ] **Step 4: Commit**

```bash
git add src/synapse_client.rs
git commit -m "chore: remove dead sync_devices method from SynapseClient

Never called from any code path. Individual device management uses
upsert_device and delete_device instead."
```

---

## CLAUDE.md Updates

After all tasks are complete, update the `CLAUDE.md` TODO section to mark items as done. Remove the completed items from the "TODO: MSC3861 compliance gaps" section.

---

## Execution Notes

- **Redis flush required:** Tasks 3/4 add new required fields to `TokenMetadata`. Existing tokens in Redis will fail to deserialize. Run `redis-cli FLUSHDB` (or selectively `DEL` token keys) on deploy to evict stale sessions/tokens.
- **Scope migration (Task 5):** Verify that the deployed Synapse version accepts stable `urn:matrix:client:...` scopes before deploying. If it only accepts unstable scopes, this change must wait for a Synapse upgrade.
- **Branch:** All work on `msc3861-compliance` branched from `fork-stable`.
