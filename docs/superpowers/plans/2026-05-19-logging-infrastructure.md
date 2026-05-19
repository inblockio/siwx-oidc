# Logging Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every server module in siwx-oidc produces actionable, structured log output at appropriate levels, with request-level tracing, error-path coverage, and documented conventions for future modules.

**Architecture:** Replace the bare `tracing_subscriber::fmt::init()` with an explicit subscriber that uses `EnvFilter` (sensible default) and optionally outputs JSON. Centralize error logging in `CustomError::into_response()` so all OIDC/WebAuthn errors are logged in one place. Add targeted error logging to `introspect.rs` and `compat.rs` which bypass `CustomError`.

**Tech Stack:** tracing, tracing-subscriber (env-filter, json features), tower-http TraceLayer

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | Replace `fmt::init()` with explicit `fmt().with_env_filter()` using default `siwx_oidc=info,tower_http=info` | RUST_LOG filtering works correctly; setting RUST_LOG overrides the default | tracing-subscriber env-filter feature works as documented | `cargo build` succeeds; `cargo test` passes |
| H2 | Configure TraceLayer with `on_request`/`on_response` at INFO level | All HTTP requests appear in logs with method, path, status, latency | tower-http TraceLayer supports callback customization | `cargo build` succeeds; manual test shows request log lines |
| H3 | Add `warn!` inside `CustomError::into_response()` for error variants | All OIDC and WebAuthn error responses are logged server-side | All error paths go through `CustomError::into_response()` (verified for oidc/webauthn routes) | `cargo test` passes; grep confirms no other IntoResponse for errors |
| H4 | Add `warn!` to introspect auth failures and compat silent-discard paths | Non-CustomError error paths also produce log output | introspect and compat are the only modules bypassing CustomError (verified) | `cargo test` passes; code review confirms coverage |
| H5 | Add `log_format` field to Config with env var `SIWEOIDC_LOG_FORMAT` | Operators can switch to JSON output via env var | Figment env parsing handles the new field; tracing-subscriber "json" feature available | `cargo build` succeeds; config deserializes correctly |
| H6 | Document logging conventions in CLAUDE.md | Future module authors use consistent log levels | Developers read CLAUDE.md | Manual review |
| H7 | Make no changes to siwx-core/ | siwx-core remains a pure library with zero logging | No accidental `use tracing` added | `grep -r "tracing" siwx-core/src/` returns nothing |

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `Cargo.toml` | Modify | Add `tracing-subscriber` "json" feature |
| `src/config.rs` | Modify | Add `log_format` field |
| `src/axum_lib.rs` | Modify | Replace subscriber init, configure TraceLayer, add error logging to `CustomError::into_response()` |
| `src/introspect.rs` | Modify | Add warn! on auth failures |
| `src/compat.rs` | Modify | Add warn! on error paths |
| `CLAUDE.md` | Modify | Add logging conventions section |
| `.claude/commands/debug-oidc.md` | Modify | Add log-format tips and RUST_LOG examples |

---

### Task 1: Add tracing-subscriber "json" feature to Cargo.toml

**Hypotheses:** H5
**Files:**
- Modify: `Cargo.toml:43`

- [ ] **Step 1: Add "json" feature to tracing-subscriber dependency**

In `Cargo.toml`, change:
```toml
tracing-subscriber = { version = "0.3.20", features = ["env-filter"] }
```
to:
```toml
tracing-subscriber = { version = "0.3.20", features = ["env-filter", "json"] }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "deps: add tracing-subscriber json feature for structured logging"
```

---

### Task 2: Add log_format config option

**Hypotheses:** H5
**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Add log_format field to Config struct**

In `src/config.rs`, add the field after the `synapse_endpoint` field:

```rust
/// Log output format: "pretty" (default, human-readable) or "json" (structured).
/// Env: `SIWEOIDC_LOG_FORMAT`
pub log_format: String,
```

- [ ] **Step 2: Set default to "pretty" in Default impl**

In the `Default` impl, add:
```rust
log_format: "pretty".to_string(),
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors (Figment will pick up `SIWEOIDC_LOG_FORMAT` automatically)

- [ ] **Step 4: Commit**

```bash
git add src/config.rs
git commit -m "feat: add log_format config option (pretty/json)"
```

---

### Task 3: Replace subscriber init with EnvFilter + optional JSON

**Hypotheses:** H1, H5
**Files:**
- Modify: `src/axum_lib.rs:31-32,432`

- [ ] **Step 1: Update imports in axum_lib.rs**

Replace:
```rust
use tracing::info;
```
with:
```rust
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};
```

- [ ] **Step 2: Replace tracing_subscriber::fmt::init() with explicit subscriber**

Replace `tracing_subscriber::fmt::init();` (line 432) with:

```rust
let env_filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| EnvFilter::new("siwx_oidc=info,tower_http=info,warn"));

match config.log_format.as_str() {
    "json" => {
        fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_timer(fmt::time::UtcTime::rfc_3339())
            .init();
    }
    _ => {
        fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .init();
    }
}
```

- [ ] **Step 3: Add time feature import**

Add to the top of the subscriber block if needed (the `fmt::time::UtcTime` requires the `time` crate via tracing-subscriber). Verify this compiles. If `UtcTime::rfc_3339()` is not available, use `fmt::time::SystemTime` instead:

```rust
// Fallback if UtcTime not available:
match config.log_format.as_str() {
    "json" => {
        fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .init();
    }
    _ => {
        fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .init();
    }
}
```

- [ ] **Step 4: Verify it compiles and tests pass**

Run: `cargo check --workspace && cargo test -p siwx-core`
Expected: compiles; siwx-core tests pass (they don't touch the subscriber)

- [ ] **Step 5: Commit**

```bash
git add src/axum_lib.rs
git commit -m "feat: structured tracing subscriber with EnvFilter and JSON option"
```

---

### Task 4: Configure TraceLayer for INFO-level request logging

**Hypotheses:** H2
**Files:**
- Modify: `src/axum_lib.rs:27-30,567`

- [ ] **Step 1: Update tower-http imports**

Replace:
```rust
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
```
with:
```rust
use tower_http::{
    classify::ServerErrorsFailureClass,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use std::time::Duration;
```

- [ ] **Step 2: Replace TraceLayer::new_for_http() with custom config**

Replace `.layer(TraceLayer::new_for_http())` with:

```rust
.layer(
    TraceLayer::new_for_http()
        .on_request(|req: &axum::http::Request<_>, _span: &tracing::Span| {
            info!(
                method = %req.method(),
                path = %req.uri().path(),
                "request"
            );
        })
        .on_response(
            |res: &axum::http::Response<_>,
             latency: Duration,
             _span: &tracing::Span| {
                info!(
                    status = res.status().as_u16(),
                    latency_ms = latency.as_millis() as u64,
                    "response"
                );
            },
        )
        .on_failure(
            |error: ServerErrorsFailureClass,
             latency: Duration,
             _span: &tracing::Span| {
                warn!(
                    error = %error,
                    latency_ms = latency.as_millis() as u64,
                    "request failed"
                );
            },
        ),
)
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors. The closures must match tower-http's expected signatures.

- [ ] **Step 4: Commit**

```bash
git add src/axum_lib.rs
git commit -m "feat: request/response logging at INFO level with method, path, status, latency"
```

---

### Task 5: Centralized error logging in CustomError::into_response()

**Hypotheses:** H3
**Files:**
- Modify: `src/axum_lib.rs:72-92`

- [ ] **Step 1: Add warn! logging to each error variant**

Replace the `IntoResponse for CustomError` impl:

```rust
impl IntoResponse for CustomError {
    fn into_response(self) -> Response {
        match self {
            CustomError::BadRequest(ref msg) => {
                warn!(error = %msg, "bad_request");
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            CustomError::BadRequestRegister(ref e) => {
                warn!(error = ?e, "bad_request_register");
                (StatusCode::BAD_REQUEST, Json(e)).into_response()
            }
            CustomError::BadRequestToken(ref e) => {
                warn!(error = ?e, "bad_request_token");
                (StatusCode::BAD_REQUEST, Json(e)).into_response()
            }
            CustomError::Unauthorized(ref msg) => {
                warn!(error = %msg, "unauthorized");
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            CustomError::NotFound => {
                (StatusCode::NOT_FOUND, self.to_string()).into_response()
            }
            CustomError::Redirect(uri) => Redirect::to(&uri).into_response(),
            CustomError::Other(ref e) => {
                warn!(error = %e, "internal_error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}
```

Note: `NotFound` and `Redirect` are left unlogged intentionally (404 is normal for missing routes; redirects are expected OIDC flow).

- [ ] **Step 2: Fix borrow checker issues**

The `ref` patterns borrow self, but `Json(e)` and `Redirect::to(&uri)` need ownership. Restructure to log first, then consume:

```rust
impl IntoResponse for CustomError {
    fn into_response(self) -> Response {
        match &self {
            CustomError::BadRequest(msg) => {
                warn!(error = %msg, "bad_request");
            }
            CustomError::BadRequestRegister(e) => {
                warn!(error = ?e, "bad_request_register");
            }
            CustomError::BadRequestToken(e) => {
                warn!(error = ?e, "bad_request_token");
            }
            CustomError::Unauthorized(msg) => {
                warn!(error = %msg, "unauthorized");
            }
            CustomError::Other(e) => {
                warn!(error = %e, "internal_error");
            }
            CustomError::NotFound | CustomError::Redirect(_) => {}
        }

        match self {
            CustomError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            CustomError::BadRequestRegister(e) => {
                (StatusCode::BAD_REQUEST, Json(e)).into_response()
            }
            CustomError::BadRequestToken(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
            CustomError::Unauthorized(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            CustomError::NotFound => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
            CustomError::Redirect(uri) => Redirect::to(&uri).into_response(),
            CustomError::Other(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors

- [ ] **Step 4: Commit**

```bash
git add src/axum_lib.rs
git commit -m "feat: centralized error logging in CustomError::into_response()"
```

---

### Task 6: Add error logging to introspect.rs

**Hypotheses:** H4
**Files:**
- Modify: `src/introspect.rs:20,67-99`

- [ ] **Step 1: Add warn import**

Change:
```rust
use tracing::debug;
```
to:
```rust
use tracing::{debug, warn};
```

- [ ] **Step 2: Add warn! for auth failure paths**

In the `introspect` function, add logging to the early-return error paths.

After the `mas_shared_secret` check (line 75):
```rust
let secret = state
    .mas_shared_secret
    .as_ref()
    .ok_or_else(|| {
        warn!("introspect: endpoint called but mas_shared_secret not configured");
        StatusCode::NOT_FOUND
    })?;
```

After the auth credential check (line 83-84):
```rust
} else {
    warn!("introspect: no Bearer token or client_secret provided");
    return Err(StatusCode::UNAUTHORIZED);
};
```

After the constant-time comparison (line 87-89):
```rust
if provided.len() != expected.len() || !bool::from(provided.ct_eq(expected)) {
    warn!("introspect: invalid shared secret");
    return Err(StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors

- [ ] **Step 4: Commit**

```bash
git add src/introspect.rs
git commit -m "feat: add warn logging to introspect auth failure paths"
```

---

### Task 7: Add error logging to compat.rs

**Hypotheses:** H4
**Files:**
- Modify: `src/compat.rs:22`

- [ ] **Step 1: Add debug import**

Change:
```rust
use tracing::warn;
```
to:
```rust
use tracing::{debug, warn};
```

- [ ] **Step 2: Add logging to revoke endpoint**

Replace:
```rust
pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    let _ = state.redis_client.delete_token(&form.token).await;
    StatusCode::OK
}
```
with:
```rust
pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    if let Err(e) = state.redis_client.delete_token(&form.token).await {
        warn!(error = %e, "revoke: failed to delete token from Redis");
    }
    StatusCode::OK
}
```

- [ ] **Step 3: Add logging to logout endpoint**

Replace the logout function body to log the deletion:
```rust
pub async fn logout(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    if let Some(TypedHeader(auth)) = bearer {
        if let Err(e) = state.redis_client.delete_token(auth.token()).await {
            warn!(error = %e, "logout: failed to delete token from Redis");
        }
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}
```

- [ ] **Step 4: Add debug logging to refresh for the happy path**

In the `refresh` function, after generating new tokens and before the final return, add:
```rust
debug!(
    username = %metadata.username,
    "refresh: tokens rotated successfully"
);
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --workspace`
Expected: compiles without errors

- [ ] **Step 6: Commit**

```bash
git add src/compat.rs
git commit -m "feat: add error and debug logging to compat endpoints"
```

---

### Task 8: Verify siwx-core purity (H7 gate)

**Hypotheses:** H7
**Files:**
- Read-only: `siwx-core/`

- [ ] **Step 1: Verify no tracing dependency in siwx-core**

Run: `grep -r "tracing" siwx-core/src/`
Expected: zero matches

Run: `grep "tracing" siwx-core/Cargo.toml`
Expected: zero matches

- [ ] **Step 2: Run siwx-core tests**

Run: `cargo test -p siwx-core`
Expected: all 57 tests pass

---

### Task 9: Run full test suite

**Hypotheses:** H1, H2, H3, H4, H5
**Files:**
- Read-only

- [ ] **Step 1: Run workspace build**

Run: `cargo build --workspace`
Expected: compiles without errors or warnings related to our changes

- [ ] **Step 2: Run siwx-core tests**

Run: `cargo test -p siwx-core`
Expected: all tests pass

- [ ] **Step 3: Run server tests (if Redis available)**

Run: `cargo test --bin siwx-oidc`
Expected: tests pass (requires Redis on localhost:6379)

- [ ] **Step 4: Commit any fixups if needed**

---

### Task 10: Document logging conventions in CLAUDE.md

**Hypotheses:** H6
**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add logging section to CLAUDE.md**

Add the following section after the "Troubleshooting" section (before "Claude Code skills"):

```markdown
## Logging conventions

**Subscriber:** Initialized in `axum_lib.rs::main()` with `EnvFilter`. Default filter:
`siwx_oidc=info,tower_http=info,warn`. Override with `RUST_LOG` env var.

**Format:** Set `SIWEOIDC_LOG_FORMAT=json` for structured JSON output (container log
aggregation). Default: human-readable (`pretty`).

**Level guidelines for new modules:**

| Level | Use for | Examples |
|-------|---------|---------|
| `error!` | Unrecoverable failures that halt a request or corrupt state | Signing key load failure, Redis pool exhausted |
| `warn!` | Recoverable errors, unexpected but handled conditions | Synapse API failure (best-effort), invalid client input, auth failures |
| `info!` | Significant state changes, request lifecycle events | Sign-in success, ceremony start/finish, server startup |
| `debug!` | Internal details useful during development | Redis key operations, token metadata, ENS resolution attempts |

**Rules:**
- siwx-core: NO logging (pure library, no tracing dependency)
- Never log secrets, tokens, cookies, or signing key material
- Use structured fields (`info!(did = %did, "sign_in success")`) not string interpolation
- Error paths: prefer logging at the boundary (`CustomError::into_response`) over scattering
  `warn!` calls through business logic
- Modules that bypass `CustomError` (introspect, compat) must log their own errors
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add logging conventions to CLAUDE.md"
```

---

### Task 11: Update debug-oidc skill

**Hypotheses:** H6
**Files:**
- Modify: `.claude/commands/debug-oidc.md`

- [ ] **Step 1: Update the "Check server logs" section**

Replace section 2 with:

```markdown
## 2. Check server logs

```bash
# If running via docker compose
docker compose logs siwx-oidc --tail 50

# If running locally with debug logging
RUST_LOG=siwx_oidc=debug,tower_http=debug cargo run

# For full trace-level output (very verbose)
RUST_LOG=siwx_oidc=trace,tower_http=trace cargo run

# For JSON output (useful for piping to jq)
SIWEOIDC_LOG_FORMAT=json RUST_LOG=siwx_oidc=debug cargo run 2>&1 | jq .
```

Key log targets:
- `siwx_oidc::oidc` -- sign-in, token, authorize, ENS resolution
- `siwx_oidc::webauthn` -- passkey ceremonies
- `siwx_oidc::axum_lib` -- startup, request/response lifecycle, error responses
- `siwx_oidc::introspect` -- token introspection (MSC3861)
- `siwx_oidc::compat` -- Matrix compat endpoints (revoke, refresh, logout)
- `siwx_oidc::synapse_client` -- Synapse provisioning API calls
- `tower_http` -- HTTP request/response traces
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/debug-oidc.md
git commit -m "docs: update debug-oidc skill with new logging targets and JSON tips"
```
