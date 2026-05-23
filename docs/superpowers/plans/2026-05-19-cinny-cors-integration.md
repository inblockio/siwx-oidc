# Cinny CORS Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable third-party Matrix clients (Cinny at app.cinny.in) to authenticate through siwx-oidc by adding CORS support at the application layer (CorsLayer) and the reverse proxy layer (production Caddyfile), validated by a programmatic e2e test.

**Architecture:** Two-layer CORS: (1) siwx-oidc adds `tower_http::cors::CorsLayer` with `Access-Control-Allow-Origin: *` per the Matrix Client-Server spec, covering all deployments regardless of proxy. (2) Production Caddyfile in `siwx-oidc-matrix-server/deploy.sh` adds an allowlist-based origin-echo snippet (matching `Caddyfile.local`) with upstream CORS stripping to prevent header duplication. E2e tests validate CORS headers on every browser-facing endpoint during a full OIDC flow.

**Tech Stack:** Rust/axum, tower-http CorsLayer, reqwest (tests), Caddy reverse proxy

**Repos:** `siwx-oidc` (branch: `cinny_integration` off `fork-stable`), `siwx-oidc-matrix-server` (branch: `cinny_integration` off `fork-stable`)

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | CorsLayer is added to the axum router with `Any` origin and standard methods/headers | All HTTP responses include `Access-Control-Allow-Origin: *` | tower-http 0.6 CorsLayer supports `Any` origin; the layer runs before route handlers | `cargo test --test e2e_cors` passes, checking CORS headers on each endpoint |
| H2 | OPTIONS preflight requests hit the CorsLayer before any route handler | Preflight returns 200 with CORS headers and empty body (no 404/405) | CorsLayer handles OPTIONS automatically; axum does not short-circuit OPTIONS before middleware | Test: `OPTIONS /token` with Origin header returns 200 + CORS headers |
| H3 | The production Caddyfile strips upstream CORS headers and adds its own allowlist-based ones | Browsers receive exactly one `Access-Control-Allow-Origin` value (not duplicated) | Caddy `header_down -X` directives remove headers before Caddy adds its own | Manual inspection of generated Caddyfile; functional test against deployed stack |
| H4 | A third-party origin (app.cinny.in) sends `Origin` header to `/_matrix/client/v3/login` | The response includes CORS headers allowing the request | CorsLayer is applied to all routes including the compat Matrix endpoints | `cargo test --test e2e_cors::test_cors_matrix_login_flows` passes |
| H5 | The full OIDC flow (register -> authorize -> sign_in -> token -> userinfo) completes with CORS headers at every cross-origin step | A Cinny-like client can complete authentication without browser CORS blocks | The endpoints that Cinny calls via XHR (not full-page redirects) all return CORS headers | `cargo test --test e2e_cors::test_full_oidc_flow_with_cors` passes |
| H6 | Adding CorsLayer does not break existing tests or the Element Web flow | All existing e2e tests still pass | CorsLayer with `Any` origin is strictly additive (adds headers, changes no behavior) | `cargo test --test e2e_msc3861` still passes |

---

## Task 1: Create `cinny_integration` branch in siwx-oidc

**Files:**
- None (git operation only)

- [ ] **Step 1: Create and checkout the branch**

```bash
cd /home/system-001/siwx-oidc
git checkout -b cinny_integration fork-stable
```

- [ ] **Step 2: Verify branch**

Run: `git branch --show-current`
Expected: `cinny_integration`

---

## Task 2: Add CorsLayer to axum router

**Hypotheses:** H1, H2, H6

**Files:**
- Modify: `src/axum_lib.rs:27-31` (imports) and `src/axum_lib.rs:606-637` (layer stack)

- [ ] **Step 1: Add CorsLayer import**

In `src/axum_lib.rs`, change the `tower_http` import block (lines 27-31) from:

```rust
use tower_http::{
    classify::ServerErrorsFailureClass,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
```

to:

```rust
use tower_http::{
    classify::ServerErrorsFailureClass,
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
```

- [ ] **Step 2: Add CorsLayer to the router's layer stack**

In `src/axum_lib.rs`, after the `.layer(TraceLayer::new_for_http()...` block (after line 637), add a new CorsLayer. The final layer section should look like:

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
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
                .max_age(Duration::from_secs(600)),
        );
```

Note: `Any` origin is Matrix-spec-compliant. The Matrix Client-Server API spec states homeservers should use `Access-Control-Allow-Origin: *`. No `allow_credentials(true)` because `*` and credentials are mutually exclusive in CORS. The cross-origin endpoints (token, userinfo, login_flows) use Bearer tokens in Authorization headers, not cookies.

- [ ] **Step 3: Build to verify compilation**

Run: `cargo build --workspace`
Expected: Compiles without errors.

- [ ] **Step 4: Run existing tests to verify no regression**

Run: `cargo test -p siwx-core`
Expected: All 57+ tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/axum_lib.rs
git commit -m "feat: add CorsLayer with permissive CORS per Matrix spec

Enables third-party Matrix clients (Cinny, FluffyChat, etc.) to make
cross-origin requests. Uses Access-Control-Allow-Origin: * as
recommended by the Matrix Client-Server API spec."
```

---

## Task 3: Write CORS e2e test

**Hypotheses:** H1, H2, H4, H5

**Files:**
- Create: `tests/e2e_cors.rs`

This test validates CORS headers on every browser-facing endpoint. It reuses the same test helpers and flow from `tests/e2e_msc3861.rs` but focuses on CORS validation. Requires a running siwx-oidc instance (with Redis) at `SIWEOIDC_HOST` (default: `http://localhost:8081`).

- [ ] **Step 1: Create the CORS e2e test file**

Create `tests/e2e_cors.rs` with the following content:

```rust
//! CORS integration tests for siwx-oidc.
//!
//! Validates that all browser-facing endpoints return correct CORS headers
//! when a third-party Origin (like app.cinny.in) is present.
//!
//! Required: siwx-oidc running at SIWEOIDC_HOST (default: http://localhost:8081)
//! with Redis available.
//!
//! Run:
//!   SIWEOIDC_HOST=http://localhost:8081 cargo test --test e2e_cors -- --nocapture

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

const CINNY_ORIGIN: &str = "https://app.cinny.in";
const FLUFFYCHAT_ORIGIN: &str = "https://fluffychat.im";

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

// ---------------------------------------------------------------------------
// Crypto helpers (same as e2e_msc3861.rs)
// ---------------------------------------------------------------------------

fn address_from_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            result.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }
    }
    result
}

fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec_id) + 27;
    format!("0x{}", hex::encode(bytes))
}

fn pkce_pair() -> (String, String) {
    use rand::Rng;
    let verifier: String = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let full = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://dummy{}", url)
    };
    let parsed = reqwest::Url::parse(&full).unwrap();
    parsed.query_pairs().into_owned().collect()
}

// ---------------------------------------------------------------------------
// CORS assertion helpers
// ---------------------------------------------------------------------------

fn assert_cors_headers(headers: &reqwest::header::HeaderMap, context: &str) {
    let acao = headers
        .get("access-control-allow-origin")
        .unwrap_or_else(|| panic!("[CORS] {}: missing Access-Control-Allow-Origin", context));
    assert_eq!(
        acao.to_str().unwrap(),
        "*",
        "[CORS] {}: Access-Control-Allow-Origin should be *",
        context
    );
}

fn assert_preflight_headers(headers: &reqwest::header::HeaderMap, context: &str) {
    assert_cors_headers(headers, context);

    let methods = headers
        .get("access-control-allow-methods")
        .unwrap_or_else(|| panic!("[CORS] {}: missing Access-Control-Allow-Methods", context));
    let methods_str = methods.to_str().unwrap();
    assert!(
        methods_str.contains("GET") || methods_str.contains("*"),
        "[CORS] {}: Allow-Methods should include GET or *",
        context
    );
    assert!(
        methods_str.contains("POST") || methods_str.contains("*"),
        "[CORS] {}: Allow-Methods should include POST or *",
        context
    );

    let allow_headers = headers
        .get("access-control-allow-headers")
        .unwrap_or_else(|| panic!("[CORS] {}: missing Access-Control-Allow-Headers", context));
    let headers_str = allow_headers.to_str().unwrap();
    assert!(
        headers_str.contains("authorization")
            || headers_str.contains("Authorization")
            || headers_str.contains("*"),
        "[CORS] {}: Allow-Headers should include authorization or *",
        context
    );
}

// ---------------------------------------------------------------------------
// Test: CORS headers on OIDC metadata endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cors_openid_configuration() {
    let base = siweoidc_host();
    let http = Client::new();

    let resp = http
        .get(format!("{}/.well-known/openid-configuration", base))
        .header("origin", CINNY_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_cors_headers(resp.headers(), "GET /.well-known/openid-configuration");
}

// ---------------------------------------------------------------------------
// Test: CORS headers on Matrix compat login_flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cors_matrix_login_flows() {
    let base = siweoidc_host();
    let http = Client::new();

    let resp = http
        .get(format!("{}/_matrix/client/v3/login", base))
        .header("origin", CINNY_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_cors_headers(resp.headers(), "GET /_matrix/client/v3/login");

    let body: Value = resp.json().await.unwrap();
    assert!(
        body["flows"].is_array(),
        "login_flows should return a flows array"
    );
}

// ---------------------------------------------------------------------------
// Test: OPTIONS preflight on /token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cors_preflight_token() {
    let base = siweoidc_host();
    let http = Client::new();

    let resp = http
        .request(reqwest::Method::OPTIONS, format!("{}/token", base))
        .header("origin", CINNY_ORIGIN)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "OPTIONS /token preflight should succeed, got {}",
        resp.status()
    );
    assert_preflight_headers(resp.headers(), "OPTIONS /token");
}

// ---------------------------------------------------------------------------
// Test: OPTIONS preflight on /_matrix/client/v3/login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cors_preflight_matrix_login() {
    let base = siweoidc_host();
    let http = Client::new();

    let resp = http
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/_matrix/client/v3/login", base),
        )
        .header("origin", FLUFFYCHAT_ORIGIN)
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "OPTIONS /_matrix/client/v3/login preflight should succeed, got {}",
        resp.status()
    );
    assert_preflight_headers(resp.headers(), "OPTIONS /_matrix/client/v3/login");
}

// ---------------------------------------------------------------------------
// Test: Full OIDC flow with CORS validation at each cross-origin step
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_oidc_flow_with_cors() {
    let base = siweoidc_host();
    let http = Client::new();
    let client_nr = no_redirect_client();

    // -- Step 1: Register a dynamic OIDC client --
    let redirect_uri = format!("{}/callback", base);
    let reg_body = serde_json::json!({
        "redirect_uris": [&redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });

    let reg_resp = http
        .post(format!("{}/register", base))
        .header("origin", CINNY_ORIGIN)
        .json(&reg_body)
        .send()
        .await
        .expect("register request failed");
    assert_eq!(reg_resp.status(), StatusCode::CREATED);
    assert_cors_headers(reg_resp.headers(), "POST /register");
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();
    eprintln!("[cors-e2e] registered client_id={}", client_id);

    // -- Step 2: Authorize (redirect, not XHR -- CORS optional but should still be present) --
    let (code_verifier, code_challenge) = pkce_pair();
    let state_param = "cors_test_state";

    let authorize_url = format!(
        "{}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state_param,
        urlencoding::encode(&code_challenge),
    );
    let auth_resp = client_nr
        .get(&authorize_url)
        .header("origin", CINNY_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER);
    assert_cors_headers(auth_resp.headers(), "GET /authorize");

    let set_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .expect("authorize must set session cookie")
        .to_str()
        .unwrap()
        .to_string();
    let session_cookie = set_cookie.split(';').next().unwrap().to_string();

    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let query = parse_query(&location);
    let nonce = query.get("nonce").expect("redirect must contain nonce");
    let domain = query.get("domain").expect("redirect must contain domain");

    // -- Step 3: Build CAIP-122 message and sign --
    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);

    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Resources:\n\
         - {redirect_uri}",
        domain = domain,
        address = address,
        base = base,
        nonce = nonce,
        issued_at = issued_at,
        redirect_uri = redirect_uri,
    );
    let signature = eip191_sign(&signing_key, &message);

    // -- Step 4: sign_in (redirect, carries session cookie) --
    let siwx_payload = serde_json::json!({
        "did": did,
        "message": message,
        "signature": signature,
    });
    let siwx_cookie_value = serde_json::to_string(&siwx_payload).unwrap();

    let sign_in_url = format!(
        "{}/sign_in?redirect_uri={}&state={}&client_id={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&redirect_uri),
        state_param,
        urlencoding::encode(&client_id),
        urlencoding::encode(&code_challenge),
    );

    let sign_in_resp = client_nr
        .get(&sign_in_url)
        .header("origin", CINNY_ORIGIN)
        .header(
            "cookie",
            format!(
                "{}; siwx={}",
                session_cookie,
                urlencoding::encode(&siwx_cookie_value)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sign_in_resp.status(), StatusCode::SEE_OTHER);
    assert_cors_headers(sign_in_resp.headers(), "GET /sign_in");

    let sign_in_location = sign_in_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_query = parse_query(&sign_in_location);
    let code = callback_query.get("code").expect("must contain code");

    // -- Step 5: Token exchange (XHR, main cross-origin endpoint for Cinny) --
    let token_resp = http
        .post(format!("{}/token", base))
        .header("origin", CINNY_ORIGIN)
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::OK);
    assert_cors_headers(token_resp.headers(), "POST /token");
    let token_json: Value = token_resp.json().await.unwrap();
    let access_token = token_json["access_token"]
        .as_str()
        .expect("must have access_token")
        .to_string();
    eprintln!("[cors-e2e] access_token={}", &access_token[..12.min(access_token.len())]);

    // -- Step 6: Userinfo (XHR, cross-origin with Bearer token) --
    let userinfo_resp = http
        .get(format!("{}/userinfo", base))
        .header("origin", CINNY_ORIGIN)
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(userinfo_resp.status(), StatusCode::OK);
    assert_cors_headers(userinfo_resp.headers(), "GET /userinfo");

    let userinfo_json: Value = userinfo_resp.json().await.unwrap();
    assert_eq!(
        userinfo_json["sub"].as_str().unwrap(),
        did,
        "userinfo sub should match the signing DID"
    );

    eprintln!("[cors-e2e] Full OIDC flow with CORS validation PASSED");
    eprintln!("[cors-e2e] DID: {}", did);
    eprintln!("[cors-e2e] All endpoints returned Access-Control-Allow-Origin: *");
}
```

- [ ] **Step 2: Run to verify tests fail (CorsLayer not yet added, or pass if already added)**

Run: `cargo test --test e2e_cors -- --nocapture`
Expected: If CorsLayer was added in Task 2, all tests pass. If running out of order, tests fail on missing CORS headers.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e_cors.rs
git commit -m "test: add CORS e2e tests for third-party Matrix client integration

Tests validate CORS headers on every browser-facing endpoint during
a full OIDC flow with Origin: https://app.cinny.in. Covers preflight
OPTIONS, OIDC metadata, Matrix compat login_flows, token exchange,
and userinfo."
```

---

## Task 4: Run all tests and validate

**Hypotheses:** H1, H2, H4, H5, H6

**Files:**
- None (verification only)

- [ ] **Step 1: Run siwx-core unit tests**

Run: `cargo test -p siwx-core`
Expected: All tests pass (no changes to siwx-core).

- [ ] **Step 2: Run CORS e2e tests against a live instance**

Run: `SIWEOIDC_HOST=http://localhost:8081 cargo test --test e2e_cors -- --nocapture`
Expected: All 5 tests pass:
- `test_cors_openid_configuration`
- `test_cors_matrix_login_flows`
- `test_cors_preflight_token`
- `test_cors_preflight_matrix_login`
- `test_full_oidc_flow_with_cors`

- [ ] **Step 3: Run existing e2e tests (regression check)**

Run: `SIWEOIDC_HOST=http://localhost:8081 cargo test --test e2e_msc3861 -- --nocapture`
Expected: All existing tests pass unchanged.

---

## Task 5: Fix production Caddyfile in siwx-oidc-matrix-server

**Hypotheses:** H3

**Files:**
- Modify: `/home/system-001/siwx-oidc-matrix-server/deploy.sh:128-164`

This task works in the `siwx-oidc-matrix-server` repo. Create a `cinny_integration` branch off `fork-stable` there.

- [ ] **Step 1: Create branch in matrix-server repo**

```bash
cd /home/system-001/siwx-oidc-matrix-server
git checkout -b cinny_integration fork-stable
```

- [ ] **Step 2: Update deploy.sh Caddyfile heredoc**

Replace the Caddyfile heredoc in `deploy.sh` (lines 128-163, the content between `cat >> "$CADDYFILE" << 'EOF'` and `EOF`) with:

```caddyfile
(siwx_cors) {
    @cors_origin {
        header Origin https://element.inblock.io
        header Origin https://app.cinny.in
    }
    @cors_preflight {
        method OPTIONS
        header Origin https://element.inblock.io
        header Origin https://app.cinny.in
    }
    header @cors_origin Access-Control-Allow-Origin "{http.request.header.Origin}"
    header @cors_origin Vary Origin
    header @cors_origin Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    header @cors_origin Access-Control-Allow-Headers "Authorization, Content-Type, X-Requested-With"
    header @cors_origin Access-Control-Allow-Credentials "true"
    header @cors_origin Access-Control-Max-Age "600"
    respond @cors_preflight 204
}

(strip_upstream_cors) {
    header_down -Access-Control-Allow-Origin
    header_down -Access-Control-Allow-Methods
    header_down -Access-Control-Allow-Headers
    header_down -Access-Control-Allow-Credentials
    header_down -Access-Control-Expose-Headers
    header_down -Access-Control-Max-Age
    header_down -Vary
}

matrix.inblock.io {
    encode zstd gzip

    handle /.well-known/matrix/server {
        respond `{"m.server": "matrix.inblock.io:443"}`
    }
    handle /.well-known/matrix/client {
        header Access-Control-Allow-Origin *
        respond `{"m.homeserver": {"base_url": "https://matrix.inblock.io"}, "m.authentication": {"issuer": "https://siwx-oidc.inblock.io"}}`
    }

    handle /_matrix/client/v3/login {
        import siwx_cors
        reverse_proxy siwx-oidc:8081 {
            import strip_upstream_cors
        }
    }
    handle /_matrix/client/v3/logout {
        import siwx_cors
        reverse_proxy siwx-oidc:8081 {
            import strip_upstream_cors
        }
    }
    handle /_matrix/client/v3/refresh {
        import siwx_cors
        reverse_proxy siwx-oidc:8081 {
            import strip_upstream_cors
        }
    }

    handle {
        reverse_proxy matrix_synapse:8080
    }
}

siwx-oidc.inblock.io {
    encode zstd gzip
    import siwx_cors
    reverse_proxy siwx-oidc:8081 {
        import strip_upstream_cors
    }
}

element.inblock.io {
    encode zstd gzip
    reverse_proxy element-web:8080
}
```

Key changes vs. the current deploy.sh:
1. Added `(siwx_cors)` snippet with allowlist for element.inblock.io and app.cinny.in
2. Added `(strip_upstream_cors)` snippet to prevent double CORS headers
3. Applied both snippets to login/logout/refresh handlers
4. Applied both snippets to siwx-oidc.inblock.io site block
5. `.well-known/matrix/client` keeps `*` (federation requirement, no credentials needed)

- [ ] **Step 3: Verify deploy.sh syntax**

Run: `bash -n /home/system-001/siwx-oidc-matrix-server/deploy.sh`
Expected: No syntax errors.

- [ ] **Step 4: Commit**

```bash
cd /home/system-001/siwx-oidc-matrix-server
git add deploy.sh
git commit -m "fix: add CORS headers for third-party Matrix clients (Cinny)

Production Caddyfile now includes:
- (siwx_cors) snippet with allowlist for element.inblock.io and app.cinny.in
- (strip_upstream_cors) snippet to prevent double headers with siwx-oidc's CorsLayer
- Applied to all siwx-oidc-proxied routes (login, logout, refresh, siwx-oidc.inblock.io)"
```

---

## Task 6: Update CLAUDE.md with CORS documentation

**Files:**
- Modify: `/home/system-001/siwx-oidc/CLAUDE.md`

- [ ] **Step 1: Add CORS section to CLAUDE.md**

Add the following section after the "Logging conventions" section:

```markdown
## CORS configuration

siwx-oidc includes a permissive CorsLayer (`Access-Control-Allow-Origin: *`) per the
Matrix Client-Server API spec. This enables any web-based Matrix client to make
cross-origin requests.

In production, the reverse proxy (Caddy) is the CORS authority. The `(strip_upstream_cors)`
snippet removes siwx-oidc's CORS headers, and the `(siwx_cors)` snippet adds allowlist-based
origin-echo headers. To allow a new client origin (e.g., Beeper), add its URL to the
`@cors_origin` and `@cors_preflight` matchers in the production Caddyfile.

**Test:** `cargo test --test e2e_cors -- --nocapture` (needs Redis + running siwx-oidc)
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add CORS configuration section to CLAUDE.md"
```
