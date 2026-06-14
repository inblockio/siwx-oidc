//! Deterministic HTTP E2E suite guarding the device-removal / session-cleanup
//! RACE and TEARDOWN hazards of siwx-oidc (hazard register H1..H14 in
//! `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`).
//!
//! Targets the MOCK stack brought up by `e2e/up.sh`:
//!   - siwx-oidc on :8080  (SIWEOIDC_HOST)
//!   - Synapse mock on :8090 (SYNAPSE_MOCK) — records a call log, supports
//!     /__reset, /__seed_device, /__state, /__set_secret, /__fail.
//!   - Redis on :6379 (only used indirectly via siwx-oidc).
//!
//! Run single-threaded with the stack up (matches the repo `#[ignore]` e2e
//! convention so `cargo test` stays green without the stack):
//!   bash e2e/up.sh
//!   cargo test --test e2e_race_teardown -- --ignored --test-threads=1 --nocapture
//!
//! Determinism: races are forced with concurrent tokio tasks aligned on a
//! `tokio::sync::Barrier`, never wall-clock sleeps, and each race test loops a
//! few rounds to defeat flakiness. Every test resets the mock and uses a fresh
//! DID so they can share the stack.
//!
//! The S3-1 / S3-3 / S3-4 race fixes (H9 / H3 / H6) have landed, so their former
//! `RUN_REPRO=1`-gated reproducers now run unconditionally as permanent regression
//! guards (search "REGRESSION GUARD") asserting no token resurrection / a single
//! device-code redemption.

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rand::rngs::OsRng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Barrier;

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8080".to_string())
}
fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}
/// The shared admin/introspection secret the stack is brought up with (e2e/up.sh).
const SHARED_SECRET: &str = "testsecret";
/// The Matrix server_name the stack is configured with (SIWEOIDC_MATRIX_SERVER_NAME).
const SERVER_NAME: &str = "matrix.test";

// ---------------------------------------------------------------------------
// Wallet identity + signing (EIP-191 / CAIP-122) — copied helper style from
// tests/e2e_account_management.rs and tests/e2e_msc3861.rs.
// ---------------------------------------------------------------------------

struct Wallet {
    key: SigningKey,
    address: String,
    did: String,
    /// `did_to_localpart(did)` — the lowercased localpart Synapse/TokenMetadata uses.
    localpart: String,
    /// `@{localpart}:matrix.test` — the mxid the mock keys devices on.
    mxid: String,
}

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
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    out
}

fn new_wallet() -> Wallet {
    let key = SigningKey::random(&mut OsRng);
    let addr = address_from_key(key.verifying_key());
    let address = eip55_checksum(&addr);
    let did = format!("did:pkh:eip155:1:{address}");
    let localpart = did.replace(':', "-").to_lowercase();
    let mxid = format!("@{localpart}:{SERVER_NAME}");
    Wallet {
        key,
        address,
        did,
        localpart,
        mxid,
    }
}

/// EIP-191 personal-sign over `message`, returning a 0x-hex 65-byte signature.
fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let (sig, rec): (Signature, RecoveryId) = key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec) + 27;
    format!("0x{}", hex::encode(bytes))
}

/// The CAIP-122 message the `/account` page JS signs (`Confirm account action.`
/// body, self-generated nonce). The account re-auth verifies only the signature
/// and DID method (no session nonce), so a self-consistent message suffices.
fn sign_account_message(w: &Wallet, base: &str) -> (String, String) {
    let domain = reqwest::Url::parse(base)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nConfirm account action.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: testnonce0001\nIssued At: 2026-06-14T00:00:00.000Z",
        addr = w.address,
    );
    let sig = eip191_sign(&w.key, &message);
    (message, sig)
}

// ---------------------------------------------------------------------------
// PKCE + redirect helpers (full /authorize -> /sign_in -> /token flow)
// ---------------------------------------------------------------------------

fn pkce_pair() -> (String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let verifier: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn no_redirect_client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let full = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://dummy{url}")
    };
    reqwest::Url::parse(&full)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// A registered OAuth client (id + secret) for the wallet auth-code flow.
struct RegisteredClient {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

async fn register_client(c: &Client, base: &str) -> RegisteredClient {
    let redirect_uri = format!("{base}/callback");
    let reg: Value = c
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [&redirect_uri],
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    RegisteredClient {
        client_id: reg["client_id"].as_str().unwrap().to_string(),
        client_secret: reg["client_secret"].as_str().unwrap().to_string(),
        redirect_uri,
    }
}

/// Tokens returned by the auth-code flow plus the Synapse device id provisioned.
struct LoginResult {
    access_token: String,
    refresh_token: String,
    device_id: String,
}

/// Drive a full wallet auth-code login for `w` and return the issued tokens +
/// the `SIWX_*` device id provisioned in the mock. One fresh client per call.
async fn wallet_login(c: &Client, base: &str, w: &Wallet) -> LoginResult {
    let rc = register_client(c, base).await;
    let (verifier, challenge) = pkce_pair();
    let state = "race_state";
    let nrc = no_redirect_client();

    // /authorize -> session cookie + nonce
    let authorize_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={state}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&challenge),
    );
    let auth_resp = nrc.get(&authorize_url).send().await.unwrap();
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER, "authorize 303");
    let session_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let q = parse_query(&location);
    let nonce = q.get("nonce").unwrap();
    let domain = q.get("domain").unwrap();

    // Build + sign the CAIP-122 message (resources must contain the redirect_uri).
    // The login path now enforces the Expiration Time (C1 safe subset), so set a
    // fresh future exp — matching what the real Svelte frontend already sends.
    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expiration_time =
        (now + chrono::Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {addr}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:\n\
         - {redirect}",
        addr = w.address,
        redirect = rc.redirect_uri,
    );
    let signature = eip191_sign(&w.key, &message);
    let siwx_cookie_value =
        serde_json::to_string(&json!({ "did": w.did, "message": message, "signature": signature }))
            .unwrap();

    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state={state}&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&challenge),
    );
    let sign_in_resp = nrc
        .get(&sign_in_url)
        .header(
            "cookie",
            format!(
                "{session_cookie}; siwx={}",
                urlencoding::encode(&siwx_cookie_value)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sign_in_resp.status(), StatusCode::SEE_OTHER, "sign_in 303");
    let code = parse_query(
        sign_in_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .get("code")
    .expect("sign_in redirect must carry code")
    .clone();

    let token: Value = exchange_code(c, base, &rc, &code, &verifier)
        .await
        .expect("token exchange must succeed");
    let access_token = token["access_token"].as_str().unwrap().to_string();
    let refresh_token = token["refresh_token"].as_str().unwrap().to_string();
    let device_id = introspect(c, &access_token).await["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    LoginResult {
        access_token,
        refresh_token,
        device_id,
    }
}

/// One-shot wallet login that stops at the auth CODE (for code-double-spend
/// tests). Returns `(RegisteredClient, code, verifier)`.
async fn wallet_login_to_code(
    c: &Client,
    base: &str,
    w: &Wallet,
) -> (RegisteredClient, String, String) {
    let rc = register_client(c, base).await;
    let (verifier, challenge) = pkce_pair();
    let state = "code_state";
    let nrc = no_redirect_client();
    let authorize_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={state}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&challenge),
    );
    let auth_resp = nrc.get(&authorize_url).send().await.unwrap();
    let session_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let q = parse_query(&location);
    let nonce = q.get("nonce").unwrap();
    let domain = q.get("domain").unwrap();
    // Login path enforces Expiration Time (C1 safe subset) — set a future exp.
    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expiration_time =
        (now + chrono::Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {addr}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:\n\
         - {redirect}",
        addr = w.address,
        redirect = rc.redirect_uri,
    );
    let signature = eip191_sign(&w.key, &message);
    let siwx_cookie_value =
        serde_json::to_string(&json!({ "did": w.did, "message": message, "signature": signature }))
            .unwrap();
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state={state}&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&challenge),
    );
    let sign_in_resp = nrc
        .get(&sign_in_url)
        .header(
            "cookie",
            format!(
                "{session_cookie}; siwx={}",
                urlencoding::encode(&siwx_cookie_value)
            ),
        )
        .send()
        .await
        .unwrap();
    let code = parse_query(
        sign_in_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .get("code")
    .unwrap()
    .clone();
    (rc, code, verifier)
}

/// Exchange an auth code for tokens. `Ok(json)` on 200, `Err(status)` otherwise.
async fn exchange_code(
    c: &Client,
    base: &str,
    rc: &RegisteredClient,
    code: &str,
    verifier: &str,
) -> Result<Value, StatusCode> {
    let resp = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code),
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap();
    if resp.status() == StatusCode::OK {
        Ok(resp.json().await.unwrap())
    } else {
        Err(resp.status())
    }
}

// ---------------------------------------------------------------------------
// Introspection (R-F2/F3/F4) + token revocation helpers
// ---------------------------------------------------------------------------

/// Introspect a token with the correct shared secret. Returns the JSON body
/// (`{"active": true, ...}` or `{"active": false}`).
async fn introspect(c: &Client, token: &str) -> Value {
    c.post(format!("{}/oauth2/introspect", oidc()))
        .bearer_auth(SHARED_SECRET)
        .form(&[("token", token)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn token_active(c: &Client, token: &str) -> bool {
    introspect(c, token).await["active"]
        .as_bool()
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Mock control helpers
// ---------------------------------------------------------------------------

async fn mock_reset(c: &Client) {
    c.post(format!("{}/__reset", mock())).send().await.unwrap();
}
async fn mock_seed_device(c: &Client, mxid: &str, device_id: &str) {
    c.post(format!("{}/__seed_device", mock()))
        .json(&json!({ "user_id": mxid, "device_id": device_id, "display_name": "Element" }))
        .send()
        .await
        .unwrap();
}
async fn mock_state(c: &Client) -> Value {
    c.get(format!("{}/__state", mock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn mock_fail(c: &Client, endpoint: &str, mode: &str) {
    c.post(format!("{}/__fail", mock()))
        .json(&json!({ "endpoint": endpoint, "mode": mode }))
        .send()
        .await
        .unwrap();
}

fn device_ids(state: &Value, mxid: &str) -> Vec<String> {
    state["devices"]
        .get(mxid)
        .and_then(|d| d.as_array())
        .map(|a| {
            a.iter()
                .map(|d| d["device_id"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Count of "METHOD path" entries in the mock call log matching a substring.
fn count_calls(state: &Value, needle: &str) -> usize {
    state["calls"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|v| v.as_str().map(|s| s.contains(needle)).unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

/// How many *effective* (state-mutating) DELETEs the mock recorded for a device.
fn effective_deletes(state: &Value, mxid: &str, device_id: &str) -> i64 {
    let key = format!("{mxid}/{device_id}");
    state["effective_deletes"]
        .get(&key)
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
}

// -- account-session cookie helpers -------------------------------------------

fn session_cookie(resp: &reqwest::Response) -> Option<String> {
    for v in resp.headers().get_all("set-cookie") {
        let s = v.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("acct_session=") {
            let val = rest.split(';').next().unwrap_or("").to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// One wallet re-auth establishing an account session; returns `(cookie, csrf)`.
async fn account_reauth(
    c: &Client,
    base: &str,
    w: &Wallet,
    action: &str,
) -> (String, String, Value) {
    let (message, signature) = sign_account_message(w, base);
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": action,
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "account re-auth ({action}) must succeed"
    );
    let cookie = session_cookie(&resp).expect("re-auth must set acct_session cookie");
    let body: Value = resp.json().await.unwrap();
    let csrf = body["csrf"]
        .as_str()
        .expect("re-auth must carry csrf")
        .to_string();
    (cookie, csrf, body)
}

/// Drive `POST /account/action` with a session cookie + csrf. Returns the response.
async fn account_action(
    c: &Client,
    base: &str,
    cookie: &str,
    action: &str,
    device_id: Option<&str>,
    csrf: &str,
) -> reqwest::Response {
    c.post(format!("{base}/account/action"))
        .header("Cookie", format!("acct_session={cookie}"))
        .json(&json!({ "action": action, "device_id": device_id, "csrf": csrf }))
        .send()
        .await
        .unwrap()
}

// ===========================================================================
// H1 (R-F5, R-H2): revoke must NOT delete the Synapse device; logout MUST.
// ===========================================================================

/// RFC 7009 `/oauth2/revoke` is token hygiene: it revokes the session's tokens
/// but must NEVER issue a Synapse `DELETE /devices` (the 2026-06-12 incident).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h1_revoke_does_not_delete_device_but_logout_does() {
    let c = Client::new();
    let base = oidc();

    // --- revoke path: tokens gone, device intact, NO DELETE in the call log ---
    mock_reset(&c).await;
    let w = new_wallet();
    let login = wallet_login(&c, &base, &w).await;
    assert!(
        token_active(&c, &login.access_token).await,
        "token active pre-revoke"
    );
    assert!(
        device_ids(&mock_state(&c).await, &w.mxid).contains(&login.device_id),
        "sign-in must upsert the SIWX device"
    );

    let r = c
        .post(format!("{base}/oauth2/revoke"))
        .form(&[("token", login.access_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "revoke is always 200 (RFC 7009)");

    let state = mock_state(&c).await;
    assert_eq!(
        count_calls(&state, "DELETE "),
        0,
        "REVOKE MUST NOT issue any Synapse DELETE /devices (H1 incident guard)"
    );
    assert!(
        device_ids(&state, &w.mxid).contains(&login.device_id),
        "revoke must leave the Synapse device intact"
    );
    assert!(
        !token_active(&c, &login.access_token).await,
        "revoke must still revoke the session's tokens"
    );

    // --- logout path: explicit intent DOES delete the device ---
    mock_reset(&c).await;
    let w2 = new_wallet();
    let login2 = wallet_login(&c, &base, &w2).await;
    assert!(
        device_ids(&mock_state(&c).await, &w2.mxid).contains(&login2.device_id),
        "second sign-in upserts its device"
    );
    let lo = c
        .post(format!("{base}/_matrix/client/v3/logout"))
        .bearer_auth(&login2.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(lo.status(), 200, "logout returns 200");

    let state = mock_state(&c).await;
    assert!(
        count_calls(&state, "DELETE ") >= 1,
        "logout (explicit sign-out) MUST issue a Synapse DELETE /devices"
    );
    assert!(
        !device_ids(&state, &w2.mxid).contains(&login2.device_id),
        "logout must delete the ending session's Synapse device"
    );
    assert!(
        !token_active(&c, &login2.access_token).await,
        "logout must revoke the session's tokens too"
    );
}

// ===========================================================================
// H2 (R-I1): N sequential sign-ins for one DID => N distinct SIWX_* device ids,
// none recycled.
// ===========================================================================

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h2_sequential_signins_mint_distinct_device_ids() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();

    let n = 4;
    let mut ids = Vec::new();
    for _ in 0..n {
        let login = wallet_login(&c, &base, &w).await;
        assert!(
            login.device_id.starts_with("SIWX_"),
            "each sign-in mints a SIWX_* id, got {}",
            login.device_id
        );
        ids.push(login.device_id);
    }

    // All distinct (no recycling).
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        n,
        "all {n} device ids must be distinct: {ids:?}"
    );

    // Synapse holds all N devices for the one user (additive upserts, no delete).
    let synapse_ids = device_ids(&mock_state(&c).await, &w.mxid);
    for id in &ids {
        assert!(
            synapse_ids.contains(id),
            "device {id} must be present in Synapse (no recycling): have {synapse_ids:?}"
        );
    }
    assert_eq!(
        synapse_ids.len(),
        n,
        "exactly {n} devices upserted, no reuse"
    );
}

// ===========================================================================
// R-F2 / R-F3 / R-F4: introspection correctness + auth.
// ===========================================================================

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn rf2_rf3_rf4_introspection_active_inactive_and_auth() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    let login = wallet_login(&c, &base, &w).await;

    // R-F2: live token is active with correct username/device_id/scope/sub.
    let intro = introspect(&c, &login.access_token).await;
    assert_eq!(intro["active"], true, "live access token must be active");
    assert_eq!(intro["username"], w.localpart, "username == localpart");
    assert_eq!(intro["device_id"], login.device_id, "device_id matches");
    assert_eq!(intro["sub"], w.did, "sub == DID");
    let scope = intro["scope"].as_str().unwrap();
    assert!(
        scope.contains(&format!("urn:matrix:client:device:{}", login.device_id)),
        "scope must carry the device urn: {scope}"
    );
    assert!(
        scope.contains("openid"),
        "scope must include openid: {scope}"
    );

    // R-F3: an unknown token is inactive.
    let unknown = introspect(&c, "mat_thisisnotarealtoken000000000000").await;
    assert_eq!(unknown["active"], false, "unknown token must be inactive");

    // R-F3: a revoked token is inactive.
    c.post(format!("{base}/oauth2/revoke"))
        .form(&[("token", login.access_token.as_str())])
        .send()
        .await
        .unwrap();
    let revoked = introspect(&c, &login.access_token).await;
    assert_eq!(revoked["active"], false, "revoked token must be inactive");

    // R-F4: a wrong shared secret is rejected (401), never a token answer.
    let login2 = wallet_login(&c, &base, &new_wallet()).await;
    let bad = c
        .post(format!("{base}/oauth2/introspect"))
        .bearer_auth("WRONG-SECRET")
        .form(&[("token", login2.access_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status(),
        StatusCode::UNAUTHORIZED,
        "introspection with a wrong shared secret must be 401"
    );
    // And missing auth entirely is also rejected.
    let none = c
        .post(format!("{base}/oauth2/introspect"))
        .form(&[("token", login2.access_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        none.status(),
        StatusCode::UNAUTHORIZED,
        "introspection without auth must be 401"
    );
}

// ===========================================================================
// H8 (R-A2): two CONCURRENT exchanges of the same auth code => exactly one wins.
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h8_concurrent_auth_code_exchange_exactly_one_wins() {
    let base = oidc();
    let c = Client::new();
    // Loop several rounds: a true double-spend window is timing-sensitive.
    for round in 0..5 {
        mock_reset(&c).await;
        let w = new_wallet();
        let (rc, code, verifier) = wallet_login_to_code(&c, &base, &w).await;
        let rc = Arc::new(rc);

        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let cc = Client::new();
            let base = base.clone();
            let rc = rc.clone();
            let code = code.clone();
            let verifier = verifier.clone();
            let b = barrier.clone();
            tasks.push(tokio::spawn(async move {
                b.wait().await;
                exchange_code(&cc, &base, &rc, &code, &verifier).await
            }));
        }
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap().is_ok() {
                ok += 1;
            }
        }
        assert_eq!(
            ok, 1,
            "round {round}: exactly one concurrent code exchange may succeed (try_consume_code)"
        );
    }
}

// ===========================================================================
// H12: device_delete targets EXACTLY the requested device when several exist.
// ===========================================================================

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h12_device_delete_targets_only_requested_device() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    // Sign in so tokens exist, then seed several extra sibling devices.
    let login = wallet_login(&c, &base, &w).await;
    mock_seed_device(&c, &w.mxid, "SIWX_sibling_1").await;
    mock_seed_device(&c, &w.mxid, "SIWX_sibling_2").await;
    let target = "SIWX_sibling_1";

    let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;
    let resp = account_action(
        &c,
        &base,
        &cookie,
        "org.matrix.device_delete",
        Some(target),
        &csrf,
    )
    .await;
    assert_eq!(resp.status(), 200, "device_delete must succeed");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "deleted");
    assert_eq!(body["device_id"], target);

    let ids = device_ids(&mock_state(&c).await, &w.mxid);
    assert!(
        !ids.contains(&target.to_string()),
        "exactly the target is gone"
    );
    assert!(
        ids.contains(&"SIWX_sibling_2".to_string()),
        "sibling_2 must survive"
    );
    assert!(
        ids.contains(&login.device_id),
        "the sign-in device must survive"
    );
    // The sign-in device's token must NOT have been revoked by deleting a sibling.
    assert!(
        token_active(&c, &login.access_token).await,
        "deleting a sibling must not revoke the sign-in device's tokens"
    );
}

// ===========================================================================
// H4: two CONCURRENT device_delete for DIFFERENT devices of the same user =>
// both deleted; neither delete's token-revoke wipes the other device's tokens.
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h4_concurrent_delete_different_devices_no_crosstalk() {
    let base = oidc();
    let c = Client::new();
    for round in 0..5 {
        mock_reset(&c).await;
        let w = new_wallet();
        // Two independent login sessions => two SIWX devices, each with its own token.
        let a = wallet_login(&c, &base, &w).await;
        let b = wallet_login(&c, &base, &w).await;
        assert_ne!(a.device_id, b.device_id, "two distinct devices");

        // One account session drives both deletes (cookie+csrf reused).
        let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;
        let cookie = Arc::new(cookie);
        let csrf = Arc::new(csrf);

        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for dev in [a.device_id.clone(), b.device_id.clone()] {
            let cc = Client::new();
            let base = base.clone();
            let cookie = cookie.clone();
            let csrf = csrf.clone();
            let bar = barrier.clone();
            tasks.push(tokio::spawn(async move {
                bar.wait().await;
                account_action(
                    &cc,
                    &base,
                    &cookie,
                    "org.matrix.device_delete",
                    Some(&dev),
                    &csrf,
                )
                .await
                .status()
            }));
        }
        for t in tasks {
            let st = t.await.unwrap();
            assert_eq!(
                st, 200,
                "round {round}: each concurrent delete must 200 (no 500)"
            );
        }

        // Both devices gone from Synapse; both tokens revoked (each delete revoked
        // its OWN device's tokens — neither wiped nor spared the other improperly).
        let ids = device_ids(&mock_state(&c).await, &w.mxid);
        assert!(!ids.contains(&a.device_id), "device A deleted");
        assert!(!ids.contains(&b.device_id), "device B deleted");
        assert!(!token_active(&c, &a.access_token).await, "A token revoked");
        assert!(!token_active(&c, &b.access_token).await, "B token revoked");
    }
}

// ===========================================================================
// H10: after a terminal account action (deactivate/erase) the acct_session
// cookie cannot drive a further /account/action.
// ===========================================================================

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h10_session_cannot_act_after_terminal_action() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    mock_seed_device(&c, &w.mxid, "SIWX_pre_deactivate").await;

    // Establish a live account session via a benign re-auth (devices_list), so the
    // cookie definitely exists, then drive deactivate THROUGH the session so the
    // server destroys the session on the terminal action.
    let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;

    let resp = account_action(
        &c,
        &base,
        &cookie,
        "org.matrix.account_deactivate",
        None,
        &csrf,
    )
    .await;
    assert_eq!(resp.status(), 200, "deactivate via session must 200");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "deactivated");

    // The SAME cookie must no longer drive any action: the session is destroyed.
    let after = account_action(&c, &base, &cookie, "org.matrix.profile", None, &csrf).await;
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "the account session must be dead after a terminal action (H10)"
    );
}

// ===========================================================================
// H14 (R-J2): Synapse unreachable during device_delete => endpoint does not
// 500, local tokens ARE still revoked, and the failure is surfaced (not 200).
// Uses the mock /__fail toggle on the delete_device endpoint.
// ===========================================================================

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h14_synapse_delete_failure_is_surfaced_not_500() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    // A real signed-in device (so the pre-delete ownership check passes via the
    // working list endpoint) — only the actual DELETE will be faulted.
    let login = wallet_login(&c, &base, &w).await;

    // Arm a 500 on the Synapse DELETE /devices path.
    mock_fail(&c, "delete_device", "500").await;

    let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;
    let resp = account_action(
        &c,
        &base,
        &cookie,
        "org.matrix.device_delete",
        Some(&login.device_id),
        &csrf,
    )
    .await;
    let status = resp.status();
    let text = resp.text().await.unwrap();
    // Always disarm before asserting so later tests are unaffected.
    mock_fail(&c, "delete_device", "off").await;

    // R-J2: never a 500, and never a misleading success.
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "must not 500: {text}"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a Synapse delete failure must surface as a clean 400, got {status}: {text}"
    );
    assert!(
        text.to_lowercase().contains("sign out device") || text.to_lowercase().contains("failed"),
        "the failure must be legibly surfaced: {text}"
    );

    // The Synapse device is still present (the DELETE failed), proving the failure
    // was real and not silently swallowed as a success.
    assert!(
        device_ids(&mock_state(&c).await, &w.mxid).contains(&login.device_id),
        "device must remain since the Synapse delete failed"
    );
}

// ===========================================================================
// RACE REGRESSION GUARDS (formerly CONFIRMED-BUG reproducers for S3-1/S3-3/S3-4,
// gated behind RUN_REPRO=1 while RED). The fixes have landed, so these now run
// unconditionally with the live stack and assert the DESIRED behavior (no token
// resurrection / single device-code redemption). They go RED again if a future
// change reintroduces the race.
//   cargo test --test e2e_race_teardown -- --ignored --test-threads=1
// ===========================================================================

// --- H3 / S3-3: concurrent device_delete on the SAME device ----------------
// Desired: no 500; at most one effective DELETE; AND after the device is deleted,
// NO token for that device remains active. The confirmed bug: the KEYS-scan
// revoke (`revoke_device_tokens`) snapshots the keyspace, then deletes per-key;
// a `/refresh` that writes a NEW token *after* the snapshot but is missed by the
// scan leaves a stale, still-active token (resurrection). To expose this
// deterministically we run a refresh "pump" (chained rotations, each minting a
// fresh access+refresh) throughout the delete window and require that, once the
// dust settles, EVERY minted token is inactive.
// REGRESSION GUARD (was repro S3-3 / H3): device_delete TOCTOU + KEYS-scan revoke
// races a refresh and a stale token survived. Fixed by the per-(user,device) token
// index + atomic Lua revoke + device-revoked tombstone (check-mint-recheck in the
// refresh paths). See fix commit for S3-3/H3. Now runs unconditionally with the
// live stack (no RUN_REPRO gate), asserting survivors == 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h3_concurrent_same_device_delete_revokes_all_tokens() {
    let base = oidc();
    let c = Client::new();
    for round in 0..6 {
        mock_reset(&c).await;
        let w = new_wallet();
        let login = wallet_login(&c, &base, &w).await;
        let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;
        let cookie = Arc::new(cookie);
        let csrf = Arc::new(csrf);
        let dev = Arc::new(login.device_id.clone());

        // Racers aligned on a barrier: two deletes of the SAME device + a refresh
        // pump that keeps minting fresh tokens for that same device throughout.
        let barrier = Arc::new(Barrier::new(3));
        let (c1, c2, cp) = (Client::new(), Client::new(), Client::new());
        let (b1, b2, bp) = (barrier.clone(), barrier.clone(), barrier.clone());
        let (base1, base2, basep) = (base.clone(), base.clone(), base.clone());
        let (k1, k2) = (cookie.clone(), cookie.clone());
        let (s1, s2) = (csrf.clone(), csrf.clone());
        let (d1, d2) = (dev.clone(), dev.clone());
        let first_refresh = login.refresh_token.clone();

        let del1 = tokio::spawn(async move {
            b1.wait().await;
            account_action(&c1, &base1, &k1, "org.matrix.device_delete", Some(&d1), &s1)
                .await
                .status()
        });
        let del2 = tokio::spawn(async move {
            b2.wait().await;
            account_action(&c2, &base2, &k2, "org.matrix.device_delete", Some(&d2), &s2)
                .await
                .status()
        });
        // Pump: chain refreshes (each rotation mints a new access+refresh) for a
        // bounded number of iterations, collecting every access token minted.
        let pump = tokio::spawn(async move {
            bp.wait().await;
            let mut minted: Vec<String> = Vec::new();
            let mut rt = first_refresh;
            for _ in 0..12 {
                let r = cp
                    .post(format!("{basep}/_matrix/client/v3/refresh"))
                    .json(&json!({ "refresh_token": rt }))
                    .send()
                    .await
                    .unwrap();
                if r.status() != StatusCode::OK {
                    break; // refresh chain revoked — expected once the sweep wins
                }
                let j: Value = r.json().await.unwrap();
                if let Some(at) = j["access_token"].as_str() {
                    minted.push(at.to_string());
                }
                match j["refresh_token"].as_str() {
                    Some(next) => rt = next.to_string(),
                    None => break,
                }
            }
            minted
        });

        let st1 = del1.await.unwrap();
        let st2 = del2.await.unwrap();
        let minted = pump.await.unwrap();

        // No 500 from either delete (idempotent-safe).
        assert_ne!(
            st1,
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete 1 must not 500"
        );
        assert_ne!(
            st2,
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete 2 must not 500"
        );

        // At most one EFFECTIVE delete reached Synapse.
        let eff = effective_deletes(&mock_state(&c).await, &w.mxid, &login.device_id);
        assert!(
            eff <= 1,
            "round {round}: at most one effective DELETE, got {eff}"
        );

        // The original token must be revoked.
        assert!(
            !token_active(&c, &login.access_token).await,
            "round {round}: original access token must be revoked after delete"
        );
        // No token minted during the delete window may survive (no resurrection).
        // THIS is the confirmed bug: the non-atomic KEYS-scan revoke can miss a
        // token written mid-scan.
        let mut survivors = 0;
        for t in &minted {
            if token_active(&c, t).await {
                survivors += 1;
            }
        }
        eprintln!(
            "[h3] round {round}: eff={eff} minted={} survivors={survivors}",
            minted.len()
        );
        assert_eq!(
            survivors, 0,
            "round {round}: {survivors} of {} refreshed tokens survived the device delete (resurrection)",
            minted.len()
        );
    }
}

// --- H6 / S3-4: account_deactivate (revoke ALL) racing an in-flight refresh -
// Desired: NO token survives — deactivate revokes ALL of the user's tokens, so a
// refresh that races (or follows) the sweep must not yield an active token. The
// confirmed bug: the deactivate sweep is a non-atomic one-shot, so a refresh
// chain keeps minting usable tokens (resurrection). A refresh pump exposes it
// deterministically (same shape as H3).
// REGRESSION GUARD (was repro S3-4 / H6): account_deactivate's non-atomic sweep let
// an in-flight refresh resurrect access. Fixed by planting a per-user deactivation
// tombstone BEFORE the sweep (checked + check-mint-rechecked by the refresh paths).
// See fix commit for S3-4/H6. Now runs unconditionally, asserting survivors == 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h6_deactivate_racing_refresh_no_resurrection() {
    let base = oidc();
    let c = Client::new();
    for round in 0..6 {
        mock_reset(&c).await;
        let w = new_wallet();
        let login = wallet_login(&c, &base, &w).await;
        let (cookie, csrf, _) = account_reauth(&c, &base, &w, "org.matrix.devices_list").await;

        let barrier = Arc::new(Barrier::new(2));
        let (cd, cp) = (Client::new(), Client::new());
        let (bd, bp) = (barrier.clone(), barrier.clone());
        let (based, basep) = (base.clone(), base.clone());
        let first_refresh = login.refresh_token.clone();

        let deact = tokio::spawn(async move {
            bd.wait().await;
            account_action(
                &cd,
                &based,
                &cookie,
                "org.matrix.account_deactivate",
                None,
                &csrf,
            )
            .await
            .status()
        });
        // Pump chained refreshes throughout the deactivate window.
        let pump = tokio::spawn(async move {
            bp.wait().await;
            let mut minted: Vec<String> = Vec::new();
            let mut rt = first_refresh;
            for _ in 0..12 {
                let r = cp
                    .post(format!("{basep}/_matrix/client/v3/refresh"))
                    .json(&json!({ "refresh_token": rt }))
                    .send()
                    .await
                    .unwrap();
                if r.status() != StatusCode::OK {
                    break;
                }
                let j: Value = r.json().await.unwrap();
                if let Some(at) = j["access_token"].as_str() {
                    minted.push(at.to_string());
                }
                match j["refresh_token"].as_str() {
                    Some(next) => rt = next.to_string(),
                    None => break,
                }
            }
            minted
        });

        let st = deact.await.unwrap();
        let minted = pump.await.unwrap();
        assert_eq!(st, 200, "round {round}: deactivate must 200");

        // The original token is gone.
        assert!(
            !token_active(&c, &login.access_token).await,
            "round {round}: original token must be revoked by deactivate"
        );
        // No refreshed token may survive: deactivate revokes ALL the user's tokens.
        // THE BUG: the non-atomic sweep lets refreshed tokens survive (resurrection).
        let mut survivors = 0;
        for t in &minted {
            if token_active(&c, t).await {
                survivors += 1;
            }
        }
        eprintln!(
            "[h6] round {round}: minted={} survivors={survivors}",
            minted.len()
        );
        assert_eq!(
            survivors, 0,
            "round {round}: {survivors} of {} refreshed tokens survived account_deactivate (resurrection)",
            minted.len()
        );
    }
}

// --- H9 / S3-1: device-code Approved branch is double-redeemable ------------
// Desired: two concurrent token polls for one approved device_code mint at most
// one token pair. The bug: delete-after-issuance with no atomic claim, so both
// polls can mint tokens.
// REGRESSION GUARD (was repro S3-1 / H9): the device-code Approved branch deleted the
// code only AFTER token issuance, so two concurrent polls each minted a token pair.
// Fixed by an atomic SETNX claim (try_claim_device_code) before issuing. See fix
// commit for S3-1/H9. Now runs unconditionally, asserting at most one token minted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h9_device_code_approved_no_double_redemption() {
    let base = oidc();
    let c = Client::new();
    for round in 0..8 {
        mock_reset(&c).await;
        let w = new_wallet();

        // Register a client and request a device code (RFC 8628 = form-encoded).
        let rc = register_client(&c, &base).await;
        let da: Value = c
            .post(format!("{base}/device_authorization"))
            .form(&[("client_id", rc.client_id.as_str()), ("scope", "openid")])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let device_code = da["device_code"].as_str().unwrap().to_string();
        let user_code = da["user_code"].as_str().unwrap().to_string();

        // Approve it with the wallet (CAIP-122 over the device-approval message).
        let domain = reqwest::Url::parse(&base)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        let nonce = "deviceapprovalnonce";
        let message = format!(
            "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nApprove device login.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z",
            addr = w.address,
        );
        let signature = eip191_sign(&w.key, &message);
        let approve = c
            .post(format!("{base}/device"))
            .json(&json!({
                "user_code": user_code, "action": "approve",
                "did": w.did, "message": message, "signature": signature
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            approve.status(),
            200,
            "round {round}: device approval must 200"
        );

        // Two concurrent token polls for the SAME approved device_code.
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let cc = Client::new();
            let base = base.clone();
            let cid = rc.client_id.clone();
            let dc = device_code.clone();
            let bar = barrier.clone();
            tasks.push(tokio::spawn(async move {
                bar.wait().await;
                let r = cc
                    .post(format!("{base}/token"))
                    .form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ("device_code", dc.as_str()),
                        ("client_id", cid.as_str()),
                    ])
                    .send()
                    .await
                    .unwrap();
                if r.status() == StatusCode::OK {
                    let j: Value = r.json().await.unwrap();
                    j["access_token"].as_str().map(|s| s.to_string())
                } else {
                    None
                }
            }));
        }
        let mut minted = Vec::new();
        for t in tasks {
            if let Some(tok) = t.await.unwrap() {
                minted.push(tok);
            }
        }
        // DESIRED: at most one token pair minted (no double redemption).
        assert!(
            minted.len() <= 1,
            "round {round}: device_code must be redeemable at most once, minted {} tokens",
            minted.len()
        );
    }
}
