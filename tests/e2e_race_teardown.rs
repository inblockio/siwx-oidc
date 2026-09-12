//! Deterministic HTTP E2E suite guarding the device-removal / session-cleanup
//! RACE and TEARDOWN hazards of siwx-oidc (hazard register H1..H14 in
//! `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`).
//!
//! Targets the MOCK stack brought up by `e2e/up.sh`:
//!   - siwx-oidc on :8080  (SIWEOIDC_HOST)
//!   - Synapse mock on :8090 (SYNAPSE_MOCK) — records a call log, supports
//!     /__reset, /__seed_user, /__seed_device, /__state, /__set_secret,
//!     /__reject_admin_token, /__profile, /__fail.
//!
//! The mock serves the TWO Synapse credential surfaces siwx-oidc has used since
//! the 1.157 port (MAS shared secret vs a minted admin-scoped token) and
//! validates the latter by really introspecting it, so an authorization
//! regression fails here rather than in production. It mirrors
//! `src/synapse_client.rs`'s route list and drifts silently when that file moves
//! an endpoint — see `e2e/README.md` for the one-line drift check.
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
use siwx_oidc::mxid::{legacy_localpart, localpart_for};
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
    /// The localpart Synapse/TokenMetadata actually ends up using for this
    /// wallet. Every test in this file `mock_reset()`s and then generates a
    /// FRESH random wallet, so the DID has no account under either scheme
    /// (legacy or modern) when the real `/sign_in` (via `wallet_login`) first
    /// provisions it — `resolve_identity` (`src/localpart.rs`, binary crate)
    /// therefore classifies it as genuinely new and hands it the MODERN
    /// base36 shape (`siwx_oidc::mxid::localpart_for`, imported above — the
    /// pure derivation lives in the library crate precisely so this
    /// integration test can call the real implementation instead of
    /// hand-copying it). This is deliberately NOT the legacy
    /// `did.replace(':', "-").to_lowercase()` shape any more: that shape is
    /// used ONLY for an account that already existed before this DID's first
    /// sign-in (grandfathering — see `tests/e2e_oauth_binding.rs`'s
    /// `mock_seed_user`, which pre-seeds the LEGACY shape for exactly that
    /// scenario and is unaffected by this change).
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
    // A brand-new random DID with no existing account -> resolve_identity
    // hands it the MODERN (base36) localpart. See the Wallet doc for why this
    // is no longer the legacy shape.
    let localpart = localpart_for(&did);
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
/// body). C1: the account re-auth now requires a server-issued single-use nonce
/// bound to the `action`, plus an Expiration Time and the action Resources, so we
/// fetch the nonce from `GET /account/nonce?action=...` and sign those exact
/// values — mirroring the embedded page.
async fn sign_account_message(
    c: &Client,
    w: &Wallet,
    base: &str,
    action: &str,
) -> (String, String) {
    let domain = reqwest::Url::parse(base)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let np: Value = c
        .get(format!("{base}/account/nonce?action={action}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = np["nonce"].as_str().unwrap();
    let expiration_time = np["expiration_time"].as_str().unwrap();
    let resources: Vec<String> = np["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nConfirm account action.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z\nExpiration Time: {expiration_time}\nResources:{res}",
        addr = w.address,
        res = resources.concat(),
    );
    let sig = eip191_sign(&w.key, &message);
    (message, sig)
}

/// Fetch a server-issued device-approval nonce and build the CAIP-122 message the
/// `/device` page JS signs (C1). Returns `(message, 0x-signature)`.
async fn sign_device_message(
    c: &Client,
    w: &Wallet,
    base: &str,
    user_code: &str,
) -> (String, String) {
    let domain = reqwest::Url::parse(base)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let np: Value = c
        .get(format!("{base}/device/nonce?user_code={user_code}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = np["nonce"].as_str().unwrap();
    let expiration_time = np["expiration_time"].as_str().unwrap();
    let resources: Vec<String> = np["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nApprove device login.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z\nExpiration Time: {expiration_time}\nResources:{res}",
        addr = w.address,
        res = resources.concat(),
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
/// Mark a localpart as an EXISTING account without seeding a device.
///
/// `reject_if_new_identity` (`src/webauthn.rs`) 400s an unprovisioned identity on
/// the device-approval path, logging `rejecting new-identity (no existing account)
/// outside login flow`. That gate is correct and is documented policy. Tests that
/// approve a device for a wallet which has never signed in must therefore declare
/// the account as returning, or they assert against the wrong precondition.
///
/// Must be called AFTER `mock_reset`, which clears the existing-user set.
async fn mock_seed_user(c: &Client, localpart: &str) {
    c.post(format!("{}/__seed_user", mock()))
        .json(&json!({ "localpart": localpart }))
        .send()
        .await
        .unwrap();
}
/// Force a user's Synapse `profiles` row into one of the three states
/// `synapse_client::has_profile_row` must tell apart: `"present"`, `"empty"`
/// (row exists, displayname and avatar both null) or `"absent"` (a `users` row
/// with NO `profiles` row — element-hq/synapse#19702).
async fn mock_profile(c: &Client, mxid: &str, state: &str) {
    c.post(format!("{}/__profile", mock()))
        .json(&json!({ "user_id": mxid, "state": state }))
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

/// The wire shape of a Synapse device deletion, as of the Synapse 1.157 port.
///
/// `synapse_client::delete_device` used to issue
/// `DELETE /_synapse/admin/v2/users/{mxid}/devices/{id}`. Synapse 1.157 deleted
/// the `admin_token` shim that made the admin API reachable with the MAS shared
/// secret, so the call moved to `POST /_synapse/mas/delete_device` with a
/// `{localpart, device_id}` body.
///
/// H1's invariant did not change — revoke must delete NO device, an explicit
/// logout must delete exactly the ending one — but the mock call log this is
/// read out of now speaks the new dialect, and the old needle (`"DELETE "`)
/// matched nothing at all afterwards. That is a needle that can only ever go
/// green, which is worse than no assertion: it is why the logout half of this
/// test was the single failure left after the mock was brought up to the
/// current contract (audit finding D12).
const DELETE_DEVICE_CALL: &str = "POST /_synapse/mas/delete_device";

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
    let (message, signature) = sign_account_message(c, w, base, action).await;
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
// GRANDFATHER (2026-09-09, Tim): an account that already exists under the
// LEGACY localpart (`did.replace(':', "-").to_lowercase()`) keeps it forever
// on real sign-in — Synapse has no user-rename API, so `resolve_identity`
// checks the legacy shape FIRST and, if it is already taken, never considers
// the modern base36 shape. This is the one invariant the whole
// matrix.org-policy-server migration depends on: get it wrong and every
// pre-migration user is silently handed a brand-new, empty account.
// ===========================================================================

/// A DID that already has an account under the LEGACY localpart must sign in
/// under that SAME legacy localpart — never the modern base36 shape a
/// genuinely new DID would get today. Drives the real `/authorize ->
/// /sign_in -> /token` flow (not just a direct provisioning call), so this
/// proves the end-to-end HTTP behavior, not just the resolution function.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn grandfathered_legacy_account_keeps_legacy_localpart_on_real_signin() {
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;

    // new_wallet()'s `localpart`/`mxid` are the MODERN (base36) shape a
    // brand-new DID gets today — see the Wallet doc. Compute the legacy shape
    // separately to simulate a pre-2026-09 account for this same DID.
    let w = new_wallet();
    let legacy_localpart = legacy_localpart(&w.did);
    let legacy_mxid = format!("@{legacy_localpart}:{SERVER_NAME}");
    assert_ne!(
        legacy_localpart, w.localpart,
        "sanity: legacy and modern really differ for this DID"
    );

    // Simulate a pre-2026-09 account: the LEGACY localpart already exists,
    // BEFORE this wallet ever signs in through this server.
    mock_seed_user(&c, &legacy_localpart).await;

    // A REAL sign-in through the actual /authorize -> /sign_in -> /token flow.
    let login = wallet_login(&c, &base, &w).await;

    // TokenMetadata.username (surfaced via introspection) must be the LEGACY
    // localpart, never the modern shape a genuinely new DID would get.
    let intro = introspect(&c, &login.access_token).await;
    assert_eq!(
        intro["username"], legacy_localpart,
        "a grandfathered account must sign in under its LEGACY localpart"
    );

    // The Synapse device must land on the LEGACY mxid, never the modern one.
    let state = mock_state(&c).await;
    assert!(
        device_ids(&state, &legacy_mxid).contains(&login.device_id),
        "sign-in must provision the device under the grandfathered legacy mxid"
    );
    assert!(
        !device_ids(&state, &w.mxid).contains(&login.device_id),
        "sign-in must NOT create a second, modern-shaped account for an existing user"
    );
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
        count_calls(&state, DELETE_DEVICE_CALL),
        0,
        "REVOKE MUST NOT delete the Synapse device (H1 incident guard)"
    );
    // Belt and braces: the PRE-1.157 dialect must be absent too. Without this a
    // revert to `DELETE /_synapse/admin/v2/users/{mxid}/devices/{id}` would slip
    // past the needle above and this guard would pass while revoke was once
    // again wedging users' cross-signing identity.
    assert_eq!(
        count_calls(&state, "DELETE "),
        0,
        "REVOKE MUST NOT issue the legacy admin-API DELETE /devices either"
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
        count_calls(&state, DELETE_DEVICE_CALL) >= 1,
        "logout (explicit sign-out) MUST issue a Synapse device deletion \
         ({DELETE_DEVICE_CALL})"
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
    const ROUNDS: usize = 6;
    let mut total_minted = 0usize;
    let mut rounds_with_mints = 0usize;
    let base = oidc();
    let c = Client::new();
    for round in 0..ROUNDS {
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

        total_minted += minted.len();
        if !minted.is_empty() {
            rounds_with_mints += 1;
        }
    }

    eprintln!(
        "[h3] totals across {ROUNDS} rounds: minted={total_minted} in \
         {rounds_with_mints} round(s)"
    );

    // ANTI-VACUITY — the guard h6 grew and this test, its twin, never had.
    //
    // `survivors == 0` is trivially true over an EMPTY `minted`, so a run where
    // the pump never lands a refresh inside the delete window reports a
    // confident green while proving nothing about resurrection. h6 sat in
    // exactly that state undetected (measured: zero pump mints in all six
    // rounds, twice, a remediation apart). Nothing structural protected h3 from
    // the same fate — it merely happened to be winning its race — so the
    // absence of this check was a silent dependency on timing, not a design.
    //
    // Unlike h6's, this window is real and the pump does win it: measured
    // 2026-09-13, `minted=1` in 6 of 6 rounds. It is not wide, though — the
    // refresh answers in ~11ms and the device-revoked tombstone lands after the
    // Synapse `delete_device` round trip, so a slower runner can lose a round.
    // Hence an aggregate rather than a per-round requirement: a single lost
    // round is timing, all six lost is a test that no longer tests anything.
    // The per-round `[h3]` lines above show the distribution, so a decay from
    // 6/6 toward 1/6 is visible in the log BEFORE it becomes a failure here.
    //
    // If this fires, the fix is to widen the window or redesign the pump, NOT to
    // delete the check: deleting it restores a test that can only ever pass.
    assert!(
        total_minted > 0,
        "VACUOUS RUN: the refresh pump minted 0 tokens inside the delete window \
         across all {ROUNDS} rounds, so `survivors == 0` proved nothing. The \
         resurrection scenario was never exercised — see the comment above \
         before touching this assertion."
    );
}

// --- H6 / S3-4: account_deactivate (revoke ALL) vs. a refresh pump ----------
// REGRESSION GUARD (was repro S3-4 / H6): account_deactivate's non-atomic sweep let
// an in-flight refresh resurrect access. Fixed by planting a per-user deactivation
// tombstone BEFORE the sweep (checked + check-mint-rechecked by the refresh paths).
//
// WHAT THIS TEST ACTUALLY PROVES — AND WHAT IT DOES NOT.
//
// It was called `h6_deactivate_racing_refresh_no_resurrection` and it does not
// race. Instrumented 2026-09-13, six rounds, six identical results:
//
//     seeded=1  post_barrier=0  first_status=401  ("M_UNKNOWN_TOKEN",
//                                                  "Session has been revoked")
//     first post-barrier refresh answered in ~11ms; deactivate took ~77ms
//
// The post-barrier loop body NEVER RUNS. Every token this test checks is the
// pre-barrier seed, so the property it establishes is the SEQUENTIAL one — "a
// token minted before the deactivate is revoked by it, and every later refresh
// is refused" — not the concurrent one its old name claimed. The 2026-09-10
// remediation that added the seed and the `total_minted > 0` guard fixed the
// silent-zero, but the guard it added is satisfied ENTIRELY by that seed, so the
// concurrent half stayed unexercised and unreported.
//
// The deactivate wins because it is BUILT to win: `account.rs` plants the
// deactivation tombstone as the first thing the handler does, before the Synapse
// call and before the sweep ("Plant the deactivation tombstone FIRST (S3-4/H6)").
// That is one cheap Redis SET after session validation, while a refresh is a
// multi-step read-mint-write. A client cannot reliably get its tombstone check in
// first, and the resurrection window it would then need — check before the plant,
// WRITE after the sweep ~70ms later — is closed a second time by the
// check-mint-recheck rollback. So the race is not merely hard to hit here: the
// fix is what makes it unhittable, and a test that demanded a post-barrier mint
// would be permanently red against correct code.
//
// The barrier is therefore KEPT and the post-barrier outcome is now ASSERTED
// rather than ignored. If a future change moves the tombstone later — the exact
// regression that would reopen S3-4 — post-barrier refreshes start succeeding,
// this test starts exercising the concurrent path for real, and `survivors == 0`
// becomes a live question again. Until then the assertion below pins the reason
// the loop does not run: the refusal must be the DEACTIVATION tombstone
// (401 M_UNKNOWN_TOKEN), never some unrelated breakage in the pump. That is the
// difference between "the race did not happen" and "the test did not work", and
// telling those two apart is the whole point of this rewrite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h6_deactivate_revokes_every_minted_token_and_the_tombstone_wins() {
    const ROUNDS: usize = 6;
    let mut total_seeded = 0usize;
    let mut total_post_barrier = 0usize;
    let base = oidc();
    let c = Client::new();
    for round in 0..ROUNDS {
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
        // Pump chained refreshes throughout the deactivate window. It reports
        // the two halves SEPARATELY: conflating them is what let the old
        // `total_minted > 0` guard be satisfied by the seed alone.
        let pump = tokio::spawn(async move {
            let mut seeded: Vec<String> = Vec::new();
            let mut post_barrier: Vec<String> = Vec::new();
            let mut first_post_refusal: Option<(StatusCode, String)> = None;
            let mut rt = first_refresh;

            // SEED ONE REFRESH *BEFORE* THE BARRIER.
            //
            // Measured 2026-09-10: without this the pump minted NOTHING in all
            // six rounds. It breaks on the first non-200, and the deactivate
            // won the barrier race every single time, so the very first refresh
            // answered 401 and the `survivors == 0` assertion below passed
            // while checking an EMPTY set — a test that could only ever pass.
            //
            // Seeding guarantees at least one refreshed token exists when the
            // deactivate sweep runs. Measured again 2026-09-13: it is also the
            // ONLY token this test ever checks, because the post-barrier loop
            // below still never runs (see the header comment). Do not
            // "simplify" the seed away, and do not let it stand in for the
            // post-barrier half — they are counted separately on purpose.
            let seed = cp
                .post(format!("{basep}/_matrix/client/v3/refresh"))
                .json(&json!({ "refresh_token": rt }))
                .send()
                .await
                .unwrap();
            if seed.status() == StatusCode::OK {
                let j: Value = seed.json().await.unwrap();
                if let Some(at) = j["access_token"].as_str() {
                    seeded.push(at.to_string());
                }
                if let Some(next) = j["refresh_token"].as_str() {
                    rt = next.to_string();
                }
            }

            bp.wait().await;
            for _ in 0..12 {
                let r = cp
                    .post(format!("{basep}/_matrix/client/v3/refresh"))
                    .json(&json!({ "refresh_token": rt }))
                    .send()
                    .await
                    .unwrap();
                if r.status() != StatusCode::OK {
                    // Record WHY the chain stopped. "The race was lost" and "the
                    // pump was broken" both produce zero post-barrier mints and
                    // must not look alike.
                    let st = r.status();
                    let body: Value = r.json().await.unwrap_or(Value::Null);
                    first_post_refusal = Some((
                        st,
                        body["errcode"]
                            .as_str()
                            .unwrap_or("<no errcode>")
                            .to_string(),
                    ));
                    break;
                }
                let j: Value = r.json().await.unwrap();
                if let Some(at) = j["access_token"].as_str() {
                    post_barrier.push(at.to_string());
                }
                match j["refresh_token"].as_str() {
                    Some(next) => rt = next.to_string(),
                    None => break,
                }
            }
            (seeded, post_barrier, first_post_refusal)
        });

        let st = deact.await.unwrap();
        let (seeded, post_barrier, first_post_refusal) = pump.await.unwrap();
        assert_eq!(st, 200, "round {round}: deactivate must 200");

        // ANTI-VACUITY, PART 1: the seed must exist. It is the token the sweep is
        // judged on, so a round without it asserts nothing whatsoever. The old
        // aggregate guard could be satisfied by a single lucky round; this is
        // per-round and cannot.
        assert_eq!(
            seeded.len(),
            1,
            "round {round}: the pre-barrier seed refresh must mint exactly one \
             token — without it `survivors == 0` below is checked against an \
             EMPTY set and proves nothing (see the header comment)"
        );

        // The original token is gone.
        assert!(
            !token_active(&c, &login.access_token).await,
            "round {round}: original token must be revoked by deactivate"
        );
        // No refreshed token may survive: deactivate revokes ALL the user's tokens.
        // THE BUG: the non-atomic sweep lets refreshed tokens survive (resurrection).
        let minted: Vec<&String> = seeded.iter().chain(post_barrier.iter()).collect();
        let mut survivors = 0;
        for t in &minted {
            if token_active(&c, t).await {
                survivors += 1;
            }
        }
        eprintln!(
            "[h6] round {round}: seeded={} post_barrier={} survivors={survivors} \
             first_post_refusal={first_post_refusal:?}",
            seeded.len(),
            post_barrier.len()
        );
        assert_eq!(
            survivors, 0,
            "round {round}: {survivors} of {} refreshed tokens survived account_deactivate (resurrection)",
            minted.len()
        );

        // ANTI-VACUITY, PART 2: the post-barrier half must have a LEGIBLE
        // outcome. Either the refresh won the race and minted (checked for
        // survival just above), or it was refused BY THE DEACTIVATION TOMBSTONE
        // — 401 M_UNKNOWN_TOKEN, from either `compat::refresh`'s pre-check or
        // its check-mint-recheck rollback. Any other answer means the pump broke
        // for a reason unrelated to deactivation, which is precisely the state
        // this test spent two remediations silently sitting in.
        match (post_barrier.len(), &first_post_refusal) {
            (0, None) => panic!(
                "round {round}: the post-barrier pump neither minted nor was \
                 refused — it did not run at all"
            ),
            (0, Some((status, errcode))) => {
                assert_eq!(
                    *status,
                    StatusCode::UNAUTHORIZED,
                    "round {round}: a refresh after account_deactivate must be \
                     refused with 401, got {status} ({errcode})"
                );
                assert_eq!(
                    errcode, "M_UNKNOWN_TOKEN",
                    "round {round}: the refusal must be the DEACTIVATION \
                     tombstone, not an unrelated pump failure"
                );
            }
            _ => {
                // The race was won: post-barrier tokens exist and were just
                // proven dead. This is the concurrent path the test is for, and
                // reaching it is a strictly better outcome than the branch above.
            }
        }

        total_seeded += seeded.len();
        total_post_barrier += post_barrier.len();
    }

    eprintln!(
        "[h6] totals across {ROUNDS} rounds: seeded={total_seeded} \
         post_barrier={total_post_barrier}"
    );

    // The aggregate guard counts ONLY the pre-barrier seeds, because that is the
    // only thing this test can honestly require. The previous version summed both
    // halves into one `total_minted > 0`, which read like a guarantee that the
    // race had been exercised and was in fact satisfied by the seed alone in
    // every round ever measured. `total_post_barrier` is REPORTED, never
    // required: demanding it would make this test permanently red against
    // correct code (the header comment explains why the tombstone always wins).
    // If it is ever non-zero, the concurrent path ran — read the header before
    // concluding that is good news, because it may mean the tombstone moved.
    assert_eq!(
        total_seeded, ROUNDS,
        "VACUOUS RUN: only {total_seeded} of {ROUNDS} rounds seeded a token \
         before the barrier, so those rounds checked `survivors == 0` against an \
         empty set and proved nothing."
    );
}

// --- H9 / S3-1: device-code Approved branch is double-redeemable ------------
// Desired: two concurrent token polls for one APPROVED device_code mint EXACTLY
// one token pair — one winner, one loser refused with an RFC 8628 error. The
// bug: delete-after-issuance with no atomic claim, so both polls could mint.
// REGRESSION GUARD (was repro S3-1 / H9): the device-code Approved branch deleted the
// code only AFTER token issuance, so two concurrent polls each minted a token pair.
// Fixed by an atomic SETNX claim (try_claim_device_code) before issuing. See fix
// commit for S3-1/H9. Now runs unconditionally.
//
// THE ASSERTION USED TO BE `minted.len() <= 1` — AND ZERO SATISFIES THAT.
//
// "At most one" is half the invariant. The half it omits is the half that says
// the grant WORKS, and omitting it made this test blind to a device-code grant
// that issues nothing to anybody. Measured 2026-09-13: an auditor patched the
// Approved branch so the claim never succeeded — a totally broken RFC 8628
// grant — rebuilt, and ran every suite CI runs. `e2e_account_management` 6/6,
// `e2e_oauth_binding` 11/11, `e2e_race_teardown` 14/14 (this test included),
// `e2e_resolve_http` 12/12 and 259 unit tests all stayed GREEN. The one test
// that went red, `e2e_device_code::device_code_grant_end_to_end`, was `#[ignore]`d
// and ran in no CI job at all (it is promoted now — see the `rust-e2e-mock` job
// in `.github/workflows/ci.yml`). This test was the only CI-visible guard on the
// whole grant, and a grant minting zero tokens passed it.
//
// So it now asserts the invariant end to end: EXACTLY one poll is served, the
// token it got is really usable (introspection says active — a 200 carrying a
// junk string is not a redemption), and the other poll is refused with a
// legitimate RFC 8628 error rather than a 500.
//
// There is no legitimate way for a round to mint zero, which is why `== 1` is
// assertable and not merely hoped for: the code is APPROVED before the polls
// start (asserted above), `try_claim_device_code` is a SETNX on a key nothing
// else can hold, and the branch behind that claim has no best-effort exit that
// swallows a failure — the Synapse work inside it is logged, never fatal. A
// round that mints zero means the grant is broken. Do not weaken this back to
// `<= 1` to get a green run; `<= 1` is what a broken grant already passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn h9_device_code_approved_no_double_redemption() {
    const ROUNDS: usize = 8;
    let mut total_minted = 0usize;
    let base = oidc();
    let c = Client::new();
    for round in 0..ROUNDS {
        mock_reset(&c).await;
        let w = new_wallet();
        // AFTER the reset (which clears the existing-user set): this test is about
        // double-redemption, not about account creation policy. Without it the
        // new-identity gate 400s the approval and the race is never exercised.
        mock_seed_user(&c, &w.localpart).await;

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
        // C1: fetch the server-issued single-use nonce bound to this user_code.
        let (message, signature) = sign_device_message(&c, &w, &base, &user_code).await;
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
                // Keep the REFUSAL, not just the absence of a token: "nobody was
                // served" and "one poll was served" are only distinguishable if
                // the loser's answer is recorded too.
                let status = r.status();
                let body: Value = r.json().await.unwrap_or(Value::Null);
                (status, body)
            }));
        }
        let mut outcomes: Vec<(StatusCode, Value)> = Vec::new();
        for t in tasks {
            outcomes.push(t.await.unwrap());
        }
        let minted: Vec<String> = outcomes
            .iter()
            .filter(|(st, _)| *st == StatusCode::OK)
            .filter_map(|(_, b)| b["access_token"].as_str().map(|s| s.to_string()))
            .collect();
        let refused: Vec<(StatusCode, String)> = outcomes
            .iter()
            .filter(|(st, _)| *st != StatusCode::OK)
            .map(|(st, b)| {
                (
                    *st,
                    b["error"]
                        .as_str()
                        .unwrap_or("<no error member>")
                        .to_string(),
                )
            })
            .collect();
        eprintln!(
            "[h9] round {round}: minted={} refused={refused:?}",
            minted.len()
        );

        // DESIRED: EXACTLY one token pair minted. `> 1` is the double-redemption
        // bug this test is named for; `== 0` is a device-code grant that serves
        // nobody, which the former `<= 1` assertion accepted as a pass.
        assert_eq!(
            minted.len(),
            1,
            "round {round}: an APPROVED device_code must be redeemed EXACTLY once \
             by two concurrent polls, minted {} (refused: {refused:?}). More than \
             one is double redemption; ZERO is a broken grant, and zero is what \
             the old `<= 1` assertion could not see.",
            minted.len()
        );

        // A 200 is not a redemption unless the thing it carried is a token. This
        // is what makes the "at least one" half real rather than a status check.
        assert!(
            token_active(&c, &minted[0]).await,
            "round {round}: the winning poll's access token must be a real, \
             introspectable, ACTIVE token"
        );

        // And the loser is refused legibly: RFC 8628 `authorization_pending`
        // while the winner holds the claim, or `expired_token` if it arrives
        // after the winner deleted the code. Never a 500, never a silent 200.
        for (status, error) in &refused {
            assert_eq!(
                *status,
                StatusCode::BAD_REQUEST,
                "round {round}: the losing poll must be refused with 400, got {status} ({error})"
            );
            assert!(
                matches!(error.as_str(), "authorization_pending" | "expired_token"),
                "round {round}: the losing poll must get an RFC 8628 error, got {error:?}"
            );
        }

        total_minted += minted.len();
    }

    // Aggregate anti-vacuity: one token per round, every round. A suite-wide
    // regression that silently stops serving the grant shows up here even if a
    // single round's `== 1` were ever relaxed.
    assert_eq!(
        total_minted, ROUNDS,
        "{total_minted} tokens minted across {ROUNDS} approved device codes: \
         each approved code must be redeemed exactly once"
    );
}

// ===========================================================================
// Refresh-token rotation GRACE WINDOW (Element-X mobile sign-out fix)
//
// Root cause (see docs/audits/2026-06-23-elementx-refresh-rotation-signout.md):
// rotation hard-deletes the old refresh token with NO grace, so a client that
// LOSES the rotation response (mobile: radio handoff, app suspension,
// cross-process refresh) replays the old token, gets `invalid_grant`, and is
// signed out. Desired: a replay within REFRESH_GRACE_TTL returns the SAME
// successor pair. Covers BOTH refresh entry points (OAuth /token = the path
// Element-X uses, and the compat /_matrix/client/v3/refresh CS-API path). A
// never-issued token still fails closed (grace must not blanket-accept).
//
// This is a normal #[ignore] guard (not RUN_REPRO-gated): it is RED against the
// pre-fix server (replay -> invalid_grant / M_UNKNOWN_TOKEN) and GREEN once the
// grace window lands.
// ===========================================================================

/// Refresh via the OAuth /token endpoint (grant_type=refresh_token) — the path
/// Element-X's matrix-rust-sdk OAuth client uses. Returns (status, json|null).
async fn oauth_refresh(c: &Client, base: &str, refresh_token: &str) -> (StatusCode, Value) {
    let resp = c
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

/// Refresh via the compat CS-API endpoint POST /_matrix/client/v3/refresh.
async fn compat_refresh(c: &Client, base: &str, refresh_token: &str) -> (StatusCode, Value) {
    let resp = c
        .post(format!("{base}/_matrix/client/v3/refresh"))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn refresh_grace_window_tolerates_replay() {
    let base = oidc();
    let c = Client::new();

    // ---- OAuth /token path (the path Element-X uses) ----
    mock_reset(&c).await;
    let w = new_wallet();
    let login = wallet_login(&c, &base, &w).await;

    // First refresh rotates: login.refresh_token is consumed; rt1/at1 are minted.
    let (s1, v1) = oauth_refresh(&c, &base, &login.refresh_token).await;
    assert_eq!(s1, StatusCode::OK, "first /token refresh must succeed");
    let rt1 = v1["refresh_token"].as_str().unwrap().to_string();
    assert!(
        token_active(&c, v1["access_token"].as_str().unwrap()).await,
        "freshly rotated access token must be active"
    );

    // Replay the OLD (just-rotated) refresh token within the grace window.
    // PRE-FIX: invalid_grant (400). POST-FIX: 200 with the SAME successor pair.
    let (s2, v2) = oauth_refresh(&c, &base, &login.refresh_token).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "grace replay of a just-rotated refresh token must succeed (got {s2}); \
         this is the Element-X mobile sign-out bug"
    );
    assert!(
        token_active(&c, v2["access_token"].as_str().unwrap()).await,
        "the access token returned on grace replay must be active"
    );
    assert_eq!(
        v2["refresh_token"].as_str().unwrap(),
        rt1,
        "grace replay must return the SAME successor refresh token (idempotent)"
    );

    // Negative: a well-formed but never-issued refresh token still fails closed.
    let (sbad, _) = oauth_refresh(&c, &base, "mcr_never_issued_grace_probe").await;
    assert_ne!(
        sbad,
        StatusCode::OK,
        "an unknown refresh token must be rejected, never graced"
    );

    // ---- Compat /_matrix/client/v3/refresh path ----
    mock_reset(&c).await;
    let w2 = new_wallet();
    let login2 = wallet_login(&c, &base, &w2).await;

    let (cs1, _) = compat_refresh(&c, &base, &login2.refresh_token).await;
    assert_eq!(cs1, StatusCode::OK, "compat first refresh must succeed");

    // Replay the OLD refresh token on the compat endpoint -> grace.
    let (cs2, cv2) = compat_refresh(&c, &base, &login2.refresh_token).await;
    assert_eq!(
        cs2,
        StatusCode::OK,
        "compat grace replay of a just-rotated refresh token must succeed (got {cs2})"
    );
    assert!(
        token_active(&c, cv2["access_token"].as_str().unwrap()).await,
        "compat grace replay access token must be active"
    );
}

// ===========================================================================
// ATTESTED DID PROFILE FIELD (`io.inblock.did`) — the SIGN-IN path.
//
// `synapse_client::publish_did_field`'s own discrimination logic is unit-tested
// in-process (`synapse_client::tests::h2_*` / `d1_*`), and its behaviour against
// a real patched Synapse is covered by `tests/e2e_did_field_live.rs`. Neither
// answers the question this test asks, which is about `sign_in` rather than
// about the client: publication is best-effort and sits INSIDE
// `oidc::provision_synapse_device`, so a homeserver that cannot accept the write
// must cost the user nothing.
//
// The row-less half is only reachable against a mock. You cannot ask a real
// Synapse for an account with a `users` row and no `profiles` row on demand —
// the three that exist on the dev homeserver are erasure artifacts — which is
// exactly why the mock grew `POST /__profile` (audit finding D12).
// ===========================================================================

/// A healthy sign-in publishes the attested DID field; a sign-in for an account
/// hit by element-hq/synapse#19702 (a `users` row with no `profiles` row) still
/// succeeds, publishing nothing.
///
/// The second half is the one that matters. On a row-less account BOTH the
/// publication PUT and the `provision_user` self-heal answer Synapse's generic
/// 500, so this asserts the login survives two independent server-side failures
/// on its provisioning path. If publication were ever promoted from best-effort
/// to fatal, a handful of pre-existing accounts would become permanently unable
/// to sign in, and nothing else in the suite would notice.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn did_field_is_published_at_signin_and_a_rowless_account_still_signs_in() {
    let c = Client::new();
    let base = oidc();

    // --- healthy account: the field lands --------------------------------
    mock_reset(&c).await;
    let w = new_wallet();
    let login = wallet_login(&c, &base, &w).await;
    assert!(
        !login.access_token.is_empty(),
        "healthy sign-in must issue a token"
    );
    let state = mock_state(&c).await;
    assert_eq!(
        state["profile_fields"][&w.mxid]["io.inblock.did"]["did"],
        json!(w.did),
        "a healthy sign-in must publish the attested DID field for its own mxid"
    );

    // --- row-less account (element-hq/synapse#19702) ----------------------
    // Same wallet, so the account already EXISTS (a `users` row); drop only its
    // `profiles` row. That is the exact shape of the bug: the two rows are
    // independent, and siwx-oidc's D1 logic exists to tell this apart from a
    // homeserver whose database is simply on fire.
    mock_reset(&c).await;
    let w2 = new_wallet();
    wallet_login(&c, &base, &w2).await;
    mock_profile(&c, &w2.mxid, "absent").await;

    let second = wallet_login(&c, &base, &w2).await;
    assert!(
        !second.access_token.is_empty(),
        "a row-less account MUST still be able to sign in — publication is \
         best-effort and must never cost the user their login"
    );
    assert!(
        token_active(&c, &second.access_token).await,
        "the token issued to a row-less account must be a real, usable token"
    );

    let state = mock_state(&c).await;
    // The publication could not be attempted (the PUT 500s), and the self-heal
    // could not repair the row either (`provision_user` with a displayname 500s
    // on the same unguarded fetchone). Both are known conditions of a known-buggy
    // dependency; both resolve when the pinned Synapse image is bumped.
    assert!(
        state["profiles"].get(&w2.mxid).is_none(),
        "the #19702 self-heal is inert on 1.159 — it must NOT appear to succeed \
         here, or this test would prove behaviour no deployed homeserver has"
    );
    assert!(
        state["profile_fields"].get(&w2.mxid).is_none(),
        "no profile row means no MSC4133 field: the publication must not appear \
         to have landed"
    );
    // The D1 "confirm before excusing" probe: a 500 on the PUT is only a
    // HYPOTHESIS of a row-less account, so the client must follow it with a
    // whole-profile GET before reporting the known condition.
    assert!(
        count_calls(
            &state,
            &format!("GET /_matrix/client/v3/profile/{}", w2.mxid)
        ) >= 1,
        "a 500 on the publication PUT must be CONFIRMED by a profile-row probe, \
         never inferred from the status code alone (audit finding D1)"
    );
    // And the sign-in device was still provisioned: the failures are confined to
    // publication, they do not poison the rest of provisioning.
    assert!(
        device_ids(&state, &w2.mxid).contains(&second.device_id),
        "device provisioning must still happen for a row-less account"
    );
}
