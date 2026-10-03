//! Deterministic HTTP E2E suite guarding the device-removal / session-cleanup
//! RACE and TEARDOWN hazards of siwx-oidc (hazard register H1..H14 in
//! `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`, which lives on the
//! `audit/siwx-oidc-functional-harness` branch, not on main).
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
    wallet_from_key(SigningKey::random(&mut OsRng))
}

fn wallet_from_key(key: SigningKey) -> Wallet {
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
#[derive(Clone)]
struct RegisteredClient {
    client_id: String,
    redirect_uri: String,
}

/// A client registered the way Element Web and Element X register: public
/// (`token_endpoint_auth_method: none`). The sessions in this suite are Matrix
/// device sessions, refreshed at both endpoints, and
/// `POST /_matrix/client/v3/refresh` refuses a confidential client's token.
async fn register_client(c: &Client, base: &str) -> RegisteredClient {
    let redirect_uri = format!("{base}/callback");
    let reg: Value = c
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [&redirect_uri],
            "token_endpoint_auth_method": "none",
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
        redirect_uri,
    }
}

/// Tokens returned by the auth-code flow plus the Synapse device id provisioned.
struct LoginResult {
    access_token: String,
    refresh_token: String,
    device_id: String,
    /// The public client the login was made with. The refresh grant at
    /// `/token` binds a token to this client.
    client_id: String,
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
        client_id: rc.client_id.clone(),
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
// GRANDFATHER (2026-09-09, the maintainer): an account that already exists under the
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
// races a refresh and a stale token survived. Fixed by the per-(user,device) grant
// index + atomic Lua revoke + device-revoked tombstone, which the rotation script
// both refresh endpoints run checks in the same atomic step as the mint. See fix
// commit for S3-3/H3. Now runs unconditionally with the live stack (no RUN_REPRO
// gate), asserting survivors == 0.
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
// tombstone BEFORE the sweep, which the rotation script both refresh endpoints run
// checks in the same atomic step as the mint.
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
// That is one cheap Redis SET after session validation, while a refresh is a read
// followed by the rotation script. A client cannot reliably get its tombstone
// check in first, and the resurrection window it would then need — check before
// the plant, WRITE after the sweep ~70ms later — does not exist: the rotation
// script checks the tombstone and writes the successor in one atomic step. So the
// race is not merely hard to hit here: the
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
        // — 401 M_UNKNOWN_TOKEN, from the rotation script's tombstone check,
        // which runs in the same atomic step as the mint. Any other answer
        // means the pump broke for a reason unrelated to deactivation, which is
        // precisely the state this test spent two remediations silently
        // sitting in.
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
        // while the winner holds the claim, `expired_token` if it arrives after
        // the winner deleted the code, or `slow_down`. The poll-rate check reads
        // and writes `last_poll` without a lock, so the second of two
        // simultaneous polls can see the first one's timestamp and be told to
        // back off; RFC 8628 §3.5 makes `slow_down` a legitimate answer to a
        // poll that came too soon. The first reader always reaches the claim,
        // so this cannot excuse a round that mints nothing: `== 1` above is the
        // property. Never a 500, never a silent 200.
        for (status, error) in &refused {
            assert_eq!(
                *status,
                StatusCode::BAD_REQUEST,
                "round {round}: the losing poll must be refused with 400, got {status} ({error})"
            );
            assert!(
                matches!(
                    error.as_str(),
                    "authorization_pending" | "expired_token" | "slow_down"
                ),
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
// Refresh rotation: one live chain (H1, I3) and lost-response recovery (H2, I4)
//
// Both refresh endpoints run the same rotation script. H1: concurrent
// refreshes of one token converge on ONE successor pair, and exactly one chain
// stays live. H2: a replay of the immediately previous refresh token returns
// the same successor pair for as long as that pair is unused, whatever the
// delay (no timer), and is refused as reuse once its access token has been
// accepted. The audit behind the recovery requirement (mobile clients that lose
// a rotation response) is docs/audits/2026-06-23-elementx-refresh-rotation-signout.md.
// ===========================================================================

/// Refresh via the OAuth /token endpoint (grant_type=refresh_token) — the path
/// Element-X's matrix-rust-sdk OAuth client uses. The login's client is
/// public, so the request names it and presents no secret: the refresh grant
/// binds a token to its client. Returns (status, json|null).
async fn oauth_refresh(
    c: &Client,
    base: &str,
    refresh_token: &str,
    login: &LoginResult,
) -> (StatusCode, Value) {
    let resp = c
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", login.client_id.as_str()),
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

/// Which refresh endpoint a test drives.
#[derive(Clone, Copy, Debug)]
enum RefreshAt {
    /// `POST /token`, `grant_type=refresh_token`, as the login's client.
    Token,
    /// `POST /_matrix/client/v3/refresh`.
    Matrix,
}

/// Refresh at `at`; returns the status and the `(access, refresh)` pair on a 200.
async fn refresh_at(
    c: &Client,
    base: &str,
    at: RefreshAt,
    refresh_token: &str,
    login: &LoginResult,
) -> (StatusCode, Value, Option<(String, String)>) {
    let (status, body) = match at {
        RefreshAt::Token => oauth_refresh(c, base, refresh_token, login).await,
        RefreshAt::Matrix => compat_refresh(c, base, refresh_token).await,
    };
    let pair = (status == StatusCode::OK).then(|| {
        (
            body["access_token"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            body["refresh_token"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    });
    (status, body, pair)
}

/// The refusal each endpoint gives an unknown (or reused) refresh token.
fn assert_refused_as_unknown(at: RefreshAt, status: StatusCode, body: &Value, what: &str) {
    match at {
        RefreshAt::Token => {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what} at /token: {body}");
            assert_eq!(body["error"], "invalid_grant", "{what} at /token: {body}");
        }
        RefreshAt::Matrix => {
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{what} at the Matrix endpoint: {body}"
            );
            assert_eq!(
                body["errcode"], "M_UNKNOWN_TOKEN",
                "{what} at the Matrix endpoint: {body}"
            );
        }
    }
}

const H1_PARALLEL: usize = 50;

/// H1: `H1_PARALLEL` concurrent refreshes of one refresh token all succeed and
/// all carry the SAME new pair; afterwards exactly one chain is live.
async fn concurrent_refreshes_converge(at: RefreshAt) {
    let base = oidc();
    let c = Client::new();
    mock_reset(&c).await;
    let login = Arc::new(wallet_login(&c, &base, &new_wallet()).await);

    let barrier = Arc::new(Barrier::new(H1_PARALLEL));
    let mut tasks = Vec::new();
    for _ in 0..H1_PARALLEL {
        let cc = Client::new();
        let base = base.clone();
        let login = login.clone();
        let b = barrier.clone();
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            let (status, body, pair) =
                refresh_at(&cc, &base, at, &login.refresh_token, &login).await;
            (status, body, pair)
        }));
    }
    let mut pairs = Vec::new();
    for t in tasks {
        let (status, body, pair) = t.await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: every concurrent refresh succeeds: {body}"
        );
        pairs.push(pair.unwrap());
    }
    let first = pairs[0].clone();
    assert_ne!(
        first.1, login.refresh_token,
        "{at:?}: the refresh token rotated"
    );
    let distinct: std::collections::HashSet<_> = pairs.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "{at:?}: all {H1_PARALLEL} responses carry the same pair, got {} distinct",
        distinct.len()
    );

    // Exactly one chain: the returned refresh token rotates once, and once that
    // pair is in use neither the original token nor the first successor
    // refreshes any more.
    let (status, body, second) = refresh_at(&c, &base, at, &first.1, &login).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{at:?}: the returned refresh token rotates: {body}"
    );
    let second = second.unwrap();
    assert_ne!(
        second.1, first.1,
        "{at:?}: the second rotation mints a new token"
    );
    assert!(
        token_active(&c, &second.0).await,
        "{at:?}: the new access token is active"
    );
    for (old, what) in [
        (&login.refresh_token, "the original token"),
        (&first.1, "the first successor"),
    ] {
        let (status, body, _) = refresh_at(&c, &base, at, old, &login).await;
        assert_refused_as_unknown(at, status, &body, what);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn concurrent_refreshes_at_the_token_endpoint_converge_on_one_pair() {
    concurrent_refreshes_converge(RefreshAt::Token).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn concurrent_refreshes_at_the_matrix_endpoint_converge_on_one_pair() {
    concurrent_refreshes_converge(RefreshAt::Matrix).await;
}

/// H2: a replay of the previous refresh token returns the same pair while the
/// pair is unused, and is reuse (refused like an unknown token) once its access
/// token has been introspected. Reuse is logged, never acted on (phase A): the
/// live chain keeps working. A never-issued token is refused.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_replay_returns_the_same_pair_until_the_new_access_token_is_used() {
    let base = oidc();
    let c = Client::new();
    for at in [RefreshAt::Token, RefreshAt::Matrix] {
        mock_reset(&c).await;
        let login = wallet_login(&c, &base, &new_wallet()).await;
        let (status, body, pair) = refresh_at(&c, &base, at, &login.refresh_token, &login).await;
        assert_eq!(status, StatusCode::OK, "{at:?}: first refresh: {body}");
        let pair = pair.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let (status, body, replay) = refresh_at(&c, &base, at, &login.refresh_token, &login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: a replay before first use recovers: {body}"
        );
        assert_eq!(
            replay.unwrap(),
            pair,
            "{at:?}: the replay returns the SAME pair"
        );

        assert!(
            token_active(&c, &pair.0).await,
            "{at:?}: the new access token is active"
        );
        let (status, body, _) = refresh_at(&c, &base, at, &login.refresh_token, &login).await;
        assert_refused_as_unknown(at, status, &body, "a replay after the new pair was used");

        let (status, body, _) = refresh_at(&c, &base, at, &pair.1, &login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: reuse revokes nothing in phase A: {body}"
        );

        let (status, body, _) =
            refresh_at(&c, &base, at, "mcr_never_issued_replay_probe", &login).await;
        assert_refused_as_unknown(at, status, &body, "a never-issued token");
    }
}

/// H2: the recovery has no timer. A replay more than a minute after the
/// rotation (the old grace window was 60 s) still returns the same pair, at
/// both endpoints. One real wait covers both.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_replay_after_more_than_a_minute_still_returns_the_same_pair() {
    let base = oidc();
    let c = Client::new();
    mock_reset(&c).await;
    let mut rotated = Vec::new();
    for at in [RefreshAt::Token, RefreshAt::Matrix] {
        let login = wallet_login(&c, &base, &new_wallet()).await;
        let (status, body, pair) = refresh_at(&c, &base, at, &login.refresh_token, &login).await;
        assert_eq!(status, StatusCode::OK, "{at:?}: first refresh: {body}");
        rotated.push((at, login, pair.unwrap()));
    }
    tokio::time::sleep(std::time::Duration::from_secs(65)).await;
    for (at, login, pair) in &rotated {
        let (status, body, replay) = refresh_at(&c, &base, *at, &login.refresh_token, login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: a replay after 65 s recovers: {body}"
        );
        assert_eq!(
            replay.as_ref(),
            Some(pair),
            "{at:?}: the replay returns the SAME pair"
        );
    }
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

// ===========================================================================
// H4 (I1 for tokens): no client-held secret is stored in the clear.
// ===========================================================================

/// The strings a client holds that the server must never store in the clear
/// (I1): every key and every value of the stack Redis is searched for each of
/// them. Add a new kind of client-held secret (authorization codes, session
/// ids, client secrets) with [`ClientHeld::add`] under its own label.
#[derive(Default)]
struct ClientHeld(Vec<(String, String)>);

impl ClientHeld {
    fn add(&mut self, label: impl Into<String>, value: &str) {
        assert!(
            !value.is_empty(),
            "a client-held string to search for is empty"
        );
        self.0.push((label.into(), value.to_string()));
    }

    /// A token and the parts a store could keep without the whole: the body
    /// after its `mat_` / `msa_` / `mcr_` prefix and, for a refresh token
    /// (`mcr_{handle}_{secret}`), the handle and the secret.
    fn add_token(&mut self, label: &str, token: &str) {
        self.add(label, token);
        if let Some((_prefix, body)) = token.split_once('_') {
            self.add(format!("{label} without its prefix"), body);
            if token.starts_with("mcr_") {
                if let Some((handle, secret)) = body.split_once('_') {
                    self.add(format!("{label} handle"), handle);
                    self.add(format!("{label} secret part"), secret);
                }
            }
        }
    }
}

/// The stack's Redis, for a test that inspects what the server stored:
/// `E2E_REDIS_URL`, else the server's own `SIWXOIDC_REDIS_URL` (the CI job sets
/// it for the server and the tests alike), else the legacy `SIWEOIDC_REDIS_URL`
/// (`e2e/env.sh`), else `REDIS_HOST`/`REDIS_PORT`. `None` when none is set.
fn stack_redis_url() -> Option<String> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    var("E2E_REDIS_URL")
        .or_else(|| var("SIWXOIDC_REDIS_URL"))
        .or_else(|| var("SIWEOIDC_REDIS_URL"))
        .or_else(|| {
            Some(format!(
                "redis://{}:{}",
                var("REDIS_HOST")?,
                var("REDIS_PORT")?
            ))
        })
}

/// Every string inside a Redis reply, whatever its shape.
fn reply_strings(value: &bb8_redis::redis::Value, out: &mut Vec<String>) {
    use bb8_redis::redis::Value;
    match value {
        Value::BulkString(bytes) => out.push(String::from_utf8_lossy(bytes).into_owned()),
        Value::SimpleString(s) => out.push(s.clone()),
        Value::VerbatimString { text, .. } => out.push(text.clone()),
        Value::Array(items) | Value::Set(items) => {
            items.iter().for_each(|item| reply_strings(item, out));
        }
        Value::Map(pairs) => pairs.iter().for_each(|(k, v)| {
            reply_strings(k, out);
            reply_strings(v, out);
        }),
        Value::Push { data, .. } => data.iter().for_each(|item| reply_strings(item, out)),
        _ => {}
    }
}

/// What a scan of the whole stack Redis found.
struct RedisScan {
    /// One line per place a client-held string appears: label, database, key.
    hits: Vec<String>,
    /// Every key, as `{db}:{key}`, for positive controls.
    keys: Vec<String>,
}

/// Scan every database of the Redis at `url`: every key, and every value of
/// every type, searched for each client-held string.
async fn scan_redis_for(url: &str, held: &ClientHeld) -> RedisScan {
    use bb8_redis::redis;
    let client = redis::Client::open(url).unwrap_or_else(|e| panic!("stack Redis URL: {e}"));
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .unwrap_or_else(|e| panic!("stack Redis at {url} is unreachable: {e}"));
    let databases: (String, u32) = redis::cmd("CONFIG")
        .arg("GET")
        .arg("databases")
        .query_async(&mut conn)
        .await
        .expect("CONFIG GET databases");
    let mut scan = RedisScan {
        hits: Vec::new(),
        keys: Vec::new(),
    };
    for db in 0..databases.1 {
        let _: () = redis::cmd("SELECT")
            .arg(db)
            .query_async(&mut conn)
            .await
            .unwrap();
        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut conn)
                .await
                .unwrap();
            for raw_key in keys {
                let key = String::from_utf8_lossy(&raw_key).into_owned();
                let kind: String = redis::cmd("TYPE")
                    .arg(&raw_key)
                    .query_async(&mut conn)
                    .await
                    .unwrap();
                let read = match kind.as_str() {
                    "string" => redis::cmd("GET").arg(&raw_key).clone(),
                    "hash" => redis::cmd("HGETALL").arg(&raw_key).clone(),
                    "list" => redis::cmd("LRANGE").arg(&raw_key).arg(0).arg(-1).clone(),
                    "set" => redis::cmd("SMEMBERS").arg(&raw_key).clone(),
                    "zset" => redis::cmd("ZRANGE").arg(&raw_key).arg(0).arg(-1).clone(),
                    "stream" => redis::cmd("XRANGE").arg(&raw_key).arg("-").arg("+").clone(),
                    // Expired between SCAN and TYPE.
                    "none" => continue,
                    other => panic!("key {key}: Redis type `{other}` is not searched"),
                };
                let value: redis::Value = read.query_async(&mut conn).await.unwrap();
                let mut strings = Vec::new();
                reply_strings(&value, &mut strings);
                for (label, secret) in &held.0 {
                    if key.contains(secret.as_str()) {
                        scan.hits
                            .push(format!("{label}: in the key of db {db} `{key}`"));
                    }
                    if strings.iter().any(|s| s.contains(secret.as_str())) {
                        scan.hits.push(format!(
                            "{label}: in the {kind} value of db {db} key `{key}`"
                        ));
                    }
                }
                scan.keys.push(format!("{db}:{key}"));
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
    }
    scan
}

/// Scan, and fail on any client-held string found; returns the scan.
async fn assert_nothing_stored_in_the_clear(
    url: &str,
    held: &ClientHeld,
    stage: &str,
) -> RedisScan {
    let scan = scan_redis_for(url, held).await;
    assert!(
        scan.hits.is_empty(),
        "{stage}: client-held strings stored in the clear (I1):\n  {}",
        scan.hits.join("\n  ")
    );
    scan
}

/// H4 for tokens: after sign-in, refresh at both endpoints, the replay of a
/// lost response (which stores the sealed successor), introspection and RFC
/// 7009 revocation, no key and no value anywhere in the stack Redis contains
/// any access or refresh token the client received, or any part of one. The
/// first scan's positive control (the digest key of the live access token)
/// proves it searched the stack's Redis.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn no_token_the_client_holds_is_stored_in_the_clear() {
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: no_token_the_client_holds_is_stored_in_the_clear: no stack \
                      Redis URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, SIWEOIDC_REDIS_URL or \
                      REDIS_HOST/REDIS_PORT); the keyspace was NOT searched";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };
    let c = Client::new();
    let base = oidc();
    let mut held = ClientHeld::default();

    let login = wallet_login(&c, &base, &new_wallet()).await;
    held.add_token("sign-in access token", &login.access_token);
    held.add_token("sign-in refresh token", &login.refresh_token);

    let (status, body, pair) =
        refresh_at(&c, &base, RefreshAt::Token, &login.refresh_token, &login).await;
    let (access1, refresh1) = pair.unwrap_or_else(|| panic!("refresh at /token: {status} {body}"));
    held.add_token("first refreshed access token", &access1);
    held.add_token("first refreshed refresh token", &refresh1);

    // A lost response replayed: the server keeps the successor pair, sealed.
    let (status, body, replayed) =
        refresh_at(&c, &base, RefreshAt::Matrix, &login.refresh_token, &login).await;
    let (replayed_access, replayed_refresh) =
        replayed.unwrap_or_else(|| panic!("replay at the Matrix endpoint: {status} {body}"));
    held.add_token("replayed access token", &replayed_access);
    held.add_token("replayed refresh token", &replayed_refresh);

    let scan =
        assert_nothing_stored_in_the_clear(&url, &held, "after a refresh and a replay").await;
    let live_access_key = format!("at/{}", hex::encode(Sha256::digest(access1.as_bytes())));
    assert!(
        scan.keys
            .iter()
            .any(|k| k.ends_with(&format!(":{live_access_key}"))),
        "positive control: the scan of {url} finds the live access token's digest key \
         {live_access_key} ({} keys scanned); is this the stack's Redis?",
        scan.keys.len()
    );

    assert!(
        token_active(&c, &access1).await,
        "the refreshed access token is active"
    );
    let (status, body, pair) = refresh_at(&c, &base, RefreshAt::Matrix, &refresh1, &login).await;
    let (access2, refresh2) =
        pair.unwrap_or_else(|| panic!("refresh at the Matrix endpoint: {status} {body}"));
    held.add_token("second refreshed access token", &access2);
    held.add_token("second refreshed refresh token", &refresh2);
    assert!(
        token_active(&c, &access2).await,
        "the second access token is active"
    );
    assert_nothing_stored_in_the_clear(&url, &held, "after introspection").await;

    let r = c
        .post(format!("{base}/oauth2/revoke"))
        .form(&[("token", refresh2.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "revoke is always 200 (RFC 7009)"
    );
    assert!(
        !token_active(&c, &access2).await,
        "the revoked session's access token is inactive"
    );
    assert_nothing_stored_in_the_clear(&url, &held, "after revocation").await;
}

// ===========================================================================
// R1: the tokens a build before the grant record wrote keep working after the
// upgrade (design 5.8, item 10 of Phase 2a).
// ===========================================================================

/// A session as a build before the grant record left it in the store: raw
/// `token/{raw}` entries for its access and refresh token.
struct LegacySession {
    at: RefreshAt,
    client_id: String,
    access_token: String,
    refresh_token: String,
}

impl LegacySession {
    fn login(&self) -> LoginResult {
        LoginResult {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            device_id: String::new(),
            client_id: self.client_id.clone(),
        }
    }
}

/// Whether `token` is a refresh token in the grant format,
/// `mcr_{22 base62}_{32 base62}`.
fn is_grant_refresh_token(token: &str) -> bool {
    let alnum = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_alphanumeric());
    token
        .strip_prefix("mcr_")
        .and_then(|rest| rest.split_once('_'))
        .is_some_and(|(handle, secret)| alnum(handle, 22) && alnum(secret, 32))
}

async fn stack_redis(url: &str) -> bb8_redis::redis::aio::MultiplexedConnection {
    bb8_redis::redis::Client::open(url)
        .unwrap_or_else(|e| panic!("stack Redis URL: {e}"))
        .get_multiplexed_async_connection()
        .await
        .unwrap_or_else(|e| panic!("stack Redis at {url} is unreachable: {e}"))
}

/// A legacy token entry exactly as 3547bd2 wrote it (`set_token` before token
/// kinds: no `kind` field, the lifetime says which kind it is), with its member
/// in the legacy device index.
async fn seed_legacy_entry(url: &str, token: &str, meta: &Value, lifetime: i64) {
    use bb8_redis::redis;
    let mut conn = stack_redis(url).await;
    let key = format!("token/{token}");
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(meta.to_string())
        .arg("EX")
        .arg(lifetime)
        .query_async(&mut conn)
        .await
        .unwrap();
    let device = meta["device_id"].as_str().unwrap_or_default();
    if !device.is_empty() {
        let idx = format!(
            "idx:user_device/{}/{device}",
            meta["username"].as_str().unwrap()
        );
        let _: () = redis::cmd("SADD")
            .arg(&idx)
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}

fn random_base62(n: usize) -> String {
    use rand::Rng;
    const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| B62[rng.gen_range(0..62)] as char).collect()
}

/// A legacy session for `at`, written into the store in the 3547bd2 layout for
/// an account and device a real sign-in created, so everything around the
/// tokens (client registration, Synapse device) is what the old build left.
async fn seed_legacy_session(c: &Client, base: &str, url: &str, at: RefreshAt) -> LegacySession {
    let login = wallet_login(c, base, &new_wallet()).await;
    let claims = introspect(c, &login.access_token).await;
    assert_eq!(
        claims["active"], true,
        "the sign-in's access token: {claims}"
    );
    let now = chrono_now();
    let session = LegacySession {
        at,
        client_id: login.client_id.clone(),
        access_token: format!("mat_{}", random_base62(32)),
        refresh_token: format!("mcr_{}", random_base62(32)),
    };
    for (token, lifetime) in [
        (&session.access_token, 300),
        (&session.refresh_token, 7_776_000),
    ] {
        let meta = json!({
            "username": claims["username"],
            "device_id": login.device_id,
            "scope": claims["scope"],
            "client_id": login.client_id,
            "iat": now,
            "exp": now + lifetime,
            "did": claims["sub"],
            "name": claims["sub"],
        });
        seed_legacy_entry(url, token, &meta, lifetime).await;
    }
    session
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn r1_sessions_file() -> String {
    std::env::var("E2E_R1_SESSIONS").unwrap_or_else(|_| {
        panic!("E2E_R1_SESSIONS names the file the mint stage writes and the check stage reads")
    })
}

/// R1, a real upgrade or its seeded stand-in. Legacy sessions come from one of
/// three places, chosen by `E2E_R1_STAGE`:
///
/// - `mint`: run against the PREVIOUS build (3547bd2 or the integration build
///   before the grant record). Signs in once per endpoint, asserts that the
///   server wrote the legacy layout (`token/{raw}`), saves the sessions to
///   `E2E_R1_SESSIONS`, and stops. Then swap the binary, keeping Redis.
/// - `check`: reads those sessions back and runs the checks below against the
///   new build, within the legacy access tokens' 300 s.
/// - unset (CI and every regular run): signs in on the server under test and
///   writes the legacy entries itself, exactly as 3547bd2 wrote them.
///
/// The checks, at `POST /token` and at `POST /_matrix/client/v3/refresh`: a
/// legacy access token introspects active; the legacy refresh token is lifted
/// and answered with tokens in the grant format; a replay before first use
/// returns the same pair; the legacy access token is still active; no key or
/// value holds the legacy refresh token or the lifted pair (H4); once the new
/// access token is used, the replay is refused as reuse; the new refresh token
/// rotates.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn legacy_tokens_keep_working_after_the_upgrade() {
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: legacy_tokens_keep_working_after_the_upgrade: no stack Redis URL \
                      (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, SIWEOIDC_REDIS_URL or \
                      REDIS_HOST/REDIS_PORT); the upgrade was NOT exercised";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };
    let c = Client::new();
    let base = oidc();
    let stage = std::env::var("E2E_R1_STAGE").unwrap_or_default();
    let sessions: Vec<LegacySession> = match stage.as_str() {
        "mint" => {
            let mut minted = Vec::new();
            for at in [RefreshAt::Token, RefreshAt::Matrix] {
                mock_reset(&c).await;
                let login = wallet_login(&c, &base, &new_wallet()).await;
                let mut conn = stack_redis(&url).await;
                let legacy: bool = bb8_redis::redis::cmd("EXISTS")
                    .arg(format!("token/{}", login.refresh_token))
                    .query_async(&mut conn)
                    .await
                    .unwrap();
                assert!(
                    legacy,
                    "mint: the server under test did not store its refresh token as \
                     token/{{raw}}: run the mint stage against the previous build"
                );
                minted.push(json!({
                    "at": format!("{at:?}"),
                    "client_id": login.client_id,
                    "access_token": login.access_token,
                    "refresh_token": login.refresh_token,
                }));
            }
            std::fs::write(r1_sessions_file(), Value::Array(minted).to_string()).unwrap();
            eprintln!(
                "R1 mint: legacy sessions written; swap the binary and run E2E_R1_STAGE=check"
            );
            return;
        }
        "check" => {
            let saved: Vec<Value> =
                serde_json::from_str(&std::fs::read_to_string(r1_sessions_file()).unwrap())
                    .unwrap();
            saved
                .iter()
                .map(|s| LegacySession {
                    at: if s["at"] == "Token" {
                        RefreshAt::Token
                    } else {
                        RefreshAt::Matrix
                    },
                    client_id: s["client_id"].as_str().unwrap().to_string(),
                    access_token: s["access_token"].as_str().unwrap().to_string(),
                    refresh_token: s["refresh_token"].as_str().unwrap().to_string(),
                })
                .collect()
        }
        "" => {
            let mut seeded = Vec::new();
            for at in [RefreshAt::Token, RefreshAt::Matrix] {
                mock_reset(&c).await;
                seeded.push(seed_legacy_session(&c, &base, &url, at).await);
            }
            seeded
        }
        other => panic!("E2E_R1_STAGE={other}: expected mint, check or unset"),
    };
    assert_eq!(sessions.len(), 2, "one legacy session per refresh endpoint");

    for session in &sessions {
        let at = session.at;
        let login = session.login();
        assert!(
            token_active(&c, &session.access_token).await,
            "{at:?}: a legacy access token introspects active after the upgrade"
        );

        let (status, body, pair) = refresh_at(&c, &base, at, &session.refresh_token, &login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: the legacy refresh token is lifted: {body}"
        );
        let (access, refresh) = pair.unwrap();
        assert!(
            access.starts_with("mat_") && is_grant_refresh_token(&refresh),
            "{at:?}: the lifted pair is in the grant format: {body}"
        );

        let (status, body, replay) =
            refresh_at(&c, &base, at, &session.refresh_token, &login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: a replay of the legacy token before first use: {body}"
        );
        assert_eq!(
            replay.unwrap(),
            (access.clone(), refresh.clone()),
            "{at:?}: the replay returns the SAME pair"
        );
        assert!(
            token_active(&c, &session.access_token).await,
            "{at:?}: the legacy access token stays active until it expires"
        );

        // H4 for the lifted session. The legacy ACCESS token stays stored as
        // token/{raw} until it expires (the read fallback), so it is not listed.
        let mut held = ClientHeld::default();
        held.add_token("legacy refresh token", &session.refresh_token);
        held.add_token("lifted access token", &access);
        held.add_token("lifted refresh token", &refresh);
        assert_nothing_stored_in_the_clear(&url, &held, &format!("{at:?}: after the lift")).await;

        assert!(
            token_active(&c, &access).await,
            "{at:?}: the lifted access token is active"
        );
        let (status, body, _) = refresh_at(&c, &base, at, &session.refresh_token, &login).await;
        assert_refused_as_unknown(
            at,
            status,
            &body,
            "the legacy token after the lifted pair was used",
        );

        let (status, body, next) = refresh_at(&c, &base, at, &refresh, &login).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{at:?}: the lifted refresh token rotates: {body}"
        );
        assert!(is_grant_refresh_token(&next.unwrap().1));
    }
}

// ===========================================================================
// H4 (I1) for every other credential a client holds: authorization codes,
// device and user codes, login session ids, the ids of the WebAuthn ceremonies
// and the CAIP-122 nonces the server hands out (Phase 2b).
// ===========================================================================

/// Lowercase hex SHA-256: the form a credential is stored under.
fn digest_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// A login started at `/authorize`: the session the cookie names and what the
/// login page reads to build its CAIP-122 message.
struct StartedLogin {
    rc: RegisteredClient,
    verifier: String,
    session_id: String,
    nonce: String,
    domain: String,
}

impl StartedLogin {
    fn cookie(&self) -> String {
        format!("session={}", self.session_id)
    }
}

/// `GET /authorize` for a fresh public client with an S256 challenge.
async fn start_login(c: &Client, base: &str) -> StartedLogin {
    let rc = register_client(c, base).await;
    start_login_for(base, rc).await
}

/// `GET /authorize` for the registered client `rc` with an S256 challenge.
async fn start_login_for(base: &str, rc: RegisteredClient) -> StartedLogin {
    let (verifier, challenge) = pkce_pair();
    let authorize_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=h4_state&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect_client()
        .get(&authorize_url)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 303");
    let session_id = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok()?.strip_prefix("session="))
        .map(|rest| rest.split(';').next().unwrap_or("").to_string())
        .find(|v| !v.is_empty())
        .expect("authorize sets the session cookie");
    let q = parse_query(resp.headers().get("location").unwrap().to_str().unwrap());
    StartedLogin {
        rc,
        verifier,
        session_id,
        nonce: q["nonce"].clone(),
        domain: q["domain"].clone(),
    }
}

/// The `siwx` cookie value (URL-encoded) the login page sets after `w` signed
/// the CAIP-122 message for `login`.
fn siwx_cookie_for(base: &str, w: &Wallet, login: &StartedLogin) -> String {
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
        domain = login.domain,
        addr = w.address,
        nonce = login.nonce,
        redirect = login.rc.redirect_uri,
    );
    let signature = eip191_sign(&w.key, &message);
    let value =
        serde_json::to_string(&json!({ "did": w.did, "message": message, "signature": signature }))
            .unwrap();
    urlencoding::encode(&value).into_owned()
}

/// `GET /sign_in` for a started login; returns the authorization code.
async fn sign_in_to_code(base: &str, w: &Wallet, login: &StartedLogin) -> String {
    let resp = no_redirect_client()
        .get(format!("{base}/sign_in"))
        .header(
            "cookie",
            format!(
                "{}; siwx={}",
                login.cookie(),
                siwx_cookie_for(base, w, login)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "sign_in 303");
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    parse_query(location)
        .get("code")
        .unwrap_or_else(|| panic!("sign_in redirect carries no code: {location}"))
        .clone()
}

/// `POST /device_authorization` for `client_id`: `(device_code, user_code)`.
async fn request_device_code(c: &Client, base: &str, client_id: &str) -> (String, String) {
    let da: Value = c
        .post(format!("{base}/device_authorization"))
        .form(&[("client_id", client_id), ("scope", "openid")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        da["device_code"].as_str().unwrap().to_string(),
        da["user_code"].as_str().unwrap().to_string(),
    )
}

/// Approve `user_code` with `w`'s wallet over a fresh server-issued nonce;
/// returns the nonce the approval consumed.
async fn approve_device(c: &Client, base: &str, w: &Wallet, user_code: &str) -> String {
    let (message, signature) = sign_device_message(c, w, base, user_code).await;
    let r = c
        .post(format!("{base}/device"))
        .json(&json!({
            "user_code": user_code, "action": "approve",
            "did": w.did, "message": message, "signature": signature
        }))
        .send()
        .await
        .unwrap();
    let status = r.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "device approval: {}",
        r.text().await.unwrap_or_default()
    );
    message
        .lines()
        .find_map(|l| l.strip_prefix("Nonce: "))
        .expect("the device message carries a nonce")
        .to_string()
}

/// One device-code poll at `/token`: `(status, body)`.
async fn poll_device_code(
    c: &Client,
    base: &str,
    device_code: &str,
    client_id: &str,
) -> (StatusCode, Value) {
    let r = c
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ])
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

/// `POST {path}` with a JSON body and optional cookie; asserts a 200 and
/// returns the body.
async fn post_ok(c: &Client, base: &str, path: &str, cookie: Option<&str>, body: Value) -> Value {
    let mut req = c.post(format!("{base}{path}")).json(&body);
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let r = req.send().await.unwrap();
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "POST {path}: {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// Whether the scan saw `key` in any database.
fn scanned(scan: &RedisScan, key: &str) -> bool {
    scan.keys.iter().any(|k| k.ends_with(&format!(":{key}")))
}

/// H4 for codes, device and user codes, session ids and nonces: a login
/// session with every WebAuthn ceremony started under it, an issued and then
/// an exchanged authorization code, an account re-auth ceremony and nonce, and
/// a device-code flow through a passkey ceremony start, approval and
/// redemption. After each stage no key and no value of the stack Redis holds
/// any of these strings. The positive controls (the digest keys of the
/// session, the code, the device code and its redemption claim) prove the scan
/// searched the stack's Redis and the credentials were stored by digest.
///
/// WebAuthn ceremonies are only started here: finishing one needs an
/// authenticator, which this suite does not drive (the browser suite does).
/// Starting one is what stores its state under the ceremony id; finishing
/// reads and deletes it, and the session update it makes goes through the
/// same session store the login uses.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn no_code_or_session_the_client_holds_is_stored_in_the_clear() {
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: no_code_or_session_the_client_holds_is_stored_in_the_clear: no \
                      stack Redis URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, SIWEOIDC_REDIS_URL or \
                      REDIS_HOST/REDIS_PORT); the keyspace was NOT searched";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    let mut held = ClientHeld::default();

    // A login session, and the ceremonies keyed by its id.
    let login = start_login(&c, &base).await;
    held.add("login session id", &login.session_id);
    let cookie = login.cookie();
    post_ok(
        &c,
        &base,
        "/webauthn/authenticate/start",
        Some(&cookie),
        json!({}),
    )
    .await;
    post_ok(
        &c,
        &base,
        "/webauthn/register/start",
        Some(&cookie),
        json!({}),
    )
    .await;
    let link_cookie = format!("{cookie}; siwx={}", siwx_cookie_for(&base, &w, &login));
    post_ok(
        &c,
        &base,
        "/link/webauthn/start",
        Some(&link_cookie),
        json!({}),
    )
    .await;
    // The account re-auth ceremony hands its id to the client in the body.
    let started = post_ok(
        &c,
        &base,
        "/account/passkey/start",
        None,
        json!({ "action": "org.matrix.profile" }),
    )
    .await;
    held.add(
        "account passkey ceremony id",
        started["session_id"]
            .as_str()
            .expect("start returns session_id"),
    );
    let account_nonce: Value = c
        .get(format!("{base}/account/nonce?action=org.matrix.profile"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    held.add(
        "account CAIP-122 nonce",
        account_nonce["nonce"].as_str().expect("account nonce"),
    );
    let scan =
        assert_nothing_stored_in_the_clear(&url, &held, "with a login session and its ceremonies")
            .await;
    let session_key = format!("session/{}", digest_hex(&login.session_id));
    assert!(
        scanned(&scan, &session_key),
        "positive control: the login session is stored under its digest key {session_key} \
         ({} keys scanned in {url})",
        scan.keys.len()
    );

    // An issued, unconsumed authorization code.
    let code = sign_in_to_code(&base, &w, &login).await;
    held.add("authorization code", &code);
    let scan = assert_nothing_stored_in_the_clear(&url, &held, "with an unconsumed code").await;
    let code_key = format!("code/{}", digest_hex(&code));
    assert!(
        scanned(&scan, &code_key),
        "positive control: the code is stored under its digest key {code_key}"
    );

    // The code exchanged.
    let tokens = exchange_code(&c, &base, &login.rc, &code, &login.verifier)
        .await
        .expect("the code exchanges");
    held.add_token("access token", tokens["access_token"].as_str().unwrap());
    held.add_token("refresh token", tokens["refresh_token"].as_str().unwrap());
    let scan = assert_nothing_stored_in_the_clear(&url, &held, "after the code exchange").await;
    assert!(
        !scanned(&scan, &code_key),
        "an exchanged code leaves no entry"
    );

    // A device-code flow: a pending code, its user code, a passkey ceremony
    // keyed by the user code, approval over a server-issued nonce, redemption.
    let device_client = register_client(&c, &base).await;
    let (device_code, user_code) = request_device_code(&c, &base, &device_client.client_id).await;
    held.add("device code", &device_code);
    held.add("user code", &user_code);
    post_ok(
        &c,
        &base,
        "/device/passkey/start",
        None,
        json!({ "user_code": user_code }),
    )
    .await;
    let scan = assert_nothing_stored_in_the_clear(&url, &held, "with a pending device code").await;
    let device_key = format!("device_code/{}", digest_hex(&device_code));
    assert!(
        scanned(&scan, &device_key),
        "positive control: the device code is stored under its digest key {device_key}"
    );
    assert!(
        scanned(&scan, &format!("user_code/{}", digest_hex(&user_code))),
        "positive control: the user code is stored under its digest key"
    );

    let device_nonce = approve_device(&c, &base, &w, &user_code).await;
    held.add("device CAIP-122 nonce", &device_nonce);
    assert_nothing_stored_in_the_clear(&url, &held, "after the device approval").await;

    let (status, body) = poll_device_code(&c, &base, &device_code, &device_client.client_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved device code redeems: {body}"
    );
    held.add_token(
        "device access token",
        body["access_token"].as_str().unwrap(),
    );
    held.add_token(
        "device refresh token",
        body["refresh_token"].as_str().unwrap(),
    );
    let scan = assert_nothing_stored_in_the_clear(&url, &held, "after redemption").await;
    let claim_key = format!("{device_key}/redeemed");
    assert!(
        scanned(&scan, &claim_key),
        "positive control: the redemption claim is keyed by the digest, {claim_key}"
    );
}

/// A confidential client (`client_secret_basic`) and the two credentials its
/// registration response returned.
struct ConfidentialClient {
    rc: RegisteredClient,
    secret: String,
    registration_token: String,
}

/// The registration metadata of a confidential client, for `POST /register`
/// and the RFC 7592 update; `client_name` tells the two apart.
fn confidential_metadata(redirect_uri: &str, client_name: &str) -> Value {
    json!({
        "redirect_uris": [redirect_uri],
        "client_name": client_name,
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })
}

async fn register_confidential_client(c: &Client, base: &str) -> ConfidentialClient {
    let redirect_uri = format!("{base}/callback");
    let reg: Value = c
        .post(format!("{base}/register"))
        .json(&confidential_metadata(&redirect_uri, "registered"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let field = |k: &str| {
        reg[k]
            .as_str()
            .unwrap_or_else(|| panic!("the registration response carries {k}: {reg}"))
            .to_string()
    };
    ConfidentialClient {
        rc: RegisteredClient {
            client_id: field("client_id"),
            redirect_uri,
        },
        secret: field("client_secret"),
        registration_token: field("registration_access_token"),
    }
}

/// `POST /token` authenticated with `secret` in an HTTP Basic header
/// (`client_secret_basic`): `(status, json|null)`.
async fn token_with_secret(
    c: &Client,
    base: &str,
    rc: &RegisteredClient,
    secret: &str,
    form: &[(&str, &str)],
) -> (StatusCode, Value) {
    let resp = c
        .post(format!("{base}/token"))
        .basic_auth(&rc.client_id, Some(secret))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json::<Value>().await.unwrap_or(Value::Null))
}

/// RFC 7592 update (`POST /client/{id}`) with `token` as the bearer: the status.
async fn update_client(c: &Client, base: &str, rc: &RegisteredClient, token: &str) -> StatusCode {
    c.post(format!("{base}/client/{}", rc.client_id))
        .bearer_auth(token)
        .json(&confidential_metadata(&rc.redirect_uri, "updated"))
        .send()
        .await
        .unwrap()
        .status()
}

/// H4 for clients: a confidential client's secret and registration access
/// token, after its registration, after it updated its registration with the
/// token, and after it authenticated with the secret at the code exchange and
/// the refresh grant. No key and no value of the stack Redis holds either. The
/// positive control (the registration's key in the scan) proves the scan read
/// the entry that would hold them. `default_clients` entries are covered in
/// process (`axum_lib` tests): the mock stack configures none.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn no_client_secret_or_registration_token_is_stored_in_the_clear() {
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: no_client_secret_or_registration_token_is_stored_in_the_clear: \
                      no stack Redis URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, SIWEOIDC_REDIS_URL \
                      or REDIS_HOST/REDIS_PORT); the keyspace was NOT searched";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };
    let c = Client::new();
    let base = oidc();
    mock_reset(&c).await;
    let client = register_confidential_client(&c, &base).await;
    let mut held = ClientHeld::default();
    held.add("client secret", &client.secret);
    held.add("registration access token", &client.registration_token);
    let key = format!("clients/{}", client.rc.client_id);
    let scan = assert_nothing_stored_in_the_clear(&url, &held, "after the registration").await;
    assert!(
        scanned(&scan, &key),
        "positive control: the scan read the registration, {key}"
    );

    // The client manages itself with its registration access token, and only
    // with it.
    assert_eq!(
        update_client(&c, &base, &client.rc, "not-the-registration-token").await,
        StatusCode::UNAUTHORIZED,
        "a wrong registration access token is refused"
    );
    assert_eq!(
        update_client(&c, &base, &client.rc, &client.registration_token).await,
        StatusCode::OK,
        "the registration access token updates the registration"
    );
    assert_nothing_stored_in_the_clear(&url, &held, "after the client updated itself").await;

    // It authenticates with its secret at the code exchange and the refresh
    // grant, and a wrong secret is refused.
    let login = start_login_for(&base, client.rc.clone()).await;
    let code = sign_in_to_code(&base, &new_wallet(), &login).await;
    let (status, tokens) = token_with_secret(
        &c,
        &base,
        &client.rc,
        &client.secret,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &login.verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the code exchanges: {tokens}");
    let refresh_token = tokens["refresh_token"].as_str().expect("a refresh token");
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let (status, body) = token_with_secret(&c, &base, &client.rc, "not-the-secret", &refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a wrong secret: {body}");
    let (status, body) = token_with_secret(&c, &base, &client.rc, &client.secret, &refresh).await;
    assert_eq!(status, StatusCode::OK, "the refresh grant: {body}");
    assert_nothing_stored_in_the_clear(
        &url,
        &held,
        "after the code exchange and the refresh grant",
    )
    .await;
}

// ===========================================================================
// R2: codes, device and user codes and login sessions a build before digest
// keys wrote keep working after the upgrade, within their lifetimes (Phase 2b).
// ===========================================================================

/// The credentials a previous build left in flight, as the client holds them.
struct InFlight {
    /// An issued, unconsumed authorization code, its client and verifier.
    code_client: RegisteredClient,
    code: String,
    code_verifier: String,
    /// A login session started at `/authorize`, not yet signed in.
    session: StartedLogin,
    /// An approved, unredeemed device code.
    approved_client: String,
    approved_device_code: String,
    approved_user_code: String,
    /// A pending device code and its user code.
    pending_client: String,
    pending_device_code: String,
    pending_user_code: String,
    /// A confidential client and an issued, unconsumed code for it: its
    /// registration is first read again when the code is exchanged with its
    /// secret.
    secret_client: ConfidentialClient,
    secret_code: String,
    secret_code_verifier: String,
    /// A confidential client whose registration is first read again when it
    /// updates itself with its registration access token.
    managed_client: ConfidentialClient,
}

impl ConfidentialClient {
    fn to_json(&self) -> Value {
        json!({
            "client_id": self.rc.client_id,
            "redirect_uri": self.rc.redirect_uri,
            "secret": self.secret,
            "registration_token": self.registration_token,
        })
    }

    fn from_json(v: &Value) -> Self {
        let s = |k: &str| {
            v[k].as_str()
                .unwrap_or_else(|| panic!("R2 file lacks the client's {k}"))
                .to_string()
        };
        ConfidentialClient {
            rc: RegisteredClient {
                client_id: s("client_id"),
                redirect_uri: s("redirect_uri"),
            },
            secret: s("secret"),
            registration_token: s("registration_token"),
        }
    }
}

impl InFlight {
    fn to_json(&self) -> Value {
        json!({
            "code_client": self.code_client.client_id,
            "code_redirect_uri": self.code_client.redirect_uri,
            "code": self.code,
            "code_verifier": self.code_verifier,
            "session_client": self.session.rc.client_id,
            "session_redirect_uri": self.session.rc.redirect_uri,
            "session_verifier": self.session.verifier,
            "session_id": self.session.session_id,
            "session_nonce": self.session.nonce,
            "session_domain": self.session.domain,
            "approved_client": self.approved_client,
            "approved_device_code": self.approved_device_code,
            "approved_user_code": self.approved_user_code,
            "pending_client": self.pending_client,
            "pending_device_code": self.pending_device_code,
            "pending_user_code": self.pending_user_code,
            "secret_client": self.secret_client.to_json(),
            "secret_code": self.secret_code,
            "secret_code_verifier": self.secret_code_verifier,
            "managed_client": self.managed_client.to_json(),
        })
    }

    fn from_json(v: &Value) -> Self {
        let s = |k: &str| {
            v[k].as_str()
                .unwrap_or_else(|| panic!("R2 file lacks {k}"))
                .to_string()
        };
        InFlight {
            code_client: RegisteredClient {
                client_id: s("code_client"),
                redirect_uri: s("code_redirect_uri"),
            },
            code: s("code"),
            code_verifier: s("code_verifier"),
            session: StartedLogin {
                rc: RegisteredClient {
                    client_id: s("session_client"),
                    redirect_uri: s("session_redirect_uri"),
                },
                verifier: s("session_verifier"),
                session_id: s("session_id"),
                nonce: s("session_nonce"),
                domain: s("session_domain"),
            },
            approved_client: s("approved_client"),
            approved_device_code: s("approved_device_code"),
            approved_user_code: s("approved_user_code"),
            pending_client: s("pending_client"),
            pending_device_code: s("pending_device_code"),
            pending_user_code: s("pending_user_code"),
            secret_client: ConfidentialClient::from_json(&v["secret_client"]),
            secret_code: s("secret_code"),
            secret_code_verifier: s("secret_code_verifier"),
            managed_client: ConfidentialClient::from_json(&v["managed_client"]),
        }
    }
}

/// Drive every flow to the point where its credential is in flight: a code
/// issued, a session started, a device code approved, another pending.
async fn put_in_flight(c: &Client, base: &str) -> InFlight {
    let w = new_wallet();
    let login = start_login(c, base).await;
    let code = sign_in_to_code(base, &w, &login).await;
    let session = start_login(c, base).await;

    let approver = new_wallet();
    mock_seed_user(c, &approver.localpart).await;
    let approved = register_client(c, base).await;
    let (approved_device_code, approved_user_code) =
        request_device_code(c, base, &approved.client_id).await;
    approve_device(c, base, &approver, &approved_user_code).await;

    let pending = register_client(c, base).await;
    let (pending_device_code, pending_user_code) =
        request_device_code(c, base, &pending.client_id).await;

    let secret_client = register_confidential_client(c, base).await;
    let secret_login = start_login_for(base, secret_client.rc.clone()).await;
    let secret_code = sign_in_to_code(base, &new_wallet(), &secret_login).await;
    let managed_client = register_confidential_client(c, base).await;
    InFlight {
        code_client: login.rc,
        code,
        code_verifier: login.verifier,
        session,
        approved_client: approved.client_id,
        approved_device_code,
        approved_user_code,
        pending_client: pending.client_id,
        pending_device_code,
        pending_user_code,
        secret_client,
        secret_code,
        secret_code_verifier: secret_login.verifier,
        managed_client,
    }
}

/// A device-code entry exactly as a build before digest keys serialized it:
/// the user code in the clear in the entry.
fn legacy_device_entry(user_code: &str, client_id: &str, status: &str, did: Option<&str>) -> Value {
    json!({
        "user_code": user_code,
        "client_id": client_id,
        "scope": "openid",
        "status": status,
        "did": did,
        "device_id": null,
        "last_poll": null,
        "created_at": chrono_now(),
    })
}

/// Rewrite what the server under test stored for `flight` into the layout a
/// build before digest keys wrote: `codes/{raw}`, `sessions/{raw}`,
/// `device_codes/{raw}` with the user code in the entry, `user_codes/{raw}` ->
/// the raw device code. The code and session entries keep their values (their
/// format did not change); the device entries are rewritten whole.
async fn rewrite_as_legacy(url: &str, flight: &InFlight) {
    use bb8_redis::redis;
    let mut conn = stack_redis(url).await;
    for (digest_key, legacy_key) in [
        (
            format!("code/{}", digest_hex(&flight.code)),
            format!("codes/{}", flight.code),
        ),
        (
            format!("session/{}", digest_hex(&flight.session.session_id)),
            format!("sessions/{}", flight.session.session_id),
        ),
        (
            format!("code/{}", digest_hex(&flight.secret_code)),
            format!("codes/{}", flight.secret_code),
        ),
    ] {
        let exists: bool = redis::cmd("EXISTS")
            .arg(&digest_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        if exists {
            let _: () = redis::cmd("RENAME")
                .arg(&digest_key)
                .arg(&legacy_key)
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        let legacy: bool = redis::cmd("EXISTS")
            .arg(&legacy_key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(legacy, "the stand-in wrote {legacy_key}");
    }
    let approver_did = {
        // The approved entry's DID, from whichever layout holds it.
        let mut did = None;
        for key in [
            format!("device_code/{}", digest_hex(&flight.approved_device_code)),
            format!("device_codes/{}", flight.approved_device_code),
        ] {
            let raw: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .unwrap();
            if let Some(raw) = raw {
                let entry: Value = serde_json::from_str(&raw).unwrap();
                did = entry["did"].as_str().map(str::to_string);
            }
        }
        did.expect("the approved device code's entry names its approver")
    };
    for (device_code, user_code, client, status, did) in [
        (
            &flight.approved_device_code,
            flight.approved_user_code.as_str(),
            &flight.approved_client,
            "Approved",
            Some(approver_did.as_str()),
        ),
        (
            &flight.pending_device_code,
            flight.pending_user_code.as_str(),
            &flight.pending_client,
            "Pending",
            None,
        ),
    ] {
        let _: () = redis::cmd("DEL")
            .arg(format!("device_code/{}", digest_hex(device_code)))
            .arg(format!("device_codes/{device_code}"))
            .arg(format!("user_code/{}", digest_hex(user_code)))
            .arg(format!("user_codes/{user_code}"))
            .query_async(&mut conn)
            .await
            .unwrap();
        let entry = legacy_device_entry(user_code, client, status, did);
        let _: () = redis::cmd("SET")
            .arg(format!("device_codes/{device_code}"))
            .arg(entry.to_string())
            .arg("EX")
            .arg(1800)
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(format!("user_codes/{user_code}"))
            .arg(device_code)
            .arg("EX")
            .arg(1800)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
    for client in [&flight.secret_client, &flight.managed_client] {
        rewrite_client_as_legacy(&mut conn, client).await;
    }
}

/// Rewrite a client's registration into the entry a build before digest keys
/// wrote, `{secret, metadata, access_token}` with both credentials in the
/// clear, keeping its metadata and its expiry.
async fn rewrite_client_as_legacy(
    conn: &mut bb8_redis::redis::aio::MultiplexedConnection,
    client: &ConfidentialClient,
) {
    use bb8_redis::redis;
    let key = format!("clients/{}", client.rc.client_id);
    let stored: String = redis::cmd("GET").arg(&key).query_async(conn).await.unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    let legacy = json!({
        "secret": client.secret,
        "metadata": stored["metadata"],
        "access_token": client.registration_token,
    });
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(legacy.to_string())
        .arg("KEEPTTL")
        .query_async(conn)
        .await
        .unwrap();
}

/// Whether the registration of `client` holds its secret and its
/// registration access token in the clear, as a build before digest keys
/// stored them.
async fn client_stored_in_the_clear(url: &str, client: &ConfidentialClient) -> bool {
    let mut conn = stack_redis(url).await;
    let stored: Option<String> = bb8_redis::redis::cmd("GET")
        .arg(format!("clients/{}", client.rc.client_id))
        .query_async(&mut conn)
        .await
        .unwrap();
    stored.is_some_and(|v| v.contains(&client.secret) && v.contains(&client.registration_token))
}

fn r2_file() -> String {
    std::env::var("E2E_R2_FILE").unwrap_or_else(|_| {
        panic!("E2E_R2_FILE names the file the mint stage writes and the check stage reads")
    })
}

/// R2, a real upgrade or its seeded stand-in. In-flight credentials come from
/// one of three places, chosen by `E2E_R2_STAGE`:
///
/// - `mint`: run against the PREVIOUS build. Puts a code, a session and two
///   device codes in flight and registers two confidential clients, asserts
///   the server stored them in the clear (`codes/{raw}`, `sessions/{raw}`,
///   `device_codes/{raw}`, `user_codes/{raw}`, and each client's secret and
///   registration access token in its entry), saves them to `E2E_R2_FILE`
///   and stops. Then swap the binary, keeping
///   Redis and the mock, and run `check` within 300 s.
/// - `check`: reads them back and runs the checks below against the new build.
/// - unset (CI and every regular run): puts them in flight on the server under
///   test and rewrites what it stored into the previous build's layout.
///
/// The checks: the code redeems once and only once; the session signs in and
/// its code exchanges; the approved device code redeems once; the pending
/// user code is still found, approved and redeemed; one client authenticates
/// with its secret at the code exchange and the refresh grant, the other
/// updates itself with its registration access token. Afterwards no key or
/// value holds the legacy code, device codes or user codes (each was deleted
/// on use), or a client's secret or registration access token (each entry was
/// upgraded to digests when it was first read). The legacy session entry stays until it expires (300 s): the new
/// build reads it in place and writes nothing in the clear. After a real
/// upgrade, the nonce the previous build consumed for its approval also keeps
/// the approved user code until it expires (300 s).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn in_flight_codes_and_sessions_survive_the_upgrade() {
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: in_flight_codes_and_sessions_survive_the_upgrade: no stack Redis \
                      URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, SIWEOIDC_REDIS_URL or \
                      REDIS_HOST/REDIS_PORT); the upgrade was NOT exercised";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };
    let c = Client::new();
    let base = oidc();
    let stage = std::env::var("E2E_R2_STAGE").unwrap_or_default();
    let flight = match stage.as_str() {
        "mint" => {
            mock_reset(&c).await;
            let flight = put_in_flight(&c, &base).await;
            let mut conn = stack_redis(&url).await;
            for key in [
                format!("codes/{}", flight.code),
                format!("codes/{}", flight.secret_code),
                format!("sessions/{}", flight.session.session_id),
                format!("device_codes/{}", flight.approved_device_code),
                format!("device_codes/{}", flight.pending_device_code),
                format!("user_codes/{}", flight.pending_user_code),
            ] {
                let legacy: bool = bb8_redis::redis::cmd("EXISTS")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .unwrap();
                assert!(
                    legacy,
                    "mint: the server under test did not store {key}: run the mint stage \
                     against the previous build"
                );
            }
            for client in [&flight.secret_client, &flight.managed_client] {
                assert!(
                    client_stored_in_the_clear(&url, client).await,
                    "mint: the server under test stored a client's credentials as digests: run \
                     the mint stage against the previous build"
                );
            }
            std::fs::write(r2_file(), flight.to_json().to_string()).unwrap();
            eprintln!("R2 mint: in-flight credentials written; swap the binary and run E2E_R2_STAGE=check");
            return;
        }
        "check" => InFlight::from_json(
            &serde_json::from_str(&std::fs::read_to_string(r2_file()).unwrap()).unwrap(),
        ),
        "" => {
            mock_reset(&c).await;
            let flight = put_in_flight(&c, &base).await;
            rewrite_as_legacy(&url, &flight).await;
            flight
        }
        other => panic!("E2E_R2_STAGE={other}: expected mint, check or unset"),
    };

    // The issued code redeems once and only once.
    let tokens = exchange_code(
        &c,
        &base,
        &flight.code_client,
        &flight.code,
        &flight.code_verifier,
    )
    .await
    .expect("a code the previous build issued redeems after the upgrade");
    assert!(token_active(&c, tokens["access_token"].as_str().unwrap()).await);
    assert_eq!(
        exchange_code(
            &c,
            &base,
            &flight.code_client,
            &flight.code,
            &flight.code_verifier
        )
        .await
        .err(),
        Some(StatusCode::BAD_REQUEST),
        "the code redeems only once"
    );

    // The session started on the previous build signs in, and its code exchanges.
    let w = new_wallet();
    let code = sign_in_to_code(&base, &w, &flight.session).await;
    let session_tokens = exchange_code(
        &c,
        &base,
        &flight.session.rc,
        &code,
        &flight.session.verifier,
    )
    .await
    .expect("the session's code exchanges");
    assert!(token_active(&c, session_tokens["access_token"].as_str().unwrap()).await);

    // The approved device code redeems once.
    let (status, body) = poll_device_code(
        &c,
        &base,
        &flight.approved_device_code,
        &flight.approved_client,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an approved device code redeems: {body}"
    );
    assert!(token_active(&c, body["access_token"].as_str().unwrap()).await);
    let (status, body) = poll_device_code(
        &c,
        &base,
        &flight.approved_device_code,
        &flight.approved_client,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("expired_token")),
        "the approved device code redeems only once: {body}"
    );

    // The pending user code is still found and can be approved.
    let r = c
        .get(format!(
            "{base}/device/verify?user_code={}",
            flight.pending_user_code
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "the pending user code is found");
    let approver = new_wallet();
    mock_seed_user(&c, &approver.localpart).await;
    approve_device(&c, &base, &approver, &flight.pending_user_code).await;
    let (status, body) = poll_device_code(
        &c,
        &base,
        &flight.pending_device_code,
        &flight.pending_client,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the device code approved after the upgrade redeems: {body}"
    );

    // The confidential client registered on the previous build authenticates
    // with its secret: first at the exchange of its code, then at the refresh
    // grant, where a wrong secret is still refused.
    let secret_client = &flight.secret_client;
    if stage != "check" {
        assert!(
            client_stored_in_the_clear(&url, secret_client).await,
            "the stand-in stored the client as the previous build did"
        );
    }
    let (status, tokens) = token_with_secret(
        &c,
        &base,
        &secret_client.rc,
        &secret_client.secret,
        &[
            ("grant_type", "authorization_code"),
            ("code", &flight.secret_code),
            ("code_verifier", &flight.secret_code_verifier),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a client registered on the previous build authenticates at /token: {tokens}"
    );
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
    ];
    let (status, body) =
        token_with_secret(&c, &base, &secret_client.rc, "not-the-secret", &refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a wrong secret: {body}");
    let (status, body) = token_with_secret(
        &c,
        &base,
        &secret_client.rc,
        &secret_client.secret,
        &refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the refresh grant: {body}");

    // The other one manages itself with its registration access token, and
    // only with it.
    let managed = &flight.managed_client.rc;
    assert_eq!(
        update_client(
            &c,
            &base,
            managed,
            &flight.managed_client.registration_token
        )
        .await,
        StatusCode::OK,
        "a client registered on the previous build updates itself"
    );
    assert_eq!(
        update_client(&c, &base, managed, "not-the-registration-token").await,
        StatusCode::UNAUTHORIZED,
        "a wrong registration access token is refused"
    );
    assert_eq!(
        update_client(
            &c,
            &base,
            managed,
            &flight.managed_client.registration_token
        )
        .await,
        StatusCode::OK,
        "the registration access token still works after the upgrade of the entry"
    );

    let mut held = ClientHeld::default();
    for client in [&flight.secret_client, &flight.managed_client] {
        held.add("previous build's client secret", &client.secret);
        held.add(
            "previous build's registration access token",
            &client.registration_token,
        );
    }
    held.add("legacy authorization code", &flight.code);
    held.add("legacy confidential client's code", &flight.secret_code);
    held.add("legacy approved device code", &flight.approved_device_code);
    // After a real upgrade the previous build's approval nonce still holds the
    // approved user code in the clear: that build consumed it with a
    // `/consumed` flag and left the entry, which expires within 300 s and which
    // the new build cannot find without the nonce. The stand-in approves on the
    // build under test, so there the user code must be gone.
    if stage != "check" {
        held.add("legacy approved user code", &flight.approved_user_code);
    }
    held.add("legacy pending device code", &flight.pending_device_code);
    held.add("legacy pending user code", &flight.pending_user_code);
    assert_nothing_stored_in_the_clear(&url, &held, "after every legacy credential was used").await;
}

// ===========================================================================
// E1 (I9): epochs. `logout/all` sets the user epoch, which refuses every grant
// of the user authenticated before it at both refresh endpoints and makes its
// access tokens inactive at introspection, while a sign-in right after it
// refreshes at once (the user tombstone it replaced refused that for 900 s).
// A client epoch refuses that client's older grants only, a global epoch every
// older grant. A user tombstone a previous build wrote still refuses for its
// lifetime. The client and global epochs have no HTTP endpoint (an operator
// sets them), so these tests write them into the stack Redis from Redis `TIME`
// exactly as the server's `set_epoch` does.
// ===========================================================================

/// The stack Redis URL, or a loud skip (a failure under `E2E_STRICT_SKIPS=1`).
fn stack_redis_or_skip(test: &str) -> Option<String> {
    let url = stack_redis_url();
    if url.is_none() {
        let marker = format!(
            "E2E_SKIP: {test}: no stack Redis URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL, \
             SIWEOIDC_REDIS_URL or REDIS_HOST/REDIS_PORT); nothing was checked"
        );
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
    }
    url
}

/// Write `key` = Redis `TIME` in milliseconds, as `set_epoch` does.
async fn write_epoch(url: &str, key: &str) {
    let mut conn = stack_redis(url).await;
    let _: String = bb8_redis::redis::cmd("EVAL")
        .arg(
            "local t = redis.call('TIME') \
             local ms = string.format('%.0f', tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)) \
             redis.call('SET', KEYS[1], ms) return ms",
        )
        .arg(1)
        .arg(key)
        .query_async(&mut conn)
        .await
        .unwrap_or_else(|e| panic!("write {key}: {e}"));
}

async fn redis_del(url: &str, key: &str) {
    let mut conn = stack_redis(url).await;
    let _: i64 = bb8_redis::redis::cmd("DEL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .unwrap();
}

/// `login`'s refresh token is refused at both refresh endpoints and its access
/// token is inactive at introspection. The Matrix endpoint is asked first: a
/// refusal by an epoch deletes the grant, and `/token` must refuse it too.
async fn assert_login_refused(c: &Client, base: &str, login: &LoginResult, what: &str) {
    for at in [RefreshAt::Matrix, RefreshAt::Token] {
        let (status, body, _) = refresh_at(c, base, at, &login.refresh_token, login).await;
        assert_refused_as_unknown(at, status, &body, what);
    }
    assert!(
        !token_active(c, &login.access_token).await,
        "{what}: the access token is still active at introspection"
    );
}

/// `login` refreshes at `/token`, then its successor at the Matrix endpoint.
async fn assert_login_refreshes(c: &Client, base: &str, login: &LoginResult, what: &str) {
    assert!(
        token_active(c, &login.access_token).await,
        "{what}: the access token is inactive"
    );
    let (status, body, pair) =
        refresh_at(c, base, RefreshAt::Token, &login.refresh_token, login).await;
    let (_, refresh) = pair.unwrap_or_else(|| panic!("{what}: /token refused: {status} {body}"));
    let (status, body, pair) = refresh_at(c, base, RefreshAt::Matrix, &refresh, login).await;
    assert!(
        pair.is_some(),
        "{what}: the Matrix endpoint refused the successor: {status} {body}"
    );
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn e1_after_logout_all_older_grants_are_refused_and_a_new_sign_in_refreshes_at_once() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();
    let first = wallet_login(&c, &base, &w).await;
    let second = wallet_login(&c, &base, &w).await;
    let resp = c
        .post(format!("{base}/_matrix/client/v3/logout/all"))
        .bearer_auth(&first.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "logout/all");
    for (login, what) in [
        (&first, "the grant that called logout/all"),
        (&second, "another grant of the user"),
    ] {
        assert_login_refused(&c, &base, login, what).await;
    }
    let after = wallet_login(&c, &base, &w).await;
    assert_login_refreshes(&c, &base, &after, "a sign-in right after logout/all").await;
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn e1_a_client_epoch_refuses_that_clients_older_grants_only() {
    let Some(url) = stack_redis_or_skip("e1_a_client_epoch_refuses_that_clients_older_grants_only")
    else {
        return;
    };
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();
    let target = wallet_login(&c, &base, &w).await;
    let other = wallet_login(&c, &base, &w).await;
    let key = format!("epoch:client/{}", target.client_id);
    write_epoch(&url, &key).await;
    assert_login_refused(&c, &base, &target, "the client's grant").await;
    assert_login_refreshes(&c, &base, &other, "the same user's grant at another client").await;
    redis_del(&url, &key).await;
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn e1_a_global_epoch_refuses_every_older_grant() {
    let Some(url) = stack_redis_or_skip("e1_a_global_epoch_refuses_every_older_grant") else {
        return;
    };
    let c = Client::new();
    let base = oidc();
    let older = [
        wallet_login(&c, &base, &new_wallet()).await,
        wallet_login(&c, &base, &new_wallet()).await,
    ];
    write_epoch(&url, "epoch:global").await;
    // Collected, so the global epoch is removed before any assertion fails:
    // left behind it would refuse nothing newer, but the stack is shared.
    let mut refused = Vec::new();
    for login in &older {
        let mut outcome = Vec::new();
        for at in [RefreshAt::Matrix, RefreshAt::Token] {
            let (status, body, _) = refresh_at(&c, &base, at, &login.refresh_token, login).await;
            outcome.push((at, status, body));
        }
        let active = token_active(&c, &login.access_token).await;
        refused.push((outcome, active));
    }
    let later = wallet_login(&c, &base, &new_wallet()).await;
    let (status, body, later_pair) =
        refresh_at(&c, &base, RefreshAt::Token, &later.refresh_token, &later).await;
    redis_del(&url, "epoch:global").await;
    for (i, (outcome, active)) in refused.iter().enumerate() {
        for (at, status, body) in outcome {
            assert_refused_as_unknown(*at, *status, body, &format!("older grant {i}"));
        }
        assert!(!active, "older grant {i}: the access token is still active");
    }
    assert!(
        later_pair.is_some(),
        "a sign-in after the global epoch refreshes: {status} {body}"
    );
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn e1_a_user_tombstone_written_by_the_previous_build_still_refuses_refresh() {
    let Some(url) = stack_redis_or_skip(
        "e1_a_user_tombstone_written_by_the_previous_build_still_refuses_refresh",
    ) else {
        return;
    };
    let c = Client::new();
    let base = oidc();
    let login = wallet_login(&c, &base, &new_wallet()).await;
    let username = introspect(&c, &login.access_token).await["username"]
        .as_str()
        .expect("introspection names the user")
        .to_string();
    let key = format!("tombstone:user/{username}");
    {
        // Exactly as the previous build planted it: `SET … 1 EX 900`.
        let mut conn = stack_redis(&url).await;
        let _: () = bb8_redis::redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(900)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
    let mut outcome = Vec::new();
    for at in [RefreshAt::Matrix, RefreshAt::Token] {
        let (status, body, _) = refresh_at(&c, &base, at, &login.refresh_token, &login).await;
        outcome.push((at, status, body));
    }
    redis_del(&url, &key).await;
    for (at, status, body) in &outcome {
        assert_refused_as_unknown(*at, *status, body, "a tombstoned user's grant");
    }
}
