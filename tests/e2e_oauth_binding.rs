//! Negative E2E tests proving the C1/C2 "safe subset" OAuth/auth hardening:
//!
//!   1. C1 login Expiration-Time enforcement (enforce-if-present) — a login
//!      CAIP-122 signature whose `Expiration Time` is in the past is rejected at
//!      `/sign_in`, while a signature with NO `Expiration Time` line at all (the
//!      headless `siwx-oidc-auth` shape) is accepted.
//!   2. C2 Step 1 (code↔client binding) — exchanging a code with a MISMATCHED
//!      `client_id` at `/token` is rejected `invalid_grant`.
//!   3. C2 Step 3 (`/sign_in` redirect re-validation) — `/sign_in` with an
//!      UNREGISTERED `redirect_uri` is rejected, no code emitted to the attacker
//!      origin (wallet / Path B; the shared validator also covers Path A).
//!   4. C2 Step 4b (reject `plain` PKCE) — a `/token` exchange of a code carrying
//!      a `plain` code_challenge is rejected, and `/authorize` rejects
//!      `code_challenge_method=plain` up front.
//!   5. C2 Step 4a (mandatory PKCE) — a `response_type=code` `/authorize` request
//!      WITHOUT a `code_challenge` is rejected; the same request WITH S256 PKCE
//!      still succeeds.
//!
//! Targets the MOCK stack brought up by `e2e/up.sh` (siwx-oidc :8080, Synapse
//! mock :8090, Redis :6379). Run single-threaded with the stack up:
//!   bash e2e/up.sh
//!   cargo test --test e2e_oauth_binding -- --ignored --test-threads=1 --nocapture

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rand::rngs::OsRng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

// ---------------------------------------------------------------------------
// Wallet identity + EIP-191 signing
// ---------------------------------------------------------------------------

struct Wallet {
    key: SigningKey,
    address: String,
    did: String,
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
    Wallet { key, address, did }
}

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

// ---------------------------------------------------------------------------
// PKCE + redirect helpers
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

/// Run /authorize for `rc`, returning (session_cookie, nonce, domain).
async fn authorize_session(
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    challenge: &str,
    state: &str,
) -> (String, String, String) {
    let authorize_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={state}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(challenge),
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
    let nonce = q.get("nonce").unwrap().clone();
    let domain = q.get("domain").unwrap().clone();
    (session_cookie, nonce, domain)
}

/// Build a login CAIP-122 message. `exp_offset_hours` is added to "now" for the
/// Expiration Time (negative ⇒ already expired). `resource` is the redirect bound
/// in the `Resources:` list.
fn build_login_message(
    w: &Wallet,
    base: &str,
    domain: &str,
    nonce: &str,
    resource: &str,
    exp_offset_hours: i64,
) -> String {
    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expiration_time = (now + chrono::Duration::hours(exp_offset_hours))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
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
         - {resource}",
        addr = w.address,
    )
}

/// Build a login CAIP-122 message with NO `Expiration Time` line at all — this is
/// exactly what the in-house headless client (`siwx-oidc-auth`) emits. The server
/// must ACCEPT it (enforce-if-present), otherwise the production agent fleet bricks.
fn build_login_message_no_exp(
    w: &Wallet,
    base: &str,
    domain: &str,
    nonce: &str,
    resource: &str,
) -> String {
    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {addr}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Resources:\n\
         - {resource}",
        addr = w.address,
    )
}

fn siwx_cookie_header(session_cookie: &str, w: &Wallet, message: &str) -> String {
    let signature = eip191_sign(&w.key, message);
    let val =
        serde_json::to_string(&json!({ "did": w.did, "message": message, "signature": signature }))
            .unwrap();
    format!("{session_cookie}; siwx={}", urlencoding::encode(&val))
}

// ===========================================================================
// 1. C1 — an EXPIRED login signature is rejected at /sign_in.
// ===========================================================================
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn expired_login_signature_is_rejected() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;
    let (_verifier, challenge) = pkce_pair();

    let (session_cookie, nonce, domain) =
        authorize_session(&nrc, &base, &rc, &challenge, "exp_state").await;

    // Expiration Time 1h in the PAST (well beyond the 120s skew allowance).
    let message = build_login_message(&w, &base, &domain, &nonce, &rc.redirect_uri, -1);
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state=exp_state&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&challenge),
    );
    let resp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie, &w, &message))
        .send()
        .await
        .unwrap();

    assert_ne!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "an expired login signature MUST NOT yield an auth-code redirect"
    );
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expired login signature must be a clean 400, got {status}: {body}"
    );
    assert!(
        body.to_lowercase().contains("expire"),
        "rejection must mention expiry: {body}"
    );

    // Control: the SAME flow with a future exp succeeds, proving it's the expiry
    // (not some unrelated breakage) that drove the rejection above.
    let (session_cookie2, nonce2, domain2) =
        authorize_session(&nrc, &base, &rc, &challenge, "exp_state").await;
    let good = build_login_message(&w, &base, &domain2, &nonce2, &rc.redirect_uri, 48);
    let ok = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie2, &w, &good))
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::SEE_OTHER,
        "a fresh (future-exp) login signature must still succeed"
    );

    // Headless-client control: a message with NO Expiration Time line at all
    // (the siwx-oidc-auth shape) must ALSO succeed — enforce-if-present must not
    // reject omitted expirations, or the production agent fleet would brick.
    let (session_cookie3, nonce3, domain3) =
        authorize_session(&nrc, &base, &rc, &challenge, "exp_state").await;
    let no_exp = build_login_message_no_exp(&w, &base, &domain3, &nonce3, &rc.redirect_uri);
    let ok_no_exp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie3, &w, &no_exp))
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok_no_exp.status(),
        StatusCode::SEE_OTHER,
        "a login signature with NO Expiration Time (headless client) must succeed"
    );
}

// ===========================================================================
// 2. C2 Step 1 — exchanging a code with a MISMATCHED client_id is rejected.
// ===========================================================================
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn mismatched_client_id_at_token_is_rejected() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();

    // Client A obtains a code (the victim/confidential client).
    let rc_a = register_client(&c, &base).await;
    // Client B is a second, independently registered client (the attacker).
    let rc_b = register_client(&c, &base).await;
    assert_ne!(rc_a.client_id, rc_b.client_id);

    let (verifier, challenge) = pkce_pair();
    let (session_cookie, nonce, domain) =
        authorize_session(&nrc, &base, &rc_a, &challenge, "bind_state").await;
    let message = build_login_message(&w, &base, &domain, &nonce, &rc_a.redirect_uri, 48);
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state=bind_state&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc_a.redirect_uri),
        urlencoding::encode(&rc_a.client_id),
        urlencoding::encode(&challenge),
    );
    let sign_in_resp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie, &w, &message))
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
    .expect("sign_in must carry code")
    .clone();

    // Attacker presents client B at /token with A's code → must be rejected.
    let bad = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code.as_str()),
            ("client_id", rc_b.client_id.as_str()),
            ("client_secret", rc_b.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let status = bad.status();
    let body = bad.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "cross-client redemption must NOT 200"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mismatched client_id must be a 400 invalid_grant, got {status}: {body}"
    );
    assert!(
        body.contains("invalid_grant") || body.to_lowercase().contains("client_id"),
        "rejection must be client/grant related: {body}"
    );

    // Control: the legitimate client A still redeems the (already-consumed) code?
    // The code was consumed by the failed attempt only if it succeeded; since it
    // was rejected BEFORE consumption is irrelevant here — instead prove a fresh
    // A-code exchanged by A succeeds, confirming the path is otherwise healthy.
    let (verifier2, challenge2) = pkce_pair();
    let (sc2, nonce2, domain2) =
        authorize_session(&nrc, &base, &rc_a, &challenge2, "bind_state2").await;
    let msg2 = build_login_message(&w, &base, &domain2, &nonce2, &rc_a.redirect_uri, 48);
    let su2 = format!(
        "{base}/sign_in?redirect_uri={}&state=bind_state2&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc_a.redirect_uri),
        urlencoding::encode(&rc_a.client_id),
        urlencoding::encode(&challenge2),
    );
    let r2 = nrc
        .get(&su2)
        .header("cookie", siwx_cookie_header(&sc2, &w, &msg2))
        .send()
        .await
        .unwrap();
    let code2 = parse_query(r2.headers().get("location").unwrap().to_str().unwrap())
        .get("code")
        .unwrap()
        .clone();
    let good = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code2.as_str()),
            ("client_id", rc_a.client_id.as_str()),
            ("client_secret", rc_a.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier2.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        good.status(),
        StatusCode::OK,
        "the legitimate client (matching client_id) must still succeed"
    );
}

// ===========================================================================
// 3. C2 Step 3 — /sign_in with an UNREGISTERED redirect_uri is rejected.
// ===========================================================================
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn unregistered_redirect_uri_at_sign_in_is_rejected() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;
    let (_verifier, challenge) = pkce_pair();

    let (session_cookie, nonce, domain) =
        authorize_session(&nrc, &base, &rc, &challenge, "redir_state").await;

    // The attacker-controlled redirect (NOT registered for this client). Bind it
    // in the signed Resources so the Path-B resource check does not pre-empt the
    // redirect re-validation — proving it is the registration check that rejects.
    let attacker = "https://attacker.example/cb";
    let message = build_login_message(&w, &base, &domain, &nonce, attacker, 48);
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state=redir_state&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(attacker),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&challenge),
    );
    let resp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie, &w, &message))
        .send()
        .await
        .unwrap();

    // Must NOT 303 to the attacker origin with a code.
    if resp.status() == StatusCode::SEE_OTHER {
        let loc = resp
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        panic!("sign_in must NOT emit a code redirect to an unregistered redirect_uri, got: {loc}");
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unregistered redirect_uri must be a clean 400, got {status}: {body}"
    );
    assert!(
        body.to_lowercase().contains("redirect_uri"),
        "rejection must mention redirect_uri: {body}"
    );
}

// ===========================================================================
// 4. C2 Step 4b — `plain` PKCE is rejected (both at /authorize and /token).
// ===========================================================================
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn plain_pkce_is_rejected() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;

    // (a) /authorize rejects code_challenge_method=plain up front.
    let plain_challenge = "this_is_a_plain_verifier_value_used_as_challenge";
    let authorize_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=plain_state&code_challenge={}&code_challenge_method=plain",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(plain_challenge),
    );
    let auth_resp = nrc.get(&authorize_url).send().await.unwrap();
    assert_eq!(
        auth_resp.status(),
        StatusCode::BAD_REQUEST,
        "/authorize must reject code_challenge_method=plain"
    );

    // (b) /token rejects a code that carries a `plain` challenge. /sign_in does
    //     not validate the method (it passes it through), so we drive it directly
    //     with method=plain to plant a `plain` CodeEntry, then exchange at /token.
    let (session_cookie, nonce, domain) = {
        // Use an S256 authorize to get a valid session + nonce, then override the
        // method only on the /sign_in leg (the server stores what /sign_in sends).
        let (_v, s256_challenge) = pkce_pair();
        authorize_session(&nrc, &base, &rc, &s256_challenge, "plain_state").await
    };
    let message = build_login_message(&w, &base, &domain, &nonce, &rc.redirect_uri, 48);
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state=plain_state&client_id={}&code_challenge={}&code_challenge_method=plain",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(plain_challenge),
    );
    let sign_in_resp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie, &w, &message))
        .send()
        .await
        .unwrap();
    assert_eq!(
        sign_in_resp.status(),
        StatusCode::SEE_OTHER,
        "sign_in (which does not validate the method) should still issue the code"
    );
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

    // The verifier for `plain` is the challenge itself; a compliant `plain` client
    // would expect this to pass. It must be REJECTED.
    let bad = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code.as_str()),
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", plain_challenge),
        ])
        .send()
        .await
        .unwrap();
    let status = bad.status();
    let body = bad.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a `plain` PKCE exchange must NOT 200"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a `plain` code_challenge_method must be rejected at /token, got {status}: {body}"
    );
    assert!(
        body.to_lowercase().contains("s256") || body.contains("invalid_grant"),
        "rejection must reference the S256-only policy: {body}"
    );
}

// ===========================================================================
// 5. C2 Step 4a — a code-flow /authorize WITHOUT a code_challenge is rejected.
//    Scope: ALL code-flow clients (every registered client carries a secret;
//    there is no client class that legitimately omits PKCE). The control proves
//    the SAME request WITH S256 PKCE still succeeds, so it is the missing
//    challenge — not unrelated breakage — that drives the rejection.
// ===========================================================================
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn authorize_without_pkce_is_rejected() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let rc = register_client(&c, &base).await;

    // (a) response_type=code with NO code_challenge → rejected.
    let no_pkce_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=nopkce_state",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
    );
    let resp = nrc.get(&no_pkce_url).send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "a code-flow /authorize without PKCE MUST NOT proceed to the login redirect"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code-flow /authorize without a code_challenge must be a clean 400, got {status}: {body}"
    );
    assert!(
        body.to_lowercase().contains("code_challenge") || body.to_lowercase().contains("pkce"),
        "rejection must mention the missing PKCE challenge: {body}"
    );

    // (b) Control: the SAME request WITH S256 PKCE succeeds (303 to the login UI).
    let (_verifier, challenge) = pkce_pair();
    let with_pkce_url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=nopkce_state&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&challenge),
    );
    let ok = nrc.get(&with_pkce_url).send().await.unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::SEE_OTHER,
        "a code-flow /authorize WITH S256 PKCE must still succeed"
    );
}
