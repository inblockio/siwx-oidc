//! Negative E2E tests proving the C1/C2 "safe subset" OAuth/auth hardening:
//!
//!   1. C1 login Expiration-Time enforcement (enforce-if-present) — a login
//!      CAIP-122 signature whose `Expiration Time` is in the past is rejected at
//!      `/sign_in`, while a signature with NO `Expiration Time` line at all (the
//!      headless `siwx-oidc-auth` shape) is accepted.
//!   2. C2 Step 1 (code↔client binding) — exchanging a code with a MISMATCHED
//!      `client_id` at `/token` is rejected `invalid_grant`.
//!   3. C2 Step 3 — `/sign_in` never sends a code to a `redirect_uri` named in
//!      its query; the code goes to the redirect URI `/authorize` bound.
//!   4. C2 Step 4b (reject `plain` PKCE) — `/authorize` rejects
//!      `code_challenge_method=plain` up front, and a `plain` challenge on the
//!      `/sign_in` query has no effect, so no code carries one.
//!   5. C2 Step 4a (mandatory PKCE) — a `response_type=code` `/authorize` request
//!      WITHOUT a `code_challenge` is rejected; the same request WITH S256 PKCE
//!      still succeeds.
//!   6. Token kinds — each endpoint accepts exactly one kind of token: the
//!      refresh endpoints only refresh tokens; introspection, `/userinfo` and
//!      the bearer-authenticated Matrix routes only access tokens (an admin
//!      token is an access token).
//!   7. Authorization codes — single use, and never a bearer token: `/userinfo`
//!      refuses a code before and after its exchange.
//!   8. The authorization request is bound at `/authorize` — only
//!      `response_type=code`, redirect URIs matched exactly, and `/sign_in`
//!      issues the code for the request `/authorize` validated (client,
//!      redirect URI, state, PKCE challenge) and reads no authorization
//!      parameter from its own query. The login page round trip keeps the
//!      exact redirect URI and state. Discovery advertises only `code`.
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

fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}

/// Mark this wallet's identity as an EXISTING account in the Synapse mock.
///
/// `reject_if_new_identity` (`src/webauthn.rs`) 400s an unprovisioned identity on
/// every non-login path — device approval and account actions included — logging
/// `rejecting new-identity (no existing account) outside login flow`. That gate is
/// CORRECT and is documented policy: creating a Matrix account is permitted ONLY at
/// the login screen.
///
/// These tests predate the gate and were asserting 200 for a wallet that had never
/// signed in, so they failed against a server that is behaving properly. Seeding
/// models the RETURNING user the tests actually mean to exercise, leaving the
/// replay/race assertion itself untouched. The Playwright suite already got this
/// right — `passkey-scoping.spec.mjs` calls `mockSeedUser` before the same approval.
async fn mock_seed_user(c: &Client, did: &str) {
    let localpart = did.replace(':', "-").to_lowercase();
    c.post(format!("{}/__seed_user", mock()))
        .json(&json!({ "localpart": localpart }))
        .send()
        .await
        .unwrap();
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
// 3. C2 Step 3 — /sign_in never sends a code to a redirect_uri from its query:
//    an unregistered one there is ignored, and a message that binds it is
//    refused.
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
    let unregistered = "https://unregistered.example/cb";
    let query = format!(
        "redirect_uri={}&state=redir_state&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(unregistered),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&challenge),
    );

    // (a) The signed message binds the registered redirect URI: the code goes
    //     there, whatever the query names.
    let s = authorize_session(&nrc, &base, &rc, &challenge, "redir_state").await;
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &query,
    )
    .await;
    let location = location_of(&resp);
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{location}");
    assert!(
        location.starts_with(&format!("{}?code=", rc.redirect_uri)),
        "the code goes to the bound redirect URI only: {location}"
    );

    // (b) A message that binds the unregistered URI instead does not match the
    //     bound request: refused, and no code is emitted anywhere.
    let s = authorize_session(&nrc, &base, &rc, &challenge, "redir_state").await;
    let resp = sign_in_raw(&nrc, &base, (&s.0, &s.1, &s.2), &w, unregistered, &query).await;
    let status = resp.status();
    let location = location_of(&resp);
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !location.contains("code="),
        "no code may be emitted for a message bound to another redirect URI: {location}"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a message bound to another redirect URI is the client's error, a 400 and not a \
         server fault, got {status}: {body}"
    );
    assert!(body.to_lowercase().contains("resource"), "{body}");
}

// ===========================================================================
// 4. C2 Step 4b — `plain` PKCE is rejected at /authorize and has no effect at /sign_in.
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

    // (b) Nor can a `plain` challenge enter through /sign_in: its query has no
    //     effect, so the code stays bound to the S256 challenge /authorize
    //     stored. The `plain` verifier does not redeem it; the S256 verifier
    //     does.
    let plain_query = format!(
        "redirect_uri={}&state=plain_state&client_id={}&code_challenge={}&code_challenge_method=plain",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(plain_challenge),
    );
    for (verifier_is_plain, what) in [(true, "the plain verifier"), (false, "the S256 verifier")] {
        let (s256_verifier, s256_challenge) = pkce_pair();
        let s = authorize_session(&nrc, &base, &rc, &s256_challenge, "plain_state").await;
        let resp = sign_in_raw(
            &nrc,
            &base,
            (&s.0, &s.1, &s.2),
            &w,
            &rc.redirect_uri,
            &plain_query,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "sign_in issues the code"
        );
        let code = parse_query(&location_of(&resp))
            .get("code")
            .unwrap()
            .clone();
        let verifier = if verifier_is_plain {
            plain_challenge.to_string()
        } else {
            s256_verifier
        };
        let resp = exchange_code(&c, &base, &rc, &code, Some(&verifier)).await;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if verifier_is_plain {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{what} must not redeem the code, got {status}: {body}"
            );
            assert!(body.contains("invalid_grant"), "{body}");
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "{what} of the bound challenge redeems the code: {body}"
            );
        }
    }
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

// ===========================================================================
// C1 — server-issued single-use nonce on device-approval & account paths
// ===========================================================================

fn host(base: &str) -> String {
    reqwest::Url::parse(base)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string()
}

/// Request a fresh device code and return its `user_code`.
async fn new_device_user_code(c: &Client, base: &str) -> String {
    let rc = register_client(c, base).await;
    let da: Value = c
        .post(format!("{base}/device_authorization"))
        .form(&[("client_id", rc.client_id.as_str()), ("scope", "openid")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    da["user_code"].as_str().unwrap().to_string()
}

/// Fetch a server-issued device-approval nonce envelope for `user_code`.
async fn device_nonce(c: &Client, base: &str, user_code: &str) -> Value {
    c.get(format!("{base}/device/nonce?user_code={user_code}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Build + sign a device-approval message from a nonce envelope.
fn build_device_message(w: &Wallet, base: &str, np: &Value) -> (String, String) {
    let res: String = np["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nApprove device login.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z\nExpiration Time: {exp}\nResources:{res}",
        domain = host(base),
        addr = w.address,
        nonce = np["nonce"].as_str().unwrap(),
        exp = np["expiration_time"].as_str().unwrap(),
    );
    let sig = eip191_sign(&w.key, &message);
    (message, sig)
}

async fn post_device_approve(
    c: &Client,
    base: &str,
    user_code: &str,
    w: &Wallet,
    message: &str,
    signature: &str,
) -> reqwest::Response {
    c.post(format!("{base}/device"))
        .json(&json!({
            "user_code": user_code, "action": "approve",
            "did": w.did, "message": message, "signature": signature
        }))
        .send()
        .await
        .unwrap()
}

/// C1 device: a fresh, properly-nonced approval SUCCEEDS; replaying the very same
/// signature (same nonce) is REJECTED (single-use nonce consumed).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn device_approval_replay_is_rejected_fresh_succeeds() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();
    // Returning user, not a brand-new identity: see `mock_seed_user`. Without this
    // the new-identity gate 400s step (a) and the replay assertion never runs.
    mock_seed_user(&c, &w.did).await;

    // (a) Fresh, correctly nonced approval → 200.
    let uc1 = new_device_user_code(&c, &base).await;
    let np = device_nonce(&c, &base, &uc1).await;
    let (message, signature) = build_device_message(&w, &base, &np);
    let ok = post_device_approve(&c, &base, &uc1, &w, &message, &signature).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "a fresh server-nonced device approval must succeed"
    );

    // (b) Replay the SAME {message, signature} on a NEW device login → rejected.
    // The nonce was single-use (consumed in (a)); the device-code is also new, so
    // this isolates the nonce check from the "code already used" guard.
    let uc2 = new_device_user_code(&c, &base).await;
    let replay = post_device_approve(&c, &base, &uc2, &w, &message, &signature).await;
    let status = replay.status();
    let body = replay.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a replayed device-approval signature must be rejected, got 200: {body}"
    );
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "replay must be 401/400, got {status}: {body}"
    );
}

/// C1 device: a message with NO server nonce (a bare self-signed EIP-191 message,
/// the OLD attack) is REJECTED — this is the exact signature-replay vector.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn device_approval_without_server_nonce_is_rejected() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();
    let uc = new_device_user_code(&c, &base).await;

    // A self-invented nonce, no Expiration Time, no Resources — exactly what the
    // pre-C1 page sent and what an attacker can mint from any leaked signature.
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nApprove device login.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: attackerchosen01\nIssued At: 2026-06-14T00:00:00.000Z",
        domain = host(&base),
        addr = w.address,
    );
    let signature = eip191_sign(&w.key, &message);
    let resp = post_device_approve(&c, &base, &uc, &w, &message, &signature).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a bare (no server nonce) device approval must be rejected, got 200: {body}"
    );
}

/// C1 device: a nonce minted for one user_code cannot approve a DIFFERENT device
/// login (cross-context binding).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn device_approval_cross_user_code_nonce_is_rejected() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();

    let uc_a = new_device_user_code(&c, &base).await;
    let uc_b = new_device_user_code(&c, &base).await;
    // Mint a nonce bound to uc_a, but try to use it to approve uc_b.
    let np = device_nonce(&c, &base, &uc_a).await;
    let (message, signature) = build_device_message(&w, &base, &np);
    let resp = post_device_approve(&c, &base, &uc_b, &w, &message, &signature).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a nonce minted for another user_code must not approve this device, got 200: {body}"
    );
}

/// Fetch a server-issued account nonce envelope for `action`.
async fn account_nonce(c: &Client, base: &str, action: &str) -> Value {
    c.get(format!("{base}/account/nonce?action={action}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn build_account_message(w: &Wallet, base: &str, np: &Value) -> (String, String) {
    let res: String = np["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nConfirm account action.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z\nExpiration Time: {exp}\nResources:{res}",
        domain = host(base),
        addr = w.address,
        nonce = np["nonce"].as_str().unwrap(),
        exp = np["expiration_time"].as_str().unwrap(),
    );
    let sig = eip191_sign(&w.key, &message);
    (message, sig)
}

async fn post_account_wallet(
    c: &Client,
    base: &str,
    action: &str,
    w: &Wallet,
    message: &str,
    signature: &str,
) -> reqwest::Response {
    c.post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": action,
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap()
}

/// C1 account: a bare signature with NO server nonce (the OLD signature-replay
/// vector — any previously-leaked EIP-191 signature) is REJECTED, NOT executed.
/// Uses `account_erase` to prove the most destructive action is gated.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn account_action_without_server_nonce_is_rejected() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();

    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nConfirm account action.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: leakedoldnonce01\nIssued At: 2026-06-14T00:00:00.000Z",
        domain = host(&base),
        addr = w.address,
    );
    let signature = eip191_sign(&w.key, &message);
    let resp = post_account_wallet(
        &c,
        &base,
        "io.inblock.account_erase",
        &w,
        &message,
        &signature,
    )
    .await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a bare (no server nonce) account_erase must be rejected, got 200: {body}"
    );
}

/// C1 account: replaying a once-used (single-use) account signature is REJECTED.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn account_action_nonce_replay_is_rejected() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();
    // Returning user, not a brand-new identity: see `mock_seed_user`. The account
    // path rejects new identities outright, so without this the first call 400s.
    mock_seed_user(&c, &w.did).await;

    // Use `profile` (idempotent, needs no Synapse) so the first call succeeds.
    let np = account_nonce(&c, &base, "org.matrix.profile").await;
    let (message, signature) = build_account_message(&w, &base, &np);
    let first =
        post_account_wallet(&c, &base, "org.matrix.profile", &w, &message, &signature).await;
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "a fresh server-nonced account action must succeed"
    );

    // Replay the SAME signature → the nonce is already consumed → rejected.
    let replay =
        post_account_wallet(&c, &base, "org.matrix.profile", &w, &message, &signature).await;
    let status = replay.status();
    let body = replay.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a replayed account signature must be rejected, got 200: {body}"
    );
}

/// C1 account OPERATION BINDING: a signature minted for `cross_signing_reset`
/// must NOT be accepted for `account_erase` (its nonce is bound to the action).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn account_action_operation_binding_is_enforced() {
    let c = Client::new();
    let base = oidc();
    let w = new_wallet();

    // Mint + sign for cross_signing_reset...
    let np = account_nonce(&c, &base, "org.matrix.cross_signing_reset").await;
    let (message, signature) = build_account_message(&w, &base, &np);

    // ...then submit it against account_erase. Rejected: the nonce was bound to a
    // different action, and the Resources audience names cross_signing_reset.
    let resp = post_account_wallet(
        &c,
        &base,
        "io.inblock.account_erase",
        &w,
        &message,
        &signature,
    )
    .await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status,
        StatusCode::OK,
        "a cross_signing_reset signature must not drive account_erase, got 200: {body}"
    );
}

// ===========================================================================
// Token kinds: each endpoint accepts exactly one kind of token.
//
// An access token (including a minted admin token) is a bearer credential: it
// is what introspection, /userinfo and the Matrix compat routes accept. A
// refresh token is accepted only by the two refresh endpoints. A token of the
// wrong kind is answered exactly like an unknown token, and the presented token
// is left untouched (it stays usable where it belongs).
// ===========================================================================

fn shared_secret() -> String {
    std::env::var("MAS_SHARED_SECRET").unwrap_or_else(|_| "testsecret".to_string())
}

/// /authorize + /sign_in with the given wallet, passing the PKCE parameters on
/// the /sign_in leg as the login page does. Returns the authorization code.
async fn sign_in_for_code(
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    w: &Wallet,
    challenge: &str,
    state: &str,
) -> String {
    let (session_cookie, nonce, domain) = authorize_session(nrc, base, rc, challenge, state).await;
    let message = build_login_message(w, base, &domain, &nonce, &rc.redirect_uri, 48);
    let sign_in_url = format!(
        "{base}/sign_in?redirect_uri={}&state={state}&client_id={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(challenge),
    );
    let resp = nrc
        .get(&sign_in_url)
        .header("cookie", siwx_cookie_header(&session_cookie, w, &message))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "setup: sign_in must issue a code (location {location:?}): {}",
        resp.text().await.unwrap_or_default()
    );
    parse_query(&location.unwrap())
        .get("code")
        .expect("setup: the sign_in redirect carries a code")
        .clone()
}

/// POST /token with the authorization_code grant. `verifier` None omits it.
async fn exchange_code(
    c: &Client,
    base: &str,
    rc: &RegisteredClient,
    code: &str,
    verifier: Option<&str>,
) -> reqwest::Response {
    let mut form = vec![
        ("code", code.to_string()),
        ("client_id", rc.client_id.clone()),
        ("client_secret", rc.client_secret.clone()),
        ("grant_type", "authorization_code".to_string()),
    ];
    if let Some(v) = verifier {
        form.push(("code_verifier", v.to_string()));
    }
    c.post(format!("{base}/token"))
        .form(&form)
        .send()
        .await
        .unwrap()
}

/// A complete code-flow sign-in for a fresh wallet, with a confidential client.
/// Returns (access, refresh, did, client): the refresh grant at `/token` binds
/// the refresh token to the client and authenticates it.
async fn login_tokens(
    c: &Client,
    nrc: &Client,
    base: &str,
) -> (String, String, String, RegisteredClient) {
    let rc = register_client(c, base).await;
    let w = new_wallet();
    let (verifier, challenge) = pkce_pair();
    let code = sign_in_for_code(nrc, base, &rc, &w, &challenge, "kind_state").await;
    let resp = exchange_code(c, base, &rc, &code, Some(&verifier)).await;
    assert_eq!(resp.status(), StatusCode::OK, "setup: code exchange");
    let body: Value = resp.json().await.unwrap();
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
        w.did,
        rc,
    )
}

/// POST /oauth2/introspect authenticated with the MAS shared secret.
async fn introspect(c: &Client, base: &str, token: &str) -> Value {
    let resp = c
        .post(format!("{base}/oauth2/introspect"))
        .bearer_auth(shared_secret())
        .form(&[("token", token), ("token_type_hint", "access_token")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "introspection answers 200");
    resp.json().await.unwrap()
}

/// POST /token with the refresh_token grant.
async fn refresh_grant(c: &Client, base: &str, token: &str) -> reqwest::Response {
    c.post(format!("{base}/token"))
        .form(&[("grant_type", "refresh_token"), ("refresh_token", token)])
        .send()
        .await
        .unwrap()
}

/// POST /_matrix/client/v3/refresh.
async fn matrix_refresh(c: &Client, base: &str, token: &str) -> reqwest::Response {
    c.post(format!("{base}/_matrix/client/v3/refresh"))
        .json(&json!({ "refresh_token": token }))
        .send()
        .await
        .unwrap()
}

async fn assert_refused_by_refresh_grant(c: &Client, base: &str, token: &str, what: &str) {
    let resp = refresh_grant(c, base, token).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the refresh_token grant must refuse {what}, got {status}: {body}"
    );
    assert!(
        body.contains("invalid_grant"),
        "{what} must be refused like an unknown token (invalid_grant): {body}"
    );
}

async fn assert_refused_by_matrix_refresh(c: &Client, base: &str, token: &str, what: &str) {
    let resp = matrix_refresh(c, base, token).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/_matrix/client/v3/refresh must refuse {what}, got {status}: {body}"
    );
    assert!(
        body.contains("M_UNKNOWN_TOKEN"),
        "{what} must be refused like an unknown token (M_UNKNOWN_TOKEN): {body}"
    );
}

/// The refresh_token grant at /token accepts only a refresh token. An access
/// token is refused like an unknown one, and stays a working access token.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn the_refresh_grant_accepts_only_a_refresh_token() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let (access, refresh, _did, rc) = login_tokens(&c, &nrc, &base).await;

    assert_refused_by_refresh_grant(&c, &base, &access, "an access token").await;
    assert_eq!(
        introspect(&c, &base, &access).await["active"],
        json!(true),
        "a refused access token must stay active (never deleted by the refusal)"
    );

    // Control: the real refresh token still refreshes.
    let ok = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "a refresh token still refreshes"
    );
}

/// The same rule at the Matrix-shaped refresh endpoint.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn the_matrix_refresh_endpoint_accepts_only_a_refresh_token() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let (access, refresh, _did, _rc) = login_tokens(&c, &nrc, &base).await;

    assert_refused_by_matrix_refresh(&c, &base, &access, "an access token").await;
    assert_eq!(
        introspect(&c, &base, &access).await["active"],
        json!(true),
        "a refused access token must stay active (never deleted by the refusal)"
    );

    // Control: the real refresh token still refreshes.
    let ok = matrix_refresh(&c, &base, &refresh).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "a refresh token still refreshes"
    );
}

/// A minted admin token is an access token: neither refresh endpoint accepts it.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn neither_refresh_endpoint_accepts_an_admin_token() {
    let base = oidc();
    let c = Client::new();
    let minted = c
        .post(format!("{base}/oauth2/admin_token"))
        .bearer_auth(shared_secret())
        .send()
        .await
        .unwrap();
    assert_eq!(minted.status(), StatusCode::OK, "setup: admin token mint");
    let minted: Value = minted.json().await.unwrap();
    let admin = minted["access_token"].as_str().unwrap().to_string();

    assert_refused_by_refresh_grant(&c, &base, &admin, "an admin token").await;
    assert_refused_by_matrix_refresh(&c, &base, &admin, "an admin token").await;

    // The refusals left the admin token itself alone.
    let intro = introspect(&c, &base, &admin).await;
    assert_eq!(intro["active"], json!(true), "the admin token stays active");
    assert!(
        intro["scope"]
            .as_str()
            .unwrap_or("")
            .contains("urn:synapse:admin:*"),
        "control: this really is the admin-scoped token: {intro}"
    );
}

/// A refresh token is not a bearer credential: introspection reports it
/// inactive, /userinfo refuses it, and the bearer-authenticated Matrix routes
/// treat it as unknown without tearing the session down.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_refresh_token_is_not_a_bearer_credential() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let (access, refresh, did, rc) = login_tokens(&c, &nrc, &base).await;

    let intro = introspect(&c, &base, &refresh).await;
    assert_eq!(
        intro["active"],
        json!(false),
        "introspection must report a refresh token inactive: {intro}"
    );

    let ui = c
        .get(format!("{base}/userinfo"))
        .bearer_auth(&refresh)
        .send()
        .await
        .unwrap();
    assert_ne!(
        ui.status(),
        StatusCode::OK,
        "GET /userinfo must refuse a refresh token: {}",
        ui.text().await.unwrap_or_default()
    );
    let ui_post = c
        .post(format!("{base}/userinfo"))
        .form(&[("access_token", refresh.as_str())])
        .send()
        .await
        .unwrap();
    assert_ne!(
        ui_post.status(),
        StatusCode::OK,
        "POST /userinfo must refuse a refresh token: {}",
        ui_post.text().await.unwrap_or_default()
    );

    // Device deletion answers a refresh token exactly like an unknown token.
    for resp in [
        c.delete(format!("{base}/_matrix/client/v3/devices/SIWX_any"))
            .bearer_auth(&refresh)
            .send()
            .await
            .unwrap(),
        c.post(format!("{base}/_matrix/client/v3/delete_devices"))
            .bearer_auth(&refresh)
            .json(&json!({ "devices": [] }))
            .send()
            .await
            .unwrap(),
    ] {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "device deletion must refuse a refresh token as its bearer, got {status}: {body}"
        );
        assert!(body.contains("M_UNKNOWN_TOKEN"), "{body}");
    }

    // Logout answers 200 for any bearer (Matrix expects it), but a refresh
    // token as the bearer must not end the session.
    for path in ["logout", "logout/all"] {
        let resp = c
            .post(format!("{base}/_matrix/client/v3/{path}"))
            .bearer_auth(&refresh)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path} answers 200");
        assert_eq!(
            introspect(&c, &base, &access).await["active"],
            json!(true),
            "a refresh token as the bearer of {path} must not end the session"
        );
    }

    // Controls: the access token is the bearer credential, and the refresh
    // token survived every refusal above and still refreshes.
    let ok = c
        .get(format!("{base}/userinfo"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "/userinfo accepts the access token"
    );
    let claims: Value = ok.json().await.unwrap();
    assert_eq!(claims["sub"], json!(did), "userinfo sub is the DID");
    let still = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(
        still.status(),
        StatusCode::OK,
        "the refresh token was not deleted by any refusal"
    );
}

// ===========================================================================
// Authorization codes: single use, and never a bearer token.
//
// A code is redeemable exactly once, at /token, with the PKCE verifier. It is
// not an access token: /userinfo refuses it before and after the exchange.
// ===========================================================================

/// An authorization code is refused at /userinfo, both before and after it is
/// exchanged. Only the access token from the exchange is a bearer credential.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn an_authorization_code_is_never_a_bearer_token() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let w = new_wallet();
    let (verifier, challenge) = pkce_pair();
    let code = sign_in_for_code(&nrc, &base, &rc, &w, &challenge, "code_bearer").await;

    let assert_refused = |resp: reqwest::Response, when: &'static str| async move {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert_ne!(
            status,
            StatusCode::OK,
            "/userinfo must refuse an authorization code {when}, got 200: {body}"
        );
    };

    assert_refused(
        c.get(format!("{base}/userinfo"))
            .bearer_auth(&code)
            .send()
            .await
            .unwrap(),
        "before the exchange (GET, bearer)",
    )
    .await;
    assert_refused(
        c.post(format!("{base}/userinfo"))
            .form(&[("access_token", code.as_str())])
            .send()
            .await
            .unwrap(),
        "before the exchange (POST, form)",
    )
    .await;

    let exchanged = exchange_code(&c, &base, &rc, &code, Some(&verifier)).await;
    assert_eq!(exchanged.status(), StatusCode::OK, "setup: code exchange");
    let tokens: Value = exchanged.json().await.unwrap();

    assert_refused(
        c.get(format!("{base}/userinfo"))
            .bearer_auth(&code)
            .send()
            .await
            .unwrap(),
        "after the exchange (GET, bearer)",
    )
    .await;
    assert_refused(
        c.post(format!("{base}/userinfo"))
            .form(&[("access_token", code.as_str())])
            .send()
            .await
            .unwrap(),
        "after the exchange (POST, form)",
    )
    .await;

    // Control: the access token from the exchange is accepted.
    let ok = c
        .get(format!("{base}/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "/userinfo accepts the access token"
    );
    let claims: Value = ok.json().await.unwrap();
    assert_eq!(claims["sub"], json!(w.did), "userinfo sub is the DID");
}

/// A second exchange of the same code fails, even with the right verifier.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn an_authorization_code_is_single_use() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let w = new_wallet();
    let (verifier, challenge) = pkce_pair();
    let code = sign_in_for_code(&nrc, &base, &rc, &w, &challenge, "code_once").await;

    let first = exchange_code(&c, &base, &rc, &code, Some(&verifier)).await;
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "the first exchange succeeds"
    );

    let second = exchange_code(&c, &base, &rc, &code, Some(&verifier)).await;
    let status = second.status();
    let body = second.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a second exchange must fail, got {status}: {body}"
    );
    assert!(body.contains("invalid_grant"), "{body}");
}

// ===========================================================================
// The authorization request is bound to the session at /authorize.
//
// /authorize accepts only `response_type=code` with an S256 challenge, matches
// the redirect URI exactly against the registration, and stores the validated
// request (client, redirect URI, state, response mode, PKCE challenge) in the
// session. /sign_in issues the code for THAT request: parameters it receives
// on the front channel may repeat the request, never change it. Discovery
// advertises only what is implemented.
// ===========================================================================

async fn register_client_with_redirect(
    c: &Client,
    base: &str,
    redirect_uri: &str,
) -> RegisteredClient {
    let reg: Value = c
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [redirect_uri],
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
        redirect_uri: redirect_uri.to_string(),
    }
}

/// GET /sign_in with a raw query string, the session cookie and a wallet
/// signature over a login message that binds `resource`.
async fn sign_in_raw(
    nrc: &Client,
    base: &str,
    session: (&str, &str, &str),
    w: &Wallet,
    resource: &str,
    query: &str,
) -> reqwest::Response {
    let (session_cookie, nonce, domain) = session;
    let message = build_login_message(w, base, domain, nonce, resource, 48);
    nrc.get(format!("{base}/sign_in?{query}"))
        .header("cookie", siwx_cookie_header(session_cookie, w, &message))
        .send()
        .await
        .unwrap()
}

fn location_of(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

/// /authorize refuses every response type except `code`: the client is sent
/// back to its (validated) redirect URI with `unsupported_response_type` and
/// its `state`, and no login session is started.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn authorize_accepts_only_the_code_response_type() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;

    for (i, response_type) in ["id_token", "token", "token id_token", "none"]
        .into_iter()
        .enumerate()
    {
        let state = format!("rt_state_{i}");
        let url = format!(
            "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type={}&state={state}",
            urlencoding::encode(&rc.client_id),
            urlencoding::encode(&rc.redirect_uri),
            urlencoding::encode(response_type),
        );
        let resp = nrc.get(&url).send().await.unwrap();
        let status = resp.status();
        let location = location_of(&resp);
        assert!(
            !location.starts_with("/?"),
            "response_type={response_type} must not reach the login page: {location}"
        );
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "response_type={response_type} is answered by redirecting to the client"
        );
        assert!(
            location.starts_with(&format!("{}?", rc.redirect_uri)),
            "the error goes to the registered redirect URI: {location}"
        );
        let q = parse_query(&location);
        assert_eq!(
            q.get("error").map(String::as_str),
            Some("unsupported_response_type"),
            "response_type={response_type}: {location}"
        );
        assert_eq!(
            q.get("state"),
            Some(&state),
            "the state is echoed: {location}"
        );
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "no login session is started for response_type={response_type}"
        );
    }

    // Control: the code flow with S256 still reaches the login page.
    let (_verifier, challenge) = pkce_pair();
    let _ = authorize_session(&nrc, &base, &rc, &challenge, "rt_ok").await;
}

/// The code is bound to the challenge sent to /authorize, whatever /sign_in
/// receives: without PKCE parameters on /sign_in (the headless client's
/// shape) the code still needs the /authorize verifier, and a different
/// challenge on /sign_in is refused.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn the_code_is_bound_to_the_challenge_sent_to_authorize() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let w = new_wallet();
    let plain_query = format!(
        "redirect_uri={}&state=bound&client_id={}",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
    );

    // (a) No PKCE parameters on /sign_in: the code needs the verifier anyway.
    let (_v1, c1) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc, &c1, "bound").await;
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &plain_query,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "sign_in issues the code"
    );
    let code = parse_query(&location_of(&resp))
        .get("code")
        .unwrap()
        .clone();
    let no_verifier = exchange_code(&c, &base, &rc, &code, None).await;
    let status = no_verifier.status();
    let body = no_verifier.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code must not be redeemable without the /authorize verifier, got {status}: {body}"
    );
    assert!(body.contains("invalid_grant"), "{body}");

    // (b) The same shape with the right verifier works.
    let (v2, c2) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc, &c2, "bound").await;
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &plain_query,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "sign_in issues the code"
    );
    let code = parse_query(&location_of(&resp))
        .get("code")
        .unwrap()
        .clone();
    let ok = exchange_code(&c, &base, &rc, &code, Some(&v2)).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "the /authorize verifier redeems the code"
    );

    // (c) A different challenge in the /sign_in query has no effect: the code
    //     is still issued for the bound request, and the verifier of the
    //     challenge named on /sign_in does not redeem it.
    let (_v3, c3) = pkce_pair();
    let (vx, cx) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc, &c3, "bound").await;
    let query = format!(
        "{plain_query}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&cx)
    );
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &query,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "sign_in issues the code"
    );
    let code = parse_query(&location_of(&resp))
        .get("code")
        .unwrap()
        .clone();
    let other = exchange_code(&c, &base, &rc, &code, Some(&vx)).await;
    let status = other.status();
    let body = other.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the verifier of a challenge named on /sign_in must not redeem the code, \
         got {status}: {body}"
    );
    assert!(body.contains("invalid_grant"), "{body}");
}

/// /sign_in reads no authorization parameter from its query: a different state
/// there has no effect, and the redirect carries the state /authorize bound.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn sign_in_ignores_a_state_in_its_query() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let w = new_wallet();

    let (_v, ch) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc, &ch, "state_one").await;
    let query = format!(
        "redirect_uri={}&state=state_two&client_id={}",
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(&rc.client_id),
    );
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &query,
    )
    .await;
    let status = resp.status();
    let location = location_of(&resp);
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "sign_in issues the code for the bound request: {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        location.starts_with(&format!("{}?", rc.redirect_uri)),
        "{location}"
    );
    assert_eq!(
        parse_query(&location).get("state").map(String::as_str),
        Some("state_one"),
        "the redirect carries the bound state, never one from the /sign_in query: {location}"
    );
}

/// /sign_in reads no authorization parameter from its query: naming another
/// (registered) client and its redirect URI there has no effect. No code is
/// ever issued to that client; the code goes to the bound redirect URI, is
/// issued for the bound client, and the other client cannot redeem it.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn sign_in_ignores_a_client_in_its_query() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc_a = register_client(&c, &base).await;
    let rc_b = register_client_with_redirect(&c, &base, &format!("{base}/other-callback")).await;
    let w = new_wallet();
    let query = format!(
        "redirect_uri={}&state=client_state&client_id={}",
        urlencoding::encode(&rc_b.redirect_uri),
        urlencoding::encode(&rc_b.client_id),
    );

    // (a) Even with the signed message binding the other client's redirect
    //     URI, no code is issued to it: the message must bind the redirect URI
    //     of the request /authorize validated.
    let (_v, ch) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc_a, &ch, "client_state").await;
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc_b.redirect_uri,
        &query,
    )
    .await;
    let location = location_of(&resp);
    assert!(
        !location.contains("code="),
        "no code may be issued to a client other than the one /authorize validated: {location}"
    );

    // (b) With the message binding the bound redirect URI, the code goes there
    //     and belongs to the bound client.
    let (verifier, ch) = pkce_pair();
    let s = authorize_session(&nrc, &base, &rc_a, &ch, "client_state").await;
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc_a.redirect_uri,
        &query,
    )
    .await;
    let status = resp.status();
    let location = location_of(&resp);
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "sign_in issues the code for the bound request: {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        location.starts_with(&format!("{}?", rc_a.redirect_uri)),
        "the code goes to the bound client's redirect URI, never to one from the \
         /sign_in query: {location}"
    );
    let code = parse_query(&location).get("code").unwrap().clone();

    // The client named on /sign_in cannot redeem it, even with the verifier.
    let as_b = exchange_code(&c, &base, &rc_b, &code, Some(&verifier)).await;
    let status = as_b.status();
    let body = as_b.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the client named on /sign_in must not redeem the code, got {status}: {body}"
    );
    assert!(body.contains("invalid_grant"), "{body}");
}

/// Redirect URIs match the registration exactly, query included, at
/// /authorize and at /sign_in.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn redirect_uris_match_the_registration_exactly() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;
    let extra = format!("{}?extra=1", rc.redirect_uri);

    // (a) /authorize: an extra query component is not the registered URI.
    let (_v, ch) = pkce_pair();
    let url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=exact&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&extra),
        urlencoding::encode(&ch),
    );
    let resp = nrc.get(&url).send().await.unwrap();
    let location = location_of(&resp);
    assert!(
        !location.starts_with("/?"),
        "/authorize must refuse a redirect URI with an extra query: {location}"
    );
    assert!(
        location.contains("unregistered_redirect_uri"),
        "/authorize names the reason: {location}"
    );

    // (b) /sign_in: the same URI in its query has no effect; the code goes to
    //     the exact URI /authorize matched and bound.
    let s = authorize_session(&nrc, &base, &rc, &ch, "exact").await;
    let query = format!(
        "redirect_uri={}&state=exact&client_id={}",
        urlencoding::encode(&extra),
        urlencoding::encode(&rc.client_id),
    );
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&s.0, &s.1, &s.2),
        &w,
        &rc.redirect_uri,
        &query,
    )
    .await;
    let status = resp.status();
    let location = location_of(&resp);
    assert_eq!(status, StatusCode::SEE_OTHER, "sign_in issues the code");
    assert!(
        location.starts_with(&format!("{}?code=", rc.redirect_uri)) && !location.contains("extra"),
        "the code goes to the bound redirect URI, never to one from the /sign_in query: {location}"
    );

    // (c) A registration that carries a query (as Element Web's does) works
    //     when the client sends exactly that URI, and only then.
    let with_query = format!("{base}/callback?app=1");
    let rq = register_client_with_redirect(&c, &base, &with_query).await;
    let bare = format!("{base}/callback");
    let url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state=exact&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rq.client_id),
        urlencoding::encode(&bare),
        urlencoding::encode(&ch),
    );
    let resp = nrc.get(&url).send().await.unwrap();
    let location = location_of(&resp);
    assert!(
        location.contains("unregistered_redirect_uri"),
        "the registered query is part of the URI; dropping it is a mismatch: {location}"
    );
    let (verifier, ch) = pkce_pair();
    let code = sign_in_for_code(&nrc, &base, &rq, &w, &ch, "exact").await;
    let ok = exchange_code(&c, &base, &rq, &code, Some(&verifier)).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "the exact registered URI works end to end"
    );
}

/// JavaScript's `encodeURI`, which the login page applies to every value of
/// its /sign_in link: it leaves `;,/?:@&=+$#` and the unreserved characters as
/// they are.
fn encode_uri(value: &str) -> String {
    const KEEP: &[u8] = b";,/?:@&=+$-_.!~*'()#";
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || KEEP.contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The /sign_in query exactly as the login page (`js/ui/src/App.svelte`)
/// builds it from the values it read off its own URL.
fn login_page_sign_in_query(page: &HashMap<String, String>) -> String {
    let get = |k: &str| page.get(k).cloned().unwrap_or_default();
    let mut tail = String::new();
    if !get("oidc_nonce").is_empty() {
        tail.push_str(&format!("&oidc_nonce={}", get("oidc_nonce")));
    }
    if !get("code_challenge").is_empty() {
        tail.push_str(&format!("&code_challenge={}", get("code_challenge")));
        let method = get("code_challenge_method");
        tail.push_str(&format!(
            "&code_challenge_method={}",
            if method.is_empty() {
                "S256".to_string()
            } else {
                method
            }
        ));
    }
    if !get("response_mode").is_empty() {
        tail.push_str(&format!("&response_mode={}", get("response_mode")));
    }
    format!(
        "redirect_uri={}&state={}&client_id={}{}",
        encode_uri(&get("redirect_uri")),
        encode_uri(&get("state")),
        encode_uri(&get("client_id")),
        encode_uri(&tail),
    )
}

/// The login page round trip keeps the exact redirect URI and state: a
/// registered redirect URI with several query parameters and a state with
/// characters the page's link does not encode both reach the client
/// unchanged, and the wallet signature binds the full redirect URI.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn the_login_page_round_trip_keeps_the_exact_redirect_uri_and_state() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let w = new_wallet();
    let redirect = format!("{base}/callback?a=1&b=2");
    let rc = register_client_with_redirect(&c, &base, &redirect).await;
    let state = "st+a&b c";
    let (verifier, challenge) = pkce_pair();

    let url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&redirect),
        urlencoding::encode(state),
        urlencoding::encode(&challenge),
    );
    let auth = nrc.get(&url).send().await.unwrap();
    assert_eq!(auth.status(), StatusCode::SEE_OTHER, "authorize");
    let session_cookie = auth
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let page = parse_query(&location_of(&auth));
    assert_eq!(
        page.get("redirect_uri"),
        Some(&redirect),
        "the login page must receive the whole redirect URI"
    );
    assert_eq!(page.get("state").map(String::as_str), Some(state));

    // The page signs the redirect URI it read, and links to /sign_in with
    // encodeURI'd values (which alters `&`, `+` and spaces here).
    let query = login_page_sign_in_query(&page);
    let resp = sign_in_raw(
        &nrc,
        &base,
        (&session_cookie, &page["nonce"], &page["domain"]),
        &w,
        &page["redirect_uri"],
        &query,
    )
    .await;
    let status = resp.status();
    let location = location_of(&resp);
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the login page round trip completes (location {location}): {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        location.starts_with(&format!("{redirect}&code=")),
        "the code goes to the exact registered redirect URI: {location}"
    );
    let q = parse_query(&location);
    assert_eq!(q.get("a").map(String::as_str), Some("1"), "{location}");
    assert_eq!(q.get("b").map(String::as_str), Some("2"), "{location}");
    assert_eq!(
        q.get("state").map(String::as_str),
        Some(state),
        "the client gets its state back unchanged: {location}"
    );
    let ok = exchange_code(&c, &base, &rc, &q["code"], Some(&verifier)).await;
    assert_eq!(ok.status(), StatusCode::OK, "the code redeems");
}

/// Discovery advertises exactly the response types /authorize implements.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn discovery_advertises_only_the_code_response_type() {
    let base = oidc();
    let meta: Value = Client::new()
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        meta["response_types_supported"],
        json!(["code"]),
        "discovery must advertise only the code response type: {}",
        meta["response_types_supported"]
    );
}

// ===========================================================================
// Refresh tokens are bound to their client (I7).
//
// A refresh token belongs to the client it was issued to. At the refresh grant
// the client named in the request (form, or the user name of an HTTP Basic
// header) must be that client, and a confidential client authenticates with
// its secret, exactly as at the code exchange. `POST /_matrix/client/v3/refresh`
// carries no client identity by specification and is not covered here.
// ===========================================================================

/// A client registered the way Element Web and Element X register: public,
/// `token_endpoint_auth_method: none`, allowed the refresh grant.
async fn register_public_client(c: &Client, base: &str) -> RegisteredClient {
    let redirect_uri = format!("{base}/callback");
    let reg: Value = c
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [&redirect_uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
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

/// A code-flow sign-in for `rc` with a fresh wallet. A confidential client
/// authenticates the exchange with its secret; a public one sends none.
/// Returns (access, refresh).
async fn tokens_for_client(
    c: &Client,
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    confidential: bool,
) -> (String, String) {
    let w = new_wallet();
    let (verifier, challenge) = pkce_pair();
    let code = sign_in_for_code(nrc, base, rc, &w, &challenge, "bind_state").await;
    let mut form = vec![
        ("code", code),
        ("client_id", rc.client_id.clone()),
        ("grant_type", "authorization_code".to_string()),
        ("code_verifier", verifier),
    ];
    if confidential {
        form.push(("client_secret", rc.client_secret.clone()));
    }
    let resp = c
        .post(format!("{base}/token"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "setup: code exchange");
    let body: Value = resp.json().await.unwrap();
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

/// POST /token with the refresh grant and the given extra form fields and
/// optional HTTP Basic credentials.
async fn refresh_as(
    c: &Client,
    base: &str,
    refresh_token: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> reqwest::Response {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    fields.extend_from_slice(form);
    let mut request = c.post(format!("{base}/token")).form(&fields);
    if let Some((user, password)) = basic {
        request = request.basic_auth(user, Some(password));
    }
    request.send().await.unwrap()
}

/// (status, error code, WWW-Authenticate header) of an error response.
async fn refusal(resp: reqwest::Response) -> (StatusCode, String, Option<String>) {
    let status = resp.status();
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (
        status,
        body["error"].as_str().unwrap_or("").to_string(),
        challenge,
    )
}

/// Another client cannot refresh the token, whether it names itself in the
/// form or in a Basic header and whatever secret it authenticates with, and a
/// request whose form and header name different clients is malformed. The
/// refusals leave the token alone: its owner refreshes it afterwards.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_refresh_token_is_refused_to_another_client() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let owner = register_client(&c, &base).await;
    let other = register_client(&c, &base).await;
    let (_access, refresh) = tokens_for_client(&c, &nrc, &base, &owner, true).await;

    let in_form = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", other.client_id.as_str()),
            ("client_secret", other.client_secret.as_str()),
        ],
        None,
    )
    .await;
    let (status, error, _) = refusal(in_form).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::BAD_REQUEST, "invalid_grant"),
        "another client, named in the form"
    );

    let in_header = refresh_as(
        &c,
        &base,
        &refresh,
        &[],
        Some((&other.client_id, &other.client_secret)),
    )
    .await;
    let (status, error, _) = refusal(in_header).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::BAD_REQUEST, "invalid_grant"),
        "another client, named in a Basic header"
    );

    let split = refresh_as(
        &c,
        &base,
        &refresh,
        &[("client_id", owner.client_id.as_str())],
        Some((&other.client_id, &owner.client_secret)),
    )
    .await;
    let (status, error, _) = refusal(split).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::BAD_REQUEST, "invalid_request"),
        "a form and a header that name different clients"
    );

    let own = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", owner.client_id.as_str()),
            ("client_secret", owner.client_secret.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(
        own.status(),
        StatusCode::OK,
        "the refusals did not consume the token: its owner refreshes it"
    );
}

/// A confidential client authenticates at the refresh grant: no credentials
/// and a wrong secret are `invalid_client` with a 401, and a request that
/// attempted HTTP Basic is answered with the matching challenge. The secret
/// goes in the form or in a Basic header. The replay of a lost response hands
/// out the successor pair only to the same client.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_confidential_client_must_authenticate_to_refresh() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let (_access, refresh) = tokens_for_client(&c, &nrc, &base, &rc, true).await;

    let anonymous = refresh_as(&c, &base, &refresh, &[], None).await;
    assert_eq!(
        refusal(anonymous).await,
        (StatusCode::UNAUTHORIZED, "invalid_client".to_string(), None),
        "no credentials, and no Basic attempt to challenge"
    );
    let named = refresh_as(
        &c,
        &base,
        &refresh,
        &[("client_id", rc.client_id.as_str())],
        None,
    )
    .await;
    let (status, error, _) = refusal(named).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_client"),
        "naming itself is not authenticating"
    );
    let wrong_basic = refresh_as(&c, &base, &refresh, &[], Some((&rc.client_id, "wrong"))).await;
    let (status, error, challenge) = refusal(wrong_basic).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_client"),
        "a wrong Basic secret"
    );
    assert!(
        challenge.is_some_and(|c| c.starts_with("Basic")),
        "a 401 for a Basic attempt carries `WWW-Authenticate: Basic` (RFC 6749 §5.2)"
    );

    // The refusals consumed nothing: the secret in the form refreshes.
    let by_form = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(by_form.status(), StatusCode::OK, "secret in the form");
    let rotated: Value = by_form.json().await.unwrap();
    let successor = rotated["refresh_token"].as_str().unwrap().to_string();

    // The old token replayed while the new pair is unused: the client recovers
    // the pair it lost, a caller without the client's credentials does not.
    let replay_anonymous = refresh_as(&c, &base, &refresh, &[], None).await;
    let (status, error, _) = refusal(replay_anonymous).await;
    assert_eq!(
        (status, error.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_client"),
        "the replay is bound to the client too"
    );
    let replay_owner = refresh_as(
        &c,
        &base,
        &refresh,
        &[
            ("client_id", rc.client_id.as_str()),
            ("client_secret", rc.client_secret.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(
        replay_owner.status(),
        StatusCode::OK,
        "the client's own replay still recovers the pair"
    );

    // The successor refreshes with the secret in a Basic header (and so no
    // client_id in the form), which also ends the recovery for the old token.
    let by_basic = refresh_as(
        &c,
        &base,
        &successor,
        &[],
        Some((&rc.client_id, &rc.client_secret)),
    )
    .await;
    assert_eq!(
        by_basic.status(),
        StatusCode::OK,
        "secret in a Basic header"
    );
}

/// A public client has nothing to authenticate with: it refreshes naming
/// itself, as Matrix clients and `siwx-oidc-auth` do, and also without
/// naming itself (provisional, for agents that never sent a client id).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_public_client_refreshes_without_client_credentials() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_public_client(&c, &base).await;
    let (_access, refresh) = tokens_for_client(&c, &nrc, &base, &rc, false).await;

    let named = refresh_as(
        &c,
        &base,
        &refresh,
        &[("client_id", rc.client_id.as_str())],
        None,
    )
    .await;
    assert_eq!(named.status(), StatusCode::OK, "naming itself");
    let body: Value = named.json().await.unwrap();
    let successor = body["refresh_token"].as_str().unwrap().to_string();

    let anonymous = refresh_as(&c, &base, &successor, &[], None).await;
    assert_eq!(
        anonymous.status(),
        StatusCode::OK,
        "naming nobody (provisional)"
    );
}

/// An `Authorization` header at `POST /token` is read, not rejected. A handler
/// that takes a Bearer and a Basic extractor side by side answered every
/// request carrying the header with a 400, so no client could authenticate with
/// `client_secret_basic`. The client id may then come from the header alone.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_basic_authorization_header_authenticates_the_code_exchange() {
    let base = oidc();
    let c = Client::new();
    let nrc = no_redirect_client();
    let rc = register_client(&c, &base).await;
    let (verifier, challenge) = pkce_pair();
    let code = sign_in_for_code(&nrc, &base, &rc, &new_wallet(), &challenge, "basic_state").await;

    let resp = c
        .post(format!("{base}/token"))
        .basic_auth(&rc.client_id, Some(&rc.client_secret))
        .form(&[
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "a Basic header carries the client id and secret: {body}"
    );
}
