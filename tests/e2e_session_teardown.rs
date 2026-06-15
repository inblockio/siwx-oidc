//! Live end-to-end tests for Synapse-side session/device teardown on logout,
//! revocation, and bulk sign-out (Feature 1/2). These assert the *Synapse* side
//! effects that cannot be unit-tested without a live homeserver: that
//! `/_matrix/client/v3/logout` deletes the ending session's Synapse device, that
//! `/_matrix/client/v3/logout/all` deletes ALL of the user's devices, and that
//! the new `/logout/all` route is actually registered.
//!
//! Self-contained: copies the auth-flow helpers from `e2e_msc3861.rs` (the same
//! pattern `e2e_msc4191_live.rs` uses) so this file runs on its own and never
//! edits the existing test files.
//!
//! NOT runnable in CI here (no live Synapse). These mirror the repo's
//! `#[ignore]` e2e convention and run in deployment:
//!
//!   SIWEOIDC_HOST=https://siwx-oidc.inblock.io MATRIX_HOST=https://matrix.inblock.io \
//!     cargo test --test e2e_session_teardown -- --ignored --nocapture
//!
//! The pure teardown logic (graceful degradation, idempotency, logout_all
//! revoking every token, route handlers returning 200) is covered by the
//! runnable Redis-backed unit tests in `src/compat.rs` (`compat::tests`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers (copied from tests/e2e_msc3861.rs; do NOT edit that file)
// ---------------------------------------------------------------------------

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

fn matrix_host() -> String {
    std::env::var("MATRIX_HOST").unwrap_or_else(|_| "http://localhost:8448".to_string())
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
    Client::builder().redirect(Policy::none()).build().unwrap()
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

/// Perform a full OIDC auth flow with the given key and return
/// `(access_token, device_id)`. `device_id` is `None` if Matrix introspection
/// is unavailable (then the Synapse-side assertions self-skip).
async fn login_with_key(
    signing_key: &SigningKey,
    address: &str,
    did: &str,
) -> (String, Option<String>) {
    let base = siweoidc_host();
    let http = Client::new();

    let redirect_uri = format!("{}/callback", base);
    let reg_body = serde_json::json!({
        "redirect_uris": [&redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });
    let reg_resp = http
        .post(format!("{}/register", base))
        .json(&reg_body)
        .send()
        .await
        .unwrap();
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

    let (code_verifier, code_challenge) = pkce_pair();
    let state = "teardown_state";
    let client = no_redirect_client();

    let authorize_url = format!(
        "{}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state,
        urlencoding::encode(&code_challenge),
    );
    let auth_resp = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER);

    let set_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .unwrap()
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
    let nonce = query.get("nonce").unwrap();
    let domain = query.get("domain").unwrap();

    // The login path now enforces the CAIP-122 Expiration Time (C1 safe subset),
    // matching what the real Svelte frontend already sets — include a future exp.
    let now = Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expiration_time =
        (now + chrono::Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:\n\
         - {redirect_uri}",
        domain = domain,
        address = address,
        base = base,
        nonce = nonce,
        issued_at = issued_at,
        expiration_time = expiration_time,
        redirect_uri = redirect_uri,
    );

    let signature = eip191_sign(signing_key, &message);
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
        state,
        urlencoding::encode(&client_id),
        urlencoding::encode(&code_challenge),
    );

    let sign_in_resp = client
        .get(&sign_in_url)
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

    let sign_in_location = sign_in_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_query = parse_query(&sign_in_location);
    let code = callback_query.get("code").unwrap().clone();

    let token_resp = http
        .post(format!("{}/token", base))
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
    let token_json: Value = token_resp.json().await.unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let matrix = matrix_host();
    let whoami_resp = http
        .get(format!("{}/_matrix/client/v3/account/whoami", matrix))
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap();
    let device_id = if whoami_resp.status() == StatusCode::OK {
        let wj: Value = whoami_resp.json().await.unwrap();
        wj["device_id"].as_str().map(|s| s.to_string())
    } else {
        None
    };

    (access_token, device_id)
}

/// Fresh throwaway Ethereum identity.
fn fresh_identity() -> (SigningKey, String, String) {
    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    (signing_key, address, did)
}

/// Whether `device_id` is currently visible against Matrix for this token.
async fn whoami_status(token: &str) -> StatusCode {
    Client::new()
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

// ---------------------------------------------------------------------------
// H1: logout tears down the ending session's Synapse device + tokens
// ---------------------------------------------------------------------------

/// After `POST /_matrix/client/v3/logout` with the session's bearer token, the
/// token must no longer authenticate against Matrix (the Synapse device for the
/// ending session was deleted and the OAuth tokens revoked). One-time deletion
/// of the *ending* session is the safe teardown; no device id is recycled.
#[tokio::test]
#[ignore]
async fn logout_deletes_ending_session_device() {
    let oidc = siweoidc_host();
    let http = Client::new();

    let (key, address, did) = fresh_identity();
    let (token, device_id) = login_with_key(&key, &address, &did).await;
    eprintln!("[e2e] logged in: device={:?}", device_id);

    if device_id.is_none() {
        eprintln!("[e2e] Matrix introspection unavailable; skipping Synapse-side assertion.");
        return;
    }
    assert_eq!(
        whoami_status(&token).await,
        StatusCode::OK,
        "fresh token must work before logout"
    );

    let logout_resp = http
        .post(format!("{}/_matrix/client/v3/logout", oidc))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        logout_resp.status(),
        StatusCode::OK,
        "logout must return 200"
    );

    assert_eq!(
        whoami_status(&token).await,
        StatusCode::UNAUTHORIZED,
        "after logout the session token must be rejected (device deleted + tokens revoked)"
    );
    eprintln!("[e2e] logout tore down the ending session's device + tokens");
}

// ---------------------------------------------------------------------------
// H1: revoke (RFC 7009) tears down the session's device + tokens
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn revoke_deletes_session_device() {
    let oidc = siweoidc_host();
    let http = Client::new();

    let (key, address, did) = fresh_identity();
    let (token, device_id) = login_with_key(&key, &address, &did).await;
    if device_id.is_none() {
        eprintln!("[e2e] Matrix introspection unavailable; skipping Synapse-side assertion.");
        return;
    }

    let revoke_resp = http
        .post(format!("{}/oauth2/revoke", oidc))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoke_resp.status(),
        StatusCode::OK,
        "revoke must return 200"
    );

    assert_eq!(
        whoami_status(&token).await,
        StatusCode::UNAUTHORIZED,
        "after revoke the session token must be rejected"
    );
}

// ---------------------------------------------------------------------------
// H3 + route wiring: logout/all tears down EVERY session, account stays active
// ---------------------------------------------------------------------------

/// The new `/_matrix/client/v3/logout/all` route must be registered (no 404),
/// must invalidate ALL of the user's sessions (each device's token rejected),
/// and must NOT deactivate the account (the user can sign in again afterwards).
#[tokio::test]
#[ignore]
async fn logout_all_invalidates_all_sessions_without_deactivating() {
    let oidc = siweoidc_host();
    let http = Client::new();

    // Same identity, two independent sessions (two devices).
    let (key, address, did) = fresh_identity();
    let (token1, device1) = login_with_key(&key, &address, &did).await;
    let (token2, device2) = login_with_key(&key, &address, &did).await;
    eprintln!("[e2e] two sessions: d1={:?} d2={:?}", device1, device2);

    // Route-wiring assertion works even without a healthy introspection path:
    // a registered route returns 200, an unregistered one returns 404.
    let bulk = http
        .post(format!("{}/_matrix/client/v3/logout/all", oidc))
        .bearer_auth(&token1)
        .send()
        .await
        .unwrap();
    assert_ne!(
        bulk.status(),
        StatusCode::NOT_FOUND,
        "/_matrix/client/v3/logout/all must be a registered route"
    );
    assert_eq!(bulk.status(), StatusCode::OK, "logout/all must return 200");

    if device1.is_none() || device2.is_none() {
        eprintln!("[e2e] Matrix introspection unavailable; skipping Synapse-side assertions.");
        return;
    }

    // Both sessions must now be rejected.
    assert_eq!(
        whoami_status(&token1).await,
        StatusCode::UNAUTHORIZED,
        "session 1 must be invalidated by logout/all"
    );
    assert_eq!(
        whoami_status(&token2).await,
        StatusCode::UNAUTHORIZED,
        "session 2 (other device) must be invalidated by logout/all"
    );

    // The account must remain ACTIVE: a fresh sign-in with the same identity
    // must still succeed (logout/all must never deactivate).
    let (token3, _device3) = login_with_key(&key, &address, &did).await;
    assert!(
        token3.starts_with("mat_"),
        "the account must stay active: re-login after logout/all must succeed"
    );
    eprintln!("[e2e] logout/all invalidated all sessions and the account stayed active");

    // Cleanup: tear down the re-login session too.
    let _ = http
        .post(format!("{}/_matrix/client/v3/logout/all", oidc))
        .bearer_auth(&token3)
        .send()
        .await;
}
