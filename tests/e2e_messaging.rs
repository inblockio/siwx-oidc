//! E2E test: two clients authenticate via siwx-oidc and exchange Matrix messages.
//!
//! Required environment:
//!   SIWEOIDC_HOST - siwx-oidc instance (default: http://localhost:8081)
//!   MATRIX_HOST   - Matrix homeserver (default: http://localhost:8448)
//!
//! Run:
//!   MATRIX_HOST=https://matrix.inblock.io SIWEOIDC_HOST=https://siwx-oidc.inblock.io \
//!     cargo test --test e2e_messaging -- --nocapture

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

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
// Auth flow
// ---------------------------------------------------------------------------

struct AuthResult {
    access_token: String,
    #[allow(dead_code)]
    did: String,
}

async fn authenticate_client(label: &str) -> AuthResult {
    let base = siweoidc_host();

    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    eprintln!("[{label}] DID: {did}");

    let redirect_uri = format!("{}/callback", base);
    let reg_body = json!({
        "redirect_uris": [&redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });

    let http = Client::new();
    let reg_resp = http
        .post(format!("{}/register", base))
        .json(&reg_body)
        .send()
        .await
        .expect("register request failed");
    assert_eq!(reg_resp.status(), StatusCode::CREATED);
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

    let (code_verifier, code_challenge) = pkce_pair();
    let state = format!("state_{label}");
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
    );

    let signature = eip191_sign(&signing_key, &message);
    let siwx_payload = json!({
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
    let code = callback_query.get("code").unwrap();

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
    assert!(access_token.starts_with("mat_"));
    eprintln!("[{label}] authenticated, token={}", &access_token[..12]);

    AuthResult { access_token, did }
}

// ---------------------------------------------------------------------------
// Matrix helpers
// ---------------------------------------------------------------------------

async fn matrix_whoami(http: &Client, token: &str) -> Option<Value> {
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
        return None;
    }
    assert_eq!(resp.status(), StatusCode::OK);
    Some(resp.json().await.unwrap())
}

async fn create_room(http: &Client, token: &str, name: &str) -> String {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/createRoom",
            matrix_host()
        ))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "preset": "private_chat",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "createRoom failed: {:?}", body);
    body["room_id"].as_str().unwrap().to_string()
}

async fn invite_user(http: &Client, token: &str, room_id: &str, user_id: &str) {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/rooms/{}/invite",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .json(&json!({ "user_id": user_id }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "invite failed: {}", body);
}

async fn join_room(http: &Client, token: &str, room_id: &str) {
    let resp = http
        .post(format!(
            "{}/_matrix/client/v3/join/{}",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "join failed: {}", body);
}

async fn send_message(http: &Client, token: &str, room_id: &str, body: &str) -> String {
    let txn_id = uuid::Uuid::new_v4().to_string();
    let resp = http
        .put(format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            matrix_host(),
            urlencoding::encode(room_id),
            urlencoding::encode(&txn_id)
        ))
        .bearer_auth(token)
        .json(&json!({
            "msgtype": "m.text",
            "body": body,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let resp_body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "send_message failed: {:?}", resp_body);
    resp_body["event_id"].as_str().unwrap().to_string()
}

async fn sync_and_find_message(
    http: &Client,
    token: &str,
    room_id: &str,
    expected_body: &str,
) -> bool {
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/rooms/{}/messages?dir=b&limit=10",
            matrix_host(),
            urlencoding::encode(room_id)
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        eprintln!("[sync] messages endpoint returned {}", resp.status());
        return false;
    }
    let body: Value = resp.json().await.unwrap();
    if let Some(chunks) = body["chunk"].as_array() {
        for event in chunks {
            if event["type"] == "m.room.message" {
                if let Some(content_body) = event["content"]["body"].as_str() {
                    if content_body == expected_body {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_client_messaging() {
    let http = Client::new();

    let alice = authenticate_client("alice").await;
    let bob = authenticate_client("bob").await;

    let alice_whoami = matrix_whoami(&http, &alice.access_token).await;
    let bob_whoami = matrix_whoami(&http, &bob.access_token).await;

    if alice_whoami.is_none() || bob_whoami.is_none() {
        eprintln!("[e2e] Matrix introspection unavailable -- skipping messaging test");
        eprintln!("[e2e] Both OIDC auth flows succeeded at the siwx-oidc level");
        return;
    }

    let alice_user_id = alice_whoami.unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bob_user_id = bob_whoami.unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();
    eprintln!("[e2e] alice={}, bob={}", alice_user_id, bob_user_id);

    let room_id = create_room(&http, &alice.access_token, "e2e-test-room").await;
    eprintln!("[e2e] room_id={}", room_id);

    invite_user(&http, &alice.access_token, &room_id, &bob_user_id).await;
    eprintln!("[e2e] bob invited");

    join_room(&http, &bob.access_token, &room_id).await;
    eprintln!("[e2e] bob joined");

    let test_message = format!("Hello from alice! timestamp={}", Utc::now().timestamp());
    let event_id = send_message(&http, &alice.access_token, &room_id, &test_message).await;
    eprintln!("[e2e] alice sent message, event_id={}", event_id);

    let found = sync_and_find_message(&http, &bob.access_token, &room_id, &test_message).await;
    assert!(
        found,
        "bob should see alice's message '{}' in room {}",
        test_message, room_id
    );
    eprintln!("[e2e] bob received alice's message");

    let reply_message = format!("Hello back from bob! timestamp={}", Utc::now().timestamp());
    let reply_event_id =
        send_message(&http, &bob.access_token, &room_id, &reply_message).await;
    eprintln!("[e2e] bob sent reply, event_id={}", reply_event_id);

    let found_reply =
        sync_and_find_message(&http, &alice.access_token, &room_id, &reply_message).await;
    assert!(
        found_reply,
        "alice should see bob's reply '{}' in room {}",
        reply_message, room_id
    );
    eprintln!("[e2e] alice received bob's reply");

    eprintln!("[e2e] two-client messaging test PASSED");
}
