//! H7: OpenID Connect Back-Channel Logout 1.0 end to end, against a siwx-oidc
//! in GENERIC mode (no MAS shared secret: every code grant is an `oidc`
//! grant) and the stub relying party in `e2e/synapse_mock.py` (`/__rp/*`).
//!
//! Environment:
//! - `SIWX_GENERIC_HOST`: the generic-mode server (default
//!   `http://localhost:18081`). It must list `localhost` in
//!   `SIWXOIDC_BACKCHANNEL_LOGOUT_ALLOWED_HOSTS`, so the stub RP on loopback
//!   may receive logout tokens.
//! - `SYNAPSE_MOCK`: the mock carrying the stub RP (default
//!   `http://localhost:8090`), reached by the server through `localhost`.
//! - `E2E_GENERIC_REDIS_URL`: the generic server's Redis, where one test seeds
//!   a client whose URI registration would refuse. Unset: that part is
//!   skipped loudly, and fails under `E2E_STRICT_SKIPS=1`.
//!
//! Run: `cargo test --test e2e_backchannel_logout -- --ignored --test-threads=1`

use k256::ecdsa::{RecoveryId, Signature as KSignature, SigningKey};
use p256::ecdsa::signature::Verifier;
use rand::rngs::OsRng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;
use std::time::{Duration, Instant};

fn generic() -> String {
    std::env::var("SIWX_GENERIC_HOST").unwrap_or_else(|_| "http://localhost:18081".to_string())
}
fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}
fn strict_skips() -> bool {
    std::env::var("E2E_STRICT_SKIPS")
        .map(|v| v == "1")
        .unwrap_or(true)
}

/// How long a delivery may take after the deletion that queued it: the
/// worker polls every second.
const DELIVERY_BOUND: Duration = Duration::from_secs(10);
/// The server's fixed retry schedule: five attempts, 2 s doubling backoff.
const MAX_ATTEMPTS: usize = 5;

// -- the stub RP -------------------------------------------------------------

fn rp_name(tag: &str) -> String {
    use rand::Rng;
    let n: u64 = rand::thread_rng().gen();
    format!("{tag}{n:x}")
}

fn rp_uri(name: &str) -> String {
    format!("{}/__rp/{name}/backchannel_logout", mock())
}

async fn rp_mode(c: &Client, name: &str, mode: &str) {
    let r = c
        .post(format!("{}/__rp/{name}/mode", mock()))
        .json(&json!({ "mode": mode }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "the mock carries the stub RP");
}

/// Every POST the stub RP received for `name`: `{content_type, body}`.
async fn rp_received(c: &Client, name: &str) -> Vec<Value> {
    let r = c
        .get(format!("{}/__rp/{name}/received", mock()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "the mock carries the stub RP");
    r.json::<Value>().await.unwrap()["received"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Wait until the stub RP holds at least `n` deliveries for `name`, or `bound`.
async fn wait_for(c: &Client, name: &str, n: usize, bound: Duration) -> Vec<Value> {
    let start = Instant::now();
    loop {
        let got = rp_received(c, name).await;
        if got.len() >= n || start.elapsed() > bound {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// -- a wallet sign-in in generic mode ------------------------------------------

struct Wallet {
    key: SigningKey,
    address: String,
    did: String,
}

fn new_wallet() -> Wallet {
    let key = SigningKey::random(&mut OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let lower = hex::encode(&hash[12..]);
    let check = Keccak256::digest(lower.as_bytes());
    let mut address = String::from("0x");
    for (i, ch) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            check[i / 2] >> 4
        } else {
            check[i / 2] & 0xf
        };
        address.push(if ch.is_ascii_alphabetic() && nibble >= 8 {
            ch.to_ascii_uppercase()
        } else {
            ch
        });
    }
    let did = format!("did:pkh:eip155:1:{address}");
    Wallet { key, address, did }
}

fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message.as_bytes());
    let prehash: [u8; 32] = h.finalize().into();
    let (sig, rec): (KSignature, RecoveryId) = key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec) + 27;
    format!("0x{}", hex::encode(bytes))
}

fn query_of(url: &str) -> HashMap<String, String> {
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

fn no_redirect() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

/// Register a public client that may refresh, with the given back-channel URI.
async fn register(c: &Client, backchannel_uri: &str) -> reqwest::Response {
    c.post(format!("{}/register", generic()))
        .json(&json!({
            "redirect_uris": [format!("{}/callback", generic())],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "backchannel_logout_uri": backchannel_uri,
            "backchannel_logout_session_required": true,
        }))
        .send()
        .await
        .unwrap()
}

async fn register_ok(c: &Client, backchannel_uri: &str) -> String {
    let r = register(c, backchannel_uri).await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "registration of {backchannel_uri}"
    );
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["backchannel_logout_uri"], backchannel_uri,
        "echoed: {body}"
    );
    body["client_id"].as_str().unwrap().to_string()
}

struct Session {
    wallet: Wallet,
    client_id: String,
    refresh_token: String,
    id_token: String,
}

/// A full wallet code flow with `offline_access` for `client_id`.
async fn sign_in(c: &Client, client_id: &str) -> Session {
    let base = generic();
    let w = new_wallet();
    let redirect_uri = format!("{base}/callback");
    let verifier: String = {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    };
    let challenge = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    };
    let nrc = no_redirect();
    let auth = nrc
        .get(format!(
            "{base}/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code&state=s&code_challenge={challenge}&code_challenge_method=S256",
            urlencoding::encode(client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode("openid offline_access"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(auth.status(), StatusCode::SEE_OTHER, "authorize 303");
    let cookie = auth.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let q = query_of(auth.headers()["location"].to_str().unwrap());
    let (nonce, domain) = (&q["nonce"], &q["domain"]);
    let now = chrono::Utc::now();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nYou are signing-in to {domain}.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {iat}\nExpiration Time: {exp}\nResources:\n- {redirect_uri}",
        addr = w.address,
        iat = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        exp = (now + chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );
    let siwx =
        json!({ "did": w.did, "message": message, "signature": eip191_sign(&w.key, &message) });
    let sign_in = nrc
        .get(format!("{base}/sign_in"))
        .header(
            "cookie",
            format!("{cookie}; siwx={}", urlencoding::encode(&siwx.to_string())),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sign_in.status(), StatusCode::SEE_OTHER, "sign_in 303");
    let code = query_of(sign_in.headers()["location"].to_str().unwrap())["code"].clone();
    let token: Value = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    Session {
        wallet: w,
        client_id: client_id.to_string(),
        refresh_token: token["refresh_token"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("generic mode issues a refresh token for offline_access: {token}")
            })
            .to_string(),
        id_token: token["id_token"].as_str().expect("an ID token").to_string(),
    }
}

async fn revoke(c: &Client, s: &Session) {
    let r = c
        .post(format!("{}/oauth2/revoke", generic()))
        .form(&[
            ("token", s.refresh_token.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", s.client_id.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "revocation");
}

fn decode(part: &str) -> Value {
    use base64::Engine;
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("base64url"),
    )
    .expect("json")
}

/// Verify a logout token against the server's JWKS and the session it ends.
async fn assert_valid_logout_token(c: &Client, delivery: &Value, s: &Session) {
    assert_eq!(
        delivery["content_type"], "application/x-www-form-urlencoded",
        "the token is POSTed as a form"
    );
    let form: HashMap<String, String> =
        url::form_urlencoded::parse(delivery["body"].as_str().unwrap().as_bytes())
            .into_owned()
            .collect();
    let token = form.get("logout_token").expect("a logout_token parameter");
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWS");
    let header = decode(parts[0]);
    let claims = decode(parts[1]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(
        header["typ"], "logout+jwt",
        "the logout token type: {header}"
    );

    let jwks: Value = c
        .get(format!("{}/jwk", generic()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header["kid"])
        .unwrap_or_else(|| panic!("the kid {} is in the JWKS", header["kid"]));
    let coord = |n: &str| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk[n].as_str().unwrap())
            .unwrap()
    };
    let mut sec1 = vec![4u8];
    sec1.extend(coord("x"));
    sec1.extend(coord("y"));
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap()
    };
    assert_eq!(sig.len(), 64, "raw r||s");
    key.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &p256::ecdsa::Signature::from_slice(&sig).unwrap(),
    )
    .expect("the logout token verifies against the JWKS");

    let discovery: Value = c
        .get(format!("{}/.well-known/openid-configuration", generic()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = decode(s.id_token.split('.').nth(1).unwrap());
    assert_eq!(claims["iss"], discovery["issuer"]);
    assert_eq!(claims["aud"], s.client_id.as_str());
    assert_eq!(claims["sub"], s.wallet.did.as_str());
    assert!(id["sid"].is_string(), "the ID token carries a sid: {id}");
    assert_eq!(
        claims["sid"], id["sid"],
        "the logout token names the ID token's sid"
    );
    assert_eq!(
        claims["events"],
        json!({"http://schemas.openid.net/event/backchannel-logout": {}})
    );
    assert!(
        claims.get("nonce").is_none(),
        "a logout token never carries a nonce"
    );
    assert!(claims["jti"].as_str().is_some_and(|j| j.len() >= 22));
    let (iat, exp) = (
        claims["iat"].as_i64().unwrap(),
        claims["exp"].as_i64().unwrap(),
    );
    assert_eq!(exp - iat, 120, "a short-lived token");
    assert!(
        (iat - chrono::Utc::now().timestamp()).abs() < 60,
        "iat is now"
    );
}

// -- the tests -------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs a generic-mode siwx-oidc and the synapse mock"]
async fn discovery_advertises_back_channel_logout_with_sessions() {
    let d: Value = Client::new()
        .get(format!("{}/.well-known/openid-configuration", generic()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        d.get("introspection_endpoint").is_none(),
        "SIWX_GENERIC_HOST must be a generic-mode server: {d}"
    );
    assert_eq!(d["backchannel_logout_supported"], true);
    assert_eq!(d["backchannel_logout_session_supported"], true);
}

#[tokio::test]
#[ignore = "needs a generic-mode siwx-oidc and the synapse mock"]
async fn revoking_a_refresh_token_sends_the_rp_a_verifiable_logout_token() {
    let c = Client::new();
    let rp = rp_name("revoke");
    let client_id = register_ok(&c, &rp_uri(&rp)).await;
    let s = sign_in(&c, &client_id).await;
    assert!(
        rp_received(&c, &rp).await.is_empty(),
        "nothing before the deletion"
    );
    revoke(&c, &s).await;
    let got = wait_for(&c, &rp, 1, DELIVERY_BOUND).await;
    assert_eq!(
        got.len(),
        1,
        "one logout token within {DELIVERY_BOUND:?}: {got:?}"
    );
    assert_valid_logout_token(&c, &got[0], &s).await;
}

#[tokio::test]
#[ignore = "needs a generic-mode siwx-oidc and the synapse mock"]
async fn end_session_sends_a_logout_token_for_the_grant_it_ends() {
    let c = Client::new();
    let rp = rp_name("endsession");
    let client_id = register_ok(&c, &rp_uri(&rp)).await;
    let ended = sign_in(&c, &client_id).await;
    let kept = sign_in(&c, &client_id).await;
    let r = no_redirect()
        .get(format!(
            "{}/end_session?id_token_hint={}",
            generic(),
            ended.id_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "the signed-out page");
    let got = wait_for(&c, &rp, 1, DELIVERY_BOUND).await;
    assert_eq!(got.len(), 1, "one logout token within {DELIVERY_BOUND:?}");
    assert_valid_logout_token(&c, &got[0], &ended).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        rp_received(&c, &rp).await.len(),
        1,
        "the other session is not logged out"
    );
    revoke(&c, &kept).await;
    let got = wait_for(&c, &rp, 2, DELIVERY_BOUND).await;
    assert_eq!(got.len(), 2);
    assert_valid_logout_token(&c, &got[1], &kept).await;
}

/// The outbox entries queued for `client_id`, read from the generic server's
/// Redis.
async fn queued_for(db: &siwx_oidc::db::RedisClient, client_id: &str) -> usize {
    db.pending_logout_entries()
        .await
        .expect("read the outbox")
        .iter()
        .filter(|(entry, _)| entry.client_id == client_id)
        .count()
}

/// Five attempts, then the entry is gone from the outbox. Waiting out a
/// sixth attempt would take 32 s, so the drop is read from the outbox itself
/// (`E2E_GENERIC_REDIS_URL`): the entry is there from the revocation on, and
/// gone right after the last attempt's answer, where a build that never drops
/// would have re-queued it.
#[tokio::test]
#[ignore = "needs a generic-mode siwx-oidc and the synapse mock"]
async fn a_failing_rp_is_retried_a_bounded_number_of_times_then_dropped() {
    let c = Client::new();
    let outbox = match std::env::var("E2E_GENERIC_REDIS_URL") {
        Ok(url) => Some(
            siwx_oidc::db::RedisClient::new(&url.parse().unwrap())
                .await
                .unwrap(),
        ),
        Err(_) => {
            assert!(
                !strict_skips(),
                "E2E_GENERIC_REDIS_URL is unset; E2E_STRICT_SKIPS=1 forbids skipping the outbox check"
            );
            eprintln!("SKIP outbox check: E2E_GENERIC_REDIS_URL unset");
            None
        }
    };
    let rp = rp_name("failing");
    rp_mode(&c, &rp, "500").await;
    let client_id = register_ok(&c, &rp_uri(&rp)).await;
    let s = sign_in(&c, &client_id).await;
    revoke(&c, &s).await;
    if let Some(db) = &outbox {
        assert_eq!(
            queued_for(db, &client_id).await,
            1,
            "the revocation queued one entry (the outbox read is the right one)"
        );
    }
    // 2 + 4 + 8 + 16 s of backoff between five attempts, plus the polls.
    let got = wait_for(&c, &rp, MAX_ATTEMPTS, Duration::from_secs(50)).await;
    assert_eq!(got.len(), MAX_ATTEMPTS, "every attempt reached the RP");
    for delivery in &got {
        assert_valid_logout_token(&c, delivery, &s).await;
    }
    if let Some(db) = &outbox {
        let start = Instant::now();
        while queued_for(db, &client_id).await > 0 && start.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            queued_for(db, &client_id).await,
            0,
            "the entry is dropped after the last attempt, never re-queued"
        );
    }
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(
        rp_received(&c, &rp).await.len(),
        MAX_ATTEMPTS,
        "dropped after the last attempt, never retried again"
    );
}

#[tokio::test]
#[ignore = "needs a generic-mode siwx-oidc and the synapse mock"]
async fn a_uri_on_a_refused_address_is_refused_at_registration_and_never_delivered_to() {
    let c = Client::new();
    let mock_port = reqwest::Url::parse(&mock())
        .unwrap()
        .port_or_known_default()
        .unwrap();
    let rp = rp_name("refused");
    // `localhost` is allowlisted; the same stub by its address is not.
    let by_address = format!("http://127.0.0.1:{mock_port}/__rp/{rp}/backchannel_logout");
    for uri in [
        by_address.as_str(),
        "https://127.0.0.1/bcl",
        "https://[::1]/bcl",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/bcl",
        "http://192.0.2.10/bcl",
    ] {
        let r = register(&c, uri).await;
        assert_eq!(
            r.status(),
            StatusCode::BAD_REQUEST,
            "{uri} is refused at registration"
        );
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["error"], "invalid_client_metadata", "{uri}");
    }

    // Delivery checks again: a client stored with that URI (as a registration
    // under another allowlist would have) is never delivered to.
    let Ok(redis_url) = std::env::var("E2E_GENERIC_REDIS_URL") else {
        assert!(
            !strict_skips(),
            "E2E_GENERIC_REDIS_URL is unset; E2E_STRICT_SKIPS=1 forbids skipping the delivery check"
        );
        eprintln!("SKIP delivery-time check: E2E_GENERIC_REDIS_URL unset");
        return;
    };
    use siwx_oidc::db::DBClient;
    let db = siwx_oidc::db::RedisClient::new(&redis_url.parse().unwrap())
        .await
        .unwrap();
    let client_id = format!("seeded-{rp}");
    let metadata: siwx_oidc::db::SiwxClientMetadata = serde_json::from_value(json!({
        "redirect_uris": [format!("{}/callback", generic())],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "backchannel_logout_uri": by_address,
    }))
    .unwrap();
    db.set_client(
        client_id.clone(),
        siwx_oidc::db::ClientEntry::new("unused", metadata, None),
    )
    .await
    .unwrap();
    let control = rp_name("control");
    let control_id = register_ok(&c, &rp_uri(&control)).await;

    let seeded = sign_in(&c, &client_id).await;
    revoke(&c, &seeded).await;
    let controlled = sign_in(&c, &control_id).await;
    revoke(&c, &controlled).await;
    let got = wait_for(&c, &control, 1, DELIVERY_BOUND).await;
    assert_eq!(
        got.len(),
        1,
        "the control RP on the allowlisted host is delivered to"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        rp_received(&c, &rp).await.is_empty(),
        "a URI on a loopback address is never connected to"
    );
}
