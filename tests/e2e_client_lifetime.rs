//! Mock-stack checks for client lifetimes: the static client from `default_clients`
//! carries no TTL and still authorizes, and a dynamic client is extended by its next use,
//! so neither expires while it is in use.
//!
//! Needs the stack from `e2e/up.sh`, which configures the static client `e2estatic`:
//!   bash e2e/up.sh
//!   source e2e/env.sh && SIWEOIDC_HOST="$SIWEOIDC_BASE_URL" \
//!     cargo test --test e2e_client_lifetime -- --ignored --test-threads=1

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siwx_oidc::db::RedisClient;
use url::Url;

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST")
        .or_else(|_| std::env::var("SIWEOIDC_BASE_URL"))
        .unwrap_or_else(|_| "http://localhost:18080".to_string())
}

fn redis_url() -> Url {
    let raw = std::env::var("SIWXOIDC_REDIS_URL")
        .or_else(|_| std::env::var("SIWEOIDC_REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    Url::parse(&raw).expect("a Redis URL")
}

async fn redis() -> RedisClient {
    RedisClient::new(&redis_url())
        .await
        .expect("the stack's Redis")
}

fn no_redirect_client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

fn pkce_challenge() -> String {
    let verifier: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `GET /authorize` for `client_id`; a registered client gets 303 to the login page.
async fn authorize_status(c: &Client, client_id: &str, redirect_uri: &str) -> StatusCode {
    let challenge = pkce_challenge();
    c.get(format!("{}/authorize", oidc()))
        .query(&[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "openid"),
            ("response_type", "code"),
            ("state", "lifetime"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .expect("GET /authorize")
        .status()
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn a_static_client_has_no_ttl_and_still_authorizes() {
    let db = redis().await;
    assert_eq!(
        db.ttl_raw("clients/e2estatic").await.unwrap(),
        -1,
        "the static client e2estatic must carry no TTL after start-up"
    );
    let c = no_redirect_client();
    assert_eq!(
        authorize_status(&c, "e2estatic", "http://localhost:0/callback").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        db.ttl_raw("clients/e2estatic").await.unwrap(),
        -1,
        "a use must not give a static client a TTL"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn a_dynamic_client_near_the_end_of_its_lifetime_is_extended_by_its_next_use() {
    let c = no_redirect_client();
    let redirect_uri = format!("{}/callback", oidc());
    let registration: Value = c
        .post(format!("{}/register", oidc()))
        .json(&json!({ "redirect_uris": [&redirect_uri], "token_endpoint_auth_method": "none" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = registration["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let db = redis().await;
    let key = format!("clients/{client_id}");
    // Simulate 29 days and 23 hours of age: one hour of lifetime left.
    db.expire_raw(&key, 3600).await.unwrap();

    assert_eq!(
        authorize_status(&c, &client_id, &redirect_uri).await,
        StatusCode::SEE_OTHER
    );

    let ttl = db.ttl_raw(&key).await.unwrap();
    assert!(
        ttl > 29 * 24 * 3600,
        "the use must restore the 30-day lifetime, got {ttl}s"
    );
    db.del_raw(&key).await.ok();
}
