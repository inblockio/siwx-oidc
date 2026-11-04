//! Resource indicators (RFC 8707) and JWT access tokens (RFC 9068) on the
//! wire, through the whole wallet code flow: a dynamically registered client
//! asks `/authorize` for the configured resource `mcpe2e`, signs in, exchanges
//! the code, and holds a JWT for that resource that verifies against `/jwk`;
//! the token endpoint refuses the code for another resource; a refresh yields
//! a new JWT for the same resource; and an ordinary request still gets an
//! opaque token. The resource is `SIWXOIDC_RESOURCES__MCPE2E` in `e2e/env.sh`
//! and the CI job.
//!
//! Targets the MOCK stack brought up by `e2e/up.sh`. Run single-threaded with
//! the stack up:
//!   bash e2e/up.sh
//!   cargo test --test e2e_resource_binding -- --ignored --test-threads=1 --nocapture

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use p256::ecdsa::signature::Verifier;
use rand::rngs::OsRng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

/// The resource `e2e/env.sh` configures, byte for byte.
const RESOURCE: &str = "http://mcp.test/mcp";

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

struct Wallet {
    key: SigningKey,
    address: String,
    did: String,
}

fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex = hex::encode(addr);
    let hash = Keccak256::digest(hex.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex.chars().enumerate() {
        let nibble = (hash[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn new_wallet() -> Wallet {
    let key = SigningKey::random(&mut OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    let address = eip55_checksum(&addr);
    let did = format!("did:pkh:eip155:1:{address}");
    Wallet { key, address, did }
}

fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let digest = Keccak256::digest(prefixed.as_bytes());
    let (sig, rid): (Signature, RecoveryId) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(27 + rid.to_byte());
    format!("0x{}", hex::encode(bytes))
}

fn pkce_pair() -> (String, String) {
    use rand::Rng;
    let verifier: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
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
    redirect_uri: String,
}

/// A public client that may refresh, as an MCP client registers.
async fn register_client(c: &Client, base: &str) -> RegisteredClient {
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
        redirect_uri,
    }
}

fn header_value(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("{name} header"))
        .to_str()
        .unwrap()
        .to_string()
}

/// `/authorize` for `rc`, with or without a resource. On a 303 to the login
/// page, returns the session cookie, the nonce and the domain; on a 303 back
/// to the client, the query it carries.
enum Authorized {
    LoginPage {
        session_cookie: String,
        nonce: String,
        domain: String,
    },
    BackToClient(HashMap<String, String>),
}

async fn authorize(
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    challenge: &str,
    scope: &str,
    resource: Option<&str>,
) -> Authorized {
    let mut url = format!(
        "{base}/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code&state=rs&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&rc.client_id),
        urlencoding::encode(&rc.redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(challenge),
    );
    if let Some(resource) = resource {
        url.push_str(&format!("&resource={}", urlencoding::encode(resource)));
    }
    let resp = nrc.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize 303");
    let location = header_value(&resp, "location");
    if location.starts_with(&rc.redirect_uri) {
        return Authorized::BackToClient(parse_query(&location));
    }
    let session_cookie = header_value(&resp, "set-cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let q = parse_query(&location);
    Authorized::LoginPage {
        session_cookie,
        nonce: q["nonce"].clone(),
        domain: q["domain"].clone(),
    }
}

fn login_message(w: &Wallet, base: &str, domain: &str, nonce: &str, resource: &str) -> String {
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

/// Sign in with the wallet and return the code.
async fn sign_in(
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    w: &Wallet,
    session_cookie: &str,
    nonce: &str,
    domain: &str,
) -> String {
    let message = login_message(w, base, domain, nonce, &rc.redirect_uri);
    let signature = eip191_sign(&w.key, &message);
    let siwx =
        serde_json::to_string(&json!({ "did": w.did, "message": message, "signature": signature }))
            .unwrap();
    let resp = nrc
        .get(format!("{base}/sign_in"))
        .header(
            "cookie",
            format!("{session_cookie}; siwx={}", urlencoding::encode(&siwx)),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "sign_in 303");
    parse_query(&header_value(&resp, "location"))
        .get("code")
        .expect("sign_in carries the code")
        .clone()
}

async fn code_flow(
    nrc: &Client,
    base: &str,
    rc: &RegisteredClient,
    w: &Wallet,
    scope: &str,
    resource: Option<&str>,
) -> (String, String) {
    let (verifier, challenge) = pkce_pair();
    let Authorized::LoginPage {
        session_cookie,
        nonce,
        domain,
    } = authorize(nrc, base, rc, &challenge, scope, resource).await
    else {
        panic!("authorize must show the login page");
    };
    let code = sign_in(nrc, base, rc, w, &session_cookie, &nonce, &domain).await;
    (code, verifier)
}

async fn exchange(
    c: &Client,
    base: &str,
    rc: &RegisteredClient,
    code: &str,
    verifier: &str,
    resource: Option<&str>,
) -> (StatusCode, Value) {
    let mut form = vec![
        ("code", code.to_string()),
        ("client_id", rc.client_id.clone()),
        ("grant_type", "authorization_code".to_string()),
        ("code_verifier", verifier.to_string()),
    ];
    if let Some(resource) = resource {
        form.push(("resource", resource.to_string()));
    }
    let resp = c
        .post(format!("{base}/token"))
        .form(&form)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap())
}

async fn refresh(c: &Client, base: &str, rc: &RegisteredClient, rt: &str) -> Value {
    let resp = c
        .post(format!("{base}/token"))
        .form(&[
            ("refresh_token", rt),
            ("client_id", rc.client_id.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "refresh");
    resp.json().await.unwrap()
}

fn segment(token: &str, i: usize) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(i).expect("a compact JWS"))
            .unwrap(),
    )
    .unwrap()
}

/// The published key with the token's `kid`.
async fn published_key(c: &Client, base: &str, kid: &str) -> p256::ecdsa::VerifyingKey {
    let jwks: Value = c
        .get(format!("{base}/jwk"))
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
        .find(|k| k["kid"] == kid)
        .unwrap_or_else(|| panic!("no published key has kid {kid}"));
    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
    let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
    let point = p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap()
}

/// The token is an RFC 9068 JWT that verifies against `/jwk`; its claims.
async fn verified_claims(c: &Client, base: &str, token: &str) -> Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "a compact JWS, not an opaque token: {token}"
    );
    let header = segment(token, 0);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    let key = published_key(c, base, header["kid"].as_str().unwrap()).await;
    let raw = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    assert_eq!(raw.len(), 64, "raw r||s");
    let signature = p256::ecdsa::Signature::from_slice(&raw).unwrap();
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("the token verifies against the published key");
    segment(token, 1)
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_request_for_the_resource_gets_a_jwt_for_it_and_refreshes_into_another() {
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;

    // Discovery lists the resource's scopes.
    let discovery: Value = c
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let scopes = discovery["scopes_supported"].as_array().unwrap();
    assert!(scopes.iter().any(|s| s == "aqua:read"), "{scopes:?}");

    // No openid needed; openid and a foreign scope asked for are dropped.
    let (code, verifier) = code_flow(
        &nrc,
        &base,
        &rc,
        &w,
        "openid aqua:write aqua:read offline_access",
        Some(RESOURCE),
    )
    .await;
    let (status, body) = exchange(&c, &base, &rc, &code, &verifier, Some(RESOURCE)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("id_token").is_none(),
        "no ID token for a resource: {body}"
    );
    // RFC 6749 section 5.1: the token type is case-insensitive (this server writes `bearer`).
    assert!(
        body["token_type"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case("bearer"),
        "{body}"
    );
    assert_eq!(body["scope"], "aqua:read aqua:write offline_access");
    assert_eq!(body["expires_in"], 300);
    let claims = verified_claims(&c, &base, body["access_token"].as_str().unwrap()).await;
    let issuer = discovery["issuer"].as_str().unwrap();
    assert_eq!(claims["iss"], issuer);
    assert_eq!(claims["sub"], w.did, "the DID, exact case");
    assert_eq!(claims["aud"], RESOURCE);
    assert_eq!(claims["client_id"], rc.client_id);
    assert_eq!(claims["scope"], "aqua:read aqua:write offline_access");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        300
    );

    // The JWT is no bearer credential of this provider's: userinfo refuses it.
    let userinfo = c
        .get(format!("{base}/userinfo"))
        .bearer_auth(body["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(userinfo.status(), StatusCode::UNAUTHORIZED);

    // A refresh: a new JWT for the same resource, a rotated refresh token.
    let refreshed = refresh(&c, &base, &rc, body["refresh_token"].as_str().unwrap()).await;
    let again = verified_claims(&c, &base, refreshed["access_token"].as_str().unwrap()).await;
    assert_eq!(again["aud"], RESOURCE);
    assert_eq!(again["sub"], w.did);
    assert_eq!(again["scope"], "aqua:read aqua:write offline_access");
    assert_ne!(again["jti"], claims["jti"]);
    assert_ne!(refreshed["refresh_token"], body["refresh_token"]);
    assert!(refreshed.get("id_token").is_none());
}

#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn a_code_for_the_resource_is_refused_for_another_and_an_unknown_resource_is_invalid_target()
{
    let base = oidc();
    let nrc = no_redirect_client();
    let c = Client::new();
    let w = new_wallet();
    let rc = register_client(&c, &base).await;

    // /authorize: an unconfigured resource goes back to the client.
    let (_, challenge) = pkce_pair();
    let Authorized::BackToClient(q) = authorize(
        &nrc,
        &base,
        &rc,
        &challenge,
        "aqua:read",
        Some("http://other.test/mcp"),
    )
    .await
    else {
        panic!("an unknown resource never reaches the login page");
    };
    assert_eq!(q["error"], "invalid_target");
    assert_eq!(q["state"], "rs");
    // /authorize: none of the resource's scopes asked for.
    let Authorized::BackToClient(q) =
        authorize(&nrc, &base, &rc, &challenge, "openid", Some(RESOURCE)).await
    else {
        panic!("nothing to issue a token for");
    };
    assert_eq!(q["error"], "invalid_scope");

    // /token: the code's resource or none, never another.
    let (code, verifier) = code_flow(&nrc, &base, &rc, &w, "aqua:read", Some(RESOURCE)).await;
    let (status, body) = exchange(
        &c,
        &base,
        &rc,
        &code,
        &verifier,
        Some("http://other.test/mcp"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // An ordinary request: an opaque token and an ID token, as before, and a
    // resource named at /token for it is refused.
    let (code, verifier) = code_flow(&nrc, &base, &rc, &w, "openid", None).await;
    let (status, body) = exchange(&c, &base, &rc, &code, &verifier, Some(RESOURCE)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
    let (code, verifier) = code_flow(&nrc, &base, &rc, &w, "openid", None).await;
    let (status, body) = exchange(&c, &base, &rc, &code, &verifier, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["id_token"].is_string());
    assert!(
        body["access_token"].as_str().unwrap().starts_with("mat_"),
        "opaque: {}",
        body["access_token"]
    );
}
