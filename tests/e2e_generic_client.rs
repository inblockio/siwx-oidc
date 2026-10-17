//! Mock-stack checks for a generic-class client, the kind a mail client is, against the
//! Matrix-mode server: what it is granted, what userinfo tells it, and that none of it
//! opens a Matrix session. The sign-in is the headless client's
//! `authenticate_with_scope_using`, so the wire is the one a real caller meets.
//!
//! Needs the stack from `e2e/up.sh`, which configures the generic static client
//! `maile2e` and the mail domain on the Matrix-mode server (the CI job sets them on that
//! step only):
//!   bash e2e/up.sh
//!   source e2e/env.sh && SIWEOIDC_HOST="$SIWEOIDC_BASE_URL" \
//!     cargo test --test e2e_generic_client -- --ignored --test-threads=1
//!
//! `no_credential_a_generic_client_holds_is_stored_in_the_clear` also searches the stack's Redis
//! (`E2E_REDIS_URL`, else `SIWXOIDC_REDIS_URL`, else `SIWEOIDC_REDIS_URL`, which `env.sh` sets).
//! Without one it skips loudly, and fails under `E2E_STRICT_SKIPS=1`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siwx_oidc::mxid::localpart_for;
use siwx_oidc_auth::{authenticate, authenticate_with_scope_using, refresh, AuthTokens, SiwxKey};
use std::collections::HashMap;
use url::Url;

const MAIL_CLIENT: &str = "maile2e";
/// A Matrix-class static client of the same stack, the control for every refusal below.
const MATRIX_CLIENT: &str = "e2estatic";
const REDIRECT_URI: &str = "http://localhost:0/callback";
const MAIL_SCOPE: &str = "openid io.inblock.mail";
const MAIL_REFRESH_SCOPE: &str = "openid io.inblock.mail offline_access";

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST")
        .or_else(|_| std::env::var("SIWEOIDC_BASE_URL"))
        .unwrap_or_else(|_| "http://localhost:18080".to_string())
}

fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}

fn shared_secret() -> String {
    std::env::var("MAS_SHARED_SECRET")
        .or_else(|_| std::env::var("SIWXOIDC_MAS_SHARED_SECRET"))
        .or_else(|_| std::env::var("SIWEOIDC_MAS_SHARED_SECRET"))
        .unwrap_or_else(|_| "testsecret".to_string())
}

fn mail_domain() -> String {
    std::env::var("SIWXOIDC_MAIL_DOMAIN").unwrap_or_else(|_| "matrix.test".to_string())
}

fn server_name() -> String {
    std::env::var("SIWXOIDC_MATRIX_SERVER_NAME")
        .or_else(|_| std::env::var("SIWEOIDC_MATRIX_SERVER_NAME"))
        .unwrap_or_else(|_| "matrix.test".to_string())
}

/// A client that follows no redirect, the kind the headless client requires.
fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

/// Sign `key` in as the mail client for exactly `scope`.
async fn mail_tokens(key: &SiwxKey, scope: &str) -> AuthTokens {
    authenticate_with_scope_using(&client(), &oidc(), MAIL_CLIENT, REDIRECT_URI, key, scope)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "sign in as {MAIL_CLIENT} for `{scope}` (is the stack from e2e/up.sh, with \
                 {MAIL_CLIENT} configured?): {e:#}"
            )
        })
}

/// Sign `key` in as the Matrix-class client: a device, the Matrix scope.
async fn matrix_tokens(key: &SiwxKey) -> AuthTokens {
    authenticate(&oidc(), MATRIX_CLIENT, REDIRECT_URI, key)
        .await
        .expect("sign in as the Matrix-class client")
}

async fn userinfo(access_token: &str) -> Response {
    client()
        .get(format!("{}/userinfo", oidc()))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap()
}

async fn introspect(token: &str) -> Value {
    let resp = client()
        .post(format!("{}/oauth2/introspect", oidc()))
        .bearer_auth(shared_secret())
        .form(&[("token", token), ("token_type_hint", "access_token")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "introspection answers 200");
    resp.json().await.unwrap()
}

async fn mock_whoami(access_token: &str) -> Response {
    client()
        .get(format!("{}/_matrix/client/v3/account/whoami", mock()))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap()
}

/// How many times `name` is a key anywhere inside `value`.
fn keys_named(value: &Value, name: &str) -> usize {
    match value {
        Value::Object(members) => members
            .iter()
            .map(|(key, inner)| {
                usize::from(key.eq_ignore_ascii_case(name)) + keys_named(inner, name)
            })
            .sum(),
        Value::Array(items) => items.iter().map(|item| keys_named(item, name)).sum(),
        _ => 0,
    }
}

async fn assert_matrix_refusal(resp: Response, error: &str, what: &str) {
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{what}");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "errcode": "M_UNKNOWN_TOKEN", "error": error }),
        "{what}"
    );
}

/// What one authorization code flow driven by hand left in the client's hands.
struct ByHand {
    did: String,
    /// The value of the `session` cookie that `/authorize` set.
    session_id: String,
    code: String,
    verifier: String,
    /// The `/token` response.
    token: Value,
}

/// One authorization code flow driven by hand, because the headless client does not hand back
/// the scope a server names, the code or the session cookie.
async fn by_hand(scope: &str) -> ByHand {
    let c = client();
    let base = oidc();
    let seed: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&seed);
    let did = SiwxKey::ed25519_from_hex(&hex::encode(seed)).unwrap().did();
    let verifier: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let authorize = c
        .get(format!("{base}/authorize"))
        .query(&[
            ("client_id", MAIL_CLIENT),
            ("redirect_uri", REDIRECT_URI),
            ("scope", scope),
            ("response_type", "code"),
            ("state", "by-hand"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER, "GET /authorize");
    let session = authorize
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("session="))
        .and_then(|value| value.split(';').next())
        .expect("a session cookie")
        .to_string();
    let login = Url::parse(&base)
        .unwrap()
        .join(authorize.headers()["location"].to_str().unwrap())
        .unwrap();
    let bound: HashMap<String, String> = login.query_pairs().into_owned().collect();

    let domain = Url::parse(&base).unwrap().host_str().unwrap().to_string();
    let z_encoded = did.strip_prefix("did:key:").unwrap();
    let issued_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let message = format!(
        "{domain} wants you to sign in with your Ed25519 key:\n{z_encoded}\n\n\
         You are signing in to {domain}.\n\n\
         URI: {REDIRECT_URI}\nVersion: 1\nNonce: {nonce}\nIssued At: {issued_at}\n\
         Resources:\n- {REDIRECT_URI}",
        nonce = bound["nonce"],
    );
    let signature = hex::encode(signing_key.sign(message.as_bytes()).to_bytes());
    let siwx = urlencoding::encode(
        &json!({ "did": did, "message": message, "signature": signature }).to_string(),
    )
    .into_owned();

    let signed_in = c
        .get(format!("{base}/sign_in"))
        .query(&[
            ("redirect_uri", bound["redirect_uri"].as_str()),
            ("state", bound["state"].as_str()),
            ("client_id", bound["client_id"].as_str()),
        ])
        .header("cookie", format!("{session}; siwx={siwx}"))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER, "GET /sign_in");
    let code = Url::parse(signed_in.headers()["location"].to_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.into_owned())
        .expect("a code in the redirect");

    let token = c
        .post(format!("{base}/token"))
        .form(&[
            ("code", code.as_str()),
            ("client_id", MAIL_CLIENT),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK, "POST /token");
    ByHand {
        did,
        session_id: session.trim_start_matches("session=").to_string(),
        code,
        verifier,
        token: token.json().await.unwrap(),
    }
}

/// The `/token` response to one flow driven by hand.
async fn code_exchange(scope: &str) -> Value {
    by_hand(scope).await.token
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn the_mailbox_claim_is_the_opaque_localpart_at_the_mail_domain() {
    let key = SiwxKey::generate_ed25519();
    let did = key.did();
    let tokens = mail_tokens(&key, MAIL_SCOPE).await;
    assert_eq!(tokens.did, did);

    let resp = userinfo(&tokens.access_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let claims: Value = resp.json().await.unwrap();

    let localpart = localpart_for(&did);
    assert!(
        localpart.len() == 16
            && localpart
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()),
        "the localpart is 16 lowercase base36 characters: {localpart}"
    );
    assert_eq!(
        claims["io.inblock.mailbox"],
        format!("{localpart}@{}", mail_domain())
    );
    assert_eq!(claims["sub"], did);
    assert_eq!(claims["preferred_username"], did);
    assert_eq!(claims["aud"], json!([MAIL_CLIENT]));
    assert_eq!(
        claims["io.inblock.mxid"],
        format!("@{localpart}:{}", server_name())
    );

    // The form-encoded POST form of the request answers the same claims.
    let posted: Value = client()
        .post(format!("{}/userinfo", oidc()))
        .form(&[("access_token", tokens.access_token.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(posted["io.inblock.mailbox"], claims["io.inblock.mailbox"]);
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn the_mailbox_claim_needs_the_mail_scope() {
    let with = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_SCOPE).await;
    let without = mail_tokens(&SiwxKey::generate_ed25519(), "openid").await;

    let granted: Value = userinfo(&with.access_token).await.json().await.unwrap();
    assert!(granted["io.inblock.mailbox"].is_string());

    let resp = userinfo(&without.access_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let claims: Value = resp.json().await.unwrap();
    assert_eq!(claims["sub"], without.did);
    assert_eq!(
        keys_named(&claims, "io.inblock.mailbox"),
        0,
        "no mail scope, no mailbox claim (the member is omitted, never null): {claims}"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn userinfo_never_carries_an_email_claim() {
    let tokens = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_REFRESH_SCOPE).await;
    let claims: Value = userinfo(&tokens.access_token).await.json().await.unwrap();
    assert!(claims["io.inblock.mailbox"].is_string(), "{claims}");
    for name in ["email", "email_verified"] {
        assert_eq!(keys_named(&claims, name), 0, "`{name}` in {claims}");
    }
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn the_grant_names_no_matrix_scope_whatever_is_requested() {
    let asked = "openid io.inblock.mail urn:matrix:client:api:* urn:synapse:admin:*";
    let response = code_exchange(asked).await;
    assert_eq!(
        response["scope"], MAIL_SCOPE,
        "the scopes the client may not have are dropped and the response says so: {response}"
    );
    assert!(
        response.get("refresh_token").is_none(),
        "no refresh token without offline_access: {response}"
    );

    let asked = "openid io.inblock.mail offline_access urn:matrix:client:api:*";
    let response = code_exchange(asked).await;
    assert_eq!(response["scope"], MAIL_REFRESH_SCOPE, "{response}");
    assert!(response["refresh_token"].is_string(), "{response}");
    assert!(
        !response.to_string().contains("urn:matrix:"),
        "the response names a Matrix scope: {response}"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn a_request_that_grants_no_openid_is_refused_at_authorize() {
    let authorize = |client_id: &'static str| async move {
        client()
            .get(format!("{}/authorize", oidc()))
            .query(&[
                ("client_id", client_id),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "urn:matrix:client:api:*"),
                ("response_type", "code"),
                ("state", "no-openid"),
                (
                    "code_challenge",
                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap()
    };

    let refused = authorize(MAIL_CLIENT).await;
    assert_eq!(refused.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(refused.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(location.as_str().split('?').next(), Some(REDIRECT_URI));
    let returned: HashMap<String, String> = location.query_pairs().into_owned().collect();
    assert_eq!(returned["error"], "invalid_scope");
    assert_eq!(returned["state"], "no-openid");

    // The same request from a Matrix-class client goes on to the login page.
    let allowed = authorize(MATRIX_CLIENT).await;
    assert_eq!(allowed.status(), StatusCode::SEE_OTHER);
    let location = allowed.headers()["location"].to_str().unwrap().to_string();
    assert!(
        !location.starts_with(REDIRECT_URI) && !location.contains("error=invalid_scope"),
        "a Matrix-class client is not refused: {location}"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn a_mail_sign_in_provisions_the_account_and_creates_no_device() {
    let key = SiwxKey::generate_ed25519();
    mail_tokens(&key, MAIL_SCOPE).await;
    let localpart = localpart_for(&key.did());
    let control = SiwxKey::generate_ed25519();
    matrix_tokens(&control).await;

    let state: Value = client()
        .get(format!("{}/__state", mock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let devices = state["devices"].to_string();
    assert!(
        state["existing_users"].to_string().contains(&localpart),
        "the account was provisioned: {}",
        state["existing_users"]
    );
    assert!(
        !devices.contains(&localpart),
        "a mail sign-in creates no Matrix device"
    );
    assert!(
        devices.contains(&localpart_for(&control.did())),
        "the control: a Matrix-class sign-in creates one, and the mock shows it"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn introspection_answers_inactive_for_a_mail_token_and_active_for_a_matrix_one() {
    let mail = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_SCOPE).await;
    assert_eq!(
        introspect(&mail.access_token).await,
        json!({ "active": false })
    );

    let matrix = matrix_tokens(&SiwxKey::generate_ed25519()).await;
    assert_eq!(
        introspect(&matrix.access_token).await["active"],
        true,
        "the control: a Matrix-class token is active at the same endpoint"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn the_matrix_routes_refuse_a_mail_token_and_tear_nothing_down() {
    let tokens = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_REFRESH_SCOPE).await;
    let bearer = tokens.access_token.as_str();
    let refused = "Invalid or missing access token";
    let c = client();
    let matrix = |path: &str| format!("{}/_matrix/client/v3/{path}", oidc());

    assert_matrix_refusal(
        c.post(matrix("logout"))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap(),
        refused,
        "logout",
    )
    .await;
    assert_matrix_refusal(
        c.post(matrix("logout/all"))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap(),
        refused,
        "logout/all",
    )
    .await;
    assert_matrix_refusal(
        c.delete(matrix("devices/SOMEDEVICE"))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap(),
        refused,
        "DELETE devices/{id}",
    )
    .await;
    assert_matrix_refusal(
        c.post(matrix("delete_devices"))
            .bearer_auth(bearer)
            .json(&json!({ "devices": ["SOMEDEVICE"] }))
            .send()
            .await
            .unwrap(),
        refused,
        "delete_devices",
    )
    .await;

    // The homeserver asks siwx-oidc about the token and is told it is not one of its own.
    let whoami = mock_whoami(bearer).await;
    assert_eq!(whoami.status(), StatusCode::UNAUTHORIZED, "whoami");
    let whoami: Value = whoami.json().await.unwrap();
    assert_eq!(whoami["errcode"], "M_UNKNOWN_TOKEN", "whoami: {whoami}");
    let matrix_token = matrix_tokens(&SiwxKey::generate_ed25519()).await;
    assert_eq!(
        mock_whoami(&matrix_token.access_token).await.status(),
        StatusCode::OK,
        "the control: a Matrix-class token passes the same whoami"
    );
    assert_eq!(
        c.post(matrix("logout"))
            .bearer_auth(&matrix_token.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "the control: the logout route accepts a Matrix-class token"
    );

    // Refusing is not tearing down: the grant is untouched.
    let claims: Value = userinfo(bearer).await.json().await.unwrap();
    assert!(claims["io.inblock.mailbox"].is_string(), "{claims}");
    let rotated = refresh(
        &oidc(),
        MAIL_CLIENT,
        tokens.refresh_token.as_deref().expect("a refresh token"),
        &tokens.did,
    )
    .await
    .expect("the grant still refreshes at /token");
    assert_ne!(rotated.access_token, tokens.access_token);
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn the_matrix_refresh_endpoint_refuses_a_mail_refresh_token_which_still_refreshes_at_token() {
    let tokens = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_REFRESH_SCOPE).await;
    let refresh_token = tokens.refresh_token.clone().expect("offline_access");

    let resp = client()
        .post(format!("{}/_matrix/client/v3/refresh", oidc()))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    assert_matrix_refusal(resp, "Invalid refresh token", "Matrix refresh").await;

    let rotated = refresh(&oidc(), MAIL_CLIENT, &refresh_token, &tokens.did)
        .await
        .expect("the refusal left the token usable at /token");
    assert_ne!(
        rotated.refresh_token.as_deref(),
        Some(refresh_token.as_str())
    );
    let claims: Value = userinfo(&rotated.access_token).await.json().await.unwrap();
    assert_eq!(
        claims["io.inblock.mailbox"],
        format!("{}@{}", localpart_for(&tokens.did), mail_domain()),
        "the rotated access token carries the mailbox claim too"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn a_mail_refresh_token_is_issued_only_for_offline_access() {
    let without = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_SCOPE).await;
    assert!(
        without.refresh_token.is_none(),
        "no offline_access, no refresh token"
    );
    let with = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_REFRESH_SCOPE).await;
    assert!(
        with.refresh_token.is_some(),
        "offline_access, a refresh token"
    );
}

#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn userinfo_answers_an_unusable_token_with_the_invalid_token_challenge() {
    let tokens = mail_tokens(&SiwxKey::generate_ed25519(), MAIL_REFRESH_SCOPE).await;
    let refresh_token = tokens.refresh_token.clone().expect("offline_access");

    let usable = userinfo(&tokens.access_token).await;
    assert_eq!(
        usable.status(),
        StatusCode::OK,
        "the control: the access token is usable"
    );
    assert!(usable.headers().get("www-authenticate").is_none());

    for (what, bearer) in [
        ("an unknown token", "mat_not-a-token-this-server-issued"),
        ("a refresh token", refresh_token.as_str()),
    ] {
        let resp = userinfo(bearer).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{what}");
        let challenges: Vec<&str> = resp
            .headers()
            .get_all("www-authenticate")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            challenges,
            ["Bearer error=\"invalid_token\""],
            "{what}: exactly one challenge"
        );
        let content_type = resp.headers()["content-type"].to_str().unwrap().to_string();
        assert!(
            content_type.starts_with("text/plain"),
            "{what}: {content_type}"
        );
        assert_eq!(resp.text().await.unwrap(), "Unknown token.", "{what}");
    }

    // No token at all is a malformed request, not a failed credential.
    let resp = client()
        .get(format!("{}/userinfo", oidc()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("www-authenticate").is_none());
    assert_eq!(resp.text().await.unwrap(), "Missing access token.");
}

/// The secret `e2e/env.sh` and the CI job give their static clients.
const STATIC_CLIENT_SECRET: &str = "not-a-secret-e2e-fixture";

/// The stack's Redis, found the way the I1 scans of `e2e_race_teardown` find it.
fn stack_redis_url() -> Option<String> {
    ["E2E_REDIS_URL", "SIWXOIDC_REDIS_URL", "SIWEOIDC_REDIS_URL"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// Searches every key and every value of the selected database for each string in `ARGV` and
/// answers `{position} key {key}` or `{position} value of {key}` for each place one appears.
const FIND_HELD_STRINGS: &str = r#"
local hits = {}
local cursor = '0'
repeat
  local page = redis.call('SCAN', cursor, 'COUNT', 1000)
  cursor = page[1]
  for _, key in ipairs(page[2]) do
    local kind = redis.call('TYPE', key)['ok']
    local values = {}
    if kind == 'string' then values = { redis.call('GET', key) }
    elseif kind == 'hash' then values = redis.call('HGETALL', key)
    elseif kind == 'list' then values = redis.call('LRANGE', key, 0, -1)
    elseif kind == 'set' then values = redis.call('SMEMBERS', key)
    elseif kind == 'zset' then values = redis.call('ZRANGE', key, 0, -1)
    elseif kind ~= 'none' then error('a key of type ' .. kind .. ' is not searched') end
    for position, needle in ipairs(ARGV) do
      if string.find(key, needle, 1, true) then
        hits[#hits + 1] = position .. ' key ' .. key
      end
      for _, value in ipairs(values) do
        if type(value) == 'string' and string.find(value, needle, 1, true) then
          hits[#hits + 1] = position .. ' value of ' .. key
          break
        end
      end
    end
  end
until cursor == '0'
return hits
"#;

type StackRedis = bb8_redis::redis::aio::MultiplexedConnection;

async fn connect_to_the_stack_redis(url: &str) -> StackRedis {
    bb8_redis::redis::Client::open(url)
        .unwrap_or_else(|e| panic!("stack Redis URL: {e}"))
        .get_multiplexed_async_connection()
        .await
        .unwrap_or_else(|e| panic!("stack Redis at {url} is unreachable: {e}"))
}

/// Every place in any database of the Redis behind `conn` where one of `held` (label, string)
/// appears in a key or a value, one line per place.
async fn find_held_strings(conn: &mut StackRedis, held: &[(String, String)]) -> Vec<String> {
    use bb8_redis::redis;
    let (_, databases): (String, u32) = redis::cmd("CONFIG")
        .arg("GET")
        .arg("databases")
        .query_async(conn)
        .await
        .expect("CONFIG GET databases");
    let mut hits = Vec::new();
    for database in 0..databases {
        let _: () = redis::cmd("SELECT")
            .arg(database)
            .query_async(conn)
            .await
            .unwrap();
        let mut invocation = redis::cmd("EVAL");
        invocation.arg(FIND_HELD_STRINGS).arg(0);
        for (_, secret) in held {
            invocation.arg(secret.as_str());
        }
        let found: Vec<String> = invocation
            .query_async(conn)
            .await
            .unwrap_or_else(|e| panic!("searching database {database}: {e}"));
        for line in found {
            let (position, place) = line.split_once(' ').expect("a position and a place");
            let (label, _) = &held[position.parse::<usize>().unwrap() - 1];
            hits.push(format!("{label}: in the {place} (database {database})"));
        }
    }
    hits
}

/// Holds a token and every part of it that the store must not contain either.
fn hold_token(held: &mut Vec<(String, String)>, label: &str, token: &str) {
    held.push((label.to_string(), token.to_string()));
    if let Some((_, body)) = token.split_once('_') {
        held.push((format!("{label} without its prefix"), body.to_string()));
        if token.starts_with("mcr_") {
            if let Some((handle, secret)) = body.split_once('_') {
                held.push((format!("{label} handle"), handle.to_string()));
                held.push((format!("{label} secret part"), secret.to_string()));
            }
        }
    }
}

/// I1 for a generic-class client: after its sign-in, a refresh, the replay of the lost response,
/// userinfo and revocation, nothing it holds appears in any key or value of the stack's Redis,
/// in any database: not its login session id, code, PKCE verifier, ID token, access and refresh
/// tokens, nor the secret of its registration. The search is proved on planted strings, so an
/// empty result cannot come from a search that finds nothing.
#[tokio::test]
#[ignore = "requires the mock stack (e2e/up.sh)"]
async fn no_credential_a_generic_client_holds_is_stored_in_the_clear() {
    use bb8_redis::redis;
    let Some(url) = stack_redis_url() else {
        let marker = "E2E_SKIP: no_credential_a_generic_client_holds_is_stored_in_the_clear: no \
                      stack Redis URL (E2E_REDIS_URL, SIWXOIDC_REDIS_URL or SIWEOIDC_REDIS_URL); \
                      the keyspace was NOT searched";
        assert!(
            std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
            "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure"
        );
        eprintln!("{marker}");
        return;
    };

    let flow = by_hand(MAIL_REFRESH_SCOPE).await;
    let text = |name: &str| {
        flow.token[name]
            .as_str()
            .unwrap_or_else(|| panic!("the token response has `{name}`: {}", flow.token))
            .to_string()
    };
    let mut held: Vec<(String, String)> = vec![
        ("login session id".into(), flow.session_id.clone()),
        ("authorization code".into(), flow.code.clone()),
        ("PKCE verifier".into(), flow.verifier.clone()),
        ("ID token".into(), text("id_token")),
        ("client secret".into(), STATIC_CLIENT_SECRET.into()),
    ];
    let refresh_token = text("refresh_token");
    hold_token(&mut held, "sign-in access token", &text("access_token"));
    hold_token(&mut held, "sign-in refresh token", &refresh_token);

    let rotated = refresh(&oidc(), MAIL_CLIENT, &refresh_token, &flow.did)
        .await
        .expect("the refresh grant rotates");
    let rotated_refresh = rotated
        .refresh_token
        .clone()
        .expect("a rotated refresh token");
    hold_token(&mut held, "rotated access token", &rotated.access_token);
    hold_token(&mut held, "rotated refresh token", &rotated_refresh);
    let replayed = refresh(&oidc(), MAIL_CLIENT, &refresh_token, &flow.did)
        .await
        .expect("the previous token replays while its successor is unused");
    assert_eq!(
        replayed.access_token, rotated.access_token,
        "the replay of a lost response returns the same pair"
    );

    let mut conn = connect_to_the_stack_redis(&url).await;
    let live_access_key = format!(
        "at/{}",
        hex::encode(Sha256::digest(rotated.access_token.as_bytes()))
    );
    let live: bool = redis::cmd("EXISTS")
        .arg(&live_access_key)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        live,
        "positive control: {url} holds the digest key of the live access token \
         {live_access_key}; is this the stack's Redis?"
    );
    assert_eq!(
        find_held_strings(&mut conn, &held).await,
        Vec::<String>::new(),
        "after a refresh and a replay: client-held strings stored in the clear (I1)"
    );

    assert_eq!(
        userinfo(&rotated.access_token).await.status(),
        StatusCode::OK,
        "the rotated access token is usable"
    );
    let revoked = client()
        .post(format!("{}/oauth2/revoke", oidc()))
        .form(&[("token", rotated_refresh.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK, "revocation is always 200");
    assert_eq!(
        userinfo(&rotated.access_token).await.status(),
        StatusCode::UNAUTHORIZED,
        "the revoked grant's access token is dead"
    );
    assert_eq!(
        find_held_strings(&mut conn, &held).await,
        Vec::<String>::new(),
        "after userinfo and revocation: client-held strings stored in the clear (I1)"
    );

    let needle = format!("scan-canary-{}", rand::random::<u32>());
    let _: () = redis::cmd("SET")
        .arg("e2e:scan-canary:string")
        .arg(&needle)
        .query_async(&mut conn)
        .await
        .unwrap();
    let _: () = redis::cmd("HSET")
        .arg("e2e:scan-canary:hash")
        .arg("member")
        .arg(&needle)
        .query_async(&mut conn)
        .await
        .unwrap();
    let planted = find_held_strings(&mut conn, &[("canary".into(), needle)]).await;
    let _: () = redis::cmd("DEL")
        .arg("e2e:scan-canary:string")
        .arg("e2e:scan-canary:hash")
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        planted.len(),
        2,
        "the search finds a string planted in a string value and in a hash value: {planted:?}"
    );
}
