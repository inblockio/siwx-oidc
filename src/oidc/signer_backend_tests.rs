//! The `socket` signing backend through the real request paths.
//!
//! An in-process `siwx-signer` service on a Unix socket signs here, so every
//! message these paths emit has also passed the signer's shape check: these
//! tests are the proof that the real emissions have the shape the signer
//! allows. The tokens verify against the JWKS the provider publishes
//! ([`jwks`]); with the signer stopped, the code exchange and signed userinfo
//! answer 503 and hand out nothing signed. Redis-backed: `token` and
//! `userinfo` go through the real grant store.

use super::client_binding_tests::{CHALLENGE, VERIFIER};
use super::*;
use crate::config::Config;
use crate::localpart::localpart_for;
use openidconnect::core::CoreIdTokenVerifier;
use openidconnect::{JsonWebKey, OAuth2TokenResponse};
use siwx_oidc::signing::socket::SocketSigner;
use siwx_oidc::test_support::TestSigner;

/// Mixed case: `sub` must come back exact.
const DID: &str = "did:key:zSignerBackendTestFixture";

fn nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Generic mode with the default `base_url`, which is the issuer a test signer
/// expects. No ENS: the DID is a `did:key`.
fn config() -> Config {
    Config {
        ens_api_url: None,
        eth_provider: None,
        ..Config::default()
    }
}

/// A public client, with a signed userinfo response when `signed`.
fn client(signed: bool) -> ClientEntry {
    let mut metadata = SiwxClientMetadata::new(
        vec![RedirectUrl::new("https://rp.example.org/cb".into()).unwrap()],
        LogoutClientMetadata::default(),
    )
    .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None));
    if signed {
        metadata = metadata
            .set_userinfo_signed_response_alg(Some(CoreJwsSigningAlgorithm::EcdsaP256Sha256));
    }
    ClientEntry::new("client-secret", metadata, None)
}

async fn store_client(db: &RedisClient, entry: ClientEntry) -> String {
    let client_id = format!("signer-{}", nonce());
    db.set_client(client_id.clone(), entry).await.unwrap();
    client_id
}

/// Store the code `sign_in` would have issued to `client_id` (with `nonce`)
/// and redeem it at the token endpoint with `signer`.
async fn exchange(
    db: &RedisClient,
    signer: &dyn ProviderSigner,
    client_id: &str,
    id_token_nonce: &str,
) -> Result<SiwxTokenResponse, CustomError> {
    let code = format!("code-{}", nonce());
    db.set_code(
        code.clone(),
        CodeEntry {
            exchange_count: 0,
            did: DID.to_string(),
            nonce: Some(Nonce::new(id_token_nonce.to_string())),
            client_id: client_id.to_string(),
            auth_time: Utc::now(),
            code_challenge: Some(CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            device_id: None,
            localpart: Some(localpart_for(DID)),
            scope: Some("openid".into()),
            client_class: Some(ClientClass::Matrix),
        },
    )
    .await
    .unwrap();
    token(
        TokenForm {
            code: Some(code),
            client_id: Some(client_id.to_string()),
            client_secret: None,
            grant_type: CoreGrantType::AuthorizationCode,
            code_verifier: Some(VERIFIER.to_string()),
            refresh_token: None,
            device_code: None,
        },
        ClientCredentials::default(),
        signer,
        &config(),
        db,
        None,
    )
    .await
}

async fn socket_signer(service: &TestSigner) -> SocketSigner {
    SocketSigner::connect(&service.socket, std::time::Duration::from_secs(2))
        .await
        .expect("the test signer answers its public key")
}

/// Requirement 1 and 2 at the token endpoint: the ID token the socket backend
/// signs carries the signer's `kid` and verifies, through openidconnect's own
/// verifier, against the JWKS this provider publishes for that backend.
#[tokio::test]
async fn an_id_token_from_the_socket_backend_verifies_with_the_published_jwks() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let key = EcdsaSigningKey::generate();
    let service = TestSigner::start(key.clone(), TestSigner::options());
    let signer = socket_signer(&service).await;
    assert_eq!(
        signer.kid(),
        key.kid(),
        "the client derives the signer's kid"
    );

    let client_id = store_client(&db, client(false)).await;
    let id_nonce = nonce();
    let response = exchange(&db, &signer, &client_id, &id_nonce)
        .await
        .expect("the socket backend signs the ID token");
    let id_token = response
        .extra_fields()
        .id_token()
        .expect("the exchange returns an ID token");

    let compact = id_token.to_string();
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(compact.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["kid"], signer.kid());
    assert_eq!(header["alg"], "ES256");

    let published = jwks(&signer, &[]).unwrap();
    assert_eq!(
        published.keys()[0].key_id().map(|k| k.as_str()),
        Some(key.kid()),
        "the JWKS publishes the signer's key under its kid"
    );
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(client_id.clone()),
        IssuerUrl::from_url(config().base_url),
        published,
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
    let claims = id_token
        .claims(&verifier, &Nonce::new(id_nonce))
        .expect("the ID token verifies against the published JWKS");
    assert_eq!(claims.subject().as_str(), DID);
    assert!(claims.access_token_hash().is_some(), "at_hash is set");
}

/// Requirement 4 at the token endpoint: with the signer down, the exchange
/// answers `ServiceUnavailable` (the token endpoint's retryable 503, see
/// `axum_lib`'s `TokenEndpointError`) and no token at all, while the same
/// exchange with the signer up succeeds.
#[tokio::test]
async fn with_the_signer_stopped_the_code_exchange_answers_503_and_no_token() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let service = TestSigner::start(EcdsaSigningKey::generate(), TestSigner::options());
    let signer = socket_signer(&service).await;
    let client_id = store_client(&db, client(false)).await;
    exchange(&db, &signer, &client_id, &nonce())
        .await
        .expect("the same exchange succeeds while the signer is up");

    service.stop();
    match exchange(&db, &signer, &client_id, &nonce()).await {
        Err(CustomError::ServiceUnavailable(msg)) => {
            assert!(
                !msg.contains("did:"),
                "the answer names nothing internal: {msg}"
            )
        }
        Err(other) => panic!("a stopped signer is a 503, not {other:?}"),
        Ok(_) => panic!("no token without a signature"),
    }
}

async fn issue_for(db: &RedisClient, client_id: &str) -> String {
    db.issue_grant(&NewGrant {
        kind: GrantKind::Oidc,
        username: localpart_for(DID),
        did: DID.to_string(),
        client_id: client_id.to_string(),
        confidential_client: false,
        device_id: String::new(),
        scope: "openid".to_string(),
        name: DID.to_string(),
        auth_ms: None,
        access_ttl: ACCESS_TOKEN_TTL,
        refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
        absolute_deadline: None,
    })
    .await
    .unwrap()
    .access_token
}

async fn userinfo_with(
    db: &RedisClient,
    signer: &dyn ProviderSigner,
    access_token: &str,
) -> Result<UserInfoResponse, CustomError> {
    userinfo(
        &config(),
        signer,
        None,
        UserInfoPayload {
            access_token: Some(access_token.to_string()),
        },
        db,
    )
    .await
}

/// Signed userinfo through the socket backend verifies with the published
/// JWKS; with the signer stopped it is a 503, while the unsigned (JSON) answer
/// needs no signer and still works.
#[tokio::test]
async fn signed_userinfo_from_the_socket_backend_verifies_and_a_stopped_signer_is_503() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let service = TestSigner::start(EcdsaSigningKey::generate(), TestSigner::options());
    let signer = socket_signer(&service).await;
    let signed_client = store_client(&db, client(true)).await;
    let json_client = store_client(&db, client(false)).await;
    let signed_token = issue_for(&db, &signed_client).await;
    let json_token = issue_for(&db, &json_client).await;

    let UserInfoResponse::Jwt(jwt) = userinfo_with(&db, &signer, &signed_token)
        .await
        .expect("the socket backend signs userinfo")
    else {
        panic!("a client registered for a signed response gets a JWT");
    };
    let compact = serde_json::to_value(jwt)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (input, signature) = compact.rsplit_once('.').unwrap();
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(input.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let published = jwks(&signer, &[]).unwrap();
    let jwk = published
        .keys()
        .iter()
        .find(|k| k.key_id().map(|id| id.as_str()) == header["kid"].as_str())
        .expect("the header names a published kid");
    jwk.verify_signature(
        &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        input.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature).unwrap(),
    )
    .expect("signed userinfo verifies against the published JWKS");

    service.stop();
    assert!(
        matches!(
            userinfo_with(&db, &signer, &signed_token).await,
            Err(CustomError::ServiceUnavailable(_))
        ),
        "no signed userinfo without the signer"
    );
    assert!(
        matches!(
            userinfo_with(&db, &signer, &json_token).await,
            Ok(UserInfoResponse::Json(_))
        ),
        "an unsigned answer does not need the signer"
    );
}

/// The in-process backends sign through the same capture path and are
/// unchanged by it: an ID token from a PEM key verifies as before.
#[tokio::test]
async fn the_pem_backend_still_signs_id_tokens_that_verify() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem()).unwrap();
    let client_id = store_client(&db, client(false)).await;
    let id_nonce = nonce();
    let response = exchange(&db, &key, &client_id, &id_nonce).await.unwrap();
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(client_id),
        IssuerUrl::from_url(config().base_url),
        jwks(&key, &[]).unwrap(),
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
    response
        .extra_fields()
        .id_token()
        .unwrap()
        .claims(&verifier, &Nonce::new(id_nonce))
        .expect("a PEM-signed ID token verifies");
    let _ = response.access_token();
}

/// `retired_signing_keys_pem` works with the socket backend as with any: the
/// JWKS is the signer's key first, then each retired key under its own kid.
#[tokio::test]
async fn the_socket_backend_publishes_its_key_and_the_retired_keys() {
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    let service = TestSigner::start(EcdsaSigningKey::generate(), TestSigner::options());
    let signer = socket_signer(&service).await;
    let retired_key = EcdsaSigningKey::generate();
    let retired_pem = p256::PublicKey::from(*ProviderSigner::verifying_key(&retired_key))
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let retired = parse_retired_verification_keys(&retired_pem).unwrap();
    let published = jwks(&signer, &retired).unwrap();
    let kids: Vec<&str> = published
        .keys()
        .iter()
        .filter_map(|k| k.key_id().map(|id| id.as_str()))
        .collect();
    assert_eq!(kids, [signer.kid(), retired_key.kid()]);
}

/// A backend that signs in process and records each message with its purpose.
struct Recording {
    key: EcdsaSigningKey,
    messages: std::sync::Mutex<Vec<(Purpose, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl ProviderSigner for Recording {
    fn backend(&self) -> &'static str {
        "recording"
    }
    fn kid(&self) -> &str {
        self.key.kid()
    }
    fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        ProviderSigner::verifying_key(&self.key)
    }
    fn is_ephemeral(&self) -> bool {
        false
    }
    async fn sign(&self, purpose: Purpose, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.messages
            .lock()
            .unwrap()
            .push((purpose, message.to_vec()));
        Ok(self.key.sign_es256(message))
    }
}

/// `msg` with its header (`0`) or payload (`1`) segment changed by `edit`.
fn tampered(msg: &[u8], segment: usize, edit: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
    let text = std::str::from_utf8(msg).unwrap();
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let mut value: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[segment]).unwrap()).unwrap();
    edit(&mut value);
    parts[segment] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    parts.join(".").into_bytes()
}

/// Requirement 5, per purpose: the messages siwx-oidc really emits (an ID token
/// from the code exchange, signed userinfo, a DID proof, a logout token) pass
/// the signer's shape check, and each one tampered (a foreign issuer, a foreign
/// kid, an unbounded or forbidden `exp`) fails it.
#[tokio::test]
async fn every_real_emission_has_the_shape_the_signer_allows_and_a_tampered_one_fails() {
    use siwx_oidc::signing::shape::{self, ShapePolicy};
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let recording = Recording {
        key: EcdsaSigningKey::generate(),
        messages: std::sync::Mutex::new(Vec::new()),
    };
    let issuer = config().base_url.as_str().to_string();

    let client_id = store_client(&db, client(false)).await;
    exchange(&db, &recording, &client_id, &nonce())
        .await
        .unwrap();
    let signed_client = store_client(&db, client(true)).await;
    let token = issue_for(&db, &signed_client).await;
    userinfo_with(&db, &recording, &token).await.unwrap();
    crate::did_assertion::did_profile_value(
        &recording,
        &issuer,
        DID,
        "@user:example.org",
        Utc::now().timestamp(),
    )
    .await
    .unwrap();
    crate::backchannel::mint_logout_token(
        &recording,
        &issuer,
        &siwx_oidc::db::outbox::LogoutEntry {
            client_id: "rp-1".into(),
            sub: DID.into(),
            sid: "sid-1".into(),
            grant: "0123456789abcdef".into(),
            attempt: 0,
        },
        Utc::now().timestamp(),
    )
    .await
    .unwrap();

    let messages = recording.messages.lock().unwrap().clone();
    let purposes: Vec<Purpose> = messages.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        purposes,
        [
            Purpose::IdToken,
            Purpose::Userinfo,
            Purpose::DidProof,
            Purpose::LogoutToken
        ],
        "each path signs once, under its own purpose"
    );
    let policy = ShapePolicy {
        kid: recording.kid().to_string(),
        issuer: issuer.clone(),
        max_token_lifetime_secs: siwx_oidc::signing::server::DEFAULT_MAX_TOKEN_LIFETIME_SECS,
        max_clock_skew_secs: siwx_oidc::signing::server::DEFAULT_MAX_CLOCK_SKEW_SECS,
    };
    let now = Utc::now().timestamp();
    for (purpose, msg) in &messages {
        assert_eq!(
            shape::check(&policy, *purpose, msg, now),
            Ok(()),
            "{purpose}: the real emission passes"
        );
        let foreign_iss = tampered(msg, 1, |p| p["iss"] = "https://attacker.example/".into());
        assert_eq!(
            shape::check(&policy, *purpose, &foreign_iss, now),
            Err(shape::ShapeError::Iss),
            "{purpose}"
        );
        let foreign_kid = tampered(msg, 0, |h| h["kid"] = "fedcba9876543210".into());
        assert_eq!(
            shape::check(&policy, *purpose, &foreign_kid, now),
            Err(shape::ShapeError::Kid),
            "{purpose}"
        );
        let long_lived = tampered(msg, 1, |p| p["exp"] = (now + 10 * 365 * 86_400).into());
        assert!(
            shape::check(&policy, *purpose, &long_lived, now).is_err(),
            "{purpose}: an unbounded exp (or any exp on a DID proof) is refused"
        );
    }
}

/// AUDIT PR83 F2: the code exchange answers a signer outage with the retryable
/// 503 (`Retry-After`), but the code was consumed and a grant issued before
/// the ID token was signed, so the retry the 503 invites is refused as an
/// already-exchanged code and the issued grant is held by nobody.
#[tokio::test]
async fn audit_pr83_a_code_exchange_retried_after_a_signer_outage_succeeds() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let key = EcdsaSigningKey::generate();
    let service = TestSigner::start(key.clone(), TestSigner::options());
    let signer = socket_signer(&service).await;
    let client_id = store_client(&db, client(false)).await;
    let code = format!("code-{}", nonce());
    db.set_code(
        code.clone(),
        CodeEntry {
            exchange_count: 0,
            did: DID.to_string(),
            nonce: None,
            client_id: client_id.to_string(),
            auth_time: Utc::now(),
            code_challenge: Some(CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            device_id: None,
            localpart: Some(localpart_for(DID)),
            scope: Some("openid".into()),
            client_class: Some(ClientClass::Matrix),
        },
    )
    .await
    .unwrap();
    let form = || TokenForm {
        code: Some(code.clone()),
        client_id: Some(client_id.to_string()),
        client_secret: None,
        grant_type: CoreGrantType::AuthorizationCode,
        code_verifier: Some(VERIFIER.to_string()),
        refresh_token: None,
        device_code: None,
    };
    service.stop();
    let first = token(
        form(),
        ClientCredentials::default(),
        &signer,
        &config(),
        &db,
        None,
    )
    .await;
    assert!(matches!(first, Err(CustomError::ServiceUnavailable(_))));
    // The signer is back (in process here): the retry the 503 asked for.
    let retry = token(
        form(),
        ClientCredentials::default(),
        &key,
        &config(),
        &db,
        None,
    )
    .await;
    assert!(
        retry.is_ok(),
        "a retried exchange after a 503 is served, not {:?}",
        retry.as_ref().err()
    );
}
