//! Tests of the signing interface, the capture path ([`super::sign_jwt`]) and
//! the socket client against signers that misbehave.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AccessToken, Audience, ClientId, EmptyAdditionalClaims, IssuerUrl, Nonce, StandardClaims,
    SubjectIdentifier,
};
use p256::ecdsa::{signature::Verifier, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::protocol::{self, ErrorCode};
use super::socket::SocketSigner;
use super::*;
use crate::test_support::{temp_dir, TestSigner};

const ISSUER: &str = "https://example.org/";
const CLIENT: &str = "client-1";

/// A backend that signs with an in-process key and records every message it
/// was asked to sign, or fails every request.
struct Recording {
    key: EcdsaSigningKey,
    messages: Mutex<Vec<(Purpose, Vec<u8>)>>,
    fail: bool,
}

impl Recording {
    fn new(fail: bool) -> Self {
        Self {
            key: EcdsaSigningKey::from_pem(&test_pem()).unwrap(),
            messages: Mutex::new(Vec::new()),
            fail,
        }
    }
}

#[async_trait]
impl ProviderSigner for Recording {
    fn backend(&self) -> &'static str {
        "recording"
    }
    fn kid(&self) -> &str {
        self.key.kid()
    }
    fn verifying_key(&self) -> &VerifyingKey {
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
        if self.fail {
            return Err(SignError::Unavailable("test backend down".to_string()));
        }
        Ok(self.key.sign_es256(message))
    }
}

fn test_pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    p256::SecretKey::random(&mut rand::thread_rng())
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn claims(now: chrono::DateTime<chrono::Utc>) -> CoreIdTokenClaims {
    CoreIdTokenClaims::new(
        IssuerUrl::new(ISSUER.to_string()).unwrap(),
        vec![Audience::new(CLIENT.to_string())],
        now + chrono::Duration::seconds(300),
        now,
        StandardClaims::new(SubjectIdentifier::new("did:key:zTest".to_string())),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new("nonce-1".to_string())))
}

/// Requirement 2: the signing input the capture records is exactly the built
/// token's `header.payload`, it is what the backend signs, and the assembled
/// token verifies through openidconnect's own verifier against the JWKS the
/// provider publishes.
#[tokio::test]
async fn sign_jwt_signs_exactly_the_captured_header_and_payload_and_verifies_with_the_jwks() {
    let backend = Recording::new(false);
    let access = AccessToken::new("access-token-1".to_string());
    let token: CoreIdToken = sign_jwt(&backend, Purpose::IdToken, |key| {
        CoreIdToken::new(
            claims(chrono::Utc::now()),
            key,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            Some(&access),
            None,
        )
    })
    .await
    .expect("the in-process backend signs");

    let compact = token.to_string();
    let (signing_input, signature) = compact.rsplit_once('.').unwrap();
    let messages = backend.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 1, "exactly one signature per token");
    assert_eq!(messages[0].0, Purpose::IdToken);
    assert_eq!(
        messages[0].1,
        signing_input.as_bytes(),
        "the backend signs the token's own header.payload bytes"
    );
    let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    assert_eq!(signature.len(), 64, "raw r||s, never DER");
    assert_ne!(
        signature,
        vec![0; 64],
        "the placeholder never leaves sign_jwt"
    );

    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signing_input.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        header,
        serde_json::json!({"alg": "ES256", "kid": backend.kid()})
    );

    let jwks = CoreJsonWebKeySet::new(vec![backend.verification_jwk()]);
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(CLIENT.to_string()),
        IssuerUrl::new(ISSUER.to_string()).unwrap(),
        jwks,
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
    let verified = token
        .claims(&verifier, &Nonce::new("nonce-1".to_string()))
        .expect("the assembled token verifies against the published JWKS");
    assert_eq!(verified.subject().as_str(), "did:key:zTest");
    assert!(
        verified.access_token_hash().is_some(),
        "at_hash is computed from the real key's algorithm"
    );
}

/// The capture path gives the in-process key the very token it signed before
/// backends: ES256 under RFC 6979 is deterministic, so the same claims signed
/// directly and through the capture give byte-identical tokens.
#[tokio::test]
async fn the_capture_path_gives_the_in_process_key_byte_identical_tokens() {
    let key = EcdsaSigningKey::from_pem(&test_pem()).unwrap();
    let now = chrono::Utc::now();
    let direct = CoreIdToken::new(
        claims(now),
        &key,
        CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        None,
        None,
    )
    .unwrap();
    let captured: CoreIdToken = sign_jwt(&key, Purpose::IdToken, |capture| {
        CoreIdToken::new(
            claims(now),
            capture,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            None,
            None,
        )
    })
    .await
    .unwrap();
    assert_eq!(direct.to_string(), captured.to_string());
}

#[tokio::test]
async fn a_backend_failure_is_returned_and_no_token_is() {
    let backend = Recording::new(true);
    let result: Result<CoreIdToken, SignError> = sign_jwt(&backend, Purpose::IdToken, |key| {
        CoreIdToken::new(
            claims(chrono::Utc::now()),
            key,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            None,
            None,
        )
    })
    .await;
    let err = result.expect_err("no token without a signature");
    assert!(err.is_backend());
    assert!(matches!(err, SignError::Unavailable(_)));
}

#[tokio::test]
async fn a_builder_that_signs_zero_or_two_times_is_an_assembly_error() {
    let key = EcdsaSigningKey::generate();
    let none: Result<CoreIdToken, SignError> = sign_jwt(&key, Purpose::IdToken, |_| {
        Err(openidconnect::JsonWebTokenError::SigningError(
            SigningError::Other("built nothing".to_string()),
        ))
    })
    .await;
    assert!(matches!(none, Err(SignError::Assembly(_))));

    let twice: Result<CoreIdToken, SignError> = sign_jwt(&key, Purpose::IdToken, |capture| {
        let _ = CoreIdToken::new(
            claims(chrono::Utc::now()),
            capture,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            None,
            None,
        )?;
        CoreIdToken::new(
            claims(chrono::Utc::now()),
            capture,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            None,
            None,
        )
    })
    .await;
    let err = twice.expect_err("two signatures for one token are refused");
    assert!(matches!(err, SignError::Assembly(_)));
    assert!(!err.is_backend(), "an assembly fault is not the signer's");
}

#[test]
fn the_in_process_key_names_its_backend() {
    assert_eq!(EcdsaSigningKey::generate().backend(), "ephemeral");
    assert_eq!(
        EcdsaSigningKey::from_pem(&test_pem()).unwrap().backend(),
        "pem"
    );
}

// -- The socket client against signers that misbehave ------------------------

/// A fake signer: answers every connection with `answer(request line)`.
fn fake_signer(
    socket: &Path,
    answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).await.unwrap() == 1 && byte[0] != b'\n' {
                request.push(byte[0]);
            }
            match answer(&request) {
                Some(bytes) => {
                    let _ = stream.write_all(&bytes).await;
                    let _ = stream.shutdown().await;
                }
                // Hold the connection open and say nothing.
                None => tokio::time::sleep(Duration::from_secs(30)).await,
            }
        }
    })
}

fn public_of(key: &EcdsaSigningKey, kid: &str) -> Vec<u8> {
    protocol::public_answer(kid, serde_json::to_value(key.verification_jwk()).unwrap())
}

fn is_public(request: &[u8]) -> bool {
    matches!(
        protocol::parse_request(request),
        Ok(protocol::Request::Public)
    )
}

const TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn connect_derives_the_kid_itself_and_refuses_a_signer_that_names_another() {
    let dir = temp_dir("client-kid");
    let socket = dir.join("s.sock");
    let key = EcdsaSigningKey::generate();
    let other = EcdsaSigningKey::generate();
    let lying_kid = other.kid().to_string();
    let task = fake_signer(&socket, move |_| Some(public_of(&key, &lying_kid)));
    let err = SocketSigner::connect(&socket, TIMEOUT)
        .await
        .err()
        .expect("a kid its key does not derive to is refused");
    match err {
        SignError::KidMismatch { got, .. } => assert_eq!(got, other.kid()),
        other => panic!("expected KidMismatch, got {other:?}"),
    }
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn connect_refuses_an_error_or_a_non_es256_answer() {
    let dir = temp_dir("client-public");
    let socket = dir.join("s.sock");
    let task = fake_signer(&socket, |_| {
        Some(protocol::error_answer(ErrorCode::Internal))
    });
    assert!(matches!(
        SocketSigner::connect(&socket, TIMEOUT).await,
        Err(SignError::Refused(ErrorCode::Internal))
    ));
    task.abort();
    let _ = std::fs::remove_file(&socket);

    let key = EcdsaSigningKey::generate();
    let kid = key.kid().to_string();
    let jwk = serde_json::to_value(key.verification_jwk()).unwrap();
    let task = fake_signer(&socket, move |_| {
        let mut answer: serde_json::Value =
            serde_json::from_slice(&protocol::public_answer(&kid, jwk.clone())).unwrap();
        answer["alg"] = serde_json::json!("RS256");
        Some(format!("{answer}\n").into_bytes())
    });
    assert!(matches!(
        SocketSigner::connect(&socket, TIMEOUT).await,
        Err(SignError::BadAnswer)
    ));
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Requirement 3: every answer is checked. A signature by another key under
/// the right kid, an answer under another kid, a DER signature, an error code
/// and garbage are each an error, never a token.
#[tokio::test]
async fn every_sign_answer_is_verified_and_a_bad_one_is_an_error_never_a_signature() {
    let dir = temp_dir("client-verify");
    let socket = dir.join("s.sock");
    let key = EcdsaSigningKey::generate();
    let impostor = EcdsaSigningKey::generate();
    let kid = key.kid().to_string();
    let mode = std::sync::Arc::new(Mutex::new("good"));
    let task = {
        let mode = mode.clone();
        let key = key.clone();
        fake_signer(&socket, move |request| {
            if is_public(request) {
                return Some(public_of(&key, key.kid()));
            }
            let Ok(protocol::Request::Sign { msg, .. }) = protocol::parse_request(request) else {
                return Some(protocol::error_answer(ErrorCode::BadRequest));
            };
            let current = *mode.lock().unwrap();
            Some(match current {
                "good" => protocol::sign_answer(key.kid(), &key.sign_es256(&msg)),
                "impostor" => protocol::sign_answer(key.kid(), &impostor.sign_es256(&msg)),
                "other-kid" => protocol::sign_answer(impostor.kid(), &impostor.sign_es256(&msg)),
                "der" => {
                    let raw = Signature::from_slice(&key.sign_es256(&msg)).unwrap();
                    protocol::sign_answer(key.kid(), raw.to_der().as_bytes())
                }
                "refused" => protocol::error_answer(ErrorCode::Shape),
                _ => b"{\"v\":1,\"surprise\":true}\n".to_vec(),
            })
        })
    };
    let signer = SocketSigner::connect(&socket, TIMEOUT).await.unwrap();
    assert_eq!(signer.kid(), kid);
    assert_eq!(signer.backend(), "socket");
    assert!(!signer.is_ephemeral(), "a socket key is durable");

    let msg = b"eyJhbGciOiJFUzI1NiJ9.e30";
    let good = signer.sign(Purpose::IdToken, msg).await.unwrap();
    ProviderSigner::verifying_key(&key)
        .verify(msg, &Signature::from_slice(&good).unwrap())
        .unwrap();

    for (case, expected) in [
        ("impostor", "BadSignature"),
        ("other-kid", "KidMismatch"),
        ("der", "BadSignature"),
        ("refused", "Refused"),
        ("garbage", "BadAnswer"),
    ] {
        *mode.lock().unwrap() = case;
        let err = signer
            .sign(Purpose::IdToken, msg)
            .await
            .expect_err("a bad answer is never a signature");
        assert!(
            format!("{err:?}").starts_with(expected),
            "{case}: expected {expected}, got {err:?}"
        );
        assert!(err.is_backend(), "{case}: a signer fault is a 503");
    }
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn no_signer_is_unavailable_and_a_silent_one_times_out() {
    let dir = temp_dir("client-down");
    let socket = dir.join("s.sock");
    assert!(matches!(
        SocketSigner::connect(&socket, TIMEOUT).await,
        Err(SignError::Unavailable(_))
    ));

    let task = fake_signer(&socket, |_| None);
    let started = std::time::Instant::now();
    let err = SocketSigner::connect(&socket, Duration::from_millis(200))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, SignError::Timeout(200)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the bound holds"
    );
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The socket backend end to end with the real service: what it signs
/// verifies against the key the client derived, and a stopped signer is
/// unavailable, not a hang.
#[tokio::test]
async fn the_socket_backend_signs_through_the_real_service_and_fails_when_it_stops() {
    let key = EcdsaSigningKey::from_pem(&test_pem()).unwrap();
    let expected_kid = key.kid().to_string();
    let mut options = TestSigner::options();
    options.issuer = ISSUER.to_string();
    let service = TestSigner::start(key, options);
    let signer = SocketSigner::connect(&service.socket, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(signer.kid(), expected_kid);
    assert_eq!(service.kid, expected_kid);

    let access = AccessToken::new("access-token-2".to_string());
    let token: CoreIdToken = sign_jwt(&signer, Purpose::IdToken, |key| {
        CoreIdToken::new(
            claims(chrono::Utc::now()),
            key,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            Some(&access),
            None,
        )
    })
    .await
    .expect("the service signs an ID token of the emitted shape");
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(CLIENT.to_string()),
        IssuerUrl::new(ISSUER.to_string()).unwrap(),
        CoreJsonWebKeySet::new(vec![signer.verification_jwk()]),
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
    token
        .claims(&verifier, &Nonce::new("nonce-1".to_string()))
        .expect("verifies against the JWKS built from the signer's public key");

    service.stop();
    let err = signer
        .sign(Purpose::IdToken, b"eyJhbGciOiJFUzI1NiJ9.e30")
        .await
        .expect_err("a stopped signer signs nothing");
    assert!(matches!(err, SignError::Unavailable(_)), "{err:?}");
}
