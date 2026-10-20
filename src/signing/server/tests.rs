//! Tests of the signer socket service, over a real Unix socket.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::*;
use crate::signing::protocol::{PublicAnswer, SignAnswer};
use crate::signing::socket::SocketSigner;
use crate::test_support::{current_uid, temp_dir, LogCapture, TestSigner, TEST_SIGNER_ISSUER};

/// Send `request` as is and read the whole answer (empty when the service
/// closed without one).
async fn exchange(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    // A refused peer is closed before anything is read: the write may fail.
    let _ = stream.write_all(request).await;
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    answer
}

fn error_of(answer: &[u8]) -> ErrorCode {
    protocol::parse_answer::<SignAnswer>(answer)
        .expect("a protocol answer")
        .expect_err("an error answer")
}

fn jws(header: serde_json::Value, payload: serde_json::Value) -> Vec<u8> {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    )
    .into_bytes()
}

/// A logout token of the shape siwx-oidc emits, for `kid`, at `now`.
fn logout_message(kid: &str, sub: &str) -> Vec<u8> {
    let now = chrono::Utc::now().timestamp();
    jws(
        serde_json::json!({"alg": "ES256", "typ": "logout+jwt", "kid": kid}),
        serde_json::json!({"iss": "http://127.0.0.1:8000/", "aud": "rp", "iat": now,
            "exp": now + 120, "jti": "j", "sub": sub,
            "events": {crate::signing::shape::BACKCHANNEL_LOGOUT_EVENT: {}}}),
    )
}

#[tokio::test]
async fn public_names_the_key_and_sign_answers_a_signature_that_verifies() {
    let key = EcdsaSigningKey::generate();
    let verifying_key = *ProviderSigner::verifying_key(&key);
    let service = TestSigner::start(key.clone(), TestSigner::options());

    let answer = exchange(&service.socket, &protocol::public_request()).await;
    let public: PublicAnswer = protocol::parse_answer(&answer).unwrap().unwrap();
    assert_eq!(public.kid, key.kid());
    assert_eq!(public.alg, "ES256");
    assert_eq!(
        public.jwk,
        serde_json::to_value(key.verification_jwk()).unwrap(),
        "the published JWK, built by the one verification_jwk"
    );
    assert!(public.jwk.get("d").is_none(), "never the private scalar");

    let msg = logout_message(key.kid(), "did:key:zSubject");
    let answer = exchange(
        &service.socket,
        &protocol::sign_request(Purpose::LogoutToken, &msg),
    )
    .await;
    let signed: SignAnswer = protocol::parse_answer(&answer).unwrap().unwrap();
    assert_eq!(signed.kid, key.kid());
    let raw = URL_SAFE_NO_PAD.decode(&signed.sig).unwrap();
    assert_eq!(raw.len(), 64, "raw r||s");
    verifying_key
        .verify(&msg, &Signature::from_slice(&raw).unwrap())
        .expect("the signature verifies over the message");
}

/// A peer of any uid but the allowed one is closed before a byte is read, and
/// the refusal is logged with its uid.
#[tokio::test]
async fn a_peer_with_another_uid_is_refused_and_logged() {
    let capture = LogCapture::start();
    let mut options = TestSigner::options();
    options.allowed_uid = current_uid().wrapping_add(1);
    let service = TestSigner::start(EcdsaSigningKey::generate(), options);

    let answer = exchange(&service.socket, &protocol::public_request()).await;
    assert!(answer.is_empty(), "no answer to a refused peer: {answer:?}");
    let err = SocketSigner::connect(&service.socket, Duration::from_secs(2))
        .await
        .err()
        .expect("a refused peer gets no key");
    assert!(err.is_backend());
    let log = capture.output();
    assert!(
        log.contains(&format!("peer_refused uid={}", current_uid())),
        "the refusal names the peer uid: {log}"
    );
}

#[tokio::test]
async fn an_oversize_request_is_too_large_and_the_limit_is_exact() {
    let service = TestSigner::start(EcdsaSigningKey::generate(), TestSigner::options());

    // One byte over the limit before any newline.
    let oversize = vec![b'a'; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        error_of(&exchange(&service.socket, &oversize).await),
        ErrorCode::TooLarge
    );
    // Exactly the limit, newline included: read in full, then judged as JSON.
    let mut at_limit = vec![b' '; MAX_REQUEST_BYTES - 1];
    at_limit.push(b'\n');
    assert_eq!(
        error_of(&exchange(&service.socket, &at_limit).await),
        ErrorCode::BadRequest
    );
    // One over, newline included.
    let mut over = vec![b' '; MAX_REQUEST_BYTES];
    over.push(b'\n');
    assert_eq!(
        error_of(&exchange(&service.socket, &over).await),
        ErrorCode::TooLarge
    );
}

#[tokio::test]
async fn bad_json_and_a_bad_version_are_answered_with_their_codes_and_never_echoed() {
    let service = TestSigner::start(EcdsaSigningKey::generate(), TestSigner::options());
    for (request, code) in [
        (&b"this is not json\n"[..], ErrorCode::BadRequest),
        (b"{\"v\":1,\"op\":\"steal\"}\n", ErrorCode::BadRequest),
        (b"{\"op\":\"public\"}\n", ErrorCode::BadVersion),
        (b"{\"v\":2,\"op\":\"public\"}\n", ErrorCode::BadVersion),
    ] {
        let answer = exchange(&service.socket, request).await;
        assert_eq!(error_of(&answer), code);
        assert_eq!(
            String::from_utf8(answer).unwrap(),
            format!("{{\"v\":1,\"error\":\"{code}\"}}\n"),
            "exactly the error, nothing of the request"
        );
    }
    // A client that half-closes without a newline is still answered.
    let mut stream = UnixStream::connect(&service.socket).await.unwrap();
    stream
        .write_all(b"{\"v\":1,\"op\":\"public\"}")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    assert!(protocol::parse_answer::<PublicAnswer>(&answer)
        .unwrap()
        .is_ok());
}

/// A message of the wrong shape is refused with `shape`, and neither the
/// refusal nor a successful signature logs a byte of the message.
#[tokio::test]
async fn a_shape_refusal_and_a_signature_log_the_purpose_and_length_never_the_message() {
    let capture = LogCapture::start();
    let key = EcdsaSigningKey::generate();
    let kid = key.kid().to_string();
    let service = TestSigner::start(key, TestSigner::options());

    // A marker only the message holds.
    let marker = "did:key:zPersonalDataMarker";
    let good = logout_message(&kid, marker);
    let answer = exchange(
        &service.socket,
        &protocol::sign_request(Purpose::LogoutToken, &good),
    )
    .await;
    assert!(protocol::parse_answer::<SignAnswer>(&answer)
        .unwrap()
        .is_ok());

    let foreign = String::from_utf8(logout_message(&kid, marker))
        .unwrap()
        .into_bytes();
    // The same message under the purpose of an ID token: the typ is wrong.
    let answer = exchange(
        &service.socket,
        &protocol::sign_request(Purpose::IdToken, &foreign),
    )
    .await;
    assert_eq!(error_of(&answer), ErrorCode::Shape);

    let log = capture.output();
    assert!(log.contains("purpose=logout_token"), "{log}");
    assert!(log.contains(&format!("len={}", good.len())), "{log}");
    assert!(log.contains("result=ok"), "{log}");
    assert!(log.contains("result=shape"), "{log}");
    assert!(log.contains("reason=typ"), "{log}");
    assert!(
        log.contains(&format!("peer_uid={}", current_uid())),
        "{log}"
    );
    assert!(!log.contains(marker), "never a byte of the message: {log}");
    let encoded = std::str::from_utf8(&good).unwrap();
    for segment in encoded.split('.') {
        assert!(!log.contains(segment), "never the encoded message: {log}");
    }
}

#[tokio::test]
async fn a_client_that_sends_nothing_is_closed_after_the_read_timeout() {
    let mut options = TestSigner::options();
    options.read_timeout = Duration::from_millis(100);
    let service = TestSigner::start(EcdsaSigningKey::generate(), options);
    let mut stream = UnixStream::connect(&service.socket).await.unwrap();
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .expect("the service closes the connection itself");
    assert!(read.is_ok());
    assert!(
        answer.is_empty(),
        "nothing is answered to an unread request"
    );
}

#[tokio::test]
async fn sign_requests_beyond_the_bound_in_a_minute_raise_one_rate_alarm() {
    let capture = LogCapture::start();
    let key = EcdsaSigningKey::generate();
    let kid = key.kid().to_string();
    let mut options = TestSigner::options();
    options.rate_alarm_per_minute = 2;
    let service = TestSigner::start(key, options);
    for _ in 0..4 {
        let msg = logout_message(&kid, "did:key:zSubject");
        let answer = exchange(
            &service.socket,
            &protocol::sign_request(Purpose::LogoutToken, &msg),
        )
        .await;
        assert!(protocol::parse_answer::<SignAnswer>(&answer)
            .unwrap()
            .is_ok());
    }
    let log = capture.output();
    assert_eq!(
        log.matches("rate_alarm").count(),
        1,
        "once per minute: {log}"
    );
    assert!(log.contains("signs_per_minute=3 bound=2"), "{log}");
}

#[test]
fn the_issuer_is_compared_in_the_form_siwx_oidc_writes_it() {
    let service = SignerService::new(
        EcdsaSigningKey::generate(),
        ServiceOptions::new(TEST_SIGNER_ISSUER),
    )
    .unwrap();
    assert_eq!(service.policy.issuer, "http://127.0.0.1:8000/");
    assert!(SignerService::new(
        EcdsaSigningKey::generate(),
        ServiceOptions::new("not a url")
    )
    .is_err());
}

#[tokio::test]
async fn bind_replaces_a_stale_socket_refuses_anything_else_and_sets_mode_0660() {
    let dir = temp_dir("bind");
    let socket = dir.join("signer.sock");
    // A socket left by a run that died: its file stays after the listener goes.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    let listener = bind(&socket).expect("a stale socket is replaced");
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, SOCKET_MODE);
    drop(listener);

    let file = dir.join("not-a-socket");
    std::fs::write(&file, b"keep me").unwrap();
    assert!(bind(&file).is_err(), "a regular file is never replaced");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");

    let link = dir.join("link.sock");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(
        bind(&link).is_err(),
        "a symlink is never followed or replaced"
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    let _ = std::fs::remove_dir_all(&dir);
}
