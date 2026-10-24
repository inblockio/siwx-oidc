//! `siwx-oidc-auth --verify-did` as a process, against a homeserver and an issuer
//! on a local socket: what it writes to stderr and stdout, and what it does not.
//!
//! The profile's plain `did` member is the homeserver's text and is not covered
//! by the proof's signature. The library reports a disagreement with the signed
//! `sub` as a flag and prints nothing; the CLI tells the user, without the value.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};

const MXID: &str = "@alice:example.org";
const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
const KID: &str = "3f2a1c0d9e8b7a65";
/// What a hostile homeserver writes into the plain `did` member.
const MARKER: &str = "did:MARKER-7f3a9c-echoed-by-the-server";

/// What the CLI printed and how it ended.
struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Serve a discovery document, a key set and one profile field on a local
/// socket, run `--verify-did` against it, and return what it printed.
/// `profile` receives the signed proof and returns the field's value.
fn run_verify_did(profile: impl FnOnce(&str) -> Value) -> Run {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let jwks = json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": KID,
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }]});
    let header = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({"alg": "ES256", "typ": "JWT", "kid": KID})).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": base, "sub": DID, "mxid": MXID, "iat": 1_757_000_000i64,
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    let proof = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );

    let routes: HashMap<&'static str, String> = HashMap::from([
        (
            "/.well-known/openid-configuration",
            json!({ "issuer": base, "jwks_uri": format!("{base}/jwk") }).to_string(),
        ),
        ("/jwk", jwks.to_string()),
        (
            "io.inblock.did",
            json!({ "io.inblock.did": profile(&proof) }).to_string(),
        ),
    ]);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let body = routes
                .iter()
                // The profile route has the percent-encoded MXID in its path; the
                // other two are exact.
                .find(|(route, _)| match **route {
                    "io.inblock.did" => path.ends_with("/io.inblock.did"),
                    exact => path == exact,
                })
                .map(|(_, body)| body.clone());
            let (status, body) = match body {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", r#"{"errcode":"M_NOT_FOUND"}"#.to_string()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_siwx-oidc-auth"))
        .args([
            "--server",
            &base,
            "--homeserver",
            &base,
            "--verify-did",
            MXID,
        ])
        .env_remove("SIWX_KEY_FILE")
        .output()
        .expect("the CLI runs");
    Run {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn a_disagreeing_plain_did_is_told_to_the_user_without_its_value() {
    let run = run_verify_did(|proof| json!({ "did": MARKER, "proof": proof }));

    assert!(run.success, "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("disagrees"),
        "the user is told: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("MARKER"),
        "the plain member reached stderr: {}",
        run.stderr
    );
    assert!(
        !run.stdout.contains("MARKER"),
        "the plain member reached stdout: {}",
        run.stdout
    );
    let printed: Value = serde_json::from_str(&run.stdout).expect("stdout is the JSON result");
    assert_eq!(printed["did"], DID, "the signed DID is the one printed");
    assert!(
        printed.get("plain_did_disagrees").is_none(),
        "the printed form is unchanged: {}",
        run.stdout
    );
}

#[test]
fn an_agreeing_plain_did_prints_nothing_to_stderr() {
    let run = run_verify_did(|proof| json!({ "did": DID, "proof": proof }));

    assert!(run.success, "stderr: {}", run.stderr);
    assert_eq!(run.stderr, "");
    let printed: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(printed["did"], DID);
}

#[test]
fn a_profile_without_a_proof_fails_without_repeating_the_plain_did() {
    let run = run_verify_did(|_| json!({ "did": MARKER }));

    assert!(!run.success);
    assert!(
        run.stderr.contains("UNVERIFIED") && run.stderr.contains("NO `proof`"),
        "the error says what is wrong: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("MARKER") && !run.stdout.contains("MARKER"),
        "the plain member reached the output: {} / {}",
        run.stderr,
        run.stdout
    );
}
