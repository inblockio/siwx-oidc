//! `remint-did-assertions` as an operator runs it: the real binary, its configuration from the
//! environment, a fake homeserver on a local socket, and the test Redis (the admin token the
//! tool mints is written there, as the server does).
//!
//! What this pins that the unit tests of `src/remint.rs` cannot: that the tool starts under
//! both of its names, builds its signer and its Synapse client from the server's own
//! settings, refuses an ephemeral key before it reads anything, and that what it prints, on
//! stdout and on stderr, is counts and public values only.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

use siwx_oidc::mxid::localpart_for;
use siwx_oidc::signing::EcdsaSigningKey;
use siwx_oidc::test_support::{random_secret, redis, redis_url, temp_dir};

const SERVER: &str = "hs.example.org";
/// For the cases that never reach the key-set check; a run that does uses the fake's own URL.
const UNUSED_ISSUER: &str = "https://auth.example.org/";
const FIELD: &str = "io.inblock.did";
const ADMIN: &str = "siwx-admin";
const DID_ANN: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
const DID_BOB: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
const DID_CY: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    p256::SecretKey::random(&mut rand::thread_rng())
        .to_pkcs8_pem(LineEnding::LF)
        .expect("a P-256 key encodes")
        .to_string()
}

/// The key set a server publishes for these keys.
fn key_set(keys: &[&EcdsaSigningKey]) -> Value {
    use siwx_oidc::signing::ProviderSigner;
    json!({"keys": keys.iter().map(|k| serde_json::to_value(k.verification_jwk()).unwrap()).collect::<Vec<_>>()})
}

/// A proof as the server's minter writes it, built here from the public wire format so the
/// test does not call the code under test to prepare its input.
fn proof(key: &EcdsaSigningKey, issuer: &str, did: &str, mxid: &str) -> String {
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": key.kid()});
    let claims = json!({"iss": issuer, "sub": did, "mxid": mxid, "iat": 1_700_000_000});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = key.sign_es256(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

// -- The fake homeserver ------------------------------------------------------------------------

#[derive(Default)]
struct Hs {
    /// localpart -> deactivated
    users: BTreeMap<String, bool>,
    profile: HashMap<String, Value>,
    puts: usize,
    list_requests: usize,
    /// Every request to a homeserver route (the user list, the profile field, the MAS probe):
    /// what "nothing was read" counts.
    reads: usize,
    /// What `GET /jwk` answers: the server's own key set.
    jwks: Value,
    jwks_requests: usize,
}

type Shared = Arc<Mutex<Hs>>;

fn localpart_of(user: &str) -> String {
    user.trim_start_matches('@')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

async fn jwk(State(hs): State<Shared>) -> impl IntoResponse {
    let mut hs = hs.lock().unwrap();
    hs.jwks_requests += 1;
    Json(hs.jwks.clone())
}

async fn list_users(State(hs): State<Shared>) -> impl IntoResponse {
    let mut hs = hs.lock().unwrap();
    hs.list_requests += 1;
    hs.reads += 1;
    let rows: Vec<Value> = hs
        .users
        .iter()
        .map(|(lp, gone)| {
            json!({"name": format!("@{lp}:{SERVER}"), "user_type": null, "deactivated": u8::from(*gone)})
        })
        .collect();
    Json(json!({"users": rows, "total": rows.len()}))
}

async fn get_field(State(hs): State<Shared>, Path(user): Path<String>) -> impl IntoResponse {
    let mut hs = hs.lock().unwrap();
    hs.reads += 1;
    match hs.profile.get(&localpart_of(&user)) {
        Some(value) => (StatusCode::OK, Json(json!({ FIELD: value }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"errcode": "M_NOT_FOUND"})),
        ),
    }
}

async fn put_field(
    State(hs): State<Shared>,
    Path(user): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let mut hs = hs.lock().unwrap();
    hs.reads += 1;
    hs.puts += 1;
    hs.profile.insert(
        localpart_of(&user),
        body.get(FIELD).cloned().unwrap_or(Value::Null),
    );
    Json(json!({}))
}

async fn probe(
    State(hs): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let lp = q.get("localpart").cloned().unwrap_or_default();
    hs.lock().unwrap().reads += 1;
    if hs.lock().unwrap().users.contains_key(&lp) {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_USER_IN_USE", "error": "taken"})),
        )
            .into_response()
    } else {
        (StatusCode::OK, Json(json!({}))).into_response()
    }
}

async fn homeserver() -> (Shared, String, tokio::task::JoinHandle<()>) {
    let hs: Shared = Arc::new(Mutex::new(Hs::default()));
    let app = Router::new()
        .route("/jwk", get(jwk))
        .route("/_synapse/admin/v2/users", get(list_users))
        .route("/_synapse/mas/is_localpart_available", get(probe))
        .route(
            &format!("/_matrix/client/v3/profile/{{user}}/{FIELD}"),
            get(get_field).put(put_field),
        )
        .with_state(hs.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (hs, url, task)
}

// -- Running the tool ---------------------------------------------------------------------------

/// How the tool is started: under its second name, or as the first argument.
#[derive(Clone, Copy)]
enum Start {
    ByName,
    ByArgument,
}

struct Setup {
    synapse_url: String,
    /// `base_url`, the issuer: the fake's own address when the run must find its key set.
    base_url: String,
    pem: Option<String>,
    secret: String,
    dir: std::path::PathBuf,
}

impl Setup {
    fn run(&self, start: Start, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
        match start {
            Start::ByName => {
                command.arg0("remint-did-assertions");
            }
            Start::ByArgument => {
                command.arg("remint-did-assertions");
            }
        }
        command
            .args(args)
            .current_dir(&self.dir)
            .env_clear()
            .env("SIWXOIDC_BASE_URL", &self.base_url)
            .env("SIWXOIDC_REDIS_URL", redis_url().as_str())
            .env("SIWXOIDC_SYNAPSE_ENDPOINT", &self.synapse_url)
            .env("SIWXOIDC_MAS_SHARED_SECRET", &self.secret)
            .env("SIWXOIDC_MATRIX_SERVER_NAME", SERVER)
            .env("SIWXOIDC_ADMIN_TOKEN_LOCALPART", ADMIN)
            // The tool installs no log subscriber; this proves a log filter changes nothing.
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null());
        if let Some(pem) = &self.pem {
            command.env("SIWXOIDC_SIGNING_KEY_PEM", pem);
        }
        command.output().expect("spawn the tool")
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tool_remints_stale_bindings_once_and_prints_counts_only() {
    if redis().await.is_none() {
        return;
    }
    let (hs, synapse_url, server) = homeserver().await;
    // The fake is also the issuer: the tool reads its key set from `base_url`.
    let issuer = format!("{synapse_url}/");
    let current_pem = pem();
    let current = EcdsaSigningKey::from_pem(&current_pem).unwrap();
    let old = EcdsaSigningKey::from_pem(&pem()).unwrap();
    let (ann, bob, cy) = (
        localpart_for(DID_ANN),
        localpart_for(DID_BOB),
        localpart_for(DID_CY),
    );
    {
        let mut hs = hs.lock().unwrap();
        hs.jwks = key_set(&[&current]);
        for lp in [&ann, &bob, &cy, &ADMIN.to_string()] {
            hs.users.insert(lp.clone(), false);
        }
        hs.users.insert("gone".to_string(), true);
        // ann: signed by a key the current JWKS no longer lists.
        let stale = proof(&old, &issuer, DID_ANN, &format!("@{ann}:{SERVER}"));
        hs.profile
            .insert(ann.clone(), json!({"did": DID_ANN, "proof": stale}));
        // bob: current.
        let fresh = proof(&current, &issuer, DID_BOB, &format!("@{bob}:{SERVER}"));
        hs.profile
            .insert(bob.clone(), json!({"did": DID_BOB, "proof": fresh}));
        // cy: no field at all, so nothing for the derivation to confirm.
    }
    let secret = random_secret(40);
    let setup = Setup {
        synapse_url,
        base_url: issuer.clone(),
        pem: Some(current_pem.clone()),
        secret: secret.clone(),
        dir: temp_dir("remint-cli"),
    };

    let dry = setup.run(Start::ByName, &["--delay-ms", "0"]);
    let dry_text = text(&dry);
    assert!(dry.status.success(), "{dry_text}");
    assert!(dry_text.contains("DRY RUN"), "{dry_text}");
    assert!(dry_text.contains("would_write: 1"), "{dry_text}");
    assert!(dry_text.contains("skipped_current: 1"), "{dry_text}");
    assert!(dry_text.contains("skipped_deactivated: 1"), "{dry_text}");
    assert!(
        dry_text.contains("skipped_no_mapping: 2"),
        "cy and the service account: {dry_text}"
    );
    assert_eq!(hs.lock().unwrap().puts, 0, "a dry run writes nothing");

    let first = setup.run(Start::ByArgument, &["--apply", "--delay-ms", "0"]);
    let first_text = text(&first);
    assert!(first.status.success(), "{first_text}");
    assert!(first_text.contains("APPLY"), "{first_text}");
    assert!(first_text.contains("written: 1"), "{first_text}");
    assert_eq!(hs.lock().unwrap().puts, 1);

    let second = setup.run(Start::ByName, &["--apply", "--delay-ms", "0"]);
    let second_text = text(&second);
    assert!(second.status.success(), "{second_text}");
    assert!(
        second_text.contains("written: 0"),
        "a rerun writes nothing: {second_text}"
    );
    assert!(second_text.contains("skipped_current: 2"), "{second_text}");
    assert_eq!(hs.lock().unwrap().puts, 1);

    // Counts only: not one account, DID, proof or credential in anything it printed.
    let everything = format!("{dry_text}\n{first_text}\n{second_text}");
    let stored = hs.lock().unwrap().profile.get(&ann).cloned().unwrap();
    let mut sensitive: Vec<String> = vec![
        ann.clone(),
        bob.clone(),
        cy.clone(),
        DID_ANN.to_string(),
        DID_BOB.to_string(),
        DID_CY.to_string(),
        "gone".to_string(),
        secret,
        current_pem.lines().nth(1).unwrap_or("pem").to_string(),
        stored["proof"].as_str().unwrap().to_string(),
        SERVER.to_string(),
    ];
    sensitive.retain(|s| !s.is_empty());
    for needle in &sensitive {
        assert!(
            !everything.contains(needle.as_str()),
            "the output must not carry {}...: {everything}",
            &needle[..needle.len().min(8)]
        );
    }
    // What it does print about itself is public: the issuer and the kid of the signing key.
    assert!(
        first_text.contains(&format!("signing kid: {}", current.kid())),
        "{first_text}"
    );

    std::fs::remove_dir_all(&setup.dir).ok();
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ephemeral_key_is_refused_before_the_homeserver_is_asked_anything() {
    let (hs, synapse_url, server) = homeserver().await;
    let setup = Setup {
        synapse_url,
        base_url: UNUSED_ISSUER.to_string(),
        pem: None,
        secret: random_secret(40),
        dir: temp_dir("remint-cli-ephemeral"),
    };

    let output = setup.run(Start::ByArgument, &["--apply"]);

    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    let shown = text(&output);
    assert!(shown.contains("ephemeral"), "{shown}");
    let hs = hs.lock().unwrap();
    assert_eq!(hs.list_requests, 0, "nothing was read");
    assert_eq!(hs.puts, 0, "nothing was written");
    std::fs::remove_dir_all(&setup.dir).ok();
    server.abort();
}

#[test]
fn an_argument_it_does_not_know_is_refused_without_echoing_its_value() {
    let setup = Setup {
        synapse_url: "http://127.0.0.1:1".to_string(),
        base_url: UNUSED_ISSUER.to_string(),
        pem: None,
        secret: random_secret(40),
        dir: temp_dir("remint-cli-args"),
    };
    let value = random_secret(24);

    let output = setup.run(Start::ByName, &[&format!("--bogus={value}")]);

    assert_eq!(output.status.code(), Some(2));
    let shown = text(&output);
    assert!(shown.contains("unknown argument"), "{shown}");
    assert!(!shown.contains(&value), "{shown}");
    std::fs::remove_dir_all(&setup.dir).ok();
}

/// The tool's key must be the one the server publishes. Otherwise `--apply` rewrites every
/// valid binding into one nobody can verify: a stale environment, or a run during a rotation
/// before the new key is live in `/jwk`. Refused before the homeserver is asked anything, in a
/// dry run too, with a fixed message.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_the_server_does_not_publish_is_refused_before_anything_is_read() {
    if redis().await.is_none() {
        return;
    }
    let current_pem = pem();
    let current = EcdsaSigningKey::from_pem(&current_pem).unwrap();
    let other = EcdsaSigningKey::from_pem(&pem()).unwrap();
    // A set that names the tool's kid for another public key.
    let mut forged = key_set(&[&other]);
    forged["keys"][0]["kid"] = json!(current.kid());
    let cases = [
        ("no key with the kid", key_set(&[&other])),
        ("the kid with another public key", forged),
    ];
    for (name, published) in cases {
        for args in [
            &["--delay-ms", "0"][..],
            &["--apply", "--delay-ms", "0"][..],
        ] {
            let (hs, synapse_url, server) = homeserver().await;
            hs.lock().unwrap().jwks = published.clone();
            let setup = Setup {
                base_url: format!("{synapse_url}/"),
                synapse_url,
                pem: Some(current_pem.clone()),
                secret: random_secret(40),
                dir: temp_dir("remint-cli-unpublished"),
            };

            let output = setup.run(Start::ByName, args);

            let shown = text(&output);
            assert_eq!(output.status.code(), Some(2), "{name}: {shown}");
            assert!(
                shown.contains("not in the key set the server publishes"),
                "{name}: {shown}"
            );
            assert!(!shown.contains(current.kid()), "{name}: {shown}");
            assert!(
                !shown.contains("DRY RUN") && !shown.contains("APPLY"),
                "{shown}"
            );
            let hs = hs.lock().unwrap();
            assert_eq!(hs.jwks_requests, 1, "{name}: it did look at the key set");
            assert_eq!(hs.reads, 0, "{name}: nothing was read");
            assert_eq!(hs.puts, 0, "{name}: nothing was written");
            std::fs::remove_dir_all(&setup.dir).ok();
            server.abort();
        }
    }
}

/// A key set that cannot be read is no proof that the key is published: refused the same way.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_key_set_is_refused_before_anything_is_read() {
    if redis().await.is_none() {
        return;
    }
    let (hs, synapse_url, server) = homeserver().await;
    let setup = Setup {
        synapse_url,
        // Nothing listens here.
        base_url: "http://127.0.0.1:1/".to_string(),
        pem: Some(pem()),
        secret: random_secret(40),
        dir: temp_dir("remint-cli-unreachable-keys"),
    };

    let output = setup.run(Start::ByArgument, &["--apply"]);

    let shown = text(&output);
    assert_eq!(output.status.code(), Some(2), "{shown}");
    assert!(shown.contains("could not be read"), "{shown}");
    let hs = hs.lock().unwrap();
    assert_eq!(hs.reads, 0, "nothing was read");
    assert_eq!(hs.puts, 0, "nothing was written");
    std::fs::remove_dir_all(&setup.dir).ok();
    server.abort();
}

// -- Starting the program: the arguments are read as bytes, never required to be text -----------

/// A non-UTF-8 argument: valid on Linux, and `std::env::args()` panics on it.
fn not_utf8() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![b'-', b'-', 0xff, 0xfe])
}

/// The tool refuses such an argument as it refuses any it does not know: exit code 2, a fixed
/// message, no value echoed, and no panic.
#[test]
fn the_tool_refuses_an_argument_that_is_not_utf8_without_panicking() {
    let setup = Setup {
        synapse_url: "http://127.0.0.1:1".to_string(),
        base_url: UNUSED_ISSUER.to_string(),
        pem: None,
        secret: random_secret(40),
        dir: temp_dir("remint-cli-not-utf8"),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
    command
        .arg0("remint-did-assertions")
        .arg(not_utf8())
        .current_dir(&setup.dir)
        .env_clear()
        .stdin(Stdio::null());

    let output = command.output().expect("spawn the tool");

    let shown = text(&output);
    assert_eq!(output.status.code(), Some(2), "{shown}");
    assert!(!shown.contains("panicked"), "{shown}");
    assert!(shown.contains("not valid UTF-8"), "{shown}");
    std::fs::remove_dir_all(&setup.dir).ok();
}

/// The normal start must not change: an argument the server never looked at, even one that is
/// not text, does not stop it. It is started the way `tests/graceful_shutdown.rs` starts it
/// (port 0, a Redis address nothing listens on, nothing from the caller's environment) and
/// must say where it listens.
#[test]
fn the_server_starts_with_an_argument_that_is_not_utf8() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;
    use std::time::Duration;

    let (reader, writer) = std::io::pipe().expect("create the output pipe");
    let mut child = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"))
        .arg(not_utf8())
        .env_clear()
        .env("SIWXOIDC_ADDRESS", "127.0.0.1")
        .env("SIWXOIDC_PORT", "0")
        .env("SIWXOIDC_BASE_URL", "http://localhost")
        .env("SIWXOIDC_REDIS_URL", "redis://127.0.0.1:1")
        .env("RUST_LOG", "siwx_oidc=info")
        .stdout(writer.try_clone().expect("share the pipe"))
        .stderr(writer)
        .spawn()
        .expect("spawn the server");
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut printed = Vec::new();
    let listening = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => {
                let found = line.contains("Listening on ");
                printed.push(line);
                if found {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };
    child.kill().ok();
    child.wait().ok();

    assert!(
        listening,
        "the server did not start; output:\n{}",
        printed.join("\n")
    );
}
