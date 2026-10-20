//! The `siwx-signer` binary as an operator runs it: `keygen`, `kid`,
//! `self-test` and `serve`, spawned as a process with an empty environment.
//!
//! Keys are generated at run time into a fresh temporary directory; nothing
//! here prints one. Hermetic: no Redis, no network, only a Unix socket in that
//! directory.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature};
use siwx_oidc::signing::protocol::{self, PublicAnswer, SignAnswer};
use siwx_oidc::signing::{EcdsaSigningKey, ProviderSigner, Purpose};
use siwx_oidc::test_support::{current_uid, temp_dir};

const BIN: &str = env!("CARGO_BIN_EXE_siwx-signer");
const START_UP: Duration = Duration::from_secs(30);

fn signer(args: &[&str]) -> Output {
    Command::new(BIN)
        .env_clear()
        .args(args)
        .output()
        .expect("run siwx-signer")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run `siwx-signer` with `args` and wait at most `limit` for it to end:
/// `None` when it was still running (it is killed then).
fn run_within(args: &[&str], limit: Duration) -> Option<Output> {
    let mut child = Command::new(BIN)
        .env_clear()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn siwx-signer");
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return Some(child.wait_with_output().unwrap());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// An empty file only its owner can read: what an operator pre-creates.
fn empty_private_file(path: &Path) {
    std::fs::File::create(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A key file written by `keygen`, and its kid.
fn generated_key(dir: &Path) -> (PathBuf, String) {
    let path = dir.join("signing_key");
    empty_private_file(&path);
    let out = signer(&["keygen", "--out", path.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", text(&out.stderr));
    let kid = text(&out.stdout)
        .trim()
        .strip_prefix("kid=")
        .expect("keygen prints kid=<kid>")
        .to_string();
    (path, kid)
}

#[test]
fn keygen_writes_a_pkcs8_key_into_an_existing_empty_file_and_prints_only_the_kid() {
    let dir = temp_dir("cli-keygen");
    let path = dir.join("signing_key");
    empty_private_file(&path);
    let out = signer(&["keygen", "--out", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "one line only");
    let kid = stdout.trim().strip_prefix("kid=").expect("kid=<kid>");
    assert_eq!(kid.len(), 16);
    assert!(kid.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(text(&out.stderr).is_empty(), "nothing else is printed");

    let pem = std::fs::read_to_string(&path).unwrap();
    assert!(
        <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pem).is_ok(),
        "a PKCS#8 PEM"
    );
    let key = EcdsaSigningKey::from_pem(&pem).expect("the provider loads it");
    assert_eq!(key.kid(), kid, "the kid is the provider's own derivation");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the operator's mode is kept");

    let out = signer(&["kid", "--key-file", path.to_str().unwrap()]);
    assert!(out.status.success());
    assert_eq!(
        text(&out.stdout),
        format!("kid={kid}\n"),
        "kid prints only the kid"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keygen_creates_nothing_and_overwrites_nothing() {
    let dir = temp_dir("cli-keygen-refusals");
    let missing = dir.join("missing");
    let out = signer(&["keygen", "--out", missing.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        !missing.exists(),
        "no O_CREAT: a missing file stays missing"
    );

    let full = dir.join("full");
    std::fs::write(&full, b"an existing key").unwrap();
    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = signer(&["keygen", "--out", full.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("not empty"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(std::fs::read(&full).unwrap(), b"an existing key");

    let open = dir.join("open");
    std::fs::File::create(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = signer(&["keygen", "--out", open.to_str().unwrap()]);
    assert!(!out.status.success(), "a file others can read is refused");
    assert_eq!(std::fs::metadata(&open).unwrap().len(), 0);

    let target = dir.join("target");
    empty_private_file(&target);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = signer(&["keygen", "--out", link.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("symlink"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        0,
        "never written through"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn self_test_passes_with_a_key_and_fails_without_printing_the_file() {
    let dir = temp_dir("cli-self-test");
    let (path, kid) = generated_key(&dir);
    let out = signer(&["self-test", "--key-file", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("self-test ok kid={kid}\n"));

    // A file that is not a key: its bytes never reach the output.
    let bad = dir.join("bad_key");
    let marker = "not-a-key-test-fixture-marker";
    std::fs::write(&bad, format!("{marker}\n")).unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    for command in ["self-test", "kid"] {
        let out = signer(&[command, "--key-file", bad.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{command}");
        let printed = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(
            !printed.contains(marker),
            "{command} printed the file: {printed}"
        );
        assert!(
            printed.contains("does not hold a PKCS#8 P-256 private key"),
            "{printed}"
        );
    }
    let out = signer(&[
        "self-test",
        "--key-file",
        dir.join("absent").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["sign"],
        &["serve", "--key-file", "k", "--socket", "s"],
        &["kid", "--key-file", "k", "--verbose", "1"],
        &["keygen"],
        &["self-test", "--key-file"],
    ] {
        let out = signer(args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    assert!(signer(&["--help"]).status.success());
}

/// A running `siwx-signer serve`; dropping it kills the process.
struct Serving {
    child: Child,
    lines: mpsc::Receiver<String>,
    printed: Vec<String>,
}

impl Serving {
    fn start(key: &Path, socket: &Path, allowed_uid: u32) -> Serving {
        let mut child = Command::new(BIN)
            .env_clear()
            .env("RUST_LOG", "info")
            .args([
                "serve",
                "--key-file",
                key.to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--issuer",
                "http://localhost",
            ])
            .arg(format!("--allowed-uid={allowed_uid}"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn siwx-signer serve");
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut serving = Serving {
            child,
            lines,
            printed: Vec::new(),
        };
        serving.wait_for("siwx-signer listening");
        serving
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + START_UP;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let found = line.contains(needle);
                    self.printed.push(line);
                    if found {
                        return;
                    }
                }
                Err(_) => panic!(
                    "siwx-signer never printed {needle:?}; output:\n{}",
                    self.printed.join("\n")
                ),
            }
        }
    }

    fn terminate(mut self) -> std::process::ExitStatus {
        // SAFETY: `kill` with a pid this test spawned and still holds.
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        let status = self.child.wait().unwrap();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(2)) {
            self.printed.push(line);
        }
        status
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn exchange(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    answer
}

#[test]
fn serve_answers_public_and_sign_on_a_0660_socket_and_cleans_up_on_sigterm() {
    let dir = temp_dir("cli-serve");
    let (key_path, kid) = generated_key(&dir);
    let key = EcdsaSigningKey::from_pem(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
    let socket = dir.join("signer.sock");
    // A socket a crashed run left behind is replaced, not an error.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());

    let serving = Serving::start(&key_path, &socket, current_uid());
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);

    // Non-dumpable: a process of the same uid cannot read its environment.
    if current_uid() != 0 {
        let environ = std::fs::read(format!("/proc/{}/environ", serving.child.id()));
        assert!(
            environ.is_err(),
            "PR_SET_DUMPABLE=0 keeps /proc/<pid>/environ from the same uid"
        );
    }

    let public: PublicAnswer =
        protocol::parse_answer(&exchange(&socket, &protocol::public_request()))
            .unwrap()
            .unwrap();
    assert_eq!(public.kid, kid);

    let now = chrono::Utc::now().timestamp();
    let msg = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid}))
                .unwrap()
        ),
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"iss": "http://localhost/",
                "sub": "did:key:zSubject", "mxid": "@u:example.org", "iat": now}))
            .unwrap()
        )
    );
    let signed: SignAnswer = protocol::parse_answer(&exchange(
        &socket,
        &protocol::sign_request(Purpose::DidProof, msg.as_bytes()),
    ))
    .unwrap()
    .expect("a DID proof of the emitted shape is signed");
    let raw = URL_SAFE_NO_PAD.decode(signed.sig).unwrap();
    ProviderSigner::verifying_key(&key)
        .verify(msg.as_bytes(), &Signature::from_slice(&raw).unwrap())
        .expect("verifies with the key file's key");

    let status = serving.terminate();
    assert!(status.success(), "SIGTERM is a clean stop: {status}");
    assert!(!socket.exists(), "the socket goes with the process");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_refuses_a_peer_of_another_uid_and_logs_it() {
    let dir = temp_dir("cli-peer");
    let (key_path, _) = generated_key(&dir);
    let socket = dir.join("signer.sock");
    let mut serving = Serving::start(&key_path, &socket, current_uid().wrapping_add(1));
    let answer = exchange(&socket, &protocol::public_request());
    assert!(answer.is_empty(), "no answer to another uid");
    serving.wait_for(&format!("peer_refused uid={}", current_uid()));
    let printed = serving.printed.join("\n");
    assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_refuses_to_replace_a_file_that_is_not_a_socket() {
    let dir = temp_dir("cli-not-socket");
    let (key_path, _) = generated_key(&dir);
    let socket = dir.join("signer.sock");
    std::fs::write(&socket, b"keep me").unwrap();
    let out = Command::new(BIN)
        .env_clear()
        .args([
            "serve",
            "--key-file",
            key_path.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--issuer",
            "http://localhost",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("not a socket"));
    assert_eq!(std::fs::read(&socket).unwrap(), b"keep me");
    let _ = std::fs::remove_dir_all(&dir);
}

/// AUDIT PR83 F7: `keygen` checks the file type only after `open`, and opens
/// without `O_NONBLOCK`, so a FIFO at `--out` blocks it forever (it waits for a
/// reader). It also writes into a file with a second hard link, so the key
/// exists under a name the operator did not choose.
#[test]
fn audit_pr83_keygen_refuses_a_fifo_at_once_and_a_hard_linked_file() {
    let dir = temp_dir("cli-keygen-audit");
    let fifo = dir.join("fifo");
    let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let finished = run_within(
        &["keygen", "--out", fifo.to_str().unwrap()],
        Duration::from_secs(3),
    )
    .map(|out| out.status);
    assert!(
        finished.is_some_and(|s| !s.success()),
        "keygen refuses a FIFO at once instead of blocking on it"
    );

    let first = dir.join("first");
    empty_private_file(&first);
    let second = dir.join("second");
    std::fs::hard_link(&first, &second).unwrap();
    let out = signer(&["keygen", "--out", second.to_str().unwrap()]);
    let written = std::fs::metadata(&first).unwrap().len();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success() && written == 0,
        "keygen refuses a file with more than one link (wrote {written} bytes)"
    );
}

/// AUDIT PR83 F8 (adapted to the fix): two signers on one socket path. A
/// second signer started while the first still serves the socket refuses to
/// take it over and exits, and the first keeps answering. When a new signer
/// has replaced the socket anyway (the old one stopped accepting, the new one
/// found it dead and bound), the old one's shutdown leaves the new socket in
/// place: it removes only the socket file it bound.
#[test]
fn audit_pr83_an_old_signer_stopping_leaves_the_new_signers_socket() {
    let dir = temp_dir("cli-serve-overlap");
    let (key_path, _kid) = generated_key(&dir);
    let socket = dir.join("signer.sock");
    let old = Serving::start(&key_path, &socket, current_uid());

    let uid = format!("--allowed-uid={}", current_uid());
    let second = run_within(
        &[
            "serve",
            "--key-file",
            key_path.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--issuer",
            "http://localhost",
            &uid,
        ],
        Duration::from_secs(10),
    )
    .expect("a second signer on a served socket exits at once");
    assert_eq!(second.status.code(), Some(1), "{}", text(&second.stderr));
    assert!(
        text(&second.stderr).contains("served by a running signer"),
        "{}",
        text(&second.stderr)
    );
    let answer = exchange(&socket, &protocol::public_request());
    assert!(
        protocol::parse_answer::<PublicAnswer>(&answer)
            .unwrap()
            .is_ok(),
        "the first signer still answers"
    );

    // The overlap the refusal cannot see: the new socket is bound at the path.
    std::fs::remove_file(&socket).unwrap();
    let new = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let _ = old.terminate();
    let reachable = UnixStream::connect(&socket).is_ok();
    drop(new);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        reachable,
        "the new signer's socket survives the old signer's shutdown"
    );
}

/// AUDIT PR83 I3: a key file that group or others can read is refused by
/// every subcommand that loads one, and the refusal prints no key byte.
#[test]
fn a_key_file_others_can_read_is_refused_by_serve_self_test_and_kid() {
    let dir = temp_dir("cli-key-mode");
    let (key_path, _kid) = generated_key(&dir);
    let pem = std::fs::read_to_string(&key_path).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let key = key_path.to_str().unwrap();
    let socket = dir.join("signer.sock");
    for args in [
        vec!["self-test", "--key-file", key],
        vec!["kid", "--key-file", key],
        vec![
            "serve",
            "--key-file",
            key,
            "--socket",
            socket.to_str().unwrap(),
            "--issuer",
            "http://localhost",
        ],
    ] {
        let out = run_within(&args, Duration::from_secs(10)).expect("refused at once");
        let printed = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{args:?}: {printed}");
        assert!(
            printed.contains("open to group or others (mode 640)"),
            "{args:?}: {printed}"
        );
        assert!(!printed.contains("PRIVATE KEY"), "{args:?}");
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(!printed.contains(line), "{args:?} printed key bytes");
        }
    }
    assert!(!socket.exists(), "serve bound nothing");
    // 0400 is fine: only the owner can read it.
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(signer(&["self-test", "--key-file", key]).status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
