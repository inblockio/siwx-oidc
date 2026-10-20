//! What `siwx-oidc` does at start for each `signing_backend`: the one start
//! line `signing backend=<name> kid=<kid>`, the configurations it refuses, and
//! the `socket` backend's start check against a real `siwx-signer` process.
//!
//! The server is spawned with an empty environment and an unreachable Redis,
//! as in `graceful_shutdown.rs`; the signer with a key generated at run time
//! into a fresh temporary directory. Hermetic.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use siwx_oidc::test_support::{current_uid, temp_dir};

const START_UP: Duration = Duration::from_secs(30);
/// Port 1 refuses at once: the server can reach no Redis.
const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

/// A spawned process and its output, stdout and stderr merged. Dropping it
/// kills the process.
struct Process {
    child: Child,
    lines: mpsc::Receiver<String>,
    printed: Vec<String>,
}

impl Process {
    fn spawn(mut command: Command) -> Process {
        let (reader, writer) = std::io::pipe().expect("an output pipe");
        command
            .stdout(writer.try_clone().expect("share the pipe"))
            .stderr(writer)
            .stdin(Stdio::null());
        let child = command.spawn().expect("spawn");
        drop(command);
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Process {
            child,
            lines,
            printed: Vec::new(),
        }
    }

    /// Wait for a line containing `needle`; `None` when the process ended first.
    fn wait_for(&mut self, needle: &str) -> Option<String> {
        let deadline = Instant::now() + START_UP;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let line = plain(&line);
                    let found = line.contains(needle);
                    self.printed.push(line.clone());
                    if found {
                        return Some(line);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) => {
                    panic!(
                        "no {needle:?} within {START_UP:?}; output:\n{}",
                        self.output()
                    )
                }
            }
        }
    }

    /// Wait for the process to exit; its status and everything it printed.
    fn exit(mut self) -> (std::process::ExitStatus, String) {
        let deadline = Instant::now() + START_UP;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "did not exit within {START_UP:?}; output:\n{}",
                self.output()
            );
            thread::sleep(Duration::from_millis(20));
        };
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(2)) {
            self.printed.push(plain(&line));
        }
        (status, self.output())
    }

    fn output(&self) -> String {
        self.printed.join("\n")
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server(env: &[(&str, &str)]) -> Process {
    let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
    command
        .env_clear()
        .env("SIWXOIDC_ADDRESS", "127.0.0.1")
        .env("SIWXOIDC_PORT", "0")
        .env("SIWXOIDC_BASE_URL", "http://localhost")
        .env("SIWXOIDC_REDIS_URL", UNREACHABLE_REDIS_URL)
        .env("RUST_LOG", "siwx_oidc=info");
    for (key, value) in env {
        command.env(key, value);
    }
    Process::spawn(command)
}

/// Strip ANSI escapes so a log line reads as text.
fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The `signing backend=… kid=…` line's two values.
fn backend_line(server: &mut Process) -> (String, String) {
    let line = server
        .wait_for("signing backend=")
        .unwrap_or_else(|| panic!("no signing line; output:\n{}", server.output()));
    let value = |name: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name}= in {line:?}"))
            .to_string()
    };
    (value("backend"), value("kid"))
}

fn listening_port(server: &mut Process) -> u16 {
    let line = server
        .wait_for("Listening on ")
        .unwrap_or_else(|| panic!("never listened; output:\n{}", server.output()));
    let (_, rest) = line.split_once("Listening on ").unwrap();
    rest.split_whitespace()
        .next()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap()
        .port()
}

fn test_pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    p256::SecretKey::random(&mut rand::thread_rng())
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

/// Generate a key with `siwx-signer keygen` and serve it on `socket` for this
/// process's uid, for the issuer `http://localhost` unless `env` says
/// otherwise. Returns the signer and the key's kid.
fn start_signer(dir: &Path, socket: &Path, env: &[(&str, &str)]) -> (Process, String) {
    let bin = env!("CARGO_BIN_EXE_siwx-signer");
    let key = dir.join("signing_key");
    std::fs::File::create(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(bin)
        .env_clear()
        .args(["keygen", "--out", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let kid = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .strip_prefix("kid=")
        .unwrap()
        .to_string();
    let mut command = Command::new(bin);
    command
        .env_clear()
        .env("SIWX_SIGNER_KEY_FILE", &key)
        .env("SIWX_SIGNER_SOCKET", socket)
        .env("SIWX_SIGNER_ISSUER", "http://localhost")
        .env("SIWX_SIGNER_ALLOWED_UID", current_uid().to_string())
        .arg("serve");
    for (key, value) in env {
        command.env(key, value);
    }
    let mut signer = Process::spawn(command);
    signer
        .wait_for("siwx-signer listening")
        .expect("the signer starts");
    (signer, kid)
}

#[test]
fn the_unset_backend_starts_as_before_and_names_its_backend() {
    let mut ephemeral = server(&[]);
    let (backend, kid) = backend_line(&mut ephemeral);
    assert_eq!(backend, "ephemeral");
    assert_eq!(kid.len(), 16);
    assert!(
        ephemeral
            .output()
            .contains("Generated ephemeral ES256 signing key"),
        "today's warning is kept: {}",
        ephemeral.output()
    );
    listening_port(&mut ephemeral);

    let pem = test_pem();
    let mut durable = server(&[("SIWXOIDC_SIGNING_KEY_PEM", &pem)]);
    let (backend, kid) = backend_line(&mut durable);
    assert_eq!(backend, "pem");
    assert_eq!(
        kid,
        siwx_oidc::signing::EcdsaSigningKey::from_pem(&pem)
            .unwrap()
            .kid()
    );
    listening_port(&mut durable);
    assert!(
        !durable.output().contains("PRIVATE KEY"),
        "{}",
        durable.output()
    );
}

/// The `socket` backend asks the signer for its key at start: the JWKS
/// publishes the signer's kid, and nothing in the start log says "ephemeral".
#[test]
fn the_socket_backend_starts_with_the_signers_key_and_publishes_it() {
    let dir = temp_dir("startup-socket");
    let socket = dir.join("signer.sock");
    let (_signer, kid) = start_signer(&dir, &socket, &[]);
    let socket = socket.to_str().unwrap().to_string();
    let mut server = server(&[
        ("SIWXOIDC_SIGNING_BACKEND", "socket"),
        ("SIWXOIDC_SIGNER_SOCKET", &socket),
    ]);
    assert_eq!(
        backend_line(&mut server),
        ("socket".to_string(), kid.clone())
    );
    let port = listening_port(&mut server);
    let output = server.output().to_lowercase();
    assert!(!output.contains("ephemeral"), "no ephemeral line: {output}");

    let jwks: serde_json::Value = reqwest::blocking_get_json(port);
    assert_eq!(jwks["keys"][0]["kid"], kid.as_str(), "{jwks}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_socket_backend_refuses_to_start_without_a_signer_or_with_a_pem() {
    let dir = temp_dir("startup-refusals");
    let absent = dir.join("absent.sock");
    let absent = absent.to_str().unwrap();
    let (status, output) = server(&[
        ("SIWXOIDC_SIGNING_BACKEND", "socket"),
        ("SIWXOIDC_SIGNER_SOCKET", absent),
    ])
    .exit();
    assert!(!status.success(), "{output}");
    assert!(output.contains("asking the signer"), "{output}");
    assert!(!output.contains("Listening on"), "{output}");

    let pem = test_pem();
    let (status, output) = server(&[
        ("SIWXOIDC_SIGNING_BACKEND", "socket"),
        ("SIWXOIDC_SIGNER_SOCKET", absent),
        ("SIWEOIDC_SIGNING_KEY_PEM", &pem),
    ])
    .exit();
    assert!(!status.success(), "{output}");
    assert!(
        output.contains("socket refuses signing_key_pem"),
        "{output}"
    );
    assert!(
        !output.contains("PRIVATE KEY"),
        "the refusal names no value"
    );

    let (status, output) = server(&[("SIWXOIDC_SIGNING_BACKEND", "socket")]).exit();
    assert!(!status.success());
    assert!(output.contains("needs signer_socket"), "{output}");

    let (status, output) = server(&[("SIWXOIDC_SIGNING_BACKEND", "pem")]).exit();
    assert!(!status.success());
    assert!(output.contains("needs signing_key_pem"), "{output}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// AUDIT PR83 F5: the signer's `public` answer names its issuer and its
/// longest token lifetime, and the server refuses to start when the signer
/// would refuse every token it asks for: another issuer, an
/// `id_token_ttl_secs` above the signer's limit, or 0. Without the check the
/// signer's healthcheck stays green while every sign-in fails.
#[test]
fn the_socket_backend_refuses_a_signer_for_another_issuer_or_a_lifetime_it_will_not_sign() {
    let dir = temp_dir("startup-fits");
    let socket = dir.join("signer.sock");
    let (_signer, _kid) = start_signer(
        &dir,
        &socket,
        &[("SIWX_SIGNER_MAX_TOKEN_LIFETIME_SECS", "600")],
    );
    let socket = socket.to_str().unwrap().to_string();
    let backend = [
        ("SIWXOIDC_SIGNING_BACKEND", "socket"),
        ("SIWXOIDC_SIGNER_SOCKET", socket.as_str()),
    ];
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut env: Vec<(&str, &str)> = backend.to_vec();
        env.extend_from_slice(extra);
        server(&env).exit()
    };

    let (status, output) = with(&[("SIWXOIDC_ID_TOKEN_TTL_SECS", "601")]);
    assert!(!status.success(), "{output}");
    assert!(
        output.contains("id_token_ttl_secs (SIWXOIDC_ID_TOKEN_TTL_SECS) is 601 s, above the signer's limit of 600 s"),
        "{output}"
    );
    assert!(!output.contains("Listening on"), "{output}");

    let (status, output) = with(&[("SIWXOIDC_ID_TOKEN_TTL_SECS", "0")]);
    assert!(!status.success(), "{output}");
    assert!(
        output.contains("SIWXOIDC_ID_TOKEN_TTL_SECS) is 0"),
        "{output}"
    );

    let (status, output) = with(&[("SIWXOIDC_BASE_URL", "http://other.localhost")]);
    assert!(!status.success(), "{output}");
    assert!(
        output.contains("the signer signs for issuer \"http://localhost/\""),
        "{output}"
    );

    // The same signer with a lifetime it signs: the server starts.
    let mut fits = server(&[
        ("SIWXOIDC_SIGNING_BACKEND", "socket"),
        ("SIWXOIDC_SIGNER_SOCKET", socket.as_str()),
        ("SIWXOIDC_ID_TOKEN_TTL_SECS", "600"),
    ]);
    assert_eq!(backend_line(&mut fits).0, "socket");
    listening_port(&mut fits);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tiny blocking GET of `/jwk` on the spawned server.
mod reqwest {
    pub fn blocking_get_json(port: u16) -> serde_json::Value {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            ::reqwest::get(format!("http://127.0.0.1:{port}/jwk"))
                .await
                .expect("GET /jwk")
                .json()
                .await
                .expect("a JSON JWKS")
        })
    }
}
