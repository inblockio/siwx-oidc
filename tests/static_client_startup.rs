//! Start-up refuses a `default_clients` entry it cannot read as a client, and names it.
//!
//! These tests run the real binary and need no Redis: the entries are read before anything
//! is written, so the refusal comes whether or not Redis is reachable. The spawned server
//! gets only the environment set here, and a Redis address nothing listens on.

#![cfg(unix)]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const REDIRECT: &str = r#""metadata":{"redirect_uris":["https://app.example.org/cb"]}"#;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start the server with only `env` set and return what it printed to stderr once it has
/// exited with a failure. A server that keeps running means start-up accepted the
/// configuration, and the test fails.
fn refused_start(env: &[(&str, String)]) -> String {
    let port = free_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
    command
        .env_clear()
        .env("SIWXOIDC_ADDRESS", "127.0.0.1")
        .env("SIWXOIDC_PORT", port.to_string())
        .env("SIWXOIDC_BASE_URL", format!("http://localhost:{port}"))
        .env("SIWXOIDC_REDIS_URL", "redis://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut server = command.spawn().expect("spawn the siwx-oidc binary");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = server.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(20) {
            server.kill().ok();
            panic!("start-up accepted the configuration: the server was still running after 20 s");
        }
        sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(!status.success(), "start-up must fail; stderr:\n{stderr}");
    stderr
}

#[test]
fn a_default_client_that_is_not_json_stops_start_up() {
    let stderr = refused_start(&[("SIWXOIDC_DEFAULT_CLIENTS__BROKEN", "not json".to_string())]);
    assert!(
        stderr.contains("default_clients.broken is not a valid client entry"),
        "the refusal names the client:\n{stderr}"
    );
}

#[test]
fn a_default_client_without_a_secret_stops_start_up() {
    let stderr = refused_start(&[(
        "SIWXOIDC_DEFAULT_CLIENTS__NOSECRET",
        format!("{{{REDIRECT}}}"),
    )]);
    assert!(
        stderr.contains("default_clients.nosecret is not a valid client entry")
            && stderr.contains("no secret"),
        "the refusal names the client and says what is missing:\n{stderr}"
    );
}

#[test]
fn a_default_client_holding_its_secret_twice_stops_start_up() {
    let stderr = refused_start(&[(
        "SIWXOIDC_DEFAULT_CLIENTS__TWICE",
        format!(
            r#"{{"secret":"not-a-secret-test-fixture","secret_digest":"{}",{REDIRECT}}}"#,
            "0".repeat(64)
        ),
    )]);
    assert!(
        stderr.contains("default_clients.twice is not a valid client entry")
            && stderr.contains("both as a digest and in the clear"),
        "the refusal names the client and the rule:\n{stderr}"
    );
}
