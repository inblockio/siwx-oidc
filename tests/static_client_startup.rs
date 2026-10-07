//! Start-up refuses a `default_clients` entry or a `mail_domain` the server could not honour
//! safely, and says which client and which rule.
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
const MAIL_REDIRECT: &str = r#""metadata":{"redirect_uris":["https://mail.example.org/cb"]}"#;

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
        stderr.contains("default_clients.broken: not a valid client entry"),
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
        stderr.contains("default_clients.nosecret: not a valid client entry")
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
        stderr.contains("default_clients.twice: not a valid client entry")
            && stderr.contains("both as a digest and in the clear"),
        "the refusal names the client and the rule:\n{stderr}"
    );
}

fn generic_entry(scopes: &str, extra: &str) -> String {
    format!(
        r#"{{"secret":"not-a-secret-test-fixture",{MAIL_REDIRECT},"class":"generic","allowed_scopes":{scopes}{extra}}}"#
    )
}

/// The environment of a deployment that has a Synapse, which a generic client needs, and
/// one generic client.
fn with_a_synapse(entry: String) -> [(&'static str, String); 2] {
    [
        (
            "SIWXOIDC_MAS_SHARED_SECRET",
            "not-a-secret-test-fixture".to_string(),
        ),
        ("SIWXOIDC_DEFAULT_CLIENTS__MAILER", entry),
    ]
}

#[test]
fn a_generic_client_without_openid_stops_start_up() {
    let stderr = refused_start(&with_a_synapse(generic_entry(r#"["profile"]"#, "")));
    assert!(
        stderr.contains("default_clients.mailer:") && stderr.contains("openid"),
        "the refusal names the client and the rule:\n{stderr}"
    );
}

#[test]
fn always_granted_scopes_outside_the_allowed_scopes_stop_start_up() {
    let stderr = refused_start(&with_a_synapse(generic_entry(
        r#"["openid"]"#,
        r#","always_granted_scopes":["io.inblock.mail"]"#,
    )));
    assert!(
        stderr.contains("default_clients.mailer:") && stderr.contains("always_granted_scopes"),
        "the refusal names the client and the rule:\n{stderr}"
    );
}

#[test]
fn a_generic_client_allowed_a_synapse_scope_stops_start_up() {
    let stderr = refused_start(&with_a_synapse(generic_entry(
        r#"["openid","urn:synapse:admin:*"]"#,
        "",
    )));
    assert!(
        stderr.contains("default_clients.mailer:") && stderr.contains("urn:synapse:admin:*"),
        "the refusal names the client and the scope:\n{stderr}"
    );
}

#[test]
fn a_generic_client_in_a_deployment_without_a_synapse_stops_start_up() {
    let stderr = refused_start(&[(
        "SIWXOIDC_DEFAULT_CLIENTS__MAILER",
        generic_entry(r#"["openid"]"#, ""),
    )]);
    assert!(
        stderr.contains("default_clients.mailer:") && stderr.contains("SIWXOIDC_MAS_SHARED_SECRET"),
        "the refusal names the client and the setting it needs:\n{stderr}"
    );
}

#[test]
fn a_mail_domain_that_is_not_a_lowercase_dns_name_stops_start_up() {
    let stderr = refused_start(&[("SIWXOIDC_MAIL_DOMAIN", "Mail.Example.org".to_string())]);
    assert!(
        stderr.contains("mail_domain") && stderr.contains("Mail.Example.org"),
        "the refusal names the setting and its value:\n{stderr}"
    );
}

#[test]
fn a_mail_domain_that_is_an_ip_address_stops_start_up() {
    let stderr = refused_start(&[("SIWXOIDC_MAIL_DOMAIN", "127.0.0.1".to_string())]);
    assert!(
        stderr.contains("mail_domain") && stderr.contains("127.0.0.1"),
        "the refusal names the setting and its value:\n{stderr}"
    );
}
