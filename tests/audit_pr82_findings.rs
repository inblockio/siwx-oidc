//! Audit of the secret-files change: each test here fails on the audited head and names the
//! finding it pins. Every secret is generated per run.

#![cfg(unix)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rand::Rng;
use siwx_oidc::test_support::{
    leaked_window, random_secret, redis_db, redis_db_url, redis_url_with_password,
};

/// The free test Redis database (see `test_support::redis_db`).
const REDIS_DB: u8 = 1;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn server(port: u16, env: &[(&str, String)]) -> Command {
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
    command
}

fn stderr_of(child: &mut Child) -> String {
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
    stderr
}

/// Runs `command` until it exits; a process still running after 20 s is killed and the
/// test fails, since every case here must be refused at start.
fn refused(mut command: Command) -> String {
    let mut child = command.spawn().expect("spawn");
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = stderr_of(&mut child);
            assert!(!status.success(), "must fail; stderr:\n{stderr}");
            return stderr;
        }
        if started.elapsed() > Duration::from_secs(20) {
            child.kill().ok();
            child.wait().ok();
            panic!("start-up accepted the configuration");
        }
        sleep(Duration::from_millis(50));
    }
}

/// F1. The inline MAS variable set to the empty string (the compose `${VAR:-}` default once
/// the value moves to a file and the file variable is blank too) starts the server in Matrix
/// mode with an empty shared secret, and `/oauth2/introspect` then accepts an empty form
/// field in place of the shared secret.
/// Start-up must refuse an empty MAS shared secret as it refuses an empty file (or, second
/// best, treat it as unset); a shared-secret check against "" must never pass.
#[tokio::test]
async fn f1_an_empty_inline_mas_shared_secret_is_refused_at_start() {
    if redis_db(REDIS_DB).await.is_none() {
        return;
    }
    let port = free_port();
    let mut child = server(
        port,
        &[
            ("SIWXOIDC_REDIS_URL", redis_db_url(REDIS_DB).to_string()),
            ("SIWXOIDC_MAS_SHARED_SECRET", String::new()),
            ("SIWXOIDC_MAS_SHARED_SECRET_FILE", String::new()),
        ],
    )
    .spawn()
    .expect("spawn");
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = stderr_of(&mut child);
            assert!(!status.success(), "{stderr}");
            assert!(stderr.contains("mas_shared_secret"), "{stderr}");
            return;
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "neither exited nor listened"
        );
        sleep(Duration::from_millis(50));
    }
    let status = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/oauth2/introspect"))
        .form(&[("token", "not-a-token"), ("client_secret", "")])
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    child.kill().ok();
    child.wait().ok();
    // Either fix closes it: refuse the empty value at start (preferred), or treat it as
    // unset (the endpoint then answers 404). What must never happen is a 200.
    assert_ne!(
        status, 200,
        "start-up accepted an empty mas_shared_secret, and /oauth2/introspect answered \
         {status} to an empty client_secret"
    );
}

/// F2. The value of a `_file` setting is echoed in the refusal. An operator who puts the
/// secret itself into `SIWXOIDC_MAS_SHARED_SECRET_FILE` (or the Redis one) gets it printed:
/// as "the path" of a file that does not exist, or, for digits, in figment's type error.
#[test]
fn f2_a_secret_pasted_into_a_file_setting_is_never_printed() {
    let digits = rand::thread_rng()
        .gen_range(10u64.pow(17)..10u64.pow(18))
        .to_string();
    for setting in [
        "SIWXOIDC_MAS_SHARED_SECRET_FILE",
        "SIWXOIDC_REDIS_PASSWORD_FILE",
    ] {
        for value in [random_secret(32), digits.clone()] {
            let stderr = refused(server(free_port(), &[(setting, value.clone())]));
            assert!(
                !stderr.contains(&value) && leaked_window(&stderr, &value).is_none(),
                "{setting}: the refusal prints the value:\n{stderr}"
            );
        }
    }
}

/// F3. `redact_url` keeps the query, and a unix-socket Redis URL carries its password in
/// the `pass` query parameter (which `secret_file::url_carries_password` knows). The new
/// `migrate-credentials` endpoint lines and the boot log of `AQUA_WEBAUTHN_REDIS_URL` both
/// print through `redact_url`, so they print that password.
#[test]
fn f3_redact_url_drops_a_password_in_the_query() {
    let password = random_secret(40);
    for url in [
        format!("redis+unix:///run/redis.sock?db=2&pass={password}"),
        format!("unix:///run/redis.sock?pass={password}&db=2"),
    ] {
        let shown = siwx_oidc::redact::redact_url(&url);
        assert_eq!(
            leaked_window(&shown, &password),
            None,
            "redact_url keeps the password: {shown}"
        );
    }
}

/// F4. `migrate-credentials --source-redis=<url>` (the `=` form most CLIs take) is not
/// parsed, and the "unknown argument" error quotes the whole argument, password included.
///
/// The URLs name a database number the Redis client refuses at once, so the tool stops
/// after parsing its arguments, without a connection attempt (the pool of a Redis nobody
/// answers on retries for minutes). That the argument was understood is asserted too: a
/// refusal by the client, not "unknown argument". For `--target-redis` the source is given
/// the same way, as the tool connects to it first.
#[test]
fn f4_migrate_credentials_never_echoes_a_url_given_with_equals() {
    let password = random_secret(40);
    let refused_at_once =
        |password: &str| redis_url_with_password(password, "127.0.0.1:1/not-a-number");
    for flag in ["--source-redis", "--target-redis"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_migrate-credentials"));
        command.env_clear();
        if flag == "--target-redis" {
            command.arg(format!(
                "--source-redis={}",
                refused_at_once("not-a-secret")
            ));
        }
        let output = command
            .arg(format!("{flag}={}", refused_at_once(&password)))
            .output()
            .expect("run migrate-credentials");
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !shown.contains("unknown argument") && shown.contains("Redis"),
            "{flag}: the argument was not understood:\n{shown}"
        );
        assert_eq!(
            leaked_window(&shown, &password),
            None,
            "{flag}: the output holds the password:\n{shown}"
        );
    }
}
