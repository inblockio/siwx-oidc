//! Secrets that come from files (`mas_shared_secret_file`, `redis_password_file`), through
//! the real binary: what it reads, what it refuses, and that no refusal or failure prints a
//! secret.
//!
//! Every secret here is generated per run. The refusal tests need no Redis (the spawned
//! server gets an address nothing listens on); the two that serve requests or connect to a
//! Redis use one of their own: a database of the test Redis, and a fake that records what
//! the client sends.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rand::Rng;
use siwx_oidc::test_support::{leaked_window, random_secret, redis_url_with_password};

/// The test Redis database these tests serve requests from. Taken: see `test_support::redis_db`.
const REDIS_DB: u8 = 3;

/// One case of the bad-setting test: what it is, the environment, the text the refusal must
/// hold (proof that it came from the case under test), and the secrets it must not hold.
type Case<'a> = (&'a str, Vec<(&'static str, String)>, &'a str, Vec<&'a str>);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A secret file in the temp dir, mode 0600, removed on drop.
struct SecretFile(PathBuf);

impl SecretFile {
    fn with(content: &str) -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "siwx-secret-files-test-{}",
            random_secret(24).to_lowercase()
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .unwrap();
        SecretFile(path)
    }

    fn path(&self) -> String {
        self.0.to_str().unwrap().to_string()
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The server with only `env` (and an address, a port and a base URL) set.
fn command(port: u16, env: &[(&str, String)]) -> Command {
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

/// Start the server and return what it printed to stderr once it has exited with a failure.
/// A server that keeps running means start-up accepted the configuration, and the test fails.
fn refused_start(env: &[(&str, String)]) -> String {
    let mut server = command(free_port(), env)
        .spawn()
        .expect("spawn the siwx-oidc binary");
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

/// Every secret in `secrets` is absent from `output`, as a whole and as any 16-character part.
fn assert_holds_none_of(output: &str, secrets: &[&str], what: &str) {
    for secret in secrets {
        assert!(
            !output.contains(secret),
            "{what}: the output holds a secret:\n{output}"
        );
        assert_eq!(
            leaked_window(output, secret),
            None,
            "{what}: the output holds part of a secret:\n{output}"
        );
    }
}

/// A server that is running, killed when dropped.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn started(port: u16, env: &[(&str, String)]) -> Server {
    let mut server = Server(
        command(port, env)
            .spawn()
            .expect("spawn the siwx-oidc binary"),
    );
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if let Some(status) = server.0.try_wait().unwrap() {
            let mut stderr = String::new();
            server
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .ok();
            panic!("the server exited ({status}) instead of listening:\n{stderr}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the server did not listen within 30 s"
        );
        sleep(Duration::from_millis(50));
    }
    server
}

// -- Refusals ----------------------------------------------------------------------------

#[test]
fn a_mas_secret_file_that_is_missing_or_empty_stops_start_up_naming_the_setting_and_the_path() {
    let missing = std::env::temp_dir().join(format!("siwx-missing-{}", random_secret(16)));
    let missing = missing.to_str().unwrap().to_string();
    let empty = SecretFile::with("\n");
    for (what, path) in [("missing", missing), ("empty", empty.path())] {
        let stderr = refused_start(&[("SIWXOIDC_MAS_SHARED_SECRET_FILE", path.clone())]);
        assert!(
            stderr.contains("FATAL")
                && stderr.contains("mas_shared_secret_file")
                && stderr.contains(&path),
            "{what}: the refusal names the setting and the path:\n{stderr}"
        );
    }
}

#[test]
fn a_mas_secret_given_inline_and_as_a_file_stops_start_up_and_prints_neither() {
    let (inline, in_file) = (random_secret(40), random_secret(40));
    let file = SecretFile::with(&format!("{in_file}\n"));
    // Both prefixes: the legacy name is the one live deployments set.
    for prefix in ["SIWXOIDC_", "SIWEOIDC_"] {
        let stderr = refused_start(&[
            (&format!("{prefix}MAS_SHARED_SECRET"), inline.clone()),
            (&format!("{prefix}MAS_SHARED_SECRET_FILE"), file.path()),
        ]);
        assert!(
            stderr.contains("mas_shared_secret_file") && stderr.contains("both set"),
            "{prefix}: {stderr}"
        );
        assert_holds_none_of(&stderr, &[&inline, &in_file], prefix);
    }
}

#[test]
fn a_redis_password_file_that_cannot_apply_stops_start_up_and_prints_no_password() {
    let (in_url, in_file) = (random_secret(40), random_secret(40));
    let file = SecretFile::with(&in_file);
    let cases = [
        (
            "a password in the URL",
            redis_url_with_password(&in_url, "redis.example.org:6379"),
            "both set",
        ),
        (
            "a URL with no host",
            "redis+unix:///run/redis.sock".to_string(),
            "cannot carry a password",
        ),
    ];
    for (what, url, rule) in cases {
        let stderr = refused_start(&[
            ("SIWXOIDC_REDIS_URL", url),
            ("SIWXOIDC_REDIS_PASSWORD_FILE", file.path()),
        ]);
        assert!(
            stderr.contains("FATAL") && stderr.contains("redis_") && stderr.contains(rule),
            "{what}: {stderr}"
        );
        assert_holds_none_of(&stderr, &[&in_url, &in_file], what);
    }
    let missing = std::env::temp_dir().join(format!("siwx-missing-{}", random_secret(16)));
    let missing = missing.to_str().unwrap().to_string();
    let stderr = refused_start(&[
        (
            "SIWXOIDC_REDIS_URL",
            "redis://redis.example.org".to_string(),
        ),
        ("SIWXOIDC_REDIS_PASSWORD_FILE", missing.clone()),
    ]);
    assert!(
        stderr.contains("redis_password_file") && stderr.contains(&missing),
        "{stderr}"
    );
}

/// A bad setting beside a real secret file: whatever refuses the start, and wherever it
/// does, the output holds no part of the secrets the start-up had read or been given.
#[test]
fn a_bad_setting_next_to_a_real_secret_file_never_prints_the_secret() {
    let (mas, redis, inline) = (random_secret(40), random_secret(40), random_secret(40));
    let mas_file = SecretFile::with(&format!("{mas}\n"));
    let redis_file = SecretFile::with(&format!("{redis}\n"));
    let files = || {
        [
            ("SIWXOIDC_MAS_SHARED_SECRET_FILE", mas_file.path()),
            ("SIWXOIDC_REDIS_PASSWORD_FILE", redis_file.path()),
        ]
    };
    // figment reads digits as a number up to the size of a u64: 19 digits is the longest
    // run that is at least one 16-character window and still read as a number.
    let digits = rand::thread_rng()
        .gen_range(10u64.pow(18)..10u64.pow(19))
        .to_string();
    let redirect = r#""metadata":{"redirect_uris":["https://app.example.org/cb"]}"#;
    let cases: Vec<Case> = vec![
        // The Redis URL, with the file's password in it, is refused by the Redis client.
        (
            "a Redis URL the client refuses",
            [(
                "SIWXOIDC_REDIS_URL",
                "redis://redis.example.org:6379/not-a-number".into(),
            )]
            .into_iter()
            .chain(files())
            .collect(),
            "Could not build Redis",
            vec![&mas, &redis],
        ),
        // The URL has its own password and a typo: its parse error must not quote it.
        (
            "an inline Redis URL that does not parse",
            [(
                "SIWXOIDC_REDIS_URL",
                redis_url_with_password(&inline, "redis.example.org:not-a-port"),
            )]
            .into_iter()
            .chain(files())
            .collect(),
            "redis_url",
            vec![&mas, &redis, &inline],
        ),
        // A static client entry that is not valid.
        (
            "a static client that is not JSON",
            [("SIWXOIDC_DEFAULT_CLIENTS__BROKEN", "not json".into())]
                .into_iter()
                .chain(files())
                .collect(),
            "default_clients.broken",
            vec![&mas, &redis],
        ),
        // A raw secret pasted into `secret_digest`.
        (
            "a raw secret in secret_digest",
            [(
                "SIWXOIDC_DEFAULT_CLIENTS__APP",
                format!(r#"{{"secret_digest":"{inline}",{redirect}}}"#),
            )]
            .into_iter()
            .chain(files())
            .collect(),
            "default_clients.app",
            vec![&mas, &redis, &inline],
        ),
        // A MAS secret figment reads as a number.
        (
            "a numeric inline MAS secret",
            [("SIWXOIDC_MAS_SHARED_SECRET", digits.clone())]
                .into_iter()
                .chain([("SIWXOIDC_REDIS_PASSWORD_FILE", redis_file.path())])
                .collect(),
            "mas_shared_secret",
            vec![&redis, &digits],
        ),
    ];
    for (what, env, expected, secrets) in cases {
        eprintln!("case: {what}");
        let stderr = refused_start(&env);
        assert!(
            stderr.to_lowercase().contains(&expected.to_lowercase()),
            "{what}: the refusal comes from the case under test ({expected}):\n{stderr}"
        );
        assert_holds_none_of(&stderr, &secrets, what);
    }
}

// -- Reads -------------------------------------------------------------------------------

/// The file's content (one newline removed) is the shared secret: the introspection
/// endpoint, which exists only in Matrix mode, accepts it as the bearer and refuses any
/// other. Needs Redis, on a database of its own.
#[tokio::test]
async fn the_mas_secret_file_is_the_secret_the_server_checks() {
    if siwx_oidc::test_support::redis_db(REDIS_DB).await.is_none() {
        return;
    }
    let secret = random_secret(48);
    let file = SecretFile::with(&format!("{secret}\r\n"));
    let port = free_port();
    let _server = started(
        port,
        &[
            (
                "SIWXOIDC_REDIS_URL",
                siwx_oidc::test_support::redis_db_url(REDIS_DB).to_string(),
            ),
            ("SIWXOIDC_MAS_SHARED_SECRET_FILE", file.path()),
        ],
    );
    let status = |bearer: String| async move {
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/oauth2/introspect"))
            .bearer_auth(bearer)
            .form(&[("token", "not-a-token")])
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(
        status(secret.clone()).await,
        200,
        "the file's secret is accepted"
    );
    assert_eq!(
        status(random_secret(48)).await,
        401,
        "another secret is refused"
    );
}

/// The password reaches the Redis server: a fake Redis records what the client sends first.
/// The password holds characters a URL must encode, and a `%` sequence, which the URL
/// encoder leaves alone and the client would decode.
#[test]
fn the_redis_password_file_is_what_the_client_sends_to_redis() {
    let password = format!("p%41:/@?#+ \u{e9}{}", random_secret(24));
    let file = SecretFile::with(&format!("{password}\n"));
    let fake = TcpListener::bind("127.0.0.1:0").unwrap();
    let redis_port = fake.local_addr().unwrap().port();
    fake.set_nonblocking(true).unwrap();
    let recorder = std::thread::spawn(move || {
        // A client that never connects must fail the test, not hang it.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut connection = loop {
            match fake.accept() {
                Ok((connection, _)) => break connection,
                Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(20)),
                Err(_) => return Vec::new(),
            }
        };
        connection.set_nonblocking(false).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut seen = Vec::new();
        let mut buffer = [0u8; 1024];
        // Answer every chunk with OK so a client that waits for a reply goes on.
        while let Ok(n @ 1..) = connection.read(&mut buffer) {
            seen.extend_from_slice(&buffer[..n]);
            if connection.write_all(b"+OK\r\n").is_err() {
                break;
            }
        }
        seen
    });
    let _server = started(
        free_port(),
        &[
            (
                "SIWXOIDC_REDIS_URL",
                format!("redis://127.0.0.1:{redis_port}"),
            ),
            ("SIWXOIDC_REDIS_PASSWORD_FILE", file.path()),
        ],
    );
    let seen = recorder.join().unwrap();
    let seen = String::from_utf8_lossy(&seen);
    assert!(
        seen.contains("AUTH") && seen.contains(&password),
        "the client did not AUTH with the file's password:\n{seen:?}"
    );
}

// -- A connect error ---------------------------------------------------------------------

/// The Redis client's own errors (a URL it refuses, a connection it cannot make) carry the
/// host and the cause and never the password. This pins the dependency: an upgrade that
/// starts quoting the URL fails here.
#[tokio::test]
async fn a_redis_connect_error_never_holds_the_password() {
    let password = random_secret(40);
    for url in [
        // Refused by the client at once.
        redis_url_with_password(&password, "redis.example.org:6379/not-a-number"),
        // Valid, and nothing listens there.
        redis_url_with_password(&password, "127.0.0.1:1"),
    ] {
        let url: url::Url = url.parse().unwrap();
        let client = bb8_redis::redis::Client::open(url.as_str());
        let error = match client {
            Err(e) => format!("{e} {e:?}"),
            Ok(client) => {
                let connect = client.get_multiplexed_async_connection();
                match tokio::time::timeout(Duration::from_secs(20), connect).await {
                    Ok(Err(e)) => format!("{e} {e:?}"),
                    other => panic!("the connect must fail: {:?}", other.map(|r| r.is_ok())),
                }
            }
        };
        assert!(!error.is_empty());
        assert_eq!(leaked_window(&error, &password), None, "{error}");
        // And through the server's own client, which wraps the same errors.
        let wrapped = siwx_oidc::db::RedisClient::new(&url).await;
        if let Err(e) = wrapped {
            let shown = format!("{e:#} {e:?}");
            assert_eq!(leaked_window(&shown, &password), None, "{shown}");
        }
    }
}
