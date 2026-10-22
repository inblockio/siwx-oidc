//! `SIWXOIDC_RELATED_ORIGINS` publishes WebAuthn related origins at
//! `GET /.well-known/webauthn` and does nothing else.
//!
//! Chrome 128+ lets a page on another origin call `navigator.credentials.get` with this
//! server's RP ID only when `https://<rp id>/.well-known/webauthn` lists that origin
//! (WebAuthn Level 3, "related origin requests"). These tests run the real binary, so they
//! prove the wiring in `axum_lib::main`, not just the parser (unit tests in `src/config.rs`):
//!
//! - the document: 200, `application/json`, exactly `{"origins":[...]}`, no cookie;
//! - the feature off (unset, empty, blank): the server starts and the path answers as any
//!   unrouted path does;
//! - a refused entry stops start-up and is named;
//! - the origins reach nothing else: the CORS answer is the same with and without them, and
//!   no module but the config, the route and the ceremony-invariance test mentions them
//!   (`related_origins_stay_out_of_every_other_module`; the ceremony origins of both RP arms
//!   are pinned in `src/webauthn.rs`, `related_origins_leave_the_ceremony_origins_of_both_rp_arms_unchanged`).
//!
//! They need no Redis: the server is pointed at an address nothing listens on, with the
//! caller's environment cleared (as in `graceful_shutdown`).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

const START_UP: Duration = Duration::from_secs(30);
const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";
const PATH: &str = "/.well-known/webauthn";

fn listening_port(line: &str) -> Option<u16> {
    let (_, rest) = line.split_once("Listening on ")?;
    let address = rest
        .split(|c: char| c.is_whitespace() || c == '\u{1b}')
        .next()?;
    address.parse::<SocketAddr>().ok().map(|a| a.port())
}

fn command(env: &[(&str, &str)]) -> Command {
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
    command
}

/// A running server; dropping it kills the process.
struct Server {
    child: Child,
    port: u16,
    /// Keeps the receiving end of the output pipe's reader alive: when the reader thread's
    /// channel closes the thread ends, the pipe closes, and the server's next log line fails.
    _output: Option<mpsc::Receiver<String>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Start the server with only `env` set and wait until it says where it listens.
fn start(env: &[(&str, &str)]) -> Server {
    let (reader, writer) = std::io::pipe().expect("create the server's output pipe");
    let mut command = command(env);
    command
        .stdout(writer.try_clone().expect("share the output pipe"))
        .stderr(writer);
    let child = command.spawn().expect("spawn the siwx-oidc binary");
    // Dropping `command` closes the parent's copies of the write end.
    drop(command);
    let mut server = Server {
        child,
        port: 0,
        _output: None,
    };

    let (sender, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + START_UP;
    let mut printed = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => {
                let port = listening_port(&line);
                printed.push(line);
                if let Some(port) = port {
                    server.port = port;
                    server._output = Some(lines);
                    return server;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                panic!(
                    "siwx-oidc did not listen within {START_UP:?}; output:\n{}",
                    printed.join("\n")
                )
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!(
                    "siwx-oidc exited before it listened (a feature that must not stop \
                     start-up did); output:\n{}",
                    printed.join("\n")
                )
            }
        }
    }
}

/// Start the server and return what it printed once it has exited with a failure. A server
/// that keeps running means start-up accepted the configuration, and the test fails.
fn refused_start(env: &[(&str, &str)]) -> String {
    let mut server = command(env)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
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

/// One answer: status, headers (names lower-cased) and body.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// `GET path` over a plain connection, with no cookie and the extra `headers`.
fn get(server: &Server, path: &str, headers: &[(&str, &str)]) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read the answer");
    let raw = String::from_utf8(raw).expect("a UTF-8 answer");
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("an incomplete answer: {raw:?}"));
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("a status line");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Answer {
        status,
        headers,
        body: body.to_string(),
    }
}

#[test]
fn the_document_lists_the_configured_origins_exactly() {
    // A repeat, a trailing slash and white space around entries are normalised away.
    let server = start(&[(
        "SIWXOIDC_RELATED_ORIGINS",
        " https://aqua-node.example.org , https://aquafier.example.net:8443/,https://aqua-node.example.org",
    )]);
    let answer = get(&server, PATH, &[]);
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert_eq!(
        answer.body,
        r#"{"origins":["https://aqua-node.example.org","https://aquafier.example.net:8443"]}"#
    );
    assert_eq!(
        answer.header("set-cookie"),
        None,
        "the document sets no cookie"
    );
}

#[test]
fn one_origin_is_a_one_element_list() {
    let server = start(&[("SIWXOIDC_RELATED_ORIGINS", "https://aqua-node.example.org")]);
    let answer = get(&server, PATH, &[]);
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.body,
        r#"{"origins":["https://aqua-node.example.org"]}"#
    );
}

#[test]
fn unset_empty_and_blank_leave_the_path_as_unrouted_as_before() {
    // `${SIWXOIDC_RELATED_ORIGINS:-}` in a compose file passes an empty string.
    for env in [
        vec![],
        vec![("SIWXOIDC_RELATED_ORIGINS", "")],
        vec![("SIWXOIDC_RELATED_ORIGINS", "   ")],
    ] {
        let server = start(&env);
        let answer = get(&server, PATH, &[]);
        let unrouted = get(&server, "/.well-known/not-served-here", &[]);
        assert_eq!(answer.status, 404, "{env:?}");
        assert_eq!(
            (answer.status, &answer.body, answer.header("content-type")),
            (
                unrouted.status,
                &unrouted.body,
                unrouted.header("content-type")
            ),
            "the feature off answers the path exactly as any unrouted path: {env:?}"
        );
        assert!(!answer.body.contains("origins"), "{env:?}");
    }
}

#[test]
fn a_refused_entry_stops_start_up_and_is_named() {
    let stderr = refused_start(&[(
        "SIWXOIDC_RELATED_ORIGINS",
        "https://aqua-node.example.org,http://plain.example.org",
    )]);
    assert!(
        stderr.contains("SIWXOIDC_RELATED_ORIGINS")
            && stderr.contains("entry 2")
            && stderr.contains("http://plain.example.org"),
        "the refusal names the setting and the entry:\n{stderr}"
    );
    let stderr = refused_start(&[("SIWXOIDC_RELATED_ORIGINS", "https://a.example.org/app")]);
    assert!(
        stderr.contains("https://a.example.org/app"),
        "the refusal names the entry:\n{stderr}"
    );
}

/// The origins are published in the document and reach no other answer: the CORS headers a
/// request from a listed origin gets are those a request from any origin gets, with the
/// feature on or off.
#[test]
fn related_origins_do_not_change_the_cors_answer() {
    let listed = "https://aqua-node.example.org";
    let on = start(&[("SIWXOIDC_RELATED_ORIGINS", listed)]);
    let off = start(&[]);
    for path in ["/health", "/.well-known/openid-configuration"] {
        for origin in [listed, "https://elsewhere.example.org"] {
            let cors = |server: &Server| {
                let answer = get(server, path, &[("Origin", origin)]);
                (
                    answer.status,
                    answer
                        .headers
                        .iter()
                        .filter(|(n, _)| n.starts_with("access-control-") || n == "vary")
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            };
            assert_eq!(cors(&on), cors(&off), "{path} from {origin}");
        }
    }
}

/// Which source files may name the setting. Anything else naming it would be a second use of
/// the origins, and the only use is the document.
#[test]
fn related_origins_stay_out_of_every_other_module() {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(files.len() > 20, "found the sources: {}", files.len());

    let mut users = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let text = std::fs::read_to_string(&file).unwrap();
        // webauthn.rs may name it in its test module only (the ceremony-invariance pin).
        let text = if relative == "webauthn.rs" {
            text.split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap()
                .to_string()
        } else {
            text
        };
        if text.contains("related_origin") || text.contains("RELATED_ORIGINS") {
            users.push(relative);
        }
    }
    users.sort();
    assert_eq!(
        users,
        ["axum_lib.rs", "config.rs"],
        "only the config (parse) and axum_lib (the document route) may use the related origins"
    );
}
