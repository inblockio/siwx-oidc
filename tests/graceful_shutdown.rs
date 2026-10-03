//! SIGTERM and SIGINT stop the server cleanly and promptly, and a request that
//! is in flight when the signal arrives is still answered.
//!
//! `docker stop` sends SIGTERM and SIGKILLs after a grace period (10 s by
//! default). In a container the server is PID 1, where the kernel drops a
//! signal that has no handler instead of terminating the process, so a fast,
//! clean stop depends entirely on the server's own handler
//! (`axum_lib::shutdown_signal`).
//!
//! These tests run the real binary. On the host it is not PID 1, so without the
//! handler a signal still ends it, but by the signal, not by `main` returning:
//! the exit-status assertion is what fails then. They need no Redis: the server
//! is pointed at an address nothing listens on, with the caller's environment
//! cleared, so no test can touch a real Redis. With no `default_clients` the
//! start-up prune runs against that address in the background and must neither
//! delay listening nor hold up shutdown. The in-flight request (`GET /resolve`
//! for an unregistered DID) asks only the homeserver, which the test plays
//! itself.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A Redis address nothing listens on: port 1 refuses at once. The spawned server is pointed
/// here so that it cannot reach a real Redis, whatever the caller's environment names.
const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

/// Start the server on a free port with `env` added; return it and its port.
///
/// The server gets only the environment set here, never the caller's: a caller's
/// `SIWXOIDC_REDIS_URL` (or the default `redis://localhost`) could name a Redis that holds
/// static clients, which a server started with no `default_clients` deletes.
fn spawn_server(env: &[(&str, String)]) -> (Child, u16) {
    let port = free_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
    command
        .env_clear()
        .env("SIWXOIDC_ADDRESS", "127.0.0.1")
        .env("SIWXOIDC_PORT", port.to_string())
        .env("SIWXOIDC_BASE_URL", format!("http://localhost:{port}"))
        .env("SIWXOIDC_REDIS_URL", UNREACHABLE_REDIS_URL)
        .env("RUST_LOG", "siwx_oidc=info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    (command.spawn().expect("spawn the siwx-oidc binary"), port)
}

/// Wait until the server accepts a connection, and return that connection.
fn connect_when_listening(server: &mut Child, port: u16) -> TcpStream {
    let started = Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            return stream;
        }
        if let Some(status) = server.try_wait().unwrap() {
            panic!("siwx-oidc exited before it listened: {status}");
        }
        if started.elapsed() > Duration::from_secs(30) {
            server.kill().ok();
            panic!("siwx-oidc did not listen on {port} within 30 s");
        }
        sleep(Duration::from_millis(50));
    }
}

fn send_signal(server: &Child, signal: &str) {
    let kill = Command::new("kill")
        .args([&format!("-{signal}"), &server.id().to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -{signal} failed: {kill}");
}

/// Wait for the server to exit, at most `within` after the signal.
fn wait_exit(server: &mut Child, signal: &str, within: Duration) -> ExitStatus {
    let signalled = Instant::now();
    loop {
        if let Some(status) = server.try_wait().unwrap() {
            return status;
        }
        if signalled.elapsed() > within {
            server.kill().ok();
            panic!("siwx-oidc still running {within:?} after SIG{signal}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn log_of(server: &mut Child) -> String {
    let mut log = String::new();
    server
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    log
}

/// Signal the server while a client holds an idle connection open, and
/// require a prompt exit with status 0 and a shutdown line naming the signal.
fn stops_cleanly_on(signal: &str) {
    let (mut server, port) = spawn_server(&[]);
    // Held open and silent across the signal: a client's idle keep-alive
    // connection must not keep the server alive until the SIGKILL.
    let idle = connect_when_listening(&mut server, port);

    send_signal(&server, signal);
    let status = wait_exit(&mut server, signal, Duration::from_secs(5));
    drop(idle);

    let log = log_of(&mut server);
    assert!(
        status.success(),
        "expected exit status 0 after SIG{signal}, got {status}; log:\n{log}"
    );
    assert!(
        log.contains("shutting down") && log.contains(&format!("SIG{signal}")),
        "no shutdown line naming SIG{signal} in the log:\n{log}"
    );
}

#[test]
fn sigterm_finishes_and_exits_zero_with_an_idle_connection_open() {
    stops_cleanly_on("TERM");
}

/// Ctrl-C in a terminal, and what some process managers send.
#[test]
fn sigint_finishes_and_exits_zero_with_an_idle_connection_open() {
    stops_cleanly_on("INT");
}

/// A listener nothing answers on, and the `redis://` URL that names it.
fn redis_trap() -> (TcpListener, String) {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let url = format!("redis://127.0.0.1:{}", trap.local_addr().unwrap().port());
    (trap, url)
}

/// Whether anything connects to `trap` within `within`.
fn connection_arrives(trap: &TcpListener, within: Duration) -> bool {
    let started = Instant::now();
    loop {
        if trap.accept().is_ok() {
            return true;
        }
        if started.elapsed() > within {
            return false;
        }
        sleep(Duration::from_millis(20));
    }
}

/// A variable set in this process, put back on drop.
struct CallerEnv {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl CallerEnv {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for CallerEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn stop(mut server: Child) {
    server.kill().ok();
    server.wait().ok();
}

/// With no `default_clients`, the one thing the server does with Redis at start-up is prune
/// the static clients an earlier configuration left there. A test server that inherited a
/// developer's `SIWXOIDC_REDIS_URL` (or the default `redis://localhost`) would delete the
/// static clients of that Redis, so the spawned server must never read the caller's
/// environment. The control makes "no connection" mean something: a server that is told a
/// Redis address does connect to it at start-up.
#[test]
fn a_spawned_server_never_reaches_the_redis_the_callers_environment_names() {
    let (told, told_url) = redis_trap();
    let (mut server, port) = spawn_server(&[("SIWXOIDC_REDIS_URL", told_url)]);
    drop(connect_when_listening(&mut server, port));
    let reached = connection_arrives(&told, Duration::from_secs(10));
    stop(server);
    assert!(
        reached,
        "control: a server given a Redis URL connects to it at start-up"
    );

    let (trap, trap_url) = redis_trap();
    let _caller = CallerEnv::set("SIWXOIDC_REDIS_URL", &trap_url);
    let (mut server, port) = spawn_server(&[]);
    drop(connect_when_listening(&mut server, port));
    let reached = connection_arrives(&trap, Duration::from_secs(2));
    stop(server);
    assert!(
        !reached,
        "the spawned server inherited the caller's SIWXOIDC_REDIS_URL and connected to it"
    );
}

/// `e2e/env.sh` exports a `default_clients` entry for the mock stack. A server that inherited
/// it would have to write it to Redis before listening, and the Redis it is pointed at is
/// unreachable, so it would exit after the pool's 30 s connection timeout and every test in
/// this file would fail. The spawned server must not see the caller's configuration at all.
#[test]
fn a_spawned_server_ignores_the_static_clients_in_the_callers_environment() {
    let _caller = CallerEnv::set(
        "SIWXOIDC_DEFAULT_CLIENTS__LEAKED",
        r#"{"secret":"not-a-secret-test-fixture","metadata":{"redirect_uris":["https://app.example.org/cb"]}}"#,
    );
    let (mut server, port) = spawn_server(&[]);
    drop(connect_when_listening(&mut server, port));
    stop(server);
}

/// A homeserver that answers every request with 200 `{}` after `delay`, and
/// reports each request line it receives.
fn slow_homeserver(delay: Duration) -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, requests) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let _ = seen.send(line);
                sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            });
        }
    });
    (port, requests)
}

/// "Finishes open requests" is the other half of a graceful stop: a lookup
/// that is waiting on the homeserver when SIGTERM arrives must still get its
/// full answer, and only then may the server exit (with status 0).
#[test]
fn a_request_in_flight_when_sigterm_arrives_is_still_answered() {
    let (homeserver, requests) = slow_homeserver(Duration::from_secs(1));
    let (mut server, port) = spawn_server(&[
        (
            "SIWXOIDC_SYNAPSE_ENDPOINT",
            format!("http://127.0.0.1:{homeserver}"),
        ),
        ("SIWXOIDC_MAS_SHARED_SECRET", "secret".to_string()),
        ("SIWXOIDC_MATRIX_SERVER_NAME", "example.org".to_string()),
    ]);
    drop(connect_when_listening(&mut server, port));

    // An unregistered DID: the lookup probes the homeserver twice (legacy,
    // then modern localpart), a second each, and needs nothing else.
    let lookup = thread::spawn(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(
                b"GET /resolve?did=did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a \
                  HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    });

    // The homeserver has the first probe: the lookup is in flight now.
    let first = requests
        .recv_timeout(Duration::from_secs(20))
        .expect("the lookup must reach the homeserver");
    assert!(first.contains("is_localpart_available"), "{first}");

    send_signal(&server, "TERM");
    let status = wait_exit(&mut server, "TERM", Duration::from_secs(10));
    let response = lookup.join().expect("the lookup thread");
    let log = log_of(&mut server);

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the request in flight must get its full answer, got:\n{response}\nlog:\n{log}"
    );
    assert!(
        response.contains(r#""exists":false"#),
        "the answer must be the lookup's own: {response}"
    );
    assert!(
        status.success(),
        "expected exit status 0 after SIGTERM, got {status}; log:\n{log}"
    );
}
