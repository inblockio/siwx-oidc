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
//!
//! The server is started on port 0 and the test reads the port it got from the
//! server's `Listening on` line. The server logs that line after the bind and
//! after the signal handlers are installed, so once it appears the port accepts
//! and a signal is handled, and the test cannot be talking to anything but the
//! server. Picking a free port in the test and passing the number on gives
//! neither: between the test releasing the port and the server binding it, any
//! other listener on the machine can be handed the same number, and the test
//! then connects to that listener, signals a server that is still starting, or
//! finds the server dead with "address already in use".

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

/// How long a server may take to log where it listens, or to refuse to start.
const START_UP: Duration = Duration::from_secs(30);

/// A Redis address nothing listens on: port 1 refuses at once. The spawned server is pointed
/// here so that it cannot reach a real Redis, whatever the caller's environment names.
const UNREACHABLE_REDIS_URL: &str = "redis://127.0.0.1:1";

/// The port named by a `Listening on <address>` log line.
fn listening_port(line: &str) -> Option<u16> {
    let (_, rest) = line.split_once("Listening on ")?;
    let address = rest
        .split(|c: char| c.is_whitespace() || c == '\u{1b}')
        .next()?;
    address.parse::<SocketAddr>().ok().map(|a| a.port())
}

/// A running server. Dropping it kills the process, so a failed assertion leaves none behind.
struct Server {
    child: Child,
    port: u16,
    /// What the server prints, stdout and stderr in the order it wrote them.
    lines: mpsc::Receiver<String>,
    printed: Vec<String>,
}

impl Server {
    /// Start the server on port 0 with `env` added, without waiting for it to listen.
    ///
    /// The server gets only the environment set here, never the caller's: a caller's
    /// `SIWXOIDC_REDIS_URL` (or the default `redis://localhost`) could name a Redis that holds
    /// static clients, which a server started with no `default_clients` deletes.
    fn spawn(env: &[(&str, String)]) -> Server {
        let (reader, writer) = std::io::pipe().expect("create the server's output pipe");
        let mut command = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"));
        command
            .env_clear()
            .env("SIWXOIDC_ADDRESS", "127.0.0.1")
            .env("SIWXOIDC_PORT", "0")
            .env("SIWXOIDC_BASE_URL", "http://localhost")
            .env("SIWXOIDC_REDIS_URL", UNREACHABLE_REDIS_URL)
            .env("RUST_LOG", "siwx_oidc=info")
            .env("RUST_BACKTRACE", "1")
            .stdout(writer.try_clone().expect("share the output pipe"))
            .stderr(writer);
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command.spawn().expect("spawn the siwx-oidc binary");

        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Server {
            child,
            port: 0,
            lines,
            printed: Vec::new(),
        }
    }

    /// Start the server and wait until it says where it listens.
    fn start(env: &[(&str, String)]) -> Server {
        let mut server = Server::spawn(env);
        server.port = server.wait_until_listening();
        server
    }

    fn wait_until_listening(&mut self) -> u16 {
        let deadline = Instant::now() + START_UP;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let port = listening_port(&line);
                    self.printed.push(line);
                    if let Some(port) = port {
                        assert_ne!(
                            port,
                            0,
                            "the server named the address it was asked for, not the one it bound; output:\n{}",
                            self.output()
                        );
                        return port;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!(
                        "siwx-oidc did not say where it listens within {START_UP:?}; output:\n{}",
                        self.output()
                    );
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.child.kill().ok();
                    let status = self.child.wait().expect("wait for the server");
                    panic!(
                        "siwx-oidc exited before it listened: {status}; output:\n{}",
                        self.output()
                    );
                }
            }
        }
    }

    /// A connection the server has accepted and answered once, now idle: the keep-alive
    /// connection of a client between two requests.
    fn idle_connection(&self) -> TcpStream {
        let mut stream =
            TcpStream::connect(("127.0.0.1", self.port)).expect("connect to the server");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream
                .read_exact(&mut byte)
                .expect("the server answers /health");
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "unexpected answer from /health: {}",
            String::from_utf8_lossy(&head)
        );
        stream.set_read_timeout(None).unwrap();
        stream
    }

    fn send_signal(&self, signal: &str) {
        let kill = Command::new("kill")
            .args([&format!("-{signal}"), &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(kill.success(), "kill -{signal} failed: {kill}");
    }

    /// Wait for the server to exit, at most `within` from now; `after` says what it was waiting for.
    fn wait_exit(&mut self, after: &str, within: Duration) -> ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                started.elapsed() <= within,
                "siwx-oidc still running {within:?} after {after}; output:\n{}",
                self.output()
            );
            sleep(Duration::from_millis(20));
        }
    }

    /// Everything the server has printed so far.
    fn output(&mut self) -> String {
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.printed.push(line);
        }
        self.printed.join("\n")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Signal the server while a client holds an idle connection open, and
/// require a prompt exit with status 0 and a shutdown line naming the signal.
fn stops_cleanly_on(signal: &str) {
    let mut server = Server::start(&[]);
    // Held open and silent across the signal: a client's idle keep-alive
    // connection must not keep the server alive until the SIGKILL. The server
    // has answered it, so it has accepted it.
    let idle = server.idle_connection();

    server.send_signal(signal);
    let status = server.wait_exit(&format!("SIG{signal}"), Duration::from_secs(5));
    drop(idle);

    let log = server.output();
    assert!(
        status.success(),
        "expected exit status 0 after SIG{signal}, got {status}; output:\n{log}"
    );
    assert!(
        log.contains("shutting down") && log.contains(&format!("SIG{signal}")),
        "no shutdown line naming SIG{signal} in the output:\n{log}"
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

/// The server logs where it listens only after it has bound, so a server that cannot bind must
/// say which address it tried: that is all an operator has to go on.
#[test]
fn a_server_that_cannot_bind_says_which_address() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let mut server = Server::spawn(&[("SIWXOIDC_PORT", port.to_string())]);

    let status = server.wait_exit("start-up", START_UP);
    let log = server.output();
    drop(taken);

    assert!(
        !status.success(),
        "a server whose port is taken must not start; output:\n{log}"
    );
    assert!(
        log.contains(&format!("could not bind 127.0.0.1:{port}")),
        "the failure must name the address; output:\n{log}"
    );
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

/// With no `default_clients`, the one thing the server does with Redis at start-up is prune
/// the static clients an earlier configuration left there. A test server that inherited a
/// developer's `SIWXOIDC_REDIS_URL` (or the default `redis://localhost`) would delete the
/// static clients of that Redis, so the spawned server must never read the caller's
/// environment. The control makes "no connection" mean something: a server that is told a
/// Redis address does connect to it at start-up.
#[test]
fn a_spawned_server_never_reaches_the_redis_the_callers_environment_names() {
    let (told, told_url) = redis_trap();
    let server = Server::start(&[("SIWXOIDC_REDIS_URL", told_url)]);
    let reached = connection_arrives(&told, Duration::from_secs(10));
    drop(server);
    assert!(
        reached,
        "control: a server given a Redis URL connects to it at start-up"
    );

    let (trap, trap_url) = redis_trap();
    let _caller = CallerEnv::set("SIWXOIDC_REDIS_URL", &trap_url);
    let server = Server::start(&[]);
    let reached = connection_arrives(&trap, Duration::from_secs(2));
    drop(server);
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
    let _server = Server::start(&[]);
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
    let mut server = Server::start(&[
        (
            "SIWXOIDC_SYNAPSE_ENDPOINT",
            format!("http://127.0.0.1:{homeserver}"),
        ),
        ("SIWXOIDC_MAS_SHARED_SECRET", "secret".to_string()),
        ("SIWXOIDC_MATRIX_SERVER_NAME", "example.org".to_string()),
    ]);
    let port = server.port;

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

    server.send_signal("TERM");
    let status = server.wait_exit("SIGTERM", Duration::from_secs(10));
    let response = lookup.join().expect("the lookup thread");
    let log = server.output();

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the request in flight must get its full answer, got:\n{response}\noutput:\n{log}"
    );
    assert!(
        response.contains(r#""exists":false"#),
        "the answer must be the lookup's own: {response}"
    );
    assert!(
        status.success(),
        "expected exit status 0 after SIGTERM, got {status}; output:\n{log}"
    );
}
