//! SIGTERM stops the server cleanly and promptly.
//!
//! `docker stop` sends SIGTERM and SIGKILLs after a grace period (10 s by
//! default). In a container the server is PID 1, where the kernel drops a
//! signal that has no handler instead of terminating the process, so a fast,
//! clean stop depends entirely on the server's own handler
//! (`axum_lib::shutdown_signal`).
//!
//! This test runs the real binary. On the host it is not PID 1, so without the
//! handler SIGTERM still ends it, but by the signal, not by `main` returning:
//! the exit-status assertion is what fails then. It needs no Redis: startup
//! opens no connection until a request needs one.

#![cfg(unix)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn sigterm_finishes_and_exits_zero_with_an_idle_connection_open() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = Command::new(env!("CARGO_BIN_EXE_siwx-oidc"))
        .env("SIWXOIDC_ADDRESS", "127.0.0.1")
        .env("SIWXOIDC_PORT", port.to_string())
        .env("SIWXOIDC_BASE_URL", format!("http://localhost:{port}"))
        .env("RUST_LOG", "siwx_oidc=info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the siwx-oidc binary");

    let started = Instant::now();
    // Held open and silent across the signal: a client's idle keep-alive
    // connection must not keep the server alive until the SIGKILL.
    let idle = loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            break stream;
        }
        if let Some(status) = server.try_wait().unwrap() {
            panic!("siwx-oidc exited before it listened: {status}");
        }
        if started.elapsed() > Duration::from_secs(30) {
            server.kill().ok();
            panic!("siwx-oidc did not listen on {port} within 30 s");
        }
        sleep(Duration::from_millis(50));
    };

    let kill = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -TERM failed: {kill}");

    let signalled = Instant::now();
    let status = loop {
        if let Some(status) = server.try_wait().unwrap() {
            break status;
        }
        if signalled.elapsed() > Duration::from_secs(5) {
            server.kill().ok();
            panic!("siwx-oidc still running 5 s after SIGTERM");
        }
        sleep(Duration::from_millis(20));
    };
    drop(idle);

    let mut log = String::new();
    server
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(
        status.success(),
        "expected exit status 0 after SIGTERM, got {status}; log:\n{log}"
    );
    assert!(
        log.contains("shutting down") && log.contains("SIGTERM"),
        "no shutdown line naming SIGTERM in the log:\n{log}"
    );
}
