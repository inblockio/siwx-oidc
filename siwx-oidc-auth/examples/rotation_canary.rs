//! Rotation canary: a headless check that a siwx-oidc deployment still signs
//! people in after its signing key was rotated.
//!
//! One persistent identity per environment (an Ed25519 key in
//! `~/.aqua-secrets/rotation-canary/<env>/key.pem`, one registered client, one
//! account that never joins a room) signs in with PKCE as an agent would, and
//! six checks judge what the server did: C1 `discovery`, C2 `jwks`, C3
//! `sign_in`, C4 `whoami`, C5 `did_proof`, C6 `logout`. Nothing the server runs
//! is changed.
//!
//! ```text
//! cargo run -p siwx-oidc-auth --example rotation_canary -- init  --env E \
//!     --issuer URL --homeserver URL --server-name NAME [--replace]
//! cargo run -p siwx-oidc-auth --example rotation_canary -- check --env E \
//!     --issuer URL (--homeserver URL --server-name NAME | --no-matrix) \
//!     --live-kid K --expect-kids K[,K...] [--dropped-kids K,...] [--baseline]
//! ```
//!
//! # Output
//!
//! Only lines of the form `CANARY <check> result=ok|FAIL|SKIP reason=<code>
//! key=value...`, values within `[A-Za-z0-9_.,:/@<>-]`, and one summary line:
//! `CANARY summary checks_run=6 skipped=0 result=ok`. With `--no-matrix`
//! (allowed only with `--env local`) it reads `checks_run=3 skipped=3`.
//!
//! Exit codes: 0 every check ran and passed; 1 a check failed; 2 usage, or the
//! stored identity is missing, loose or for another issuer; 3 logout not proven
//! (the run's refresh token was not refused afterwards, tokens may live until
//! they expire); 4 the tripwire fired (the canary account has a room or a device
//! that is not this run's: someone else is using the key).
//!
//! # What the checks decide on
//!
//! - A logout that answers 200 proves nothing (siwx-oidc answers 200 for a
//!   token it does not know), so C6 passes only when a refresh with the run's
//!   refresh token is then refused with `invalid_grant`.
//! - No device id is proposed: with deleted-device markers on, a pinned id would
//!   be refused for a year once it was signed out. The server mints
//!   `SIWX_<uuid>` per run and the logout deletes it, best-effort: it answers
//!   200 whether or not the device went. The ledger `devices.json`, which only
//!   this program writes, therefore holds four things. The devices a run left
//!   behind (it died, or the logout went by `/oauth2/revoke`): the next run
//!   tolerates and deletes them. The devices the canary is finished with, each
//!   with the time of its last use (a logout it proved, because the refresh
//!   token was refused, or a deletion): one still listed at a later run is
//!   reported as `device_survived_logout` and deleted again, not taken for a
//!   stranger, but only while it has the canary's display name and was not used
//!   after that time (siwx-oidc recreates a deleted id for a client that
//!   proposes it, so an id proves nothing). A device leaves the ledger only
//!   when a reading shows it gone, never on an answer. The devices a marker
//!   excused, which stay excused only while nobody uses them. And a marker for
//!   each sign-in that was started and not finished, because the server makes
//!   the device before the code exchange. A device nobody recorded fires the
//!   tripwire, unless a live marker can explain it, and a marker explains a
//!   device only if the device has a minted `SIWX_` id, carries the canary's
//!   own display name and has never been seen in use (no `last_seen_ts`).
//!   Markers expire after three days and at most sixteen are kept
//!   (`identity::ATTEMPT_MAX_AGE_SECS`, `identity::ATTEMPT_CAP`). While the
//!   tripwire is fired nothing is excused, recorded or deleted.
//! - Only `--baseline` (the run before a rotation) may register a new client
//!   when the stored one is refused. A later run that cannot use it fails: that
//!   is what an existing client's stored registration would see.
//! - `iat` and `exp` are judged against the server's `Date`, never this host's
//!   clock; the measured skew is printed.
//!
//! # Output hygiene
//!
//! Every credential this program holds (the access, refresh and ID token, the
//! registration access token, the account-action nonce and signature, the DID
//! proof, the session cookies the replies set, the key's PEM) is a
//! `hygiene::Secret`, whose `Debug` and `Display` print `[redacted]`. The
//! authorization code, the PKCE verifier and the CAIP-122 nonce live only
//! inside `siwx_oidc_auth`'s code flow and never reach this program; the
//! cookie of the `/authorize` probe, the one session this program opens itself,
//! is held by the taint check and dropped. Errors from the library, reqwest and
//! the server are mapped to reason codes and their text is dropped,
//! `AuthTokens` is consumed on arrival and never printed. Every line passes a
//! taint check that refuses a line containing 12 consecutive characters of any
//! held credential (a refusal marker is printed instead and the run fails).
//! `panic = "abort"` cannot be set per example, so a panic hook prints only the
//! source location and leaves with `_exit(70)` (no unwinding, no `atexit`
//! handlers, no `SIGABRT` for a crash handler to turn into a core file).
//! `RLIMIT_CORE` is set to 0 first, and on Linux `PR_SET_DUMPABLE` is cleared,
//! so a crash leaves no core file and no other process of the user can read
//! the memory through `ptrace` or `/proc/<pid>/mem`.
//!
//! The modules live in `rotation_canary/`; their tests, and the hermetic runs
//! against a fake server, are in `tests/rotation_canary_unit.rs`.

#[cfg(unix)]
#[path = "rotation_canary/checks.rs"]
mod checks;
#[cfg(unix)]
#[path = "rotation_canary/cli.rs"]
mod cli;
#[cfg(unix)]
#[path = "rotation_canary/flow.rs"]
mod flow;
#[cfg(unix)]
#[path = "rotation_canary/hygiene.rs"]
mod hygiene;
#[cfg(unix)]
#[path = "rotation_canary/identity.rs"]
mod identity;
#[cfg(unix)]
#[path = "rotation_canary/init.rs"]
mod init;
#[cfg(unix)]
#[path = "rotation_canary/jose.rs"]
mod jose;
#[cfg(unix)]
#[path = "rotation_canary/net.rs"]
mod net;
#[cfg(unix)]
#[path = "rotation_canary/report.rs"]
mod report;

#[cfg(unix)]
fn main() {
    use report::{emit, Reason, Verdict};

    hygiene::install_panic_hook();
    if !hygiene::disable_core_dumps() {
        emit("hardening", Verdict::Fail, Reason::CoreLimit, &[]);
        std::process::exit(2);
    }
    let parsed = match cli::parse(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(cli::Early::Help(text)) => {
            print!("{text}");
            return;
        }
        Err(cli::Early::Usage(reason)) => {
            emit("usage", Verdict::Fail, reason, &[]);
            std::process::exit(2);
        }
    };
    let Some(root) = identity::default_root() else {
        emit("usage", Verdict::Fail, Reason::NoHome, &[]);
        std::process::exit(2);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            emit("runtime", Verdict::Fail, Reason::Internal, &[]);
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(async {
        match parsed {
            cli::Parsed::Init(cfg) => init::run(cfg, &root).await,
            cli::Parsed::Check(cfg) => checks::run(cfg, &root).await,
        }
    });
    std::process::exit(code);
}

#[cfg(not(unix))]
fn main() {
    eprintln!("rotation_canary needs a unix host (file modes, flock, setrlimit)");
    std::process::exit(2);
}
