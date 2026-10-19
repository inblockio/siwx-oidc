//! Unit and hermetic tests of the rotation canary (`examples/rotation_canary.rs`).
//!
//! An example's own tests are not run by `cargo test` unless its manifest entry
//! says so, so the canary's modules are compiled here as well and their tests
//! run with the rest of the crate's. Nothing in this file needs a network: the
//! hermetic runs of `check` and `init` talk to a fake siwx-oidc server and
//! homeserver inside the test process (`hermetic.rs`).
//!
//! ```text
//! cargo test -p siwx-oidc-auth --test rotation_canary_unit
//! ```

#![cfg(unix)]
// The example's `main` is the only user of a few items.
#![allow(dead_code)]

#[path = "../examples/rotation_canary/checks.rs"]
mod checks;
#[path = "../examples/rotation_canary/cli.rs"]
mod cli;
#[path = "../examples/rotation_canary/flow.rs"]
mod flow;
#[path = "rotation_canary_unit/hermetic.rs"]
mod hermetic;
#[path = "../examples/rotation_canary/hygiene.rs"]
mod hygiene;
#[path = "../examples/rotation_canary/identity.rs"]
mod identity;
#[path = "../examples/rotation_canary/init.rs"]
mod init;
#[path = "../examples/rotation_canary/jose.rs"]
mod jose;
#[path = "../examples/rotation_canary/net.rs"]
mod net;
#[path = "../examples/rotation_canary/report.rs"]
mod report;
