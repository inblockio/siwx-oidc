//! Output hygiene: credentials in redacting newtypes, a taint check on every
//! printed line, a value charset, a panic hook that prints only a location,
//! and no core dumps.
//!
//! The canary holds no credential it could print by accident: the access,
//! refresh and ID tokens, the registration access token, the account-action
//! nonce and the signature over it live in [`Secret`]. The authorization code,
//! the PKCE verifier, the CAIP-122 nonce and the session cookie are created and
//! consumed inside `siwx_oidc_auth`'s code flow and never reach this program.

use std::fmt;
use std::io::Write;
#[cfg(not(test))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::report::Reason;

/// Every credential the process has held, for the taint check.
static CREDENTIALS: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[cfg(not(test))]
static TAINT_TRIPPED: AtomicBool = AtomicBool::new(false);

// The tests run in parallel threads of one process and some of them trip the
// check on purpose, so under test the flag is per thread.
#[cfg(test)]
thread_local! {
    static TAINT_TRIPPED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// A credential: an access, refresh or ID token, a registration access token,
/// a nonce or a signature over one. `Debug` and `Display` print `[redacted]`,
/// so a stray `{:?}` of a struct that holds one cannot leak it. Creating one
/// registers its value with the taint check.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        register_credential(&value);
        Secret(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A line is refused when it contains this many consecutive characters of a
/// held credential.
pub const TAINT_WINDOW: usize = 12;

/// Hold `value` in the taint check. A value shorter than a window cannot be
/// matched by window and is not held.
pub fn register_credential(value: &str) {
    if value.chars().count() < TAINT_WINDOW {
        return;
    }
    let mut held = CREDENTIALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !held.iter().any(|v| v == value) {
        held.push(value.to_string());
    }
}

/// Whether `line` contains any [`TAINT_WINDOW`]-character window of any of
/// `credentials`.
pub fn taint_hit(line: &str, credentials: &[String]) -> bool {
    credentials.iter().any(|credential| {
        let starts: Vec<usize> = credential
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(credential.len()))
            .collect();
        // `starts` has one more entry than the credential has characters.
        (0..starts.len().saturating_sub(TAINT_WINDOW))
            .any(|i| line.contains(&credential[starts[i]..starts[i + TAINT_WINDOW]]))
    })
}

/// The line to print for `line`: itself, or, when it carries a window of a held
/// credential, a refusal marker that names only the check (a literal of this
/// program). A refusal fails the run.
pub fn guard(line: String, check: &str) -> String {
    let held = CREDENTIALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if taint_hit(&line, &held) {
        trip();
        format!(
            "CANARY taint result=FAIL reason={} check={}",
            Reason::OutputRefused.code(),
            value(check)
        )
    } else {
        line
    }
}

#[cfg(not(test))]
fn trip() {
    TAINT_TRIPPED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
fn trip() {
    TAINT_TRIPPED.with(|t| t.set(true));
}

#[cfg(not(test))]
pub fn taint_tripped() -> bool {
    TAINT_TRIPPED.load(Ordering::SeqCst)
}

#[cfg(test)]
pub fn taint_tripped() -> bool {
    TAINT_TRIPPED.with(|t| t.get())
}

/// Collect this thread's printed lines instead of printing them.
#[cfg(test)]
pub fn start_capture() {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

/// The lines printed since [`start_capture`].
#[cfg(test)]
pub fn take_capture() -> Vec<String> {
    CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default())
}

/// The longest value printed.
const MAX_VALUE: usize = 120;

fn allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ',' | ':' | '/' | '@' | '<' | '>' | '-')
}

/// A printed value keeps only `[A-Za-z0-9_.,:/@<>-]` (everything else becomes
/// `_`, so a server-supplied string can neither inject a line nor a field) and
/// at most [`MAX_VALUE`] characters. Empty prints as `<none>`.
pub fn value(s: &str) -> String {
    let out: String = s
        .chars()
        .take(MAX_VALUE)
        .map(|c| if allowed(c) { c } else { '_' })
        .collect();
    if out.is_empty() {
        "<none>".to_string()
    } else {
        out
    }
}

/// Print one finished line to stdout through the taint check. A closed stdout
/// is ignored: the verdict is the exit code.
pub fn print_line(line: String, check: &str) {
    let line = guard(line, check);
    #[cfg(test)]
    {
        let captured = CAPTURE.with(|c| match c.borrow_mut().as_mut() {
            Some(lines) => {
                lines.push(line.clone());
                true
            }
            None => false,
        });
        if captured {
            return;
        }
    }
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// `panic = "abort"` cannot be set for an example, so a hook prints the source
/// location and nothing else (the payload can carry anything, a response body
/// included) and aborts.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", short_path(l.file()), l.line()))
            .unwrap_or_default();
        let mut err = std::io::stderr().lock();
        let _ = writeln!(
            err,
            "CANARY panic result=FAIL reason=internal_error at={}",
            value(&at)
        );
        let _ = err.flush();
        std::process::abort();
    }));
}

/// The last two components of a path: enough to find the line, no home
/// directory in the output.
fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit(['/', '\\']).take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

/// `setrlimit(RLIMIT_CORE, 0)`: a crash cannot leave a core file holding a key
/// or a token. `true` when the limit is now zero.
#[cfg(unix)]
pub fn disable_core_dumps() -> bool {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid, initialised `rlimit` that outlives the call.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_TOKEN: &str = "mat_Zq3xV9bLk2TgWn7YpRa5HcDs1EuJf8Ko";

    #[test]
    fn debug_and_display_of_a_credential_print_redacted() {
        let secret = Secret::new(FAKE_TOKEN.to_string());
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{secret:#?}"), "[redacted]");
        assert_eq!(format!("{secret}"), "[redacted]");
        assert_eq!(format!("{secret:>40}"), "[redacted]");
        assert_eq!(secret.expose(), FAKE_TOKEN);
    }

    #[test]
    fn a_struct_holding_credentials_prints_redacted_under_derived_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Held {
            access: Secret,
            refresh: Option<Secret>,
        }
        let held = Held {
            access: Secret::new(FAKE_TOKEN.to_string()),
            refresh: Some(Secret::new(
                "mcr_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            )),
        };
        let shown = format!("{held:?} {held:#?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains("Zq3xV9bLk2Tg"), "{shown}");
        assert!(!shown.contains("AAAAAAAAAAAA"), "{shown}");
    }

    #[test]
    fn taint_check_refuses_a_line_containing_a_window_of_a_token() {
        let creds = vec![FAKE_TOKEN.to_string()];
        // The whole token, a 12-character window in the middle, and the last
        // 12 characters all trip the check.
        assert!(taint_hit(&format!("x token={FAKE_TOKEN} y"), &creds));
        assert!(taint_hit("a=Zq3xV9bLk2Tg b", &creds));
        assert!(taint_hit(
            &format!("a={}", &FAKE_TOKEN[FAKE_TOKEN.len() - TAINT_WINDOW..]),
            &creds
        ));
        // Eleven characters are not a window; a different token is not held.
        assert!(!taint_hit("a=Zq3xV9bLk2T b", &creds));
        assert!(!taint_hit(
            "a=mat_Other0000000000000000000000000000 b",
            &creds
        ));
        assert!(!taint_hit(
            "CANARY summary checks_run=6 skipped=0 result=ok",
            &creds
        ));
    }

    #[test]
    fn taint_check_covers_multibyte_credentials_without_panicking() {
        let creds = vec!["ключ-секрет-значение".to_string()];
        assert!(taint_hit("x ключ-секрет-з y", &creds));
        assert!(!taint_hit("x ключ-секре y", &creds));
    }

    #[test]
    fn guard_prints_a_refusal_marker_instead_of_a_tainted_line() {
        let held = "mat_GuardTestToken0123456789abcdefgh";
        let _secret = Secret::new(held.to_string());
        let clean = guard("CANARY whoami result=ok reason=ok".to_string(), "whoami");
        assert_eq!(clean, "CANARY whoami result=ok reason=ok");
        assert!(!taint_tripped());
        let refused = guard(
            format!("CANARY whoami result=ok reason=ok token={held}"),
            "whoami",
        );
        assert_eq!(
            refused,
            "CANARY taint result=FAIL reason=output_refused check=whoami"
        );
        assert!(!refused.contains("GuardTestToken"));
        assert!(taint_tripped(), "a refusal must fail the run");
    }

    #[test]
    fn a_location_keeps_two_path_components() {
        assert_eq!(
            short_path("/home/someone/.cargo/registry/src/x/reqwest/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(
            short_path("siwx-oidc-auth/examples/rotation_canary.rs"),
            "examples/rotation_canary.rs"
        );
        assert_eq!(short_path("main.rs"), "main.rs");
    }

    #[test]
    fn values_keep_only_the_charset_and_cannot_inject_a_line() {
        assert_eq!(
            value("https://matrix.example.org:8448"),
            "https://matrix.example.org:8448"
        );
        assert_eq!(value("@a_b-c.d:example.org"), "@a_b-c.d:example.org");
        assert_eq!(value("a b=c\nCANARY summary x"), "a_b_c_CANARY_summary_x");
        assert_eq!(value("100%"), "100_");
        assert_eq!(value(""), "<none>");
        assert_eq!(value(&"a".repeat(500)).len(), 120);
    }
}
