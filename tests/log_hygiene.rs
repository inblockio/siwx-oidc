//! Logs carry fingerprints of credentials, never the credentials (I1, logs).
//!
//! Three kinds of pin, because no one of them covers every log site:
//!
//! 1. **Behaviour.** The Redis token and code paths run under a captured
//!    subscriber at DEBUG level, and the output must name the fingerprint of
//!    each value and never the value. The device flow, the WebAuthn ceremonies
//!    and the request-logging layer have the same test beside their code
//!    (`device_auth`, `webauthn`, `axum_lib`), because they live in the binary
//!    crate, which this file cannot link.
//! 2. **Debug output.** A struct that holds a credential prints its fingerprint
//!    under `{:?}`, so a future `?entry` in a log field cannot leak it.
//! 3. **Source scan.** Some sites cannot be reached from a test (a Redis error
//!    path, the passkey mirror to a second store). The scan reads `src/`, finds
//!    every `info!`/`warn!`/`debug!`/`error!`/`trace!` outside `#[cfg(test)]`
//!    code, and fails when one names a variable that holds a credential without
//!    wrapping it in [`siwx_oidc::redact::fingerprint`] (or `redact_key` /
//!    `redact_url`). A site that is deliberate and safe is added to
//!    [`ALLOWED`] with its reason, so the exception is visible in review.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use chrono::Utc;
use siwx_oidc::db::*;
use siwx_oidc::redact::fingerprint;
use siwx_oidc::test_support::{redis, LogCapture};

/// A value no log may contain and a fingerprint that must stand in for it.
fn assert_logged_only_as_fingerprint(output: &str, what: &str, value: &str) {
    let lines_with = |needle: &str| {
        output
            .lines()
            .filter(|l| l.contains(needle))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        !output.contains(value),
        "the {what} appears in the logs in the clear:\n{}",
        lines_with(value)
    );
    assert!(
        output.contains(&fingerprint(value)),
        "the logs never name the fingerprint of the {what}, so the test proves nothing; \
         captured:\n{output}"
    );
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}

fn access_metadata(did: &str) -> TokenMetadata {
    let now = Utc::now().timestamp();
    TokenMetadata {
        username: "log-hygiene".to_string(),
        device_id: unique("DEV"),
        scope: "openid".to_string(),
        client_id: "log-hygiene-client".to_string(),
        iat: now,
        exp: now + 300,
        did: did.to_string(),
        name: did.to_string(),
        kind: Some(TokenKind::Access),
    }
}

// -- 1. behaviour --------------------------------------------------------

/// `set_code`, both outcomes of `try_consume_code`, `set_token`, `get_token`
/// and `delete_token` log at `debug!`; none may print the code or the token,
/// which are the Redis keys' own suffixes.
#[tokio::test]
async fn the_redis_code_and_token_paths_log_fingerprints_never_values() {
    let Some(db) = redis().await else {
        return;
    };
    let code = unique("code-");
    let token = unique("mat_");
    let did = "did:key:zDnaeLOGHYGIENE";

    let logs = LogCapture::start();
    db.set_code(
        code.clone(),
        CodeEntry {
            exchange_count: 0,
            did: did.to_string(),
            nonce: None,
            client_id: "log-hygiene-client".to_string(),
            auth_time: Utc::now(),
            code_challenge: None,
            code_challenge_method: None,
            device_id: None,
            localpart: None,
        },
    )
    .await
    .unwrap();
    assert!(db.try_consume_code(code.clone()).await.unwrap().is_some());
    assert!(
        db.try_consume_code(code.clone()).await.unwrap().is_none(),
        "the second exchange of a code finds nothing"
    );
    db.set_token(&token, &access_metadata(did), 60)
        .await
        .unwrap();
    assert!(db.get_token(&token).await.unwrap().is_some());
    db.delete_token(&token).await.unwrap();
    let output = logs.output();

    assert_logged_only_as_fingerprint(&output, "authorization code", &code);
    assert_logged_only_as_fingerprint(&output, "access token", &token);
}

// -- 2. Debug output -----------------------------------------------------

/// `RotatedToken` holds the raw successor pair and `DeviceCodeEntry` the raw
/// user code. Neither is logged today; both print fingerprints under `{:?}` and
/// `{:#?}` so that logging one by mistake is not a leak.
#[test]
fn a_struct_that_holds_a_credential_prints_its_fingerprint_under_debug() {
    let access = unique("mat_");
    let refresh = unique("mcr_");
    let rotated = RotatedToken {
        access_token: access.clone(),
        refresh_token: refresh.clone(),
        access_exp: 1,
    };
    let user_code = "WDJB-MJHT".to_string();
    let device = DeviceCodeEntry {
        user_code: user_code.clone(),
        client_id: "log-hygiene-client".to_string(),
        scope: "openid".to_string(),
        status: DeviceCodeStatus::Pending,
        did: None,
        device_id: None,
        last_poll: None,
        created_at: 0,
    };
    let shown = format!("{rotated:?}\n{rotated:#?}\n{device:?}\n{device:#?}");
    assert_logged_only_as_fingerprint(&shown, "successor access token", &access);
    assert_logged_only_as_fingerprint(&shown, "successor refresh token", &refresh);
    assert_logged_only_as_fingerprint(&shown, "user code", &user_code);
    assert!(
        shown.contains("log-hygiene-client"),
        "the rest of the struct still prints: {shown}"
    );
}

// -- 3. source scan ------------------------------------------------------

/// Variables that hold a credential, or a Redis key that embeds one, wherever
/// they appear.
const CREDENTIAL_NAMES: &[&str] = &[
    "access_token",
    "client_secret",
    "code",
    "cookie",
    "cred_id",
    "cred_id_b64",
    "cred_key",
    "credential_id",
    "dc",
    "device_code",
    "link_key",
    "new_access",
    "new_refresh",
    "password",
    "refresh_token",
    "registration_access_token",
    "rt",
    "secret",
    "session_id",
    "token",
    "user_code",
];

/// Names that are credentials only in one file, where they are a Redis key.
const CREDENTIAL_NAMES_BY_FILE: &[(&str, &[&str])] = &[
    (
        "src/db/redis.rs",
        &["key", "idx_key", "index_key", "tomb_key"],
    ),
    // The dual-write Redis URL carries a password.
    ("src/credential_store.rs", &["url"]),
];

/// A log site that names one of the variables above and is safe. Each entry is
/// `(file, line number)` with the reason; the scan has no other exemption.
const ALLOWED: &[(&str, usize, &str)] = &[];

const LOG_MACROS: &[&str] = &["info", "warn", "debug", "error", "trace"];
const MASKING_CALLS: &[&str] = &["fingerprint", "redact_key", "redact_url"];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Punct(char),
}

/// For a raw string starting at `i` (`r"`, `r#"`, `br##"`, …): the index just
/// past its opening quote, and its number of `#`s.
fn raw_string_open(chars: &[char], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if chars.get(j) == Some(&'b') {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    (chars.get(j) == Some(&'"')).then_some((j + 1, hashes))
}

/// A Rust lexer that is just good enough to find macro calls: it drops comments
/// and keeps string literals whole, so an identifier in a comment or in a string
/// is never mistaken for code, and a brace in a literal never unbalances a scan.
fn lex(src: &str) -> Vec<(Tok, usize)> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line) = (0usize, 1usize);
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                let mut depth = 1;
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 1;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 1;
                    }
                    i += 1;
                }
            }
            // r"…", r#"…"#, br"…" (raw strings): no escapes, closed by `"` + the same `#`s.
            'r' | 'b' if raw_string_open(&chars, i).is_some() => {
                let (mut j, hashes) = raw_string_open(&chars, i).unwrap();
                let (start, start_line) = (j, line);
                while j < chars.len()
                    && !(chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')))
                {
                    if chars[j] == '\n' {
                        line += 1;
                    }
                    j += 1;
                }
                out.push((Tok::Str(chars[start..j].iter().collect()), start_line));
                i = (j + 1 + hashes).min(chars.len());
            }
            '"' => {
                let start_line = line;
                let mut j = i + 1;
                let mut s = String::new();
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\' && j + 1 < chars.len() {
                        if chars[j + 1] == '\n' {
                            line += 1;
                        }
                        s.push(chars[j + 1]);
                        j += 2;
                        continue;
                    }
                    if chars[j] == '\n' {
                        line += 1;
                    }
                    s.push(chars[j]);
                    j += 1;
                }
                out.push((Tok::Str(s), start_line));
                i = j + 1;
            }
            '\'' => {
                // A char literal ('x', '\n', '\'') or a lifetime ('a).
                if chars.get(i + 1) == Some(&'\\') {
                    let mut j = i + 2;
                    while j < chars.len() && chars[j] != '\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    out.push((Tok::Punct('\''), line));
                    i += 1;
                }
            }
            c if c.is_ascii_digit() => {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                out.push((Tok::Punct('0'), line));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                out.push((Tok::Ident(chars[start..i].iter().collect()), line));
            }
            c => {
                out.push((Tok::Punct(c), line));
                i += 1;
            }
        }
    }
    out
}

fn is_open(t: &Tok) -> bool {
    matches!(t, Tok::Punct('(') | Tok::Punct('[') | Tok::Punct('{'))
}

fn is_close(t: &Tok) -> bool {
    matches!(t, Tok::Punct(')') | Tok::Punct(']') | Tok::Punct('}'))
}

/// The index just past the group that opens at `open`.
fn skip_group(toks: &[(Tok, usize)], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < toks.len() {
        if is_open(&toks[i].0) {
            depth += 1;
        } else if is_close(&toks[i].0) {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    toks.len()
}

/// `#[cfg(test)]` at `i`: the index just past the item it gates.
fn skip_cfg_test_item(toks: &[(Tok, usize)], i: usize) -> Option<usize> {
    let pattern = [
        Tok::Punct('#'),
        Tok::Punct('['),
        Tok::Ident("cfg".into()),
        Tok::Punct('('),
        Tok::Ident("test".into()),
        Tok::Punct(')'),
        Tok::Punct(']'),
    ];
    if i + pattern.len() > toks.len()
        || !pattern.iter().enumerate().all(|(k, p)| &toks[i + k].0 == p)
    {
        return None;
    }
    let mut j = i + pattern.len();
    while j < toks.len() {
        match &toks[j].0 {
            Tok::Punct(';') => return Some(j + 1),
            Tok::Punct('{') => return Some(skip_group(toks, j)),
            t if is_open(t) => j = skip_group(toks, j),
            _ => j += 1,
        }
    }
    Some(toks.len())
}

/// The `{name` captures of a format string (`{x}`, `{x:?}`, never `{{`).
fn inline_captures(fmt: &str) -> Vec<String> {
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            if chars.get(i + 1) == Some(&'{') {
                i += 2;
                continue;
            }
            let mut j = i + 1;
            let mut name = String::new();
            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                name.push(chars[j]);
                j += 1;
            }
            if !name.is_empty() {
                out.push(name);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Every `(line, name)` where a log macro in `src` names a credential variable.
fn naming_sites(src: &str, deny: &HashSet<&str>) -> Vec<(usize, String)> {
    let toks = lex(src);
    let mut found = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if let Some(next) = skip_cfg_test_item(&toks, i) {
            i = next;
            continue;
        }
        let is_log_macro = matches!(&toks[i].0, Tok::Ident(n) if LOG_MACROS.contains(&n.as_str()))
            && toks.get(i + 1).map(|t| &t.0) == Some(&Tok::Punct('!'))
            && toks.get(i + 2).is_some_and(|t| is_open(&t.0));
        if !is_log_macro {
            i += 1;
            continue;
        }
        let end = skip_group(&toks, i + 2);
        let mut k = i + 3;
        while k < end - 1 {
            match &toks[k].0 {
                Tok::Ident(n)
                    if MASKING_CALLS.contains(&n.as_str())
                        && toks.get(k + 1).map(|t| &t.0) == Some(&Tok::Punct('(')) =>
                {
                    k = skip_group(&toks, k + 1);
                    continue;
                }
                Tok::Ident(n) if deny.contains(n.as_str()) => found.push((toks[k].1, n.clone())),
                Tok::Str(s) => {
                    for name in inline_captures(s) {
                        if deny.contains(name.as_str()) {
                            found.push((toks[k].1, name));
                        }
                    }
                }
                _ => {}
            }
            k += 1;
        }
        i = end;
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The scanner finds what it is meant to find, so a green scan of `src/` means
/// something.
#[test]
fn the_scanner_finds_an_unmasked_credential_and_accepts_a_fingerprint() {
    let deny: HashSet<&str> = ["token", "user_code"].into_iter().collect();
    let leaky = r#"
        fn a() {
            tracing::info!(user_code = %req.user_code, "device denied");
            warn!("mirror: {token} failed");
            debug!("stored {}", token);
        }
    "#;
    let names: Vec<_> = naming_sites(leaky, &deny)
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(
        names,
        ["user_code", "user_code", "token", "token"],
        "field name and value, an inline capture, and a positional argument"
    );

    let clean = r#"
        fn a() {
            info!(user_code_fp = %fingerprint(&req.user_code), "device denied");
            warn!("mirror: {} failed", redact_key(&token));
            // debug!("stored {}", token);
            let s = "info!(token)";
        }
        #[cfg(test)]
        mod tests {
            fn t() { info!("{token}"); }
        }
    "#;
    assert_eq!(naming_sites(clean, &deny), vec![]);
}

#[test]
fn no_log_site_names_a_credential_without_its_fingerprint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 20, "found only {} sources", files.len());

    let mut violations = Vec::new();
    let mut sites_scanned = 0usize;
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let mut deny: HashSet<&str> = CREDENTIAL_NAMES.iter().copied().collect();
        for (file, names) in CREDENTIAL_NAMES_BY_FILE {
            if *file == rel {
                deny.extend(names.iter().copied());
            }
        }
        let src = std::fs::read_to_string(path).unwrap();
        sites_scanned += src.matches("!(").count();
        for (line, name) in naming_sites(&src, &deny) {
            if !ALLOWED.iter().any(|(f, l, _)| *f == rel && *l == line) {
                violations.push(format!("{rel}:{line}: `{name}`"));
            }
        }
    }
    assert!(sites_scanned > 500, "the scan saw almost no macros");
    assert!(
        violations.is_empty(),
        "log sites that name a credential variable without `fingerprint(..)`, \
         `redact_key(..)` or `redact_url(..)`:\n  {}",
        violations.join("\n  ")
    );
}
