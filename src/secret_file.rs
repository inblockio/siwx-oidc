//! Secrets read from files, for a container that gets them as read-only mounts
//! (`/run/secrets/<name>`) instead of environment variables or a compose file.
//!
//! The rules, in one place so the server and the tests read the same ones:
//!
//! - The path is absolute and names a regular file (a symbolic link is followed). A
//!   named pipe or a device is refused before it is opened, so a wrong path cannot block
//!   start-up or read an endless stream.
//! - The value is the file's content with at most one trailing line ending removed
//!   (`\n` or `\r\n`), because files are written with an editor or `echo`. What is
//!   left must not start or end with whitespace, hold a control character or start with
//!   a byte order mark. Other readers of the same file (Synapse strips all surrounding
//!   whitespace from its MAS secret file) would read another value than this one, and
//!   a refusal at start is better than two services that disagree about a secret.
//! - An unreadable file, a file that is not UTF-8, one larger than
//!   [`MAX_SECRET_FILE_BYTES`] and an empty value are errors.
//! - **An error names the setting and, for a path that is absolute, the path, and never
//!   any content.** That holds for the I/O error text (the operating system names the
//!   failure, not the data) and for the checks made on the content, which say only what
//!   rule failed. A path that is not absolute is not shown: it may be the secret itself,
//!   pasted into the wrong setting.
//!
//! Lives in the library crate so `tests/*.rs` can pin it.

use std::io::Read;
use url::Url;

/// The largest secret file read. A secret is a few dozen bytes; the bound keeps a
/// path that names the wrong file (a log, a device) from being read into memory.
pub const MAX_SECRET_FILE_BYTES: u64 = 8192;

/// The value in `path`, as `setting` (the name an operator knows, used in errors).
pub fn read(setting: &str, path: &str) -> Result<String, String> {
    // Checked first and never echoed: a path that is not absolute is most likely the
    // secret itself, given to the file setting by mistake.
    if !std::path::Path::new(path).is_absolute() {
        return Err(format!(
            "{setting}: the path of the secret file must be absolute (it is not shown here); \
             in a container a mounted secret is under /run/secrets"
        ));
    }
    let cannot = |why: String| format!("{setting}: cannot read the secret file {path}: {why}");
    // `metadata` follows a symbolic link. A named pipe would block `open` forever and a
    // device would be read as if it held a secret, so only a regular file is opened.
    let kind = std::fs::metadata(path).map_err(|e| cannot(e.to_string()))?;
    if !kind.is_file() {
        return Err(cannot("it is not a regular file".into()));
    }
    let file = std::fs::File::open(path).map_err(|e| cannot(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| cannot(e.to_string()))?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(cannot(format!(
            "it is larger than {MAX_SECRET_FILE_BYTES} bytes"
        )));
    }
    let text = String::from_utf8(bytes).map_err(|_| cannot("it is not valid UTF-8".into()))?;
    let value = strip_one_line_ending(&text);
    if value.trim().is_empty() {
        return Err(format!("{setting}: the secret file {path} is empty"));
    }
    if value.starts_with('\u{feff}') {
        return Err(cannot(
            "it starts with a byte order mark (save it as plain UTF-8)".into(),
        ));
    }
    if value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace) {
        return Err(cannot(
            "it has whitespace at the start or the end (one final newline is allowed); \
             another reader of the same file would strip it and read a different secret"
                .into(),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(cannot(
            "it holds a control character (a secret is one line)".into(),
        ));
    }
    Ok(value.to_string())
}

/// `text` without one trailing `\r\n` or `\n`.
fn strip_one_line_ending(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

/// The error for a secret given both inline and as a file.
pub fn both_set(file_setting: &str, inline_setting: &str) -> String {
    format!(
        "{file_setting} and {inline_setting} are both set: give the secret one way only \
         (remove {inline_setting}, or {file_setting})"
    )
}

/// Whether `url` already carries a password: in its user information, or as the
/// `pass` query parameter a unix-socket Redis URL takes.
pub fn url_carries_password(url: &Url) -> bool {
    url.password().is_some() || url.query_pairs().any(|(key, _)| key == "pass")
}

/// Whether `url` names a unix socket. The Redis client reads a unix-socket password only
/// from the `pass` parameter of the URL, never from its user information.
fn is_unix_socket_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "unix" | "redis+unix" | "valkey+unix")
}

/// `url` with `password` as its password, for any password.
///
/// `Url::set_password` percent-encodes everything the URL syntax reserves, with one
/// exception: it leaves `%` as it is, so a password that holds `%41` would be sent to
/// the server as `A` once the Redis client decodes it. The `%` is therefore encoded
/// first. `setting` names the URL's setting in the error for a URL that cannot carry
/// a password at all (no host).
pub fn url_with_password(setting: &str, url: &Url, password: &str) -> Result<Url, String> {
    let mut url = url.clone();
    url.set_password(Some(&password.replace('%', "%25")))
        .map_err(|()| {
            format!("{setting} cannot carry a password: it has no host; use a URL with a host")
        })?;
    Ok(url)
}

/// `url` with the password in the file at `path` as its password: the one rule for every
/// Redis URL whose password may come from a file (`redis_password_file`, and
/// `AQUA_WEBAUTHN_REDIS_PASSWORD_FILE` for the credential store).
///
/// `url_setting` and `file_setting` are the names an operator knows, with the
/// environment variable if there is one. Refused, with an error that names them and holds
/// no content: a URL that already carries a password (the file and the inline password
/// together are never accepted), a unix-socket URL of any spelling and with any host (the
/// client would ignore the password), a URL that cannot carry a password, and a file
/// that [`read`] refuses.
pub fn redis_url_with_password_file(
    url_setting: &str,
    url: &Url,
    file_setting: &str,
    path: &str,
) -> Result<Url, String> {
    if url_carries_password(url) {
        return Err(both_set(
            file_setting,
            &format!("the password in {url_setting}"),
        ));
    }
    if is_unix_socket_scheme(url) {
        return Err(format!(
            "{file_setting} cannot be used with {url_setting}: it is a unix-socket URL, which \
             cannot carry a password from a file (the Redis client reads a unix-socket \
             password only from the `pass` parameter of the URL itself); use a TCP URL"
        ));
    }
    let password = read(file_setting, path)?;
    url_with_password(url_setting, url, &password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{leaked_window, random_secret};
    use std::path::PathBuf;

    /// A file in the temp dir, removed on drop.
    struct TempFile(PathBuf);

    impl TempFile {
        fn with(content: &[u8]) -> Self {
            use std::io::Write;
            let path = std::env::temp_dir().join(format!(
                "siwx-secret-file-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::File::create_new(&path)
                .and_then(|mut f| f.write_all(content))
                .unwrap();
            TempFile(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn one_trailing_line_ending_is_removed_and_nothing_else() {
        for (content, value) in [
            ("abc", "abc"),
            ("abc\n", "abc"),
            ("abc\r\n", "abc"),
            // Whitespace inside the value belongs to it, and so does any non-ASCII text.
            ("a b\n", "a b"),
            ("p\u{e4}ss \u{20ac}\u{fc}\r\n", "p\u{e4}ss \u{20ac}\u{fc}"),
        ] {
            let file = TempFile::with(content.as_bytes());
            assert_eq!(read("setting", file.path()).unwrap(), value, "{content:?}");
        }
    }

    /// O-F5: Synapse strips all surrounding whitespace from its MAS secret file, so a
    /// file shared by both services with more than one final newline (or a space) would
    /// give two secrets. Each of these is refused, by the rule that names it, and the
    /// error holds no content.
    #[test]
    fn a_value_that_another_reader_would_read_differently_is_refused() {
        let secret = random_secret(32);
        for (what, content, rule) in [
            ("two newlines", format!("{secret}\n\n"), "whitespace"),
            ("two CRLFs", format!("{secret}\r\n\r\n"), "whitespace"),
            ("a lone CR", format!("{secret}\r"), "whitespace"),
            ("a leading space", format!(" {secret}\n"), "whitespace"),
            ("a trailing space", format!("{secret} \n"), "whitespace"),
            ("a leading tab", format!("\t{secret}"), "whitespace"),
            (
                "a no-break space at the end",
                format!("{secret}\u{a0}"),
                "whitespace",
            ),
            ("two lines", format!("{secret}\n{secret}\n"), "control"),
            ("an inner tab", format!("{secret}\t{secret}"), "control"),
            ("an inner NUL", format!("{secret}\0{secret}"), "control"),
            ("a BOM", format!("\u{feff}{secret}\n"), "byte order mark"),
        ] {
            let file = TempFile::with(content.as_bytes());
            let error = read("some_setting_file", file.path()).unwrap_err();
            assert!(
                error.contains("some_setting_file")
                    && error.contains(file.path())
                    && error.contains(rule),
                "{what}: {error}"
            );
            assert_eq!(leaked_window(&error, &secret), None, "{what}: {error}");
        }
        // A value of nothing but whitespace is an empty value.
        for content in [" ", "  \n", "\t\r\n", "\n\n"] {
            let file = TempFile::with(content.as_bytes());
            let error = read("some_setting_file", file.path()).unwrap_err();
            assert!(error.contains("empty"), "{content:?}: {error}");
        }
    }

    /// O-F2: the value of a file setting that is not a path is most likely the secret,
    /// pasted into the wrong setting. It is refused without being shown.
    #[test]
    fn a_path_that_is_not_absolute_is_refused_without_being_shown() {
        let pasted = random_secret(40);
        for value in [
            pasted.clone(),
            format!("./{pasted}"),
            format!("dir/{pasted}"),
        ] {
            let error = read("some_setting_file", &value).unwrap_err();
            assert!(
                error.contains("some_setting_file") && error.contains("absolute"),
                "{error}"
            );
            assert_eq!(leaked_window(&error, &pasted), None, "{error}");
        }
    }

    /// O-F8: a path that names a named pipe blocked start-up forever (`open` waits for a
    /// writer). Run in a thread, so that a regression fails the test instead of hanging it.
    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_a_regular_file_is_refused_before_it_is_opened() {
        let fifo = std::env::temp_dir().join(format!(
            "siwx-secret-fifo-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let named = fifo.to_str().unwrap().to_string();
        std::thread::spawn(move || {
            for path in [named.as_str(), "/dev/null", "/dev/zero", "/"] {
                tx.send((path.to_string(), read("some_setting_file", path)))
                    .ok();
            }
        });
        for _ in 0..4 {
            let (path, outcome) = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("read blocked on a path that is not a regular file");
            let error = outcome.unwrap_err();
            assert!(
                error.contains("some_setting_file")
                    && error.contains(&path)
                    && error.contains("not a regular file"),
                "{path}: {error}"
            );
        }
        std::fs::remove_file(&fifo).ok();
    }

    /// A symbolic link to a regular file is followed, as a mounted secret may be one
    /// (a Kubernetes secret volume is a link into a versioned directory).
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_to_a_regular_file_is_followed() {
        let target = TempFile::with(b"linked-value\n");
        let link = std::env::temp_dir().join(format!(
            "siwx-secret-link-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::os::unix::fs::symlink(&target.0, &link).unwrap();
        let value = read("some_setting_file", link.to_str().unwrap());
        std::fs::remove_file(&link).ok();
        assert_eq!(value.unwrap(), "linked-value");
    }

    #[test]
    fn an_unreadable_file_is_an_error_that_names_the_setting_and_the_path() {
        let path = std::env::temp_dir().join(format!("siwx-missing-{}", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap();
        let error = read("some_setting_file", path).unwrap_err();
        assert!(
            error.contains("some_setting_file") && error.contains(path),
            "{error}"
        );
        // A directory opens and then fails to read: the same error.
        let error = read("some_setting_file", std::env::temp_dir().to_str().unwrap()).unwrap_err();
        assert!(error.contains("some_setting_file"), "{error}");
    }

    #[test]
    fn an_empty_value_is_an_error() {
        for content in ["", "\n", "\r\n"] {
            let file = TempFile::with(content.as_bytes());
            let error = read("some_setting_file", file.path()).unwrap_err();
            assert!(
                error.contains("some_setting_file")
                    && error.contains(file.path())
                    && error.contains("empty"),
                "{content:?}: {error}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_text_or_is_too_large_is_refused_without_a_word_of_its_content() {
        let secret = random_secret(64);
        let mut not_utf8 = secret.as_bytes().to_vec();
        not_utf8.push(0xff);
        let mut too_large = secret.as_bytes().to_vec();
        too_large.resize(MAX_SECRET_FILE_BYTES as usize + 1, b'x');
        for content in [not_utf8, too_large] {
            let file = TempFile::with(&content);
            let error = read("some_setting_file", file.path()).unwrap_err();
            assert!(
                error.contains("some_setting_file") && error.contains(file.path()),
                "{error}"
            );
            assert_eq!(
                leaked_window(&error, &secret),
                None,
                "the error holds content"
            );
        }
        // The bound is on the file, and a file of exactly that size is read.
        let at_the_bound = TempFile::with(&vec![b'x'; MAX_SECRET_FILE_BYTES as usize]);
        assert_eq!(
            read("s", at_the_bound.path()).unwrap().len() as u64,
            MAX_SECRET_FILE_BYTES
        );
    }

    #[test]
    fn a_password_in_the_user_information_or_the_query_counts_as_carried() {
        let with_password = |rest| crate::test_support::redis_url_with_password("pw", rest);
        let named_with_password = |rest| with_password(rest).replacen("://", "://user", 1);
        for (url, carried) in [
            ("redis://redis.example.org:6379".to_string(), false),
            ("redis://user@redis.example.org".to_string(), false),
            (with_password("redis.example.org"), true),
            (named_with_password("redis.example.org/2"), true),
            ("redis+unix:///run/redis.sock?db=1".to_string(), false),
            ("redis+unix:///run/redis.sock?pass=pw".to_string(), true),
        ] {
            assert_eq!(
                url_carries_password(&Url::parse(&url).unwrap()),
                carried,
                "{url}"
            );
        }
    }

    /// The point of the pre-encoding: whatever the password holds, the Redis client
    /// decodes the URL back to it. Run through the client's own URL parser.
    #[test]
    fn any_password_reaches_the_redis_client_unchanged() {
        let url = Url::parse("redis://user@redis.example.org:6379/2").unwrap();
        // Every printable ASCII character once, a percent sequence, a non-ASCII
        // character, and a random tail.
        let all_ascii: String = (0x20u8..0x7f).map(char::from).collect();
        let passwords = [
            all_ascii,
            "p%41ss%".to_string(),
            "%25%zz%".to_string(),
            "pä:ß@/?#é€".to_string(),
            random_secret(48),
        ];
        for password in passwords {
            let with = url_with_password("redis_url", &url, &password).unwrap();
            let client = bb8_redis::redis::Client::open(with.as_str())
                .unwrap_or_else(|e| panic!("the client refuses the URL: {e}"));
            let info = client.get_connection_info();
            assert_eq!(info.redis_settings().password(), Some(password.as_str()));
            assert_eq!(
                info.redis_settings().username(),
                Some("user"),
                "the user name stays"
            );
            assert_eq!(with.host_str(), Some("redis.example.org"));
            assert_eq!(with.port(), Some(6379));
            assert_eq!(with.path(), "/2");
        }
    }

    #[test]
    fn a_url_without_a_host_cannot_carry_a_password() {
        // A scheme this module does not know as a unix socket, with no host.
        let url = Url::parse("redis:///no-host").unwrap();
        let error = url_with_password("redis_url", &url, "whatever").unwrap_err();
        assert!(
            error.contains("redis_url") && error.contains("cannot carry a password"),
            "{error}"
        );
        assert!(!error.contains("whatever"));
    }

    /// Grok F2: the Redis client reads a unix-socket password only from the `pass`
    /// parameter, so a password from a file put into the user information (which `localhost`
    /// as host allows) was silently dropped. Every unix scheme is refused, with any host.
    #[test]
    fn a_password_file_is_refused_for_every_unix_socket_url() {
        let password = random_secret(40);
        let file = TempFile::with(password.as_bytes());
        for url in [
            "unix:///run/redis.sock",
            "unix://localhost/run/redis.sock",
            "redis+unix:///run/redis.sock",
            "redis+unix://localhost/run/redis.sock",
            "redis+unix://redis.example.org/run/redis.sock?db=1",
            "valkey+unix:///run/valkey.sock",
            "valkey+unix://localhost/run/valkey.sock",
        ] {
            let error = redis_url_with_password_file(
                "redis_url",
                &Url::parse(url).unwrap(),
                "redis_password_file",
                file.path(),
            )
            .unwrap_err();
            assert!(
                error.contains("redis_url")
                    && error.contains("redis_password_file")
                    && error.contains("unix-socket"),
                "{url}: {error}"
            );
            assert_eq!(leaked_window(&error, &password), None, "{url}: {error}");
        }
    }

    #[test]
    fn the_shared_redis_rule_puts_the_file_password_into_a_tcp_url_and_refuses_the_rest() {
        let (in_url, in_file) = (random_secret(40), random_secret(40));
        let file = TempFile::with(format!("{in_file}\n").as_bytes());
        let names = |url: &str| {
            redis_url_with_password_file(
                "the url",
                &Url::parse(url).unwrap(),
                "the file",
                file.path(),
            )
        };
        // The password lands in the URL, whatever it holds, and the rest stays.
        let with = names("redis://user@redis.example.org:6380/3").unwrap();
        let client = bb8_redis::redis::Client::open(with.as_str()).unwrap();
        let info = client.get_connection_info();
        assert_eq!(info.redis_settings().password(), Some(in_file.as_str()));
        assert_eq!(info.redis_settings().username(), Some("user"));
        assert_eq!(info.redis_settings().db(), 3);
        // A password in the URL (user information or the `pass` parameter) is "both set".
        for url in [
            crate::test_support::redis_url_with_password(&in_url, "redis.example.org"),
            format!("redis://redis.example.org?pass={in_url}"),
        ] {
            let error = names(&url).unwrap_err();
            assert!(
                error.contains("the file")
                    && error.contains("the url")
                    && error.contains("both set"),
                "{error}"
            );
            for secret in [&in_url, &in_file] {
                assert_eq!(leaked_window(&error, secret), None, "{error}");
            }
        }
        // An unreadable file names the file setting and the path.
        let missing = redis_url_with_password_file(
            "the url",
            &Url::parse("redis://redis.example.org").unwrap(),
            "the file",
            "/nonexistent/siwx-secret",
        )
        .unwrap_err();
        assert!(
            missing.contains("the file") && missing.contains("/nonexistent/siwx-secret"),
            "{missing}"
        );
    }

    #[test]
    fn both_set_names_both_settings() {
        let error = both_set("some_setting_file", "some_setting");
        assert!(
            error.contains("some_setting_file") && error.contains("some_setting "),
            "{error}"
        );
    }
}
