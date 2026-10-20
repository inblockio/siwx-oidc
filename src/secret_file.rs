//! Secrets read from files, for a container that gets them as read-only mounts
//! (`/run/secrets/<name>`) instead of environment variables or a compose file.
//!
//! The rules, in one place so the server and the tests read the same ones:
//!
//! - The value is the file's content with at most one trailing line ending removed
//!   (`\n` or `\r\n`), because files are written with an editor or `echo`. Nothing
//!   else is trimmed: a secret may start or end with a space, and a second newline
//!   belongs to the value.
//! - An unreadable file, a file that is not UTF-8, one larger than
//!   [`MAX_SECRET_FILE_BYTES`] and an empty value are errors.
//! - **An error names the setting and the path and never any content.** That holds
//!   for the I/O error text (the operating system names the failure, not the data)
//!   and for the checks made on the content, which say only what rule failed.
//!
//! Lives in the library crate so `tests/*.rs` can pin it.

use std::io::Read;
use url::Url;

/// The largest secret file read. A secret is a few dozen bytes; the bound keeps a
/// path that names the wrong file (a log, a device) from being read into memory.
pub const MAX_SECRET_FILE_BYTES: u64 = 8192;

/// The value in `path`, as `setting` (the name an operator knows, used in errors).
pub fn read(setting: &str, path: &str) -> Result<String, String> {
    let cannot = |why: String| format!("{setting}: cannot read the secret file {path}: {why}");
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
    if value.is_empty() {
        return Err(format!("{setting}: the secret file {path} is empty"));
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

/// `url` with `password` as its password, for any password.
///
/// `Url::set_password` percent-encodes everything the URL syntax reserves, with one
/// exception: it leaves `%` as it is, so a password that holds `%41` would be sent to
/// the server as `A` once the Redis client decodes it. The `%` is therefore encoded
/// first. `setting` names the URL's setting in the error for a URL that cannot carry
/// a password at all (no host: a unix-socket URL).
pub fn url_with_password(setting: &str, url: &Url, password: &str) -> Result<Url, String> {
    let mut url = url.clone();
    url.set_password(Some(&password.replace('%', "%25")))
        .map_err(|()| {
            format!(
                "{setting} cannot carry a password: it has no host (a unix-socket URL, for \
                 example); use a URL with a host"
            )
        })?;
    Ok(url)
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
            ("abc\n\n", "abc\n"),
            ("abc\r\n\r\n", "abc\r\n"),
            ("abc\r", "abc\r"),
            (" abc \n", " abc "),
            ("a\nb\n", "a\nb"),
        ] {
            let file = TempFile::with(content.as_bytes());
            assert_eq!(read("setting", file.path()).unwrap(), value, "{content:?}");
        }
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
        let url = Url::parse("redis+unix:///run/redis.sock").unwrap();
        let error = url_with_password("redis_url", &url, "whatever").unwrap_err();
        assert!(
            error.contains("redis_url") && error.contains("cannot carry a password"),
            "{error}"
        );
        assert!(!error.contains("whatever"));
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
