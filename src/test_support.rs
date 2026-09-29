//! Redis for the Redis-backed tests: the one place that decides whether such a
//! test runs, skips, or fails.
//!
//! - `SIWX_TEST_REDIS_URL` names the Redis; the default is `redis://localhost`.
//! - Without `SIWX_TEST_REQUIRE_REDIS`, a test that cannot reach it prints one
//!   `SKIP <test>: …` line to stderr and returns, so `cargo test` still runs on
//!   a machine without Redis.
//! - With `SIWX_TEST_REQUIRE_REDIS=1` the same test panics instead. CI sets it,
//!   so a CI run can never report an unexercised Redis test as a pass.
//!
//! Not `#[cfg(test)]`, on purpose: the binary crate's unit tests and every
//! `tests/*.rs` file link this library compiled *without* `cfg(test)`, so a
//! test-only module would be invisible to all of them. Nothing outside tests
//! calls it, and it is hidden from the docs.

use std::io::Write;
use std::time::Duration;

use url::Url;

use crate::db::RedisClient;

/// Names the Redis the tests use.
pub const REDIS_URL_VAR: &str = "SIWX_TEST_REDIS_URL";

/// `1` turns an unreachable Redis into a test failure instead of a skip.
pub const REQUIRE_REDIS_VAR: &str = "SIWX_TEST_REQUIRE_REDIS";

const DEFAULT_REDIS_URL: &str = "redis://localhost";

/// How long the reachability probe waits for an address that neither answers
/// nor refuses. A refused connection fails at once.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The Redis URL the tests use: `SIWX_TEST_REDIS_URL`, else `redis://localhost`.
pub fn redis_url() -> Url {
    let raw = std::env::var(REDIS_URL_VAR).unwrap_or_else(|_| DEFAULT_REDIS_URL.to_string());
    Url::parse(&raw).unwrap_or_else(|e| panic!("{REDIS_URL_VAR}={raw:?} is not a URL: {e}"))
}

/// Whether `SIWX_TEST_REQUIRE_REDIS=1` is set.
///
/// Any value other than unset, empty, `0` or `1` is a panic rather than a
/// quiet "not required": a typo such as `true` must not switch the guard off.
pub fn redis_required() -> bool {
    required_from(std::env::var(REQUIRE_REDIS_VAR).ok().as_deref())
}

fn required_from(value: Option<&str>) -> bool {
    match value {
        None | Some("") | Some("0") => false,
        Some("1") => true,
        Some(other) => panic!("{REQUIRE_REDIS_VAR}={other:?}: use 1 to require Redis, or unset it"),
    }
}

/// A client for the test Redis, or `None` after [`skip_or_fail`] when it is
/// unreachable.
pub async fn redis() -> Option<RedisClient> {
    let url = redis_url();
    if let Err(reason) = probe(&url).await {
        return skip_or_fail(&format!("no Redis at {} ({reason})", redacted(&url)));
    }
    Some(
        RedisClient::new(&url)
            .await
            .unwrap_or_else(|e| panic!("{REDIS_URL_VAR}: cannot build a client: {e:#}")),
    )
}

/// One bounded `PING` on a fresh connection, proving a Redis answers at `url`.
///
/// `RedisClient::new` cannot answer this: it never connects (bb8 builds the
/// pool with `min_idle` 0), so it returns `Ok` with nothing listening, and the
/// first command then waits out bb8's 30-second connection timeout. That is
/// why the old per-module `RedisClient::new(..).ok()` guards never skipped:
/// without Redis those tests failed after 30 seconds.
pub async fn probe(url: &Url) -> Result<(), String> {
    use bb8_redis::redis;
    let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
    let ping = async {
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<String>(&mut conn).await
    };
    match tokio::time::timeout(PROBE_TIMEOUT, ping).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {PROBE_TIMEOUT:?}")),
    }
}

/// Skip the calling test with one `SKIP` line on stderr, or panic when
/// `SIWX_TEST_REQUIRE_REDIS=1`. Returns `None` so a caller can
/// `return skip_or_fail(..)` from an `Option`-returning helper.
///
/// The line is written to the stderr handle, not through `eprintln!`: libtest
/// captures `eprintln!` output and discards it for a passing test, and a
/// skipped test passes, so an `eprintln!` skip is silent in a plain
/// `cargo test`. The test is named from the current thread: libtest names each
/// test's thread after the test path, and a `#[tokio::test]` body runs on it.
pub fn skip_or_fail<T>(reason: &str) -> Option<T> {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unnamed test thread>")
        .to_string();
    assert!(
        !redis_required(),
        "{test}: {reason}; {REQUIRE_REDIS_VAR}=1 forbids skipping a Redis-backed test"
    );
    // One `write_all` of the whole line: stderr is unbuffered, so `writeln!`
    // would issue a write per piece and interleave with libtest's own output.
    let line =
        format!("SKIP {test}: {reason} (set {REQUIRE_REDIS_VAR}=1 to make this a failure)\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
    None
}

/// The URL without its password, for log lines.
fn redacted(url: &Url) -> Url {
    let mut shown = url.clone();
    let _ = shown.set_password(None);
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsed from a value, not from the process environment: setting the
    /// variable here would flip it for every Redis-backed test running
    /// concurrently in this binary.
    #[test]
    fn only_1_requires_redis_and_unset_empty_or_0_do_not() {
        assert!(required_from(Some("1")));
        assert!(!required_from(None));
        assert!(!required_from(Some("")));
        assert!(!required_from(Some("0")));
    }

    #[test]
    #[should_panic(expected = "use 1 to require Redis")]
    fn a_misspelt_require_value_is_a_panic_not_a_quiet_no() {
        required_from(Some("true"));
    }
}
