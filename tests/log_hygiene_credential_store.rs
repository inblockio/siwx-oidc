//! The credential store's boot check names the Redis it was pointed at. A Redis
//! URL carries its password (`redis://:password@host`), so neither the log line
//! nor the error that stops the boot may print it.
//!
//! A test file of its own because it sets a process-wide environment variable
//! and the store memoises its connection for the life of the process: no other
//! test may share this process.

use siwx_oidc::credential_store::{probe_at_boot, ENABLE_ENV};
use siwx_oidc::test_support::LogCapture;

#[tokio::test]
async fn the_boot_check_never_prints_the_redis_password() {
    let password = "hunter2-LOGHYGIENE";
    // A well-formed URL whose database number the Redis client refuses fails
    // the connect at once and takes the boot check's refusal path. (A URL
    // nobody answers on does not: the pool retries for minutes, which no test
    // can afford.)
    std::env::set_var(
        ENABLE_ENV,
        format!("redis://:{password}@redis.invalid:6379/not-a-number"),
    );

    let logs = LogCapture::start();
    let outcome = probe_at_boot().await;
    let output = logs.output();

    let error = outcome.expect_err("an unreachable store must refuse to boot");
    let error = format!("{error:#}");
    assert!(
        error.contains("redis.invalid"),
        "the refusal still names the host it could not reach: {error}"
    );
    assert!(
        !error.contains(password),
        "the boot error prints the Redis password: {error}"
    );
    assert!(
        !output.contains(password),
        "the logs print the Redis password:\n{output}"
    );
}
