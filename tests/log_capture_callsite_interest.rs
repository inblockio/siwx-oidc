//! `LogCapture` sees an event whose callsite another thread hit first.
//!
//! tracing-core caches, per callsite, whether any subscriber wants it. While
//! exactly one dispatcher is registered it computes that from the dispatcher of
//! the thread that first reaches the callsite. A capture is thread-local, so a
//! callsite first hit on a thread without one is cached as "never", and the
//! capturing thread then loses every later event from it. In a binary of many
//! parallel tests this made a log assertion fail about every other run.
//!
//! A test file of its own because the loss needs the capture to be the only
//! registered dispatcher: any other test that starts a `LogCapture` in this
//! process would hide it.

use siwx_oidc::test_support::LogCapture;

fn emit() {
    tracing::debug!("callsite-interest-probe");
}

#[test]
fn an_event_from_a_callsite_first_hit_on_another_thread_is_still_captured() {
    let logs = LogCapture::start();

    // The first hit on a thread that has no capture of its own.
    std::thread::spawn(emit).join().expect("probe thread");

    emit();
    assert!(
        logs.output().contains("callsite-interest-probe"),
        "the capture lost an event because another thread reached its callsite first"
    );
}
