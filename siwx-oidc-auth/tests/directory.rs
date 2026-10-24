//! The directory client, through its public API, against local servers only.
//!
//! The servers are in `directory/support.rs`: a fake siwx-oidc (the headless
//! sign-in flow, discovery, the key set, `/resolve`, `/register`) and a fake
//! homeserver (the directory module, the standard user directory, the profile
//! route). Time is a clock the tests move by hand, so the cache and token
//! lifetimes are checked at their edges without sleeping.

#[path = "directory/support.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use siwx_oidc_auth::directory::{
    register_public_client, DidState, DirectoryEntry, DirectoryError, DirectoryResults,
    ServiceSession, ServiceSessionConfig, Tuning,
};
use siwx_oidc_auth::SiwxKey;
use support::*;

const MIN: Duration = Duration::from_secs(60);

fn verified(did: &str) -> Value {
    json!({"state": "verified", "value": did})
}

fn states(results: &DirectoryResults) -> Vec<Value> {
    results
        .results
        .iter()
        .map(|e| serde_json::to_value(&e.did).unwrap())
        .collect()
}

/// One local hit with a valid published proof.
fn published(w: &World, name: &str) -> Value {
    let (m, d) = (mxid(name), did_of(name));
    hit(&m, Some(name), Some(w.issuer.field(&d, &m)))
}

// ---------------------------------------------------------------------------
// The result shape (plan 4.1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_results_serialize_exactly_as_plan_4_1() {
    let w = World::new().await;
    let (a, b, c) = (mxid("alice"), mxid("bob"), mxid("carol"));
    w.hs.module_hits(vec![
        hit(
            &a,
            Some("Alice"),
            Some(w.issuer.field(&did_of("Alice"), &a)),
        ),
        hit(&b, None, None),
        hit(
            &c,
            Some("Carol"),
            Some(json!({"did": did_of("Carol"), "proof": "x.y.z"})),
        ),
    ]);
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "a", 10)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&got).unwrap(),
        json!({
            "results": [
                {"mxid": a, "alias": "Alice", "did": {"state": "verified", "value": did_of("Alice")}},
                {"mxid": b, "did": {"state": "not_yet_published"}},
                {"mxid": c, "alias": "Carol", "did": {"state": "invalid"}},
            ],
            "limited": false
        })
    );
}

/// A COMPILE-TIME property asserted at run time, the way
/// `verified_did_cannot_be_deserialized` does it for `VerifiedDid`: a
/// deserializable "verified" value is an entrance that skips the proof check.
#[test]
fn the_result_types_cannot_be_deserialized() {
    #[allow(dead_code)]
    struct Probe<T>(std::marker::PhantomData<T>);
    impl<T: serde::de::DeserializeOwned> Probe<T> {
        fn deserializable() -> bool {
            true
        }
    }
    trait NotDeserializable {
        fn deserializable() -> bool {
            false
        }
    }
    impl<T> NotDeserializable for Probe<T> {}

    assert!(!Probe::<DirectoryResults>::deserializable());
    assert!(!Probe::<DirectoryEntry>::deserializable());
    assert!(!Probe::<DidState>::deserializable());
    // The control: the probe does detect a type that is deserializable.
    assert!(Probe::<Value>::deserializable());
}

// ---------------------------------------------------------------------------
// Client registration (RFC 7591)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_posts_a_public_client_and_returns_only_its_id() {
    let issuer = Issuer::start().await;
    let id = register_public_client(&issuer.mock.base, REDIRECT_URI, "Directory Service")
        .await
        .unwrap();
    assert_eq!(id, "registered-fixture-client");

    let sent = issuer.mock.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].path, "/register");
    assert_eq!(
        sent[0].json(),
        json!({
            "redirect_uris": [REDIRECT_URI],
            "client_name": "Directory Service",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        })
    );
}

#[tokio::test]
async fn a_refused_registration_is_an_error_naming_the_status() {
    let issuer = Issuer::start().await;
    issuer.with(|s| s.register_status = 400);
    let err = register_public_client(&issuer.mock.base, REDIRECT_URI, "x")
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("400"), "{err:#}");
}

// ---------------------------------------------------------------------------
// ServiceSession
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_session_signs_in_with_its_key_on_the_fixed_device() {
    let w = World::new().await;
    let session = w.session();
    assert_eq!(session.did(), w.service_key().did());
    assert_eq!(session.access_token().await.unwrap(), "access-1");

    let reqs = w.issuer.mock.requests();
    let authorize = reqs.iter().find(|r| r.path == "/authorize").unwrap();
    let q = authorize.query_pairs();
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], REDIRECT_URI);
    assert!(
        q["scope"].contains(&format!("urn:matrix:client:device:{DEVICE_ID}")),
        "{}",
        q["scope"]
    );
    // The signature of the key goes in the `siwx` cookie of /sign_in.
    let sign_in = reqs.iter().find(|r| r.path == "/sign_in").unwrap();
    let cookie = urlencoding::decode(&sign_in.headers["cookie"])
        .unwrap()
        .into_owned();
    assert!(cookie.contains(&w.service_key().did()), "{cookie}");
}

#[tokio::test]
async fn a_fresh_token_is_reused_without_another_request() {
    let w = World::new().await;
    let session = w.session();
    let first = session.access_token().await.unwrap();
    w.clock.advance(Duration::from_secs(200));
    assert_eq!(session.access_token().await.unwrap(), first);
    assert_eq!(w.issuer.sign_ins(), 1);
    assert_eq!(w.issuer.refreshes(), 0);
}

#[tokio::test]
async fn the_token_is_refreshed_before_it_expires() {
    let w = World::new().await;
    let session = w.session();
    assert_eq!(session.access_token().await.unwrap(), "access-1");

    // expires_in 300, refresh margin 30: still fresh at 269 s, renewed at 271 s.
    w.clock.advance(Duration::from_secs(269));
    assert_eq!(session.access_token().await.unwrap(), "access-1");
    assert_eq!(w.issuer.refreshes(), 0);
    w.clock.advance(Duration::from_secs(2));
    assert_eq!(session.access_token().await.unwrap(), "access-2");
    assert_eq!(w.issuer.refreshes(), 1);
    assert_eq!(w.issuer.sign_ins(), 1, "a refresh is not a new sign-in");

    let refresh = w
        .issuer
        .mock
        .requests()
        .into_iter()
        .find(|r| r.form().get("grant_type").map(String::as_str) == Some("refresh_token"))
        .unwrap();
    assert_eq!(refresh.form()["refresh_token"], "refresh-1");
    assert_eq!(refresh.form()["client_id"], CLIENT_ID);
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let w = World::new().await;
    let session = Arc::new(w.session());
    session.access_token().await.unwrap();
    w.clock.advance(Duration::from_secs(280));
    // Slow enough that every caller arrives while the refresh is in flight.
    w.issuer
        .with(|s| s.refresh_delay = Duration::from_millis(300));

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let s = session.clone();
        tasks.push(tokio::spawn(async move { s.access_token().await.unwrap() }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), "access-2");
    }
    assert_eq!(w.issuer.refreshes(), 1, "single flight");
    assert_eq!(w.issuer.sign_ins(), 1);
}

#[tokio::test]
async fn a_failed_refresh_falls_back_to_a_fresh_sign_in() {
    let w = World::new().await;
    let session = w.session();
    session.access_token().await.unwrap();
    w.issuer.with(|s| s.refresh_status = 400);
    w.clock.advance(Duration::from_secs(280));
    assert_eq!(session.access_token().await.unwrap(), "access-2");
    assert_eq!(w.issuer.refreshes(), 1, "the refresh was tried");
    assert_eq!(w.issuer.sign_ins(), 2, "and then the key signed in again");
}

#[tokio::test]
async fn without_a_refresh_token_the_session_signs_in_again() {
    let w = World::new().await;
    w.issuer.with(|s| s.issue_refresh = false);
    let session = w.session();
    session.access_token().await.unwrap();
    w.clock.advance(Duration::from_secs(280));
    assert_eq!(session.access_token().await.unwrap(), "access-2");
    assert_eq!(w.issuer.refreshes(), 0);
    assert_eq!(w.issuer.sign_ins(), 2);
}

#[tokio::test]
async fn a_sign_in_refusal_is_typed_and_only_a_transient_one_is_retryable() {
    for (code, retryable) in [
        ("access_denied", false),
        ("invalid_scope", false),
        ("temporarily_unavailable", true),
    ] {
        let w = World::new().await;
        w.issuer.with(|s| s.sign_in_error = Some(code.to_string()));
        let err = w.session().access_token().await.unwrap_err();
        assert!(
            matches!(err, DirectoryError::SignIn { .. }),
            "{code}: {err:?}"
        );
        assert_eq!(err.is_retryable(), retryable, "{code}");
    }
}

#[tokio::test]
async fn nothing_that_prints_a_session_or_its_errors_names_a_token_or_the_key() {
    let w = World::new().await;
    let session = w.session();
    session.access_token().await.unwrap();
    let printed = format!("{session:?}");
    assert!(
        !printed.contains("access-1") && !printed.contains("refresh-1"),
        "{printed}"
    );
    assert!(!printed.contains("PRIVATE"), "{printed}");
    let config = format!("{:?}", w.session_config());
    assert!(!config.contains("PRIVATE"), "{config}");
    let client = format!("{:?}", w.directory());
    assert!(!client.contains("access-1"), "{client}");
}

/// Tokens live in memory and the module writes and prints nothing: the code
/// before its test module names no file API and no output macro. A scan of the
/// source, like `tests/log_hygiene.rs` in the server crate, because a negative
/// like this has no behaviour to run.
#[test]
fn the_module_touches_no_file_and_prints_nothing() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/directory.rs")).unwrap();
    let code = src.split("\n#[cfg(test)]").next().unwrap();
    for banned in [
        "std::fs",
        "tokio::fs",
        "File::",
        "OpenOptions",
        "println!",
        "eprintln!",
        "print!(",
        "dbg!",
        "tracing::",
        "log::",
        "write_all",
    ] {
        assert!(
            !code.contains(banned),
            "src/directory.rs names `{banned}` outside its tests"
        );
    }
}

// ---------------------------------------------------------------------------
// search_for_asker: the module transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_module_is_asked_with_the_service_token_for_the_resolved_asker() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "  ada  ", 5)
        .await
        .unwrap();

    let resolve = w
        .issuer
        .mock
        .requests()
        .into_iter()
        .find(|r| r.path == "/resolve")
        .unwrap();
    assert_eq!(resolve.query_pairs()["did"], ASKER_DID);

    let call =
        w.hs.mock
            .requests()
            .into_iter()
            .find(|r| r.path == MODULE_PATH)
            .unwrap();
    assert_eq!(call.method, "POST");
    assert_eq!(call.bearer().as_deref(), Some("access-1"));
    assert_eq!(
        call.json(),
        json!({"asker": ASKER_MXID, "term": "ada", "limit": 5})
    );

    assert_eq!(got.results.len(), 1);
    assert_eq!(got.results[0].mxid, mxid("alice"));
    assert_eq!(got.results[0].alias.as_deref(), Some("alice"));
    assert_eq!(
        got.results[0].did.verified_did(),
        Some(did_of("alice").as_str())
    );
    assert!(!got.limited);
}

#[tokio::test]
async fn an_unknown_asker_gets_the_empty_result_and_the_module_is_not_called() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    let got = w
        .directory()
        .search_for_asker(&w.session(), "did:key:zNobodyKnowsThisOne", "ada", 5)
        .await
        .unwrap();
    assert!(got.results.is_empty() && !got.limited);
    assert_eq!(w.hs.module_calls(), 0);
    assert_eq!(w.issuer.sign_ins(), 0, "no token is needed to say nobody");
}

#[tokio::test]
async fn an_asker_no_sign_in_could_accept_gets_the_same_empty_result() {
    let w = World::new().await;
    w.issuer.with(|s| s.resolve_status = 400);
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap();
    assert!(got.results.is_empty());
    assert_eq!(w.hs.module_calls(), 0);
}

#[tokio::test]
async fn an_issuer_that_cannot_answer_resolve_fails_the_search_retryably() {
    let w = World::new().await;
    w.issuer.with(|s| s.resolve_status = 502);
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
    assert!(err.is_retryable());
    assert_eq!(w.hs.module_calls(), 0);
}

#[tokio::test]
async fn a_found_asker_is_cached_ten_minutes_and_a_miss_sixty_seconds() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    let resolves = |w: &World| w.issuer.mock.count("GET", "/resolve");

    for _ in 0..2 {
        dir.search_for_asker(&session, ASKER_DID, "ada", 5)
            .await
            .unwrap();
    }
    assert_eq!(resolves(&w), 1);
    w.clock.advance(9 * MIN + Duration::from_secs(59));
    dir.search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap();
    assert_eq!(resolves(&w), 1, "still cached at 9 min 59 s");
    w.clock.advance(Duration::from_secs(2));
    dir.search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap();
    assert_eq!(resolves(&w), 2, "asked again after ten minutes");

    // A miss is remembered for a minute at most, so a new account is found soon.
    let unknown = "did:key:zNotYetAnAccount";
    dir.search_for_asker(&session, unknown, "ada", 5)
        .await
        .unwrap();
    w.clock.advance(Duration::from_secs(59));
    dir.search_for_asker(&session, unknown, "ada", 5)
        .await
        .unwrap();
    assert_eq!(resolves(&w), 3, "the miss was cached");
    w.clock.advance(Duration::from_secs(2));
    w.issuer.with(|s| {
        s.resolve.insert(
            unknown.to_string(),
            "@newcomer-fixture:example.org".to_string(),
        );
    });
    dir.search_for_asker(&session, unknown, "ada", 5)
        .await
        .unwrap();
    assert_eq!(resolves(&w), 4, "asked again after a minute");
    assert_eq!(
        w.hs.module_calls(),
        5,
        "and the new account is searched for"
    );
}

#[tokio::test]
async fn a_rejected_service_token_signs_in_again_once_and_retries_once() {
    let w = World::new().await;
    let hits = vec![published(&w, "alice")];
    w.hs.on_module(move |_, n| {
        if n == 0 {
            Resp::json(401, json!({"errcode": "M_UNKNOWN_TOKEN"}))
        } else {
            Resp::json(200, json!({"results": hits.clone(), "limited": false}))
        }
    });
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap();
    assert_eq!(got.results.len(), 1);
    let bearers: Vec<_> =
        w.hs.mock
            .requests()
            .iter()
            .filter(|r| r.path == MODULE_PATH)
            .map(|r| r.bearer().unwrap())
            .collect();
    assert_eq!(bearers, ["access-1", "access-2"]);
    assert_eq!(w.issuer.sign_ins(), 2, "a fresh sign-in, not a refresh");
    assert_eq!(w.issuer.refreshes(), 0);
}

#[tokio::test]
async fn a_second_401_is_unauthorized_and_is_not_retried_again() {
    let w = World::new().await;
    w.hs.on_module(|_, _| Resp::json(401, json!({"errcode": "M_UNKNOWN_TOKEN"})));
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Unauthorized), "{err:?}");
    assert!(!err.is_retryable());
    assert_eq!(w.hs.module_calls(), 2);
    assert_eq!(w.issuer.sign_ins(), 2);
}

#[tokio::test]
async fn a_403_is_not_admitted_and_signs_in_no_more() {
    let w = World::new().await;
    w.hs.on_module(|_, _| Resp::json(403, json!({"errcode": "M_FORBIDDEN"})));
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::NotAdmitted), "{err:?}");
    assert!(!err.is_retryable());
    assert_eq!(w.hs.module_calls(), 1);
    assert_eq!(w.issuer.sign_ins(), 1);
}

#[tokio::test]
async fn a_429_is_rate_limited_with_the_servers_hint() {
    let w = World::new().await;
    w.hs.on_module(|_, _| {
        Resp::json(
            429,
            json!({"errcode": "M_LIMIT_EXCEEDED", "retry_after_ms": 1500}),
        )
    });
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    match &err {
        DirectoryError::RateLimited { retry_after } => {
            assert_eq!(*retry_after, Some(Duration::from_millis(1500)))
        }
        other => panic!("{other:?}"),
    }
    assert!(err.is_retryable());
}

#[tokio::test]
async fn a_server_error_from_the_module_is_retryable_and_names_no_term() {
    let w = World::new().await;
    w.hs.on_module(|_, _| Resp::json(500, json!({"errcode": "M_UNKNOWN"})));
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "a-secret-search-term", 5)
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("a-secret-search-term"));
}

#[tokio::test]
async fn a_slow_module_times_out_with_a_retryable_error() {
    let w = World::new().await;
    w.hs.on_module(|_, _| {
        Resp::json(200, json!({"results": [], "limited": false})).delayed(Duration::from_secs(2))
    });
    let tuning = Tuning {
        request_timeout: Duration::from_millis(200),
        ..Tuning::default()
    };
    let err = w
        .directory_with(tuning)
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn an_answer_may_fill_256_kib_and_not_one_byte_more() {
    const CAP: usize = 256 * 1024;
    let w = World::new().await;
    // Valid JSON padded with spaces to an exact size.
    let padded = |n: usize| {
        let mut body = br#"{"results":[],"limited":false}"#.to_vec();
        body.resize(n, b' ');
        body
    };
    let at_cap = padded(CAP);
    w.hs.on_module(move |_, _| Resp::bytes(200, at_cap.clone()));
    let dir = w.directory();
    let session = w.session();
    dir.search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap();

    let over = padded(CAP + 1);
    w.hs.on_module(move |_, _| Resp::bytes(200, over.clone()));
    let err = dir
        .search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Protocol(_)), "{err:?}");
}

#[tokio::test]
async fn more_rows_than_the_limit_are_cut_and_marked_limited() {
    let w = World::new().await;
    w.hs.module_hits(vec![
        published(&w, "a1"),
        published(&w, "a2"),
        published(&w, "a3"),
    ]);
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "a", 2)
        .await
        .unwrap();
    assert_eq!(got.results.len(), 2);
    assert!(got.limited);
}

#[tokio::test]
async fn the_module_may_answer_the_empty_object_when_the_directory_is_off() {
    let w = World::new().await;
    w.hs.on_module(|_, _| Resp::json(200, json!({})));
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
        .await
        .unwrap();
    assert!(got.results.is_empty() && !got.limited);
}

#[tokio::test]
async fn a_malformed_module_answer_is_an_error_never_an_empty_result() {
    for body in [
        json!([1, 2]),
        json!({"results": "no"}),
        json!({"results": [{"display_name": "x"}]}),
        json!({"results": [{"user_id": "not-an-mxid"}]}),
    ] {
        let w = World::new().await;
        w.hs.on_module(move |_, _| Resp::json(200, body.clone()));
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(matches!(err, DirectoryError::Protocol(_)), "{err:?}");
    }
}

#[tokio::test]
async fn the_bounds_are_checked_before_any_call_on_both_transports() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    let long = "a".repeat(65);
    let bad: [(&str, u32); 5] = [("", 5), ("   \t ", 5), (&long, 5), ("ok", 0), ("ok", 21)];
    for (term, limit) in bad {
        let err = dir
            .search_for_asker(&session, ASKER_DID, term, limit)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::InvalidInput(_)),
            "{term:?} {limit}: {err:?}"
        );
        assert!(!err.is_retryable());
        let err = dir
            .search_as_user("user-token", term, limit)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::InvalidInput(_)),
            "{term:?} {limit}: {err:?}"
        );
    }
    // An empty asker and an empty token are refused before any call too.
    let before = w.requests_total();
    let err = dir
        .search_for_asker(&session, "", "ok", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::InvalidInput(_)), "{err:?}");
    let err = dir.search_as_user("", "ok", 5).await.unwrap_err();
    assert!(matches!(err, DirectoryError::InvalidInput(_)), "{err:?}");
    assert_eq!(w.requests_total(), before);
    // The bounds themselves are allowed: 1 and 20, and 64 characters.
    let edge = "é".repeat(64);
    let padded = format!("  {edge}  ");
    dir.search_for_asker(&session, ASKER_DID, &padded, 20)
        .await
        .unwrap();
    dir.search_for_asker(&session, ASKER_DID, "a", 1)
        .await
        .unwrap();
    let sent =
        w.hs.mock
            .requests()
            .into_iter()
            .find(|r| r.path == MODULE_PATH)
            .unwrap()
            .json();
    assert_eq!(
        sent["term"],
        edge.as_str(),
        "the term goes out trimmed, counted in characters"
    );
}

#[tokio::test]
async fn nothing_was_sent_for_the_rejected_inputs() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    assert!(dir
        .search_for_asker(&session, ASKER_DID, "", 5)
        .await
        .is_err());
    assert!(dir
        .search_for_asker(&session, ASKER_DID, "ok", 21)
        .await
        .is_err());
    assert!(dir.search_as_user("t", "ok", 0).await.is_err());
    assert_eq!(w.requests_total(), 0);
}

#[tokio::test]
async fn a_session_of_another_deployment_never_gets_to_send_its_token() {
    let w = World::new().await;
    let other = ServiceSession::new(ServiceSessionConfig::new(
        "http://127.0.0.1:1",
        &w.hs.mock.base,
        CLIENT_ID,
        REDIRECT_URI,
        DEVICE_ID,
        SiwxKey::generate_ed25519(),
    ))
    .unwrap();
    let err = w
        .directory()
        .search_for_asker(&other, ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::InvalidInput(_)), "{err:?}");
    assert_eq!(w.requests_total(), 0);
}

// ---------------------------------------------------------------------------
// The proof check
// ---------------------------------------------------------------------------

/// A proof whose payload was changed after signing.
fn tampered(proof: &str, name: &str, value: Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let parts: Vec<&str> = proof.split('.').collect();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    payload[name] = value;
    let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    format!("{}.{forged}.{}", parts[0], parts[2])
}

#[tokio::test]
async fn each_hit_is_verified_not_yet_published_or_invalid_by_its_own_proof() {
    let w = World::new().await;
    let (alice, bob, carol, dave, erin, frank, gina, remote, hank) = (
        mxid("alice"),
        mxid("bob"),
        mxid("carol"),
        mxid("dave"),
        mxid("erin"),
        mxid("frank"),
        mxid("gina"),
        "@carol:other.example".to_string(),
        mxid("hank"),
    );
    let ok = w.issuer.field(&did_of("Alice"), &alice);
    // The unsigned `did` member names someone else; only the signed `sub` counts.
    let lying = json!({"did": did_of("Mallory"), "proof": w.issuer.proof(&did_of("Bob"), &bob)});
    let proof_of_alice_for_carol =
        json!({"did": did_of("Alice"), "proof": w.issuer.proof(&did_of("Alice"), &alice)});
    let forged = json!({"did": did_of("Dave"), "proof": tampered(&w.issuer.proof(&did_of("Dave"), &dave), "sub", json!(did_of("Mallory")))});
    let remote_proof = w.issuer.field(&did_of("Remote"), &remote);
    w.hs.module_hits(vec![
        hit(&alice, Some("Alice"), Some(ok)),
        hit(&bob, Some("Bob"), Some(lying)),
        hit(&carol, Some("Carol"), Some(proof_of_alice_for_carol)),
        hit(&dave, Some("Dave"), Some(forged)),
        hit(&erin, Some("Erin"), None),
        hit(&frank, Some("Frank"), Some(json!({"did": did_of("Frank")}))),
        hit(
            &gina,
            Some("Gina"),
            Some(json!({"did": did_of("Gina"), "proof": ""})),
        ),
        hit(&remote, Some("Remote"), Some(remote_proof)),
        hit(&hank, Some("Hank"), Some(json!(did_of("Hank")))),
    ]);
    let got = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "a", 20)
        .await
        .unwrap();
    assert_eq!(
        states(&got),
        vec![
            verified(&did_of("Alice")),
            verified(&did_of("Bob")), // the signed sub, not the plain member
            json!({"state": "invalid"}), // a proof for another MXID
            json!({"state": "invalid"}), // a tampered payload
            json!({"state": "not_yet_published"}), // no field
            json!({"state": "not_yet_published"}), // a field without a proof
            json!({"state": "not_yet_published"}), // an empty proof is no proof
            json!({"state": "not_yet_published"}), // a remote user, whatever the field says
            json!({"state": "not_yet_published"}), // the legacy bare string
        ]
    );
}

#[tokio::test]
async fn discovery_and_keys_are_fetched_once_and_cached_five_minutes() {
    let w = World::new().await;
    let (a, b, c) = (
        published(&w, "alice"),
        published(&w, "bob"),
        published(&w, "carol"),
    );
    w.hs.on_module(move |_, n| {
        let hits = vec![[&a, &b, &c][n].clone()];
        Resp::json(200, json!({"results": hits, "limited": false}))
    });
    let dir = w.directory();
    let session = w.session();
    let fetches = |w: &World| {
        (
            w.issuer
                .mock
                .count("GET", "/.well-known/openid-configuration"),
            w.issuer.mock.count("GET", "/jwk"),
        )
    };
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    w.clock.advance(4 * MIN);
    let second = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert!(
        second.results[0].did.verified_did().is_some(),
        "verified from the cached keys"
    );
    assert_eq!(fetches(&w), (1, 1));
    w.clock.advance(MIN + Duration::from_secs(1));
    let third = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert!(third.results[0].did.verified_did().is_some());
    assert_eq!(fetches(&w), (2, 2), "refetched after five minutes");
}

#[tokio::test]
async fn a_warm_search_costs_one_request_and_none_to_the_issuer() {
    // Plan H6: with the caches warm, a search is the module call and nothing else.
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice"), published(&w, "bob")]);
    let dir = w.directory();
    let session = w.session();
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();

    let (issuer, homeserver) = (w.issuer.mock.total(), w.hs.mock.total());
    let again = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert!(again.results.iter().all(|e| e.did.verified_did().is_some()));
    assert_eq!(
        w.issuer.mock.total(),
        issuer,
        "no resolve, no keys, no token"
    );
    assert_eq!(w.hs.mock.total(), homeserver + 1, "only the module call");
}

#[tokio::test]
async fn a_search_with_no_proof_to_check_fetches_no_keys() {
    let w = World::new().await;
    w.hs.module_hits(vec![
        hit(&mxid("alice"), None, None),
        hit("@r:other.example", None, None),
    ]);
    w.directory()
        .search_for_asker(&w.session(), ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(
        w.issuer
            .mock
            .count("GET", "/.well-known/openid-configuration"),
        0
    );
    assert_eq!(w.issuer.mock.count("GET", "/jwk"), 0);
}

#[tokio::test]
async fn a_verified_result_is_kept_for_ten_minutes_and_not_a_second_longer() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    let dir = w.directory();
    let session = w.session();
    let ask = || dir.search_for_asker(&session, ASKER_DID, "a", 5);

    assert!(ask().await.unwrap().results[0].did.verified_did().is_some());
    // The issuer drops the key (a rotation, a compromise): its JWKS no longer has it.
    w.issuer.with(|s| s.jwks = json!({"keys": []}));

    w.clock.advance(9 * MIN + Duration::from_secs(59));
    let still = ask().await.unwrap();
    assert!(
        still.results[0].did.verified_did().is_some(),
        "within ten minutes it still stands"
    );
    w.clock.advance(Duration::from_secs(2));
    let gone = ask().await.unwrap();
    assert_eq!(
        gone.results[0].did,
        DidState::Invalid,
        "after ten minutes it is checked again"
    );
}

#[tokio::test]
async fn a_cached_verification_is_for_that_mxid_and_that_proof_only() {
    let w = World::new().await;
    let alice_field = w.issuer.field(&did_of("Alice"), &mxid("alice"));
    w.hs.module_hits(vec![hit(&mxid("alice"), None, Some(alice_field.clone()))]);
    let dir = w.directory();
    let session = w.session();
    assert!(dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap()
        .results[0]
        .did
        .verified_did()
        .is_some());

    // Bob copies Alice's genuine proof into his own profile.
    w.hs.module_hits(vec![hit(&mxid("bob"), None, Some(alice_field))]);
    let replay = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(replay.results[0].did, DidState::Invalid);

    // Alice herself, with a different proof: the cached verdict is not hers to reuse.
    let other = w.issuer.field(&did_of("AliceTwo"), &mxid("alice"));
    w.hs.module_hits(vec![hit(&mxid("alice"), None, Some(other))]);
    let again = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(
        again.results[0].did.verified_did(),
        Some(did_of("AliceTwo").as_str())
    );
    let forged = tampered(
        &w.issuer.proof(&did_of("Alice"), &mxid("alice")),
        "sub",
        json!(did_of("Mallory")),
    );
    w.hs.module_hits(vec![hit(
        &mxid("alice"),
        None,
        Some(json!({"did": did_of("Alice"), "proof": forged})),
    )]);
    let forged = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(forged.results[0].did, DidState::Invalid);
}

#[tokio::test]
async fn an_invalid_proof_is_never_remembered_as_verified() {
    let w = World::new().await;
    let key2 = "fixture-kid-2";
    let (m, d) = (mxid("alice"), did_of("Alice"));
    let proof = w.issuer.proof_with(key2, &d, &m, &w.issuer.mock.base);
    w.hs.module_hits(vec![hit(&m, None, Some(json!({"did": d, "proof": proof})))]);
    let dir = w.directory();
    let session = w.session();
    let ask = || dir.search_for_asker(&session, ASKER_DID, "a", 5);

    assert_eq!(
        ask().await.unwrap().results[0].did,
        DidState::Invalid,
        "kid-2 is not in the key set"
    );
    assert_eq!(dir.cache_stats().verified, 0);

    // The issuer publishes kid-2. The cached key set is the old one for up to five minutes.
    let jwk2 = w.issuer.with(|s| jwk_of(&s.proof_key, key2));
    w.issuer
        .with(|s| s.jwks["keys"].as_array_mut().unwrap().push(jwk2));
    assert_eq!(ask().await.unwrap().results[0].did, DidState::Invalid);
    w.clock.advance(5 * MIN + Duration::from_secs(1));
    let now = ask().await.unwrap();
    assert!(
        now.results[0].did.verified_did().is_some(),
        "the earlier invalid left nothing behind"
    );
}

#[tokio::test]
async fn a_failure_to_get_the_keys_fails_the_search_and_is_stored_nowhere() {
    enum Fault {
        Discovery,
        Keys,
        SlowKeys,
    }
    for fault in [Fault::Discovery, Fault::Keys, Fault::SlowKeys] {
        let w = World::new().await;
        w.hs.module_hits(vec![published(&w, "alice")]);
        let tuning = Tuning {
            request_timeout: Duration::from_millis(250),
            ..Tuning::default()
        };
        let dir = w.directory_with(tuning);
        let session = w.session();
        match fault {
            Fault::Discovery => w.issuer.with(|s| s.discovery_status = 500),
            Fault::Keys => w.issuer.with(|s| s.jwks_status = 500),
            Fault::SlowKeys => w.issuer.with(|s| s.jwks_delay = Duration::from_secs(2)),
        }
        let err = dir
            .search_for_asker(&session, ASKER_DID, "a", 5)
            .await
            .unwrap_err();
        assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
        assert!(err.is_retryable());
        let stats = dir.cache_stats();
        assert_eq!((stats.verified, stats.keys_cached), (0, false));

        // The issuer comes back: the same search verifies, so nothing of the failure was kept.
        w.issuer.with(|s| {
            s.discovery_status = 200;
            s.jwks_status = 200;
            s.jwks_delay = Duration::ZERO;
        });
        let again = dir
            .search_for_asker(&session, ASKER_DID, "a", 5)
            .await
            .unwrap();
        assert!(again.results[0].did.verified_did().is_some());
    }
}

#[tokio::test]
async fn a_discovery_document_naming_another_issuer_verifies_nothing() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    w.issuer
        .with(|s| s.discovery_issuer = Some("https://elsewhere.example.org".into()));
    let err = w
        .directory()
        .search_for_asker(&w.session(), ASKER_DID, "a", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
}

#[tokio::test]
async fn the_caches_are_bounded() {
    let w = World::new().await;
    let tuning = Tuning {
        max_cache_entries: 3,
        ..Tuning::default()
    };
    let dir = w.directory_with(tuning);
    let session = w.session();
    let names = ["n1", "n2", "n3", "n4", "n5"];
    w.hs.module_hits(names.iter().map(|n| published(&w, n)).collect());
    let got = dir
        .search_for_asker(&session, ASKER_DID, "n", 20)
        .await
        .unwrap();
    assert!(got.results.iter().all(|e| e.did.verified_did().is_some()));
    assert_eq!(dir.cache_stats().verified, 3);

    for i in 0..5 {
        let did = format!("did:key:zAsker{i}");
        w.issuer.with(|s| {
            s.resolve
                .insert(did.clone(), format!("@asker{i}-fixture:example.org"));
        });
        dir.search_for_asker(&session, &did, "n", 5).await.unwrap();
    }
    assert_eq!(dir.cache_stats().resolved, 3);
}

// ---------------------------------------------------------------------------
// search_as_user: the user's own Matrix session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_users_own_token_searches_and_the_profiles_are_read_without_it() {
    let w = World::new().await;
    let (a, b) = (mxid("alice"), mxid("bob"));
    w.hs.directory_rows(vec![
        json!({"user_id": a, "display_name": "Alice", "avatar_url": "mxc://example.org/x"}),
        json!({"user_id": b}),
    ]);
    w.hs.profile(&a, Some(w.issuer.field(&did_of("Alice"), &a)));
    w.hs.profile(&b, None);
    let got = w
        .directory()
        .search_as_user("user-token-fixture", "  al ", 7)
        .await
        .unwrap();

    let call =
        w.hs.mock
            .requests()
            .into_iter()
            .find(|r| r.path == USER_DIRECTORY_PATH)
            .unwrap();
    assert_eq!(call.bearer().as_deref(), Some("user-token-fixture"));
    assert_eq!(call.json(), json!({"search_term": "al", "limit": 7}));
    for r in
        w.hs.mock
            .requests()
            .iter()
            .filter(|r| r.path.starts_with("/_matrix/client/v3/profile/"))
    {
        assert!(
            !r.headers.contains_key("authorization"),
            "a profile read carries no credential"
        );
        assert!(r.path.ends_with("/io.inblock.did"), "{}", r.path);
    }
    assert_eq!(
        w.issuer.mock.count("POST", "/token"),
        0,
        "no service sign-in is involved"
    );
    assert_eq!(
        serde_json::to_value(&got).unwrap(),
        json!({"results": [
            {"mxid": a, "alias": "Alice", "did": {"state": "verified", "value": did_of("Alice")}},
            {"mxid": b, "did": {"state": "not_yet_published"}},
        ], "limited": false})
    );
}

#[tokio::test]
async fn at_most_eight_profiles_are_read_at_a_time() {
    let w = World::new().await;
    let names: Vec<String> = (0..20).map(|i| format!("u{i}")).collect();
    w.hs.directory_rows(names.iter().map(|n| json!({"user_id": mxid(n)})).collect());
    for n in &names {
        let m = mxid(n);
        w.hs.profile(&m, Some(w.issuer.field(&did_of(n), &m)));
    }
    w.hs.profile_delay(Duration::from_millis(120));
    let got = w
        .directory()
        .search_as_user("user-token-fixture", "u", 20)
        .await
        .unwrap();
    assert_eq!(got.results.len(), 20);
    assert!(got.results.iter().all(|e| e.did.verified_did().is_some()));
    assert_eq!(w.hs.profile_reads(), 20);
    assert_eq!(
        w.hs.mock.max_in_flight(),
        8,
        "concurrent, and never more than eight"
    );
}

#[tokio::test]
async fn a_remote_user_is_not_asked_for_and_a_failing_profile_fails_the_search() {
    let w = World::new().await;
    let (a, remote) = (mxid("alice"), "@carol:other.example".to_string());
    w.hs.directory_rows(vec![json!({"user_id": remote}), json!({"user_id": a})]);
    w.hs.profile(&a, Some(json!({"did": did_of("Alice")})));
    let got = w.directory().search_as_user("t", "a", 5).await.unwrap();
    assert_eq!(states(&got), vec![json!({"state": "not_yet_published"}); 2]);
    assert_eq!(
        w.hs.profile_reads(),
        1,
        "the remote user's profile was not read"
    );

    // A profile that cannot be read is an unknown state, not a verdict about the person.
    w.hs.profile_status(&a, 500);
    let err = w.directory().search_as_user("t", "a", 5).await.unwrap_err();
    assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn the_users_token_being_refused_is_unauthorized_and_is_not_retried() {
    let w = World::new().await;
    w.hs.on_user_directory(|_, _| Resp::json(401, json!({"errcode": "M_UNKNOWN_TOKEN"})));
    let err = w
        .directory()
        .search_as_user("stale", "a", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Unauthorized), "{err:?}");
    assert_eq!(w.hs.mock.count("POST", USER_DIRECTORY_PATH), 1);

    w.hs.on_user_directory(|_, _| {
        Resp::json(
            429,
            json!({"errcode": "M_LIMIT_EXCEEDED", "retry_after_ms": 800}),
        )
    });
    let err = w.directory().search_as_user("t", "a", 5).await.unwrap_err();
    assert!(matches!(err, DirectoryError::RateLimited { .. }), "{err:?}");
}

#[tokio::test]
async fn both_transports_give_the_same_answer_for_the_same_people() {
    let w = World::new().await;
    let (a, b, c) = (mxid("alice"), mxid("bob"), mxid("carol"));
    let fields = [
        Some(w.issuer.field(&did_of("Alice"), &a)),
        None,
        Some(json!({"did": did_of("Carol"), "proof": w.issuer.proof(&did_of("Carol"), &a)})),
    ];
    w.hs.module_hits(vec![
        hit(&a, Some("Alice"), fields[0].clone()),
        hit(&b, Some("Bob"), fields[1].clone()),
        hit(&c, Some("Carol"), fields[2].clone()),
    ]);
    w.hs.directory_rows(vec![
        json!({"user_id": a, "display_name": "Alice"}),
        json!({"user_id": b, "display_name": "Bob"}),
        json!({"user_id": c, "display_name": "Carol"}),
    ]);
    for (m, f) in [&a, &b, &c].into_iter().zip(fields) {
        w.hs.profile(m, f);
    }
    let dir = w.directory();
    let via_module = dir
        .search_for_asker(&w.session(), ASKER_DID, "a", 10)
        .await
        .unwrap();
    let via_user = dir.search_as_user("t", "a", 10).await.unwrap();
    assert_eq!(via_module, via_user);
    assert_eq!(
        states(&via_user),
        vec![
            verified(&did_of("Alice")),
            json!({"state": "not_yet_published"}),
            json!({"state": "invalid"})
        ]
    );
}

// ---------------------------------------------------------------------------
// Follow-ups from the PR 88 review (issue 89)
// ---------------------------------------------------------------------------

/// Eight callers at once, each holding its own handle to the session.
async fn eight_callers(session: Arc<ServiceSession>) -> Vec<Result<String, DirectoryError>> {
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = session.clone();
        tasks.push(tokio::spawn(async move { s.access_token().await }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

#[tokio::test]
async fn waiters_share_one_failed_renewal_instead_of_signing_in_one_after_another() {
    // With the cooldown at zero the sharing is the waiters' own doing, not the
    // cooldown's.
    for cooldown in [Duration::from_secs(5), Duration::ZERO] {
        let w = World::new().await;
        w.issuer.with(|s| s.sign_in_delay = Duration::from_secs(3));
        let tuning = Tuning {
            sign_in_timeout: Duration::from_millis(300),
            failed_sign_in_cooldown: cooldown,
            ..Tuning::default()
        };
        let session = Arc::new(w.session_with(tuning));
        let started = std::time::Instant::now();
        for got in eight_callers(session).await {
            let err = got.unwrap_err();
            assert!(matches!(err, DirectoryError::SignIn { .. }), "{err:?}");
            assert!(err.is_retryable(), "a timeout is worth another try");
        }
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "eight callers waited {:?}: one after another, not together",
            started.elapsed()
        );
        assert_eq!(
            w.issuer.mock.count("GET", "/sign_in"),
            1,
            "one attempt in flight, its outcome shared"
        );
    }
}

#[tokio::test]
async fn after_a_failed_sign_in_the_next_try_waits_out_the_cooldown() {
    let w = World::new().await;
    w.issuer
        .with(|s| s.sign_in_error = Some("temporarily_unavailable".into()));
    let session = w.session();
    let first = session.access_token().await.unwrap_err();
    assert!(first.is_retryable(), "{first:?}");
    assert_eq!(w.issuer.mock.count("GET", "/sign_in"), 1);

    // The issuer is back, but the cooldown has not passed: the answer is the
    // failure that was just seen, and nothing is sent.
    w.issuer.with(|s| s.sign_in_error = None);
    w.clock.advance(Duration::from_millis(4900));
    let second = session.access_token().await.unwrap_err();
    assert!(
        matches!(second, DirectoryError::SignIn { .. }),
        "{second:?}"
    );
    assert_eq!(second.to_string(), first.to_string());
    assert_eq!(second.is_retryable(), first.is_retryable());
    assert_eq!(w.issuer.mock.count("GET", "/sign_in"), 1, "no request");

    // Five seconds after the failure, the next call tries again.
    w.clock.advance(Duration::from_millis(100));
    assert_eq!(session.access_token().await.unwrap(), "access-1");
    assert_eq!(w.issuer.mock.count("GET", "/sign_in"), 2);
}

#[tokio::test]
async fn the_cooldown_is_a_tuning_and_zero_means_no_waiting() {
    let w = World::new().await;
    w.issuer
        .with(|s| s.sign_in_error = Some("temporarily_unavailable".into()));
    let tuning = Tuning {
        failed_sign_in_cooldown: Duration::ZERO,
        ..Tuning::default()
    };
    let session = w.session_with(tuning);
    session.access_token().await.unwrap_err();
    w.issuer.with(|s| s.sign_in_error = None);
    assert_eq!(session.access_token().await.unwrap(), "access-1");
}

#[tokio::test]
async fn a_failed_renewal_is_shared_by_a_caller_that_was_refused_its_token() {
    // The module refuses the token, and the sign-in that should replace it
    // fails: the caller gets that failure, and the second caller (inside the
    // cooldown) the same one without a request.
    let w = World::new().await;
    w.hs.on_module(|_, _| Resp::json(401, json!({"errcode": "M_UNKNOWN_TOKEN"})));
    let dir = w.directory();
    let session = w.session();
    session.access_token().await.unwrap();
    w.issuer
        .with(|s| s.sign_in_error = Some("temporarily_unavailable".into()));
    let err = dir
        .search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::SignIn { .. }), "{err:?}");
    let again = dir
        .search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap_err();
    assert!(matches!(again, DirectoryError::SignIn { .. }), "{again:?}");
    assert_eq!(
        w.issuer.mock.count("GET", "/sign_in"),
        2,
        "the first sign-in and the one that failed; the second caller sent nothing"
    );
}

#[tokio::test]
async fn an_absurd_expires_in_is_capped_and_never_loses_the_new_tokens() {
    for expires_in in [u64::MAX, u64::MAX / 2, 1 << 40] {
        let w = World::new().await;
        w.issuer.with(|s| s.expires_in = Some(expires_in));
        let session = w.session();
        assert_eq!(session.access_token().await.unwrap(), "access-1");

        // Capped at 24 hours: good for 23, renewed after 25.
        w.clock.advance(Duration::from_secs(23 * 3600));
        assert_eq!(session.access_token().await.unwrap(), "access-1");
        assert_eq!(w.issuer.refreshes(), 0);
        w.issuer.with(|s| s.expires_in = Some(300));
        w.clock.advance(Duration::from_secs(2 * 3600));
        assert_eq!(session.access_token().await.unwrap(), "access-2");
        assert_eq!(
            w.issuer.refreshes(),
            1,
            "renewed with the refresh token the first answer brought"
        );
        assert_eq!(w.issuer.sign_ins(), 1);
    }
}

/// A body over the cap, valid JSON padded with spaces.
fn over_the_cap() -> Vec<u8> {
    let mut body = br#"{"errcode":"M_LARGE"}"#.to_vec();
    body.resize(256 * 1024 + 1, b' ');
    body
}

#[tokio::test]
async fn an_error_status_is_classified_by_its_status_however_large_its_body() {
    for chunked in [false, true] {
        let answer = move |status: u16| {
            let r = Resp::bytes(status, over_the_cap());
            if chunked {
                r.chunked()
            } else {
                r
            }
        };

        // 429, 5xx and 403 on the service transport.
        let w = World::new().await;
        w.hs.on_module(move |_, _| answer(429));
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::RateLimited { .. }),
            "chunked {chunked}: {err:?}"
        );
        assert!(err.is_retryable());

        let w = World::new().await;
        w.hs.on_module(move |_, _| answer(503));
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::Unavailable(_)),
            "chunked {chunked}: {err:?}"
        );
        assert!(err.is_retryable());

        let w = World::new().await;
        w.hs.on_module(move |_, _| answer(403));
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::NotAdmitted),
            "chunked {chunked}: {err:?}"
        );

        // Any other status keeps the status and no code.
        let w = World::new().await;
        w.hs.on_module(move |_, _| answer(404));
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DirectoryError::UnexpectedStatus {
                    status: 404,
                    errcode: None
                }
            ),
            "chunked {chunked}: {err:?}"
        );

        // A 401 still signs the service in again once, and retries once.
        let w = World::new().await;
        let hits = vec![published(&w, "alice")];
        w.hs.on_module(move |_, n| {
            if n == 0 {
                answer(401)
            } else {
                Resp::json(200, json!({"results": hits.clone(), "limited": false}))
            }
        });
        let got = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap();
        assert_eq!(got.results.len(), 1, "chunked {chunked}");
        assert_eq!(w.issuer.sign_ins(), 2, "chunked {chunked}: signed in again");
        assert_eq!(w.hs.module_calls(), 2);

        // And on the user transport.
        let w = World::new().await;
        w.hs.on_user_directory(move |_, _| answer(401));
        let err = w
            .directory()
            .search_as_user("t", "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::Unauthorized),
            "chunked {chunked}: {err:?}"
        );

        // A profile read on the user transport.
        let w = World::new().await;
        w.hs.directory_rows(vec![json!({"user_id": mxid("alice")})]);
        w.hs.profile_answer(&mxid("alice"), answer(503));
        let err = w
            .directory()
            .search_as_user("t", "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::Unavailable(_)),
            "chunked {chunked}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_success_over_the_cap_is_still_a_protocol_error_with_or_without_a_length() {
    for chunked in [false, true] {
        let w = World::new().await;
        w.hs.on_module(move |_, _| {
            let mut body = br#"{"results":[],"limited":false}"#.to_vec();
            body.resize(256 * 1024 + 1, b' ');
            let r = Resp::bytes(200, body);
            if chunked {
                r.chunked()
            } else {
                r
            }
        });
        let err = w
            .directory()
            .search_for_asker(&w.session(), ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::Protocol(_)),
            "chunked {chunked}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_chunked_answer_without_a_length_is_cut_off_at_the_cap() {
    const CAP: usize = 256 * 1024;
    let w = World::new().await;
    let padded = |n: usize| {
        let mut body = br#"{"results":[],"limited":false}"#.to_vec();
        body.resize(n, b' ');
        body
    };
    // Exactly the cap, streamed: accepted.
    let at_cap = padded(CAP);
    w.hs.on_module(move |_, _| Resp::bytes(200, at_cap.clone()).chunked());
    let dir = w.directory();
    let session = w.session();
    dir.search_for_asker(&session, ASKER_DID, "ada", 5)
        .await
        .unwrap();

    // One byte more, and a body of 8 MiB: both refused, the second without
    // being buffered (the server's writes fail once the client hangs up).
    for size in [CAP + 1, 8 * 1024 * 1024] {
        let over = padded(size);
        w.hs.on_module(move |_, _| Resp::bytes(200, over.clone()).chunked());
        let err = dir
            .search_for_asker(&session, ASKER_DID, "ada", 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::Protocol(_)),
            "{size}: {err:?}"
        );
    }
}

#[tokio::test]
async fn concurrent_searches_make_one_discovery_and_key_set_fetch() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    w.issuer.with(|s| s.jwks_delay = Duration::from_millis(300));
    let dir = w.directory();
    let session = Arc::new(w.session());
    session.access_token().await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dir, session) = (dir.clone(), session.clone());
        tasks.push(tokio::spawn(async move {
            dir.search_for_asker(&session, ASKER_DID, "a", 5).await
        }));
    }
    for t in tasks {
        let got = t.await.unwrap().unwrap();
        assert!(got.results[0].did.verified_did().is_some());
    }
    assert_eq!(w.issuer.mock.count("GET", "/jwk"), 1, "one key set fetch");
    assert_eq!(
        w.issuer
            .mock
            .count("GET", "/.well-known/openid-configuration"),
        1,
        "one discovery fetch"
    );
}

#[tokio::test]
async fn a_failed_key_set_fetch_is_shared_by_the_searches_that_waited_for_it() {
    let w = World::new().await;
    w.hs.module_hits(vec![published(&w, "alice")]);
    w.issuer.with(|s| {
        s.jwks_status = 500;
        s.jwks_delay = Duration::from_millis(300);
    });
    let dir = w.directory();
    let session = Arc::new(w.session());
    session.access_token().await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dir, session) = (dir.clone(), session.clone());
        tasks.push(tokio::spawn(async move {
            dir.search_for_asker(&session, ASKER_DID, "a", 5).await
        }));
    }
    for t in tasks {
        let err = t.await.unwrap().unwrap_err();
        assert!(matches!(err, DirectoryError::Unavailable(_)), "{err:?}");
        assert!(err.is_retryable());
    }
    assert_eq!(w.issuer.mock.count("GET", "/jwk"), 1, "one attempt, shared");

    // Nothing of the failure is kept: the next search asks again.
    w.issuer.with(|s| {
        s.jwks_status = 200;
        s.jwks_delay = Duration::ZERO;
    });
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert!(got.results[0].did.verified_did().is_some());
    assert_eq!(w.issuer.mock.count("GET", "/jwk"), 2);
}

/// A hit whose proof is signed by `key` under `kid`.
fn signed_by(w: &World, key: &p256::ecdsa::SigningKey, kid: &str, name: &str) -> Value {
    let (m, d) = (mxid(name), did_of(name));
    let proof = mint(
        key,
        kid,
        &json!({"iss": w.issuer.mock.base, "sub": d, "mxid": m, "iat": 1_757_000_000}),
    );
    hit(&m, Some(name), Some(json!({"did": d, "proof": proof})))
}

#[tokio::test]
async fn a_proof_with_an_unknown_kid_refetches_the_key_set_once_per_thirty_seconds() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    let jwk_fetches = || w.issuer.mock.count("GET", "/jwk");

    // The first search fetches and caches the issuer's first key set.
    w.hs.module_hits(vec![published(&w, "alice")]);
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(jwk_fetches(), 1);

    // The issuer rotates its key. Carol's proof is signed with the new one.
    let new_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    w.issuer
        .with(|s| s.jwks = json!({"keys": [jwk_of(&new_key, "fixture-kid-2")]}));
    w.hs.module_hits(vec![signed_by(&w, &new_key, "fixture-kid-2", "carol")]);

    // Inside 30 seconds of the last fetch the kid is unknown and stays so.
    w.clock.advance(Duration::from_secs(29));
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(states(&got), vec![json!({"state": "invalid"})]);
    assert_eq!(jwk_fetches(), 1, "rate limited: no refetch yet");

    // Thirty seconds after it, the unknown kid is worth one refetch.
    w.clock.advance(Duration::from_secs(1));
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(states(&got), vec![verified(&did_of("carol"))]);
    assert_eq!(jwk_fetches(), 2);
    assert_eq!(
        w.issuer
            .mock
            .count("GET", "/.well-known/openid-configuration"),
        2,
        "discovery is fetched again with the keys"
    );

    // A kid that the fresh set does not have either is invalid, and asking
    // again inside the interval does not fetch again.
    let rogue = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    w.hs.module_hits(vec![signed_by(&w, &rogue, "no-such-kid", "dave")]);
    for _ in 0..3 {
        let got = dir
            .search_for_asker(&session, ASKER_DID, "a", 5)
            .await
            .unwrap();
        assert_eq!(states(&got), vec![json!({"state": "invalid"})]);
    }
    assert_eq!(jwk_fetches(), 2);
    w.clock.advance(Duration::from_secs(30));
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(states(&got), vec![json!({"state": "invalid"})]);
    assert_eq!(jwk_fetches(), 3, "one more refetch, then invalid again");
}

#[tokio::test]
async fn many_searches_with_an_unknown_kid_cost_the_issuer_one_refetch() {
    let w = World::new().await;
    let dir = w.directory();
    let session = Arc::new(w.session());
    w.hs.module_hits(vec![published(&w, "alice")]);
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    w.clock.advance(Duration::from_secs(30));

    let new_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    w.issuer.with(|s| {
        s.jwks = json!({"keys": [jwk_of(&new_key, "fixture-kid-2")]});
        s.jwks_delay = Duration::from_millis(300);
    });
    w.hs.module_hits(vec![signed_by(&w, &new_key, "fixture-kid-2", "carol")]);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dir, session) = (dir.clone(), session.clone());
        tasks.push(tokio::spawn(async move {
            dir.search_for_asker(&session, ASKER_DID, "a", 5).await
        }));
    }
    for t in tasks {
        let got = t.await.unwrap().unwrap();
        assert_eq!(states(&got), vec![verified(&did_of("carol"))]);
    }
    assert_eq!(
        w.issuer.mock.count("GET", "/jwk"),
        2,
        "the first fetch and one refetch"
    );
}

#[tokio::test]
async fn a_failed_unknown_kid_refetch_never_fails_a_search() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    let jwk_fetches = || w.issuer.mock.count("GET", "/jwk");

    // The first search caches the key set (the issuer's first key).
    w.hs.module_hits(vec![published(&w, "alice")]);
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(jwk_fetches(), 1);

    // The issuer rotates to a second key but is down when asked. A search
    // that returns a proof under the new kid next to alice's old one: the new
    // one is `invalid` for this answer, alice is `verified`, nothing fails.
    let new_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    w.issuer.with(|s| {
        s.jwks = json!({"keys": [jwk_of(&s.proof_key, KID), jwk_of(&new_key, "fixture-kid-2")]});
        s.jwks_status = 500;
    });
    w.hs.module_hits(vec![
        signed_by(&w, &new_key, "fixture-kid-2", "carol"),
        published(&w, "alice"),
    ]);
    w.clock.advance(Duration::from_secs(30));
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .expect("a failed refetch for an unknown kid is not a failed search");
    assert_eq!(
        states(&got),
        vec![json!({"state": "invalid"}), verified(&did_of("alice"))]
    );
    assert_eq!(jwk_fetches(), 2, "the refetch was tried, and failed");

    // The issuer is back. Inside the 30 s the failure is not held against the
    // search either, and the issuer is not asked again.
    w.issuer.with(|s| s.jwks_status = 200);
    w.clock.advance(Duration::from_secs(29));
    for _ in 0..3 {
        let got = dir
            .search_for_asker(&session, ASKER_DID, "a", 5)
            .await
            .expect("the stored failure does not fail searches while the set is valid");
        assert_eq!(
            states(&got),
            vec![json!({"state": "invalid"}), verified(&did_of("alice"))]
        );
    }
    assert_eq!(
        jwk_fetches(),
        2,
        "the 30 s limit still holds after a failure"
    );

    // The invalid verdict was kept nowhere: after the limit the refetch
    // succeeds and the same proof now verifies.
    w.clock.advance(Duration::from_secs(1));
    let got = dir
        .search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(
        states(&got),
        vec![verified(&did_of("carol")), verified(&did_of("alice"))]
    );
    assert_eq!(jwk_fetches(), 3);
}

#[tokio::test]
async fn searches_waiting_on_a_failed_unknown_kid_refetch_are_answered_not_failed() {
    let w = World::new().await;
    let dir = w.directory();
    let session = Arc::new(w.session());
    w.hs.module_hits(vec![published(&w, "alice")]);
    dir.search_for_asker(&session, ASKER_DID, "a", 5)
        .await
        .unwrap();
    w.clock.advance(Duration::from_secs(30));

    let new_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    w.issuer.with(|s| {
        s.jwks = json!({"keys": [jwk_of(&new_key, "fixture-kid-2")]});
        s.jwks_status = 500;
        s.jwks_delay = Duration::from_millis(300);
    });
    w.hs.module_hits(vec![
        signed_by(&w, &new_key, "fixture-kid-2", "carol"),
        published(&w, "alice"),
    ]);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dir, session) = (dir.clone(), session.clone());
        tasks.push(tokio::spawn(async move {
            dir.search_for_asker(&session, ASKER_DID, "a", 5).await
        }));
    }
    for t in tasks {
        let got = t.await.unwrap().expect("not a failed search");
        assert_eq!(
            states(&got),
            vec![json!({"state": "invalid"}), verified(&did_of("alice"))]
        );
    }
    assert_eq!(
        w.issuer.mock.count("GET", "/jwk"),
        2,
        "the first fetch and one failed refetch, shared"
    );
}

/// Every character Python's `str.strip()` removes (`str.isspace()`, checked
/// against Python 3 with Unicode 16): Rust's whitespace plus U+001C to U+001F.
const MODULE_TRIMS: [char; 29] = [
    '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', ' ',
    '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}',
    '\u{202f}', '\u{205f}', '\u{3000}',
];

fn module_terms(w: &World) -> Vec<String> {
    w.hs.mock
        .requests()
        .iter()
        .filter(|r| r.path == MODULE_PATH)
        .map(|r| r.json()["term"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_term_the_module_would_refuse_is_refused_before_any_call() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    for term in [
        // Control characters inside the term.
        "ada\u{0}x",
        "a\u{7}b",
        "a\nb",
        "a\tb",
        "a\u{1c}b",
        "a\u{85}b",
        "a\u{9f}b",
        // At an end, where only whitespace is trimmed and these are not.
        "\u{7f}",
        "\u{9f}a",
        "ada\u{7}",
        "\u{1b}ada",
        "a\u{85}\u{0}",
        // Nothing but what the module trims.
        "\u{1c}",
        "\u{1f}\u{1f}",
        " \u{85}\u{a0}",
        "",
    ] {
        let err = dir
            .search_for_asker(&session, ASKER_DID, term, 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DirectoryError::InvalidInput(_)),
            "{term:?}: {err:?}"
        );
        let err = dir.search_as_user("tok", term, 5).await.unwrap_err();
        assert!(
            matches!(err, DirectoryError::InvalidInput(_)),
            "{term:?}: {err:?}"
        );
    }
    assert_eq!(w.requests_total(), 0, "nothing was sent for any of them");
}

#[tokio::test]
async fn the_term_is_trimmed_exactly_as_the_module_trims_it() {
    let w = World::new().await;
    let dir = w.directory();
    let session = w.session();
    for c in MODULE_TRIMS {
        for term in [
            format!("{c}ada"),
            format!("ada{c}"),
            format!("{c}{c}ada{c}"),
        ] {
            dir.search_for_asker(&session, ASKER_DID, &term, 5)
                .await
                .unwrap_or_else(|e| panic!("{term:?}: {e:?}"));
        }
    }
    assert!(
        module_terms(&w).iter().all(|t| t == "ada"),
        "{:?}",
        module_terms(&w)
    );
    assert_eq!(module_terms(&w).len(), MODULE_TRIMS.len() * 3);

    // What the module keeps, the client keeps: format and separator characters
    // that are not whitespace, and a line separator inside the term.
    for term in [
        "\u{200b}ada",
        "\u{180e}ada",
        "\u{feff}ada",
        "a\u{2028}b",
        "a b",
    ] {
        dir.search_for_asker(&session, ASKER_DID, term, 5)
            .await
            .unwrap();
        assert_eq!(module_terms(&w).last().unwrap(), term);
    }
}

#[tokio::test]
async fn the_server_name_is_compared_the_way_synapse_does_exactly() {
    let w = World::new().await;
    let other_case = "@alice:EXAMPLE.org";
    let proof_for_other_case = w.issuer.field(&did_of("alice"), other_case);
    w.hs.module_hits(vec![
        hit(other_case, Some("Alice"), Some(proof_for_other_case)),
        published(&w, "bob"),
    ]);
    let dir = w.directory();
    let got = dir
        .search_for_asker(&w.session(), ASKER_DID, "a", 5)
        .await
        .unwrap();
    assert_eq!(
        states(&got),
        vec![
            json!({"state": "not_yet_published"}),
            verified(&did_of("bob"))
        ],
        "another spelling of the server name is another server"
    );

    // On the user transport its profile is not even read.
    w.hs.directory_rows(vec![
        json!({"user_id": other_case}),
        json!({"user_id": mxid("bob")}),
    ]);
    w.hs.profile(
        &mxid("bob"),
        Some(w.issuer.field(&did_of("bob"), &mxid("bob"))),
    );
    let got = dir.search_as_user("t", "a", 5).await.unwrap();
    assert_eq!(got.results[0].did, DidState::NotYetPublished);
    assert_eq!(w.hs.profile_reads(), 1);
}

#[tokio::test]
async fn the_public_verifier_follows_no_redirect_for_the_key_set() {
    let w = World::new().await;
    // An attacker's origin serves a key set it holds the key to, and a proof
    // signed with it. If the redirect from the issuer's own `jwks_uri` were
    // followed, the proof would verify as the issuer's.
    let attacker_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let attacker_jwks = json!({"keys": [jwk_of(&attacker_key, KID)]});
    let attacker = Mock::start(move |_| Resp::json(200, attacker_jwks.clone())).await;
    let issuer = &w.issuer.mock.base;
    let proof = mint(
        &attacker_key,
        KID,
        &json!({"iss": issuer, "sub": did_of("mallory"), "mxid": mxid("mallory"), "iat": 1}),
    );

    // Control: a proof of the issuer's own key verifies.
    let honest = w.issuer.proof(&did_of("alice"), &mxid("alice"));
    siwx_oidc_auth::verify_did_assertion(issuer, &honest, &mxid("alice"))
        .await
        .unwrap();

    w.issuer
        .with(|s| s.jwks_redirect = Some(format!("{}/jwk", attacker.base)));
    let err = siwx_oidc_auth::verify_did_assertion(issuer, &proof, &mxid("mallory"))
        .await
        .expect_err("the redirect must not be followed");
    assert!(format!("{err:#}").contains("302"), "{err:#}");
    assert_eq!(attacker.total(), 0, "the other origin was never asked");
}

#[tokio::test]
async fn an_unregistered_client_is_a_typed_sign_in_error() {
    let w = World::new().await;
    w.issuer.with(|s| s.authorize_status = Some(401));
    let err = w.session().access_token().await.unwrap_err();
    assert!(err.is_unknown_client(), "{err:?}");
    assert!(
        !err.is_retryable(),
        "registering again is the caller's move"
    );
    let DirectoryError::SignIn { source } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(
        source.downcast_ref::<siwx_oidc_auth::AuthError>(),
        Some(&siwx_oidc_auth::AuthError::UnknownClient)
    );
    assert!(siwx_oidc_auth::is_unknown_client(source));

    // Another failure at /authorize is not that.
    let w = World::new().await;
    w.issuer.with(|s| s.authorize_status = Some(500));
    let err = w.session().access_token().await.unwrap_err();
    assert!(!err.is_unknown_client(), "{err:?}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn a_401_with_a_challenge_is_not_an_unknown_client() {
    // A proxy's auth wall answers 401 with a challenge; the server's own
    // answer for an unregistered client has none. Registering again would not
    // get past the wall.
    for challenge in [r#"Basic realm="corp""#, "Bearer", "Negotiate"] {
        let w = World::new().await;
        w.issuer.with(|s| {
            s.authorize_status = Some(401);
            s.authorize_challenge = Some(challenge.to_string());
        });
        let err = w.session().access_token().await.unwrap_err();
        assert!(!err.is_unknown_client(), "{challenge}: {err:?}");
        assert!(
            !err.is_retryable(),
            "{challenge}: the same call meets the same wall: {err:?}"
        );
        let DirectoryError::SignIn { source } = &err else {
            panic!("{err:?}");
        };
        assert!(!siwx_oidc_auth::is_unknown_client(source));
        assert!(format!("{source:#}").contains("401"), "{source:#}");
    }
}

#[tokio::test]
async fn any_expires_in_keeps_the_pair_the_session_renews_with() {
    // A lifetime that serde would refuse loses nothing: the sign-in's refresh
    // token is the one the renewal uses.
    for (raw, renewed_after) in [
        ("1e20", Duration::from_secs(25 * 3600)),
        ("18446744073709551616", Duration::from_secs(25 * 3600)),
        ("3600.5", Duration::from_secs(3600)),
        ("-7", Duration::from_secs(10)),
        ("\"soon\"", Duration::from_secs(60)),
        ("null", Duration::from_secs(60)),
    ] {
        let w = World::new().await;
        w.issuer.with(|s| s.expires_in_raw = Some(raw.to_string()));
        let session = w.session();
        assert_eq!(session.access_token().await.unwrap(), "access-1", "{raw}");
        w.issuer.with(|s| s.expires_in_raw = None);
        w.clock.advance(renewed_after);
        assert_eq!(session.access_token().await.unwrap(), "access-2", "{raw}");
        assert_eq!(
            w.issuer.refreshes(),
            1,
            "{raw}: renewed with the first pair"
        );
        assert_eq!(w.issuer.sign_ins(), 1, "{raw}");
    }
}

/// A chain of `hops` redirects that ends at the profile answer of `field`.
async fn profile_behind_redirects(hops: usize, field: Value) -> Mock {
    let mut next = Mock::start(move |_| Resp::json(200, json!({ "io.inblock.did": field }))).await;
    let mut hold = Vec::new();
    for _ in 1..hops {
        let target = format!("{}/p", next.base);
        hold.push(next);
        next = Mock::start(move |_| Resp::found(target.clone())).await;
    }
    let target = format!("{}/p", next.base);
    let first = Mock::start(move |_| Resp::found(target.clone())).await;
    // The hops stay up for as long as the first one is used.
    std::mem::forget(hold);
    std::mem::forget(next);
    first
}

#[tokio::test]
async fn fetch_and_verify_did_follows_up_to_three_redirects_for_the_profile_read() {
    let w = World::new().await;
    let field = w.issuer.field(&did_of("alice"), &mxid("alice"));

    // A homeserver may redirect (a canonical host, a trailing-slash rule). The
    // proof is pinned to the issuer, so where the profile came from adds no
    // trust, and a redirect costs nothing.
    let home = profile_behind_redirects(3, field.clone()).await;
    let verified =
        siwx_oidc_auth::fetch_and_verify_did(&home.base, &mxid("alice"), &w.issuer.mock.base)
            .await
            .expect("three redirects are followed");
    assert_eq!(verified.did(), did_of("alice"));

    // A fourth is one too many.
    let home = profile_behind_redirects(4, field).await;
    let err = siwx_oidc_auth::fetch_and_verify_did(&home.base, &mxid("alice"), &w.issuer.mock.base)
        .await
        .expect_err("a chain of four is refused");
    assert!(format!("{err:#}").contains("redirect"), "{err:#}");
}
