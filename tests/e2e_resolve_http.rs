//! HTTP-layer contract tests for `GET /resolve` — the public, unauthenticated
//! DID ↔ MXID lookup (`src/resolve.rs`).
//!
//! # The gap this closes
//!
//! `src/resolve.rs` carries 15 unit tests and every one of them builds a
//! `ResolveQuery` **struct** and calls `resolve::resolve(…)` directly. That is
//! the right shape for the resolution *logic*, and it is structurally blind to
//! everything between a socket and that function:
//!
//! - the `Query<ResolveQuery>` extractor, which rejects malformed query strings
//!   **before** the handler runs and therefore before `ResolveError` gets a say;
//! - the method routing (`get(resolve_handler)` vs an accidental `any()`);
//! - `ResolveError`'s `IntoResponse` — the unit tests reach it only through a
//!   `status_of` helper that throws the body and the headers away.
//!
//! Those three are the whole externally-visible contract of a route whose
//! consumers are, by design, arbitrary unauthenticated third parties. A
//! consumer never calls `resolve()`; it parses bytes off the wire. So this suite
//! asserts on **raw bytes, raw status, raw headers, and the raw JSON key set** —
//! never on a deserialized `ResolveResponse`, because a typed decode is exactly
//! as blind as the unit tests: a `skip_serializing_if` that silently dropped a
//! `null` key would round-trip into a perfectly happy struct.
//!
//! The documented contract these tests hold the route to is
//! `docs/api/openapi.yaml` (`ResolveResponse`: `required: [did, mxid, exists,
//! attested]`; `ResolveError`: `required: [error, message]`) and
//! `docs/api/README.md` ("`/resolve` always returns all four keys", "`/resolve`
//! never returns 500").
//!
//! # One test here is EXPECTED RED
//!
//! [`a_repeated_query_parameter_is_rejected_with_the_documented_error_envelope`]
//! fails against the code as it stands, on purpose. A repeated selector
//! (`?did=a&did=b`) is rejected by serde's `Query` extractor, which answers a
//! **`text/plain`** 400 that never reaches `ResolveError::into_response` — so
//! the documented JSON envelope is not what a caller gets. It is written to the
//! contract and must not be weakened to the observed behaviour; see that test's
//! own doc comment for the exact body and the shape of the fix.
//!
//! # Running
//!
//! `#[ignore]` on every test, matching the repo convention for suites that need
//! the live mock stack — a plain `cargo test` has no listener to talk to and
//! must stay green. Bring the stack up first and run single-threaded, because
//! every test resets the shared Synapse mock:
//!
//! ```text
//! bash e2e/up.sh
//! cargo test --test e2e_resolve_http -- --ignored --test-threads=1
//! ```
//!
//! Env overrides: `SIWEOIDC_HOST` (default `http://localhost:8080`),
//!                `SYNAPSE_MOCK` (default `http://localhost:8090`).

use std::collections::BTreeSet;

use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use siwx_oidc::mxid::localpart_for;
use siwx_oidc_auth::did_assertion::DID_PROFILE_FIELD;

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8080".to_string())
}
fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}

/// The Matrix server_name the stack is configured with
/// (`SIWEOIDC_MATRIX_SERVER_NAME` in `e2e/env.sh` and in the `rust-e2e-mock` CI
/// job). The mock keys its state on `@localpart:{this}`, so the two must agree.
const SERVER_NAME: &str = "matrix.test";
/// The MAS shared secret the stack is brought up with. Used here only to mint an
/// admin-scoped token, which is the sole way to write a profile field on the
/// mock — see [`seed_published_did`].
const SHARED_SECRET: &str = "testsecret";

/// The four keys `docs/api/openapi.yaml` marks `required` on `ResolveResponse`.
/// A `BTreeSet` so the comparison is order-insensitive: serde emits declaration
/// order, but a consumer parses a JSON object and key order is not part of the
/// contract — key *presence* is.
fn expected_response_keys() -> BTreeSet<String> {
    ["attested", "did", "exists", "mxid"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Mixed case ON PURPOSE, for the same reason `src/resolve.rs`'s unit tests use
/// a mixed-case vector: a `did:key` multibase payload is case-sensitive, so an
/// all-lowercase DID could not tell "exact case preserved on the wire" apart
/// from "lowercased and happened to match".
const DID_ATTESTED: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
/// A second identity, seeded as an existing account that publishes nothing —
/// the case where the 200 body must carry an explicit `"did": null`.
const DID_SEEDED_SILENT: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
/// An identity that has never signed in on this homeserver.
const DID_UNKNOWN: &str = "did:key:z6MkpFemPtmjvPZ1gFYM6d68tuwxxrcec4H2Ck23FRchU9ue";

// ---------------------------------------------------------------------------
// One HTTP answer, kept as RAW TEXT
// ---------------------------------------------------------------------------

/// A response, preserved as status + content type + undecoded body.
///
/// Nothing here is deserialized into `ResolveResponse` or `ResolveError`, and
/// that is the point of the suite rather than an oversight: a typed decode
/// cannot see a dropped `null` key, cannot see a body that is not JSON at all
/// (the duplicate-parameter case), and turns a missing `Content-Type` into
/// silence. All three are live deviations this file has to be able to name.
struct Answer {
    status: StatusCode,
    /// `None` when the response carried no `Content-Type` header — which is
    /// itself observable behaviour (Axum's 405 and 404 answers carry none).
    content_type: Option<String>,
    body: String,
}

impl Answer {
    /// The body parsed as JSON, with a failure message that quotes the actual
    /// bytes. A parse failure here is a finding, not a test bug, so it must say
    /// what arrived.
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| {
            panic!(
                "expected a JSON body, got {e}. status={} content_type={:?} body={:?}",
                self.status, self.content_type, self.body
            )
        })
    }

    /// The top-level JSON object's key set.
    fn keys(&self) -> BTreeSet<String> {
        self.json()
            .as_object()
            .unwrap_or_else(|| panic!("expected a JSON object, got body={:?}", self.body))
            .keys()
            .cloned()
            .collect()
    }
}

/// `GET /resolve?{raw_query}`.
///
/// Takes the query string **raw and pre-built**, never a `(key, value)` list:
/// several of the cases below — a repeated parameter, a bare `?did` with no
/// `=`, a `;` used as a separator — are not expressible through a map, and they
/// are precisely the inputs that reach the extractor instead of the handler.
async fn get_resolve(c: &Client, raw_query: &str) -> Answer {
    send_resolve(c, Method::GET, raw_query).await
}

async fn send_resolve(c: &Client, method: Method, raw_query: &str) -> Answer {
    let url = format!("{}/resolve?{raw_query}", oidc());
    let resp = c
        .request(method, &url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e} (is the stack up?)"));
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.text().await.unwrap_or_default();
    Answer {
        status,
        content_type,
        body,
    }
}

/// Assert the documented error envelope: the status, a JSON content type, and a
/// body object carrying `error` and `message` as strings
/// (`docs/api/openapi.yaml` `components.schemas.ResolveError`,
/// `required: [error, message]`).
///
/// `mxid` is the one optional member and is deliberately not required here — it
/// is present only when an mxid was already resolved before an upstream
/// failure, which the 502 test checks on its own.
fn assert_documented_error_envelope(answer: &Answer, expected: StatusCode, what: &str) {
    assert_eq!(
        answer.status, expected,
        "{what}: expected {expected}, got {} with body {:?}",
        answer.status, answer.body
    );
    assert_eq!(
        answer.content_type.as_deref(),
        Some("application/json"),
        "{what}: the documented error envelope is JSON; body was {:?}",
        answer.body
    );
    let body = answer.json();
    assert!(
        body["error"].is_string(),
        "{what}: ResolveError requires a string `error` discriminator, got {body}"
    );
    assert!(
        body["message"].is_string(),
        "{what}: ResolveError requires a string `message`, got {body}"
    );
}

// ---------------------------------------------------------------------------
// Synapse mock levers (e2e/synapse_mock.py)
// ---------------------------------------------------------------------------

async fn mock_reset(c: &Client) {
    c.post(format!("{}/__reset", mock()))
        .send()
        .await
        .expect("mock __reset failed (is e2e/synapse_mock.py up?)");
}

/// Mark a localpart as an EXISTING account (a `users` row AND a `profiles`
/// row), without seeding a device.
async fn mock_seed_user(c: &Client, localpart: &str) {
    c.post(format!("{}/__seed_user", mock()))
        .json(&json!({ "localpart": localpart }))
        .send()
        .await
        .expect("mock __seed_user failed");
}

/// Force a user's `profiles` row into `"present"`, `"empty"` or `"absent"`.
///
/// `"absent"` — a `users` row with NO `profiles` row — is how this suite reaches
/// the 502 branch at all: element-hq/synapse#19702 makes the profile-field GET
/// answer a generic 500 for such an account, and the mock reproduces that
/// faithfully. The mock has no fault lever for the profile-field read itself
/// (`__fail` recognises only delete_device, list_devices, deactivate,
/// query_user, publish_did_field), so this is the only route to an
/// `Upstream` error.
async fn mock_profile(c: &Client, mxid: &str, state: &str) {
    c.post(format!("{}/__profile", mock()))
        .json(&json!({ "user_id": mxid, "state": state }))
        .send()
        .await
        .expect("mock __profile failed");
}

/// Every request the mock has served since the last `__reset`, as
/// `"{METHOD} {path}"`. The mock logs BEFORE authenticating, so a rejected call
/// still shows up — which is what makes "no call was made at all" a meaningful
/// assertion rather than an unfalsifiable one.
async fn mock_calls(c: &Client) -> Vec<String> {
    let state: Value = c
        .get(format!("{}/__state", mock()))
        .send()
        .await
        .expect("mock __state failed")
        .json()
        .await
        .expect("mock __state must be JSON");
    state["calls"]
        .as_array()
        .expect("__state must carry a `calls` array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

/// Publish `did` as `account`'s `io.inblock.did` profile field.
///
/// Goes the long way round — mint an admin-scoped token at
/// `POST /oauth2/admin_token`, then `PUT` the field — because the mock has **no
/// seeding lever for MSC4133 profile fields**: `__seed_user` and `__profile`
/// write the `profiles` row only, and `PROFILE_FIELDS` is reachable exclusively
/// through the authenticated write path that `synapse_client::publish_did_field`
/// uses. The mock validates that token by really introspecting it against
/// siwx-oidc, so a failure here is an `admin_token.rs` problem and NOT a
/// `/resolve` one — the panic messages say so.
///
/// The value is the real `{did, proof}` wire object, and the field name comes
/// from the shipped consumer's shared constant rather than a literal, so a
/// rename cannot make this test seed a field the server never reads.
async fn seed_published_did(c: &Client, mxid: &str, did: &str) {
    let minted: Value = c
        .post(format!("{}/oauth2/admin_token", oidc()))
        .bearer_auth(SHARED_SECRET)
        .send()
        .await
        .expect("admin_token mint request failed")
        .json()
        .await
        .expect("admin_token response must be JSON (a /resolve-unrelated failure)");
    let token = minted["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("admin_token response carried no access_token: {minted}"));

    let resp = c
        .put(format!(
            "{}/_matrix/client/v3/profile/{}/{}",
            mock(),
            urlencoding::encode(mxid),
            DID_PROFILE_FIELD
        ))
        .bearer_auth(token)
        .json(
            &json!({ DID_PROFILE_FIELD: { "did": did, "proof": "eyJhbGciOiJFUzI1NiJ9.e30.sig" } }),
        )
        .send()
        .await
        .expect("publishing the DID field on the mock failed");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "seeding the profile field must succeed; this is setup, not the assertion under test"
    );
}

fn mxid_for(did: &str) -> String {
    format!("@{}:{SERVER_NAME}", localpart_for(did))
}

// ---------------------------------------------------------------------------
// The known deviation
// ---------------------------------------------------------------------------

/// **EXPECTED RED against the current code — do not weaken this to match it.**
///
/// A repeated selector is a caller error like any other, and every caller error
/// this endpoint reports is documented to arrive as
/// `{"error": …, "message": …}` with `Content-Type: application/json`
/// (`docs/api/openapi.yaml` `ResolveError`). What actually arrives is
///
/// ```text
/// HTTP/1.1 400 Bad Request
/// content-type: text/plain; charset=utf-8
///
/// Failed to deserialize query string: .: duplicate field `did`
/// ```
///
/// because `ResolveQuery` is pulled out by `Query<T>`, whose serde rejection is
/// turned into a response by **Axum**, not by `ResolveError::into_response`.
/// Nothing in `src/resolve.rs` runs. The unit tests cannot see this: they
/// construct the struct that the extractor failed to build.
///
/// It matters more here than on an authenticated route. `/resolve` exists for
/// third-party consumers who were told, in writing, that an error is a JSON
/// object with an `error` discriminator — so the one failure mode reachable by
/// a plain typo in a URL is also the one that hands them a body their parser
/// rejects, with no discriminator to branch on.
///
/// The fix is at the wiring, not in the handler: give the extractor a rejection
/// that renders as `ResolveError::BadRequest` (a `FromRequestParts` wrapper
/// around `Query`, or `WithRejection`), so that *every* 400 on this path leaves
/// through the one `IntoResponse` that already exists. Both selectors are
/// asserted because the extractor rejects each by name.
#[tokio::test]
#[ignore]
async fn a_repeated_query_parameter_is_rejected_with_the_documented_error_envelope() {
    let c = Client::new();
    mock_reset(&c).await;

    for raw in [
        "did=did:key:zAaa&did=did:key:zBbb",
        "mxid=@alice:matrix.test&mxid=@bob:matrix.test",
    ] {
        let answer = get_resolve(&c, raw).await;
        assert_documented_error_envelope(
            &answer,
            StatusCode::BAD_REQUEST,
            &format!("repeated selector `?{raw}`"),
        );
    }
}

// ---------------------------------------------------------------------------
// The error envelope
// ---------------------------------------------------------------------------

/// Every error the handler itself produces reaches the wire as the documented
/// envelope — the sweep that says the shape is a property of the route and not
/// of one lucky branch.
///
/// Scoped to errors that reach `resolve_handler`. Rejections raised *before* it
/// (the repeated parameter above; the 405 and 404 below) are a separate,
/// deliberately separate, finding: bundling them in here would make one red
/// test stand for four different causes.
#[tokio::test]
#[ignore]
async fn every_error_the_handler_produces_carries_the_documented_json_envelope() {
    let c = Client::new();
    mock_reset(&c).await;

    for raw in [
        // no selector at all
        "",
        // a selector with no value reads as no selector
        "did=",
        "did",
        // two selectors: two different questions
        "did=did:key:zAaa&mxid=@alice:matrix.test",
        // an mxid this provider cannot answer for
        "mxid=@alice:matrix.org",
        // and the four ways an mxid can fail to be one
        "mxid=alice:matrix.test",
        "mxid=@alice",
        "mxid=@:matrix.test",
        "mxid=@alice:",
    ] {
        let answer = get_resolve(&c, raw).await;
        assert_documented_error_envelope(&answer, StatusCode::BAD_REQUEST, &format!("`?{raw}`"));
    }
}

/// Zero selectors and two selectors are both 400s, and each says which of the
/// two it was — the diagnosis is the useful part, and a shared "bad request"
/// string would make the two indistinguishable to the caller who has to fix it.
#[tokio::test]
#[ignore]
async fn passing_both_or_neither_selector_is_a_400_with_the_error_envelope() {
    let c = Client::new();
    mock_reset(&c).await;

    let neither = get_resolve(&c, "").await;
    assert_documented_error_envelope(&neither, StatusCode::BAD_REQUEST, "no selector");
    let message = neither.json()["message"].as_str().unwrap().to_string();
    assert!(
        message.contains("exactly one") && message.contains("did") && message.contains("mxid"),
        "the no-selector message must name both selectors: {message}"
    );

    let both = get_resolve(&c, &format!("did={DID_UNKNOWN}&mxid=@alice:{SERVER_NAME}")).await;
    assert_documented_error_envelope(&both, StatusCode::BAD_REQUEST, "both selectors");
    let message = both.json()["message"].as_str().unwrap().to_string();
    assert!(
        message.contains("not both"),
        "the two-selector message must say the two are different questions, not repeat the \
         no-selector text: {message}"
    );
}

/// An mxid belonging to another homeserver is a 400 that names **both** servers,
/// so the caller can see the mismatch rather than guess at it.
#[tokio::test]
#[ignore]
async fn an_mxid_for_a_foreign_homeserver_is_a_400_naming_both_homeservers() {
    let c = Client::new();
    mock_reset(&c).await;

    let answer = get_resolve(&c, "mxid=@alice:matrix.org").await;
    assert_documented_error_envelope(&answer, StatusCode::BAD_REQUEST, "foreign homeserver");
    let message = answer.json()["message"].as_str().unwrap().to_string();
    assert!(
        message.contains("matrix.org") && message.contains(SERVER_NAME),
        "the message must name the foreign server AND ours: {message}"
    );
}

/// A string that cannot be a Matrix ID is refused on syntax alone — the
/// homeserver is never asked.
///
/// The observable proof is the mock's request log, which is empty afterwards.
/// That log is trustworthy for this claim because the mock appends to it
/// **before** authenticating, so a call that would have been rejected still
/// leaves a trace; an empty log therefore means no request was made, not that a
/// request was made and hidden.
///
/// Why it matters beyond saving a round trip: `is_localpart_available` maps any
/// 4xx to "taken", so a localpart the homeserver would reject as
/// `M_INVALID_USERNAME` would come back through this endpoint as an account
/// that exists. Parsing first is what keeps that from being reachable from the
/// open internet.
#[tokio::test]
#[ignore]
async fn a_syntactically_impossible_mxid_is_rejected_without_asking_the_homeserver() {
    let c = Client::new();
    mock_reset(&c).await;

    let answer = get_resolve(&c, "mxid=alice:matrix.test").await;
    assert_documented_error_envelope(&answer, StatusCode::BAD_REQUEST, "mxid with no `@`");
    assert!(
        answer.json()["message"]
            .as_str()
            .unwrap()
            .contains("must start with `@`"),
        "the message must say what is wrong with it: {}",
        answer.body
    );

    let calls = mock_calls(&c).await;
    assert!(
        calls.is_empty(),
        "a request that cannot be a Matrix ID must not reach the homeserver, but the mock \
         logged: {calls:?}"
    );
}

/// The 502 branch, on the wire: when the homeserver cannot be read, the answer
/// is an error carrying the already-resolved `mxid` — never a 200 with a guess,
/// and never a 500.
///
/// Reached through a row-less account (a `users` row with no `profiles` row),
/// which is element-hq/synapse#19702 and makes the profile-field read answer a
/// generic 500. That is the only lever the mock offers for this branch; see
/// [`mock_profile`].
#[tokio::test]
#[ignore]
async fn an_unreadable_profile_field_is_a_502_carrying_the_envelope_and_the_resolved_mxid() {
    let c = Client::new();
    mock_reset(&c).await;
    let mxid = mxid_for(DID_SEEDED_SILENT);
    mock_seed_user(&c, &localpart_for(DID_SEEDED_SILENT)).await;
    mock_profile(&c, &mxid, "absent").await;

    for raw in [format!("mxid={mxid}"), format!("did={DID_SEEDED_SILENT}")] {
        let answer = get_resolve(&c, &raw).await;
        assert_documented_error_envelope(&answer, StatusCode::BAD_GATEWAY, &format!("`?{raw}`"));
        let body = answer.json();
        assert_eq!(
            body["error"].as_str(),
            Some("upstream_error"),
            "the discriminator must say the upstream failed, not that the caller erred: {body}"
        );
        assert_eq!(
            body["mxid"].as_str(),
            Some(mxid.as_str()),
            "the mxid WAS resolved before the failure; discarding it would make the error \
             strictly less useful than it can be: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// The 200 body
// ---------------------------------------------------------------------------

/// All four keys, always, `null` where unknown — asserted on the **raw JSON
/// object's key set**, not on a decoded struct.
///
/// This is the assertion a `#[serde(skip_serializing_if = "Option::is_none")]`
/// on `did` or `mxid` would fail and a typed test would not: serde would drop
/// the key, `serde_json::from_str::<ResolveResponse>` would happily fill the
/// `Option` back in with `None`, and a consumer that branches on key presence
/// would start taking a path it has never taken. `docs/api/README.md` promises
/// callers they never need both a key-presence branch and a null branch.
///
/// Both directions are covered, because each produces a *different* null:
/// `?did=` on an unknown identity nulls nothing but reports `exists: false`,
/// while `?mxid=` on an account that publishes nothing nulls `did` itself.
#[tokio::test]
#[ignore]
async fn a_successful_lookup_returns_all_four_keys_with_null_where_unknown() {
    let c = Client::new();
    mock_reset(&c).await;
    let localpart = localpart_for(DID_SEEDED_SILENT);
    let mxid = mxid_for(DID_SEEDED_SILENT);
    mock_seed_user(&c, &localpart).await;

    // ?mxid= on an existing account that publishes no DID: `did` is null.
    let answer = get_resolve(&c, &format!("mxid={mxid}")).await;
    assert_eq!(answer.status, StatusCode::OK, "body={:?}", answer.body);
    assert_eq!(
        answer.keys(),
        expected_response_keys(),
        "every key, always: body={:?}",
        answer.body
    );
    let body = answer.json();
    assert!(
        body["did"].is_null(),
        "an account publishing nothing must report `did: null`, not omit the key: {body}"
    );
    assert_eq!(body["mxid"].as_str(), Some(mxid.as_str()));
    assert_eq!(body["exists"], json!(true));
    assert_eq!(body["attested"], json!(false));

    // ?did= for an identity that has never signed in here: nothing is null, but
    // `exists` is false and the mxid reported is the one it WOULD get.
    let answer = get_resolve(&c, &format!("did={DID_UNKNOWN}")).await;
    assert_eq!(answer.status, StatusCode::OK, "body={:?}", answer.body);
    assert_eq!(
        answer.keys(),
        expected_response_keys(),
        "every key, always: body={:?}",
        answer.body
    );
    let body = answer.json();
    assert_eq!(body["did"].as_str(), Some(DID_UNKNOWN));
    assert_eq!(body["mxid"].as_str(), Some(mxid_for(DID_UNKNOWN).as_str()));
    assert_eq!(body["exists"], json!(false));
    assert_eq!(body["attested"], json!(false));
}

/// The fully-populated 200: an account that publishes its own DID answers with
/// all four keys non-null, and the DID comes back in **exact case**.
///
/// The case assertion is the one that would have caught siwx-oidc#17 at the HTTP
/// boundary: a `did:key` multibase payload is key material, and a response that
/// lowercased it would name a different key while looking entirely well-formed.
#[tokio::test]
#[ignore]
async fn an_account_publishing_its_own_did_is_reported_attested_in_exact_case() {
    let c = Client::new();
    mock_reset(&c).await;
    let localpart = localpart_for(DID_ATTESTED);
    let mxid = mxid_for(DID_ATTESTED);
    mock_seed_user(&c, &localpart).await;
    seed_published_did(&c, &mxid, DID_ATTESTED).await;

    for raw in [format!("did={DID_ATTESTED}"), format!("mxid={mxid}")] {
        let answer = get_resolve(&c, &raw).await;
        assert_eq!(
            answer.status,
            StatusCode::OK,
            "`?{raw}` body={:?}",
            answer.body
        );
        assert_eq!(answer.keys(), expected_response_keys(), "`?{raw}`");
        let body = answer.json();
        assert_eq!(
            body["did"].as_str(),
            Some(DID_ATTESTED),
            "`?{raw}`: exact case, never normalised"
        );
        assert_eq!(body["mxid"].as_str(), Some(mxid.as_str()), "`?{raw}`");
        assert_eq!(body["exists"], json!(true), "`?{raw}`");
        assert_eq!(body["attested"], json!(true), "`?{raw}`");
    }
}

/// An empty value for the *other* selector reads as **absent**, so
/// `?did=…&mxid=` is a one-selector request and answers 200.
///
/// Pinned because the two documents disagree in tone and a reader could
/// reasonably "fix" this into a 400: `docs/api/openapi.yaml` describes the 400
/// as "not exactly one selector", while `src/resolve.rs` is explicit that an
/// empty value is what a client emits when it forgot to fill a parameter in and
/// that "exactly one selector" is the more useful diagnosis than "that is not a
/// DID". The module doc is the deliberate rule and the unit test
/// `an_empty_selector_value_is_treated_as_absent` already pins it below the HTTP
/// layer; this is the same rule observed from outside.
#[tokio::test]
#[ignore]
async fn an_empty_second_selector_reads_as_absent_rather_than_as_a_second_selector() {
    let c = Client::new();
    mock_reset(&c).await;

    let answer = get_resolve(&c, &format!("did={DID_UNKNOWN}&mxid=")).await;
    assert_eq!(
        answer.status,
        StatusCode::OK,
        "an empty `mxid=` is not a second question: body={:?}",
        answer.body
    );
    assert_eq!(answer.keys(), expected_response_keys());
    assert_eq!(answer.json()["did"].as_str(), Some(DID_UNKNOWN));
}

// ---------------------------------------------------------------------------
// Method routing and headers
// ---------------------------------------------------------------------------

/// The route is registered with `get(…)`, not `any(…)`: a `GET` is answered and
/// every other method is a 405 that advertises what is allowed.
///
/// A read-only lookup that quietly accepted `POST`, `PUT` or `DELETE` would be
/// indistinguishable, to a caller and to a reverse proxy writing method-based
/// rules, from one that mutates. The `Allow` header is asserted because a 405
/// without it is a dead end for anything trying to discover the surface.
///
/// Note the shape of the 405 itself: Axum answers it from the method router,
/// with an EMPTY body and no `Content-Type`. That is the same class of gap as
/// the repeated-parameter case above — anything rejected before
/// `resolve_handler` runs escapes the documented envelope — and is left
/// unasserted here rather than silently blessed.
#[tokio::test]
#[ignore]
async fn the_route_answers_get_and_answers_405_to_every_other_method() {
    let c = Client::new();
    mock_reset(&c).await;

    let ok = get_resolve(&c, &format!("did={DID_UNKNOWN}")).await;
    assert_eq!(ok.status, StatusCode::OK, "GET must be served");

    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let url = format!("{}/resolve?did={DID_UNKNOWN}", oidc());
        let resp = c
            .request(method.clone(), &url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} request failed: {e}"));
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} on a read-only lookup must be a 405, not a handled request"
        );
        let allow = resp
            .headers()
            .get(reqwest::header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            allow.contains("GET"),
            "{method}: a 405 must advertise the methods that ARE allowed, got Allow: {allow:?}"
        );
    }
}

/// `Content-Type: application/json` on the success path and on the handler's
/// error paths alike.
///
/// Worth its own test rather than folding into the envelope helper: a consumer
/// choosing its parser off the header is the normal case, and a 200 that is
/// JSON while the errors are `text/plain` is precisely the trap the
/// repeated-parameter deviation lays. Both paths are checked in one place so
/// the asymmetry cannot be introduced without something going red.
#[tokio::test]
#[ignore]
async fn the_content_type_is_application_json_on_both_the_success_and_the_error_path() {
    let c = Client::new();
    mock_reset(&c).await;

    for (raw, expected) in [
        (format!("did={DID_UNKNOWN}"), StatusCode::OK),
        (String::new(), StatusCode::BAD_REQUEST),
        (
            "mxid=@alice:matrix.org".to_string(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let answer = get_resolve(&c, &raw).await;
        assert_eq!(answer.status, expected, "`?{raw}` body={:?}", answer.body);
        assert_eq!(
            answer.content_type.as_deref(),
            Some("application/json"),
            "`?{raw}` answered {} with Content-Type {:?}",
            answer.status,
            answer.content_type
        );
    }
}

/// `docs/api/README.md`: "**`/resolve` never returns 500.**" Held against a
/// corpus of inputs chosen to be hostile rather than representative.
///
/// A 500 here would be worse than on any other route in this service: it is
/// unauthenticated, so the corpus below is what an arbitrary stranger can send,
/// and the module doc's contract is that an unanswerable question degrades into
/// a *named* 502 or 503 rather than a stack trace. The corpus deliberately
/// includes the inputs that reach Axum rather than the handler — a 500 is
/// forbidden whichever layer produces the response.
#[tokio::test]
#[ignore]
async fn no_query_string_this_endpoint_accepts_can_make_it_answer_500() {
    let c = Client::new();
    mock_reset(&c).await;

    let huge = "x".repeat(20_000);
    let corpus = vec![
        String::new(),
        "did".to_string(),
        "did=".to_string(),
        "mxid=".to_string(),
        "did=&mxid=".to_string(),
        // repeated selectors — the extractor's territory
        "did=a&did=b".to_string(),
        "mxid=@a:matrix.test&mxid=@b:matrix.test".to_string(),
        // `;` is not a separator to serde_urlencoded, so this is ONE value that
        // happens to look like two parameters — a quiet way past the
        // duplicate-field rejection, and it must still not 500.
        "did=a;did=b".to_string(),
        // percent-encoded separators inside a value
        "did=did%3Akey%3AzAbc%26x%3Dy".to_string(),
        // bytes that are not valid UTF-8 once decoded
        "did=%FF%FE".to_string(),
        // a very long value
        format!("did={huge}"),
        format!("mxid=@{huge}:matrix.test"),
        // malformed mxids of every shape
        "mxid=@".to_string(),
        "mxid=:".to_string(),
        "mxid=@ :matrix.test".to_string(),
        "mxid=@alice:matrix.test:8448".to_string(),
        "mxid=@alice:matrix.org".to_string(),
        // unknown parameters alongside a good one
        format!("did={DID_UNKNOWN}&foo=bar&foo=baz"),
    ];

    for raw in corpus {
        let answer = get_resolve(&c, &raw).await;
        assert_ne!(
            answer.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "`?{raw}` answered 500; this route must degrade into a named 400/502/503 \
             instead. body={:?}",
            answer.body
        );
    }
}
