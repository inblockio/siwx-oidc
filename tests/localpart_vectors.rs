//! Golden vectors for the DID -> Matrix localpart derivation, as a FILE.
//!
//! `src/mxid.rs` pins the same values in its own unit tests, but those are
//! Rust constants nobody outside this crate can read. Every other copy of the
//! derivation (the Element Web `resolve-did-search` patch in
//! siwx-oidc-matrix-server, `e2e/browser/mxid-helper.mjs`) is hand-maintained
//! and can only be checked against something it can load. This fixture is that
//! something: a mirror's test suite embeds or reads
//! `tests/fixtures/localpart-vectors.json`, and this test guarantees the file
//! states what the library actually computes.
//!
//! If this fails, do not "fix" the fixture: the derivation changed, and a
//! changed derivation silently reassigns Matrix accounts.

use siwx_oidc::mxid::{canonicalize, legacy_localpart, localpart_for};

#[test]
fn the_vector_file_is_what_the_library_computes() {
    let raw = include_str!("fixtures/localpart-vectors.json");
    let doc: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    let vectors = doc["vectors"].as_array().expect("a `vectors` array");
    assert!(vectors.len() >= 6, "the fixture lost vectors");

    for v in vectors {
        let did = v["did"].as_str().expect("did");
        assert_eq!(
            canonicalize(did),
            v["canonical"].as_str().unwrap(),
            "canonical of {did}"
        );
        assert_eq!(
            localpart_for(did),
            v["localpart"].as_str().unwrap(),
            "localpart of {did}"
        );
        assert_eq!(
            legacy_localpart(did),
            v["legacy_localpart"].as_str().unwrap(),
            "legacy localpart of {did}"
        );
    }
}
