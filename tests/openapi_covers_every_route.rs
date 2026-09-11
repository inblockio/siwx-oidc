//! The OpenAPI description is ENFORCED, not decorative.
//!
//! An API document that nothing checks is worse than no document: it is
//! confidently wrong, and a consumer has no way to tell which half is stale.
//! This test reads the router out of `src/axum_lib.rs` and fails when a route
//! exists there and not in `docs/api/openapi.yaml`, so a new endpoint cannot
//! ship undocumented.
//!
//! It deliberately checks ONE direction. "Every route is documented" is the
//! property that protects consumers; the reverse ("every documented path is a
//! route") would fight legitimate cases — a path served by the reverse proxy in
//! front of this service, or one documented ahead of a staged rollout — and a
//! test that cries wolf gets an ignore list bolted on, at which point it
//! protects nothing.
//!
//! Source-text parsing rather than router introspection is a deliberate
//! trade-off: `axum::Router` exposes no way to enumerate its routes, and the
//! alternative — a hand-maintained list of paths in this file — would be a
//! second source of truth that drifts exactly like the document it is meant to
//! guard.

use std::collections::BTreeSet;
use std::fs;

const AXUM_LIB: &str = "src/axum_lib.rs";
const OIDC: &str = "src/oidc.rs";
const OPENAPI: &str = "docs/api/openapi.yaml";

/// Paths that are intentionally absent from the API document.
///
/// Static assets: files the browser fetches, not an
/// interface anyone programs against. Everything else belongs in the document.
const NOT_AN_API: &[&str] = &["/", "/error", "/favicon.png", "/img"];

/// Resolve `pub const NAME: &str = "value";` out of `src/oidc.rs`, so a renamed
/// constant moves the expectation with it instead of silently dropping a route.
fn path_constants() -> Vec<(String, String)> {
    let src = fs::read_to_string(OIDC).expect("read src/oidc.rs");
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": &str = ") else {
            continue;
        };
        if !name.ends_with("_PATH") {
            continue;
        }
        let value = value.trim_end_matches(';').trim().trim_matches('"');
        out.push((name.to_string(), value.to_string()));
    }
    assert!(
        out.len() >= 8,
        "expected the OIDC path constants to be found in {OIDC}; got {out:?}"
    );
    out
}

/// Every path the router serves, as a literal.
fn routed_paths() -> BTreeSet<String> {
    let src = fs::read_to_string(AXUM_LIB).expect("read src/axum_lib.rs");
    let constants = path_constants();
    let mut paths = BTreeSet::new();

    for raw in src.split(".route(").skip(1) {
        // The first argument ends at the first comma that is not inside the
        // argument itself. Both forms in use are simple enough to split on the
        // first comma: a string literal, or `oidc::NAME_PATH`.
        let arg = raw.split(',').next().unwrap_or_default().trim();

        if let Some(literal) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
            paths.insert(literal.to_string());
            continue;
        }
        if let Some(name) = arg.strip_prefix("oidc::") {
            if let Some((_, value)) = constants.iter().find(|(n, _)| n == name) {
                paths.insert(value.clone());
                continue;
            }
        }
        // `&format!("{}/{{id}}", oidc::CLIENT_PATH)` — the one computed route.
        if arg.starts_with("&format!") {
            let Some(name) = raw.split("oidc::").nth(1) else {
                panic!("computed route argument names no path constant: {arg}");
            };
            let name: String = name
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            let (_, base) = constants
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("unknown path constant in computed route: {name}"));
            paths.insert(format!("{base}/{{id}}"));
            continue;
        }
        panic!(
            "could not work out the path of a `.route(` call from its first argument: {arg}\n\
             Teach this test the new form rather than deleting the check."
        );
    }

    assert!(
        paths.len() > 20,
        "parsed suspiciously few routes ({}) — the parser has probably stopped \
         matching the router's shape, which would make this test pass vacuously",
        paths.len()
    );
    paths
}

#[test]
fn every_route_is_described_in_the_openapi_document() {
    let spec = fs::read_to_string(OPENAPI).expect("read docs/api/openapi.yaml");
    let mut undocumented = Vec::new();

    for path in routed_paths() {
        if NOT_AN_API.contains(&path.as_str()) {
            continue;
        }
        // Top-level keys under `paths:` are indented two spaces. Matching the
        // exact `\n  {path}:` shape avoids a substring match passing because the
        // path happened to appear inside a description.
        if !spec.contains(&format!("\n  {path}:")) {
            undocumented.push(path);
        }
    }

    assert!(
        undocumented.is_empty(),
        "these routes exist in {AXUM_LIB} but are not described in {OPENAPI}:\n  {}\n\n\
         Add them to the document. If one is genuinely not part of the API \
         (a static asset, say), add it to NOT_AN_API with a reason.",
        undocumented.join("\n  ")
    );
}

#[test]
fn the_static_asset_exemptions_are_all_still_routes() {
    // A stale exemption is how an ignore list quietly grows into a way of
    // skipping real endpoints. If a path here is no longer served at all, it
    // should be deleted from NOT_AN_API, not left as cover.
    let routed = routed_paths();
    let src = fs::read_to_string(AXUM_LIB).expect("read src/axum_lib.rs");
    for exempt in NOT_AN_API {
        assert!(
            routed.contains(*exempt) || src.contains(&format!("\"{exempt}\"")),
            "{exempt} is exempted from the API document but is not served anywhere \
             in {AXUM_LIB} — delete the exemption"
        );
    }
}
