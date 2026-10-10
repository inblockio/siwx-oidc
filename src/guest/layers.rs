//! The request and response rules every `/guest` route shares (S1 slice B).
//!
//! The guest router is merged into the app AFTER the global CORS layer, so it
//! inherits none of it: each rule below is the guest path's own, and a change
//! here can never leak into the existing routes.
//!
//! - Every guest response, an error included, carries the GP-SEC-39 headers.
//! - A POST must be `application/json` (415) and at most [`BODY_LIMIT`] bytes
//!   (413); a route that needs more (`claim/finish`) layers [`claim_body_limit`].
//! - The cookie and no-credential group checks `Origin` and `Sec-Fetch-Site` on
//!   POST (403) and answers no CORS: a browser on another origin may neither
//!   drive nor read it. GET is not checked: no GET changes state, and the join
//!   page is reached by a top-level navigation from a link in a mail or chat,
//!   which a browser sends as `Sec-Fetch-Site: none` or `cross-site`.
//! - The Bearer group gets the same `*` CORS as the global layer, without
//!   credentials: the host tool and the Meet client call it from their own
//!   origins, and the Bearer token is the whole authorisation.
//! - With guest mode off, every `/guest` path answers 503 `guest_unavailable`.
//!   With it on, an unknown one answers 404.

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::Url;

/// The body cap on guest routes (GP-SEC-04).
pub const BODY_LIMIT: usize = 4 * 1024;
/// The body cap on `claim/finish`, which carries a WebAuthn attestation (GP-SEC-04).
#[cfg_attr(not(test), allow(dead_code))] // until `claim/finish` (S7)
pub const CLAIM_BODY_LIMIT: usize = 16 * 1024;

/// The GP-SEC-39 headers, set on every guest response.
const SECURITY_HEADERS: [(&str, &str); 5] = [
    (
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; \
         form-action 'self'; frame-ancestors 'none'",
    ),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
    ("cache-control", "no-store"),
];

/// The body cap for a route that takes a WebAuthn attestation. Layer it on that
/// route only; the innermost limit wins.
#[cfg_attr(not(test), allow(dead_code))] // until `claim/finish` (S7)
pub fn claim_body_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(CLAIM_BODY_LIMIT)
}

/// A guest error: `{"error": code}` and nothing from the request.
pub fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

/// The issuer origin a same-origin request names in `Origin`: scheme, host and
/// port of `base_url`, without a path.
pub fn issuer_origin(base_url: &Url) -> String {
    base_url.origin().ascii_serialization()
}

/// Assemble the guest router from its two groups.
///
/// `cookie_routes` are authorised by the guest cookie or by nothing (redeem,
/// peek, continue, resume, the claim); `bearer_routes` by an access token (the
/// host's invites, the client's end). Disabled, the groups are dropped and every
/// `/guest` path answers 503.
pub fn build(
    enabled: bool,
    base_url: &Url,
    cookie_routes: Router,
    bearer_routes: Router,
) -> Router {
    let shell = if enabled {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let fallback = any(move || async move {
        error(
            shell,
            if enabled {
                "not_found"
            } else {
                "guest_unavailable"
            },
        )
    });
    let mut router = Router::new()
        .route("/guest", fallback.clone())
        // `{*rest}` does not match an empty rest.
        .route("/guest/", fallback.clone())
        .route("/guest/{*rest}", fallback);
    if enabled {
        let cookie_routes = cookie_routes.layer(middleware::from_fn_with_state(
            issuer_origin(base_url),
            require_same_origin,
        ));
        let bearer_routes = bearer_routes.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
        );
        router = router
            .merge(cookie_routes)
            .merge(bearer_routes)
            .layer(middleware::from_fn(require_json))
            .layer(DefaultBodyLimit::max(BODY_LIMIT));
    }
    router.layer(middleware::map_response(guest_response))
}

/// 415 for a POST whose media type is not `application/json`. Parameters such as
/// `charset` are allowed; a missing `Content-Type` is refused like a wrong one.
async fn require_json(request: Request, next: Next) -> Response {
    if request.method() == Method::POST {
        let json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
        }
    }
    next.run(request).await
}

/// 403 for a POST that is not provably same-origin (GP-SEC-40): at least one of
/// `Origin` and `Sec-Fetch-Site` is present, and each one present matches. A
/// browser always sends one of them on a POST; their absence means a client
/// that is not a browser on the issuer's page, which the cookie routes do not serve.
async fn require_same_origin(
    State(issuer_origin): State<String>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::POST {
        let headers = request.headers();
        let origin = headers.get(header::ORIGIN);
        let fetch_site = headers.get("sec-fetch-site");
        let origin_ok = origin.is_none_or(|v| v.as_bytes() == issuer_origin.as_bytes());
        let fetch_site_ok = fetch_site.is_none_or(|v| v.as_bytes() == b"same-origin");
        if (origin.is_none() && fetch_site.is_none()) || !origin_ok || !fetch_site_ok {
            return error(StatusCode::FORBIDDEN, "forbidden_origin");
        }
    }
    next.run(request).await
}

/// Set the GP-SEC-39 headers, and give an error that axum produced itself (an
/// over-long body, a wrong method) the same JSON shape as the guest's own.
async fn guest_response(response: Response) -> Response {
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
    let mut response = if (status.is_client_error() || status.is_server_error()) && !is_json {
        let code = match status {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "bad_request",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
            StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
            _ => "error",
        };
        let (mut parts, body) = error(status, code).into_parts();
        // Keep what an inner layer set (`Allow` on a 405, CORS headers).
        for (name, value) in response.headers() {
            if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
                parts.headers.entry(name).or_insert(value.clone());
            }
        }
        Response::from_parts(parts, body)
    } else {
        response
    };
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    //! Driven over a real socket, as the request-logging test is: the layers are
    //! the subject, so only a request through the whole stack shows them.
    use super::*;
    use axum::{body::Bytes, routing::post};
    use reqwest::header::HeaderMap;
    use tokio::net::TcpListener;

    const ISSUER: &str = "https://id.example.org";

    async fn echo(body: Bytes) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "len": body.len() }))
    }

    /// A guest router with one test route per group, merged into an app shaped like
    /// `axum_lib`'s: one ordinary route behind the global `*` CORS layer.
    async fn serve(enabled: bool) -> String {
        let cookie = Router::new()
            .route("/guest/t/cookie", post(echo).get(|| async { "ok" }))
            .route("/guest/t/claim", post(echo).layer(claim_body_limit()));
        let bearer = Router::new().route("/guest/t/bearer", post(echo).get(|| async { "ok" }));
        let app = Router::new()
            .route("/plain", post(echo).get(|| async { "ok" }))
            .layer(CorsLayer::new().allow_origin(AllowOrigin::any()))
            .merge(build(enabled, &Url::parse(ISSUER).unwrap(), cookie, bearer));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn assert_guest_headers(headers: &HeaderMap, what: &str) {
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(
                headers.get(name).map(|v| v.to_str().unwrap()),
                Some(value),
                "{what}: {name}"
            );
        }
    }

    async fn post_json(
        base: &str,
        path: &str,
        body: String,
        extra: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut req = reqwest::Client::new()
            .post(format!("{base}{path}"))
            .header("content-type", "application/json")
            .body(body);
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        req.send().await.unwrap()
    }

    async fn error_code(response: reqwest::Response) -> String {
        let v: serde_json::Value = response.json().await.unwrap();
        v["error"].as_str().unwrap().to_string()
    }

    #[test]
    fn the_issuer_origin_is_scheme_host_and_port_only() {
        let origin = |u: &str| issuer_origin(&Url::parse(u).unwrap());
        assert_eq!(origin("https://id.example.org/"), "https://id.example.org");
        assert_eq!(
            origin("https://id.example.org/sub/path"),
            "https://id.example.org"
        );
        assert_eq!(origin("http://localhost:18080"), "http://localhost:18080");
        assert_eq!(
            origin("https://id.example.org:443"),
            "https://id.example.org"
        );
    }

    #[tokio::test]
    async fn the_cookie_group_refuses_a_post_that_is_not_provably_same_origin() {
        let base = serve(true).await;
        let cases: [(&[(&str, &str)], u16); 8] = [
            (&[("origin", ISSUER)], 200),
            (&[("sec-fetch-site", "same-origin")], 200),
            (
                &[("origin", ISSUER), ("sec-fetch-site", "same-origin")],
                200,
            ),
            (&[], 403),
            (&[("origin", "https://evil.example.org")], 403),
            (&[("origin", "null")], 403),
            (&[("sec-fetch-site", "same-site")], 403),
            (&[("origin", ISSUER), ("sec-fetch-site", "cross-site")], 403),
        ];
        for (headers, want) in cases {
            let r = post_json(&base, "/guest/t/cookie", "{}".into(), headers).await;
            assert_eq!(r.status().as_u16(), want, "{headers:?}");
            assert_guest_headers(r.headers(), "cookie group");
            assert!(r.headers().get("access-control-allow-origin").is_none());
            if want == 403 {
                assert_eq!(error_code(r).await, "forbidden_origin");
            }
        }
        // A navigation to a guest page comes from a link: GET is never origin-checked.
        let r = reqwest::Client::new()
            .get(format!("{base}/guest/t/cookie"))
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn only_the_bearer_group_answers_cors() {
        let base = serve(true).await;
        let client = reqwest::Client::new();
        let r = post_json(
            &base,
            "/guest/t/bearer",
            "{}".into(),
            &[("origin", "https://meet.example.org")],
        )
        .await;
        assert_eq!(r.status(), 200, "the Bearer group has no origin check");
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        assert!(r
            .headers()
            .get("access-control-allow-credentials")
            .is_none());
        assert_guest_headers(r.headers(), "bearer group");

        let preflight = |path: &'static str| {
            client
                .request(Method::OPTIONS, format!("{base}{path}"))
                .header("origin", "https://meet.example.org")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "authorization, content-type",
                )
                .send()
        };
        let r = preflight("/guest/t/bearer").await.unwrap();
        assert!(r.status().is_success(), "{}", r.status());
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
        assert_guest_headers(r.headers(), "bearer preflight");

        let r = preflight("/guest/t/cookie").await.unwrap();
        assert!(r.headers().get("access-control-allow-origin").is_none());
        assert_guest_headers(r.headers(), "cookie preflight");
    }

    #[tokio::test]
    async fn a_post_must_be_json() {
        let base = serve(true).await;
        let client = reqwest::Client::new();
        for path in ["/guest/t/cookie", "/guest/t/bearer"] {
            for content_type in [
                Some("text/plain"),
                Some("application/x-www-form-urlencoded"),
                Some("multipart/form-data; boundary=x"),
                Some("application/jsonx"),
                None,
            ] {
                let mut req = client
                    .post(format!("{base}{path}"))
                    .header("origin", ISSUER)
                    .body("{}");
                if let Some(ct) = content_type {
                    req = req.header("content-type", ct);
                }
                let r = req.send().await.unwrap();
                assert_eq!(r.status(), 415, "{path} {content_type:?}");
                assert_guest_headers(r.headers(), "415");
                assert_eq!(error_code(r).await, "unsupported_media_type");
            }
            let r = post_json(&base, path, "{}".into(), &[("origin", ISSUER)]).await;
            assert_eq!(r.status(), 200, "{path} plain json");
            let r = client
                .post(format!("{base}{path}"))
                .header("origin", ISSUER)
                .header("content-type", "Application/JSON; charset=utf-8")
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "{path} json with a charset");
        }
    }

    #[tokio::test]
    async fn the_body_is_capped_at_4_kib_and_16_kib_on_the_claim() {
        let base = serve(true).await;
        let o = [("origin", ISSUER)];
        for (path, cap) in [
            ("/guest/t/cookie", BODY_LIMIT),
            ("/guest/t/bearer", BODY_LIMIT),
            ("/guest/t/claim", CLAIM_BODY_LIMIT),
        ] {
            let r = post_json(&base, path, "x".repeat(cap), &o).await;
            assert_eq!(r.status(), 200, "{path} at the cap");
            let r = post_json(&base, path, "x".repeat(cap + 1), &o).await;
            assert_eq!(r.status(), 413, "{path} over the cap");
            assert_guest_headers(r.headers(), "413");
            assert_eq!(error_code(r).await, "payload_too_large");
        }
        let r = post_json(&base, "/guest/t/cookie", "x".repeat(CLAIM_BODY_LIMIT), &o).await;
        assert_eq!(
            r.status(),
            413,
            "the claim cap does not leak to other routes"
        );
    }

    #[tokio::test]
    async fn an_unknown_guest_path_is_a_404_with_the_headers() {
        let base = serve(true).await;
        let client = reqwest::Client::new();
        for path in ["/guest", "/guest/", "/guest/nope", "/guest/a/b/c"] {
            let r = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(r.status(), 404, "{path}");
            assert_guest_headers(r.headers(), path);
            assert!(r.headers().get("access-control-allow-origin").is_none());
            assert_eq!(error_code(r).await, "not_found");
        }
        let r = client
            .put(format!("{base}/guest/t/bearer"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405);
        assert!(
            r.headers().get("allow").is_some(),
            "the Allow header survives"
        );
        assert_guest_headers(r.headers(), "405");
        assert_eq!(error_code(r).await, "method_not_allowed");
    }

    #[tokio::test]
    async fn guest_mode_off_answers_503_on_every_guest_path() {
        let base = serve(false).await;
        let client = reqwest::Client::new();
        for path in [
            "/guest",
            "/guest/",
            "/guest/t/cookie",
            "/guest/t/bearer",
            "/guest/invites",
        ] {
            for method in [Method::GET, Method::POST, Method::OPTIONS] {
                let r = client
                    .request(method.clone(), format!("{base}{path}"))
                    .header("origin", "https://meet.example.org")
                    .header("content-type", "application/json")
                    .body("{}")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(r.status(), 503, "{method} {path}");
                assert_guest_headers(r.headers(), "503");
                assert!(r.headers().get("access-control-allow-origin").is_none());
                assert_eq!(error_code(r).await, "guest_unavailable");
            }
        }
    }

    #[tokio::test]
    async fn the_other_routes_get_none_of_the_guest_rules() {
        for enabled in [false, true] {
            let base = serve(enabled).await;
            let r = reqwest::Client::new()
                .post(format!("{base}/plain"))
                .header("origin", "https://evil.example.org")
                .header("content-type", "text/plain")
                .body("x".repeat(BODY_LIMIT * 2))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "enabled={enabled}");
            assert_eq!(r.headers()["access-control-allow-origin"], "*");
            for (name, _) in SECURITY_HEADERS {
                assert!(
                    r.headers().get(name).is_none(),
                    "{name} leaked, enabled={enabled}"
                );
            }
        }
    }
}
