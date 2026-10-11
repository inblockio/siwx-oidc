//! The hand-off to the portal (work package S4a): the `/authorize` marker branch and
//! the `/guest/continue` ceremony.
//!
//! - `/authorize` with the scope `urn:io.inblock:guest` is routed here by the handler in
//!   `axum_lib.rs` (guest mode on). It never renders the login page: a live guest session
//!   becomes a login session carrying `guest_id` and the browser goes to
//!   `GET /guest/continue`; anything else is `interaction_required` on the redirect URI.
//! - `GET /guest/continue` serves the page (compiled in; the session facts it needs are
//!   written into `data-` attributes, no inline script). The page loads the stored key,
//!   signs the continue message and `POST`s it.
//! - `POST /guest/continue` rebuilds the message, checks the DID against the record and
//!   the signature, and writes `verified_did` on the login session, so `sign_in` stays
//!   Path A. The guest branch of `sign_in` itself is S4b; until then it ends in the
//!   503 seam [`guest_sign_in_seam`].
//!
//! The marker only routes the request: it is stripped from the scope the session binds,
//! so it is never granted, and it is not in discovery.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use super::invite::GuestState;
use super::layers::error;
use crate::config::Config;
use crate::oidc::{AuthorizeParams, CustomError};
use siwx_oidc::db::guest_records::GuestSession;
use siwx_oidc::db::{DBClient, RedisClient, SessionEntry, SESSION_COOKIE_NAME};
use siwx_oidc::guest_admission::{verify_continue_proof, ContinueError};

/// The scope word that routes an `/authorize` request here.
pub const GUEST_MARKER_SCOPE: &str = "urn:io.inblock:guest";
/// Where the `/authorize` marker branch sends the browser.
pub const CONTINUE_PATH: &str = "/guest/continue";

const CONTINUE_HTML: &str = include_str!("../../static/guest/continue.html");

/// Whether a scope string carries the marker as a whole word.
pub fn scope_has_marker(scope: &str) -> bool {
    scope.split(' ').any(|s| s == GUEST_MARKER_SCOPE)
}

/// The scope without the marker, words in their original order.
fn strip_marker(scope: &str) -> String {
    scope
        .split(' ')
        .filter(|s| !s.is_empty() && *s != GUEST_MARKER_SCOPE)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The value of cookie `name` in the request's `Cookie` headers.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.to_string())
}

/// The guest session cookie's name: `__Host-` on https, plain on http development.
fn guest_cookie_name(config: &Config) -> &'static str {
    if config.base_url.scheme() == "https" {
        "__Host-guest_session"
    } else {
        "guest_session"
    }
}

/// S6 seam: the kill switch. Returns whether guest hand-offs are switched off
/// (`guest:control == disabled`, set by the operator). S6 fills this in; until then it is
/// never engaged here. Both `/authorize` and `/guest/continue` ask it, so a guest session
/// stops handing off the moment it is.
pub async fn guest_kill_switch_engaged(_redis: &RedisClient) -> anyhow::Result<bool> {
    // S6: read the control key.
    Ok(false)
}

/// The record behind the request's guest cookie, if it is a live session and the kill
/// switch is off. `Ok(None)` is "no live session" in every shape: no cookie, unknown
/// handle, reaping, claimed, past its deadline, switched off.
async fn live_guest(
    config: &Config,
    redis: &RedisClient,
    headers: &HeaderMap,
) -> anyhow::Result<Option<GuestSession>> {
    let Some(handle) = cookie_value(headers, guest_cookie_name(config)) else {
        return Ok(None);
    };
    let Some(record) = redis.read_guest_session(&handle).await? else {
        return Ok(None);
    };
    if !record.is_live() || guest_kill_switch_engaged(redis).await? {
        return Ok(None);
    }
    Ok(Some(record))
}

// ---------------------------------------------------------------------------------
// /authorize
// ---------------------------------------------------------------------------------

/// An error on the redirect URI (RFC 6749 4.1.2.1), with the state when there is one.
fn to_redirect(
    params: &AuthorizeParams,
    state: Option<&str>,
    error: &str,
    description: Option<&str>,
) -> CustomError {
    let mut url = params.redirect_uri.url().clone();
    {
        let mut q = url.query_pairs_mut();
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        q.append_pair("error", error);
        if let Some(d) = description {
            q.append_pair("error_description", d);
        }
    }
    CustomError::Redirect(url.to_string())
}

/// The marker branch of `/authorize`. The caller has checked that guest mode is on and
/// that the scope carries the marker.
pub async fn authorize(
    config: &Config,
    redis: &RedisClient,
    params: AuthorizeParams,
    headers: &HeaderMap,
) -> Result<(HeaderMap, Redirect), CustomError> {
    // The static public client and its exact redirect URIs. Nothing else may use the
    // marker, and neither failure may redirect anywhere (the redirect URI is untrusted).
    if config.guest_client_id.as_deref() != Some(params.client_id.as_str()) {
        return Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        ));
    }
    if !config
        .guest_client_redirect_uris
        .iter()
        .any(|u| u == params.redirect_uri.url())
    {
        return Err(CustomError::Redirect(
            "/error?message=unregistered_redirect_uri".to_string(),
        ));
    }
    let state = params.state.clone();
    let st = state.as_deref();
    let fail = |error: &str, description: &str| to_redirect(&params, st, error, Some(description));
    if st.is_none() {
        return Err(to_redirect(
            &params,
            None,
            "invalid_request",
            Some("Missing state"),
        ));
    }
    if !matches!(
        params.response_type,
        Some(openidconnect::core::CoreResponseType::Code)
    ) {
        return Err(fail(
            "unsupported_response_type",
            "Only response_type=code is supported.",
        ));
    }
    // PKCE S256 is mandatory; a missing method means S256, as everywhere else.
    if params.code_challenge.is_none()
        || params
            .code_challenge_method
            .as_deref()
            .is_some_and(|m| m != "S256")
    {
        return Err(fail("invalid_request", "S256 PKCE is required."));
    }
    // The portal asks silently: the issuer never shows a page it did not choose.
    if !matches!(
        params.prompt,
        Some(openidconnect::core::CoreAuthPrompt::None)
    ) {
        return Err(fail("invalid_request", "prompt=none is required."));
    }
    // Same-site topology: a navigation started on another site is refused before any
    // guest state is read. `Sec-Fetch-Site` is set by the browser, not the page.
    if config.guest_client_topology == "same-site"
        && headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return Err(fail("access_denied", "Cross-site request refused."));
    }
    // The scope the session binds and the code is granted for: the marker is gone.
    let granted = strip_marker(params.scope.as_str());
    if !granted.split(' ').any(|s| s == "openid") {
        return Err(fail("invalid_scope", "The openid scope is required."));
    }

    let live = match live_guest(config, redis, headers).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "guest authorize: record lookup failed");
            return Err(fail("temporarily_unavailable", "Try again."));
        }
    };
    let Some(record) = live else {
        return Err(fail("interaction_required", "No guest session."));
    };
    let cookie = crate::oidc::start_guest_session(
        &params,
        st.unwrap_or_default(),
        granted,
        record.localpart,
        redis,
    )
    .await?;
    let mut out = HeaderMap::new();
    out.insert(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .map_err(|_| anyhow::anyhow!("session cookie"))?,
    );
    Ok((out, Redirect::to(CONTINUE_PATH)))
}

/// S4b seam: a verified guest session reached code issuance. The fence
/// (`minted`/`provisioning` to `provisioning`), the fail-closed provisioning, the marker
/// PUT, the canonical-name PUT, the caps and the `active` write replace this body; until
/// then no code is issued to a guest. Called from `oidc::sign_in` before the session is
/// marked signed in, so a refusal here burns nothing.
pub fn guest_sign_in_seam(session: &SessionEntry) -> Result<(), CustomError> {
    // A guest session is finished only by /guest/continue, which writes `verified_did`.
    if session.verified_did.is_none() {
        return Err(CustomError::Unauthorized(
            "The guest hand-off was not completed.".to_string(),
        ));
    }
    // S4b: provision here and fall through to code issuance.
    Err(CustomError::Coded {
        status: 503,
        code: "unavailable",
    })
}

// ---------------------------------------------------------------------------------
// /guest/continue
// ---------------------------------------------------------------------------------

/// What the page needs, or why it cannot run.
struct Ready {
    state: &'static str,
    did: String,
    redirect_uri: String,
    nonce: String,
}

/// The login session the hand-off belongs to, with the live guest it must belong to.
async fn hand_off_context(
    state: &GuestState,
    headers: &HeaderMap,
) -> Result<(String, SessionEntry, GuestSession), &'static str> {
    let Some(session_id) = cookie_value(headers, SESSION_COOKIE_NAME) else {
        return Err("no_session");
    };
    let entry = match state.redis.get_session(session_id.clone()).await {
        Ok(Some(e)) => e,
        Ok(None) => return Err("no_session"),
        Err(e) => {
            warn!(error = %e, "guest continue: session lookup failed");
            return Err("unavailable");
        }
    };
    let (Some(guest_id), Some(_)) = (entry.guest_id.as_deref(), entry.request.as_ref()) else {
        return Err("no_session");
    };
    let record = match live_guest(&state.config, &state.redis, headers).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err("no_guest"),
        Err(e) => {
            warn!(error = %e, "guest continue: record lookup failed");
            return Err("unavailable");
        }
    };
    if record.localpart != guest_id {
        return Err("no_guest");
    }
    Ok((session_id, entry, record))
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// `GET /guest/continue`. The same shell in every case; `data-state` says what it may do:
/// `ready`, `no_guest` (no live guest cookie: "open your invitation link again"),
/// `no_session` (not a guest hand-off) or `unavailable`.
pub async fn continue_page(State(state): State<GuestState>, headers: HeaderMap) -> Response {
    let ready = match hand_off_context(&state, &headers).await {
        Ok((_, entry, record)) => {
            let request = entry
                .request
                .unwrap_or_else(|| unreachable!("checked above"));
            Ready {
                state: "ready",
                did: record.did,
                redirect_uri: request.redirect_uri,
                nonce: entry.siwe_nonce,
            }
        }
        Err(why) => Ready {
            state: why,
            did: String::new(),
            redirect_uri: String::new(),
            nonce: String::new(),
        },
    };
    // Always 200: `layers::guest_response` replaces the body of any error status with the
    // JSON error shell, and the page must reach the browser to say what to do. The
    // state is in `data-state`.
    let body = CONTINUE_HTML
        .replace("{{STATE}}", ready.state)
        .replace("{{DID}}", &html_escape(&ready.did))
        .replace("{{REDIRECT}}", &html_escape(&ready.redirect_uri))
        .replace("{{NONCE}}", &html_escape(&ready.nonce));
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

#[derive(Deserialize)]
struct ContinueBody {
    redirect_uri: String,
    message: String,
    signature: String,
}

fn decode_signature(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| STANDARD.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .ok()
}

/// `POST /guest/continue` `{redirect_uri, message, signature}`. 200 `{"next":"/sign_in"}`
/// after `verified_did` is written; the page then navigates there.
///
/// Refusals: 400 `bad_request` (unreadable body or message), `redirect_not_allowed`,
/// `nonce_mismatch`, `resource_mismatch`; 401 `no_session` (no live guest cookie, a record
/// that is reaping or past its deadline, or no guest login session), `did_mismatch`,
/// `signature_invalid`; 503 `unavailable`.
pub async fn continue_post(
    State(state): State<GuestState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(req) = serde_json::from_slice::<ContinueBody>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let (session_id, mut entry, record) = match hand_off_context(&state, &headers).await {
        Ok(t) => t,
        Err("unavailable") => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Err(_) => return error(StatusCode::UNAUTHORIZED, "no_session"),
    };
    let bound = entry
        .request
        .as_ref()
        .map(|r| r.redirect_uri.clone())
        .unwrap_or_default();
    let in_list = state
        .config
        .guest_client_redirect_uris
        .iter()
        .any(|u| u.as_str() == req.redirect_uri);
    if !in_list || req.redirect_uri != bound {
        return error(StatusCode::BAD_REQUEST, "redirect_not_allowed");
    }
    let Some(signature) = decode_signature(&req.signature) else {
        return error(StatusCode::UNAUTHORIZED, "signature_invalid");
    };
    if let Err(why) = verify_continue_proof(
        &state.config.base_url,
        &record.did,
        &bound,
        &entry.siwe_nonce,
        &req.message,
        &signature,
        Utc::now(),
    ) {
        return match why {
            ContinueError::DidMismatch => error(StatusCode::UNAUTHORIZED, "did_mismatch"),
            ContinueError::SignatureInvalid => error(StatusCode::UNAUTHORIZED, "signature_invalid"),
            ContinueError::NonceMismatch => error(StatusCode::BAD_REQUEST, "nonce_mismatch"),
            ContinueError::ResourceMismatch => error(StatusCode::BAD_REQUEST, "resource_mismatch"),
            ContinueError::Malformed => error(StatusCode::BAD_REQUEST, "bad_request"),
        };
    }
    entry.verified_did = Some(record.did);
    if let Err(e) = state.redis.set_session(session_id, entry).await {
        warn!(error = %e, "guest continue: session write failed");
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    let mut response = Json(json!({"next": "/sign_in"})).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    //! Driven against a real Redis: the marker branch is called directly (it needs no
    //! socket), `/guest/continue` is driven over a real socket through the whole guest
    //! stack, with keys made by the dalek crate.
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::Signer as _;
    use rand::rngs::OsRng;
    use serde_json::Value;
    use siwx_oidc::db::{DBClient, RedisClient};
    use siwx_oidc::guest_admission::build_continue_message;
    use tokio::net::TcpListener;

    const ISSUER: &str = "https://id.example.org";
    const REDIRECT: &str = "https://meet.example.org/auth/callback";
    const CLIENT: &str = "meet-guest";

    fn uniq() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    struct Guest {
        sk: ed25519_dalek::SigningKey,
        did: String,
    }

    impl Guest {
        fn new() -> Self {
            let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let mut b = vec![0xed, 0x01];
            b.extend_from_slice(sk.verifying_key().as_bytes());
            let did = format!("did:key:z{}", bs58::encode(b).into_string());
            Guest { sk, did }
        }
        fn sign(&self, message: &str) -> String {
            URL_SAFE_NO_PAD.encode(self.sk.sign(message.as_bytes()).to_bytes())
        }
    }

    struct Env {
        base: String,
        redis: RedisClient,
        config: Config,
    }

    async fn env(edit: impl Fn(&mut Config)) -> Option<Env> {
        let redis = siwx_oidc::test_support::redis().await?;
        let mut config = Config {
            guest_enabled: true,
            base_url: url::Url::parse(ISSUER).unwrap(),
            guest_client_id: Some(CLIENT.into()),
            guest_client_redirect_uris: vec![url::Url::parse(REDIRECT).unwrap()],
            ..Config::default()
        };
        edit(&mut config);
        let app = super::super::routes::router(&config, redis.clone(), None);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Some(Env {
            base: format!("http://{addr}"),
            redis,
            config,
        })
    }

    /// A guest record (any state, deadline `deadline_in` seconds away) and its handle.
    async fn record(e: &Env, g: &Guest, state: &str, deadline_in: i64) -> (String, String) {
        let (localpart, handle) = (siwx_oidc::mxid::localpart_for(&g.did), uniq());
        e.redis
            .put_guest_for_test(&localpart, &g.did, state, deadline_in, &handle)
            .await;
        (localpart, handle)
    }

    fn params(client: &str, redirect: &str, scope: &str, extra: Value) -> AuthorizeParams {
        let mut v = json!({
            "client_id": client,
            "redirect_uri": redirect,
            "scope": scope,
            "response_type": "code",
            "state": "st-1",
            "prompt": "none",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        });
        for (k, val) in extra.as_object().unwrap() {
            if val.is_null() {
                v.as_object_mut().unwrap().remove(k);
            } else {
                v[k] = val.clone();
            }
        }
        serde_json::from_value(v).expect("authorize params")
    }

    const SCOPE: &str =
        "openid urn:matrix:client:api:* urn:matrix:client:device:ABCDEFGH urn:io.inblock:guest";

    fn cookies(e: &Env, handle: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{}={handle}", guest_cookie_name(&e.config))
                .parse()
                .unwrap(),
        );
        h
    }

    fn err_url(r: Result<(HeaderMap, Redirect), CustomError>) -> String {
        match r {
            Err(CustomError::Redirect(u)) => u,
            Err(CustomError::Unauthorized(m)) => format!("unauthorized:{m}"),
            Err(_) => "other-error".into(),
            Ok(_) => "ok".into(),
        }
    }

    fn session_cookie_of(h: &HeaderMap) -> String {
        let c = h[header::SET_COOKIE].to_str().unwrap();
        c.split(';').next().unwrap().to_string() // `session=<id>`
    }

    /// ST-24, ST-30, ST-44 (the cross-site half): every refusal of the marker branch, and
    /// the one success. A refusal never reaches the point where a session is written.
    #[tokio::test]
    async fn st24_st30_st44_the_authorize_marker_vectors() {
        let Some(e) = env(|_| {}).await else { return };
        let g = Guest::new();
        let (_, handle) = record(&e, &g, "minted", 600).await;
        let ok_h = cookies(&e, &handle);
        let run = |p: AuthorizeParams, h: HeaderMap| {
            let (cfg, redis) = (e.config.clone(), e.redis.clone());
            async move { authorize(&cfg, &redis, p, &h).await }
        };
        // A foreign client, even with the Meet client's exact redirect (a dynamic client
        // sharing it): no session, no redirect.
        let r = err_url(run(params("dyn-1", REDIRECT, SCOPE, json!({})), ok_h.clone()).await);
        assert!(r.starts_with("unauthorized:"), "{r}");
        // Redirects outside the list: foreign host, http, a different path, a query suffix.
        for bad in [
            "https://evil.example.net/auth/callback",
            "http://meet.example.org/auth/callback",
            "https://meet.example.org/auth/callback/",
            "https://meet.example.org/auth/callback?x=1",
        ] {
            let r = err_url(run(params(CLIENT, bad, SCOPE, json!({})), ok_h.clone()).await);
            assert_eq!(r, "/error?message=unregistered_redirect_uri", "{bad}");
        }
        // The request shape: errors go to the redirect URI with the state.
        let cases = [
            (
                "no PKCE",
                json!({"code_challenge": null, "code_challenge_method": null}),
                "invalid_request",
            ),
            (
                "plain PKCE",
                json!({"code_challenge_method": "plain"}),
                "invalid_request",
            ),
            ("no prompt", json!({"prompt": null}), "invalid_request"),
            (
                "prompt=login",
                json!({"prompt": "login"}),
                "invalid_request",
            ),
            ("no state", json!({"state": null}), "invalid_request"),
        ];
        for (name, extra, code) in cases {
            let r = err_url(run(params(CLIENT, REDIRECT, SCOPE, extra), ok_h.clone()).await);
            assert!(
                r.starts_with(REDIRECT) && r.contains(&format!("error={code}")),
                "{name}: {r}"
            );
        }
        let r = err_url(
            run(
                params(CLIENT, REDIRECT, "urn:io.inblock:guest", json!({})),
                ok_h.clone(),
            )
            .await,
        );
        assert!(r.contains("error=invalid_scope"), "{r}");
        // ST-44 / ST-24: a navigation marked cross-site is refused under same-site, before
        // the record is read, and writes nothing.
        let mut cross = ok_h.clone();
        cross.insert("sec-fetch-site", "cross-site".parse().unwrap());
        let r = err_url(run(params(CLIENT, REDIRECT, SCOPE, json!({})), cross.clone()).await);
        assert!(
            r.contains("error=access_denied") && r.contains("state=st-1"),
            "{r}"
        );
        // No cookie, an unknown handle, a record past its deadline, reaping, claimed.
        let none = HeaderMap::new();
        let r = err_url(run(params(CLIENT, REDIRECT, SCOPE, json!({})), none).await);
        assert!(
            r.contains("error=interaction_required") && r.contains("state=st-1"),
            "{r}"
        );
        let r = err_url(
            run(
                params(CLIENT, REDIRECT, SCOPE, json!({})),
                cookies(&e, "unknown"),
            )
            .await,
        );
        assert!(r.contains("error=interaction_required"), "{r}");
        for (state, left) in [
            ("minted", -5),
            ("active", -5),
            ("reaping", 600),
            ("claimed", 600),
        ] {
            let g2 = Guest::new();
            let (_, h2) = record(&e, &g2, state, left).await;
            let r =
                err_url(run(params(CLIENT, REDIRECT, SCOPE, json!({})), cookies(&e, &h2)).await);
            assert!(
                r.contains("error=interaction_required"),
                "{state}/{left}: {r}"
            );
        }
        // A live record: the browser goes to /guest/continue, with a session that carries
        // the guest id and the scope WITHOUT the marker.
        for state in ["minted", "provisioning", "active"] {
            let g2 = Guest::new();
            let (localpart, h2) = record(&e, &g2, state, 600).await;
            let (headers, redirect) =
                run(params(CLIENT, REDIRECT, SCOPE, json!({})), cookies(&e, &h2))
                    .await
                    .unwrap_or_else(|_| panic!("{state} must hand off"));
            let resp = redirect.into_response();
            assert_eq!(resp.headers()[header::LOCATION], CONTINUE_PATH);
            let sid = session_cookie_of(&headers)
                .split_once('=')
                .unwrap()
                .1
                .to_string();
            let s = e.redis.get_session(sid).await.unwrap().unwrap();
            assert_eq!(s.guest_id.as_deref(), Some(localpart.as_str()));
            assert!(s.verified_did.is_none());
            let req = s.request.unwrap();
            assert_eq!(
                req.scope.as_deref(),
                Some("openid urn:matrix:client:api:* urn:matrix:client:device:ABCDEFGH")
            );
            assert_eq!(req.redirect_uri, REDIRECT);
            assert_eq!(req.state, "st-1");
        }
        // Under `cross-site` topology the header is not judged.
        let e2 = env(|c| c.guest_client_topology = "cross-site".into())
            .await
            .unwrap();
        let g3 = Guest::new();
        let (_, h3) = record(&e2, &g3, "active", 600).await;
        let mut ch = cookies(&e2, &h3);
        ch.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(authorize(
            &e2.config,
            &e2.redis,
            params(CLIENT, REDIRECT, SCOPE, json!({})),
            &ch
        )
        .await
        .is_ok());
    }

    #[test]
    fn the_marker_is_a_whole_word_and_is_stripped() {
        assert!(scope_has_marker("openid urn:io.inblock:guest"));
        assert!(!scope_has_marker("openid urn:io.inblock:guestx"));
        assert!(!scope_has_marker("openid"));
        assert_eq!(strip_marker("openid  urn:io.inblock:guest a"), "openid a");
    }

    // ----- /guest/continue -----

    struct Hand {
        session_cookie: String,
        nonce: String,
        guest: Guest,
        handle: String,
        localpart: String,
    }

    /// A live guest with an `/authorize` session behind it.
    async fn hand_off(e: &Env, state: &str) -> Hand {
        let guest = Guest::new();
        let (localpart, handle) = record(e, &guest, state, 600).await;
        let (headers, _) = authorize(
            &e.config,
            &e.redis,
            params(CLIENT, REDIRECT, SCOPE, json!({})),
            &cookies(e, &handle),
        )
        .await
        .unwrap();
        let session_cookie = session_cookie_of(&headers);
        let sid = session_cookie.split_once('=').unwrap().1.to_string();
        let nonce = e.redis.get_session(sid).await.unwrap().unwrap().siwe_nonce;
        Hand {
            session_cookie,
            nonce,
            guest,
            handle,
            localpart,
        }
    }

    fn message(e: &Env, did: &str, redirect: &str, nonce: &str, offset: i64) -> String {
        let now = Utc::now() + Duration::seconds(offset);
        build_continue_message(
            &e.config.base_url,
            did,
            redirect,
            nonce,
            now,
            now + Duration::minutes(5),
        )
        .unwrap()
    }

    async fn post(e: &Env, h: &Hand, cookie: Option<&str>, body: Value) -> (u16, Value) {
        let mut req = reqwest::Client::new()
            .post(format!("{}/guest/continue", e.base))
            .header("content-type", "application/json")
            .header("origin", ISSUER)
            .body(body.to_string());
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        } else {
            let both = format!(
                "{}; {}={}",
                h.session_cookie,
                guest_cookie_name(&e.config),
                h.handle
            );
            req = req.header("cookie", both);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    fn body(redirect: &str, message: &str, signature: &str) -> Value {
        json!({"redirect_uri": redirect, "message": message, "signature": signature})
    }

    async fn verified_did_of(e: &Env, h: &Hand) -> Option<String> {
        let sid = h.session_cookie.split_once('=').unwrap().1.to_string();
        e.redis
            .get_session(sid)
            .await
            .unwrap()
            .unwrap()
            .verified_did
    }

    #[tokio::test]
    async fn the_continue_vectors() {
        let Some(e) = env(|_| {}).await else { return };

        // Good signature: 200, and verified_did is the record's DID.
        let h = hand_off(&e, "minted").await;
        let m = message(&e, &h.guest.did, REDIRECT, &h.nonce, 0);
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
        assert_eq!((st, j["next"].as_str()), (200, Some("/sign_in")), "{j}");
        assert_eq!(verified_did_of(&e, &h).await, Some(h.guest.did.clone()));

        // DID mismatch: another key signs a message that names itself. 401 did_mismatch.
        let h = hand_off(&e, "active").await;
        let other = Guest::new();
        let m = message(&e, &other.did, REDIRECT, &h.nonce, 0);
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &other.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (401, Some("did_mismatch")));
        assert_eq!(verified_did_of(&e, &h).await, None);

        // Bad signature: the right DID, another key's signature. 401 signature_invalid.
        let m = message(&e, &h.guest.did, REDIRECT, &h.nonce, 0);
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &other.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (401, Some("signature_invalid")));
        // ... and a signature over a different text.
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign("x"))).await;
        assert_eq!((st, j["error"].as_str()), (401, Some("signature_invalid")));
        // ... and one that does not decode.
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, "!!")).await;
        assert_eq!((st, j["error"].as_str()), (401, Some("signature_invalid")));

        // Nonce mismatch: 400.
        let m = message(&e, &h.guest.did, REDIRECT, "someoneElsesNonce", 0);
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (400, Some("nonce_mismatch")));

        // Resource mismatch: a message that binds another URI. 400.
        let m = message(
            &e,
            &h.guest.did,
            "https://meet.example.org/other",
            &h.nonce,
            0,
        );
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (400, Some("resource_mismatch")));

        // Redirect outside the list, or not the bound one: 400, even with a good message.
        let evil = "https://evil.example.net/cb";
        let m = message(&e, &h.guest.did, evil, &h.nonce, 0);
        let (st, j) = post(&e, &h, None, body(evil, &m, &h.guest.sign(&m))).await;
        assert_eq!(
            (st, j["error"].as_str()),
            (400, Some("redirect_not_allowed"))
        );

        // Times: an expired message and one issued in the future. 400.
        for offset in [-3600, 3600] {
            let m = message(&e, &h.guest.did, REDIRECT, &h.nonce, offset);
            let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
            assert_eq!(
                (st, j["error"].as_str()),
                (400, Some("bad_request")),
                "{offset}"
            );
        }
        // Not JSON in the shape: 400.
        let (st, _) = post(&e, &h, None, json!({"x": 1})).await;
        assert_eq!(st, 400);
        assert_eq!(
            verified_did_of(&e, &h).await,
            None,
            "no refusal wrote verified_did"
        );

        // Missing guest cookie (the login session alone): 401 no_session.
        let m = message(&e, &h.guest.did, REDIRECT, &h.nonce, 0);
        let only_session = h.session_cookie.clone();
        let (st, j) = post(
            &e,
            &h,
            Some(&only_session),
            body(REDIRECT, &m, &h.guest.sign(&m)),
        )
        .await;
        assert_eq!((st, j["error"].as_str()), (401, Some("no_session")));
        // Missing login session (the guest cookie alone): 401 no_session.
        let only_guest = format!("{}={}", guest_cookie_name(&e.config), h.handle);
        let (st, j) = post(
            &e,
            &h,
            Some(&only_guest),
            body(REDIRECT, &m, &h.guest.sign(&m)),
        )
        .await;
        assert_eq!((st, j["error"].as_str()), (401, Some("no_session")));

        // A record that went to reaping, or past its deadline, after /authorize: refused.
        for (state, left) in [("reaping", 600), ("active", -5), ("claimed", 600)] {
            let h = hand_off(&e, "active").await;
            e.redis
                .put_guest_for_test(&h.localpart, &h.guest.did, state, left, &h.handle)
                .await;
            let m = message(&e, &h.guest.did, REDIRECT, &h.nonce, 0);
            let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
            assert_eq!(
                (st, j["error"].as_str()),
                (401, Some("no_session")),
                "{state}/{left}"
            );
            assert_eq!(verified_did_of(&e, &h).await, None);
        }

        // Another guest's cookie on this guest's login session: refused.
        let a = hand_off(&e, "active").await;
        let b = hand_off(&e, "active").await;
        let mixed = format!(
            "{}; {}={}",
            a.session_cookie,
            guest_cookie_name(&e.config),
            b.handle
        );
        let m = message(&e, &b.guest.did, REDIRECT, &a.nonce, 0);
        let (st, j) = post(&e, &a, Some(&mixed), body(REDIRECT, &m, &b.guest.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (401, Some("no_session")));
    }

    #[tokio::test]
    async fn the_continue_page_states_and_the_assets() {
        let Some(e) = env(|_| {}).await else { return };
        let h = hand_off(&e, "minted").await;
        let get = |cookie: Option<String>| {
            let url = format!("{}/guest/continue", e.base);
            async move {
                let mut r = reqwest::Client::new()
                    .get(url)
                    .header("sec-fetch-site", "same-origin");
                if let Some(c) = cookie {
                    r = r.header("cookie", c);
                }
                let r = r.send().await.unwrap();
                (
                    r.status().as_u16(),
                    r.headers().clone(),
                    r.text().await.unwrap(),
                )
            }
        };
        let both = format!(
            "{}; {}={}",
            h.session_cookie,
            guest_cookie_name(&e.config),
            h.handle
        );
        let (st, headers, page) = get(Some(both)).await;
        assert_eq!(st, 200);
        assert!(page.contains("data-state=\"ready\""));
        assert!(page.contains(&format!("data-did=\"{}\"", h.guest.did)));
        assert!(page.contains(&format!("data-redirect=\"{REDIRECT}\"")));
        assert!(page.contains(&format!("data-nonce=\"{}\"", h.nonce)));
        assert!(!page.contains("{{"), "every placeholder is filled");
        assert!(headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"));
        // No guest cookie: the page says to open the link again. No cookies at all: no session.
        let (st, _, page) = get(Some(h.session_cookie.clone())).await;
        assert_eq!(st, 200);
        assert!(
            page.contains("data-state=\"no_guest\"") && !page.contains(&h.guest.did),
            "{page}"
        );
        let (st, _, page) = get(None).await;
        assert_eq!(st, 200);
        assert!(page.contains("data-state=\"no_session\""));
        // Both new scripts are on the allow-list.
        for f in ["continue.js", "continue-message.js"] {
            let r = reqwest::get(format!("{}/guest/assets/{f}", e.base))
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "{f}");
        }
    }

    /// ST-37 (guest half): a valid signature from a guest key is refused on all four
    /// signature sites, for a record in every state, while an MVP did:key with no record
    /// is not. The sites are exercised through the one helper they all call.
    #[tokio::test]
    async fn st37_a_valid_guest_signature_is_refused_on_every_site() {
        let Some(e) = env(|_| {}).await else { return };
        for state in ["minted", "provisioning", "active", "reaping", "claimed"] {
            let g = Guest::new();
            record(&e, &g, state, 600).await;
            let r = crate::oidc::refuse_guest_did(&e.redis, &g.did).await;
            assert!(
                matches!(
                    r,
                    Err(CustomError::Coded {
                        status: 403,
                        code: "guest_identity"
                    })
                ),
                "{state}"
            );
        }
        let mvp = Guest::new();
        assert!(crate::oidc::refuse_guest_did(&e.redis, &mvp.did)
            .await
            .is_ok());
    }

    /// ST-37, the wiring: each of the four signature sites calls the helper after its
    /// signature check. A source-level guard (a full signature ceremony per site needs a
    /// device or account fixture of its own); removing a call fails here.
    #[test]
    fn st37_each_of_the_four_sites_calls_the_guest_refusal() {
        for (site, src, needle) in [
            (
                "sign_in Path B",
                include_str!("../oidc.rs"),
                "refuse_guest_did(db_client, &siwx_cookie.did)",
            ),
            (
                "account re-auth",
                include_str!("../account.rs"),
                "refuse_guest_did(db_client, &req.did)",
            ),
            (
                "device approval",
                include_str!("../device_auth.rs"),
                "refuse_guest_did(db_client, did)",
            ),
            (
                "link_start",
                include_str!("../axum_lib.rs"),
                "refuse_guest_did(&state.redis_client, &primary_did)",
            ),
        ] {
            assert!(src.contains(needle), "{site} must refuse a guest DID");
        }
    }

    /// The 503 seam: a verified guest session reaches code issuance and gets
    /// `503 {"error":"unavailable"}`; a guest session that skipped /guest/continue is
    /// refused before that.
    #[tokio::test]
    async fn the_sign_in_guest_seam_is_a_503_for_a_verified_guest() {
        let Some(e) = env(|_| {}).await else { return };
        let h = hand_off(&e, "active").await;
        let sid = h.session_cookie.split_once('=').unwrap().1.to_string();
        let mut s = e.redis.get_session(sid).await.unwrap().unwrap();
        assert!(matches!(
            guest_sign_in_seam(&s),
            Err(CustomError::Unauthorized(_))
        ));
        s.verified_did = Some(h.guest.did.clone());
        let r = guest_sign_in_seam(&s);
        assert!(matches!(
            r,
            Err(CustomError::Coded {
                status: 503,
                code: "unavailable"
            })
        ));
        let resp = r.unwrap_err().into_response();
        assert_eq!(resp.status(), 503);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"unavailable"}"#);
    }
}
