//! Test support for the directory client: a raw-socket HTTP server (the style
//! `did_assertion.rs` and the rotation canary already use, so no HTTP-server
//! dependency enters the lock file), a fake siwx-oidc that serves the headless
//! sign-in flow and the key set, a fake homeserver with the directory module
//! and the standard user directory, and a clock the tests move by hand.
//!
//! Every key made here is generated in memory for the test that uses it.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use siwx_oidc_auth::directory::{
    Clock, DirectoryClient, DirectoryConfig, ServiceSession, ServiceSessionConfig, Tuning,
};
use siwx_oidc_auth::SiwxKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const SERVER_NAME: &str = "example.org";
pub const CLIENT_ID: &str = "fixture-client";
pub const REDIRECT_URI: &str = "https://service.example.org/callback";
pub const DEVICE_ID: &str = "directory-service";
pub const KID: &str = "fixture-kid-1";
pub const ASKER_DID: &str = "did:key:zFixtureAsker00000000000000000000000000000000";
pub const ASKER_MXID: &str = "@asker-fixture:example.org";

pub fn mxid(name: &str) -> String {
    format!("@{name}:{SERVER_NAME}")
}

pub fn did_of(name: &str) -> String {
    format!("did:key:zFixture{name}0000000000000000000000000000")
}

// ---------------------------------------------------------------------------
// The HTTP server
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    /// Percent-decoded, without the query.
    pub path: String,
    pub query: String,
    /// Lower-cased names.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }
    pub fn form(&self) -> HashMap<String, String> {
        serde_urlencoded::from_bytes(&self.body).expect("a form body")
    }
    pub fn query_pairs(&self) -> HashMap<String, String> {
        serde_urlencoded::from_str(&self.query).unwrap_or_default()
    }
    pub fn bearer(&self) -> Option<String> {
        self.headers
            .get("authorization")?
            .strip_prefix("Bearer ")
            .map(str::to_string)
    }
}

#[derive(Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
    /// Send the body with `Transfer-Encoding: chunked` and no `Content-Length`,
    /// so a client cannot know its size before it has read it.
    pub chunked: bool,
    /// Declare a `Content-Length` this many bytes longer than the body and hang
    /// up after it: the head arrives and then reading the body fails.
    pub short_by: usize,
    /// Send the head, then wait this long before the first byte of the body: an
    /// answer whose status arrives and whose body then stalls.
    pub stall_body: Duration,
}

impl Resp {
    pub fn json(status: u16, body: Value) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
            delay: Duration::ZERO,
            chunked: false,
            short_by: 0,
            stall_body: Duration::ZERO,
        }
    }
    pub fn bytes(status: u16, body: Vec<u8>) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
            delay: Duration::ZERO,
            chunked: false,
            short_by: 0,
            stall_body: Duration::ZERO,
        }
    }
    /// A plain-text answer, as the server's own error pages are.
    pub fn text(status: u16, body: &str) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
            chunked: false,
            short_by: 0,
            stall_body: Duration::ZERO,
        }
    }
    pub fn redirect(location: String, cookie: Option<&str>) -> Resp {
        let mut headers = vec![("Location".to_string(), location)];
        if let Some(c) = cookie {
            headers.push(("Set-Cookie".into(), format!("{c}; Path=/")));
        }
        Resp {
            status: 303,
            headers,
            body: Vec::new(),
            delay: Duration::ZERO,
            chunked: false,
            short_by: 0,
            stall_body: Duration::ZERO,
        }
    }
    /// A 302, the redirect a misdirected key fetch would meet.
    pub fn found(location: String) -> Resp {
        Resp {
            status: 302,
            ..Resp::redirect(location, None)
        }
    }
    /// The body is cut short: the head promises 100 more bytes than arrive.
    pub fn truncated(mut self) -> Resp {
        self.short_by = 100;
        self
    }
    pub fn body_stalled(mut self, d: Duration) -> Resp {
        self.stall_body = d;
        self
    }
    pub fn chunked(mut self) -> Resp {
        self.chunked = true;
        self
    }
    pub fn delayed(mut self, d: Duration) -> Resp {
        self.delay = d;
        self
    }
    pub fn header(mut self, k: &str, v: &str) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub struct Mock {
    pub base: String,
    log: Arc<Mutex<Vec<Req>>>,
    max_in_flight: Arc<AtomicUsize>,
}

impl Mock {
    pub async fn start<F>(handler: F) -> Mock
    where
        F: Fn(&Req) -> Resp + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        {
            let (log, in_flight, max_in_flight) =
                (log.clone(), in_flight.clone(), max_in_flight.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let (handler, log, in_flight, max_in_flight) = (
                        handler.clone(),
                        log.clone(),
                        in_flight.clone(),
                        max_in_flight.clone(),
                    );
                    tokio::spawn(async move {
                        serve(sock, handler, log, in_flight, max_in_flight).await;
                    });
                }
            });
        }
        Mock {
            base,
            log,
            max_in_flight,
        }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    pub fn count(&self, method: &str, path: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method && r.path == path)
            .count()
    }

    pub fn total(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }
}

async fn serve<F>(
    mut sock: TcpStream,
    handler: Arc<F>,
    log: Arc<Mutex<Vec<Req>>>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
) where
    F: Fn(&Req) -> Resp + Send + Sync + 'static,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let want: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let (raw_path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let path = urlencoding::decode(&raw_path)
        .map(|c| c.into_owned())
        .unwrap_or(raw_path);
    let req = Req {
        method,
        path,
        query,
        headers,
        body,
    };
    log.lock().unwrap().push(req.clone());

    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    max_in_flight.fetch_max(now, Ordering::SeqCst);
    let resp = handler(&req);
    if !resp.delay.is_zero() {
        tokio::time::sleep(resp.delay).await;
    }
    in_flight.fetch_sub(1, Ordering::SeqCst);

    let mut out = if resp.chunked {
        format!(
            "HTTP/1.1 {} X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n",
            resp.status
        )
    } else {
        format!(
            "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
            resp.status,
            resp.body.len() + resp.short_by
        )
    };
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = sock.write_all(out.as_bytes()).await;
    if !resp.stall_body.is_zero() {
        let _ = sock.flush().await;
        tokio::time::sleep(resp.stall_body).await;
    }
    if resp.chunked {
        // 16 KiB chunks. A client that has read enough and hangs up makes a
        // write fail, which ends the answer: that is the point of the cap.
        for chunk in resp.body.chunks(16 * 1024) {
            let framed = [format!("{:x}\r\n", chunk.len()).as_bytes(), chunk, b"\r\n"].concat();
            if sock.write_all(&framed).await.is_err() {
                return;
            }
        }
        let _ = sock.write_all(b"0\r\n\r\n").await;
    } else {
        let _ = sock.write_all(&resp.body).await;
    }
    let _ = sock.shutdown().await;
}

// ---------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TestClock {
    base: Instant,
    offset_ms: Arc<AtomicU64>,
}

impl TestClock {
    pub fn new() -> TestClock {
        TestClock {
            base: Instant::now(),
            offset_ms: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn advance(&self, by: Duration) {
        self.offset_ms
            .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
    pub fn clock(&self) -> Clock {
        let (base, offset) = (self.base, self.offset_ms.clone());
        Clock::new(move || base + Duration::from_millis(offset.load(Ordering::SeqCst)))
    }
}

// ---------------------------------------------------------------------------
// Proofs and keys (generated in memory, never stored)
// ---------------------------------------------------------------------------

pub fn jwk_of(key: &SigningKey, kid: &str) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC", "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        "use": "sig", "alg": "ES256", "kid": kid,
    })
}

pub fn mint(key: &SigningKey, kid: &str, payload: &Value) -> String {
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": kid});
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let input = format!("{h}.{p}");
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

// ---------------------------------------------------------------------------
// The fake siwx-oidc
// ---------------------------------------------------------------------------

/// What a refused registration says in free text, which no error may repeat.
pub const REGISTER_DESCRIPTION: &str = "REGISTER-DESCRIPTION-written-by-the-server";

pub struct IssuerState {
    pub proof_key: SigningKey,
    /// What `/jwk` serves.
    pub jwks: Value,
    pub discovery_status: u16,
    pub jwks_status: u16,
    pub jwks_delay: Duration,
    /// Answer `/jwk` with a 302 to this URL instead of the key set.
    pub jwks_redirect: Option<String>,
    /// How long `/sign_in` takes to answer.
    pub sign_in_delay: Duration,
    /// How long `/authorize` takes to answer.
    pub authorize_delay: Duration,
    /// How long the code exchange at `/token` takes to answer.
    pub token_delay: Duration,
    /// Answer `/authorize` with this status and the server's own plain-text
    /// body for an unregistered client, instead of the redirect.
    pub authorize_status: Option<u16>,
    /// A `WWW-Authenticate` challenge to put on that answer, as a proxy's auth
    /// wall would (the server's own answer has none).
    pub authorize_challenge: Option<String>,
    /// A `Retry-After` header to put on that answer, as a rate limiter's 429
    /// would have it.
    pub authorize_retry_after: Option<String>,
    /// What the discovery document names as its issuer; `None` is its own URL.
    pub discovery_issuer: Option<String>,
    /// DID to the MXID `/resolve` finds; a DID that is absent does not exist.
    pub resolve: HashMap<String, String>,
    pub resolve_status: u16,
    /// A `Retry-After` header to put on a refused `/resolve`, as a rate
    /// limiter's 429 would have it.
    pub resolve_retry_after: Option<String>,
    /// A body, spelled any way (not JSON, JSON of the wrong shape), to answer a
    /// `200` `/resolve` with instead of the lookup.
    pub resolve_body: Option<String>,
    pub seq: u32,
    pub current_refresh: Option<String>,
    pub expires_in: Option<u64>,
    /// `expires_in` as JSON text, spelled any way (`1e20`, `"soon"`), instead of
    /// `expires_in`.
    pub expires_in_raw: Option<String>,
    pub issue_refresh: bool,
    pub refresh_status: u16,
    pub refresh_delay: Duration,
    /// A `Retry-After` header to put on a refused refresh, as a rate limiter's
    /// 429 would have it.
    pub refresh_retry_after: Option<String>,
    /// `error` code to put on the `/sign_in` redirect instead of a code.
    pub sign_in_error: Option<String>,
    pub register_status: u16,
    /// A `Retry-After` header to put on a refused registration, as a rate
    /// limiter's 429 would have it.
    pub register_retry_after: Option<String>,
}

pub struct Issuer {
    pub mock: Mock,
    pub st: Arc<Mutex<IssuerState>>,
}

impl Issuer {
    pub async fn start() -> Issuer {
        let proof_key = SigningKey::random(&mut rand::rngs::OsRng);
        let jwks = json!({ "keys": [jwk_of(&proof_key, KID)] });
        let mut resolve = HashMap::new();
        resolve.insert(ASKER_DID.to_string(), ASKER_MXID.to_string());
        let st = Arc::new(Mutex::new(IssuerState {
            proof_key,
            jwks,
            discovery_status: 200,
            jwks_status: 200,
            jwks_delay: Duration::ZERO,
            jwks_redirect: None,
            sign_in_delay: Duration::ZERO,
            authorize_delay: Duration::ZERO,
            token_delay: Duration::ZERO,
            authorize_status: None,
            authorize_challenge: None,
            authorize_retry_after: None,
            discovery_issuer: None,
            resolve,
            resolve_status: 200,
            resolve_retry_after: None,
            resolve_body: None,
            seq: 0,
            current_refresh: None,
            expires_in: Some(300),
            expires_in_raw: None,
            issue_refresh: true,
            refresh_status: 200,
            refresh_delay: Duration::ZERO,
            refresh_retry_after: None,
            sign_in_error: None,
            register_status: 201,
            register_retry_after: None,
        }));
        let shared = st.clone();
        let mock = Mock::start(move |r| issuer_route(&shared, r)).await;
        Issuer { mock, st }
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut IssuerState) -> T) -> T {
        f(&mut self.st.lock().unwrap())
    }

    /// The count of token requests of one grant type.
    pub fn grants(&self, grant_type: &str) -> usize {
        self.mock
            .requests()
            .iter()
            .filter(|r| r.method == "POST" && r.path == "/token")
            .filter(|r| r.form().get("grant_type").map(String::as_str) == Some(grant_type))
            .count()
    }

    pub fn sign_ins(&self) -> usize {
        self.grants("authorization_code")
    }

    pub fn refreshes(&self) -> usize {
        self.grants("refresh_token")
    }

    /// A compact proof signed by the issuer's key for `sub` and `mxid`.
    pub fn proof(&self, sub: &str, mxid: &str) -> String {
        self.proof_with(KID, sub, mxid, &self.mock.base)
    }

    pub fn proof_with(&self, kid: &str, sub: &str, mxid: &str, iss: &str) -> String {
        let key = self.with(|s| s.proof_key.clone());
        mint(
            &key,
            kid,
            &json!({"iss": iss, "sub": sub, "mxid": mxid, "iat": 1_757_000_000}),
        )
    }

    /// The `io.inblock.did` object a published account carries.
    pub fn field(&self, sub: &str, mxid: &str) -> Value {
        json!({ "did": sub, "proof": self.proof(sub, mxid) })
    }
}

fn issuer_route(st: &Arc<Mutex<IssuerState>>, r: &Req) -> Resp {
    let host = r.headers.get("host").cloned().unwrap_or_default();
    let base = format!("http://{host}");
    let mut s = st.lock().unwrap();
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/.well-known/openid-configuration") => {
            if s.discovery_status != 200 {
                return Resp::json(s.discovery_status, json!({"error": "fixture"}));
            }
            let issuer = s.discovery_issuer.clone().unwrap_or_else(|| base.clone());
            Resp::json(
                200,
                json!({"issuer": issuer, "jwks_uri": format!("{base}/jwk")}),
            )
        }
        ("GET", "/jwk") => {
            if let Some(to) = &s.jwks_redirect {
                return Resp::found(to.clone());
            }
            if s.jwks_status != 200 {
                return Resp::json(s.jwks_status, json!({"error": "fixture"}));
            }
            Resp::json(200, s.jwks.clone()).delayed(s.jwks_delay)
        }
        ("GET", "/resolve") => {
            if s.resolve_status != 200 {
                let mut resp = Resp::json(s.resolve_status, json!({"error": "fixture"}));
                if let Some(wait) = &s.resolve_retry_after {
                    resp = resp.header("Retry-After", wait);
                }
                return resp;
            }
            if let Some(body) = &s.resolve_body {
                return Resp::bytes(200, body.clone().into_bytes());
            }
            let did = r.query_pairs().get("did").cloned().unwrap_or_default();
            match s.resolve.get(&did) {
                Some(mxid) => Resp::json(
                    200,
                    json!({"did": did, "mxid": mxid, "exists": true, "attested": true}),
                ),
                None => Resp::json(
                    200,
                    json!({"did": did, "mxid": null, "exists": false, "attested": false}),
                ),
            }
        }
        ("POST", "/register") => {
            if s.register_status != 201 {
                // The code is a short token and may be repeated; the description
                // is the server's free text and must not be.
                let mut resp = Resp::json(
                    s.register_status,
                    json!({
                        "error": "invalid_client_metadata",
                        "error_description": REGISTER_DESCRIPTION,
                    }),
                );
                if let Some(wait) = &s.register_retry_after {
                    resp = resp.header("Retry-After", wait);
                }
                return resp;
            }
            Resp::json(
                201,
                json!({
                    "client_id": "registered-fixture-client",
                    "client_secret": "fixture-client-secret-must-not-leak",
                    "registration_access_token": "fixture-registration-token-must-not-leak",
                }),
            )
        }
        ("GET", "/authorize") => {
            if let Some(status) = s.authorize_status {
                let mut resp = Resp::text(status, "Unrecognised client id.");
                if let Some(wait) = &s.authorize_retry_after {
                    resp = resp.header("Retry-After", wait);
                }
                return match &s.authorize_challenge {
                    Some(challenge) => resp.header("WWW-Authenticate", challenge),
                    None => resp,
                };
            }
            let q = r.query_pairs();
            Resp::redirect(
                format!(
                    "/sign_in?nonce=fixture-nonce&state=headless&redirect_uri={}&client_id={}",
                    urlencoding::encode(q.get("redirect_uri").map(String::as_str).unwrap_or("")),
                    urlencoding::encode(q.get("client_id").map(String::as_str).unwrap_or("")),
                ),
                Some("session=fixture-session"),
            )
            .delayed(s.authorize_delay)
        }
        ("GET", "/sign_in") => {
            let cookie = r.headers.get("cookie").cloned().unwrap_or_default();
            if !(cookie.contains("session=fixture-session") && cookie.contains("siwx=")) {
                return Resp::json(400, json!({"error": "no signed-in cookie"}));
            }
            let uri = r
                .query_pairs()
                .get("redirect_uri")
                .cloned()
                .unwrap_or_default();
            let delay = s.sign_in_delay;
            if let Some(error) = &s.sign_in_error {
                return Resp::redirect(
                    format!("{uri}?error={error}&error_description=fixture&state=headless"),
                    None,
                )
                .delayed(delay);
            }
            Resp::redirect(format!("{uri}?code=fixture-code&state=headless"), None).delayed(delay)
        }
        ("POST", "/token") => {
            let form = r.form();
            match form.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let delay = s.token_delay;
                    token_answer(&mut s).delayed(delay)
                }
                Some("refresh_token") => {
                    let delay = s.refresh_delay;
                    if s.refresh_status != 200
                        || s.current_refresh.as_deref()
                            != form.get("refresh_token").map(String::as_str)
                    {
                        let status = if s.refresh_status != 200 {
                            s.refresh_status
                        } else {
                            400
                        };
                        let mut refused =
                            Resp::json(status, json!({"error": "invalid_grant"})).delayed(delay);
                        if let Some(wait) = &s.refresh_retry_after {
                            refused = refused.header("Retry-After", wait);
                        }
                        return refused;
                    }
                    token_answer(&mut s).delayed(delay)
                }
                _ => Resp::json(400, json!({"error": "unsupported_grant_type"})),
            }
        }
        _ => Resp::json(404, json!({"error": "not found"})),
    }
}

/// The 200 answer of `/token`: the pair, with `expires_in` as the state says.
fn token_answer(s: &mut IssuerState) -> Resp {
    let raw = s.expires_in_raw.clone();
    let mut body = issue(s);
    match raw {
        None => Resp::json(200, body),
        Some(raw) => {
            body.as_object_mut().unwrap().remove("expires_in");
            let mut text = body.to_string();
            text.pop(); // the closing brace
            text.push_str(&format!(",\"expires_in\":{raw}}}"));
            Resp::bytes(200, text.into_bytes())
        }
    }
}

fn issue(s: &mut IssuerState) -> Value {
    s.seq += 1;
    let mut body = json!({
        "access_token": format!("access-{}", s.seq),
        "token_type": "Bearer",
    });
    if let Some(n) = s.expires_in {
        body["expires_in"] = json!(n);
    }
    if s.issue_refresh {
        let refresh = format!("refresh-{}", s.seq);
        body["refresh_token"] = json!(refresh);
        s.current_refresh = Some(refresh);
    } else {
        s.current_refresh = None;
    }
    body
}

// ---------------------------------------------------------------------------
// The fake homeserver
// ---------------------------------------------------------------------------

type Handler = Arc<dyn Fn(&Req, usize) -> Resp + Send + Sync>;

pub struct HsState {
    module: Handler,
    module_calls: usize,
    user_directory: Handler,
    user_directory_calls: usize,
    whoami_calls: usize,
    /// mxid to the profile answer; an mxid that is absent answers 404.
    profiles: HashMap<String, Resp>,
    profile_delay: Duration,
    /// mxid to answers given in turn, one per read; the last repeats. Wins over `profiles`.
    profile_scripts: HashMap<String, (usize, Vec<Resp>)>,
    /// `GET /account/whoami`, which the user transport asks once to learn the
    /// homeserver's own name.
    whoami: Handler,
}

pub struct Homeserver {
    pub mock: Mock,
    pub st: Arc<Mutex<HsState>>,
}

pub const MODULE_PATH: &str = "/_synapse/client/io.inblock/directory/v1/search";
pub const USER_DIRECTORY_PATH: &str = "/_matrix/client/v3/user_directory/search";
pub const WHOAMI_PATH: &str = "/_matrix/client/v3/account/whoami";

pub fn hit(user_id: &str, display_name: Option<&str>, did_field: Option<Value>) -> Value {
    let mut v = json!({ "user_id": user_id });
    if let Some(n) = display_name {
        v["display_name"] = json!(n);
    }
    if let Some(f) = did_field {
        v["did_field"] = f;
    }
    v
}

impl Homeserver {
    pub async fn start() -> Homeserver {
        let empty: Handler =
            Arc::new(|_, _| Resp::json(200, json!({"results": [], "limited": false})));
        let st = Arc::new(Mutex::new(HsState {
            module: empty.clone(),
            module_calls: 0,
            user_directory: empty,
            user_directory_calls: 0,
            whoami_calls: 0,
            profiles: HashMap::new(),
            profile_delay: Duration::ZERO,
            profile_scripts: HashMap::new(),
            whoami: Arc::new(|_, _| {
                Resp::json(
                    200,
                    json!({"user_id": mxid("whoami-fixture"), "device_id": "D"}),
                )
            }),
        }));
        let shared = st.clone();
        let mock = Mock::start(move |r| hs_route(&shared, r)).await;
        Homeserver { mock, st }
    }

    /// Answer every module call with these hits.
    pub fn module_hits(&self, hits: Vec<Value>) {
        self.on_module(move |_, _| {
            Resp::json(200, json!({"results": hits.clone(), "limited": false}))
        });
    }

    /// `f(request, zero-based call number)`.
    pub fn on_module(&self, f: impl Fn(&Req, usize) -> Resp + Send + Sync + 'static) {
        self.st.lock().unwrap().module = Arc::new(f);
    }

    /// `f(request, zero-based call number)`.
    pub fn on_whoami(&self, f: impl Fn(&Req, usize) -> Resp + Send + Sync + 'static) {
        self.st.lock().unwrap().whoami = Arc::new(f);
    }

    pub fn whoami_calls(&self) -> usize {
        self.mock.count("GET", WHOAMI_PATH)
    }

    pub fn user_directory_calls(&self) -> usize {
        self.mock.count("POST", USER_DIRECTORY_PATH)
    }

    pub fn on_user_directory(&self, f: impl Fn(&Req, usize) -> Resp + Send + Sync + 'static) {
        self.st.lock().unwrap().user_directory = Arc::new(f);
    }

    /// Standard user-directory rows (`user_id`, `display_name`).
    pub fn directory_rows(&self, rows: Vec<Value>) {
        self.on_user_directory(move |_, _| {
            Resp::json(200, json!({"results": rows.clone(), "limited": false}))
        });
    }

    pub fn profile(&self, mxid: &str, field: Option<Value>) {
        let resp = match field {
            Some(v) => Resp::json(200, json!({ "io.inblock.did": v })),
            None => Resp::json(404, json!({"errcode": "M_NOT_FOUND"})),
        };
        self.st
            .lock()
            .unwrap()
            .profiles
            .insert(mxid.to_string(), resp);
    }

    pub fn profile_status(&self, mxid: &str, status: u16) {
        self.st.lock().unwrap().profiles.insert(
            mxid.to_string(),
            Resp::json(status, json!({"errcode": "M_UNKNOWN"})),
        );
    }

    /// Any answer at all for one profile.
    pub fn profile_answer(&self, mxid: &str, resp: Resp) {
        self.st
            .lock()
            .unwrap()
            .profiles
            .insert(mxid.to_string(), resp);
    }

    /// The answers to the reads of one profile, in the order the reads arrive.
    pub fn profile_script(&self, mxid: &str, answers: Vec<Resp>) {
        self.st
            .lock()
            .unwrap()
            .profile_scripts
            .insert(mxid.to_string(), (0, answers));
    }

    pub fn profile_delay(&self, d: Duration) {
        self.st.lock().unwrap().profile_delay = d;
    }

    pub fn module_calls(&self) -> usize {
        self.mock.count("POST", MODULE_PATH)
    }

    pub fn profile_reads(&self) -> usize {
        self.mock
            .requests()
            .iter()
            .filter(|r| r.path.starts_with("/_matrix/client/v3/profile/"))
            .count()
    }
}

fn hs_route(st: &Arc<Mutex<HsState>>, r: &Req) -> Resp {
    let (handler, n) = {
        let mut s = st.lock().unwrap();
        if r.method == "GET" && r.path == WHOAMI_PATH {
            let n = s.whoami_calls;
            s.whoami_calls += 1;
            (Some(s.whoami.clone()), n)
        } else if r.method == "POST" && r.path == MODULE_PATH {
            let n = s.module_calls;
            s.module_calls += 1;
            (Some(s.module.clone()), n)
        } else if r.method == "POST" && r.path == USER_DIRECTORY_PATH {
            let n = s.user_directory_calls;
            s.user_directory_calls += 1;
            (Some(s.user_directory.clone()), n)
        } else {
            (None, 0)
        }
    };
    if let Some(h) = handler {
        return h(r, n);
    }
    const PREFIX: &str = "/_matrix/client/v3/profile/";
    if r.method == "GET" {
        if let Some(rest) = r.path.strip_prefix(PREFIX) {
            let mut s = st.lock().unwrap();
            let delay = s.profile_delay;
            let mxid = rest.strip_suffix("/io.inblock.did").unwrap_or(rest);
            let scripted = s.profile_scripts.get_mut(mxid).map(|(next, answers)| {
                let answer = answers[(*next).min(answers.len() - 1)].clone();
                *next += 1;
                answer
            });
            let found = scripted.as_ref().or_else(|| s.profiles.get(mxid));
            return match found {
                Some(p) => Resp {
                    status: p.status,
                    headers: p.headers.clone(),
                    body: p.body.clone(),
                    // The answer's own delay (one slow server), or the
                    // homeserver-wide one, whichever is longer.
                    delay: p.delay.max(delay),
                    chunked: p.chunked,
                    short_by: p.short_by,
                    stall_body: p.stall_body,
                },
                None => Resp::json(404, json!({"errcode": "M_NOT_FOUND"})).delayed(delay),
            };
        }
    }
    Resp::json(404, json!({"errcode": "M_UNRECOGNIZED"}))
}

// ---------------------------------------------------------------------------
// A whole deployment
// ---------------------------------------------------------------------------

pub struct World {
    pub issuer: Issuer,
    pub hs: Homeserver,
    pub clock: TestClock,
    service_key_pem: String,
}

impl World {
    pub async fn new() -> World {
        let key = SiwxKey::generate_ed25519();
        World {
            issuer: Issuer::start().await,
            hs: Homeserver::start().await,
            clock: TestClock::new(),
            service_key_pem: key.to_pem().unwrap(),
        }
    }

    pub fn service_key(&self) -> SiwxKey {
        SiwxKey::from_pem(&self.service_key_pem).unwrap()
    }

    pub fn config(&self) -> DirectoryConfig {
        DirectoryConfig::new(&self.issuer.mock.base, &self.hs.mock.base, SERVER_NAME)
            .with_clock(self.clock.clock())
    }

    pub fn directory(&self) -> DirectoryClient {
        DirectoryClient::new(self.config()).unwrap()
    }

    pub fn directory_with(&self, tuning: Tuning) -> DirectoryClient {
        DirectoryClient::new(self.config().with_tuning(tuning)).unwrap()
    }

    pub fn session_config(&self) -> ServiceSessionConfig {
        ServiceSessionConfig::new(
            &self.issuer.mock.base,
            &self.hs.mock.base,
            CLIENT_ID,
            REDIRECT_URI,
            DEVICE_ID,
            self.service_key(),
        )
        .with_clock(self.clock.clock())
    }

    pub fn session(&self) -> ServiceSession {
        ServiceSession::new(self.session_config()).unwrap()
    }

    pub fn session_with(&self, tuning: Tuning) -> ServiceSession {
        ServiceSession::new(self.session_config().with_tuning(tuning)).unwrap()
    }

    pub fn requests_total(&self) -> usize {
        self.issuer.mock.total() + self.hs.mock.total()
    }
}
