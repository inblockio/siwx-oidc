//! Hermetic runs of `check` and `init` against an in-process fake of a
//! siwx-oidc server and its homeserver (one listener, shared state). They
//! cover what a deployment cannot be made to do on demand: a logout that
//! revokes nothing, a server whose clock is an hour off, an ID token signed by
//! another key, a hostile server that echoes a credential into a field the
//! canary prints.
//!
//! The runs call `checks::run` and `init::run` themselves and read the lines
//! through `hygiene::start_capture`, so what is asserted on is what would have
//! been printed.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use siwx_oidc_auth::SiwxKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::checks;
use crate::cli::{CheckConfig, InitConfig, Matrix};
use crate::flow::REDIRECT_URI;
use crate::hygiene::{self, Secret};
use crate::identity::{self, ClientRecord, LogoutRoute};
use crate::init;
use crate::jose::kid_from_xy;

const SERVER_NAME: &str = "matrix.test";

fn random(prefix: &str, len: usize) -> String {
    let tail: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    format!("{prefix}{tail}")
}

fn kid_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    kid_from_xy(point.x().unwrap(), point.y().unwrap())
}

fn jwk_of(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid_of(key),
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
}

fn jws(key: &SigningKey, header: Value, claims: Value) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// How the fake misbehaves. Everything defaults to a healthy deployment.
#[derive(Clone)]
struct Quirks {
    /// The server's clock is this many seconds ahead of this host's.
    clock_offset: i64,
    /// The ID token is signed by this key instead of the published one.
    id_signed_by: Option<SigningKey>,
    /// The ID token's `iat` is this far from the server's clock.
    id_iat_shift: i64,
    /// The ID token header names the access token as its kid.
    id_kid_is_access_token: bool,
    /// whoami names the refresh token as the device.
    device_is_refresh_token: bool,
    /// The DID proof's `iat` is this far from the server's clock.
    proof_iat_shift: i64,
    /// The logout answers `logout_status` and revokes nothing.
    logout_is_noop: bool,
    logout_status: u16,
    /// `/token` answers this status once the session was logged out.
    token_status_after_logout: Option<u16>,
    rooms: usize,
    extra_devices: Vec<String>,
}

impl Default for Quirks {
    fn default() -> Self {
        Quirks {
            clock_offset: 0,
            id_signed_by: None,
            id_iat_shift: 0,
            id_kid_is_access_token: false,
            device_is_refresh_token: false,
            proof_iat_shift: 0,
            logout_is_noop: false,
            logout_status: 200,
            token_status_after_logout: None,
            rooms: 0,
            extra_devices: Vec::new(),
        }
    }
}

struct State {
    base: String,
    signing: SigningKey,
    extra_jwks: Vec<Value>,
    client_id: String,
    did: String,
    mxid: String,
    quirks: Quirks,
    logged_out: bool,
    access: String,
    refresh: String,
    device: String,
    /// Every credential the fake handed out, for the leak assertions.
    minted: Vec<String>,
    devices: Vec<String>,
    display_name: Option<String>,
}

#[derive(Clone)]
struct Fake {
    state: Arc<Mutex<State>>,
    base: String,
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn reply(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: body.to_string(),
    }
}

fn redirect(location: String, cookie: Option<&str>) -> Response {
    let mut headers = vec![("Location".to_string(), location)];
    if let Some(cookie) = cookie {
        headers.push(("Set-Cookie".to_string(), format!("{cookie}; Path=/")));
    }
    Response {
        status: 303,
        headers,
        body: String::new(),
    }
}

impl Fake {
    async fn start() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let state = Arc::new(Mutex::new(State {
            base: base.clone(),
            signing,
            extra_jwks: Vec::new(),
            client_id: random("client-", 12),
            did: String::new(),
            mxid: format!("@{}:{SERVER_NAME}", random("", 16).to_lowercase()),
            quirks: Quirks::default(),
            logged_out: true,
            access: String::new(),
            refresh: String::new(),
            device: String::new(),
            minted: Vec::new(),
            devices: Vec::new(),
            display_name: None,
        }));
        let fake = Fake { state, base };
        let serving = fake.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let fake = serving.clone();
                tokio::spawn(async move { fake.serve(stream).await });
            }
        });
        fake
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    fn live_kid(&self) -> String {
        self.with(|s| kid_of(&s.signing))
    }

    fn quirks(&self, f: impl FnOnce(&mut Quirks)) {
        self.with(|s| f(&mut s.quirks));
    }

    async fn serve(&self, mut stream: TcpStream) {
        let Some(request) = read_request(&mut stream).await else {
            return;
        };
        let response = self.route(&request);
        let now = Utc::now().timestamp() + self.with(|s| s.quirks.clock_offset);
        let date = DateTime::from_timestamp(now, 0)
            .unwrap()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let mut out = format!(
            "HTTP/1.1 {} X\r\nDate: {date}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            response.body.len()
        );
        for (k, v) in &response.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&response.body);
        let _ = stream.write_all(out.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    fn bearer(request: &Request) -> Option<String> {
        request
            .headers
            .get("authorization")?
            .strip_prefix("Bearer ")
            .map(str::to_string)
    }

    fn authorised(&self, request: &Request) -> bool {
        let bearer = Self::bearer(request);
        self.with(|s| !s.logged_out && bearer.as_deref() == Some(s.access.as_str()))
    }

    fn mint_session(&self, s: &mut State) -> Value {
        s.access = random("mat_", 32);
        s.refresh = format!("{}{}", random("mcr_", 22), random("_", 32));
        s.logged_out = false;
        let now = Utc::now().timestamp() + s.quirks.clock_offset;
        let live_kid = kid_of(&s.signing);
        let header_kid = if s.quirks.id_kid_is_access_token {
            s.access.clone()
        } else {
            live_kid
        };
        let iat = now + s.quirks.id_iat_shift;
        let signer = s
            .quirks
            .id_signed_by
            .clone()
            .unwrap_or_else(|| s.signing.clone());
        let id_token = jws(
            &signer,
            json!({"alg": "ES256", "kid": header_kid}),
            json!({"iss": format!("{}/", s.base), "aud": [s.client_id], "sub": s.did, "iat": iat, "exp": iat + 300}),
        );
        s.minted
            .extend([s.access.clone(), s.refresh.clone(), id_token.clone()]);
        json!({
            "access_token": s.access, "token_type": "Bearer", "id_token": id_token,
            "expires_in": 300, "refresh_token": s.refresh,
        })
    }

    fn route(&self, r: &Request) -> Response {
        let base = self.base.clone();
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => reply(
                200,
                json!({"issuer": format!("{base}/"), "jwks_uri": format!("{base}/jwk")}),
            ),
            ("GET", "/jwk") => self.with(|s| {
                let mut keys = vec![jwk_of(&s.signing)];
                keys.extend(s.extra_jwks.clone());
                reply(200, json!({ "keys": keys }))
            }),
            ("POST", "/register") => self.with(|s| {
                let registration_token = random("rat_", 40);
                s.minted.push(registration_token.clone());
                s.client_id = random("client-", 12);
                reply(
                    201,
                    json!({"client_id": s.client_id, "registration_access_token": registration_token}),
                )
            }),
            ("GET", "/authorize") => self.with(|s| {
                if r.query.get("client_id") != Some(&s.client_id) {
                    return reply(401, json!({"error": "Unrecognised client id."}));
                }
                redirect(
                    format!(
                        "/sign_in?nonce={}&state=headless&redirect_uri={}&client_id={}",
                        random("", 16),
                        urlencoding::encode(REDIRECT_URI),
                        s.client_id
                    ),
                    Some("session=fake-session"),
                )
            }),
            ("GET", "/sign_in") => {
                let cookie = r.headers.get("cookie").cloned().unwrap_or_default();
                if cookie.contains("session=fake-session") && cookie.contains("siwx=") {
                    redirect(format!("{REDIRECT_URI}?code=fake-code&state=headless"), None)
                } else {
                    reply(400, json!({"error": "no session"}))
                }
            }
            ("POST", "/token") => self.token(r),
            ("POST", "/oauth2/revoke") => self.with(|s| {
                let form = form_of(&r.body);
                if form.get("token") == Some(&s.refresh) {
                    s.logged_out = true;
                }
                reply(200, json!({}))
            }),
            ("POST", "/_matrix/client/v3/logout") => {
                if Self::bearer(r).is_none() {
                    return reply(200, json!({}));
                }
                let authorised = self.authorised(r);
                self.with(|s| {
                    if authorised && !s.quirks.logout_is_noop {
                        s.logged_out = true;
                        let own = s.device.clone();
                        s.devices.retain(|d| *d != own);
                    }
                    reply(s.quirks.logout_status, json!({}))
                })
            }
            ("GET", "/_matrix/client/v3/account/whoami") => {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                self.with(|s| {
                    let device = if s.quirks.device_is_refresh_token {
                        s.refresh.clone()
                    } else {
                        s.device.clone()
                    };
                    reply(200, json!({"user_id": s.mxid, "device_id": device}))
                })
            }
            ("GET", "/_matrix/client/v3/joined_rooms") => {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                self.with(|s| {
                    reply(
                        200,
                        json!({"joined_rooms": vec!["!room:matrix.test"; s.quirks.rooms]}),
                    )
                })
            }
            ("GET", "/_matrix/client/v3/devices") => {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                self.with(|s| {
                    let mut ids = s.devices.clone();
                    ids.extend(s.quirks.extra_devices.clone());
                    let devices: Vec<Value> = ids.iter().map(|d| json!({"device_id": d})).collect();
                    reply(200, json!({ "devices": devices }))
                })
            }
            ("DELETE", p) if p.starts_with("/_matrix/client/v3/devices/") => {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                let id = urlencoding::decode(p.rsplit('/').next().unwrap())
                    .unwrap()
                    .to_string();
                self.with(|s| {
                    s.devices.retain(|d| *d != id);
                    s.quirks.extra_devices.retain(|d| *d != id);
                });
                reply(200, json!({}))
            }
            ("GET", p)
                if p.starts_with("/_matrix/client/v3/profile/") && p.ends_with("/io.inblock.did") =>
            {
                self.with(|s| {
                    let now = Utc::now().timestamp() + s.quirks.clock_offset;
                    let proof = jws(
                        &s.signing,
                        json!({"alg": "ES256", "typ": "JWT", "kid": kid_of(&s.signing)}),
                        json!({"iss": format!("{}/", s.base), "sub": s.did, "mxid": s.mxid, "iat": now + s.quirks.proof_iat_shift}),
                    );
                    s.minted.push(proof.clone());
                    reply(200, json!({"io.inblock.did": {"did": s.did, "proof": proof}}))
                })
            }
            ("PUT", p)
                if p.starts_with("/_matrix/client/v3/profile/") && p.ends_with("/displayname") =>
            {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                let body: Value = serde_json::from_slice(&r.body).unwrap_or_default();
                self.with(|s| s.display_name = body["displayname"].as_str().map(str::to_string));
                reply(200, json!({}))
            }
            _ => reply(404, json!({"errcode": "M_UNRECOGNIZED"})),
        }
    }

    fn token(&self, r: &Request) -> Response {
        let form = form_of(&r.body);
        self.with(|s| match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => {
                if form.get("code") != Some(&"fake-code".to_string())
                    || !form.contains_key("code_verifier")
                {
                    return reply(400, json!({"error": "invalid_grant"}));
                }
                let body = self.mint_session(s);
                s.device = random("SIWX_", 8);
                let own = s.device.clone();
                s.devices.push(own);
                reply(200, body)
            }
            Some("refresh_token") => {
                if s.logged_out {
                    if let Some(status) = s.quirks.token_status_after_logout {
                        return reply(status, json!({"error": "temporarily_unavailable"}));
                    }
                }
                if form.get("refresh_token") == Some(&s.refresh) && !s.logged_out {
                    let body = self.mint_session(s);
                    return reply(200, body);
                }
                reply(
                    400,
                    json!({"error": "invalid_grant", "error_description": "gone"}),
                )
            }
            _ => reply(400, json!({"error": "unsupported_grant_type"})),
        })
    }
}

fn form_of(body: &[u8]) -> HashMap<String, String> {
    serde_urlencoded::from_bytes::<Vec<(String, String)>>(body)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

async fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), form_of(q.as_bytes())),
        None => (target, HashMap::new()),
    };
    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

// -- the harness ------------------------------------------------------------

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "rotation-canary-hermetic-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        Scratch(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn identity_for(root: &Path, fake: &Fake, route: LogoutRoute) -> PathBuf {
    let dir = identity::ensure_dir(root, "local").unwrap();
    let key = SiwxKey::generate_ed25519();
    identity::write_new_key(&dir, &Secret::new(key.to_pem().unwrap())).unwrap();
    let (client_id, mxid) = fake.with(|s| {
        s.did = key.did();
        (s.client_id.clone(), s.mxid.clone())
    });
    identity::write_client(
        &dir,
        &ClientRecord {
            version: 1,
            issuer: fake.base.clone(),
            client_id,
            logout_route: route,
            mxid,
        },
    )
    .unwrap();
    dir
}

fn check_cfg(fake: &Fake, matrix: bool) -> CheckConfig {
    let live = fake.live_kid();
    CheckConfig {
        env: "local".to_string(),
        issuer: fake.base.clone(),
        matrix: matrix.then(|| Matrix {
            homeserver: fake.base.clone(),
            server_name: SERVER_NAME.to_string(),
        }),
        live_kid: live.clone(),
        expect: BTreeSet::from([live]),
        dropped: BTreeSet::new(),
        baseline: false,
    }
}

struct Run {
    code: i32,
    lines: Vec<String>,
}

impl Run {
    fn line(&self, check: &str) -> &str {
        self.lines
            .iter()
            .find(|l| l.starts_with(&format!("CANARY {check} ")))
            .unwrap_or_else(|| panic!("no {check} line in {:#?}", self.lines))
    }

    fn has(&self, check: &str, text: &str) -> bool {
        self.line(check).contains(text)
    }

    fn summary(&self) -> &str {
        self.lines.last().unwrap()
    }
}

async fn run_check(cfg: CheckConfig, root: &Path) -> Run {
    hygiene::start_capture();
    let code = checks::run(cfg, root).await;
    Run {
        code,
        lines: hygiene::take_capture(),
    }
}

/// Every printed line has the schema, and none carries a credential the fake
/// handed out.
fn assert_clean(run: &Run, fake: &Fake) {
    let minted = fake.with(|s| s.minted.clone());
    for line in &run.lines {
        assert!(line.starts_with("CANARY "), "{line}");
        for part in line.split(' ').skip(2) {
            let (key, value) = part
                .split_once('=')
                .unwrap_or_else(|| panic!("no key=value in {line}"));
            assert!(
                key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{line}"
            );
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.,:/@<>-".contains(c)),
                "{line}"
            );
        }
        assert!(
            !hygiene::taint_hit(line, &minted),
            "a credential in: {line}"
        );
    }
}

#[tokio::test]
async fn a_healthy_deployment_passes_all_six_checks() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("healthy"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert_eq!(run.lines.len(), 7);
    assert_eq!(
        run.summary(),
        "CANARY summary checks_run=6 skipped=0 result=ok"
    );
    assert!(run.has("sign_in", "client=reused"));
    assert!(run.has("sign_in", "sig=verified"));
    assert!(run.has("logout", "tripwire=clean"));
    assert!(run.has("logout", "refresh=refused"));
    assert_clean(&run, &fake);
    assert!(fake.with(|s| s.logged_out), "the run's session is ended");
}

#[tokio::test]
async fn a_server_clock_an_hour_off_this_hosts_does_not_fail_the_sign_in() {
    // iat and exp follow the server's clock, and so does the judgement.
    let (fake, scratch) = (Fake::start().await, Scratch::new("clock"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.clock_offset = 3600);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
}

#[tokio::test]
async fn an_id_token_minted_on_another_clock_than_the_servers_date_fails_the_sign_in() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("skew"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.id_iat_shift = -600);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(
        run.has("sign_in", "result=FAIL reason=clock_skew"),
        "{}",
        run.line("sign_in")
    );
    assert!(run.has("logout", "result=ok"), "the session is still ended");
}

#[tokio::test]
async fn an_id_token_signed_by_another_key_fails_the_sign_in_and_still_logs_out() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("sig"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.id_signed_by = Some(SigningKey::random(&mut rand::rngs::OsRng)));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(run.has("sign_in", "result=FAIL reason=signature_invalid"));
    assert!(run.has("whoami", "result=ok"));
    assert!(run.has("logout", "result=ok"));
    assert!(fake.with(|s| s.logged_out));
    assert_clean(&run, &fake);
}

#[tokio::test]
async fn a_wrong_live_kid_fails_c3_and_c5_and_names_both_kids() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("kid"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let retired = SigningKey::random(&mut rand::rngs::OsRng);
    fake.with(|s| s.extra_jwks.push(jwk_of(&retired)));
    let mut cfg = check_cfg(&fake, true);
    cfg.expect.insert(kid_of(&retired));
    cfg.live_kid = kid_of(&retired);
    let run = run_check(cfg, &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(run.has("jwks", "result=ok"));
    assert!(run.has("sign_in", "reason=kid_mismatch"));
    assert!(run.has("sign_in", &format!("got_kid={}", fake.live_kid())));
    assert!(run.has("did_proof", "reason=did_kid_mismatch"));
}

#[tokio::test]
async fn a_dropped_kid_that_is_still_published_fails_c2() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("dropped"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let exposed = SigningKey::random(&mut rand::rngs::OsRng);
    fake.with(|s| s.extra_jwks.push(jwk_of(&exposed)));
    let mut cfg = check_cfg(&fake, true);
    cfg.dropped.insert(kid_of(&exposed));
    let run = run_check(cfg, &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(run.has("jwks", "reason=dropped_kid_present"));
    assert!(run.has("jwks", &format!("dropped_present={}", kid_of(&exposed))));
    assert!(
        run.has("sign_in", "result=ok"),
        "the other checks still ran"
    );
}

#[tokio::test]
async fn a_stale_did_proof_fails_c5() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("stale"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.proof_iat_shift = -3600);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(
        run.has("did_proof", "reason=did_proof_stale"),
        "{}",
        run.line("did_proof")
    );
    assert!(run.has("did_proof", "verify=ok"));
}

#[tokio::test]
async fn a_logout_that_revokes_nothing_is_exit_3_and_the_pair_it_issued_is_revoked() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("noop"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.logout_is_noop = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 3, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=logout_ineffective"));
    assert!(
        run.has("logout", "logout_status=200"),
        "a 200 from logout proved nothing"
    );
    assert!(run.has("logout", "refresh=accepted"));
    assert!(
        run.has("logout", "cleanup=revoked"),
        "{}",
        run.line("logout")
    );
    assert_clean(&run, &fake);
}

#[tokio::test]
async fn a_refresh_that_cannot_be_judged_leaves_the_logout_unproven_exit_3() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("unproven"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.token_status_after_logout = Some(503));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 3);
    assert!(run.has("logout", "reason=logout_unproven"));
    assert!(run.has("logout", "refresh=unknown"));
}

#[tokio::test]
async fn a_logout_that_answers_503_is_exit_3_even_when_the_refresh_is_refused() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("status"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.logout_status = 503);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 3);
    assert!(run.has("logout", "reason=logout_status"));
    assert!(run.has("logout", "refresh=refused"));
}

#[tokio::test]
async fn a_second_device_fires_the_tripwire_exit_4_and_is_left_alone() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("tripwire"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.extra_devices = vec!["STRANGER".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=identity_compromised"));
    assert!(run.has("logout", "strangers=STRANGER"));
    assert!(
        fake.with(|s| s.quirks.extra_devices.contains(&"STRANGER".to_string())),
        "evidence stays"
    );
    assert!(
        fake.with(|s| s.logged_out),
        "the run's own session is still ended"
    );
}

#[tokio::test]
async fn a_joined_room_fires_the_tripwire() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("room"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.rooms = 1);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4);
    assert!(run.has("logout", "rooms=1"));
}

#[tokio::test]
async fn a_device_the_canary_left_behind_is_tolerated_and_forgotten() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("leftover"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    identity::write_pending(&dir, &BTreeSet::from(["SIWX_old".to_string()])).unwrap();
    fake.quirks(|q| q.extra_devices = vec!["SIWX_old".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("logout", "leftovers=SIWX_old"));
    assert!(run.has("logout", "cleaned=1"));
    assert!(fake.with(|s| s.quirks.extra_devices.is_empty()));
    let ledger = identity::read_pending(&dir);
    assert!(!ledger.contains("SIWX_old"));
    assert_eq!(
        ledger.len(),
        1,
        "this run's own device stays until the next run sees it gone"
    );
}

#[tokio::test]
async fn a_credential_a_hostile_server_puts_in_a_printed_field_is_refused() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("taint"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    // The ID token's kid is the access token; the failing sign_in line would print it as got_kid.
    fake.quirks(|q| q.id_kid_is_access_token = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    let (access, refresh) = fake.with(|s| (s.access.clone(), s.refresh.clone()));
    assert_eq!(run.code, 1);
    assert_eq!(
        run.line("taint"),
        "CANARY taint result=FAIL reason=output_refused check=sign_in"
    );
    for line in &run.lines {
        assert!(
            !hygiene::taint_hit(line, &[access.clone(), refresh.clone()]),
            "{line}"
        );
    }
    assert!(run.summary().ends_with("result=FAIL"));
    assert!(hygiene::taint_tripped());
}

#[tokio::test]
async fn a_device_id_that_is_a_credential_is_refused_too_and_the_real_device_reads_as_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("taint-device"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.device_is_refresh_token = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    let refresh = fake.with(|s| s.refresh.clone());
    assert_eq!(
        run.line("taint"),
        "CANARY taint result=FAIL reason=output_refused check=whoami"
    );
    for line in &run.lines {
        assert!(
            !hygiene::taint_hit(line, std::slice::from_ref(&refresh)),
            "{line}"
        );
    }
    // whoami named something else than the device the homeserver lists: the
    // listed one is nobody's, so the tripwire fires (the safe direction).
    assert_eq!(run.code, 4);
}

#[tokio::test]
async fn a_client_the_server_forgot_fails_a_post_rotation_run_and_is_replaced_at_baseline() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("client"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let stored = identity::read_client(&dir).unwrap().client_id;
    fake.with(|s| s.client_id = "someone-elses-client".to_string());
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(run.has("sign_in", "reason=client_refused"));
    assert!(run.has("sign_in", "client=refused"));
    for check in ["whoami", "did_proof", "logout"] {
        assert!(run.has(check, "result=SKIP reason=no_sign_in"));
    }
    assert_eq!(
        identity::read_client(&dir).unwrap().client_id,
        stored,
        "not replaced"
    );

    let mut cfg = check_cfg(&fake, true);
    cfg.baseline = true;
    let run = run_check(cfg, &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("sign_in", "client=registered"));
    let replaced = identity::read_client(&dir).unwrap().client_id;
    assert_ne!(replaced, stored);
    assert_eq!(replaced, fake.with(|s| s.client_id.clone()));
    assert_clean(&run, &fake);
}

#[tokio::test]
async fn no_matrix_in_env_local_runs_three_checks_and_still_revokes() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("nomatrix"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let run = run_check(check_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert_eq!(
        run.summary(),
        "CANARY summary checks_run=3 skipped=3 result=ok"
    );
    assert!(run.has("logout", "result=SKIP reason=no_matrix revoked=yes"));
    assert!(fake.with(|s| s.logged_out));
}

#[tokio::test]
async fn the_revoke_route_ends_the_session_through_oauth2_revoke() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("revoke"));
    identity_for(&scratch.0, &fake, LogoutRoute::Revoke);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("logout", "route=revoke"));
    assert!(run.has("logout", "logout_status=200"));
    assert!(run.has("logout", "refresh=refused"));
}

#[tokio::test]
async fn init_makes_the_identity_prints_no_credential_and_refuses_to_run_twice() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("init"));
    let cfg = || InitConfig {
        env: "local".to_string(),
        issuer: fake.base.clone(),
        matrix: Matrix {
            homeserver: fake.base.clone(),
            server_name: SERVER_NAME.to_string(),
        },
        replace: false,
    };
    hygiene::start_capture();
    let code = init::run(cfg(), &scratch.0).await;
    let lines = hygiene::take_capture();
    assert_eq!(code, 0, "{lines:#?}");
    assert_eq!(
        lines.last().unwrap(),
        &format!(
            "CANARY init result=ok reason=ok env=local mxid={}",
            fake.with(|s| s.mxid.clone())
        )
    );
    let dir = scratch.0.join("local");
    let client = identity::read_client(&dir).unwrap();
    assert_eq!(client.logout_route, LogoutRoute::Matrix);
    assert_eq!(client.issuer, fake.base);
    assert_eq!(
        fake.with(|s| s.display_name.clone()).as_deref(),
        Some("rotation-canary")
    );
    assert!(fake.with(|s| s.logged_out), "init logs out");
    assert!(identity::load_key(&dir).is_ok());
    let minted = fake.with(|s| s.minted.clone());
    for line in &lines {
        assert!(!hygiene::taint_hit(line, &minted), "{line}");
    }
    assert!(
        minted.iter().any(|t| t.starts_with("rat_")),
        "the registration token was handed out"
    );

    hygiene::start_capture();
    let again = init::run(cfg(), &scratch.0).await;
    let lines = hygiene::take_capture();
    assert_eq!(again, 2);
    assert_eq!(
        lines,
        vec!["CANARY init_identity result=FAIL reason=identity_exists".to_string()]
    );
}

// -- process-level hygiene --------------------------------------------------

#[test]
fn a_panic_prints_only_its_location_and_aborts() {
    use std::os::unix::process::ExitStatusExt;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hermetic::panic_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ROTATION_CANARY_PANIC_CHILD", "1")
        .output()
        .unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("CANARY panic result=FAIL reason=internal_error at="),
        "{all}"
    );
    assert!(all.contains("hermetic.rs:"), "{all}");
    assert!(
        !all.contains("SECRET-PANIC-PAYLOAD"),
        "the payload must not be printed: {all}"
    );
    assert_eq!(out.status.signal(), Some(6), "aborted, not unwound: {all}");
}

/// Run only by the test above, in a child process.
#[test]
fn panic_child() {
    if std::env::var_os("ROTATION_CANARY_PANIC_CHILD").is_none() {
        return;
    }
    hygiene::install_panic_hook();
    let token = "mat_SECRET-PANIC-PAYLOAD0123456789abcdef";
    panic!("response body was {token}");
}

#[test]
fn core_dumps_are_off_after_startup() {
    assert!(hygiene::disable_core_dumps());
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `limit` is a valid out-pointer for the call.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
}
