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
use crate::flow::{self, REDIRECT_URI};
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

/// The Ed25519 key a `did:key:z6Mk...` names.
fn did_verifying_key(did: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = bs58::decode(did.strip_prefix("did:key:z")?)
        .into_vec()
        .ok()?;
    let key: [u8; 32] = bytes.strip_prefix(&[0xED, 0x01])?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).ok()
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
    /// `POST /logout` without a token answers this (status, with a Matrix
    /// `errcode`) instead of 200: an edge that does not route it.
    logout_probe: Option<(u16, bool)>,
    /// The logout revokes the tokens but leaves the device.
    leave_device_on_logout: bool,
    /// `DELETE /devices/{id}` answers this and deletes nothing when not 200.
    delete_device_status: u16,
    /// whoami names this account instead of the signed-in one.
    whoami_user_id: Option<String>,
    /// The code exchange fails after `/sign_in` made the device.
    token_fails: bool,
    /// `/oauth2/revoke` answers 200 and revokes nothing.
    revoke_is_noop: bool,
    /// `/account/wallet` refuses with this status.
    erase_refused: Option<u16>,
    /// whoami answers this status.
    whoami_status: Option<u16>,
    /// How `GET /devices` describes a device, by id: its display name and its
    /// `last_seen_ts`. A device not named here is described the way Synapse
    /// describes one the canary made: named after the canary's client, and seen
    /// once its token was used (an unfinished sign-in's never was).
    device_meta: HashMap<String, (Option<String>, Option<i64>)>,
    /// `/authorize` sets one more cookie, with this value, besides the session.
    authorize_cookie: Option<String>,
    /// `DELETE /devices/{id}` answers 200 and deletes nothing (siwx-oidc's
    /// best-effort teardown).
    delete_device_is_noop: bool,
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
            logout_probe: None,
            leave_device_on_logout: false,
            delete_device_status: 200,
            whoami_user_id: None,
            token_fails: false,
            revoke_is_noop: false,
            erase_refused: None,
            whoami_status: None,
            device_meta: HashMap::new(),
            authorize_cookie: None,
            delete_device_is_noop: false,
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
    /// The device `/sign_in` made, before the code was exchanged.
    signed_in_device: String,
    /// Every credential the fake handed out, for the leak assertions.
    minted: Vec<String>,
    devices: Vec<String>,
    /// When a device's token was last used, in the server's clock (ms): what
    /// Synapse lists as its `last_seen_ts`.
    seen_ms: HashMap<String, i64>,
    display_name: Option<String>,
    /// Whether the key's DID has an account (`/sign_in` makes it).
    account_exists: bool,
    /// Nonces handed out by `/account/nonce`, until used.
    nonces: Vec<String>,
    erased: bool,
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

fn text_reply(status: u16, body: &str) -> Response {
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
            signed_in_device: String::new(),
            minted: Vec::new(),
            devices: Vec::new(),
            seen_ms: HashMap::new(),
            display_name: None,
            account_exists: true,
            nonces: Vec::new(),
            erased: false,
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
        self.with(|s| {
            let ok = !s.logged_out && bearer.as_deref() == Some(s.access.as_str());
            if ok {
                // Like Synapse: a device whose token is used has been seen.
                let at = Utc::now().timestamp_millis() + s.quirks.clock_offset * 1000;
                let device = s.device.clone();
                s.seen_ms.insert(device, at);
            }
            ok
        })
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
                let client_secret = random("cs_", 40);
                s.minted
                    .extend([registration_token.clone(), client_secret.clone()]);
                s.client_id = random("client-", 12);
                reply(
                    201,
                    json!({
                        "client_id": s.client_id,
                        "registration_access_token": registration_token,
                        "client_secret": client_secret,
                    }),
                )
            }),
            ("GET", "/authorize") => self.with(|s| {
                if r.query.get("client_id") != Some(&s.client_id) {
                    return reply(401, json!({"error": "Unrecognised client id."}));
                }
                let mut response = redirect(
                    format!(
                        "/sign_in?nonce={}&state=headless&redirect_uri={}&client_id={}",
                        random("", 16),
                        urlencoding::encode(REDIRECT_URI),
                        s.client_id
                    ),
                    Some("session=fake-session"),
                );
                if let Some(value) = &s.quirks.authorize_cookie {
                    response
                        .headers
                        .push(("Set-Cookie".to_string(), format!("probe={value}; Path=/")));
                }
                response
            }),
            ("GET", "/sign_in") => {
                let cookie = r.headers.get("cookie").cloned().unwrap_or_default();
                if cookie.contains("session=fake-session") && cookie.contains("siwx=") {
                    // Like the server: the device is made here, before the code is
                    // exchanged at `/token`.
                    self.with(|s| {
                        s.signed_in_device = random("SIWX_", 8);
                        let made = s.signed_in_device.clone();
                        s.devices.push(made);
                        s.account_exists = true;
                    });
                    redirect(format!("{REDIRECT_URI}?code=fake-code&state=headless"), None)
                } else {
                    reply(400, json!({"error": "no session"}))
                }
            }
            ("POST", "/token") => self.token(r),
            ("POST", "/oauth2/revoke") => self.with(|s| {
                let form = form_of(&r.body);
                if form.get("token") == Some(&s.refresh) && !s.quirks.revoke_is_noop {
                    s.logged_out = true;
                }
                reply(200, json!({}))
            }),
            ("POST", "/_matrix/client/v3/logout") => {
                if Self::bearer(r).is_none() {
                    return match self.with(|s| s.quirks.logout_probe) {
                        None => reply(200, json!({})),
                        Some((status, true)) => {
                            reply(status, json!({"errcode": "M_UNRECOGNIZED", "error": "x"}))
                        }
                        Some((status, false)) => text_reply(status, "<html>not matrix</html>"),
                    };
                }
                let authorised = self.authorised(r);
                self.with(|s| {
                    if authorised && !s.quirks.logout_is_noop {
                        s.logged_out = true;
                        if !s.quirks.leave_device_on_logout {
                            let own = s.device.clone();
                            s.devices.retain(|d| *d != own);
                        }
                    }
                    reply(s.quirks.logout_status, json!({}))
                })
            }
            ("GET", "/_matrix/client/v3/account/whoami") => {
                if !self.authorised(r) {
                    return reply(401, json!({"errcode": "M_UNKNOWN_TOKEN"}));
                }
                if let Some(status) = self.with(|s| s.quirks.whoami_status) {
                    return reply(status, json!({"errcode": "M_UNKNOWN"}));
                }
                self.with(|s| {
                    let device = if s.quirks.device_is_refresh_token {
                        s.refresh.clone()
                    } else {
                        s.device.clone()
                    };
                    let user_id = s.quirks.whoami_user_id.clone().unwrap_or(s.mxid.clone());
                    reply(200, json!({"user_id": user_id, "device_id": device}))
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
                    let devices: Vec<Value> = ids
                        .iter()
                        .map(|d| {
                            let (name, seen) = s.quirks.device_meta.get(d).cloned().unwrap_or((
                                Some(flow::DEVICE_NAME.to_string()),
                                s.seen_ms.get(d).copied(),
                            ));
                            json!({
                                "device_id": d, "display_name": name,
                                "last_seen_ip": null, "last_seen_ts": seen,
                            })
                        })
                        .collect();
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
                    if s.quirks.delete_device_status != 200 {
                        return reply(s.quirks.delete_device_status, json!({"errcode": "M_UNKNOWN"}));
                    }
                    if s.quirks.delete_device_is_noop {
                        return reply(200, json!({}));
                    }
                    s.devices.retain(|d| *d != id);
                    s.quirks.extra_devices.retain(|d| *d != id);
                    reply(200, json!({}))
                })
            }
            ("GET", "/account/nonce") => self.with(|s| {
                let nonce = random("n", 24);
                s.minted.push(nonce.clone());
                s.nonces.push(nonce.clone());
                let expires = Utc::now().timestamp() + s.quirks.clock_offset + 300;
                reply(
                    200,
                    json!({
                        "nonce": nonce,
                        "expiration_time": DateTime::from_timestamp(expires, 0).unwrap()
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        "resources": [format!("{}/account?action=io.inblock.account_erase", s.base)],
                    }),
                )
            }),
            ("POST", "/account/wallet") => self.wallet(r),
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

    /// `POST /account/wallet` for the erase action: the signature must be the
    /// DID's over the message, the message must carry a nonce the fake issued.
    fn wallet(&self, r: &Request) -> Response {
        let body: Value = serde_json::from_slice(&r.body).unwrap_or_default();
        let field = |name: &str| body[name].as_str().unwrap_or_default().to_string();
        let (action, did, message, signature) = (
            field("action"),
            field("did"),
            field("message"),
            field("signature"),
        );
        self.with(|s| {
            if let Some(status) = s.quirks.erase_refused {
                return text_reply(status, "refused");
            }
            let signed = did_verifying_key(&did).is_some_and(|key| {
                use ed25519_dalek::Verifier;
                hex::decode(&signature)
                    .ok()
                    .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                    .is_some_and(|sig| key.verify(message.as_bytes(), &sig).is_ok())
            });
            let nonce = s.nonces.iter().position(|n| message.contains(n.as_str()));
            if action != "io.inblock.account_erase" || !signed || nonce.is_none() {
                return reply(401, json!({"error": "bad signature or nonce"}));
            }
            s.nonces.remove(nonce.unwrap());
            if !s.account_exists {
                return text_reply(
                    400,
                    "This passkey/wallet is not linked to an existing account. Create an account at sign-in first.",
                );
            }
            s.account_exists = false;
            s.erased = true;
            let csrf = random("csrf_", 32);
            let cookie = random("acct_", 32);
            s.minted.extend([csrf.clone(), cookie.clone()]);
            let mut response = reply(
                200,
                json!({"status": "completed", "action": action, "kind": "erased", "csrf": csrf}),
            );
            response
                .headers
                .push(("Set-Cookie".to_string(), format!("acct_session={cookie}; Path=/")));
            response
        })
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
                if s.quirks.token_fails {
                    return reply(500, json!({"error": "server_error"}));
                }
                let body = self.mint_session(s);
                s.device = s.signed_in_device.clone();
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
    identity::update_ledger(&dir, |l| {
        l.pending.insert("SIWX_old".to_string());
    })
    .unwrap();
    fake.quirks(|q| q.extra_devices = vec!["SIWX_old".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("logout", "leftovers=SIWX_old"));
    assert!(run.has("logout", "cleaned=1"));
    assert!(fake.with(|s| s.quirks.extra_devices.is_empty()));
    let ledger = identity::read_ledger(&dir);
    assert!(
        ledger.pending.is_empty(),
        "the leftover is no longer tolerated blindly"
    );
    assert!(
        ledger.logged_out.contains("SIWX_old"),
        "the 200 is not proof: it leaves the ledger when a run sees it gone"
    );
}

#[tokio::test]
async fn a_leftover_that_cannot_be_deleted_fails_the_check() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("stuck"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    identity::update_ledger(&dir, |l| {
        l.pending.insert("SIWX_old".to_string());
    })
    .unwrap();
    fake.quirks(|q| {
        q.extra_devices = vec!["SIWX_old".to_string()];
        q.delete_device_status = 500;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=leftover_not_deleted"));
    assert!(run.has("logout", "stuck=SIWX_old"));
    assert!(
        identity::read_ledger(&dir).pending.contains("SIWX_old"),
        "it stays on the ledger until it is gone"
    );
}

#[tokio::test]
async fn the_account_the_key_resolves_to_must_stay_the_one_init_recorded() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("mxid"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.whoami_user_id = Some("@someone-else:matrix.test".to_string()));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(
        run.has("whoami", "result=FAIL reason=mxid_changed"),
        "{}",
        run.line("whoami")
    );
    assert!(run.has("whoami", "mxid=@someone-else:matrix.test"));
    assert!(run.has(
        "whoami",
        &format!("recorded={}", fake.with(|s| s.mxid.clone()))
    ));
    assert!(run.has("logout", "result=ok"), "the session is still ended");
    assert_eq!(
        identity::read_client(&dir).unwrap().mxid,
        fake.with(|s| s.mxid.clone()),
        "the record is not rewritten to follow the server"
    );
}

#[tokio::test]
async fn an_identity_whose_init_never_learned_its_account_is_not_checked() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("halfmade"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let mut record = identity::read_client(&dir).unwrap();
    record.mxid = String::new();
    identity::write_client(&dir, &record).unwrap();
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 2);
    assert_eq!(
        run.lines,
        vec!["CANARY identity result=FAIL reason=not_initialized".to_string()]
    );
}

#[tokio::test]
async fn a_proven_matrix_logout_takes_the_device_off_the_ledger_and_a_revoke_logout_keeps_it() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("ledger-drop"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0);
    let device = fake.with(|s| s.device.clone());
    let ledger = identity::read_ledger(&dir);
    assert_eq!(
        ledger.logged_out.ids(),
        BTreeSet::from([device.clone()]),
        "the proof is about the grant: the device waits on the ledger until a run sees it gone"
    );
    assert!(ledger.pending.is_empty() && ledger.unfinished.is_empty());
    let at = ledger.logged_out.at(&device).unwrap();
    assert!(
        (Utc::now().timestamp() - at).abs() < 60,
        "with the time the canary last used it"
    );
    // The next run finds it gone and forgets it, and holds its own.
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let device = fake.with(|s| s.device.clone());
    assert_eq!(
        identity::read_ledger(&dir).logged_out.ids(),
        BTreeSet::from([device])
    );

    let (fake, scratch) = (Fake::start().await, Scratch::new("ledger-keep"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Revoke);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0);
    let device = fake.with(|s| s.device.clone());
    assert_eq!(
        identity::read_ledger(&dir).pending,
        BTreeSet::from([device]),
        "`/oauth2/revoke` may leave the device: it stays until a run sees it gone"
    );
}

#[tokio::test]
async fn a_sign_in_that_failed_after_its_device_was_made_is_reported_then_forgiven() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("unfinished"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);

    // Run 1: the server made the device at /sign_in, the code exchange failed.
    fake.quirks(|q| q.token_fails = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert!(run.has("sign_in", "reason=sign_in_failed"));
    let ledger = identity::read_ledger(&dir);
    assert_eq!(ledger.attempts.len(), 1, "the attempt is on the ledger");
    assert!(ledger.pending.is_empty(), "and the device is not");
    let killed = fake.with(|s| s.signed_in_device.clone());
    assert_eq!(fake.with(|s| s.devices.clone()), vec![killed.clone()]);

    // Run 2: the device is there, unrecorded, and explained by the attempt:
    // reported under its own reason (exit 1), not the tripwire (exit 4).
    fake.quirks(|q| q.token_fails = false);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "result=FAIL reason=unfinished_sign_in_device"));
    assert!(run.has("logout", &format!("unfinished={killed}")));
    assert!(run.has("logout", "tripwire=clean"));
    let ledger = identity::read_ledger(&dir);
    assert!(ledger.attempts.is_empty(), "the marker is spent");
    assert!(
        ledger.unfinished.contains(&killed) && !ledger.pending.contains(&killed),
        "excused as unfinished, which holds only while nobody uses it"
    );

    // Run 3: it is a leftover, tolerated and deleted.
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("logout", &format!("leftovers={killed}")));
    assert!(run.has("logout", "cleaned=1"));
    let ledger = identity::read_ledger(&dir);
    assert!(ledger.pending.is_empty() && ledger.unfinished.is_empty());
    assert!(ledger.attempts.is_empty());
    assert_eq!(
        ledger.logged_out.ids(),
        BTreeSet::from([fake.with(|s| s.device.clone()), killed]),
        "this run's own, proven device and the one it deleted wait to be seen gone"
    );
    assert!(fake.with(|s| s.devices.is_empty()));
}

/// A marker an earlier run left, started `age_secs` ago by this host's clock.
fn leave_marker(dir: &Path, id: &str, age_secs: i64) {
    let at = Utc::now().timestamp() - age_secs;
    identity::update_ledger(dir, |l| {
        l.attempts.push(identity::Attempt {
            id: id.to_string(),
            at,
        })
    })
    .unwrap();
}

#[tokio::test]
async fn a_device_that_no_attempt_can_explain_still_fires_the_tripwire() {
    // No marker at all.
    let (fake, scratch) = (Fake::start().await, Scratch::new("nomarker"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_stranger".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);

    // A marker, but the device is not of the kind the server mints without a proposal.
    let (fake, scratch) = (Fake::start().await, Scratch::new("othermarker"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "old", 0);
    fake.quirks(|q| q.extra_devices = vec!["ELEMENTXDEVICE".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "strangers=ELEMENTXDEVICE"));
    assert_eq!(
        identity::read_ledger(&dir).attempts.len(),
        1,
        "the marker is evidence too while the tripwire is fired"
    );

    // One marker explains one device, not two.
    let (fake, scratch) = (Fake::start().await, Scratch::new("twodevices"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "old", 0);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_a".to_string(), "SIWX_b".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
}

#[tokio::test]
async fn a_run_that_never_learned_its_device_records_the_one_it_cannot_explain_as_its_own() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("nowhoami"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    // whoami fails, so this run never learns its device id, and the logout
    // leaves the device behind.
    fake.quirks(|q| {
        q.whoami_status = Some(503);
        q.leave_device_on_logout = true;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("whoami", "reason=whoami_status"));
    assert!(
        run.has("logout", "result=ok"),
        "its one unexplained device is its own"
    );
    let left = fake.with(|s| s.signed_in_device.clone());
    let ledger = identity::read_ledger(&dir);
    assert!(
        ledger.logged_out.contains(&left),
        "recorded like a device whoami named: {ledger:?}"
    );
    assert!(ledger.attempts.is_empty(), "the marker did its job");

    // The next run finds it listed, as Synapse lists it once its token was used.
    fake.quirks(|q| {
        q.whoami_status = None;
        q.leave_device_on_logout = false;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=device_survived_logout"));
    assert!(run.has("logout", &format!("survivors={left}")));
    assert!(run.has("logout", "tripwire=clean"));
}

/// How a homeserver describes a stranger's device: any name or none, seen or not.
fn describe(fake: &Fake, id: &str, name: Option<&str>, last_seen_ts: Option<i64>) {
    fake.quirks(|q| {
        q.device_meta
            .insert(id.to_string(), (name.map(str::to_string), last_seen_ts));
    });
}

#[tokio::test]
async fn a_stranger_with_a_siwx_id_cannot_pass_as_an_unfinished_sign_in() {
    // Each stranger has a live marker to hide behind and an id of the kind the
    // server mints, and each fails one of the other two conditions.
    let strangers: [(&str, Option<&str>, Option<i64>); 3] = [
        ("another-clients-name", Some("Element Web"), None),
        ("no-name", None, None),
        (
            "seen-in-use",
            Some("rotation-canary"),
            Some(1_700_000_000_000),
        ),
    ];
    for (tag, name, last_seen_ts) in strangers {
        let (fake, scratch) = (Fake::start().await, Scratch::new(tag));
        let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
        leave_marker(&dir, "leftover", 60);
        fake.quirks(|q| q.extra_devices = vec!["SIWX_stranger".to_string()]);
        describe(&fake, "SIWX_stranger", name, last_seen_ts);
        let run = run_check(check_cfg(&fake, true), &scratch.0).await;
        assert_eq!(run.code, 4, "{tag}: {:#?}", run.lines);
        assert!(run.has("logout", "reason=identity_compromised"), "{tag}");
        assert!(run.has("logout", "strangers=SIWX_stranger"), "{tag}");
        assert!(
            fake.with(|s| s
                .quirks
                .extra_devices
                .contains(&"SIWX_stranger".to_string())),
            "{tag}: evidence stays"
        );
        assert_eq!(
            identity::read_ledger(&dir).attempts.len(),
            1,
            "{tag}: the marker is evidence too while the tripwire is fired"
        );
    }

    // The same marker and the same id, but a device that looks like the
    // canary's own unfinished sign-in: reported, not the tripwire.
    let (fake, scratch) = (Fake::start().await, Scratch::new("own-unfinished"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "leftover", 60);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_killed".to_string()]);
    describe(&fake, "SIWX_killed", Some("rotation-canary"), None);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=unfinished_sign_in_device"));
    assert!(run.has("logout", "unfinished=SIWX_killed"));
    assert!(run.has("logout", "tripwire=clean"));
}

#[tokio::test]
async fn a_marker_older_than_the_age_limit_explains_no_device() {
    let age_limit = identity::ATTEMPT_MAX_AGE_SECS;
    // Just past the limit: the canary-shaped device reads as a stranger.
    let (fake, scratch) = (Fake::start().await, Scratch::new("stale-marker"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "stale", age_limit + 120);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_killed".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "strangers=SIWX_killed"));

    // Just inside it: the same device is the canary's own unfinished sign-in.
    let (fake, scratch) = (Fake::start().await, Scratch::new("fresh-marker"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "fresh", age_limit - 600);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_killed".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=unfinished_sign_in_device"));
}

#[tokio::test]
async fn the_markers_a_ledger_holds_are_capped() {
    let cap = identity::ATTEMPT_CAP;
    // Forty live markers, but the ledger keeps (and counts) `cap` of them, this
    // run's own among them, so `cap` unrecorded devices are one too many.
    let (fake, scratch) = (Fake::start().await, Scratch::new("marker-cap"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    for n in 0..40 {
        leave_marker(&dir, &format!("m{n}"), 60);
    }
    let devices: Vec<String> = (0..cap).map(|n| format!("SIWX_dead{n}")).collect();
    fake.quirks(|q| q.extra_devices = devices.clone());
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(
        identity::read_ledger(&dir).attempts.len() <= cap,
        "the file does not grow past the cap either"
    );

    // One fewer is within what the cap allows: reported, not the tripwire.
    let (fake, scratch) = (Fake::start().await, Scratch::new("marker-cap-ok"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    for n in 0..40 {
        leave_marker(&dir, &format!("m{n}"), 60);
    }
    let devices: Vec<String> = (0..cap - 1).map(|n| format!("SIWX_dead{n}")).collect();
    fake.quirks(|q| q.extra_devices = devices.clone());
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=unfinished_sign_in_device"));
}

#[tokio::test]
async fn a_device_that_outlives_a_proven_logout_is_reported_and_deleted_not_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("survivor"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);

    // Run 1: the logout is proven (the refresh token is refused), but the
    // homeserver keeps the device, as siwx-oidc's best-effort delete may.
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let survivor = fake.with(|s| s.device.clone());
    assert!(fake.with(|s| s.devices.contains(&survivor)));
    assert_eq!(
        identity::read_ledger(&dir).logged_out.ids(),
        BTreeSet::from([survivor.clone()])
    );

    // Run 2: it is still listed. Under its own reason, deleted, no tripwire.
    fake.quirks(|q| q.leave_device_on_logout = false);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "result=FAIL reason=device_survived_logout"));
    assert!(run.has("logout", &format!("survivors={survivor}")));
    assert!(run.has("logout", "survivors_cleaned=1"));
    assert!(run.has("logout", "tripwire=clean"));
    assert!(!run.has("logout", "strangers="));
    assert!(
        !fake.with(|s| s.devices.contains(&survivor)),
        "the survivor was deleted"
    );
    assert_clean(&run, &fake);
    let second = fake.with(|s| s.device.clone());
    assert_eq!(
        identity::read_ledger(&dir).logged_out.ids(),
        BTreeSet::from([survivor.clone(), second]),
        "the 200 is not proof: the survivor stays until a run sees it gone"
    );

    // Run 3: nothing survived; the ledger holds only the last run's device.
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(!run.has("logout", "survivors="));
    let third = fake.with(|s| s.device.clone());
    assert_eq!(
        identity::read_ledger(&dir).logged_out.ids(),
        BTreeSet::from([third]),
        "a device seen gone is forgotten"
    );
}

#[tokio::test]
async fn a_survivor_that_cannot_be_deleted_stays_on_the_ledger_and_fails_the_check() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("survivor-stuck"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let survivor = fake.with(|s| s.device.clone());

    fake.quirks(|q| {
        q.leave_device_on_logout = false;
        q.delete_device_status = 500;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=leftover_not_deleted"));
    assert!(run.has("logout", &format!("survivors={survivor}")));
    assert!(run.has("logout", &format!("stuck={survivor}")));
    assert!(run.has("logout", "survivors_cleaned=0"));
    assert!(run.has("logout", "tripwire=clean"));
    assert!(identity::read_ledger(&dir).logged_out.contains(&survivor));
}

#[tokio::test]
async fn a_survivor_beside_a_stranger_does_not_excuse_it_and_nothing_is_deleted() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("survivor-stranger"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let survivor = fake.with(|s| s.device.clone());

    fake.quirks(|q| {
        q.leave_device_on_logout = false;
        q.extra_devices = vec!["STRANGER".to_string()];
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "strangers=STRANGER"));
    assert!(run.has("logout", &format!("survivors={survivor}")));
    assert!(
        fake.with(|s| s.devices.contains(&survivor)),
        "evidence stays while the tripwire is fired"
    );
    assert!(identity::read_ledger(&dir).logged_out.contains(&survivor));
}

#[tokio::test]
async fn the_cookie_of_the_authorize_probe_is_held_as_a_credential() {
    let (fake, http) = (Fake::start().await, crate::flow::http().unwrap());
    let cookie = random("sess-", 24);
    fake.quirks(|q| q.authorize_cookie = Some(cookie.clone()));
    assert!(!hygiene::raw_tainted(&cookie), "not held before the probe");
    let client_id = fake.with(|s| s.client_id.clone());
    let probe = crate::flow::probe_authorize(&http, &fake.base, &client_id).await;
    assert!(matches!(probe, crate::flow::Probe::Valid { .. }));
    assert!(hygiene::raw_tainted(&cookie), "the value is held");
    assert!(
        hygiene::raw_tainted(&format!("probe={cookie}")),
        "so is the whole pair"
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

fn init_cfg(fake: &Fake, replace: bool) -> InitConfig {
    InitConfig {
        env: "local".to_string(),
        issuer: fake.base.clone(),
        matrix: Matrix {
            homeserver: fake.base.clone(),
            server_name: SERVER_NAME.to_string(),
        },
        replace,
    }
}

async fn run_init(cfg: InitConfig, root: &Path) -> Run {
    hygiene::start_capture();
    let code = init::run(cfg, root).await;
    Run {
        code,
        lines: hygiene::take_capture(),
    }
}

#[tokio::test]
async fn init_pins_revoke_only_when_the_edge_answers_with_a_matrix_refusal() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("probe-revoke"));
    fake.quirks(|q| q.logout_probe = Some((404, true)));
    let run = run_init(init_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("init_client", "logout_route=revoke"));
    let dir = scratch.0.join("local");
    assert_eq!(
        identity::read_client(&dir).unwrap().logout_route,
        LogoutRoute::Revoke
    );
    // The revoke route may leave the device: init's device is on the ledger.
    let device = fake.with(|s| s.device.clone());
    assert_eq!(
        identity::read_ledger(&dir).pending,
        BTreeSet::from([device])
    );
    assert!(identity::read_ledger(&dir).attempts.is_empty());
}

#[tokio::test]
async fn init_records_nothing_when_the_probe_says_nothing_about_the_route() {
    for (status, errcode) in [
        (429, true),
        (503, true),
        (502, false),
        (404, false),
        (500, false),
    ] {
        let (fake, scratch) = (Fake::start().await, Scratch::new("probe-fail"));
        fake.quirks(|q| q.logout_probe = Some((status, errcode)));
        let run = run_init(init_cfg(&fake, false), &scratch.0).await;
        assert_eq!(run.code, 1, "{status} {errcode}: {:#?}", run.lines);
        assert_eq!(
            run.line("init_client"),
            format!("CANARY init_client result=FAIL reason=route_probe_failed status={status}")
        );
        let dir = scratch.0.join("local");
        assert!(
            !identity::client_exists(&dir),
            "no client record for {status}"
        );
        assert!(!dir.join(identity::DEVICES_FILE).exists());
        assert!(
            fake.with(|s| s.devices.is_empty()),
            "no sign-in was started"
        );
    }
}

#[tokio::test]
async fn init_with_a_matrix_logout_puts_its_device_on_the_logged_out_list() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("init-ledger"));
    let run = run_init(init_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let ledger = identity::read_ledger(&scratch.0.join("local"));
    let device = fake.with(|s| s.device.clone());
    assert_eq!(
        ledger.logged_out.ids(),
        BTreeSet::from([device]),
        "the proven logout deleted the device, best-effort: the first check sees it gone"
    );
    assert!(ledger.pending.is_empty() && ledger.unfinished.is_empty());
    assert!(ledger.attempts.is_empty(), "and the attempt is finished");
}

#[tokio::test]
async fn an_init_whose_sign_in_failed_leaves_a_half_made_identity_that_replace_can_clear() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("init-half"));
    fake.quirks(|q| q.token_fails = true);
    let run = run_init(init_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    let dir = scratch.0.join("local");
    assert!(identity::key_exists(&dir));
    assert_eq!(
        identity::read_client(&dir).unwrap().mxid,
        "",
        "the account was never learned"
    );
    assert_eq!(identity::read_ledger(&dir).attempts.len(), 1);
    // `check` will not run on it.
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 2);

    // The server made the device and the account at /sign_in; the key can erase it.
    fake.quirks(|q| q.token_fails = false);
    let did = identity::load_key(&dir).unwrap().did();
    fake.with(|s| s.did = did);
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("init_erase", "erased=yes"));
}

#[tokio::test]
async fn replace_erases_the_old_account_with_the_old_key_and_makes_a_new_identity() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let old_did = identity::load_key(&dir).unwrap().did();
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert_eq!(
        run.line("init_erase"),
        "CANARY init_erase result=ok reason=ok erased=yes"
    );
    assert!(fake.with(|s| s.erased), "the old account was erased");
    assert_ne!(
        identity::load_key(&dir).unwrap().did(),
        old_did,
        "a new key"
    );
    assert_eq!(
        identity::read_client(&dir).unwrap().mxid,
        fake.with(|s| s.mxid.clone())
    );
    // The erase reply's nonce, csrf token and cookie are credentials.
    let minted = fake.with(|s| s.minted.clone());
    assert!(minted.iter().any(|t| t.starts_with("csrf_")));
    assert!(minted.iter().any(|t| t.starts_with("acct_")));
    assert!(
        minted.iter().any(|t| t.starts_with("cs_")),
        "a client secret"
    );
    for line in &run.lines {
        assert!(!hygiene::taint_hit(line, &minted), "{line}");
    }
    assert!(!hygiene::taint_tripped());
    // And the taint check holds them, whether or not any line was about to print one.
    for prefix in ["csrf_", "acct_", "cs_", "rat_", "n"] {
        let token = minted.iter().find(|t| t.starts_with(prefix)).unwrap();
        assert!(hygiene::raw_tainted(token), "{prefix}... is not held");
    }
}

#[tokio::test]
async fn replace_goes_on_when_the_server_says_the_key_has_no_account() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace-none"));
    identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.with(|s| s.account_exists = false);
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert_eq!(
        run.line("init_erase"),
        "CANARY init_erase result=ok reason=ok erased=no_account"
    );
}

#[tokio::test]
async fn replace_stops_when_the_server_refuses_the_erase_for_any_other_reason() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace-refused"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let before = identity::load_key(&dir).unwrap().did();
    fake.quirks(|q| q.erase_refused = Some(401));
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1);
    assert_eq!(
        run.line("init_erase"),
        "CANARY init_erase result=FAIL reason=erase_failed status=401"
    );
    assert_eq!(
        identity::load_key(&dir).unwrap().did(),
        before,
        "nothing was replaced"
    );
    assert!(identity::client_exists(&dir));
}

#[tokio::test]
async fn replace_refuses_when_the_key_is_gone_but_the_record_names_an_account() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace-nokey"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    std::fs::remove_file(dir.join(identity::KEY_FILE)).unwrap();
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 2);
    assert_eq!(
        run.lines,
        vec![format!(
            "CANARY init_erase result=FAIL reason=key_missing mxid={}",
            fake.with(|s| s.mxid.clone())
        )]
    );
    assert!(
        identity::client_exists(&dir),
        "the record that names the account stays"
    );
    assert!(!fake.with(|s| s.erased));
}

#[tokio::test]
async fn replace_refuses_a_client_record_it_cannot_read() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace-garbage"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let before = identity::load_key(&dir).unwrap().did();
    std::fs::write(dir.join(identity::CLIENT_FILE), b"{ not json").unwrap();
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 2);
    assert_eq!(
        run.lines,
        vec!["CANARY init_identity result=FAIL reason=identity_unreadable".to_string()]
    );
    assert_eq!(
        identity::load_key(&dir).unwrap().did(),
        before,
        "the key is untouched"
    );
    assert!(!fake.with(|s| s.erased));
}

#[tokio::test]
async fn replace_of_a_record_that_never_learned_its_account_with_no_key_has_nothing_to_strand() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("replace-empty"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let mut record = identity::read_client(&dir).unwrap();
    record.mxid = String::new();
    identity::write_client(&dir, &record).unwrap();
    std::fs::remove_file(dir.join(identity::KEY_FILE)).unwrap();
    let run = run_init(init_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
}

#[tokio::test]
async fn no_matrix_with_a_revoke_that_revokes_nothing_fails_the_summary_exit_3() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("nomatrix-revoke"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.revoke_is_noop = true);
    let run = run_check(check_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 3, "{:#?}", run.lines);
    assert!(run.has("logout", "result=FAIL reason=logout_ineffective"));
    assert!(run.has("logout", "revoked=no"));
    assert_eq!(
        run.summary(),
        "CANARY summary checks_run=4 skipped=2 result=FAIL"
    );
    assert!(
        identity::read_ledger(&dir).attempts.is_empty(),
        "no Matrix side, no device, no marker"
    );
}

#[test]
fn a_proxy_named_by_the_environment_is_not_used() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hermetic::proxy_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ROTATION_CANARY_PROXY_CHILD", "1")
        // Nothing listens on the discard port: a request through it fails.
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("all_proxy", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run only by the test above, in a child process whose environment names a proxy.
#[tokio::test]
async fn proxy_child() {
    if std::env::var_os("ROTATION_CANARY_PROXY_CHILD").is_none() {
        return;
    }
    let fake = Fake::start().await;
    let http = crate::net::client().unwrap();
    let reply = crate::net::send(http.get(format!("{}/jwk", fake.base)))
        .await
        .expect("the request must go direct, not through HTTP_PROXY");
    assert_eq!(reply.status, 200);
}

// -- process-level hygiene --------------------------------------------------

#[test]
fn a_panic_prints_only_its_location_and_leaves_with_exit_70() {
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
    assert_eq!(
        out.status.code(),
        Some(70),
        "_exit(70): no unwinding, no SIGABRT for a crash handler: {all}"
    );
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
    // SAFETY: `PR_GET_DUMPABLE` takes plain integers.
    #[cfg(target_os = "linux")]
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
}

// ---------------------------------------------------------------------------
// Review round of PR #81: the fixes the audit tests above pin, and their edges.
// ---------------------------------------------------------------------------

/// A retired device (a proven logout, or a deletion) as the ledger holds it,
/// retired `ago` seconds ago.
fn retire(dir: &Path, id: &str, ago: i64) {
    let at = Utc::now().timestamp() - ago;
    identity::update_ledger(dir, |l| l.logged_out.insert(id.to_string(), at)).unwrap();
}

#[tokio::test]
async fn a_canary_named_device_recreated_on_a_retired_id_and_used_since_is_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("retired-used"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    retire(&dir, "SIWX_retired", 3_600);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_retired".to_string()]);
    // As the canary's client would name it, used a minute ago: after the canary
    // last used the id, an hour ago.
    describe(
        &fake,
        "SIWX_retired",
        Some("rotation-canary"),
        Some(seen_now_ms()),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=identity_compromised"));
    assert!(run.has("logout", "strangers=SIWX_retired"));
    assert!(
        fake.with(|s| s.quirks.extra_devices.contains(&"SIWX_retired".to_string())),
        "evidence stays"
    );
    assert!(identity::read_ledger(&dir)
        .logged_out
        .contains("SIWX_retired"));

    // The same id, last used before the canary retired it: its own survivor.
    let (fake, scratch) = (Fake::start().await, Scratch::new("retired-unused"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    retire(&dir, "SIWX_retired", 3_600);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_retired".to_string()]);
    describe(
        &fake,
        "SIWX_retired",
        Some("rotation-canary"),
        Some((Utc::now().timestamp() - 3_700) * 1000),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=device_survived_logout"));
    assert!(run.has("logout", "survivors=SIWX_retired"));
    assert!(run.has("logout", "tripwire=clean"));
}

#[tokio::test]
async fn init_s_device_on_a_retired_id_that_was_used_since_is_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("init-retired-used"));
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_init(init_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let dir = scratch.0.join("local");
    let init_device = fake.with(|s| s.device.clone());
    assert!(identity::read_ledger(&dir)
        .logged_out
        .contains(&init_device));
    // Init's logout was an hour ago and somebody used the device after it.
    retire(&dir, &init_device, 3_600);
    fake.quirks(|q| q.leave_device_on_logout = false);
    describe(
        &fake,
        &init_device,
        Some("rotation-canary"),
        Some(seen_now_ms()),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", &format!("strangers={init_device}")));
}

#[tokio::test]
async fn a_leftover_whose_delete_was_a_silent_noop_is_reported_next_time_not_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("leftover-noop"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    identity::update_ledger(&dir, |l| {
        l.pending.insert("SIWX_old".to_string());
    })
    .unwrap();
    fake.quirks(|q| {
        q.extra_devices = vec!["SIWX_old".to_string()];
        q.delete_device_is_noop = true;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(run.has("logout", "cleaned=1"));
    assert!(identity::read_ledger(&dir).logged_out.contains("SIWX_old"));

    // The 200 deleted nothing: the next run reports it, and does not fire.
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "reason=device_survived_logout"));
    assert!(run.has("logout", "survivors=SIWX_old"));

    // Once the server really deletes it, a run sees it gone and forgets it.
    fake.quirks(|q| q.delete_device_is_noop = false);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    assert!(!identity::read_ledger(&dir).logged_out.contains("SIWX_old"));
}

#[tokio::test]
async fn a_room_that_fired_the_tripwire_does_not_leave_a_marker_to_excuse_a_second_device() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("room-marker"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "earlier", 60);
    fake.quirks(|q| {
        q.rooms = 1;
        q.extra_devices = vec!["SIWX_first".to_string()];
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "unfinished=SIWX_first"));
    let ledger = identity::read_ledger(&dir);
    assert!(
        !ledger.pending.contains("SIWX_first") && !ledger.unfinished.contains("SIWX_first"),
        "a fired tripwire excuses and records nothing: {ledger:?}"
    );
    assert_eq!(ledger.attempts.len(), 1, "the marker stays as evidence");
    assert!(fake.with(|s| s.quirks.extra_devices.contains(&"SIWX_first".to_string())));

    // The room is gone, but a second device appeared: one marker covers one
    // device, not the first and the second.
    fake.quirks(|q| {
        q.rooms = 0;
        q.extra_devices = vec!["SIWX_first".to_string(), "SIWX_second".to_string()];
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    assert!(run.has("logout", "strangers=SIWX_first,SIWX_second"));
}

// ---------------------------------------------------------------------------
// Review of the tripwire fix (#81): each `audit_*` test states the secure
// expectation. `audit_a2` is a known gap, tracked in #84.
// ---------------------------------------------------------------------------

fn seen_now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// A1: a device excused as unfinished goes to `pending`; a later run tolerates
/// it as a leftover whatever happened to it since, so a device that was unseen
/// at run 1 and used afterwards is deleted with exit 0.
#[tokio::test]
async fn audit_a1_an_excused_device_used_afterwards_is_not_laundered_as_a_leftover() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a1"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "failed-run", 60);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_dormant".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "unfinished=SIWX_dormant"));
    // The holder of the device now uses its token.
    describe(
        &fake,
        "SIWX_dormant",
        Some("rotation-canary"),
        Some(seen_now_ms()),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(
        run.code, 4,
        "a device unseen when excused and seen now is a stranger's: {:#?}",
        run.lines
    );
}

/// A2: a fired tripwire is not sticky: a marker recorded after the fire (a
/// later run that failed before `/sign_in`) excuses the same devices.
#[tokio::test]
#[ignore = "known gap, tracked in #84 (item 1)"]
async fn audit_a2_a_fired_tripwire_is_not_excused_by_a_later_marker() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a2"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    leave_marker(&dir, "m1", 60);
    fake.quirks(|q| q.extra_devices = vec!["SIWX_x".to_string(), "SIWX_y".to_string()]);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 4, "{:#?}", run.lines);
    leave_marker(&dir, "m2", 0);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(
        run.code, 4,
        "the devices that fired the tripwire are excused now: {:#?}",
        run.lines
    );
}

/// A3: a run whose whoami failed on the revoke route (the device stays by
/// design) puts its own device on no list; Synapse marks it seen (the run's
/// own GET /devices used the token), so the next run fires exit 4.
#[tokio::test]
async fn audit_a3_a_failed_whoami_on_the_revoke_route_does_not_fire_the_next_run() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a3"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Revoke);
    fake.quirks(|q| q.whoami_status = Some(503));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    let left = fake.with(|s| s.signed_in_device.clone());
    assert!(fake.with(|s| s.devices.contains(&left)));
    // Not on any list was the bug; the run's one unexplained device is its own.
    let ledger = identity::read_ledger(&dir);
    assert!(
        ledger.pending.contains(&left),
        "the device stays by design: {ledger:?}"
    );
    fake.quirks(|q| q.whoami_status = None);
    // As Synapse lists it: run 1 used its token for joined_rooms and devices.
    describe(&fake, &left, Some("rotation-canary"), Some(seen_now_ms()));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_ne!(run.code, 4, "the canary's own device: {:#?}", run.lines);
}

/// A4: a device id on `logged_out` is a survivor by id alone. A stranger who
/// proposes that id at sign-in (siwx-oidc upserts a proposed id; with flag 2
/// off a deleted id is recreated) gets exit 1 and the evidence deleted.
#[tokio::test]
async fn audit_a4_a_stranger_on_a_logged_out_id_is_not_a_survivor() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a4"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let gone = fake.with(|s| s.device.clone());
    assert!(!fake.with(|s| s.devices.contains(&gone)));
    assert!(identity::read_ledger(&dir).logged_out.contains(&gone));
    // A stranger signs in proposing that id, and uses it.
    fake.quirks(|q| q.extra_devices = vec![gone.clone()]);
    describe(&fake, &gone, Some("Element Web"), Some(seen_now_ms()));
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(
        run.code, 4,
        "recreated after the proven logout and used: {:#?}",
        run.lines
    );
}

/// A5: the survivor's delete answers 200 (siwx-oidc's best-effort teardown)
/// but the device stays; it leaves `logged_out` on the 200 and the next run
/// takes the canary's own device for a stranger.
#[tokio::test]
async fn audit_a5_a_survivor_whose_delete_was_a_silent_noop_stays_on_the_ledger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a5"));
    let dir = identity_for(&scratch.0, &fake, LogoutRoute::Matrix);
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let survivor = fake.with(|s| s.device.clone());
    fake.quirks(|q| {
        q.leave_device_on_logout = false;
        q.delete_device_is_noop = true;
    });
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_eq!(run.code, 1, "{:#?}", run.lines);
    assert!(run.has("logout", "survivors_cleaned=1"));
    assert!(fake.with(|s| s.devices.contains(&survivor)), "still there");
    describe(
        &fake,
        &survivor,
        Some("rotation-canary"),
        Some(seen_now_ms()),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_ne!(
        run.code,
        4,
        "the canary's own device, whose deletion was answered 200: {:#?} ledger={:?}",
        run.lines,
        identity::read_ledger(&dir)
    );
}

/// A6: init's proven Matrix logout takes its device off the ledger without
/// putting it on `logged_out`, so a device that outlives init's logout fires
/// the first check (the #79 item 2 fix is not applied to init).
#[tokio::test]
async fn audit_a6_a_device_that_outlives_inits_logout_is_not_a_stranger() {
    let (fake, scratch) = (Fake::start().await, Scratch::new("audit-a6"));
    fake.quirks(|q| q.leave_device_on_logout = true);
    let run = run_init(init_cfg(&fake, false), &scratch.0).await;
    assert_eq!(run.code, 0, "{:#?}", run.lines);
    let init_device = fake.with(|s| s.device.clone());
    assert!(fake.with(|s| s.devices.contains(&init_device)));
    fake.quirks(|q| q.leave_device_on_logout = false);
    describe(
        &fake,
        &init_device,
        Some("rotation-canary"),
        Some(seen_now_ms()),
    );
    let run = run_check(check_cfg(&fake, true), &scratch.0).await;
    assert_ne!(run.code, 4, "init's own device: {:#?}", run.lines);
}
