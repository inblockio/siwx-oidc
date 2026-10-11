//! The guest claim, server half (S7a, design 07 M9a, 05 section 4).
//!
//! `POST /guest/claim/start` and `POST /guest/claim/finish` turn a live guest into a kept
//! account: a passkey is registered against the guest's own `did:key` (the DID never
//! changes, GP-CLM-09), and one Lua compare-and-set moves the record `active` to
//! `claimed`. The server never held a guest key (A1), so nothing is destroyed at the
//! commit; "the guest DID is claimed" is the record state, which `/guest/continue` and
//! Path B of `sign_in` refuse from then on (a claimed account signs in with its passkey).
//!
//! Authorised by the `__Host-guest_session` cookie only; a Bearer token is refused. The
//! origin check and the JSON-only rule are the layers' (see [`super::layers`]).
//!
//! Order of `finish` (GP-CLM-06): lock (`SET NX EX 30`), gate, `link_finish` (credential
//! written, set-if-absent), compare-and-set. A lost compare-and-set deletes exactly the
//! credential this call wrote and answers 409. After the commit the pre-claim devices are
//! revoked one by one (never `revoke_all_user_tokens`, which would lock the claimant out).
//!
//! Refusals (all `guest_refused` audit events, route `claim_start` / `claim_finish`):
//! 401 `no_session`; 410 `ended`; 409 `already_claimed`, `claim_in_progress`, `lost_race`;
//! 403 `claim_unavailable`; 400 `bad_request`, `verify_failed`; 503 `unavailable`.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use siwx_oidc::db::guest_records::{ClaimCas, ClaimRead};
use siwx_oidc::db::RedisClient;
use tracing::{info, warn};
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use super::handoff::{bearer_token, cookie_value, guest_cookie_name, guest_kill_switch_engaged};
use super::invite::GuestState;
use super::layers::error;
use crate::oidc::CustomError;

const START: &str = "claim_start";
const FINISH: &str = "claim_finish";

async fn refuse(
    state: &GuestState,
    route: &'static str,
    status: StatusCode,
    code: &'static str,
) -> Response {
    super::audit::refused(&state.redis, route, code).await;
    error(status, code)
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

/// The cookie handle and its hash. A request carrying a Bearer token is refused outright:
/// the claim is authorised by the cookie alone.
#[allow(clippy::result_large_err)]
async fn handle_of(
    state: &GuestState,
    headers: &HeaderMap,
    route: &'static str,
) -> Result<(String, String), Response> {
    if bearer_token(headers).is_some() {
        return Err(refuse(state, route, StatusCode::UNAUTHORIZED, "no_session").await);
    }
    match cookie_value(headers, guest_cookie_name(&state.config)) {
        Some(h) if !h.is_empty() => {
            let hash = siwx_oidc::db::guest_records::handle_hash(&h);
            Ok((h, hash))
        }
        _ => Err(refuse(state, route, StatusCode::UNAUTHORIZED, "no_session").await),
    }
}

/// Whether the room's state lists `mxid` as joined.
fn is_joined(events: &[Value], mxid: &str) -> bool {
    events.iter().any(|e| {
        e["type"] == "m.room.member"
            && e["state_key"] == mxid
            && e["content"]["membership"] == "join"
    })
}

/// The claim gate (CP-01..06, CP-11, CP-12). Run at start and again at finish.
#[allow(clippy::result_large_err)]
async fn gate(
    state: &GuestState,
    handle: &str,
    route: &'static str,
) -> Result<ClaimRead, Response> {
    let cfg = &state.config;
    if !cfg.guest_claim_enabled {
        return Err(refuse(state, route, StatusCode::FORBIDDEN, "claim_unavailable").await);
    }
    match guest_kill_switch_engaged(&state.redis).await {
        Ok(false) => {}
        Ok(true) => {
            return Err(refuse(state, route, StatusCode::FORBIDDEN, "claim_unavailable").await)
        }
        Err(e) => {
            warn!(error = %e, "guest claim: kill switch unreadable");
            return Err(unavailable());
        }
    }
    let session = match state.redis.read_guest_session(handle).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "guest claim: record lookup failed");
            return Err(unavailable());
        }
    };
    let Some(session) = session else {
        // The handle of a claimed guest resolves for ten minutes: a duplicate or a retry
        // after a lost response must read 409, never "no session".
        return Err(match state.redis.read_claimed_handle(handle).await {
            Ok(Some(_)) => refuse(state, route, StatusCode::CONFLICT, "already_claimed").await,
            Ok(None) => refuse(state, route, StatusCode::UNAUTHORIZED, "no_session").await,
            Err(e) => {
                warn!(error = %e, "guest claim: claimed marker unreadable");
                unavailable()
            }
        });
    };
    let rec = match state.redis.read_claim(&session.localpart).await {
        Ok(Some(r)) => r,
        Ok(None) => return Err(refuse(state, route, StatusCode::UNAUTHORIZED, "no_session").await),
        Err(e) => {
            warn!(error = %e, "guest claim: record read failed");
            return Err(unavailable());
        }
    };
    match rec.state.as_str() {
        "active" => {}
        "claimed" => {
            return Err(refuse(state, route, StatusCode::CONFLICT, "already_claimed").await)
        }
        "reaping" => return Err(refuse(state, route, StatusCode::GONE, "ended").await),
        // minted / provisioning (no account yet, or half-made) and anything unknown.
        _ => return Err(refuse(state, route, StatusCode::FORBIDDEN, "claim_unavailable").await),
    }
    if rec.deadline.is_none_or(|d| rec.now >= d) {
        return Err(refuse(state, route, StatusCode::GONE, "ended").await);
    }
    if rec.host_banned || rec.claimed_count >= cfg.guest_max_claimed {
        return Err(refuse(state, route, StatusCode::FORBIDDEN, "claim_unavailable").await);
    }

    // CP-06 and CP-11: the Synapse account exists and is active, and it is joined to its
    // invite's room. Fail closed: a probe fault is 503, never a pass.
    let (Some(synapse), Some(server_name)) =
        (state.synapse.as_deref(), cfg.matrix_server_name.as_deref())
    else {
        return Err(unavailable());
    };
    let new_identity = crate::webauthn::reject_if_new_identity(Some(synapse), &rec.did).await;
    let deactivated = match new_identity {
        Ok(()) => crate::webauthn::reject_if_deactivated(Some(synapse), &rec.did).await,
        e => e,
    };
    match deactivated {
        Ok(()) => {}
        Err(CustomError::ServiceUnavailable(_)) => return Err(unavailable()),
        Err(_) => return Err(refuse(state, route, StatusCode::GONE, "ended").await),
    }
    let mxid = format!("@{}:{}", rec.localpart, server_name);
    match synapse.room_state(&rec.room_id).await {
        Ok(Some(events)) if is_joined(&events, &mxid) => {}
        Ok(_) => return Err(refuse(state, route, StatusCode::GONE, "ended").await),
        Err(e) => {
            warn!(error = %e, "guest claim: room membership unreadable");
            return Err(unavailable());
        }
    }
    Ok(rec)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ceremony_id(hash: &str) -> String {
    format!("claim_{hash}")
}

/// `POST /guest/claim/start`: WebAuthn creation options for the guest's own DID. Idempotent:
/// it replaces the pending challenge.
pub async fn start(
    State(state): State<GuestState>,
    headers: HeaderMap,
    // Read only so the 4 KiB body cap applies; the body carries nothing.
    _body: Bytes,
) -> Response {
    let (handle, hash) = match handle_of(&state, &headers, START).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    let rec = match gate(&state, &handle, START).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Some(webauthn) = state.webauthn.as_deref() else {
        return refuse(&state, START, StatusCode::FORBIDDEN, "claim_unavailable").await;
    };
    let typed = format!("{} {}", rec.first_name, rec.second_name);
    let typed = typed.trim();
    let label = (!typed.is_empty()).then(|| typed.to_string());
    match crate::webauthn::link_start(webauthn, &state.redis, &ceremony_id(&hash), &rec.did, label)
        .await
    {
        Ok(ccr) => no_store(Json(ccr).into_response()),
        Err(e) => {
            warn!(error = %e, "guest claim start: link_start failed");
            unavailable()
        }
    }
}

/// `POST /guest/claim/finish`: the attestation (and `keep_email`), the commit, the cookie.
pub async fn finish(State(state): State<GuestState>, headers: HeaderMap, body: Bytes) -> Response {
    let (handle, hash) = match handle_of(&state, &headers, FINISH).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    let parsed = serde_json::from_slice::<Value>(&body).ok().and_then(|v| {
        let keep_email = v
            .get("keep_email")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        serde_json::from_value::<RegisterPublicKeyCredential>(v)
            .ok()
            .map(|c| (c, keep_email))
    });
    let Some((credential, keep_email)) = parsed else {
        return refuse(&state, FINISH, StatusCode::BAD_REQUEST, "bad_request").await;
    };
    let token = uuid::Uuid::new_v4().simple().to_string();
    match state.redis.take_claim_lock(&hash, &token).await {
        Ok(true) => {}
        Ok(false) => {
            return refuse(&state, FINISH, StatusCode::CONFLICT, "claim_in_progress").await
        }
        Err(e) => {
            warn!(error = %e, "guest claim: lock unavailable");
            return unavailable();
        }
    }
    let response = finish_locked(&state, &handle, &hash, credential, keep_email).await;
    state.redis.release_claim_lock(&hash, &token).await;
    response
}

async fn finish_locked(
    state: &GuestState,
    handle: &str,
    hash: &str,
    credential: RegisterPublicKeyCredential,
    keep_email: bool,
) -> Response {
    let rec = match gate(state, handle, FINISH).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Some(webauthn) = state.webauthn.as_deref() else {
        return refuse(state, FINISH, StatusCode::FORBIDDEN, "claim_unavailable").await;
    };
    // The credential write. An error before it (no challenge, bad attestation, a credential
    // id that is already known) wrote nothing and compensates nothing.
    let linked =
        match crate::webauthn::link_finish(webauthn, &state.redis, &ceremony_id(hash), credential)
            .await
        {
            Ok(l) if l.primary_did == rec.did => l,
            Ok(l) => {
                // Cannot happen (the DID is the challenge's); undo what this call wrote.
                let _ = crate::webauthn::delete_linked_credential(
                    &state.redis,
                    &l.credential_id,
                    &l.primary_did,
                )
                .await;
                return refuse(state, FINISH, StatusCode::BAD_REQUEST, "verify_failed").await;
            }
            Err(e) => {
                info!(error = %e, "guest claim finish: credential refused");
                return refuse(state, FINISH, StatusCode::BAD_REQUEST, "verify_failed").await;
            }
        };
    let cas = state
        .redis
        .commit_guest_claim(
            &rec.localpart,
            hash,
            &linked.credential_id,
            state.config.guest_max_claimed,
            keep_email,
        )
        .await;
    let cas = match cas {
        Ok(c) => c,
        Err(e) => {
            // The outcome is unknown: compensating could leave a claimed account with no
            // credential. Leave the credential (the reaper's teardown of an unclaimed
            // guest removes what is listed under its DID) and let the guest retry.
            warn!(error = %e, "guest claim: commit failed");
            return unavailable();
        }
    };
    if cas != ClaimCas::Claimed {
        if let Err(e) =
            crate::webauthn::delete_linked_credential(&state.redis, &linked.credential_id, &rec.did)
                .await
        {
            warn!(error = %e, "guest claim: compensation failed");
        }
        return match cas {
            ClaimCas::Already => {
                refuse(state, FINISH, StatusCode::CONFLICT, "already_claimed").await
            }
            ClaimCas::Capped => {
                refuse(state, FINISH, StatusCode::FORBIDDEN, "claim_unavailable").await
            }
            _ => refuse(state, FINISH, StatusCode::CONFLICT, "lost_race").await,
        };
    }

    super::audit::claimed(
        &rec.localpart,
        &rec.invite_id,
        &siwx_oidc::redact::fingerprint(&linked.credential_id),
    );
    // Revoke the pre-claim devices; a failure stays in `guest:claim_revoke` for the reaper.
    if let Err(e) = finish_claim_revoke(&state.redis, &rec.localpart).await {
        warn!(error = %e, "guest claim: device revocation deferred to the reaper");
    }
    let mut response = no_store(Json(json!({"state": "claimed"})).into_response());
    match state.redis.create_user_session(&rec.did).await {
        Ok(token) => {
            let cookie = crate::axum_lib::user_cookie_set(&state.config.base_url, &token);
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(header::SET_COOKIE, v);
            }
        }
        Err(e) => warn!(error = %e, "guest claim: siwx_user cookie not minted"),
    }
    response
}

/// Revoke the tokens of every device the guest held at the commit, one by one, then take the
/// localpart off `guest:claim_revoke`. Idempotent: the reaper tick runs it for what a crash
/// left behind. The Synapse device rows stay (GP-CLM-11); only the Redis grants die.
pub async fn finish_claim_revoke(redis: &RedisClient, localpart: &str) -> anyhow::Result<()> {
    for device in redis.read_pre_claim_devices(localpart).await? {
        redis.revoke_device_tokens(localpart, &device).await?;
    }
    redis.claim_revoke_done(localpart).await
}

#[cfg(test)]
mod tests {
    //! Driven over a real socket through the whole guest stack, against a real Redis and an
    //! in-process Synapse mock. The authenticator is hand-made: a P-256 key and a `none`
    //! attestation, which is all `webauthn-rs` needs to register a passkey.
    use super::*;
    use crate::config::Config;
    use crate::synapse_client::SynapseClient;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use sha2::{Digest, Sha256};
    use siwx_oidc::db::guest_records::{devices_key, CLAIMED_KEY};
    use siwx_oidc::db::{DBClient, TokenKind, TokenMetadata};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const ISSUER: &str = "https://id.example.org";
    const SERVER: &str = "matrix.example.org";
    const ROOM: &str = "!room:matrix.example.org";

    fn uniq() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[derive(Default)]
    struct Synapse {
        existing: HashSet<String>,
        deactivated: bool,
        joined: HashSet<String>,
        room_status: Option<u16>,
        down: bool,
    }

    struct Env {
        base: String,
        redis: RedisClient,
        config: Config,
        synapse: Arc<Mutex<Synapse>>,
        http: reqwest::Client,
    }

    struct Guest {
        localpart: String,
        did: String,
        handle: String,
    }

    async fn env(db: Option<u8>, edit: impl Fn(&mut Config)) -> Option<Env> {
        let redis = match db {
            None => siwx_oidc::test_support::redis().await?,
            Some(n) => siwx_oidc::test_support::redis_db(n).await?,
        };
        let synapse = Arc::new(Mutex::new(Synapse::default()));
        let mock = synapse.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let mock = mock.clone();
            async move {
                let path = req.uri().path().to_string();
                let query = req.uri().query().unwrap_or_default().to_string();
                let lp = query.strip_prefix("localpart=").unwrap_or_default().to_string();
                let m = mock.lock().unwrap();
                if m.down {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
                }
                if path == "/_synapse/mas/is_localpart_available" {
                    return if m.existing.contains(&lp) {
                        (StatusCode::BAD_REQUEST, Json(json!({"errcode": "M_USER_IN_USE", "error": "taken"}))).into_response()
                    } else {
                        (StatusCode::OK, Json(json!({"available": true}))).into_response()
                    };
                }
                if path == "/_synapse/mas/query_user" {
                    return if m.existing.contains(&lp) {
                        Json(json!({"user_id": format!("@{lp}:{SERVER}"), "is_deactivated": m.deactivated})).into_response()
                    } else {
                        (StatusCode::NOT_FOUND, Json(json!({"errcode": "M_NOT_FOUND"}))).into_response()
                    };
                }
                if path.starts_with("/_synapse/admin/v1/rooms/") {
                    if let Some(code) = m.room_status {
                        return (StatusCode::from_u16(code).unwrap(), Json(json!({}))).into_response();
                    }
                    let state: Vec<Value> = m.joined.iter().map(|mxid| json!({"type": "m.room.member", "state_key": mxid, "content": {"membership": "join"}})).collect();
                    return Json(json!({"state": state})).into_response();
                }
                (StatusCode::OK, Json(json!({}))).into_response()
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let client = SynapseClient::new(&format!("http://{addr}"), "secret").with_admin_mint(
            redis.clone(),
            "siwx-admin".into(),
            300,
        );
        let mut config = Config {
            guest_enabled: true,
            guest_claim_enabled: true,
            base_url: url::Url::parse(ISSUER).unwrap(),
            matrix_server_name: Some(SERVER.into()),
            ..Config::default()
        };
        edit(&mut config);
        let wa = crate::webauthn::build_webauthn(&config.base_url, None, None).unwrap();
        let app = super::super::routes::router_with(
            &config,
            redis.clone(),
            Some(Arc::new(client)),
            Some(Arc::new(wa.webauthn)),
        );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Some(Env {
            base: format!("http://{addr}"),
            redis,
            config,
            synapse,
            http: reqwest::Client::new(),
        })
    }

    /// A live, admitted guest: record `active`, due in ten minutes, two devices with a
    /// live token each, its Synapse account present and joined to the room.
    async fn guest(e: &Env) -> Guest {
        let id = uniq();
        let did = format!("did:key:z6Mk{id}");
        let localpart = siwx_oidc::mxid::localpart_for(&did);
        let handle = uniq();
        e.redis
            .put_guest_for_test(&localpart, &did, "active", 600, &handle)
            .await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&localpart);
        for (f, v) in [
            ("invite_id", format!("inv{id}")),
            ("room_id", ROOM.to_string()),
            ("host", format!("host{id}")),
            ("first_name", "Erika".into()),
            ("second_name", "Muster".into()),
            ("email", "erika@example.org".into()),
        ] {
            e.redis.hset_for_test(&key, f, &v).await;
        }
        let score = e.redis.due_score_for_test(&localpart).await;
        assert!(score.is_none());
        e.redis
            .due_add_for_test(&localpart, chrono::Utc::now().timestamp() + 600)
            .await;
        for d in ["DEVA", "DEVB"] {
            e.redis.sadd_raw_for_test(&devices_key(&localpart), d).await;
        }
        {
            let mut s = e.synapse.lock().unwrap();
            s.existing.insert(localpart.clone());
            s.joined.insert(format!("@{localpart}:{SERVER}"));
        }
        Guest {
            localpart,
            did,
            handle,
        }
    }

    async fn token(e: &Env, g: &Guest, device: &str) -> String {
        let t = format!("mat_{}", uniq());
        let meta = TokenMetadata {
            username: g.localpart.clone(),
            device_id: device.into(),
            scope: "openid".into(),
            client_id: "c".into(),
            iat: 0,
            exp: i64::MAX,
            did: g.did.clone(),
            name: "n".into(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        };
        e.redis.set_token(&t, &meta, 300).await.unwrap();
        t
    }

    fn cookie(e: &Env, g: &Guest) -> String {
        format!("{}={}", guest_cookie_name(&e.config), g.handle)
    }

    async fn post(
        e: &Env,
        path: &str,
        cookie: Option<&str>,
        bearer: Option<&str>,
        body: String,
    ) -> (u16, Value, HeaderMap) {
        let mut r = e
            .http
            .post(format!("{}{path}", e.base))
            .header("content-type", "application/json")
            .header("origin", ISSUER)
            .header("sec-fetch-site", "same-origin");
        if let Some(c) = cookie {
            r = r.header("cookie", c);
        }
        if let Some(b) = bearer {
            r = r.bearer_auth(b);
        }
        let r = r.body(body).send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        (status, r.json().await.unwrap_or(Value::Null), headers)
    }

    async fn start(e: &Env, g: &Guest) -> (u16, Value) {
        let (s, v, _) = post(
            e,
            "/guest/claim/start",
            Some(&cookie(e, g)),
            None,
            "{}".into(),
        )
        .await;
        (s, v)
    }

    /// A software authenticator: a fresh P-256 credential, registered with a `none`
    /// attestation over the challenge `start` returned.
    fn attest(options: &Value, cred_id: &[u8]) -> Value {
        let pk = &options["publicKey"];
        let challenge = pk["challenge"].as_str().expect("challenge");
        let rp_id = pk["rp"]["id"].as_str().expect("rp id");
        let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x().unwrap(), point.y().unwrap());
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(y);
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(0x45); // UP, UV, AT
        auth.extend_from_slice(&[0, 0, 0, 0]);
        auth.extend_from_slice(&[0u8; 16]);
        auth.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(cred_id);
        auth.extend_from_slice(&cose);
        let mut att = vec![0xa3, 0x63];
        att.extend_from_slice(b"fmt");
        att.push(0x64);
        att.extend_from_slice(b"none");
        att.push(0x67);
        att.extend_from_slice(b"attStmt");
        att.push(0xa0);
        att.push(0x68);
        att.extend_from_slice(b"authData");
        att.push(0x59);
        att.extend_from_slice(&(auth.len() as u16).to_be_bytes());
        att.extend_from_slice(&auth);
        let client_data = json!({"type": "webauthn.create", "challenge": challenge, "origin": ISSUER, "crossOrigin": false});
        json!({
            "id": B64.encode(cred_id),
            "rawId": B64.encode(cred_id),
            "type": "public-key",
            "response": {
                "attestationObject": B64.encode(&att),
                "clientDataJSON": B64.encode(client_data.to_string()),
            },
            "extensions": {},
        })
    }

    async fn finish(e: &Env, g: &Guest, body: &Value) -> (u16, Value, HeaderMap) {
        post(
            e,
            "/guest/claim/finish",
            Some(&cookie(e, g)),
            None,
            body.to_string(),
        )
        .await
    }

    /// Start, attest, finish: the whole ceremony for `g` with credential id `cred`.
    async fn claim(e: &Env, g: &Guest, cred: &[u8]) -> (u16, Value, HeaderMap) {
        let (s, opts) = start(e, g).await;
        assert_eq!(s, 200, "start: {opts}");
        finish(e, g, &attest(&opts, cred)).await
    }

    async fn state_of(e: &Env, g: &Guest) -> Option<String> {
        e.redis
            .read_claim(&g.localpart)
            .await
            .unwrap()
            .map(|r| r.state)
    }

    /// CP-01..06, CP-11, CP-12 and the kill switch: each alone refuses `start` and `finish`
    /// with its own code and writes nothing; the untouched guest passes.
    #[tokio::test]
    async fn every_gate_condition_refuses_alone() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let Some(ctl) = env(Some(4), |_| {}).await else {
            return;
        };
        let Some(capped) = env(None, |c| c.guest_max_claimed = 0).await else {
            return;
        };
        let Some(off) = env(None, |c| c.guest_claim_enabled = false).await else {
            return;
        };

        // Records changed to state `s`.
        for (state, want) in [
            ("minted", (403, "claim_unavailable")),
            ("provisioning", (403, "claim_unavailable")),
            ("reaping", (410, "ended")),
            ("claimed", (409, "already_claimed")),
        ] {
            let g = guest(&e).await;
            e.redis
                .hset_for_test(
                    &siwx_oidc::db::guest_invites::guest_account_key(&g.localpart),
                    "state",
                    state,
                )
                .await;
            let (s, v) = start(&e, &g).await;
            assert_eq!((s, v["error"].as_str().unwrap()), want, "state {state}");
        }
        // Past the deadline by Redis TIME.
        let g = guest(&e).await;
        e.redis
            .hset_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&g.localpart),
                "deadline",
                "1",
            )
            .await;
        assert_eq!(start(&e, &g).await.0, 410);
        // Host banned.
        let g = guest(&e).await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&g.localpart);
        let host = format!("banned{}", uniq());
        e.redis.hset_for_test(&key, "host", &host).await;
        e.redis
            .sadd_raw_for_test(siwx_oidc::db::guest_invites::BANNED_HOSTS_KEY, &host)
            .await;
        assert_eq!(start(&e, &g).await.1["error"], "claim_unavailable");
        // Account deactivated, account missing, not in the room, room unknown, Synapse down.
        let g = guest(&e).await;
        e.synapse.lock().unwrap().deactivated = true;
        assert_eq!(start(&e, &g).await, (410, json!({"error": "ended"})));
        e.synapse.lock().unwrap().deactivated = false;
        e.synapse.lock().unwrap().existing.remove(&g.localpart);
        assert_eq!(start(&e, &g).await.0, 410, "account missing");
        e.synapse
            .lock()
            .unwrap()
            .existing
            .insert(g.localpart.clone());
        e.synapse.lock().unwrap().joined.clear();
        assert_eq!(start(&e, &g).await.0, 410, "not in the room");
        e.synapse
            .lock()
            .unwrap()
            .joined
            .insert(format!("@{}:{SERVER}", g.localpart));
        e.synapse.lock().unwrap().room_status = Some(404);
        assert_eq!(start(&e, &g).await.0, 410, "room unknown");
        e.synapse.lock().unwrap().room_status = Some(500);
        assert_eq!(start(&e, &g).await.0, 503, "a probe fault is never a pass");
        e.synapse.lock().unwrap().room_status = None;
        e.synapse.lock().unwrap().down = true;
        assert_eq!(start(&e, &g).await.0, 503);
        e.synapse.lock().unwrap().down = false;
        // The flag, the cap, the kill switch.
        let g2 = guest(&off).await;
        assert_eq!(start(&off, &g2).await.1["error"], "claim_unavailable");
        let g3 = guest(&capped).await;
        assert_eq!(start(&capped, &g3).await.1["error"], "claim_unavailable");
        let g4 = guest(&ctl).await;
        assert_eq!(start(&ctl, &g4).await.0, 200, "before the switch");
        ctl.redis
            .hset_for_test("guest:control", "disabled", "1")
            .await;
        assert_eq!(start(&ctl, &g4).await.1["error"], "claim_unavailable");
        ctl.redis
            .hset_for_test("guest:control", "disabled", "0")
            .await;
        // No cookie, an unknown handle, a Bearer token (even beside a valid cookie).
        let g = guest(&e).await;
        let (s, v, _) = post(&e, "/guest/claim/start", None, None, "{}".into()).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (401, "no_session"));
        let (s, _, _) = post(
            &e,
            "/guest/claim/start",
            Some(&format!("{}=nope", guest_cookie_name(&e.config))),
            None,
            "{}".into(),
        )
        .await;
        assert_eq!(s, 401);
        let t = token(&e, &g, "DEVA").await;
        let (s, v, _) = post(
            &e,
            "/guest/claim/start",
            Some(&cookie(&e, &g)),
            Some(&t),
            "{}".into(),
        )
        .await;
        assert_eq!(
            (s, v["error"].as_str().unwrap()),
            (401, "no_session"),
            "Bearer refused"
        );
        let (s, _, _) = post(&e, "/guest/claim/finish", None, Some(&t), "{}".into()).await;
        assert_eq!(s, 401);
        // The untouched guest passes, and nothing above wrote a claim.
        assert_eq!(start(&e, &g).await.0, 200);
        assert_eq!(state_of(&e, &g).await.as_deref(), Some("active"));
    }

    /// The whole claim: state, due entry, DID, devices, cookies, and every reader after it.
    #[tokio::test]
    async fn the_claim_commits_and_every_reader_follows() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let g = guest(&e).await;
        let t_a = token(&e, &g, "DEVA").await;
        let t_b = token(&e, &g, "DEVB").await;
        let t_other = token(&e, &g, "DEVC").await;
        assert!(e.redis.due_score_for_test(&g.localpart).await.is_some());
        let cred = format!("cred-{}", uniq());
        let (s, v, h) = claim(&e, &g, cred.as_bytes()).await;
        assert_eq!((s, v), (200, json!({"state": "claimed"})));
        assert!(
            h.get_all(header::SET_COOKIE)
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("siwx_user=")),
            "siwx_user set"
        );
        // State and the schedule.
        let rec = e.redis.read_claim(&g.localpart).await.unwrap().unwrap();
        assert_eq!(
            (rec.state.as_str(), rec.did.as_str()),
            ("claimed", g.did.as_str()),
            "DID unchanged"
        );
        assert_eq!(rec.deadline, None);
        assert!(!rec.email_present, "e-mail dropped without keep_email");
        assert!(
            e.redis.due_score_for_test(&g.localpart).await.is_none(),
            "off guest:due"
        );
        assert!(e
            .redis
            .smembers_raw(CLAIMED_KEY)
            .await
            .unwrap()
            .contains(&g.localpart));
        assert_eq!(
            e.redis.read_pre_claim_devices(&g.localpart).await.unwrap(),
            ["DEVA", "DEVB"]
        );
        assert!(
            e.redis
                .pending_claim_revokes()
                .await
                .unwrap()
                .iter()
                .all(|l| l != &g.localpart),
            "revocation finished"
        );
        // Per-device revoke: the guest's devices die, nothing else.
        assert!(e.redis.check_access_token(&t_a).await.unwrap().is_none());
        assert!(e.redis.check_access_token(&t_b).await.unwrap().is_none());
        assert!(
            e.redis
                .check_access_token(&t_other)
                .await
                .unwrap()
                .is_some(),
            "not a recorded device"
        );
        // The credential is linked to the same DID.
        let link = e
            .redis
            .get_raw(&format!("webauthn:link/{}", B64.encode(cred.as_bytes())))
            .await
            .unwrap()
            .unwrap();
        assert!(link.contains(&g.did));
        // Readers: resume says claimed, end 409 on the cookie, a repeat claim 409, continue refused.
        let c = cookie(&e, &g);
        let r = e
            .http
            .get(format!("{}/guest/resume", e.base))
            .header("cookie", &c)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.json::<Value>().await.unwrap(),
            json!({"state": "claimed"})
        );
        let (s, v, _) = post(&e, "/guest/end", Some(&c), None, "{}".into()).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (409, "claimed"));
        let (s, v) = start(&e, &g).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (409, "already_claimed"));
        let (s, _, _) = post(&e, "/guest/continue", Some(&c), None, json!({"redirect_uri": "https://meet.example.org/cb", "message": "m", "signature": "s"}).to_string()).await;
        assert_eq!(s, 401, "/guest/continue refuses a claimed account");
        assert!(
            e.redis
                .read_guest_session(&g.handle)
                .await
                .unwrap()
                .is_none(),
            "no live session behind the handle"
        );
        // The refresh guard passes a claimed account, with no deadline left to pass.
        let read = e
            .redis
            .guest_refresh_read(&g.localpart, "FRESH")
            .await
            .unwrap();
        assert!(read.deadline.is_none());
        assert!(super::super::handoff::refresh_verdict(&read));
        // The reaper never takes it, even with a stale schedule entry.
        e.redis.due_add_for_test(&g.localpart, 1).await;
        assert_eq!(
            e.redis.cas_guest_reaping(&g.localpart).await.unwrap(),
            siwx_oidc::db::guest_records::ReapCas::Claimed
        );
        assert_eq!(
            e.redis.end_guest_now(&g.localpart).await.unwrap(),
            siwx_oidc::db::guest_records::EndOutcome::Claimed
        );
        assert_eq!(state_of(&e, &g).await.as_deref(), Some("claimed"));
    }

    /// `keep_email: true` keeps the address.
    #[tokio::test]
    async fn keep_email_keeps_the_address() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let g = guest(&e).await;
        let (s, opts) = start(&e, &g).await;
        assert_eq!(s, 200);
        let mut body = attest(&opts, format!("cred-{}", uniq()).as_bytes());
        body["keep_email"] = json!(true);
        assert_eq!(finish(&e, &g, &body).await.0, 200);
        assert!(
            e.redis
                .read_claim(&g.localpart)
                .await
                .unwrap()
                .unwrap()
                .email_present
        );
    }

    /// ST-38: N concurrent finishes of one ceremony make exactly one claim.
    #[tokio::test]
    async fn st38_concurrent_finishes_make_one_claim() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let e = Arc::new(e);
        let g = Arc::new(guest(&e).await);
        let (s, opts) = start(&e, &g).await;
        assert_eq!(s, 200);
        let body = Arc::new(attest(&opts, format!("cred-{}", uniq()).as_bytes()));
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let (e, g, body) = (e.clone(), g.clone(), body.clone());
            tasks.push(tokio::spawn(async move { finish(&e, &g, &body).await }));
        }
        let mut ok = 0;
        for t in tasks {
            let (s, v, _) = t.await.unwrap();
            match s {
                200 => ok += 1,
                409 => assert!(
                    matches!(
                        v["error"].as_str(),
                        Some("claim_in_progress" | "already_claimed")
                    ),
                    "{v}"
                ),
                400 => assert_eq!(v["error"], "verify_failed"),
                other => panic!("unexpected {other}: {v}"),
            }
        }
        assert_eq!(ok, 1, "exactly one claim");
        assert_eq!(state_of(&e, &g).await.as_deref(), Some("claimed"));
        let members = e.redis.smembers_raw(CLAIMED_KEY).await.unwrap();
        assert_eq!(members.iter().filter(|m| **m == g.localpart).count(), 1);
    }

    /// A finish that names a known credential id is refused and leaves the first credential
    /// alone (GP-CLM-02, G3).
    #[tokio::test]
    async fn a_known_credential_id_is_refused_and_untouched() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let (a, b) = (guest(&e).await, guest(&e).await);
        let cred = format!("cred-{}", uniq());
        assert_eq!(claim(&e, &a, cred.as_bytes()).await.0, 200);
        let key = format!("webauthn:link/{}", B64.encode(cred.as_bytes()));
        let before = e.redis.get_raw(&key).await.unwrap().unwrap();
        let (s, v, _) = claim(&e, &b, cred.as_bytes()).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (400, "verify_failed"));
        assert_eq!(
            e.redis.get_raw(&key).await.unwrap().unwrap(),
            before,
            "still A's"
        );
        assert_eq!(state_of(&e, &b).await.as_deref(), Some("active"));
    }

    /// The reaper (or the clock) winning between the credential and the commit: the CAS
    /// refuses, nothing but the record changes, and the compensation deletes only a link that
    /// names the DID.
    #[tokio::test]
    async fn a_lost_commit_changes_nothing_and_compensation_is_bound_to_the_did() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let r = &e.redis;
        for (how, field, value) in [
            ("reaping", "state", "reaping"),
            ("past deadline", "deadline", "1"),
            ("promoted", "promoted_at", "1"),
        ] {
            let g = guest(&e).await;
            let key = siwx_oidc::db::guest_invites::guest_account_key(&g.localpart);
            r.hset_for_test(&key, field, value).await;
            let cas = r
                .commit_guest_claim(
                    &g.localpart,
                    &siwx_oidc::db::guest_records::handle_hash(&g.handle),
                    "c",
                    200,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(cas, ClaimCas::Lost, "{how}");
            assert!(
                !r.smembers_raw(CLAIMED_KEY)
                    .await
                    .unwrap()
                    .contains(&g.localpart),
                "{how}"
            );
            assert!(
                r.read_pre_claim_devices(&g.localpart)
                    .await
                    .unwrap()
                    .is_empty(),
                "{how}"
            );
        }
        assert_eq!(
            r.commit_guest_claim("nobody", "h", "c", 200, false)
                .await
                .unwrap(),
            ClaimCas::Gone
        );
        // Compensation: a link that names another DID is not deleted.
        let g = guest(&e).await;
        let cred = format!("cred-{}", uniq());
        assert_eq!(claim(&e, &g, cred.as_bytes()).await.0, 200);
        let id = B64.encode(cred.as_bytes());
        assert!(
            !crate::webauthn::delete_linked_credential(r, &id, "did:key:zSomeoneElse")
                .await
                .unwrap()
        );
        assert!(r
            .get_raw(&format!("webauthn:credential/{id}"))
            .await
            .unwrap()
            .is_some());
        assert!(crate::webauthn::delete_linked_credential(r, &id, &g.did)
            .await
            .unwrap());
        assert!(r
            .get_raw(&format!("webauthn:credential/{id}"))
            .await
            .unwrap()
            .is_none());
        assert!(r
            .get_raw(&format!("webauthn:link/{id}"))
            .await
            .unwrap()
            .is_none());
    }

    /// The finish gate runs again: a guest removed from the room between start and finish is
    /// refused before any credential is written. A repeat finish after the lock is held.
    #[tokio::test]
    async fn finish_repeats_the_gate_and_the_lock_refuses_a_second_call() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let g = guest(&e).await;
        let (_, opts) = start(&e, &g).await;
        e.synapse.lock().unwrap().joined.clear();
        let body = attest(&opts, format!("cred-{}", uniq()).as_bytes());
        let (s, v, _) = finish(&e, &g, &body).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (410, "ended"));
        assert!(
            e.redis
                .get_raw(&format!(
                    "webauthn:credential/{}",
                    body["id"].as_str().unwrap()
                ))
                .await
                .unwrap()
                .is_none(),
            "no credential written"
        );
        // The lock held by another call.
        let hash = siwx_oidc::db::guest_records::handle_hash(&g.handle);
        assert!(e.redis.take_claim_lock(&hash, "other").await.unwrap());
        let (s, v, _) = finish(&e, &g, &body).await;
        assert_eq!(
            (s, v["error"].as_str().unwrap()),
            (409, "claim_in_progress")
        );
        e.redis.release_claim_lock(&hash, "other").await;
    }

    /// Caps: 413 over 16 KiB on finish, over 4 KiB on start; a body that is no attestation is 400.
    #[tokio::test]
    async fn body_caps_and_bad_bodies() {
        let Some(e) = env(None, |_| {}).await else {
            return;
        };
        let g = guest(&e).await;
        let c = cookie(&e, &g);
        let big = |n: usize| json!({"pad": "x".repeat(n)}).to_string();
        assert_eq!(
            post(&e, "/guest/claim/finish", Some(&c), None, big(17 * 1024))
                .await
                .0,
            413
        );
        assert_eq!(
            post(&e, "/guest/claim/start", Some(&c), None, big(5 * 1024))
                .await
                .0,
            413
        );
        assert_eq!(
            post(&e, "/guest/claim/finish", Some(&c), None, big(8 * 1024))
                .await
                .0,
            400
        );
    }
}
