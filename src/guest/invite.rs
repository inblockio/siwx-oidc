//! The host API of the guest path (work package S2b): create, list and end
//! invitations. The pure rules are `siwx_oidc::guest_invite`, the room audit
//! `siwx_oidc::guest_room_audit`, the store `siwx_oidc::db::guest_invites`.
//!
//! Every route here is Bearer-authorised and goes through [`authorise_host`]:
//! a live access token that is not the minted admin token, not an unpromoted guest
//! account, in `guest_hosts`, with the kill switch off. A refusal is a 403 with a
//! fixed class (`admin_token`, `guest_token`, `not_a_host`, `disabled`). Nothing
//! from Synapse or from the request body is ever echoed.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::warn;

use super::layers::error;
use crate::config::Config;
use crate::synapse_client::{matrix_user_id, SynapseClient};
use siwx_oidc::db::guest_invites::{CreateOutcome, InviteView, NewBatch, NewInvite, QuotaLimits};
use siwx_oidc::db::guest_records::GuestView;
use siwx_oidc::db::RedisClient;
use siwx_oidc::guest_admission::NonceKey;
use siwx_oidc::guest_invite::{
    self as rules, is_host, join_link, new_invite_id, new_secret, secret_hash, valid_invite_id,
    CreateRequest, Limits, ADMIN_SUBJECT,
};
use siwx_oidc::guest_room_audit::{audit_room, may_invite, RoomState};

#[derive(Clone)]
pub struct GuestState {
    pub(super) config: Arc<Config>,
    pub(super) redis: RedisClient,
    pub(super) synapse: Option<Arc<SynapseClient>>,
    /// The HMAC key of the peek nonce, shared by peek and redeem: derived from the
    /// signing key when one is configured (so it survives a restart and is the same
    /// on every instance), else random per process.
    pub(super) nonce_key: NonceKey,
}

impl GuestState {
    pub fn new(config: Config, redis: RedisClient, synapse: Option<Arc<SynapseClient>>) -> Self {
        let nonce_key = match config.signing_key_pem.as_deref() {
            Some(pem) if !pem.is_empty() => NonceKey::derive(pem.as_bytes()),
            _ => NonceKey::random(),
        };
        Self {
            config: Arc::new(config),
            redis,
            synapse,
            nonce_key,
        }
    }
}

/// The caller of a host route, once every common check has passed.
pub struct Host {
    /// `TokenMetadata.username`: the key of the host in Redis.
    pub username: String,
    pub did: String,
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

fn forbidden(class: &'static str) -> Response {
    error(StatusCode::FORBIDDEN, class)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

/// The common checks of contract §2. Order: token, admin token, guest account,
/// host list, kill switch. The guest-account read is the seam S3 fills with real
/// records; today no record exists, so the answer is "not a guest".
pub async fn authorise_host(state: &GuestState, headers: &HeaderMap) -> Result<Host, Response> {
    let Some(token) = bearer(headers) else {
        return Err(error(StatusCode::UNAUTHORIZED, "invalid_token"));
    };
    let meta = match state.redis.check_access_token(token).await {
        Ok(Some(meta)) if meta.exp > Utc::now().timestamp() => meta,
        Ok(_) => return Err(error(StatusCode::UNAUTHORIZED, "invalid_token")),
        Err(e) => {
            warn!(error = %e, "guest host auth: token store unavailable");
            return Err(unavailable());
        }
    };
    if meta.did == ADMIN_SUBJECT {
        return Err(forbidden("admin_token"));
    }
    match state.redis.is_unpromoted_guest(&meta.username).await {
        Ok(false) => {}
        Ok(true) => return Err(forbidden("guest_token")),
        Err(e) => {
            warn!(error = %e, "guest host auth: guest record read failed");
            return Err(unavailable());
        }
    }
    if !is_host(&state.config.guest_hosts, &meta.username, &meta.did) {
        return Err(forbidden("not_a_host"));
    }
    match state.redis.guest_kill_switch_on().await {
        Ok(false) => {}
        Ok(true) => return Err(forbidden("disabled")),
        Err(e) => {
            warn!(error = %e, "guest host auth: control read failed");
            return Err(unavailable());
        }
    }
    Ok(Host {
        username: meta.username,
        did: meta.did,
    })
}

/// The Matrix ids of `guest_hosts`: a localpart entry is used as is, a DID entry
/// goes through the account localpart rule (grandfathering included).
async fn host_mxids(
    config: &Config,
    server_name: &str,
    synapse: &SynapseClient,
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in config.guest_hosts.iter().filter(|e| !e.trim().is_empty()) {
        let localpart = if entry.starts_with("did:") {
            crate::localpart::resolve_identity(entry, Some(synapse))
                .await?
                .localpart
        } else {
            entry.clone()
        };
        out.push(matrix_user_id(&localpart, server_name));
    }
    Ok(out)
}

/// `POST /guest/invites`.
pub async fn create(State(state): State<GuestState>, headers: HeaderMap, body: Bytes) -> Response {
    let host = match authorise_host(&state, &headers).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    let config = &state.config;
    let (Some(server_name), Some(synapse)) = (
        config.matrix_server_name.as_deref(),
        state.synapse.as_deref(),
    ) else {
        return unavailable();
    };
    let Ok(request) = serde_json::from_slice::<CreateRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let limits = Limits {
        server_name,
        max_guests: config.guest_max_guests,
        allow_open_links: config.guest_allow_open_links,
        open_link_max_uses: config.guest_open_link_max_uses,
        open_link_max_ttl_secs: config.guest_open_link_max_ttl_secs,
    };
    // A hostile room id is refused here, before any upstream call (ST-06).
    let valid = match rules::validate(request, &limits) {
        Ok(v) => v,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };

    // A3: the caller's power first, then the template.
    let events = match synapse.room_state(&valid.room_id).await {
        Ok(Some(events)) => events,
        Ok(None) => return error(StatusCode::UNPROCESSABLE_ENTITY, "room_not_found"),
        Err(e) => {
            warn!(error = %e, "guest invite: room state read failed");
            return unavailable();
        }
    };
    let room = RoomState::from_events(&events);
    let caller = matrix_user_id(&host.username, server_name);
    let power = may_invite(&room, &caller);
    if power == Some(false) {
        return forbidden("not_room_host");
    }
    let hosts = match host_mxids(config, server_name, synapse).await {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "guest invite: host list could not be resolved");
            return unavailable();
        }
    };
    if let Err(violations) = audit_room(&room, &hosts) {
        let mut reasons: Vec<&str> = violations.iter().map(|v| v.code()).collect();
        reasons.sort_unstable();
        reasons.dedup();
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "room_template", "reasons": reasons })),
        )
            .into_response();
    }
    if power != Some(true) {
        return forbidden("not_room_host");
    }

    let mut secrets = Vec::new();
    let invites: Vec<NewInvite> = valid
        .labels
        .iter()
        .map(|label| {
            let secret = new_secret();
            let invite = NewInvite {
                id: new_invite_id(),
                secret_hash: secret_hash(&secret),
                label: label.clone(),
            };
            secrets.push(secret);
            invite
        })
        .collect();
    let batch = NewBatch {
        host: &host.username,
        host_did: &host.did,
        room_id: &valid.room_id,
        kind: valid.kind,
        max_guests: valid.max_guests,
        expires_in: valid.expires_in,
        session_secs: valid.session_secs,
        recording_expected: valid.recording_expected,
        invites: &invites,
    };
    let quotas = QuotaLimits {
        max_invites: config.guest_host_max_invites,
        max_open_invites: config.guest_host_max_open_invites,
        per_hour: config.guest_host_invites_per_hour,
        session_max_secs: config.guest_session_max_secs,
    };
    match state.redis.create_guest_invites(&batch, &quotas).await {
        Ok(CreateOutcome::Created { expires_at, .. }) => {
            let issuer = config.base_url.as_str();
            let links: Vec<Value> = invites
                .iter()
                .zip(&secrets)
                .map(|(i, secret)| {
                    json!({
                        "id": i.id,
                        "label": i.label,
                        "link": join_link(issuer, &i.id, secret),
                        "expires_at": expires_at,
                    })
                })
                .collect();
            Json(json!({ "invites": links })).into_response()
        }
        Ok(CreateOutcome::Refused(class)) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "quota_exceeded", "quota": class })),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "guest invite: store write failed");
            unavailable()
        }
    }
}

/// What a host sees of an invite. There is deliberately no secret and no hash.
/// `guests` lists the invite's live guests (name, optional e-mail, state) and `counts`
/// is derived from them: `redeemed` is the invite's burn count, `active` the guests
/// not ending (minted, provisioning, active, claimed), `ended` those being reaped, and
/// `reaped` the redeemed guests whose record is gone.
fn public_view(v: &InviteView, guests: &[GuestView]) -> Value {
    let ending = guests.iter().filter(|g| g.state == "reaping").count() as u64;
    let active = guests.len() as u64 - ending;
    let reaped = v.used.saturating_sub(guests.len() as u64);
    let guests: Vec<Value> = guests
        .iter()
        .map(|g| {
            let mut o = json!({
                "first_name": g.first_name,
                "second_name": g.second_name,
                "state": g.state,
            });
            if let Some(email) = &g.email {
                o["email"] = json!(email);
            }
            o
        })
        .collect();
    json!({
        "id": v.id,
        "label": v.label,
        "kind": v.kind,
        "state": v.state,
        "room_id": v.room_id,
        "max_guests": v.max_guests,
        "counts": { "redeemed": v.used, "active": active, "ended": ending, "reaped": reaped },
        "guests": guests,
        "session_secs": v.session_secs,
        "recording_expected": v.recording_expected,
        "created_at": v.created_at,
        "expires_at": v.expires_at,
    })
}

/// `GET /guest/invites`: the caller's own invites.
pub async fn list(State(state): State<GuestState>, headers: HeaderMap) -> Response {
    let host = match authorise_host(&state, &headers).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    match state.redis.list_guest_invites(&host.username).await {
        Ok(views) => {
            let ids: Vec<String> = views.iter().map(|v| v.id.clone()).collect();
            let mut guests = match state.redis.guests_of_invites(&ids).await {
                Ok(g) => g,
                Err(e) => {
                    warn!(error = %e, "guest invite: guest list failed");
                    return unavailable();
                }
            };
            let invites: Vec<Value> = views
                .iter()
                .map(|v| public_view(v, &guests.remove(&v.id).unwrap_or_default()))
                .collect();
            Json(json!({ "invites": invites })).into_response()
        }
        Err(e) => {
            warn!(error = %e, "guest invite: list failed");
            unavailable()
        }
    }
}

/// Move the deadline of the unclaimed guests of just-revoked invites to now (never
/// later; `claimed` is skipped), so the reaper (S5) finds them due. Fail-closed: an
/// error is a 503 `unavailable`, so "End meeting" never answers 200 while a guest stays
/// live. The host retries; the revoke is idempotent and the move is repeatable.
async fn move_guest_deadlines_to_now(
    state: &GuestState,
    invite_ids: &[String],
) -> Result<(), Response> {
    match state.redis.move_guest_deadlines_to_now(invite_ids).await {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!(error = %e, "guest invite: moving guest deadlines failed");
            Err(unavailable())
        }
    }
}

/// `POST /guest/invites/{invite_id}/end`: 404 unless the caller made it.
pub async fn end_invite(
    State(state): State<GuestState>,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> Response {
    let host = match authorise_host(&state, &headers).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    if !valid_invite_id(&invite_id) {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    match state
        .redis
        .revoke_guest_invite(&host.username, &invite_id)
        .await
    {
        Ok(true) => {
            if let Err(r) = move_guest_deadlines_to_now(&state, &[invite_id]).await {
                return r;
            }
            Json(json!({ "revoked": 1 })).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(e) => {
            warn!(error = %e, "guest invite: revoke failed");
            unavailable()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndMeeting {
    room_id: String,
}

/// `POST /guest/meetings/end`: revoke every invite of the caller for one room.
pub async fn end_meeting(
    State(state): State<GuestState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let host = match authorise_host(&state, &headers).await {
        Ok(h) => h,
        Err(r) => return r,
    };
    let Ok(EndMeeting { room_id }) = serde_json::from_slice(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Some(server_name) = state.config.matrix_server_name.as_deref() else {
        return unavailable();
    };
    if !siwx_oidc::guest_room_audit::valid_room_id(&room_id, server_name) {
        return error(StatusCode::BAD_REQUEST, "bad_room_id");
    }
    // The caller's own invites for this room, read before the revoke (the set is the
    // caller's and the room's, so no other host's invite is in it).
    let ids = match state
        .redis
        .smembers_raw(&siwx_oidc::db::guest_invites::by_room_key(
            &host.username,
            &room_id,
        ))
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            warn!(error = %e, "guest invite: reading the meeting's invites failed");
            return unavailable();
        }
    };
    match state
        .redis
        .revoke_guest_invites_for_room(&host.username, &room_id)
        .await
    {
        Ok(n) => {
            if let Err(r) = move_guest_deadlines_to_now(&state, &ids).await {
                return r;
            }
            Json(json!({ "revoked": n })).into_response()
        }
        Err(e) => {
            warn!(error = %e, "guest invite: end meeting failed");
            unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    //! Driven over a real socket against a real Redis and a small Synapse stand-in,
    //! so the whole path (Bearer, host checks, room audit, store) is under test.
    use super::*;
    use serde_json::json;
    use siwx_oidc::db::{DBClient, TokenKind, TokenMetadata};
    use siwx_oidc::guest_room_audit::{CALL_EVENT_TYPES, CALL_MEMBER_TYPES};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    const SERVER: &str = "example.org";
    const ROOM: &str = "!room1:example.org";
    const ISSUER: &str = "https://id.example.org";

    #[derive(Default)]
    struct Mock {
        /// room id -> Ok(state events) | Err(status)
        rooms: HashMap<String, Result<Vec<Value>, u16>>,
        room_reads: Vec<String>,
    }

    fn nonce() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    fn ev(kind: &str, key: &str, sender: &str, content: Value) -> Value {
        json!({"type": kind, "state_key": key, "sender": sender, "content": content})
    }

    /// A room that passes the template, hosted by `host` (a localpart).
    fn good_room(host: &str) -> Vec<Value> {
        let h = format!("@{host}:{SERVER}");
        let mut events = json!({"m.room.name": 50, "m.room.topic": 50, "m.room.avatar": 50, "m.room.pinned_events": 50});
        for t in CALL_MEMBER_TYPES.iter().chain(CALL_EVENT_TYPES.iter()) {
            events[t] = json!(0);
        }
        vec![
            ev(
                "m.room.create",
                "",
                &h,
                json!({"room_version": "10", "m.federate": false}),
            ),
            ev("m.room.member", &h, &h, json!({"membership": "join"})),
            ev(
                "m.room.power_levels",
                "",
                &h,
                json!({"users": {h.clone(): 100}, "users_default": 0, "events_default": 50,
                       "state_default": 50, "invite": 50, "kick": 50, "ban": 50, "redact": 50,
                       "events": events}),
            ),
            ev("m.room.join_rules", "", &h, json!({"join_rule": "knock"})),
            ev(
                "m.room.history_visibility",
                "",
                &h,
                json!({"history_visibility": "joined"}),
            ),
            ev(
                "m.room.guest_access",
                "",
                &h,
                json!({"guest_access": "forbidden"}),
            ),
            ev(
                "m.room.encryption",
                "",
                &h,
                json!({"algorithm": "m.megolm.v1.aes-sha2"}),
            ),
            ev("m.room.name", "", &h, json!({"name": "Meeting"})),
            ev("io.inblock.guest_room", "", &h, json!({"version": 1})),
        ]
    }

    struct Env {
        base: String,
        redis: RedisClient,
        mock: Arc<Mutex<Mock>>,
        client: reqwest::Client,
        host: String,
        host_token: String,
    }

    async fn seed_token(redis: &RedisClient, username: &str, did: &str) -> String {
        let token = format!("mat_{}", nonce());
        let meta = TokenMetadata {
            username: username.into(),
            device_id: String::new(),
            scope: "openid".into(),
            client_id: "c".into(),
            iat: 0,
            exp: i64::MAX,
            did: did.into(),
            name: "n".into(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        };
        redis.set_token(&token, &meta, 300).await.unwrap();
        token
    }

    /// `db` picks the Redis database; `edit` adjusts the configuration after the
    /// per-test host has been added to `guest_hosts`.
    async fn env_in(db: Option<u8>, edit: impl Fn(&mut Config)) -> Option<Env> {
        let redis = match db {
            None => siwx_oidc::test_support::redis().await?,
            Some(n) => siwx_oidc::test_support::redis_db(n).await?,
        };
        let host = format!("host{}", nonce());
        let mock = Arc::new(Mutex::new(Mock::default()));
        mock.lock()
            .unwrap()
            .rooms
            .insert(ROOM.into(), Ok(good_room(&host)));
        let synapse_url = {
            let mock = mock.clone();
            let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
                let mock = mock.clone();
                async move {
                    let path = req.uri().path().to_string();
                    if let Some(rest) = path.strip_prefix("/_synapse/admin/v1/rooms/") {
                        let id = urlencoding::decode(rest.trim_end_matches("/state")).unwrap().into_owned();
                        let mut m = mock.lock().unwrap();
                        m.room_reads.push(id.clone());
                        return match m.rooms.get(&id) {
                            Some(Ok(events)) => (StatusCode::OK, Json(json!({"state": events}))).into_response(),
                            Some(Err(code)) => (StatusCode::from_u16(*code).unwrap(), Json(json!({"errcode": "M_SECRET", "error": "Board-meeting-of-Erika"}))).into_response(),
                            None => (StatusCode::NOT_FOUND, Json(json!({}))).into_response(),
                        };
                    }
                    (StatusCode::OK, Json(json!({}))).into_response()
                }
            });
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
            format!("http://{addr}")
        };
        let synapse = SynapseClient::new(&synapse_url, "secret").with_admin_mint(
            redis.clone(),
            "siwx-admin".into(),
            300,
        );
        let mut config = Config {
            guest_enabled: true,
            base_url: url::Url::parse(ISSUER).unwrap(),
            matrix_server_name: Some(SERVER.into()),
            guest_hosts: vec![host.clone()],
            guest_host_max_invites: 50,
            guest_host_invites_per_hour: 200,
            ..Config::default()
        };
        edit(&mut config);
        let app = super::super::routes::router(&config, redis.clone(), Some(Arc::new(synapse)));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let host_token = seed_token(&redis, &host, "did:key:zHost").await;
        Some(Env {
            base: format!("http://{addr}"),
            redis,
            mock,
            client: reqwest::Client::new(),
            host,
            host_token,
        })
    }

    async fn env(edit: impl Fn(&mut Config)) -> Option<Env> {
        env_in(None, edit).await
    }

    impl Env {
        async fn post(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
            let r = self
                .client
                .post(format!("{}{path}", self.base))
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
        }
        async fn get_text(&self, path: &str, token: &str) -> (u16, String) {
            let r = self
                .client
                .get(format!("{}{path}", self.base))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
        async fn invites_of_host(&self) -> usize {
            self.redis
                .smembers_raw(&siwx_oidc::db::guest_invites::by_host_key(&self.host))
                .await
                .unwrap()
                .len()
        }
        async fn create(&self, body: Value) -> (u16, Value) {
            self.post("/guest/invites", &self.host_token, body).await
        }
    }

    /// ST-01 / ST-05: an unlisted token, the minted admin token and a guest account get
    /// a 403 with a fixed class, and nothing is written or read from Synapse.
    #[tokio::test]
    async fn st01_st05_unlisted_admin_and_guest_tokens_are_refused_with_nothing_written() {
        let Some(e) = env(|_| {}).await else { return };
        let stranger = seed_token(&e.redis, &format!("s{}", nonce()), "did:key:zS").await;
        let admin = seed_token(&e.redis, &e.host, ADMIN_SUBJECT).await;
        let body = json!({"room_id": ROOM});
        assert_eq!(
            e.post("/guest/invites", &stranger, body.clone()).await,
            (403, json!({"error": "not_a_host"}))
        );
        assert_eq!(
            e.post("/guest/invites", &admin, body.clone()).await,
            (403, json!({"error": "admin_token"}))
        );
        let (status, text) = e.get_text("/guest/invites", &stranger).await;
        assert_eq!((status, text.as_str()), (403, r#"{"error":"not_a_host"}"#));
        assert_eq!(
            e.post("/guest/invites", "mat_unknown", body.clone())
                .await
                .0,
            401
        );
        assert_eq!(e.invites_of_host().await, 0);
        assert!(
            e.mock.lock().unwrap().room_reads.is_empty(),
            "a refused caller never reaches Synapse"
        );
    }

    #[tokio::test]
    async fn st05_a_host_account_with_an_unpromoted_guest_record_is_refused_and_a_promoted_one_is_not(
    ) {
        let Some(e) = env(|_| {}).await else { return };
        let key = siwx_oidc::db::guest_invites::guest_account_key(&e.host);
        e.redis.hset_raw_for_test(&key, "state", "active").await;
        assert_eq!(
            e.create(json!({"room_id": ROOM})).await,
            (403, json!({"error": "guest_token"}))
        );
        e.redis.hset_raw_for_test(&key, "promoted_at", "1").await;
        assert_eq!(e.create(json!({"room_id": ROOM})).await.0, 200);
        e.redis.del_raw(&key).await.unwrap();
    }

    /// ST-05: the kill switch blocks mint. Own database: the key is global.
    #[tokio::test]
    async fn st05_the_kill_switch_blocks_create_and_list() {
        let Some(e) = env_in(Some(12), |_| {}).await else {
            return;
        };
        e.redis
            .set_raw(siwx_oidc::db::guest_invites::CONTROL_KEY, "disabled")
            .await
            .unwrap();
        let (a, b) = (
            e.create(json!({"room_id": ROOM})).await,
            e.get_text("/guest/invites", &e.host_token).await,
        );
        e.redis
            .del_raw(siwx_oidc::db::guest_invites::CONTROL_KEY)
            .await
            .unwrap();
        assert_eq!(a, (403, json!({"error": "disabled"})));
        assert_eq!(b.0, 403);
        assert_eq!(e.create(json!({"room_id": ROOM})).await.0, 200);
    }

    /// ST-06: hostile room ids never reach Synapse; host B gets 404 on host A's invite.
    #[tokio::test]
    async fn st06_hostile_room_ids_never_reach_synapse() {
        let Some(e) = env(|_| {}).await else { return };
        for bad in [
            "../x",
            "!a/b:example.org",
            "!a?x",
            "!a%2fb",
            "!a\nb",
            "!a:other.org",
            "room",
            "!",
        ] {
            assert_eq!(
                e.create(json!({"room_id": bad})).await,
                (400, json!({"error": "bad_room_id"})),
                "{bad:?}"
            );
        }
        assert!(e.mock.lock().unwrap().room_reads.is_empty());
        assert_eq!(e.invites_of_host().await, 0);
    }

    #[tokio::test]
    async fn st06_host_b_cannot_see_or_end_host_as_invite() {
        let b_name = format!("hostb{}", nonce());
        let Some(e) = env({
            let b = b_name.clone();
            move |c| c.guest_hosts.push(b.clone())
        })
        .await
        else {
            return;
        };
        let (status, made) = e.create(json!({"room_id": ROOM})).await;
        assert_eq!(status, 200);
        let id = made["invites"][0]["id"].as_str().unwrap().to_string();
        let b_token = seed_token(&e.redis, &b_name, "did:key:zB").await;
        let (s, text) = e.get_text("/guest/invites", &b_token).await;
        assert_eq!(s, 200);
        assert!(!text.contains(&id), "B must not see A's invite: {text}");
        assert_eq!(
            e.post(&format!("/guest/invites/{id}/end"), &b_token, json!({}))
                .await,
            (404, json!({"error": "not_found"}))
        );
        let (_, mine) = e.get_text("/guest/invites", &e.host_token).await;
        assert!(
            mine.contains(r#""state":"active""#),
            "A's invite is untouched: {mine}"
        );
        assert_eq!(
            e.post("/guest/meetings/end", &b_token, json!({"room_id": ROOM}))
                .await
                .1,
            json!({"revoked": 0})
        );
        assert_eq!(
            e.post(
                &format!("/guest/invites/{id}/end"),
                &e.host_token,
                json!({})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            e.post(
                &format!("/guest/invites/{id}/end"),
                &e.host_token,
                json!({})
            )
            .await
            .0,
            200,
            "idempotent"
        );
        assert_eq!(
            e.post("/guest/invites/not-an-id/end", &e.host_token, json!({}))
                .await
                .0,
            404
        );
    }

    /// The list carries neither the secret nor its hash.
    #[tokio::test]
    async fn the_list_carries_no_secret_and_no_hash() {
        let Some(e) = env(|_| {}).await else { return };
        let (status, made) = e
            .create(json!({"room_id": ROOM, "count": 2, "labels": ["Ada", "Bob"]}))
            .await;
        assert_eq!(status, 200);
        let links = made["invites"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        let mut hashes = Vec::new();
        for (l, label) in links.iter().zip(["Ada", "Bob"]) {
            let link = l["link"].as_str().unwrap();
            let (path, secret) = link.split_once('#').unwrap();
            assert!(path.starts_with("https://id.example.org/guest/join/"));
            assert!(secret.starts_with("gi_") && secret.len() == 35);
            assert_eq!(l["label"], label);
            hashes.push(rules::secret_hash(secret));
            // Only the hash is stored.
            let stored = e
                .redis
                .get_hash_field_for_test(
                    &siwx_oidc::db::guest_invites::invite_key(l["id"].as_str().unwrap()),
                    "secret_hash",
                )
                .await;
            assert_eq!(stored.as_deref(), hashes.last().map(String::as_str));
        }
        let (s, text) = e.get_text("/guest/invites", &e.host_token).await;
        assert_eq!(s, 200);
        assert!(!text.contains("gi_") && !text.contains("secret"), "{text}");
        for h in hashes {
            assert!(!text.contains(&h), "the list leaks a hash");
        }
        assert!(text.contains("Ada") && text.contains("Bob"));
    }

    #[tokio::test]
    async fn create_refusals_in_the_room_checks() {
        let Some(e) = env(|_| {}).await else { return };
        // Unknown room: 422. Synapse down: 503 and no Synapse text.
        assert_eq!(
            e.create(json!({"room_id": "!nope:example.org"})).await,
            (422, json!({"error": "room_not_found"}))
        );
        e.mock
            .lock()
            .unwrap()
            .rooms
            .insert("!down:example.org".into(), Err(500));
        let (s, b) = e.create(json!({"room_id": "!down:example.org"})).await;
        assert_eq!((s, b.to_string().contains("Erika")), (503, false));
        // A template violation: no encryption.
        let mut room = good_room(&e.host);
        room.retain(|v| v["type"] != "m.room.encryption");
        e.mock
            .lock()
            .unwrap()
            .rooms
            .insert("!bad:example.org".into(), Ok(room));
        let (s, b) = e.create(json!({"room_id": "!bad:example.org"})).await;
        assert_eq!(s, 422);
        assert_eq!(b["error"], "room_template");
        assert!(!b["reasons"].as_array().unwrap().is_empty());
        // The caller is not joined with invite power.
        let mut room = good_room(&format!("other{}", nonce()));
        room.retain(|v| !(v["type"] == "m.room.member"));
        e.mock
            .lock()
            .unwrap()
            .rooms
            .insert("!notmine:example.org".into(), Ok(room));
        assert_eq!(
            e.create(json!({"room_id": "!notmine:example.org"})).await.0,
            403
        );
        assert_eq!(e.invites_of_host().await, 0, "no refusal writes anything");
    }

    /// ST-02 through the route, and the 429 class.
    #[tokio::test]
    async fn st02_quota_429_through_the_route() {
        let Some(e) = env(|c| c.guest_host_max_invites = 2).await else {
            return;
        };
        assert_eq!(e.create(json!({"room_id": ROOM, "count": 2})).await.0, 200);
        assert_eq!(
            e.create(json!({"room_id": ROOM})).await,
            (
                429,
                json!({"error": "quota_exceeded", "quota": "host_invites"})
            )
        );
        assert_eq!(e.invites_of_host().await, 2);
    }

    /// ST-09: single by default, open behind the flag with its caps, bulk labels, 72 h ceiling.
    #[tokio::test]
    async fn st09_kinds_caps_and_the_72_hour_ceiling() {
        let Some(e) = env(|_| {}).await else { return };
        assert_eq!(
            e.create(json!({"room_id": ROOM, "kind": "open"})).await,
            (400, json!({"error": "open_links_disabled"}))
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "expires_in": 259_201}))
                .await,
            (400, json!({"error": "bad_expires_in"}))
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "expires_in": 259_200}))
                .await
                .0,
            200
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "session_secs": 599}))
                .await
                .1,
            json!({"error": "bad_session_secs"})
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "session_secs": 14_401}))
                .await
                .1,
            json!({"error": "bad_session_secs"})
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "count": 11})).await.1,
            json!({"error": "bad_count"})
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "count": 2, "labels": ["a"]}))
                .await
                .1,
            json!({"error": "bad_labels"})
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "labels": ["x".repeat(41)]}))
                .await
                .1,
            json!({"error": "bad_labels"})
        );
        assert_eq!(
            e.create(json!({"room_id": ROOM, "bogus": 1})).await.1,
            json!({"error": "bad_request"})
        );

        let Some(o) = env(|c| c.guest_allow_open_links = true).await else {
            return;
        };
        assert_eq!(
            o.create(json!({"room_id": ROOM, "kind": "open", "max_guests": 11}))
                .await
                .1,
            json!({"error": "bad_max_guests"})
        );
        assert_eq!(
            o.create(json!({"room_id": ROOM, "kind": "open", "expires_in": 86_401}))
                .await
                .1,
            json!({"error": "bad_expires_in"})
        );
        assert_eq!(
            o.create(
                json!({"room_id": ROOM, "kind": "open", "max_guests": 10, "expires_in": 86_400})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            o.create(json!({"room_id": ROOM, "kind": "open"})).await.1,
            json!({"error": "quota_exceeded", "quota": "host_open_invites"})
        );
        let (_, text) = o.get_text("/guest/invites", &o.host_token).await;
        assert!(text.contains(r#""kind":"open""#));
    }

    #[tokio::test]
    async fn ending_a_meeting_revokes_the_callers_invites_for_that_room() {
        let Some(e) = env(|_| {}).await else { return };
        e.mock
            .lock()
            .unwrap()
            .rooms
            .insert("!room2:example.org".into(), Ok(good_room(&e.host)));
        e.create(json!({"room_id": ROOM, "count": 2})).await;
        e.create(json!({"room_id": "!room2:example.org"})).await;
        assert_eq!(
            e.post(
                "/guest/meetings/end",
                &e.host_token,
                json!({"room_id": ROOM})
            )
            .await,
            (200, json!({"revoked": 2}))
        );
        assert_eq!(
            e.post(
                "/guest/meetings/end",
                &e.host_token,
                json!({"room_id": "../x"})
            )
            .await
            .0,
            400
        );
        let (_, text) = e.get_text("/guest/invites", &e.host_token).await;
        let v: Value = serde_json::from_str(&text).unwrap();
        let states: Vec<&str> = v["invites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["state"].as_str().unwrap())
            .collect();
        assert_eq!(states.iter().filter(|s| **s == "revoked").count(), 2);
        assert_eq!(states.iter().filter(|s| **s == "active").count(), 1);
    }
}
