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
pub async fn start(State(state): State<GuestState>, headers: HeaderMap) -> Response {
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
