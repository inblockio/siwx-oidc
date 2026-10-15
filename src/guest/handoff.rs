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
use tracing::{info, warn};

use super::invite::GuestState;
use super::layers::error;
use crate::config::Config;
use crate::oidc::{AuthorizeParams, CustomError};
use crate::synapse_client::{DeviceUpsert, SynapseClient};
use siwx_oidc::db::guest_records::{
    EndOutcome, GuestSession, HandoffBegin, HandoffRefusal, HANDOFF_LEASE_SECS,
};
use siwx_oidc::db::{
    AuthorizationRequest, ClientClass, ClientEntry, DBClient, RedisClient, SessionEntry,
    SESSION_COOKIE_NAME,
};
use siwx_oidc::guest_admission::{verify_continue_proof, ContinueError};
use url::Url;

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
pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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
pub(super) fn guest_cookie_name(config: &Config) -> &'static str {
    if config.base_url.scheme() == "https" {
        "__Host-guest_session"
    } else {
        "guest_session"
    }
}

/// The kill switch (S6, GP-SEC-48): whether guest hand-offs are switched off
/// (`guest:control` field `disabled` is `1` or `true`, set by the operator). `Err` when the
/// control cannot be read or does not parse; every caller treats that as engaged. Both
/// `/authorize` and `/guest/continue` ask it (and `/guest/resume` through [`live_guest`]),
/// so a guest session stops handing off the moment it is.
pub async fn guest_kill_switch_engaged(redis: &RedisClient) -> anyhow::Result<bool> {
    Ok(redis.guest_control().await?.disabled)
}

/// The refresh guard (S5), asked by `/token` (refresh grant) and `compat::refresh` for a
/// grant they are about to rotate. `Ok(true)`: rotate. `Ok(false)`: answer `invalid_grant`.
/// `Err`: a Redis read failed, the caller answers 5xx; the guard never passes on an error.
///
/// Only a grant of the guest client is looked at (`guest_client_id`; no Redis read for any
/// other, and none is needed when the client is not configured). For a guest-client grant
/// the answer is [`refresh_verdict`] of one read of its record, the device set and the
/// operator's control (`disabled`, `reap_before`). The deadline is also written into the grant (`absolute_exp`), so the
/// rotation script refuses past it on its own; this guard adds the reasons the grant
/// cannot know.
pub async fn guest_refresh_allowed(
    guest_client_id: Option<&str>,
    redis: &RedisClient,
    grant: &siwx_oidc::db::grant::GrantView,
) -> anyhow::Result<bool> {
    if guest_client_id != Some(grant.client_id.as_str()) {
        return Ok(true);
    }
    let read = redis
        .guest_refresh_read(&grant.username, &grant.device_id)
        .await?;
    let allowed = refresh_verdict(&read);
    if !allowed {
        super::audit::refused(redis, "refresh", "guest_grant").await;
    }
    Ok(allowed)
}

/// The refusals of contract section 6 (and the operator's `disabled` and `reap_before`), as a function of what was read. A record that
/// is gone, `reaping` or in a state this build does not know refuses; a `claimed` account
/// is a persistent account and is not this guard's.
pub fn refresh_verdict(read: &siwx_oidc::db::guest_records::GuestRefreshRead) -> bool {
    match read.state.as_deref() {
        Some("claimed") => true,
        Some("minted" | "provisioning" | "active") => {
            read.deadline.is_some_and(|d| read.now < d)
                && read.device_recorded
                && !read.disabled
                && !read.reap_before_due()
        }
        _ => false,
    }
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

    if crate::oidc::scope_device_id(&granted).is_err() {
        return Err(fail("invalid_scope", crate::oidc::INVALID_DEVICE_ID_MSG));
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

/// The first check of the guest branch of `sign_in`, before the session is marked signed
/// in (so a refusal burns nothing): a guest session is finished only by
/// `/guest/continue`, which writes `verified_did`.
pub fn guest_sign_in_precheck(session: &SessionEntry) -> Result<(), CustomError> {
    if session.verified_did.is_none() {
        return Err(CustomError::Unauthorized(
            "The guest hand-off was not completed.".to_string(),
        ));
    }
    Ok(())
}

/// An error on the redirect URI of a bound request (RFC 6749 4.1.2.1), in the fragment
/// when the request asked for `response_mode=fragment`.
fn redirect_error(request: &AuthorizationRequest, error: &str) -> CustomError {
    match Url::parse(&request.redirect_uri) {
        Ok(mut url) => {
            let pairs = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &request.state)
                .append_pair("error", error)
                .finish();
            if request.response_mode.as_deref() == Some("fragment") {
                url.set_fragment(Some(&pairs));
            } else {
                url.query_pairs_mut()
                    .append_pair("state", &request.state)
                    .append_pair("error", error);
            }
            CustomError::Redirect(url.to_string())
        }
        Err(_) => CustomError::BadRequest("The bound redirect_uri does not parse.".to_string()),
    }
}

/// What the guest branch hands `sign_in`: the account and the device the code is for.
pub struct GuestGrant {
    pub localpart: String,
    pub device_id: String,
}

/// The guest branch of `sign_in` (S4b), in the contract's order, failing closed:
///
/// 1. the fence ([`RedisClient::guest_handoff_begin`]): CAS to `provisioning` with a 120 s
///    lease, the write-ahead device id, the device cap and the hand-off rate;
/// 2. the account check, until one attempt of this record passed it (`acct_checked`): an
///    existing account under the localpart whose `user_type` is not `io.inblock.guest`
///    refuses with `access_denied`; a pass is recorded under the lease before step 3;
/// 3. `provision_user`, seeded with "First Second" plus the suffix;
/// 4. the admin PUT of `user_type = io.inblock.guest`;
/// 5. the admin PUT of the canonical display name (the P4 module lets a guest without it
///    only leave);
/// 6. the device;
/// 7. the record `active` (only for the attempt that still holds the lease).
///
/// Steps 2 to 6 share one deadline, [`HANDOFF_STEPS_TIMEOUT`]. Any other failure: no code, the
/// lease released, the record left `provisioning` (a retry re-takes it and heals), a
/// device this attempt created deleted again. A refusal is an
/// error on the redirect URI.
#[allow(clippy::too_many_arguments)]
pub async fn provision_guest(
    config: Option<&Config>,
    redis: &RedisClient,
    synapse: Option<&SynapseClient>,
    server_name: Option<&str>,
    session: &SessionEntry,
    request: &AuthorizationRequest,
    client: &ClientEntry,
    did: &str,
) -> Result<GuestGrant, CustomError> {
    let (Some(config), Some(guest_id)) = (config, session.guest_id.as_deref()) else {
        return Err(CustomError::Coded {
            status: 503,
            code: "unavailable",
        });
    };
    // The client and the redirect again, from the config: the bound request is only as
    // good as the session that carried it.
    let redirect_ok = Url::parse(&request.redirect_uri)
        .is_ok_and(|u| config.guest_client_redirect_uris.contains(&u));
    if config.guest_client_id.as_deref() != Some(request.client_id.as_str())
        || !redirect_ok
        || client.class != ClientClass::Matrix
    {
        return Err(CustomError::BadRequest(
            "This client is not the guest client.".to_string(),
        ));
    }
    let localpart = siwx_oidc::mxid::localpart_for(did);
    if localpart != guest_id || session.verified_did.as_deref() != Some(did) {
        return Err(redirect_error(request, "access_denied"));
    }
    let unavailable = || redirect_error(request, "temporarily_unavailable");
    let (Some(synapse), Some(server_name)) = (synapse, server_name) else {
        warn!("guest hand-off: no homeserver is configured");
        return Err(unavailable());
    };
    let record = match redis.read_guest_by_localpart(&localpart).await {
        Ok(Some(r)) if r.did == did && r.is_live() => r,
        Ok(_) => return Err(redirect_error(request, "access_denied")),
        Err(e) => {
            warn!(error = %e, "guest hand-off: record lookup failed");
            return Err(unavailable());
        }
    };
    if matches!(guest_kill_switch_engaged(redis).await, Ok(true) | Err(_)) {
        super::audit::refused(redis, "authorize", "disabled").await;
        return Err(unavailable());
    }
    let names = match redis.read_guest_resume(&record.localpart).await {
        Ok(Some(n)) => n,
        _ => return Err(unavailable()),
    };
    let display_name = format!(
        "{} {}{}",
        names.first_name, names.second_name, config.guest_name_suffix
    );
    let proposed = match request.scope.as_deref().map(crate::oidc::scope_device_id) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(id))) => Some(id),
        Some(Err(_)) => return Err(redirect_error(request, "invalid_scope")),
    };
    let device_id = proposed
        .unwrap_or_else(|| format!("SIWX_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
    let attempt = uuid::Uuid::new_v4().simple().to_string();

    let (was_active, account_checked, fresh_device) = match redis
        .guest_handoff_begin(
            &localpart,
            &attempt,
            &device_id,
            config.guest_max_devices,
            config.guest_handoff_per_minute,
        )
        .await
    {
        Ok(HandoffBegin::Started {
            was_active,
            account_checked,
            fresh_device,
        }) => (was_active, account_checked, fresh_device),
        Ok(HandoffBegin::Refused(HandoffRefusal::NotLive)) => {
            return Err(redirect_error(request, "access_denied"))
        }
        Ok(HandoffBegin::Refused(why)) => {
            info!(?why, "guest hand-off refused");
            return Err(unavailable());
        }
        Err(e) => {
            warn!(error = %e, "guest hand-off: fence failed");
            return Err(unavailable());
        }
    };

    // Everything below runs inside the lease: past `HANDOFF_STEPS_TIMEOUT` the attempt
    // gives up, so a slow Synapse cannot outlive the lease and race the reaper.
    let steps_deadline = tokio::time::Instant::now() + steps_timeout();

    // An account under the localpart that is not a guest's was made elsewhere (the same
    // did:key signed in as a member): never stamp the guest marker on it, or the reaper
    // erases it at the deadline. Once a check passed (`acct_checked`, written before
    // `provision_user`), a retry skips it: its own half-made account may not carry the
    // marker yet. Skipping on the state alone would not do, as a crash, a dropped request
    // or a timeout leaves `provisioning` before any account was made.
    if !was_active && !account_checked {
        let refusal = match tokio::time::timeout_at(
            steps_deadline,
            synapse.admin_get_user(&localpart, server_name),
        )
        .await
        {
            Ok(Ok(None)) => None,
            Ok(Ok(Some(row))) if row.user_type.as_deref() == Some(GUEST_USER_TYPE) => None,
            Ok(Ok(Some(_))) => {
                super::audit::refused(redis, "authorize", "account_exists").await;
                Some(redirect_error(request, "access_denied"))
            }
            Ok(Err(e)) => {
                warn!(error = %e, "guest hand-off: the account check failed");
                Some(unavailable())
            }
            Err(_) => {
                warn!("guest hand-off: the account check timed out");
                Some(unavailable())
            }
        };
        if let Some(refusal) = refusal {
            if let Err(e) = redis
                .guest_handoff_release(&localpart, &attempt, Some(&device_id))
                .await
            {
                warn!(error = %e, "guest hand-off: releasing the lease failed (it expires)");
            }
            return Err(refusal);
        }
        if !matches!(
            redis.guest_handoff_mark_checked(&localpart, &attempt).await,
            Ok(true)
        ) {
            warn!("guest hand-off: recording the account check failed or the lease was lost");
            if let Err(e) = redis
                .guest_handoff_release(&localpart, &attempt, Some(&device_id))
                .await
            {
                warn!(error = %e, "guest hand-off: releasing the lease failed (it expires)");
            }
            return Err(unavailable());
        }
    }

    let mut device_created = false;
    let mut device_step = false;
    let steps = async {
        if !was_active {
            synapse.provision_user(&localpart, &display_name).await?;
            synapse
                .admin_put_user(
                    &localpart,
                    server_name,
                    "user_type",
                    &json!({"user_type": GUEST_USER_TYPE}),
                )
                .await?;
            synapse
                .admin_put_user(
                    &localpart,
                    server_name,
                    "displayname",
                    &json!({"displayname": display_name}),
                )
                .await?;
        }
        device_step = true;
        if synapse.upsert_device(&localpart, &device_id).await? == DeviceUpsert::Created {
            device_created = true;
            if let Err(e) = synapse
                .update_device_display_name(
                    &localpart,
                    &device_id,
                    &crate::oidc::device_display_name(&request.client_id, Some(client)),
                )
                .await
            {
                warn!(error = %e, "naming the guest device failed (non-fatal)");
            }
        }
        anyhow::Ok(())
    };
    // On a timeout the step in flight is dropped. Before the device step no device of this
    // attempt can exist; inside it whether Synapse made the device is unknown, so the
    // failure path below deletes it when this attempt added the id.
    let (steps, timed_out) = match tokio::time::timeout_at(steps_deadline, steps).await {
        Ok(r) => (r, false),
        Err(_) => (Err(anyhow::anyhow!("the hand-off steps timed out")), true),
    };

    let activated = match steps {
        Ok(()) => redis.guest_handoff_activate(&localpart, &attempt).await,
        Err(e) => Err(e),
    };
    match activated {
        Ok(true) => {
            super::audit::signin();
            Ok(GuestGrant {
                localpart,
                device_id,
            })
        }
        failure => {
            match &failure {
                Ok(_) => warn!("guest hand-off: the lease was lost before activation"),
                Err(e) => warn!(error = %e, "guest hand-off failed; no code is issued"),
            }
            // A device this attempt created, or may have created before a timeout under an
            // id it added, is taken back, and the write-ahead id leaves the set once the
            // delete succeeded. A timeout before the device step made no device, so a fresh
            // id simply leaves. Otherwise repeated timeouts fill the device cap with ids
            // Synapse never made. (An upsert request already sent can still land after the
            // delete; the reaper's account erase removes that device.)
            let mut no_device = (!was_active && !device_created && !timed_out)
                || (timed_out && fresh_device && !device_step);
            if device_created || (timed_out && fresh_device && device_step) {
                no_device = matches!(
                    tokio::time::timeout(
                        HANDOFF_CLEANUP_TIMEOUT,
                        synapse.delete_device(&localpart, &device_id, server_name),
                    )
                    .await,
                    Ok(Ok(()))
                );
            }
            if let Err(e) = redis
                .guest_handoff_release(&localpart, &attempt, no_device.then_some(&device_id[..]))
                .await
            {
                warn!(error = %e, "guest hand-off: releasing the lease failed (it expires)");
            }
            Err(unavailable())
        }
    }
}

/// The overall cap on a hand-off's Synapse steps (the account check, provisioning, the
/// device). Half the 120 s lease, so an attempt ends, and its cleanup (a device delete, the
/// release) runs, before its lease can lapse and the reaper's CAS can take the record.
pub const HANDOFF_STEPS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const _: () = assert!(HANDOFF_STEPS_TIMEOUT.as_secs() * 2 <= HANDOFF_LEASE_SECS);

/// The bound on a failed hand-off's device delete, so the cleanup ends inside the lease.
const HANDOFF_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const _: () = assert!(
    HANDOFF_STEPS_TIMEOUT.as_secs() + HANDOFF_CLEANUP_TIMEOUT.as_secs() < HANDOFF_LEASE_SECS
);

#[cfg(test)]
tokio::task_local! {
    /// A shorter steps deadline for one test's task.
    static STEPS_TIMEOUT_FOR_TEST: std::time::Duration;
}

fn steps_timeout() -> std::time::Duration {
    #[cfg(test)]
    if let Ok(d) = STEPS_TIMEOUT_FOR_TEST.try_with(|d| *d) {
        return d;
    }
    HANDOFF_STEPS_TIMEOUT
}

/// The `user_type` the P4 module and the reaper recognise a guest by.
pub const GUEST_USER_TYPE: &str = "io.inblock.guest";

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

/// A refusal of `POST /guest/continue`: audited as `guest_refused` (route `continue`, the
/// error code as the reason) and counted for the burst alert, then answered. A 503 is not
/// a refusal and does not come through here.
async fn refuse(state: &GuestState, status: StatusCode, code: &'static str) -> Response {
    super::audit::refused(&state.redis, "continue", code).await;
    error(status, code)
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
        return refuse(&state, StatusCode::BAD_REQUEST, "bad_request").await;
    };
    let (session_id, mut entry, record) = match hand_off_context(&state, &headers).await {
        Ok(t) => t,
        Err("unavailable") => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Err(_) => return refuse(&state, StatusCode::UNAUTHORIZED, "no_session").await,
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
        return refuse(&state, StatusCode::BAD_REQUEST, "redirect_not_allowed").await;
    }
    let Some(signature) = decode_signature(&req.signature) else {
        return refuse(&state, StatusCode::UNAUTHORIZED, "signature_invalid").await;
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
        let (status, code) = match why {
            ContinueError::DidMismatch => (StatusCode::UNAUTHORIZED, "did_mismatch"),
            ContinueError::SignatureInvalid => (StatusCode::UNAUTHORIZED, "signature_invalid"),
            ContinueError::NonceMismatch => (StatusCode::BAD_REQUEST, "nonce_mismatch"),
            ContinueError::ResourceMismatch => (StatusCode::BAD_REQUEST, "resource_mismatch"),
            ContinueError::Malformed => (StatusCode::BAD_REQUEST, "bad_request"),
        };
        return refuse(&state, status, code).await;
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

// ---------------------------------------------------------------------------------
// In-session reads (contract section 5) and the ended page (section 6)
// ---------------------------------------------------------------------------------

const ENDED_HTML: &str = include_str!("../../static/guest/ended.html");

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

/// `GET /guest/context`: the guest's Bearer, the room, deadline, invite and meeting name
/// of its record. No Synapse call; the room id is only ever in this body.
///
/// 401 `invalid_token` for a missing, unknown or expired token; 403 `not_a_guest` for a
/// valid token whose subject has no guest record (a host's or a registered user's);
/// 503 `unavailable` on a Redis error.
pub async fn context(State(state): State<GuestState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let meta = match state.redis.check_access_token(token).await {
        Ok(Some(m)) if m.exp > Utc::now().timestamp() => m,
        Ok(_) => return error(StatusCode::UNAUTHORIZED, "invalid_token"),
        Err(e) => {
            warn!(error = %e, "guest context: token store unavailable");
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
    };
    match state.redis.read_guest_context(&meta.username).await {
        Ok(Some(c)) => {
            let mut response = Json(json!({
                "room_id": c.room_id,
                "deadline": c.deadline,
                "invite_id": c.invite_id,
                "meeting_name": c.meeting_name,
            }))
            .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => error(StatusCode::FORBIDDEN, "not_a_guest"),
        Err(e) => {
            warn!(error = %e, "guest context: record read failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

/// `POST /guest/end` (S5): the guest ends its own session. The guest's Bearer, or the
/// cookie with the same-origin check (403 `forbidden_origin`); the Bearer wins when both
/// are sent. The deadline moves to now (record and `guest:due`), so the reaper erases the
/// guest within a tick; the cookie is cleared. 200 `{"state":"ending"}`, also when the
/// record is already ending (second call) or, on the cookie, already gone
/// (`{"state":"ended"}`). 409 `claimed` for a claimed account. 401 `invalid_token` without
/// a credential or with a bad token, 403 `not_a_guest` for a valid token that is not a
/// guest's, 503 `unavailable` on a Redis error.
pub async fn end(State(state): State<GuestState>, headers: HeaderMap) -> Response {
    let localpart = if let Some(token) = bearer_token(&headers) {
        match state.redis.check_access_token(token).await {
            Ok(Some(m)) if m.exp > Utc::now().timestamp() => m.username,
            Ok(_) => return error(StatusCode::UNAUTHORIZED, "invalid_token"),
            Err(e) => {
                warn!(error = %e, "guest end: token store unavailable");
                return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
        }
    } else {
        let issuer = super::layers::issuer_origin(&state.config.base_url);
        if !super::layers::same_origin_ok(&headers, &issuer) {
            return error(StatusCode::FORBIDDEN, "forbidden_origin");
        }
        let Some(handle) = cookie_value(&headers, guest_cookie_name(&state.config)) else {
            return error(StatusCode::UNAUTHORIZED, "invalid_token");
        };
        match state.redis.read_guest_session(&handle).await {
            Ok(Some(r)) => r.localpart,
            Ok(None) => {
                // A guest that claimed in the last ten minutes still holds this cookie: the
                // account is kept, nothing is ended (409, like the Bearer path).
                return match state.redis.read_claimed_handle(&handle).await {
                    Ok(Some(_)) => error(StatusCode::CONFLICT, "claimed"),
                    Ok(None) => ended_response(&state.config, "ended"),
                    Err(e) => {
                        warn!(error = %e, "guest end: claimed marker unreadable");
                        error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
                    }
                };
            }
            Err(e) => {
                warn!(error = %e, "guest end: record lookup failed");
                return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
        }
    };
    match state.redis.end_guest_now(&localpart).await {
        Ok(EndOutcome::Moved | EndOutcome::Ending) => ended_response(&state.config, "ending"),
        Ok(EndOutcome::Claimed) => error(StatusCode::CONFLICT, "claimed"),
        Ok(EndOutcome::Gone) => error(StatusCode::FORBIDDEN, "not_a_guest"),
        Err(e) => {
            warn!(error = %e, "guest end: moving the deadline failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

/// 200 with the session cookie cleared.
fn ended_response(config: &Config, state: &str) -> Response {
    let mut response = Json(json!({ "state": state })).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&super::redeem::session_cookie(&config.base_url, "", 0)) {
        headers.append(header::SET_COOKIE, v);
    }
    response
}

/// Whether the cookie's handle still maps to a claimed account (the ten minutes after a
/// claim). `Err(())`: Redis could not be read.
async fn claimed_marker(state: &GuestState, headers: &HeaderMap) -> Result<bool, ()> {
    let Some(handle) = cookie_value(headers, guest_cookie_name(&state.config)) else {
        return Ok(false);
    };
    match state.redis.read_claimed_handle(&handle).await {
        Ok(found) => Ok(found.is_some()),
        Err(e) => {
            warn!(error = %e, "guest resume: claimed marker unreadable");
            Err(())
        }
    }
}

/// The advisory `claim_allowed` (05 section 3.3): the flag, an `active` record before its
/// deadline, the host not banned, and room under `guest_max_claimed`. The admission read of
/// CP-11 is left to start and finish (resume stays a Redis-only read). A fault is `false`.
async fn claim_allowed(state: &GuestState, localpart: &str) -> bool {
    if !state.config.guest_claim_enabled {
        return false;
    }
    match state.redis.read_claim(localpart).await {
        Ok(Some(c)) => {
            c.state == "active"
                && c.deadline.is_some_and(|d| c.now < d)
                && !c.host_banned
                && c.claimed_count < state.config.guest_max_claimed
        }
        _ => false,
    }
}

/// The fixed Meet start URL (public config): where the claim page's "Back to the call" and
/// "Sign in" lead. `null` when unset.
fn client_url(state: &GuestState) -> Option<String> {
    state
        .config
        .guest_client_url
        .as_ref()
        .map(|u| u.to_string())
}

/// `GET /guest/resume`: what the issuer pages need to greet a returning guest. The
/// cookie authorises it; a request that says it comes from another origin is refused
/// (the cookie is `SameSite=Lax`, and the answer carries no CORS header, so this is the
/// belt on top of the braces). No secret in the body. No live record (no cookie, unknown
/// handle, reaping, past the deadline, kill switch on) is `{"state": "no_session"}`.
///
/// After a claim the cookie answers `{"state": "claimed"}` for 10 minutes (the claimed-handle
/// marker), then `no_session`; the helper page forgets the browser key on `claimed`.
pub async fn resume(State(state): State<GuestState>, headers: HeaderMap) -> Response {
    let issuer = super::layers::issuer_origin(&state.config.base_url);
    let foreign_origin = headers
        .get(header::ORIGIN)
        .is_some_and(|o| o.to_str().ok() != Some(issuer.as_str()));
    let foreign_site = headers
        .get("sec-fetch-site")
        .is_some_and(|v| v.to_str().ok() != Some("same-origin"));
    if foreign_origin || foreign_site {
        return error(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    let record = match live_guest(&state.config, &state.redis, &headers).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "guest resume: record lookup failed");
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
    };
    let body = match record {
        None => match claimed_marker(&state, &headers).await {
            Ok(true) => json!({"state": "claimed", "client_url": client_url(&state)}),
            Ok(false) => json!({"state": "no_session"}),
            Err(()) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        },
        Some(r) => match state.redis.read_guest_resume(&r.localpart).await {
            Ok(Some(v)) => json!({
                "first_name": v.first_name,
                "second_name": v.second_name,
                "state": v.state,
                "seconds_left": (r.deadline - r.now).max(0),
                "did": v.did,
                "claim_allowed": claim_allowed(&state, &r.localpart).await,
                "email_present": v.email_present,
                "client_url": client_url(&state),
            }),
            Ok(None) => json!({"state": "no_session"}),
            Err(e) => {
                warn!(error = %e, "guest resume: record read failed");
                return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
        },
    };
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /guest/ended`: the page a portal sends a guest to after `invalid_grant`. The same
/// bytes for everyone: it needs no cookie and no record (the guest account is gone by the
/// time anyone reads it), says the account is deleted and calls `forgetKey()` on this
/// browser's key store. After a claim (ten minutes) the page reads
/// `resume`, says the account is kept and still forgets the browser key.
pub async fn ended_page() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        ENDED_HTML,
    )
        .into_response()
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
        env_in(None, edit).await
    }

    /// `db`: an own Redis database, for a test that sets the global `guest:control`.
    async fn env_in(db: Option<u8>, edit: impl Fn(&mut Config)) -> Option<Env> {
        let redis = match db {
            None => siwx_oidc::test_support::redis().await?,
            Some(n) => siwx_oidc::test_support::redis_db(n).await?,
        };
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

    /// Every refusal `/guest/continue` answers is counted for the refusal-burst alert
    /// (one per request); the success is not, and neither is a store fault.
    #[tokio::test]
    async fn each_continue_refusal_is_counted() {
        let Some(db) = siwx_oidc::test_support::redis_db(5).await else {
            return;
        };
        db.flush_db_for_test().await;
        let e = env_in(Some(5), |_| {}).await.unwrap();
        let h = hand_off(&e, "active").await;
        let other = Guest::new();
        let evil = "https://evil.example.net/cb";
        let good = message(&e, &h.guest.did, REDIRECT, &h.nonce, 0);
        let other_msg = message(&e, &other.did, REDIRECT, &h.nonce, 0);
        let wrong_nonce = message(&e, &h.guest.did, REDIRECT, "someoneElsesNonce", 0);
        let wrong_uri = message(
            &e,
            &h.guest.did,
            "https://meet.example.org/other",
            &h.nonce,
            0,
        );
        let only_guest = format!("{}={}", guest_cookie_name(&e.config), h.handle);
        let cases: Vec<(&str, Option<&str>, Value, u16, &str)> = vec![
            (
                "did_mismatch",
                None,
                body(REDIRECT, &other_msg, &other.sign(&other_msg)),
                401,
                "did_mismatch",
            ),
            (
                "signature_invalid",
                None,
                body(REDIRECT, &good, &other.sign(&good)),
                401,
                "signature_invalid",
            ),
            (
                "undecodable",
                None,
                body(REDIRECT, &good, "!!"),
                401,
                "signature_invalid",
            ),
            (
                "nonce_mismatch",
                None,
                body(REDIRECT, &wrong_nonce, &h.guest.sign(&wrong_nonce)),
                400,
                "nonce_mismatch",
            ),
            (
                "redirect_unlisted",
                None,
                body(
                    "https://meet.example.org/other",
                    &wrong_uri,
                    &h.guest.sign(&wrong_uri),
                ),
                400,
                "redirect_not_allowed",
            ),
            (
                "redirect_not_allowed",
                None,
                body(evil, &good, &h.guest.sign(&good)),
                400,
                "redirect_not_allowed",
            ),
            ("bad_request", None, json!({"x": 1}), 400, "bad_request"),
            (
                "no_session",
                Some(only_guest.as_str()),
                body(REDIRECT, &good, &h.guest.sign(&good)),
                401,
                "no_session",
            ),
        ];
        let mut expect = 0;
        for (what, cookie, b, status, code) in cases {
            let (st, j) = post(&e, &h, cookie, b).await;
            assert_eq!((st, j["error"].as_str()), (status, Some(code)), "{what}");
            expect += 1;
            assert_eq!(db.guest_refusal_total_for_test().await, expect, "{what}");
        }
        // The resource_mismatch error (a message that binds another URI) is its own class.
        let m = message(
            &e,
            &h.guest.did,
            "https://meet.example.org/other",
            &h.nonce,
            0,
        );
        let (st, j) = post(&e, &h, None, body(REDIRECT, &m, &h.guest.sign(&m))).await;
        assert_eq!((st, j["error"].as_str()), (400, Some("resource_mismatch")));
        expect += 1;
        assert_eq!(db.guest_refusal_total_for_test().await, expect);
        // A good signature is no refusal.
        let (st, _) = post(&e, &h, None, body(REDIRECT, &good, &h.guest.sign(&good))).await;
        assert_eq!(st, 200);
        assert_eq!(db.guest_refusal_total_for_test().await, expect);
        db.flush_db_for_test().await;
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

    // ---- S4b: provisioning, context, resume, ended, claim ----------------------------

    use axum::extract::{Path as AxPath, State as AxState};
    use axum::routing::{get as ax_get, post as ax_post};
    use std::sync::{Arc, Mutex};

    const SERVER: &str = "example.org";
    const ADMIN_LP: &str = "siwx-test-admin";

    #[derive(Default)]
    struct Flags {
        fail_marker: bool,
        fail_name: bool,
        provision_delay_ms: u64,
        /// The admin GET of the account: `None` answers 404, `Some(row)` 200 with it.
        existing_account: Option<Value>,
        fail_account_check: bool,
        /// A 404 without `M_NOT_FOUND`, as a proxy hiding the admin API answers.
        bare_404: bool,
        fail_delete_device: bool,
        upsert_delay_ms: u64,
        fail_upsert: bool,
    }

    #[derive(Clone, Default)]
    struct MockSynapse {
        log: Arc<Mutex<Vec<(String, String)>>>,
        flags: Arc<Mutex<Flags>>,
    }

    impl MockSynapse {
        fn calls(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(c, _)| c.clone())
                .collect()
        }
        fn bodies(&self, call_prefix: &str) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c.starts_with(call_prefix))
                .map(|(_, b)| b.clone())
                .collect()
        }
        fn count(&self, call_prefix: &str) -> usize {
            self.bodies(call_prefix).len()
        }
    }

    async fn spawn_mock() -> (MockSynapse, SynapseClient) {
        async fn rec(m: &MockSynapse, call: String, body: String) {
            m.log.lock().unwrap().push((call, body));
        }
        let mock = MockSynapse::default();
        let app = axum::Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                ax_get(
                    |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        if q.get("localpart").map(String::as_str) == Some(ADMIN_LP) {
                            (
                                StatusCode::BAD_REQUEST,
                                r#"{"errcode":"M_USER_IN_USE","error":"taken"}"#,
                            )
                        } else {
                            (StatusCode::OK, "{}")
                        }
                    },
                ),
            )
            .route(
                "/_synapse/mas/query_user",
                ax_get(|| async { StatusCode::NOT_FOUND }),
            )
            .route(
                "/_synapse/mas/provision_user",
                ax_post(|AxState(m): AxState<MockSynapse>, b: String| async move {
                    let delay = m.flags.lock().unwrap().provision_delay_ms;
                    rec(&m, "POST provision_user".into(), b).await;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    "{}"
                }),
            )
            .route(
                "/_synapse/mas/upsert_device",
                ax_post(|AxState(m): AxState<MockSynapse>, b: String| async move {
                    let (delay, fail) = {
                        let f = m.flags.lock().unwrap();
                        (f.upsert_delay_ms, f.fail_upsert)
                    };
                    rec(&m, "POST upsert_device".into(), b).await;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    if fail {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "{}");
                    }
                    (StatusCode::CREATED, "{}")
                }),
            )
            .route(
                "/_synapse/mas/update_device_display_name",
                ax_post(|AxState(m): AxState<MockSynapse>, b: String| async move {
                    rec(&m, "POST update_device_display_name".into(), b).await;
                    "{}"
                }),
            )
            .route(
                "/_synapse/mas/delete_device",
                ax_post(|AxState(m): AxState<MockSynapse>, b: String| async move {
                    rec(&m, "POST delete_device".into(), b).await;
                    if m.flags.lock().unwrap().fail_delete_device {
                        (StatusCode::INTERNAL_SERVER_ERROR, "{}")
                    } else {
                        (StatusCode::OK, "{}")
                    }
                }),
            )
            .route(
                "/_synapse/admin/v2/users/{mxid}",
                ax_get(
                    |AxState(m): AxState<MockSynapse>, AxPath(mxid): AxPath<String>| async move {
                        rec(&m, format!("GET admin/users/{mxid}"), String::new()).await;
                        let f = m.flags.lock().unwrap();
                        if f.fail_account_check {
                            return (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_string());
                        }
                        if f.bare_404 {
                            return (StatusCode::NOT_FOUND, "Not Found".to_string());
                        }
                        match &f.existing_account {
                            None => (
                                StatusCode::NOT_FOUND,
                                r#"{"errcode":"M_NOT_FOUND","error":"User not found"}"#.to_string(),
                            ),
                            Some(row) => (StatusCode::OK, row.to_string()),
                        }
                    },
                )
                .put(
                    |AxState(m): AxState<MockSynapse>,
                     AxPath(mxid): AxPath<String>,
                     headers: HeaderMap,
                     b: String| async move {
                        assert!(headers.contains_key(header::AUTHORIZATION));
                        let v: Value = serde_json::from_str(&b).unwrap();
                        let which = if v.get("user_type").is_some() {
                            "user_type"
                        } else {
                            "displayname"
                        };
                        rec(&m, format!("PUT admin/users/{mxid} {which}"), b).await;
                        let (fail_marker, fail_name) = {
                            let f = m.flags.lock().unwrap();
                            (f.fail_marker, f.fail_name)
                        };
                        if (which == "user_type" && fail_marker)
                            || (which == "displayname" && fail_name)
                        {
                            (StatusCode::INTERNAL_SERVER_ERROR, "{}")
                        } else {
                            (StatusCode::OK, "{}")
                        }
                    },
                ),
            )
            .with_state(mock.clone());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let redis = siwx_oidc::test_support::redis().await.unwrap();
        let client = SynapseClient::new(&format!("http://{addr}"), "shared-secret")
            .with_admin_mint(redis, ADMIN_LP.to_string(), 300);
        (mock, client)
    }

    /// The guest client as start-up seeds it.
    async fn seed_guest_client(e: &Env) {
        let (id, entry) = crate::guest::guest_client_entry(&e.config)
            .unwrap()
            .unwrap();
        e.redis.set_client(id, entry).await.unwrap();
    }

    /// A fresh login session for an existing record, as `/authorize` and a verified
    /// `/guest/continue` leave it. Returns the session id.
    async fn start_session(e: &Env, g: &Guest, handle: &str, device: &str) -> String {
        let scope = format!(
            "openid urn:matrix:client:api:* urn:matrix:client:device:{device} urn:io.inblock:guest"
        );
        let (headers, _) = authorize(
            &e.config,
            &e.redis,
            params(CLIENT, REDIRECT, &scope, json!({})),
            &cookies(e, handle),
        )
        .await
        .unwrap();
        let sid = session_cookie_of(&headers)
            .split_once('=')
            .unwrap()
            .1
            .to_string();
        let mut s = e.redis.get_session(sid.clone()).await.unwrap().unwrap();
        s.verified_did = Some(g.did.clone());
        e.redis.set_session(sid.clone(), s).await.unwrap();
        sid
    }

    async fn sign_in_as(
        e: &Env,
        synapse: &SynapseClient,
        sid: &str,
    ) -> Result<(url::Url, String), CustomError> {
        use headers::HeaderMapExt;
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={sid}").parse().unwrap(),
        );
        crate::oidc::sign_in(
            &e.config.base_url,
            &["key".to_string()],
            &[],
            h.typed_get::<headers::Cookie>().unwrap(),
            &e.redis,
            Some(synapse),
            Some(SERVER),
            None,
            Some(&e.config),
        )
        .await
    }

    fn redirect_error_of(r: Result<(url::Url, String), CustomError>) -> String {
        match r {
            Err(CustomError::Redirect(u)) => {
                let u = url::Url::parse(&u).unwrap();
                assert_eq!(u.as_str().split('?').next().unwrap(), REDIRECT);
                u.query_pairs()
                    .find(|(k, _)| k == "error")
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            }
            Err(_) => "other-error".into(),
            Ok(_) => "ok".into(),
        }
    }

    async fn guest_env(edit: impl Fn(&mut Config)) -> Option<(Env, MockSynapse, SynapseClient)> {
        let e = env(edit).await?;
        seed_guest_client(&e).await;
        let (mock, client) = spawn_mock().await;
        Some((e, mock, client))
    }

    async fn record_of(e: &Env, localpart: &str) -> std::collections::HashMap<String, String> {
        e.redis
            .hgetall_for_test(&siwx_oidc::db::guest_invites::guest_account_key(localpart))
            .await
    }

    /// The marker, then the name, each exactly once and before the device; the account is
    /// seeded with "First Second (Guest)"; the record is `active` and a code is issued
    /// for the guest's localpart and the proposed device.
    #[tokio::test]
    async fn provisioning_order_bodies_and_the_active_record() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        e.redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&lp),
                "first_name",
                "Ada",
            )
            .await;
        e.redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&lp),
                "second_name",
                "Lovelace",
            )
            .await;
        let sid = start_session(&e, &g, &handle, "DEVICE0001").await;
        let (url, did) = sign_in_as(&e, &synapse, &sid).await.expect("sign in");
        assert_eq!(did, g.did);
        assert!(url.query_pairs().any(|(k, _)| k == "code"));
        let calls = mock.calls();
        let mxid = format!("%40{lp}%3Aexample.org");
        let _ = mxid;
        let kinds: Vec<&str> = calls
            .iter()
            .map(|c| {
                if c.starts_with("GET admin/users/") {
                    "account check"
                } else if c.starts_with("PUT") && c.ends_with("user_type") {
                    "marker"
                } else if c.starts_with("PUT") && c.ends_with("displayname") {
                    "name"
                } else {
                    c.as_str()
                }
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "account check",
                "POST provision_user",
                "marker",
                "name",
                "POST upsert_device",
                "POST update_device_display_name"
            ],
            "the order is: account check, account, marker, canonical name, device"
        );
        let seed: Value = serde_json::from_str(&mock.bodies("POST provision_user")[0]).unwrap();
        assert_eq!(
            seed,
            json!({"localpart": lp, "set_displayname": "Ada Lovelace (Guest)"})
        );
        assert_eq!(
            mock.bodies("PUT")[0],
            r#"{"user_type":"io.inblock.guest"}"#,
            "the exact marker body"
        );
        assert_eq!(
            mock.bodies("PUT")[1],
            r#"{"displayname":"Ada Lovelace (Guest)"}"#,
            "the exact canonical-name body"
        );
        let rec = record_of(&e, &lp).await;
        assert_eq!(rec["state"], "active");
        assert!(!rec.contains_key("lease_owner") && !rec.contains_key("lease_until"));
        assert_eq!(rec["device_id"], "DEVICE0001");
        // The code is for the guest's account and device.
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();
        let entry = e.redis.try_consume_code(code).await.unwrap().unwrap();
        assert_eq!(entry.localpart.as_deref(), Some(lp.as_str()));
        assert_eq!(entry.device_id.as_deref(), Some("DEVICE0001"));
        assert_eq!(
            entry
                .scope
                .as_deref()
                .map(|s| s.contains("urn:io.inblock:guest")),
            Some(false)
        );
    }

    /// ST-43: a refused marker PUT (then a refused canonical-name PUT) leaves no device
    /// and no code, the record `provisioning` with the lease released; a retry with the
    /// PUT working heals.
    #[tokio::test]
    async fn st43_a_refused_marker_or_name_put_issues_nothing_and_a_retry_heals() {
        for which in ["marker", "name"] {
            let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
                return;
            };
            let g = Guest::new();
            let (lp, handle) = record(&e, &g, "minted", 600).await;
            {
                let mut f = mock.flags.lock().unwrap();
                f.fail_marker = which == "marker";
                f.fail_name = which == "name";
            }
            let sid = start_session(&e, &g, &handle, "DEVICE0002").await;
            assert_eq!(
                redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
                "temporarily_unavailable",
                "{which}"
            );
            assert_eq!(mock.count("POST upsert_device"), 0, "{which}: no device");
            if which == "marker" {
                assert_eq!(
                    mock.count("PUT"),
                    1,
                    "the name is not attempted after a refused marker"
                );
            }
            let rec = record_of(&e, &lp).await;
            assert_eq!(rec["state"], "provisioning", "{which}: not active");
            assert!(!rec.contains_key("lease_owner"), "{which}: lease released");
            assert!(
                e.redis
                    .try_consume_code("x".into())
                    .await
                    .unwrap()
                    .is_none(),
                "no code"
            );
            // Retry with the PUT working: heals.
            {
                let mut f = mock.flags.lock().unwrap();
                f.fail_marker = false;
                f.fail_name = false;
            }
            let sid = start_session(&e, &g, &handle, "DEVICE0002").await;
            let (url, _) = sign_in_as(&e, &synapse, &sid)
                .await
                .expect("the retry heals");
            assert!(url.query_pairs().any(|(k, _)| k == "code"));
            assert_eq!(record_of(&e, &lp).await["state"], "active");
            assert_eq!(mock.count("POST upsert_device"), 1);
        }
    }

    /// SS4 audit #2: a failing `upsert_device` on the guest branch is the
    /// `temporarily_unavailable` redirect with no code (never an issuer page), with SS4
    /// flag 2 on and off alike; the retry heals.
    #[tokio::test]
    async fn a_failing_guest_upsert_redirects_temporarily_unavailable() {
        for flag2 in [true, false] {
            let Some((e, mock, synapse)) = guest_env(|c| c.refuse_deleted_device_ids = flag2).await
            else {
                return;
            };
            mock.flags.lock().unwrap().fail_upsert = true;
            let g = Guest::new();
            let (lp, handle) = record(&e, &g, "minted", 600).await;
            let sid = start_session(&e, &g, &handle, "DEVICE0009").await;
            let r = sign_in_as(&e, &synapse, &sid).await;
            assert_eq!(
                redirect_error_of(r),
                "temporarily_unavailable",
                "flag 2 {flag2}"
            );
            assert_eq!(mock.count("POST upsert_device"), 1);
            assert_eq!(record_of(&e, &lp).await["state"], "provisioning");
            mock.flags.lock().unwrap().fail_upsert = false;
            let sid = start_session(&e, &g, &handle, "DEVICE0009").await;
            let (url, _) = sign_in_as(&e, &synapse, &sid)
                .await
                .expect("the retry heals");
            assert!(url.query_pairs().any(|(k, _)| k == "code"));
        }
    }

    /// The fence: two sign-ins at once provision once; the other is told to come back.
    #[tokio::test]
    async fn the_fence_lets_one_of_two_concurrent_sign_ins_provision() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        mock.flags.lock().unwrap().provision_delay_ms = 400;
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let a = start_session(&e, &g, &handle, "DEVICE0003").await;
        let b = start_session(&e, &g, &handle, "DEVICE0004").await;
        let (ra, rb) = tokio::join!(sign_in_as(&e, &synapse, &a), sign_in_as(&e, &synapse, &b));
        let outcomes = [redirect_error_of(ra), redirect_error_of(rb)];
        assert_eq!(
            outcomes.iter().filter(|o| *o == "ok").count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| *o == "temporarily_unavailable")
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(mock.count("POST provision_user"), 1);
        assert_eq!(mock.count("PUT"), 2);
        assert_eq!(record_of(&e, &lp).await["state"], "active");
    }

    /// #49 F5: a `minted` record whose localpart already has an account that is not a
    /// guest's (the same did:key signed in as a member) is refused with `access_denied`
    /// before anything is written to Synapse, with the lease and the write-ahead device
    /// released and no `acct_checked`, so the next attempt checks again.
    #[tokio::test]
    async fn f5_a_minted_record_refuses_an_existing_member_account() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        mock.flags.lock().unwrap().existing_account =
            Some(json!({"name": format!("@{lp}:{SERVER}"), "user_type": null}));
        for round in 0..2 {
            let sid = start_session(&e, &g, &handle, "DEVICE0005").await;
            assert_eq!(
                redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
                "access_denied",
                "round {round}"
            );
            assert_eq!(
                mock.count("GET admin/users/"),
                round + 1,
                "checked each time"
            );
            assert_eq!(mock.count("POST provision_user"), 0, "round {round}");
            assert_eq!(mock.count("PUT"), 0, "no marker on a member's account");
            assert_eq!(mock.count("POST upsert_device"), 0, "round {round}");
            let rec = record_of(&e, &lp).await;
            assert_ne!(rec["state"], "active", "round {round}");
            assert!(!rec.contains_key("acct_checked"), "round {round}");
            assert!(
                !rec.contains_key("lease_owner"),
                "round {round}: lease released"
            );
            assert_eq!(
                e.redis.scard_for_test(&format!("guest:devices/{lp}")).await,
                0,
                "round {round}: the write-ahead device is dropped"
            );
        }
        // A failing check fails closed the same way, as `temporarily_unavailable`.
        mock.flags.lock().unwrap().fail_account_check = true;
        let sid = start_session(&e, &g, &handle, "DEVICE0005").await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "temporarily_unavailable"
        );
        assert_eq!(mock.count("POST provision_user"), 0);
        assert!(!record_of(&e, &lp).await.contains_key("acct_checked"));

        // A 404 that is not Synapse's `M_NOT_FOUND` is no proof of absence.
        {
            let mut f = mock.flags.lock().unwrap();
            f.fail_account_check = false;
            f.bare_404 = true;
        }
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let sid = start_session(&e, &g, &handle, "DEVICE0009").await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "temporarily_unavailable"
        );
        assert_eq!(mock.count("POST provision_user"), 0);
        assert!(!record_of(&e, &lp).await.contains_key("acct_checked"));
    }

    /// #49 F5 (audit 1): a record left `provisioning` by an attempt that never passed the
    /// check (a crash, a dropped request, a timeout) is checked again: the state alone
    /// does not skip the check.
    #[tokio::test]
    async fn f5_a_provisioning_record_without_a_passed_check_is_checked() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "provisioning", 600).await;
        mock.flags.lock().unwrap().existing_account =
            Some(json!({"name": format!("@{lp}:{SERVER}"), "user_type": null}));
        let sid = start_session(&e, &g, &handle, "DEVICE0010").await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "access_denied"
        );
        assert_eq!(mock.count("GET admin/users/"), 1);
        assert_eq!(mock.count("POST provision_user"), 0);
        assert_eq!(mock.count("PUT"), 0);
    }

    /// #49 F5: an existing account that already carries the guest marker is this guest's
    /// and is provisioned over, and the pass is recorded (`acct_checked`); a retry after a
    /// passed check (its own half-made account, maybe without the marker yet) is not
    /// checked again.
    #[tokio::test]
    async fn f5_a_guest_account_proceeds_and_a_provisioning_retry_is_not_checked() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        mock.flags.lock().unwrap().existing_account =
            Some(json!({"name": format!("@{lp}:{SERVER}"), "user_type": GUEST_USER_TYPE}));
        let sid = start_session(&e, &g, &handle, "DEVICE0006").await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "ok"
        );
        assert_eq!(mock.count("POST provision_user"), 1);
        assert_eq!(record_of(&e, &lp).await["acct_checked"], "1");

        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "provisioning", 600).await;
        e.redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&lp),
                "acct_checked",
                "1",
            )
            .await;
        mock.flags.lock().unwrap().existing_account =
            Some(json!({"name": format!("@{lp}:{SERVER}"), "user_type": null}));
        let before = mock.count("GET admin/users/");
        let sid = start_session(&e, &g, &handle, "DEVICE0007").await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "ok"
        );
        assert_eq!(
            mock.count("GET admin/users/"),
            before,
            "no check after a passed one"
        );
        assert_eq!(record_of(&e, &lp).await["state"], "active");
    }

    /// #54 L1: the hand-off steps share one deadline below the lease. A Synapse slower
    /// than that ends the attempt (no code, lease released; it timed out before the device
    /// step, so no device was made and the fresh id leaves the set, #55 low 3) instead of
    /// outliving the lease.
    #[tokio::test]
    async fn l1_hand_off_steps_slower_than_the_deadline_give_up() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        mock.flags.lock().unwrap().provision_delay_ms = 2_000;
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let sid = start_session(&e, &g, &handle, "DEVICE0008").await;
        let started = std::time::Instant::now();
        let r = STEPS_TIMEOUT_FOR_TEST
            .scope(
                std::time::Duration::from_millis(300),
                sign_in_as(&e, &synapse, &sid),
            )
            .await;
        assert_eq!(redirect_error_of(r), "temporarily_unavailable");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1_500),
            "it did not wait for Synapse: {:?}",
            started.elapsed()
        );
        assert_eq!(mock.count("PUT"), 0, "no step after the deadline");
        let rec = record_of(&e, &lp).await;
        assert_eq!(rec["state"], "provisioning");
        assert!(!rec.contains_key("lease_owner"), "lease released");
        assert_eq!(
            mock.count("POST delete_device"),
            0,
            "no device step, nothing to delete"
        );
        assert_eq!(
            e.redis.scard_for_test(&format!("guest:devices/{lp}")).await,
            0,
            "the fresh write-ahead id leaves the set"
        );
        assert!(
            HANDOFF_STEPS_TIMEOUT < std::time::Duration::from_secs(HANDOFF_LEASE_SECS),
            "the deadline is below the lease"
        );
    }

    /// #55 low 3: a timed-out attempt takes back only what it may have made under an id it
    /// added itself: before the device step the id just leaves; inside it the device is
    /// deleted and the id leaves only when the delete succeeded. An earlier attempt's id is
    /// never deleted, so the cap never forgets a device that may exist and repeated
    /// timeouts do not fill it with ids that do not.
    #[tokio::test]
    async fn low3_a_timed_out_attempt_takes_back_only_the_id_it_added() {
        let Some((e, mock, synapse)) = guest_env(|c| c.guest_handoff_per_minute = 10).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let set = format!("guest:devices/{lp}");
        let attempt = |dev: &'static str| {
            let (e, g, handle, synapse) = (&e, &g, &handle, &synapse);
            async move {
                let sid = start_session(e, g, handle, dev).await;
                let r = STEPS_TIMEOUT_FOR_TEST
                    .scope(
                        std::time::Duration::from_millis(300),
                        sign_in_as(e, synapse, &sid),
                    )
                    .await;
                assert_eq!(redirect_error_of(r), "temporarily_unavailable");
            }
        };
        let deleted = || {
            mock.bodies("POST delete_device")
                .iter()
                .map(|b| serde_json::from_str::<Value>(b).unwrap()["device_id"].clone())
                .collect::<Vec<_>>()
        };

        // Timed out in provisioning, before the device step: no delete, the id leaves.
        mock.flags.lock().unwrap().provision_delay_ms = 2_000;
        attempt("DEVICE0009").await;
        assert!(deleted().is_empty());
        assert_eq!(e.redis.scard_for_test(&set).await, 0);

        // Timed out inside the device step under a fresh id, the delete fails: kept.
        {
            let mut f = mock.flags.lock().unwrap();
            f.provision_delay_ms = 0;
            f.upsert_delay_ms = 2_000;
            f.fail_delete_device = true;
        }
        attempt("DEVICE000A").await;
        assert_eq!(deleted(), vec![json!("DEVICE000A")]);
        assert_eq!(
            e.redis.scard_for_test(&set).await,
            1,
            "kept: the device may exist"
        );

        // The same id again is not this attempt's: no delete, still counted.
        mock.flags.lock().unwrap().fail_delete_device = false;
        attempt("DEVICE000A").await;
        assert_eq!(deleted().len(), 1, "an earlier attempt's id is kept");
        assert_eq!(e.redis.scard_for_test(&set).await, 1);

        // A fresh id whose delete succeeds leaves the set.
        attempt("DEVICE000B").await;
        assert_eq!(deleted(), vec![json!("DEVICE000A"), json!("DEVICE000B")]);
        assert_eq!(
            e.redis.scard_for_test(&set).await,
            1,
            "only DEVICE000A is left"
        );
        assert_eq!(record_of(&e, &lp).await["state"], "provisioning");
    }

    /// An expired lease may be re-taken; a live one of another attempt may not.
    #[tokio::test]
    async fn a_lease_is_live_for_120_seconds_then_free() {
        let Some(e) = env(|_| {}).await else { return };
        let g = Guest::new();
        let (lp, _) = record(&e, &g, "minted", 600).await;
        let begin = |attempt: &'static str, dev: &'static str| {
            let (r, lp) = (e.redis.clone(), lp.clone());
            async move {
                r.guest_handoff_begin(&lp, attempt, dev, 8, 100)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            begin("a1", "d1").await,
            HandoffBegin::Started {
                was_active: false,
                account_checked: false,
                fresh_device: true
            }
        );
        assert_eq!(
            begin("a2", "d2").await,
            HandoffBegin::Refused(HandoffRefusal::Busy)
        );
        let key = siwx_oidc::db::guest_invites::guest_account_key(&lp);
        e.redis.hset_raw_for_test(&key, "lease_until", "1").await;
        assert_eq!(
            begin("a2", "d2").await,
            HandoffBegin::Started {
                was_active: false,
                account_checked: false,
                fresh_device: true
            },
            "an expired lease is re-taken"
        );
        assert_eq!(record_of(&e, &lp).await["lease_owner"], "a2");
    }

    /// At most 8 devices (here 2) and at most 3 hand-offs a minute.
    #[tokio::test]
    async fn the_device_cap_and_the_hand_off_rate_refuse_with_temporarily_unavailable() {
        // Device cap 2, rate high.
        let Some((e, mock, synapse)) = guest_env(|c| {
            c.guest_max_devices = 2;
            c.guest_handoff_per_minute = 100;
        })
        .await
        else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let mut results = Vec::new();
        for dev in ["DEVA0001", "DEVB0002", "DEVC0003"] {
            let sid = start_session(&e, &g, &handle, dev).await;
            results.push(redirect_error_of(sign_in_as(&e, &synapse, &sid).await));
        }
        assert_eq!(results, ["ok", "ok", "temporarily_unavailable"]);
        assert_eq!(mock.count("POST upsert_device"), 2);
        assert_eq!(
            mock.count("POST provision_user"),
            1,
            "an active guest is not provisioned again"
        );
        assert_eq!(
            e.redis.scard_for_test(&format!("guest:devices/{lp}")).await,
            2
        );

        // Rate 3 a minute, caps high: the fourth hand-off inside the minute is refused.
        let Some((e, _mock, synapse)) = guest_env(|c| {
            c.guest_max_devices = 100;
            c.guest_handoff_per_minute = 3;
        })
        .await
        else {
            return;
        };
        let g = Guest::new();
        let (_, handle) = record(&e, &g, "minted", 600).await;
        let mut results = Vec::new();
        for dev in ["DEVA0001", "DEVB0002", "DEVC0003", "DEVD0004"] {
            let sid = start_session(&e, &g, &handle, dev).await;
            results.push(redirect_error_of(sign_in_as(&e, &synapse, &sid).await));
        }
        assert_eq!(results, ["ok", "ok", "ok", "temporarily_unavailable"]);
    }

    /// Refusals that are not retryable: a wrong client, a record that is not live.
    #[tokio::test]
    async fn a_record_that_is_not_live_or_a_foreign_client_gets_no_code() {
        let Some((e, mock, synapse)) = guest_env(|_| {}).await else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "minted", 600).await;
        let sid = start_session(&e, &g, &handle, "DEVICE0009").await;
        // The reaper got there first.
        e.redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&lp),
                "state",
                "reaping",
            )
            .await;
        assert_eq!(
            redirect_error_of(sign_in_as(&e, &synapse, &sid).await),
            "access_denied"
        );
        assert!(mock.calls().is_empty(), "nothing reached Synapse");
        // A session whose client is not the guest client is refused without a redirect.
        let (lp2, h2) = record(&e, &Guest::new(), "minted", 600).await;
        let _ = (lp2, h2);
        let mut cfg = e.config.clone();
        cfg.guest_client_id = Some("someone-else".into());
        let g2 = Guest::new();
        let (_, handle2) = record(&e, &g2, "minted", 600).await;
        let sid2 = start_session(&e, &g2, &handle2, "DEVICE0010").await;
        let e2 = Env {
            base: e.base.clone(),
            redis: e.redis.clone(),
            config: cfg,
        };
        assert!(matches!(
            sign_in_as(&e2, &synapse, &sid2).await,
            Err(CustomError::BadRequest(_))
        ));
        assert!(mock.calls().is_empty());
    }

    /// `io.inblock.guest: true` for a guest's token, absent for everyone else; ST-39 (the
    /// claim of a claimed or unknown account is absent too).
    #[tokio::test]
    async fn st39_the_guest_claim_is_true_for_a_guest_and_absent_otherwise() {
        let Some(e) = env(|_| {}).await else { return };
        let g = Guest::new();
        let (lp, _) = record(&e, &g, "active", 600).await;
        let claim = |client: &'static str, lp: String, cfg: Config| {
            let r = e.redis.clone();
            async move {
                crate::oidc::guest_claim(&cfg, &r, client, &lp)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            claim(CLIENT, lp.clone(), e.config.clone()).await,
            Some(true)
        );
        assert_eq!(
            claim("other-client", lp.clone(), e.config.clone()).await,
            None
        );
        assert_eq!(claim(CLIENT, "nobody".into(), e.config.clone()).await, None);
        let mut off = e.config.clone();
        off.guest_enabled = false;
        assert_eq!(claim(CLIENT, lp.clone(), off).await, None);
        e.redis
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&lp),
                "state",
                "claimed",
            )
            .await;
        assert_eq!(claim(CLIENT, lp, e.config.clone()).await, None);
        // On the wire: present as `true`, never `false`, never null.
        let with = serde_json::to_value(crate::oidc::SidClaims {
            sid: Some("s".into()),
            guest: Some(true),
        })
        .unwrap();
        assert_eq!(with, json!({"sid": "s", "io.inblock.guest": true}));
        let without = serde_json::to_value(crate::oidc::SidClaims {
            sid: Some("s".into()),
            guest: None,
        })
        .unwrap();
        assert_eq!(without, json!({"sid": "s"}));
        let userinfo = serde_json::to_value(crate::oidc::SiwxAdditionalClaims::default()).unwrap();
        assert!(userinfo.get("io.inblock.guest").is_none());
    }

    async fn get(e: &Env, path: &str, headers: &[(&str, &str)]) -> (u16, Value, String) {
        let mut req = reqwest::Client::new().get(format!("{}{path}", e.base));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::Null),
            text,
        )
    }

    async fn seed_token(e: &Env, username: &str, did: &str) -> String {
        use siwx_oidc::db::{TokenKind, TokenMetadata};
        let token = format!("mat_{}", uniq());
        let meta = TokenMetadata {
            username: username.into(),
            device_id: String::new(),
            scope: "openid".into(),
            client_id: CLIENT.into(),
            iat: 0,
            exp: i64::MAX,
            did: did.into(),
            name: "n".into(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        };
        e.redis.set_token(&token, &meta, 300).await.unwrap();
        token
    }

    /// `GET /guest/context`: 200 with the four fields for a guest token; 401 for no or an
    /// unknown token; 403 `not_a_guest` for a valid token that is not a guest's.
    #[tokio::test]
    async fn the_context_vectors() {
        let Some(e) = env(|_| {}).await else { return };
        let g = Guest::new();
        let (lp, _) = record(&e, &g, "active", 600).await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&lp);
        let invite = format!("ctx{}", uniq());
        e.redis
            .hset_raw_for_test(&key, "room_id", "!room:example.org")
            .await;
        e.redis.hset_raw_for_test(&key, "invite_id", &invite).await;
        let token = seed_token(&e, &lp, &g.did).await;
        let bearer = format!("Bearer {token}");
        let (status, body, _) = get(&e, "/guest/context", &[("authorization", &bearer)]).await;
        assert_eq!(status, 200);
        assert_eq!(body["room_id"], "!room:example.org");
        assert_eq!(body["invite_id"], invite);
        assert!(body["deadline"].as_i64().unwrap() > 0);
        assert_eq!(body["meeting_name"], "", "no invite stored: empty text");
        assert_eq!(body.as_object().unwrap().len(), 4);
        assert_eq!(get(&e, "/guest/context", &[]).await.0, 401);
        assert_eq!(
            get(&e, "/guest/context", &[("authorization", "Bearer nope")])
                .await
                .0,
            401
        );
        let other = seed_token(&e, &format!("host{}", uniq()), "did:key:zHost").await;
        let (status, body, _) = get(
            &e,
            "/guest/context",
            &[("authorization", &format!("Bearer {other}"))],
        )
        .await;
        assert_eq!((status, body["error"].as_str()), (403, Some("not_a_guest")));
    }

    /// S6: `disabled` makes the cookie no live session for `/guest/resume` (the shared
    /// reader `live_guest` that `/authorize` and `/guest/continue` also use) and clearing it
    /// restores it; an unreadable control (an old plain-string key) is a 503, never a pass.
    #[tokio::test]
    async fn the_kill_switch_ends_resume_and_an_unreadable_control_fails_closed() {
        use siwx_oidc::db::guest_invites::CONTROL_KEY;
        let Some(e) = env_in(Some(13), |_| {}).await else {
            return;
        };
        e.redis.flush_db_for_test().await;
        let g = Guest::new();
        let (_lp, handle) = record(&e, &g, "active", 600).await;
        let cookie = format!("{}={handle}", guest_cookie_name(&e.config));
        let headers = [("cookie", cookie.as_str())];
        let resume = || get(&e, "/guest/resume", &headers);
        assert_eq!(resume().await.1["state"], "active");
        e.redis
            .hset_raw_for_test(CONTROL_KEY, "disabled", "1")
            .await;
        assert_eq!(
            resume().await.1,
            json!({"state": "no_session"}),
            "non-revealing"
        );
        assert!(guest_kill_switch_engaged(&e.redis).await.unwrap());
        e.redis.del_raw(CONTROL_KEY).await.unwrap();
        assert_eq!(resume().await.1["state"], "active");
        e.redis.set_raw(CONTROL_KEY, "disabled").await.unwrap();
        assert_eq!(resume().await.0, 503);
        assert!(guest_kill_switch_engaged(&e.redis).await.is_err());
        e.redis.flush_db_for_test().await;
    }

    /// `GET /guest/resume`: the record's face for the cookie, no secret; `no_session`
    /// without a live record; a foreign origin refused.
    #[tokio::test]
    async fn the_resume_vectors() {
        let Some(e) = env(|c| {
            c.guest_claim_enabled = true;
            c.guest_client_url = Some(url::Url::parse("https://meet.example.org/start").unwrap());
        })
        .await
        else {
            return;
        };
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "active", 600).await;
        let key = siwx_oidc::db::guest_invites::guest_account_key(&lp);
        e.redis.hset_raw_for_test(&key, "first_name", "Ada").await;
        e.redis
            .hset_raw_for_test(&key, "second_name", "Lovelace")
            .await;
        let cookie = format!("{}={handle}", guest_cookie_name(&e.config));
        let (status, body, text) = get(&e, "/guest/resume", &[("cookie", &cookie)]).await;
        assert_eq!(status, 200);
        assert_eq!(body["first_name"], "Ada");
        assert_eq!(body["second_name"], "Lovelace");
        assert_eq!(body["state"], "active");
        assert_eq!(body["did"], g.did);
        assert_eq!(body["claim_allowed"], true);
        assert_eq!(body["email_present"], false);
        let left = body["seconds_left"].as_i64().unwrap();
        assert!((590..=600).contains(&left), "{left}");
        assert_eq!(body["client_url"], "https://meet.example.org/start");
        assert_eq!(body.as_object().unwrap().len(), 8);
        assert!(!text.contains(&handle), "no secret in the body");
        e.redis
            .hset_raw_for_test(&key, "email", "a@example.org")
            .await;
        assert_eq!(
            get(&e, "/guest/resume", &[("cookie", &cookie)]).await.1["email_present"],
            true
        );
        // No cookie, an unknown handle, a record that is reaping: no_session.
        for headers in [vec![], vec![("cookie", "guest_session=unknown")]] {
            let (status, body, _) = get(&e, "/guest/resume", &headers).await;
            assert_eq!((status, body), (200, json!({"state": "no_session"})));
        }
        // A cross-origin read is refused.
        let (status, _, _) = get(
            &e,
            "/guest/resume",
            &[("cookie", &cookie), ("origin", "https://evil.example.org")],
        )
        .await;
        assert_eq!(status, 403);
        let (status, _, _) = get(
            &e,
            "/guest/resume",
            &[("cookie", &cookie), ("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(status, 403);
        e.redis.hset_raw_for_test(&key, "state", "reaping").await;
        assert_eq!(
            get(&e, "/guest/resume", &[("cookie", &cookie)]).await.1,
            json!({"state": "no_session"})
        );
    }

    /// `GET /guest/ended` needs no cookie and no record, says the account is deleted and
    /// loads the script that calls `forgetKey()`; the script is on the asset allow-list.
    #[tokio::test]
    async fn the_ended_page_is_served_without_a_cookie_or_a_record() {
        let Some(e) = env(|_| {}).await else { return };
        let (status, _, text) = get(&e, "/guest/ended", &[]).await;
        assert_eq!(status, 200);
        assert!(text.contains("This guest account is deleted; this browser forgets its key."));
        assert!(text.contains("/guest/assets/ended.js"));
        let (status, _, js) = get(&e, "/guest/assets/ended.js", &[]).await;
        assert_eq!(status, 200);
        assert!(js.contains("forgetKey"));
    }

    /// The guest client is a static public client with exactly the configured redirects.
    #[test]
    fn the_guest_client_is_a_public_client_with_exact_redirects() {
        let config = Config {
            guest_enabled: true,
            guest_client_id: Some(CLIENT.into()),
            guest_client_redirect_uris: vec![url::Url::parse(REDIRECT).unwrap()],
            ..Config::default()
        };
        let (id, entry) = crate::guest::guest_client_entry(&config).unwrap().unwrap();
        assert_eq!(id, CLIENT);
        assert_eq!(
            entry.metadata.token_endpoint_auth_method(),
            Some(&openidconnect::core::CoreClientAuthMethod::None)
        );
        let uris: Vec<_> = entry
            .metadata
            .redirect_uris()
            .iter()
            .map(|u| u.as_str())
            .collect();
        assert_eq!(uris, [REDIRECT]);
        let off = Config::default();
        assert!(crate::guest::guest_client_entry(&off).unwrap().is_none());
    }

    // ---- S5: refresh verdict, POST /guest/end ----

    fn read(state: Option<&str>, deadline: Option<i64>, device: bool) -> GuestRefreshRead {
        GuestRefreshRead {
            state: state.map(str::to_string),
            deadline,
            device_recorded: device,
            now: 1_000,
            created_at: Some(500),
            disabled: false,
            reap_before: None,
        }
    }
    use siwx_oidc::db::guest_records::GuestRefreshRead;

    /// The refusals of contract section 6 as a pure function, including the kill switch
    /// and `reap_before` (S6).
    #[test]
    fn st11_the_refresh_verdict_has_exactly_the_refusals() {
        let ok = |r: GuestRefreshRead| refresh_verdict(&r);
        assert!(ok(read(Some("active"), Some(1_001), true)));
        assert!(ok(read(Some("minted"), Some(2_000), true)));
        // at the deadline: refused (`now < deadline` is the live side)
        assert!(!ok(read(Some("active"), Some(1_000), true)));
        assert!(!ok(read(Some("active"), Some(900), true)));
        assert!(!ok(read(Some("reaping"), Some(2_000), true)));
        let mut killed = read(Some("active"), Some(2_000), true);
        killed.disabled = true;
        assert!(!ok(killed));
        assert!(!ok(read(Some("active"), Some(2_000), false)));
        assert!(!ok(read(None, None, false)));
        assert!(!ok(read(Some("weird"), Some(2_000), true)));
        // a claimed account is a persistent account: not this guard's
        assert!(ok(read(Some("claimed"), Some(1), false)));
        // reap_before: minted at or before it is refused, after it is untouched, a
        // missing mint time matches, a claimed record is never touched
        let mut rb = read(Some("active"), Some(2_000), true);
        rb.reap_before = Some(500);
        assert!(!ok(rb.clone()));
        rb.reap_before = Some(499);
        assert!(ok(rb.clone()));
        rb.created_at = None;
        assert!(!ok(rb));
        let mut claimed = read(Some("claimed"), Some(1), false);
        claimed.reap_before = Some(10_000);
        claimed.disabled = true;
        assert!(ok(claimed));
    }

    async fn post_end(e: &Env, headers: &[(&str, &str)]) -> (u16, Value, Vec<String>) {
        // The guest layers take JSON only on a POST, as on every guest route.
        let mut r = reqwest::Client::new()
            .post(format!("{}/guest/end", e.base))
            .header("content-type", "application/json")
            .body("{}");
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        let r = r.send().await.unwrap();
        let status = r.status().as_u16();
        let cookies = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let body = r.json::<Value>().await.unwrap_or(Value::Null);
        (status, body, cookies)
    }

    async fn deadline_and_due(e: &Env, localpart: &str) -> (i64, Option<f64>) {
        let d = e
            .redis
            .get_hash_field_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(localpart),
                "deadline",
            )
            .await
            .unwrap()
            .parse()
            .unwrap();
        (d, e.redis.zscore_for_test("guest:due", localpart).await)
    }

    /// `POST /guest/end`: the Bearer, the cookie (same-origin only), a foreign origin
    /// (403), a claimed account (409), a second call (200), no credential (401).
    #[tokio::test]
    async fn st33_the_guest_end_vectors() {
        let Some(e) = env(|_| {}).await else { return };
        let now = Utc::now().timestamp();
        let same = [("origin", ISSUER)];

        // the cookie
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "active", 600).await;
        let cookie = format!("{}={handle}", guest_cookie_name(&e.config));
        let (st, body, set) = post_end(&e, &[("cookie", &cookie), ("origin", ISSUER)]).await;
        assert_eq!((st, body["state"].as_str()), (200, Some("ending")));
        assert!(
            set[0].contains("guest_session=;") && set[0].contains("Max-Age=0"),
            "{set:?}"
        );
        let (d, due) = deadline_and_due(&e, &lp).await;
        assert!(
            (now - 2..=now + 2).contains(&d),
            "deadline moved to now: {d} vs {now}"
        );
        assert_eq!(due, Some(d as f64));
        // twice: 200, deadline not moved again
        let (st, body, _) = post_end(&e, &[("cookie", &cookie), ("origin", ISSUER)]).await;
        assert_eq!((st, body["state"].as_str()), (200, Some("ending")));
        assert_eq!(deadline_and_due(&e, &lp).await.0, d);

        // a foreign origin, a cross-site fetch, and no provenance at all: 403, nothing moved
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "active", 600).await;
        let cookie = format!("{}={handle}", guest_cookie_name(&e.config));
        for hs in [
            vec![
                ("cookie", cookie.as_str()),
                ("origin", "https://evil.example.org"),
            ],
            vec![
                ("cookie", cookie.as_str()),
                ("origin", ISSUER),
                ("sec-fetch-site", "cross-site"),
            ],
            vec![("cookie", cookie.as_str())],
        ] {
            let (st, body, _) = post_end(&e, &hs).await;
            assert_eq!(
                (st, body["error"].as_str()),
                (403, Some("forbidden_origin"))
            );
        }
        assert!(deadline_and_due(&e, &lp).await.0 > now + 500);
        // no credential: 401
        let (st, body, _) = post_end(&e, &same).await;
        assert_eq!((st, body["error"].as_str()), (401, Some("invalid_token")));
        // a cookie whose record is gone: 200 ended, cookie cleared
        let unknown = format!("{}=nosuchhandle", guest_cookie_name(&e.config));
        let (st, body, set) =
            post_end(&e, &[("cookie", unknown.as_str()), ("origin", ISSUER)]).await;
        assert_eq!((st, body["state"].as_str()), (200, Some("ended")));
        assert!(set[0].contains("Max-Age=0"));

        // claimed: 409, nothing moved
        let g = Guest::new();
        let (lp, handle) = record(&e, &g, "claimed", 600).await;
        let cookie = format!("{}={handle}", guest_cookie_name(&e.config));
        let (st, body, _) = post_end(&e, &[("cookie", &cookie), ("origin", ISSUER)]).await;
        assert_eq!((st, body["error"].as_str()), (409, Some("claimed")));
        assert!(deadline_and_due(&e, &lp).await.0 > now + 500);
        assert_eq!(e.redis.zscore_for_test("guest:due", &lp).await, None);

        // the Bearer, from another origin (the portal), no origin check, CORS open
        let g = Guest::new();
        let (lp, _) = record(&e, &g, "active", 600).await;
        let token = seed_token(&e, &lp, &g.did).await;
        let bearer = format!("Bearer {token}");
        let portal = [
            ("authorization", bearer.as_str()),
            ("origin", "https://meet.example.org"),
        ];
        let (st, body, _) = post_end(&e, &portal).await;
        assert_eq!((st, body["state"].as_str()), (200, Some("ending")));
        let (d, due) = deadline_and_due(&e, &lp).await;
        assert!((now - 2..=now + 2).contains(&d));
        assert_eq!(due, Some(d as f64));
        let (st, _, _) = post_end(&e, &portal).await;
        assert_eq!(st, 200, "a second call on an ending record");
        // a valid token that is not a guest's, and a bad token
        let other = seed_token(&e, &format!("host{}", uniq()), "did:key:zHost").await;
        let (st, body, _) = post_end(&e, &[("authorization", &format!("Bearer {other}"))]).await;
        assert_eq!((st, body["error"].as_str()), (403, Some("not_a_guest")));
        let (st, _, _) = post_end(&e, &[("authorization", "Bearer nope")]).await;
        assert_eq!(st, 401);
        // a guest at the Bearer whose record is claimed: 409
        let g = Guest::new();
        let (lp, _) = record(&e, &g, "claimed", 600).await;
        let token = seed_token(&e, &lp, &g.did).await;
        let (st, _, _) = post_end(&e, &[("authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(st, 409);
    }
}
