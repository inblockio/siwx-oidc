//! The `/guest` routes. Every route registered here is read by
//! `tests/openapi_covers_every_route.rs`, as the ones in `axum_lib.rs` are, so a
//! guest endpoint cannot ship undocumented. The shared rules (headers, JSON only,
//! body cap, origin check, CORS, the 503 and 404 shells) are in [`super::layers`].

use std::sync::Arc;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use super::handoff;
use super::invite::{self, GuestState};
use super::redeem;
use crate::config::Config;
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::RedisClient;

/// The join page: the same bytes for every invite id. The page reads the id from its
/// path and the secret from `location.hash`, which a browser never sends.
const JOIN_HTML: &str = include_str!("../../static/guest/join.html");

/// The only files `/guest/assets/{file}` serves. Compiled in, so no path from the
/// request ever reaches the file system.
const ASSETS: [(&str, &str, &str); 5] = [
    (
        "continue.js",
        "text/javascript; charset=utf-8",
        include_str!("../../static/guest/continue.js"),
    ),
    (
        "continue-message.js",
        "text/javascript; charset=utf-8",
        include_str!("../../static/guest/continue-message.js"),
    ),
    (
        "join.js",
        "text/javascript; charset=utf-8",
        include_str!("../../static/guest/join.js"),
    ),
    (
        "guest-key.js",
        "text/javascript; charset=utf-8",
        include_str!("../../static/guest/guest-key.js"),
    ),
    (
        "guest.css",
        "text/css; charset=utf-8",
        include_str!("../../static/guest/guest.css"),
    ),
];

/// `GET /guest/join/{invite_id}`. The id is not read: a link scanner and a stranger
/// get the page a guest gets, and learn nothing about the invite.
async fn join_page() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        JOIN_HTML,
    )
        .into_response()
}

/// `GET /guest/assets/{file}`: a fixed allow-list, else the guest 404.
async fn asset(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    match ASSETS.iter().find(|(name, _, _)| *name == file) {
        Some((_, content_type, body)) => {
            ([(header::CONTENT_TYPE, *content_type)], *body).into_response()
        }
        None => super::layers::error(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// The guest router, merged into the app after the global CORS layer.
pub fn router(config: &Config, redis: RedisClient, synapse: Option<Arc<SynapseClient>>) -> Router {
    // Authorised by the guest cookie or by nothing: origin-checked, no CORS.
    let state = GuestState::new(config.clone(), redis, synapse);
    let cookie_routes = Router::new()
        .route("/guest/peek", post(redeem::peek))
        .route("/guest/redeem", post(redeem::redeem))
        // The hand-off ceremony (S4): the page for the browser, the proof from its script.
        .route(
            "/guest/continue",
            get(handoff::continue_page).post(handoff::continue_post),
        )
        // Top-level navigations and sub-resources of the join page: GET, so the
        // origin check (POST only) does not apply; the layers still add the headers.
        .route("/guest/join/{invite_id}", get(join_page))
        .route("/guest/assets/{file}", get(asset))
        .with_state(state.clone());
    // Authorised by a Bearer token: `*` CORS, no origin check.
    let bearer_routes = Router::new()
        .route("/guest/invites", post(invite::create).get(invite::list))
        .route("/guest/invites/{invite_id}/end", post(invite::end_invite))
        .route("/guest/meetings/end", post(invite::end_meeting))
        .with_state(state);
    super::layers::build(
        config.guest_enabled,
        &config.base_url,
        cookie_routes,
        bearer_routes,
    )
}
