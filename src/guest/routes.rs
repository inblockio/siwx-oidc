//! The `/guest` routes. Every route registered here is read by
//! `tests/openapi_covers_every_route.rs`, as the ones in `axum_lib.rs` are, so a
//! guest endpoint cannot ship undocumented. The shared rules (headers, JSON only,
//! body cap, origin check, CORS, the 503 and 404 shells) are in [`super::layers`].

use std::sync::Arc;

use axum::{routing::post, Router};

use super::invite::{self, GuestState};
use crate::config::Config;
use crate::synapse_client::SynapseClient;
use siwx_oidc::db::RedisClient;

/// The guest router, merged into the app after the global CORS layer.
pub fn router(config: &Config, redis: RedisClient, synapse: Option<Arc<SynapseClient>>) -> Router {
    // Authorised by the guest cookie or by nothing: origin-checked, no CORS.
    let cookie_routes = Router::new();
    // Authorised by a Bearer token: `*` CORS, no origin check.
    let state = GuestState::new(config.clone(), redis, synapse);
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
