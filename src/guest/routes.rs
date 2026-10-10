//! The `/guest` routes. Every route registered here is read by
//! `tests/openapi_covers_every_route.rs`, as the ones in `axum_lib.rs` are, so a
//! guest endpoint cannot ship undocumented. The shared rules (headers, JSON only,
//! body cap, origin check, CORS, the 503 and 404 shells) are in [`super::layers`].

use axum::Router;

use crate::config::Config;

/// The guest router, merged into the app after the global CORS layer.
pub fn router(config: &Config) -> Router {
    // Authorised by the guest cookie or by nothing: origin-checked, no CORS.
    let cookie_routes = Router::new();
    // Authorised by a Bearer token: `*` CORS, no origin check.
    let bearer_routes = Router::new();
    super::layers::build(
        config.guest_enabled,
        &config.base_url,
        cookie_routes,
        bearer_routes,
    )
}
