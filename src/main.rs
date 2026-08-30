// Harmless content marker (S5 branch-based CI deploys, 2026-07-31): proves a
// push to `dev` produces a genuinely new, distinct :dev image on GHCR and
// that dev-staging's pull-model timer converges onto it. See
// siwx-oidc-matrix-server's docs/2026-07-30-dev-staging-dev-aquafire.md §9.
mod account;
mod admin_token;
mod axum_lib;
mod compat;
mod config;
mod device_auth;
mod introspect;
mod oidc;
mod synapse_client;
mod webauthn;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
