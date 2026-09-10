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
// Provider-attested DID assertions: the field name, the `{did, proof}` value
// builder, and the ES256 minter behind the `io.inblock.did` profile object.
//
// The write channel that calls it is `oidc::provision_synapse_device` ->
// `synapse_client::publish_did_field`, reached from BOTH sign-in paths. The
// `#[allow(dead_code)]` that sat here while only the minter existed is gone;
// if it ever needs to come back, that means the publication call site was
// deleted and users stopped getting an attested DID.
mod did_assertion;
mod introspect;
mod localpart;
mod oidc;
mod synapse_client;
mod webauthn;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
