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
// Provider-attested DID assertions (the `proof` half of the `io.inblock.did`
// profile object).
//
// W1a ships the minter and its wire-format contract; the write channel that
// calls it lives in `oidc::provision_synapse_device` and lands in the following
// task. Until then nothing in the binary calls into this module, so it is dead
// code by construction. The allow sits HERE, on the declaration, so it is a
// single line to delete when the write channel lands — rather than a scatter of
// per-item allows that would quietly outlive their reason.
#[allow(dead_code)]
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
