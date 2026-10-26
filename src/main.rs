// Harmless content marker left by the S5 branch-based CI deploy test
// (2026-07-31), which proved a push to `dev` produced a distinct :dev image on
// GHCR. Historical: CI stopped building a `dev` branch image on 2026-09-29
// (#20).
mod account;
mod admin_token;
mod axum_lib;
mod backchannel;
mod compat;
mod config;
mod device_auth;
// SS4 flag 3: removes devices no client can use (off by default).
mod device_reaper;
// Provider-attested DID assertions: the field name, the `{did, proof}` value
// builder, and the ES256 minter behind the `io.inblock.did` profile object.
//
// The write channel that calls it is `oidc::provision_synapse_account` ->
// `synapse_client::publish_did_field`, reached from BOTH sign-in paths. The
// `#[allow(dead_code)]` that sat here while only the minter existed is gone;
// if it ever needs to come back, that means the publication call site was
// deleted and users stopped getting an attested DID.
mod did_assertion;
mod guest;
mod introspect;
mod localpart;
mod oidc;
// The operator tool `remint-did-assertions`: this binary under a second name.
mod remint;
// GET /resolve: the public DID <-> MXID directory lookup. Read-only, and a
// discovery hint only — see the module doc's "never an authorization source".
mod resolve;
mod synapse_client;
mod teardown;
mod webauthn;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // `remint-did-assertions` is this binary under a second name (the image links it), or its
    // first argument: it needs the server's own modules, which exist only in this crate.
    if let Some(args) = remint::invoked_as_tool(std::env::args()) {
        return remint::cli_main(args).await;
    }
    axum_lib::main().await;
    std::process::ExitCode::SUCCESS
}
