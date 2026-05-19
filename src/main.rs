mod axum_lib;
mod compat;
mod config;
#[cfg(feature = "identity")]
mod identity;
mod introspect;
mod oidc;
mod synapse_client;
mod webauthn;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
