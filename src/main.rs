mod axum_lib;
mod compat;
mod config;
mod introspect;
mod oidc;
mod synapse_client;
mod webauthn;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
