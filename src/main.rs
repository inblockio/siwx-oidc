mod axum_lib;
mod config;
mod introspect;
mod oidc;
mod webauthn;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
