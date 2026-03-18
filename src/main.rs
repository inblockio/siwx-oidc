mod axum_lib;
mod config;
mod oidc;

#[tokio::main]
async fn main() {
    axum_lib::main().await
}
