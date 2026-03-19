use anyhow::Result;
use clap::{Parser, ValueEnum};
use siwx_oidc_auth::{authenticate, SiwxKey};

/// Headless OIDC client for siwx-oidc.
///
/// Authenticates with a siwx-oidc server using a local did:key private key
/// and prints the resulting OIDC tokens as JSON.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Base URL of the siwx-oidc server.
    #[arg(long)]
    server: String,

    /// OIDC client ID registered with the server.
    #[arg(long)]
    client_id: String,

    /// Registered redirect URI (must be in Resources of the signed message).
    #[arg(long)]
    redirect_uri: String,

    /// Key type to use for signing.
    #[arg(long, default_value = "ed25519")]
    key_type: KeyTypeArg,

    /// Hex-encoded private key (32 bytes). If omitted, a random key is generated.
    #[arg(long)]
    key_hex: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum KeyTypeArg {
    Ed25519,
    P256,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let key = match (&cli.key_type, &cli.key_hex) {
        (KeyTypeArg::Ed25519, Some(hex)) => SiwxKey::ed25519_from_hex(hex)?,
        (KeyTypeArg::P256, Some(hex)) => SiwxKey::p256_from_hex(hex)?,
        (KeyTypeArg::Ed25519, None) => {
            let k = SiwxKey::generate_ed25519();
            eprintln!("Generated DID: {}", k.did());
            k
        }
        (KeyTypeArg::P256, None) => {
            let k = SiwxKey::generate_p256();
            eprintln!("Generated DID: {}", k.did());
            k
        }
    };

    let tokens = authenticate(&cli.server, &cli.client_id, &cli.redirect_uri, &key).await?;
    println!("{}", serde_json::to_string_pretty(&tokens)?);
    Ok(())
}
