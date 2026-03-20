use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use siwx_oidc_auth::{authenticate, SiwxKey};

/// Headless OIDC client for siwx-oidc.
///
/// Authenticates with a remote siwx-oidc server using a local did:key
/// private key and prints the resulting OIDC tokens as JSON.
///
/// The server must have "key" in supported_did_methods.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Just print the did:key DID derived from the key and exit.
    #[arg(long)]
    print_did: bool,

    /// Base URL of the siwx-oidc server (required unless --print-did).
    #[arg(long, required_unless_present = "print_did")]
    server: Option<String>,

    /// OIDC client ID registered with the server (required unless --print-did).
    #[arg(long, required_unless_present = "print_did")]
    client_id: Option<String>,

    /// Registered redirect URI (required unless --print-did).
    #[arg(long, required_unless_present = "print_did")]
    redirect_uri: Option<String>,

    // -- Key input (priority: --key-file > SIWX_KEY_FILE > --key-hex > generate) --
    /// Path to a PKCS#8 PEM private key file. Auto-detects Ed25519 vs P-256.
    /// Can also be set via SIWX_KEY_FILE environment variable.
    #[arg(long, env = "SIWX_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Key type (only needed with --key-hex or when generating a key).
    #[arg(long, default_value = "ed25519")]
    key_type: KeyTypeArg,

    /// Hex-encoded 32-byte private key seed. For dev/testing only.
    #[arg(long)]
    key_hex: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum KeyTypeArg {
    Ed25519,
    P256,
}

fn load_key(cli: &Cli) -> Result<SiwxKey> {
    // Priority 1: PEM file (--key-file or SIWX_KEY_FILE env)
    if let Some(path) = &cli.key_file {
        let key = SiwxKey::from_pem_file(path)?;
        eprintln!("Loaded {} key from {}", key.type_label(), path.display());
        return Ok(key);
    }

    // Priority 2: hex seed (--key-hex, needs --key-type)
    if let Some(hex) = &cli.key_hex {
        return match cli.key_type {
            KeyTypeArg::Ed25519 => SiwxKey::ed25519_from_hex(hex),
            KeyTypeArg::P256 => SiwxKey::p256_from_hex(hex),
        };
    }

    // Priority 3: generate ephemeral key, print PEM to stderr for saving
    let key = match cli.key_type {
        KeyTypeArg::Ed25519 => SiwxKey::generate_ed25519(),
        KeyTypeArg::P256 => SiwxKey::generate_p256(),
    };
    eprintln!(
        "No key provided — generated ephemeral {} key.\n\
         Save this PEM to reuse the same DID:\n\n{}",
        key.type_label(),
        key.to_pem()?,
    );
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = load_key(&cli)?;

    if cli.print_did {
        println!("{}", key.did());
        return Ok(());
    }

    // These are required_unless_present = "print_did", so safe to unwrap.
    let server = cli.server.as_deref().unwrap();
    let client_id = cli.client_id.as_deref().unwrap();
    let redirect_uri = cli.redirect_uri.as_deref().unwrap();

    if server.is_empty() || client_id.is_empty() || redirect_uri.is_empty() {
        bail!("--server, --client-id, and --redirect-uri are all required");
    }

    eprintln!("DID: {}", key.did());
    let tokens = authenticate(server, client_id, redirect_uri, &key).await?;
    println!("{}", serde_json::to_string_pretty(&tokens)?);
    Ok(())
}
