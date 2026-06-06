use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use siwx_oidc_auth::{authenticate_device_flow, authenticate_with_device, refresh, SiwxKey};

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

    /// Use RFC 8628 Device Authorization Grant. The user approves on another
    /// device (browser with wallet or passkey). No local signing key needed.
    #[arg(long)]
    device_flow: bool,

    /// Base URL of the siwx-oidc server (required unless --print-did).
    #[arg(long, required_unless_present = "print_did")]
    server: Option<String>,

    /// OIDC client ID registered with the server.
    #[arg(long, required_unless_present = "print_did")]
    client_id: Option<String>,

    /// Registered redirect URI (required for initial auth code flow).
    #[arg(long)]
    redirect_uri: Option<String>,

    /// Pin a stable Matrix device_id for this session. When set, the server
    /// provisions (and re-provisions) this exact Synapse device instead of
    /// minting a fresh SIWX_<uuid> on every login. Use a stable value (e.g. the
    /// service-account name) so a long-lived agent keeps one device across
    /// re-authentications. Auth-code flow only.
    #[arg(long)]
    device_id: Option<String>,

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

    /// Refresh token from a previous authentication. When provided, exchanges
    /// it for new tokens instead of performing a full auth flow.
    #[arg(long)]
    refresh_token: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum KeyTypeArg {
    Ed25519,
    P256,
}

fn load_key(cli: &Cli) -> Result<SiwxKey> {
    if let Some(path) = &cli.key_file {
        let key = SiwxKey::from_pem_file(path)?;
        eprintln!("Loaded {} key from {}", key.type_label(), path.display());
        return Ok(key);
    }

    if let Some(hex) = &cli.key_hex {
        return match cli.key_type {
            KeyTypeArg::Ed25519 => SiwxKey::ed25519_from_hex(hex),
            KeyTypeArg::P256 => SiwxKey::p256_from_hex(hex),
        };
    }

    let key = match cli.key_type {
        KeyTypeArg::Ed25519 => SiwxKey::generate_ed25519(),
        KeyTypeArg::P256 => SiwxKey::generate_p256(),
    };
    eprintln!(
        "No key provided -- generated ephemeral {} key.\n\
         Save this PEM to reuse the same DID:\n\n{}",
        key.type_label(),
        key.to_pem()?,
    );
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.print_did {
        let key = load_key(&cli)?;
        println!("{}", key.did());
        return Ok(());
    }

    let server = cli.server.as_deref().unwrap();
    let client_id = cli.client_id.as_deref().unwrap();

    if server.is_empty() || client_id.is_empty() {
        bail!("--server and --client-id are required");
    }

    if cli.device_flow {
        let tokens = authenticate_device_flow(server, client_id).await?;
        println!("{}", serde_json::to_string_pretty(&tokens)?);
        return Ok(());
    }

    let key = load_key(&cli)?;
    eprintln!("DID: {}", key.did());

    let tokens = if let Some(rt) = &cli.refresh_token {
        refresh(server, client_id, rt, &key.did()).await?
    } else {
        let redirect_uri = cli.redirect_uri.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--redirect-uri is required for initial authentication")
        })?;
        if redirect_uri.is_empty() {
            bail!("--redirect-uri must not be empty");
        }
        authenticate_with_device(
            server,
            client_id,
            redirect_uri,
            &key,
            cli.device_id.as_deref(),
        )
        .await?
    };
    println!("{}", serde_json::to_string_pretty(&tokens)?);
    Ok(())
}
