use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use siwx_oidc_auth::{
    authenticate_device_flow, authenticate_with_device, fetch_and_verify_did, refresh, AuthTokens,
    SiwxKey,
};

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
    ///
    /// With --verify-did this is the ISSUER whose JWKS must have signed the
    /// assertion. It is a trust anchor, not a hint: pointing it at a server the
    /// user controls would make any DID "verify".
    #[arg(long, required_unless_present = "print_did")]
    server: Option<String>,

    /// Verify the provider-attested DID published in this Matrix ID's profile
    /// (`@localpart:server`) and print it as JSON.
    ///
    /// Fetches `io.inblock.did` from --homeserver, verifies the proof against
    /// --server's JWKS, and — the part that matters — checks that the proof's
    /// `mxid` claim is this exact account, so a proof copied out of somebody
    /// else's public profile is rejected rather than accepted.
    ///
    /// The result is a DISCOVERY HINT, not authorization: it proves the
    /// provider asserted this binding, not that whoever you are talking to
    /// controls the DID key. Authorize from an OIDC `sub` this provider issued,
    /// or from a fresh signature by the DID key itself.
    #[arg(long, value_name = "MXID", requires = "homeserver")]
    verify_did: Option<String>,

    /// Base URL of the Matrix homeserver's client API (e.g.
    /// https://matrix.example.org). Used with --verify-did.
    #[arg(long)]
    homeserver: Option<String>,

    /// OIDC client ID registered with the server.
    ///
    /// Not needed for --verify-did: reading and verifying a published DID is an
    /// unauthenticated, client-less operation (the profile GET is public and
    /// the JWKS is public), so requiring a registered client would be theatre.
    #[arg(long, required_unless_present_any = ["print_did", "verify_did"])]
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
    ///
    /// Needs no key: the refresh request carries no signature. Key input, when
    /// given, only fills the output's `did`; without it `did` is left out.
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

/// The key for `--refresh-token`: the one the caller supplied, or none. Never
/// a generated one.
///
/// The refresh grant sends `grant_type`, `client_id` and `refresh_token` and
/// nothing signed (`siwx_oidc_auth::refresh`), so the server never sees a key.
/// A supplied key only labels the output's `did`. Generating one, as
/// [`load_key`] does for sign-in, would report a random DID that has nothing
/// to do with the session, and print a private key nobody asked for.
fn refresh_key(cli: &Cli) -> Result<Option<SiwxKey>> {
    if cli.key_file.is_none() && cli.key_hex.is_none() {
        return Ok(None);
    }
    load_key(cli).map(Some)
}

/// The JSON printed for a refresh. The refresh response has no ID token, so
/// the session's DID is known only from a supplied key; without one the `did`
/// member is left out rather than filled with a guess.
fn refresh_output(tokens: &AuthTokens, did_known: bool) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(tokens)?;
    if !did_known {
        if let Some(object) = value.as_object_mut() {
            object.remove("did");
        }
    }
    Ok(value)
}

/// `--refresh-token`: exchange the refresh token for new tokens and build the
/// JSON to print.
///
/// Split out of `main` so the rule is tested where it is applied: without key
/// input no key is loaded or generated, the exchange is given no DID, and the
/// output leaves `did` out. `exchange` performs the refresh request, given the
/// DID to label the tokens with (empty when unknown); `main` passes
/// [`refresh`].
async fn refresh_command<F, Fut>(cli: &Cli, exchange: F) -> Result<serde_json::Value>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<AuthTokens>>,
{
    let key = refresh_key(cli)?;
    let did = key.as_ref().map(SiwxKey::did);
    if let Some(did) = &did {
        eprintln!("DID: {did}");
    }
    let tokens = exchange(did.clone().unwrap_or_default()).await?;
    refresh_output(&tokens, did.is_some())
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

    // --verify-did is a read-only lookup: no key, no client_id, no tokens. It
    // must run before client_id is unwrapped, which is None for this mode.
    if let Some(mxid) = cli.verify_did.as_deref() {
        // clap's `requires = "homeserver"` already enforces this; the explicit
        // error keeps the failure honest if that attribute is ever dropped.
        let homeserver = cli
            .homeserver
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--homeserver is required with --verify-did"))?;
        let verified = fetch_and_verify_did(homeserver, mxid, server).await?;
        println!("{}", serde_json::to_string_pretty(&verified)?);
        return Ok(());
    }

    let client_id = cli.client_id.as_deref().unwrap();

    if server.is_empty() || client_id.is_empty() {
        bail!("--server and --client-id are required");
    }

    if cli.device_flow {
        let tokens = authenticate_device_flow(server, client_id).await?;
        println!("{}", serde_json::to_string_pretty(&tokens)?);
        return Ok(());
    }

    if let Some(rt) = &cli.refresh_token {
        let output = refresh_command(&cli, |did| async move {
            refresh(server, client_id, rt, &did).await
        })
        .await?;
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let key = load_key(&cli)?;
    eprintln!("DID: {}", key.did());

    let redirect_uri = cli
        .redirect_uri
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--redirect-uri is required for initial authentication"))?;
    if redirect_uri.is_empty() {
        bail!("--redirect-uri must not be empty");
    }
    let tokens = authenticate_with_device(
        server,
        client_id,
        redirect_uri,
        &key,
        cli.device_id.as_deref(),
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&tokens)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn parse(args: &[&str]) -> Cli {
        // `--key-file` also reads SIWX_KEY_FILE; these tests are about the
        // flags alone.
        std::env::remove_var("SIWX_KEY_FILE");
        let mut argv = vec![
            "siwx-oidc-auth",
            "--server",
            "https://id.example.org",
            "--client-id",
            "agent",
            "--refresh-token",
            "mcr_example",
        ];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).expect("valid arguments")
    }

    fn tokens(did: &str) -> AuthTokens {
        AuthTokens {
            access_token: "mat_example".to_string(),
            token_type: "bearer".to_string(),
            id_token: None,
            expires_in: Some(300),
            refresh_token: Some("mcr_next".to_string()),
            did: did.to_string(),
        }
    }

    /// The refresh request carries no signature, so without key input the CLI
    /// must not invent a key (and with it a DID for the output).
    #[test]
    fn refresh_without_key_input_generates_no_key() {
        assert!(refresh_key(&parse(&[])).unwrap().is_none());
    }

    #[test]
    fn refresh_uses_a_supplied_key_to_label_the_did() {
        let key = refresh_key(&parse(&["--key-hex", HEX_SEED]))
            .unwrap()
            .expect("a supplied key is used");
        assert_eq!(
            key.did(),
            SiwxKey::ed25519_from_hex(HEX_SEED).unwrap().did()
        );
    }

    /// The whole refresh command, not just its helpers: with no key input the
    /// exchange is given no DID and the printed JSON carries none. Generating
    /// a key here would label the session with a random DID.
    #[tokio::test]
    async fn the_refresh_command_without_key_input_sends_and_prints_no_did() {
        let seen = std::sync::Mutex::new(None);
        let output = refresh_command(&parse(&[]), |did| {
            *seen.lock().unwrap() = Some(did.clone());
            async move { Ok(tokens(&did)) }
        })
        .await
        .unwrap();
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(""),
            "no DID may be sent"
        );
        assert!(
            output.get("did").is_none(),
            "no DID may be printed: {output}"
        );
        assert_eq!(output["access_token"], "mat_example");
    }

    #[tokio::test]
    async fn the_refresh_command_labels_the_tokens_with_a_supplied_key() {
        let expected = SiwxKey::ed25519_from_hex(HEX_SEED).unwrap().did();
        let output = refresh_command(&parse(&["--key-hex", HEX_SEED]), |did| async move {
            Ok(tokens(&did))
        })
        .await
        .unwrap();
        assert_eq!(output["did"], expected.as_str());
    }

    #[test]
    fn refresh_output_leaves_out_a_did_it_does_not_know() {
        let without = refresh_output(&tokens(""), false).unwrap();
        assert!(without.get("did").is_none(), "{without}");
        assert_eq!(without["access_token"], "mat_example");
        assert_eq!(without["refresh_token"], "mcr_next");

        let with = refresh_output(&tokens("did:key:z6MkExample"), true).unwrap();
        assert_eq!(with["did"], "did:key:z6MkExample");
    }
}
