//! `siwx-signer`: the process that alone holds siwx-oidc's private signing key
//! when siwx-oidc runs with `signing_backend = socket`.
//!
//! ```text
//! siwx-signer serve --key-file <path> --socket <path> --issuer <url> [--allowed-uid <uid>]
//! siwx-signer self-test --key-file <path>
//! siwx-signer keygen --out <path>
//! siwx-signer kid --key-file <path>
//! ```
//!
//! Every subcommand first makes the process non-dumpable
//! (`prctl(PR_SET_DUMPABLE, 0)`: no core dump, no ptrace attach by the same
//! uid) and installs a panic hook that prints the location only, never a
//! payload. Nothing this binary prints or logs carries key bytes or the bytes
//! it signs. See `docs/signer.md`.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::zeroize::Zeroizing;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use siwx_oidc::signing::server::{self, ServiceOptions, SignerService};
use siwx_oidc::signing::{EcdsaSigningKey, ProviderSigner};
use tracing::info;

const USAGE: &str = "\
usage:
  siwx-signer serve --key-file <path> --socket <path> --issuer <url> [options]
  siwx-signer self-test --key-file <path>
  siwx-signer keygen --out <path>
  siwx-signer kid --key-file <path>

serve options (each flag can also be set by its environment variable):
  --key-file <path>                 SIWX_SIGNER_KEY_FILE     PKCS#8 P-256 private key (PEM)
  --socket <path>                   SIWX_SIGNER_SOCKET       Unix socket to listen on (mode 0660)
  --issuer <url>                    SIWX_SIGNER_ISSUER       siwx-oidc's base_url; every token's `iss`
  --allowed-uid <uid>               SIWX_SIGNER_ALLOWED_UID  the only peer uid served (default 10001)
  --max-token-lifetime-secs <n>     SIWX_SIGNER_MAX_TOKEN_LIFETIME_SECS  longest exp - iat (default 3600)
  --max-clock-skew-secs <n>         SIWX_SIGNER_MAX_CLOCK_SKEW_SECS      iat distance from now (default 300)
  --rate-alarm-per-minute <n>       SIWX_SIGNER_RATE_ALARM_PER_MINUTE    0 turns it off (default 600)
  --read-timeout-ms <n>             SIWX_SIGNER_READ_TIMEOUT_MS          (default 2000)

self-test loads the key and signs and verifies a fixed internal message
(exit 0 when it works); it is the container healthcheck and signs nothing
outward. keygen writes a fresh key into an EXISTING, EMPTY regular file that
only its owner can read; it prints only `kid=<kid>`. kid prints only
`kid=<kid>`.
";

/// A usage error (exit 2) or a failure (exit 1). The message never carries key
/// bytes.
enum Failure {
    Usage(String),
    Failed(String),
}

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|info| {
        // The location only: a payload could have been formatted from key
        // material somewhere down the call chain.
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "an unknown location".to_string());
        eprintln!("siwx-signer: internal error at {at}; details withheld");
    }));
    if let Err(e) = not_dumpable() {
        eprintln!("siwx-signer: {e}");
        return ExitCode::from(1);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(e)) => {
            eprintln!("siwx-signer: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Failed(e)) => {
            eprintln!("siwx-signer: {e}");
            ExitCode::from(1)
        }
    }
}

/// `prctl(PR_SET_DUMPABLE, 0)`: the kernel writes no core dump of this process
/// and refuses ptrace from processes of the same uid.
fn not_dumpable() -> Result<(), String> {
    // SAFETY: PR_SET_DUMPABLE takes integer arguments only and touches no memory
    // of this process.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "prctl(PR_SET_DUMPABLE, 0) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn run(args: &[String]) -> Result<(), Failure> {
    let Some((command, rest)) = args.split_first() else {
        return Err(Failure::Usage("a subcommand is required".to_string()));
    };
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "serve" => serve(&flags),
        "self-test" => {
            flags.only(&["key-file"])?;
            self_test(&flags.path("key-file", "SIWX_SIGNER_KEY_FILE")?)
        }
        "keygen" => {
            flags.only(&["out"])?;
            let out = flags
                .value("out", None)
                .ok_or_else(|| Failure::Usage("keygen needs --out <path>".to_string()))?;
            let kid = keygen(Path::new(&out)).map_err(Failure::Failed)?;
            println!("kid={kid}");
            Ok(())
        }
        "kid" => {
            flags.only(&["key-file"])?;
            let key = load_key(&flags.path("key-file", "SIWX_SIGNER_KEY_FILE")?)?;
            println!("kid={}", key.kid());
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(Failure::Usage(format!("unknown subcommand `{other}`"))),
    }
}

/// `--name value` and `--name=value` pairs.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(Failure::Usage(format!("unexpected argument `{arg}`")));
            };
            let (name, value) = match flag.split_once('=') {
                Some((name, value)) => (name.to_string(), value.to_string()),
                None => {
                    let value = it
                        .next()
                        .ok_or_else(|| Failure::Usage(format!("--{flag} needs a value")))?;
                    (flag.to_string(), value.clone())
                }
            };
            if pairs.iter().any(|(n, _)| *n == name) {
                return Err(Failure::Usage(format!("--{name} given twice")));
            }
            pairs.push((name, value));
        }
        Ok(Flags(pairs))
    }

    /// Refuse any flag not in `allowed`.
    fn only(&self, allowed: &[&str]) -> Result<(), Failure> {
        match self.0.iter().find(|(n, _)| !allowed.contains(&n.as_str())) {
            Some((name, _)) => Err(Failure::Usage(format!("unknown option --{name}"))),
            None => Ok(()),
        }
    }

    /// The flag's value, else the environment variable's.
    fn value(&self, name: &str, env: Option<&str>) -> Option<String> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .or_else(|| env.and_then(|e| std::env::var(e).ok()))
            .filter(|v| !v.is_empty())
    }

    fn path(&self, name: &str, env: &str) -> Result<PathBuf, Failure> {
        self.value(name, Some(env))
            .map(PathBuf::from)
            .ok_or_else(|| Failure::Usage(format!("--{name} (or {env}) is required")))
    }

    fn number<T: std::str::FromStr>(
        &self,
        name: &str,
        env: &str,
        default: T,
    ) -> Result<T, Failure> {
        match self.value(name, Some(env)) {
            None => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| Failure::Usage(format!("--{name} (or {env}) must be a number"))),
        }
    }
}

/// Load the PKCS#8 P-256 key at `path`. The file's bytes are wiped from memory
/// after parsing; an error names the path and the kind of failure only.
fn load_key(path: &Path) -> Result<EcdsaSigningKey, Failure> {
    let pem = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        Failure::Failed(format!(
            "cannot read the key file {}: {}",
            path.display(),
            e.kind()
        ))
    })?);
    EcdsaSigningKey::from_pem(&pem).map_err(|_| {
        Failure::Failed(format!(
            "the key file {} does not hold a PKCS#8 P-256 private key",
            path.display()
        ))
    })
}

fn self_test(key_file: &Path) -> Result<(), Failure> {
    let key = load_key(key_file)?;
    let message = b"siwx-signer self-test: a fixed internal message, never sent anywhere";
    let raw = key.sign_es256(message);
    let signature = p256::ecdsa::Signature::from_slice(&raw)
        .map_err(|_| Failure::Failed("self-test: the signature is not 64 raw bytes".to_string()))?;
    ProviderSigner::verifying_key(&key)
        .verify(message, &signature)
        .map_err(|_| Failure::Failed("self-test: the signature does not verify".to_string()))?;
    println!("self-test ok kid={}", key.kid());
    Ok(())
}

/// Write a fresh key into `out`, which must already exist, be a regular file
/// (not a symlink), be empty, and be readable by its owner only. The file is
/// opened without `O_CREAT` and with `O_NOFOLLOW`, and checked again through
/// the open handle, so nothing at `out` is created or replaced.
fn keygen(out: &Path) -> Result<String, String> {
    let shown = out.display();
    let meta = std::fs::symlink_metadata(out).map_err(|e| {
        format!(
            "{shown}: {}; keygen writes into an existing, empty file (create it first, with \
             its owner and mode 0600)",
            e.kind()
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{shown} is a symlink; refusing to write through it"
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(out)
        .map_err(|e| format!("cannot open {shown}: {}", e.kind()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect {shown}: {}", e.kind()))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.len() != 0 {
        return Err(format!("{shown} is not empty; refusing to overwrite a key"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is open to group or others (mode {:o}); make it 0600 first",
            meta.permissions().mode() & 0o777
        ));
    }
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| "the new key does not encode to PKCS#8".to_string())?;
    // The kid comes from the one derivation the provider uses, through the PEM
    // as written, so it is the kid this file will load with.
    let key = EcdsaSigningKey::from_pem(&pem)
        .map_err(|_| "the new key does not load back".to_string())?;
    file.write_all(pem.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {shown}: {}", e.kind()))?;
    Ok(key.kid().to_string())
}

fn serve(flags: &Flags) -> Result<(), Failure> {
    flags.only(&[
        "key-file",
        "socket",
        "issuer",
        "allowed-uid",
        "max-token-lifetime-secs",
        "max-clock-skew-secs",
        "rate-alarm-per-minute",
        "read-timeout-ms",
    ])?;
    let key_file = flags.path("key-file", "SIWX_SIGNER_KEY_FILE")?;
    let socket = flags.path("socket", "SIWX_SIGNER_SOCKET")?;
    let issuer = flags
        .value("issuer", Some("SIWX_SIGNER_ISSUER"))
        .ok_or_else(|| {
            Failure::Usage("--issuer (or SIWX_SIGNER_ISSUER) is required".to_string())
        })?;
    let options = ServiceOptions {
        allowed_uid: flags.number(
            "allowed-uid",
            "SIWX_SIGNER_ALLOWED_UID",
            server::DEFAULT_ALLOWED_UID,
        )?,
        issuer,
        max_token_lifetime_secs: flags.number(
            "max-token-lifetime-secs",
            "SIWX_SIGNER_MAX_TOKEN_LIFETIME_SECS",
            server::DEFAULT_MAX_TOKEN_LIFETIME_SECS,
        )?,
        max_clock_skew_secs: flags.number(
            "max-clock-skew-secs",
            "SIWX_SIGNER_MAX_CLOCK_SKEW_SECS",
            server::DEFAULT_MAX_CLOCK_SKEW_SECS,
        )?,
        rate_alarm_per_minute: flags.number(
            "rate-alarm-per-minute",
            "SIWX_SIGNER_RATE_ALARM_PER_MINUTE",
            server::DEFAULT_RATE_ALARM_PER_MINUTE,
        )?,
        read_timeout: Duration::from_millis(flags.number(
            "read-timeout-ms",
            "SIWX_SIGNER_READ_TIMEOUT_MS",
            u64::try_from(server::DEFAULT_READ_TIMEOUT.as_millis()).unwrap_or(2000),
        )?),
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        // Plain text into a container log; colour only on a terminal.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();

    let key = load_key(&key_file)?;
    let allowed_uid = options.allowed_uid;
    let service = SignerService::new(key, options).map_err(|e| Failure::Failed(e.to_string()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failure::Failed(format!("cannot start the runtime: {e}")))?;
    runtime.block_on(async {
        let listener = server::bind(&socket).map_err(|e| Failure::Failed(format!("{e:#}")))?;
        info!(
            kid = %service.kid(),
            socket = %socket.display(),
            allowed_uid,
            "siwx-signer listening"
        );
        let service = Arc::new(service);
        tokio::select! {
            () = service.serve(listener) => {}
            () = shutdown_signal() => {
                info!("siwx-signer stopping");
            }
        }
        // The socket goes with the process; a stale one would be removed at the
        // next start anyway.
        let _ = std::fs::remove_file(&socket);
        Ok(())
    })
}

/// SIGTERM or SIGINT. In a container this process is PID 1, which ignores a
/// signal it installed no handler for.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
