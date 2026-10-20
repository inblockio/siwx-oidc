//! The `siwx-signer` socket service: the only place the private key is used
//! when siwx-oidc runs with `signing_backend = socket`.
//!
//! One request per connection ([`super::protocol`]). The service checks the
//! peer's uid (`SO_PEERCRED`) before it reads a byte and closes a connection
//! from any other uid with a logged `peer_refused uid=<n>`. A request is read
//! up to [`MAX_REQUEST_BYTES`] and within the read timeout; a `sign` request is
//! signed only when its message has the shape its purpose allows
//! ([`super::shape`]).
//!
//! # What is logged
//!
//! One line per request: the operation, the purpose, the `kid`, the message
//! length, the peer uid and the result (with a fixed reason for a shape
//! refusal). Never the message bytes (a token payload carries personal data)
//! and never key material. Signatures are counted per purpose and refusals
//! apart; a summary line is logged each minute that saw any, and a
//! `rate_alarm` warning once in a minute in which the signatures made exceed
//! the configured bound (a refusal signs nothing and is not counted there).
//!
//! # The socket file
//!
//! [`bind`] replaces a socket file only when nothing accepts connections on
//! it (a signer that died), and refuses to start while another signer still
//! serves it. On shutdown the signer removes the socket file only while it is
//! still the one it bound ([`SocketFile::remove`]): when two signers overlap in
//! a restart, the old one's stop never deletes the new one's socket.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use super::protocol::{self, ErrorCode, Request, MAX_REQUEST_BYTES};
use super::shape::{self, ShapePolicy};
use super::{EcdsaSigningKey, ProviderSigner, Purpose};

/// The uid siwx-oidc runs as in the published image.
pub const DEFAULT_ALLOWED_UID: u32 = 10001;
/// The default longest `exp - iat` of a token the signer signs (seconds). It
/// must be at least siwx-oidc's `id_token_ttl_secs` (default 300).
pub const DEFAULT_MAX_TOKEN_LIFETIME_SECS: i64 = 3600;
/// The default allowed distance of `iat` from the signer's clock (seconds).
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 300;
/// The default bound on signatures per minute before `rate_alarm`.
pub const DEFAULT_RATE_ALARM_PER_MINUTE: u64 = 600;
/// The default bound on reading one request.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The mode of the socket: owner and group read and write. The directory's
/// group (shared with siwx-oidc) is set by the operator.
pub const SOCKET_MODE: u32 = 0o660;

/// How the service is run.
#[derive(Clone, Debug)]
pub struct ServiceOptions {
    /// The only uid that may connect.
    pub allowed_uid: u32,
    /// The issuer siwx-oidc writes into `iss` (its `base_url`).
    pub issuer: String,
    pub max_token_lifetime_secs: i64,
    pub max_clock_skew_secs: i64,
    /// Zero turns the alarm off.
    pub rate_alarm_per_minute: u64,
    pub read_timeout: Duration,
}

impl ServiceOptions {
    /// The defaults, for `issuer`.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            allowed_uid: DEFAULT_ALLOWED_UID,
            issuer: issuer.into(),
            max_token_lifetime_secs: DEFAULT_MAX_TOKEN_LIFETIME_SECS,
            max_clock_skew_secs: DEFAULT_MAX_CLOCK_SKEW_SECS,
            rate_alarm_per_minute: DEFAULT_RATE_ALARM_PER_MINUTE,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

/// Counts of the current minute.
#[derive(Default)]
struct Window {
    /// Signatures made, per purpose (indexed by [`slot`]).
    signed: [u64; 4],
    /// Requests refused (any error answer). Not part of the alarm: a refusal
    /// signs nothing.
    refused: u64,
    /// Whether this minute's `rate_alarm` was logged.
    alarmed: bool,
}

impl Window {
    fn signatures(&self) -> u64 {
        self.signed.iter().sum()
    }
}

/// The signing service. Holds the key; never prints it (`EcdsaSigningKey` has
/// no `Debug`).
pub struct SignerService {
    key: EcdsaSigningKey,
    policy: ShapePolicy,
    options: ServiceOptions,
    public_answer: Vec<u8>,
    window: Mutex<Window>,
}

fn slot(purpose: Purpose) -> usize {
    match purpose {
        Purpose::IdToken => 0,
        Purpose::DidProof => 1,
        Purpose::LogoutToken => 2,
        Purpose::Userinfo => 3,
    }
}

impl SignerService {
    /// A service for `key`. The issuer is read as a URL and compared in the
    /// form siwx-oidc writes it (`https://example.org` reads
    /// `https://example.org/`).
    pub fn new(key: EcdsaSigningKey, mut options: ServiceOptions) -> Result<Self> {
        let issuer = url::Url::parse(&options.issuer)
            .with_context(|| format!("--issuer {:?} is not a URL", options.issuer))?;
        options.issuer = issuer.as_str().to_string();
        if options.max_token_lifetime_secs <= 0 || options.max_clock_skew_secs < 0 {
            return Err(anyhow!(
                "the token lifetime bound must be positive and the clock skew not negative"
            ));
        }
        let kid = key.kid().to_string();
        let jwk = serde_json::to_value(ProviderSigner::verification_jwk(&key))
            .context("the public JWK does not encode")?;
        Ok(Self {
            policy: ShapePolicy {
                kid: kid.clone(),
                issuer: options.issuer.clone(),
                max_token_lifetime_secs: options.max_token_lifetime_secs,
                max_clock_skew_secs: options.max_clock_skew_secs,
            },
            public_answer: protocol::public_answer(
                &kid,
                jwk,
                &options.issuer,
                options.max_token_lifetime_secs,
            ),
            key,
            options,
            window: Mutex::new(Window::default()),
        })
    }

    /// The `kid` of the key this service signs with.
    pub fn kid(&self) -> &str {
        self.key.kid()
    }

    /// Accept connections on `listener` until the process ends.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let ticker = self.clone();
        tokio::spawn(async move {
            let mut every_minute = tokio::time::interval(Duration::from_secs(60));
            every_minute.tick().await;
            loop {
                every_minute.tick().await;
                ticker.close_window();
            }
        });
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let service = self.clone();
                    tokio::spawn(async move { service.handle(stream).await });
                }
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Log the minute's counts (when there were any) and start a new minute.
    fn close_window(&self) {
        let window = std::mem::take(&mut *self.window.lock().unwrap_or_else(|e| e.into_inner()));
        if window.signatures() > 0 || window.refused > 0 {
            info!(
                id_tokens = window.signed[slot(Purpose::IdToken)],
                did_proofs = window.signed[slot(Purpose::DidProof)],
                logout_tokens = window.signed[slot(Purpose::LogoutToken)],
                userinfo_responses = window.signed[slot(Purpose::Userinfo)],
                refused = window.refused,
                kid = %self.kid(),
                "sign counts (last minute)"
            );
        }
    }

    /// Count one request: a signature made for `Some(purpose)`, a refusal for
    /// `None`. Warn once in a minute whose signatures exceed the bound.
    fn count(&self, purpose: Option<Purpose>) {
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let Some(purpose) = purpose else {
            window.refused += 1;
            return;
        };
        window.signed[slot(purpose)] += 1;
        let signs = window.signatures();
        let bound = self.options.rate_alarm_per_minute;
        if bound > 0 && signs > bound && !window.alarmed {
            window.alarmed = true;
            warn!(
                signs_per_minute = signs,
                bound,
                kid = %self.kid(),
                "rate_alarm"
            );
        }
    }

    async fn handle(&self, mut stream: UnixStream) {
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(e) => {
                warn!(error = %e, "peer credentials unavailable, connection closed");
                return;
            }
        };
        if uid != self.options.allowed_uid {
            warn!(uid, "peer_refused");
            return;
        }
        let reply = match tokio::time::timeout(self.options.read_timeout, read_request(&mut stream))
            .await
        {
            Err(_) => {
                warn!(peer_uid = uid, result = %"timeout", "request not read in time");
                return;
            }
            Ok(Err(e)) => {
                warn!(peer_uid = uid, error = %e, "request read failed");
                return;
            }
            Ok(Ok(None)) => {
                warn!(peer_uid = uid, result = %ErrorCode::TooLarge, "request refused");
                self.count(None);
                protocol::error_answer(ErrorCode::TooLarge)
            }
            Ok(Ok(Some(line))) => self.answer(&line, chrono::Utc::now().timestamp(), uid),
        };
        let write = async {
            stream.write_all(&reply).await?;
            stream.shutdown().await
        };
        if let Ok(Err(e)) = tokio::time::timeout(self.options.read_timeout, write).await {
            warn!(peer_uid = uid, error = %e, "answer write failed");
        }
    }

    /// The answer to one request line (without its newline), at `now`.
    pub fn answer(&self, line: &[u8], now: i64, peer_uid: u32) -> Vec<u8> {
        let kid = self.kid();
        match protocol::parse_request(line) {
            Err(refusal) => {
                warn!(peer_uid, len = line.len(), result = %refusal, "request refused");
                self.count(None);
                protocol::error_answer(refusal)
            }
            Ok(Request::Public) => {
                info!(op = %"public", kid = %kid, peer_uid, result = %"ok", "request");
                self.public_answer.clone()
            }
            Ok(Request::Sign { purpose, msg }) => {
                match shape::check(&self.policy, purpose, &msg, now) {
                    Err(reason) => {
                        warn!(
                            op = %"sign",
                            purpose = %purpose,
                            kid = %kid,
                            len = msg.len(),
                            peer_uid,
                            result = %ErrorCode::Shape,
                            reason = %reason.as_str(),
                            "request refused"
                        );
                        self.count(None);
                        protocol::error_answer(ErrorCode::Shape)
                    }
                    Ok(()) => {
                        let signature = self.key.sign_es256(&msg);
                        info!(
                            op = %"sign",
                            purpose = %purpose,
                            kid = %kid,
                            len = msg.len(),
                            peer_uid,
                            result = %"ok",
                            "request"
                        );
                        self.count(Some(purpose));
                        protocol::sign_answer(kid, &signature)
                    }
                }
            }
        }
    }
}

/// Read one request: the bytes before the first newline, or before EOF when
/// the client half-closed without one. `None` when it exceeds
/// [`MAX_REQUEST_BYTES`] (newline included) before either.
async fn read_request(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok((line.len() < MAX_REQUEST_BYTES).then_some(line));
        }
        if let Some(end) = chunk[..n].iter().position(|b| *b == b'\n') {
            line.extend_from_slice(&chunk[..end]);
            return Ok((line.len() < MAX_REQUEST_BYTES).then_some(line));
        }
        line.extend_from_slice(&chunk[..n]);
        if line.len() >= MAX_REQUEST_BYTES {
            return Ok(None);
        }
    }
}

/// How long [`bind`] waits for an existing socket to accept a connection.
const LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Bind the socket at `path`, mode [`SOCKET_MODE`].
///
/// An existing socket file is replaced only when nothing accepts connections
/// on it (a signer that died left it). One that a running signer still serves
/// is refused, as is anything else at the path (a file, a directory, a
/// symlink), which is never deleted. Between the bind and the mode change the
/// socket has the umask's mode; a peer that connects in that moment is still
/// refused by the uid check.
///
/// Returns the listener and the [`SocketFile`] it made, which the caller
/// removes on shutdown.
pub fn bind(path: &Path) -> Result<(UnixListener, SocketFile)> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            match accepts_connections(path) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(anyhow!(
                        "{} is served by a running signer; refusing to take it over (stop that \
                         signer first)",
                        path.display()
                    ))
                }
                Err(e) => {
                    return Err(anyhow!(
                        "cannot tell whether a signer still serves {}: {e}; refusing to \
                         replace it",
                        path.display()
                    ))
                }
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing the stale socket {}", path.display()))?
        }
        Ok(_) => {
            return Err(anyhow!(
                "{} exists and is not a socket; refusing to replace it",
                path.display()
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow!("cannot inspect {}: {e}", path.display())),
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    let file = SocketFile::of(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("setting the mode of {}", path.display()))?;
    Ok((listener, file))
}

/// Whether a process accepts connections on the socket at `path`: a connect
/// that succeeds, or does not finish within [`LIVENESS_PROBE_TIMEOUT`] (a full
/// backlog, a stopped process), means yes; a refused one means no. Any other
/// failure is returned, and the caller replaces nothing.
fn accepts_connections(path: &Path) -> io::Result<bool> {
    let (sender, answer) = std::sync::mpsc::channel();
    let probe = path.to_path_buf();
    // A blocking connect in a thread of its own, so a socket that never
    // answers cannot hold the start; the thread ends with its connect.
    std::thread::spawn(move || {
        let _ = sender.send(std::os::unix::net::UnixStream::connect(probe).map(drop));
    });
    match answer.recv_timeout(LIVENESS_PROBE_TIMEOUT) {
        Ok(Ok(())) => Ok(true),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(false),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(true),
    }
}

/// The socket file a [`bind`] made, known by its device and inode.
#[derive(Debug)]
pub struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl SocketFile {
    fn of(path: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspecting the new socket {}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    /// Remove the socket file if it is still the one [`bind`] made. A socket
    /// another signer has bound at the path since is left alone. Returns
    /// whether the file was removed.
    pub fn remove(&self) -> bool {
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.dev() == self.dev && meta.ino() == self.ino => {
                std::fs::remove_file(&self.path).is_ok()
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
