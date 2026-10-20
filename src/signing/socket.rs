//! The `socket` backend: siwx-oidc asks a separate `siwx-signer` process,
//! which alone holds the private key, over a Unix socket ([`super::protocol`]).
//!
//! The public key is asked for once, at start ([`SocketSigner::connect`]), and
//! its `kid` is derived here from the key the signer answers with, never taken
//! from the answer: a signer that names a `kid` other than the one its key
//! derives to is refused. Every signature is then checked before it is used:
//! the answer must name that `kid`, and the signature must verify against the
//! cached public key (one P-256 verify). A failure is an error, never a token.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::protocol::{self, PublicAnswer, SignAnswer, MAX_ANSWER_BYTES};
use super::{fingerprint_of_public, ProviderSigner, Purpose, SignError};

/// The default bound on one signer round trip.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// A signer reached over a Unix socket.
pub struct SocketSigner {
    path: PathBuf,
    timeout: Duration,
    kid: String,
    verifying_key: VerifyingKey,
}

impl SocketSigner {
    /// Ask the signer at `path` for its public key, and keep it.
    ///
    /// Fails when the signer cannot be reached within `timeout`, answers
    /// anything but an ES256 P-256 public key, or names a `kid` other than the
    /// one this process derives from that key.
    pub async fn connect(path: impl Into<PathBuf>, timeout: Duration) -> Result<Self, SignError> {
        let path = path.into();
        let answer = round_trip(&path, timeout, &protocol::public_request()).await?;
        let public: PublicAnswer = match protocol::parse_answer(&answer) {
            Some(Ok(public)) => public,
            Some(Err(code)) => return Err(SignError::Refused(code)),
            None => return Err(SignError::BadAnswer),
        };
        if public.alg != "ES256" {
            return Err(SignError::BadAnswer);
        }
        let verifying_key = p256_from_jwk(&public.jwk).ok_or(SignError::BadAnswer)?;
        let kid = fingerprint_of_public(&verifying_key);
        if public.kid != kid {
            return Err(SignError::KidMismatch {
                expected: kid,
                got: public.kid,
            });
        }
        Ok(Self {
            path,
            timeout,
            kid,
            verifying_key,
        })
    }

    /// The socket this signer is reached at.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl ProviderSigner for SocketSigner {
    fn backend(&self) -> &'static str {
        "socket"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn is_ephemeral(&self) -> bool {
        false
    }

    async fn sign(&self, purpose: Purpose, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let request = protocol::sign_request(purpose, message);
        let answer = round_trip(&self.path, self.timeout, &request).await?;
        let signed: SignAnswer = match protocol::parse_answer(&answer) {
            Some(Ok(signed)) => signed,
            Some(Err(code)) => return Err(SignError::Refused(code)),
            None => return Err(SignError::BadAnswer),
        };
        if signed.kid != self.kid {
            return Err(SignError::KidMismatch {
                expected: self.kid.clone(),
                got: signed.kid,
            });
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&signed.sig)
            .map_err(|_| SignError::BadAnswer)?;
        // Raw r‖s, exactly 64 bytes: `from_slice` refuses any other length,
        // DER included.
        let signature = Signature::from_slice(&bytes).map_err(|_| SignError::BadSignature)?;
        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| SignError::BadSignature)?;
        Ok(bytes)
    }
}

/// The P-256 public key of an EC JWK (`kty` EC, `crv` P-256, `x`, `y`), or
/// `None`. The point is checked to be on the curve.
fn p256_from_jwk(jwk: &serde_json::Value) -> Option<VerifyingKey> {
    if jwk.get("kty")?.as_str()? != "EC" || jwk.get("crv")?.as_str()? != "P-256" {
        return None;
    }
    let coordinate = |name: &str| {
        URL_SAFE_NO_PAD
            .decode(jwk.get(name)?.as_str()?)
            .ok()
            .filter(|c| c.len() == 32)
    };
    let mut sec1 = vec![0x04];
    sec1.extend(coordinate("x")?);
    sec1.extend(coordinate("y")?);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// One request and its answer, the whole exchange bounded by `timeout`.
async fn round_trip(path: &Path, timeout: Duration, request: &[u8]) -> Result<Vec<u8>, SignError> {
    let exchange = async {
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|e| SignError::Unavailable(e.to_string()))?;
        stream
            .write_all(request)
            .await
            .map_err(|e| SignError::Unavailable(e.to_string()))?;
        let mut answer = Vec::new();
        (&mut stream)
            .take(MAX_ANSWER_BYTES as u64 + 1)
            .read_to_end(&mut answer)
            .await
            .map_err(|e| SignError::Unavailable(e.to_string()))?;
        if answer.is_empty() {
            // The signer closes without an answer only on a refused peer.
            return Err(SignError::Unavailable(
                "the signer closed the connection without an answer".to_string(),
            ));
        }
        if answer.len() > MAX_ANSWER_BYTES {
            return Err(SignError::BadAnswer);
        }
        Ok(answer)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| SignError::Timeout(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)))?
}
