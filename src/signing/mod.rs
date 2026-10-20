//! The provider's signing interface and its backends.
//!
//! Every use of the provider's private key goes through one async trait,
//! [`ProviderSigner`]: ID tokens and signed userinfo (`oidc`), the DID
//! assertion (`did_assertion`) and back-channel logout tokens (`backchannel`).
//! Two backends implement it:
//!
//! | `signing_backend` | Backend | Who holds the private key |
//! |---|---|---|
//! | `pem` | [`EcdsaSigningKey`] from `signing_key_pem` | this process |
//! | `ephemeral` | [`EcdsaSigningKey::generate`] | this process, until it exits |
//! | `socket` | [`socket::SocketSigner`] | the `siwx-signer` process only |
//!
//! # Synchronous openidconnect, asynchronous backends
//!
//! openidconnect's [`PrivateSigningKey::sign`] is synchronous, and a socket
//! round trip is not. Blocking inside it (`block_in_place`) panics on a
//! current-thread runtime, which is what the tests run on. [`sign_jwt`]
//! therefore lets openidconnect build the token against a [`CaptureKey`],
//! which records the signing input and returns a placeholder signature, then
//! signs that input through the backend and puts the real signature in place
//! of the placeholder. The token's header and payload are the bytes
//! openidconnect produced; only the third segment changes.
//!
//! # Shared with `siwx-signer`
//!
//! This module is in the library crate so the `siwx-signer` binary signs with
//! the same [`EcdsaSigningKey`] and derives the same `kid`
//! ([`fingerprint_of_public`]) as the provider: a second copy of either would
//! drift. The wire protocol is [`protocol`], the per-purpose message checks are
//! [`shape`], and the signer's socket service is [`server`].

use std::sync::Mutex;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};
use openidconnect::{JsonWebKeyId, JsonWebTokenError, PrivateSigningKey, SigningError};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey,
};

pub mod protocol;
pub mod server;
pub mod shape;
pub mod socket;

pub use protocol::Purpose;

// -- ES256 key wrapper implementing openidconnect's PrivateSigningKey ------

/// The provider's ES256 signing key, carrying the two facts that anything
/// *durable* signed by it needs to know: **which** key it is (`kid`), and
/// whether it will still exist after the next restart (`ephemeral`).
///
/// # `kid` identifies the KEY, not the slot
///
/// This wrapper used to take a caller-supplied `kid`, and both construction
/// sites in `axum_lib::main` passed the literal `"key1"`, the operator's
/// configured key and the randomly generated fallback were stamped with the
/// SAME identifier. `"key1"` is a *slot* name, not a *key* name, and the
/// distinction stops being cosmetic the moment we sign something that outlives
/// the process.
///
/// DID assertions (`crate::did_assertion`) are written into a user's Synapse
/// profile and stay there indefinitely. Under a constant `kid`, a restart that
/// mints a fresh ephemeral key yields **a different key under the same `kid`**,
/// so every previously stored assertion fails verification as
/// `bad signature`, the single worst diagnostic available, because to a
/// verifier "bad signature" reads as *forgery*, and to an operator it offers
/// nothing to grep for. Deriving `kid` from the public key turns exactly that
/// event into `kid "3f2a…" is not present in the JWKS`: honest, self-describing,
/// and immediately actionable ("the key rotated; set SIWEOIDC_SIGNING_KEY_PEM").
///
/// This is hypothesis H4 of the attested-DID design ("`kid` must identify the
/// key, not the slot"), pinned by
/// `oidc::tests::h4_two_generated_keys_get_different_kids` and
/// `oidc::tests::h4_the_same_pem_yields_the_same_kid_across_constructions`.
///
/// **Do not reintroduce a caller-supplied `kid`.** The constructors deliberately
/// accept no `kid` argument, so a slot name cannot be stamped onto a key again;
/// that absence IS the fix. Likewise, do not "simplify" `kid` back to an
/// `Option<JsonWebKeyId>`: a JWKS entry without a `kid` forces every verifier to
/// trial-verify against every key, which erases the unknown-kid diagnostic this
/// type exists to produce.
#[derive(Clone)]
pub struct EcdsaSigningKey {
    key: SigningKey,
    /// Always present and always derived from `key`, never configured.
    /// See the type-level doc.
    kid: JsonWebKeyId,
    /// `true` when the key was generated at startup and therefore dies with the
    /// process. Read by `did_assertion::mint_did_assertion`, which refuses to
    /// mint a durable, off-server artifact with a key it knows is temporary.
    ephemeral: bool,
}

impl EcdsaSigningKey {
    /// Load the operator's durable key (`SIWEOIDC_SIGNING_KEY_PEM`).
    ///
    /// The resulting key is marked NON-ephemeral, which is what unlocks DID
    /// assertion minting. That marking is a claim about *operator intent*
    /// (a PEM was configured, so the same key is expected across restarts), not
    /// a proof, nothing here can verify the operator will keep passing the same
    /// PEM. The key-derived `kid` is the safety net for when they do not.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("Invalid ECDSA private key PEM: {}", e))?;
        Ok(Self::with_derived_kid(key, false))
    }

    /// Generate a throwaway key for a deployment with no configured PEM.
    ///
    /// Marked ephemeral: tokens signed by it stop verifying at the next restart
    /// (which is merely annoying, clients re-authenticate), and DID assertions
    /// are suppressed entirely (which is the point, see `did_assertion`).
    pub fn generate() -> Self {
        Self::with_derived_kid(SigningKey::random(&mut rand::thread_rng()), true)
    }

    /// The single place a `kid` is computed. Both constructors funnel through
    /// here precisely so the "derive it, never accept it" rule cannot be
    /// violated by adding a third constructor that forgets.
    fn with_derived_kid(key: SigningKey, ephemeral: bool) -> Self {
        let kid = JsonWebKeyId::new(Self::fingerprint_of(&key));
        Self {
            key,
            kid,
            ephemeral,
        }
    }

    /// First 16 hex chars of SHA-256 over the SEC1 **uncompressed** public key.
    ///
    /// 64 bits of a cryptographic hash: not collision-resistant in the
    /// adversarial sense, and it does not need to be. `kid` is a *lookup hint*
    /// into a JWKS this provider publishes, a collision would only ever pick
    /// the wrong key of our own, and the signature check then fails. It is not a
    /// security boundary; the signature is.
    fn fingerprint_of(key: &SigningKey) -> String {
        fingerprint_of_public(key.verifying_key())
    }

    /// Non-sensitive identifier for the signing key: the first 16 hex chars of a
    /// SHA-256 over the SEC1-encoded *public* key. Safe to log, it reveals no
    /// private material but lets operators correlate which ephemeral key is live.
    ///
    /// Identical by construction to `kid()`; kept as a distinct name because the
    /// startup log lines read as "fingerprint" and the JWS header reads as
    /// "kid", and conflating the two names in either place would obscure one of
    /// them.
    pub fn public_key_fingerprint(&self) -> String {
        Self::fingerprint_of(&self.key)
    }

    /// The `kid` published in the JWKS and stamped into every JWS header this
    /// key produces. Derived from the public key; see the type-level doc.
    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    /// `true` when this key was generated at startup and will not survive the
    /// process.
    ///
    /// The one caller that matters is `did_assertion::mint_did_assertion`:
    /// writing a durable assertion into a user's Synapse profile with a key we
    /// KNOW is about to disappear is writing garbage into someone else's
    /// database. Invariant 5 of the plan: never write a durable assertion with
    /// an ephemeral key.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Raw ES256 signature over `message`: **r‖s, exactly 64 bytes, never DER**.
    ///
    /// RFC 7515 §3.1 / RFC 7518 §3.4 mandate the fixed-width concatenation; the
    /// `ecdsa` crate's `Signature::to_bytes()` is already that encoding, while
    /// its `to_der()` is the 70 to 72 byte X.509 form that every JWS verifier
    /// rejects. Do not "helpfully" switch to DER: the failure is silent at mint
    /// time and only surfaces as an unverifiable proof in a stranger's profile.
    /// `did_assertion::tests::signature_is_64_raw_bytes_never_der` asserts the
    /// length explicitly for exactly this reason.
    pub fn sign_es256(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().to_vec()
    }
}

impl PrivateSigningKey for EcdsaSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        _signature_alg: &<CoreJsonWebKey as openidconnect::JsonWebKey>::SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        // JWS ES256 requires the raw r||s encoding (64 bytes), not DER.
        // Delegated so the ID-token path and the DID-assertion path can never
        // drift onto different signature encodings.
        Ok(self.sign_es256(message))
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        verification_jwk(self.key.verifying_key(), self.kid.as_str())
    }
}

/// The `kid` for a P-256 **public** key: first 16 hex chars of SHA-256 over the
/// SEC1 uncompressed encoding.
///
/// Split out of `EcdsaSigningKey::fingerprint_of` (which now delegates here) so
/// that a RETIRED key, of which we hold only the public half, derives a `kid`
/// **byte-identically** to the one it had while it was live. That identity is
/// the entire mechanism: a durably-stored DID assertion carries the `kid` its
/// signer had at mint time, and a verifier resolves it against the JWKS by that
/// string. Two derivations that agree "in principle" but differ in one byte
/// would leave every retired proof unverifiable while looking correct. Do not
/// give the retired path its own copy of this.
pub fn fingerprint_of_public(key: &p256::ecdsa::VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let pubkey = key.to_encoded_point(false);
    let digest = Sha256::digest(pubkey.as_bytes());
    let hex = hex::encode(digest);
    hex[..16].to_string()
}

/// The one place a published verification JWK is constructed, for the live key
/// and for retired keys alike.
///
/// Single-sourced for the same reason as [`fingerprint_of_public`]: a retired
/// key must be indistinguishable, to a verifier, from what the live key
/// published before rotation. `use`/`alg`/`crv` all matter to a strict verifier.
pub fn verification_jwk(verifying_key: &p256::ecdsa::VerifyingKey, kid: &str) -> CoreJsonWebKey {
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let mut jwk_value = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
    });
    // Always present: a JWKS entry with no `kid` forces verifiers to
    // trial-verify against every published key, which destroys the
    // "unknown kid" diagnostic that the key-derived `kid` exists to give
    // (see the `EcdsaSigningKey` doc, H4). It also stops mattering as a
    // nicety the moment more than one key is published, which is exactly
    // what retired keys do.
    jwk_value["kid"] = serde_json::Value::String(kid.to_string());
    serde_json::from_value(jwk_value).expect("Failed to construct EC JWK")
}

// -- The signing interface -------------------------------------------------

/// Why a signature could not be had. The messages name the failure, never the
/// bytes that were to be signed (a token payload carries personal data) and
/// never key material.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The signer could not be reached or the connection broke.
    #[error("the signer is unavailable: {0}")]
    Unavailable(String),
    /// The signer did not answer within the configured bound.
    #[error("the signer did not answer within {0} ms")]
    Timeout(u64),
    /// The signer answered with one of the protocol's error codes.
    #[error("the signer refused the request: {0}")]
    Refused(protocol::ErrorCode),
    /// The answer is not a protocol answer of the expected shape.
    #[error("the signer's answer is malformed")]
    BadAnswer,
    /// The answer names a `kid` other than the key this process verifies with.
    #[error("the signer answered with kid {got}, expected {expected}")]
    KidMismatch { expected: String, got: String },
    /// The signature does not verify against the signer's public key.
    #[error("the signer's signature does not verify against its public key")]
    BadSignature,
    /// openidconnect could not build the token, or the built token is not the
    /// compact JWS the capture expects. Not a backend fault.
    #[error("the token could not be assembled: {0}")]
    Assembly(String),
}

impl SignError {
    /// Whether asking again can succeed: the signer down, slow or misbehaving,
    /// or failing on its own side (`internal`). A request answers it with a
    /// retryable 503. A refusal of the request itself (`shape`, `bad_request`,
    /// `too_large`, `bad_version`) and a token that could not be assembled
    /// fail the same way every time, and are never answered as retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            SignError::Assembly(_) => false,
            SignError::Refused(code) => *code == protocol::ErrorCode::Internal,
            SignError::Unavailable(_)
            | SignError::Timeout(_)
            | SignError::BadAnswer
            | SignError::KidMismatch { .. }
            | SignError::BadSignature => true,
        }
    }
}

/// The provider's signing interface: one ES256 key, wherever it is held.
///
/// Every private-key use goes through [`ProviderSigner::sign`]; the public half
/// ([`ProviderSigner::verifying_key`], [`ProviderSigner::verification_jwk`]) is
/// what the JWKS publishes and what `id_token_hint` is verified against.
#[async_trait]
pub trait ProviderSigner: Send + Sync {
    /// `pem`, `ephemeral` or `socket`: the backend, for the start log line.
    fn backend(&self) -> &'static str;
    /// The key-derived `kid` stamped into every JWS header this signer signs.
    fn kid(&self) -> &str;
    /// The public key every signature of this signer verifies against.
    fn verifying_key(&self) -> &VerifyingKey;
    /// `true` when the key dies with this process: then no DID assertion is
    /// minted (`did_assertion::mint_did_assertion`).
    fn is_ephemeral(&self) -> bool;
    /// The published JWK of the key, built by the one [`verification_jwk`].
    fn verification_jwk(&self) -> CoreJsonWebKey {
        verification_jwk(self.verifying_key(), self.kid())
    }
    /// A raw ES256 signature (r‖s, exactly 64 bytes) over `message`, which is
    /// the signing input of a JWS for `purpose`.
    async fn sign(&self, purpose: Purpose, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

#[async_trait]
impl ProviderSigner for EcdsaSigningKey {
    fn backend(&self) -> &'static str {
        if self.ephemeral {
            "ephemeral"
        } else {
            "pem"
        }
    }

    fn kid(&self) -> &str {
        self.kid.as_str()
    }

    fn verifying_key(&self) -> &VerifyingKey {
        self.key.verifying_key()
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    async fn sign(&self, _purpose: Purpose, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.sign_es256(message))
    }
}

// -- Signing an openidconnect token through an async backend ---------------

/// The length of the placeholder signature a [`CaptureKey`] returns: the length
/// of a real ES256 signature, so nothing that measures the token sees a
/// difference.
const PLACEHOLDER_SIGNATURE_LEN: usize = 64;

/// A [`PrivateSigningKey`] that signs nothing: it records the signing input
/// openidconnect hands it and returns a placeholder signature of zeros.
///
/// It publishes the real signer's JWK, so the header's `kid` and every hash
/// openidconnect derives from the key (`at_hash`) are what the real key would
/// give. A token it took part in is never handed out: [`sign_jwt`] replaces
/// the placeholder before it returns.
pub struct CaptureKey {
    jwk: CoreJsonWebKey,
    inputs: Mutex<Vec<Vec<u8>>>,
}

impl CaptureKey {
    /// A capture key that publishes `jwk`.
    pub fn new(jwk: CoreJsonWebKey) -> Self {
        Self {
            jwk,
            inputs: Mutex::new(Vec::new()),
        }
    }

    /// The one signing input openidconnect asked for. More than one, or none,
    /// is an assembly error: the token would carry a signature over something
    /// else than what is signed below.
    fn into_input(self) -> Result<Vec<u8>, SignError> {
        let mut inputs = self.inputs.into_inner().unwrap_or_else(|e| e.into_inner());
        match inputs.len() {
            1 => Ok(inputs.remove(0)),
            n => Err(SignError::Assembly(format!(
                "the token builder asked for {n} signatures, expected one"
            ))),
        }
    }
}

impl PrivateSigningKey for CaptureKey {
    type VerificationKey = CoreJsonWebKey;

    // The algorithm is not checked here, as `EcdsaSigningKey` never checked it:
    // the header says what the caller asked for. The socket signer's shape check
    // refuses a header whose `alg` is not ES256.
    fn sign(
        &self,
        _signature_alg: &CoreJwsSigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        self.inputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message.to_vec());
        Ok(vec![0; PLACEHOLDER_SIGNATURE_LEN])
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        self.jwk.clone()
    }
}

/// Build an openidconnect token with `build` and sign it through `signer`.
///
/// `build` gets a [`CaptureKey`] in place of a signing key (for example
/// `|key| SiwxIdToken::new(claims, key, alg, Some(&access_token), None)`). The
/// signing input it records must equal the built token's `header.payload`
/// segment, byte for byte, or nothing is signed; the backend then signs that
/// input and the token is reassembled with the real signature. The result is
/// parsed back through the token type's own deserializer, which keeps the
/// signed bytes as they are.
pub async fn sign_jwt<T>(
    signer: &dyn ProviderSigner,
    purpose: Purpose,
    build: impl FnOnce(&CaptureKey) -> Result<T, JsonWebTokenError>,
) -> Result<T, SignError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let capture = CaptureKey::new(signer.verification_jwk());
    let unsigned = build(&capture).map_err(|e| SignError::Assembly(e.to_string()))?;
    let input = capture.into_input()?;
    let compact = match serde_json::to_value(&unsigned) {
        Ok(serde_json::Value::String(compact)) => compact,
        _ => {
            return Err(SignError::Assembly(
                "the token does not serialize to a compact JWS".to_string(),
            ))
        }
    };
    let (signing_input, _placeholder) = compact
        .rsplit_once('.')
        .ok_or_else(|| SignError::Assembly("the token has no signature segment".to_string()))?;
    if signing_input.as_bytes() != input.as_slice() {
        return Err(SignError::Assembly(
            "the captured signing input is not the token's header.payload".to_string(),
        ));
    }
    let signature = signer.sign(purpose, &input).await?;
    let signed = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&signature));
    serde_json::from_value(serde_json::Value::String(signed))
        .map_err(|e| SignError::Assembly(format!("the signed token does not parse: {e}")))
}

#[cfg(test)]
mod tests;
