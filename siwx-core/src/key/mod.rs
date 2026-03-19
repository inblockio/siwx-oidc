//! `DIDMethod` for `did:key`.
//!
//! Supports Ed25519 (`z6Mk…`) and P-256 (`zDn…`) key types.
//! Encoding: `z` (base58btc multibase) + multicodec varint prefix + raw key bytes.

use crate::{did_method::DIDMethod, error::SiwxError};
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519Key};
use p256::{
    ecdsa::{Signature as P256Sig, VerifyingKey as P256Key},
    EncodedPoint,
};

/// Multicodec varint for Ed25519 public key (0xED01).
pub(crate) const ED25519_PREFIX: &[u8] = &[0xED, 0x01];
/// Multicodec varint for P-256 public key (0x1200).
pub(crate) const P256_PREFIX: &[u8] = &[0x80, 0x24];

pub(crate) enum KeyType {
    Ed25519(Vec<u8>), // 32-byte raw pubkey
    P256(Vec<u8>),    // 33-byte compressed SEC1 point
}

/// Decode the base58btc body of a `z{body}` multibase+multicodec key string.
/// `z_body` must NOT include the leading `z`.
pub(crate) fn decode_multibase_key(z_body: &str) -> Result<KeyType, SiwxError> {
    let bytes = bs58::decode(z_body)
        .into_vec()
        .map_err(|e| SiwxError::InvalidDid(format!("base58btc decode error: {e}")))?;
    if bytes.starts_with(ED25519_PREFIX) {
        Ok(KeyType::Ed25519(bytes[ED25519_PREFIX.len()..].to_vec()))
    } else if bytes.starts_with(P256_PREFIX) {
        Ok(KeyType::P256(bytes[P256_PREFIX.len()..].to_vec()))
    } else {
        Err(SiwxError::InvalidDid(format!(
            "unknown multicodec prefix {:02x?}",
            &bytes[..2.min(bytes.len())]
        )))
    }
}

/// Verify a signature given a decoded KeyType and the message.
pub(crate) fn verify_with_key(
    key: KeyType,
    message: &str,
    signature: &[u8],
) -> Result<bool, SiwxError> {
    match key {
        KeyType::Ed25519(raw) => {
            let key_bytes: [u8; 32] = raw.try_into().map_err(|_| {
                SiwxError::InvalidSignature("Ed25519 public key must be 32 bytes".to_string())
            })?;
            let verifying_key = Ed25519Key::from_bytes(&key_bytes)
                .map_err(|e| SiwxError::InvalidSignature(format!("invalid Ed25519 key: {e}")))?;
            if signature.len() != 64 {
                return Err(SiwxError::InvalidSignature(format!(
                    "Ed25519 signature must be 64 bytes, got {}",
                    signature.len()
                )));
            }
            let sig = Ed25519Sig::from_slice(signature)
                .map_err(|e| SiwxError::InvalidSignature(format!("invalid Ed25519 sig: {e}")))?;
            Ok(verifying_key.verify(message.as_bytes(), &sig).is_ok())
        }
        KeyType::P256(raw) => {
            let point = EncodedPoint::from_bytes(&raw).map_err(|e| {
                SiwxError::InvalidSignature(format!("invalid P-256 encoded point: {e}"))
            })?;
            let verifying_key = P256Key::from_encoded_point(&point)
                .map_err(|e| SiwxError::InvalidSignature(format!("invalid P-256 key: {e}")))?;
            let sig = P256Sig::from_der(signature)
                .or_else(|_| P256Sig::from_slice(signature))
                .map_err(|e| SiwxError::InvalidSignature(format!("invalid P-256 sig: {e}")))?;
            Ok(verifying_key.verify(message.as_bytes(), &sig).is_ok())
        }
    }
}

pub(crate) fn key_type_label(key: &KeyType) -> &'static str {
    match key {
        KeyType::Ed25519(_) => "Ed25519",
        KeyType::P256(_) => "P-256",
    }
}

pub struct KeyMethod;

impl DIDMethod for KeyMethod {
    fn method_name(&self) -> &str {
        "key"
    }

    fn display_label(&self, did: &str) -> Result<String, SiwxError> {
        let z_body = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| SiwxError::InvalidDid(did.to_string()))?;
        let label = key_type_label(&decode_multibase_key(z_body)?);
        let short = &z_body[..z_body.len().min(8)];
        Ok(format!("z{short}… ({label})"))
    }

    fn address_for_message(&self, did: &str) -> Result<String, SiwxError> {
        did.strip_prefix("did:key:")
            .map(|s| s.to_string())
            .ok_or_else(|| SiwxError::InvalidDid(did.to_string()))
    }

    fn has_chain_id(&self, _did: &str) -> bool {
        false
    }

    fn chain_id(&self, _did: &str) -> Result<Option<String>, SiwxError> {
        Ok(None)
    }

    fn canonical_subject(&self, did: &str) -> Result<String, SiwxError> {
        Ok(did.to_string())
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, SiwxError> {
        let z_body = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| SiwxError::InvalidDid(did.to_string()))?;
        verify_with_key(decode_multibase_key(z_body)?, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use rand::rngs::OsRng;

    pub(super) fn ed25519_did(key: &Ed25519SigningKey) -> String {
        let mut bytes = ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(&bytes).into_string())
    }

    pub(super) fn p256_did(key: &P256SigningKey) -> String {
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes = P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        format!("did:key:z{}", bs58::encode(&bytes).into_string())
    }

    #[test]
    fn ed25519_roundtrip() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        assert!(did.starts_with("did:key:z6Mk"), "expected z6Mk prefix, got {did}");
        let sig = key.sign(b"hello did:key");
        assert!(KeyMethod.verify(&did, "hello did:key", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn ed25519_wrong_key_rejects() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let key2 = Ed25519SigningKey::generate(&mut OsRng);
        let did2 = ed25519_did(&key2);
        let sig = key.sign(b"test");
        assert!(!KeyMethod.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn p256_roundtrip_fixed() {
        let key = P256SigningKey::random(&mut OsRng);
        let did = p256_did(&key);
        let sig: P256Signature = key.sign(b"hello p256 key");
        assert!(KeyMethod.verify(&did, "hello p256 key", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn p256_roundtrip_der() {
        let key = P256SigningKey::random(&mut OsRng);
        let did = p256_did(&key);
        let sig: P256Signature = key.sign(b"hello p256 key");
        assert!(KeyMethod.verify(&did, "hello p256 key", sig.to_der().as_bytes()).unwrap());
    }

    #[test]
    fn p256_wrong_key_rejects() {
        let key = P256SigningKey::random(&mut OsRng);
        let key2 = P256SigningKey::random(&mut OsRng);
        let did2 = p256_did(&key2);
        let sig: P256Signature = key.sign(b"test");
        assert!(!KeyMethod.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn display_label_ed25519() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let label = KeyMethod.display_label(&ed25519_did(&key)).unwrap();
        assert!(label.contains("Ed25519"), "{label}");
    }

    #[test]
    fn display_label_p256() {
        let key = P256SigningKey::random(&mut OsRng);
        let label = KeyMethod.display_label(&p256_did(&key)).unwrap();
        assert!(label.contains("P-256"), "{label}");
    }

    #[test]
    fn canonical_subject_is_full_did() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        assert_eq!(KeyMethod.canonical_subject(&did).unwrap(), did);
    }

    #[test]
    fn address_for_message_strips_did_key() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        let addr = KeyMethod.address_for_message(&did).unwrap();
        assert!(addr.starts_with("z6Mk"));
    }

    #[test]
    fn invalid_multicodec_errors() {
        // base58btc of [0x00, 0x01, ...] — unknown prefix
        let bad_body = bs58::encode(&[0x00u8, 0x01, 0x02, 0x03]).into_string();
        let did = format!("did:key:z{bad_body}");
        assert!(KeyMethod.verify(&did, "msg", &[0u8; 64]).is_err());
    }
}
