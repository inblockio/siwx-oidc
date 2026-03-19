//! P-256 (NIST) ECDSA cipher suite for `did:pkh:p256`.
//! Ported from aqua-rs-auth/src/verify_p256.rs.

use crate::cipher_suite::CipherSuite;
use crate::did::pubkey_from_p256_did;
use crate::error::SiwxError;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;

pub struct P256Suite;

impl CipherSuite for P256Suite {
    fn namespace(&self) -> &str {
        "p256"
    }

    fn has_chain_id(&self) -> bool {
        false
    }

    fn did_segments(&self) -> usize {
        1 // address (compressed pubkey) only
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, SiwxError> {
        let pubkey_bytes = pubkey_from_p256_did(did)?;
        let point = EncodedPoint::from_bytes(pubkey_bytes)
            .map_err(|e| SiwxError::InvalidSignature(format!("invalid p256 encoded point: {e}")))?;
        let verifying_key = VerifyingKey::from_encoded_point(&point)
            .map_err(|e| SiwxError::InvalidSignature(format!("invalid p256 pubkey: {e}")))?;

        // Accept both DER and fixed-size (64-byte r‖s) encoding.
        let sig = Signature::from_der(signature)
            .or_else(|_| Signature::from_slice(signature))
            .map_err(|e| SiwxError::InvalidSignature(format!("invalid p256 signature: {e}")))?;

        match verifying_key.verify(message.as_bytes(), &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Parse `"0x{compressed_pubkey_hex}"` into `("0x{…}", None)`.
    fn parse_did_parts(&self, did_remainder: &str) -> Result<(String, Option<String>), SiwxError> {
        Ok((did_remainder.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let compressed = signing_key.verifying_key().to_encoded_point(true);
        let did = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip_fixed() {
        let (key, did) = make_keypair();
        let msg = "hello siwx";
        let sig: Signature = key.sign(msg.as_bytes());
        assert!(P256Suite.verify(&did, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn sign_and_verify_roundtrip_der() {
        let (key, did) = make_keypair();
        let msg = "hello siwx";
        let sig: Signature = key.sign(msg.as_bytes());
        assert!(P256Suite.verify(&did, msg, sig.to_der().as_bytes()).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _) = make_keypair();
        let (_, did2) = make_keypair();
        let sig: Signature = key.sign(b"test");
        assert!(!P256Suite.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig: Signature = key.sign(b"original");
        assert!(!P256Suite.verify(&did, "tampered", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn parse_did_parts_p256() {
        let (address, chain) = P256Suite.parse_did_parts("0xdeadbeef").unwrap();
        assert_eq!(address, "0xdeadbeef");
        assert_eq!(chain, None);
    }
}
