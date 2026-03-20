//! Ed25519 cipher suite for `did:pkh:ed25519`.
//! Ported from aqua-rs-auth/src/verify_ed25519.rs.

use crate::cipher_suite::CipherSuite;
use crate::did::pubkey_from_ed25519_did;
use crate::error::SiwxError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub struct Ed25519Suite;

impl CipherSuite for Ed25519Suite {
    fn namespace(&self) -> &str {
        "ed25519"
    }

    fn has_chain_id(&self) -> bool {
        false
    }

    fn did_segments(&self) -> usize {
        1 // address (pubkey) only
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, SiwxError> {
        let pubkey_bytes = pubkey_from_ed25519_did(did)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| SiwxError::InvalidSignature(format!("invalid ed25519 pubkey: {e}")))?;

        if signature.len() != 64 {
            return Err(SiwxError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }

        let sig = Signature::from_slice(signature)
            .map_err(|e| SiwxError::InvalidSignature(format!("invalid ed25519 signature: {e}")))?;

        match verifying_key.verify(message.as_bytes(), &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Parse `"0x{pubkey_hex}"` into `("0x{pubkey_hex}", None)`.
    fn parse_did_parts(&self, did_remainder: &str) -> Result<(String, Option<String>), SiwxError> {
        Ok((did_remainder.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = make_keypair();
        let msg = "hello siwx";
        let sig = key.sign(msg.as_bytes());
        assert!(Ed25519Suite.verify(&did, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _) = make_keypair();
        let (_, did2) = make_keypair();
        let sig = key.sign(b"test");
        assert!(!Ed25519Suite.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig = key.sign(b"original");
        assert!(!Ed25519Suite
            .verify(&did, "tampered", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn bad_signature_length_errors() {
        let (_, did) = make_keypair();
        assert!(Ed25519Suite.verify(&did, "msg", &[0u8; 32]).is_err());
    }

    #[test]
    fn parse_did_parts_ed25519() {
        let (address, chain) = Ed25519Suite.parse_did_parts("0xdeadbeef").unwrap();
        assert_eq!(address, "0xdeadbeef");
        assert_eq!(chain, None);
    }
}
