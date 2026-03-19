//! `PkhMethod` — `DIDMethod` implementation for `did:pkh`.
//!
//! Dispatches to the `CipherSuite` registry for all crypto operations.
//! The server only sees `DIDMethod`; `CipherSuite` is hidden here.

use crate::cipher_suite::find_cipher_suite;
use crate::did_method::DIDMethod;
use crate::error::SiwxError;

pub struct PkhMethod;

impl DIDMethod for PkhMethod {
    fn method_name(&self) -> &str {
        "pkh"
    }

    fn display_label(&self, did: &str) -> Result<String, SiwxError> {
        let (ns, _) = split_namespace(did)?;
        let address = self.address_for_message(did)?;
        // Truncate long keys for display: "0x1234…5678"
        let short = if address.len() > 12 {
            format!("{}…{}", &address[..6], &address[address.len() - 4..])
        } else {
            address
        };
        let tag = match ns {
            "eip155" => "Ethereum",
            "ed25519" => "Ed25519",
            "p256" => "P-256",
            other => other,
        };
        Ok(format!("{short} ({tag})"))
    }

    fn address_for_message(&self, did: &str) -> Result<String, SiwxError> {
        let (ns, remainder) = split_namespace(did)?;
        let suite = find_cipher_suite(ns)
            .ok_or_else(|| SiwxError::UnsupportedMethod(ns.to_string()))?;
        let (address, _) = suite.parse_did_parts(remainder)?;
        // For eip155 always return EIP-55 checksummed form.
        if ns == "eip155" {
            return crate::pkh::eip155::checksummed_address(did);
        }
        Ok(address)
    }

    fn has_chain_id(&self, did: &str) -> bool {
        split_namespace(did)
            .ok()
            .and_then(|(ns, _)| find_cipher_suite(ns))
            .map(|s| s.has_chain_id())
            .unwrap_or(false)
    }

    fn chain_id(&self, did: &str) -> Result<Option<String>, SiwxError> {
        let (ns, remainder) = split_namespace(did)?;
        let suite = find_cipher_suite(ns)
            .ok_or_else(|| SiwxError::UnsupportedMethod(ns.to_string()))?;
        let (_, chain_id) = suite.parse_did_parts(remainder)?;
        Ok(chain_id)
    }

    fn canonical_subject(&self, did: &str) -> Result<String, SiwxError> {
        // The full DID string is the OIDC sub claim for did:pkh.
        Ok(did.to_string())
    }

    fn verify(
        &self,
        did: &str,
        canonical_msg: &str,
        signature: &[u8],
    ) -> Result<bool, SiwxError> {
        let (ns, _) = split_namespace(did)?;
        let suite = find_cipher_suite(ns)
            .ok_or_else(|| SiwxError::UnsupportedMethod(ns.to_string()))?;
        suite.verify(did, canonical_msg, signature)
    }
}

/// Split `did:pkh:{ns}:{remainder}` into `(ns, remainder)`.
fn split_namespace(did: &str) -> Result<(&str, &str), SiwxError> {
    let rest = did
        .strip_prefix("did:pkh:")
        .ok_or_else(|| SiwxError::InvalidDid(format!("expected did:pkh: prefix: {did}")))?;
    let colon = rest
        .find(':')
        .ok_or_else(|| SiwxError::InvalidDid(format!("no namespace in: {did}")))?;
    Ok((&rest[..colon], &rest[colon + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::{address_from_verifying_key, eip55_checksum};
    use sha3::{Digest, Keccak256};

    // ── eip155 helpers ──────────────────────────────────────────────────────

    fn eth_sign(key: &k256::ecdsa::SigningKey, msg: &str) -> Vec<u8> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(rec_id) + 27;
        bytes.to_vec()
    }

    fn make_eip155_keypair() -> (k256::ecdsa::SigningKey, String) {
        use rand::rngs::OsRng;
        let secret = k256::SecretKey::random(&mut OsRng);
        let key = k256::ecdsa::SigningKey::from(&secret);
        let addr = address_from_verifying_key(key.verifying_key());
        let did = format!("did:pkh:eip155:1:0x{}", eip55_checksum(&addr));
        (key, did)
    }

    #[test]
    fn method_name() {
        assert_eq!(PkhMethod.method_name(), "pkh");
    }

    #[test]
    fn supports_pkh_did() {
        assert!(PkhMethod.supports_did("did:pkh:eip155:1:0xAbc"));
        assert!(!PkhMethod.supports_did("did:key:z6Mk"));
        assert!(!PkhMethod.supports_did("did:peer:0z"));
    }

    #[test]
    fn canonical_subject_is_full_did() {
        let did = "did:pkh:eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
        assert_eq!(PkhMethod.canonical_subject(did).unwrap(), did);
    }

    #[test]
    fn has_chain_id_eip155() {
        assert!(PkhMethod.has_chain_id("did:pkh:eip155:1:0xAbc"));
    }

    #[test]
    fn has_chain_id_ed25519_false() {
        let pk_hex = hex::encode([0xAA; 32]);
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        assert!(!PkhMethod.has_chain_id(&did));
    }

    #[test]
    fn chain_id_eip155() {
        let did = "did:pkh:eip155:137:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
        assert_eq!(
            PkhMethod.chain_id(did).unwrap(),
            Some("eip155:137".to_string())
        );
    }

    #[test]
    fn verify_eip155_roundtrip() {
        let (key, did) = make_eip155_keypair();
        let msg = "Sign-In With X test message";
        let sig = eth_sign(&key, msg);
        assert!(PkhMethod.verify(&did, msg, &sig).unwrap());
    }

    #[test]
    fn verify_eip155_wrong_key_rejects() {
        let (key, _) = make_eip155_keypair();
        let (_, did2) = make_eip155_keypair();
        let sig = eth_sign(&key, "test");
        assert!(!PkhMethod.verify(&did2, "test", &sig).unwrap());
    }

    #[test]
    fn verify_unknown_namespace_errors() {
        let did = "did:pkh:solana:0xabc";
        let result = PkhMethod.verify(did, "msg", &[0u8; 64]);
        assert!(matches!(result, Err(SiwxError::UnsupportedMethod(_))));
    }

    #[test]
    fn display_label_eip155() {
        let (_, did) = make_eip155_keypair();
        let label = PkhMethod.display_label(&did).unwrap();
        assert!(label.contains("Ethereum"), "label was: {label}");
    }

    #[test]
    fn display_label_ed25519() {
        let pk_hex = hex::encode([0xBB; 32]);
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        let label = PkhMethod.display_label(&did).unwrap();
        assert!(label.contains("Ed25519"), "label was: {label}");
    }
}
