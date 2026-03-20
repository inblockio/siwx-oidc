//! `DIDMethod` for `did:peer`.
//!
//! Supports:
//! - Variant 0: `did:peer:0z{multibase-key}` — single inception key, same encoding as did:key.
//! - Variant 2: `did:peer:2.{elements}` — multi-key; selects the first `V` (verification) element.
//!
//! Key decoding is shared with the `key` module.

use crate::{
    did_method::DIDMethod,
    error::SiwxError,
    key::{decode_multibase_key, key_type_label, verify_with_key},
};

pub struct PeerMethod;

/// Extract the base58btc body (without leading `z`) of the verification key from a did:peer.
fn extract_z_body(did: &str) -> Result<String, SiwxError> {
    let body = did
        .strip_prefix("did:peer:")
        .ok_or_else(|| SiwxError::InvalidDid(did.to_string()))?;

    if let Some(rest) = body.strip_prefix('0') {
        // Variant 0: did:peer:0z{key}
        rest.strip_prefix('z')
            .map(|k| k.to_string())
            .ok_or_else(|| {
                SiwxError::InvalidDid(format!(
                    "did:peer variant 0 body must start with 'z': {did}"
                ))
            })
    } else if let Some(rest) = body.strip_prefix('2') {
        // Variant 2: did:peer:2.{elements} — find first V (verification) element.
        for component in rest.split('.') {
            if component.starts_with('V') {
                if let Some(pos) = component.find('z') {
                    return Ok(component[pos + 1..].to_string());
                }
            }
        }
        Err(SiwxError::InvalidDid(format!(
            "no V (verification) key found in did:peer variant 2: {did}"
        )))
    } else {
        Err(SiwxError::InvalidDid(format!(
            "unsupported did:peer variant: {did}"
        )))
    }
}

impl DIDMethod for PeerMethod {
    fn method_name(&self) -> &str {
        "peer"
    }

    /// Only accept variant 0 and variant 2; reject other variants.
    fn supports_did(&self, did: &str) -> bool {
        did.starts_with("did:peer:0z") || did.starts_with("did:peer:2.")
    }

    fn display_label(&self, did: &str) -> Result<String, SiwxError> {
        let z_body = extract_z_body(did)?;
        let label = key_type_label(&decode_multibase_key(&z_body)?);
        let short = &z_body[..z_body.len().min(8)];
        Ok(format!("z{short}… (peer/{label})"))
    }

    fn address_for_message(&self, did: &str) -> Result<String, SiwxError> {
        extract_z_body(did).map(|b| format!("z{b}"))
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
        let z_body = extract_z_body(did)?;
        verify_with_key(decode_multibase_key(&z_body)?, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{ED25519_PREFIX, P256_PREFIX};
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::{Signature as P256Sig, SigningKey as P256SigningKey};
    use rand::rngs::OsRng;

    fn z_encode_ed25519(key: &Ed25519SigningKey) -> String {
        let mut bytes = ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        bs58::encode(&bytes).into_string()
    }

    fn z_encode_p256(key: &P256SigningKey) -> String {
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes = P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        bs58::encode(&bytes).into_string()
    }

    #[test]
    fn variant0_ed25519_roundtrip() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = format!("did:peer:0z{}", z_encode_ed25519(&key));
        let sig = key.sign(b"hello peer v0");
        assert!(PeerMethod
            .verify(&did, "hello peer v0", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn variant0_p256_roundtrip() {
        let key = P256SigningKey::random(&mut OsRng);
        let did = format!("did:peer:0z{}", z_encode_p256(&key));
        let sig: P256Sig = key.sign(b"p256 peer v0");
        assert!(PeerMethod
            .verify(&did, "p256 peer v0", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn variant2_verification_key_used() {
        let enc_key = Ed25519SigningKey::generate(&mut OsRng);
        let ver_key = Ed25519SigningKey::generate(&mut OsRng);
        let did = format!(
            "did:peer:2.Ez{}.Vz{}",
            z_encode_ed25519(&enc_key),
            z_encode_ed25519(&ver_key)
        );
        // must verify with the V (verification) key
        let sig = ver_key.sign(b"hello peer v2");
        assert!(PeerMethod
            .verify(&did, "hello peer v2", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn variant2_enc_key_does_not_verify() {
        let enc_key = Ed25519SigningKey::generate(&mut OsRng);
        let ver_key = Ed25519SigningKey::generate(&mut OsRng);
        let did = format!(
            "did:peer:2.Ez{}.Vz{}",
            z_encode_ed25519(&enc_key),
            z_encode_ed25519(&ver_key)
        );
        // signing with the E (encryption) key should fail
        let sig = enc_key.sign(b"hello peer v2");
        assert!(!PeerMethod
            .verify(&did, "hello peer v2", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn variant2_v_key_first_order_also_works() {
        // V element can appear before E
        let enc_key = Ed25519SigningKey::generate(&mut OsRng);
        let ver_key = Ed25519SigningKey::generate(&mut OsRng);
        let did = format!(
            "did:peer:2.Vz{}.Ez{}",
            z_encode_ed25519(&ver_key),
            z_encode_ed25519(&enc_key)
        );
        let sig = ver_key.sign(b"v before e");
        assert!(PeerMethod
            .verify(&did, "v before e", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn supports_did_only_v0_and_v2() {
        assert!(PeerMethod.supports_did("did:peer:0z6Mkfoo"));
        assert!(PeerMethod.supports_did("did:peer:2.Ez6Mk.Vz6Mk"));
        assert!(!PeerMethod.supports_did("did:peer:1zQm"));
        assert!(!PeerMethod.supports_did("did:peer:3foo"));
        assert!(!PeerMethod.supports_did("did:key:z6Mk"));
    }

    #[test]
    fn unsupported_variant_errors() {
        assert!(extract_z_body("did:peer:1zQmXXX").is_err());
    }

    #[test]
    fn canonical_subject_is_full_did() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = format!("did:peer:0z{}", z_encode_ed25519(&key));
        assert_eq!(PeerMethod.canonical_subject(&did).unwrap(), did);
    }
}
