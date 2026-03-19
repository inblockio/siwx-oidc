//! DID parsing helpers for CAIP-122 verification.
//! Ported from aqua-rs-auth/src/did.rs.

use crate::error::SiwxError;
use sha3::{Digest, Keccak256};

/// Extract the DID namespace (e.g. `"eip155"`, `"ed25519"`, `"p256"`).
pub fn parse_did_namespace(did: &str) -> Result<&str, SiwxError> {
    let rest = did
        .strip_prefix("did:pkh:")
        .ok_or_else(|| SiwxError::InvalidDid(format!("expected 'did:pkh:' prefix: {did}")))?;
    rest.split(':')
        .next()
        .ok_or_else(|| SiwxError::InvalidDid(format!("no namespace in DID: {did}")))
}

/// Parse the 20-byte Ethereum address from a `did:pkh:eip155:{chain}:0x{hex}` DID.
pub fn address_from_did(did: &str) -> Result<[u8; 20], SiwxError> {
    // Strip "did:pkh:eip155:" then take the last segment after ":"
    let rest = did
        .strip_prefix("did:pkh:eip155:")
        .ok_or_else(|| SiwxError::InvalidDid(format!("expected eip155 DID: {did}")))?;
    let hex_str = rest
        .rsplit(':')
        .next()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(|| SiwxError::InvalidDid(format!("missing 0x address in eip155 DID: {did}")))?;
    if hex_str.len() != 40 {
        return Err(SiwxError::InvalidDid(format!(
            "eip155 address must be 40 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| SiwxError::InvalidDid("address must be exactly 20 bytes".into()))
}

/// Extract the 32-byte Ed25519 public key from a `did:pkh:ed25519:0x{hex}` DID.
pub fn pubkey_from_ed25519_did(did: &str) -> Result<[u8; 32], SiwxError> {
    let hex_str = did
        .strip_prefix("did:pkh:ed25519:0x")
        .ok_or_else(|| SiwxError::InvalidDid(format!("expected ed25519 DID: {did}")))?;
    if hex_str.len() != 64 {
        return Err(SiwxError::InvalidDid(format!(
            "ed25519 pubkey must be 64 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| SiwxError::InvalidDid("ed25519 pubkey must be 32 bytes".into()))
}

/// Extract the 33-byte compressed P-256 public key from a `did:pkh:p256:0x{hex}` DID.
pub fn pubkey_from_p256_did(did: &str) -> Result<[u8; 33], SiwxError> {
    let hex_str = did
        .strip_prefix("did:pkh:p256:0x")
        .ok_or_else(|| SiwxError::InvalidDid(format!("expected p256 DID: {did}")))?;
    if hex_str.len() != 66 {
        return Err(SiwxError::InvalidDid(format!(
            "p256 compressed pubkey must be 66 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| SiwxError::InvalidDid("p256 compressed pubkey must be 33 bytes".into()))
}

/// Derive the Ethereum address from a secp256k1 verifying key.
/// `address = keccak256(uncompressed_pubkey[1..])[12..]`
pub fn address_from_verifying_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 mixed-case checksum encoding of a 20-byte Ethereum address.
pub fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(40);
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            result.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_known_vector() {
        let raw = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&raw);
        assert_eq!(eip55_checksum(&addr), "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn parse_eip155_namespace() {
        let ns =
            parse_did_namespace("did:pkh:eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
                .unwrap();
        assert_eq!(ns, "eip155");
    }

    #[test]
    fn address_from_did_any_chain() {
        // should work for any chain id, not just 1
        let did = "did:pkh:eip155:137:0xab5801a7d398351b8be11c439e05c5b3259aec9b";
        assert!(address_from_did(did).is_ok());
    }

    #[test]
    fn invalid_did_prefix_errors() {
        assert!(parse_did_namespace("not:a:did").is_err());
    }
}
