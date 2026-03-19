//! `DIDMethod` — the primary extensibility trait for siwx-oidc.
//!
//! The server dispatches exclusively on this trait. `CipherSuite` is an
//! implementation detail hidden inside `PkhMethod`.

use crate::error::SiwxError;

/// Handles DID interpretation, CAIP-122 field extraction, and verification
/// for one DID method (e.g. "pkh", "key", "peer").
///
/// Implementations must be `Send + Sync` (used behind `Arc` in axum state).
pub trait DIDMethod: Send + Sync {
    /// The method name, e.g. `"pkh"`, `"key"`, `"peer"`.
    fn method_name(&self) -> &str;

    /// Returns true if this method should handle `did`.
    fn supports_did(&self, did: &str) -> bool {
        let prefix = format!("did:{}:", self.method_name());
        did.starts_with(&prefix)
    }

    /// Human-readable label for UI display, e.g. `"0x1234…5678 (Ethereum)"`.
    fn display_label(&self, did: &str) -> Result<String, SiwxError>;

    /// The address string embedded in the CAIP-122 canonical message.
    /// For eip155 this is the EIP-55 checksummed address; for ed25519/p256
    /// it is the hex-encoded public key.
    fn address_for_message(&self, did: &str) -> Result<String, SiwxError>;

    /// True if this DID encodes a CAIP-2 chain ID (only eip155 does).
    fn has_chain_id(&self, did: &str) -> bool;

    /// The CAIP-2 chain ID if present, e.g. `Some("eip155:1")`.
    fn chain_id(&self, did: &str) -> Result<Option<String>, SiwxError>;

    /// The `sub` claim value for OIDC tokens.
    /// For did:pkh this is the full DID string, e.g. `"did:pkh:eip155:1:0x…"`.
    fn canonical_subject(&self, did: &str) -> Result<String, SiwxError>;

    /// Verify a CAIP-122 signature.
    ///
    /// - `did` — the signer's full DID string
    /// - `canonical_msg` — the canonical CAIP-122 message that was signed
    /// - `signature` — raw signature bytes (caller hex-decodes from cookie)
    fn verify(
        &self,
        did: &str,
        canonical_msg: &str,
        signature: &[u8],
    ) -> Result<bool, SiwxError>;
}

/// All registered DID method handlers, in priority order.
///
/// Add one line here when a new `DIDMethod` implementation is ready.
pub fn all_did_methods() -> Vec<Box<dyn DIDMethod>> {
    use crate::key::KeyMethod;
    use crate::peer::PeerMethod;
    use crate::pkh::PkhMethod;
    vec![Box::new(PkhMethod), Box::new(KeyMethod), Box::new(PeerMethod)]
}

/// Find the handler for `did`, or `None` if no registered method matches.
pub fn find_did_method(did: &str) -> Option<Box<dyn DIDMethod>> {
    all_did_methods().into_iter().find(|m| m.supports_did(did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_unknown_did_returns_none() {
        assert!(find_did_method("did:unknown:foo").is_none());
    }

    #[test]
    fn all_did_methods_has_pkh_key_peer() {
        let methods = all_did_methods();
        let names: Vec<&str> = methods.iter().map(|m| m.method_name()).collect();
        assert!(names.contains(&"pkh"));
        assert!(names.contains(&"key"));
        assert!(names.contains(&"peer"));
    }

    #[test]
    fn find_pkh_did_returns_some() {
        assert!(find_did_method("did:pkh:eip155:1:0xAbc").is_some());
    }

    #[test]
    fn find_key_did_returns_some() {
        assert!(find_did_method("did:key:z6MkiTBz1y").is_some());
    }

    #[test]
    fn find_peer_v0_returns_some() {
        assert!(find_did_method("did:peer:0z6Mkfoo").is_some());
    }

    #[test]
    fn find_peer_v1_returns_none() {
        // variant 1 is not supported
        assert!(find_did_method("did:peer:1zQm").is_none());
    }
}
