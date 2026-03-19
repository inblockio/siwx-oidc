//! `CipherSuite` — the secondary extensibility trait, internal to `PkhMethod`.
//!
//! The server never imports this trait directly. It is an implementation
//! detail of `PkhMethod` that enables per-namespace crypto dispatch.

use crate::error::SiwxError;

/// Handles crypto primitives for one `did:pkh` namespace
/// (e.g. "eip155", "ed25519", "p256").
pub trait CipherSuite: Send + Sync {
    /// The namespace string, e.g. `"eip155"`, `"ed25519"`, `"p256"`.
    fn namespace(&self) -> &str;

    /// True if DIDs in this namespace encode a CAIP-2 chain ID.
    /// Only `eip155` returns true.
    fn has_chain_id(&self) -> bool;

    /// Number of colon-separated segments after `did:pkh:{namespace}:`.
    /// eip155 → 2 (`chain_id:address`); ed25519/p256 → 1 (`address`).
    fn did_segments(&self) -> usize;

    /// Verify a CAIP-122 signature for this namespace.
    ///
    /// - `did` — the full DID string
    /// - `message` — the canonical CAIP-122 message that was signed
    /// - `signature` — raw signature bytes
    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, SiwxError>;

    /// Parse the DID remainder (everything after `did:pkh:{namespace}:`)
    /// into `(address, chain_id)`.
    ///
    /// For eip155 `"1:0xAbCd…"` → `("0xAbCd…", Some("eip155:1"))`.
    /// For ed25519 `"0x{pubkey}"` → `("0x{pubkey}", None)`.
    fn parse_did_parts(&self, did_remainder: &str)
        -> Result<(String, Option<String>), SiwxError>;
}

/// All registered cipher suite handlers, in priority order.
///
/// Add one line here when a new `CipherSuite` implementation is ready.
pub fn all_cipher_suites() -> Vec<Box<dyn CipherSuite>> {
    vec![]
}

/// Find the cipher suite for the given namespace name.
pub fn find_cipher_suite(namespace: &str) -> Option<Box<dyn CipherSuite>> {
    all_cipher_suites()
        .into_iter()
        .find(|cs| cs.namespace() == namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_unknown_namespace_returns_none() {
        assert!(find_cipher_suite("solana").is_none());
    }

    #[test]
    fn all_cipher_suites_compiles() {
        let suites = all_cipher_suites();
        // empty until Phase 1.3 adds the three cipher suites
        assert_eq!(suites.len(), 0);
    }
}
