//! The sealed successor (I1 + I4): the one stored value that must be handed back
//! later, encrypted so that only a presenter of the previous refresh token can
//! read it.
//!
//! When a refresh token rotates, its grant keeps the new pair as
//! `successor_sealed` until that pair is first used (design 5.4), so a client
//! that lost the rotation response can replay the old token and receive the same
//! pair. Storing the pair in the clear would put two live credentials at rest,
//! so it is encrypted:
//!
//! - key: HKDF-SHA256 over the plaintext of the refresh token that was presented
//!   to the rotation (the token a replay presents again), no salt, info
//!   [`SEAL_INFO`]; 32 bytes;
//! - cipher: AES-256-GCM with a random 96-bit nonce, the grant id as associated
//!   data, so a sealed value copied into another grant does not open;
//! - stored form: base64url (no padding) of `version byte || nonce || ciphertext`.
//!
//! The server never holds the key: it derives it from the token the client
//! presents and forgets it. A wrong token, a tampered value or another grant's
//! value fails to open, and [`open`] says so with `None`, never a panic.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::anyhow;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// HKDF info string. Versioned: a change of the key derivation changes it.
pub const SEAL_INFO: &[u8] = b"siwx-oidc/refresh-successor/v1";

/// First byte of the stored form; a change of the format changes it.
const SEAL_VERSION: u8 = 1;
/// AES-GCM nonce length: 96 bits.
const NONCE_LEN: usize = 12;

/// The AES-256-GCM cipher keyed by HKDF-SHA256 over the presented token.
fn cipher(presented_refresh: &str) -> anyhow::Result<Aes256Gcm> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, presented_refresh.as_bytes())
        .expand(SEAL_INFO, &mut key)
        .map_err(|_| anyhow!("HKDF output length rejected"))?;
    Ok(Aes256Gcm::new(&key.into()))
}

/// The successor pair a sealed value carries.
///
/// `Debug` is written by hand: the pair is two live credentials, so each prints
/// as its fingerprint (see [`crate::redact`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorPair {
    /// The successor access token.
    pub access_token: String,
    /// The successor refresh token.
    pub refresh_token: String,
    /// Unix expiry of the successor access token (drives `expires_in`).
    pub access_exp: i64,
}

impl std::fmt::Debug for SuccessorPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuccessorPair")
            .field(
                "access_token_fp",
                &crate::redact::fingerprint(&self.access_token),
            )
            .field(
                "refresh_token_fp",
                &crate::redact::fingerprint(&self.refresh_token),
            )
            .field("access_exp", &self.access_exp)
            .finish()
    }
}

/// Seal `pair` under a key derived from `presented_refresh`, bound to `grant_id`.
pub fn seal(
    presented_refresh: &str,
    grant_id: &str,
    pair: &SuccessorPair,
) -> anyhow::Result<String> {
    let plaintext = serde_json::to_vec(pair)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher(presented_refresh)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: grant_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("sealing the successor failed"))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

/// Open a value [`seal`] produced. `None` if the token, the grant id or the
/// value is not the one it was sealed with.
pub fn open(presented_refresh: &str, grant_id: &str, sealed: &str) -> Option<SuccessorPair> {
    let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
    let (&version, rest) = bytes.split_first()?;
    if version != SEAL_VERSION || rest.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let plaintext = cipher(presented_refresh)
        .ok()?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: grant_id.as_bytes(),
            },
        )
        .ok()?;
    serde_json::from_slice(&plaintext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> SuccessorPair {
        SuccessorPair {
            access_token: "mat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            refresh_token: "mcr_BBBBBBBBBBBBBBBBBBBBBB_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            access_exp: 1_700_000_300,
        }
    }

    const PRESENTED: &str = "mcr_DDDDDDDDDDDDDDDDDDDDDD_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
    const GRANT: &str = "aa11";

    #[test]
    fn the_presenter_of_the_previous_token_opens_the_successor() {
        let sealed = seal(PRESENTED, GRANT, &pair()).unwrap();
        assert_eq!(open(PRESENTED, GRANT, &sealed), Some(pair()));
    }

    #[test]
    fn a_wrong_token_cannot_open_the_successor() {
        let sealed = seal(PRESENTED, GRANT, &pair()).unwrap();
        assert!(open(PRESENTED, GRANT, &sealed).is_some(), "control opens");
        let other = PRESENTED.replace('E', "F");
        assert_eq!(open(&other, GRANT, &sealed), None);
        // The successor's own refresh token does not open it either.
        assert_eq!(open(&pair().refresh_token, GRANT, &sealed), None);
    }

    #[test]
    fn a_sealed_successor_moved_to_another_grant_does_not_open() {
        let sealed = seal(PRESENTED, GRANT, &pair()).unwrap();
        assert!(open(PRESENTED, GRANT, &sealed).is_some(), "control opens");
        assert_eq!(open(PRESENTED, "bb22", &sealed), None);
    }

    #[test]
    fn the_sealed_value_names_neither_token_and_is_fresh_each_time() {
        let a = seal(PRESENTED, GRANT, &pair()).unwrap();
        let b = seal(PRESENTED, GRANT, &pair()).unwrap();
        assert!(!a.is_empty());
        assert_ne!(a, b, "a fresh nonce per seal");
        for secret in [&pair().access_token, &pair().refresh_token] {
            assert!(!a.contains(secret.as_str()));
            assert!(!a.contains(&secret[4..]));
        }
    }

    #[test]
    fn tampered_or_garbage_values_fail_to_open_without_a_panic() {
        let sealed = seal(PRESENTED, GRANT, &pair()).unwrap();
        assert!(open(PRESENTED, GRANT, &sealed).is_some(), "control opens");
        let mut bytes = sealed.clone().into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        for garbage in [
            "",
            "!",
            "AA",
            "AQ",
            &tampered,
            &sealed[..sealed.len() / 2],
            "é",
        ] {
            assert_eq!(open(PRESENTED, GRANT, garbage), None, "{garbage:?}");
        }
    }
}
