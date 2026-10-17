//! What a log line may say about a credential: a fingerprint, never the value.
//!
//! A bearer value in a log is a credential in a second store, with weaker access
//! control and a longer life than the one it came from. Logs are shipped, indexed
//! and read by people who must not be able to act as a user, so every log site
//! that would name an access token, refresh token, authorization code, device
//! code, user code, session id, cookie, client secret or registration access
//! token, directly or inside a Redis key, names [`fingerprint`] of it instead.
//! Passkey credential ids are treated the same way: a credential id alone
//! authenticates nothing, but it links a person's browser to a DID, and the
//! fingerprint serves a debugging reader just as well.
//!
//! The fingerprint is the first [`FINGERPRINT_HEX_LEN`] hex characters of the
//! SHA-256 digest of the value. That is enough to tell whether two lines name the
//! same value, and an operator can compute it for a value they hold
//! (`printf %s "$value" | sha256sum | cut -c1-8`) to find the lines about it. It
//! is far too short to identify a value, and it is deliberately not longer: a
//! user code has about 34 bits of entropy, so a 64-bit fingerprint of it would be
//! the code itself to anyone willing to enumerate.
//!
//! This module is in the library crate so that `tests/*.rs` can link it and pin
//! it: `tests/log_hygiene.rs` captures the log output of the Redis paths and of
//! the device flow, and scans the sources for log sites that name a credential
//! variable without it.

use sha2::{Digest, Sha256};

/// Hex characters in a [`fingerprint`] (32 bits).
pub const FINGERPRINT_HEX_LEN: usize = 8;

/// A short, stable, one-way name for `value`, safe to log.
///
/// The empty string has a fingerprint like any other value.
pub fn fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..FINGERPRINT_HEX_LEN / 2])
}

/// A Redis key `namespace/identifier` with the identifier replaced by its
/// [`fingerprint`]: `codes/3fa9c01b`, `webauthn:link/91d0aa42`.
///
/// Redis keys here embed the credential they index (`codes/{code}`,
/// `token/{token}`, `webauthn:link/{credential id}`), so a key is as sensitive
/// as its value. The namespace is everything before the first `/` and stays
/// readable, because it is what a debugging reader needs. A key with no `/` is
/// fingerprinted whole.
pub fn redact_key(key: &str) -> String {
    match key.split_once('/') {
        Some((namespace, identifier)) => format!("{namespace}/{}", fingerprint(identifier)),
        None => fingerprint(key),
    }
}

/// `url` without its user name and password, for log lines and error messages.
///
/// A Redis URL carries the password (`redis://:password@host:6379`), so printing
/// the configured URL prints the secret. An input that is not a URL is replaced
/// by a placeholder rather than echoed, because whatever it is, it was meant to
/// be one.
pub fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            // These fail only for a URL that cannot carry credentials at all
            // (`mailto:`), which has nothing to remove.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        Err(_) => "<not a URL>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_is_eight_lowercase_hex_characters() {
        let fp = fingerprint("mat_0123456789abcdef");
        assert_eq!(fp.len(), FINGERPRINT_HEX_LEN);
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{fp}"
        );
    }

    /// The value is `sha256(value)[..4]`, so an operator can compute it for a
    /// value they hold. SHA-256("abc") starts `ba7816bf8f01cfea…` (FIPS 180-2).
    #[test]
    fn a_fingerprint_is_the_sha256_prefix_an_operator_can_recompute() {
        assert_eq!(fingerprint("abc"), "ba7816bf");
    }

    #[test]
    fn a_fingerprint_is_stable_and_tells_values_apart() {
        assert_eq!(fingerprint("one"), fingerprint("one"));
        assert_ne!(fingerprint("one"), fingerprint("two"));
        assert_eq!(fingerprint(""), "e3b0c442", "SHA-256 of the empty string");
    }

    #[test]
    fn a_redis_key_keeps_its_namespace_and_fingerprints_the_identifier() {
        let key = "codes/5a1f7c3e-0000-4000-8000-0123456789ab";
        let shown = redact_key(key);
        assert_eq!(
            shown,
            format!(
                "codes/{}",
                fingerprint("5a1f7c3e-0000-4000-8000-0123456789ab")
            )
        );
        assert!(!shown.contains("5a1f7c3e"));
        assert_eq!(
            redact_key("webauthn:link/AbCd_-9"),
            format!("webauthn:link/{}", fingerprint("AbCd_-9"))
        );
    }

    #[test]
    fn a_redis_key_without_a_namespace_is_fingerprinted_whole() {
        assert_eq!(redact_key("loose-secret"), fingerprint("loose-secret"));
    }

    #[test]
    fn a_url_loses_its_password_and_user_name() {
        let shown = redact_url("redis://user:hunter2@redis.internal:6379/2");
        assert_eq!(shown, "redis://redis.internal:6379/2");
        assert_eq!(
            redact_url("redis://:hunter2@redis.internal:6379"),
            "redis://redis.internal:6379"
        );
        assert_eq!(
            redact_url("redis://redis.internal:6379"),
            "redis://redis.internal:6379"
        );
    }

    #[test]
    fn something_that_is_not_a_url_is_not_echoed() {
        assert_eq!(redact_url("hunter2-but-no-scheme"), "<not a URL>");
    }
}
