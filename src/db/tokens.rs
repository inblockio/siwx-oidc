//! Token formats (design 5.2) and the digests tokens are stored under (I1).
//!
//! | Token | Format | Stored as |
//! |---|---|---|
//! | access | `mat_` + 32 base62 | `at/{digest(token)}` |
//! | admin (a `service` grant's access token) | `msa_` + 32 base62 | `at/{digest(token)}` |
//! | refresh | `mcr_` + handle (22 base62, about 131 random bits) + `_` + secret (32 base62) | `digest(token)` in its grant's `current_rt` / `previous_rt` |
//!
//! The same formats serve both modes. The handle names the grant
//! (`grant/{digest(handle)}`), so every refresh token of a chain, current or
//! superseded, leads to its grant (RFC 9700 §4.14.2 implementation note); that is
//! what lets superseded tokens be recognised as reuse. The handle is random and
//! never derived from a Matrix device id, which other users can see.
//!
//! [`digest`] is the lowercase hex SHA-256 of a value. Unsalted is sufficient for
//! tokens with at least 128 bits of entropy (RFC 6819 §5.1.4.1.3).

use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

/// Prefix of an access token.
pub const ACCESS_TOKEN_PREFIX: &str = "mat_";
/// Prefix of the access token of a `service` grant (a minted admin token).
pub const ADMIN_TOKEN_PREFIX: &str = "msa_";
/// Prefix of a refresh token.
pub const REFRESH_TOKEN_PREFIX: &str = "mcr_";
/// Length of the random part of an access token and of a refresh token's secret.
pub const SECRET_LEN: usize = 32;
/// Length of a grant handle: 22 base62 characters carry about 131 bits.
pub const HANDLE_LEN: usize = 22;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn random_base62(len: usize) -> String {
    let mut rng = thread_rng();
    (0..len)
        .map(|_| BASE62[rng.gen_range(0..BASE62.len())] as char)
        .collect()
}

/// A new access token: `mat_` + 32 base62.
pub fn new_access_token() -> String {
    format!("{ACCESS_TOKEN_PREFIX}{}", random_base62(SECRET_LEN))
}

/// A new admin token: `msa_` + 32 base62.
pub fn new_admin_token() -> String {
    format!("{ADMIN_TOKEN_PREFIX}{}", random_base62(SECRET_LEN))
}

/// A new random grant handle (22 base62).
pub fn new_grant_handle() -> String {
    random_base62(HANDLE_LEN)
}

/// A new OIDC session id (`sid`, 22 base62, about 131 random bits): random,
/// never derived from a handle, a token or a Matrix device id.
pub fn new_session_id() -> String {
    random_base62(HANDLE_LEN)
}

/// A new refresh token of the grant named by `handle`: `mcr_{handle}_{secret}`.
pub fn new_refresh_token(handle: &str) -> String {
    format!(
        "{REFRESH_TOKEN_PREFIX}{handle}_{}",
        random_base62(SECRET_LEN)
    )
}

/// The two parts of a refresh token in the current format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParsedRefreshToken<'a> {
    /// The grant handle; the grant lives at `grant/{digest(handle)}`.
    pub handle: &'a str,
}

impl std::fmt::Debug for ParsedRefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedRefreshToken")
            .field("handle_fp", &crate::redact::fingerprint(self.handle))
            .finish()
    }
}

/// Parse a refresh token in the current format. `None` for anything else: a
/// legacy refresh token, another kind of token, or garbage. Never panics.
pub fn parse_refresh_token(token: &str) -> Option<ParsedRefreshToken<'_>> {
    let rest = token.strip_prefix(REFRESH_TOKEN_PREFIX)?;
    let (handle, secret) = rest.split_once('_')?;
    let base62 =
        |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_alphanumeric());
    (base62(handle, HANDLE_LEN) && base62(secret, SECRET_LEN))
        .then_some(ParsedRefreshToken { handle })
}

/// Lowercase hex SHA-256 of `value`: the form every token and handle is stored in.
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_base62(s: &str) -> bool {
        s.bytes().all(|b| b.is_ascii_alphanumeric())
    }

    #[test]
    fn access_and_admin_tokens_carry_their_prefix_and_32_base62() {
        for (token, prefix) in [
            (new_access_token(), ACCESS_TOKEN_PREFIX),
            (new_admin_token(), ADMIN_TOKEN_PREFIX),
        ] {
            let rest = token.strip_prefix(prefix).expect("prefix");
            assert_eq!(rest.len(), SECRET_LEN, "random part length");
            assert!(is_base62(rest), "random part is base62");
        }
        assert_ne!(new_access_token(), new_access_token());
    }

    #[test]
    fn a_refresh_token_names_its_handle_and_parses_back_to_it() {
        let handle = new_grant_handle();
        assert_eq!(handle.len(), HANDLE_LEN);
        assert!(is_base62(&handle));
        let token = new_refresh_token(&handle);
        let rest = token.strip_prefix(REFRESH_TOKEN_PREFIX).expect("prefix");
        let (h, secret) = rest.split_once('_').expect("separator");
        assert_eq!(h, handle);
        assert_eq!(secret.len(), SECRET_LEN);
        assert!(is_base62(secret));
        assert_eq!(
            parse_refresh_token(&token).map(|p| p.handle),
            Some(&*handle)
        );
        // Two tokens of one grant share the handle, never the secret.
        assert_ne!(token, new_refresh_token(&handle));
    }

    #[test]
    fn grant_handles_are_random() {
        let a = new_grant_handle();
        assert!(!a.is_empty());
        assert_ne!(a, new_grant_handle());
    }

    #[test]
    fn malformed_refresh_tokens_are_unknown_never_a_panic() {
        let handle = "A".repeat(HANDLE_LEN);
        let secret = "b".repeat(SECRET_LEN);
        let good = format!("mcr_{handle}_{secret}");
        assert!(parse_refresh_token(&good).is_some(), "the control parses");
        let bad = [
            String::new(),
            "mcr_".to_string(),
            "mcr__".to_string(),
            // A legacy refresh token: prefix + 32 base62, no handle.
            format!("mcr_{secret}"),
            // A legacy generic-mode refresh token: no prefix at all.
            secret.clone(),
            format!("mat_{handle}_{secret}"),
            format!("MCR_{handle}_{secret}"),
            format!("mcr_{handle}_{secret}_"),
            format!("mcr_{handle}__{secret}"),
            format!("mcr_{handle}_{secret}x"),
            format!("mcr_{}_{secret}", &handle[1..]),
            format!("mcr_{handle}x_{secret}"),
            format!("mcr_{}-_{secret}", &handle[1..]),
            format!("mcr_{handle}_{}é", &secret[2..]),
            format!("mcr_{}é_{secret}", &handle[2..]),
            format!("mcr_{handle}_{}", "\u{0}".repeat(SECRET_LEN)),
            format!(" {good}"),
            format!("{good} "),
            "mcr_".repeat(10_000),
        ];
        for token in &bad {
            assert!(
                parse_refresh_token(token).is_none(),
                "{token:?} must not parse"
            );
        }
    }

    #[test]
    fn digest_is_the_lowercase_hex_sha256() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
