//! Opaque, fixed-width Matrix localpart derivation from a DID.
//!
//! This is the pure, dependency-light half of the derivation (only `sha2` —
//! no Synapse, no axum, no tokio), which is why it lives in the **library**
//! crate: `tests/*.rs` integration tests link only against `siwx_oidc` (this
//! crate), never against the `siwx-oidc` binary crate, and previously could
//! not reach this logic at all — one test file hand-copied it, and the copy
//! silently diverged from the real algorithm (unconditionally lowercasing
//! every DID, which is wrong for `did:key`/`did:peer` — see below). Moving
//! the pure derivation here means every caller, binary and test alike, runs
//! the exact same code.
//!
//! The grandfathering policy that decides which derivation a given DID
//! actually gets ([`crate::localpart::resolve_identity`] et al.) stays in the
//! **binary** crate, because it depends on `SynapseClient`, which is not
//! exposed from this library crate (see the note at the top of `src/lib.rs`).
//!
//! # Why this exists
//!
//! [`legacy_localpart`] derives a localpart by replacing `:` with `-` and
//! lowercasing, e.g. `did:pkh:eip155:1:0x7a76…` becomes
//! `did-pkh-eip155-1-0x7a76…` — an 80+ character MXID built from five
//! hyphen-separated alphanumeric "words". matrix.org's MSC4284 policy server
//! runs a `UserIdContainsWordsFilter` that counts those hyphen/underscore
//! separated runs in the localpart and refuses to sign messages once the
//! count is high enough; a controlled A/B against the dev homeserver
//! (2026-09-09) confirmed the long, five-word shape is refused while a short,
//! single-run localpart on the *same* server is signed.
//!
//! [`localpart_for`] replaces the human-readable-but-unbounded derivation with
//! a deterministic hash-derived one: exactly 16 lowercase base36 characters,
//! **one** maximal alphanumeric run, no separators of any kind.
//!
//! Synapse has **no user-rename API**, so switching every identity over to
//! [`localpart_for`] would silently give every account that already exists
//! under [`legacy_localpart`] a brand-new, empty Matrix account — losing its
//! rooms, DMs and history. [`crate::localpart::resolve_identity`] (binary
//! crate) is the grandfathering policy that reconciles the two: an identity
//! that already has an account keeps whichever localpart it already has
//! (checking the legacy shape first, since that is what every pre-2026-09
//! account is keyed on); only a genuinely new identity gets the new,
//! policy-server-safe shape. See that function's own doc for the exact rules,
//! and the module-level note on the fail-safe direction a caller must take
//! when Synapse cannot be reached to decide.
//!
//! # Canonicalisation is method-aware — do not "simplify" this to one rule
//!
//! The DID is lowercased before hashing **only** for `did:pkh`:
//!
//! - **`did:pkh:*` — lowercase.** The mixed case in an `0x…` Ethereum address
//!   is an EIP-55 checksum, not part of the identity. `legacy_localpart`
//!   already lowercases for exactly this reason, and
//!   `account::cross_signing_reset_localpart_is_canonical_lowercase` pins the
//!   invariant that a mixed-case and an all-lowercase wallet DID name ONE
//!   Matrix account. [`localpart_for`] must preserve that: folding case here
//!   and not there would split one account's cross-signing reset grant and
//!   device readback across two different localparts.
//!
//! - **`did:key:*` / `did:peer:*` — case preserved, NOT lowercased.** These
//!   are multibase `z`-prefixed base58btc encodings, where upper/lower case
//!   both occur in the alphabet and case IS part of the encoded bytes, not
//!   decoration. Folding case here does not normalise a checksum, it silently
//!   maps two *different* public keys onto the same identity. This already
//!   happened in production: a `did:key` reconstructed from a Matrix
//!   localpart differed in 17 of 48 base58 characters from the original,
//!   because an intermediate step round-tripped it through a lowercased
//!   localpart (filed as siwx-oidc#17). Lowercasing `did:key`/`did:peer`
//!   before hashing would bake that same collision into every future
//!   localpart derived from a passkey DID.
//!
//! If a future DID method is added, decide its canonicalisation the same way:
//! ask whether the method's case is a checksum over already-lowercase/fixed
//! data (canonicalise) or part of the encoded key material itself (preserve).
//! Default to preserving case — an unnecessary collision is far worse than an
//! unnecessary distinction.
//!
//! # Why 80 bits of hash and not fewer
//!
//! `oidc::provision_synapse_device` treats "localpart already taken" as "this
//! is the existing account": when `is_localpart_available` is false it skips
//! `provision_user` and upserts a device onto whatever account already owns
//! that localpart. Two different DIDs that hash to the same localpart are
//! therefore not a cosmetic collision — they are the same Matrix account,
//! sharing its rooms, keys and message history.
//!
//! `did:key`/`did:peer` DIDs are self-issued: a passkey or a local keypair can
//! be generated offline, for free, in bulk, by anyone, including an attacker.
//! An attacker who wants to take over (or eavesdrop via device-sharing on) a
//! target's account only needs to grind keypairs until one produces the
//! target's localpart — this is a preimage/collision search against the
//! account, not a passive birthday-paradox concern, so the safety margin has
//! to be a full preimage resistance width, not a "collisions are unlikely"
//! width. At 32 bits that grind is roughly one CPU-day; at the 80 bits used
//! here it is computationally infeasible with any resources available to an
//! individual attacker. 80 bits of the underlying SHA-256 digest are kept
//! (not all 256) purely to fit the 16-character output budget matrix.org's
//! policy server appears to tolerate; 36^16 ≈ 2^82.7 comfortably covers all
//! 2^80 possible values, so the encoding never truncates and every output is
//! exactly 16 characters wide.

use sha2::{Digest, Sha256};

/// Derive a Matrix localpart from a DID by replacing colons with dashes and
/// lowercasing — the pre-2026-09 derivation.
///
/// # Why this is still here
///
/// This produced every localpart siwx-oidc ever minted before
/// [`crate::localpart::resolve_identity`]'s grandfathering rule shipped
/// (2026-09-09). Synapse has **no user-rename API**, so every account that
/// already exists is permanently keyed on this exact string — deleting this
/// function would silently orphan every pre-migration user onto a brand-new,
/// empty account the next time they sign in. It is permanent infrastructure,
/// not dead code: grandfathering depends on it forever.
/// [`crate::localpart::resolve_identity`] always checks this shape FIRST,
/// before ever considering [`localpart_for`].
pub fn legacy_localpart(did: &str) -> String {
    did.replace(':', "-").to_lowercase()
}

/// Base36 alphabet used for the localpart encoding: digits then lowercase
/// letters, matching Matrix's `[a-z0-9]` localpart character constraint (no
/// separators — see the module doc for why that matters to the policy
/// server).
const BASE36_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Fixed output width in characters. `36^16 ≈ 2^82.7 > 2^80`, so a 16-char
/// base36 string always has room for the full 80-bit value with zero
/// truncation risk; padding on the left with `0` keeps every output exactly
/// this wide.
const OUTPUT_WIDTH: usize = 16;

/// Number of leading digest bytes kept as the integer to encode (80 bits).
/// See the module doc's "why 80 bits" section — this is a preimage-resistance
/// budget against an attacker grinding self-issued DIDs, not a birthday-bound
/// collision margin.
const DIGEST_BYTES_KEPT: usize = 10;

/// Derive a deterministic, opaque, fixed-width Matrix localpart from a DID.
///
/// This is the shape a genuinely NEW identity gets — see
/// [`crate::localpart::resolve_identity`] (binary crate), which decides, per
/// DID, whether an identity is new or should be grandfathered onto
/// [`legacy_localpart`] instead. Do not call this directly from a
/// provisioning path; go through `resolve_identity` so the grandfathering
/// rule is never bypassed.
pub fn localpart_for(did: &str) -> String {
    let canonical = canonicalize(did);
    let digest = Sha256::digest(canonical.as_bytes());
    let mut bytes = [0u8; DIGEST_BYTES_KEPT];
    bytes.copy_from_slice(&digest[..DIGEST_BYTES_KEPT]);
    let n = bytes
        .iter()
        .fold(0u128, |acc, &byte| (acc << 8) | u128::from(byte));
    encode_base36_padded(n)
}

/// Method-aware canonicalisation. See the module doc: `did:pkh` case is a
/// checksum (fold it), `did:key`/`did:peer` case is key material (preserve
/// it). Anything else is passed through unchanged, which preserves case by
/// default — the safer default per the module doc.
fn canonicalize(did: &str) -> String {
    if did.starts_with("did:pkh:") {
        did.to_lowercase()
    } else {
        did.to_string()
    }
}

/// Encode `n` as lowercase base36, left-zero-padded to exactly
/// [`OUTPUT_WIDTH`] characters. Split out from [`localpart_for`] so the
/// zero-padding path can be exercised directly against small integers rather
/// than hunting for a DID whose digest happens to start with zero bytes.
fn encode_base36_padded(mut n: u128) -> String {
    let mut digits = Vec::with_capacity(OUTPUT_WIDTH);
    if n == 0 {
        digits.push(BASE36_ALPHABET[0]);
    }
    while n > 0 {
        let digit = (n % 36) as usize;
        digits.push(BASE36_ALPHABET[digit]);
        n /= 36;
    }
    while digits.len() < OUTPUT_WIDTH {
        digits.push(BASE36_ALPHABET[0]);
    }
    digits.reverse();
    // SAFETY-by-construction: every byte pushed above comes from
    // `BASE36_ALPHABET`, which is ASCII, so this is always valid UTF-8.
    String::from_utf8(digits).expect("base36 alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact vectors computed and verified against this implementation on
    /// 2026-09-09. Do not "fix" these to match a future refactor — a change
    /// to any of them silently reassigns Matrix accounts.
    const PKH_LOWER: &str = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
    const PKH_MIXED: &str = "did:pkh:eip155:1:0x7A760ea15d76F935c8646b449AF488c2B0021734";
    const PKH_EXPECTED: &str = "37rb2h7bdij3o1qm";

    const KEY_UPPER: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
    const KEY_UPPER_EXPECTED: &str = "0f2g2c0d3vclsu3i";
    const KEY_LOWER: &str = "did:key:z6mkmwzijj2k3ckqvqnmmgvkefmhdse4zxrfvqksxdmgba4v";
    const KEY_LOWER_EXPECTED: &str = "4qhlwf2qqvk7sqfw";

    #[test]
    fn vector_pkh_lower() {
        assert_eq!(localpart_for(PKH_LOWER), PKH_EXPECTED);
    }

    #[test]
    fn vector_pkh_mixed() {
        assert_eq!(localpart_for(PKH_MIXED), PKH_EXPECTED);
    }

    #[test]
    fn vector_key_upper() {
        assert_eq!(localpart_for(KEY_UPPER), KEY_UPPER_EXPECTED);
    }

    #[test]
    fn vector_key_lower() {
        assert_eq!(localpart_for(KEY_LOWER), KEY_LOWER_EXPECTED);
    }

    /// Counterpart of `account::cross_signing_reset_localpart_is_canonical_lowercase`:
    /// a mixed-case and an all-lowercase `did:pkh` wallet DID are ONE account,
    /// because the EIP-55 mixed case is a checksum over the same address, not
    /// separate identity. If this test starts failing, the cross-signing
    /// reset grant and the device readback for wallet users will silently
    /// split across two localparts.
    #[test]
    fn pkh_case_folding_is_canonical_lowercase() {
        assert_eq!(
            localpart_for(PKH_LOWER),
            localpart_for(PKH_MIXED),
            "mixed-case and lowercase did:pkh must yield the same localpart"
        );
    }

    /// Counterpart of the previous test in the other direction: `did:key`
    /// case is NOT a checksum, it is encoded key material (multibase
    /// base58btc), so two differently-cased strings are two different public
    /// keys and must resolve to different localparts. Folding case here
    /// reproduces the production incident in siwx-oidc#17, where a `did:key`
    /// round-tripped through a lowercased localpart differed in 17 of 48
    /// base58 characters from the original and silently authorised nobody.
    #[test]
    fn key_case_is_preserved_not_folded() {
        assert_ne!(
            localpart_for(KEY_UPPER),
            localpart_for(KEY_LOWER),
            "did:key case must NOT be folded — case is identity, not a checksum"
        );
    }

    /// Output shape, checked across all three DID methods currently in scope
    /// (pkh, key, peer): always exactly 16 characters, always `[a-z0-9]`
    /// only, and — the actual policy-server constraint — exactly ONE maximal
    /// `[a-zA-Z0-9]+` run, i.e. no separator characters at all. policyserv's
    /// `UserIdContainsWordsFilter` counts separator-delimited runs in the
    /// localpart; reintroducing even one separator would reintroduce the
    /// exact bug this module exists to fix.
    #[test]
    fn output_shape_is_16_char_single_run_base36() {
        let inputs = [
            "did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
            "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734",
            "did:pkh:solana:mainnet:11111111111111111111111111111111",
            "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v",
            "did:key:zDnaeYLmSJ9F2xLZPHVDaC5CzHzT2LzHVDaC5CzHzT2LzHVD",
            "did:peer:0z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v",
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRUqZAsvhgSfvY9ZBLM",
        ];

        for did in inputs {
            let lp = localpart_for(did);
            assert_eq!(
                lp.chars().count(),
                OUTPUT_WIDTH,
                "localpart for {did} must be exactly {OUTPUT_WIDTH} chars, got {lp:?}"
            );
            assert!(
                lp.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "localpart for {did} must be only [a-z0-9], got {lp:?}"
            );
            let runs = lp
                .chars()
                .fold((0usize, false), |(count, in_run), c| {
                    let is_word_char = c.is_ascii_alphanumeric();
                    if is_word_char && !in_run {
                        (count + 1, true)
                    } else {
                        (count, is_word_char)
                    }
                })
                .0;
            assert_eq!(
                runs, 1,
                "localpart for {did} must be a single alphanumeric run \
                 (no separators), got {lp:?} with {runs} runs"
            );
        }
    }

    /// Determinism: hashing the same DID twice must yield the same localpart
    /// (no randomness, no time/nonce dependence anywhere in the pipeline).
    #[test]
    fn deterministic_across_repeated_calls() {
        assert_eq!(localpart_for(PKH_LOWER), localpart_for(PKH_LOWER));
        assert_eq!(localpart_for(KEY_UPPER), localpart_for(KEY_UPPER));
    }

    /// Exercises the left-zero-padding branch directly against the internal
    /// base36 helper (per the module doc, easier and more robust than hunting
    /// for a DID whose digest happens to start with zero bytes).
    #[test]
    fn base36_padding_is_exercised() {
        assert_eq!(encode_base36_padded(0), "0000000000000000");
        assert_eq!(encode_base36_padded(1), "0000000000000001");
        assert_eq!(encode_base36_padded(35), "000000000000000z");
        assert_eq!(encode_base36_padded(36), "0000000000000010");
        // Max 80-bit value still fits in 16 base36 chars with no truncation
        // (36^16 ≈ 2^82.7 > 2^80 - 1), and needs no padding.
        let max_80_bit: u128 = (1u128 << 80) - 1;
        let encoded = encode_base36_padded(max_80_bit);
        assert_eq!(encoded.chars().count(), OUTPUT_WIDTH);
        assert!(!encoded.starts_with('0'));
    }
}
