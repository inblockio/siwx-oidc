//! Guest admission (work package S3a, design 01 §4 B3, 04 GP-SEC-16..22, API contract
//! §3 and §6): everything `POST /guest/peek` and `POST /guest/redeem` decide about the
//! request body, as pure functions. No Redis, no Synapse, no axum, so every rule is
//! tested without them. The routes and the atomic Redis script are slice 2.
//!
//! The model (A1): the guest's identity is a `did:key` generated in the guest's
//! browser as a non-extractable WebCrypto key. The server never holds a private key.
//! Redeem binds the server guest record to that DID with a proof of possession: a
//! CAIP-122-style message (see [`build_redeem_message`]) signed by the browser key.
//!
//! Contents:
//! * [`validate_names`]: GP-SEC-16..18 (NFC, length, character classes, UAX 39
//!   single-script, skeleton match against a reserved list and the host's name).
//! * [`validate_email`] with [`EmailPolicy`]: GP-SEC-21/22, syntax only.
//! * [`check_consent`] and [`GUEST_CONSENT_VERSION`].
//! * [`admit_did`] and [`did_sha256_hex`]: `did:key` Ed25519 and P-256 only.
//! * [`NonceKey`], [`mint_nonce`], [`check_nonce`]: the stateless peek nonce.
//! * [`verify_redeem_proof`]: the proof of possession, one failure class.

use std::collections::HashSet;

use aqua_auth::find_did_method;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;
use unicode_security::MixedScript;
use url::Url;

// ---------------------------------------------------------------------------------
// Names (GP-SEC-16 to 18)
// ---------------------------------------------------------------------------------

/// The longest name part, in Unicode scalar values, after normalisation.
pub const MAX_NAME_CHARS: usize = 40;
/// Combining marks allowed in a row.
pub const MAX_MARKS_IN_A_ROW: usize = 2;
/// A raw name part longer than this (bytes) is refused before any normalisation work.
const MAX_NAME_RAW_BYTES: usize = 512;

/// Words a guest may not present as a name, whatever the case or lookalike letters.
/// The word "guest" and the words of the configured name suffix are added at check
/// time (`NameRules::name_suffix`).
pub const RESERVED_NAMES: &[&str] = &[
    "admin",
    "administrator",
    "host",
    "moderator",
    "system",
    "support",
    "guest",
    "aqua",
    "inblock",
    "server",
];

/// Why a name was refused. Each maps to a stable reason class ([`NameError::reason`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// Empty after trimming.
    Empty,
    /// More than [`MAX_NAME_CHARS`] scalar values.
    TooLong,
    /// A character or a character arrangement that is not allowed.
    Chars,
    /// More than one script in one part (UAX 39).
    MixedScript,
    /// Matches a reserved word or the host's display name (UAX 39 skeleton).
    Reserved,
}

impl NameError {
    /// The stable reason class of the 422 answer.
    pub fn reason(self) -> &'static str {
        match self {
            NameError::Empty => "name_empty",
            NameError::TooLong => "name_too_long",
            NameError::Chars => "name_chars",
            NameError::MixedScript => "name_mixed_script",
            NameError::Reserved => "name_reserved",
        }
    }
}

/// The configuration a name is judged against.
#[derive(Clone, Copy, Debug, Default)]
pub struct NameRules<'a> {
    /// `guest_name_suffix` (for example `" (Guest)"`): its words are reserved.
    pub name_suffix: &'a str,
    /// The host's display name when the best-effort read succeeded; `None` skips that rule.
    pub host_display_name: Option<&'a str>,
}

/// A name that passed [`validate_names`], in its normalised form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidName {
    pub first: String,
    pub second: String,
}

fn is_mark(c: char) -> bool {
    is_combining_mark(c)
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic() && !c.is_numeric() && !is_mark(c)
}

fn is_joiner(c: char) -> bool {
    matches!(c, '-' | '\'' | '\u{2019}')
}

/// NFC, trim, collapse inner whitespace to one space, then the length and character
/// rules, then the single-script rule. Control characters (tab and newline included)
/// are refused before whitespace is collapsed.
fn normalise_part(raw: &str) -> Result<String, NameError> {
    if raw.len() > MAX_NAME_RAW_BYTES {
        return Err(NameError::TooLong);
    }
    if raw.chars().any(char::is_control) {
        return Err(NameError::Chars);
    }
    let nfc: String = raw.nfc().collect();
    let part = nfc.split_whitespace().collect::<Vec<_>>().join(" ");
    if part.is_empty() {
        return Err(NameError::Empty);
    }
    if part.chars().count() > MAX_NAME_CHARS {
        return Err(NameError::TooLong);
    }
    check_chars(&part)?;
    if !part.as_str().is_single_script() {
        return Err(NameError::MixedScript);
    }
    Ok(part)
}

/// The allowed alphabet and its arrangement: letters, marks (at most two in a row, only
/// after a letter or mark), single spaces, hyphen and apostrophe between letters, and a
/// period only directly after a single letter ("J.").
fn check_chars(part: &str) -> Result<(), NameError> {
    let cs: Vec<char> = part.chars().collect();
    let n = cs.len();
    let letterish = |c: char| is_letter(c) || is_mark(c);
    let mut marks = 0usize;
    for i in 0..n {
        let c = cs[i];
        let prev = if i > 0 { Some(cs[i - 1]) } else { None };
        let next = cs.get(i + 1).copied();
        if is_mark(c) {
            marks += 1;
            if marks > MAX_MARKS_IN_A_ROW || !prev.is_some_and(letterish) {
                return Err(NameError::Chars);
            }
            continue;
        }
        marks = 0;
        if is_letter(c) {
            continue;
        }
        let ok = match c {
            ' ' => prev.is_some_and(|p| letterish(p) || p == '.') && next.is_some(),
            c if is_joiner(c) => prev.is_some_and(letterish) && next.is_some_and(is_letter),
            '.' => {
                let single_letter = prev.is_some_and(is_letter)
                    && (i == 1
                        || cs
                            .get(i.wrapping_sub(2))
                            .is_some_and(|&b| b == ' ' || is_joiner(b)));
                single_letter && next.is_none_or(|x| x == ' ' || x == '-')
            }
            _ => false,
        };
        if !ok {
            return Err(NameError::Chars);
        }
    }
    Ok(())
}

/// The UAX 39 skeleton, lowercased: two strings that look alike compare equal.
fn skeleton_key(s: &str) -> String {
    skeleton(&s.to_lowercase())
        .collect::<String>()
        .to_lowercase()
}

/// Validate both name parts (GP-SEC-16..18). Returns the normalised parts, or the first
/// rule that failed. Order per part: empty, length, characters, script; the reserved
/// and host-name rules run last, over both parts.
pub fn validate_names(
    first: &str,
    second: &str,
    rules: &NameRules<'_>,
) -> Result<ValidName, NameError> {
    let first = normalise_part(first)?;
    let second = normalise_part(second)?;

    let mut reserved: HashSet<String> = RESERVED_NAMES.iter().map(|w| skeleton_key(w)).collect();
    for word in rules
        .name_suffix
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
    {
        reserved.insert(skeleton_key(word));
    }
    let joined = format!("{first} {second}");
    let hit = [&first, &second, &joined]
        .iter()
        .any(|p| reserved.contains(&skeleton_key(p)));
    let host_hit = rules.host_display_name.is_some_and(|h| {
        let h = skeleton_key(&h.split_whitespace().collect::<Vec<_>>().join(" "));
        !h.is_empty()
            && (h == skeleton_key(&joined) || h == skeleton_key(&format!("{second} {first}")))
    });
    if hit || host_hit {
        return Err(NameError::Reserved);
    }
    Ok(ValidName { first, second })
}

// ---------------------------------------------------------------------------------
// E-mail (GP-SEC-21/22)
// ---------------------------------------------------------------------------------

/// The e-mail policy of an invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailPolicy {
    Off,
    Optional,
    Required,
}

impl EmailPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            EmailPolicy::Off => "off",
            EmailPolicy::Optional => "optional",
            EmailPolicy::Required => "required",
        }
    }
}

/// Why an e-mail field was refused. Stable reason classes via [`EmailError::reason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailError {
    Required,
    Invalid,
    NotAllowed,
}

impl EmailError {
    pub fn reason(self) -> &'static str {
        match self {
            EmailError::Required => "email_required",
            EmailError::Invalid => "email_invalid",
            EmailError::NotAllowed => "email_not_allowed",
        }
    }
}

/// The longest address (RFC 5321 path limit, GP-SEC-21).
pub const MAX_EMAIL_CHARS: usize = 254;
/// The longest local part.
pub const MAX_EMAIL_LOCAL_CHARS: usize = 64;

const EMAIL_ATEXT_SYMBOLS: &str = "!#$%&'*+/=?^_`{|}~-";

/// Judge `email` against `policy`. A missing or blank field is "no address". On success
/// returns the address to store: trimmed, domain lowercased, the local part untouched.
pub fn validate_email(
    policy: EmailPolicy,
    email: Option<&str>,
) -> Result<Option<String>, EmailError> {
    let email = email.map(str::trim).filter(|e| !e.is_empty());
    match (policy, email) {
        (EmailPolicy::Off, None) | (EmailPolicy::Optional, None) => Ok(None),
        (EmailPolicy::Required, None) => Err(EmailError::Required),
        (EmailPolicy::Off, Some(_)) => Err(EmailError::NotAllowed),
        (_, Some(e)) => email_syntax(e).map(Some).ok_or(EmailError::Invalid),
    }
}

/// Syntax only, no DNS: ASCII dot-atom local part (at most 64), a dotted ASCII domain of
/// letter-digit-hyphen labels (so IDNA `xn--` labels pass), at most 254 in all.
fn email_syntax(e: &str) -> Option<String> {
    if e.len() > MAX_EMAIL_CHARS || !e.is_ascii() {
        return None;
    }
    let (local, domain) = e.rsplit_once('@')?;
    if local.is_empty() || local.len() > MAX_EMAIL_LOCAL_CHARS {
        return None;
    }
    let atom_ok = |a: &str| {
        !a.is_empty()
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || EMAIL_ATEXT_SYMBOLS.contains(c))
    };
    if !local.split('.').all(atom_ok) {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !labels.iter().all(|l| label_ok(l)) {
        return None;
    }
    if labels
        .last()
        .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some(format!("{local}@{}", domain.to_ascii_lowercase()))
}

// ---------------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------------

/// The consent text version a guest must accept. Bumping it invalidates every open join
/// page: the peek answer carries it, the redeem body must echo it. A constant for now;
/// it moves to configuration when the consent text becomes editable.
pub const GUEST_CONSENT_VERSION: &str = "1";
/// The longest consent variant label.
const MAX_CONSENT_VARIANT_CHARS: usize = 32;

/// The `consent` object of the redeem body.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub version: String,
    pub variant: String,
}

/// The only consent failure: the stable reason class is `consent_required`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentRequired;

impl ConsentRequired {
    pub fn reason(self) -> &'static str {
        "consent_required"
    }
}

/// The version must equal `expected` (normally [`GUEST_CONSENT_VERSION`]) and the variant
/// must be a short `[A-Za-z0-9_-]` label, so it is safe to store and to log.
pub fn check_consent(consent: &Consent, expected: &str) -> Result<(), ConsentRequired> {
    let variant_ok = !consent.variant.is_empty()
        && consent.variant.len() <= MAX_CONSENT_VARIANT_CHARS
        && consent
            .variant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if consent.version == expected && variant_ok {
        Ok(())
    } else {
        Err(ConsentRequired)
    }
}

// ---------------------------------------------------------------------------------
// DID admission
// ---------------------------------------------------------------------------------

/// The curves a guest `did:key` may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidCurve {
    Ed25519,
    P256,
}

impl DidCurve {
    /// The label the CAIP-122 message and Path B use for the curve.
    pub fn label(self) -> &'static str {
        match self {
            DidCurve::Ed25519 => "Ed25519",
            DidCurve::P256 => "P-256",
        }
    }
}

/// Why a DID was refused. Stable reason classes via [`DidError::reason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidError {
    /// Malformed, or not the canonical encoding.
    Invalid,
    /// Well formed but another method or curve.
    Unsupported,
    /// The derived localpart is all digits, which Synapse refuses. The helper regenerates the key.
    Unusable,
}

impl DidError {
    pub fn reason(self) -> &'static str {
        match self {
            DidError::Invalid => "did_invalid",
            DidError::Unsupported => "did_unsupported",
            DidError::Unusable => "did_unusable",
        }
    }
}

/// A `did:key` that passed [`admit_did`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedDid {
    /// The DID exactly as supplied (it is canonical, so this is also its only form).
    pub did: String,
    /// The Matrix localpart, from the same function Path B uses for a new `did:key`.
    pub localpart: String,
    pub curve: DidCurve,
}

/// Multicodec prefixes as unsigned varints: Ed25519 public key 0xed, P-256 public key 0x1200.
const ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
const P256_PREFIX: [u8; 2] = [0x80, 0x24];

/// Read an unsigned varint (at most 3 bytes) from the front of `b`.
fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &byte) in b.iter().take(3).enumerate() {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Synapse refuses an all-numeric localpart (it reads as a guest user id). The base36
/// derivation yields one with probability about 5e-9; the helper then regenerates its key.
pub fn localpart_is_unusable(localpart: &str) -> bool {
    localpart.chars().all(|c| c.is_ascii_digit())
}

/// Parse and admit a `did:key`: Ed25519 or P-256 (compressed point) in the canonical
/// encoding only. The localpart is [`crate::mxid::localpart_for`], the derivation Path B
/// gives a new `did:key` identity.
pub fn admit_did(did: &str) -> Result<AdmittedDid, DidError> {
    if !did.starts_with("did:") {
        return Err(DidError::Invalid);
    }
    let Some(rest) = did.strip_prefix("did:key:") else {
        // A well-formed other method (did:pkh, did:peer, ...).
        let method = did["did:".len()..].split(':').next().unwrap_or("");
        return if !method.is_empty()
            && method
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            Err(DidError::Unsupported)
        } else {
            Err(DidError::Invalid)
        };
    };
    let body = rest.strip_prefix('z').ok_or(DidError::Invalid)?;
    if body.is_empty() || body.len() > 100 {
        return Err(DidError::Invalid);
    }
    let bytes = bs58::decode(body)
        .into_vec()
        .map_err(|_| DidError::Invalid)?;
    let (code, _) = read_varint(&bytes).ok_or(DidError::Invalid)?;
    let curve = match code {
        0xed => DidCurve::Ed25519,
        0x1200 => DidCurve::P256,
        _ => return Err(DidError::Unsupported),
    };
    let (prefix, key_len) = match curve {
        DidCurve::Ed25519 => (ED25519_PREFIX, 32),
        DidCurve::P256 => (P256_PREFIX, 33),
    };
    // Canonical: the exact prefix, exactly the key length, and the string re-encodes
    // byte-identically (no non-minimal varint, no trailing bytes, no leading-zero games).
    if bytes.len() != prefix.len() + key_len || bytes[..prefix.len()] != prefix {
        return Err(DidError::Invalid);
    }
    if curve == DidCurve::P256 {
        use p256::ecdsa::VerifyingKey;
        if !matches!(bytes[2], 0x02 | 0x03) || VerifyingKey::from_sec1_bytes(&bytes[2..]).is_err() {
            return Err(DidError::Invalid);
        }
    }
    if format!("did:key:z{}", bs58::encode(&bytes).into_string()) != did {
        return Err(DidError::Invalid);
    }
    let localpart = crate::mxid::localpart_for(did);
    if localpart_is_unusable(&localpart) {
        return Err(DidError::Unusable);
    }
    Ok(AdmittedDid {
        did: did.to_string(),
        localpart,
        curve,
    })
}

/// `hex(sha256(canonical DID))`: the suffix of the durable `erased:did/<hex>` marker the
/// token lifecycle writes (`db::redis::erased_did_key`), canonicalised by
/// [`crate::mxid::canonicalize`] like the marker. S5 writes the same key.
pub fn did_sha256_hex(did: &str) -> String {
    hex::encode(Sha256::digest(crate::mxid::canonicalize(did).as_bytes()))
}

// ---------------------------------------------------------------------------------
// The peek nonce
// ---------------------------------------------------------------------------------

/// How long a peek nonce lives.
pub const PEEK_NONCE_TTL_SECS: u64 = 300;
/// HKDF info (domain label) of the nonce key.
pub const PEEK_NONCE_INFO: &[u8] = b"siwx-oidc guest peek nonce v1";

/// The HMAC key of the peek nonce. Never printed.
#[derive(Clone)]
pub struct NonceKey([u8; 32]);

impl std::fmt::Debug for NonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NonceKey(..)")
    }
}

impl NonceKey {
    /// Derive the key from existing server secret material (HKDF-SHA256, info
    /// [`PEEK_NONCE_INFO`]). Slice 2 feeds it `config.signing_key_pem`.
    pub fn derive(secret_material: &[u8]) -> Self {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(None, secret_material)
            .expand(PEEK_NONCE_INFO, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        NonceKey(out)
    }

    /// A fresh random key, for a server that has no durable secret material (it dies with
    /// the process, as an ephemeral signing key does; a nonce lives only 5 minutes).
    pub fn random() -> Self {
        let mut out = [0u8; 32];
        OsRng.fill_bytes(&mut out);
        NonceKey(out)
    }
}

fn nonce_mac(key: &NonceKey, invite_id: &str, expiry: u64) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC takes any key length");
    mac.update(PEEK_NONCE_INFO);
    mac.update(&[0]);
    mac.update(invite_id.as_bytes());
    mac.update(&[0]);
    mac.update(expiry.to_string().as_bytes());
    mac
}

/// Mint `<expiry_unix>.<b64url(hmac)>` for `invite_id`, valid [`PEEK_NONCE_TTL_SECS`] from `now_unix`.
pub fn mint_nonce(key: &NonceKey, invite_id: &str, now_unix: u64) -> String {
    let expiry = now_unix + PEEK_NONCE_TTL_SECS;
    let tag = nonce_mac(key, invite_id, expiry).finalize().into_bytes();
    format!("{expiry}.{}", URL_SAFE_NO_PAD.encode(tag))
}

/// Why a peek nonce was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceError {
    /// Malformed, tampered, or minted for another invite or under another key.
    Invalid,
    /// Authentic but past its expiry.
    Expired,
}

/// Check `nonce` for `invite_id`: the MAC is compared in constant time, then the expiry.
pub fn check_nonce(
    key: &NonceKey,
    invite_id: &str,
    nonce: &str,
    now_unix: u64,
) -> Result<(), NonceError> {
    if nonce.len() > 96 {
        return Err(NonceError::Invalid);
    }
    let (expiry, tag) = nonce.split_once('.').ok_or(NonceError::Invalid)?;
    if expiry.is_empty() || expiry.len() > 20 || !expiry.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NonceError::Invalid);
    }
    let expiry: u64 = expiry.parse().map_err(|_| NonceError::Invalid)?;
    let tag = URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| NonceError::Invalid)?;
    nonce_mac(key, invite_id, expiry)
        .verify_slice(&tag) // constant time
        .map_err(|_| NonceError::Invalid)?;
    if now_unix >= expiry {
        return Err(NonceError::Expired);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------
// The redeem proof of possession
// ---------------------------------------------------------------------------------

/// The statement line of the redeem message.
pub const REDEEM_STATEMENT: &str = "Join as a guest";
/// The resource prefix naming the invite; the invite id follows.
pub const REDEEM_RESOURCE_PREFIX: &str = "urn:io.inblock:guest:invite:";
/// The longest `expiration-time` minus `issued-at` (10 minutes).
pub const POP_MAX_VALIDITY_SECS: i64 = 600;
/// Clock skew allowed on `issued-at` and `expiration-time`, as on the Path B login.
pub const POP_CLOCK_SKEW_SECS: i64 = 120;

/// The single failure class of the proof (`proof_invalid`). It says nothing about which
/// check failed, so it is no oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofError;

impl ProofError {
    pub fn reason(self) -> &'static str {
        "proof_invalid"
    }
}

/// The CAIP-122 domain of an issuer: its host, with the port when it is not the default.
fn issuer_domain(issuer: &Url) -> Option<String> {
    let host = issuer.host_str()?;
    Some(match issuer.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// The `URI:` line value: the issuer base URL without a trailing slash, which is what a
/// browser's `location.origin` gives.
fn issuer_uri(issuer: &Url) -> String {
    issuer.as_str().trim_end_matches('/').to_string()
}

/// The fields of a redeem message, as they appear on its lines.
struct MessageFields<'a> {
    domain: &'a str,
    label: &'a str,
    did: &'a str,
    uri: &'a str,
    nonce: &'a str,
    issued_at: &'a str,
    expiration_time: &'a str,
    invite_id: &'a str,
}

fn format_redeem_message(f: &MessageFields<'_>) -> String {
    let MessageFields {
        domain,
        label,
        did,
        uri,
        nonce,
        issued_at,
        expiration_time,
        invite_id,
    } = f;
    format!(
        "{domain} wants you to sign in with your {label} account:\n\
         {did}\n\
         \n\
         {REDEEM_STATEMENT}\n\
         \n\
         URI: {uri}\n\
         Version: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:\n\
         - {REDEEM_RESOURCE_PREFIX}{invite_id}"
    )
}

/// The ISO 8601 form the browser's `toISOString()` produces: millisecond precision, `Z`.
fn iso_ms(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Build the exact message the browser must sign. The server uses it in tests and to
/// document the format; `verify_redeem_proof` rebuilds the same bytes from what it parses.
/// The message never contains the invite secret: only the public `invite_id`.
pub fn build_redeem_message(
    issuer: &Url,
    did: &str,
    invite_id: &str,
    nonce: &str,
    issued_at: DateTime<Utc>,
    expiration_time: DateTime<Utc>,
) -> Result<String, ProofError> {
    let admitted = admit_did(did).map_err(|_| ProofError)?;
    Ok(format_redeem_message(&MessageFields {
        domain: &issuer_domain(issuer).ok_or(ProofError)?,
        label: admitted.curve.label(),
        did,
        uri: &issuer_uri(issuer),
        nonce,
        issued_at: &iso_ms(issued_at),
        expiration_time: &iso_ms(expiration_time),
        invite_id,
    }))
}

fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    if !raw.ends_with('Z') {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Verify the proof of possession of a redeem. `message` is parsed strictly (a fixed
/// twelve-line layout; anything extra, missing or reordered fails), then rebuilt from the
/// parsed time and nonce fields plus the expected issuer, DID and invite id, and the two
/// must match byte for byte. Then: nonce valid for this invite, times valid against `now`
/// (expiry at most [`POP_MAX_VALIDITY_SECS`] after issue), and the signature valid for
/// the DID's key. `signature` is the raw Ed25519 signature, or for P-256 the WebCrypto
/// ECDSA r||s form over SHA-256 (the shared `did:key` verifier also accepts DER).
///
/// Every failure is the same [`ProofError`].
pub fn verify_redeem_proof(
    issuer: &Url,
    invite_id: &str,
    did: &str,
    message: &str,
    signature: &[u8],
    nonce_key: &NonceKey,
    now: DateTime<Utc>,
) -> Result<(), ProofError> {
    let admitted = admit_did(did).map_err(|_| ProofError)?;
    let domain = issuer_domain(issuer).ok_or(ProofError)?;

    let lines: Vec<&str> = message.split('\n').collect();
    if lines.len() != 12 {
        return Err(ProofError);
    }
    let field = |i: usize, prefix: &str| lines[i].strip_prefix(prefix);
    let nonce = field(7, "Nonce: ").ok_or(ProofError)?;
    let issued_raw = field(8, "Issued At: ").ok_or(ProofError)?;
    let expires_raw = field(9, "Expiration Time: ").ok_or(ProofError)?;

    // Structure, issuer, address, statement, invite resource: one comparison.
    let expected = format_redeem_message(&MessageFields {
        domain: &domain,
        label: admitted.curve.label(),
        did,
        uri: &issuer_uri(issuer),
        nonce,
        issued_at: issued_raw,
        expiration_time: expires_raw,
        invite_id,
    });
    if expected != message {
        return Err(ProofError);
    }

    let issued = parse_time(issued_raw).ok_or(ProofError)?;
    let expires = parse_time(expires_raw).ok_or(ProofError)?;
    let skew = chrono::Duration::seconds(POP_CLOCK_SKEW_SECS);
    if issued > now + skew
        || expires <= issued
        || expires - issued > chrono::Duration::seconds(POP_MAX_VALIDITY_SECS)
        || now - skew >= expires
    {
        return Err(ProofError);
    }

    let now_unix = u64::try_from(now.timestamp()).map_err(|_| ProofError)?;
    check_nonce(nonce_key, invite_id, nonce, now_unix).map_err(|_| ProofError)?;

    let method = find_did_method(did).ok_or(ProofError)?;
    match method.verify(did, message, signature) {
        Ok(true) => Ok(()),
        _ => Err(ProofError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::Signer as _;

    // ----- names -----

    fn rules() -> NameRules<'static> {
        NameRules {
            name_suffix: " (Guest)",
            host_display_name: Some("Hannah Hostmann"),
        }
    }

    fn name(first: &str, second: &str) -> Result<ValidName, NameError> {
        validate_names(first, second, &rules())
    }

    fn name_err(first: &str, second: &str) -> NameError {
        name(first, second).expect_err("must be refused")
    }

    #[test]
    fn valid_names_pass_and_are_normalised() {
        for (f, s) in [
            ("Zoë", "Müller"),
            ("O'Brien", "Smith"),
            ("J. R.", "Tolkien"),
            ("Anne-Marie", "Dupont"),
            ("さくら", "田中"),
            ("Анна", "Иванова"),
            ("Ada", "Lovelace"),
        ] {
            assert!(name(f, s).is_ok(), "{f} {s}");
        }
        // NFC: decomposed "e" + U+0308 becomes the single scalar "ë"; whitespace collapses.
        let n = name("  Zoe\u{308} ", "van   der\tWal").unwrap_err();
        assert_eq!(n, NameError::Chars, "a tab is a control character");
        let n = name("  Zoe\u{308} ", "van   der Wal").unwrap();
        assert_eq!(n.first, "Zoë");
        assert_eq!(n.second, "van der Wal");
    }

    #[test]
    fn length_is_counted_in_scalars_after_normalisation() {
        let forty = "a".repeat(40);
        assert!(name(&forty, "x").is_ok());
        assert_eq!(name_err(&"a".repeat(41), "x"), NameError::TooLong);
        assert_eq!(name_err(&"a".repeat(5000), "x"), NameError::TooLong);
        // 20 decomposed é are 40 scalars after NFC, not 20 + 20 combining marks.
        assert!(name(&"e\u{301}".repeat(20), "x").is_ok());
        assert_eq!(name_err("", "x"), NameError::Empty);
        assert_eq!(name_err("x", "  \u{a0} "), NameError::Empty);
    }

    #[test]
    fn character_rules_each_have_a_failing_vector() {
        assert_eq!(name_err("Anna2", "x"), NameError::Chars, "digit");
        assert_eq!(name_err("Anna\u{1F600}", "x"), NameError::Chars, "emoji");
        assert_eq!(name_err("Anna\u{202e}", "x"), NameError::Chars, "RLO bidi");
        assert_eq!(
            name_err("An\u{200b}na", "x"),
            NameError::Chars,
            "zero width space"
        );
        assert_eq!(
            name_err("An\u{200d}na", "x"),
            NameError::Chars,
            "ZWJ format char"
        );
        assert_eq!(name_err("Anna\u{7}", "x"), NameError::Chars, "control");
        assert_eq!(name_err("Anna$", "x"), NameError::Chars, "symbol");
        assert_eq!(name_err("Ⅷ", "x"), NameError::Chars, "roman numeral");
        // Three combining marks in a row (x + three accents; x has no precomposed form, so NFC keeps all three).
        assert_eq!(name_err("x\u{301}\u{301}\u{301}b", "x"), NameError::Chars);
        // Two are fine.
        assert!(name("x\u{301}\u{323}b", "x").is_ok());
        // A mark with no base letter.
        assert_eq!(name_err("\u{301}a", "x"), NameError::Chars);
        // Period only directly after a single letter.
        assert_eq!(name_err("Jo.", "x"), NameError::Chars);
        assert_eq!(name_err(".J", "x"), NameError::Chars);
        assert_eq!(name_err("J.R.", "x"), NameError::Chars);
        // Separators sit between letters.
        assert_eq!(name_err("-Anna", "x"), NameError::Chars);
        assert_eq!(name_err("Anna--Marie", "x"), NameError::Chars);
        assert_eq!(name_err("Anna'", "x"), NameError::Chars);
    }

    #[test]
    fn mixed_script_parts_are_refused() {
        // Cyrillic "а" inside a Latin word.
        assert_eq!(name_err("P\u{430}ul", "x"), NameError::MixedScript);
        // Greek capital Alpha followed by Latin: the confusable "Αdmin".
        assert_eq!(name_err("\u{391}dmin", "x"), NameError::MixedScript);
        // Latin and Han in one part.
        assert_eq!(name_err("Anna田中", "x"), NameError::MixedScript);
        // A Japanese mix of Han and kana is one writing system.
        assert!(name("田中さくら", "カタカナ").is_ok());
        // Different scripts in different parts are each single-script.
        assert!(name("Анна", "Smith").is_ok());
    }

    #[test]
    fn reserved_and_host_names_match_by_skeleton() {
        for w in [
            "admin",
            "ADMIN",
            "Administrator",
            "Host",
            "moderator",
            "System",
            "support",
            "guest",
            "Aqua",
            "inblock",
            "SERVER",
        ] {
            assert_eq!(name_err(w, "x"), NameError::Reserved, "{w}");
            assert_eq!(name_err("x", w), NameError::Reserved, "{w} as second part");
        }
        // Mathematical bold letters are Common script, so only the skeleton catches them.
        assert_eq!(
            name_err("\u{1d41a}\u{1d41d}\u{1d426}\u{1d422}\u{1d427}", "x"),
            NameError::Reserved
        );
        // Fullwidth letters.
        assert_eq!(name_err("\u{ff21}dmin", "x"), NameError::Reserved);
        // The word of the configured suffix.
        let r = NameRules {
            name_suffix: " (Visitor)",
            host_display_name: None,
        };
        assert_eq!(validate_names("visitor", "x", &r), Err(NameError::Reserved));
        // The host's display name, in either order, any case.
        assert_eq!(name_err("hannah", "HOSTMANN"), NameError::Reserved);
        assert_eq!(name_err("Hostmann", "Hannah"), NameError::Reserved);
        // Without a host name the rule is skipped.
        let r = NameRules {
            name_suffix: " (Guest)",
            host_display_name: None,
        };
        assert!(validate_names("hannah", "hostmann", &r).is_ok());
    }

    #[test]
    fn name_reason_classes_are_stable() {
        let all = [
            (NameError::Empty, "name_empty"),
            (NameError::TooLong, "name_too_long"),
            (NameError::Chars, "name_chars"),
            (NameError::MixedScript, "name_mixed_script"),
            (NameError::Reserved, "name_reserved"),
        ];
        for (e, r) in all {
            assert_eq!(e.reason(), r);
        }
    }

    // ----- e-mail -----

    #[test]
    fn email_policy_by_presence() {
        use EmailPolicy::*;
        let good = Some("Anna@Example.ORG");
        // off
        assert_eq!(validate_email(Off, None), Ok(None));
        assert_eq!(validate_email(Off, Some("  ")), Ok(None));
        assert_eq!(validate_email(Off, good), Err(EmailError::NotAllowed));
        assert_eq!(
            validate_email(Off, Some("nonsense")),
            Err(EmailError::NotAllowed)
        );
        // optional
        assert_eq!(validate_email(Optional, None), Ok(None));
        assert_eq!(
            validate_email(Optional, good),
            Ok(Some("Anna@example.org".into()))
        );
        assert_eq!(
            validate_email(Optional, Some("nonsense")),
            Err(EmailError::Invalid)
        );
        // required
        assert_eq!(validate_email(Required, None), Err(EmailError::Required));
        assert_eq!(
            validate_email(Required, Some("")),
            Err(EmailError::Required)
        );
        assert_eq!(
            validate_email(Required, good),
            Ok(Some("Anna@example.org".into()))
        );
        assert_eq!(
            validate_email(Required, Some("a@b")),
            Err(EmailError::Invalid)
        );
    }

    #[test]
    fn email_syntax_rules() {
        let ok = |e: &str| validate_email(EmailPolicy::Optional, Some(e)).is_ok();
        assert!(ok("a.b+tag@example.org"));
        assert!(ok("user@xn--bcher-kva.example"), "IDNA domain");
        assert!(!ok("user@bücher.example"), "raw non-ASCII domain");
        assert!(!ok("bücher@example.org"), "non-ASCII local part");
        assert!(!ok("a@@example.org"));
        assert!(!ok(".a@example.org"));
        assert!(!ok("a..b@example.org"));
        assert!(!ok("a b@example.org"));
        assert!(!ok("a@-example.org"));
        assert!(!ok("a@example..org"));
        assert!(!ok("a@example.123"), "numeric TLD");
        assert!(!ok("@example.org"));
        assert!(!ok("a@example.org\r\nBcc: x@y.z"));
        let local64 = "a".repeat(64);
        assert!(ok(&format!("{local64}@example.org")));
        assert!(!ok(&format!("{}@example.org", "a".repeat(65))));
        // 254 in all passes, 255 does not.
        let domain = format!(
            "{}.{}.{}.org",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(57)
        );
        let at254 = format!("{local64}@{domain}");
        assert_eq!(at254.len(), 254);
        assert!(ok(&at254));
        assert!(!ok(&format!("{at254}x")));
        let reasons = [
            EmailError::Required,
            EmailError::Invalid,
            EmailError::NotAllowed,
        ];
        assert_eq!(
            reasons.map(EmailError::reason),
            ["email_required", "email_invalid", "email_not_allowed"]
        );
    }

    // ----- consent -----

    #[test]
    fn consent_version_must_match() {
        let c = |v: &str, var: &str| Consent {
            version: v.into(),
            variant: var.into(),
        };
        assert!(check_consent(&c("1", "a"), GUEST_CONSENT_VERSION).is_ok());
        assert_eq!(
            check_consent(&c("2", "a"), GUEST_CONSENT_VERSION),
            Err(ConsentRequired)
        );
        assert_eq!(
            check_consent(&c("", "a"), GUEST_CONSENT_VERSION),
            Err(ConsentRequired)
        );
        assert_eq!(
            check_consent(&c("1", ""), GUEST_CONSENT_VERSION),
            Err(ConsentRequired)
        );
        assert_eq!(
            check_consent(&c("1", "a b"), GUEST_CONSENT_VERSION),
            Err(ConsentRequired)
        );
        assert_eq!(ConsentRequired.reason(), "consent_required");
        assert!(serde_json::from_str::<Consent>(r#"{"version":"1","variant":"a","x":1}"#).is_err());
    }

    // ----- keys -----

    fn ed_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut OsRng)
    }

    fn ed_did(k: &ed25519_dalek::SigningKey) -> String {
        let mut b = ED25519_PREFIX.to_vec();
        b.extend_from_slice(k.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(b).into_string())
    }

    fn p_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut OsRng)
    }

    fn p_did(k: &p256::ecdsa::SigningKey) -> String {
        let mut b = P256_PREFIX.to_vec();
        b.extend_from_slice(k.verifying_key().to_encoded_point(true).as_bytes());
        format!("did:key:z{}", bs58::encode(b).into_string())
    }

    // ----- DID admission -----

    #[test]
    fn did_admission_accepts_both_curves_with_the_path_b_localpart() {
        let d = ed_did(&ed_key());
        let a = admit_did(&d).unwrap();
        assert_eq!(a.curve, DidCurve::Ed25519);
        assert_eq!(a.did, d);
        assert_eq!(a.localpart, crate::mxid::localpart_for(&d));
        assert_eq!(a.localpart.len(), 16);
        let d = p_did(&p_key());
        assert!(d.starts_with("did:key:zDn"));
        let a = admit_did(&d).unwrap();
        assert_eq!(a.curve, DidCurve::P256);
        assert_eq!(a.localpart, crate::mxid::localpart_for(&d));
    }

    #[test]
    fn did_admission_refuses_what_is_not_canonical_or_not_supported() {
        let key = ed_key();
        let d = ed_did(&key);
        let body = d.strip_prefix("did:key:z").unwrap();
        // Another method: unsupported, not malformed.
        let pkh = "did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        assert_eq!(admit_did(pkh), Err(DidError::Unsupported));
        assert_eq!(admit_did("did:peer:0z6Mkfoo"), Err(DidError::Unsupported));
        // Malformed.
        for bad in [
            "",
            "z6Mk",
            "did:",
            "did:key:",
            "did:key:6Mk",
            "did:key:z",
            "did:key:z0OIl",
            "did:KEY:z6Mk",
        ] {
            assert!(
                matches!(
                    admit_did(bad),
                    Err(DidError::Invalid | DidError::Unsupported)
                ),
                "{bad}"
            );
        }
        assert_eq!(
            admit_did("did:key:z0OIl"),
            Err(DidError::Invalid),
            "bad base58 alphabet"
        );
        assert_eq!(
            admit_did("did:key:u6Mk"),
            Err(DidError::Invalid),
            "other multibase"
        );
        // Trailing junk after a valid key.
        let mut b = bs58::decode(body).into_vec().unwrap();
        b.push(0);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&b).into_string())),
            Err(DidError::Invalid)
        );
        // Truncated key.
        b.truncate(30);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&b).into_string())),
            Err(DidError::Invalid)
        );
        // Non-minimal varint for the Ed25519 code (0xed 0x81 0x00), same key bytes.
        let mut v = vec![0xed, 0x81, 0x00];
        v.extend_from_slice(key.verifying_key().as_bytes());
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&v).into_string())),
            Err(DidError::Invalid)
        );
        // Wrong multicodec: secp256k1 (0xe7 0x01) with a 33-byte key, X25519 (0xec 0x01).
        let mut k1 = vec![0xe7, 0x01, 0x02];
        k1.extend_from_slice(&[7u8; 32]);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&k1).into_string())),
            Err(DidError::Unsupported)
        );
        let mut x = vec![0xec, 0x01];
        x.extend_from_slice(&[7u8; 32]);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&x).into_string())),
            Err(DidError::Unsupported)
        );
        // P-256 prefix with an uncompressed-looking or off-curve point.
        let mut p = P256_PREFIX.to_vec();
        p.push(0x04);
        p.extend_from_slice(&[1u8; 32]);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&p).into_string())),
            Err(DidError::Invalid)
        );
        let mut p = P256_PREFIX.to_vec();
        p.push(0x02);
        p.extend_from_slice(&[0xffu8; 32]);
        assert_eq!(
            admit_did(&format!("did:key:z{}", bs58::encode(&p).into_string())),
            Err(DidError::Invalid)
        );
        let reasons = [DidError::Invalid, DidError::Unsupported, DidError::Unusable];
        assert_eq!(
            reasons.map(DidError::reason),
            ["did_invalid", "did_unsupported", "did_unusable"]
        );
    }

    #[test]
    fn all_numeric_localparts_are_unusable() {
        assert!(localpart_is_unusable("0123456789012345"));
        assert!(!localpart_is_unusable("012345678901234a"));
        assert!(!localpart_is_unusable(&crate::mxid::localpart_for(
            &ed_did(&ed_key())
        )));
    }

    #[test]
    fn did_hash_matches_the_erased_marker_format() {
        let d = ed_did(&ed_key());
        let h = did_sha256_hex(&d);
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            hex::encode(Sha256::digest(d.as_bytes())),
            "did:key is case-preserved, hashed as is"
        );
        // did:pkh is folded to lowercase before hashing, like the marker.
        let up = "did:pkh:eip155:1:0xB9C5714089478A327F09197987F16F9E5D936E8A";
        assert_eq!(did_sha256_hex(up), did_sha256_hex(&up.to_lowercase()));
    }

    // ----- nonce -----

    #[test]
    fn peek_nonce_valid_expired_foreign_and_tampered() {
        let key = NonceKey::derive(b"some server secret");
        let n = mint_nonce(&key, "inv_abc", 1_000);
        assert!(n.starts_with("1300."));
        assert_eq!(check_nonce(&key, "inv_abc", &n, 1_000), Ok(()));
        assert_eq!(check_nonce(&key, "inv_abc", &n, 1_299), Ok(()));
        assert_eq!(
            check_nonce(&key, "inv_abc", &n, 1_300),
            Err(NonceError::Expired)
        );
        assert_eq!(
            check_nonce(&key, "inv_other", &n, 1_000),
            Err(NonceError::Invalid)
        );
        // Another key, including the same secret under a different derivation.
        assert_eq!(
            check_nonce(&NonceKey::derive(b"other"), "inv_abc", &n, 1_000),
            Err(NonceError::Invalid)
        );
        assert_eq!(
            check_nonce(&NonceKey::random(), "inv_abc", &n, 1_000),
            Err(NonceError::Invalid)
        );
        // Extending the expiry invalidates the MAC.
        let (_, tag) = n.split_once('.').unwrap();
        assert_eq!(
            check_nonce(&key, "inv_abc", &format!("9999.{tag}"), 1_000),
            Err(NonceError::Invalid)
        );
        // A flipped tag character, garbage and junk.
        let mut t = n.clone().into_bytes();
        let last = t.len() - 1;
        t[last] = if t[last] == b'A' { b'B' } else { b'A' };
        assert!(check_nonce(&key, "inv_abc", &String::from_utf8(t).unwrap(), 1_000).is_err());
        for junk in ["", ".", "x.y", "1300", "1300.", "-5.AAAA", &"9".repeat(200)] {
            assert_eq!(
                check_nonce(&key, "inv_abc", junk, 1_000),
                Err(NonceError::Invalid),
                "{junk}"
            );
        }
        assert_eq!(format!("{key:?}"), "NonceKey(..)");
    }

    // ----- proof of possession -----

    const INVITE: &str = "inv_abc123";

    fn issuer() -> Url {
        Url::parse("https://sso.example.org").unwrap()
    }

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 11, 12, 0, 0).unwrap()
    }

    struct Fixture {
        key: NonceKey,
        nonce: String,
    }

    fn fixture() -> Fixture {
        let key = NonceKey::derive(b"proof fixture secret");
        let nonce = mint_nonce(&key, INVITE, t0().timestamp() as u64);
        Fixture { key, nonce }
    }

    fn msg(f: &Fixture, did: &str) -> String {
        build_redeem_message(
            &issuer(),
            did,
            INVITE,
            &f.nonce,
            t0(),
            t0() + chrono::Duration::seconds(300),
        )
        .unwrap()
    }

    fn verify(
        f: &Fixture,
        did: &str,
        m: &str,
        sig: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), ProofError> {
        verify_redeem_proof(&issuer(), INVITE, did, m, sig, &f.key, now)
    }

    #[test]
    fn valid_ed25519_and_p256_proofs_pass() {
        let f = fixture();
        let k = ed_key();
        let did = ed_did(&k);
        let m = msg(&f, &did);
        assert!(m.starts_with(
            "sso.example.org wants you to sign in with your Ed25519 account:\ndid:key:z6Mk"
        ));
        assert!(
            m.contains("\n\nJoin as a guest\n\nURI: https://sso.example.org\nVersion: 1\nNonce: ")
        );
        assert!(m.ends_with("Resources:\n- urn:io.inblock:guest:invite:inv_abc123"));
        let sig = k.sign(m.as_bytes()).to_bytes();
        assert_eq!(verify(&f, &did, &m, &sig, t0()), Ok(()));
        assert_eq!(
            verify(&f, &did, &m, &sig, t0() + chrono::Duration::seconds(200)),
            Ok(())
        );

        let k = p_key();
        let did = p_did(&k);
        let m = msg(&f, &did);
        assert!(m.contains("P-256 account:"));
        let sig: p256::ecdsa::Signature = k.sign(m.as_bytes());
        assert_eq!(sig.to_bytes().len(), 64, "WebCrypto P1363 r||s");
        assert_eq!(verify(&f, &did, &m, &sig.to_bytes(), t0()), Ok(()));
    }

    #[test]
    fn the_message_never_holds_a_secret_and_a_port_is_part_of_the_domain() {
        let f = fixture();
        let did = ed_did(&ed_key());
        let local = Url::parse("http://localhost:8000/").unwrap();
        let m = build_redeem_message(
            &local,
            &did,
            INVITE,
            &f.nonce,
            t0(),
            t0() + chrono::Duration::seconds(60),
        )
        .unwrap();
        assert!(m.starts_with("localhost:8000 wants you"));
        assert!(m.contains("URI: http://localhost:8000\n"));
        // Only the public invite id is named.
        assert_eq!(m.matches("inv_abc123").count(), 1);
    }

    /// One mutation per failing vector; each must give the single proof error, and the
    /// unmutated control must pass, so the vector is the only reason for the failure.
    #[test]
    fn every_check_fails_on_its_own_vector() {
        let f = fixture();
        let k = ed_key();
        let did = ed_did(&k);
        let good = msg(&f, &did);
        let sign = |m: &str| k.sign(m.as_bytes()).to_bytes();
        assert_eq!(
            verify(&f, &did, &good, &sign(&good), t0()),
            Ok(()),
            "control"
        );

        // Message mutations, re-signed by the right key so only the mutation can fail.
        let mutations: Vec<(&str, String)> = vec![
            (
                "wrong domain",
                good.replace("sso.example.org wants", "evil.example.org wants"),
            ),
            (
                "wrong uri",
                good.replace(
                    "URI: https://sso.example.org",
                    "URI: https://evil.example.org",
                ),
            ),
            (
                "uri with slash",
                good.replace(
                    "URI: https://sso.example.org",
                    "URI: https://sso.example.org/",
                ),
            ),
            ("wrong address", good.replace(&did, &ed_did(&ed_key()))),
            (
                "wrong label",
                good.replace("Ed25519 account", "P-256 account"),
            ),
            (
                "wrong statement",
                good.replace("Join as a guest", "Join as a host"),
            ),
            ("wrong version", good.replace("Version: 1", "Version: 2")),
            (
                "wrong nonce",
                good.replace(
                    &f.nonce,
                    &mint_nonce(&f.key, "inv_other", t0().timestamp() as u64),
                ),
            ),
            ("garbage nonce", good.replace(&f.nonce, "1.2")),
            (
                "other invite resource",
                good.replace("invite:inv_abc123", "invite:inv_zzz999"),
            ),
            (
                "missing invite resource",
                good.replace("\nResources:\n- urn:io.inblock:guest:invite:inv_abc123", ""),
            ),
            (
                "extra resource",
                format!("{good}\n- https://evil.example.org"),
            ),
            (
                "extra unknown line",
                good.replace("Version: 1\n", "Version: 1\nChain ID: 1\n"),
            ),
            ("trailing newline", format!("{good}\n")),
            ("CRLF", good.replace('\n', "\r\n")),
            ("empty", String::new()),
            (
                "expiry before issue",
                good.replace("T12:05:00.000Z", "T11:59:00.000Z"),
            ),
            (
                "validity over 10 min",
                good.replace("T12:05:00.000Z", "T12:10:01.000Z"),
            ),
            (
                "non-UTC time",
                good.replace("T12:00:00.000Z", "T12:00:00.000+00:00"),
            ),
        ];
        for (what, m) in &mutations {
            assert_eq!(
                verify(&f, &did, m, &sign(m), t0()),
                Err(ProofError),
                "{what}"
            );
        }

        // Expired: the 5-minute message checked 6 minutes later is past expiry plus skew.
        assert_eq!(
            verify(
                &f,
                &did,
                &good,
                &sign(&good),
                t0() + chrono::Duration::seconds(300 + 121)
            ),
            Err(ProofError),
            "expired"
        );
        // The peek nonce itself expired (message validity would still hold).
        let late = fixture_with_late_expiry(&k, &did);
        assert_eq!(late, Err(ProofError), "nonce expired");
        // Issued in the future beyond skew.
        assert_eq!(
            verify(
                &f,
                &did,
                &good,
                &sign(&good),
                t0() - chrono::Duration::seconds(121)
            ),
            Err(ProofError),
            "issued in the future"
        );
        assert_eq!(
            verify(
                &f,
                &did,
                &good,
                &sign(&good),
                t0() - chrono::Duration::seconds(100)
            ),
            Ok(()),
            "inside skew"
        );

        // The claimed did differs from the message address.
        let other = ed_did(&ed_key());
        assert_eq!(
            verify(&f, &other, &good, &sign(&good), t0()),
            Err(ProofError),
            "wrong did"
        );
        // Signature by another key; truncated; bit-flipped; wrong message.
        let stranger = ed_key();
        let bad = stranger.sign(good.as_bytes()).to_bytes();
        assert_eq!(
            verify(&f, &did, &good, &bad, t0()),
            Err(ProofError),
            "other key"
        );
        assert_eq!(
            verify(&f, &did, &good, &sign(&good)[..32], t0()),
            Err(ProofError),
            "short signature"
        );
        assert_eq!(
            verify(&f, &did, &good, &[], t0()),
            Err(ProofError),
            "no signature"
        );
        assert_eq!(
            verify(&f, &did, &good, &sign("something else"), t0()),
            Err(ProofError),
            "signed other text"
        );
        // Another invite id or another issuer on the verifying side.
        assert_eq!(
            verify_redeem_proof(
                &issuer(),
                "inv_other",
                &did,
                &good,
                &sign(&good),
                &f.key,
                t0()
            ),
            Err(ProofError)
        );
        let elsewhere = Url::parse("https://other.example.org").unwrap();
        assert_eq!(
            verify_redeem_proof(&elsewhere, INVITE, &did, &good, &sign(&good), &f.key, t0()),
            Err(ProofError)
        );
        // A nonce from another server key.
        assert_eq!(
            verify_redeem_proof(
                &issuer(),
                INVITE,
                &did,
                &good,
                &sign(&good),
                &NonceKey::random(),
                t0()
            ),
            Err(ProofError)
        );
        // A DID that is not admitted at all.
        let pkh = "did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        assert_eq!(verify(&f, pkh, &good, &sign(&good), t0()), Err(ProofError));
    }

    /// A nonce minted at t0 checked 301 s later while the message is still within its own validity.
    fn fixture_with_late_expiry(
        k: &ed25519_dalek::SigningKey,
        did: &str,
    ) -> Result<(), ProofError> {
        let f = fixture();
        let m = build_redeem_message(
            &issuer(),
            did,
            INVITE,
            &f.nonce,
            t0(),
            t0() + chrono::Duration::seconds(600),
        )
        .unwrap();
        let sig = k.sign(m.as_bytes()).to_bytes();
        verify(&f, did, &m, &sig, t0() + chrono::Duration::seconds(301))
    }

    #[test]
    fn p256_failing_vectors() {
        let f = fixture();
        let k = p_key();
        let did = p_did(&k);
        let m = msg(&f, &did);
        let sig: p256::ecdsa::Signature = k.sign(m.as_bytes());
        assert_eq!(verify(&f, &did, &m, &sig.to_bytes(), t0()), Ok(()));
        let stranger = p_key();
        let bad: p256::ecdsa::Signature = stranger.sign(m.as_bytes());
        assert_eq!(
            verify(&f, &did, &m, &bad.to_bytes(), t0()),
            Err(ProofError),
            "other key"
        );
        let wrong_domain = m.replace("sso.example.org wants", "evil.example.org wants");
        let s2: p256::ecdsa::Signature = k.sign(wrong_domain.as_bytes());
        assert_eq!(
            verify(&f, &did, &wrong_domain, &s2.to_bytes(), t0()),
            Err(ProofError)
        );
        assert_eq!(
            verify(&f, &did, &m, &sig.to_bytes()[..63], t0()),
            Err(ProofError)
        );
        // An Ed25519 signature does not verify under a P-256 did.
        let e = ed_key();
        assert_eq!(
            verify(&f, &did, &m, &e.sign(m.as_bytes()).to_bytes(), t0()),
            Err(ProofError)
        );
        assert_eq!(ProofError.reason(), "proof_invalid");
    }
}
