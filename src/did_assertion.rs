//! Provider-attested DID assertions: a compact ES256 JWS binding a DID to a
//! Matrix ID.
//!
//! # What this is for
//!
//! siwx-oidc publishes each user's DID into their Synapse profile under the
//! custom field `io.inblock.did`, as an object `{"did": …, "proof": …}`. The
//! `proof` is the artifact this module mints. Without it the field is merely a
//! *claim by whoever last wrote the profile*; with it, a relying party can check
//! that **this provider** asserted **this DID** for **this MXID**.
//!
//! Before this existed, the only published copy of a user's DID lived in
//! `displayname` — a field the user can rewrite at will — so a consumer reading
//! displayname-as-DID could be handed *someone else's* DID. Separating the
//! provider-owned DID from the user-owned alias is the security fix; the proof
//! is what makes the separation checkable off-server.
//!
//! # THE FIELD IS A DISCOVERY HINT, NEVER AN AUTHORIZATION SOURCE
//!
//! Authorization resolves a DID from the OIDC `sub` claim of a token this
//! provider issued, or from a signature made by the DID's own key. A DID read
//! out of a profile — proof or no proof — tells you what to *look up*, not what
//! to *permit*. A verifier that skips the `mxid` binding check below turns this
//! into a replay primitive: user B copies A's perfectly valid proof into B's own
//! profile and it verifies in isolation. The binding claim is the only thing
//! that stops that, and checking it is the *consumer's* job.
//!
//! (Related, and load-bearing: `MEMORY.md` → "MXID to DID is not invertible".
//! A `did:key` rebuilt from a Matrix localpart is a DIFFERENT key — 17 of 48
//! base58 chars differed in the 2026-09-09 incident, filed as siwx-oidc#17.
//! Resolve DIDs from `sub` or from this field, never from a localpart, and
//! compare them byte-for-byte.)
//!
//! # Everything here is world-readable
//!
//! `GET /_matrix/client/v3/profile/{user}/{field}` authenticates only when
//! `require_auth_for_profile_requests` is set, which defaults to **False**
//! (Synapse v1.159.0 `config/server.py:561`), and custom fields federate via
//! `on_profile_query`. A DID is public by nature so this is fine — but it means
//! **nothing private may ever be added to the assertion**. No email, no session
//! id, no internal identifier. Plan invariant 4.
//!
//! # Wire format — this is a CONTRACT, not an implementation detail
//!
//! A verifier ships separately in the `siwx-oidc-auth` client crate. Both sides
//! were written against this block; changing it silently breaks every stored
//! assertion, which cannot be re-minted for users who never sign in again.
//!
//! ```text
//! Compact JWS, ES256 (ECDSA P-256 + SHA-256), RFC 7515 §3.1.
//!
//! signing_input = BASE64URL(UTF8(header_json)) || "." || BASE64URL(UTF8(payload_json))
//! signature     = ES256 over signing_input, raw r||s, exactly 64 bytes, NOT DER
//! jws           = signing_input || "." || BASE64URL(signature)
//!
//! header_json  = {"alg":"ES256","typ":"JWT","kid":"<kid>"}
//! payload_json = {"iss":"<issuer>","sub":"<exact-case DID>","mxid":"<@localpart:server>","iat":<unix seconds>}
//!
//! BASE64URL = base64url, NO padding
//! ```
//!
//! Field ORDER in both JSON documents is fixed by the declaration order of
//! [`DidAssertionHeader`] and [`DidAssertionClaims`] (serde emits struct fields
//! in declaration order). Reordering them changes the bytes that get signed.
//! It does not break a conforming verifier — a verifier re-signs the *received*
//! bytes, not a re-serialization — but it does break byte-for-byte fixtures, so
//! reorder deliberately or not at all.
//!
//! ## `sub` is the DID, deliberately
//!
//! The same claim name the ID token already uses (CLAUDE.md breaking change #1:
//! `sub` became `did:pkh:eip155:1:0xAddr`). A consumer can compare an
//! assertion's `sub` to an ID token's `sub` with zero translation — and, per the
//! memory note above, translation is exactly where DID identity goes wrong.
//!
//! DIDs are **case-sensitive**: `did:key` multibase-base58btc payloads carry
//! meaning in their case. `sub` is written verbatim, never normalised, never
//! lowercased. (The Matrix *localpart* is lowercased — that is a different
//! value living in `mxid`, and the two must not be confused.)
//!
//! ## `mxid` is what stops replay
//!
//! A consumer MUST compare this claim to the profile the proof was read from.
//! Without that comparison a stolen proof verifies anywhere. This module cannot
//! enforce it (it never sees the read), which is why the shipped client-side
//! verifier takes the expected MXID as a required argument rather than offering
//! it as advice. Plan hypothesis H6.
//!
//! ## There is no `exp`, on purpose
//!
//! The binding is permanent. Localparts are never recycled (see the no-recycling
//! rule in CLAUDE.md's MSC3861 device lifecycle section, which is about device
//! ids but reflects the same discipline), and a DID does not stop being that
//! user's DID. An expiry would convert a statement that stays **true** into a
//! credential that goes **stale**, and would require re-minting for accounts
//! that may never sign in again. `payload_has_no_exp_claim` asserts on the raw
//! decoded JSON keys so that an accidental future `exp` fails the suite rather
//! than shipping.
//!
//! ## Nothing is minted with an ephemeral key
//!
//! Plan invariant 5. See [`mint_did_assertion`].
//!
//! Reference: `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Once;
use tracing::{debug, warn};

use crate::oidc::EcdsaSigningKey;

/// The only signature algorithm this module mints or accepts.
///
/// Checked against the received header BEFORE any signature work, so
/// `{"alg":"none"}` and the classic `alg`-confusion downgrades die at the
/// parser rather than reaching a verification routine that might be persuaded to
/// treat a public key as an HMAC secret.
pub const ALG_ES256: &str = "ES256";

/// `typ` header value. `JWT` (not `JOSE`) because the payload is a JSON claims
/// set, which is exactly what RFC 7519 §5.1 describes, and because every
/// off-the-shelf JOSE library a consumer might reach for expects it.
pub const TYP_JWT: &str = "JWT";

/// The claims bound by a DID assertion.
///
/// **Declaration order is the wire order** — see the module doc. `iat` is
/// seconds since the Unix epoch as an `i64` (NumericDate, RFC 7519 §2), matching
/// `chrono::DateTime::timestamp()`, which is what every caller in this codebase
/// already has in hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidAssertionClaims {
    /// The provider's issuer URL — the same value as the OIDC `iss`.
    pub iss: String,
    /// The subject: the user's DID, **exact case, never normalised**.
    pub sub: String,
    /// The Matrix ID this DID is bound to, `@localpart:server`. The replay
    /// guard; a consumer must compare it to the profile it read the proof from.
    pub mxid: String,
    /// Issued-at, Unix seconds. Informational: there is no `exp` and no
    /// freshness requirement — see the module doc.
    pub iat: i64,
}

/// The JOSE header. Declaration order is the wire order (see the module doc).
///
/// Deliberately NOT `#[serde(deny_unknown_fields)]` on the deserialize side:
/// a header that grows a field in a future minter must still verify with today's
/// code, and an unknown header field cannot change what was signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DidAssertionHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// One-shot latch for the ephemeral-key warning.
///
/// Tradeoff, stated explicitly: the suppression is a *configuration* fact, not a
/// per-request event, and `mint_did_assertion` is called on every sign-in. A
/// plain `warn!` per call would emit one line per login forever and train
/// operators to filter the string — which is precisely the line that explains a
/// missing `proof` key. So the `warn!` fires once per process (the startup
/// banner in `axum_lib::main` is the other, guaranteed copy), and each
/// individual suppression is still traceable at `debug!` when someone is
/// actually looking.
static EPHEMERAL_MINT_WARNED: Once = Once::new();

/// Mint a compact ES256 JWS binding `did` to `mxid`.
///
/// Returns `None` — and mints nothing — when the provider's signing key is
/// ephemeral.
///
/// # Why the ephemeral gate is here and not at the call site
///
/// The assertion is written into **someone else's database** (a Synapse profile)
/// and stays there. Signing it with a key we already know will not survive the
/// process is writing garbage into a user's profile: at the next restart the key
/// is gone, its `kid` is no longer in the JWKS, and the proof is permanently
/// unverifiable — for a user who may never sign in again to have it re-minted.
/// Refusing to mint leaves `{"did": …}` with no `proof` key, which is an honest
/// "unproven", instead of a `proof` that lies. Plan invariant 5 / hypothesis H5.
///
/// Putting the gate in the minter rather than at the (currently one, eventually
/// several) call sites means a new call site cannot forget it.
///
/// # `now` is injected
///
/// Not `Utc::now()`: `iat` is part of the signed bytes, so a caller-supplied
/// clock is the only way a test can assert on an exact payload. Production
/// callers pass `Utc::now().timestamp()`.
///
/// # Panics
///
/// Never in practice. `serde_json::to_vec` over these two structs — plain
/// `String`s and one `i64`, no maps with non-string keys, no floats and
/// therefore no `NaN` — has no reachable failure mode, so it is `expect`ed
/// rather than folded into the `Option`. Folding it in would make `None`
/// ambiguous between "ephemeral key" (expected, benign) and "serialization
/// broke" (impossible, and if it ever happened, silent).
pub fn mint_did_assertion(
    key: &EcdsaSigningKey,
    issuer: &str,
    did: &str,
    mxid: &str,
    now: i64,
) -> Option<String> {
    if key.is_ephemeral() {
        EPHEMERAL_MINT_WARNED.call_once(|| {
            warn!(
                kid = %key.kid(),
                "signing key is ephemeral: provider-attested DID assertions are \
                 NOT being minted, and user profiles will carry a `did` with no \
                 `proof`. Set SIWEOIDC_SIGNING_KEY_PEM to a durable key. \
                 (Logged once per process; per-call detail is at debug level.)"
            );
        });
        debug!(
            mxid = %mxid,
            "DID assertion suppressed: ephemeral signing key"
        );
        return None;
    }

    let header = DidAssertionHeader {
        alg: ALG_ES256.to_string(),
        typ: TYP_JWT.to_string(),
        kid: key.kid().to_string(),
    };
    let claims = DidAssertionClaims {
        iss: issuer.to_string(),
        sub: did.to_string(),
        mxid: mxid.to_string(),
        iat: now,
    };

    let header_json =
        serde_json::to_vec(&header).expect("DID assertion header is always encodable");
    let payload_json =
        serde_json::to_vec(&claims).expect("DID assertion claims are always encodable");

    // RFC 7515 §3.1: the signature covers the ASCII of
    // `BASE64URL(header) . BASE64URL(payload)` — the ENCODED forms, not the raw
    // JSON. Signing the raw JSON is the classic implementation bug here and
    // produces a JWS that no conforming verifier accepts.
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header_json),
        URL_SAFE_NO_PAD.encode(&payload_json)
    );

    let signature = key.sign_es256(signing_input.as_bytes());
    debug_assert_eq!(
        signature.len(),
        64,
        "ES256 JWS signatures are raw r||s (64 bytes), never DER"
    );

    Some(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    ))
}

/// Verify a DID assertion against a public key that the caller has ALREADY
/// established is the right one, and return its claims.
///
/// # THIS IS NOT THE SHIPPED VERIFIER — do not use it as one
///
/// It exists so this module can prove its own output verifies (and keeps
/// verifying), and it deliberately does **not** do the two things that make a
/// verifier safe:
///
/// 1. It does not resolve `kid` against the issuer's JWKS. The caller hands it a
///    key; if the caller hands it the wrong key, verification fails, which is
///    safe — but if the caller hands it a key it fetched from somewhere the
///    attacker controls, nothing here notices.
/// 2. **It does not check the `mxid` binding.** A proof that verifies here is
///    still a replay if it was read out of a different user's profile (plan
///    hypothesis H6). The consumer-facing verifier in the `siwx-oidc-auth`
///    crate takes the expected MXID as a required argument precisely so that
///    check cannot be forgotten; this helper cannot, because it never sees the
///    profile the proof came from.
///
/// What it does enforce: exactly three dot-separated parts, `alg` = `ES256`
/// checked *before* any signature work (so `alg:none` and `alg:HS256`
/// downgrades die at the parser), a signature that decodes to exactly 64 raw
/// r‖s bytes, and a signature valid over the received `signing_input` bytes —
/// the received bytes, never a re-serialization, so field-order or whitespace
/// drift in a future minter cannot cause a spurious failure.
pub fn verify_with_key(jws: &str, key: &VerifyingKey) -> Result<DidAssertionClaims> {
    let mut parts = jws.split('.');
    let (header_b64, payload_b64, signature_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => bail!(
                "malformed compact JWS: expected exactly three '.'-separated parts, got {}",
                jws.split('.').count()
            ),
        };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| anyhow!("JWS header is not valid unpadded base64url: {e}"))?;
    let header: DidAssertionHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow!("JWS header is not a DID assertion header: {e}"))?;

    // Algorithm agility is an attack surface, not a feature. One algorithm,
    // checked first, before a single byte of key material is touched.
    if header.alg != ALG_ES256 {
        bail!(
            "unsupported JWS alg {:?}: DID assertions are {ALG_ES256} only",
            header.alg
        );
    }
    if header.typ != TYP_JWT {
        bail!(
            "unsupported JWS typ {:?}: DID assertions are {TYP_JWT} only",
            header.typ
        );
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| anyhow!("JWS signature is not valid unpadded base64url: {e}"))?;
    // 64 == raw r||s. A DER-encoded ECDSA signature is 70-72 bytes; rejecting on
    // length here turns "someone switched to to_der()" into a precise error
    // instead of an opaque verification failure.
    if signature_bytes.len() != 64 {
        bail!(
            "JWS signature is {} bytes: ES256 requires raw r||s of exactly 64 (a 70-72 byte \
             signature means DER, which is not the JWS encoding)",
            signature_bytes.len()
        );
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("JWS signature is not a valid P-256 r||s pair: {e}"))?;

    // Re-derive the signing input from the RECEIVED bytes, by slicing the input
    // string rather than re-encoding the parsed header. Re-encoding would make
    // verification depend on this process serializing exactly like the minter
    // did — a coupling that breaks the moment either side reorders a field.
    let signing_input = &jws[..header_b64.len() + 1 + payload_b64.len()];
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|e| anyhow!("DID assertion signature verification failed: {e}"))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| anyhow!("JWS payload is not valid unpadded base64url: {e}"))?;
    let claims: DidAssertionClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("JWS payload is not a DID assertion claims set: {e}"))?;

    Ok(claims)
}

/// Test-only: a freshly generated P-256 private key in PKCS#8 PEM form, the same
/// shape an operator puts in `SIWEOIDC_SIGNING_KEY_PEM`.
///
/// Lives here rather than in each test module so the "load the same PEM twice
/// and compare kids" test in `oidc.rs` and the mint/verify tests below are
/// provably exercising the same key format.
#[cfg(test)]
pub(crate) fn test_p256_pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    p256::SecretKey::random(&mut rand::thread_rng())
        .to_pkcs8_pem(LineEnding::LF)
        .expect("P-256 secret key always encodes to PKCS#8 PEM")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::{JsonWebKey, PrivateSigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::pkcs8::DecodePrivateKey;
    use serde_json::Value;

    const ISSUER: &str = "https://siwx-oidc.inblock.io";
    /// Mixed case ON PURPOSE. `did:key` multibase payloads are case-sensitive;
    /// a minter that lowercased `sub` would produce a proof for a DIFFERENT key
    /// (MEMORY.md "MXID to DID is not invertible" / siwx-oidc#17).
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const MXID: &str = "@k3f9x2q7ab4d8m1p:inblock.io";
    const IAT: i64 = 1_757_500_000;

    fn durable_key() -> (EcdsaSigningKey, VerifyingKey) {
        let pem = test_p256_pem();
        let key = EcdsaSigningKey::from_pem(&pem).expect("test PEM must load");
        // Derive the verifying key straight from the PEM, INDEPENDENTLY of
        // `EcdsaSigningKey`, so the round-trip test cannot pass by both sides
        // sharing the same bug.
        let vk = *P256SigningKey::from_pkcs8_pem(&pem)
            .expect("test PEM must load")
            .verifying_key();
        (key, vk)
    }

    fn mint(key: &EcdsaSigningKey) -> String {
        mint_did_assertion(key, ISSUER, DID, MXID, IAT).expect("durable key must mint")
    }

    fn decode_part(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url part"))
            .expect("part is JSON")
    }

    /// H4b: the `kid` a relying party finds in the published JWKS is the same
    /// `kid` it finds in an assertion header. If these ever diverge, every proof
    /// is unresolvable even though both halves look individually correct.
    #[test]
    fn h4b_jwks_kid_equals_the_assertion_header_kid() {
        let (key, _) = durable_key();
        let jwk = key.as_verification_key();
        let jwk_kid = jwk
            .key_id()
            .expect("published JWK must carry a kid")
            .as_str()
            .to_string();

        let jws = mint(&key);
        let header = decode_part(jws.split('.').next().unwrap());

        assert_eq!(
            header["kid"].as_str().unwrap(),
            jwk_kid,
            "assertion header kid must match the kid published in the JWKS"
        );
        assert_eq!(
            jwk_kid,
            key.kid(),
            "kid() must agree with the published JWK"
        );
    }

    /// H5: an ephemeral key mints nothing. Writing a durable proof with a key
    /// that dies at restart writes permanently-unverifiable garbage into a
    /// user's profile.
    #[test]
    fn h5_ephemeral_key_mints_no_assertion() {
        let key = EcdsaSigningKey::generate();
        assert!(key.is_ephemeral(), "generate() must mark the key ephemeral");
        assert!(
            mint_did_assertion(&key, ISSUER, DID, MXID, IAT).is_none(),
            "an ephemeral key must never mint a durable assertion"
        );
    }

    /// H5, other direction: a configured PEM is durable and does mint.
    #[test]
    fn h5_durable_pem_key_mints_an_assertion() {
        let (key, _) = durable_key();
        assert!(
            !key.is_ephemeral(),
            "from_pem() must mark the key as durable"
        );
        assert!(mint_did_assertion(&key, ISSUER, DID, MXID, IAT).is_some());
    }

    #[test]
    fn minted_jws_has_exactly_three_parts_and_the_exact_header() {
        let (key, _) = durable_key();
        let jws = mint(&key);

        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS is exactly three parts: {jws}");

        let header = decode_part(parts[0]);
        let obj = header.as_object().expect("header is a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["alg", "kid", "typ"],
            "header carries exactly alg/typ/kid — nothing else is signed into it"
        );
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"].as_str().unwrap(), key.kid());

        // Base64url must be UNPADDED (RFC 7515 §2). A stray '=' is a different
        // string and therefore a different signing input.
        assert!(
            !jws.contains('='),
            "compact JWS must use unpadded base64url: {jws}"
        );
    }

    #[test]
    fn payload_carries_exactly_the_four_claims_and_preserves_did_case() {
        let (key, _) = durable_key();
        let jws = mint(&key);
        let payload = decode_part(jws.split('.').nth(1).unwrap());
        let obj = payload.as_object().expect("payload is a JSON object");

        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["iat", "iss", "mxid", "sub"]);

        assert_eq!(payload["iss"], ISSUER);
        assert_eq!(
            payload["sub"].as_str().unwrap(),
            DID,
            "the DID must be reproduced byte-for-byte, case included"
        );
        assert_eq!(payload["mxid"], MXID);
        assert_eq!(payload["iat"].as_i64().unwrap(), IAT);
    }

    /// The `exp`-absence guard. Asserted on the RAW decoded object's key set so
    /// that a future "let's add an expiry" fails here loudly instead of quietly
    /// converting a permanently-true statement into a stale credential.
    #[test]
    fn payload_has_no_exp_claim() {
        let (key, _) = durable_key();
        let jws = mint(&key);
        let payload = decode_part(jws.split('.').nth(1).unwrap());
        let obj = payload.as_object().unwrap();
        assert!(
            !obj.contains_key("exp"),
            "DID assertions are permanent bindings and must carry no exp: {payload}"
        );
        assert!(!obj.contains_key("nbf"), "no nbf either: {payload}");
    }

    /// The r‖s guard. A DER-encoded ECDSA signature is 70-72 bytes; 64 is the
    /// only length RFC 7518 §3.4 permits for ES256. Asserted explicitly because
    /// switching to `to_der()` fails silently at mint time and only surfaces as
    /// an unverifiable proof already sitting in a user's profile.
    #[test]
    fn signature_is_64_raw_bytes_never_der() {
        let (key, _) = durable_key();
        let jws = mint(&key);
        let sig = URL_SAFE_NO_PAD
            .decode(jws.split('.').nth(2).unwrap())
            .expect("signature is base64url");
        assert_eq!(
            sig.len(),
            64,
            "ES256 signature must be raw r||s (64 bytes); {} suggests DER",
            sig.len()
        );
    }

    #[test]
    fn verify_with_key_accepts_a_freshly_minted_assertion() {
        let (key, vk) = durable_key();
        let jws = mint(&key);
        let claims = verify_with_key(&jws, &vk).expect("freshly minted assertion must verify");
        assert_eq!(
            claims,
            DidAssertionClaims {
                iss: ISSUER.to_string(),
                sub: DID.to_string(),
                mxid: MXID.to_string(),
                iat: IAT,
            }
        );
    }

    #[test]
    fn verify_rejects_a_tampered_did_in_the_payload() {
        let (key, vk) = durable_key();
        let jws = mint(&key);
        let parts: Vec<&str> = jws.split('.').collect();

        // The tamper is applied to the DECODED JSON TEXT, not to a
        // `serde_json::Value` round-trip.
        //
        // This matters, and it is a trap this test previously fell into:
        // `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature
        // is on, so decoding and re-serializing reorders the claims
        // (iss,sub,mxid,iat -> iat,iss,mxid,sub). The re-encoded payload would
        // then differ from the signed bytes even with NO tamper at all, and the
        // test would have passed while proving nothing about the DID. Operating
        // on the raw text keeps every other byte identical, so the ONLY reason
        // verification can fail is the substituted DID.
        let payload_json =
            String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).expect("payload is UTF-8");
        let tampered_did = DID.replacen("zDna", "zDnb", 1);
        assert_ne!(tampered_did, DID);
        let tampered_json = payload_json.replace(DID, &tampered_did);
        assert_ne!(
            tampered_json, payload_json,
            "the substitution must actually have changed the payload"
        );

        // Control leg: re-encoding the UNCHANGED text must still verify. Without
        // this, a failure below could be an artifact of the repack rather than
        // evidence that the signature binds the DID.
        let repacked_intact = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(payload_json.as_bytes()),
            parts[2]
        );
        assert!(
            verify_with_key(&repacked_intact, &vk).is_ok(),
            "control: a byte-identical repack must still verify"
        );

        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(tampered_json.as_bytes()),
            parts[2]
        );
        assert!(
            verify_with_key(&forged, &vk).is_err(),
            "a substituted DID must not verify under the original signature"
        );
    }

    #[test]
    fn verify_rejects_a_truncated_signature() {
        let (key, vk) = durable_key();
        let jws = mint(&key);
        let parts: Vec<&str> = jws.split('.').collect();
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig.truncate(32);
        let truncated = format!("{}.{}.{}", parts[0], parts[1], URL_SAFE_NO_PAD.encode(&sig));
        assert!(
            verify_with_key(&truncated, &vk).is_err(),
            "a 32-byte signature must be rejected, not zero-extended"
        );
    }

    #[test]
    fn verify_rejects_an_assertion_from_a_different_key() {
        let (key, _) = durable_key();
        let (_other_key, other_vk) = durable_key();
        let jws = mint(&key);
        assert!(
            verify_with_key(&jws, &other_vk).is_err(),
            "an assertion must not verify under a key that did not sign it"
        );
    }

    /// H7 downgrade guard: `alg` is checked before any signature work, so the
    /// classic `alg:none` forgery is rejected at the parser.
    #[test]
    fn verify_rejects_alg_none_before_touching_the_signature() {
        let (key, vk) = durable_key();
        let jws = mint(&key);
        let parts: Vec<&str> = jws.split('.').collect();
        let mut header = decode_part(parts[0]);
        header["alg"] = Value::String("none".into());
        let repacked = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let downgraded = format!("{}.{}.{}", repacked, parts[1], parts[2]);

        let err = verify_with_key(&downgraded, &vk)
            .expect_err("alg:none must be rejected")
            .to_string();
        assert!(
            err.contains("unsupported JWS alg"),
            "alg must be rejected by the alg check, not incidentally by the \
             signature check: {err}"
        );
    }

    #[test]
    fn verify_rejects_a_jws_that_is_not_three_parts() {
        let (key, vk) = durable_key();
        let jws = mint(&key);
        let two_parts: String = jws.rsplit_once('.').unwrap().0.to_string();
        assert!(verify_with_key(&two_parts, &vk).is_err());
        assert!(verify_with_key(&format!("{jws}.extra"), &vk).is_err());
    }
}
