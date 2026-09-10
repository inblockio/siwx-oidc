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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
// Only [`verify_with_key`] needs these, and that helper is `#[cfg(test)]` —
// see its doc comment for why it must never be reachable from production code.
#[cfg(test)]
use anyhow::{anyhow, bail, Result};
#[cfg(test)]
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Once;
use tracing::{debug, warn};

use crate::oidc::EcdsaSigningKey;

/// The MSC4133 custom profile field that carries the provider-attested DID.
///
/// # This is a THREE-SIDED wire contract, not a string constant
///
/// The same literal has to be identical in three independently-deployed places,
/// and they do not fail together — they fail *apart*, silently:
///
/// | Side | Where | What it does with the name |
/// |---|---|---|
/// | provider (this crate) | [`crate::synapse_client::SynapseClient::publish_did_field`] | `PUT /_matrix/client/v3/profile/{mxid}/{field}`, body keyed by the field |
/// | consumer | `siwx-oidc-auth`'s own `DID_PROFILE_FIELD` (`siwx-oidc-auth/src/did_assertion.rs`) | reads the field and the `{field: value}` envelope Synapse echoes back |
/// | homeserver | `experimental_features.msc4133_key_denylist` in `../siwx-oidc-matrix-server/entrypoints/matrix_server.sh` | refuses a *user's* write/delete of exactly this name |
///
/// Renaming it is therefore a **migration, not an edit**. All three sides must
/// move together, and for at least one full upgrade cycle the consumer has to
/// **dual-read** the old and new names — otherwise every account that has not
/// signed in since the rename reads as "no published DID". Worse, the
/// homeserver side fails *open*: a denylist entry that still names the old key
/// leaves the new field user-writable, which is precisely the vulnerability
/// this whole feature exists to close (see
/// `docs/audits/2026-09-10-msc4133-acl-probe.md`, legs 2 and 3).
///
/// The name satisfies Synapse's Common Namespaced Identifier Grammar,
/// `^[a-z][a-z0-9_.-]{0,254}$` (v1.159.0 `util/stringutils.py:53`) — which is
/// also why a DID can never be a field *name*: that grammar forbids uppercase
/// and colons.
pub const DID_PROFILE_FIELD: &str = "io.inblock.did";

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

/// Everything the DID-publication side effect needs, bundled so a sign-in path
/// carries **one** extra parameter instead of two.
///
/// # Why a struct for two fields
///
/// [`crate::oidc::provision_synapse_device`] already took six arguments, four of
/// which are `&str`/`Option<&str>`. Adding a seventh and eighth positional
/// string is how call sites start passing `issuer` where `did` belongs — the
/// compiler cannot tell two `&str`s apart, and both call sites are on the
/// login path where a mix-up is a silently wrong assertion in a user's profile,
/// not a crash. A named struct makes the mistake a type error at construction.
///
/// # Why it is `Option`al at the call site
///
/// One `None` turns the whole feature off in one place. That is the shape a
/// deployment without this feature needs, and it is also the shape a unit test
/// of `provision_synapse_device` needs when it is asserting something else
/// entirely (see `provision_user_display_name_is_the_localpart_never_the_did`).
///
/// Note that `None` is NOT how the ephemeral-key case is expressed: an
/// ephemeral key still publishes `{"did": …}` (without a `proof`), because the
/// DID itself is true and worth publishing. See [`did_profile_value`].
pub struct DidPublication<'a> {
    /// The provider's ES256 signing key. Whether it is durable enough to mint a
    /// `proof` is decided inside [`mint_did_assertion`], never here.
    pub key: &'a EcdsaSigningKey,
    /// The OIDC issuer URL (`config.base_url`), written verbatim into `iss`.
    ///
    /// It must be the value a consumer's OIDC discovery document reports as
    /// `issuer`, because the shipped verifier compares the two
    /// (trailing-slash-insensitively) and rejects a mismatch as "minted by a
    /// different provider".
    pub issuer: &'a str,
}

/// Build the exact JSON value published at [`DID_PROFILE_FIELD`].
///
/// ```json
/// { "did": "did:key:zDn…", "proof": "<compact ES256 JWS>" }
/// ```
///
/// # The `proof` member is absent, not empty, when the key is ephemeral
///
/// [`mint_did_assertion`] returns `None` for an ephemeral key (plan invariant 5
/// — never write a durable assertion with a key that dies at restart), and this
/// function then omits the `proof` key **entirely**. That is the honest state,
/// not a failure: the DID is still true and still worth publishing, it simply
/// carries no provider signature. The shipped consumer distinguishes the two
/// cases by discriminator — `DidAssertionError::ProofAbsent` versus a
/// verification error — so an operator can tell "this deployment has no
/// configured signing key" apart from "this proof is bad" without reading logs.
///
/// Do not "improve" this by emitting `"proof": null` or `"proof": ""`: the
/// consumer filters an empty string back out (`siwx-oidc-auth`'s
/// `.filter(|s| !s.is_empty())`), so both spellings would land in the same
/// bucket while making the stored JSON claim something exists that does not.
///
/// # Why an object rather than two profile fields
///
/// One `PUT` is one canonical-JSON blob, so the DID and its proof cannot drift
/// apart (one write landing while the other fails), and the homeserver-side
/// denylist that protects this value is **one** entry rather than two — a
/// smaller Synapse patch to forward-port on every version bump. See the plan's
/// "Why one field and not two".
///
/// # Nothing private may ever be added here
///
/// `GET /_matrix/client/v3/profile/{user}/{field}` is unauthenticated by
/// default (`require_auth_for_profile_requests`, Synapse v1.159.0
/// `config/server.py:561`) and custom fields federate. Anything this function
/// returns is world-readable, forever. Plan invariant 4.
pub fn did_profile_value(
    key: &EcdsaSigningKey,
    issuer: &str,
    did: &str,
    mxid: &str,
    now: i64,
) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    // Exact case. A `did:key` multibase payload carries meaning in its case and
    // is NOT recoverable from the (lowercased) Matrix localpart — MEMORY.md
    // "MXID to DID is not invertible", filed as siwx-oidc#17.
    value.insert(
        "did".to_string(),
        serde_json::Value::String(did.to_string()),
    );
    if let Some(proof) = mint_did_assertion(key, issuer, did, mxid, now) {
        value.insert("proof".to_string(), serde_json::Value::String(proof));
    }
    serde_json::Value::Object(value)
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
///
/// # `#[cfg(test)]` is the enforcement of the warning above
///
/// While the whole module was `#[allow(dead_code)]` (it was, until the write
/// channel landed), "do not use it as one" was a doc comment and nothing more.
/// Gating it on `cfg(test)` makes that warning a compile error instead: a
/// future production call site cannot reach an unbound verifier by accident,
/// which is the mistake that turns a signature check into a replay primitive.
/// The consumer-facing verifier lives in `siwx-oidc-auth` and takes the
/// expected MXID as a required argument.
#[cfg(test)]
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

    // -- did_profile_value: the object that actually lands in the profile ----

    /// **H1** (value half) — the published object is exactly `{did, proof}`,
    /// with the DID reproduced byte-for-byte.
    ///
    /// Asserted on the RAW key set, not just on the two members being present,
    /// so that a future addition to this object has to be a deliberate edit
    /// here. Everything in it is world-readable and federates (plan invariant
    /// 4), which makes "one more harmless field" the exact mistake to make hard.
    #[test]
    fn h1_did_profile_value_is_did_plus_proof() {
        let (key, vk) = durable_key();
        let value = did_profile_value(&key, ISSUER, DID, MXID, IAT);
        let obj = value.as_object().expect("the field value is a JSON object");

        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["did", "proof"],
            "nothing but the DID and its proof may be published: {value}"
        );
        assert_eq!(
            obj["did"].as_str().unwrap(),
            DID,
            "the DID must be exact-case; a lowercased did:key is a DIFFERENT key \
             (MEMORY.md 'MXID to DID is not invertible', siwx-oidc#17)"
        );

        // The `proof` member must be the real thing, not merely a string.
        let claims = verify_with_key(obj["proof"].as_str().unwrap(), &vk)
            .expect("the published proof must verify under the publishing key");
        assert_eq!(claims.sub, DID);
        assert_eq!(claims.mxid, MXID);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.iat, IAT);
    }

    /// **H5** (value half) — an ephemeral key publishes the DID with **no
    /// `proof` key at all**.
    ///
    /// Not `"proof": null`, not `"proof": ""`. The consumer filters an empty
    /// string back out, so both spellings would land in the same bucket while
    /// making the stored JSON assert that something exists which does not. The
    /// key-set assertion below is what forbids them.
    #[test]
    fn h5_ephemeral_key_publishes_a_did_with_no_proof_key() {
        let key = EcdsaSigningKey::generate();
        assert!(key.is_ephemeral());
        let value = did_profile_value(&key, ISSUER, DID, MXID, IAT);
        let obj = value.as_object().expect("the field value is a JSON object");

        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["did"],
            "an ephemeral key must publish the DID alone — absent, not null, not empty: {value}"
        );
        assert_eq!(obj["did"].as_str().unwrap(), DID);
    }

    /// The `mxid` a value is built for really is the one bound inside the
    /// proof. If `did_profile_value` ever passed its arguments to
    /// `mint_did_assertion` in the wrong order (four `&str`s in a row), the
    /// object would still look perfectly well-formed and every consumer would
    /// reject it as a replay.
    #[test]
    fn did_profile_value_binds_the_mxid_it_was_given() {
        let (key, vk) = durable_key();
        let other_mxid = "@zzzzzzzzzzzzzzzz:inblock.io";
        let value = did_profile_value(&key, ISSUER, DID, other_mxid, IAT);
        let claims =
            verify_with_key(value["proof"].as_str().unwrap(), &vk).expect("proof must verify");
        assert_eq!(claims.mxid, other_mxid);
        assert_eq!(claims.sub, DID, "sub is the DID, mxid is the Matrix ID");
    }
}

/// **H8** — the server's minter and the shipped client verifier interoperate.
///
/// # Why this test is the one that matters
///
/// The minter (this module) and the verifier
/// (`siwx-oidc-auth/src/did_assertion.rs`) were written independently, by
/// different agents, against a written wire-format spec. Both sides have
/// thorough unit tests; both sides pass them; neither proves the other can read
/// what it wrote. A single disagreement — DER instead of raw r‖s, padded
/// base64, a re-serialized signing input, a `kid` that is not the JWKS `kid` —
/// produces two internally-consistent implementations that never verify a
/// single real assertion between them, and every other test in this change
/// would still be green. So this runs the real minter against the real
/// verifier, over real HTTP, through the real `oidc::jwks` document.
///
/// # Why it lives here and not in `tests/`
///
/// `tests/*.rs` integration tests link against the `siwx_oidc` **library**
/// crate (`src/lib.rs`), and both the minter and `EcdsaSigningKey` live in the
/// **binary** crate's module tree (`src/main.rs`). A file under `tests/`
/// literally cannot name `mint_did_assertion`. A `#[cfg(test)]` module in the
/// binary can, and `[dev-dependencies]` are linked for it — which is what makes
/// the cross-crate call possible at all. (The same reasoning is already
/// recorded in `localpart.rs`'s `resolve_identity_tests` module doc.)
#[cfg(test)]
mod interop_with_the_shipped_verifier {
    use super::*;
    use axum::routing::get;
    use axum::{Json, Router};
    use siwx_oidc_auth::did_assertion::{verify_did_assertion, DidAssertionError};
    use tokio::net::TcpListener;

    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const MXID: &str = "@k3f9x2q7ab4d8m1p:inblock.io";
    const OTHER_MXID: &str = "@w9q2h4t6y8u0i1o3:inblock.io";
    const IAT: i64 = 1_757_500_000;

    /// Serve the two documents a consumer actually fetches: OIDC discovery and
    /// the JWKS. Both come from the SAME production code paths the real server
    /// uses (`oidc::jwks`), so a change to the published JWK shape breaks this
    /// test rather than silently breaking every deployed consumer.
    ///
    /// Returns the issuer base URL and the server task handle.
    async fn spawn_issuer(key: &EcdsaSigningKey) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral issuer port");
        let addr = listener.local_addr().expect("issuer local_addr");
        let issuer = format!("http://{addr}");

        let jwks_json = serde_json::to_value(
            // No retired keys: this fixture is about the LIVE key's JWK shape.
            // `oidc::tests::after_rotation_the_jwks_carries_both_the_live_and_the_retired_kid`
            // covers the retired half.
            crate::oidc::jwks(key, &[]).expect("the production JWKS builder must succeed"),
        )
        .expect("a JWKS always serializes");
        let discovery = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwk"),
        });

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/jwk", get(move || async move { Json(jwks_json) }));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("issuer server");
        });
        (issuer, handle)
    }

    /// H8: mint here, verify there. The `proof` is taken out of the exact
    /// object [`did_profile_value`] publishes, not from a hand-built JWS, so
    /// this covers the envelope as well as the signature.
    #[tokio::test]
    async fn h8_server_minted_assertion_verifies_in_the_client_crate() {
        let key = EcdsaSigningKey::from_pem(&test_p256_pem()).expect("test PEM must load");
        let (issuer, handle) = spawn_issuer(&key).await;

        let value = did_profile_value(&key, &issuer, DID, MXID, IAT);
        let proof = value["proof"]
            .as_str()
            .expect("a durable key must publish a proof");

        let verified = verify_did_assertion(&issuer, proof, MXID)
            .await
            .expect("the shipped verifier must accept a genuinely minted assertion");

        assert_eq!(
            verified.did(),
            DID,
            "the DID must survive the round trip byte for byte"
        );
        assert_eq!(verified.mxid(), MXID);
        assert_eq!(verified.issued_at(), IAT);
        // Trailing-slash-insensitive on the verifier's side; assert the exact
        // string here because our issuer never grows one.
        assert_eq!(verified.issuer(), issuer);

        handle.abort();
    }

    /// H6/H8: the replay guard holds across the crate boundary too.
    ///
    /// This is the whole security property of the `mxid` claim: user B copies
    /// A's perfectly valid, correctly-signed proof into B's own profile. The
    /// signature verifies — it is genuine — and the assertion must still be
    /// rejected. Asserted HERE, against the real verifier, rather than only in
    /// the client crate's own tests, because a minter that forgot to set `mxid`
    /// (or set it to the localpart, or to the DID) would pass every test on the
    /// client side and produce universally-replayable proofs.
    #[tokio::test]
    async fn h8_replayed_assertion_is_rejected_across_the_crate_boundary() {
        let key = EcdsaSigningKey::from_pem(&test_p256_pem()).expect("test PEM must load");
        let (issuer, handle) = spawn_issuer(&key).await;

        let value = did_profile_value(&key, &issuer, DID, MXID, IAT);
        let proof = value["proof"].as_str().unwrap();

        // Control leg: the same proof DOES verify for the account it names, so
        // the rejection below cannot be an artifact of a broken fixture.
        assert!(
            verify_did_assertion(&issuer, proof, MXID).await.is_ok(),
            "control: the proof must verify for its own mxid"
        );

        let err = verify_did_assertion(&issuer, proof, OTHER_MXID)
            .await
            .expect_err("a proof presented for another account must be rejected")
            .to_string();
        assert!(
            err.contains("REPLAYED ASSERTION"),
            "the rejection must be the mxid binding check, not an incidental \
             signature failure: {err}"
        );

        handle.abort();
    }

    /// H5/H8: an ephemeral key's proof-less object is reported by the consumer
    /// as the typed, downcastable `ProofAbsent`, not as a verification failure.
    ///
    /// The two must not be confused: `ProofAbsent` means "this deployment has
    /// no configured signing key", which an operator fixes with
    /// `SIWEOIDC_SIGNING_KEY_PEM`; a verification failure means "this proof is
    /// not acceptable", which they investigate. This asserts the server's
    /// omission lands in the consumer's intended bucket.
    #[test]
    fn h5_proofless_object_maps_to_the_consumers_proof_absent_discriminator() {
        let key = EcdsaSigningKey::generate();
        let value = did_profile_value(&key, "https://issuer.example", DID, MXID, IAT);
        assert!(
            value.get("proof").is_none(),
            "precondition: an ephemeral key publishes no proof"
        );

        // Reproduce the branch `fetch_and_verify_did` takes on this exact
        // object: an object whose `proof` member is absent.
        let proof = value
            .get("proof")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        assert!(proof.is_none());
        let e = DidAssertionError::ProofAbsent {
            mxid: MXID.to_string(),
            // Named `unverified_did` on the consumer side on purpose: the value
            // is whatever the profile happened to contain, with nothing
            // vouching for it. Do not rename it back to `did` here.
            unverified_did: DID.to_string(),
        };
        assert!(
            e.to_string().contains("UNVERIFIABLE"),
            "the consumer must call a proof-less DID unverifiable, not usable: {e}"
        );
    }
}
