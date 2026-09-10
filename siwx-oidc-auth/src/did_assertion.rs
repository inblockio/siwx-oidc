//! Verification of provider-attested DID assertions published in a Matrix profile.
//!
//! # What this module is for
//!
//! siwx-oidc publishes each user's DID into their Matrix profile under the
//! MSC4133 custom field [`DID_PROFILE_FIELD`] (`io.inblock.did`). The value is a
//! JSON **object**, written atomically by the provider with an admin-scoped
//! token:
//!
//! ```json
//! {
//!   "did":   "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB",
//!   "proof": "<compact ES256 JWS>"
//! }
//! ```
//!
//! `proof` is deliberately **optional**: when the issuer's signing key is
//! ephemeral (no `SIWEOIDC_SIGNING_KEY_PEM`) the server refuses to mint one,
//! because writing a durable assertion signed by a key that dies at the next
//! restart is writing garbage into someone's profile. See
//! `docs/superpowers/plans/2026-09-10-immutable-attested-did.md` H5 (line 136)
//! and the "Never write a durable assertion with an ephemeral key" invariant
//! (line 170). This module surfaces that case as the typed, distinguishable
//! [`DidAssertionError::ProofAbsent`] — never a panic, and never a silent pass.
//!
//! # THE TRUST MODEL — read before you use any of this
//!
//! **This field is a discovery hint. It is NOT an authorization source.**
//!
//! A verified assertion proves exactly one thing: *the provider asserted, at
//! `iat`, that this DID belongs to this Matrix user*. It does NOT prove that
//! the holder controls the DID's private key right now, and it is not a
//! capability. Authorization MUST come from one of:
//!
//! 1. the OIDC `sub` claim of a token **this provider issued** (validated
//!    against the provider's JWKS), or
//! 2. a fresh signature by the DID key itself (what the aqua node's grant
//!    ceremony already requires — it is safe with or without any of this).
//!
//! The assertion exists to protect the *next* consumer, the one that would
//! otherwise read a DID out of `displayname` — a field the **user** can rewrite
//! at will, so a consumer treating displayname-as-DID can be handed someone
//! else's DID. Separating the provider-owned DID from the user-owned alias is
//! the security fix; see the three-tier table in the plan (lines 17-27).
//!
//! # The field is world-readable and it federates
//!
//! `GET /_matrix/client/v3/profile/{user}/{field}` authenticates only when
//! `require_auth_for_profile_requests` is set, and that defaults to **False**
//! (Synapse v1.159.0 `config/server.py:561`); custom fields also federate via
//! `on_profile_query`. Everything in this object is public. **Nothing private
//! may ever be added to it** (plan invariant 4, line 169).
//!
//! # Wire contract (must match the server's minter byte for byte)
//!
//! ```text
//! Compact JWS, ES256 (ECDSA P-256 + SHA-256), RFC 7515 section 3.1.
//!
//! signing_input = BASE64URL(UTF8(header_json)) || "." || BASE64URL(UTF8(payload_json))
//! signature     = ES256 over signing_input, raw r||s, exactly 64 bytes, NOT DER
//! jws           = signing_input || "." || BASE64URL(signature)
//!
//! header_json  = {"alg":"ES256","typ":"JWT","kid":"<kid>"}
//! payload_json = {"iss":"<issuer>","sub":"<exact-case DID>","mxid":"<@localpart:server>","iat":<unix seconds>}
//!
//! BASE64URL = base64url, NO padding.
//! ```
//!
//! Two details of that contract are load-bearing and have already been chosen
//! for us by the server side; do not "normalize" them here:
//!
//! - **r‖s, not DER.** `src/oidc.rs:116-124` signs with
//!   `Signature::to_bytes()` and comments the reason. A DER-accepting verifier
//!   would quietly accept a shape we never emit and widen the parser surface.
//! - **`kid` identifies the key, not the slot.** `src/axum_lib.rs` historically
//!   stamped `kid = "key1"` on both the configured and the generated key, so a
//!   restart with an ephemeral key would leave every stored assertion failing
//!   as "bad signature" — indistinguishable from an attack. Deriving `kid` from
//!   the public key (`src/oidc.rs:104-110` `public_key_fingerprint()`) turns
//!   that into an honest, diagnosable "kid not present in JWKS", which is
//!   exactly why [`verify_did_assertion`] treats a missing `kid` match as a
//!   **hard error** and never falls back to trying every key in the set.
//!
//! There is deliberately **no `exp`** claim. The binding is permanent —
//! localparts are never recycled and a DID never stops being that user's DID —
//! so a stale assertion stays *true* rather than decaying into a stale
//! credential (plan lines 83-85). Nothing in this module rejects on age; do not
//! add an age check "for hygiene", it would make correct old assertions fail.

use std::fmt;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};

/// The MSC4133 custom profile field that carries the provider-attested DID.
///
/// This is a **wire contract**, not an implementation detail: the server writes
/// it, Synapse's key denylist protects it by this exact name, and every
/// consumer reads it. Changing the string means every deployed consumer must
/// dual-read the old and the new key for at least one full upgrade cycle, so
/// treat a rename as a migration, not an edit.
///
/// The name satisfies Synapse's Common Namespaced Identifier Grammar,
/// `^[a-z][a-z0-9_.-]{0,254}$` (`util/stringutils.py:53`) — which is also why a
/// DID can never be a field *name*: the grammar forbids uppercase and colons.
pub const DID_PROFILE_FIELD: &str = "io.inblock.did";

/// Timeout for the discovery / JWKS / profile fetches.
///
/// Chosen so a black-holed homeserver fails the call instead of hanging a CLI
/// or an agent loop forever. Verification itself is pure CPU and unbounded only
/// by the input length.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// A DID assertion that verified against the issuer's JWKS **and** bound the
/// Matrix ID it was read from.
///
/// Every field here came out of the signed payload, so all four are covered by
/// the signature. In particular `issuer` is the assertion's own `iss` claim
/// (already checked equal to the discovery document's `issuer`, modulo a
/// trailing slash) rather than the discovery value, so a caller that stores
/// this struct is storing only attested data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDid {
    /// The DID, exact case, from the `sub` claim.
    ///
    /// This is deliberately the same claim the ID token carries (CLAUDE.md
    /// breaking change #1: `sub` is `did:pkh:eip155:1:0x…`, not a bare
    /// address), so a consumer can compare an assertion's `sub` to an ID
    /// token's `sub` with no translation step in between.
    pub did: String,
    /// The Matrix ID this DID is bound to. Always equal to the `expected_mxid`
    /// the caller passed — the comparison is what makes replay fail.
    pub mxid: String,
    /// The issuer that signed the assertion (`iss` claim).
    pub issuer: String,
    /// Unix seconds at which the provider made the assertion (`iat` claim).
    ///
    /// Informational only. There is no `exp`, and age is **not** grounds for
    /// rejection; see the module docs.
    pub issued_at: i64,
}

// ---------------------------------------------------------------------------
// Typed, machine-checkable outcomes
// ---------------------------------------------------------------------------

/// The two *expected* non-verifying outcomes of [`fetch_and_verify_did`].
///
/// These are conditions a healthy deployment produces on purpose, so they get a
/// discriminator a caller can `match` on instead of a string a caller would
/// have to grep. Same reasoning as the server's
/// `CustomError::UnknownCredential` (`src/oidc.rs:170-178`): an expected user
/// condition must not be logged, or handled, as an internal error.
///
/// Everything else — a bad signature, a tampered payload, an `alg` we do not
/// mint, a `kid` that is not in the JWKS, a replayed assertion — is an
/// untyped [`anyhow::Error`] carrying a human-readable diagnosis, because those
/// are all "this proof is not acceptable" and a caller has exactly one correct
/// response to all of them: do not trust the DID.
///
/// Recover the discriminator with `err.downcast_ref::<DidAssertionError>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidAssertionError {
    /// The profile carries no `io.inblock.did` field at all.
    FieldAbsent { mxid: String },
    /// The field exists but has no `proof` — the issuer's signing key was
    /// ephemeral, so it refused to mint a durable assertion (plan H5).
    ///
    /// The `did` here is the plain, **unverified** value. It is reported so an
    /// operator can see what the profile claims; it must not be trusted.
    ProofAbsent { mxid: String, did: String },
}

impl fmt::Display for DidAssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidAssertionError::FieldAbsent { mxid } => write!(
                f,
                "no `{DID_PROFILE_FIELD}` field on the Matrix profile of {mxid}: this account has \
                 no provider-published DID (it never signed in through siwx-oidc, the field was \
                 published before this account existed, or the homeserver is withholding custom \
                 profile fields)"
            ),
            DidAssertionError::ProofAbsent { mxid, did } => write!(
                f,
                "the `{DID_PROFILE_FIELD}` field of {mxid} carries did `{did}` but NO `proof`: the \
                 issuer refused to mint one because its signing key is ephemeral (no configured \
                 signing key PEM). The binding is UNVERIFIABLE — treat it as absent, not as a DID \
                 you may act on"
            ),
        }
    }
}

impl std::error::Error for DidAssertionError {}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The two OIDC discovery fields we need. Both are REQUIRED by OpenID Connect
/// Discovery 1.0 §3, so a document missing either is a broken issuer and a
/// deserialization failure is the right, loud answer.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwks {
    #[serde(default)]
    keys: Vec<Jwk>,
}

/// One JWK, every field optional on purpose.
///
/// A JWKS is attacker-adjacent input in the general case, and more importantly
/// a *typed* struct with required fields would collapse "this key has no kid"
/// and "this key has the wrong curve" into one opaque serde error. Optional
/// fields let each check produce its own diagnosable message.
#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// The JWS protected header. Optional fields for the same reason as [`Jwk`]:
/// "no `alg` at all" and "`alg` we refuse" must not share an error message.
#[derive(Deserialize)]
struct JwsHeader {
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct AssertionClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    mxid: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
}

/// The profile-field read: `GET …/profile/{mxid}/io.inblock.did` answers
/// `{"io.inblock.did": <value>}`, echoing the requested field name as the key.
#[derive(Deserialize)]
struct ProfileFieldResponse {
    #[serde(rename = "io.inblock.did", default)]
    field: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a DID assertion and **bind it to the profile it was read from**.
///
/// # Trust model — this is a discovery hint, not authorization
///
/// A successful return proves that `issuer_base_url`'s signing key asserted the
/// `did` ↔ `expected_mxid` binding at `issued_at`. It does **not** prove the
/// holder controls the DID key right now, and it grants nothing. Authorization
/// MUST come from the OIDC `sub` claim of a token this provider issued, or from
/// a fresh signature by the DID key itself. See the module docs for the full
/// statement, including the fact that the source field is world-readable and
/// federates.
///
/// # The mxid binding is the whole security property
///
/// `expected_mxid` is **not** optional, and there is no flag to skip it.
/// Without this comparison, user B copies user A's perfectly valid,
/// correctly-signed proof into B's own profile and it verifies — the signature
/// is genuine, it is simply an assertion about somebody else. That is plan
/// hypothesis H6 (line 137) and it is pinned by
/// `h6_valid_assertion_replayed_for_another_user_is_rejected`. If you are
/// tempted to add `verify_did_assertion_unbound()`, read that test first: the
/// check lives *inside* the helper precisely so it cannot be forgotten by a
/// caller, which is the failure mode a doc-comment warning does not prevent.
///
/// # Order of operations (each step exists to close a specific hole)
///
/// 1. exactly three dot-separated parts;
/// 2. **`alg` is checked before any key is fetched** — `none` and the HMAC
///    family are rejected by name (RFC 8725 §3.1 algorithm confusion: an
///    attacker who can pick the alg turns a *public* verification key into an
///    HMAC secret);
/// 3. discovery → `jwks_uri` → JWKS;
/// 4. the JWK is selected **by `kid`, with no fallback**. "Try every key" would
///    turn a rotated or ephemeral key into a silent bad-signature failure
///    instead of a loud, diagnosable "unknown kid";
/// 5. the verifying key is rebuilt from the JWK's affine `x`/`y`;
/// 6. the signature must be exactly 64 raw bytes (r‖s) and is verified over the
///    ASCII of the *original* first two parts — never over a re-serialization
///    of the decoded JSON, which would let a semantically-equal-but-textually-
///    different payload verify;
/// 7. `iss` must equal the discovery document's `issuer`, trailing slashes
///    normalized away on both sides;
/// 8. `mxid` must equal `expected_mxid`;
/// 9. `sub` becomes [`VerifiedDid::did`].
///
/// # Arguments
///
/// - `issuer_base_url`: base URL of the siwx-oidc server, e.g.
///   `https://siwx.example.com`. Discovery is fetched from
///   `{issuer_base_url}/.well-known/openid-configuration`.
/// - `jws`: the compact JWS from the profile object's `proof` member.
/// - `expected_mxid`: the full Matrix ID (`@localpart:server`) of the profile
///   the proof was read from.
pub async fn verify_did_assertion(
    issuer_base_url: &str,
    jws: &str,
    expected_mxid: &str,
) -> Result<VerifiedDid> {
    // -- 1. Structure ------------------------------------------------------
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!(
            "malformed proof: a compact JWS has exactly 3 dot-separated parts, got {}. \
             (A 5-part value is a JWE, which siwx-oidc never mints.)",
            parts.len()
        );
    }
    let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);

    // The signing input is the ORIGINAL base64 text of the first two parts,
    // joined by '.'. These are borrowed slices of `jws`, so this format! is
    // byte-identical to the bytes that were signed. Never rebuild it by
    // re-encoding the decoded JSON: serde_json would re-order or re-space the
    // members and a genuine proof would fail (or, worse, a crafted one that
    // canonicalizes to the same JSON would pass).
    let signing_input = format!("{header_b64}.{payload_b64}");

    // -- 2. Header, and the alg gate BEFORE any key is touched -------------
    let header_bytes = decode_b64url(header_b64).context(
        "proof header is not valid unpadded base64url (RFC 7515 §2: BASE64URL carries no padding)",
    )?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).context("proof header is not valid JSON")?;

    match header.alg.as_deref() {
        Some("ES256") => {}
        None => bail!(
            "proof header carries no `alg`: RFC 7515 §4.1.1 makes it mandatory, and siwx-oidc \
             always stamps ES256"
        ),
        Some("none") => bail!(
            "proof header declares alg=\"none\": an unsigned JWS is not a proof. Rejected before \
             any key was fetched (RFC 8725 §3.1)"
        ),
        Some(alg) if alg.starts_with("HS") => bail!(
            "proof header declares the symmetric alg `{alg}`, but the issuer's key is an asymmetric \
             P-256 key. This is the classic algorithm-confusion attack — it asks the verifier to \
             use a PUBLIC key as an HMAC secret, which anyone who reads the JWKS also knows. \
             Rejected before any key was fetched (RFC 8725 §3.1)"
        ),
        Some(alg) => bail!(
            "unsupported proof alg `{alg}`: siwx-oidc mints ES256 and this verifier accepts \
             nothing else"
        ),
    }

    // `typ` is a media type, so RFC 7515 §4.1.9 makes the comparison
    // case-insensitive. Absent is fine: `typ` is optional and only advisory.
    if let Some(typ) = header.typ.as_deref() {
        if !typ.eq_ignore_ascii_case("JWT") {
            bail!("proof header declares typ=`{typ}`; expected `JWT` or no `typ` at all");
        }
    }

    // A proof without a `kid` is not ours: the minter always stamps the key
    // fingerprint. Accepting one would force the "try every key" fallback that
    // step 4 exists to forbid.
    let kid = header
        .kid
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "proof header carries no `kid`. siwx-oidc always stamps one (the public-key \
                 fingerprint, `src/oidc.rs:104-110`), so a proof without one was not minted by \
                 this provider"
            )
        })?;

    // -- 3. Discovery ------------------------------------------------------
    let http = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?;

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_base_url.trim_end_matches('/')
    );
    let discovery: Discovery = get_json(&http, &discovery_url)
        .await
        .context("OIDC discovery fetch failed")?;

    // -- 4. JWKS, selected by kid, with NO fallback ------------------------
    let jwks: Jwks = get_json(&http, &discovery.jwks_uri)
        .await
        .with_context(|| format!("JWKS fetch from {} failed", discovery.jwks_uri))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .ok_or_else(|| {
            let offered: Vec<&str> = jwks.keys.iter().filter_map(|k| k.kid.as_deref()).collect();
            // The kid MUST appear in this message: an operator reading it needs
            // to tell "the issuer rotated its key" apart from "this proof is
            // forged", and those look identical without the two kid lists.
            anyhow!(
                "no JWK with kid `{kid}` in the JWKS at {} (it offers: [{}]). The issuer's signing \
                 key has been rotated or was ephemeral and did not survive a restart. This is \
                 deliberately a hard failure: trying every key instead would turn a rotated key \
                 into an indistinguishable \"bad signature\"",
                discovery.jwks_uri,
                offered.join(", ")
            )
        })?;

    // -- 5. Rebuild the verifying key from the JWK -------------------------
    let verifying_key = verifying_key_from_jwk(jwk, kid)?;

    // -- 6. Signature: exactly 64 raw bytes, r||s --------------------------
    let signature_bytes =
        decode_b64url(signature_b64).context("proof signature is not valid unpadded base64url")?;
    if signature_bytes.len() != 64 {
        bail!(
            "proof signature is {} bytes; ES256 is exactly 64 (raw r||s, 32 bytes each). A ~70-byte \
             value is DER, which siwx-oidc never emits (`src/oidc.rs:116-124`)",
            signature_bytes.len()
        );
    }
    let signature = Signature::from_slice(&signature_bytes)
        .context("proof signature is 64 bytes but is not a valid P-256 (r, s) pair")?;

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| {
            anyhow!(
                "proof signature does not verify under the JWKS key `{kid}`: {e}. The payload was \
                 altered, or the proof was signed by a different key"
            )
        })?;

    // -- 7-9. Claims (only now that the bytes are proven authentic) --------
    let payload_bytes =
        decode_b64url(payload_b64).context("proof payload is not valid unpadded base64url")?;
    let claims: AssertionClaims =
        serde_json::from_slice(&payload_bytes).context("proof payload is not valid JSON")?;

    let iss = claims
        .iss
        .ok_or_else(|| anyhow!("proof payload has no `iss` claim"))?;
    if normalize_issuer(&iss) != normalize_issuer(&discovery.issuer) {
        bail!(
            "proof `iss` is `{iss}` but the discovery document at {discovery_url} says the issuer \
             is `{}`. This proof was minted by a different provider",
            discovery.issuer
        );
    }

    let sub = claims
        .sub
        .ok_or_else(|| anyhow!("proof payload has no `sub` claim (the DID)"))?;
    if !sub.starts_with("did:") {
        // Cheap sanity check, not a parser: a consumer indexes on this value,
        // and an empty or non-DID `sub` would be silently stored as an identity.
        bail!("proof `sub` is `{sub}`, which is not a DID (it must start with `did:`)");
    }

    let mxid = claims
        .mxid
        .ok_or_else(|| anyhow!("proof payload has no `mxid` claim, so it binds nothing"))?;

    // -- 8. THE BINDING. Do not remove, do not make optional. --------------
    //
    // Byte-exact comparison, deliberately not case-folded. Our localparts are
    // lowercase base36 by construction, and case-folding here would let a
    // profile at `@Alice:server` satisfy a proof for `@alice:server`.
    if mxid != expected_mxid {
        bail!(
            "REPLAYED ASSERTION: the proof is validly signed but binds `{mxid}`, while it was \
             presented for `{expected_mxid}`. This is exactly the copy-someone-else's-proof attack \
             the `mxid` claim exists to stop; the DID in it belongs to another account"
        );
    }

    let issued_at = claims
        .iat
        .ok_or_else(|| anyhow!("proof payload has no `iat` claim"))?;

    Ok(VerifiedDid {
        did: sub,
        mxid,
        issuer: iss,
        issued_at,
    })
}

/// Fetch `io.inblock.did` from a Matrix homeserver and return the DID **only**
/// if its proof verifies and binds this exact `mxid`.
///
/// # Trust model — this is a discovery hint, not authorization
///
/// Identical to [`verify_did_assertion`]: a successful return proves the
/// provider asserted this DID ↔ mxid binding, not that the holder controls the
/// DID key now, and it authorizes nothing. Authorization MUST come from the
/// OIDC `sub` of a token this provider issued, or from a fresh signature by the
/// DID key itself. The profile field is world-readable and federates
/// (Synapse's profile GET is unauthenticated by default,
/// `config/server.py:561`), so nothing private belongs in it.
///
/// # Why this exists when [`verify_did_assertion`] already does the work
///
/// So the binding cannot be forgotten. This function passes the `mxid` it just
/// fetched *from* as the `expected_mxid` it verifies *against*, which makes the
/// replay check structurally impossible to skip. A caller that hand-rolls
/// "fetch, then verify" can pass the wrong mxid — or a constant — and the
/// mistake is invisible in review. Prefer this entry point.
///
/// # Distinct outcomes
///
/// - field absent → [`DidAssertionError::FieldAbsent`] (downcastable);
/// - field present but `proof` absent → [`DidAssertionError::ProofAbsent`]
///   (downcastable) — the issuer's key was ephemeral, so the binding is
///   unverifiable and must be treated as absent, NOT as a usable DID;
/// - the object's plain `did` disagrees with the verified `sub` → the
///   **verified** value is returned and the disagreement is reported on stderr.
///   The plain member is untrusted decoration for humans and debuggers; only
///   `sub` is covered by the signature.
///
/// # Arguments
///
/// - `homeserver_base_url`: e.g. `https://matrix.example.org` (the client-API
///   host, not the `server_name`).
/// - `mxid`: full Matrix ID, `@localpart:server`.
/// - `issuer_base_url`: base URL of the siwx-oidc server whose JWKS signs the
///   proof.
pub async fn fetch_and_verify_did(
    homeserver_base_url: &str,
    mxid: &str,
    issuer_base_url: &str,
) -> Result<VerifiedDid> {
    let http = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?;

    // Unauthenticated on purpose: the stable v3 profile route is registered
    // unconditionally on Synapse 1.159.0 (`rest/client/profile.py:100-103`) and
    // `require_auth_for_profile_requests` defaults to False, so a bearer token
    // is not required to read a public DID. Sending one would be worse, not
    // better: it would leak the caller's identity to every homeserver polled.
    let url = format!(
        "{}/_matrix/client/v3/profile/{}/{}",
        homeserver_base_url.trim_end_matches('/'),
        urlencoding::encode(mxid),
        DID_PROFILE_FIELD
    );

    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;

    // 404 is the healthy "no such field" answer. Note that a 500 here is NOT
    // simply an error: element-hq/synapse#19702 is still present in 1.159.0 and
    // makes a row-less account (a `users` row with no `profiles` row) 500 where
    // a healthy account 404s. It is surfaced as an error with the body attached
    // rather than silently folded into FieldAbsent, because "state unknown" and
    // "definitely absent" are different answers.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(DidAssertionError::FieldAbsent {
            mxid: mxid.to_string(),
        }
        .into());
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "GET {url} returned {status}: {body}. (A 500 on this route can mean the account has a \
             `users` row but no `profiles` row — element-hq/synapse#19702, unfixed in 1.159.0 — so \
             the field state is UNKNOWN, not absent.)"
        );
    }

    let parsed: ProfileFieldResponse = resp
        .json()
        .await
        .with_context(|| format!("GET {url} did not return the expected JSON object"))?;

    let value = match parsed.field {
        Some(serde_json::Value::Null) | None => {
            return Err(DidAssertionError::FieldAbsent {
                mxid: mxid.to_string(),
            }
            .into())
        }
        Some(v) => v,
    };

    // A bare string is the pre-object legacy shape (and is also what a user
    // could write by hand where the denylist is not yet deployed). It carries
    // no proof by construction, so it lands in the same unverifiable bucket as
    // a proof-less object rather than being trusted.
    let (plain_did, proof) = match &value {
        serde_json::Value::String(s) => (Some(s.clone()), None),
        serde_json::Value::Object(map) => (
            map.get("did")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            map.get("proof")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        ),
        other => bail!(
            "the `{DID_PROFILE_FIELD}` field of {mxid} is neither an object nor a string: {other}"
        ),
    };

    let Some(proof) = proof else {
        return Err(DidAssertionError::ProofAbsent {
            mxid: mxid.to_string(),
            did: plain_did.unwrap_or_default(),
        }
        .into());
    };

    let verified = verify_did_assertion(issuer_base_url, &proof, mxid).await?;

    if let Some(message) = plain_did_disagreement(plain_did.as_deref(), &verified.did) {
        eprintln!("warning: {message}");
    }

    Ok(verified)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Describe a disagreement between the object's plain `did` member and the
/// signed `sub`, or `None` when they agree (or there is no plain member).
///
/// Split out of [`fetch_and_verify_did`] so the wording is unit-testable
/// without capturing stderr. The plain member exists so a human running
/// `curl … | jq` can see the DID; it is NOT covered by the signature, so when
/// the two differ the signed one wins and the plain one must be called
/// untrusted in the message — an operator who reads "mismatch" and then acts on
/// the value printed first has learned the wrong lesson.
fn plain_did_disagreement(plain: Option<&str>, verified: &str) -> Option<String> {
    match plain {
        Some(p) if p != verified => Some(format!(
            "the `{DID_PROFILE_FIELD}` object's plain `did` member is `{p}`, which disagrees with \
             the signed `sub` `{verified}`. The plain member is UNTRUSTED (it is not covered by \
             the proof's signature); the verified value `{verified}` is the one being returned"
        )),
        _ => None,
    }
}

/// Trailing-slash-insensitive issuer comparison.
///
/// The `url` crate renders `http://host:8000` as `http://host:8000/`, so an
/// issuer that passed through a `Url` round-trip on either side gains a slash
/// the other side does not have, and a naive `==` would spuriously reject a
/// perfectly good proof. Only the trailing slash is normalized: scheme, host,
/// port and path are compared verbatim, so `https://a.example` never matches
/// `https://b.example`.
fn normalize_issuer(s: &str) -> &str {
    s.trim_end_matches('/')
}

fn decode_b64url(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow!("base64url decode failed: {e}"))
}

/// Rebuild a P-256 verifying key from a JWK's affine coordinates.
///
/// `kid` is only used to make the errors nameable; it has already been matched
/// by the caller.
fn verifying_key_from_jwk(jwk: &Jwk, kid: &str) -> Result<VerifyingKey> {
    match jwk.kty.as_deref() {
        Some("EC") => {}
        other => bail!(
            "JWK `{kid}` has kty={:?}; ES256 requires an EC key",
            other.unwrap_or("<absent>")
        ),
    }
    match jwk.crv.as_deref() {
        Some("P-256") => {}
        other => bail!(
            "JWK `{kid}` has crv={:?}; ES256 is defined only over P-256 (RFC 7518 §3.4). A key on \
             another curve cannot verify an ES256 signature no matter how the bytes line up",
            other.unwrap_or("<absent>")
        ),
    }

    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| anyhow!("JWK `{kid}` has no `x` coordinate"))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| anyhow!("JWK `{kid}` has no `y` coordinate"))?;

    let x = decode_b64url(x).with_context(|| format!("JWK `{kid}` `x` is not base64url"))?;
    let y = decode_b64url(y).with_context(|| format!("JWK `{kid}` `y` is not base64url"))?;

    // Both coordinates are fixed-width for the curve — RFC 7518 §6.2.1.2
    // requires the full 32-byte octet string, left-padded, NOT a minimal
    // integer encoding. The length check is also what makes the
    // `FieldBytes::from_slice` calls below infallible; those panic on a
    // mismatch, so this `if` must not be "simplified" away.
    if x.len() != 32 || y.len() != 32 {
        bail!(
            "JWK `{kid}` coordinates are {}/{} bytes; P-256 requires exactly 32 each (RFC 7518 \
             §6.2.1.2: fixed-width, left-padded)",
            x.len(),
            y.len()
        );
    }

    let point = EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    VerifyingKey::from_encoded_point(&point)
        .map_err(|e| anyhow!("JWK `{kid}` coordinates are not a point on P-256: {e}"))
}

async fn get_json<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url} failed"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("GET {url} returned {status}: {body}");
    }
    resp.json()
        .await
        .with_context(|| format!("GET {url} did not return the expected JSON"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ALICE: &str = "@alice:example.org";
    const BOB: &str = "@bob:example.org";
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const OTHER_DID: &str = "did:key:zDnaerx9CtbPJ100000000000000000000000000000000000";
    const KID: &str = "3f2a1c0d9e8b7a65";
    const IAT: i64 = 1_757_000_000;

    /// An address nothing listens on, used to PROVE that a check happens before
    /// any network I/O: if the `alg` gate ever moved after the key fetch, the
    /// error would become a connection failure and the assertions below would
    /// fail loudly instead of silently passing for the wrong reason.
    const UNREACHABLE_ISSUER: &str = "http://127.0.0.1:1";

    // -- minting (we sign our own test vectors) ----------------------------
    //
    // These tests deliberately do NOT call the server's minter: it lives in the
    // other crate and is written in parallel to the same spec, so depending on
    // it would let a shared misreading of the spec pass as agreement. Minting
    // straight from the RFC text here means the two implementations meet only
    // on the wire format.

    fn mint(key: &SigningKey, header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{h}.{p}");
        // `to_bytes()` is the raw r||s form the server also emits
        // (`src/oidc.rs:116-124`). A DER encoding here would make every test
        // pass against a verifier we do not ship.
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn header_of(kid: &str) -> serde_json::Value {
        json!({ "alg": "ES256", "typ": "JWT", "kid": kid })
    }

    fn payload_of(iss: &str, sub: &str, mxid: &str) -> serde_json::Value {
        json!({ "iss": iss, "sub": sub, "mxid": mxid, "iat": IAT })
    }

    fn jwk_of(key: &SigningKey, kid: &str) -> serde_json::Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
        })
    }

    // -- the in-process origin server --------------------------------------

    /// A minimal HTTP/1.1 origin server for tests.
    ///
    /// WHY raw sockets: `axum` and `hyper` are NOT dependencies of this crate,
    /// and this task must not add one (a test-only dependency would still enter
    /// the workspace lock graph). A GET-only, no-keep-alive server is ~40 lines
    /// and has no failure modes of its own worth debugging: it reads until the
    /// end of the request head, percent-decodes the path, looks it up in a
    /// table, writes one response with `Connection: close`, and hangs up.
    /// Because every response closes the connection, reqwest opens a fresh one
    /// per request and no pipelining or chunked-body handling is needed.
    ///
    /// `routes` receives the bound base URL, because a discovery document has
    /// to name the very port it is served from and the port is only known after
    /// the bind.
    async fn spawn_mock_http<F>(routes: F) -> String
    where
        F: FnOnce(&str) -> Vec<(String, u16, String)>,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let table: HashMap<String, (u16, String)> = routes(&base)
            .into_iter()
            .map(|(path, status, body)| (path, (status, body)))
            .collect();

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let table = table.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let raw_path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let path = urlencoding::decode(&raw_path)
                        .map(|c| c.into_owned())
                        .unwrap_or(raw_path);
                    let (status, body) = table
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, r#"{"errcode":"M_NOT_FOUND"}"#.to_string()));
                    let reason = match status {
                        200 => "OK",
                        404 => "Not Found",
                        _ => "Status",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        base
    }

    fn discovery_and_jwks(
        base: &str,
        issuer: &str,
        jwks: serde_json::Value,
    ) -> Vec<(String, u16, String)> {
        vec![
            (
                "/.well-known/openid-configuration".to_string(),
                200,
                json!({ "issuer": issuer, "jwks_uri": format!("{base}/jwk") }).to_string(),
            ),
            ("/jwk".to_string(), 200, jwks.to_string()),
        ]
    }

    /// The mock decodes the request path, so routes are registered in decoded
    /// form even though reqwest sends `%40alice%3Aexample.org`.
    fn profile_route(mxid: &str, status: u16, body: String) -> (String, u16, String) {
        (
            format!("/_matrix/client/v3/profile/{mxid}/{DID_PROFILE_FIELD}"),
            status,
            body,
        )
    }

    // -- H8: the round trip -------------------------------------------------

    #[tokio::test]
    async fn h8_mint_serve_and_verify_round_trips() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let verified = verify_did_assertion(&base, &jws, ALICE).await.unwrap();

        assert_eq!(verified.did, DID);
        assert_eq!(verified.mxid, ALICE);
        assert_eq!(verified.issuer, base);
        assert_eq!(verified.issued_at, IAT);
    }

    // -- H6: THE test. Replay across accounts must fail. --------------------

    #[tokio::test]
    async fn h6_valid_assertion_replayed_for_another_user_is_rejected() {
        // Alice's assertion is genuine: minted by the real issuer key, correct
        // `iss`, intact signature. The ONLY thing wrong is that it is being
        // presented as if it described Bob -- which is exactly what happens when
        // user B copies the object out of user A's public profile into their
        // own. If this test ever goes green by returning Ok, the whole feature
        // is worth nothing: any user could claim any other user's DID.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let alice_jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));

        // Sanity: it really is a valid assertion when presented honestly.
        verify_did_assertion(&base, &alice_jws, ALICE)
            .await
            .unwrap();

        let err = verify_did_assertion(&base, &alice_jws, BOB)
            .await
            .expect_err("a valid proof for alice MUST NOT verify for bob");
        let msg = format!("{err:#}");
        assert!(msg.contains(ALICE), "error must name the bound mxid: {msg}");
        assert!(
            msg.contains(BOB),
            "error must name the presented mxid: {msg}"
        );
    }

    // -- H7: the tamper matrix ---------------------------------------------

    #[tokio::test]
    async fn h7_tampered_payload_is_rejected() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let parts: Vec<&str> = jws.split('.').collect();
        let swapped = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload_of(&base, OTHER_DID, ALICE)).unwrap());
        let tampered = format!("{}.{}.{}", parts[0], swapped, parts[2]);

        let err = verify_did_assertion(&base, &tampered, ALICE)
            .await
            .expect_err("a rewritten payload must not verify");
        assert!(
            format!("{err:#}").contains("does not verify"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn h7_truncated_signature_is_rejected() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let parts: Vec<&str> = jws.split('.').collect();
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig.len(), 64, "ES256 must be 64 raw bytes to begin with");
        sig.truncate(63);
        let truncated = format!("{}.{}.{}", parts[0], parts[1], URL_SAFE_NO_PAD.encode(&sig));

        let err = verify_did_assertion(&base, &truncated, ALICE)
            .await
            .expect_err("a 63-byte signature must not verify");
        let msg = format!("{err:#}");
        assert!(msg.contains("63"), "error must state the length: {msg}");
    }

    #[tokio::test]
    async fn h7_alg_none_is_rejected_before_any_key_is_fetched() {
        // Issuer points at a dead port: reaching the network at all would
        // produce a connection error instead of the assertion below, which is
        // how this test proves the alg gate runs FIRST.
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload_of(UNREACHABLE_ISSUER, DID, ALICE)).unwrap());
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"none","typ":"JWT","kid":KID})).unwrap());
        let jws = format!("{header}.{payload}.");

        let err = verify_did_assertion(UNREACHABLE_ISSUER, &jws, ALICE)
            .await
            .expect_err("alg=none must never verify");
        let msg = format!("{err:#}");
        assert!(msg.contains("none"), "error must name the alg: {msg}");
        assert!(
            !msg.contains("GET "),
            "the alg gate must run before any fetch: {msg}"
        );
    }

    #[tokio::test]
    async fn h7_hmac_alg_is_rejected_before_any_key_is_fetched() {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload_of(UNREACHABLE_ISSUER, DID, ALICE)).unwrap());
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"HS256","typ":"JWT","kid":KID})).unwrap());
        // The "signature" an attacker would attach: an HMAC over the signing
        // input keyed with the PUBLIC key. Its content is irrelevant -- the alg
        // must be refused before anything looks at it.
        let jws = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));

        let err = verify_did_assertion(UNREACHABLE_ISSUER, &jws, ALICE)
            .await
            .expect_err("a symmetric alg must never verify against an EC issuer");
        let msg = format!("{err:#}");
        assert!(msg.contains("HS256"), "error must name the alg: {msg}");
        assert!(
            !msg.contains("GET "),
            "the alg gate must run before any fetch: {msg}"
        );
    }

    #[tokio::test]
    async fn h7_unknown_kid_error_names_the_kid() {
        // The JWKS offers a different kid, which is exactly what an operator
        // sees after a key rotation or an ephemeral-key restart. The message
        // must carry both kids or the two causes are indistinguishable.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, "rotated-successor")] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("an unmatched kid must be a hard error, never a try-every-key fallback");
        let msg = format!("{err:#}");
        assert!(msg.contains(KID), "error must name the proof's kid: {msg}");
        assert!(
            msg.contains("rotated-successor"),
            "error must list the kids the JWKS offers: {msg}"
        );
    }

    #[tokio::test]
    async fn h7_jwk_with_wrong_curve_is_rejected() {
        let key = SigningKey::random(&mut OsRng);
        let mut jwk = jwk_of(&key, KID);
        jwk["crv"] = json!("P-384");
        let jwks = json!({ "keys": [jwk] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("ES256 must not be verified against a non-P-256 JWK");
        assert!(
            format!("{err:#}").contains("P-256"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn h7_signature_from_a_different_key_is_rejected() {
        let issuer_key = SigningKey::random(&mut OsRng);
        let attacker_key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&issuer_key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        // Correct kid, correct claims, wrong signer.
        let jws = mint(
            &attacker_key,
            &header_of(KID),
            &payload_of(&base, DID, ALICE),
        );
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("a proof signed by a foreign key must not verify");
        assert!(
            format!("{err:#}").contains("does not verify"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn h7_jwk_with_short_coordinate_is_rejected() {
        // RFC 7518 6.2.1.2 requires the fixed-width, left-padded octet string.
        // A minimal-integer encoding would panic `FieldBytes::from_slice`
        // without the explicit length check in `verifying_key_from_jwk`.
        let key = SigningKey::random(&mut OsRng);
        let mut jwk = jwk_of(&key, KID);
        jwk["x"] = json!(URL_SAFE_NO_PAD.encode([1u8; 31]));
        let jwks = json!({ "keys": [jwk] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("a 31-byte coordinate must be rejected, not panic");
        assert!(
            format!("{err:#}").contains("32"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn header_without_kid_is_rejected() {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload_of(UNREACHABLE_ISSUER, DID, ALICE)).unwrap());
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"ES256","typ":"JWT"})).unwrap());
        let jws = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]));

        let err = verify_did_assertion(UNREACHABLE_ISSUER, &jws, ALICE)
            .await
            .expect_err("a proof with no kid is not one of ours");
        assert!(
            format!("{err:#}").contains("kid"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn jws_without_three_parts_is_rejected() {
        for bad in ["", "a.b", "a.b.c.d", "a.b.c.d.e"] {
            let err = verify_did_assertion(UNREACHABLE_ISSUER, bad, ALICE)
                .await
                .expect_err("only a 3-part compact JWS is acceptable");
            assert!(
                format!("{err:#}").contains("3 dot-separated parts"),
                "unexpected error for {bad:?}: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn typ_must_be_jwt_or_absent() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        // Absent typ: fine.
        let no_typ = mint(
            &key,
            &json!({"alg":"ES256","kid":KID}),
            &payload_of(&base, DID, ALICE),
        );
        verify_did_assertion(&base, &no_typ, ALICE).await.unwrap();

        // Wrong typ: rejected.
        let bad_typ = mint(
            &key,
            &json!({"alg":"ES256","typ":"dpop+jwt","kid":KID}),
            &payload_of(&base, DID, ALICE),
        );
        let err = verify_did_assertion(&base, &bad_typ, ALICE)
            .await
            .expect_err("an unexpected typ must be rejected");
        assert!(
            format!("{err:#}").contains("dpop+jwt"),
            "unexpected error: {err:#}"
        );
    }

    // -- issuer checks ------------------------------------------------------

    #[tokio::test]
    async fn iss_mismatch_is_rejected() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        // Signed with the key the trust anchor actually serves, correct kid,
        // intact signature -- but the payload names a DIFFERENT issuer. That is
        // what a proof minted by another provider (or a copy of one) looks like
        // when it is presented against this anchor's JWKS.
        let jws = mint(
            &key,
            &header_of(KID),
            &payload_of("https://evil.example", DID, ALICE),
        );
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("iss must match the discovery document");
        assert!(
            format!("{err:#}").contains("different provider"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn iss_differing_only_by_a_trailing_slash_is_accepted() {
        // The `url` crate renders `http://host:8000` as `http://host:8000/`, so
        // one side of this comparison routinely grows a slash the other lacks.
        // A naive == here would reject perfectly good proofs in production.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| {
            let with_slash = format!("{b}/");
            discovery_and_jwks(b, &with_slash, jwks)
        })
        .await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, DID, ALICE));
        let verified = verify_did_assertion(&base, &jws, ALICE).await.unwrap();
        assert_eq!(verified.did, DID);
    }

    #[tokio::test]
    async fn sub_that_is_not_a_did_is_rejected() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let jws = mint(&key, &header_of(KID), &payload_of(&base, "alice", ALICE));
        let err = verify_did_assertion(&base, &jws, ALICE)
            .await
            .expect_err("a `sub` that is not a DID must not be handed to a consumer");
        assert!(
            format!("{err:#}").contains("not a DID"),
            "unexpected error: {err:#}"
        );
    }

    // -- fetch_and_verify_did ----------------------------------------------

    #[tokio::test]
    async fn fetch_and_verify_did_happy_path_binds_the_fetched_mxid() {
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });

        let base = spawn_mock_http(move |b| {
            let jws = mint(&key, &header_of(KID), &payload_of(b, DID, ALICE));
            let mut routes = discovery_and_jwks(b, b, jwks);
            routes.push(profile_route(
                ALICE,
                200,
                json!({ DID_PROFILE_FIELD: { "did": DID, "proof": jws } }).to_string(),
            ));
            routes
        })
        .await;

        let verified = fetch_and_verify_did(&base, ALICE, &base).await.unwrap();
        assert_eq!(verified.did, DID);
        assert_eq!(verified.mxid, ALICE);
    }

    #[tokio::test]
    async fn fetch_absent_field_is_a_typed_field_absent_error() {
        // No profile route registered at all -> the mock answers 404, exactly
        // as Synapse does for an account with no such custom field.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| discovery_and_jwks(b, b, jwks)).await;

        let err = fetch_and_verify_did(&base, ALICE, &base)
            .await
            .expect_err("an absent field is not a DID");
        let typed = err
            .downcast_ref::<DidAssertionError>()
            .expect("the absent-field case must be machine-checkable, not a string");
        assert_eq!(
            typed,
            &DidAssertionError::FieldAbsent {
                mxid: ALICE.to_string()
            }
        );
        assert!(
            format!("{err:#}").contains(DID_PROFILE_FIELD),
            "message must name the field: {err:#}"
        );
    }

    #[tokio::test]
    async fn fetch_field_without_proof_is_a_typed_proof_absent_error() {
        // What the server writes when its signing key is ephemeral (plan H5):
        // the `did` member, and NO `proof` key at all. It must be a distinct,
        // downcastable outcome from "no field" -- and it must NOT be a pass.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });
        let base = spawn_mock_http(move |b| {
            let mut routes = discovery_and_jwks(b, b, jwks);
            routes.push(profile_route(
                ALICE,
                200,
                json!({ DID_PROFILE_FIELD: { "did": DID } }).to_string(),
            ));
            routes
        })
        .await;

        let err = fetch_and_verify_did(&base, ALICE, &base)
            .await
            .expect_err("an unproven DID must not be returned as verified");
        let typed = err
            .downcast_ref::<DidAssertionError>()
            .expect("the proof-absent case must be machine-checkable");
        assert_eq!(
            typed,
            &DidAssertionError::ProofAbsent {
                mxid: ALICE.to_string(),
                did: DID.to_string(),
            }
        );
        assert!(
            !matches!(typed, DidAssertionError::FieldAbsent { .. }),
            "proof-absent must be distinguishable from field-absent"
        );
        assert!(
            format!("{err:#}").contains("UNVERIFIABLE"),
            "message must say the binding cannot be trusted: {err:#}"
        );
    }

    #[tokio::test]
    async fn fetch_plain_did_disagreement_returns_the_verified_sub() {
        // The plain `did` member is not covered by the signature, so when the
        // two disagree the signed `sub` is the answer and the plain member is
        // decoration. Returning the plain one would hand a caller a value an
        // attacker could have chosen.
        let key = SigningKey::random(&mut OsRng);
        let jwks = json!({ "keys": [jwk_of(&key, KID)] });

        let base = spawn_mock_http(move |b| {
            let jws = mint(&key, &header_of(KID), &payload_of(b, DID, ALICE));
            let mut routes = discovery_and_jwks(b, b, jwks);
            routes.push(profile_route(
                ALICE,
                200,
                json!({ DID_PROFILE_FIELD: { "did": OTHER_DID, "proof": jws } }).to_string(),
            ));
            routes
        })
        .await;

        let verified = fetch_and_verify_did(&base, ALICE, &base).await.unwrap();
        assert_eq!(
            verified.did, DID,
            "the SIGNED sub must win over the plain member"
        );
        assert_ne!(verified.did, OTHER_DID);
    }

    #[test]
    fn plain_did_disagreement_names_both_and_calls_the_plain_member_untrusted() {
        assert_eq!(plain_did_disagreement(None, DID), None);
        assert_eq!(plain_did_disagreement(Some(DID), DID), None);

        let msg = plain_did_disagreement(Some(OTHER_DID), DID)
            .expect("a disagreement must be surfaced, not swallowed");
        assert!(msg.contains(OTHER_DID), "must name the plain member: {msg}");
        assert!(msg.contains(DID), "must name the verified sub: {msg}");
        assert!(
            msg.contains("UNTRUSTED"),
            "must say which of the two is untrusted, or an operator will act on \
             whichever is printed first: {msg}"
        );
    }

    #[test]
    fn normalize_issuer_only_touches_the_trailing_slash() {
        assert_eq!(
            normalize_issuer("http://host:8000/"),
            normalize_issuer("http://host:8000")
        );
        assert_ne!(
            normalize_issuer("https://a.example"),
            normalize_issuer("https://b.example")
        );
        assert_ne!(
            normalize_issuer("https://host/a"),
            normalize_issuer("https://host/b")
        );
    }

    #[test]
    fn did_profile_field_is_the_wire_contract() {
        // Pinned deliberately: this string is written by the server, protected
        // by a Synapse denylist entry, and read by every consumer. A rename is
        // a migration (dual-read for a full upgrade cycle), never an edit.
        assert_eq!(DID_PROFILE_FIELD, "io.inblock.did");
    }
}
