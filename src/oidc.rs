// Portions of this file are derived from siwe-oidc (https://github.com/spruceid/siwe-oidc),
// Copyright Spruce Systems, Inc. and contributors, used under the Apache License 2.0.
// Modified by inblock.io assets GmbH. See NOTICE.

use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use cookie::{Cookie, SameSite};
use headers::{self, authorization::Bearer};
use openidconnect::{
    core::{
        CoreAuthErrorResponseType, CoreAuthPrompt, CoreClaimName, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeySet,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRegisterErrorResponseType, CoreResponseType, CoreSubjectIdentifierType, CoreTokenType,
    },
    registration::EmptyAdditionalClientRegistrationResponse,
    url::Url,
    AccessToken, AdditionalClaims, Audience, AuthUrl, ClientConfigUrl, ClientId, ClientSecret,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndUserName, EndUserUsername, IdToken,
    IdTokenClaims, IdTokenFields, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, LocalizedClaim, Nonce,
    OpPolicyUrl, OpTosUrl, PrivateSigningKey, RedirectUrl, RefreshToken, RegistrationAccessToken,
    RegistrationUrl, RequestUrl, ResponseTypes, Scope, SigningError, StandardClaims,
    StandardTokenResponse, SubjectIdentifier, TokenUrl, UserInfoClaims, UserInfoJsonWebToken,
    UserInfoUrl,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::time;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use urlencoding::decode;
use uuid::Uuid;

use aqua_auth::find_did_method;
use siwx_oidc::db::grant::{
    EndedGrant, GrantKind, InvalidReason, NewGrant, RefreshPeek, RotateOutcome, RotateRequest,
};
use siwx_oidc::db::*;
use subtle::ConstantTimeEq;

use crate::did_assertion::DidPublication;
use crate::synapse_client::{DeviceUpsert, PublishOutcome, SynapseClient};

/// Constant-time string comparison to prevent timing attacks on secrets.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---------------------------------------------------------------------------
// ES256 signing key (replaces RSA signing, so this provider performs no RSA
// private-key operation — the surface of the RUSTSEC-2023-0071 Marvin attack;
// see security/vex/siwx-oidc.openvex.json)
// ---------------------------------------------------------------------------

lazy_static::lazy_static! {
    static ref SCOPES: Vec<Scope> = vec![
        Scope::new("openid".to_string()),
        Scope::new("profile".to_string()),
        // A refresh token for a generic client is issued only when this was
        // requested and the registration allows the refresh grant (I10).
        Scope::new("offline_access".to_string()),
        // Stable Matrix scopes (MSC2967 graduated)
        Scope::new("urn:matrix:client:api:*".to_string()),
        Scope::new("urn:matrix:client:device:*".to_string()),
        // MSC2967 unstable prefixes (still used by Element X)
        Scope::new("urn:matrix:org.matrix.msc2967.client:api:*".to_string()),
        Scope::new("urn:matrix:org.matrix.msc2967.client:device:*".to_string()),
    ];
}
const SIGNING_ALG: [CoreJwsSigningAlgorithm; 1] = [CoreJwsSigningAlgorithm::EcdsaP256Sha256];
pub const METADATA_PATH: &str = "/.well-known/openid-configuration";
pub const JWK_PATH: &str = "/jwk";
pub const TOKEN_PATH: &str = "/token";
pub const AUTHORIZE_PATH: &str = "/authorize";
pub const REGISTER_PATH: &str = "/register";
pub const CLIENT_PATH: &str = "/client";
pub const USERINFO_PATH: &str = "/userinfo";
pub const SIGNIN_PATH: &str = "/sign_in";
/// OpenID Connect RP-Initiated Logout 1.0 `end_session_endpoint`.
pub const END_SESSION_PATH: &str = "/end_session";
pub const SIWX_COOKIE_KEY: &str = "siwx";
/// RFC 8628 grant type of the device-code grant (`POST /token`).
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The token store. Concrete because the grant record (`siwx_oidc::db::grant`)
/// is implemented on `RedisClient` itself, outside the `DBClient` trait.
type DBClientType = RedisClient;

// -- ES256 key wrapper implementing openidconnect's PrivateSigningKey ------

/// The provider's ES256 signing key, carrying the two facts that anything
/// *durable* signed by it needs to know: **which** key it is (`kid`), and
/// whether it will still exist after the next restart (`ephemeral`).
///
/// # `kid` identifies the KEY, not the slot
///
/// This wrapper used to take a caller-supplied `kid`, and both construction
/// sites in `axum_lib::main` passed the literal `"key1"` — the operator's
/// configured key and the randomly generated fallback were stamped with the
/// SAME identifier. `"key1"` is a *slot* name, not a *key* name, and the
/// distinction stops being cosmetic the moment we sign something that outlives
/// the process.
///
/// DID assertions (`crate::did_assertion`) are written into a user's Synapse
/// profile and stay there indefinitely. Under a constant `kid`, a restart that
/// mints a fresh ephemeral key yields **a different key under the same `kid`**,
/// so every previously stored assertion fails verification as
/// `bad signature` — the single worst diagnostic available, because to a
/// verifier "bad signature" reads as *forgery*, and to an operator it offers
/// nothing to grep for. Deriving `kid` from the public key turns exactly that
/// event into `kid "3f2a…" is not present in the JWKS`: honest, self-describing,
/// and immediately actionable ("the key rotated; set SIWEOIDC_SIGNING_KEY_PEM").
///
/// This is hypothesis H4 of the attested-DID design ("`kid` must identify the
/// key, not the slot"), pinned by
/// `oidc::tests::h4_two_generated_keys_get_different_kids` and
/// `oidc::tests::h4_the_same_pem_yields_the_same_kid_across_constructions`.
///
/// **Do not reintroduce a caller-supplied `kid`.** The constructors deliberately
/// accept no `kid` argument, so a slot name cannot be stamped onto a key again;
/// that absence IS the fix. Likewise, do not "simplify" `kid` back to an
/// `Option<JsonWebKeyId>`: a JWKS entry without a `kid` forces every verifier to
/// trial-verify against every key, which erases the unknown-kid diagnostic this
/// type exists to produce.
#[derive(Clone)]
pub struct EcdsaSigningKey {
    key: SigningKey,
    /// Always present and always derived from `key` — never configured.
    /// See the type-level doc.
    kid: JsonWebKeyId,
    /// `true` when the key was generated at startup and therefore dies with the
    /// process. Read by `did_assertion::mint_did_assertion`, which refuses to
    /// mint a durable, off-server artifact with a key it knows is temporary.
    ephemeral: bool,
}

impl EcdsaSigningKey {
    /// Load the operator's durable key (`SIWEOIDC_SIGNING_KEY_PEM`).
    ///
    /// The resulting key is marked NON-ephemeral, which is what unlocks DID
    /// assertion minting. That marking is a claim about *operator intent*
    /// (a PEM was configured, so the same key is expected across restarts), not
    /// a proof — nothing here can verify the operator will keep passing the same
    /// PEM. The key-derived `kid` is the safety net for when they do not.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("Invalid ECDSA private key PEM: {}", e))?;
        Ok(Self::with_derived_kid(key, false))
    }

    /// Generate a throwaway key for a deployment with no configured PEM.
    ///
    /// Marked ephemeral: tokens signed by it stop verifying at the next restart
    /// (which is merely annoying — clients re-authenticate), and DID assertions
    /// are suppressed entirely (which is the point — see `did_assertion`).
    pub fn generate() -> Self {
        Self::with_derived_kid(SigningKey::random(&mut rand::thread_rng()), true)
    }

    /// The single place a `kid` is computed. Both constructors funnel through
    /// here precisely so the "derive it, never accept it" rule cannot be
    /// violated by adding a third constructor that forgets.
    fn with_derived_kid(key: SigningKey, ephemeral: bool) -> Self {
        let kid = JsonWebKeyId::new(Self::fingerprint_of(&key));
        Self {
            key,
            kid,
            ephemeral,
        }
    }

    /// First 16 hex chars of SHA-256 over the SEC1 **uncompressed** public key.
    ///
    /// 64 bits of a cryptographic hash: not collision-resistant in the
    /// adversarial sense, and it does not need to be. `kid` is a *lookup hint*
    /// into a JWKS this provider publishes — a collision would only ever pick
    /// the wrong key of our own, and the signature check then fails. It is not a
    /// security boundary; the signature is.
    fn fingerprint_of(key: &SigningKey) -> String {
        fingerprint_of_public(key.verifying_key())
    }

    /// Non-sensitive identifier for the signing key: the first 16 hex chars of a
    /// SHA-256 over the SEC1-encoded *public* key. Safe to log — it reveals no
    /// private material but lets operators correlate which ephemeral key is live.
    ///
    /// Identical by construction to `kid()`; kept as a distinct name because the
    /// startup log lines read as "fingerprint" and the JWS header reads as
    /// "kid", and conflating the two names in either place would obscure one of
    /// them.
    pub fn public_key_fingerprint(&self) -> String {
        Self::fingerprint_of(&self.key)
    }

    /// The `kid` published in the JWKS and stamped into every JWS header this
    /// key produces. Derived from the public key; see the type-level doc.
    pub fn kid(&self) -> &str {
        self.kid.as_str()
    }

    /// `true` when this key was generated at startup and will not survive the
    /// process.
    ///
    /// The one caller that matters is `did_assertion::mint_did_assertion`:
    /// writing a durable assertion into a user's Synapse profile with a key we
    /// KNOW is about to disappear is writing garbage into someone else's
    /// database. Invariant 5 of the plan: never write a durable assertion with
    /// an ephemeral key.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Raw ES256 signature over `message`: **r‖s, exactly 64 bytes, never DER**.
    ///
    /// RFC 7515 §3.1 / RFC 7518 §3.4 mandate the fixed-width concatenation; the
    /// `ecdsa` crate's `Signature::to_bytes()` is already that encoding, while
    /// its `to_der()` is the 70–72 byte X.509 form that every JWS verifier
    /// rejects. Do not "helpfully" switch to DER: the failure is silent at mint
    /// time and only surfaces as an unverifiable proof in a stranger's profile.
    /// `did_assertion::tests::signature_is_64_raw_bytes_never_der` asserts the
    /// length explicitly for exactly this reason.
    pub fn sign_es256(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().to_vec()
    }
}

impl PrivateSigningKey for EcdsaSigningKey {
    type VerificationKey = CoreJsonWebKey;

    fn sign(
        &self,
        _signature_alg: &<CoreJsonWebKey as openidconnect::JsonWebKey>::SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningError> {
        // JWS ES256 requires the raw r||s encoding (64 bytes), not DER.
        // Delegated so the ID-token path and the DID-assertion path can never
        // drift onto different signature encodings.
        Ok(self.sign_es256(message))
    }

    fn as_verification_key(&self) -> CoreJsonWebKey {
        verification_jwk(self.key.verifying_key(), self.kid.as_str())
    }
}

/// The `kid` for a P-256 **public** key: first 16 hex chars of SHA-256 over the
/// SEC1 uncompressed encoding.
///
/// Split out of `EcdsaSigningKey::fingerprint_of` (which now delegates here) so
/// that a RETIRED key — of which we hold only the public half — derives a `kid`
/// **byte-identically** to the one it had while it was live. That identity is
/// the entire mechanism: a durably-stored DID assertion carries the `kid` its
/// signer had at mint time, and a verifier resolves it against the JWKS by that
/// string. Two derivations that agree "in principle" but differ in one byte
/// would leave every retired proof unverifiable while looking correct. Do not
/// give the retired path its own copy of this.
fn fingerprint_of_public(key: &p256::ecdsa::VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let pubkey = key.to_encoded_point(false);
    let digest = Sha256::digest(pubkey.as_bytes());
    let hex = hex::encode(digest);
    hex[..16].to_string()
}

/// The one place a published verification JWK is constructed, for the live key
/// and for retired keys alike.
///
/// Single-sourced for the same reason as [`fingerprint_of_public`]: a retired
/// key must be indistinguishable, to a verifier, from what the live key
/// published before rotation. `use`/`alg`/`crv` all matter to a strict verifier.
fn verification_jwk(verifying_key: &p256::ecdsa::VerifyingKey, kid: &str) -> CoreJsonWebKey {
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let mut jwk_value = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
    });
    // Always present: a JWKS entry with no `kid` forces verifiers to
    // trial-verify against every published key, which destroys the
    // "unknown kid" diagnostic that the key-derived `kid` exists to give
    // (see the `EcdsaSigningKey` doc, H4). It also stops mattering as a
    // nicety the moment more than one key is published, which is exactly
    // what retired keys do.
    jwk_value["kid"] = serde_json::Value::String(kid.to_string());
    serde_json::from_value(jwk_value).expect("Failed to construct EC JWK")
}

// -- ID tokens ---------------------------------------------------------------

/// The claims this provider adds to an ID token: the session id of the grant
/// the token was issued with (I8; OpenID Connect Front-/Back-Channel Logout
/// and RP-Initiated Logout name a session by it). Omitted, never `null`, when
/// a grant has none (a `service` grant never comes with an ID token).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SidClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

impl AdditionalClaims for SidClaims {}

/// The ID token claim set: the OIDC Core claims plus [`SidClaims`].
pub type SiwxIdTokenClaims = IdTokenClaims<SidClaims, CoreGenderClaim>;
/// A signed ID token of [`SiwxIdTokenClaims`].
pub type SiwxIdToken =
    IdToken<SidClaims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;
/// The token response fields carrying a [`SiwxIdToken`].
pub type SiwxIdTokenFields = IdTokenFields<
    SidClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
/// `POST /token`'s response: `CoreTokenResponse` with [`SidClaims`] in the ID
/// token. The JSON shape is unchanged apart from the `sid` claim inside it.
pub type SiwxTokenResponse = StandardTokenResponse<SiwxIdTokenFields, CoreTokenType>;

// -- Error types -----------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct TokenError {
    pub error: CoreErrorResponseType,
    pub error_description: String,
}

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0:?}")]
    BadRequestRegister(RegisterError),
    #[error("{0:?}")]
    BadRequestToken(TokenError),
    #[error("{0}")]
    Unauthorized(String),
    /// A presented passkey credential is not registered on this server (a stale or
    /// revoked key chosen from the platform picker). Renders as HTTP 401 with a
    /// machine-readable JSON discriminator so the client can prune it via
    /// `signalUnknownCredential`. Carries the base64url credential id. This is an
    /// EXPECTED user condition, not an internal error: it is logged as
    /// `unknown_credential`, never `internal_error`.
    #[error("unknown_credential: {0}")]
    UnknownCredential(String),
    #[error("Not found")]
    NotFound,
    #[error("{0:?}")]
    Redirect(String),
    /// A dependency this request could not proceed without — Synapse — was
    /// unreachable or refused our credentials, so a check that must not be
    /// skipped could not be completed. Renders as **503**.
    ///
    /// # Why not a 4xx, and why not a 500
    ///
    /// Not a 4xx: the caller did nothing wrong, and a 4xx tells them to change a
    /// request that was already correct. That is not a cosmetic distinction —
    /// the first user of this variant
    /// ([`crate::webauthn::reject_if_new_identity`]) spent its 400 telling a
    /// legitimate user to create an account they may well already have, and the
    /// second ([`crate::webauthn::reject_if_deactivated`]) spent its **401**
    /// telling every user on an unhealthy homeserver that their account had been
    /// deactivated. Both were safe and both were false.
    ///
    /// Not [`CustomError::Other`]'s 500 either: this is a KNOWN, classified,
    /// handled, fail-closed condition, and the flows that raise it are
    /// documented to degrade rather than 500. A 500 would claim an unhandled
    /// internal error and would put a diagnosed fault in the same bucket as an
    /// undiagnosed one, which is precisely the signal an operator needs kept
    /// separate.
    ///
    /// 503 is the honest answer — server-side, transient, retryable — and it is
    /// the one that stays legible in a proxy access log, where nobody is reading
    /// the message body.
    ///
    /// The payload is the USER-FACING message only. The underlying cause is
    /// logged at the point of failure and must never be put on the wire.
    #[error("{0}")]
    ServiceUnavailable(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<crate::webauthn::VerifyError> for CustomError {
    fn from(e: crate::webauthn::VerifyError) -> Self {
        match e {
            // The single typed case: surface it so handlers return a structured 401.
            crate::webauthn::VerifyError::UnknownCredential(cred_id) => {
                CustomError::UnknownCredential(cred_id)
            }
            // Every other verification failure keeps its existing 500/Other behavior.
            crate::webauthn::VerifyError::Other(inner) => CustomError::Other(inner),
        }
    }
}

// -- JWK / metadata helpers ------------------------------------------------

/// PEM armour of the only key form [`parse_retired_verification_keys`] accepts.
const PUBLIC_PEM_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PUBLIC_PEM_END: &str = "-----END PUBLIC KEY-----";

/// Parse `SIWEOIDC_RETIRED_SIGNING_KEYS_PEM` into verification JWKs.
///
/// # Why retired keys have to stay published at all (2026-09-10 audit, D2)
///
/// A DID assertion is written into a user's Synapse profile **durably and with
/// no `exp`** — deliberately, because the DID↔mxid binding it attests is
/// permanent (see [`crate::did_assertion`]). But its only verification anchor
/// is this provider's JWKS, and until now that JWKS contained exactly one key:
/// the live one. So rotating `SIWEOIDC_SIGNING_KEY_PEM` did not merely
/// invalidate sessions (which is fine — clients re-authenticate); it made every
/// proof ever written **permanently unverifiable** for anyone who does not sign
/// in again to have it re-asserted. The key-derived `kid` makes that state
/// diagnosable ("unknown kid" rather than "bad signature") but not recoverable.
///
/// This is not hypothetical: dev's signing key was exposed on 2026-09-09, and
/// rotation is the correct response to an exposure. The point of this config is
/// that responding correctly to an incident must not also destroy the evidence
/// trail every consumer relies on.
///
/// # PUBLIC keys only — and this REJECTS a private PEM on purpose
///
/// A retired key needs to *verify*, never to *sign*; signing always uses the
/// live key alone (see [`jwks`]). Accepting the private form would therefore
/// grant a capability nothing needs, and — the decisive argument — the
/// motivating case is a key that was **compromised**. The lazy path for an
/// operator holding a compromised private PEM is to paste it straight into the
/// retired list, where it would live on indefinitely in the process
/// environment, where a bare `printenv` in the container prints it whole
/// (multiline PEM values included). A config that
/// makes "keep the compromised secret around forever" the path of least
/// resistance is a bad config. So a private PEM is a hard error with the
/// one-line fix in the message:
///
/// ```text
/// openssl pkey -in old-signing-key.pem -pubout
/// ```
///
/// # Format
///
/// One or more SPKI `-----BEGIN PUBLIC KEY-----` blocks concatenated, in any
/// order, with arbitrary text between them (so a comment naming each retired
/// key and the date it was retired is fine, and encouraged). Each must be a
/// P-256 key, because ES256 is the only algorithm this provider has ever
/// signed with.
///
/// # Fails LOUD
///
/// Any unparseable input is an `Err`, and the caller ([`crate::axum_lib`])
/// turns it into a startup panic. Skipping a bad entry with a `warn!` would
/// produce a server that boots fine and silently cannot verify the exact
/// artifacts this feature exists to keep verifiable — the failure would surface
/// months later, in someone else's consumer, as an unexplained "unknown kid".
pub fn parse_retired_verification_keys(pem_bundle: &str) -> Result<Vec<CoreJsonWebKey>> {
    use p256::pkcs8::DecodePublicKey;

    if pem_bundle.contains("PRIVATE KEY") {
        return Err(anyhow!(
            "SIWXOIDC_RETIRED_SIGNING_KEYS_PEM contains a PRIVATE key. Retired keys are published for VERIFICATION only and must be the public half — a retired key never signs anything, and keeping a rotated-out (often compromised) private key in the process environment is exactly the exposure that motivates rotation. Convert it with: openssl pkey -in <old-key>.pem -pubout"
        ));
    }

    let mut keys = Vec::new();
    let mut rest = pem_bundle;
    while let Some(begin) = rest.find(PUBLIC_PEM_BEGIN) {
        let after_begin = &rest[begin..];
        let end = after_begin.find(PUBLIC_PEM_END).ok_or_else(|| {
            anyhow!(
                "SIWXOIDC_RETIRED_SIGNING_KEYS_PEM has a '{PUBLIC_PEM_BEGIN}' with no matching '{PUBLIC_PEM_END}' — the PEM block is truncated"
            )
        })? + PUBLIC_PEM_END.len();
        let block = &after_begin[..end];

        let public_key = p256::PublicKey::from_public_key_pem(block).map_err(|e| {
            anyhow!(
                "SIWXOIDC_RETIRED_SIGNING_KEYS_PEM entry {} is not a valid P-256 SPKI public key: {e}. ES256 is the only algorithm this provider has ever signed with, so a retired key of any other curve could not have produced a proof to verify.",
                keys.len() + 1
            )
        })?;
        let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);
        let kid = fingerprint_of_public(&verifying_key);
        keys.push(verification_jwk(&verifying_key, &kid));

        rest = &after_begin[end..];
    }

    if keys.is_empty() {
        return Err(anyhow!(
            "SIWXOIDC_RETIRED_SIGNING_KEYS_PEM is set but contains no '{PUBLIC_PEM_BEGIN}' block. Unset it, or supply the public half of each retired signing key (openssl pkey -in <old-key>.pem -pubout)."
        ));
    }
    Ok(keys)
}

/// The published JWKS: the LIVE signing key first, then any retired
/// verification keys.
///
/// # Signing is unaffected
///
/// `retired` are JWKs — public material with no signing capability by
/// construction. There is no code path by which a retired key can sign
/// anything; the live [`EcdsaSigningKey`] is the only thing
/// [`PrivateSigningKey`] is implemented for. Publishing a key is *permission to
/// verify*, never permission to issue.
///
/// # Order and de-duplication
///
/// The live key is first so a verifier that (wrongly) trial-verifies in
/// document order hits the common case immediately. Entries are de-duplicated
/// by `kid`, which makes the operationally likely mistake harmless: an operator
/// rotating keys naturally appends the OLD key to the retired list and, at some
/// point, forgets to remove one — or leaves the still-live key in it. A JWKS
/// with the same `kid` twice is legal but invites a verifier to pick the first
/// match and stop, so collapsing them is strictly better than publishing both.
///
/// # This does NOT make rotation free
///
/// Retired keys keep OLD proofs verifiable. They do nothing for a key that was
/// compromised *before* it was retired: an attacker holding the private half
/// can mint assertions that verify against the retired JWK exactly as well as
/// genuine ones. Retiring a compromised key is therefore a trade — recoverable
/// history against a live forgery window — and the reason [`crate::did_assertion`]
/// stamps `iat`. If a key is known to have been abused, DROP it from this list
/// and accept that its proofs die; re-assertion happens on the next sign-in.
/// Do not document this feature as "rotation is now safe".
pub fn jwks(
    signing_key: &EcdsaSigningKey,
    retired: &[CoreJsonWebKey],
) -> Result<CoreJsonWebKeySet, CustomError> {
    use openidconnect::JsonWebKey;

    let live = signing_key.as_verification_key();
    let live_kid = live.key_id().map(|k| k.as_str().to_string());
    let mut seen: Vec<String> = live_kid.into_iter().collect();
    let mut keys = vec![live];

    for jwk in retired {
        let kid = jwk.key_id().map(|k| k.as_str().to_string());
        match kid {
            // A retired JWK always has a derived kid (verification_jwk sets it
            // unconditionally); the `None` arm exists only because the JWK type
            // permits it, and is kept rather than published so a hand-built
            // key-id-less entry cannot silently defeat the de-duplication.
            Some(kid) if !seen.contains(&kid) => {
                seen.push(kid);
                keys.push(jwk.clone());
            }
            Some(_) => {}
            None => keys.push(jwk.clone()),
        }
    }

    Ok(CoreJsonWebKeySet::new(keys))
}

pub fn metadata(config: &crate::config::Config) -> Result<CoreProviderMetadata, CustomError> {
    let base_url = &config.base_url;
    let pm = CoreProviderMetadata::new(
        IssuerUrl::from_url(base_url.clone()),
        AuthUrl::from_url(
            base_url
                .join(AUTHORIZE_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        JsonWebKeySetUrl::from_url(
            base_url
                .join(JWK_PATH)
                .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
        ),
        // Exactly what `authorize` accepts: the authorization-code flow.
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        // The `sub` is the user's DID, the same for every client
        // (docs/identity-model.md), which is what `public` means.
        vec![CoreSubjectIdentifierType::Public],
        SIGNING_ALG.to_vec(),
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::from_url(
        base_url
            .join(TOKEN_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_endpoint(Some(UserInfoUrl::from_url(
        base_url
            .join(USERINFO_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_userinfo_signing_alg_values_supported(Some(SIGNING_ALG.to_vec()))
    .set_scopes_supported(Some(SCOPES.clone()))
    .set_claims_supported(Some(vec![
        CoreClaimName::new("sub".to_string()),
        CoreClaimName::new("aud".to_string()),
        CoreClaimName::new("exp".to_string()),
        CoreClaimName::new("iat".to_string()),
        CoreClaimName::new("iss".to_string()),
        CoreClaimName::new("preferred_username".to_string()),
        CoreClaimName::new("name".to_string()),
        CoreClaimName::new("picture".to_string()),
    ]))
    .set_registration_endpoint(Some(RegistrationUrl::from_url(
        base_url
            .join(REGISTER_PATH)
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_token_endpoint_auth_methods_supported(Some(vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
    ]))
    // Only what the operator configured. The terms and privacy policy are the
    // deployment's own documents, so there is no default to fall back to, and
    // an unset key omits the field (openidconnect skips `None`).
    .set_op_policy_uri(config.op_policy_uri.clone().map(OpPolicyUrl::from_url))
    .set_op_tos_uri(config.op_tos_uri.clone().map(OpTosUrl::from_url));

    Ok(pm)
}

// -- Shared bits of the server-rendered pages (/account, /device) ----------

/// Escape a value for an HTML text node or a double-quoted attribute.
fn escape_html(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The `<title>` of a server-rendered page: `{title} · {issuer host}`, or
/// `title` alone when the base URL has no host. Never a fixed brand: the page
/// belongs to whoever runs this deployment.
pub fn page_title(title: &str, base_url: &str) -> String {
    match Url::parse(base_url).ok().as_ref().and_then(Url::host_str) {
        Some(host) => escape_html(&format!("{title} · {host}")),
        None => escape_html(title),
    }
}

/// The legal footer of the server-rendered pages, linking exactly the terms
/// and privacy policy the operator configured (`op_tos_uri`, `op_policy_uri`,
/// the values discovery advertises). Empty when neither is set: a deployment
/// must not point its users at documents it did not write. The login page
/// (`js/ui/src/App.svelte`) builds the same footer from discovery.
pub fn legal_footer_html(tos: Option<&Url>, policy: Option<&Url>) -> String {
    let links: Vec<String> = [(tos, "Terms of Use"), (policy, "Privacy Policy")]
        .into_iter()
        .filter_map(|(url, label)| {
            url.map(|u| format!(r#"<a href="{}">{label}</a>"#, escape_html(u.as_str())))
        })
        .collect();
    if links.is_empty() {
        return String::new();
    }
    format!(
        r#"<div class="footer">
        <p>By continuing you agree to the
          {}.
        </p>
      </div>"#,
        links.join(" and\n          ")
    )
}

/// Whether this deployment runs in delegated-auth mode: a MAS shared secret is
/// configured, so Synapse can delegate authentication to this provider.
///
/// Token introspection and the RFC 8628 device-code grant work only in this
/// mode: `introspect::introspect` answers 404 without the secret, and both
/// `/device_authorization` and [`token_device_code`] refuse the grant with
/// [`device_grant_unsupported`]. Discovery reads the same predicate
/// ([`provider_metadata_value`]), so it never advertises an endpoint or grant
/// this deployment would refuse.
pub fn delegated_auth_enabled(config: &crate::config::Config) -> bool {
    config.mas_shared_secret.is_some()
}

/// The refusal of the RFC 8628 device-code grant outside delegated-auth mode:
/// a 400 with an RFC 6749 §5.2 body, `unsupported_grant_type`, which RFC 8628
/// §3.2 prescribes for `/device_authorization` errors as well. One value for
/// both endpoints, so a client sees the same answer at either.
pub fn device_grant_unsupported() -> CustomError {
    CustomError::BadRequestToken(TokenError {
        error: CoreErrorResponseType::UnsupportedGrantType,
        error_description: "device_code grant requires MSC3861 mode.".to_string(),
    })
}

/// Build the full OIDC provider-metadata document served at [`METADATA_PATH`],
/// including the non-standard Matrix/MSC extensions that the `openidconnect`
/// crate cannot represent natively (introspection, device authorization,
/// revocation, prompt values, and MSC4191 account management).
///
/// It advertises only what this deployment serves. Introspection and the
/// device-code grant (with its `device_authorization_endpoint`) appear only in
/// delegated-auth mode ([`delegated_auth_enabled`]). `matrix_ready` says a
/// Synapse client AND a Matrix server name are configured; without both,
/// `GET /resolve` answers 503 and every account action a 400, so neither
/// `io.inblock.resolve_endpoint` nor MSC4191 account management is advertised.
///
/// `config.account_management_uri` is the MSC4191 account-management URL; when
/// `None` it defaults to `{base_url}/account`. The advertised
/// `account_management_actions_supported` list is sourced from
/// [`crate::account::SUPPORTED_ACTIONS`] so discovery and dispatch never drift.
pub fn provider_metadata_value(
    config: &crate::config::Config,
    matrix_ready: bool,
) -> Result<serde_json::Value, CustomError> {
    let base_url = &config.base_url;
    let pm = metadata(config)?;
    let mut value =
        serde_json::to_value(pm).map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
    let base = base_url.as_str().trim_end_matches('/');
    value["code_challenge_methods_supported"] = serde_json::json!(["S256"]);
    // matrix-js-sdk v42 (Element Web >= 1.12.24) `isValidAuthMetadata` hard-
    // requires BOTH modes here, else it silently falls back to legacy SSO
    // (404 under MSC3861). Only advertised because /sign_in honors fragment —
    // advertising without honoring would be strictly worse for v42 clients.
    value["response_modes_supported"] = serde_json::json!(["query", "fragment"]);
    let mut grant_types = vec!["authorization_code", "refresh_token"];
    // A standalone deployment would answer these with a 404 (introspection) or
    // `unsupported_grant_type` (the device-code poll), after the user had
    // already approved the device. Not advertising them is the honest answer.
    if delegated_auth_enabled(config) {
        value["introspection_endpoint"] = serde_json::json!(format!("{}/oauth2/introspect", base));
        value["introspection_endpoint_auth_methods_supported"] =
            serde_json::json!(["client_secret_post", "bearer"]);
        grant_types.push(DEVICE_CODE_GRANT_TYPE);
        value["device_authorization_endpoint"] =
            serde_json::json!(format!("{}/device_authorization", base));
    }
    value["grant_types_supported"] = serde_json::json!(grant_types);
    value["revocation_endpoint"] = serde_json::json!(format!("{}/oauth2/revoke", base));
    // RP-initiated logout ends the grant an ID token's `sid` names, in both modes.
    value["end_session_endpoint"] = serde_json::json!(format!("{base}{END_SESSION_PATH}"));
    // Back-channel logout is sent for `oidc` grants only, and only generic mode
    // issues them: in Matrix mode every grant is a Matrix device grant.
    if !delegated_auth_enabled(config) {
        value["backchannel_logout_supported"] = serde_json::json!(true);
        value["backchannel_logout_session_supported"] = serde_json::json!(true);
    }
    value["token_endpoint_auth_methods_supported"] =
        serde_json::json!(["client_secret_basic", "client_secret_post", "none"]);
    value["prompt_values_supported"] = serde_json::json!(["login", "create"]);
    // Both advertised ONLY when this deployment can answer them: a client that
    // finds a key will use it, and a route that answers 503 (`/resolve`) or an
    // account page whose every action answers 400 turns discovery into a
    // guaranteed failed request.
    if matrix_ready {
        // MSC4191: account management discovery (stable v1.18).
        let account_uri = config
            .account_management_uri
            .as_ref()
            .map(|u| u.as_str().to_string())
            .unwrap_or_else(|| format!("{}/account", base));
        value["account_management_uri"] = serde_json::json!(account_uri);
        value["account_management_actions_supported"] =
            serde_json::json!(crate::account::SUPPORTED_ACTIONS);
        value[RESOLVE_ENDPOINT_METADATA_KEY] = serde_json::json!(format!("{}/resolve", base));
    }
    Ok(value)
}

/// The provider-metadata key advertising `GET /resolve` (see `resolve.rs`).
///
/// # Why in the OIDC discovery document
///
/// A client that wants to resolve a DID on some homeserver needs to find THAT
/// homeserver's resolver, and the one document every OAuth-aware Matrix client
/// already fetches for a homeserver is `/_matrix/client/v1/auth_metadata` —
/// which Synapse (MAS-mode delegation) serves by forwarding this document with
/// unknown keys intact (`synapse/api/auth/mas.py::ServerMetadata`,
/// `extra="allow"`; `account_management_uri` reaches clients the same way,
/// verified live). So advertising it here needs no Synapse, well-known or
/// Caddy change, and it works for any homeserver delegating auth to a
/// siwx-oidc that sets this, including a federated peer's.
///
/// RFC 8414 §2 permits additional metadata parameters; the reverse-DNS name
/// keeps it out of any registered namespace. It is a DISCOVERY HINT like the
/// endpoint it names: a consumer still verifies the account it is pointed at
/// (the published `io.inblock.did` field), and nothing is authorized by it.
///
/// Contract: the Element Web `resolve-did-search` patch reads this exact key.
pub const RESOLVE_ENDPOINT_METADATA_KEY: &str = "io.inblock.resolve_endpoint";

// -- ENS resolution -------------------------------------------------------
//
// Opt-in: with neither eth_provider nor ens_api_url configured (the default)
// no lookup happens and no address leaves the server.
//
// Order: when eth_provider is set, the on-chain legacy ENS registry is asked
// first (classic reverse records only; no NameWrapper). The HTTP API
// (ens_api_url, e.g. api.ensdata.net; handles CCIP Read / NameWrapper /
// offchain names server-side) is used when there is no eth_provider or the
// on-chain lookup finds nothing.

/// Resolve ENS primary name via HTTP API.
/// API must accept GET /{address} and return JSON with `ens_primary` field.
async fn resolve_name_http(api_url: &Url, address_string: &str) -> Option<String> {
    let url = format!(
        "{}/{}",
        api_url.as_str().trim_end_matches('/'),
        address_string
    );
    let client = reqwest::Client::new();
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(name) = json.get("ens_primary").and_then(|v| v.as_str()) {
                    if !name.is_empty() {
                        info!("ENS resolved (HTTP API): {} -> {}", address_string, name);
                        return Some(name.to_string());
                    }
                }
            }
            None
        }
        Ok(resp) => {
            debug!(
                "ENS API returned status {} for {}",
                resp.status(),
                address_string
            );
            None
        }
        Err(e) => {
            debug!("ENS API request failed for {}: {}", address_string, e);
            None
        }
    }
}

/// Resolve ENS primary name via on-chain legacy ENS registry.
async fn resolve_name_onchain(eth_provider: &Url, address: &Address) -> Option<String> {
    use alloy::ens::ProviderEnsExt;
    let provider = alloy::providers::ProviderBuilder::new().connect_http(eth_provider.clone());
    match provider.lookup_address(address).await {
        Ok(n) => {
            info!("ENS resolved (on-chain): {} -> {}", address, n);
            Some(n)
        }
        Err(e) => {
            debug!("ENS on-chain lookup failed for {}: {}", address, e);
            None
        }
    }
}

async fn resolve_name(
    ens_api_url: Option<&Url>,
    eth_provider: Option<&Url>,
    address: &Address,
) -> Option<String> {
    let address_string = address.to_checksum(None);

    // eth_provider overrides: use on-chain ENS registry directly.
    if let Some(provider) = eth_provider {
        if let Some(name) = resolve_name_onchain(provider, address).await {
            return Some(name);
        }
    }

    // HTTP API, when configured (handles CCIP Read / NameWrapper / offchain names).
    if let Some(api_url) = ens_api_url {
        if let Some(name) = resolve_name_http(api_url, &address_string).await {
            return Some(name);
        }
    }

    None
}

async fn resolve_claims(
    config: &crate::config::Config,
    did: &str,
) -> StandardClaims<CoreGenderClaim> {
    // canonical_subject is the OIDC sub claim — full DID string for did:pkh.
    let subject = find_did_method(did)
        .and_then(|m| m.canonical_subject(did).ok())
        .unwrap_or_else(|| did.to_string());

    // address_for_message is used for ENS resolution input.
    let address_str = find_did_method(did)
        .and_then(|m| m.address_for_message(did).ok())
        .unwrap_or_else(|| did.to_string());

    // ENS resolution only for eip155 DIDs.
    let ens_name = if did.starts_with("did:pkh:eip155:") {
        if let Ok(addr) = address_str.parse::<Address>() {
            resolve_name(
                config.ens_api_url.as_ref(),
                config.eth_provider.as_ref(),
                &addr,
            )
            .await
        } else {
            None
        }
    } else {
        None
    };

    // preferred_username is ALWAYS the full DID (the Matrix localpart travels in
    // introspection's `username`, never here). name is the ENS name when
    // available (an OIDC claim only; the Matrix displayname is the alias seeded
    // at first sign-in).
    let mut claims = StandardClaims::new(SubjectIdentifier::new(subject))
        .set_preferred_username(Some(EndUserUsername::new(did.to_string())));
    if let Some(name) = ens_name {
        let mut m = LocalizedClaim::new();
        m.insert(None, EndUserName::new(name));
        claims = claims.set_name(Some(m));
    }
    claims
}

// -- Token endpoint --------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct TokenForm {
    pub code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: CoreGrantType,
    /// PKCE code verifier (required if code_challenge was sent in /authorize).
    pub code_verifier: Option<String>,
    /// Refresh token (required when grant_type=refresh_token).
    pub refresh_token: Option<String>,
    /// Device code (required when grant_type=device_code).
    pub device_code: Option<String>,
}

/// What the HTTP request says about the calling client outside the form: the
/// `Authorization` header, which carries a client secret as `Basic` (with the
/// client id as the user name, RFC 6749 §2.3.1) or, for some clients, as `Bearer`.
#[derive(Default)]
pub struct ClientCredentials {
    /// The user name of an `Authorization: Basic` header: the client id.
    pub basic_client_id: Option<String>,
    /// The secret from the `Authorization` header (the Basic password or the
    /// Bearer token). It wins over `client_secret` in the form.
    pub secret: Option<String>,
}

pub async fn token(
    form: TokenForm,
    credentials: ClientCredentials,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
) -> Result<SiwxTokenResponse, CustomError> {
    match form.grant_type {
        CoreGrantType::AuthorizationCode => {
            token_authorization_code(form, credentials, signing_key, config, db_client).await
        }
        CoreGrantType::RefreshToken => {
            token_refresh(form, credentials, config, db_client).await
        }
        CoreGrantType::DeviceCode => {
            token_device_code(form, signing_key, config, db_client, synapse_client).await
        }
        _ => Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::UnsupportedGrantType,
            error_description: "Supported grant_types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:device_code."
                .to_string(),
        })),
    }
}

/// The client a request names, from the form and from an HTTP Basic header.
/// They name the same client or only one of them is present: a request that
/// names two different clients is malformed (RFC 6749 §2.3 allows one
/// authentication method per request).
fn named_client_id(
    form: &TokenForm,
    credentials: &ClientCredentials,
) -> Result<Option<String>, CustomError> {
    match (
        form.client_id.as_deref(),
        credentials.basic_client_id.as_deref(),
    ) {
        (Some(in_form), Some(in_header)) if !constant_time_eq(in_form, in_header) => {
            Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidRequest,
                error_description:
                    "client_id differs between the request body and the Authorization header."
                        .to_string(),
            }))
        }
        (Some(client_id), _) | (None, Some(client_id)) => Ok(Some(client_id.to_string())),
        (None, None) => Ok(None),
    }
}

// Client authentication at `POST /token`, for the two grants bound to a client:
// the authorization code (`authenticate_code_client`, strict) and the refresh
// token (`authenticate_refresh_client`, which tolerates a registration that has
// expired). Both apply the same three steps through the same helpers, so they
// cannot drift:
//
// 1. The client the request names (`named_client_id`, form or Basic header)
//    must be the client the grant was issued to: `invalid_grant` otherwise. A
//    request that names none is fine here (`check_named_client`).
// 2. A secret the request presents is checked against the registration
//    (`invalid_client`: "Bad secret."), whether the client is confidential or
//    not (`check_client_secret`).
// 3. A request that presents none must come from a public client
//    (`invalid_client`: "Secret required."); which clients are confidential is
//    decided in one place, `client_is_confidential`, which also sets the flag a
//    grant records at issuance for the endpoint that cannot authenticate a
//    client (`POST /_matrix/client/v3/refresh`).

/// Step 1: the client the request names, if any, is the grant's client.
/// `credential` names the grant in the error text.
fn check_named_client(
    bound_client_id: &str,
    named_client_id: Option<&str>,
    credential: &str,
) -> Result<(), CustomError> {
    match named_client_id {
        Some(named) if !bound_client_id.is_empty() && !constant_time_eq(named, bound_client_id) => {
            Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: format!("client_id does not match the {credential}."),
            }))
        }
        _ => Ok(()),
    }
}

/// Steps 2 and 3 against the client's registration: a presented secret must
/// match it, and a request without one must come from a public client.
fn check_client_secret(
    client_entry: &ClientEntry,
    presented_secret: Option<&str>,
    config: &crate::config::Config,
) -> Result<(), CustomError> {
    match presented_secret {
        Some(secret) if !client_entry.secret_matches(secret) => {
            Err(CustomError::Unauthorized("Bad secret.".to_string()))
        }
        Some(_) => Ok(()),
        None if client_is_confidential(Some(client_entry), config.require_secret) => {
            Err(CustomError::Unauthorized("Secret required.".to_string()))
        }
        None => Ok(()),
    }
}

/// Authenticate the client of an authorization code: the three steps above,
/// and the registration must exist (a code was issued minutes ago to a
/// registered client, so its absence is a fault: `invalid_client`). Returns
/// the registration.
async fn authenticate_code_client(
    bound_client_id: &str,
    named_client_id: Option<&str>,
    presented_secret: Option<&str>,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<ClientEntry, CustomError> {
    check_named_client(bound_client_id, named_client_id, "authorization code")?;
    let client_entry = db_client
        .get_client(bound_client_id.to_string())
        .await?
        .ok_or_else(|| CustomError::Unauthorized("Unrecognised client id.".to_string()))?;
    check_client_secret(&client_entry, presented_secret, config)?;
    Ok(client_entry)
}

/// Authenticate the client of a refresh token: the three steps above, except
/// that a registration that is gone is tolerated when the request presents no
/// secret. A refresh token outlives its client's registration (30 days against
/// 90), and refusing every such token would sign out every session older than a
/// registration. Nothing is lost against the status quo: a secret cannot be
/// checked against a registration that is gone, and a request that presents
/// one is still refused (`invalid_client`).
///
/// This runs before the rotation script, as RFC 6749 orders it (client
/// authentication first, §3.2.1 and §6). A consequence, kept on purpose: a
/// superseded refresh token presented with a wrong secret is answered
/// `invalid_client`, not like an unknown token. Telling the two apart needs a
/// real token of the grant and reveals nothing about the token's state.
async fn authenticate_refresh_client(
    bound_client_id: &str,
    named_client_id: Option<&str>,
    presented_secret: Option<&str>,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    check_named_client(bound_client_id, named_client_id, "refresh token")?;
    match db_client.get_client(bound_client_id.to_string()).await? {
        Some(client_entry) => check_client_secret(&client_entry, presented_secret, config),
        None if presented_secret.is_none() => Ok(()),
        None => Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        )),
    }
}

/// Whether a client must authenticate with a secret: a registered
/// `token_endpoint_auth_method` other than `none`, or none registered while
/// `require_secret`. A client with no registration counts as public. The one
/// rule behind step 3 above and behind the `confidential` flag a grant records
/// at issuance, so `POST /_matrix/client/v3/refresh`, which cannot
/// authenticate a client, refuses exactly the grants whose client
/// `POST /token` would ask for a secret.
pub(crate) fn client_is_confidential(client: Option<&ClientEntry>, require_secret: bool) -> bool {
    match client.map(|c| c.metadata.token_endpoint_auth_method()) {
        None => false,
        Some(Some(CoreClientAuthMethod::None)) => false,
        Some(Some(_)) => true,
        Some(None) => require_secret,
    }
}

async fn token_refresh(
    form: TokenForm,
    credentials: ClientCredentials,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<SiwxTokenResponse, CustomError> {
    let named_client = named_client_id(&form, &credentials)?;
    let presented_secret = credentials.secret.or(form.client_secret);
    let rt = form.refresh_token.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "refresh_token parameter is required.".to_string(),
        })
    })?;

    // What the token names: the grant its handle names (or that a legacy token
    // was lifted into), or a legacy refresh token (`token/{raw}`, written
    // before the grant record) not lifted yet. An access or admin token,
    // garbage, and a token of a grant that is gone are all answered exactly
    // like an unknown token.
    let (bound_client, legacy) = match db_client.peek_refresh_token(&rt).await? {
        RefreshPeek::Grant(grant) => (grant.client_id, None),
        RefreshPeek::Legacy(legacy) => (legacy.meta.client_id.clone(), Some(legacy)),
        RefreshPeek::Unknown => return Err(unknown_refresh_token()),
    };

    // A refresh token belongs to the client it was issued to (I7): before the
    // rotation script runs, the request must be that client, and a
    // confidential client must authenticate. `POST /_matrix/client/v3/refresh`
    // carries no client identity, so it refuses a confidential client's grant
    // instead (`compat::refresh`).
    authenticate_refresh_client(
        &bound_client,
        named_client.as_deref(),
        presented_secret.as_deref(),
        config,
        db_client,
    )
    .await?;

    // The one rotation script (I3) decides everything else atomically: rotate,
    // replay the unused successor of a lost response (I4), or refuse. The
    // script checks the named client again; it can only agree here. A legacy
    // refresh token is lifted into a grant instead (design 5.8): answered with
    // a pair in the current format, so no user signs in again; its grant
    // records the client's confidentiality by the rule every issuance uses.
    let request = RotateRequest {
        presented: &rt,
        client_id: named_client.as_deref(),
        refuse_confidential: false,
    };
    let outcome = match &legacy {
        Some(legacy) => {
            let client = db_client.get_client(legacy.meta.client_id.clone()).await?;
            let confidential = client_is_confidential(client.as_ref(), config.require_secret);
            db_client
                .lift_legacy_refresh_token(&request, legacy, confidential)
                .await?
        }
        None => db_client.rotate_refresh_token(&request).await?,
    };
    let (pair, expires_in) = match outcome {
        RotateOutcome::Rotated(pair) | RotateOutcome::Replayed(pair) => {
            let expires_in = pair.expires_in(ACCESS_TOKEN_TTL);
            (pair.pair, expires_in)
        }
        // Reuse (I5, phase A): recorded, and answered like an unknown token.
        RotateOutcome::Reuse(event) => {
            event.emit();
            return Err(unknown_refresh_token());
        }
        RotateOutcome::Invalid(InvalidReason::Revoked) => {
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "Session has been revoked.".to_string(),
            }));
        }
        RotateOutcome::Invalid(_) | RotateOutcome::ConfidentialClient => {
            return Err(unknown_refresh_token());
        }
        // The same answer `check_named_client` gives a request that names
        // another client.
        RotateOutcome::ClientMismatch => {
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "client_id does not match the refresh token.".to_string(),
            }));
        }
    };

    let mut response = SiwxTokenResponse::new(
        AccessToken::new(pair.access_token),
        CoreTokenType::Bearer,
        SiwxIdTokenFields::new(None, EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(expires_in)));
    response.set_refresh_token(Some(RefreshToken::new(pair.refresh_token)));
    Ok(response)
}

/// The answer to a refresh token that is unknown, expired, of another kind, or
/// reused: one answer, so a refusal reveals nothing about which it was.
fn unknown_refresh_token() -> CustomError {
    CustomError::BadRequestToken(TokenError {
        error: CoreErrorResponseType::InvalidGrant,
        error_description: "Unknown or expired refresh token.".to_string(),
    })
}

fn device_code_error(error: &str, description: &str) -> CustomError {
    CustomError::BadRequestToken(TokenError {
        error: CoreErrorResponseType::Extension(error.to_string()),
        error_description: description.to_string(),
    })
}

async fn token_device_code(
    form: TokenForm,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
) -> Result<SiwxTokenResponse, CustomError> {
    if !delegated_auth_enabled(config) {
        return Err(device_grant_unsupported());
    }

    let dc = form.device_code.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "device_code parameter is required.".to_string(),
        })
    })?;
    let client_id = form.client_id.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "client_id parameter is required.".to_string(),
        })
    })?;

    let (device_ref, mut entry) = db_client
        .get_device_code(&dc)
        .await?
        .ok_or_else(|| device_code_error("expired_token", "Device code expired or not found."))?;

    if entry.client_id != client_id {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "client_id mismatch.".to_string(),
        }));
    }

    // Rate limiting: reject if polling faster than the interval.
    let now_ts = Utc::now().timestamp();
    if let Some(last) = entry.last_poll {
        if now_ts - last < DEVICE_CODE_INTERVAL as i64 {
            entry.last_poll = Some(now_ts);
            let _ = db_client
                .update_device_code(&device_ref, &entry, DEVICE_CODE_LIFETIME)
                .await;
            return Err(device_code_error(
                "slow_down",
                "Polling too fast. Increase interval.",
            ));
        }
    }
    entry.last_poll = Some(now_ts);
    let _ = db_client
        .update_device_code(&device_ref, &entry, DEVICE_CODE_LIFETIME)
        .await;

    match entry.status {
        DeviceCodeStatus::Pending => Err(device_code_error(
            "authorization_pending",
            "User has not yet approved.",
        )),
        DeviceCodeStatus::Denied => {
            let _ = db_client.delete_device_code(&device_ref).await;
            let _ = db_client.delete_user_code_mapping(&entry).await;
            Err(device_code_error(
                "access_denied",
                "User denied the request.",
            ))
        }
        DeviceCodeStatus::Approved => {
            // Atomically claim this approved device_code BEFORE issuing any token
            // (S3-1 / H9). Without this, two concurrent polls both pass the
            // `status == Approved` check and each mint a token pair (+ a phantom
            // device). The SETNX-style claim ensures exactly one poll issues
            // tokens; concurrent losers fall back to authorization_pending (the
            // winner deletes the device_code at the end, so a subsequent poll then
            // gets expired_token — same as a normal completed flow).
            if !db_client.try_claim_device_code(&dc).await? {
                debug!(device_code_fp = %siwx_oidc::redact::fingerprint(&dc), "device_code already claimed by a concurrent poll");
                return Err(device_code_error(
                    "authorization_pending",
                    "Device code is being processed.",
                ));
            }

            let did = entry
                .did
                .as_ref()
                .ok_or_else(|| device_code_error("server_error", "Approved but no DID."))?
                .clone();

            let proposed_device_id = extract_device_id_from_scope(&entry.scope);
            debug!(
                scope = %entry.scope,
                extracted_device_id = ?proposed_device_id,
                "device_code grant: scope extraction"
            );

            match proposed_device_id {
                Some(ref proposed) => {
                    info!(proposed_device_id = %proposed, "using client-proposed device_id from scope")
                }
                None => warn!(
                    scope = %entry.scope,
                    "no device_id found in scope, generating one"
                ),
            }

            // Resolve ONCE (grandfathering decision) and reuse it for both
            // provisioning and TokenMetadata.username, exactly like sign_in.
            // Best-effort: a Synapse hiccup degrades to the legacy localpart
            // (never modern — see resolve_identity_or_legacy's fail-safe
            // direction), matching the pre-existing degraded-provisioning path.
            let resolved = crate::localpart::resolve_identity_or_legacy(&did, synapse_client).await;
            // Same DID publication as the wallet/passkey login path: the QR
            // flow provisions a real session for a real identity, so it must
            // publish (and re-assert) the same attested field. Both call sites
            // route through the ONE `provision_synapse_device`, so there is no
            // third place this could be forgotten.
            let publication = DidPublication {
                key: signing_key,
                issuer: config.base_url.as_str(),
            };
            // Named after the client that started the grant, like sign_in.
            // The name is cosmetic, so a failed client read falls back to the
            // client id instead of failing a grant the user already approved.
            let client = db_client
                .get_client(client_id.clone())
                .await
                .unwrap_or_else(|e| {
                    warn!(error = %e, "device_code grant: client read failed; naming the device after its client id");
                    None
                });
            let device_name = device_display_name(&client_id, client.as_ref());
            // The client's proposal goes in as is, so provisioning mints the id
            // when there is none and can tell a minted id (new, so it is named)
            // from a client-supplied one (maybe renamed by the user, so named
            // only when confirmed new). Without a Synapse client nothing is
            // provisioned and the id is minted here, for the token scope alone.
            let dev_id = provision_synapse_device(
                &did,
                &resolved,
                synapse_client,
                &device_name,
                proposed_device_id.as_deref(),
                config.matrix_server_name.as_deref(),
                Some(&publication),
            )
            .await
            .unwrap_or_else(|| resolve_device_id(proposed_device_id.as_deref()));

            let now = Utc::now();
            let username = resolved.localpart;
            let scope = format!(
                "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
                dev_id
            );

            let claims = resolve_claims(config, &did).await;
            let display_name = claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string())
                .unwrap_or_else(|| did.clone());

            // One Matrix-device grant per approved device code (I2).
            let client_entry = db_client.get_client(client_id.clone()).await?;
            let issued = db_client
                .issue_grant(&NewGrant {
                    kind: GrantKind::MatrixDevice,
                    username,
                    did: did.clone(),
                    client_id: client_id.clone(),
                    confidential_client: client_is_confidential(
                        client_entry.as_ref(),
                        config.require_secret,
                    ),
                    device_id: dev_id.clone(),
                    scope: scope.clone(),
                    name: display_name,
                    // The approval, recorded from Redis `TIME`; an entry an
                    // older build approved counts from this poll.
                    auth_ms: entry.auth_ms,
                    access_ttl: ACCESS_TOKEN_TTL,
                    refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
                })
                .await?;
            let access_token = issued.access_token;
            let refresh_token = issued.refresh_token.ok_or_else(|| {
                anyhow!("device_code grant: issue_grant returned no refresh token")
            })?;

            let core_id_token = SiwxIdTokenClaims::new(
                IssuerUrl::from_url(config.base_url.clone()),
                vec![Audience::new(client_id)],
                now + Duration::seconds(config.id_token_ttl_secs as i64),
                now,
                claims,
                SidClaims { sid: issued.sid },
            );

            let id_token = SiwxIdToken::new(
                core_id_token,
                signing_key,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                Some(&AccessToken::new(access_token.clone())),
                None,
            )
            .map_err(|e| anyhow!("{}", e))?;

            // Cleanup
            let _ = db_client.delete_device_code(&device_ref).await;
            let _ = db_client.delete_user_code_mapping(&entry).await;

            info!(did = %did, device_id = %dev_id, "device_code grant: tokens issued");

            let mut response = SiwxTokenResponse::new(
                AccessToken::new(access_token),
                CoreTokenType::Bearer,
                SiwxIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
            );
            response.set_expires_in(Some(&time::Duration::from_secs(ACCESS_TOKEN_TTL)));
            response.set_refresh_token(Some(RefreshToken::new(refresh_token)));
            response.set_scopes(Some(
                scope
                    .split_whitespace()
                    .map(|s| Scope::new(s.to_string()))
                    .collect(),
            ));
            Ok(response)
        }
    }
}

/// The scopes generic mode can grant, in the order they are issued.
const GENERIC_GRANTABLE_SCOPES: [&str; 3] = ["openid", "profile", "offline_access"];

/// What a generic-mode code exchange issues for the scope the authorization
/// request asked for.
#[derive(Debug, PartialEq, Eq)]
struct GenericGrant {
    /// The scope recorded on the tokens: the requested scopes among
    /// [`GENERIC_GRANTABLE_SCOPES`] that the registration allows, in that order.
    scope: String,
    /// Whether a refresh token is issued.
    refresh_token: bool,
    /// Whether the token response must name the scope, because it differs from
    /// the request (RFC 6749 §5.1).
    report_scope: bool,
}

/// The grant for a generic-mode (no MAS shared secret) code exchange (I10):
/// least privilege for a relying party that is not a Matrix client.
///
/// - The scope granted is what was requested, limited to `openid`, `profile`
///   and `offline_access`. Matrix scopes mean nothing here and are not granted.
///   If nothing grantable was requested the grant is `openid`: the exchange
///   issues an ID token regardless, so that is what is being granted
///   (provisional).
/// - `offline_access`, and with it a refresh token, is granted only when the
///   client's registration allows the refresh grant. A registration that lists
///   no `grant_types` is not a restriction (provisional): refusing it would
///   withhold refresh tokens from clients that registered before this rule
///   existed and never listed any.
/// - `requested == None` is a code written by a build from before the scope
///   travelled with it. Such a code lives 300 s, and for that window it is
///   exchanged as it always was: `openid profile` and a refresh token.
fn generic_grant(requested: Option<&str>, registration: &ClientEntry) -> GenericGrant {
    let Some(requested) = requested else {
        return GenericGrant {
            scope: "openid profile".to_string(),
            refresh_token: true,
            report_scope: false,
        };
    };
    let asked: Vec<&str> = requested.split_whitespace().collect();
    let may_refresh = registration_may_refresh(&registration.metadata);
    let granted: Vec<&str> = GENERIC_GRANTABLE_SCOPES
        .iter()
        .copied()
        .filter(|scope| asked.contains(scope))
        .filter(|scope| *scope != "offline_access" || may_refresh)
        .collect();
    let refresh_token = granted.contains(&"offline_access");
    let scope = if granted.is_empty() {
        "openid".to_string()
    } else {
        granted.join(" ")
    };
    let report_scope = {
        let mut requested_set = asked.clone();
        requested_set.sort_unstable();
        requested_set.dedup();
        let mut granted_set: Vec<&str> = scope.split(' ').collect();
        granted_set.sort_unstable();
        requested_set != granted_set
    };
    GenericGrant {
        scope,
        refresh_token,
        report_scope,
    }
}

async fn token_authorization_code(
    form: TokenForm,
    credentials: ClientCredentials,
    signing_key: &EcdsaSigningKey,
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<SiwxTokenResponse, CustomError> {
    // A malformed request is refused before the code is touched.
    let named_client = named_client_id(&form, &credentials)?;
    let presented_secret = credentials.secret.or(form.client_secret);
    let code = form.code.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidRequest,
            error_description: "code parameter is required.".to_string(),
        })
    })?;

    let code_entry = db_client.try_consume_code(code).await?.ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "Unknown or already-exchanged code.".to_string(),
        })
    })?;

    // Bind the code to the client it was issued to, and authenticate that
    // client, through the helpers the refresh grant uses too. A correct client
    // presents the same `client_id` at /authorize and /token; a code carries its
    // client_id (always set by `sign_in`), and the rest of the function runs
    // against the code's client, never the request's. This stops a leaked
    // confidential client's code from being redeemed by a different (public)
    // client.
    let client_id = if !code_entry.client_id.is_empty() {
        code_entry.client_id.clone()
    } else {
        named_client.clone().unwrap_or_default()
    };
    let client_entry = authenticate_code_client(
        &client_id,
        named_client.as_deref(),
        presented_secret.as_deref(),
        config,
        db_client,
    )
    .await?;

    // PKCE: every code carries the challenge `/authorize` bound to its session,
    // and the verifier must match it. A code without a challenge (only an older
    // build wrote those) is refused.
    let challenge = code_entry.code_challenge.as_ref().ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description:
                "This authorization code carries no PKCE challenge; restart the sign-in."
                    .to_string(),
        })
    })?;
    let verifier = form.code_verifier.as_ref().ok_or_else(|| {
        CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "code_verifier required (PKCE).".to_string(),
        })
    })?;
    let method = code_entry
        .code_challenge_method
        .as_deref()
        .unwrap_or("S256");
    // C2 Step 4b: reject the `plain` PKCE method. Discovery advertises S256
    // only (`code_challenge_methods_supported = ["S256"]`); no compliant
    // client sends `plain`, and the downgrade weakens the PKCE binding.
    let computed = match method {
        "S256" => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        }
        _ => {
            return Err(CustomError::BadRequestToken(TokenError {
                error: CoreErrorResponseType::InvalidGrant,
                error_description: "Unsupported code_challenge_method (only S256 is allowed)."
                    .to_string(),
            }));
        }
    };
    if !constant_time_eq(&computed, challenge) {
        return Err(CustomError::BadRequestToken(TokenError {
            error: CoreErrorResponseType::InvalidGrant,
            error_description: "code_verifier mismatch.".to_string(),
        }));
    }

    let msc3861_mode = config.mas_shared_secret.is_some();

    let now = Utc::now();
    // This request is DIFFERENT from the sign_in that provisioned the account,
    // so the resolved localpart travels via `CodeEntry.localpart` (set at
    // sign_in) rather than being recomputed here. `None` means the entry was
    // written by a pre-migration build with no such field — every account
    // that predates this field is, by definition, a legacy account, so
    // `legacy_localpart` is the correct (not merely best-effort) fallback.
    let username = code_entry
        .localpart
        .clone()
        .unwrap_or_else(|| crate::localpart::legacy_localpart(&code_entry.did));
    let claims = resolve_claims(config, &code_entry.did).await;
    let display_name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .unwrap_or_else(|| code_entry.did.clone());

    // Matrix mode records the Matrix scope for the device and always issues a
    // refresh token, whatever was requested: Synapse, Element Web and Element X
    // depend on exactly that. Generic mode grants what was requested and
    // allowed, and issues a refresh token only for `offline_access` (I10).
    let (kind, scope, issue_refresh_token, report_scope) = if msc3861_mode {
        let device_id = code_entry.device_id.clone().unwrap_or_default();
        (
            GrantKind::MatrixDevice,
            format!(
                "openid urn:matrix:client:api:* urn:matrix:client:device:{}",
                device_id
            ),
            true,
            false,
        )
    } else {
        let grant = generic_grant(code_entry.scope.as_deref(), &client_entry);
        (
            GrantKind::Oidc,
            grant.scope,
            grant.refresh_token,
            grant.report_scope,
        )
    };

    // One grant per code exchange (I2): its first access token, its refresh
    // token when one is issued, and its index entries, written in one step.
    let issued = db_client
        .issue_grant(&NewGrant {
            kind,
            username,
            did: code_entry.did.clone(),
            client_id: client_id.clone(),
            confidential_client: client_is_confidential(Some(&client_entry), config.require_secret),
            device_id: code_entry.device_id.clone().unwrap_or_default(),
            scope: scope.clone(),
            name: display_name,
            auth_ms: Some(code_entry.auth_time.timestamp_millis()),
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_inactivity_secs: issue_refresh_token.then_some(REFRESH_TOKEN_TTL),
        })
        .await?;
    let refresh_token = issued.refresh_token.map(RefreshToken::new);
    let access_token = AccessToken::new(issued.access_token);

    let core_id_token = SiwxIdTokenClaims::new(
        IssuerUrl::from_url(config.base_url.clone()),
        vec![Audience::new(client_id.clone())],
        now + Duration::seconds(config.id_token_ttl_secs as i64),
        now,
        claims,
        SidClaims { sid: issued.sid },
    )
    .set_nonce(code_entry.nonce)
    .set_auth_time(Some(code_entry.auth_time));

    let id_token = SiwxIdToken::new(
        core_id_token,
        signing_key,
        CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        Some(&access_token),
        None,
    )
    .map_err(|e| anyhow!("{}", e))?;

    let expires_in_secs = ACCESS_TOKEN_TTL;

    let mut response = SiwxTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        SiwxIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&time::Duration::from_secs(expires_in_secs)));
    response.set_refresh_token(refresh_token);
    // RFC 6749 §5.1: the response says the granted scope when it differs from
    // the request. Only generic mode can differ; Matrix mode never put one here.
    if report_scope {
        response.set_scopes(Some(
            scope
                .split_whitespace()
                .map(|s| Scope::new(s.to_string()))
                .collect(),
        ));
    }
    Ok(response)
}

// -- Authorize endpoint ----------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: RedirectUrl,
    pub scope: Scope,
    pub response_type: Option<CoreResponseType>,
    pub state: Option<String>,
    pub nonce: Option<Nonce>,
    pub prompt: Option<CoreAuthPrompt>,
    pub request_uri: Option<RequestUrl>,
    pub request: Option<String>,
    /// PKCE code_challenge.
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method. Only "S256" is accepted; "plain" is
    /// rejected at /authorize.
    pub code_challenge_method: Option<String>,
    /// OAuth response_mode ("query" or "fragment"). matrix-js-sdk v42
    /// (Element Web >= 1.12.24) sends `fragment` and reads the authorization
    /// response ONLY from the URL fragment.
    pub response_mode: Option<String>,
}

pub async fn authorize(
    params: AuthorizeParams,
    db_client: &DBClientType,
) -> Result<(String, Box<Cookie<'_>>), CustomError> {
    let client_entry = db_client
        .get_client(params.client_id.clone())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?;

    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let Some(client_entry) = client_entry else {
        return Err(CustomError::Unauthorized(
            "Unrecognised client id.".to_string(),
        ));
    };
    if !redirect_uri_is_registered(&client_entry, &params.redirect_uri) {
        return Err(CustomError::Redirect(
            "/error?message=unregistered_redirect_uri".to_string(),
        ));
    }

    let state = if let Some(s) = params.state.clone() {
        s
    } else if params.request_uri.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestUriNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else if params.request.is_some() {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::RequestNotSupported.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    } else {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing state");
        return Err(CustomError::Redirect(url.to_string()));
    };

    if let Some(CoreAuthPrompt::None) = params.prompt {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::InteractionRequired.as_ref(),
        );
        return Err(CustomError::Redirect(url.to_string()));
    }

    let Some(response_type) = params.response_type.as_ref() else {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut()
            .append_pair("error", CoreAuthErrorResponseType::InvalidRequest.as_ref());
        url.query_pairs_mut()
            .append_pair("error_description", "Missing response_type");
        return Err(CustomError::Redirect(url.to_string()));
    };
    // Only the authorization-code flow is implemented, and discovery advertises
    // only `code`. Any other response type goes back to the (validated)
    // redirect URI as `unsupported_response_type` (RFC 6749 §4.1.2.1), and no
    // login session is started.
    if !matches!(response_type, CoreResponseType::Code) {
        let mut url = params.redirect_uri.url().clone();
        url.query_pairs_mut().append_pair("state", &state);
        url.query_pairs_mut().append_pair(
            "error",
            CoreAuthErrorResponseType::UnsupportedResponseType.as_ref(),
        );
        url.query_pairs_mut()
            .append_pair("error_description", "Only response_type=code is supported.");
        return Err(CustomError::Redirect(url.to_string()));
    }

    let scope_str = params.scope.as_str().trim();
    let scopes: Vec<&str> = scope_str.split(' ').filter(|s| !s.is_empty()).collect();
    let has_openid = scopes.contains(&"openid");
    let has_matrix_scope = scopes.iter().any(|s| s.starts_with("urn:matrix:"));
    if !has_openid && !has_matrix_scope {
        return Err(
            anyhow!("The 'openid' scope or a Matrix scope (urn:matrix:*) is required.").into(),
        );
    }

    // Validate response_mode strictly (invalid_request semantics): discovery
    // advertises exactly {"query","fragment"}, so anything else is a 400 rather
    // than a silently-ignored param the client then waits on.
    if let Some(rm) = &params.response_mode {
        if rm != "query" && rm != "fragment" {
            return Err(CustomError::BadRequest(format!(
                "Unsupported response_mode '{rm}' (only 'query' and 'fragment' are supported)."
            )));
        }
    }
    // C2 Step 4b: reject `code_challenge_method=plain` up front. Discovery
    // advertises S256 only. A missing method defaults to S256.
    if let Some(ccm) = &params.code_challenge_method {
        if ccm != "S256" {
            return Err(CustomError::BadRequest(
                "Unsupported code_challenge_method (only S256 is allowed).".to_string(),
            ));
        }
    }
    // C2 Step 4a: require S256 PKCE on every authorization request (the code
    // flow is the only one). PKCE binds a redeemed code to the client that
    // started the request. Every real client already sends S256 (Element X per
    // the Matrix OAuth 2.0 profile, the in-house `siwx-oidc-auth` lib, and all
    // e2e flows). Scope: ALL clients — every registered `ClientEntry` carries a
    // server-issued secret regardless of `token_endpoint_auth_method`, so there
    // is no client class that legitimately omits PKCE to exempt. The
    // device-code grant (RFC 8628) does NOT pass through /authorize.
    let Some(code_challenge) = params.code_challenge.clone() else {
        return Err(CustomError::BadRequest(
            "code_challenge is required (S256 PKCE) for the authorization-code flow.".to_string(),
        ));
    };

    // Bind the request validated above to the login session. `sign_in` issues
    // the code for exactly this request (client, redirect URI, state, response
    // mode, PKCE challenge) and never for parameters it receives on the front
    // channel, which may repeat it but not change it.
    let session_id = Uuid::new_v4();
    let session_secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    db_client
        .set_session(
            session_id.to_string(),
            SessionEntry {
                siwe_nonce: nonce.clone(),
                secret: session_secret.clone(),
                signin_count: 0,
                verified_did: None,
                request: Some(AuthorizationRequest {
                    client_id: params.client_id.clone(),
                    redirect_uri: params.redirect_uri.as_str().to_string(),
                    state: state.clone(),
                    response_mode: params.response_mode.clone(),
                    code_challenge: code_challenge.clone(),
                    scope: Some(params.scope.as_str().to_string()),
                    nonce: params.nonce.clone(),
                }),
            },
        )
        .await?;
    let is_https = params.redirect_uri.url().scheme() == "https";
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .same_site(SameSite::Strict)
        .http_only(true)
        .secure(is_https)
        .max_age(cookie::time::Duration::seconds(
            SESSION_LIFETIME.try_into().unwrap(),
        ))
        .build();

    let domain = params
        .redirect_uri
        .url()
        .host()
        .map(|h| h.to_string())
        .unwrap_or_else(|| params.redirect_uri.url().scheme().to_string());
    // The login page reads these values to build its CAIP-122 message (which
    // binds `redirect_uri` in its `Resources:`) and its link to /sign_in. Each
    // value is percent-encoded so the page reads it back exactly: a redirect
    // URI with several query parameters, or a state with `&` or `+`, would
    // otherwise be cut or altered. /sign_in itself reads none of them; it
    // takes the request from the session.
    let mut page = url::form_urlencoded::Serializer::new(String::new());
    page.append_pair("nonce", &nonce)
        .append_pair("domain", &domain)
        .append_pair("redirect_uri", params.redirect_uri.as_str())
        .append_pair("state", &state)
        .append_pair("client_id", &params.client_id);
    if let Some(n) = &params.nonce {
        page.append_pair("oidc_nonce", n.secret());
    }
    page.append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");
    // Absent/"query" appends nothing.
    if params.response_mode.as_deref() == Some("fragment") {
        page.append_pair("response_mode", "fragment");
    }
    Ok((format!("/?{}", page.finish()), Box::new(session_cookie)))
}

// -- SiwX sign-in ----------------------------------------------------------

/// Cookie set by the frontend after the user signs the CAIP-122 challenge.
#[derive(Serialize, Deserialize)]
pub struct SiwxCookie {
    pub did: String,
    /// The canonical CAIP-122 message string that was signed.
    pub message: String,
    /// Hex-encoded signature bytes, optionally prefixed with "0x".
    pub signature: String,
}

/// Extract the `Nonce: {value}` line from a CAIP-122 message. Public so the
/// device/account CAIP-122 paths can read the nonce to consume it from the
/// server-issued single-use nonce store (C1) before validating the envelope.
pub fn extract_nonce_pub(message: &str) -> Option<&str> {
    extract_nonce(message)
}

/// Extract the `Nonce: {value}` line from a CAIP-122 message.
fn extract_nonce(message: &str) -> Option<&str> {
    message
        .lines()
        .find(|l| l.starts_with("Nonce: "))
        .map(|l| l.trim_start_matches("Nonce: ").trim())
}

/// Extract the `Expiration Time: {value}` line from a CAIP-122 message.
fn extract_expiration_time(message: &str) -> Option<&str> {
    message
        .lines()
        .find(|l| l.starts_with("Expiration Time: "))
        .map(|l| l.trim_start_matches("Expiration Time: ").trim())
}

/// C1 (login path): enforce the CAIP-122 `Expiration Time` **only when present**.
/// The browser login frontend (`App.svelte`) sets a 48h `expirationTime`, so for
/// it this closes the "valid forever" replay gap on the login path. A ~120s skew
/// allowance absorbs client/server clock drift.
///
/// **Enforce-if-present (don't break headless clients).** The in-house headless
/// client `siwx-oidc-auth` (the exact login path used by the production agent
/// fleet) does NOT emit an `Expiration Time` line in its CAIP-122 message
/// (`siwx-oidc-auth/src/lib.rs::build_message`). Rejecting messages that omit the
/// line would brick every agent. So a message with NO `Expiration Time` is
/// accepted; a message that HAS one is rejected only when it is actually expired
/// (past, beyond the skew). The replay window for an omitted exp is bounded
/// elsewhere by the single-use nonce / session lifetime.
///
/// Not used by the device-approval and account paths: those make `Expiration
/// Time` MANDATORY instead (see [`validate_caip122_envelope`]).
const CAIP122_EXPIRY_SKEW_SECS: i64 = 120;

fn enforce_login_expiration(message: &str, now: chrono::DateTime<Utc>) -> Result<(), CustomError> {
    // Enforce-if-present: a missing Expiration Time is accepted (headless clients
    // like siwx-oidc-auth legitimately omit it). Only enforce when one is set.
    let Some(raw) = extract_expiration_time(message) else {
        return Ok(());
    };
    let exp = chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| CustomError::BadRequest(format!("Invalid Expiration Time: {}", e)))?
        .with_timezone(&Utc);
    if now - chrono::Duration::seconds(CAIP122_EXPIRY_SKEW_SECS) >= exp {
        return Err(CustomError::BadRequest(
            "CAIP-122 signature has expired".to_string(),
        ));
    }
    Ok(())
}

/// Extract resource URIs from the `Resources:` section of a CAIP-122 message.
fn extract_resources(message: &str) -> Vec<&str> {
    let mut in_resources = false;
    let mut out = vec![];
    for line in message.lines() {
        if line == "Resources:" {
            in_resources = true;
        } else if in_resources && line.starts_with("- ") {
            out.push(line[2..].trim());
        } else if in_resources {
            break;
        }
    }
    out
}

/// What a CAIP-122 message MUST satisfy for the device-approval / account paths.
///
/// `nonce` is the exact server-issued single-use nonce that was minted for this
/// operation; `resources` is the set of resource URIs that MUST all appear in the
/// message `Resources:` block (this is the operation/domain binding — e.g. the
/// account audience names the specific `action`, so a signature minted for one
/// action cannot be replayed for another).
pub struct Caip122Expectation<'a> {
    pub nonce: &'a str,
    pub resources: &'a [String],
}

/// C1 shared envelope validator for the device-approval and account CAIP-122
/// paths. Unlike the login path (`enforce_login_expiration`, which is lenient
/// because the headless `siwx-oidc-auth` lib omits an Expiration Time), these
/// paths are driven ONLY by the embedded pages, which we update to always emit a
/// server nonce + Expiration Time + Resources — so here all three are MANDATORY.
///
/// Checks, in order:
///  - `Nonce:` is present and exactly equals the expected server-issued nonce
///    (single-use consumption happens at the caller, against the Redis store);
///  - `Expiration Time:` is present, RFC3339-parseable, and not expired (with a
///    [`CAIP122_EXPIRY_SKEW_SECS`] clock-skew allowance) — ABSENT is rejected;
///  - every expected resource URI appears in the message `Resources:` block.
///
/// The single-use / cross-context-binding guarantee is provided by the caller
/// consuming the nonce from the Redis nonce store and checking the bound context;
/// this function validates the *contents* of the signed message.
pub fn validate_caip122_envelope(
    message: &str,
    expected: &Caip122Expectation,
    now: chrono::DateTime<Utc>,
) -> Result<(), CustomError> {
    let msg_nonce = extract_nonce(message).ok_or_else(|| {
        CustomError::BadRequest("Nonce not found in CAIP-122 message".to_string())
    })?;
    if msg_nonce != expected.nonce {
        return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
    }

    // Expiration Time is MANDATORY on these paths (the pages always set it).
    let raw_exp = extract_expiration_time(message).ok_or_else(|| {
        CustomError::BadRequest("CAIP-122 message is missing an Expiration Time".to_string())
    })?;
    let exp = chrono::DateTime::parse_from_rfc3339(raw_exp)
        .map_err(|e| CustomError::BadRequest(format!("Invalid Expiration Time: {}", e)))?
        .with_timezone(&Utc);
    if now - chrono::Duration::seconds(CAIP122_EXPIRY_SKEW_SECS) >= exp {
        return Err(CustomError::BadRequest(
            "CAIP-122 signature has expired".to_string(),
        ));
    }

    // Operation/domain binding: every expected resource must be present.
    let present = extract_resources(message);
    for want in expected.resources {
        if !present.iter().any(|r| r == want) {
            return Err(CustomError::BadRequest(format!(
                "Missing or mismatched resource: {}",
                want
            )));
        }
    }
    Ok(())
}

/// Whether `redirect_uri` is one of the client's registered redirect URIs.
///
/// The match is exact (RFC 9700 §4.1.3): the whole URL, query included,
/// compared after URL parsing. A registration that carries a query (Element Web
/// registers `…/?no_universal_links=true`) matches only that exact query, and
/// an extra or missing query component is a different URI. This is the one
/// matcher for both `authorize` and `sign_in`, so the two cannot disagree.
fn redirect_uri_is_registered(client: &ClientEntry, redirect_uri: &RedirectUrl) -> bool {
    client
        .metadata
        .redirect_uris()
        .iter()
        .any(|registered| registered.url() == redirect_uri.url())
}

/// Whether `uri` is one of the client's registered `post_logout_redirect_uris`,
/// matched exactly like [`redirect_uri_is_registered`] (RFC 9700 §4.1.3: the
/// whole URL, query included, after URL parsing). The one matcher for
/// RP-initiated logout, so a URI that is not registered never redirects.
fn post_logout_redirect_uri_is_registered(client: &ClientEntry, uri: &Url) -> bool {
    client
        .metadata
        .additional_metadata()
        .post_logout_redirect_uris
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|registered| registered.url() == uri)
}

/// C2 Step 3: re-validate a `redirect_uri` against the client's *registered*
/// redirect_uris with the same exact match as `authorize`
/// ([`redirect_uri_is_registered`]). Used by `sign_in` so a code is never
/// appended to an unregistered redirect_uri, on BOTH the wallet (Path B) and
/// WebAuthn (Path A) login paths.
/// Returns the client's entry, so the caller can use its registration (the
/// device name in `sign_in`) without a second read.
async fn validate_registered_redirect_uri(
    client_id: &str,
    redirect_uri: &RedirectUrl,
    db_client: &DBClientType,
) -> Result<ClientEntry, CustomError> {
    let client_entry = db_client
        .get_client(client_id.to_string())
        .await
        .map_err(|e| anyhow!("Failed to get kv: {}", e))?
        .ok_or_else(|| CustomError::Unauthorized("Unrecognised client id.".to_string()))?;

    if !redirect_uri_is_registered(&client_entry, redirect_uri) {
        return Err(CustomError::BadRequest(
            "redirect_uri is not registered for this client.".to_string(),
        ));
    }
    Ok(client_entry)
}

/// Verify the `siwx` cookie's CAIP-122 signature and nonce against the session.
/// Returns the verified DID on success. Does NOT consume the session.
pub fn verify_siwx_cookie(
    cookies: &headers::Cookie,
    session: &SessionEntry,
    allowed_did_methods: &[String],
    allowed_pkh_namespaces: &[String],
) -> Result<String, CustomError> {
    let siwx_cookie: SiwxCookie = match cookies.get(SIWX_COOKIE_KEY) {
        Some(c) => serde_json::from_str(
            &decode(c).map_err(|e| anyhow!("Could not decode siwx cookie: {}", e))?,
        )
        .map_err(|e| anyhow!("Could not deserialize siwx cookie: {}", e))?,
        None => {
            return Err(CustomError::BadRequest(
                "No `siwx` cookie — sign in with a wallet first".to_string(),
            ));
        }
    };

    let sig_hex = siwx_cookie
        .signature
        .strip_prefix("0x")
        .unwrap_or(&siwx_cookie.signature);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

    let did_method = find_did_method(&siwx_cookie.did)
        .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", siwx_cookie.did)))?;

    if !allowed_did_methods
        .iter()
        .any(|m| m == did_method.method_name())
    {
        return Err(CustomError::BadRequest(format!(
            "DID method '{}' is not enabled on this server",
            did_method.method_name()
        )));
    }
    if did_method.method_name() == "pkh" {
        let namespace = siwx_cookie
            .did
            .strip_prefix("did:pkh:")
            .and_then(|s| s.split(':').next())
            .unwrap_or("");
        if !allowed_pkh_namespaces.iter().any(|n| n == namespace) {
            return Err(CustomError::BadRequest(format!(
                "did:pkh namespace '{namespace}' is not enabled on this server"
            )));
        }
    }

    let valid = did_method
        .verify(&siwx_cookie.did, &siwx_cookie.message, &sig_bytes)
        .map_err(|e| anyhow!("Verification error: {}", e))?;
    if !valid {
        return Err(CustomError::Unauthorized(
            "Signature verification failed".to_string(),
        ));
    }

    let msg_nonce = extract_nonce(&siwx_cookie.message)
        .ok_or_else(|| anyhow!("Nonce not found in CAIP-122 message"))?;
    if msg_nonce != session.siwe_nonce {
        return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
    }

    // C1 (login path): enforce the message Expiration Time.
    enforce_login_expiration(&siwx_cookie.message, Utc::now())?;

    Ok(siwx_cookie.did)
}

/// A bound request for `client_id` at `https://example.com/callback`, as
/// `authorize` would store it. For tests that drive `sign_in` directly.
#[cfg(test)]
pub(crate) fn bound_test_request(client_id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: client_id.to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        state: "state".to_string(),
        response_mode: None,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
        scope: None,
        nonce: None,
    }
}

/// The authorization request this sign-in completes: the one `/authorize`
/// validated and bound to the session. It is the only source of the client,
/// redirect URI, state, response mode, PKCE challenge and nonce: `sign_in`
/// reads no authorization parameter from its own query. The login page still
/// appends them to its `/sign_in` link (encoded with `encodeURI`, which alters
/// `&`, `+` and other characters in a state or redirect URI); they are never
/// parsed.
fn bound_request(session: &SessionEntry) -> Result<AuthorizationRequest, CustomError> {
    session.request.clone().ok_or_else(|| {
        CustomError::BadRequest(
            "This sign-in has no bound authorization request (it was started before a \
             server update). Restart the sign-in from the application."
                .to_string(),
        )
    })
}

/// Extract a device_id from a scope string containing `urn:matrix:client:device:XXX`.
fn extract_device_id_from_scope(scope: &str) -> Option<String> {
    const STABLE_PREFIX: &str = "urn:matrix:client:device:";
    const MSC2967_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";
    scope
        .split_whitespace()
        .find_map(|s| {
            s.strip_prefix(STABLE_PREFIX)
                .or_else(|| s.strip_prefix(MSC2967_PREFIX))
                .map(|id| id.to_string())
        })
        .filter(|id| !id.is_empty())
}

/// Resolve the device_id to provision: use the client-proposed id when present,
/// otherwise mint a fresh `SIWX_{uuid8}`.
fn resolve_device_id(proposed_device_id: Option<&str>) -> String {
    match proposed_device_id {
        Some(proposed) => proposed.to_string(),
        None => format!("SIWX_{}", &Uuid::new_v4().to_string()[..8]),
    }
}

/// Synapse's limit on a device display name (`MAX_DEVICE_DISPLAY_NAME_LEN` in
/// `synapse/handlers/device.py`, 1.161.0, counted in code points). A longer
/// name makes `update_device_display_name` answer 400 `M_TOO_LARGE` and the
/// new device would stay unnamed, so the name is cut to fit.
const MAX_DEVICE_DISPLAY_NAME_CHARS: usize = 100;

/// The display name for a Synapse device created by a sign-in through
/// `client_id`: the client's registered `client_name` (RFC 7591), else the
/// client id itself.
///
/// Never a fixed brand. Every client used to get "Element Web" (or "Element
/// X" on the device-code path), so an agent's or any other client's session
/// showed up in the user's device list under a client it was not. The
/// untagged `client_name` wins; a client that registered only language-tagged
/// names (`client_name#de`) gets the one with the lexicographically smallest
/// tag. The tagged names sit in a `HashMap`, so "the first one" would change
/// from one sign-in to the next.
fn device_display_name(client_id: &str, client: Option<&ClientEntry>) -> String {
    let registered = client
        .and_then(|c| c.metadata.client_name())
        .and_then(|names| {
            names.get(None).or_else(|| {
                names
                    .iter()
                    .filter_map(|(tag, name)| Some((tag?.as_ref(), name)))
                    .min_by_key(|(tag, _)| *tag)
                    .map(|(_, name)| name)
            })
        })
        .map(|name| name.trim())
        .filter(|name| !name.is_empty());
    registered
        .unwrap_or(client_id)
        .chars()
        .take(MAX_DEVICE_DISPLAY_NAME_CHARS)
        .collect()
}

/// Was this displayname written by US, or chosen by the USER?
///
/// `true` only for the two strings provisioning has ever seeded: the raw DID
/// (until 2026-09-10) and the bare localpart (2026-09-10 to 2026-09-11).
/// Byte-equality, deliberately — see the call site for why a fuzzier match is
/// the wrong direction, and `alias_migration_*` for the cases this pins.
///
/// A cleared or absent displayname is NOT this function's business: the caller
/// only reaches it with a value Synapse actually returned, because "the user
/// deliberately emptied their name" is precisely the state the 2026-08-02
/// live falsification caught this code clobbering.
fn provider_written_displayname(current: &str, did: &str, localpart: &str) -> bool {
    current == did || current == localpart
}

/// Provision a Synapse user+device for a DID. Best-effort: failures are logged
/// but never fail the auth flow. Idempotent: re-provisioning the same device_id
/// is a plain upsert that preserves the device's E2EE keys. Never deletes an
/// existing device (device teardown is explicit — see `compat` / account actions).
///
/// **Cross-signing reset arm (product 3B, 2026-07-25):** after upsert, always
/// best-effort `allow_cross_signing_reset` so a half-reset client can publish
/// replacement public keys without requiring a separate `/account` visit on
/// every recovery path. First-time bootstrap still relies on MSC3967 when no
/// master exists; this call is a no-op or soft-fail in that case and must not
/// fail sign-in. Explicit MSC4312 account reauth remains available and still
/// uses the honesty gate in `account.rs`.
///
/// `proposed_device_id`: the client-supplied device_id from the OAuth scope
/// (stable for Element Web and Element X). When `None`, a fresh `SIWX_{uuid}`
/// is minted.
///
/// `display_name` is the name a device CREATED by this sign-in gets
/// ([`device_display_name`]). An existing device keeps its name: the device is
/// upserted without one and named only when Synapse reports it created it (see
/// the upsert below).
///
/// **Loud failure + self-heal (2026-08-01 incident, discriminator corrected
/// 2026-08-02):** a `provision_user` failure at first sign-in used to be
/// logged at `warn!` and never retried, leaving the account with a Synapse
/// `users` row but no `profiles` row — permanently unable to set a
/// displayname (upstream Synapse #19702). A first-sign-in failure is now
/// logged at `error!`. For an *existing* account (the
/// `is_localpart_available == false` branch), if `server_name` is supplied
/// this also best-effort self-heals: it checks
/// `SynapseClient::has_profile_row` and, only when the row is confirmed
/// truly absent, re-runs `provision_user`. That confirmation is
/// errcode-discriminated (`M_UNKNOWN` = absent, everything else = present or
/// unknown/fail-safe) — a naive "404 = absent" check was live-falsified on
/// Synapse 1.154.0 (a row with a null displayname AND null avatar also
/// 404s) and clobbered a deliberately-cleared displayname before this fix.
/// See the table on `SynapseClient::has_profile_row`. The repair call itself
/// is currently inert on Synapse builds still affected by
/// element-hq/synapse#19702 (`set_displayname` 500s on a row-less account);
/// it self-activates once the deployment's Synapse image is bumped past that
/// fix — see the comment on the heal branch below. `server_name: None` (no
/// `SIWEOIDC_MATRIX_SERVER_NAME` configured) skips the check entirely,
/// preserving prior behavior for standalone deployments.
///
/// `localpart` is the value already decided by
/// [`crate::localpart::resolve_identity`] for this sign-in (grandfathered
/// legacy, already-migrated modern, or a genuinely new modern identity) — it
/// is the single source of truth here; this function does not (re)compute a
/// localpart from `did` itself. The `is_localpart_available` probe below is
/// therefore an idempotent re-confirmation of a decision already made by the
/// caller, not a fresh decision.
///
/// # The three identity tiers, and why they are separated here
///
/// | Tier | Value | Owner | Mutable | Where |
/// |---|---|---|---|---|
/// | alias | a display name | the **user** | yes, freely | Synapse `displayname` |
/// | MXID | `@{base36(sha256(did)[..10])}:{server}` | derived | no (no rename API) | Synapse `users` row |
/// | DID | `did:key:…` / `did:pkh:…` + provider signature | the **provider** | no | profile field `io.inblock.did` |
///
/// Until 2026-09-10 tiers 1 and 3 were **conflated**: `provision_user` was
/// called with `did` as its displayname argument, so a user's only published
/// DID lived in a field the user can rewrite at will (verified live — the ACL
/// probe's leg 5: `displayname` routes through `set_field` → `set_displayname`
/// and never reaches the guard that protects `io.inblock.did`). A consumer
/// reading displayname-as-a-DID could therefore be handed *somebody else's*
/// DID. Splitting the tiers is the security fix; the assertion below is what
/// makes the split checkable off-server.
///
/// `did_publication` carries the signing key and issuer for that third tier;
/// `None` disables publication entirely.
///
/// # Why this takes a `ResolvedIdentity` and not a `localpart: &str`
///
/// Because the localpart's PROVENANCE decides whether the DID tier may be
/// written at all, and a bare `&str` cannot carry it. `resolve_identity_or_legacy`
/// is infallible by design: on a probe error it GUESSES the legacy shape (the
/// correct fail-safe direction — see its doc). Before 2026-09-10 that guess
/// flowed in here as an anonymous string, and this function then re-probed,
/// found the guessed localpart free, provisioned it, and published a
/// **correctly-signed** assertion binding the user's DID to a brand-new WRONG
/// mxid — see [`crate::localpart::ResolvedIdentity::degraded`] for the full
/// scenario. Taking the whole struct makes it impossible to call this with a
/// localpart whose origin nobody stated, which is the only structural way to
/// stop a future third call site from reintroducing the bug.
pub async fn provision_synapse_device(
    did: &str,
    identity: &crate::localpart::ResolvedIdentity,
    synapse_client: Option<&SynapseClient>,
    display_name: &str,
    proposed_device_id: Option<&str>,
    server_name: Option<&str>,
    did_publication: Option<&DidPublication<'_>>,
) -> Option<String> {
    let synapse = synapse_client?;
    let localpart = identity.localpart.as_str();
    let dev_id = resolve_device_id(proposed_device_id);
    // Tier 1. Derived here once and used by all three write paths below (first
    // sign-in, row-absent self-heal, provider-written migration) so they cannot
    // seed three different names for one account.
    let alias = siwx_oidc::alias::alias_for(did);
    debug!("provisioning device_id={} for did={}", dev_id, did);

    match synapse.is_localpart_available(localpart).await {
        Ok(true) => {
            // ALIAS TIER SEED — a generated pseudonym, NEVER the DID.
            //
            // `provision_user`'s second argument is the user's *displayname*, a
            // user-writable field. Seeding it with the DID published a
            // provider-looking assertion into a surface any user can rewrite
            // (see the three-tier table above), so a consumer reading
            // displayname-as-identity could be handed someone else's DID. The
            // interim fix seeded the localpart, which was honest but
            // unreadable; `alias::alias_for` keeps the security property (the
            // string carries no DID and no key material, so it cannot be
            // mistaken for an identifier) and restores a name a human can say
            // out loud. It is deterministic in the DID, so the same person gets
            // the same name on any deployment, and non-empty, so Synapse still
            // creates the `profiles` row that keeps #19702 away from new
            // accounts. The user owns it from this moment on: it is written
            // ONCE, here, and never re-asserted.
            if let Err(e) = synapse.provision_user(localpart, &alias).await {
                error!(
                    did = %did,
                    error = %e,
                    "provision_user failed at first sign-in — account may be half-provisioned (no profile row); will retry at next login"
                );
            }
        }
        Ok(false) => {
            // Self-heal: re-check for the case where a PRIOR first-sign-in
            // provision_user call failed, leaving a `users` row but no
            // `profiles` row. Never runs when server_name is unavailable
            // (standalone deployments) and never overwrites an existing row
            // (see SynapseClient::has_profile_row's discriminator table —
            // corrected 2026-08-02 after a live falsification on Synapse
            // 1.154.0 where the original "any 404 = absent" premise clobbered
            // a deliberately-cleared displayname).
            //
            // Repair is currently INERT on Synapse builds affected by
            // element-hq/synapse#19702 (`_check_profile_size` crashes on a
            // row-less account): the has_profile_row check correctly detects
            // the absent row and this branch correctly re-calls
            // provision_user, but that MAS `set_displayname` call itself hits
            // the same upstream bug and 500s (traced live to
            // profile_handler.set_displayname -> profile.py:354). The
            // resulting `error!` line below is intentional per-login
            // observability, not a new failure mode — first-time provisioning
            // is unaffected (registration creates the row before
            // set_displayname is ever called). The heal becomes effective
            // automatically once the deployment's pinned Synapse image is
            // bumped past the upstream fix; no code change will be needed
            // here when that happens.
            //
            // Erasure note: `has_profile_row` also reads a GDPR-erased
            // account's purged row (see account::execute_action's
            // `io.inblock.account_erase`, which calls
            // `SynapseClient::deactivate_user(.., erase: true)`) as "truly
            // absent" by the same M_UNKNOWN discriminator. If an erased
            // account ever completed sign-in again, this would resurrect a
            // bare profile row (displayname = the generated alias, since 2026-09-11)
            // — accepted, since that reveals nothing beyond the mxid the caller
            // already presented to authenticate.
            if let Some(server_name) = server_name {
                match synapse.read_profile(localpart, server_name).await {
                    Ok(profile) if profile.row_present => {
                        // ALIAS-TIER MIGRATION. Rewrite the displayname only
                        // when it is byte-equal to a string WE wrote — the raw
                        // DID (pre-2026-09-10) or the bare localpart
                        // (2026-09-10..2026-09-11). Anything else, including an
                        // absent or cleared one, is the user's and is left
                        // alone.
                        //
                        // Byte-equal, never prefix or case-folded: the point of
                        // the test is "nothing but our own provisioning could
                        // have produced this exact string". A fuzzier match
                        // would eventually overwrite something a user chose,
                        // which is the failure the 2026-08-02 discriminator fix
                        // exists to prevent, and a missed migration costs only
                        // a stale name until the user edits it themselves.
                        //
                        // Migrating the DID case is the point: leaving it there
                        // does not create a new forgery path (a user could
                        // always set any displayname to any string) but it
                        // perpetuates the convention that displayname carries
                        // the DID, and that convention is what makes a naive
                        // consumer read it as an identity source at all.
                        if let Some(current) = profile.displayname.as_deref() {
                            if provider_written_displayname(current, did, localpart) {
                                info!(
                                    did = %did,
                                    "migrating a provider-written displayname to the generated alias"
                                );
                                if let Err(e) = synapse.provision_user(localpart, &alias).await {
                                    warn!(
                                        did = %did,
                                        error = %e,
                                        "alias migration failed — the old displayname stands; will retry at next login"
                                    );
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        warn!(
                            did = %did,
                            "existing account has no profile row — re-running provisioning (self-heal)"
                        );
                        // Same alias-tier seed as the first-sign-in branch
                        // above: the generated pseudonym, never the DID.
                        if let Err(e) = synapse.provision_user(localpart, &alias).await {
                            error!(
                                did = %did,
                                error = %e,
                                "provision_user self-heal retry failed — account remains half-provisioned (expected on Synapse builds still affected by element-hq/synapse#19702; resolves automatically once the pinned image is bumped)"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            did = %did,
                            error = %e,
                            "profile read failed — skipping self-heal and alias migration this login"
                        );
                    }
                }
            }
        }
        Err(e) => warn!("is_localpart_available check failed: {}", e),
    }

    // DID TIER — publish the provider-attested DID into the ACL-protected
    // profile field, on EVERY sign-in.
    //
    // # Why re-assert every time instead of only at provisioning
    //
    // This is the self-heal, and it is load-bearing rather than defensive. The
    // Synapse write-ACL we carry (a backport of element-hq/synapse#19980; see
    // `docs/audits/2026-09-10-msc4133-acl-probe.md`) is **prospective only**:
    // it refuses new user writes to this field but neither validates nor
    // migrates a value that was written BEFORE the denylist was applied.
    // Upstream has the identical gap, acknowledged in the PR's review thread
    // `r3783167037`. Re-asserting on every login closes it from the other side,
    // with no janitor process and no migration script: any account whose field
    // a user clobbered while the server was unprotected is corrected the next
    // time that user signs in. The write is idempotent, so the steady-state
    // cost is one PUT per login.
    //
    // # Best-effort, exactly like its neighbours
    //
    // Plan invariant 1: sign-in NEVER fails because of this feature. Every
    // outcome — including a 500 from a row-less account (#19702) — is logged
    // and dropped, the same contract `upsert_device` and
    // `allow_cross_signing_reset` have immediately below.
    //
    // # No `server_name`, no publication
    //
    // The assertion binds an `mxid`, which cannot be built without the server
    // name, and an assertion binding a guessed mxid would be worse than none
    // (it would verify for nobody, or — far worse — for the wrong account on a
    // homeserver that later adopts that name). A standalone deployment with no
    // `SIWEOIDC_MATRIX_SERVER_NAME` therefore skips this entirely, exactly like
    // the self-heal branch above: degrade, never 500.
    //
    // # A GUESSED localpart is never asserted (2026-09-10 audit, D4)
    //
    // `identity.degraded` means `resolve_identity_or_legacy` could not reach
    // Synapse and fell back to the legacy shape. Everything ELSE in this
    // function stays best-effort on that guess — provisioning a possibly-wrong
    // account is recoverable, and refusing to provision would fail the login,
    // which invariant 1 forbids. Publication is the one step that is NOT
    // recoverable: it mints a durable, off-server, cryptographically valid
    // `{did, proof}` that a consumer is *supposed* to trust, and Synapse has no
    // rename API to undo the account it names. So the assertion is suppressed
    // and only the assertion.
    //
    // The asymmetry is the whole point: a wrong `upsert_device` is noise, a
    // wrong SIGNED assertion is a second account claiming the same DID with
    // provider authority behind it, indistinguishable to any verifier from the
    // real one. Publishing nothing is strictly better than publishing a
    // confident lie, and it costs one login of staleness because the write is
    // idempotent and unconditional on every subsequent healthy sign-in.
    if identity.degraded {
        warn!(
            did = %did,
            localpart = %localpart,
            "attested DID field NOT asserted: identity resolution had DEGRADED (Synapse probe \
             failed, localpart is the fail-safe legacy guess). Publishing a signed assertion for \
             a guessed mxid could bind this DID to a duplicate account permanently. Re-asserted \
             automatically at the next healthy sign-in"
        );
    } else if let (Some(publication), Some(server_name)) = (did_publication, server_name) {
        let mxid = crate::synapse_client::matrix_user_id(localpart, server_name);
        let value = crate::did_assertion::did_profile_value(
            publication.key,
            publication.issuer,
            did,
            &mxid,
            Utc::now().timestamp(),
        );
        match synapse
            .publish_did_field(localpart, server_name, &value)
            .await
        {
            Ok(PublishOutcome::Written) => info!(
                did = %did,
                %mxid,
                "published the attested DID profile field"
            ),
            // NOT `error!`: a known, bounded condition of a known-buggy
            // dependency (see SynapseClient::publish_did_field). It resolves by
            // itself once the pinned Synapse image is bumped past #19702.
            Ok(PublishOutcome::RowLessAccount) => warn!(
                did = %did,
                %mxid,
                "attested DID field not written: this account has no profile row \
                 (element-hq/synapse#19702, confirmed by a profile-row probe). Retried \
                 automatically at the next sign-in"
            ),
            Err(e) => warn!(
                did = %did,
                %mxid,
                error = %e,
                "publishing the attested DID profile field failed (non-fatal)"
            ),
        }
    }

    // Upsert WITHOUT a name, then name the device only if this upsert created
    // it. Synapse overwrites an existing device's name whenever one is sent,
    // and a client may re-authenticate with its own device id for a device
    // the user renamed. Synapse's 201 is the one race-free signal that the
    // device is new: a separate "does it exist?" read could be overtaken by a
    // concurrent sign-in. Failing to name a new device is cosmetic.
    match synapse.upsert_device(localpart, &dev_id).await {
        Ok(DeviceUpsert::Created) => {
            if let Err(e) = synapse
                .update_device_display_name(localpart, &dev_id, display_name)
                .await
            {
                warn!(device_id = %dev_id, error = %e, "naming the new device failed (non-fatal)");
            }
        }
        Ok(DeviceUpsert::AlreadyExisted) => {}
        Err(e) => warn!("upsert_device failed: {}", e),
    }

    // 3B: arm reset window after every successful login provision (best-effort).
    if let Err(e) = synapse.allow_cross_signing_reset(localpart).await {
        warn!(
            did = %did,
            error = %e,
            "allow_cross_signing_reset after login provision failed (non-fatal)"
        );
    } else {
        info!(
            did = %did,
            "allow_cross_signing_reset armed after login provision"
        );
    }

    Some(dev_id)
}

/// `did_publication` carries the provider's signing key + issuer for the
/// attested `io.inblock.did` profile field (see
/// [`provision_synapse_device`]). It is built by the axum handler, which is the
/// one place that holds both `AppState::signing_key` and `config.base_url`;
/// `None` disables publication.
#[allow(clippy::too_many_arguments)]
pub async fn sign_in(
    _base_url: &Url,
    allowed_did_methods: &[String],
    allowed_pkh_namespaces: &[String],
    cookies: headers::Cookie,
    db_client: &DBClientType,
    synapse_client: Option<&SynapseClient>,
    server_name: Option<&str>,
    did_publication: Option<&DidPublication<'_>>,
) -> Result<(Url, String), CustomError> {
    let session_id = if let Some(c) = cookies.get(SESSION_COOKIE_NAME) {
        c
    } else {
        return Err(CustomError::BadRequest(
            "Session cookie not found".to_string(),
        ));
    };
    let session_entry = if let Some(e) = db_client.get_session(session_id.to_string()).await? {
        e
    } else {
        return Err(CustomError::BadRequest("Session not found".to_string()));
    };

    // The request this sign-in completes, as `/authorize` bound it. Checked
    // before the session is spent.
    let request = bound_request(&session_entry)?;
    let redirect_uri = RedirectUrl::new(request.redirect_uri.clone())
        .map_err(|e| anyhow!("bound redirect_uri does not parse: {}", e))?;

    // Atomically mark session as signed-in (prevents race-condition double sign-in).
    if !db_client
        .try_mark_session_signed_in(session_id.to_string())
        .await?
    {
        return Err(CustomError::BadRequest(
            "Session has already logged in".to_string(),
        ));
    }

    // -- Determine the authenticated DID --
    // Path A: Server-verified ceremony (WebAuthn). The DID was already verified
    //         by the ceremony endpoint and stored in the Redis session — trusted.
    // Path B: Client-set CAIP-122 cookie (existing wallet flow — untrusted, must verify).
    let did = if let Some(ref verified_did) = session_entry.verified_did {
        info!("sign_in: server-verified did={}", verified_did);
        let did_method = find_did_method(verified_did)
            .ok_or_else(|| CustomError::BadRequest(format!("Unsupported DID: {}", verified_did)))?;
        if !allowed_did_methods
            .iter()
            .any(|m| m == did_method.method_name())
        {
            return Err(CustomError::BadRequest(format!(
                "DID method '{}' is not enabled on this server",
                did_method.method_name()
            )));
        }
        // Enforce pkh namespace allowlist (same check as CAIP-122 path).
        if did_method.method_name() == "pkh" {
            let namespace = verified_did
                .strip_prefix("did:pkh:")
                .and_then(|s| s.split(':').next())
                .unwrap_or("");
            if !allowed_pkh_namespaces.iter().any(|n| n == namespace) {
                return Err(CustomError::BadRequest(format!(
                    "did:pkh namespace '{namespace}' is not enabled on this server"
                )));
            }
        }
        verified_did.clone()
    } else {
        // Path B: CAIP-122 cookie verification (unchanged from original)
        let siwx_cookie: SiwxCookie = match cookies.get(SIWX_COOKIE_KEY) {
            Some(c) => serde_json::from_str(
                &decode(c).map_err(|e| anyhow!("Could not decode siwx cookie: {}", e))?,
            )
            .map_err(|e| anyhow!("Could not deserialize siwx cookie: {}", e))?,
            None => {
                return Err(anyhow!("No `siwx` cookie").into());
            }
        };

        let sig_hex = siwx_cookie
            .signature
            .strip_prefix("0x")
            .unwrap_or(&siwx_cookie.signature);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| CustomError::BadRequest(format!("Bad signature: {}", e)))?;

        let did_method = find_did_method(&siwx_cookie.did).ok_or_else(|| {
            CustomError::BadRequest(format!("Unsupported DID: {}", siwx_cookie.did))
        })?;

        if !allowed_did_methods
            .iter()
            .any(|m| m == did_method.method_name())
        {
            return Err(CustomError::BadRequest(format!(
                "DID method '{}' is not enabled on this server",
                did_method.method_name()
            )));
        }
        if did_method.method_name() == "pkh" {
            let namespace = siwx_cookie
                .did
                .strip_prefix("did:pkh:")
                .and_then(|s| s.split(':').next())
                .unwrap_or("");
            if !allowed_pkh_namespaces.iter().any(|n| n == namespace) {
                return Err(CustomError::BadRequest(format!(
                    "did:pkh namespace '{namespace}' is not enabled on this server"
                )));
            }
        }

        info!("sign_in: did={}", siwx_cookie.did);
        let valid = did_method
            .verify(&siwx_cookie.did, &siwx_cookie.message, &sig_bytes)
            .map_err(|e| anyhow!("Verification error: {}", e))?;
        if !valid {
            return Err(CustomError::Unauthorized(
                "Signature verification failed".to_string(),
            ));
        }

        let msg_nonce = extract_nonce(&siwx_cookie.message)
            .ok_or_else(|| anyhow!("Nonce not found in CAIP-122 message"))?;
        if msg_nonce != session_entry.siwe_nonce {
            return Err(CustomError::BadRequest("Nonce mismatch".to_string()));
        }

        let redirect_url = redirect_uri.url();
        if !extract_resources(&siwx_cookie.message)
            .iter()
            .any(|r| Url::parse(r).ok().as_ref() == Some(redirect_url))
        {
            // The client signed a message that binds no (or another) redirect
            // URI: its mistake, not a server fault.
            return Err(CustomError::BadRequest(
                "Missing or mismatched resource in CAIP-122 message".to_string(),
            ));
        }

        // C1 (login path): enforce the message Expiration Time. The login
        // frontend already sets a 48h `expirationTime`, so this is server-only
        // and non-breaking. Only the wallet (Path B) CAIP-122 path is affected;
        // the WebAuthn (Path A) ceremony has no CAIP-122 message to expire.
        enforce_login_expiration(&siwx_cookie.message, Utc::now())?;

        siwx_cookie.did
    };

    // Deactivation gate. Synapse's delegated-auth path never checks
    // `users.deactivated` (zero references in `api/auth/mas.py`, 1.159.0) — it
    // trusts our introspection — and `is_localpart_available` reports a
    // deactivated user's localpart as *taken*, so without this a deactivated or
    // erased account signed straight back in and got a full session. Placed
    // after the DID is proven but BEFORE `provision_synapse_device`, so a
    // rejected sign-in leaves no Synapse state behind.
    //
    // # This runs BEFORE `resolve_identity_or_legacy` below, DELIBERATELY
    //
    // The 2026-09-13 audit observed that because this gate fails closed on a
    // probe error, a PERSISTENT Synapse fault can never reach the
    // `resolve_identity_or_legacy` call ~20 lines down, and therefore never
    // reaches the `degraded` guard that suppresses DID publication (2026-09-10
    // audit, D4) — making that guard look like near-dead code on the login path.
    // The observation is correct and the ordering is still right. Do not swap
    // them to "make the guard reachable". `sign_in_deactivation_order_tests`
    // (end of this file) fails if the gate moves anywhere later in `sign_in`.
    //
    // Swapping them would not trade coverage for safety, it would build a live
    // deactivation BYPASS. `resolve_identity_or_legacy` is infallible by
    // construction: on a probe error it returns the fail-safe LEGACY localpart
    // with `degraded: true`. Feed that guess to the gate and, for a modern-only
    // account, `query_user(legacy_localpart)` answers 404 — which the gate reads
    // as `Ok(None)`, "no such account, nothing to reject" — and the deactivated
    // user signs in. That is not hypothetical: the two MAS probes are separate
    // routes, so a partial fault where `is_localpart_available` fails and
    // `query_user` answers is exactly the shape
    // `webauthn::tests::a_query_user_failure_is_a_probe_failure_not_a_deactivation`
    // models. This is why `reject_if_deactivated` calls the FALLIBLE
    // `resolve_identity` and refuses the guess — the same rule `resolve.rs`
    // follows, for the same reason.
    //
    // `degraded` is narrowed on this path, not dead. It still fires here when
    // the fault arrives BETWEEN the gate's probe and the resolution below (two
    // independent round trips — a flaky or mid-restart Synapse), which is
    // precisely the residual window a fail-closed gate cannot cover. And it is
    // fully exercised on the paths that have no gate in front of it: the
    // device-code grant in `token` (this file, `resolve_identity_or_legacy`
    // under `grant_type=device_code` — the deactivation gate for that flow ran
    // at APPROVAL time, in a different request, possibly minutes earlier), and
    // the cosmetic `detected_mxid` / `new_user` displays in
    // `axum_lib::detected_mxid_for` and `webauthn_authenticate_finish`.
    crate::webauthn::reject_if_deactivated(synapse_client, &did).await?;

    // C2 Step 3: re-validate the bound redirect_uri against the client's
    // registered set before issuing the code. `authorize` matched it when it
    // bound the request; this re-check covers a registration that changed or
    // expired since, on BOTH the wallet (Path B) and WebAuthn (Path A) paths.
    // Path B additionally binds the redirect via the signed `Resources:` list
    // above.
    let client =
        validate_registered_redirect_uri(&request.client_id, &redirect_uri, db_client).await?;
    let device_name = device_display_name(&request.client_id, Some(&client));

    // Extract a client-proposed device_id from the bound request's scope (if any).
    let proposed_device_id = request
        .scope
        .as_deref()
        .and_then(extract_device_id_from_scope);
    // Resolve ONCE (grandfathering decision), and reuse the result as the
    // single source of truth for both provisioning and the CodeEntry the
    // eventual /token exchange reads back. Best-effort: a Synapse hiccup here
    // must not fail sign-in, so an error degrades to the legacy localpart
    // (never the modern one — see resolve_identity_or_legacy's fail-safe
    // direction) exactly like the pre-existing degraded-provisioning path.
    //
    // ORDERING (2026-09-13 audit): `reject_if_deactivated` above has already
    // failed closed on a persistent probe error, so on THIS path the `degraded`
    // fallback covers only the residual window — a fault arriving between that
    // gate's probe and this one. That is deliberate and must not be "fixed" by
    // reordering: the full argument, including the deactivation bypass a swap
    // would open and the paths that do exercise `degraded` freely, is at the
    // gate's call site above.
    let resolved = crate::localpart::resolve_identity_or_legacy(&did, synapse_client).await;
    let device_id = provision_synapse_device(
        &did,
        &resolved,
        synapse_client,
        &device_name,
        proposed_device_id.as_deref(),
        server_name,
        did_publication,
    )
    .await;

    let code_entry = CodeEntry {
        did: did.clone(),
        nonce: request.nonce.clone(),
        exchange_count: 0,
        client_id: request.client_id.clone(),
        // The authentication, from Redis `TIME` like every lifetime deadline
        // (I6); the grant's absolute expiry counts from it.
        auth_time: chrono::DateTime::<Utc>::from_timestamp_millis(
            db_client.server_time_ms().await?,
        )
        .ok_or_else(|| anyhow!("Redis TIME out of range"))?,
        code_challenge: Some(request.code_challenge.clone()),
        code_challenge_method: Some("S256".to_string()),
        localpart: Some(resolved.localpart.clone()),
        device_id,
        scope: request.scope.clone(),
    };

    let code = Uuid::new_v4();
    db_client.set_code(code.to_string(), code_entry).await?;

    let mut url = redirect_uri.url().clone();
    if request.response_mode.as_deref() == Some("fragment") {
        // matrix-js-sdk v42 requested `response_mode=fragment` on /authorize
        // (round-tripped here via the login SPA) and reads the authorization
        // response ONLY from the URL fragment. ALL response params go in the
        // fragment; any query the registered redirect_uri already carries stays
        // untouched with nothing appended to it.
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code.to_string())
            .append_pair("state", &request.state)
            .finish();
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().append_pair("code", &code.to_string());
        url.query_pairs_mut().append_pair("state", &request.state);
    }
    // Surface the resolved DID alongside the redirect so the HTTP handler can mint
    // the opaque login user-session cookie ONLY on this success path (a real login
    // that just issued a code). Error/early returns never reach here.
    Ok((url, did))
}

// -- Client registration ---------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RegisterError {
    error: CoreRegisterErrorResponseType,
}

/// What dynamic registration checks beyond the metadata's own form: the SSRF
/// guard on `backchannel_logout_uri` (D3) and the D4 switch.
#[derive(Clone, Debug, Default)]
pub struct RegistrationPolicy {
    pub guard: crate::backchannel::UriGuard,
    /// D4 (provisional): a client that may receive refresh tokens must register
    /// a `backchannel_logout_uri`. Off by default, and never in Matrix mode.
    pub require_backchannel_for_refresh: bool,
}

impl RegistrationPolicy {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            guard: crate::backchannel::UriGuard::new(&config.backchannel_logout_allowed_hosts),
            require_backchannel_for_refresh: config.backchannel_logout_required_for_refresh
                && !delegated_auth_enabled(config),
        }
    }
}

pub async fn register(
    payload: SiwxClientMetadata,
    base_url: Url,
    db_client: &DBClientType,
    policy: &RegistrationPolicy,
) -> Result<SiwxClientRegistrationResponse, CustomError> {
    let id = Uuid::new_v4();
    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let redirect_uris = payload.redirect_uris().to_vec();
    for uri in redirect_uris.iter() {
        if uri.url().fragment().is_some() {
            return Err(CustomError::BadRequestRegister(RegisterError {
                error: CoreRegisterErrorResponseType::InvalidRedirectUri,
            }));
        }
    }
    check_logout_metadata(&payload, policy).await?;
    let logout_metadata = payload.additional_metadata().clone();

    let access_token = RegistrationAccessToken::new(
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(11)
            .map(char::from)
            .collect(),
    );

    // The response below is the only place the secret and the registration
    // access token appear: the entry keeps their digests.
    let entry = ClientEntry::new(&secret, payload, Some(access_token.secret()));
    db_client.set_client(id.to_string(), entry).await?;

    Ok(SiwxClientRegistrationResponse::new(
        ClientId::new(id.to_string()),
        redirect_uris,
        logout_metadata,
        EmptyAdditionalClientRegistrationResponse::default(),
    )
    .set_client_secret(Some(ClientSecret::new(secret)))
    .set_registration_client_uri(Some(ClientConfigUrl::from_url(
        base_url
            .join(&format!("{}/{}", CLIENT_PATH, id))
            .map_err(|e| anyhow!("Unable to join URL: {}", e))?,
    )))
    .set_registration_access_token(Some(access_token)))
}

/// The logout metadata a registration may carry, else
/// `invalid_client_metadata` (RFC 7591 §3.2.2): every
/// `post_logout_redirect_uris` entry is an absolute URI without a fragment
/// (as `redirect_uris`); a `backchannel_logout_uri` passes the SSRF guard
/// ([`crate::backchannel::UriGuard::check`]: no fragment, `https`, every
/// resolved address outside the refused classes, unless the host is
/// allowlisted); and with the D4 switch on, a client that may receive refresh
/// tokens registers one.
async fn check_logout_metadata(
    payload: &SiwxClientMetadata,
    policy: &RegistrationPolicy,
) -> Result<(), CustomError> {
    let invalid = || {
        CustomError::BadRequestRegister(RegisterError {
            error: CoreRegisterErrorResponseType::InvalidClientMetadata,
        })
    };
    let extra = payload.additional_metadata();
    let uris = extra
        .post_logout_redirect_uris
        .as_deref()
        .unwrap_or_default();
    if uris.iter().any(|uri| uri.url().fragment().is_some()) {
        return Err(invalid());
    }
    match &extra.backchannel_logout_uri {
        Some(uri) => {
            if let Err(refusal) = policy.guard.check(uri).await {
                warn!(
                    host = uri.host_str().unwrap_or_default(),
                    refusal = ?refusal,
                    "registration: backchannel_logout_uri refused"
                );
                return Err(invalid());
            }
        }
        None if policy.require_backchannel_for_refresh && registration_may_refresh(payload) => {
            return Err(invalid());
        }
        None => {}
    }
    Ok(())
}

/// Whether a registration allows the refresh grant: it lists `refresh_token`
/// in `grant_types`, or lists no `grant_types` at all (provisional).
fn registration_may_refresh(metadata: &SiwxClientMetadata) -> bool {
    metadata
        .grant_types()
        .is_none_or(|grants| grants.contains(&CoreGrantType::RefreshToken))
}

// -- RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) -------------

/// The parameters of `GET`/`POST` [`END_SESSION_PATH`]. `logout_hint` and
/// `ui_locales` are accepted by being ignored.
#[derive(Debug, Default, Deserialize)]
pub struct EndSessionParams {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// The claims end-session reads from a verified `id_token_hint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HintClaims {
    pub sub: String,
    pub aud: Vec<String>,
    pub sid: Option<String>,
}

/// Why an `id_token_hint` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintError {
    /// Not a compact JWS with a JSON header and payload carrying `sub` and `aud`.
    Malformed,
    /// `alg` is not ES256 (`none` and `HS*` included).
    Algorithm,
    /// No `kid`, or one that is neither the live key's nor a retired key's.
    UnknownKid,
    /// The signature does not verify over the received bytes.
    Signature,
    /// `iss` is not this provider.
    Issuer,
}

/// Verify an `id_token_hint`: an ID token this provider signed, with the live
/// key or a retired one, named by its `kid`, over the received bytes, and
/// issued by this provider. Its expiry is NOT checked: RP-Initiated Logout
/// §2 lets an RP send an expired ID token, which still names the session.
pub fn verify_id_token_hint(
    hint: &str,
    signing_key: &EcdsaSigningKey,
    retired: &[CoreJsonWebKey],
    issuer: &IssuerUrl,
) -> Result<HintClaims, HintError> {
    use openidconnect::JsonWebKey;

    let mut parts = hint.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HintError::Malformed);
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| HintError::Malformed)
    };
    let header: serde_json::Value =
        serde_json::from_slice(&decode(header)?).map_err(|_| HintError::Malformed)?;
    if header["alg"] != "ES256" {
        return Err(HintError::Algorithm);
    }
    let kid = header["kid"].as_str().ok_or(HintError::UnknownKid)?;
    let live = signing_key.as_verification_key();
    let key = std::iter::once(&live)
        .chain(retired.iter())
        .find(|k| k.key_id().map(|id| id.as_str()) == Some(kid))
        .ok_or(HintError::UnknownKid)?;
    let signing_input_len = hint.len() - signature.len() - 1;
    key.verify_signature(
        &CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        &hint.as_bytes()[..signing_input_len],
        &decode(signature)?,
    )
    .map_err(|_| HintError::Signature)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode(payload)?).map_err(|_| HintError::Malformed)?;
    if claims["iss"].as_str() != Some(issuer.as_str()) {
        return Err(HintError::Issuer);
    }
    let sub = claims["sub"]
        .as_str()
        .ok_or(HintError::Malformed)?
        .to_string();
    let aud = match &claims["aud"] {
        serde_json::Value::String(one) => vec![one.clone()],
        serde_json::Value::Array(many) => many
            .iter()
            .map(|a| a.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or(HintError::Malformed)?,
        _ => return Err(HintError::Malformed),
    };
    let sid = claims["sid"].as_str().map(str::to_string);
    Ok(HintClaims { sub, aud, sid })
}

/// What end-session answers.
#[derive(Debug, PartialEq, Eq)]
pub enum EndSessionOutcome {
    /// Back to the registered `post_logout_redirect_uri`, `state` appended.
    Redirect(Url),
    /// The signed-out page; `ended` says whether a grant was ended.
    SignedOut { ended: bool },
}

/// A store fault on a sign-out path: retryable, never a pretended success.
pub(crate) fn store_unavailable(e: anyhow::Error) -> CustomError {
    warn!(error = %e, "sign-out: the token store is unavailable");
    CustomError::ServiceUnavailable("The session store is unavailable; retry.".to_string())
}

/// OpenID Connect RP-Initiated Logout 1.0 at [`END_SESSION_PATH`].
///
/// Everything is checked before anything is ended: an `id_token_hint` must be
/// an ID token this provider signed ([`verify_id_token_hint`]; expired is
/// fine); a `client_id` must be the hint's audience; a
/// `post_logout_redirect_uri` must be registered for that client, matched
/// exactly ([`post_logout_redirect_uri_is_registered`]). Any failure is a 400
/// that ends nothing and never redirects, so no unregistered URI is ever a
/// redirect target. Then the grant the hint's `sid` names is ended, if it
/// belongs to the hint's client and `sub` ([`RedisClient::end_grant_by_sid`]):
/// only that grant, never a Matrix device (a device sign-out is the Matrix
/// `logout`; see `compat::TeardownPolicy`). A hint without a `sid` (an ID
/// token issued before grants had one) ends nothing. Back-channel logout of an
/// ended `oidc` grant is enqueued by the deletion script itself (`drop_grant`).
pub async fn end_session(
    params: EndSessionParams,
    signing_key: &EcdsaSigningKey,
    retired: &[CoreJsonWebKey],
    config: &crate::config::Config,
    db_client: &DBClientType,
) -> Result<EndSessionOutcome, CustomError> {
    let issuer = IssuerUrl::from_url(config.base_url.clone());
    let hint = match params.id_token_hint.as_deref().filter(|h| !h.is_empty()) {
        Some(raw) => Some(
            verify_id_token_hint(raw, signing_key, retired, &issuer).map_err(|reason| {
                warn!(?reason, "end_session: id_token_hint refused");
                CustomError::BadRequest(
                    "id_token_hint is not an ID token this provider issued.".to_string(),
                )
            })?,
        ),
        None => None,
    };
    let named_client = params.client_id.as_deref().filter(|c| !c.is_empty());
    let client_id = match (&hint, named_client) {
        (Some(hint), Some(named)) => {
            if !hint.aud.iter().any(|aud| aud == named) {
                warn!(
                    client_id = named,
                    "end_session: client_id is not the hint's audience"
                );
                return Err(CustomError::BadRequest(
                    "client_id does not match the id_token_hint.".to_string(),
                ));
            }
            Some(named.to_string())
        }
        (Some(hint), None) => match hint.aud.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        },
        (None, named) => named.map(str::to_string),
    };

    let redirect = match params
        .post_logout_redirect_uri
        .as_deref()
        .filter(|u| !u.is_empty())
    {
        None => None,
        Some(raw) => {
            let refused = || {
                warn!("end_session: post_logout_redirect_uri is not registered for the client");
                CustomError::BadRequest(
                    "post_logout_redirect_uri is not registered for this client.".to_string(),
                )
            };
            let mut uri = Url::parse(raw).map_err(|_| refused())?;
            let client_id = client_id.as_deref().ok_or_else(refused)?;
            let client = db_client
                .get_client(client_id.to_string())
                .await
                .map_err(store_unavailable)?
                .ok_or_else(refused)?;
            if !post_logout_redirect_uri_is_registered(&client, &uri) {
                return Err(refused());
            }
            if let Some(state) = params.state.as_deref() {
                uri.query_pairs_mut().append_pair("state", state);
            }
            Some(uri)
        }
    };

    let mut ended = false;
    if let (Some(hint), Some(client_id)) = (&hint, client_id.as_deref()) {
        if let Some(sid) = hint.sid.as_deref() {
            match db_client
                .end_grant_by_sid(sid, client_id, &hint.sub)
                .await
                .map_err(store_unavailable)?
            {
                EndedGrant::Ended { grant_id, kind } => {
                    ended = true;
                    info!(grant_fp = %grant_id.fingerprint(), grant_kind = kind.as_str(),
                        client_id, "end_session: grant ended");
                }
                EndedGrant::NotFound => {
                    debug!(client_id, "end_session: no live grant carries the sid")
                }
                EndedGrant::Mismatch => warn!(
                    client_id,
                    "end_session: the sid names a grant of another client or subject; nothing ended"
                ),
            }
        } else {
            debug!(
                client_id,
                "end_session: the hint carries no sid; nothing ended"
            );
        }
    }
    Ok(match redirect {
        Some(uri) => EndSessionOutcome::Redirect(uri),
        None => EndSessionOutcome::SignedOut { ended },
    })
}

/// The page end-session shows when it does not redirect. Reflects no input.
pub fn signed_out_page(ended: bool) -> String {
    let message = if ended {
        "You are signed out: the session has ended."
    } else {
        "Nothing to sign out: no session was named, or it had already ended."
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Signed out</title></head><body><p>{message}</p></body></html>"
    )
}

// -- Client info / update / delete -----------------------------------------

async fn client_access(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<ClientEntry, CustomError> {
    let access_token = if let Some(b) = bearer {
        b.token().to_string()
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };
    let client_entry = db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?;
    if !client_entry.access_token_matches(&access_token) {
        return Err(CustomError::Unauthorized("Bad access token.".to_string()));
    }
    Ok(client_entry)
}

pub async fn clientinfo(
    client_id: String,
    db_client: &DBClientType,
) -> Result<SiwxClientMetadata, CustomError> {
    Ok(db_client
        .get_client(client_id)
        .await?
        .ok_or(CustomError::NotFound)?
        .metadata)
}

pub async fn client_delete(
    client_id: String,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
) -> Result<(), CustomError> {
    client_access(client_id.clone(), bearer, db_client).await?;
    Ok(db_client.delete_client(client_id).await?)
}

pub async fn client_update(
    client_id: String,
    payload: SiwxClientMetadata,
    bearer: Option<Bearer>,
    db_client: &DBClientType,
    policy: &RegistrationPolicy,
) -> Result<(), CustomError> {
    let mut client_entry = client_access(client_id.clone(), bearer, db_client).await?;
    check_logout_metadata(&payload, policy).await?;
    client_entry.metadata = payload;
    Ok(db_client.set_client(client_id, client_entry).await?)
}

// -- UserInfo endpoint -----------------------------------------------------

#[derive(Deserialize)]
pub struct UserInfoPayload {
    pub access_token: Option<String>,
}

/// The provider-specific claims siwx-oidc adds to the standard OIDC userinfo
/// set: today, exactly one — the caller's Matrix ID, on the wire as
/// `io.inblock.mxid`.
///
/// # Why the claim is namespaced, and why it is not called `mxid`
///
/// There is no registered OIDC claim for a Matrix ID (IANA's "JSON Web Token
/// Claims" registry has none, and MSC3861 defines none either), so an
/// unqualified `mxid` would be this provider squatting a bare name in a shared
/// namespace — the collision hazard OIDC Core §5.1.2 tells extensions to avoid
/// with a collision-resistant name. It also matches the profile field the same
/// value can be looked up against
/// ([`crate::did_assertion::DID_PROFILE_FIELD`] = `io.inblock.did`), so the two
/// provider-specific identity surfaces read as one family rather than two
/// conventions.
///
/// The name below is spelled out as a literal rather than referencing a
/// constant because `#[serde(rename = …)]` takes a string literal and cannot
/// interpolate one. There is therefore exactly ONE place the wire name is
/// written, and
/// `userinfo_mxid_claim_tests::the_claim_name_on_the_wire_is_io_inblock_mxid`
/// asserts that literal against a serialized response so a rename shows up as a
/// failing test rather than as a silently-renamed claim.
///
/// # The claim is OMITTED, never null, when there is no Matrix ID
///
/// `skip_serializing_if` rather than a serialized `null`, for the same reason
/// `did_assertion::did_profile_value` omits an absent `proof`: a present key
/// asserts that the thing exists. A standalone deployment (no
/// `SIWEOIDC_MATRIX_SERVER_NAME`) has no Matrix ID to report, and saying
/// `"io.inblock.mxid": null` would make a consumer's `if "io.inblock.mxid" in
/// claims` branch take the wrong turn while looking correct.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SiwxAdditionalClaims {
    /// The caller's fully-qualified Matrix ID, `@localpart:server_name`.
    #[serde(
        rename = "io.inblock.mxid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mxid: Option<String>,
}

impl AdditionalClaims for SiwxAdditionalClaims {}

/// This provider's userinfo claim set: the OIDC Core standard claims plus
/// [`SiwxAdditionalClaims`].
///
/// Replaces `CoreUserInfoClaims` (which pins `EmptyAdditionalClaims`)
/// everywhere `/userinfo` is built or rendered. The standard claims —
/// `iss`, `aud`, `sub`, `preferred_username` — are produced by exactly the same
/// [`resolve_claims`] call as before and are byte-identical; see the note on
/// [`userinfo`].
pub type SiwxUserInfoClaims = UserInfoClaims<SiwxAdditionalClaims, CoreGenderClaim>;

/// The signed-JWT twin of [`SiwxUserInfoClaims`], for clients registered with a
/// `userinfo_signed_response_alg`.
///
/// The claim has to appear in BOTH response variants or a relying party would
/// see a different identity depending on a registration setting it did not
/// think was about identity at all. `openidconnect` 4.0.1 makes
/// `UserInfoJsonWebToken` generic over the additional-claims type (it is a
/// `JsonWebToken<…, UserInfoClaimsImpl<AC, GC>, …>` internally), so the JWT
/// variant needs no special handling beyond naming the same `AC` — only the two
/// JOSE parameters that `CoreUserInfoJsonWebToken` was pinning for us have to be
/// restated here.
pub type SiwxUserInfoJsonWebToken = UserInfoJsonWebToken<
    SiwxAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub enum UserInfoResponse {
    Json(SiwxUserInfoClaims),
    Jwt(SiwxUserInfoJsonWebToken),
}

/// Build the `io.inblock.mxid` claim from a localpart this request ALREADY has
/// in hand.
///
/// # No Synapse round trip, on purpose
///
/// `TokenMetadata.username` is the localpart `localpart::resolve_identity`
/// resolved at sign-in — the grandfathering decision has already been made and
/// recorded. Re-deriving it here would risk contradicting it (a grandfathered
/// legacy account would be handed the modern shape), and probing Synapse would
/// put a network call on a hot, read-only endpoint to recompute a value the
/// struct already carries.
///
/// # Both "omit" cases are honest
///
/// - `server_name = None` — a standalone deployment. There is no homeserver, so
///   there is no Matrix ID; a guessed one would name an account on a server that
///   does not exist.
/// - an empty `localpart` — the token records no localpart. The claim is then
///   omitted, never derived from the DID: `legacy_localpart(did)` is a fallback
///   for PROVISIONING continuity, where the alternative is severing a user from
///   their account. This is not that: a userinfo claim is a statement of fact
///   to a relying party, and the honest answer to "which localpart did we
///   resolve for this session" is "this token does not record one". An omitted
///   claim degrades a consumer to the lookup it would have done anyway
///   (`GET /resolve?did=…`, see [`crate::resolve`]); a derived one could quietly
///   name the wrong account. `@:server` would not be a Matrix ID either, but a
///   parse error waiting at the consumer.
fn mxid_claim(config: &crate::config::Config, localpart: &str) -> SiwxAdditionalClaims {
    let mxid = match config.matrix_server_name.as_deref() {
        Some(server_name) if !localpart.is_empty() => Some(crate::synapse_client::matrix_user_id(
            localpart,
            server_name,
        )),
        _ => None,
    };
    SiwxAdditionalClaims { mxid }
}

/// `GET|POST /userinfo`.
///
/// # `sub` and `preferred_username` are UNCHANGED
///
/// Both still come from [`resolve_claims`] and both are still the DID. The
/// `io.inblock.mxid` claim is purely ADDITIVE: anything already reading `sub` (the
/// only authorization-bearing claim here) or `preferred_username` is
/// byte-for-byte unaffected, and nothing in this function may ever be
/// "simplified" into replacing one of them with the Matrix ID — the three-tier
/// identity model (see `docs/identity-model.md`) exists precisely because a consumer that
/// reads a Matrix identifier where it expected a DID, or the reverse, resolves
/// the wrong account.
pub async fn userinfo(
    config: &crate::config::Config,
    signing_key: &EcdsaSigningKey,
    bearer: Option<Bearer>,
    payload: UserInfoPayload,
    db_client: &DBClientType,
) -> Result<UserInfoResponse, CustomError> {
    let token_str = if let Some(b) = bearer {
        b.token().to_string()
    } else if let Some(c) = payload.access_token {
        c
    } else {
        return Err(CustomError::BadRequest("Missing access token.".to_string()));
    };

    // Only an access token is a bearer credential (MSC3861 `mat_` tokens and
    // standalone tokens alike). An authorization code, a refresh token and an
    // unknown string all get the same answer: a code is redeemable only at the
    // token endpoint, with its PKCE verifier.
    let metadata = db_client
        .check_access_token(&token_str)
        .await?
        .ok_or_else(|| CustomError::BadRequest("Unknown token.".to_string()))?;
    if metadata.exp <= Utc::now().timestamp() {
        return Err(CustomError::BadRequest("Token expired.".to_string()));
    }
    let client_entry = db_client
        .get_client(metadata.client_id.clone())
        .await?
        .ok_or_else(|| CustomError::BadRequest("Unknown client.".to_string()))?;
    // `metadata.username` IS the localpart (see `TokenMetadata::username`),
    // already resolved through the grandfathering rule at sign-in.
    let additional = mxid_claim(config, &metadata.username);
    let response = SiwxUserInfoClaims::new(resolve_claims(config, &metadata.did).await, additional)
        .set_issuer(Some(IssuerUrl::from_url(config.base_url.clone())))
        .set_audiences(Some(vec![Audience::new(metadata.client_id)]));
    match client_entry.metadata.userinfo_signed_response_alg() {
        None => Ok(UserInfoResponse::Json(response)),
        Some(alg) => Ok(UserInfoResponse::Jwt(
            SiwxUserInfoJsonWebToken::new(response, signing_key, alg.clone())
                .map_err(|_| anyhow!("Error signing response."))?,
        )),
    }
}

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    use aqua_auth::{address_from_verifying_key, eip55_checksum};
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use sha3::{Digest, Keccak256};
    use test_log::test;

    // -- Signing key identity (H4/H5) -------------------------------------
    //
    // These pin the property the whole DID-assertion feature rests on: a `kid`
    // names a KEY, so a key swap is diagnosable. See the `EcdsaSigningKey` doc.

    /// H4: two independently generated keys must NOT share a `kid`.
    ///
    /// The regression this catches is the old behaviour verbatim — both
    /// constructors were handed the literal `"key1"`, so a restart produced a
    /// different key under an identical `kid` and every durably-stored
    /// assertion started failing as "bad signature" (indistinguishable from
    /// forgery) instead of "unknown kid" (obviously a key rotation).
    #[test]
    fn h4_two_generated_keys_get_different_kids() {
        let a = EcdsaSigningKey::generate();
        let b = EcdsaSigningKey::generate();
        assert_ne!(
            a.kid(),
            b.kid(),
            "independently generated keys must not share a kid"
        );
        assert_eq!(a.kid(), a.public_key_fingerprint());
        assert_eq!(
            a.kid().len(),
            16,
            "kid is the first 16 hex chars of SHA-256 over the SEC1 public key"
        );
        assert!(a.kid().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// H4, the other half: the `kid` is a pure function of the key, so the SAME
    /// PEM yields the SAME `kid` across constructions — which is what makes a
    /// restart with a configured key a no-op for previously issued assertions.
    #[test]
    fn h4_the_same_pem_yields_the_same_kid_across_constructions() {
        let pem = crate::did_assertion::test_p256_pem();
        let first = EcdsaSigningKey::from_pem(&pem).expect("test PEM must load");
        let second = EcdsaSigningKey::from_pem(&pem).expect("test PEM must load");
        assert_eq!(
            first.kid(),
            second.kid(),
            "the same PEM must always produce the same kid"
        );

        // And it really is key-derived, not a constant: a different PEM differs.
        let other = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        assert_ne!(first.kid(), other.kid());
    }

    /// H5 at the key layer: provenance is recorded, and it is the PEM (operator
    /// intent to persist) that marks a key durable.
    #[test]
    fn h5_generated_keys_are_ephemeral_and_pem_keys_are_durable() {
        assert!(
            EcdsaSigningKey::generate().is_ephemeral(),
            "a generated key dies with the process and must say so"
        );
        assert!(
            !EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
                .expect("test PEM must load")
                .is_ephemeral(),
            "a configured PEM is the operator asserting the key persists"
        );
    }

    /// The JWKS a relying party fetches must always carry a `kid`; without one,
    /// a verifier has to trial-verify against every published key and the
    /// "unknown kid" diagnostic disappears.
    #[test]
    fn published_jwk_always_carries_the_derived_kid() {
        use openidconnect::JsonWebKey;
        for key in [
            EcdsaSigningKey::generate(),
            EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem()).unwrap(),
        ] {
            let jwk = key.as_verification_key();
            assert_eq!(
                jwk.key_id().map(|k| k.as_str().to_string()),
                Some(key.kid().to_string()),
                "every published JWK must carry the key-derived kid"
            );
        }
    }

    // -- D2 (2026-09-10 audit): retired signing keys stay in the JWKS -------
    //
    // A DID assertion is stored durably in a user's Synapse profile with no
    // `exp`, and its only verification anchor is this provider's JWKS. Before
    // this, the JWKS held exactly one key — the live one — so rotating
    // `SIWEOIDC_SIGNING_KEY_PEM` made every proof ever written permanently
    // unverifiable. Dev's signing key was exposed on 2026-09-09, and rotation
    // is the correct response to that, so this is a real path, not a thought
    // experiment.

    /// The public half of a private PEM, in the SPKI form the config accepts.
    fn public_pem_of(private_pem: &str) -> String {
        use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        p256::SecretKey::from_pkcs8_pem(private_pem)
            .expect("test PEM must load")
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("P-256 public key always encodes to SPKI PEM")
    }

    /// THE invariant of the whole feature: a retired key's published `kid` is
    /// **byte-identical** to the `kid` it had while live.
    ///
    /// A stored proof carries the `kid` its signer had at mint time, and a
    /// verifier resolves it against the JWKS by that exact string. If the two
    /// derivations ever diverge by one byte, every retired proof stays
    /// unverifiable while the JWKS *looks* correct — the failure surfaces in
    /// somebody else's consumer, long after the rotation, as "unknown kid".
    /// This is why `fingerprint_of_public` is single-sourced.
    #[test]
    fn a_retired_key_keeps_the_exact_kid_it_had_while_live() {
        use openidconnect::JsonWebKey;
        let private_pem = crate::did_assertion::test_p256_pem();
        let live = EcdsaSigningKey::from_pem(&private_pem).expect("test PEM must load");
        let live_kid = live.kid().to_string();

        let retired = parse_retired_verification_keys(&public_pem_of(&private_pem))
            .expect("the public half of a valid signing key must parse");

        assert_eq!(retired.len(), 1);
        assert_eq!(
            retired[0].key_id().map(|k| k.as_str().to_string()),
            Some(live_kid),
            "a retired key MUST publish the same kid it published while live, or every \
             already-stored proof becomes unresolvable"
        );
    }

    /// The retired JWK must be byte-identical to what the live key published,
    /// not merely carry the same `kid`: `crv`/`use`/`alg`/`x`/`y` all matter to
    /// a strict verifier, and a retired key is supposed to be indistinguishable
    /// from its pre-rotation self.
    #[test]
    fn a_retired_jwk_is_identical_to_what_the_live_key_published() {
        let private_pem = crate::did_assertion::test_p256_pem();
        let live = EcdsaSigningKey::from_pem(&private_pem).expect("test PEM must load");
        let retired = parse_retired_verification_keys(&public_pem_of(&private_pem)).unwrap();

        assert_eq!(
            serde_json::to_value(&retired[0]).unwrap(),
            serde_json::to_value(live.as_verification_key()).unwrap(),
            "the retired JWK must be the same document the live key published"
        );
    }

    /// The end-to-end shape an operator gets after a rotation: the NEW key
    /// signs, and BOTH kids are published.
    #[test]
    fn after_rotation_the_jwks_carries_both_the_live_and_the_retired_kid() {
        use openidconnect::JsonWebKey;
        let old_pem = crate::did_assertion::test_p256_pem();
        let old_key = EcdsaSigningKey::from_pem(&old_pem).unwrap();
        let new_key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem()).unwrap();

        let retired = parse_retired_verification_keys(&public_pem_of(&old_pem)).unwrap();
        let set = jwks(&new_key, &retired).expect("jwks must build");
        let kids: Vec<String> = set
            .keys()
            .iter()
            .filter_map(|k| k.key_id().map(|i| i.as_str().to_string()))
            .collect();

        assert_eq!(
            kids,
            vec![new_key.kid().to_string(), old_key.kid().to_string()],
            "the live key comes first, the retired key follows"
        );
    }

    /// With no retired keys configured, the JWKS is exactly what it was before
    /// this feature: one key, the live one. The feature is inert until used.
    #[test]
    fn no_retired_keys_publishes_exactly_the_live_key() {
        let key = EcdsaSigningKey::generate();
        let set = jwks(&key, &[]).expect("jwks must build");
        assert_eq!(set.keys().len(), 1);
    }

    /// The operationally likely mistake: an operator leaves the still-live key
    /// in the retired list (or lists the same retired key twice). A `kid`
    /// published twice invites a verifier to take the first match and stop, so
    /// duplicates are collapsed rather than emitted.
    #[test]
    fn a_duplicated_kid_is_published_once() {
        let pem = crate::did_assertion::test_p256_pem();
        let key = EcdsaSigningKey::from_pem(&pem).unwrap();
        let public = public_pem_of(&pem);
        // The live key listed as retired, twice over.
        let retired = parse_retired_verification_keys(&format!("{public}\n{public}")).unwrap();
        assert_eq!(retired.len(), 2, "the parser itself does not de-duplicate");

        let set = jwks(&key, &retired).expect("jwks must build");
        assert_eq!(
            set.keys().len(),
            1,
            "the live key must not be republished under its own kid"
        );
    }

    /// Several retired keys in one bundle, with prose between them — the shape
    /// an operator actually writes after two rotations, annotating which key is
    /// which.
    #[test]
    fn multiple_retired_keys_parse_with_comments_between_them() {
        let a = public_pem_of(&crate::did_assertion::test_p256_pem());
        let b = public_pem_of(&crate::did_assertion::test_p256_pem());
        let bundle = format!("# retired 2026-09-09 (exposed)\n{a}\n# retired 2026-06-01\n{b}\n");
        let keys = parse_retired_verification_keys(&bundle).expect("both blocks must parse");
        assert_eq!(keys.len(), 2);
    }

    /// A PRIVATE key is refused, with the fix in the message.
    ///
    /// Not fussiness: a retired key never signs, so the private half grants a
    /// capability nothing needs, and the motivating case is a key that was
    /// COMPROMISED. Accepting it would make "keep the compromised secret in the
    /// environment forever" the path of least resistance, where any bare
    /// `printenv` in the container prints it whole.
    #[test]
    fn a_private_key_is_refused_with_the_openssl_fix() {
        let err = parse_retired_verification_keys(&crate::did_assertion::test_p256_pem())
            .expect_err("a private key must never be accepted as a retired key")
            .to_string();
        assert!(
            err.contains("PRIVATE"),
            "the message must name the problem: {err}"
        );
        assert!(
            err.contains("openssl pkey"),
            "the message must carry the one-line fix: {err}"
        );
    }

    /// Garbage fails LOUD rather than being skipped.
    ///
    /// Silently dropping a bad entry would boot a server that cannot verify the
    /// very artifacts this config exists to keep verifiable, with the cause
    /// buried in a startup log. Both shapes of "bad" are covered: no PEM block
    /// at all, and a block that is not a P-256 SPKI key.
    #[test]
    fn malformed_retired_keys_are_a_hard_error_never_a_skip() {
        let err = parse_retired_verification_keys("not a pem at all")
            .expect_err("a bundle with no PEM block must be an error, not an empty Vec")
            .to_string();
        assert!(err.contains("BEGIN PUBLIC KEY"), "{err}");

        let err = parse_retired_verification_keys(
            "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n",
        )
        .expect_err("a well-armoured non-key must be an error")
        .to_string();
        assert!(err.contains("P-256"), "{err}");

        let err = parse_retired_verification_keys("-----BEGIN PUBLIC KEY-----\nabc\n")
            .expect_err("a truncated block must be an error")
            .to_string();
        assert!(err.contains("truncated"), "{err}");
    }

    /// `None` after a loud skip when Redis is unavailable (`siwx_oidc::test_support`).
    async fn default_config() -> Option<(Config, RedisClient)> {
        let config = Config::default();
        let db_client = siwx_oidc::test_support::redis().await?;
        db_client
            .set_client(
                "client".into(),
                ClientEntry::new(
                    "secret",
                    SiwxClientMetadata::new(
                        vec![RedirectUrl::new("https://example.com".into()).unwrap()],
                        LogoutClientMetadata::default(),
                    ),
                    None,
                ),
            )
            .await
            .unwrap();
        Some((config, db_client))
    }

    fn config_no_ens() -> Config {
        Config {
            ens_api_url: None,
            eth_provider: None,
            ..Config::default()
        }
    }

    #[test(tokio::test)]
    async fn test_claims_without_ens() {
        // Without ENS config, preferred_username is always the full DID.
        let did = "did:pkh:eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let config = config_no_ens();
        let res = resolve_claims(&config, did).await;
        assert_eq!(
            res.preferred_username().map(|u| u.to_string()),
            Some(did.to_string())
        );
        // No ENS resolution → name claim should be absent.
        assert!(res.name().is_none());
    }

    #[test(tokio::test)]
    async fn test_claims_non_eip155() {
        // Non-eip155 DID — preferred_username is the full DID, no ENS attempt.
        let did = "did:pkh:ed25519:0xabcdef1234567890";
        let config = config_no_ens();
        let res = resolve_claims(&config, did).await;
        assert_eq!(
            res.preferred_username().map(|u| u.to_string()),
            Some(did.to_string())
        );
    }

    #[derive(Deserialize)]
    struct AuthorizeQueryParams {
        nonce: String,
    }

    /// The PKCE example pair from RFC 7636, Appendix B.
    const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn code_request(response_type: CoreResponseType) -> AuthorizeParams {
        AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::new("https://example.com".into()).unwrap(),
            scope: Scope::new("openid".to_string()),
            response_type: Some(response_type),
            state: Some("state".into()),
            nonce: Some(Nonce::new("oidc-nonce".into())),
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some(RFC7636_CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        }
    }

    /// `authorize` refuses every response type but `code`, back to the
    /// validated redirect URI with `unsupported_response_type` and the state.
    #[tokio::test]
    async fn authorize_refuses_every_response_type_but_code() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        for response_type in [
            CoreResponseType::IdToken,
            CoreResponseType::Token,
            CoreResponseType::None,
        ] {
            match authorize(code_request(response_type.clone()), &db_client).await {
                Err(CustomError::Redirect(url)) => {
                    let url = Url::parse(&url).unwrap();
                    let q: std::collections::HashMap<_, _> = url.query_pairs().collect();
                    assert_eq!(url.host_str(), Some("example.com"), "{url}");
                    assert_eq!(
                        q.get("error").map(|v| v.as_ref()),
                        Some("unsupported_response_type"),
                        "{url}"
                    );
                    assert_eq!(q.get("state").map(|v| v.as_ref()), Some("state"), "{url}");
                }
                other => panic!("{response_type:?} must be refused, got {other:?}"),
            }
        }
    }

    /// `authorize` binds the validated request to the session it starts.
    #[tokio::test]
    async fn authorize_binds_the_request_to_the_session() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let mut params = code_request(CoreResponseType::Code);
        params.response_mode = Some("fragment".into());
        let (_url, cookie) = authorize(params, &db_client).await.unwrap();
        let session = db_client
            .get_session(cookie.value().to_string())
            .await
            .unwrap()
            .expect("authorize stores the session");
        assert_eq!(
            session.request,
            Some(AuthorizationRequest {
                client_id: "client".into(),
                redirect_uri: "https://example.com".into(),
                state: "state".into(),
                response_mode: Some("fragment".into()),
                code_challenge: RFC7636_CHALLENGE.into(),
                scope: Some("openid".into()),
                nonce: Some(Nonce::new("oidc-nonce".into())),
            })
        );
    }

    fn session_with(request: Option<AuthorizationRequest>) -> SessionEntry {
        SessionEntry {
            siwe_nonce: "n".into(),
            secret: "s".into(),
            signin_count: 0,
            verified_did: None,
            request,
        }
    }

    const ROUND_TRIP_REDIRECT: &str = "https://example.com/callback?a=1&b=2";
    const ROUND_TRIP_STATE: &str = "st+a&b c";

    async fn seed_round_trip_client(db: &RedisClient, client_id: &str) {
        db.set_client(
            client_id.to_string(),
            ClientEntry::new(
                "secret",
                SiwxClientMetadata::new(
                    vec![RedirectUrl::new(ROUND_TRIP_REDIRECT.into()).unwrap()],
                    LogoutClientMetadata::default(),
                ),
                None,
            ),
        )
        .await
        .unwrap();
    }

    /// `authorize` hands the login page every value percent-encoded, so the
    /// page reads back the exact redirect URI (which its CAIP-122 message
    /// binds) and state, even with several query parameters or `&` and `+`.
    #[tokio::test]
    async fn authorize_hands_the_login_page_the_exact_values() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let client_id = format!("round-trip-{}", Uuid::new_v4().simple());
        seed_round_trip_client(&db_client, &client_id).await;
        let mut params = code_request(CoreResponseType::Code);
        params.client_id = client_id.clone();
        params.redirect_uri = RedirectUrl::new(ROUND_TRIP_REDIRECT.into()).unwrap();
        params.state = Some(ROUND_TRIP_STATE.into());
        let (page_url, _cookie) = authorize(params, &db_client).await.unwrap();
        let page = Url::parse(&format!("https://login.example{page_url}")).unwrap();
        let q: std::collections::HashMap<_, _> = page.query_pairs().into_owned().collect();
        assert_eq!(
            q.get("redirect_uri").map(String::as_str),
            Some(ROUND_TRIP_REDIRECT)
        );
        assert_eq!(q.get("state").map(String::as_str), Some(ROUND_TRIP_STATE));
        assert_eq!(q.get("client_id"), Some(&client_id));
        assert_eq!(q.get("oidc_nonce").map(String::as_str), Some("oidc-nonce"));
        assert_eq!(
            q.get("code_challenge").map(String::as_str),
            Some(RFC7636_CHALLENGE)
        );
        assert_eq!(
            q.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(
            !q.contains_key("response_mode"),
            "query mode is not forwarded"
        );
    }

    /// `sign_in` reads no authorization parameter from its query (it takes
    /// none): the code goes to the bound redirect URI with the bound state, and
    /// the stored code carries the bound client, challenge, nonce and scope.
    #[tokio::test]
    async fn sign_in_issues_the_code_for_the_bound_request() {
        sign_in_round_trip(false).await;
    }

    /// The same for a session a build before Phase 2b started (it lives 300 s):
    /// stored under its raw id, with the scope and the OIDC nonce beside the
    /// bound request. Its code carries both, as before the upgrade.
    #[tokio::test]
    async fn a_session_the_previous_build_bound_issues_its_code_with_its_scope_and_nonce() {
        sign_in_round_trip(true).await;
    }

    async fn sign_in_round_trip(previous_build: bool) {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let nonce = Uuid::new_v4().simple().to_string();
        let client_id = format!("round-trip-{nonce}");
        seed_round_trip_client(&db_client, &client_id).await;
        let session_id = format!("round-trip-{nonce}");
        if previous_build {
            // Exactly the JSON 88027dc serialized for this session.
            let stored = serde_json::json!({
                "siwe_nonce": nonce,
                "oidc_nonce": "oidc-nonce",
                "secret": "secret",
                "signin_count": 0,
                "verified_did": "did:key:zDnaeBOUNDREQUEST",
                "scope": "openid profile offline_access",
                "request": {
                    "client_id": client_id,
                    "redirect_uri": ROUND_TRIP_REDIRECT,
                    "state": ROUND_TRIP_STATE,
                    "response_mode": null,
                    "code_challenge": RFC7636_CHALLENGE,
                },
            });
            db_client
                .set_ex_raw(&format!("sessions/{session_id}"), &stored.to_string(), 300)
                .await
                .unwrap();
        } else {
            db_client
                .set_session(
                    session_id.clone(),
                    SessionEntry {
                        siwe_nonce: nonce.clone(),
                        secret: "secret".into(),
                        signin_count: 0,
                        verified_did: Some("did:key:zDnaeBOUNDREQUEST".into()),
                        request: Some(AuthorizationRequest {
                            client_id: client_id.clone(),
                            redirect_uri: ROUND_TRIP_REDIRECT.into(),
                            state: ROUND_TRIP_STATE.into(),
                            response_mode: None,
                            code_challenge: RFC7636_CHALLENGE.into(),
                            scope: Some("openid profile offline_access".into()),
                            nonce: Some(Nonce::new("oidc-nonce".into())),
                        }),
                    },
                )
                .await
                .unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={session_id}")).unwrap(),
        );
        let (url, _did) = sign_in(
            &Url::parse("https://example.com").unwrap(),
            &["key".to_string()],
            &[],
            headers.typed_get::<headers::Cookie>().unwrap(),
            &db_client,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(
            url.as_str()
                .starts_with(&format!("{ROUND_TRIP_REDIRECT}&code=")),
            "the code goes to the bound redirect URI: {url}"
        );
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q.get("a").map(String::as_str), Some("1"));
        assert_eq!(q.get("b").map(String::as_str), Some("2"));
        assert_eq!(q.get("state").map(String::as_str), Some(ROUND_TRIP_STATE));
        let entry = db_client
            .try_consume_code(q["code"].clone())
            .await
            .unwrap()
            .expect("the code is stored");
        assert_eq!(entry.client_id, client_id);
        assert_eq!(entry.code_challenge.as_deref(), Some(RFC7636_CHALLENGE));
        assert_eq!(entry.code_challenge_method.as_deref(), Some("S256"));
        assert_eq!(
            entry.nonce.as_ref().map(|n| n.secret().as_str()),
            Some("oidc-nonce")
        );
        assert_eq!(
            entry.scope.as_deref(),
            Some("openid profile offline_access"),
            "the scope /authorize bound to the session travels into the code, \
             where the token endpoint reads what was requested"
        );
    }

    /// A session written by an older build carries no bound request; the
    /// sign-in is refused with a clear "restart" error.
    #[test]
    fn a_session_without_a_bound_request_is_refused() {
        match bound_request(&session_with(None)) {
            Err(CustomError::BadRequest(msg)) => assert!(msg.contains("Restart"), "{msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[derive(Deserialize)]
    struct SignInQueryParams {
        code: String,
    }

    /// EIP-191 sign helper — mirrors Eip155Suite::verify's prehash logic.
    fn eth_sign(key: &k256::ecdsa::SigningKey, msg: &str) -> String {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(rec_id) + 27;
        format!("0x{}", hex::encode(bytes))
    }

    #[tokio::test]
    async fn e2e_flow() {
        let Some((config, db_client)) = default_config().await else {
            return;
        };

        // Generate an eip155 keypair (same approach as Eip155Suite tests).
        let secret = k256::SecretKey::random(&mut rand::thread_rng());
        let signing_key = k256::ecdsa::SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let address_str = format!("0x{}", eip55_checksum(&addr));
        let did = format!("did:pkh:eip155:1:{address_str}");

        let base_url = Url::parse("https://example.com").unwrap();
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(base_url.clone()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some(RFC7636_CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();

        // Build the CAIP-122 message (EIP-4361 format for eip155). The login
        // path now enforces the Expiration Time (C1 safe subset), so include a
        // future exp — exactly as the real frontend already does.
        let expiration_time =
            (Utc::now() + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let message = format!(
            "example.com wants you to sign in with your Ethereum account:\n\
             {address_str}\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: {}\n\
             Issued At: 2023-04-17T11:01:24.862Z\n\
             Expiration Time: {expiration_time}\n\
             Resources:\n\
             - https://example.com",
            authorize_params.nonce,
        );
        let signature = eth_sign(&signing_key, &message);
        let siwx_cookie = serde_json::to_string(&SiwxCookie {
            did,
            message,
            signature,
        })
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{cookie}; {SIWX_COOKIE_KEY}={siwx_cookie}")).unwrap(),
        );
        let cookie = headers.typed_get::<headers::Cookie>().unwrap();
        let default_methods = vec!["pkh".to_string()];
        let default_namespaces = vec![
            "eip155".to_string(),
            "ed25519".to_string(),
            "p256".to_string(),
        ];
        let (redirect_url, _did) = sign_in(
            &base_url,
            &default_methods,
            &default_namespaces,
            cookie,
            &db_client,
            None, // no synapse_client in tests
            None, // no matrix_server_name in tests
            None, // DID publication is off: no Synapse to publish into
        )
        .await
        .unwrap();
        // Default (no response_mode): query delivery, never a fragment.
        assert!(
            redirect_url.fragment().is_none(),
            "default sign_in redirect must not carry a fragment: {redirect_url}"
        );
        let signin_params: SignInQueryParams =
            serde_urlencoded::from_str(redirect_url.query().unwrap()).unwrap();
        let oidc_signing_key = EcdsaSigningKey::generate();
        // The code is not a bearer token: /userinfo refuses it.
        assert!(
            userinfo(
                &config,
                &oidc_signing_key,
                None,
                UserInfoPayload {
                    access_token: Some(signin_params.code.clone()),
                },
                &db_client,
            )
            .await
            .is_err(),
            "/userinfo must refuse an authorization code"
        );
        // It is exchanged at the token endpoint, and the access token from the
        // exchange is accepted at /userinfo.
        let tokens = token(
            TokenForm {
                code: Some(signin_params.code),
                client_id: Some("client".into()),
                client_secret: Some("secret".into()),
                grant_type: CoreGrantType::AuthorizationCode,
                code_verifier: Some(RFC7636_VERIFIER.into()),
                refresh_token: None,
                device_code: None,
            },
            ClientCredentials::default(),
            &oidc_signing_key,
            &config,
            &db_client,
            None,
        )
        .await
        .unwrap();
        let _ = userinfo(
            &config,
            &oidc_signing_key,
            None,
            UserInfoPayload {
                access_token: Some(
                    openidconnect::OAuth2TokenResponse::access_token(&tokens)
                        .secret()
                        .clone(),
                ),
            },
            &db_client,
        )
        .await
        .unwrap();
    }

    /// js-sdk v42 path: authorize with `response_mode=fragment` forwards the
    /// mode to the SPA, and sign_in delivers `#code=…&state=…` with NO query
    /// residue (v42 reads the authorization response ONLY from the fragment).
    #[tokio::test]
    async fn e2e_flow_fragment_response_mode() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };

        let secret = k256::SecretKey::random(&mut rand::thread_rng());
        let signing_key = k256::ecdsa::SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let address_str = format!("0x{}", eip55_checksum(&addr));
        let did = format!("did:pkh:eip155:1:{address_str}");

        let base_url = Url::parse("https://example.com").unwrap();
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(base_url.clone()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some(RFC7636_CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("fragment".into()),
        };
        let (redirect_url, cookie) = authorize(params, &db_client).await.unwrap();
        assert!(
            redirect_url.contains("&response_mode=fragment"),
            "authorize must forward response_mode to the SPA: {redirect_url}"
        );
        let authorize_params: AuthorizeQueryParams =
            serde_urlencoded::from_str(redirect_url.split("/?").collect::<Vec<&str>>()[1]).unwrap();

        let expiration_time =
            (Utc::now() + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let message = format!(
            "example.com wants you to sign in with your Ethereum account:\n\
             {address_str}\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: {}\n\
             Issued At: 2023-04-17T11:01:24.862Z\n\
             Expiration Time: {expiration_time}\n\
             Resources:\n\
             - https://example.com",
            authorize_params.nonce,
        );
        let signature = eth_sign(&signing_key, &message);
        let siwx_cookie = serde_json::to_string(&SiwxCookie {
            did,
            message,
            signature,
        })
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{cookie}; {SIWX_COOKIE_KEY}={siwx_cookie}")).unwrap(),
        );
        let cookie = headers.typed_get::<headers::Cookie>().unwrap();
        let (redirect_url, _did) = sign_in(
            &base_url,
            &["pkh".to_string()],
            &["eip155".to_string()],
            cookie,
            &db_client,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            redirect_url.query().is_none(),
            "fragment mode must leave the redirect query untouched: {redirect_url}"
        );
        let fragment = redirect_url
            .fragment()
            .expect("fragment mode must deliver the response in the fragment");
        assert!(
            fragment.contains("code="),
            "fragment must carry the code: {redirect_url}"
        );
        assert!(
            fragment.contains("state=state"),
            "fragment must carry the state: {redirect_url}"
        );
    }

    /// Redirect URIs match the registration exactly, query included.
    #[test]
    fn redirect_uri_matching_is_exact() {
        let client = |registered: &str| {
            ClientEntry::new(
                "secret",
                SiwxClientMetadata::new(
                    vec![RedirectUrl::new(registered.into()).unwrap()],
                    LogoutClientMetadata::default(),
                ),
                None,
            )
        };
        let uri = |u: &str| RedirectUrl::new(u.into()).unwrap();

        let plain = client("https://example.com/cb");
        assert!(redirect_uri_is_registered(
            &plain,
            &uri("https://example.com/cb")
        ));
        assert!(!redirect_uri_is_registered(
            &plain,
            &uri("https://example.com/cb?x=1")
        ));
        assert!(!redirect_uri_is_registered(
            &plain,
            &uri("https://example.com/cb/x")
        ));
        assert!(!redirect_uri_is_registered(
            &plain,
            &uri("https://example.com/cb#x")
        ));

        let with_query = client("https://example.com/?no_universal_links=true");
        assert!(redirect_uri_is_registered(
            &with_query,
            &uri("https://example.com/?no_universal_links=true")
        ));
        assert!(!redirect_uri_is_registered(
            &with_query,
            &uri("https://example.com/")
        ));
        assert!(!redirect_uri_is_registered(
            &with_query,
            &uri("https://example.com/?no_universal_links=true&x=1")
        ));
    }

    #[tokio::test]
    async fn authorize_rejects_unsupported_response_mode() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("form_post".into()),
        };
        match authorize(params, &db_client).await {
            Err(CustomError::BadRequest(msg)) => {
                assert!(
                    msg.contains("form_post"),
                    "rejection must name the bad value: {msg}"
                );
            }
            other => panic!("expected BadRequest for response_mode=form_post, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_accepts_query_response_mode_without_forwarding() {
        // Explicit "query" is valid but default: the SPA URL stays byte-identical
        // to the absent-param case (nothing forwarded).
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("openid".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: Some("query".into()),
        };
        let (redirect_url, _cookie) = authorize(params, &db_client).await.unwrap();
        assert!(
            !redirect_url.contains("response_mode"),
            "explicit query mode must not be forwarded: {redirect_url}"
        );
    }

    /// A config whose issuer is `https://siwx-oidc.example.com/`; everything
    /// else keeps its default (standalone mode, no legal URIs).
    fn discovery_config() -> Config {
        Config {
            base_url: Url::parse("https://siwx-oidc.example.com/").unwrap(),
            ..Config::default()
        }
    }

    #[test]
    fn provider_metadata_advertises_response_modes() {
        // js-sdk v42 `isValidAuthMetadata` hard-requires both modes.
        let value = provider_metadata_value(&discovery_config(), false).unwrap();
        assert_eq!(
            value["response_modes_supported"],
            serde_json::json!(["query", "fragment"])
        );
    }

    #[tokio::test]
    async fn authorize_accepts_matrix_scopes() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(
                Url::parse("https://example.com").unwrap(),
            ),
            scope: Scope::new(
                "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEF".to_string(),
            ),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            // C2 Step 4a: PKCE is mandatory for the code flow — a valid S256
            // challenge so this scope-acceptance test exercises the real path.
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_ok(),
            "authorize must accept Matrix scopes: {:?}",
            result.err()
        );
    }

    #[test]
    fn discovery_metadata_contains_matrix_scopes() {
        let pm = metadata(&discovery_config()).unwrap();
        let json = serde_json::to_value(&pm).unwrap();
        let scopes = json["scopes_supported"]
            .as_array()
            .expect("scopes_supported must be an array");
        let scope_strings: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();

        // Core OIDC scopes
        assert!(scope_strings.contains(&"openid"), "missing openid");
        assert!(scope_strings.contains(&"profile"), "missing profile");

        // Stable Matrix scopes
        assert!(
            scope_strings.contains(&"urn:matrix:client:api:*"),
            "missing stable urn:matrix:client:api:*"
        );
        assert!(
            scope_strings.contains(&"urn:matrix:client:device:*"),
            "missing stable urn:matrix:client:device:*"
        );

        // MSC2967 unstable Matrix scopes (used by Element X)
        assert!(
            scope_strings.contains(&"urn:matrix:org.matrix.msc2967.client:api:*"),
            "missing unstable urn:matrix:org.matrix.msc2967.client:api:*"
        );
        assert!(
            scope_strings.contains(&"urn:matrix:org.matrix.msc2967.client:device:*"),
            "missing unstable urn:matrix:org.matrix.msc2967.client:device:*"
        );
    }

    /// The OIDC `sub` is the user's DID, the same value for every client
    /// (`docs/identity-model.md`), which is the definition of a *public*
    /// subject type. Discovery used to say `pairwise`, which promises a
    /// different `sub` per client and would lead a relying party to expect one.
    #[test]
    fn discovery_advertises_public_subjects_only() {
        let value = provider_metadata_value(&discovery_config(), true).unwrap();
        assert_eq!(
            value["subject_types_supported"],
            serde_json::json!(["public"]),
            "the sub is the DID, identical for every client"
        );
    }

    /// `POST /token` reads the client secret from an `Authorization: Basic`
    /// header (`client_secret_basic`), from the form (`client_secret_post`), and
    /// accepts a public client with no secret (`none`). Discovery lists what
    /// the endpoint implements, so a client that picks the RFC 8414 default
    /// (`client_secret_basic`) finds it.
    #[test]
    fn discovery_advertises_every_client_authentication_method_the_token_endpoint_accepts() {
        let value = provider_metadata_value(&discovery_config(), true).unwrap();
        assert_eq!(
            value["token_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "client_secret_post", "none"]),
        );
    }

    #[test]
    fn provider_metadata_advertises_msc4191_account_management() {
        // AC1: served metadata must include account_management_uri and an
        // account_management_actions_supported array containing the four real
        // actions plus their session_* aliases. Synapse forwards this document
        // verbatim to /_matrix/client/v1/auth_metadata (verified live).
        let value = provider_metadata_value(&discovery_config(), true).unwrap();

        assert_eq!(
            value["account_management_uri"], "https://siwx-oidc.example.com/account",
            "account_management_uri must default to {{base}}/account"
        );

        let actions: Vec<&str> = value["account_management_actions_supported"]
            .as_array()
            .expect("account_management_actions_supported must be an array")
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        for required in [
            "org.matrix.profile",
            "org.matrix.devices_list",
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.cross_signing_reset",
            "org.matrix.account_deactivate",
            "io.inblock.account_erase",
            "io.inblock.account_reactivate",
            "org.matrix.sessions_list",
            "org.matrix.session_view",
            "org.matrix.session_end",
        ] {
            assert!(actions.contains(&required), "missing action {required}");
        }
    }

    #[test]
    fn provider_metadata_advertises_resolve_only_when_it_can_answer() {
        let on = provider_metadata_value(&discovery_config(), true).unwrap();
        assert_eq!(
            on[RESOLVE_ENDPOINT_METADATA_KEY], "https://siwx-oidc.example.com/resolve",
            "the advertised endpoint must be {{base}}/resolve, the route axum serves"
        );
        assert_eq!(
            RESOLVE_ENDPOINT_METADATA_KEY, "io.inblock.resolve_endpoint",
            "the Element Web resolve-did-search patch reads this exact key"
        );

        let off = provider_metadata_value(&discovery_config(), false).unwrap();
        assert!(
            off.get(RESOLVE_ENDPOINT_METADATA_KEY).is_none(),
            "a deployment that would answer 503 must not advertise the route"
        );
    }

    /// Discovery advertises exactly the response types `authorize` accepts.
    #[test]
    fn discovery_advertises_only_the_code_response_type() {
        for matrix_ready in [true, false] {
            let value = provider_metadata_value(&discovery_config(), matrix_ready).unwrap();
            assert_eq!(
                value["response_types_supported"],
                serde_json::json!(["code"])
            );
        }
    }

    #[test]
    fn provider_metadata_honours_account_management_uri_override() {
        let config = Config {
            account_management_uri: Some(Url::parse("https://account.example.com/manage").unwrap()),
            ..discovery_config()
        };
        let value = provider_metadata_value(&config, true).unwrap();
        assert_eq!(
            value["account_management_uri"],
            "https://account.example.com/manage"
        );
    }

    /// Without a Synapse client or a Matrix server name every account action
    /// answers 400, so neither the account page nor its actions may be
    /// advertised, even when the operator configured the page's URL.
    #[test]
    fn account_management_is_advertised_only_when_the_actions_can_run() {
        let config = Config {
            account_management_uri: Some(Url::parse("https://account.example.com/manage").unwrap()),
            ..discovery_config()
        };
        let standalone = provider_metadata_value(&config, false).unwrap();
        for key in [
            "account_management_uri",
            "account_management_actions_supported",
        ] {
            assert!(
                standalone.get(key).is_none(),
                "{key} must not be advertised without Synapse and a server name: {standalone}"
            );
        }
        let ready = provider_metadata_value(&config, true).unwrap();
        assert!(ready["account_management_actions_supported"].is_array());
    }

    /// The terms of service and privacy policy are the deployment's own, so
    /// discovery carries exactly what the operator configured and omits an
    /// unset field rather than pointing at a default document.
    #[test]
    fn discovery_advertises_legal_uris_only_when_configured() {
        let unset = provider_metadata_value(&discovery_config(), false).unwrap();
        assert!(
            unset.get("op_tos_uri").is_none(),
            "no default terms of service may be advertised: {unset}"
        );
        assert!(
            unset.get("op_policy_uri").is_none(),
            "no default privacy policy may be advertised: {unset}"
        );

        let config = Config {
            op_tos_uri: Some(Url::parse("https://legal.example.org/terms").unwrap()),
            op_policy_uri: Some(Url::parse("https://legal.example.org/privacy").unwrap()),
            ..discovery_config()
        };
        let set = provider_metadata_value(&config, false).unwrap();
        assert_eq!(set["op_tos_uri"], "https://legal.example.org/terms");
        assert_eq!(set["op_policy_uri"], "https://legal.example.org/privacy");
    }

    /// The footer of the server-rendered pages links exactly what discovery
    /// advertises: nothing when nothing is configured, and each document only
    /// when it is.
    #[test]
    fn the_legal_footer_links_only_configured_documents() {
        let tos = Url::parse("https://legal.example.org/terms?v=1&lang=en").unwrap();
        let policy = Url::parse("https://legal.example.org/privacy").unwrap();

        assert_eq!(legal_footer_html(None, None), "", "no terms, no footer");

        let both = legal_footer_html(Some(&tos), Some(&policy));
        assert!(both.contains(
            r#"<a href="https://legal.example.org/terms?v=1&amp;lang=en">Terms of Use</a>"#
        ));
        assert!(both.contains(r#"<a href="https://legal.example.org/privacy">Privacy Policy</a>"#));
        assert!(!both.contains("/legal/"), "{both}");

        let tos_only = legal_footer_html(Some(&tos), None);
        assert!(tos_only.contains("Terms of Use") && !tos_only.contains("Privacy Policy"));
        let policy_only = legal_footer_html(None, Some(&policy));
        assert!(policy_only.contains("Privacy Policy") && !policy_only.contains("Terms of Use"));
    }

    /// A page title names the deployment it came from, never a fixed brand.
    #[test]
    fn a_page_title_names_the_issuer_host_not_a_brand() {
        assert_eq!(
            page_title("Account", "https://id.example.org/"),
            "Account · id.example.org"
        );
        assert_eq!(page_title("Account", "not a url"), "Account");
        assert!(!page_title("Account", "https://id.example.org").contains("inblock"));
    }

    /// Standalone discovery lists only what a standalone deployment serves.
    /// Introspection answers 404 there and the device-code poll is refused, so
    /// neither the endpoints nor the grant type may be advertised; revocation
    /// works in both modes and stays.
    #[test]
    fn discovery_advertises_introspection_and_the_device_grant_only_in_delegated_auth_mode() {
        let standalone = provider_metadata_value(&discovery_config(), false).unwrap();
        for key in [
            "introspection_endpoint",
            "introspection_endpoint_auth_methods_supported",
            "device_authorization_endpoint",
        ] {
            assert!(
                standalone.get(key).is_none(),
                "standalone discovery must not advertise {key}: {standalone}"
            );
        }
        assert_eq!(
            standalone["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            standalone["revocation_endpoint"],
            "https://siwx-oidc.example.com/oauth2/revoke"
        );

        let delegated = provider_metadata_value(
            &Config {
                mas_shared_secret: Some("shared-secret".to_string()),
                ..discovery_config()
            },
            false,
        )
        .unwrap();
        assert_eq!(
            delegated["introspection_endpoint"],
            "https://siwx-oidc.example.com/oauth2/introspect"
        );
        assert_eq!(
            delegated["introspection_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_post", "bearer"])
        );
        assert_eq!(
            delegated["device_authorization_endpoint"],
            "https://siwx-oidc.example.com/device_authorization"
        );
        assert_eq!(
            delegated["grant_types_supported"],
            serde_json::json!([
                "authorization_code",
                "refresh_token",
                DEVICE_CODE_GRANT_TYPE
            ])
        );
        assert_eq!(
            delegated["revocation_endpoint"],
            "https://siwx-oidc.example.com/oauth2/revoke"
        );
    }

    /// The token endpoint refuses the device-code grant outside delegated-auth
    /// mode, even for a code a user already approved, and leaves the code as
    /// it was: nothing is redeemed, nothing is issued.
    #[tokio::test]
    async fn the_device_code_grant_is_refused_outside_delegated_auth_mode() {
        let Some((config, db)) = default_config().await else {
            return;
        };
        assert!(
            !delegated_auth_enabled(&config),
            "Config::default() is standalone"
        );
        let device_code = format!("dvc_standalone-{}", Uuid::new_v4().simple());
        db.set_device_code(
            &device_code,
            &DeviceCodeEntry {
                user_code_digest: siwx_oidc::db::tokens::digest(&format!(
                    "SA-{}",
                    Uuid::new_v4().simple()
                )),
                legacy_user_code: None,
                client_id: "client".to_string(),
                scope: "openid".to_string(),
                status: DeviceCodeStatus::Approved,
                did: Some("did:key:zDnSTANDALONEDEVICECODE".to_string()),
                device_id: None,
                last_poll: None,
                created_at: Utc::now().timestamp(),
                auth_ms: None,
            },
            DEVICE_CODE_LIFETIME,
        )
        .await
        .unwrap();

        let refused = token(
            TokenForm {
                code: None,
                client_id: Some("client".to_string()),
                client_secret: None,
                grant_type: CoreGrantType::DeviceCode,
                code_verifier: None,
                refresh_token: None,
                device_code: Some(device_code.clone()),
            },
            ClientCredentials::default(),
            &EcdsaSigningKey::generate(),
            &config,
            &db,
            None,
        )
        .await;
        match refused {
            Err(CustomError::BadRequestToken(e)) => {
                assert_eq!(e.error, CoreErrorResponseType::UnsupportedGrantType)
            }
            Err(other) => panic!("expected unsupported_grant_type, got {other:?}"),
            Ok(_) => panic!("a standalone deployment must not redeem a device code"),
        }
        let (device_ref, entry) = db
            .get_device_code(&device_code)
            .await
            .unwrap()
            .expect("the refused code must be left in place");
        assert_eq!(entry.status, DeviceCodeStatus::Approved);
        db.delete_device_code(&device_ref).await.ok();
    }

    /// A device-code poll that loses the claim to a concurrent poll logs that at
    /// `debug!`. The device code is the credential the device polls with, so the
    /// line names its fingerprint, never the code. Needs Redis.
    #[tokio::test]
    async fn a_device_poll_that_loses_the_claim_logs_the_code_only_as_a_fingerprint() {
        use siwx_oidc::redact::fingerprint;

        let Some((config, db)) = default_config().await else {
            return;
        };
        let config = Config {
            mas_shared_secret: Some("shared-secret".to_string()),
            ..config
        };
        let device_code = format!("dvc_claimlost-{}", Uuid::new_v4().simple());
        db.set_device_code(
            &device_code,
            &DeviceCodeEntry {
                user_code_digest: siwx_oidc::db::tokens::digest(&format!(
                    "CL-{}",
                    Uuid::new_v4().simple()
                )),
                legacy_user_code: None,
                client_id: "client".to_string(),
                scope: "openid".to_string(),
                status: DeviceCodeStatus::Approved,
                did: Some("did:key:zDnCLAIMLOST".to_string()),
                device_id: None,
                last_poll: None,
                created_at: Utc::now().timestamp(),
                auth_ms: None,
            },
            DEVICE_CODE_LIFETIME,
        )
        .await
        .unwrap();
        assert!(
            db.try_claim_device_code(&device_code).await.unwrap(),
            "the winning poll claims the code"
        );

        let logs = siwx_oidc::test_support::LogCapture::start();
        let losing = token(
            TokenForm {
                code: None,
                client_id: Some("client".to_string()),
                client_secret: None,
                grant_type: CoreGrantType::DeviceCode,
                code_verifier: None,
                refresh_token: None,
                device_code: Some(device_code.clone()),
            },
            ClientCredentials::default(),
            &EcdsaSigningKey::generate(),
            &config,
            &db,
            None,
        )
        .await;
        let output = logs.output();
        match losing {
            Err(CustomError::BadRequestToken(e)) => assert_eq!(
                e.error,
                CoreErrorResponseType::Extension("authorization_pending".to_string())
            ),
            other => panic!(
                "the losing poll must be told to wait: {:?}",
                other.map(|_| ())
            ),
        }
        assert!(
            output.contains(&fingerprint(&device_code)),
            "the claim-lost line names the code's fingerprint; captured:\n{output}"
        );
        assert!(
            !output.contains(&device_code),
            "the device code appears in the logs in the clear:\n{output}"
        );
        if let Ok(Some((device_ref, _))) = db.get_device_code(&device_code).await {
            db.delete_device_code(&device_ref).await.ok();
        }
    }

    #[tokio::test]
    async fn authorize_accepts_matrix_only_scopes_without_openid() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(
                Url::parse("https://example.com").unwrap(),
            ),
            scope: Scope::new(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:ABCDEF".to_string(),
            ),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            // C2 Step 4a: PKCE is mandatory for the code flow — a valid S256
            // challenge so this scope-acceptance test exercises the real path.
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_ok(),
            "authorize must accept Matrix-only scopes (no openid): {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn authorize_rejects_invalid_scope() {
        let Some((_config, db_client)) = default_config().await else {
            return;
        };
        let params = AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: RedirectUrl::from_url(Url::parse("https://example.com").unwrap()),
            scope: Scope::new("profile email".to_string()),
            response_type: Some(CoreResponseType::Code),
            state: Some("state".into()),
            nonce: None,
            prompt: None,
            request_uri: None,
            request: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        };
        let result = authorize(params, &db_client).await;
        assert!(
            result.is_err(),
            "authorize must reject scopes without openid or urn:matrix:*"
        );
    }

    #[test]
    fn test_extract_device_id_from_scope() {
        // Stable prefix
        assert_eq!(
            extract_device_id_from_scope(
                "openid urn:matrix:client:api:* urn:matrix:client:device:W6ujlqyJoG5+BxH9eLdYgizkylgTS9z6ZzWqRM0FIBQ"
            ),
            Some("W6ujlqyJoG5+BxH9eLdYgizkylgTS9z6ZzWqRM0FIBQ".to_string())
        );
        assert_eq!(
            extract_device_id_from_scope(
                "openid urn:matrix:client:api:* urn:matrix:client:device:SIWX_43efbac7"
            ),
            Some("SIWX_43efbac7".to_string())
        );
        // MSC2967 unstable prefix (used by Element X)
        assert_eq!(
            extract_device_id_from_scope(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:CW2fdkGgZZW8StwGioe2CVKBb3685OjKt8wRUR0iZyc"
            ),
            Some("CW2fdkGgZZW8StwGioe2CVKBb3685OjKt8wRUR0iZyc".to_string())
        );
        // Device ID with slash (base64url-encoded, as sent by Element X)
        assert_eq!(
            extract_device_id_from_scope(
                "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:r8LXBERpNLfhbR3a/Wy1m9xE6ennsd2RJltz0xLrt3A"
            ),
            Some("r8LXBERpNLfhbR3a/Wy1m9xE6ennsd2RJltz0xLrt3A".to_string())
        );
        assert_eq!(extract_device_id_from_scope("openid"), None);
        assert_eq!(
            extract_device_id_from_scope("openid urn:matrix:client:api:*"),
            None
        );
        assert_eq!(
            extract_device_id_from_scope("openid urn:matrix:client:device:"),
            None
        );
    }

    #[test]
    fn test_resolve_device_id_uses_proposed() {
        let id = resolve_device_id(Some("2VeUcPZUV5"));
        assert_eq!(id, "2VeUcPZUV5");
    }

    #[test]
    fn test_resolve_device_id_mints_when_absent() {
        let id = resolve_device_id(None);
        assert!(id.starts_with("SIWX_"));
        assert_eq!(id.len(), "SIWX_".len() + 8);
    }

    /// Build a minimal CAIP-122-shaped message, optionally carrying an
    /// `Expiration Time:` line (mirrors what the browser frontend would emit).
    fn login_message_with_exp(exp: Option<&str>) -> String {
        let mut msg = String::from(
            "example.com wants you to sign in with your Ethereum account:\n\
             0xabc\n\n\
             You are signing-in to example.com.\n\n\
             URI: https://example.com\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: deadbeef\n\
             Issued At: 2023-04-17T11:01:24.862Z\n",
        );
        if let Some(e) = exp {
            msg.push_str(&format!("Expiration Time: {e}\n"));
        }
        msg.push_str("Resources:\n- https://example.com");
        msg
    }

    /// Enforce-if-present: a message with NO `Expiration Time` line is ACCEPTED.
    /// This is the headless-client (siwx-oidc-auth) login path — its
    /// `build_message` omits the line, and rejecting it would brick the agent
    /// fleet.
    #[test]
    fn login_expiration_missing_is_accepted() {
        let now = Utc::now();
        let msg = login_message_with_exp(None);
        assert!(
            enforce_login_expiration(&msg, now).is_ok(),
            "a message with no Expiration Time must be accepted (headless clients omit it)"
        );
    }

    /// Enforce-if-present: a message WITH an Expiration Time in the PAST (beyond
    /// the skew) is REJECTED with an "expired" error.
    #[test]
    fn login_expiration_present_but_expired_is_rejected() {
        let now = Utc::now();
        let past = (now - Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let msg = login_message_with_exp(Some(&past));
        let err = enforce_login_expiration(&msg, now)
            .expect_err("a present-but-expired Expiration Time must be rejected");
        let rendered = format!("{err:?}").to_lowercase();
        assert!(
            rendered.contains("expire"),
            "rejection must mention expiry: {rendered}"
        );
    }

    /// Enforce-if-present: a message WITH a future Expiration Time is ACCEPTED.
    #[test]
    fn login_expiration_present_and_future_is_accepted() {
        let now = Utc::now();
        let future =
            (now + Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let msg = login_message_with_exp(Some(&future));
        assert!(
            enforce_login_expiration(&msg, now).is_ok(),
            "a future Expiration Time must be accepted"
        );
    }
}

/// **H11** — the alias tier and the DID tier stay separated.
///
/// # What is being pinned, and why it is a security test
///
/// `SynapseClient::provision_user`'s second argument is the account's
/// **displayname**, and displayname is user-writable: it routes through
/// Synapse's `set_field` -> `set_displayname` and never reaches the
/// profile-field guard the `io.inblock.did` denylist installs. That was not
/// inferred, it was measured — `docs/audits/2026-09-10-msc4133-acl-probe.md`
/// leg 5, where a plain user's PUT to `displayname` answered **200** on the
/// very image where the same user's PUT to `io.inblock.did` answered 403.
///
/// So passing the DID there published a provider-looking DID into a field any
/// user can rewrite, and a consumer reading displayname-as-a-DID could be
/// handed somebody else's. The fix is one argument; the test is here because
/// nothing else about the system changes if it regresses — provisioning still
/// succeeds, sign-in still works, and every other test stays green.
///
/// # The mock
///
/// Extends `localpart.rs`'s `spawn_mock_synapse` pattern (in-process axum on an
/// ephemeral port, built only from crates already in `[dependencies]`) to the
/// four MAS endpoints `provision_synapse_device` touches, recording every
/// request body. `did_publication` is `None` throughout: these tests are about
/// the alias tier, and `None` keeps them free of the Redis-backed admin mint
/// that the DID tier needs.
#[cfg(test)]
mod provision_synapse_device_tests {
    use super::*;
    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// Mixed case ON PURPOSE: a `did:key` payload is case-sensitive, and the
    /// legacy localpart derived from it is lowercased. A test using an
    /// all-lowercase DID could not tell "displayname is the localpart" apart
    /// from "displayname is the DID, lowercased".
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const LOCALPART: &str = "k3f9x2q7ab4d8m1p";
    const SERVER_NAME: &str = "inblock.io";

    /// A localpart that was genuinely RESOLVED against Synapse — the normal
    /// case, and the only one under which the DID tier may be written.
    ///
    /// Spelled out per call site rather than defaulted so that `degraded` stays
    /// visible: it is the field that decides whether a durable signed assertion
    /// is minted, and hiding it behind a `Default` would stop these tests
    /// documenting which case they exercise.
    fn resolved_identity() -> crate::localpart::ResolvedIdentity {
        crate::localpart::ResolvedIdentity {
            localpart: LOCALPART.to_string(),
            is_new: false,
            degraded: false,
        }
    }

    /// A localpart that was GUESSED because the Synapse probe failed
    /// (`localpart::resolve_identity_or_legacy`'s fail-safe fallback).
    fn degraded_identity() -> crate::localpart::ResolvedIdentity {
        crate::localpart::ResolvedIdentity {
            localpart: LOCALPART.to_string(),
            is_new: false,
            degraded: true,
        }
    }

    #[derive(Clone)]
    struct MockState {
        /// Request bodies, keyed by the MAS endpoint's last path segment.
        calls: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
        /// True when `is_localpart_available` should answer "free" (a brand-new
        /// account), false when it should answer "taken" (a returning one).
        localpart_free: bool,
        /// Body served by `GET /_matrix/client/v3/profile/{mxid}`, as a
        /// `(status, json)` pair. `M_UNKNOWN` at 404 is the ONLY shape
        /// `has_profile_row` reads as "truly absent" (see its table).
        profile_reply: (axum::http::StatusCode, serde_json::Value),
    }

    async fn record(
        state: &MockState,
        endpoint: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        state
            .calls
            .lock()
            .unwrap()
            .entry(endpoint.to_string())
            .or_default()
            .push(body);
        (axum::http::StatusCode::OK, Json(serde_json::json!({}))).into_response()
    }

    async fn spawn(
        localpart_free: bool,
        profile_reply: (axum::http::StatusCode, serde_json::Value),
    ) -> (
        SynapseClient,
        Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let calls: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = MockState {
            calls: calls.clone(),
            localpart_free,
            profile_reply,
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mock-synapse port");
        let addr = listener.local_addr().expect("mock-synapse local_addr");

        let app = Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                get(|State(s): State<MockState>| async move {
                    if s.localpart_free {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"available": true})),
                        )
                            .into_response()
                    } else {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"errcode": "M_USER_IN_USE"})),
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/_synapse/mas/provision_user",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "provision_user", b).await
                    },
                ),
            )
            .route(
                "/_synapse/mas/upsert_device",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "upsert_device", b).await
                    },
                ),
            )
            .route(
                "/_synapse/mas/allow_cross_signing_reset",
                post(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "allow_cross_signing_reset", b).await
                    },
                ),
            )
            .route(
                "/_matrix/client/v3/profile/{mxid}",
                get(|State(s): State<MockState>| async move {
                    (s.profile_reply.0, Json(s.profile_reply.1.clone())).into_response()
                }),
            )
            .route(
                "/_matrix/client/v3/profile/{mxid}/{field}",
                axum::routing::put(
                    |State(s): State<MockState>, Json(b): Json<serde_json::Value>| async move {
                        record(&s, "publish_did_field", b).await
                    },
                ),
            )
            // Anything the routes above do not claim is recorded under
            // `unmatched`, so a test can assert that a request was NOT made.
            // Without this, "no profile write happened" would be a vacuous
            // assertion about a key the mock never writes under any
            // circumstances — the exact shape of a test that passes while
            // proving nothing.
            .fallback(
                |State(s): State<MockState>, req: axum::extract::Request| async move {
                    let seen = serde_json::json!({
                        "method": req.method().to_string(),
                        "path": req.uri().path().to_string(),
                    });
                    record(&s, "unmatched", seen).await
                },
            )
            .with_state(state);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock-synapse");
        });
        let client = SynapseClient::new(&format!("http://{addr}"), "shared-secret");
        (client, calls, handle)
    }

    /// Every `provision_user` body recorded by the mock.
    fn provision_bodies(
        calls: &Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
    ) -> Vec<serde_json::Value> {
        calls
            .lock()
            .unwrap()
            .get("provision_user")
            .cloned()
            .unwrap_or_default()
    }

    /// Assert a recorded `provision_user` body seeds the displayname with the
    /// generated alias and NOT with the DID, in any spelling.
    fn assert_alias_is_not_the_did(body: &serde_json::Value) {
        let display = body["set_displayname"]
            .as_str()
            .expect("provision_user must send set_displayname");
        assert_eq!(
            body["localpart"].as_str().unwrap(),
            LOCALPART,
            "the localpart must be the one the caller resolved, not one re-derived here"
        );
        assert_eq!(
            display,
            siwx_oidc::alias::alias_for(DID),
            "the displayname seed must be the generated alias (ACL probe leg 5: displayname \
             is USER-WRITABLE, so a DID published there is not provider-owned — and the \
             localpart, the interim seed, is unreadable)"
        );
        assert_ne!(display, DID, "the DID must never be the displayname");
        assert_ne!(
            display, LOCALPART,
            "the interim localpart seed is superseded by the alias"
        );
        // Case-insensitively too: `legacy_localpart` lowercases, so a
        // regression that passed a lowercased DID would still be a DID in a
        // user-writable field.
        assert!(
            !display.to_ascii_lowercase().contains("did:"),
            "no DID in any spelling may reach the alias tier: {display}"
        );
    }

    /// H11, first sign-in: a brand-new account is provisioned with the
    /// generated alias as its displayname.
    #[tokio::test]
    async fn h11_first_signin_seeds_displayname_with_the_alias_never_the_did() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ true,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;

        let device_id = provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None, // DID publication off: this test is about the alias tier
        )
        .await;
        assert_eq!(device_id.as_deref(), Some("SIWX_test"));

        let bodies = provision_bodies(&calls);
        assert_eq!(
            bodies.len(),
            1,
            "a new account is provisioned exactly once: {bodies:?}"
        );
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// H11, self-heal: the row-absent repair path uses the same seed.
    ///
    /// This is the second (and only other) `provision_user` call site. A fix
    /// applied to just the first one would leave the DID leaking into
    /// displayname for exactly the accounts that are already damaged.
    #[tokio::test]
    async fn h11_self_heal_seeds_displayname_with_the_alias_never_the_did() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            // The one 404 shape `has_profile_row` reads as truly absent.
            (
                axum::http::StatusCode::NOT_FOUND,
                serde_json::json!({"errcode": "M_UNKNOWN", "error": "No row found"}),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        let bodies = provision_bodies(&calls);
        assert_eq!(
            bodies.len(),
            1,
            "the self-heal must re-run provisioning exactly once: {bodies:?}"
        );
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// Pure discriminator: only the two strings provisioning ever seeded are
    /// "ours". Unit-tested separately from the async path because it is the
    /// whole safety argument for rewriting someone's profile.
    #[test]
    fn provider_written_displayname_matches_only_our_own_seeds() {
        assert!(
            provider_written_displayname(DID, DID, LOCALPART),
            "the raw DID was our seed until 2026-09-10"
        );
        assert!(
            provider_written_displayname(LOCALPART, DID, LOCALPART),
            "the bare localpart was our seed until 2026-09-11"
        );
        assert!(
            !provider_written_displayname("Ayla Tikhonov", DID, LOCALPART),
            "a generated alias is the user's the moment it is written"
        );
        assert!(!provider_written_displayname(
            "A Name The User Chose",
            DID,
            LOCALPART
        ));
        assert!(
            !provider_written_displayname("", DID, LOCALPART),
            "an empty name is not a seed we wrote"
        );
        // Byte-equality, not prefix and not case-folded: all three of these are
        // strings a USER could plausibly set, and rewriting them would be the
        // clobber this discriminator exists to prevent.
        assert!(!provider_written_displayname(
            &DID.to_uppercase(),
            DID,
            LOCALPART
        ));
        assert!(!provider_written_displayname(
            &format!("{DID} (me)"),
            DID,
            LOCALPART
        ));
        assert!(!provider_written_displayname(
            &LOCALPART[..8],
            DID,
            LOCALPART
        ));
    }

    /// MIGRATION, the case that motivated it: an account still carrying the raw
    /// DID as its displayname — every account provisioned before 2026-09-10 —
    /// is rewritten to the alias at its next sign-in.
    ///
    /// Leaving it does not open a forgery path (anyone can set any
    /// displayname), but it perpetuates the convention that displayname carries
    /// the DID, which is what makes a consumer read it as identity at all.
    #[tokio::test]
    async fn alias_migration_rewrites_a_displayname_that_is_the_raw_did() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (
                axum::http::StatusCode::OK,
                serde_json::json!({ "displayname": DID }),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        let bodies = provision_bodies(&calls);
        assert_eq!(bodies.len(), 1, "exactly one rewrite: {bodies:?}");
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// MIGRATION: the interim seed (the bare opaque localpart) is also ours to
    /// replace. It is honest but unreadable, and it was only ever a stopgap.
    #[tokio::test]
    async fn alias_migration_rewrites_a_displayname_that_is_the_bare_localpart() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (
                axum::http::StatusCode::OK,
                serde_json::json!({ "displayname": LOCALPART }),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        let bodies = provision_bodies(&calls);
        assert_eq!(bodies.len(), 1, "exactly one rewrite: {bodies:?}");
        assert_alias_is_not_the_did(&bodies[0]);
        handle.abort();
    }

    /// MIGRATION, the case that must NOT fire: a displayname the user
    /// deliberately CLEARED.
    ///
    /// Synapse answers 200 with no `displayname` key for that state, and an
    /// empty name is not a string we ever wrote. Re-seeding it would be the
    /// exact regression the 2026-08-02 discriminator fix was written for, in a
    /// new place — a user who wants no name would have it restored at every
    /// single login.
    #[tokio::test]
    async fn alias_migration_leaves_a_cleared_displayname_alone() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        assert!(
            provision_bodies(&calls).is_empty(),
            "a cleared displayname is the user's choice and must survive every login"
        );
        handle.abort();
    }

    /// GRANDFATHERING: a returning account with a profile row is never
    /// re-provisioned, so a displayname the user chose is never clobbered.
    ///
    /// This is the claim that makes the seed change safe to ship without a
    /// migration. It is asserted rather than assumed because it is a claim
    /// about a code path (`Ok(false)` + `has_profile_row == true` -> no call),
    /// not about intent, and the same argument is what protects the deliberate
    /// clearing of a displayname that the 2026-08-02 discriminator fix was
    /// written for.
    #[tokio::test]
    async fn existing_account_with_a_profile_row_is_never_reprovisioned() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (
                axum::http::StatusCode::OK,
                serde_json::json!({"displayname": "A Name The User Chose"}),
            ),
        )
        .await;

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            None,
        )
        .await;

        assert!(
            provision_bodies(&calls).is_empty(),
            "a returning account with a profile row must NOT be re-provisioned; \
             doing so would overwrite the user's own displayname"
        );
        // The rest of the login-time provisioning still ran.
        let calls = calls.lock().unwrap();
        assert!(calls.contains_key("upsert_device"));
        assert!(calls.contains_key("allow_cross_signing_reset"));
        handle.abort();
    }

    /// The POSITIVE wiring test: with a `server_name` and a publication
    /// context, `provision_synapse_device` really does write the attested DID
    /// field.
    ///
    /// The `no_server_name_…` test below proves the feature can be turned off;
    /// on its own that is also what a deleted call site looks like. This one
    /// proves the call site exists and is reached from the function BOTH
    /// sign-in paths route through — which is the single insertion point the
    /// whole design depends on.
    ///
    /// Needs Redis, because publication goes through the admin mint (see
    /// `synapse_client`'s publish tests for the same constraint and the pure
    /// classifier that keeps the classification covered when this skips).
    #[tokio::test]
    async fn publication_is_wired_into_the_shared_signin_path() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            handle.abort();
            return;
        };
        let synapse = synapse.with_admin_mint(redis, "siwx-admin".to_string(), 300);

        let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        let publication = DidPublication {
            key: &key,
            issuer: "https://issuer.example",
        };

        provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            Some(&publication),
        )
        .await;

        let calls = calls.lock().unwrap();
        let published = calls
            .get("publish_did_field")
            .expect("the DID field must be published on every sign-in");
        assert_eq!(published.len(), 1, "exactly one write per sign-in");
        let value = &published[0][crate::did_assertion::DID_PROFILE_FIELD];
        assert_eq!(
            value["did"].as_str(),
            Some(DID),
            "the exact-case DID must be what lands in the profile: {:?}",
            published[0]
        );
        assert!(
            value["proof"]
                .as_str()
                .is_some_and(|p| p.split('.').count() == 3),
            "a durable key must publish a three-part compact JWS: {:?}",
            published[0]
        );
        handle.abort();
    }

    /// **D4 (2026-09-10 audit): a GUESSED localpart is never asserted.**
    ///
    /// Identical setup to `publication_is_wired_into_the_shared_signin_path`
    /// above — same mock, same Redis-backed admin mint, same publication
    /// context, same `server_name` — with EXACTLY ONE variable changed:
    /// `degraded: true`. So a failure here can only mean the suppression
    /// stopped working, not that publication was broken for some other reason.
    /// That pairing is deliberate; do not "simplify" this test by weakening its
    /// setup, because a test that would also pass with publication globally
    /// broken proves nothing.
    ///
    /// The scenario: `resolve_identity_or_legacy` could not reach Synapse and
    /// guessed the legacy localpart for a user whose real account is
    /// modern-shaped. Provisioning proceeds (recoverable); publication must not
    /// (a valid, correctly-verifying assertion binding the DID to a duplicate
    /// account is permanent — Synapse has no rename API).
    ///
    /// The other provisioning calls are asserted to still happen, so a
    /// regression that "fixes" this by bailing out of the whole function fails
    /// here too.
    #[tokio::test]
    async fn a_degraded_identity_provisions_but_never_publishes_an_assertion() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ false,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            handle.abort();
            return;
        };
        let synapse = synapse.with_admin_mint(redis, "siwx-admin".to_string(), 300);

        let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        let publication = DidPublication {
            key: &key,
            issuer: "https://issuer.example",
        };

        provision_synapse_device(
            DID,
            &degraded_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            Some(SERVER_NAME),
            Some(&publication),
        )
        .await;

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.get("publish_did_field"),
            None,
            "a signed assertion must NEVER be minted for a localpart nobody resolved: {calls:?}"
        );
        // ...and the rest of provisioning is untouched: the suppression is
        // surgical, not a bail-out. Failing the login is what invariant 1
        // forbids, and refusing to provision would do exactly that.
        assert!(
            calls.contains_key("upsert_device"),
            "degraded identity must still provision its device: {calls:?}"
        );
        assert!(
            calls.contains_key("allow_cross_signing_reset"),
            "degraded identity must still arm the cross-signing reset window: {calls:?}"
        );
        handle.abort();
    }

    /// With no `server_name`, nothing is published and nothing 500s.
    ///
    /// A standalone deployment (no `SIWEOIDC_MATRIX_SERVER_NAME`) cannot build
    /// an mxid, and an assertion binding a guessed mxid would be worse than
    /// none. The DID tier is skipped entirely; the rest of provisioning is
    /// unaffected. Plan invariant: degrade, never 500.
    #[tokio::test]
    async fn no_server_name_skips_publication_without_disturbing_provisioning() {
        let (synapse, calls, handle) = spawn(
            /* localpart_free */ true,
            (axum::http::StatusCode::OK, serde_json::json!({})),
        )
        .await;

        let key = EcdsaSigningKey::from_pem(&crate::did_assertion::test_p256_pem())
            .expect("test PEM must load");
        let publication = DidPublication {
            key: &key,
            issuer: "https://issuer.example",
        };

        let device_id = provision_synapse_device(
            DID,
            &resolved_identity(),
            Some(&synapse),
            "Element Web",
            Some("SIWX_test"),
            None, // no SIWEOIDC_MATRIX_SERVER_NAME
            Some(&publication),
        )
        .await;

        assert_eq!(device_id.as_deref(), Some("SIWX_test"));
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.get("unmatched"),
            None,
            "no request may be made outside the four MAS endpoints — in particular no PUT to \
             the profile route — when there is no server_name to build an mxid from"
        );
        assert!(calls.contains_key("provision_user"));
        assert!(calls.contains_key("upsert_device"));
        handle.abort();
    }
}

/// Tests for the `io.inblock.mxid` userinfo claim (`SiwxAdditionalClaims`).
///
/// # What these pin, and why each one exists
///
/// The claim is a wire contract with three independent ways to regress, so each
/// gets its own test rather than one happy-path assertion:
///
/// 1. **The name.** `#[serde(rename = …)]` takes a literal, so the name lives in
///    exactly one place in the source — and a literal is exactly the kind of
///    thing a rename refactor silently changes. The literal is therefore spelled
///    out again HERE, by hand, rather than referenced from the struct: a test
///    that read the name out of the code under test would agree with any rename.
/// 2. **Absence is absence.** `skip_serializing_if` must OMIT the key, not emit
///    `null` — a consumer branching on key presence takes the wrong turn on a
///    null. Asserted with `.get(…).is_none()` on the raw JSON map, which is the
///    only way to tell the two apart.
/// 3. **Both variants carry it.** A client with a `userinfo_signed_response_alg`
///    gets a signed JWT instead of JSON; if the claim only made it into one of
///    them, a relying party would see a different identity depending on a
///    registration setting that has nothing to do with identity.
///
/// And, in every case, that `sub` and `preferred_username` are still the DID:
/// the claim is additive, and `sub` is the only authorization-bearing value here
/// (see [`userinfo`]'s doc).
///
/// Redis-backed, like the rest of this file's token tests: `userinfo` resolves
/// its caller through `get_token`, and stubbing that out would test a different
/// function than the one that ships.
#[cfg(test)]
mod userinfo_mxid_claim_tests {
    use super::*;
    use crate::config::Config;

    /// A `did:key`, not a `did:pkh`: `resolve_claims` performs an ENS lookup for
    /// `did:pkh:eip155:` subjects, and a unit test must not depend on the
    /// network. Mixed case on purpose — `sub` must come back byte-identical.
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const LOCALPART: &str = "k3f9x2q7ab4d8m1p";
    const SERVER_NAME: &str = "inblock.io";
    /// Spelled out by hand. See this module's doc, point 1.
    const CLAIM: &str = "io.inblock.mxid";

    fn nonce() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        (base << 20) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF)
    }

    /// Config with (or without) a Matrix homeserver configured. ENS is disabled
    /// so nothing here can reach the network.
    fn config_with_server_name(server_name: Option<&str>) -> Config {
        Config {
            ens_api_url: None,
            eth_provider: None,
            matrix_server_name: server_name.map(str::to_string),
            ..Config::default()
        }
    }

    /// Register a client, optionally one that wants a SIGNED userinfo response.
    async fn seed_client(db: &RedisClient, client_id: &str, signed: bool) -> anyhow::Result<()> {
        let mut metadata = SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://example.com".into()).unwrap()],
            LogoutClientMetadata::default(),
        );
        if signed {
            metadata = metadata
                .set_userinfo_signed_response_alg(Some(CoreJwsSigningAlgorithm::EcdsaP256Sha256));
        }
        db.set_client(
            client_id.to_string(),
            ClientEntry::new("secret", metadata, None),
        )
        .await
    }

    fn token_meta(client_id: &str, username: &str) -> TokenMetadata {
        TokenMetadata {
            username: username.to_string(),
            device_id: "SIWX_test".to_string(),
            scope: "openid".to_string(),
            client_id: client_id.to_string(),
            iat: 0,
            exp: i64::MAX,
            did: DID.to_string(),
            name: "n".to_string(),
            kind: Some(TokenKind::Access),
        }
    }

    /// `None` after a loud skip when Redis is unavailable (`siwx_oidc::test_support`).
    async fn db() -> Option<RedisClient> {
        siwx_oidc::test_support::redis().await
    }

    /// Drive the real `userinfo` and return the JSON body a client would see.
    async fn userinfo_json(config: &Config, db: &RedisClient, token: &str) -> serde_json::Value {
        let key = EcdsaSigningKey::generate();
        match userinfo(
            config,
            &key,
            None,
            UserInfoPayload {
                access_token: Some(token.to_string()),
            },
            db,
        )
        .await
        .expect("userinfo must succeed for a live token")
        {
            UserInfoResponse::Json(claims) => serde_json::to_value(claims).unwrap(),
            UserInfoResponse::Jwt(_) => panic!("this client did not request a signed response"),
        }
    }

    /// The happy path, and the only place the claim NAME is asserted.
    #[tokio::test]
    async fn the_claim_name_on_the_wire_is_io_inblock_mxid() {
        let Some(db) = db().await else {
            return;
        };
        let client_id = format!("mxid-claim-{}", nonce());
        seed_client(&db, &client_id, false).await.unwrap();
        let token = format!("tok_{}", nonce());
        db.set_token(&token, &token_meta(&client_id, LOCALPART), 120)
            .await
            .unwrap();

        let body = userinfo_json(&config_with_server_name(Some(SERVER_NAME)), &db, &token).await;

        assert_eq!(
            body.get(CLAIM).and_then(|v| v.as_str()),
            Some(format!("@{LOCALPART}:{SERVER_NAME}").as_str()),
            "the Matrix ID must be published under exactly `{CLAIM}`: {body}"
        );
        // Additive, not a replacement: both DID-bearing claims are untouched.
        assert_eq!(
            body.get("sub").and_then(|v| v.as_str()),
            Some(DID),
            "`sub` must still be the exact-case DID"
        );
        assert_eq!(
            body.get("preferred_username").and_then(|v| v.as_str()),
            Some(DID),
            "`preferred_username` must still be the DID"
        );
    }

    /// A standalone deployment has no homeserver, so there is no Matrix ID —
    /// and the key must be ABSENT, not `null`. See this module's doc, point 2.
    #[tokio::test]
    async fn without_a_matrix_server_name_the_claim_is_omitted_not_null() {
        let Some(db) = db().await else {
            return;
        };
        let client_id = format!("mxid-claim-standalone-{}", nonce());
        seed_client(&db, &client_id, false).await.unwrap();
        let token = format!("tok_{}", nonce());
        db.set_token(&token, &token_meta(&client_id, LOCALPART), 120)
            .await
            .unwrap();

        let body = userinfo_json(&config_with_server_name(None), &db, &token).await;

        assert!(
            body.get(CLAIM).is_none(),
            "with no SIWXOIDC_MATRIX_SERVER_NAME the claim must not appear at all \
             (a `null` would make a consumer's `if CLAIM in claims` branch take the \
             wrong turn): {body}"
        );
        assert_eq!(
            body.get("sub").and_then(|v| v.as_str()),
            Some(DID),
            "a standalone deployment still gets the full standard claim set"
        );
    }

    /// A token that records no localpart omits the claim; it is never derived
    /// from the DID, which could name a different account than the one this
    /// session was provisioned under. See `mxid_claim`'s doc.
    #[tokio::test]
    async fn a_token_without_a_recorded_localpart_omits_the_claim_rather_than_deriving_one() {
        let Some(db) = db().await else {
            return;
        };
        let client_id = format!("mxid-claim-no-localpart-{}", nonce());
        seed_client(&db, &client_id, false).await.unwrap();
        let token = format!("tok_{}", nonce());
        db.set_token(&token, &token_meta(&client_id, ""), 120)
            .await
            .unwrap();

        let body = userinfo_json(&config_with_server_name(Some(SERVER_NAME)), &db, &token).await;

        assert!(
            body.get(CLAIM).is_none(),
            "a token with no recorded localpart must not carry a derived Matrix ID: {body}"
        );
        assert_eq!(
            body.get("sub").and_then(|v| v.as_str()),
            Some(DID),
            "`sub` is still the exact-case DID"
        );
    }

    /// Only an access token is a bearer credential at `/userinfo`: an
    /// authorization code and a refresh token are refused like unknown tokens.
    #[tokio::test]
    async fn userinfo_accepts_only_an_access_token() {
        let Some(db) = db().await else {
            return;
        };
        let client_id = format!("mxid-claim-kinds-{}", nonce());
        seed_client(&db, &client_id, false).await.unwrap();
        let config = config_with_server_name(Some(SERVER_NAME));
        let key = EcdsaSigningKey::generate();

        let code = format!("code_{}", nonce());
        db.set_code(
            code.clone(),
            CodeEntry {
                exchange_count: 0,
                did: DID.to_string(),
                nonce: None,
                client_id: client_id.clone(),
                auth_time: Utc::now(),
                code_challenge: None,
                code_challenge_method: None,
                device_id: None,
                localpart: Some(LOCALPART.to_string()),
                scope: None,
            },
        )
        .await
        .unwrap();
        let refresh = format!("tok_{}", nonce());
        db.set_token(
            &refresh,
            &TokenMetadata {
                kind: Some(TokenKind::Refresh),
                ..token_meta(&client_id, LOCALPART)
            },
            120,
        )
        .await
        .unwrap();

        for (what, token) in [
            ("an authorization code", code),
            ("a refresh token", refresh),
        ] {
            let out = userinfo(
                &config,
                &key,
                None,
                UserInfoPayload {
                    access_token: Some(token),
                },
                &db,
            )
            .await;
            assert!(
                matches!(out, Err(CustomError::BadRequest(ref m)) if m == "Unknown token."),
                "/userinfo must refuse {what} like an unknown token"
            );
        }
    }

    /// The signed-JWT variant must carry the same claim. See this module's doc,
    /// point 3.
    #[tokio::test]
    async fn the_signed_jwt_variant_carries_the_claim_too() {
        let Some(db) = db().await else {
            return;
        };
        let client_id = format!("mxid-claim-jwt-{}", nonce());
        seed_client(&db, &client_id, true).await.unwrap();
        let token = format!("tok_{}", nonce());
        db.set_token(&token, &token_meta(&client_id, LOCALPART), 120)
            .await
            .unwrap();

        let key = EcdsaSigningKey::generate();
        let response = userinfo(
            &config_with_server_name(Some(SERVER_NAME)),
            &key,
            None,
            UserInfoPayload {
                access_token: Some(token.clone()),
            },
            &db,
        )
        .await
        .expect("userinfo must succeed for a live token");

        let jwt = match response {
            UserInfoResponse::Jwt(jwt) => serde_json::to_value(jwt)
                .unwrap()
                .as_str()
                .expect("a signed userinfo response serializes as the compact JWT string")
                .to_string(),
            UserInfoResponse::Json(_) => {
                panic!("a client with userinfo_signed_response_alg must get the JWT variant")
            }
        };

        // Decode the payload of the compact JWS the client actually receives —
        // not a re-serialization of the claims object, which would prove only
        // that serde works.
        let payload = jwt
            .split('.')
            .nth(1)
            .expect("a compact JWS has three parts");
        let payload: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("the JWS payload is base64url-unpadded"),
        )
        .unwrap();

        assert_eq!(
            payload.get(CLAIM).and_then(|v| v.as_str()),
            Some(format!("@{LOCALPART}:{SERVER_NAME}").as_str()),
            "the signed variant must carry the same Matrix ID as the JSON one: {payload}"
        );
        assert_eq!(
            payload.get("sub").and_then(|v| v.as_str()),
            Some(DID),
            "`sub` is unchanged in the signed variant too"
        );
    }
}

/// `sign_in` decides deactivation BEFORE it resolves the login localpart.
///
/// The ordering rule is argued at the gate's call site in [`sign_in`]: the
/// deactivation gate must run before `resolve_identity_or_legacy`, because that
/// resolver is infallible and answers a probe error with a GUESSED legacy
/// localpart. A gate that consumed the guess would ask `query_user` about the
/// wrong account, read the 404 as "no account, nothing to reject", and let a
/// deactivated modern-only account sign straight back in.
///
/// The `webauthn` tests pin the gate in isolation; nothing there can see where
/// `sign_in` calls it. These tests drive `sign_in` itself, with a server-verified
/// DID in the Redis session (the passkey path) and an in-process homeserver that
/// records every request it receives, and pin two things:
///
/// - **the outcome**: a deactivated account is refused, and a probe fault fails
///   closed, before anything is provisioned;
/// - **the order**: the gate's own probes are the ONLY requests `sign_in` makes
///   on those paths. Resolving the localpart first shows up as extra
///   `is_localpart_available` probes ahead of `query_user`, and provisioning
///   first shows up as MAS writes, so moving the gate anywhere later in
///   `sign_in` fails these tests even when the outcome alone would not change.
///
/// Redis-backed like the rest of this file's `sign_in` tests (`e2e_flow`): the
/// session is read and marked signed-in through the real `DBClient`.
#[cfg(test)]
mod sign_in_deactivation_order_tests {
    use super::*;
    use crate::localpart::{legacy_localpart, localpart_for};
    use axum::extract::{Query, State};
    use axum::http::{Method, StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// Synthetic; `find_did_method` checks only the `did:key:` prefix, and the
    /// gate never parses the key.
    const DID: &str = "did:key:zDnSIGNINDEACTIVATIONORDER";
    const SERVER_NAME: &str = "example.org";
    const REDIRECT: &str = "https://example.com/callback";

    /// What the homeserver answers, per localpart, and what it was asked.
    #[derive(Default)]
    struct Homeserver {
        /// `is_localpart_available` answers 500: a fault on ONE route, the
        /// partial-outage shape the ordering note describes.
        faulted: HashSet<String>,
        /// `is_localpart_available` answers `400 M_USER_IN_USE`. A deactivated
        /// account's localpart is taken as far as Synapse is concerned.
        taken: HashSet<String>,
        /// `query_user` answers `is_deactivated: true`; any other localpart is
        /// a 404, which `query_user` reads as "no such account".
        deactivated: HashSet<String>,
        /// Every request, in arrival order.
        log: Mutex<Vec<String>>,
    }

    async fn is_localpart_available(
        State(hs): State<Arc<Homeserver>>,
        Query(q): Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let lp = q.get("localpart").cloned().unwrap_or_default();
        hs.log
            .lock()
            .unwrap()
            .push(format!("is_localpart_available {lp}"));
        if hs.faulted.contains(&lp) {
            (StatusCode::INTERNAL_SERVER_ERROR, "").into_response()
        } else if hs.taken.contains(&lp) {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"errcode": "M_USER_IN_USE", "error": "in use"})),
            )
                .into_response()
        } else {
            (StatusCode::OK, Json(serde_json::json!({"available": true}))).into_response()
        }
    }

    async fn query_user(
        State(hs): State<Arc<Homeserver>>,
        Query(q): Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let lp = q.get("localpart").cloned().unwrap_or_default();
        hs.log.lock().unwrap().push(format!("query_user {lp}"));
        if hs.deactivated.contains(&lp) {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "user_id": format!("@{lp}:{SERVER_NAME}"),
                    "display_name": null,
                    "avatar_url": null,
                    "is_suspended": false,
                    "is_deactivated": true,
                })),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"errcode": "M_NOT_FOUND", "error": "User not found"})),
            )
                .into_response()
        }
    }

    /// Anything else `sign_in` might send (provisioning, profile reads) is
    /// recorded and answered with an empty 200, so a gate moved past
    /// provisioning shows up in the log instead of as an unrelated error.
    async fn anything_else(
        State(hs): State<Arc<Homeserver>>,
        method: Method,
        uri: Uri,
    ) -> axum::response::Response {
        hs.log
            .lock()
            .unwrap()
            .push(format!("{method} {}", uri.path()));
        (StatusCode::OK, Json(serde_json::json!({}))).into_response()
    }

    /// Run one passkey-path `sign_in` for [`DID`] against `hs`; return the
    /// outcome and the homeserver's request log, or `None` after a loud skip
    /// when Redis is unavailable (`siwx_oidc::test_support`).
    async fn sign_in_against(
        hs: Homeserver,
    ) -> Option<(Result<(Url, String), CustomError>, Vec<String>)> {
        let hs = Arc::new(hs);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral homeserver port");
        let addr = listener.local_addr().expect("homeserver local_addr");
        let app = Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                get(is_localpart_available),
            )
            .route("/_synapse/mas/query_user", get(query_user))
            .fallback(anything_else)
            .with_state(hs.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("homeserver");
        });
        let synapse = SynapseClient::new(&format!("http://{addr}"), "secret");

        let Some(db) = siwx_oidc::test_support::redis().await else {
            server.abort();
            return None;
        };
        let nonce = Uuid::new_v4().simple().to_string();
        let client_id = format!("deactivation-order-{nonce}");
        db.set_client(
            client_id.clone(),
            ClientEntry::new(
                "secret",
                SiwxClientMetadata::new(
                    vec![RedirectUrl::new(REDIRECT.into()).unwrap()],
                    LogoutClientMetadata::default(),
                ),
                None,
            ),
        )
        .await
        .unwrap();
        // The passkey path: the ceremony already verified the DID and stored it
        // in the session, so `sign_in` needs no CAIP-122 cookie.
        let session_id = format!("deactivation-order-{nonce}");
        db.set_session(
            session_id.clone(),
            SessionEntry {
                siwe_nonce: nonce.clone(),
                secret: "secret".into(),
                signin_count: 0,
                verified_did: Some(DID.to_string()),
                request: Some(bound_test_request(&client_id)),
            },
        )
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={session_id}")).unwrap(),
        );
        let cookies = headers.typed_get::<headers::Cookie>().unwrap();

        let result = sign_in(
            &Url::parse("https://example.com").unwrap(),
            &["key".to_string()],
            &[],
            cookies,
            &db,
            Some(&synapse),
            Some(SERVER_NAME),
            None,
        )
        .await;
        server.abort();
        let log = hs.log.lock().unwrap().clone();
        Some((result, log))
    }

    /// A healthy homeserver and a genuinely deactivated account that exists only
    /// under the MODERN localpart. `sign_in` refuses it with the deactivation
    /// message, and the only requests it made are the gate's own three probes:
    /// legacy is free, modern is taken, and the modern account is deactivated.
    #[tokio::test]
    async fn sign_in_refuses_a_deactivated_account_before_resolving_or_provisioning() {
        let legacy = legacy_localpart(DID);
        let modern = localpart_for(DID);
        let Some((result, log)) = sign_in_against(Homeserver {
            taken: HashSet::from([modern.clone()]),
            deactivated: HashSet::from([modern.clone()]),
            ..Homeserver::default()
        })
        .await
        else {
            return;
        };

        match result {
            Err(CustomError::Unauthorized(msg)) => {
                assert_eq!(msg, crate::webauthn::DEACTIVATED_REJECT_MSG);
            }
            other => panic!("a deactivated account must not sign in, got {other:?}"),
        }
        assert_eq!(
            log,
            vec![
                format!("is_localpart_available {legacy}"),
                format!("is_localpart_available {modern}"),
                format!("query_user {modern}"),
            ],
            "the deactivation gate must be the first and only thing sign_in asks the \
             homeserver on this path: extra availability probes before `query_user` mean \
             the login localpart was resolved first, and anything after it means \
             provisioning ran for an account that is being refused"
        );
    }

    /// The bypass shape from the ordering note: the legacy availability probe
    /// fails while `query_user` would answer, and the deactivated account lives
    /// under the MODERN localpart. `resolve_identity_or_legacy` would answer this
    /// fault with the legacy guess, and `query_user` on that guess is a 404. The
    /// gate must instead fail closed with the "could not check" 503, having sent
    /// nothing but the one failed probe.
    #[tokio::test]
    async fn a_partial_probe_fault_fails_sign_in_closed_before_any_legacy_guess() {
        let legacy = legacy_localpart(DID);
        let modern = localpart_for(DID);
        let Some((result, log)) = sign_in_against(Homeserver {
            faulted: HashSet::from([legacy.clone()]),
            taken: HashSet::from([modern.clone()]),
            deactivated: HashSet::from([modern.clone()]),
            ..Homeserver::default()
        })
        .await
        else {
            return;
        };

        match result {
            Err(CustomError::ServiceUnavailable(msg)) => {
                assert_eq!(msg, crate::webauthn::DEACTIVATION_CHECK_UNAVAILABLE_MSG);
            }
            other => panic!(
                "a probe fault must fail sign-in closed, never fall back to the legacy \
                 guess and let a deactivated modern-only account in; got {other:?}"
            ),
        }
        assert_eq!(
            log,
            vec![format!("is_localpart_available {legacy}")],
            "the gate's failed probe must be the only request: a second probe means the \
             login localpart was resolved (and guessed) before the gate decided"
        );
    }
}

#[cfg(test)]
mod device_display_name_tests {
    //! The Synapse device a sign-in creates is named after the OAuth client
    //! (its registered `client_name`, else its client id), never after a fixed
    //! brand, and an existing device's name is never overwritten.
    use super::*;
    use crate::config::Config;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use headers::{HeaderMap, HeaderMapExt, HeaderValue};
    use openidconnect::{ClientName, LanguageTag};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// Synthetic; `find_did_method` checks only the `did:key:` prefix.
    const DID: &str = "did:key:zDnDEVICEDISPLAYNAMETEST";
    const SERVER_NAME: &str = "example.org";
    const REDIRECT: &str = "https://example.com/callback";
    const USERS_NAME: &str = "Chosen by the user";

    /// A homeserver on which every localpart is taken (an existing, active
    /// account, so nothing is provisioned and no gate refuses), with Synapse
    /// 1.161.0's device semantics: `upsert_device` answers 201 for a device it
    /// inserts and 200 for one it already has, and OVERWRITES an existing
    /// device's name whenever one is sent; `update_device_display_name` sets
    /// the name of a device that exists. `always_200` models a homeserver or
    /// proxy that never says 201.
    struct Homeserver {
        /// device id -> display name
        devices: Mutex<HashMap<String, Option<String>>>,
        upserts: Mutex<Vec<serde_json::Value>>,
        renames: Mutex<Vec<serde_json::Value>>,
        always_200: bool,
    }

    async fn spawn(
        devices: &[&str],
    ) -> (SynapseClient, Arc<Homeserver>, tokio::task::JoinHandle<()>) {
        spawn_with(devices, false).await
    }

    async fn spawn_with(
        devices: &[&str],
        always_200: bool,
    ) -> (SynapseClient, Arc<Homeserver>, tokio::task::JoinHandle<()>) {
        let hs = Arc::new(Homeserver {
            devices: Mutex::new(
                devices
                    .iter()
                    .map(|d| (d.to_string(), Some(USERS_NAME.to_string())))
                    .collect(),
            ),
            upserts: Mutex::new(Vec::new()),
            renames: Mutex::new(Vec::new()),
            always_200,
        });
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral homeserver port");
        let addr = listener.local_addr().expect("homeserver local_addr");
        let app = Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                get(|| async {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"errcode": "M_USER_IN_USE", "error": "in use"})),
                    )
                }),
            )
            .route(
                "/_synapse/mas/query_user",
                get(|| async {
                    (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"errcode": "M_NOT_FOUND", "error": "User not found"})),
                    )
                }),
            )
            .route(
                "/_synapse/mas/upsert_device",
                post(
                    |State(hs): State<Arc<Homeserver>>, Json(body): Json<serde_json::Value>| async move {
                        hs.upserts.lock().unwrap().push(body.clone());
                        let id = body["device_id"].as_str().unwrap().to_string();
                        let name = body["display_name"].as_str().map(str::to_string);
                        let mut devices = hs.devices.lock().unwrap();
                        let created = match devices.get_mut(&id) {
                            None => {
                                devices.insert(id, name);
                                true
                            }
                            Some(existing) => {
                                if name.is_some() {
                                    *existing = name;
                                }
                                false
                            }
                        };
                        let status = if created && !hs.always_200 {
                            StatusCode::CREATED
                        } else {
                            StatusCode::OK
                        };
                        (status, Json(serde_json::json!({})))
                    },
                ),
            )
            .route(
                "/_synapse/mas/update_device_display_name",
                post(
                    |State(hs): State<Arc<Homeserver>>, Json(body): Json<serde_json::Value>| async move {
                        hs.renames.lock().unwrap().push(body.clone());
                        let id = body["device_id"].as_str().unwrap();
                        let name = body["display_name"].as_str().unwrap().to_string();
                        match hs.devices.lock().unwrap().get_mut(id) {
                            Some(existing) => {
                                *existing = Some(name);
                                StatusCode::OK
                            }
                            None => StatusCode::NOT_FOUND,
                        }
                    },
                ),
            )
            // Profile reads, cross-signing reset and anything else: an empty 200.
            .fallback(|| async { (StatusCode::OK, Json(serde_json::json!({}))).into_response() })
            .with_state(hs.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("homeserver");
        });
        (
            SynapseClient::new(&format!("http://{addr}"), "secret"),
            hs,
            server,
        )
    }

    fn client_entry(client_name: Option<&str>) -> ClientEntry {
        let mut metadata = SiwxClientMetadata::new(
            vec![RedirectUrl::new(REDIRECT.into()).unwrap()],
            LogoutClientMetadata::default(),
        );
        if let Some(name) = client_name {
            let mut names = LocalizedClaim::new();
            names.insert(None, ClientName::new(name.to_string()));
            metadata = metadata.set_client_name(Some(names));
        }
        ClientEntry::new("secret", metadata, None)
    }

    /// Asserts that exactly one device was upserted, that the upsert carried
    /// no name, and that the device was then named `expected` (`None`: not
    /// named at all). Returns the device id.
    fn the_one_device(hs: &Homeserver, expected: Option<&str>) -> String {
        let upserts = hs.upserts.lock().unwrap().clone();
        assert_eq!(upserts.len(), 1, "exactly one device upsert: {upserts:?}");
        assert!(
            upserts[0].get("display_name").is_none(),
            "an upsert must never carry a name: Synapse would overwrite an existing \
             device's: {}",
            upserts[0]
        );
        let device_id = upserts[0]["device_id"].as_str().unwrap().to_string();
        let renames = hs.renames.lock().unwrap().clone();
        match expected {
            Some(name) => {
                assert_eq!(renames.len(), 1, "exactly one rename: {renames:?}");
                assert_eq!(renames[0]["device_id"], device_id.as_str());
                assert_eq!(renames[0]["display_name"], name);
            }
            None => assert!(
                renames.is_empty(),
                "a device this sign-in did not create must not be renamed: {renames:?}"
            ),
        }
        device_id
    }

    /// Run one passkey-path `sign_in` for [`DID`] through a client registered
    /// with `client_name`, with no device id in the session scope. `None` when
    /// Redis is unavailable (the test then skips, see `test_support`).
    async fn sign_in_through(client_name: Option<&str>) -> Option<(String, Arc<Homeserver>)> {
        let db = siwx_oidc::test_support::redis().await?;
        let (synapse, hs, server) = spawn(&[]).await;
        let nonce = Uuid::new_v4().simple().to_string();
        let client_id = format!("device-name-{nonce}");
        db.set_client(client_id.clone(), client_entry(client_name))
            .await
            .unwrap();
        let session_id = format!("device-name-{nonce}");
        db.set_session(
            session_id.clone(),
            SessionEntry {
                siwe_nonce: nonce.clone(),
                secret: "secret".into(),
                signin_count: 0,
                verified_did: Some(DID.to_string()),
                request: Some(bound_test_request(&client_id)),
            },
        )
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={session_id}")).unwrap(),
        );
        sign_in(
            &Url::parse("https://example.com").unwrap(),
            &["key".to_string()],
            &[],
            headers.typed_get::<headers::Cookie>().unwrap(),
            &db,
            Some(&synapse),
            Some(SERVER_NAME),
            None,
        )
        .await
        .expect("sign_in must succeed against a healthy homeserver");
        server.abort();
        Some((client_id, hs))
    }

    #[test]
    fn the_device_is_named_after_the_registered_client_name() {
        assert_eq!(
            device_display_name("cid", Some(&client_entry(Some("Aqua Agent")))),
            "Aqua Agent"
        );
        assert_eq!(
            device_display_name("cid", Some(&client_entry(Some("  Aqua Agent\n")))),
            "Aqua Agent",
            "surrounding whitespace is not part of a name"
        );
    }

    #[test]
    fn without_a_registered_name_the_device_is_named_after_the_client_id() {
        assert_eq!(device_display_name("my-agent", None), "my-agent");
        assert_eq!(
            device_display_name("my-agent", Some(&client_entry(None))),
            "my-agent"
        );
        assert_eq!(
            device_display_name("my-agent", Some(&client_entry(Some("   ")))),
            "my-agent",
            "a blank client_name names nothing"
        );
    }

    #[test]
    fn a_language_tagged_name_is_used_when_there_is_no_default_one() {
        let mut entry = client_entry(None);
        let mut names = LocalizedClaim::new();
        names.insert(
            Some(LanguageTag::new("de".to_string())),
            ClientName::new("Mein Agent".to_string()),
        );
        entry.metadata = entry.metadata.set_client_name(Some(names));
        assert_eq!(device_display_name("cid", Some(&entry)), "Mein Agent");
    }

    /// The untagged name wins over every tagged one; without it the smallest
    /// tag wins, on every call, although the tagged names sit in a `HashMap`
    /// whose iteration order differs from one instance to the next.
    #[test]
    fn a_language_tagged_name_is_chosen_deterministically() {
        let tagged = [
            ("fr", "Mon Agent"),
            ("nl", "Mijn Agent"),
            ("de", "Mein Agent"),
            ("en-GB", "My Agent"),
        ];
        for default in [None, Some("Agent")] {
            for _ in 0..64 {
                let mut entry = client_entry(None);
                let mut names = LocalizedClaim::new();
                if let Some(name) = default {
                    names.insert(None, ClientName::new(name.to_string()));
                }
                for (tag, name) in tagged {
                    names.insert(
                        Some(LanguageTag::new(tag.to_string())),
                        ClientName::new(name.to_string()),
                    );
                }
                entry.metadata = entry.metadata.set_client_name(Some(names));
                assert_eq!(
                    device_display_name("cid", Some(&entry)),
                    default.unwrap_or("Mein Agent")
                );
            }
        }
    }

    /// Synapse answers `update_device_display_name` with 400 `M_TOO_LARGE` for
    /// a name over 100 code points, and the device would then stay unnamed.
    #[test]
    fn a_long_client_name_is_cut_to_synapses_limit() {
        let long = "é".repeat(150);
        let name = device_display_name("cid", Some(&client_entry(Some(&long))));
        assert_eq!(name.chars().count(), MAX_DEVICE_DISPLAY_NAME_CHARS);
        assert_eq!(MAX_DEVICE_DISPLAY_NAME_CHARS, 100);
        assert_eq!(
            device_display_name(&"c".repeat(150), None).chars().count(),
            100
        );
    }

    #[tokio::test]
    async fn sign_in_names_a_new_device_after_the_registered_client() {
        let Some((_, hs)) = sign_in_through(Some("Aqua Agent")).await else {
            return;
        };
        let device_id = the_one_device(&hs, Some("Aqua Agent"));
        assert!(device_id.starts_with("SIWX_"), "{device_id}");
    }

    #[tokio::test]
    async fn sign_in_names_a_new_device_after_the_client_id_without_a_client_name() {
        let Some((client_id, hs)) = sign_in_through(None).await else {
            return;
        };
        the_one_device(&hs, Some(&client_id));
    }

    fn identity() -> crate::localpart::ResolvedIdentity {
        crate::localpart::ResolvedIdentity {
            localpart: crate::localpart::localpart_for(DID),
            is_new: false,
            degraded: false,
        }
    }

    async fn provision(
        synapse: &SynapseClient,
        device: Option<&str>,
        server_name: Option<&str>,
    ) -> Option<String> {
        provision_synapse_device(
            DID,
            &identity(),
            Some(synapse),
            "Aqua Agent",
            device,
            server_name,
            None,
        )
        .await
    }

    /// A client re-authenticating with its own device id, for a device the
    /// user renamed: the name stays the user's.
    #[tokio::test]
    async fn a_client_supplied_device_that_exists_keeps_its_name() {
        let (synapse, hs, server) = spawn(&["CLIENTDEVICE"]).await;
        let device_id = provision(&synapse, Some("CLIENTDEVICE"), Some(SERVER_NAME)).await;
        server.abort();
        assert_eq!(device_id.as_deref(), Some("CLIENTDEVICE"));
        the_one_device(&hs, None);
        assert_eq!(
            hs.devices.lock().unwrap()["CLIENTDEVICE"].as_deref(),
            Some(USERS_NAME)
        );
    }

    #[tokio::test]
    async fn a_client_supplied_device_that_is_new_gets_the_client_name() {
        let (synapse, hs, server) = spawn(&["SOMEOTHERDEVICE"]).await;
        provision(&synapse, Some("CLIENTDEVICE"), Some(SERVER_NAME)).await;
        server.abort();
        assert_eq!(the_one_device(&hs, Some("Aqua Agent")), "CLIENTDEVICE");
        assert_eq!(
            hs.devices.lock().unwrap()["CLIENTDEVICE"].as_deref(),
            Some("Aqua Agent")
        );
    }

    /// Naming reads nothing about the account, so it needs no MXID: a new
    /// device is named without a server name too.
    #[tokio::test]
    async fn a_new_device_is_named_without_a_server_name() {
        let (synapse, hs, server) = spawn(&[]).await;
        provision(&synapse, Some("CLIENTDEVICE"), None).await;
        server.abort();
        the_one_device(&hs, Some("Aqua Agent"));
    }

    /// Only Synapse's 201 means "this upsert created the device". A homeserver
    /// that answers 200 for everything leaves every device unnamed rather than
    /// risk renaming one the user named.
    #[tokio::test]
    async fn upsert_names_only_a_device_this_sign_in_creates() {
        let (synapse, hs, server) = spawn_with(&[], true).await;
        provision(&synapse, Some("CLIENTDEVICE"), Some(SERVER_NAME)).await;
        provision(&synapse, None, Some(SERVER_NAME)).await;
        server.abort();
        assert_eq!(hs.upserts.lock().unwrap().len(), 2);
        assert!(
            hs.renames.lock().unwrap().is_empty(),
            "without a 201 nothing may be renamed"
        );
    }

    /// The grant of an approved device code counts from the approval, the
    /// authentication, which the approval records on the entry from Redis
    /// `TIME`; not from the poll that redeems it (I6).
    #[tokio::test]
    async fn a_device_grant_counts_its_lifetime_from_the_approval() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let (synapse, _hs, server) = spawn(&[]).await;
        let nonce = Uuid::new_v4().simple().to_string();
        let client_id = format!("device-auth-time-{nonce}");
        db.set_client(client_id.clone(), client_entry(Some("Pocket Client")))
            .await
            .unwrap();
        let device_code = format!("dvc_auth-time-{nonce}");
        let approved_at = Utc::now().timestamp() - 1_000;
        db.set_device_code(
            &device_code,
            &DeviceCodeEntry {
                user_code_digest: siwx_oidc::db::tokens::digest(&format!("AT-{nonce}")),
                legacy_user_code: None,
                client_id: client_id.clone(),
                scope: "openid".to_string(),
                status: DeviceCodeStatus::Approved,
                did: Some(DID.to_string()),
                device_id: None,
                last_poll: None,
                created_at: approved_at - 10,
                auth_ms: Some(approved_at * 1000),
            },
            DEVICE_CODE_LIFETIME,
        )
        .await
        .unwrap();
        let config = Config {
            mas_shared_secret: Some("secret".to_string()),
            matrix_server_name: Some(SERVER_NAME.to_string()),
            ..Config::default()
        };
        let response = token(
            TokenForm {
                code: None,
                client_id: Some(client_id),
                client_secret: None,
                grant_type: CoreGrantType::DeviceCode,
                code_verifier: None,
                refresh_token: None,
                device_code: Some(device_code),
            },
            ClientCredentials::default(),
            &EcdsaSigningKey::generate(),
            &config,
            &db,
            Some(&synapse),
        )
        .await
        .expect("an approved device code must be redeemed");
        server.abort();
        let access = openidconnect::OAuth2TokenResponse::access_token(&response);
        let grant = db
            .lookup_access_token(access.secret())
            .await
            .unwrap()
            .expect("the issued access token is live")
            .grant;
        assert_eq!(grant.auth_time, approved_at, "auth_time is the approval");
        assert_eq!(grant.auth_ms, approved_at * 1000, "auth_ms is the approval");
    }

    /// The QR / device-code path used to name every device "Element X".
    #[tokio::test]
    async fn the_device_code_grant_names_the_device_after_its_client() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let (synapse, hs, server) = spawn(&[]).await;
        let nonce = Uuid::new_v4().simple().to_string();
        let client_id = format!("device-name-dc-{nonce}");
        db.set_client(client_id.clone(), client_entry(Some("Pocket Client")))
            .await
            .unwrap();
        let device_code = format!("dvc_device-name-{nonce}");
        db.set_device_code(
            &device_code,
            &DeviceCodeEntry {
                user_code_digest: siwx_oidc::db::tokens::digest(&format!("DN-{nonce}")),
                legacy_user_code: None,
                client_id: client_id.clone(),
                scope: "openid".to_string(),
                status: DeviceCodeStatus::Approved,
                did: Some(DID.to_string()),
                device_id: None,
                last_poll: None,
                created_at: Utc::now().timestamp(),
                auth_ms: None,
            },
            DEVICE_CODE_LIFETIME,
        )
        .await
        .unwrap();
        let config = Config {
            mas_shared_secret: Some("secret".to_string()),
            matrix_server_name: Some(SERVER_NAME.to_string()),
            ..Config::default()
        };
        let response = token(
            TokenForm {
                code: None,
                client_id: Some(client_id),
                client_secret: None,
                grant_type: CoreGrantType::DeviceCode,
                code_verifier: None,
                refresh_token: None,
                device_code: Some(device_code),
            },
            ClientCredentials::default(),
            &EcdsaSigningKey::generate(),
            &config,
            &db,
            Some(&synapse),
        )
        .await
        .expect("an approved device code must be redeemed");
        server.abort();
        let device_id = the_one_device(&hs, Some("Pocket Client"));
        assert!(device_id.starts_with("SIWX_"), "{device_id}");
        let scopes: Vec<String> = openidconnect::OAuth2TokenResponse::scopes(&response)
            .expect("the device-code response carries its scope")
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            scopes.contains(&format!("urn:matrix:client:device:{device_id}")),
            "the token must be scoped to the device that was provisioned: {scopes:?}"
        );
    }
}

#[cfg(test)]
mod client_binding_tests {
    //! A refresh token belongs to the client it was issued to (I7), and the
    //! token endpoint authenticates a client the same way for the code exchange
    //! and the refresh grant. Needs Redis.
    use super::*;
    use crate::config::Config;
    use openidconnect::core::CoreClientAuthMethod;

    pub(super) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    pub(super) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    pub(super) const SECRET: &str = "the-registered-secret";

    pub(super) fn unique(prefix: &str) -> String {
        format!("{prefix}{}", Uuid::new_v4().simple())
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Registration {
        /// `token_endpoint_auth_method: none`, as Element Web and Element X register.
        Public,
        /// `client_secret_post`.
        Confidential,
        /// No `token_endpoint_auth_method`: confidential when `require_secret`.
        Unset,
    }

    async fn seed_client(db: &RedisClient, registration: Registration) -> String {
        seed_client_with(db, registration, None).await
    }

    /// A client registered with the given grant types (`None`: the registration
    /// names none).
    pub(super) async fn seed_client_with(
        db: &RedisClient,
        registration: Registration,
        grant_types: Option<Vec<CoreGrantType>>,
    ) -> String {
        let id = unique("bind-");
        let mut metadata = SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://example.com/cb".into()).unwrap()],
            LogoutClientMetadata::default(),
        );
        metadata = match registration {
            Registration::Public => {
                metadata.set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None))
            }
            Registration::Confidential => metadata
                .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::ClientSecretPost)),
            Registration::Unset => metadata,
        };
        if let Some(grants) = grant_types {
            metadata = metadata.set_grant_types(Some(grants));
        }
        db.set_client(id.clone(), ClientEntry::new(SECRET, metadata, None))
            .await
            .unwrap();
        id
    }

    /// A deviceless grant of `client_id` with a refresh token; returns the token.
    async fn seed_refresh_token(db: &RedisClient, client_id: &str) -> String {
        db.issue_grant(&NewGrant {
            kind: GrantKind::Oidc,
            username: unique("localpart"),
            did: "did:key:zDnBINDING".into(),
            client_id: client_id.into(),
            confidential_client: false,
            device_id: String::new(),
            scope: "openid".into(),
            name: "did:key:zDnBINDING".into(),
            auth_ms: Some(Utc::now().timestamp_millis()),
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
        })
        .await
        .unwrap()
        .refresh_token
        .expect("the grant carries a refresh token")
    }

    async fn seed_code(db: &RedisClient, client_id: &str) -> String {
        seed_code_with_scope(db, client_id, None).await
    }

    /// A code `sign_in` issued for an authorization request that asked for `scope`.
    pub(super) async fn seed_code_with_scope(
        db: &RedisClient,
        client_id: &str,
        scope: Option<&str>,
    ) -> String {
        let code = unique("code-");
        db.set_code(
            code.clone(),
            CodeEntry {
                exchange_count: 0,
                did: "did:key:zDnBINDING".into(),
                nonce: None,
                client_id: client_id.into(),
                auth_time: Utc::now(),
                code_challenge: Some(CHALLENGE.into()),
                code_challenge_method: Some("S256".into()),
                device_id: None,
                localpart: Some(unique("localpart")),
                scope: scope.map(str::to_string),
            },
        )
        .await
        .unwrap();
        code
    }

    /// What the caller says about itself: the `client_id` of the form, the
    /// `client_secret` of the form, and a secret from an `Authorization` header.
    #[derive(Clone, Copy)]
    struct Presented<'a> {
        client_id: Option<&'a str>,
        form_secret: Option<&'a str>,
        /// The user name of an `Authorization: Basic` header.
        header_client_id: Option<&'a str>,
        header_secret: Option<&'a str>,
    }

    const NOTHING: Presented<'static> = Presented {
        client_id: None,
        form_secret: None,
        header_client_id: None,
        header_secret: None,
    };

    async fn refresh(
        db: &RedisClient,
        config: &Config,
        refresh_token: &str,
        who: Presented<'_>,
    ) -> Result<SiwxTokenResponse, CustomError> {
        token(
            TokenForm {
                code: None,
                client_id: who.client_id.map(str::to_string),
                client_secret: who.form_secret.map(str::to_string),
                grant_type: CoreGrantType::RefreshToken,
                code_verifier: None,
                refresh_token: Some(refresh_token.to_string()),
                device_code: None,
            },
            ClientCredentials {
                basic_client_id: who.header_client_id.map(str::to_string),
                secret: who.header_secret.map(str::to_string),
            },
            &EcdsaSigningKey::generate(),
            config,
            db,
            None,
        )
        .await
    }

    async fn exchange(
        db: &RedisClient,
        config: &Config,
        code: &str,
        who: Presented<'_>,
    ) -> Result<SiwxTokenResponse, CustomError> {
        token(
            TokenForm {
                code: Some(code.to_string()),
                client_id: who.client_id.map(str::to_string),
                client_secret: who.form_secret.map(str::to_string),
                grant_type: CoreGrantType::AuthorizationCode,
                code_verifier: Some(VERIFIER.to_string()),
                refresh_token: None,
                device_code: None,
            },
            ClientCredentials {
                basic_client_id: who.header_client_id.map(str::to_string),
                secret: who.header_secret.map(str::to_string),
            },
            &EcdsaSigningKey::generate(),
            config,
            db,
            None,
        )
        .await
    }

    /// The answer, reduced to what a client sees: success, `invalid_grant`
    /// (the grant does not belong to this client), or `invalid_client` (the
    /// client did not authenticate).
    fn outcome(result: &Result<SiwxTokenResponse, CustomError>) -> String {
        match result {
            Ok(_) => "ok".to_string(),
            Err(CustomError::BadRequestToken(e)) => match e.error {
                CoreErrorResponseType::InvalidGrant => "invalid_grant".to_string(),
                CoreErrorResponseType::InvalidRequest => "invalid_request".to_string(),
                ref other => format!("{other:?}"),
            },
            Err(CustomError::Unauthorized(message)) => format!("invalid_client: {message}"),
            Err(other) => format!("unexpected: {other:?}"),
        }
    }

    fn refresh_token_of(result: Result<SiwxTokenResponse, CustomError>) -> String {
        use openidconnect::OAuth2TokenResponse;
        result
            .unwrap_or_else(|e| panic!("the refresh must succeed: {e:?}"))
            .refresh_token()
            .expect("a rotation returns a refresh token")
            .secret()
            .clone()
    }

    /// The token's grant exists and was never rotated: a refusal consumed nothing.
    async fn still_exists(db: &RedisClient, refresh_token: &str) -> bool {
        db.peek_refresh_grant(refresh_token)
            .await
            .unwrap()
            .is_some_and(|grant| grant.generation == 0)
    }

    /// Another client, even one that authenticates correctly as itself, cannot
    /// refresh the token. A refusal leaves the token alone.
    #[tokio::test]
    async fn a_refresh_token_is_refused_to_a_client_it_was_not_issued_to() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let owner = seed_client(&db, Registration::Public).await;
        let other = seed_client(&db, Registration::Confidential).await;
        let rt = seed_refresh_token(&db, &owner).await;

        let stolen = refresh(
            &db,
            &config,
            &rt,
            Presented {
                client_id: Some(&other),
                form_secret: Some(SECRET),
                header_client_id: None,
                header_secret: None,
            },
        )
        .await;
        assert_eq!(outcome(&stolen), "invalid_grant");
        assert!(
            still_exists(&db, &rt).await,
            "a refusal never deletes the token"
        );

        let own = refresh(
            &db,
            &config,
            &rt,
            Presented {
                client_id: Some(&owner),
                ..NOTHING
            },
        )
        .await;
        assert_eq!(outcome(&own), "ok", "the owner still refreshes it");
    }

    /// Every path that authenticates a client compares digests: the code
    /// exchange and the refresh grant (the secret) and `/client/{id}`
    /// management (the registration access token). A client entry the previous
    /// build stored in the clear authenticates with its secret and token, and
    /// a digest read out of Redis is refused everywhere.
    #[tokio::test]
    async fn every_client_authentication_compares_digests_of_what_is_presented() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let id = unique("prev-client-");
        let metadata = SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://example.com/cb".into()).unwrap()],
            LogoutClientMetadata::default(),
        )
        .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::ClientSecretBasic));
        let previous_build = serde_json::json!({
            "secret": SECRET,
            "metadata": metadata,
            "access_token": "the-registration-token",
        });
        db.set_ex_raw(&format!("clients/{id}"), &previous_build.to_string(), 600)
            .await
            .unwrap();
        let bearer = |token: &str| Some(headers::Authorization::bearer(token).unwrap().0);
        let outcome = |r: Result<(), CustomError>| match r {
            Ok(()) => "ok".to_string(),
            Err(CustomError::Unauthorized(message)) => format!("invalid_client: {message}"),
            Err(other) => format!("{other:?}"),
        };

        // The previous build's entry: the plaintext credentials authenticate.
        let code = authenticate_code_client(&id, None, Some(SECRET), &config, &db).await;
        assert_eq!(outcome(code.map(|_| ())), "ok");
        let stored = db.get_client(id.clone()).await.unwrap().unwrap();
        assert!(!db
            .get_raw(&format!("clients/{id}"))
            .await
            .unwrap()
            .unwrap()
            .contains(SECRET));
        let refresh = authenticate_refresh_client(&id, None, Some(SECRET), &config, &db).await;
        assert_eq!(outcome(refresh), "ok");
        let manage = client_access(id.clone(), bearer("the-registration-token"), &db).await;
        assert_eq!(outcome(manage.map(|_| ())), "ok");

        // What Redis holds is no credential.
        let secret_digest = stored.secret_digest.as_str();
        let token_digest = stored.access_token_digest.clone().unwrap();
        let code = authenticate_code_client(&id, None, Some(secret_digest), &config, &db).await;
        assert_eq!(outcome(code.map(|_| ())), "invalid_client: Bad secret.");
        let refresh =
            authenticate_refresh_client(&id, None, Some(secret_digest), &config, &db).await;
        assert_eq!(outcome(refresh), "invalid_client: Bad secret.");
        let manage = client_access(id.clone(), bearer(&token_digest), &db).await;
        assert_eq!(
            outcome(manage.map(|_| ())),
            "invalid_client: Bad access token."
        );
        db.del_raw(&format!("clients/{id}")).await.unwrap();
    }

    /// A confidential client authenticates at the refresh grant exactly as it
    /// does at the code exchange: with the secret in the form or in a header.
    #[tokio::test]
    async fn a_confidential_client_must_authenticate_to_refresh() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let client = seed_client(&db, Registration::Confidential).await;
        let rt = seed_refresh_token(&db, &client).await;

        for (what, who, expected) in [
            (
                "no credentials",
                NOTHING,
                "invalid_client: Secret required.",
            ),
            (
                "a client_id and no secret",
                Presented {
                    client_id: Some(&client),
                    ..NOTHING
                },
                "invalid_client: Secret required.",
            ),
            (
                "a wrong form secret",
                Presented {
                    client_id: Some(&client),
                    form_secret: Some("wrong"),
                    header_client_id: None,
                    header_secret: None,
                },
                "invalid_client: Bad secret.",
            ),
            (
                "a wrong header secret",
                Presented {
                    header_secret: Some("wrong"),
                    ..NOTHING
                },
                "invalid_client: Bad secret.",
            ),
        ] {
            let result = refresh(&db, &config, &rt, who).await;
            assert_eq!(outcome(&result), expected, "{what}");
            assert!(
                still_exists(&db, &rt).await,
                "{what}: the token is untouched"
            );
        }

        let with_form_secret = refresh(
            &db,
            &config,
            &rt,
            Presented {
                client_id: Some(&client),
                form_secret: Some(SECRET),
                header_client_id: None,
                header_secret: None,
            },
        )
        .await;
        let rt2 = refresh_token_of(with_form_secret);
        let with_header_secret = refresh(
            &db,
            &config,
            &rt2,
            Presented {
                header_secret: Some(SECRET),
                ..NOTHING
            },
        )
        .await;
        assert_eq!(outcome(&with_header_secret), "ok");
    }

    /// A refresh token written before the grant record (`token/{raw}`), as the
    /// previous build left it for `client_id`. Returns the raw token.
    async fn seed_legacy_refresh_token(db: &RedisClient, client_id: &str) -> String {
        seed_legacy_device_refresh_token(db, client_id, "").await
    }

    /// [`seed_legacy_refresh_token`] for a Matrix device: the scope names the
    /// Matrix API and the device, as the previous build wrote an agent's token
    /// (`device_id` empty: a deviceless token with the `openid` scope).
    async fn seed_legacy_device_refresh_token(
        db: &RedisClient,
        client_id: &str,
        device_id: &str,
    ) -> String {
        let raw = format!("mcr_{}", Uuid::new_v4().simple());
        let now = Utc::now().timestamp();
        let scope = if device_id.is_empty() {
            "openid".to_string()
        } else {
            format!("openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}")
        };
        db.set_token(
            &raw,
            &TokenMetadata {
                username: unique("localpart"),
                device_id: device_id.into(),
                scope,
                client_id: client_id.into(),
                iat: now,
                exp: now + REFRESH_TOKEN_TTL as i64,
                did: "did:key:zDnBINDING".into(),
                name: "did:key:zDnBINDING".into(),
                kind: Some(TokenKind::Refresh),
            },
            REFRESH_TOKEN_TTL,
        )
        .await
        .unwrap();
        raw
    }

    /// Item 10 at `POST /token`: a legacy refresh token is lifted into a grant
    /// and answered with a pair in the current format, but only for its own
    /// client, authenticated exactly like any refresh; a refused request leaves
    /// the legacy entry alone. The lifted grant records whether its client is
    /// confidential by the one rule (`client_is_confidential`), so the Matrix
    /// endpoint refuses its tokens exactly when this endpoint demands a secret.
    #[tokio::test]
    async fn a_legacy_refresh_token_is_lifted_for_its_own_client_with_its_confidentiality() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let other = seed_client(&db, Registration::Public).await;
        for registration in [Registration::Confidential, Registration::Public] {
            let client = seed_client(&db, registration).await;
            let legacy = seed_legacy_refresh_token(&db, &client).await;
            let named_other = refresh(
                &db,
                &config,
                &legacy,
                Presented {
                    client_id: Some(&other),
                    ..NOTHING
                },
            )
            .await;
            assert_eq!(
                outcome(&named_other),
                "invalid_grant",
                "{registration:?}: another client"
            );
            let confidential = matches!(registration, Registration::Confidential);
            if confidential {
                let no_secret = refresh(
                    &db,
                    &config,
                    &legacy,
                    Presented {
                        client_id: Some(&client),
                        ..NOTHING
                    },
                )
                .await;
                assert_eq!(outcome(&no_secret), "invalid_client: Secret required.");
            }
            assert!(
                db.get_token(&legacy).await.unwrap().is_some(),
                "{registration:?}: a refused request leaves the legacy entry"
            );

            let lifted = refresh(
                &db,
                &config,
                &legacy,
                Presented {
                    client_id: Some(&client),
                    form_secret: confidential.then_some(SECRET),
                    ..NOTHING
                },
            )
            .await;
            let new_rt = refresh_token_of(lifted);
            assert!(
                siwx_oidc::db::tokens::parse_refresh_token(&new_rt).is_some(),
                "{registration:?}: the answer is in the current format"
            );
            assert!(
                db.get_token(&legacy).await.unwrap().is_none(),
                "{registration:?}: the legacy entry is gone"
            );
            let grant = db.peek_refresh_grant(&new_rt).await.unwrap().unwrap();
            assert_eq!(grant.client_id, client);
            assert_eq!(
                grant.confidential_client, confidential,
                "{registration:?}: the lifted grant records the client's confidentiality"
            );
            assert_eq!(grant.generation, 1);
        }
    }

    /// A public client authenticates nothing: it may name itself or not. Naming
    /// is optional because `siwx-oidc-auth` and Matrix clients send the id but
    /// an older agent may not (provisional: see docs/matrix-integration.md).
    #[tokio::test]
    async fn a_public_client_refreshes_with_or_without_naming_itself() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let client = seed_client(&db, Registration::Public).await;
        let rt = seed_refresh_token(&db, &client).await;

        let named = refresh(
            &db,
            &config,
            &rt,
            Presented {
                client_id: Some(&client),
                ..NOTHING
            },
        )
        .await;
        let rt2 = refresh_token_of(named);
        let anonymous = refresh(&db, &config, &rt2, NOTHING).await;
        assert_eq!(outcome(&anonymous), "ok");
    }

    /// A client registered without an authentication method is confidential
    /// when `require_secret` is on and public when it is off, the same rule the
    /// code exchange applies.
    #[tokio::test]
    async fn an_unset_authentication_method_follows_require_secret() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let client = seed_client(&db, Registration::Unset).await;
        let strict = Config {
            require_secret: true,
            ..Config::default()
        };
        let lax = Config {
            require_secret: false,
            ..Config::default()
        };

        let rt = seed_refresh_token(&db, &client).await;
        assert_eq!(
            outcome(&refresh(&db, &strict, &rt, NOTHING).await),
            "invalid_client: Secret required."
        );
        assert_eq!(outcome(&refresh(&db, &lax, &rt, NOTHING).await), "ok");
    }

    /// A refresh token outlives its client's registration (a registration lasts
    /// 30 days, a refresh token 90 days from its last use). Refusing every such
    /// token would sign out every session older than a registration, so the
    /// token keeps refreshing when the request names the same client or none.
    /// What cannot be done: name another client, or present a secret that can
    /// no longer be checked. Provisional: a deployment decision for the
    /// maintainers (see docs/matrix-integration.md).
    #[tokio::test]
    async fn a_token_outlives_its_clients_registration_but_not_its_binding() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let gone = seed_client(&db, Registration::Public).await;
        let other = seed_client(&db, Registration::Public).await;
        let rt = seed_refresh_token(&db, &gone).await;
        db.delete_client(gone.clone()).await.unwrap();

        assert_eq!(
            outcome(
                &refresh(
                    &db,
                    &config,
                    &rt,
                    Presented {
                        client_id: Some(&other),
                        ..NOTHING
                    }
                )
                .await
            ),
            "invalid_grant",
            "another client is refused"
        );
        assert_eq!(
            outcome(
                &refresh(
                    &db,
                    &config,
                    &rt,
                    Presented {
                        client_id: Some(&gone),
                        form_secret: Some(SECRET),
                        header_client_id: None,
                        header_secret: None
                    }
                )
                .await
            ),
            "invalid_client: Unrecognised client id.",
            "a secret that cannot be checked is refused"
        );
        let named = refresh(
            &db,
            &config,
            &rt,
            Presented {
                client_id: Some(&gone),
                ..NOTHING
            },
        )
        .await;
        let rt2 = refresh_token_of(named);
        assert_eq!(
            outcome(&refresh(&db, &config, &rt2, NOTHING).await),
            "ok",
            "the same client, or none, still refreshes"
        );
    }

    /// The same at the lift: a LEGACY refresh token (`token/{raw}`, written by
    /// a build before the grant record) whose client registration is gone is
    /// lifted and answered in the current format, whether the request names
    /// the client or not, and stays bound to that client. This is the shape of
    /// most refresh tokens a long-running deployment holds at the upgrade (an
    /// agent's registration expires after 30 days, its refresh token lives 90
    /// days from its last use). A registration that is gone counts as public
    /// under either `require_secret` (`client_is_confidential(None)`).
    #[tokio::test]
    async fn a_legacy_token_whose_registration_is_gone_is_lifted_at_the_token_endpoint() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let other = seed_client(&db, Registration::Public).await;
        for require_secret in [true, false] {
            let config = Config {
                require_secret,
                ..Config::default()
            };
            for (device, names_itself) in [
                ("", true),
                ("AQUA_LIFTGONE", true),
                ("AQUA_LIFTGONE", false),
            ] {
                let what = format!(
                    "require_secret={require_secret} device={device:?} names_itself={names_itself}"
                );
                let gone = seed_client(&db, Registration::Public).await;
                let legacy = seed_legacy_device_refresh_token(&db, &gone, device).await;
                db.delete_client(gone.clone()).await.unwrap();

                let foreign = refresh(
                    &db,
                    &config,
                    &legacy,
                    Presented {
                        client_id: Some(&other),
                        ..NOTHING
                    },
                )
                .await;
                assert_eq!(outcome(&foreign), "invalid_grant", "{what}: another client");
                assert!(
                    db.get_token(&legacy).await.unwrap().is_some(),
                    "{what}: a refused request leaves the legacy entry"
                );

                let lifted = refresh(
                    &db,
                    &config,
                    &legacy,
                    Presented {
                        client_id: names_itself.then_some(gone.as_str()),
                        ..NOTHING
                    },
                )
                .await;
                let new_rt = refresh_token_of(lifted);
                assert!(
                    siwx_oidc::db::tokens::parse_refresh_token(&new_rt).is_some(),
                    "{what}: the answer is in the current format"
                );
                assert!(
                    db.get_token(&legacy).await.unwrap().is_none(),
                    "{what}: the legacy entry is gone"
                );
                let grant = db.peek_refresh_grant(&new_rt).await.unwrap().unwrap();
                assert_eq!(grant.client_id, gone, "{what}: still bound to its client");
                assert!(
                    !grant.confidential_client,
                    "{what}: a registration that is gone is public"
                );
                assert_eq!(grant.generation, 1, "{what}");
                assert_eq!(grant.device_id, device, "{what}: the device is kept");

                assert_eq!(
                    outcome(
                        &refresh(
                            &db,
                            &config,
                            &new_rt,
                            Presented {
                                client_id: Some(&other),
                                ..NOTHING
                            }
                        )
                        .await
                    ),
                    "invalid_grant",
                    "{what}: the lifted grant is bound to its client"
                );
                assert_eq!(
                    outcome(&refresh(&db, &config, &new_rt, NOTHING).await),
                    "ok",
                    "{what}: the lifted token rotates"
                );
            }
        }
    }

    /// An HTTP Basic header names the client in its user name, and that is
    /// checked exactly like a `client_id` in the form, at both grants. A form
    /// and a header that name different clients are a malformed request.
    #[tokio::test]
    async fn a_basic_header_names_the_client_like_the_form_does() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let owner = seed_client(&db, Registration::Confidential).await;
        let other = seed_client(&db, Registration::Confidential).await;
        let rt = seed_refresh_token(&db, &owner).await;

        let someone_else = Presented {
            header_client_id: Some(&other),
            header_secret: Some(SECRET),
            ..NOTHING
        };
        assert_eq!(
            outcome(&refresh(&db, &config, &rt, someone_else).await),
            "invalid_grant"
        );
        let spent = seed_code(&db, &owner).await;
        assert_eq!(
            outcome(&exchange(&db, &config, &spent, someone_else).await),
            "invalid_grant"
        );

        // A form and a header that name different clients are malformed, and
        // refused before the code is spent.
        let split = Presented {
            client_id: Some(&owner),
            header_client_id: Some(&other),
            header_secret: Some(SECRET),
            ..NOTHING
        };
        let intact = seed_code(&db, &owner).await;
        assert_eq!(
            outcome(&refresh(&db, &config, &rt, split).await),
            "invalid_request"
        );
        assert_eq!(
            outcome(&exchange(&db, &config, &intact, split).await),
            "invalid_request"
        );
        assert!(
            still_exists(&db, &rt).await,
            "refusals leave the token alone"
        );

        let own = Presented {
            header_client_id: Some(&owner),
            header_secret: Some(SECRET),
            ..NOTHING
        };
        assert_eq!(
            outcome(&exchange(&db, &config, &intact, own).await),
            "ok",
            "the malformed request did not spend the code"
        );
        assert_eq!(outcome(&refresh(&db, &config, &rt, own).await), "ok");
    }

    /// The replay of a lost response (I4) hands out the successor pair, so it
    /// needs the same client binding as a fresh rotation: anyone holding the old
    /// token must not get the new pair without the client's credentials.
    #[tokio::test]
    async fn a_replay_is_bound_to_the_client_too() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let client = seed_client(&db, Registration::Confidential).await;
        let other = seed_client(&db, Registration::Confidential).await;
        let old = seed_refresh_token(&db, &client).await;
        let credentials = Presented {
            client_id: Some(&client),
            form_secret: Some(SECRET),
            header_client_id: None,
            header_secret: None,
        };

        let successor = refresh_token_of(refresh(&db, &config, &old, credentials).await);
        assert_eq!(
            outcome(&refresh(&db, &config, &old, NOTHING).await),
            "invalid_client: Secret required.",
            "a replay without credentials gets no successor pair"
        );
        assert_eq!(
            outcome(
                &refresh(
                    &db,
                    &config,
                    &old,
                    Presented {
                        client_id: Some(&other),
                        form_secret: Some(SECRET),
                        header_client_id: None,
                        header_secret: None
                    }
                )
                .await
            ),
            "invalid_grant",
            "a replay by another client gets no successor pair"
        );
        let replay = refresh_token_of(refresh(&db, &config, &old, credentials).await);
        assert_eq!(
            replay, successor,
            "the client itself still recovers the same pair while it is unused"
        );
    }

    /// A replay returns the successor pair only while that pair is live and
    /// unused. Once the successor has been rotated away or its grant revoked,
    /// handing the pair out would answer a lost-response retry with tokens that
    /// do not work. The replay is `invalid_grant`, like any unknown token.
    #[tokio::test]
    async fn a_replay_whose_successor_has_been_rotated_or_revoked_is_refused() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let client = seed_client(&db, Registration::Public).await;

        // Rotated: the client received the successor and has since used it.
        let old = seed_refresh_token(&db, &client).await;
        let successor = refresh_token_of(refresh(&db, &config, &old, NOTHING).await);
        assert_eq!(
            refresh_token_of(refresh(&db, &config, &old, NOTHING).await),
            successor,
            "while the successor is live the replay returns it"
        );
        let next = refresh_token_of(refresh(&db, &config, &successor, NOTHING).await);
        assert_ne!(next, successor);
        assert_eq!(
            outcome(&refresh(&db, &config, &old, NOTHING).await),
            "invalid_grant",
            "a replay whose successor was rotated gets no pair"
        );

        // Revoked: the successor was deleted before the client used it.
        let old = seed_refresh_token(&db, &client).await;
        let successor = refresh_token_of(refresh(&db, &config, &old, NOTHING).await);
        db.revoke_grant_of_token(&successor)
            .await
            .unwrap()
            .expect("the successor's grant is revoked");
        assert_eq!(
            outcome(&refresh(&db, &config, &old, NOTHING).await),
            "invalid_grant",
            "a replay whose successor was revoked gets no pair"
        );
    }

    /// H2 (I4, I5 phase A): the lost-response decision reads state, never a
    /// clock. With the grant's recorded timestamps moved an hour into the past,
    /// a replay of the previous refresh token still returns the same pair; once
    /// the new access token has been accepted (as introspection or `/userinfo`
    /// accepts it), the same replay is reuse: `invalid_grant`, one security
    /// event with fingerprints only, and nothing revoked.
    #[tokio::test]
    async fn a_replay_an_hour_later_returns_the_same_pair_and_after_use_is_reuse() {
        use bb8_redis::redis::AsyncCommands;
        use openidconnect::OAuth2TokenResponse;
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let client = seed_client(&db, Registration::Public).await;
        let old = seed_refresh_token(&db, &client).await;
        let first = refresh(&db, &config, &old, NOTHING).await.unwrap();
        let pair = (
            first.access_token().secret().clone(),
            refresh_token_of(Ok(first)),
        );

        let grant = db.peek_refresh_grant(&old).await.unwrap().unwrap();
        let key = format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_GRANT_PREFIX,
            grant.grant_id.as_str()
        );
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        for field in ["last_used", "auth_time"] {
            let _: i64 = conn.hincr(&key, field, -3600).await.unwrap();
        }

        let replay = refresh(&db, &config, &old, NOTHING).await.unwrap();
        assert_eq!(
            (
                replay.access_token().secret().clone(),
                refresh_token_of(Ok(replay))
            ),
            pair,
            "an hour later the replay returns the SAME pair"
        );

        assert!(
            db.lookup_access_token(&pair.0).await.unwrap().is_some(),
            "the new access token is accepted"
        );
        let logs = siwx_oidc::test_support::LogCapture::start();
        assert_eq!(
            outcome(&refresh(&db, &config, &old, NOTHING).await),
            "invalid_grant",
            "after first use the replay is reuse, answered like an unknown token"
        );
        let output = logs.output();
        let events: Vec<&str> = output
            .lines()
            .filter(|l| l.contains(siwx_oidc::db::grant::REUSE_EVENT_MESSAGE))
            .collect();
        assert_eq!(events.len(), 1, "exactly one reuse event: {output}");
        let event = events[0];
        for field in [
            "security_event=\"refresh_token_reuse\"",
            "branch=\"previous_after_use\"",
            "grant_kind=oidc",
            "generation=1",
            "grant_revoked=false",
        ] {
            assert!(event.contains(field), "the event carries {field}: {event}");
        }
        assert!(
            event.contains(grant.grant_id.fingerprint()),
            "the event names the grant by its fingerprint: {event}"
        );
        for secret in [&old, &pair.0, &pair.1] {
            assert!(
                !output.contains(secret.as_str()),
                "no token in the logs: {output}"
            );
        }
        assert_eq!(
            outcome(&refresh(&db, &config, &pair.1, NOTHING).await),
            "ok",
            "phase A revokes nothing: the live chain keeps working"
        );
    }

    /// I5 phase B at `POST /token`, with `reuse_revokes_grant` on: a superseded
    /// refresh token gets exactly the answer an unknown token gets, the reuse
    /// event records that the grant was revoked, and the grant is gone, so the
    /// current holder's refresh token is refused too and the RP is sent one
    /// back-channel logout token.
    #[tokio::test]
    async fn with_reuse_enforcement_a_superseded_token_at_the_token_endpoint_ends_its_grant() {
        let Some(base) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let db = base.clone().with_reuse_enforcement(true);
        let config = Config::default();
        let client = seed_client(&db, Registration::Public).await;
        let first = seed_refresh_token(&db, &client).await;
        let grant = db.peek_refresh_grant(&first).await.unwrap().unwrap();
        let second = refresh_token_of(refresh(&db, &config, &first, NOTHING).await);
        let current = refresh_token_of(refresh(&db, &config, &second, NOTHING).await);

        let unknown = refresh(&db, &config, "mcr_not_a_token", NOTHING).await;
        let logs = siwx_oidc::test_support::LogCapture::start();
        let reused = refresh(&db, &config, &first, NOTHING).await;
        assert_eq!(outcome(&reused), "invalid_grant");
        assert_eq!(
            format!("{reused:?}"),
            format!("{unknown:?}"),
            "reuse is answered exactly like an unknown token"
        );
        let output = logs.output();
        let events: Vec<&str> = output
            .lines()
            .filter(|l| l.contains(siwx_oidc::db::grant::REUSE_EVENT_MESSAGE))
            .collect();
        assert_eq!(events.len(), 1, "exactly one reuse event: {output}");
        assert!(
            events[0].contains("grant_revoked=true"),
            "the event records the revocation: {}",
            events[0]
        );

        assert!(
            db.peek_refresh_grant(&current).await.unwrap().is_none(),
            "the grant is gone"
        );
        assert_eq!(
            outcome(&refresh(&db, &config, &current, NOTHING).await),
            "invalid_grant",
            "the current holder is refused at its next refresh"
        );
        let queued = db
            .pending_logout_entries()
            .await
            .unwrap()
            .into_iter()
            .filter(|(e, _)| e.grant == grant.grant_id.as_str())
            .count();
        assert_eq!(queued, 1, "one back-channel logout entry for the RP");
    }

    /// A grant records its client as confidential exactly when `POST /token`
    /// demands that client's secret: the one rule (`client_is_confidential`)
    /// behind both, so `POST /_matrix/client/v3/refresh`, which refuses a
    /// confidential client's grant, refuses exactly the grants it could not
    /// authenticate.
    #[tokio::test]
    async fn a_grant_records_its_client_as_confidential_exactly_when_token_demands_a_secret() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let strict = Config {
            require_secret: true,
            ..Config::default()
        };
        let lax = Config {
            require_secret: false,
            ..Config::default()
        };
        for (registration, config, label, confidential) in [
            (Registration::Public, &strict, "public", false),
            (Registration::Confidential, &lax, "confidential", true),
            (Registration::Unset, &strict, "unset, secret required", true),
            (Registration::Unset, &lax, "unset, secret optional", false),
        ] {
            let client = seed_client(&db, registration).await;
            let code = seed_code_with_scope(&db, &client, Some("openid offline_access")).await;
            let with_secret = Presented {
                client_id: Some(&client),
                form_secret: Some(SECRET),
                header_client_id: None,
                header_secret: None,
            };
            let rt = refresh_token_of(exchange(&db, config, &code, with_secret).await);
            let grant = db.peek_refresh_grant(&rt).await.unwrap().unwrap();
            assert_eq!(
                grant.confidential_client, confidential,
                "{label}: the flag the grant records"
            );
            let named_only = Presented {
                client_id: Some(&client),
                ..NOTHING
            };
            let demanded = outcome(&refresh(&db, config, &rt, named_only).await)
                == "invalid_client: Secret required.";
            assert_eq!(
                grant.confidential_client, demanded,
                "{label}: the recorded flag and the secret /token demands agree"
            );
        }
    }

    /// The two grants authenticate the client through the same helpers, so
    /// they cannot drift: every way a request can present itself gets the same
    /// answer from the code exchange and the refresh grant.
    #[tokio::test]
    async fn the_code_exchange_and_the_refresh_grant_authenticate_clients_identically() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let strict = Config {
            require_secret: true,
            ..Config::default()
        };
        let lax = Config {
            require_secret: false,
            ..Config::default()
        };
        let other = seed_client(&db, Registration::Confidential).await;

        for (registration, config, label) in [
            (Registration::Public, &strict, "public"),
            (Registration::Confidential, &strict, "confidential"),
            (Registration::Unset, &strict, "unset, secret required"),
            (Registration::Unset, &lax, "unset, secret optional"),
        ] {
            let client = seed_client(&db, registration).await;
            for (what, who) in [
                ("nothing", NOTHING),
                (
                    "its id",
                    Presented {
                        client_id: Some(&client),
                        ..NOTHING
                    },
                ),
                (
                    "its id and secret",
                    Presented {
                        client_id: Some(&client),
                        form_secret: Some(SECRET),
                        header_client_id: None,
                        header_secret: None,
                    },
                ),
                (
                    "its id and a wrong secret",
                    Presented {
                        client_id: Some(&client),
                        form_secret: Some("wrong"),
                        header_client_id: None,
                        header_secret: None,
                    },
                ),
                (
                    "a header secret",
                    Presented {
                        header_secret: Some(SECRET),
                        ..NOTHING
                    },
                ),
                (
                    "another client's id and secret",
                    Presented {
                        client_id: Some(&other),
                        form_secret: Some(SECRET),
                        header_client_id: None,
                        header_secret: None,
                    },
                ),
            ] {
                let code = seed_code(&db, &client).await;
                let rt = seed_refresh_token(&db, &client).await;
                let by_code = outcome(&exchange(&db, config, &code, who).await);
                let by_refresh = outcome(&refresh(&db, config, &rt, who).await);
                assert_eq!(
                    by_refresh, by_code,
                    "{label} client presenting {what}: the refresh grant answered \
                     `{by_refresh}`, the code exchange `{by_code}`"
                );
            }
        }
    }
}

#[cfg(test)]
mod scope_grant_tests {
    //! What the code exchange issues for the scope that was requested.
    //!
    //! Generic mode (no MAS shared secret) grants only what was asked for and
    //! allowed, and issues a refresh token only for `offline_access` to a client
    //! whose registration allows the refresh grant (I10). Matrix mode is
    //! unchanged: the Matrix scope for the device and a refresh token, whatever
    //! was requested. Needs Redis.
    use super::client_binding_tests::{
        seed_client_with, seed_code_with_scope, unique, Registration, VERIFIER,
    };
    use super::*;
    use crate::config::Config;
    use openidconnect::OAuth2TokenResponse;

    fn generic() -> Config {
        Config::default()
    }

    fn matrix() -> Config {
        Config {
            mas_shared_secret: Some("shared-secret".to_string()),
            ..Config::default()
        }
    }

    fn may_refresh() -> Option<Vec<CoreGrantType>> {
        Some(vec![
            CoreGrantType::AuthorizationCode,
            CoreGrantType::RefreshToken,
        ])
    }

    fn code_grant_only() -> Option<Vec<CoreGrantType>> {
        Some(vec![CoreGrantType::AuthorizationCode])
    }

    /// Redeem a code for a public client that sends no secret.
    async fn exchange(
        db: &RedisClient,
        config: &Config,
        client_id: &str,
        code: &str,
    ) -> SiwxTokenResponse {
        token(
            TokenForm {
                code: Some(code.to_string()),
                client_id: Some(client_id.to_string()),
                client_secret: None,
                grant_type: CoreGrantType::AuthorizationCode,
                code_verifier: Some(VERIFIER.to_string()),
                refresh_token: None,
                device_code: None,
            },
            ClientCredentials::default(),
            &EcdsaSigningKey::generate(),
            config,
            db,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("the exchange must succeed: {e:?}"))
    }

    /// A public client, a code that asked for `scope`, and the exchange.
    async fn issue(
        db: &RedisClient,
        config: &Config,
        grants: Option<Vec<CoreGrantType>>,
        scope: Option<&str>,
    ) -> SiwxTokenResponse {
        let client = seed_client_with(db, Registration::Public, grants).await;
        let code = seed_code_with_scope(db, &client, scope).await;
        exchange(db, config, &client, &code).await
    }

    fn scope_of(response: &SiwxTokenResponse) -> Option<String> {
        response.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    async fn recorded_scope(db: &RedisClient, response: &SiwxTokenResponse) -> String {
        db.check_access_token(response.access_token().secret())
            .await
            .unwrap()
            .expect("the access token is stored")
            .scope
    }

    /// Without `offline_access` there is no refresh token: a client that did
    /// not ask for one does not hold a credential that outlives its session.
    #[tokio::test]
    async fn generic_mode_issues_a_refresh_token_only_for_offline_access() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };

        let without = issue(&db, &generic(), may_refresh(), Some("openid profile")).await;
        assert!(
            without.refresh_token().is_none(),
            "no offline_access, no refresh token"
        );
        assert_eq!(recorded_scope(&db, &without).await, "openid profile");
        assert_eq!(
            scope_of(&without),
            None,
            "the granted scope equals the requested one, so the response omits it"
        );

        let with = issue(
            &db,
            &generic(),
            may_refresh(),
            Some("openid profile offline_access"),
        )
        .await;
        assert!(with.refresh_token().is_some(), "offline_access asked for");
        assert_eq!(
            recorded_scope(&db, &with).await,
            "openid profile offline_access"
        );
        assert_eq!(scope_of(&with), None, "granted as requested");
    }

    /// `offline_access` also needs the client's registration to allow the
    /// refresh grant. The scope that is not granted is not in the issued scope,
    /// and the response says what was granted because it differs.
    #[tokio::test]
    async fn generic_mode_grants_offline_access_only_to_a_client_that_may_refresh() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };

        let refused = issue(
            &db,
            &generic(),
            code_grant_only(),
            Some("openid offline_access"),
        )
        .await;
        assert!(
            refused.refresh_token().is_none(),
            "the registration lists no refresh_token grant"
        );
        assert_eq!(recorded_scope(&db, &refused).await, "openid");
        assert_eq!(
            scope_of(&refused).as_deref(),
            Some("openid"),
            "the response names the granted scope, which differs from the request"
        );

        // Provisional: a registration that names no grant types is not a
        // restriction. A client that never listed any would otherwise lose
        // refresh tokens it was entitled to under the registration it made.
        let unspecified = issue(&db, &generic(), None, Some("openid offline_access")).await;
        assert!(unspecified.refresh_token().is_some());
        assert_eq!(
            recorded_scope(&db, &unspecified).await,
            "openid offline_access"
        );
    }

    /// The issued scope reflects the request intersected with what generic mode
    /// supports; Matrix scopes mean nothing there and are not granted.
    #[tokio::test]
    async fn generic_mode_issues_the_scope_that_was_requested_and_supported() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };

        let openid_only = issue(&db, &generic(), may_refresh(), Some("openid")).await;
        assert_eq!(recorded_scope(&db, &openid_only).await, "openid");

        let mixed = issue(
            &db,
            &generic(),
            may_refresh(),
            Some("openid email urn:matrix:client:api:* profile"),
        )
        .await;
        assert_eq!(
            recorded_scope(&db, &mixed).await,
            "openid profile",
            "supported scopes only, in a fixed order"
        );
        assert_eq!(
            scope_of(&mixed).as_deref(),
            Some("openid profile"),
            "the granted scope differs from the request, so the response says so"
        );

        // Nothing supported was asked for: the exchange still issues an ID
        // token, so `openid` is what is granted (provisional).
        let matrix_only = issue(
            &db,
            &generic(),
            may_refresh(),
            Some("urn:matrix:client:api:*"),
        )
        .await;
        assert_eq!(recorded_scope(&db, &matrix_only).await, "openid");
    }

    /// A code written before the scope travelled with it (an earlier build, for
    /// the 300 s a code lives) is exchanged as it was then: `openid profile`
    /// and a refresh token.
    #[tokio::test]
    async fn generic_mode_exchanges_a_code_with_no_recorded_scope_as_before() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let legacy = issue(&db, &generic(), may_refresh(), None).await;
        assert!(legacy.refresh_token().is_some());
        assert_eq!(recorded_scope(&db, &legacy).await, "openid profile");
        assert_eq!(scope_of(&legacy), None);
    }

    /// Matrix mode is unchanged: whatever the request asked for, the code grant
    /// records the Matrix scope for the device and issues a refresh token, and
    /// the response carries no `scope`.
    /// The claims of a response's ID token, decoded without verification.
    pub(super) fn id_token_claims(response: &SiwxTokenResponse) -> serde_json::Value {
        let jws = response
            .extra_fields()
            .id_token()
            .expect("the code exchange returns an ID token")
            .to_string();
        let payload = jws.split('.').nth(1).expect("a compact JWS");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }

    /// One raw `GET` on the test Redis.
    pub(super) async fn raw_get(key: &str) -> Option<String> {
        let url = siwx_oidc::test_support::redis_url();
        let client = bb8_redis::redis::Client::open(url.as_str()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        bb8_redis::redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap()
    }

    /// The grant id an access token belongs to, read from the store.
    async fn grant_of_access_token(access: &str) -> Option<String> {
        let url = siwx_oidc::test_support::redis_url();
        let client = bb8_redis::redis::Client::open(url.as_str()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let key = format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            siwx_oidc::db::tokens::digest(access)
        );
        bb8_redis::redis::cmd("HGET")
            .arg(key)
            .arg("grant")
            .query_async(&mut conn)
            .await
            .unwrap()
    }

    /// Every ID token carries the `sid` of the grant the exchange created (I8),
    /// in both modes, and two exchanges get two different sids.
    #[tokio::test]
    async fn every_id_token_carries_the_sid_of_its_grant() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let mut sids = Vec::new();
        for config in [generic(), generic(), matrix()] {
            let response = issue(&db, &config, may_refresh(), Some("openid offline_access")).await;
            let claims = id_token_claims(&response);
            let sid = claims["sid"]
                .as_str()
                .unwrap_or_else(|| panic!("the ID token carries a sid: {claims}"))
                .to_string();
            let grant = grant_of_access_token(response.access_token().secret())
                .await
                .expect("the access token names its grant");
            assert_eq!(
                raw_get(&format!(
                    "{}/{sid}",
                    siwx_oidc::db::grant::KV_GRANT_SID_IDX_PREFIX
                ))
                .await
                .as_deref(),
                Some(grant.as_str()),
                "the sid names the grant of this exchange"
            );
            assert!(!sids.contains(&sid), "each grant has its own sid");
            sids.push(sid);
        }
    }

    #[tokio::test]
    async fn matrix_mode_issues_the_matrix_scope_and_a_refresh_token_whatever_was_requested() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        for requested in [
            None,
            Some("openid"),
            Some("openid profile"),
            Some("openid offline_access"),
            Some("urn:matrix:client:api:*"),
        ] {
            let client = seed_client_with(&db, Registration::Public, code_grant_only()).await;
            let code = seed_code_with_scope(&db, &client, requested).await;
            // Give the code a device, as provisioning does.
            let mut entry = db.try_consume_code(code).await.unwrap().unwrap();
            entry.device_id = Some("SIWX_ABCD1234".to_string());
            let code = unique("code-");
            db.set_code(code.clone(), entry).await.unwrap();

            let response = exchange(&db, &matrix(), &client, &code).await;
            assert!(
                response.refresh_token().is_some(),
                "Matrix mode issues a refresh token (requested {requested:?})"
            );
            assert_eq!(
                recorded_scope(&db, &response).await,
                "openid urn:matrix:client:api:* urn:matrix:client:device:SIWX_ABCD1234",
                "requested {requested:?}"
            );
            assert_eq!(
                scope_of(&response),
                None,
                "Matrix mode never put a scope in the token response (requested {requested:?})"
            );
            assert!(
                response.access_token().secret().starts_with("mat_")
                    && response
                        .refresh_token()
                        .unwrap()
                        .secret()
                        .starts_with("mcr_"),
                "Matrix token prefixes are unchanged"
            );
        }
    }

    fn registration(grants: Option<Vec<CoreGrantType>>) -> ClientEntry {
        let mut metadata = SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://example.com/cb".into()).unwrap()],
            LogoutClientMetadata::default(),
        );
        if let Some(grants) = grants {
            metadata = metadata.set_grant_types(Some(grants));
        }
        ClientEntry::new("secret", metadata, None)
    }

    /// The pure decision, without Redis: ordering and duplicates do not matter,
    /// the response names the scope only when it differs from the request.
    #[test]
    fn the_generic_grant_follows_the_request_and_the_registration() {
        let grant =
            |requested: Option<&str>, grants| generic_grant(requested, &registration(grants));
        let expect = |scope: &str, refresh_token: bool, report_scope: bool| GenericGrant {
            scope: scope.to_string(),
            refresh_token,
            report_scope,
        };

        assert_eq!(
            grant(Some("profile  openid openid"), None),
            expect("openid profile", false, false),
            "order, spacing and repeats of the request are immaterial"
        );
        assert_eq!(
            grant(Some("offline_access openid"), may_refresh()),
            expect("openid offline_access", true, false)
        );
        assert_eq!(
            grant(Some("openid offline_access"), code_grant_only()),
            expect("openid", false, true),
            "offline_access needs the refresh grant in the registration"
        );
        assert_eq!(
            grant(Some("openid email"), None),
            expect("openid", false, true),
            "a scope generic mode does not know is not granted"
        );
        assert_eq!(
            grant(Some(""), None),
            expect("openid", false, true),
            "nothing requested: openid, because an ID token is issued"
        );
        assert_eq!(
            grant(None, code_grant_only()),
            expect("openid profile", true, false),
            "a code with no recorded scope is exchanged as it was before the scope travelled"
        );
    }

    /// Discovery says `offline_access` is a scope this provider honours.
    #[test]
    fn discovery_advertises_offline_access() {
        let value = provider_metadata_value(&Config::default(), false).unwrap();
        let scopes: Vec<&str> = value["scopes_supported"]
            .as_array()
            .expect("scopes_supported is an array")
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert!(scopes.contains(&"offline_access"), "{scopes:?}");
        for kept in ["openid", "profile", "urn:matrix:client:api:*"] {
            assert!(scopes.contains(&kept), "{kept} is still advertised");
        }
    }
}

#[cfg(test)]
mod end_session_tests {
    //! RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): the
    //! `id_token_hint` check, the exact `post_logout_redirect_uri` match, the
    //! registration metadata and discovery. Redis-backed tests skip without it.
    use super::client_binding_tests::{unique, VERIFIER};
    use super::scope_grant_tests::id_token_claims;
    use super::*;
    use crate::config::Config;
    use openidconnect::{OAuth2TokenResponse, PostLogoutRedirectUrl};

    fn issuer() -> IssuerUrl {
        IssuerUrl::from_url(Config::default().base_url)
    }

    /// An ID token for `client_id` and `did` carrying `sid`, signed by `key`,
    /// issued `age` seconds ago and valid for `ttl` seconds from then.
    fn id_token(
        key: &EcdsaSigningKey,
        client_id: &str,
        did: &str,
        sid: Option<&str>,
        age: i64,
        ttl: i64,
    ) -> String {
        let iat = Utc::now() - Duration::seconds(age);
        let claims = SiwxIdTokenClaims::new(
            issuer(),
            vec![Audience::new(client_id.to_string())],
            iat + Duration::seconds(ttl),
            iat,
            StandardClaims::new(SubjectIdentifier::new(did.to_string())),
            SidClaims {
                sid: sid.map(str::to_string),
            },
        );
        SiwxIdToken::new(
            claims,
            key,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            None,
            None,
        )
        .unwrap()
        .to_string()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn an_id_token_hint_verifies_with_the_live_or_a_retired_key_expired_or_not() {
        let live = EcdsaSigningKey::generate();
        let fresh = id_token(&live, "rp", "did:key:zDnLive", Some("SID1"), 0, 300);
        let expired = id_token(&live, "rp", "did:key:zDnLive", Some("SID1"), 7200, 300);
        for hint in [&fresh, &expired] {
            assert_eq!(
                verify_id_token_hint(hint, &live, &[], &issuer()),
                Ok(HintClaims {
                    sub: "did:key:zDnLive".into(),
                    aud: vec!["rp".into()],
                    sid: Some("SID1".into()),
                })
            );
        }
        let old = EcdsaSigningKey::generate();
        let by_old = id_token(&old, "rp", "did:key:zDnOld", None, 0, 300);
        assert_eq!(
            verify_id_token_hint(&by_old, &live, &[old.as_verification_key()], &issuer())
                .map(|c| c.sid),
            Ok(None),
            "a retired key still verifies; a hint without a sid names nothing"
        );
        assert_eq!(
            verify_id_token_hint(&by_old, &live, &[], &issuer()),
            Err(HintError::UnknownKid)
        );
    }

    #[test]
    fn a_tampered_foreign_unsigned_or_misissued_hint_is_refused() {
        let live = EcdsaSigningKey::generate();
        let hint = id_token(&live, "rp", "did:key:zDnLive", Some("SID1"), 0, 300);
        let parts: Vec<&str> = hint.split('.').collect();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims["sid"] = serde_json::json!("SID2");
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            b64(claims.to_string().as_bytes()),
            parts[2]
        );
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let foreign_key = EcdsaSigningKey::generate();
        let input = format!("{}.{}", parts[0], parts[1]);
        let foreign = format!("{input}.{}", b64(&foreign_key.sign_es256(input.as_bytes())));
        let with_alg = |alg: &str| {
            let mut h = header.clone();
            h["alg"] = serde_json::json!(alg);
            format!(
                "{}.{}.{}",
                b64(h.to_string().as_bytes()),
                parts[1],
                parts[2]
            )
        };
        let mut no_kid = header.clone();
        no_kid.as_object_mut().unwrap().remove("kid");
        let no_kid = format!(
            "{}.{}.{}",
            b64(no_kid.to_string().as_bytes()),
            parts[1],
            parts[2]
        );
        let other_issuer = IssuerUrl::new("https://other.example.org/".into()).unwrap();
        for (what, hint, issuer, expected) in [
            (
                "a tampered payload",
                tampered,
                issuer(),
                HintError::Signature,
            ),
            (
                "another key under our kid",
                foreign,
                issuer(),
                HintError::Signature,
            ),
            ("alg none", with_alg("none"), issuer(), HintError::Algorithm),
            (
                "alg HS256",
                with_alg("HS256"),
                issuer(),
                HintError::Algorithm,
            ),
            ("no kid", no_kid, issuer(), HintError::UnknownKid),
            (
                "another issuer",
                hint.clone(),
                other_issuer,
                HintError::Issuer,
            ),
            (
                "four parts",
                format!("{hint}.x"),
                issuer(),
                HintError::Malformed,
            ),
            (
                "garbage",
                "garbage".to_string(),
                issuer(),
                HintError::Malformed,
            ),
        ] {
            assert_eq!(
                verify_id_token_hint(&hint, &live, &[], &issuer),
                Err(expected),
                "{what}"
            );
        }
    }

    fn client_metadata(post_logout: &[&str]) -> SiwxClientMetadata {
        SiwxClientMetadata::new(
            vec![RedirectUrl::new("https://rp.example.org/cb".into()).unwrap()],
            LogoutClientMetadata {
                post_logout_redirect_uris: Some(
                    post_logout
                        .iter()
                        .map(|u| PostLogoutRedirectUrl::new(u.to_string()).unwrap())
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None))
        .set_grant_types(Some(vec![
            CoreGrantType::AuthorizationCode,
            CoreGrantType::RefreshToken,
        ]))
    }

    #[test]
    fn post_logout_redirect_uri_matching_is_exact() {
        let client = ClientEntry::new(
            "s",
            client_metadata(&["https://rp.example.org/bye?x=1"]),
            None,
        );
        let is = |u: &str| post_logout_redirect_uri_is_registered(&client, &Url::parse(u).unwrap());
        assert!(is("https://rp.example.org/bye?x=1"));
        for other in [
            "https://rp.example.org/bye",
            "https://rp.example.org/bye?x=1&y=2",
            "https://rp.example.org/bye?x=2",
            "https://rp.example.org/bye/?x=1",
            "http://rp.example.org/bye?x=1",
            "https://rp.example.org.evil.example/bye?x=1",
        ] {
            assert!(!is(other), "{other}");
        }
        let none = ClientEntry::new("s", client_metadata(&[]), None);
        assert!(!post_logout_redirect_uri_is_registered(
            &none,
            &Url::parse("https://rp.example.org/bye?x=1").unwrap()
        ));
    }

    #[test]
    fn discovery_advertises_the_end_session_endpoint() {
        for config in [
            Config::default(),
            Config {
                mas_shared_secret: Some("s".into()),
                ..Config::default()
            },
        ] {
            let value = provider_metadata_value(&config, false).unwrap();
            assert_eq!(
                value["end_session_endpoint"],
                "http://127.0.0.1:8000/end_session"
            );
        }
    }

    #[tokio::test]
    async fn registration_stores_and_echoes_post_logout_redirect_uris_and_refuses_a_fragment() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let base = Config::default().base_url;
        let response = register(
            client_metadata(&["https://rp.example.org/bye"]),
            base.clone(),
            &db,
            &RegistrationPolicy::default(),
        )
        .await
        .expect("registration succeeds");
        let echoed = serde_json::to_value(&response).unwrap();
        assert_eq!(
            echoed["post_logout_redirect_uris"],
            serde_json::json!(["https://rp.example.org/bye"])
        );
        let stored = db
            .get_client(response.client_id().to_string())
            .await
            .unwrap()
            .expect("stored");
        assert!(post_logout_redirect_uri_is_registered(
            &stored,
            &Url::parse("https://rp.example.org/bye").unwrap()
        ));
        let refused = register(
            client_metadata(&["https://rp.example.org/bye#f"]),
            base,
            &db,
            &RegistrationPolicy::default(),
        )
        .await;
        match refused {
            Err(CustomError::BadRequestRegister(e)) => assert_eq!(
                serde_json::to_value(&e).unwrap()["error"],
                "invalid_client_metadata"
            ),
            other => panic!("a fragment must be refused, got {other:?}"),
        }
    }

    /// End-to-end in process, generic mode: an `oidc` grant from a real code
    /// exchange is ended by its ID token, and the RP is sent back to its exact
    /// registered URI with `state`; an expired hint naming another grant ends
    /// that one; nothing else ends.
    #[tokio::test]
    async fn end_session_ends_the_named_oidc_grant_and_redirects_with_state() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let key = EcdsaSigningKey::generate();
        let client_id = unique("endsess-");
        db.set_client(
            client_id.clone(),
            ClientEntry::new("s", client_metadata(&["https://rp.example.org/bye"]), None),
        )
        .await
        .unwrap();
        let code = super::client_binding_tests::seed_code_with_scope(
            &db,
            &client_id,
            Some("openid offline_access"),
        )
        .await;
        let response = token(
            TokenForm {
                code: Some(code),
                client_id: Some(client_id.clone()),
                client_secret: None,
                grant_type: CoreGrantType::AuthorizationCode,
                code_verifier: Some(VERIFIER.to_string()),
                refresh_token: None,
                device_code: None,
            },
            ClientCredentials::default(),
            &key,
            &config,
            &db,
            None,
        )
        .await
        .expect("the exchange succeeds");
        let hint = response.extra_fields().id_token().unwrap().to_string();
        let did = id_token_claims(&response)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        let access = response.access_token().secret().clone();
        let refresh = response
            .refresh_token()
            .expect("offline_access")
            .secret()
            .clone();

        // A second grant of the same client and user, named by an expired hint.
        let other = db
            .issue_grant(&NewGrant {
                kind: GrantKind::Oidc,
                username: unique("lp"),
                did: did.clone(),
                client_id: client_id.clone(),
                confidential_client: false,
                device_id: String::new(),
                scope: "openid".into(),
                name: did.clone(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: None,
            })
            .await
            .unwrap();
        let expired = id_token(&key, &client_id, &did, other.sid.as_deref(), 7200, 300);

        let params = |hint: &str, uri: Option<&str>| EndSessionParams {
            id_token_hint: Some(hint.to_string()),
            client_id: None,
            post_logout_redirect_uri: uri.map(str::to_string),
            state: Some("s 1&2".into()),
        };
        let refused = end_session(
            params(&hint, Some("https://rp.example.org/bye/")),
            &key,
            &[],
            &config,
            &db,
        )
        .await;
        assert!(
            matches!(refused, Err(CustomError::BadRequest(_))),
            "{refused:?}"
        );
        assert!(
            db.check_access_token(&access).await.unwrap().is_some(),
            "a refused request ends nothing"
        );

        let outcome = end_session(
            params(&hint, Some("https://rp.example.org/bye")),
            &key,
            &[],
            &config,
            &db,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            EndSessionOutcome::Redirect(
                Url::parse("https://rp.example.org/bye?state=s+1%262").unwrap()
            )
        );
        assert!(
            db.check_access_token(&access).await.unwrap().is_none(),
            "the access token is inactive"
        );
        assert!(
            matches!(
                db.peek_refresh_token(&refresh).await.unwrap(),
                RefreshPeek::Unknown
            ),
            "the refresh token names nothing"
        );
        assert!(
            db.check_access_token(&other.access_token)
                .await
                .unwrap()
                .is_some(),
            "only the named grant ended"
        );

        let outcome = end_session(params(&expired, None), &key, &[], &config, &db)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            EndSessionOutcome::SignedOut { ended: true },
            "an expired hint still names its grant"
        );
        assert!(db
            .check_access_token(&other.access_token)
            .await
            .unwrap()
            .is_none());
        let again = end_session(params(&expired, None), &key, &[], &config, &db)
            .await
            .unwrap();
        assert_eq!(again, EndSessionOutcome::SignedOut { ended: false });
    }

    /// A store fault on the way is a retryable 503, never an answer about the
    /// request: a fault while ending the grant the hint's `sid` names is not
    /// "nothing to end" (200), and a fault while reading the client for its
    /// `post_logout_redirect_uri` is not "not registered" (400). Each fault is a
    /// value of the wrong type at the key the step reads.
    #[tokio::test]
    async fn a_store_fault_while_ending_the_grant_or_reading_the_client_is_a_503() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let config = Config::default();
        let key = EcdsaSigningKey::generate();
        let did = "did:key:zDnEndSessionFault";
        let params = |hint: String, uri: Option<&str>| EndSessionParams {
            id_token_hint: Some(hint),
            client_id: None,
            post_logout_redirect_uri: uri.map(str::to_string),
            state: None,
        };

        // Ending the grant: the sid index is not a string.
        let client_id = unique("endsess-fault-grant-");
        let sid = unique("SIDFAULT");
        let sid_idx = format!("{}/{sid}", siwx_oidc::db::grant::KV_GRANT_SID_IDX_PREFIX);
        db.sadd_raw(&sid_idx, "x").await.unwrap();
        let hint = id_token(&key, &client_id, did, Some(&sid), 0, 300);
        let outcome = end_session(params(hint, None), &key, &[], &config, &db).await;
        db.del_raw(&sid_idx).await.ok();
        assert!(
            matches!(outcome, Err(CustomError::ServiceUnavailable(_))),
            "a fault ending the grant is a 503, got {outcome:?}"
        );

        // Reading the client: its registration is not a string.
        let client_id = unique("endsess-fault-client-");
        let client_key = format!("clients/{client_id}");
        db.sadd_raw(&client_key, "x").await.unwrap();
        let hint = id_token(&key, &client_id, did, Some(&unique("SID")), 0, 300);
        let outcome = end_session(
            params(hint, Some("https://rp.example.org/bye")),
            &key,
            &[],
            &config,
            &db,
        )
        .await;
        db.del_raw(&client_key).await.ok();
        assert!(
            matches!(outcome, Err(CustomError::ServiceUnavailable(_))),
            "a fault reading the client is a 503, got {outcome:?}"
        );
    }
}

#[cfg(test)]
mod backchannel_registration_tests {
    //! OpenID Connect Back-Channel Logout 1.0: the registration metadata, the
    //! SSRF guard at registration, the D4 switch and discovery.
    use super::*;
    use crate::config::Config;

    fn payload(extra: serde_json::Value) -> SiwxClientMetadata {
        let mut doc = serde_json::json!({ "redirect_uris": ["https://rp.example.org/cb"] });
        for (k, v) in extra.as_object().unwrap() {
            doc[k] = v.clone();
        }
        serde_json::from_value(doc).unwrap()
    }

    fn refused_as_metadata(result: Result<impl std::fmt::Debug, CustomError>, what: &str) {
        match result {
            Err(CustomError::BadRequestRegister(e)) => assert_eq!(
                serde_json::to_value(&e).unwrap()["error"],
                "invalid_client_metadata",
                "{what}"
            ),
            other => panic!("{what} must be refused as invalid_client_metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn registration_stores_backchannel_logout_metadata_and_refuses_an_unsafe_uri() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let base = Config::default().base_url;
        let open = RegistrationPolicy::default();
        let response = register(
            payload(serde_json::json!({
                "backchannel_logout_uri": "https://192.0.2.10/bcl?rp=1",
                "backchannel_logout_session_required": true,
            })),
            base.clone(),
            &db,
            &open,
        )
        .await
        .expect("a public https URI is accepted");
        let echoed = serde_json::to_value(&response).unwrap();
        assert_eq!(
            echoed["backchannel_logout_uri"],
            "https://192.0.2.10/bcl?rp=1"
        );
        assert_eq!(echoed["backchannel_logout_session_required"], true);
        let stored = db
            .get_client(response.client_id().to_string())
            .await
            .unwrap()
            .expect("stored");
        let extra = stored.metadata.additional_metadata();
        assert_eq!(
            extra.backchannel_logout_uri.as_ref().map(Url::as_str),
            Some("https://192.0.2.10/bcl?rp=1")
        );
        assert_eq!(extra.backchannel_logout_session_required, Some(true));

        for uri in [
            "http://192.0.2.10/bcl",
            "https://192.0.2.10/bcl#f",
            "https://127.0.0.1/bcl",
            "https://[::1]/bcl",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/bcl",
            "https://[fd00::1]/bcl",
            "https://100.64.0.1/bcl",
            "https://localhost/bcl",
        ] {
            let result = register(
                payload(serde_json::json!({ "backchannel_logout_uri": uri })),
                base.clone(),
                &db,
                &open,
            )
            .await;
            refused_as_metadata(result, uri);
        }

        let listed = RegistrationPolicy {
            guard: crate::backchannel::UriGuard::new(&["localhost".to_string()]),
            ..RegistrationPolicy::default()
        };
        register(
            payload(serde_json::json!({ "backchannel_logout_uri": "http://localhost:9/bcl" })),
            base.clone(),
            &db,
            &listed,
        )
        .await
        .expect("an allowlisted host is accepted");

        let id = response.client_id().to_string();
        let token = response
            .registration_access_token()
            .unwrap()
            .secret()
            .clone();
        let update = client_update(
            id,
            payload(serde_json::json!({ "backchannel_logout_uri": "https://127.0.0.1/bcl" })),
            Some(headers::Authorization::bearer(&token).unwrap().0),
            &db,
            &open,
        )
        .await;
        refused_as_metadata(update, "an update to a loopback URI");
    }

    #[tokio::test]
    async fn the_d4_switch_requires_a_backchannel_uri_from_a_client_that_may_refresh() {
        let Some(db) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let generic_on = Config {
            backchannel_logout_required_for_refresh: true,
            ..Config::default()
        };
        let matrix_on = Config {
            mas_shared_secret: Some("s".into()),
            ..generic_on.clone()
        };
        let base = Config::default().base_url;
        let required = RegistrationPolicy::from_config(&generic_on);
        assert!(required.require_backchannel_for_refresh);
        for (what, extra) in [
            ("no grant_types (refresh allowed)", serde_json::json!({})),
            (
                "grant_types with refresh_token",
                serde_json::json!({"grant_types": ["authorization_code", "refresh_token"]}),
            ),
        ] {
            let result = register(payload(extra), base.clone(), &db, &required).await;
            refused_as_metadata(result, what);
        }
        for (what, extra, policy) in [
            (
                "a client that may not refresh",
                serde_json::json!({"grant_types": ["authorization_code"]}),
                required.clone(),
            ),
            (
                "a client with a back-channel URI",
                serde_json::json!({"backchannel_logout_uri": "https://192.0.2.10/bcl"}),
                required.clone(),
            ),
            (
                "the switch off",
                serde_json::json!({}),
                RegistrationPolicy::from_config(&Config::default()),
            ),
            (
                "Matrix mode",
                serde_json::json!({}),
                RegistrationPolicy::from_config(&matrix_on),
            ),
        ] {
            register(payload(extra), base.clone(), &db, &policy)
                .await
                .unwrap_or_else(|e| panic!("{what} registers: {e:?}"));
        }
    }

    #[test]
    fn discovery_advertises_backchannel_logout_only_in_generic_mode() {
        let generic = provider_metadata_value(&Config::default(), false).unwrap();
        assert_eq!(generic["backchannel_logout_supported"], true);
        assert_eq!(generic["backchannel_logout_session_supported"], true);
        let matrix = provider_metadata_value(
            &Config {
                mas_shared_secret: Some("s".into()),
                ..Config::default()
            },
            true,
        )
        .unwrap();
        assert!(
            matrix.get("backchannel_logout_supported").is_none()
                && matrix.get("backchannel_logout_session_supported").is_none(),
            "Matrix mode sends no logout token, so it advertises none: {matrix}"
        );
    }
}
