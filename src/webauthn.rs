//! WebAuthn/passkey ceremony — server-layer authentication (Layer 2).
//!
//! This module handles the full WebAuthn ceremony. Registration and challenge
//! issuance use the `webauthn-rs` safe API; assertions are verified by
//! `aqua_auth::verify_webauthn_assertion` against the challenge stored in Redis
//! (see `verify_credential`).
//! It does NOT extend `DIDMethod` — see docs/design/webauthn-plan.md for rationale.
//!
//! After successful authentication, the verified DID is stored in the Redis session.
//! `sign_in` reads it from there (server-side, trusted).

use anyhow::{anyhow, Result};
use aqua_auth::{verify_webauthn_assertion, AssertionPolicy, WebAuthnAssertionParams};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use siwx_oidc::db::{Ceremony, DBClient};
use thiserror::Error;
use tracing::{info, warn};
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{AllowCredentials, AuthenticatorSelectionCriteria, ResidentKeyRequirement};

use siwx_oidc::db::RedisClient;

// -- Redis key prefixes for WebAuthn state --

const CREDENTIAL_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_CREDENTIAL_PREFIX;
// The same constant the library's credential-identity resolver and the backfill
// read, so a reader and this writer cannot drift onto different key spellings.
// Ownership of the namespace is unchanged: `link_finish` is still the only
// writer.
const LINK_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_LINK_PREFIX;
const CHALLENGE_TTL: u64 = 120; // 2 min

// -- DID derivation from P-256 public key --
//
// Not implemented here. `aqua_auth::p256_compressed_from_passkey` and
// `aqua_auth::did_key_from_p256_compressed` are the same computation, and since
// the `=0.6.1-dev` alignment `Passkey` is literally the same type in both
// crates, so the local copies (a multicodec constant, a COSE -> compressed-SEC1
// extractor, and a base58 encoder) were duplicates rather than an independent
// implementation. Byte-identity is pinned by
// `derivation_is_byte_identical_to_the_pre_0_7_0_local_helpers` below, against
// the values the deleted code produced for the real fixture blob.

/// The compressed (33-byte SEC1) P-256 public key a passkey authenticates with.
fn compressed_pubkey_from_passkey(passkey: &Passkey) -> Result<[u8; 33]> {
    aqua_auth::p256_compressed_from_passkey(passkey).map_err(|e| anyhow!("{}", e))
}

fn did_from_passkey(passkey: &Passkey) -> Result<String> {
    let compressed = compressed_pubkey_from_passkey(passkey)?;
    Ok(aqua_auth::did_key_from_p256_compressed(&compressed))
}

/// Derive the `did:key:zDn…` for a stored WebAuthn credential from its raw JSON
/// (the value stored at `webauthn:credential/{cred_id}`), or `None` if the JSON
/// is not a deserializable P-256 passkey.
///
/// This is the resolver `RedisClient::purge_identity` uses for its best-effort
/// standalone-credential pass: it lets the DB layer stay free of the webauthn-rs
/// types while still reusing the single source of truth for DID derivation.
pub fn derive_did_from_credential_json(cred_json: &str) -> Option<String> {
    let passkey: Passkey = serde_json::from_str(cred_json).ok()?;
    did_from_passkey(&passkey).ok()
}

/// The error message returned by every server-enforced new-account-creation
/// reject (account re-auth + QR/device approval). New-account creation is
/// permitted ONLY at the login screen, behind the new-user gate; in the
/// account-management and QR/device-approval flows it is impossible.
pub const NEW_IDENTITY_REJECT_MSG: &str =
    "This passkey/wallet is not linked to an existing account. \
     Create an account at sign-in first.";

/// The error message returned when the new-account check could not be
/// **completed** — as distinct from completing and finding no account.
///
/// # Why this is a second message and not the same one
///
/// [`reject_if_new_identity`] fails closed on both facts, and it must keep doing
/// so: nothing is provisioned either way, and sign-in is equally broken, so no
/// duplicate account can be created down either path. But the two facts are not
/// the same fact, and until this constant existed they shared
/// [`NEW_IDENTITY_REJECT_MSG`] — so a server-side misconfiguration told the user
/// to go and create an account. That is a safe answer and a misleading
/// diagnosis: the user cannot fix it, the advice cannot even be *followed*
/// (sign-in is down too), and the real cause is invisible to the only person who
/// could act on it. The two real causes are an unreachable Synapse and a
/// rejected MAS shared secret — the latter an `Err` rather than a silent "the
/// localpart is taken" only since the availability-conflation fix
/// (`docs/audits/2026-09-12-localpart-availability-conflation.md`), which is
/// what made this message worth separating out.
///
/// # What it may and may not say
///
/// It names the server as the faulty party, says the condition is worth
/// retrying, and points at an administrator if it persists. It deliberately
/// leaks **nothing** operational: no Synapse endpoint, no HTTP status, no
/// errcode, and above all no hint that a shared secret is involved — this body
/// is rendered verbatim by the account and device-approval pages to a caller who
/// has proven a DID but is otherwise a stranger. Everything diagnostic goes to
/// the `warn!` beside the reject, which is the surface an operator reads and a
/// caller does not. Pinned by
/// `the_detection_failure_message_leaks_no_server_internals`.
///
/// # The asymmetry with [`reject_if_deactivated`] was WITHDRAWN (2026-09-13)
///
/// This paragraph used to say the analogous split would be wrong in that gate,
/// because distinguishing "deactivated" from "could not tell" would let an
/// **unauthenticated prober** learn account state. A follow-up audit falsified
/// the premise: there is no unauthenticated prober at any of that gate's five
/// call sites — every one runs after a verified CAIP-122 signature or a
/// verified WebAuthn assertion for the very DID being asked about — and on a
/// healthy server its 401 already identified deactivation uniquely, so the
/// conflation blurred nothing an attacker could induce. It only told every user
/// on an unhealthy homeserver that their account had been deactivated.
///
/// [`reject_if_deactivated`] therefore now splits its arms the same way this
/// one does, and the two gates are **symmetric**. The full evidence — the
/// call-site table and the healthy-server argument — lives at
/// [`DEACTIVATION_CHECK_UNAVAILABLE_MSG`]. Do not restore either conflation.
///
/// Distinguishing the two cases here leaks nothing independently of that
/// argument, because the fact being distinguished is already public:
/// `GET /resolve?did=…` answers `exists: false` for exactly this condition, and
/// the DID → localpart derivation is a pure `sha2` function
/// ([`crate::localpart`] over `mxid::localpart_for`) that anyone can compute
/// offline.
pub const IDENTITY_CHECK_UNAVAILABLE_MSG: &str =
    "The server could not complete a required account check right now. \
     Nothing has been changed. Please try again in a moment, and contact a \
     server administrator if this keeps happening.";

/// Server-enforced reject for the account + QR/device flows: if a Synapse client
/// is configured AND the authenticated `did` resolves to a NON-existent account
/// under EITHER localpart scheme (`resolve_identity(..).is_new == true` — see
/// `crate::localpart`, which checks the grandfathered legacy shape first and
/// only then the modern one), return a clear `BadRequest` and provision
/// nothing. Call this AFTER the DID is cryptographically verified but BEFORE any
/// action runs / any device-code entry is mutated.
///
/// Graceful degradation: when `synapse` is `None` the new-identity status cannot
/// be detected, so this is a no-op (the flow's existing `require_synapse` /
/// `server_name` guards already `BadRequest` for the actions that need Synapse).
/// Returning the existing-identity path unchanged keeps `is_new == false`
/// a strict no-op.
///
/// # Two rejects, two different facts
///
/// Both reject and both fail closed — that part is the security property and
/// must not change — but they are reported differently, because they are
/// different answers to the user:
///
/// | Outcome | Error | Status | Meaning |
/// |---|---|---|---|
/// | `Ok(is_new == true)` | `BadRequest(`[`NEW_IDENTITY_REJECT_MSG`]`)` | 400 | the check RAN: there is no such account, and this flow may not create one |
/// | `Err(_)` | `ServiceUnavailable(`[`IDENTITY_CHECK_UNAVAILABLE_MSG`]`)` | 503 | the check could not run at all; we say nothing about whether the account exists |
///
/// Collapsing the second into the first is safe but misleading, and was the
/// behaviour until this split — see [`IDENTITY_CHECK_UNAVAILABLE_MSG`] for the
/// full argument. [`reject_if_deactivated`] now splits its arms the same way
/// (2026-09-13); the asymmetry an earlier revision of these docs recorded
/// between the two gates has been withdrawn.
pub async fn reject_if_new_identity(
    synapse: Option<&crate::synapse_client::SynapseClient>,
    did: &str,
) -> Result<(), crate::oidc::CustomError> {
    let synapse = match synapse {
        Some(s) => s,
        None => return Ok(()),
    };
    match crate::localpart::resolve_identity(did, Some(synapse)).await {
        Ok(resolved) if resolved.is_new => {
            info!(did = %did, "rejecting new-identity (no existing account) outside login flow");
            Err(crate::oidc::CustomError::BadRequest(
                NEW_IDENTITY_REJECT_MSG.to_string(),
            ))
        }
        Ok(_) => Ok(()),
        // A detection failure must not silently create an account: this still
        // fails CLOSED, and that is not negotiable. What changed is only the
        // diagnosis — "we could not check" is a server fault, not "you have no
        // account here" (see IDENTITY_CHECK_UNAVAILABLE_MSG). The underlying
        // error stays here in the log, where an operator can act on it, and
        // never goes on the wire to the caller.
        Err(e) => {
            warn!(
                did = %did,
                error = %e,
                "new-identity detection failed, rejecting to avoid silent creation"
            );
            Err(crate::oidc::CustomError::ServiceUnavailable(
                IDENTITY_CHECK_UNAVAILABLE_MSG.to_string(),
            ))
        }
    }
}

/// The error message returned when an account genuinely IS deactivated.
///
/// Deliberately does NOT distinguish "deactivated" from "erased" to the
/// caller: both mean the same thing to the person at the keyboard, and Synapse
/// reports them identically (`is_deactivated == true`) anyway.
///
/// It IS distinguished from [`DEACTIVATION_CHECK_UNAVAILABLE_MSG`] — the check
/// having *failed* is a different fact from the check having *found* a
/// deactivated account, and the two were conflated until 2026-09-13. See that
/// constant for the argument.
pub const DEACTIVATED_REJECT_MSG: &str = "This account has been deactivated and cannot sign in. \
     Contact a server administrator if you believe this is a mistake.";

/// The error message returned when the deactivation check could not be
/// **completed** — as distinct from completing and finding a deactivated
/// account.
///
/// # Why this is a second message and not the same one
///
/// [`reject_if_deactivated`] fails closed on both facts, and it must keep doing
/// so: a Synapse outage must never silently re-open access to a deactivated
/// account. That is the security property and it is unchanged. What changed on
/// 2026-09-13 is only the *diagnosis*. Until then both arms returned
/// `Unauthorized(`[`DEACTIVATED_REJECT_MSG`]`)`, so a single unhealthy Synapse
/// told **every user on the homeserver** that their account had been
/// deactivated and that they should go and argue with an administrator about
/// it. Observed in the wild as:
///
/// ```text
/// WARN identity resolution failed, rejecting to avoid reviving a deactivated
///      account: localpart_status: HTTP 500 Internal Server Error
/// WARN unauthorized error=This account has been deactivated and cannot sign in…
/// response status=401
/// ```
///
/// That is the same defect [`reject_if_new_identity`] was cured of in the
/// sibling fix: **a check that could not RUN is not a check that found
/// something.** The claim is not merely misleading, it is *false* — and it is
/// false in the one direction a user cannot investigate, because the only
/// person who could act on the real cause never sees it.
///
/// # The recorded objection, and why it does not hold
///
/// This gate's documentation used to argue the conflation was deliberate:
/// distinguishing the two answers "WOULD let an unauthenticated prober learn
/// account state". Two independent reasons that does not survive contact with
/// the code.
///
/// **1. There is no unauthenticated prober.** Every one of the five call sites
/// runs *after* the caller has proven control of the DID being asked about:
///
/// | Call site | Proof already established |
/// |---|---|
/// | `oidc::sign_in` | a verified CAIP-122 signature (Path B) or a WebAuthn assertion the ceremony endpoint verified and stored as `session.verified_did` (Path A) |
/// | `account::account_wallet` | `DIDMethod::verify` on the CAIP-122 message, plus a consumed single-use action-bound nonce |
/// | `account::account_passkey_finish` | `webauthn::verify_credential` |
/// | `device_auth::device_approve` | `DIDMethod::verify`, plus a consumed single-use nonce bound to this `user_code` |
/// | `device_auth::device_approve_passkey` | `webauthn::verify_credential`, in the route handler that calls it |
///
/// A "prober" here is therefore someone holding the account's own key, asking
/// about their own account. Telling them their account is deactivated is not a
/// leak, it is the answer they are entitled to — and it is the message's entire
/// purpose.
///
/// **2. On a healthy server the state was never hidden anyway.** With Synapse
/// up, an active account returns `Ok(())`, an absent one returns `Ok(())`, and
/// a deactivated one returns 401 — so the 401 already identifies deactivation
/// uniquely. The conflation only blurred the answer during a fault the caller
/// cannot induce and does not control. It bought ambiguity on exactly the
/// occasions when nobody was enumerating and everybody was locked out: it
/// protected nothing and misinformed everyone.
///
/// (Account *existence* is separately public regardless — `GET /resolve?did=…`
/// answers `exists`, and the DID → localpart derivation is a pure `sha2`
/// function anyone can compute offline. So the two gates are now symmetric, and
/// the asymmetry the sibling fix recorded between them is **withdrawn**.)
///
/// # What it may and may not say
///
/// It names the server as the faulty party, says the condition is worth
/// retrying, and points at an administrator if it persists. It leaks **nothing**
/// operational: no Synapse endpoint, no HTTP status, no errcode, no localpart.
/// Everything diagnostic goes to the `warn!` beside the reject, which is the
/// surface an operator reads and a caller does not. Pinned by
/// `the_deactivation_failure_message_leaks_no_server_internals`.
///
/// # Why it is byte-identical to [`IDENTITY_CHECK_UNAVAILABLE_MSG`]
///
/// On the account and device-approval paths [`reject_if_new_identity`] runs
/// immediately before this gate, so two *distinguishable* "could not check"
/// messages would tell the caller **which** gate they got past — i.e. that an
/// account exists for their DID. That fact is already public via `/resolve`, so
/// this is a small thing; but it is free to close and there is no
/// corresponding benefit to distinguishing them, since a user cannot act on
/// which internal probe failed and an operator reads the log, not the body.
///
/// They are nonetheless two constants, not one alias, because they belong to
/// two gates with two different `warn!` lines and two different owners; either
/// may need to be reworded for its own gate. Pinned equal by
/// `the_two_unavailable_messages_are_deliberately_indistinguishable`, which is
/// the place to record the decision if a future change makes them diverge on
/// purpose.
pub const DEACTIVATION_CHECK_UNAVAILABLE_MSG: &str =
    "The server could not complete a required account check right now. \
     Nothing has been changed. Please try again in a moment, and contact a \
     server administrator if this keeps happening.";

/// Server-enforced reject for a **deactivated** account.
///
/// # Why this exists
///
/// Deactivation was enforceable nowhere before this gate. Synapse's delegated
/// auth path (`synapse/api/auth/mas.py`, 1.159.0) contains **zero** references
/// to `deactivated` — under MSC3861 Synapse does not own the tokens, so it
/// trusts our introspection response and never consults `users.deactivated`.
/// On our side the user epoch (`epoch:user/{username}`, which replaced the
/// bounded-TTL user tombstone) refuses grants authenticated BEFORE the
/// deactivation (S3-4 / H6, I9), and by design nothing newer: it is no
/// authority over a sign-in made after it. The net effect was that
/// `account_deactivate` and `account_erase` were undone by simply signing in
/// again: `is_localpart_available` reports a deactivated user's localpart as
/// *taken*, so the new-identity gate classified them as a normal returning
/// account and issued a full session.
///
/// Synapse is therefore the authority here, via
/// [`SynapseClient::query_user`](crate::synapse_client::SynapseClient::query_user).
///
/// # Semantics
///
/// * `synapse == None` — no-op. Standalone deployments have no account to
///   deactivate, and this must never 500 a working standalone login.
/// * account exists and `is_deactivated == true` — `Unauthorized`.
/// * account exists and `is_deactivated == false` — `Ok(())`.
/// * account does **not** exist (`query_user` → `None`) — `Ok(())`. That is the
///   new-identity case and belongs to [`reject_if_new_identity`]; conflating the
///   two here would break first-time sign-in, which is legitimate at the login
///   screen.
/// * probe failed — **fails closed**, as a `ServiceUnavailable`. A Synapse
///   outage must not silently re-open access to deactivated accounts.
///
/// # Two rejects, two different facts (2026-09-13)
///
/// Both reject and both fail closed — that part is the security property and
/// must not change — but they are reported differently, because they are
/// different answers to the user:
///
/// | Outcome | Error | Status | Meaning |
/// |---|---|---|---|
/// | `query_user` → `Ok(Some(info))` with `info.is_deactivated` | `Unauthorized(`[`DEACTIVATED_REJECT_MSG`]`)` | 401 | the check RAN: this account is deactivated |
/// | either probe → `Err(_)` | `ServiceUnavailable(`[`DEACTIVATION_CHECK_UNAVAILABLE_MSG`]`)` | 503 | the check could not run at all; we say nothing about the account |
///
/// This matches [`reject_if_new_identity`] exactly, and that symmetry is now
/// the point. An earlier revision of these docs claimed the split would be
/// WRONG here because it leaks account state to an unauthenticated prober;
/// that objection is **withdrawn** — see
/// [`DEACTIVATION_CHECK_UNAVAILABLE_MSG`] for the evidence (there is no
/// unauthenticated prober at any of the five call sites, and on a healthy
/// server the 401 already identified deactivation uniquely). Do not
/// re-conflate the arms.
///
/// **Grandfathering-aware (2026-09):** which localpart to query is itself
/// resolved via [`crate::localpart::resolve_identity`] (grandfathered legacy
/// first, then modern) rather than a single fixed derivation — querying the
/// wrong scheme for a migrated/modern-only account would silently read back
/// "no account" and treat a deactivated user as new-identity-safe. A
/// resolution failure fails closed exactly like a `query_user` failure below,
/// and for the same reason: **the FALLIBLE `resolve_identity`, never
/// `resolve_identity_or_legacy`.** The fail-safe legacy guess would hand this
/// gate a localpart that may not be the user's, and `query_user` on the wrong
/// localpart answers `Ok(None)` — which this function reads as "no account,
/// nothing to reject". That is a live deactivation bypass, not a degradation,
/// which is why the guess is refused here and the whole request fails instead.
/// See the ordering note at this gate's `oidc::sign_in` call site.
pub async fn reject_if_deactivated(
    synapse: Option<&crate::synapse_client::SynapseClient>,
    did: &str,
) -> Result<(), crate::oidc::CustomError> {
    let synapse = match synapse {
        Some(s) => s,
        None => return Ok(()),
    };
    let localpart = match crate::localpart::resolve_identity(did, Some(synapse)).await {
        // Still fails CLOSED — not negotiable. Only the diagnosis changed: "we
        // could not check" is a server fault, not "your account was
        // deactivated" (see DEACTIVATION_CHECK_UNAVAILABLE_MSG). The underlying
        // error stays here in the log, where an operator can act on it, and
        // never goes on the wire to the caller.
        Err(e) => {
            warn!(
                did = %did,
                error = %e,
                "identity resolution failed, rejecting to avoid reviving a deactivated account"
            );
            return Err(crate::oidc::CustomError::ServiceUnavailable(
                DEACTIVATION_CHECK_UNAVAILABLE_MSG.to_string(),
            ));
        }
        Ok(resolved) => resolved.localpart,
    };
    match synapse.query_user(&localpart).await {
        Ok(Some(info)) if info.is_deactivated => {
            info!(did = %did, "rejecting sign-in for deactivated account");
            Err(crate::oidc::CustomError::Unauthorized(
                DEACTIVATED_REJECT_MSG.to_string(),
            ))
        }
        // Active account, or no account at all (the new-identity case).
        Ok(_) => Ok(()),
        // The second half of the same fail-closed-but-honest rule as the
        // resolution arm above: reachable on its own whenever
        // `is_localpart_available` answers but `query_user` does not (a partial
        // Synapse outage, a proxy serving one MAS route and not the other, a
        // rotated shared secret racing a restart).
        Err(e) => {
            warn!(
                did = %did,
                error = %e,
                "deactivation probe failed, rejecting to avoid reviving a deactivated account"
            );
            Err(crate::oidc::CustomError::ServiceUnavailable(
                DEACTIVATION_CHECK_UNAVAILABLE_MSG.to_string(),
            ))
        }
    }
}

// -- Request/response types for the HTTP API --

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub did: String,
    pub credential_id: String,
}

#[derive(Serialize)]
pub struct AuthenticateFinishResponse {
    pub ok: bool,
    pub did: String,
}

/// Typed outcome of a failed assertion verification.
///
/// `UnknownCredential` is the single, narrowly-scoped case where the presented
/// credential is not registered on this server (a stale/revoked passkey selected
/// from the platform picker). It is constructed at exactly one site (the Redis
/// credential lookup miss) and carries the base64url credential id so the handler
/// can echo it back to the client for a privacy-safe `signalUnknownCredential`
/// prune. Every OTHER failure mode (expired/decoded challenge, empty id, signature
/// mismatch, missing UV flag, sign-count regression) stays `Other` and keeps its
/// existing 500/internal-error classification. This isolation is load-bearing: a
/// valid passkey must never be signaled for pruning because of a transient or
/// unrelated failure.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The presented credential id is not registered on this server.
    /// Carries the base64url credential id.
    #[error("Credential not found: {0}")]
    UnknownCredential(String),
    /// Any other verification failure (challenge, signature, flags, counter, I/O).
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// -- Account linking (Phase 2) --

/// Stored at `webauthn:link/{cred_id_b64}` — maps a passkey credential to a primary DID.
#[derive(Serialize, Deserialize)]
pub struct LinkEntry {
    pub primary_did: String,
    pub label: String,
}

/// Challenge state for link ceremonies — wraps the registration state with the primary DID.
#[derive(Serialize, Deserialize)]
struct LinkChallengeState {
    reg_state_json: String,
    primary_did: String,
}

#[derive(Serialize)]
pub struct LinkFinishResponse {
    pub credential_id: String,
    pub primary_did: String,
}

/// Upgrade a passkey registration challenge to require a **discoverable (resident)**
/// credential. `webauthn-rs`'s `start_passkey_registration` requests
/// `residentKey: discouraged`, which yields non-discoverable credentials usable only
/// when the server supplies their id in `allowCredentials`. In a usernameless flow
/// that forces enumerating EVERY credential to the browser (a privacy leak + a
/// server-wide passkey picker). Requesting a resident key instead lets the
/// authenticator surface only the user's own passkey, so `authenticate_start` can use
/// an empty `allowCredentials`. (Existing non-resident credentials predate this and
/// must be re-registered to gain discoverability.)
fn require_resident_key(ccr: &mut CreationChallengeResponse) {
    let sel = ccr
        .public_key
        .authenticator_selection
        .get_or_insert_with(AuthenticatorSelectionCriteria::default);
    sel.resident_key = Some(ResidentKeyRequirement::Required);
    sel.require_resident_key = true;
}

// -- Registration ceremony --

pub async fn register_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    display_name: Option<String>,
) -> Result<CreationChallengeResponse> {
    let user_unique_id = Uuid::new_v4();
    let name = display_name.as_deref().unwrap_or("passkey-user");

    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, name, name, None)
        .map_err(|e| anyhow!("WebAuthn registration start failed: {:?}", e))?;
    require_resident_key(&mut ccr);

    // Store registration state in Redis (consumed by register_finish).
    let state_json = serde_json::to_string(&reg_state)
        .map_err(|e| anyhow!("Failed to serialize registration state: {}", e))?;
    redis
        .put_ceremony_state(Ceremony::Challenge, session_id, &state_json, CHALLENGE_TTL)
        .await?;

    info!(
        "webauthn register_start: session={}",
        siwx_oidc::redact::fingerprint(session_id)
    );
    Ok(ccr)
}

/// Typed outcome of a failed registration finish.
///
/// `AlreadyRegistered` is the one case a handler renders differently: the
/// credential id is already in use (a stored passkey, link state, or, with the
/// shared credential store enabled, a row in that store), so the registration
/// was refused and nothing was written. Every other failure (missing or expired
/// challenge, attestation verification, I/O) stays `Other`.
#[derive(Debug, Error)]
pub enum RegisterFinishError {
    /// The deployment serves a distinct unified relying party: keys are created
    /// in the browser and proven by their first login, so there is nothing to
    /// finish on the server (answered 410).
    #[error("registration no longer finishes on the server")]
    Retired,
    /// A passkey, link state or shared-store row already exists under this
    /// credential id; nothing was written.
    #[error("credential id already registered")]
    AlreadyRegistered,
    /// Any other registration failure.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// `register/finish` for the relying parties this server serves. A deployment
/// with a distinct unified RP finishes nothing on the server
/// ([`RegisterFinishError::Retired`]); a single-RP deployment verifies and
/// stores the passkey with [`register_finish`].
pub async fn register_finish_for(
    dispatch: &RpDispatch,
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<RegisterFinishResponse, RegisterFinishError> {
    if dispatch.unified.is_some() {
        return Err(RegisterFinishError::Retired);
    }
    register_finish(webauthn, redis, session_id, reg_response).await
}

/// Verify a registration and store its passkey.
///
/// Create-only: the passkey is written with an atomic set-if-absent, before any
/// index or mirror write, so an id that already has a stored passkey or link
/// state is refused with [`RegisterFinishError::AlreadyRegistered`] and the
/// stored passkey, the link entry, the `by_did` index and the credential-store
/// mirror stay exactly as they were. With the shared credential store enabled,
/// an id that store already holds is refused the same way, checked first
/// ([`siwx_oidc::credential_store::shared_store_holds`]); that check and the
/// mirror write are not one atomic step (see there).
pub async fn register_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<RegisterFinishResponse, RegisterFinishError> {
    // Retrieve and consume the registration state.
    let state_json = redis
        .take_ceremony_state(Ceremony::Challenge, session_id)
        .await?
        .ok_or_else(|| anyhow!("No registration challenge found (expired or already used)"))?;

    let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize registration state: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow!("WebAuthn registration verification failed: {:?}", e))?;

    let did = did_from_passkey(&passkey)?;
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(passkey.cred_id());

    // With the shared credential store enabled, the mirror write below inserts
    // or replaces, so an id the store already holds is refused before anything
    // is written. A no-op when the flag is off.
    if siwx_oidc::credential_store::shared_store_holds(&cred_id_b64).await? {
        info!(
            "webauthn register_finish: credential id held by the shared credential store, refused: cred_id={}",
            siwx_oidc::redact::fingerprint(&cred_id_b64)
        );
        return Err(RegisterFinishError::AlreadyRegistered);
    }

    // Store the credential persistently (no TTL), only if the id is new: neither
    // a stored passkey nor link state may exist under it. Link state is only
    // read here; `link_finish` stays its only writer.
    let cred_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize passkey: {}", e))?;
    let created = redis
        .set_nx_raw_guarded(
            &format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64),
            &format!("{}/{}", LINK_PREFIX, cred_id_b64),
            &cred_json,
        )
        .await?;
    if !created {
        info!(
            "webauthn register_finish: credential id already registered, refused: cred_id={}",
            siwx_oidc::redact::fingerprint(&cred_id_b64)
        );
        return Err(RegisterFinishError::AlreadyRegistered);
    }

    // Maintain the webauthn:by_did reverse index so a returning login can scope
    // the passkey picker to this DID's keys without a credential keyspace scan.
    // A standalone passkey resolves to its derived did:key. Best-effort: the index
    // is advisory (get_passkeys_for_did self-heals via scan), so a hiccup here must
    // not fail the registration the user just completed.
    if let Err(e) = redis.index_add_passkey(&did, &cred_id_b64).await {
        info!(
            "webauthn register_finish: by_did index update failed: {}",
            e
        );
    }

    // Dual-write into aqua-auth's credential store when it is enabled. A fresh
    // registration is unlinked, so its identity is the derived did:key. No-op
    // when the flag is off, and best-effort when it is on: the legacy write
    // above already succeeded, so the user is not locked out either way.
    siwx_oidc::credential_store::mirror_credential(&cred_id_b64, &cred_json, &did, None).await;

    info!(
        "webauthn register_finish: did={} cred_id={}",
        did,
        siwx_oidc::redact::fingerprint(&cred_id_b64)
    );
    Ok(RegisterFinishResponse {
        did,
        credential_id: cred_id_b64,
    })
}

// -- Authentication ceremony (discoverable / passkeys) --

/// Begin a WebAuthn assertion ceremony.
///
/// Two paths, selected by `scope_did`:
///
/// * `None` — **discoverable (usernameless)** authentication: `allow_credentials`
///   is left EMPTY. Credentials are registered as discoverable resident keys (see
///   `require_resident_key`), so the authenticator surfaces only the user's own
///   passkey and `verify_credential` resolves it by raw id. We must NOT enumerate
///   stored credentials here: that leaked every credential id to unauthenticated
///   callers and produced a server-wide passkey picker. This is the historical
///   (and still-default) behavior; ALL callers pass `None` until the cookie wiring
///   lands, so the runtime behavior is identical to before.
///
/// * `Some(did)` — **scoped** authentication: `allow_credentials` is set to exactly
///   the credentials that resolve to `did` (its standalone passkeys plus any
///   wallet-linked ones), via `get_passkeys_for_did`. The picker then shows only
///   that account. Enumeration-safety: this path runs ONLY when a caller supplies a
///   DID, and a caller may only do so after resolving it from a VALID opaque
///   user-session token (a forged/guessed token is a Redis miss -> `None` ->
///   usernameless). If the resolved credential set is EMPTY (e.g. a wallet-only DID
///   with no linked passkey), we fall back to leaving `allow_credentials` empty
///   (discoverable) rather than emitting a broken empty picker that would block
///   every key.
///
/// Note: we deliberately do NOT use `start_passkey_authentication` / persist a
/// `PasskeyAuthentication` finish-state. `verify_credential` verifies the assertion
/// MANUALLY (via `aqua_auth::verify_webauthn_assertion`) against the challenge
/// STRING stored in Redis; it never consumes a webauthn-rs finish-state. So for the
/// scoped path we obtain a `RequestChallengeResponse` exactly as the usernameless
/// path does and set `allow_credentials` directly (the shape the pre-discoverable
/// code used). The stored challenge and `verify_credential` are unchanged.
///
/// `legacy` picks the relying party the offer names: the unified RP by default
/// (`false`), the legacy RP on request (`true`). With a single-RP configuration
/// (`dispatch.unified` is `None`) both are the legacy RP, exactly as before.
pub async fn authenticate_start(
    dispatch: &RpDispatch,
    redis: &RedisClient,
    session_id: &str,
    scope_did: Option<&str>,
    legacy: bool,
) -> Result<RequestChallengeResponse> {
    authenticate_start_with_hint(dispatch, redis, session_id, scope_did, legacy, None).await
}

/// The unified request options in the webauthn-rs response shape, over a fresh
/// random challenge (or the given one) and an optional allow list.
fn unified_request_options(
    rp_id: &str,
    challenge: &[u8; 32],
    allow: &[Vec<u8>],
) -> Result<RequestChallengeResponse> {
    let options = aqua_auth::request_options(rp_id, challenge, allow);
    let mut value = serde_json::to_value(&options)
        .map_err(|e| anyhow!("Failed to encode request options: {}", e))?;
    // The aqua-auth shape omits an empty allow list; the webauthn-rs shape
    // requires the key.
    if let Some(public_key) = value.get_mut("publicKey").and_then(|v| v.as_object_mut()) {
        public_key
            .entry("allowCredentials")
            .or_insert_with(|| serde_json::json!([]));
    }
    serde_json::from_value::<RequestChallengeResponse>(value)
        .map_err(|e| anyhow!("Failed to read request options: {}", e))
}

fn fresh_challenge() -> [u8; 32] {
    use rand::RngCore;
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

/// What the store-free unified login keeps between its prompts: the sign-up key
/// hint from the login start, then the first assertion's pending recovery while
/// a second assertion is awaited. Public keys only.
#[derive(Serialize, Deserialize, Default)]
struct UnifiedCeremonyState {
    #[serde(default)]
    hint: Option<String>,
    #[serde(default)]
    pending: Option<aqua_auth::PendingRecovery>,
}

/// [`authenticate_start`] plus the sign-up key hint of the unified RP:
/// `key_hint_spki_b64url` is the base64url SubjectPublicKeyInfo of a key the
/// browser just created. A value that does not decode or is no P-256 key is
/// ignored, never an error. The legacy arm ignores it.
pub async fn authenticate_start_with_hint(
    dispatch: &RpDispatch,
    redis: &RedisClient,
    session_id: &str,
    scope_did: Option<&str>,
    legacy: bool,
    key_hint_spki_b64url: Option<&str>,
) -> Result<RequestChallengeResponse> {
    let legacy_arm = !matches!((&dispatch.unified, legacy), (Some(_), false));
    let mut rcr = match (&dispatch.unified, legacy) {
        (Some(unified), false) => {
            let hint = key_hint_spki_b64url
                .and_then(|h| URL_SAFE_NO_PAD.decode(h.trim_end_matches('=')).ok())
                .and_then(|der| aqua_auth::DidHint::from_spki_der(&der).ok())
                .map(|h| h.as_str().to_owned());
            let state = UnifiedCeremonyState {
                hint,
                pending: None,
            };
            let state_json = serde_json::to_string(&state)
                .map_err(|e| anyhow!("Failed to encode login state: {}", e))?;
            redis
                .put_ceremony_state(Ceremony::Unified, session_id, &state_json, CHALLENGE_TTL)
                .await?;
            unified_request_options(&unified.rp_id, &fresh_challenge(), &[])?
        }
        _ => {
            let (rcr, _auth_state) = dispatch
                .legacy_webauthn
                .start_discoverable_authentication()
                .map_err(|e| anyhow!("WebAuthn auth start failed: {:?}", e))?;
            rcr
        }
    };

    // The unified arm is discoverable only: the scope DID's stored ids are
    // legacy credentials, and listing them would exclude the store-free key.
    let scope_did = scope_did.filter(|_| legacy_arm);
    if let Some(did) = scope_did {
        // The UNION of the legacy webauthn:by_did index (with its scan
        // self-heal) and, when the flag is on, aqua-auth's did index -- not a
        // preference for one over the other. An EMPTY result is advisory and
        // means usernameless rather than denied, but a PARTIAL result is not:
        // a non-empty allow_credentials restricts the authenticator to exactly
        // that set, so omitting a passkey the backfill has not reached yet
        // locks that device out. See credential_store::list_credential_ids.
        let cred_ids = siwx_oidc::credential_store::list_credential_ids(
            redis,
            did,
            derive_did_from_credential_json,
        )
        .await?;
        // Empty set -> fall back to discoverable (leave allow_credentials empty) so a
        // wallet-only DID does not produce a broken empty picker that blocks all keys.
        if !cred_ids.is_empty() {
            let allow_list: Vec<AllowCredentials> = cred_ids
                .iter()
                .filter_map(|cred_id_b64| {
                    let bytes = URL_SAFE_NO_PAD.decode(cred_id_b64).ok()?;
                    Some(AllowCredentials {
                        type_: "public-key".to_string(),
                        // webauthn-rs-proto 0.6.1-dev types this as a plain
                        // `Vec<u8>` (it was `Base64UrlSafeData` in 0.6.0-dev).
                        // The JSON wire form is unchanged: the field still
                        // serializes as unpadded base64url via `serde_as`.
                        id: bytes,
                        transports: None,
                    })
                })
                .collect();
            rcr.public_key.allow_credentials = allow_list;
            info!(
                "webauthn authenticate_start: session={} scoped did={} creds={}",
                siwx_oidc::redact::fingerprint(session_id),
                did,
                rcr.public_key.allow_credentials.len()
            );
        } else {
            info!(
                "webauthn authenticate_start: session={} scope did={} resolved 0 creds -> discoverable fallback",
                siwx_oidc::redact::fingerprint(session_id),
                did
            );
        }
    }

    let challenge_b64 = URL_SAFE_NO_PAD.encode(&*rcr.public_key.challenge);
    redis
        .put_ceremony_state(
            Ceremony::Challenge,
            session_id,
            &challenge_b64,
            CHALLENGE_TTL,
        )
        .await?;

    info!(
        "webauthn authenticate_start: session={}",
        siwx_oidc::redact::fingerprint(session_id)
    );
    Ok(rcr)
}

/// Take the stored challenge for `session_id` and decode it.
async fn take_challenge(redis: &RedisClient, session_id: &str) -> Result<Vec<u8>, VerifyError> {
    let challenge_b64 = redis
        .take_ceremony_state(Ceremony::Challenge, session_id)
        .await?
        .ok_or_else(|| anyhow!("No auth challenge found (expired or already used)"))?;

    Ok(URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .map_err(|e| anyhow!("Failed to decode stored challenge: {}", e))?)
}

/// Assertion verification for the login flow, dispatched on the relying party
/// the authenticator signed for (`authenticatorData[0..32]`, the rpIdHash).
/// An RP the policy does not serve is refused before any credential-store read.
/// The legacy RP takes the stored-passkey path; the unified RP is verified from
/// the assertion alone (see [`verify_credential_step`]). This wrapper carries no
/// request hints and treats a second-assertion request as a failure.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn verify_credential(
    redis: &RedisClient,
    session_id: &str,
    dispatch: &RpDispatch,
    auth_response: &PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    match verify_credential_step(redis, session_id, dispatch, auth_response, &[]).await? {
        LoginStep::Done { resp, .. } => Ok(resp),
        LoginStep::NeedSecondAssertion(_) => {
            Err(anyhow!("a second assertion is required to identify the key").into())
        }
    }
}

/// The result of one login assertion.
pub enum LoginStep {
    /// The signer is known. `principal` is present when it was recovered from
    /// the assertion on the unified RP (no stored credential was read).
    Done {
        resp: AuthenticateFinishResponse,
        principal: Option<aqua_auth::Principal>,
    },
    /// The first visit of a key that no hint names: prompt again with these
    /// options (allowCredentials is that one credential). A plain re-prompt.
    NeedSecondAssertion(RequestChallengeResponse),
}

/// [`verify_credential`] with the request's hints (`aqua_did_hint` cookies, the
/// `siwx_user` session DID): the unified arm needs them to pick the signer.
pub async fn verify_credential_step(
    redis: &RedisClient,
    session_id: &str,
    dispatch: &RpDispatch,
    auth_response: &PublicKeyCredential,
    extra_hints: &[aqua_auth::DidHint],
) -> Result<LoginStep, VerifyError> {
    let auth_data = &*auth_response.response.authenticator_data;
    if auth_data.len() < 37 {
        return Err(anyhow!("authenticatorData is too short").into());
    }
    let rp_id_hash: [u8; 32] = auth_data[..32]
        .try_into()
        .map_err(|_| anyhow!("authenticatorData is too short"))?;

    let challenge_bytes = take_challenge(redis, session_id).await?;

    match dispatch.policy.entry_for_rp_id_hash(&rp_id_hash) {
        None => Err(anyhow!("assertion is for a relying party this server does not serve").into()),
        Some(entry) if entry.rp_id_hash == dispatch.legacy_rp_id_hash => {
            let resp = verify_stored_credential(
                redis,
                &challenge_bytes,
                &dispatch.legacy_rp_id,
                &dispatch.legacy_origin,
                auth_response,
            )
            .await?;
            Ok(LoginStep::Done {
                resp,
                principal: None,
            })
        }
        Some(_) => match &dispatch.unified {
            Some(unified) => {
                verify_unified(
                    redis,
                    session_id,
                    dispatch,
                    unified,
                    &challenge_bytes,
                    auth_response,
                    extra_hints,
                )
                .await
            }
            None => Err(anyhow!("unified RP not enabled").into()),
        },
    }
}

/// Unified-RP login: verify the assertion and recover its two candidate keys,
/// then pick the signer by hints or by a second assertion. Reads no stored
/// credential.
async fn verify_unified(
    redis: &RedisClient,
    session_id: &str,
    dispatch: &RpDispatch,
    unified: &UnifiedRp,
    challenge: &[u8],
    cred: &PublicKeyCredential,
    extra_hints: &[aqua_auth::DidHint],
) -> Result<LoginStep, VerifyError> {
    let enc = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    let assertion = aqua_auth::AssertionJson {
        id: cred.id.clone(),
        raw_id: enc(&cred.raw_id),
        type_: cred.type_.clone(),
        response: aqua_auth::AssertionResponseJson {
            authenticator_data: enc(&cred.response.authenticator_data),
            client_data_json: enc(&cred.response.client_data_json),
            signature: enc(&cred.response.signature),
            user_handle: cred.response.user_handle.as_deref().map(enc),
        },
        client_extension_results: serde_json::json!({}),
    };
    let recovered = aqua_auth::verify_and_recover(
        &assertion,
        aqua_auth::ExpectedChallenge::Exact(challenge),
        &dispatch.policy,
    )
    .map_err(|e| anyhow!("assertion refused: {}", e))?;
    if recovered.rp_id != unified.rp_id {
        return Err(anyhow!("assertion is for another relying party").into());
    }

    let state: UnifiedCeremonyState = match redis
        .take_ceremony_state(Ceremony::Unified, session_id)
        .await?
    {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => UnifiedCeremonyState::default(),
    };
    let done = |principal: aqua_auth::Principal| LoginStep::Done {
        resp: AuthenticateFinishResponse {
            ok: true,
            did: principal.did().to_owned(),
        },
        principal: Some(principal),
    };

    if let Some(pending) = state.pending {
        let principal = pending
            .resolve(&recovered)
            .map_err(|e| anyhow!("second assertion refused: {}", e))?;
        return Ok(done(principal));
    }

    let mut hints: Vec<aqua_auth::DidHint> = Vec::new();
    hints.extend(state.hint.as_deref().and_then(aqua_auth::DidHint::parse));
    hints.extend(extra_hints.iter().cloned());
    // Known-principal lookup (Synapse) is deferred: no candidate is "known".
    match recovered.select(&hints, [false, false]) {
        aqua_auth::Selection::Selected { principal, .. } => Ok(done(principal)),
        aqua_auth::Selection::NeedSecondAssertion(pending) => {
            let next = fresh_challenge();
            let rcr = unified_request_options(
                &unified.rp_id,
                &next,
                &[pending.credential_id().to_vec()],
            )?;
            redis
                .put_ceremony_state(
                    Ceremony::Challenge,
                    session_id,
                    &URL_SAFE_NO_PAD.encode(next),
                    CHALLENGE_TTL,
                )
                .await?;
            let state_json = serde_json::to_string(&UnifiedCeremonyState {
                hint: None,
                pending: Some(pending),
            })
            .map_err(|e| anyhow!("Failed to encode login state: {}", e))?;
            redis
                .put_ceremony_state(Ceremony::Unified, session_id, &state_json, CHALLENGE_TTL)
                .await?;
            Ok(LoginStep::NeedSecondAssertion(rcr))
        }
    }
}

/// The `Set-Cookie` that names the verified principal as the DID hint, only
/// after a verified login on the unified RP. This is the deliberate exception
/// to the host-only cookie invariant: the cookie is scoped to the unified RP
/// id so every service under it can pick the right candidate key.
pub fn login_hint_cookie(dispatch: &RpDispatch, step: &LoginStep) -> Option<String> {
    let unified = dispatch.unified.as_ref()?;
    match step {
        LoginStep::Done {
            principal: Some(principal),
            ..
        } => Some(aqua_auth::hint_set_cookie(
            principal,
            &aqua_auth::HintCookieConfig::for_rp_id(&unified.rp_id),
        )),
        _ => None,
    }
}

/// Registration options for the unified RP (ES256, resident key required);
/// `None` when no distinct unified RP is configured. Options only: nothing is
/// stored and no credential is written by the server.
pub fn unified_registration_options(
    dispatch: &RpDispatch,
    display_name: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    let Some(unified) = &dispatch.unified else {
        return Ok(None);
    };
    let name = display_name.unwrap_or("passkey-user");
    let options = aqua_auth::creation_options(&unified.rp_id, "Aqua", name, &fresh_challenge());
    Ok(Some(serde_json::to_value(&options).map_err(|e| {
        anyhow!("Failed to encode creation options: {}", e)
    })?))
}

/// The pre-dispatch signature: verify against ONE relying party, whatever the
/// assertion names. Account and device flows stay on the legacy ceremony.
pub async fn verify_credential_legacy(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: &PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let challenge_bytes = take_challenge(redis, session_id).await?;
    verify_stored_credential(redis, &challenge_bytes, rp_id, rp_origin, auth_response).await
}

/// Core WebAuthn assertion verification against the stored passkey: credential
/// lookup, cryptographic verification, counter update, and DID resolution.
/// Shared by the OIDC login flow, the account flow and the device approval flow.
async fn verify_stored_credential(
    redis: &RedisClient,
    challenge_bytes: &[u8],
    rp_id: &str,
    rp_origin: &str,
    auth_response: &PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(&*auth_response.raw_id);
    if cred_id_b64.is_empty() {
        return Err(anyhow!("Empty credential ID in WebAuthn assertion").into());
    }
    let cred_key = format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64);
    // Read-through: aqua-auth's credential store first when the flag is on, this
    // namespace on a miss. The fallback is what makes the flag safe to flip
    // before the backfill has run.
    let cred_json = siwx_oidc::credential_store::read_blob(redis, &cred_id_b64)
        .await?
        // The ONLY site that yields VerifyError::UnknownCredential. A stale/revoked
        // passkey selected from the picker lands here (lookup precedes signature
        // verification), so this is reachable without a forged signature. Keeping the
        // lookup before verification is load-bearing for the 401-not-500 path.
        .ok_or_else(|| VerifyError::UnknownCredential(cred_id_b64.clone()))?;
    let passkey: Passkey = serde_json::from_str(&cred_json)
        .map_err(|e| anyhow!("Failed to deserialize credential: {}", e))?;

    let compressed_pubkey = compressed_pubkey_from_passkey(&passkey)?;

    let der_sig = &*auth_response.response.signature;
    let sig = Signature::from_der(der_sig)
        .map_err(|e| anyhow!("Failed to DER-decode ECDSA signature: {}", e))?;
    let sig_bytes = sig.to_bytes();

    let params = WebAuthnAssertionParams {
        credential_public_key: &compressed_pubkey,
        authenticator_data: &auth_response.response.authenticator_data,
        client_data_json: &auth_response.response.client_data_json,
        signature: &sig_bytes,
        expected_challenge: challenge_bytes,
        expected_origin: rp_origin,
        expected_rp_id: rp_id,
    };

    match verify_webauthn_assertion(&params) {
        Ok(true) => {}
        Ok(false) => return Err(anyhow!("WebAuthn assertion signature verification failed").into()),
        Err(e) => return Err(anyhow!("WebAuthn assertion verification error: {}", e).into()),
    }

    let flags = auth_response.response.authenticator_data[32];
    if flags & 0x04 == 0 {
        return Err(anyhow!("User Verification flag not set").into());
    }

    let passkey_did = did_from_passkey(&passkey)?;

    // A `webauthn:link` entry OVERRIDES the DID derived from the passkey. That
    // rule now lives in one place, `credential_identity`, because the
    // credential-store backfill has to reproduce it exactly: if the two ever
    // disagreed, every linked credential would be stored under one principal and
    // authenticate as another. Read-only; linking is still written only by
    // `link_finish` below.
    let did = siwx_oidc::credential_identity::resolve_credential_identity(
        redis,
        &cred_id_b64,
        &passkey_did,
    )
    .await?
    .did;

    let auth_data = &*auth_response.response.authenticator_data;
    if auth_data.len() >= 37 {
        let new_counter =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        let mut passkey_value: serde_json::Value =
            serde_json::from_str(&cred_json).map_err(|e| {
                anyhow!(
                    "Failed to parse stored credential for counter update: {}",
                    e
                )
            })?;
        if let Some(cred) = passkey_value.get_mut("cred") {
            let stored_counter = cred.get("counter").and_then(|c| c.as_u64()).unwrap_or(0) as u32;
            if (new_counter > 0 || stored_counter > 0) && new_counter < stored_counter {
                return Err(anyhow!(
                    "Sign count regression (stored={}, got={}), possible cloned authenticator",
                    stored_counter,
                    new_counter
                )
                .into());
            }
            cred["counter"] = serde_json::json!(new_counter);
        }
        redis
            .set_raw(
                &cred_key,
                &serde_json::to_string(&passkey_value)
                    .map_err(|e| anyhow!("Failed to serialize credential counter: {}", e))?,
            )
            .await?;
        // Dual-write the counter. aqua-auth keeps it in a sidecar field rather
        // than inside the blob, and its store is monotonic, so a replayed lower
        // value is ignored there exactly as the regression check above rejects
        // it here.
        siwx_oidc::credential_store::mirror_sign_count(&cred_id_b64, new_counter).await;
    }

    info!(
        "webauthn verify_credential: did={} cred={}",
        did,
        siwx_oidc::redact::fingerprint(&cred_id_b64)
    );
    Ok(AuthenticateFinishResponse { ok: true, did })
}

/// Full authenticate-finish for the OIDC login flow: verifies the credential and,
/// once the login is done, stores the verified DID in the Redis session (needed
/// by `sign_in`). `hints` are the request hints of the unified login; a hintless
/// first visit answers with a second-assertion prompt and stores nothing yet.
pub async fn authenticate_finish_step(
    redis: &RedisClient,
    session_id: &str,
    dispatch: &RpDispatch,
    auth_response: PublicKeyCredential,
    hints: &[aqua_auth::DidHint],
) -> Result<LoginStep, VerifyError> {
    let step = verify_credential_step(redis, session_id, dispatch, &auth_response, hints).await?;
    if let LoginStep::Done { resp, .. } = &step {
        let mut session = redis
            .get_session(session_id.to_string())
            .await?
            .ok_or_else(|| anyhow!("Session not found"))?;
        session.verified_did = Some(resp.did.clone());
        redis.set_session(session_id.to_string(), session).await?;
    }
    Ok(step)
}

// -- Account linking ceremony (Phase 2) ------------------------------------

pub async fn link_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    primary_did: &str,
    display_name: Option<String>,
) -> Result<CreationChallengeResponse> {
    let user_unique_id = Uuid::new_v4();
    let name = display_name.as_deref().unwrap_or("linked-passkey");

    let (mut ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, name, name, None)
        .map_err(|e| anyhow!("WebAuthn registration start failed: {:?}", e))?;
    require_resident_key(&mut ccr);

    // Store registration state + primary_did in Redis.
    let reg_state_json = serde_json::to_string(&reg_state)
        .map_err(|e| anyhow!("Failed to serialize registration state: {}", e))?;
    let link_state = LinkChallengeState {
        reg_state_json,
        primary_did: primary_did.to_string(),
    };
    let state_json = serde_json::to_string(&link_state)
        .map_err(|e| anyhow!("Failed to serialize link challenge state: {}", e))?;
    redis
        .put_ceremony_state(Ceremony::Link, session_id, &state_json, CHALLENGE_TTL)
        .await?;

    info!(
        "webauthn link_start: session={} primary_did={}",
        siwx_oidc::redact::fingerprint(session_id),
        primary_did
    );
    Ok(ccr)
}

pub async fn link_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<LinkFinishResponse> {
    // Retrieve and consume the link challenge state.
    let state_json = redis
        .take_ceremony_state(Ceremony::Link, session_id)
        .await?
        .ok_or_else(|| anyhow!("No link challenge found (expired or already used)"))?;

    let link_state: LinkChallengeState = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize link challenge state: {}", e))?;
    let reg_state: PasskeyRegistration = serde_json::from_str(&link_state.reg_state_json)
        .map_err(|e| anyhow!("Failed to deserialize registration state: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow!("WebAuthn registration verification failed: {:?}", e))?;

    let cred_id_b64 = URL_SAFE_NO_PAD.encode(passkey.cred_id());

    // Store the credential persistently (same as register_finish).
    let cred_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize passkey: {}", e))?;
    redis
        .set_raw(
            &format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64),
            &cred_json,
        )
        .await?;

    // Store the link mapping: cred_id → primary_did.
    let link_entry = LinkEntry {
        primary_did: link_state.primary_did.clone(),
        label: "linked".to_string(),
    };
    let link_json = serde_json::to_string(&link_entry)
        .map_err(|e| anyhow!("Failed to serialize link entry: {}", e))?;
    redis
        .set_raw(&format!("{}/{}", LINK_PREFIX, cred_id_b64), &link_json)
        .await?;

    // Maintain the webauthn:by_did reverse index against the PRIMARY (wallet) DID:
    // a linked passkey resolves to primary_did at verify time, so a returning login
    // scoped to the wallet DID must surface this passkey. Best-effort (advisory).
    if let Err(e) = redis
        .index_add_passkey(&link_state.primary_did, &cred_id_b64)
        .await
    {
        info!("webauthn link_finish: by_did index update failed: {}", e);
    }

    // Dual-write into aqua-auth's credential store when it is enabled, under the
    // PRIMARY did and with the link's label, because that is what
    // `resolve_credential_identity` (and therefore a login) resolves for this
    // credential. Writing the derived did:key here would record a principal the
    // login path never produces. The link entry itself is NOT mirrored: it stays
    // owned by, and readable only from, this namespace.
    siwx_oidc::credential_store::mirror_credential(
        &cred_id_b64,
        &cred_json,
        &link_state.primary_did,
        Some(link_entry.label.clone()),
    )
    .await;

    info!(
        "webauthn link_finish: cred_id={} primary_did={}",
        siwx_oidc::redact::fingerprint(&cred_id_b64),
        link_state.primary_did
    );
    Ok(LinkFinishResponse {
        credential_id: cred_id_b64,
        primary_did: link_state.primary_did,
    })
}

pub struct WebauthnConfig {
    pub webauthn: Webauthn,
    pub rp_id: String,
    pub rp_origin: String,
}

/// Build the Webauthn instance from config.
pub fn build_webauthn(
    base_url: &Url,
    rp_id: Option<&str>,
    rp_origin: Option<&str>,
) -> Result<WebauthnConfig> {
    let default_rp_id = base_url
        .host_str()
        .ok_or_else(|| anyhow!("SIWXOIDC_BASE_URL has no host — cannot derive WebAuthn RP ID"))?
        .to_string();
    let resolved_rp_id = rp_id.unwrap_or(&default_rp_id).to_string();

    let default_origin = base_url.as_str().trim_end_matches('/').to_string();
    let resolved_rp_origin = rp_origin
        .unwrap_or(&default_origin)
        .trim_end_matches('/')
        .to_string();
    let rp_origin_url = Url::parse(&resolved_rp_origin)
        .map_err(|e| anyhow!("Invalid SIWXOIDC_RP_ORIGIN: {}", e))?;

    let webauthn = WebauthnBuilder::new(&resolved_rp_id, &rp_origin_url)
        .map_err(|e| {
            anyhow!(
                "WebauthnBuilder::new failed (rp_id={}, origin={}): {:?}",
                resolved_rp_id,
                rp_origin_url,
                e
            )
        })?
        .build()
        .map_err(|e| anyhow!("Webauthn::build failed: {:?}", e))?;

    Ok(WebauthnConfig {
        webauthn,
        rp_id: resolved_rp_id,
        rp_origin: resolved_rp_origin,
    })
}

/// The unified relying party, when it differs from the legacy one.
pub struct UnifiedRp {
    pub rp_id: String,
}

/// The relying parties this server serves and the policy that tells them apart
/// by the rpIdHash in `authenticatorData`. The legacy RP is the one
/// `WebauthnConfig` (and so `AppState::webauthn`) carries; the unified RP is
/// present only when configured differently.
pub struct RpDispatch {
    pub legacy_rp_id: String,
    pub legacy_origin: String,
    legacy_rp_id_hash: [u8; 32],
    legacy_webauthn: Webauthn,
    pub unified: Option<UnifiedRp>,
    policy: AssertionPolicy,
}

/// Build the legacy `WebauthnConfig` and the dispatch over it.
///
/// Two relying parties exist only when BOTH `legacy_rp_id` and a different
/// `rp_id` are set: then `rp_id` / `rp_origin` name the unified RP and
/// `legacy_rp_id` the legacy one (origin `base_url`). In every other case there
/// is one RP and the legacy config is exactly what
/// `build_webauthn(base_url, rp_id, rp_origin)` gave before (`legacy_rp_id`
/// alone names that one RP; neither set means the host of `base_url`).
pub fn build_rp_dispatch(
    base_url: &Url,
    rp_id: Option<&str>,
    rp_origin: Option<&str>,
    legacy_rp_id: Option<&str>,
) -> Result<(WebauthnConfig, RpDispatch)> {
    let host = base_url
        .host_str()
        .ok_or_else(|| anyhow!("SIWXOIDC_BASE_URL has no host, cannot derive WebAuthn RP ID"))?;
    // Two RPs are opt-in: a distinct unified RP exists only when the legacy RP
    // is named explicitly. Without `legacy_rp_id`, `rp_id` keeps its
    // pre-dispatch meaning (the one RP), so an existing deployment that set
    // `SIWXOIDC_RP_ID` to a domain other than the host of `base_url` does not
    // silently change shape on upgrade.
    let legacy_id = legacy_rp_id.or(rp_id).unwrap_or(host);
    let unified_id = legacy_rp_id.and(rp_id).filter(|id| *id != legacy_id);
    let legacy = if unified_id.is_none() {
        build_webauthn(base_url, Some(legacy_id), rp_origin)?
    } else {
        build_webauthn(base_url, Some(legacy_id), None)?
    };

    let mut builder = AssertionPolicy::builder().rp(&legacy.rp_id, &[legacy.rp_origin.as_str()]);
    let unified = match unified_id {
        Some(id) => {
            let unified = build_webauthn(base_url, Some(id), rp_origin)?;
            builder = builder.and_then(|b| b.rp(&unified.rp_id, &[unified.rp_origin.as_str()]));
            Some(UnifiedRp {
                rp_id: unified.rp_id,
            })
        }
        None => None,
    };
    let policy = builder
        .and_then(|b| b.build())
        .map_err(|e| anyhow!("Invalid WebAuthn relying party policy: {}", e))?;

    use sha2::{Digest, Sha256};
    let dispatch = RpDispatch {
        legacy_rp_id: legacy.rp_id.clone(),
        legacy_origin: legacy.rp_origin.clone(),
        legacy_rp_id_hash: Sha256::digest(legacy.rp_id.as_bytes()).into(),
        legacy_webauthn: legacy.webauthn.clone(),
        unified,
        policy,
    };
    Ok((legacy, dispatch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use siwx_oidc::mxid::legacy_localpart;
    use std::collections::{HashMap, HashSet};
    use tokio::task::JoinHandle;

    /// `derive_did_from_credential_json` is the resolver `RedisClient::purge_identity`
    /// uses for its best-effort standalone-credential pass (pass b). It MUST fail
    /// closed: anything that is not a deserializable P-256 passkey returns `None`
    /// (never panics). This is what keeps a webauthn-rs serialization drift from
    /// turning purge into a silent crash; the load-bearing link-based pass (a) is
    /// unaffected, and a drift surfaces as pass (b) returning `None` (covered here),
    /// not as a panic in an erasure request.
    ///
    /// NOTE (residual coverage gap, tracked in the lifecycle audit): the POSITIVE
    /// round-trip (a real serialized webauthn-rs `Passkey` JSON -> stable
    /// `did:key:zDn…`) is exercised only by the ignored e2e webauthn path and the
    /// production read path, not a hermetic fixture, because constructing a valid
    /// `Passkey` needs a software authenticator dependency we deliberately do not add.
    #[test]
    fn derive_did_from_credential_json_fails_closed_on_non_passkey_input() {
        assert_eq!(derive_did_from_credential_json(""), None, "empty input");
        assert_eq!(
            derive_did_from_credential_json("not json at all"),
            None,
            "garbage input"
        );
        assert_eq!(
            derive_did_from_credential_json("{}"),
            None,
            "empty object is not a passkey"
        );
        assert_eq!(
            derive_did_from_credential_json(r#"{"cred":{"unexpected":"shape"}}"#),
            None,
            "wrong-shaped JSON must not panic, must return None"
        );
    }

    /// Byte-identity across the 0.7.0 helper deletion.
    ///
    /// `compressed_pubkey_from_passkey` and `did_from_passkey` used to be
    /// implemented here (a `P256_MULTICODEC` constant, a COSE -> compressed-SEC1
    /// extractor, a base58 encoder) and now delegate to aqua-auth. The two
    /// values below were produced by the DELETED local implementation against
    /// this exact fixture, so this test fails if the delegation is not
    /// bit-for-bit the same computation.
    ///
    /// The compressed key matters as much as the DID: it is what
    /// `verify_credential` hands to `verify_webauthn_assertion` as
    /// `credential_public_key`, so a single flipped byte would reject every
    /// login rather than merely rename an identity.
    #[test]
    fn derivation_is_byte_identical_to_the_pre_0_7_0_local_helpers() {
        const BLOB: &str = include_str!("../tests/fixtures/passkey_webauthn_rs_0_6_0_dev.json");
        const PRE_0_7_0_COMPRESSED_HEX: &str =
            "02a463503d9518bd64a40f5760b9b3b4cd2c419848896a959109434c4453773da4";
        const PRE_0_7_0_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";

        let passkey: Passkey = serde_json::from_str(BLOB).expect("fixture parses");
        let compressed = compressed_pubkey_from_passkey(&passkey).expect("P-256");
        assert_eq!(compressed.len(), 33, "compressed SEC1 is 33 bytes");
        assert_eq!(
            hex::encode(compressed),
            PRE_0_7_0_COMPRESSED_HEX,
            "the compressed public key must be byte-identical to the deleted local helper"
        );
        assert_eq!(
            did_from_passkey(&passkey).expect("derives"),
            PRE_0_7_0_DID,
            "the derived did:key must be byte-identical to the deleted local helper"
        );
        assert_eq!(
            derive_did_from_credential_json(BLOB).as_deref(),
            Some(PRE_0_7_0_DID),
            "the purge-path resolver must agree too"
        );
    }

    /// The serialized `Passkey` blob written by webauthn-rs **0.6.0-dev** (the
    /// version this crate ran before the `=0.6.1-dev` alignment) must still
    /// deserialize under 0.6.1-dev, and must still derive the same
    /// `did:key:zDn…`. That is what makes the credential store shareable with
    /// aqua-auth/aqua-node/aquafier: a passkey registered by the old binary is
    /// readable by the new one, and both agree on the identity it maps to.
    ///
    /// The fixture is a REAL blob, produced by a full `start_passkey_registration`
    /// /`finish_passkey_registration` ceremony against a `webauthn-authenticator-rs`
    /// SoftToken linked to webauthn-rs 0.6.0-dev, then copied verbatim. It closes the
    /// positive-round-trip coverage gap noted on the test above without adding a
    /// software-authenticator dependency to this crate.
    #[test]
    fn passkey_blob_from_webauthn_rs_060dev_still_deserializes_and_derives_same_did() {
        const BLOB: &str = include_str!("../tests/fixtures/passkey_webauthn_rs_0_6_0_dev.json");
        const EXPECTED_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";
        const EXPECTED_CRED_ID: &str = "437HJ4gJirHMj5bDSeoDN6ODix56R_i5GgCLhqF0L9I";

        let passkey: Passkey = serde_json::from_str(BLOB)
            .expect("a 0.6.0-dev Passkey blob must deserialize under the pinned webauthn-rs");

        assert_eq!(
            URL_SAFE_NO_PAD.encode(passkey.cred_id()),
            EXPECTED_CRED_ID,
            "credential id must be stable across the webauthn-rs bump"
        );
        assert_eq!(
            did_from_passkey(&passkey).expect("P-256 passkey"),
            EXPECTED_DID,
            "did:key derivation must be stable across the webauthn-rs bump"
        );
        assert_eq!(
            derive_did_from_credential_json(BLOB).as_deref(),
            Some(EXPECTED_DID),
            "the purge-path resolver must agree with did_from_passkey"
        );

        // Re-serializing must not rewrite the stored blob: the counter-update
        // path in `verify_credential` writes the value back, so a serialization
        // drift here would silently rewrite every credential on first login.
        let reserialized = serde_json::to_string(&passkey).expect("serialize");
        assert_eq!(
            reserialized.trim(),
            BLOB.trim(),
            "re-serialization must be byte-identical to the 0.6.0-dev blob"
        );
    }

    /// H5 (graceful degradation): when no Synapse client is configured the
    /// account/QR flows cannot detect a new identity, so `reject_if_new_identity`
    /// is a strict no-op (returns Ok). Deterministic, no network: this is the
    /// branch that preserves standalone-deployment behavior. (The other guards in
    /// those flows already BadRequest for the actions that need Synapse.)
    #[tokio::test]
    async fn reject_if_new_identity_is_noop_without_synapse() {
        assert!(
            reject_if_new_identity(None, "did:key:zDnANYTHING")
                .await
                .is_ok(),
            "no Synapse client must be a no-op (cannot detect, do not reject)"
        );
    }

    /// H5 (fail-closed): a Synapse client that is present but UNREACHABLE is a
    /// detection failure. We must NOT fall through and provision a new account.
    ///
    /// It rejects — and it rejects as a **server fault**, with
    /// `IDENTITY_CHECK_UNAVAILABLE_MSG`, not with the new-identity message. That
    /// separation is the whole point: a user whose sign-in is broken by a
    /// server-side problem must not be told to go and create an account. Points
    /// at an unroutable endpoint so the request fails fast without a live
    /// Synapse.
    #[tokio::test]
    async fn reject_if_new_identity_fails_closed_on_synapse_error() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable.
        let synapse = crate::synapse_client::SynapseClient::new("http://192.0.2.1:1", "secret");
        let err = reject_if_new_identity(Some(&synapse), "did:key:zDnUNREACHABLE")
            .await
            .expect_err("detection failure must reject, not silently create");
        match err {
            crate::oidc::CustomError::ServiceUnavailable(msg) => {
                assert_eq!(msg, IDENTITY_CHECK_UNAVAILABLE_MSG);
                // Asserted EXPLICITLY, not merely implied by the line above: the
                // two messages being distinguishable is the fix, so a future
                // "simplification" back onto one string has to fail here rather
                // than quietly restore the misleading diagnosis.
                assert_ne!(
                    msg, NEW_IDENTITY_REJECT_MSG,
                    "a detection failure must never be reported as 'no such account'"
                );
            }
            other => panic!("expected ServiceUnavailable, got {:?}", other),
        }
    }

    /// The other half of the separation, and the reason the pair cannot collapse
    /// back into one: an identity the probe SUCCESSFULLY determined to be new
    /// still gets `NEW_IDENTITY_REJECT_MSG` and a `BadRequest`. Without this, the
    /// new-identity arm could drift onto the unavailable message and the sibling
    /// test above would still pass.
    ///
    /// Drives `localpart.rs`'s in-process mock homeserver (no live stack, no
    /// network) with an EMPTY set of existing localparts, so both the legacy and
    /// the modern shape read as free and `resolve_identity` reports
    /// `is_new == true`.
    #[tokio::test]
    async fn a_genuinely_new_identity_still_gets_the_new_identity_message() {
        use crate::localpart::resolve_identity_tests::spawn_mock_synapse_with_did_fields;

        let (synapse, handle) =
            spawn_mock_synapse_with_did_fields(HashSet::new(), HashMap::new()).await;
        let err = reject_if_new_identity(Some(&synapse), "did:key:zDnBRANDNEW")
            .await
            .expect_err("a new identity must be rejected outside the login flow");
        match err {
            crate::oidc::CustomError::BadRequest(msg) => {
                assert_eq!(msg, NEW_IDENTITY_REJECT_MSG);
                assert_ne!(
                    msg, IDENTITY_CHECK_UNAVAILABLE_MSG,
                    "a determinate 'no such account' must not be dressed up as a server fault"
                );
            }
            other => panic!("expected BadRequest, got {:?}", other),
        }
        handle.abort();
    }

    /// The case that actually motivated the split, at the level the e2e test
    /// `wrong_mas_shared_secret_fails_closed_not_open` exercises end to end: a
    /// REACHABLE Synapse that answers `403` on `/_synapse/mas/*` because the
    /// shared secret is wrong or rotated.
    ///
    /// This became reachable only with the availability-conflation fix
    /// (`docs/audits/2026-09-12-localpart-availability-conflation.md`): before
    /// it, a rejected credential was folded into "the localpart is taken", so
    /// every user on the homeserver looked like a normal returning account and
    /// this gate never fired at all. Worth its own test rather than leaning on
    /// the unreachable-host case above, because "reachable but refusing us" is
    /// the failure an operator will actually hit.
    #[tokio::test]
    async fn a_rejected_mas_shared_secret_is_a_detection_failure_not_a_new_identity() {
        use crate::localpart::resolve_identity_tests::{
            spawn_mock_synapse_configured, MockSynapseConfig,
        };

        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            reject_secret: true,
            ..MockSynapseConfig::default()
        })
        .await;
        let err = reject_if_new_identity(Some(&synapse), "did:key:zDnWRONGSECRET")
            .await
            .expect_err("a rejected credential must reject, not silently create");
        match err {
            crate::oidc::CustomError::ServiceUnavailable(msg) => {
                assert_eq!(msg, IDENTITY_CHECK_UNAVAILABLE_MSG);
                assert_ne!(
                    msg, NEW_IDENTITY_REJECT_MSG,
                    "our own misconfigured credential is not the user's missing account"
                );
            }
            other => panic!("expected ServiceUnavailable, got {:?}", other),
        }
        handle.abort();
    }

    /// The detection-failure message is rendered VERBATIM to the caller: both the
    /// account page and the device-approval page show the response body for any
    /// non-2xx (`showStatus(await r.text())`). The caller has proven a DID and
    /// nothing else, so the message must carry no operational detail — a leaked
    /// "403 from /_synapse/mas" would hand a stranger a map of our internals and
    /// tell them our shared secret is the thing that is wrong.
    ///
    /// Everything diagnostic belongs in the `warn!` beside the reject instead,
    /// which only an operator reads. This test pins both directions: what the
    /// message must NOT say, and the two things the wording is REQUIRED to
    /// convey (retry, then escalate).
    #[test]
    fn the_detection_failure_message_leaks_no_server_internals() {
        let lower = IDENTITY_CHECK_UNAVAILABLE_MSG.to_lowercase();
        for forbidden in [
            "secret",
            "synapse",
            "403",
            "401",
            "errcode",
            "m_",
            "token",
            "http",
            "localpart",
        ] {
            assert!(
                !lower.contains(forbidden),
                "the detection-failure message must not mention {forbidden:?}: \
                 {IDENTITY_CHECK_UNAVAILABLE_MSG}"
            );
        }
        // And it must not hand out the one piece of advice that is actively
        // wrong here, which is the entire reason this constant exists.
        assert!(
            !lower.contains("create an account"),
            "a server fault must not be reported as 'you have no account': \
             {IDENTITY_CHECK_UNAVAILABLE_MSG}"
        );
        assert!(
            lower.contains("try again"),
            "the condition is transient, so the message must invite a retry: \
             {IDENTITY_CHECK_UNAVAILABLE_MSG}"
        );
        assert!(
            lower.contains("administrator"),
            "a persisting server fault needs an escalation path: \
             {IDENTITY_CHECK_UNAVAILABLE_MSG}"
        );
    }

    /// Graceful degradation, mirroring `reject_if_new_identity_is_noop_without_synapse`:
    /// a standalone deployment has no Synapse account to deactivate, so the gate
    /// must be a strict no-op rather than failing closed and breaking every login.
    #[tokio::test]
    async fn reject_if_deactivated_is_noop_without_synapse() {
        assert!(
            reject_if_deactivated(None, "did:key:zDnANYTHING")
                .await
                .is_ok(),
            "no Synapse client must be a no-op (cannot detect, do not reject)"
        );
    }

    /// Fail-closed AND honestly diagnosed: a present-but-UNREACHABLE Synapse is a
    /// detection failure. It must NOT fall through to a working session — that is
    /// exactly the bypass this gate exists to close, and a Synapse outage is the
    /// moment it would matter most.
    ///
    /// It rejects — and since 2026-09-13 it rejects as a **server fault**, with
    /// `DEACTIVATION_CHECK_UNAVAILABLE_MSG`, not by claiming the account was
    /// deactivated. That separation is the whole point: a single unhealthy
    /// homeserver used to tell every user on it that their account had been
    /// deactivated and that they should go and argue with an administrator.
    /// Points at an unroutable endpoint so the request fails fast without a live
    /// Synapse; this is the `resolve_identity` half of the two `Err` arms (the
    /// `query_user` half has its own test below).
    #[tokio::test]
    async fn reject_if_deactivated_fails_closed_on_synapse_error() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable.
        let synapse = crate::synapse_client::SynapseClient::new("http://192.0.2.1:1", "secret");
        let err = reject_if_deactivated(Some(&synapse), "did:key:zDnUNREACHABLE")
            .await
            .expect_err("probe failure must reject, not revive a deactivated account");
        match err {
            crate::oidc::CustomError::ServiceUnavailable(msg) => {
                assert_eq!(msg, DEACTIVATION_CHECK_UNAVAILABLE_MSG);
                // Asserted EXPLICITLY, not merely implied by the line above: the
                // two messages being distinguishable IS the fix, so a future
                // "simplification" back onto one string has to fail here rather
                // than quietly restore the false accusation.
                assert_ne!(
                    msg, DEACTIVATED_REJECT_MSG,
                    "a probe failure must never be reported as 'your account was deactivated'"
                );
            }
            other => panic!("expected ServiceUnavailable, got {:?}", other),
        }
    }

    /// The OTHER `Err` arm, which the unreachable-host test above cannot reach:
    /// `is_localpart_available` answers normally (so `resolve_identity` succeeds
    /// and hands back a localpart) and then `query_user` fails.
    ///
    /// This is not a contrived split. The two probes are different routes with
    /// different handlers, so a proxy serving one and not the other, a partial
    /// Synapse outage, or a shared secret rotated between the two calls all land
    /// here and nowhere else. Before this test the arm was entirely unguarded —
    /// the audit found it had no coverage at all.
    #[tokio::test]
    async fn a_query_user_failure_is_a_probe_failure_not_a_deactivation() {
        let (synapse, handle) = spawn_mas_mock(MasMock {
            // The account EXISTS under the legacy shape, so `resolve_identity`
            // grandfathers it and returns without ever consulting `query_user`.
            existing: HashSet::from([legacy_localpart(DEACTIVATION_TEST_DID)]),
            // …and then the deactivation probe itself is the thing that breaks.
            query_user_status: Some(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            ..MasMock::default()
        })
        .await;
        let err = reject_if_deactivated(Some(&synapse), DEACTIVATION_TEST_DID)
            .await
            .expect_err("a failed deactivation probe must reject, not let the user through");
        match err {
            crate::oidc::CustomError::ServiceUnavailable(msg) => {
                assert_eq!(msg, DEACTIVATION_CHECK_UNAVAILABLE_MSG);
                assert_ne!(
                    msg, DEACTIVATED_REJECT_MSG,
                    "our own broken probe is not the user's deactivated account"
                );
            }
            other => panic!("expected ServiceUnavailable, got {:?}", other),
        }
        handle.abort();
    }

    /// **The positive case, which had NO test at all until 2026-09-13.** The
    /// audit disabled the `is_deactivated` arm outright and the entire suite
    /// stayed green: every "deactivation" assertion in the file was actually
    /// being satisfied by a *probe failure* returning the same message, so the
    /// gate's whole reason for existing was unverified.
    ///
    /// A genuinely deactivated account — Synapse healthy, `query_user` answering
    /// `is_deactivated: true` — must get `Unauthorized(DEACTIVATED_REJECT_MSG)`,
    /// and must NOT get the server-fault message. Together with the two `Err`
    /// tests above this is what stops the arms collapsing back into one.
    ///
    /// The mock models production exactly: Synapse reports a deactivated user's
    /// localpart as *taken*, which is precisely why the new-identity gate does
    /// not catch these users and this gate had to exist.
    #[tokio::test]
    async fn a_genuinely_deactivated_account_still_gets_the_deactivated_message() {
        let legacy = legacy_localpart(DEACTIVATION_TEST_DID);
        let (synapse, handle) = spawn_mas_mock(MasMock {
            existing: HashSet::from([legacy.clone()]),
            users: HashMap::from([(legacy, true)]),
            ..MasMock::default()
        })
        .await;
        let err = reject_if_deactivated(Some(&synapse), DEACTIVATION_TEST_DID)
            .await
            .expect_err("a deactivated account must not be able to sign back in");
        match err {
            crate::oidc::CustomError::Unauthorized(msg) => {
                assert_eq!(msg, DEACTIVATED_REJECT_MSG);
                assert_ne!(
                    msg, DEACTIVATION_CHECK_UNAVAILABLE_MSG,
                    "a determinate 'this account is deactivated' must not be dressed up \
                     as a transient server fault the user should retry"
                );
            }
            other => panic!("expected Unauthorized, got {:?}", other),
        }
        handle.abort();
    }

    /// The two `Ok` arms, pinned so the gate cannot become a blanket reject the
    /// moment someone hardens it. An ACTIVE account passes, and an ABSENT one
    /// passes too — the absent case belongs to `reject_if_new_identity`, and
    /// conflating it here would break legitimate first-time sign-in at the login
    /// screen, which is the one place account creation is allowed.
    #[tokio::test]
    async fn an_active_or_absent_account_passes_the_deactivation_gate() {
        let legacy = legacy_localpart(DEACTIVATION_TEST_DID);
        let (synapse, handle) = spawn_mas_mock(MasMock {
            existing: HashSet::from([legacy.clone()]),
            users: HashMap::from([(legacy, false)]),
            ..MasMock::default()
        })
        .await;
        assert!(
            reject_if_deactivated(Some(&synapse), DEACTIVATION_TEST_DID)
                .await
                .is_ok(),
            "an ACTIVE account must pass the deactivation gate"
        );
        handle.abort();

        // A genuinely unknown identity: BOTH localpart shapes read as free, so
        // `resolve_identity` reports `is_new` and hands back the modern shape,
        // and the mock has no `users` entry for it -> 404 -> `Ok(None)`.
        let (synapse, handle) = spawn_mas_mock(MasMock::default()).await;
        assert!(
            reject_if_deactivated(Some(&synapse), DEACTIVATION_TEST_DID)
                .await
                .is_ok(),
            "an ABSENT account is the new-identity case and belongs to \
             reject_if_new_identity, not to this gate — rejecting it here would \
             break first-time sign-in at the login screen"
        );
        handle.abort();
    }

    /// The deactivation-failure message is rendered VERBATIM to the caller: the
    /// account and device-approval pages show the response body for any non-2xx,
    /// and `/sign_in` is a full-page navigation whose body the browser paints as
    /// plain text. The caller has proven a DID and nothing else, so the message
    /// must carry no operational detail — a leaked "500 from /_synapse/mas" would
    /// hand a stranger a map of our internals.
    ///
    /// Everything diagnostic belongs in the `warn!` beside the reject instead,
    /// which only an operator reads. This pins both directions: what the message
    /// must NOT say, and the two things the wording is REQUIRED to convey (retry,
    /// then escalate). It also pins the one claim that must be absent — that the
    /// account was deactivated — which is the entire reason the constant exists.
    #[test]
    fn the_deactivation_failure_message_leaks_no_server_internals() {
        let lower = DEACTIVATION_CHECK_UNAVAILABLE_MSG.to_lowercase();
        for forbidden in [
            "secret",
            "synapse",
            "500",
            "503",
            "403",
            "401",
            "errcode",
            "m_",
            "token",
            "http",
            "localpart",
            "mxid",
        ] {
            assert!(
                !lower.contains(forbidden),
                "the deactivation-failure message must not mention {forbidden:?}: \
                 {DEACTIVATION_CHECK_UNAVAILABLE_MSG}"
            );
        }
        // And it must not make the one claim that is actively FALSE here, which
        // is the entire reason this constant exists.
        assert!(
            !lower.contains("deactivat"),
            "a probe failure must not be reported as 'your account was deactivated': \
             {DEACTIVATION_CHECK_UNAVAILABLE_MSG}"
        );
        assert!(
            lower.contains("try again"),
            "the condition is transient, so the message must invite a retry: \
             {DEACTIVATION_CHECK_UNAVAILABLE_MSG}"
        );
        assert!(
            lower.contains("administrator"),
            "a persisting server fault needs an escalation path: \
             {DEACTIVATION_CHECK_UNAVAILABLE_MSG}"
        );
    }

    /// The two "could not check" messages are byte-equal ON PURPOSE, and this
    /// test is where that decision is recorded.
    ///
    /// On the account and device-approval paths `reject_if_new_identity` runs
    /// immediately before `reject_if_deactivated`. If the two 503 bodies differed,
    /// a caller could tell WHICH gate they reached — i.e. that they got past the
    /// new-identity check, i.e. that an account exists for their DID. That fact is
    /// already public via `GET /resolve?did=…`, so this is a small thing; but it
    /// costs nothing to close and there is no compensating benefit, because a user
    /// cannot act on which internal probe failed and an operator reads the two
    /// distinct `warn!` lines rather than the body.
    ///
    /// They remain two constants rather than one alias because they belong to two
    /// gates with two different owners. If a future change makes them diverge
    /// deliberately, delete this test *and say why here* — do not weaken it to an
    /// `assert_ne!`, and do not merge the constants either.
    #[test]
    fn the_two_unavailable_messages_are_deliberately_indistinguishable() {
        assert_eq!(
            DEACTIVATION_CHECK_UNAVAILABLE_MSG, IDENTITY_CHECK_UNAVAILABLE_MSG,
            "two distinguishable 'could not check' bodies would tell the caller which \
             gate they reached, and so whether an account exists — see this test's doc"
        );
        // The pair being equal must not be allowed to make the OTHER pair equal:
        // "we could not check" and "you are deactivated" are the split this whole
        // fix is about.
        assert_ne!(DEACTIVATION_CHECK_UNAVAILABLE_MSG, DEACTIVATED_REJECT_MSG);
        assert_ne!(IDENTITY_CHECK_UNAVAILABLE_MSG, NEW_IDENTITY_REJECT_MSG);
    }

    // -- MAS mock for the deactivation gate ----------------------------------
    //
    // `localpart::resolve_identity_tests`'s mock serves `is_localpart_available`
    // but NOT `query_user`, so it cannot express any of the states this gate
    // actually decides on. Rather than widen a helper another module owns, the
    // deactivation tests carry their own two-route mock — which is also the only
    // way to fault ONE of the two routes while the other answers normally, the
    // exact shape `a_query_user_failure_is_a_probe_failure_not_a_deactivation`
    // needs.

    /// A `did:key` whose legacy localpart is short enough to be a valid Synapse
    /// user id, so `resolve_identity` grandfathers it instead of taking the
    /// `Unusable` branch. Shared by the deactivation tests so the mock's
    /// `existing`/`users` keys always name the same account.
    const DEACTIVATION_TEST_DID: &str = "did:key:zDnDEACTIVATIONGATE";

    #[derive(Default)]
    struct MasMock {
        /// Localparts that read as "already taken": `400 M_USER_IN_USE`. A
        /// deactivated user's localpart IS taken as far as Synapse is concerned,
        /// which is exactly why this gate had to exist.
        existing: HashSet<String>,
        /// localpart -> `is_deactivated`. A localpart with no entry answers 404,
        /// which `query_user` maps to `Ok(None)` (no such account).
        users: HashMap<String, bool>,
        /// When set, `query_user` answers this status with no body instead of
        /// doing anything — the lever for faulting ONE of the two routes.
        query_user_status: Option<axum::http::StatusCode>,
    }

    async fn spawn_mas_mock(
        cfg: MasMock,
    ) -> (crate::synapse_client::SynapseClient, JoinHandle<()>) {
        use axum::extract::{Query, State};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::{Json, Router};
        use std::sync::Arc;

        async fn available(
            State(cfg): State<Arc<MasMock>>,
            Query(params): Query<HashMap<String, String>>,
        ) -> axum::response::Response {
            let localpart = params.get("localpart").cloned().unwrap_or_default();
            if cfg.existing.contains(&localpart) {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"errcode": "M_USER_IN_USE", "error": "in use"})),
                )
                    .into_response()
            } else {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({"available": true})),
                )
                    .into_response()
            }
        }

        async fn query_user(
            State(cfg): State<Arc<MasMock>>,
            Query(params): Query<HashMap<String, String>>,
        ) -> axum::response::Response {
            if let Some(status) = cfg.query_user_status {
                return (status, "").into_response();
            }
            let localpart = params.get("localpart").cloned().unwrap_or_default();
            match cfg.users.get(&localpart) {
                Some(is_deactivated) => (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({
                        "user_id": format!("@{localpart}:example.org"),
                        "display_name": null,
                        "avatar_url": null,
                        "is_suspended": false,
                        "is_deactivated": is_deactivated,
                    })),
                )
                    .into_response(),
                // Synapse's own "no such user" shape, which `query_user` reads as
                // `Ok(None)` — the new-identity case, not a failure.
                None => (
                    axum::http::StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"errcode": "M_NOT_FOUND", "error": "User not found"})),
                )
                    .into_response(),
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mas-mock port");
        let addr = listener.local_addr().expect("mas-mock local_addr");
        let app = Router::new()
            .route("/_synapse/mas/is_localpart_available", get(available))
            .route("/_synapse/mas/query_user", get(query_user))
            .with_state(Arc::new(cfg));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mas-mock server");
        });
        let client = crate::synapse_client::SynapseClient::new(&format!("http://{addr}"), "secret");
        (client, handle)
    }
    /// The gate reads exactly one field off the MAS wire, so pin the shape of
    /// `MasQueryUserResource.Response` (synapse 1.159.0). Two properties matter:
    /// an ACTIVE user must parse to `is_deactivated == false` (a parse that
    /// defaulted the wrong way would silently lock every user out), and an
    /// unknown extra field must not break parsing on a security path.
    #[test]
    fn mas_user_info_parses_the_synapse_wire_shape() {
        use crate::synapse_client::MasUserInfo;

        let active: MasUserInfo = serde_json::from_str(
            r#"{"user_id":"@alice:example.org","display_name":"Alice","avatar_url":null,
                 "is_suspended":false,"is_deactivated":false}"#,
        )
        .expect("active user must parse");
        assert!(
            !active.is_deactivated,
            "active user must not read as deactivated"
        );
        assert_eq!(active.user_id, "@alice:example.org");

        let gone: MasUserInfo = serde_json::from_str(
            r#"{"user_id":"@bob:example.org","display_name":null,"avatar_url":null,
                 "is_suspended":false,"is_deactivated":true,"future_field":42}"#,
        )
        .expect("unknown fields must not break a security-gate parse");
        assert!(
            gone.is_deactivated,
            "deactivated user must read as deactivated"
        );
    }

    /// H2 (enumeration-safety): a FORGED `siwx_user` cookie token is a Redis miss,
    /// so the handler resolves `scope_did = None` and `authenticate_start` runs the
    /// usernameless (discoverable) path with an EMPTY `allowCredentials` — leaking
    /// zero credential ids. This exercises the exact seam the HTTP handler uses
    /// (`lookup_user_session` -> `authenticate_start(scope_did)`), end to end against
    /// Redis. Needs Redis (`siwx_oidc::test_support::redis`).
    #[tokio::test]
    async fn forged_user_cookie_yields_usernameless_empty_allow_credentials() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };

        // A localhost RP is valid for WebauthnBuilder (origin must be https OR
        // localhost); this lets the test build a real Webauthn without TLS.
        let base = Url::parse("http://localhost:8000").unwrap();
        let (_cfg, dispatch) =
            build_rp_dispatch(&base, None, None, None).expect("build rp dispatch");

        // A forged/guessed token that was never minted -> lookup must miss -> None.
        let nonce = Uuid::new_v4().simple().to_string();
        let forged = format!("forged{nonce}deadbeefcafe");
        let scope_did = redis
            .lookup_user_session(&forged)
            .await
            .expect("lookup must not error");
        assert!(
            scope_did.is_none(),
            "a forged token must be a Redis miss -> None (usernameless fallback)"
        );

        // Drive authenticate_start with the resolved (None) scope: usernameless.
        let session_id = format!("forgedsess{nonce}");
        let rcr = authenticate_start(&dispatch, &redis, &session_id, scope_did.as_deref(), false)
            .await
            .expect("authenticate_start must succeed");
        assert!(
            rcr.public_key.allow_credentials.is_empty(),
            "forged cookie -> usernameless -> allowCredentials MUST be empty (no enumeration)"
        );
    }

    /// A unified-RP login offers discoverable credentials only: a scope DID
    /// (the `siwx_user` cookie) that still has stored legacy credentials must
    /// not narrow the unified request to those ids, or the store-free key is
    /// excluded from the picker. Needs Redis.
    #[tokio::test]
    async fn unified_login_ignores_the_scope_dids_legacy_allow_list() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let nonce = Uuid::new_v4().simple().to_string();
        let did = format!("did:key:zDnU{nonce}");
        let cred = URL_SAFE_NO_PAD.encode(format!("credU-{nonce}").as_bytes());
        redis.index_add_passkey(&did, &cred).await.expect("seed");

        let unified_session = format!("unisess{nonce}");
        let unified = authenticate_start_with_hint(
            &dispatch,
            &redis,
            &unified_session,
            Some(&did),
            false,
            None,
        )
        .await
        .expect("unified start");
        let legacy_session = format!("legsess{nonce}");
        let legacy = authenticate_start_with_hint(
            &dispatch,
            &redis,
            &legacy_session,
            Some(&did),
            true,
            None,
        )
        .await
        .expect("legacy start");
        redis
            .del_raw(&format!(
                "{}/{did}",
                siwx_oidc::db::KV_WEBAUTHN_BY_DID_PREFIX
            ))
            .await
            .ok();
        assert_eq!(unified.public_key.rp_id, UNIFIED_TEST_RP);
        assert!(
            unified.public_key.allow_credentials.is_empty(),
            "unified RP: discoverable only, the scope DID's legacy ids must not narrow it"
        );
        assert_eq!(
            legacy.public_key.allow_credentials.len(),
            1,
            "the legacy arm keeps scoping to the DID's stored credentials"
        );
    }

    /// A ceremony's session id is the key to its challenge in Redis and arrives
    /// as a cookie, so it is a credential for the ceremony's duration. The start
    /// of each ceremony logs at `info!`; the logs may name the session only by
    /// fingerprint. Needs Redis (`siwx_oidc::test_support::redis`).
    #[tokio::test]
    async fn the_ceremony_starts_log_session_ids_only_as_fingerprints() {
        use siwx_oidc::redact::fingerprint;

        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let base = Url::parse("http://localhost:8000").unwrap();
        let (cfg, dispatch) =
            build_rp_dispatch(&base, None, None, None).expect("build rp dispatch");
        let nonce = Uuid::new_v4().simple().to_string();
        let did = format!("did:key:zDnLOG{nonce}");
        let cred = URL_SAFE_NO_PAD.encode(format!("cred-{nonce}").as_bytes());
        redis.index_add_passkey(&did, &cred).await.expect("seed");

        let register_session = format!("regsess{nonce}");
        let scoped_session = format!("scopedsess{nonce}");
        let open_session = format!("opensess{nonce}");
        let link_session = format!("linksess{nonce}");

        let logs = siwx_oidc::test_support::LogCapture::start();
        register_start(&cfg.webauthn, &redis, &register_session, None)
            .await
            .expect("register_start");
        authenticate_start(&dispatch, &redis, &scoped_session, Some(&did), false)
            .await
            .expect("scoped authenticate_start");
        authenticate_start(&dispatch, &redis, &open_session, None, false)
            .await
            .expect("usernameless authenticate_start");
        link_start(&cfg.webauthn, &redis, &link_session, &did, None)
            .await
            .expect("link_start");
        let output = logs.output();

        for session in [
            &register_session,
            &scoped_session,
            &open_session,
            &link_session,
        ] {
            assert!(
                !output.contains(session.as_str()),
                "session id {session} appears in the logs in the clear:\n{}",
                output
                    .lines()
                    .filter(|l| l.contains(session.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            assert!(
                output.contains(&fingerprint(session)),
                "the logs never name the fingerprint of session {session}; captured:\n{output}"
            );
        }
        assert!(
            !output.contains(&cred),
            "a credential id appears in the logs in the clear:\n{output}"
        );
    }

    /// H1/H2 (positive scoping): a VALID `siwx_user` session for DID A makes
    /// `authenticate_start` offer EXACTLY A's credential and NEVER B's. This is the
    /// other half of the forged-cookie test — it proves the scoped path is correct,
    /// not merely safe, and is the server-side twin of the browser two-credential
    /// case. Seeds the `by_did` index directly (the SMEMBERS fast path) so it needs no
    /// real attestation. Needs Redis (`siwx_oidc::test_support::redis`).
    #[tokio::test]
    async fn valid_user_session_scopes_allow_credentials_to_its_did_only() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let base = Url::parse("http://localhost:8000").unwrap();
        let (_cfg, dispatch) =
            build_rp_dispatch(&base, None, None, None).expect("build rp dispatch");

        let nonce = Uuid::new_v4().simple().to_string();
        let did_a = format!("did:key:zDnA{nonce}");
        let did_b = format!("did:key:zDnB{nonce}");
        let cred_a = URL_SAFE_NO_PAD.encode(format!("credA-{nonce}").as_bytes());
        let cred_b = URL_SAFE_NO_PAD.encode(format!("credB-{nonce}").as_bytes());
        redis
            .index_add_passkey(&did_a, &cred_a)
            .await
            .expect("seed A");
        redis
            .index_add_passkey(&did_b, &cred_b)
            .await
            .expect("seed B");

        // Mint the opaque user-session the handler resolves from the siwx_user cookie.
        let token = redis
            .create_user_session(&did_a)
            .await
            .expect("mint session");
        let scope_did = redis.lookup_user_session(&token).await.expect("lookup");
        assert_eq!(scope_did.as_deref(), Some(did_a.as_str()));

        let session_id = format!("scopesess{nonce}");
        let rcr = authenticate_start(&dispatch, &redis, &session_id, scope_did.as_deref(), false)
            .await
            .expect("authenticate_start");

        let offered: Vec<String> = rcr
            .public_key
            .allow_credentials
            .iter()
            .map(|c| URL_SAFE_NO_PAD.encode(&*c.id))
            .collect();
        assert_eq!(
            offered,
            vec![cred_a.clone()],
            "scoped to A: offer exactly A's credential"
        );
        assert!(
            !offered.contains(&cred_b),
            "B's credential must NEVER be offered when scoped to A"
        );

        // Cleanup so reruns stay isolated (no TTL on by_did / user-session here).
        redis.index_remove_passkey(&did_a, &cred_a).await.ok();
        redis.index_remove_passkey(&did_b, &cred_b).await.ok();
        redis.destroy_user_session(&token).await.ok();
    }

    // -- Registration through a software authenticator ------------------------
    //
    // These helpers answer `register_start`'s options for the
    // `http://localhost:8000` RP the way a browser authenticator would, with a
    // `none` attestation built by a minimal CBOR writer instead of a
    // software-authenticator dependency.

    const REG_TEST_ORIGIN: &str = "http://localhost:8000";

    /// One CBOR head: major type `major`, argument `n` (RFC 8949 section 3).
    fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend_from_slice(
                    &u32::try_from(n)
                        .expect("test CBOR stays small")
                        .to_be_bytes(),
                );
            }
        }
    }

    fn cbor_int(out: &mut Vec<u8>, v: i64) {
        if v >= 0 {
            cbor_head(out, 0, v as u64);
        } else {
            cbor_head(out, 1, (-1 - v) as u64);
        }
    }

    fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
        cbor_head(out, 2, b.len() as u64);
        out.extend_from_slice(b);
    }

    fn cbor_text(out: &mut Vec<u8>, s: &str) {
        cbor_head(out, 3, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }

    /// The did:key a registration of `key` resolves to.
    fn did_of(key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(true);
        let compressed: [u8; 33] = point.as_bytes().try_into().expect("compressed P-256");
        aqua_auth::did_key_from_p256_compressed(&compressed)
    }

    /// The authenticator's answer to `challenge`: a `none` attestation of a
    /// user-verified ES256 credential `cred_id` holding `key`'s public key.
    fn none_attestation(
        challenge: &[u8],
        cred_id: &[u8],
        key: &p256::ecdsa::SigningKey,
    ) -> RegisterPublicKeyCredential {
        use sha2::{Digest, Sha256};

        let client_data_json = serde_json::json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": REG_TEST_ORIGIN,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes();

        let point = key.verifying_key().to_encoded_point(false);
        let mut cose_key = Vec::new();
        cbor_head(&mut cose_key, 5, 5);
        cbor_int(&mut cose_key, 1); // kty
        cbor_int(&mut cose_key, 2); // EC2
        cbor_int(&mut cose_key, 3); // alg
        cbor_int(&mut cose_key, -7); // ES256
        cbor_int(&mut cose_key, -1); // crv
        cbor_int(&mut cose_key, 1); // P-256
        cbor_int(&mut cose_key, -2);
        cbor_bytes(&mut cose_key, point.x().expect("x"));
        cbor_int(&mut cose_key, -3);
        cbor_bytes(&mut cose_key, point.y().expect("y"));

        let mut auth_data = Sha256::digest(b"localhost").to_vec();
        auth_data.push(0x45); // UP | UV | AT
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // signCount
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(&cose_key);

        let mut attestation_object = Vec::new();
        cbor_head(&mut attestation_object, 5, 3);
        cbor_text(&mut attestation_object, "fmt");
        cbor_text(&mut attestation_object, "none");
        cbor_text(&mut attestation_object, "attStmt");
        cbor_head(&mut attestation_object, 5, 0);
        cbor_text(&mut attestation_object, "authData");
        cbor_bytes(&mut attestation_object, &auth_data);

        RegisterPublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(cred_id),
            raw_id: cred_id.to_vec(),
            response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        }
    }

    /// `register_start` then `register_finish` for credential `cred_id` holding `key`.
    async fn register_with(
        webauthn: &Webauthn,
        redis: &RedisClient,
        cred_id: &[u8],
        key: &p256::ecdsa::SigningKey,
    ) -> Result<RegisterFinishResponse, RegisterFinishError> {
        let session_id = format!("regtest{}", Uuid::new_v4().simple());
        let ccr = register_start(webauthn, redis, &session_id, None)
            .await
            .expect("register_start");
        let reg = none_attestation(&ccr.public_key.challenge, cred_id, key);
        register_finish(webauthn, redis, &session_id, reg).await
    }

    /// The route's registration finish by deployment shape. A single-RP
    /// deployment (the default, no distinct unified RP) still registers and
    /// stores the passkey; a deployment with a distinct unified RP answers
    /// Retired (410) and writes nothing. Needs Redis.
    #[tokio::test]
    async fn register_finish_route_by_deployment_shape() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let (cfg, single) =
            build_rp_dispatch(&Url::parse(REG_TEST_ORIGIN).unwrap(), None, None, None)
                .expect("single-RP dispatch");
        assert!(single.unified.is_none());
        let two = two_rp_dispatch();

        // single-RP: register_start, then the routed finish stores the passkey
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_key = format!("{CREDENTIAL_PREFIX}/{}", URL_SAFE_NO_PAD.encode(&cred_id));
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let session_id = format!("regroute{}", Uuid::new_v4().simple());
        let ccr = register_start(&cfg.webauthn, &redis, &session_id, None)
            .await
            .expect("register_start");
        let reg = none_attestation(&ccr.public_key.challenge, &cred_id, &key);
        let done = register_finish_for(&single, &cfg.webauthn, &redis, &session_id, reg).await;
        let stored = redis.get_raw(&cred_key).await.expect("GET");
        redis.del_raw(&cred_key).await.ok();
        let resp = done.expect("a single-RP deployment still registers");
        assert_eq!(resp.did, did_of(&key));
        assert!(stored.is_some(), "the passkey was stored");

        // unified RP: Retired, and nothing is written
        let cred_id2 = Uuid::new_v4().as_bytes().to_vec();
        let cred_key2 = format!("{CREDENTIAL_PREFIX}/{}", URL_SAFE_NO_PAD.encode(&cred_id2));
        let key2 = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let session2 = format!("regroute{}", Uuid::new_v4().simple());
        let ccr2 = register_start(&cfg.webauthn, &redis, &session2, None)
            .await
            .expect("register_start");
        let reg2 = none_attestation(&ccr2.public_key.challenge, &cred_id2, &key2);
        let gone = register_finish_for(&two, &cfg.webauthn, &redis, &session2, reg2).await;
        let written = redis.get_raw(&cred_key2).await.expect("GET");
        redis.del_raw(&cred_key2).await.ok();
        assert!(matches!(gone, Err(RegisterFinishError::Retired)));
        assert!(written.is_none(), "a unified deployment stores nothing");
        let ce: crate::oidc::CustomError = RegisterFinishError::Retired.into();
        assert!(matches!(ce, crate::oidc::CustomError::Gone));
    }

    fn reg_test_webauthn() -> WebauthnConfig {
        build_webauthn(&Url::parse(REG_TEST_ORIGIN).unwrap(), None, None).expect("build webauthn")
    }

    fn by_did_key(did: &str) -> String {
        format!("{}/{}", siwx_oidc::db::KV_WEBAUTHN_BY_DID_PREFIX, did)
    }

    /// Registration is create-only: a second registration under a credential id
    /// that is already stored is refused, and leaves the stored passkey and the
    /// second key's DID index exactly as they were. Needs Redis
    /// (`siwx_oidc::test_support::redis`).
    #[tokio::test]
    async fn registering_an_existing_credential_id_is_refused_and_the_stored_blob_is_unchanged() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let cfg = reg_test_webauthn();
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
        let cred_key = format!("{CREDENTIAL_PREFIX}/{cred_b64}");
        let key_a = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let key_b = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (did_a, did_b) = (did_of(&key_a), did_of(&key_b));

        let first = register_with(&cfg.webauthn, &redis, &cred_id, &key_a)
            .await
            .expect("the first registration of a fresh id succeeds");
        assert_eq!(first.did, did_a);
        let stored = redis
            .get_raw(&cred_key)
            .await
            .expect("GET")
            .expect("the first registration stored the passkey");

        let second = register_with(&cfg.webauthn, &redis, &cred_id, &key_b).await;
        let after = redis.get_raw(&cred_key).await.expect("GET");
        let index_b = redis
            .smembers_raw(&by_did_key(&did_b))
            .await
            .expect("SMEMBERS");

        // Cleanup before asserting, so a failing run leaves nothing behind.
        redis.del_raw(&cred_key).await.ok();
        redis.index_remove_passkey(&did_a, &cred_b64).await.ok();
        redis.index_remove_passkey(&did_b, &cred_b64).await.ok();

        assert_eq!(
            after.as_deref(),
            Some(stored.as_str()),
            "the stored passkey for an existing credential id was replaced"
        );
        assert!(
            matches!(second, Err(RegisterFinishError::AlreadyRegistered)),
            "a second registration under an existing credential id must be refused as \
             AlreadyRegistered, got {:?}",
            second.as_ref().map(|r| &r.did)
        );
        assert!(
            !index_b.contains(&cred_b64),
            "the second key's DID index lists the existing credential id"
        );
    }

    /// A credential id that has link state (`webauthn:link/{id}`) but no stored
    /// passkey is refused too: no passkey is stored, the key's DID index is
    /// untouched, and the link entry stays as it was. Needs Redis.
    #[tokio::test]
    async fn registering_an_id_with_existing_link_state_is_refused() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let cfg = reg_test_webauthn();
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
        let cred_key = format!("{CREDENTIAL_PREFIX}/{cred_b64}");
        let link_key = format!("{LINK_PREFIX}/{cred_b64}");
        let link_json = serde_json::to_string(&LinkEntry {
            primary_did: format!("did:pkh:eip155:1:0x{}", Uuid::new_v4().simple()),
            label: "test".to_string(),
        })
        .unwrap();
        redis
            .set_raw(&link_key, &link_json)
            .await
            .expect("seed link");
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let did = did_of(&key);

        let resp = register_with(&cfg.webauthn, &redis, &cred_id, &key).await;
        let stored = redis.get_raw(&cred_key).await.expect("GET");
        let link_after = redis.get_raw(&link_key).await.expect("GET");
        let index = redis
            .smembers_raw(&by_did_key(&did))
            .await
            .expect("SMEMBERS");

        redis.del_raw(&cred_key).await.ok();
        redis.del_raw(&link_key).await.ok();
        redis.index_remove_passkey(&did, &cred_b64).await.ok();

        assert!(
            matches!(resp, Err(RegisterFinishError::AlreadyRegistered)),
            "an id with existing link state must be refused as AlreadyRegistered, got {:?}",
            resp.as_ref().map(|r| &r.did)
        );
        assert_eq!(
            stored, None,
            "a passkey was stored for an id with link state"
        );
        assert_eq!(link_after.as_deref(), Some(link_json.as_str()));
        assert!(
            !index.contains(&cred_b64),
            "the key's DID index lists the id"
        );
    }

    /// Control: a credential id never seen before registers, is stored, and is
    /// indexed under the DID of its key. Needs Redis.
    #[tokio::test]
    async fn a_fresh_credential_id_still_registers() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let cfg = reg_test_webauthn();
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
        let cred_key = format!("{CREDENTIAL_PREFIX}/{cred_b64}");
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let did = did_of(&key);

        let resp = register_with(&cfg.webauthn, &redis, &cred_id, &key).await;
        let stored = redis.get_raw(&cred_key).await.expect("GET");
        let index = redis
            .smembers_raw(&by_did_key(&did))
            .await
            .expect("SMEMBERS");

        redis.del_raw(&cred_key).await.ok();
        redis.index_remove_passkey(&did, &cred_b64).await.ok();

        let resp = resp.expect("a fresh credential id registers");
        assert_eq!(resp.did, did);
        assert_eq!(resp.credential_id, cred_b64);
        let stored = stored.expect("the passkey is stored");
        assert_eq!(
            derive_did_from_credential_json(&stored).as_deref(),
            Some(did.as_str())
        );
        assert_eq!(index, vec![cred_b64]);
    }

    // -- Registration with the shared credential store enabled ---------------
    //
    // `credential_store::shared_store` reads `AQUA_WEBAUTHN_REDIS_URL` once per
    // process and memoises the answer, so the store-enabled mode cannot be
    // switched on inside this test process. The test below therefore runs in
    // two roles: as a normal test it re-runs itself as a child process of this
    // test binary with the flag set, and checks that the child ran exactly one
    // test and passed it.

    /// Set in the child process; selects the child role.
    const SHARED_STORE_CHILD_VAR: &str = "SIWX_TEST_SHARED_STORE_CHILD";

    /// The Redis database the child's shared credential store lives in: the
    /// test Redis server, a database of its own, so the store and the legacy
    /// namespace are as separate as two deployments' stores would be.
    const SHARED_STORE_TEST_DB: u8 = 11;

    const SHARED_STORE_TEST_NAME: &str =
        "webauthn::tests::a_credential_id_held_only_by_the_shared_store_is_refused";

    /// With the shared credential store enabled, a credential id the store
    /// already holds is refused even when the legacy namespace has no entry for
    /// it (the store is shared with another service, or the legacy entry is
    /// gone): the store row keeps its DID and key, nothing is written to the
    /// legacy namespace, and the second key's DID index is untouched. A fresh
    /// id still registers and is mirrored into the store (control). Needs Redis.
    #[tokio::test]
    async fn a_credential_id_held_only_by_the_shared_store_is_refused() {
        if std::env::var_os(SHARED_STORE_CHILD_VAR).is_some() {
            return shared_store_child().await;
        }
        if siwx_oidc::test_support::redis().await.is_none() {
            return;
        }
        let mut store_url = siwx_oidc::test_support::redis_url();
        store_url.set_path(&format!("/{SHARED_STORE_TEST_DB}"));
        let out = tokio::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                SHARED_STORE_TEST_NAME,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(SHARED_STORE_CHILD_VAR, "1")
            .env(siwx_oidc::credential_store::ENABLE_ENV, store_url.as_str())
            // The parent reached Redis, so the child must not skip.
            .env(siwx_oidc::test_support::REQUIRE_REDIS_VAR, "1")
            .output()
            .await
            .expect("run the child test");
        // Indented, so no line of the child's report starts with `test result:`
        // in this process's output.
        let indent = |b: &[u8]| {
            String::from_utf8_lossy(b)
                .lines()
                .map(|l| format!("  | {l}\n"))
                .collect::<String>()
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed"),
            "the store-enabled child run failed or did not run exactly one test ({}):\n{}{}",
            out.status,
            indent(&out.stdout),
            indent(&out.stderr)
        );
    }

    /// The child role of [`a_credential_id_held_only_by_the_shared_store_is_refused`].
    async fn shared_store_child() {
        use aqua_auth::webauthn_store::{CredentialId, NewCredential, WebauthnCredentialBackend};

        let redis = siwx_oidc::test_support::redis()
            .await
            .expect("Redis is required in the child");
        let store = siwx_oidc::credential_store::shared_store()
            .await
            .expect("the child runs with the shared credential store enabled");
        let cfg = reg_test_webauthn();

        // Control: a fresh id registers, and the mirror writes it to the store
        // under its key's did:key. This also proves the store is live.
        let fresh_id = Uuid::new_v4().as_bytes().to_vec();
        let fresh_b64 = URL_SAFE_NO_PAD.encode(&fresh_id);
        let key_c = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let did_c = did_of(&key_c);
        let fresh = register_with(&cfg.webauthn, &redis, &fresh_id, &key_c).await;
        let mirrored = store.get_by_id(&CredentialId(fresh_id.clone())).await;
        redis
            .del_raw(&format!("{CREDENTIAL_PREFIX}/{fresh_b64}"))
            .await
            .ok();
        redis.index_remove_passkey(&did_c, &fresh_b64).await.ok();
        store.delete(&did_c, &CredentialId(fresh_id)).await.ok();
        assert_eq!(fresh.expect("a fresh id registers").did, did_c);
        assert_eq!(
            mirrored
                .expect("store lookup")
                .expect("the fresh id is mirrored into the store")
                .did,
            did_c
        );

        // An id that only the store holds.
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
        let cred_key = format!("{CREDENTIAL_PREFIX}/{cred_b64}");
        let key_a = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let key_b = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (did_a, did_b) = (did_of(&key_a), did_of(&key_b));
        let blob_a = format!(r#"{{"held_by":"another service","did":"{did_a}"}}"#);
        store
            .insert(NewCredential {
                did: did_a.clone(),
                credential_id: CredentialId(cred_id.clone()),
                public_key: blob_a.clone().into_bytes(),
                sign_count: 0,
                transports: Vec::new(),
                label: None,
            })
            .await
            .expect("seed the store row");

        let second = register_with(&cfg.webauthn, &redis, &cred_id, &key_b).await;
        let row_after = store.get_by_id(&CredentialId(cred_id.clone())).await;
        let legacy_after = redis.get_raw(&cred_key).await.expect("GET");
        let index_b = redis
            .smembers_raw(&by_did_key(&did_b))
            .await
            .expect("SMEMBERS");

        // Cleanup before asserting, so a failing run leaves nothing behind.
        store
            .delete(&did_a, &CredentialId(cred_id.clone()))
            .await
            .ok();
        store
            .delete(&did_b, &CredentialId(cred_id.clone()))
            .await
            .ok();
        redis.del_raw(&cred_key).await.ok();
        redis.index_remove_passkey(&did_b, &cred_b64).await.ok();

        let row_after = row_after
            .expect("store lookup")
            .expect("the store row still exists");
        assert_eq!(
            (row_after.did.as_str(), row_after.public_key.as_slice()),
            (did_a.as_str(), blob_a.as_bytes()),
            "the store row for an id it already held was replaced"
        );
        assert!(
            matches!(second, Err(RegisterFinishError::AlreadyRegistered)),
            "an id the shared store holds must be refused as AlreadyRegistered, got {:?}",
            second.as_ref().map(|r| &r.did)
        );
        assert_eq!(
            legacy_after, None,
            "a passkey was stored in the legacy namespace for an id the store holds"
        );
        assert!(
            !index_b.contains(&cred_b64),
            "the second key's DID index lists the id"
        );
    }

    // -- rpIdHash dispatch (two relying parties) --------------------------------

    const UNIFIED_TEST_RP: &str = "example.org";
    const UNIFIED_TEST_ORIGIN: &str = "https://siwx.example.org";

    /// Legacy RP `localhost` (origin `REG_TEST_ORIGIN`) plus a distinct unified RP.
    fn two_rp_dispatch() -> RpDispatch {
        let (_cfg, dispatch) = build_rp_dispatch(
            &Url::parse(REG_TEST_ORIGIN).unwrap(),
            Some(UNIFIED_TEST_RP),
            Some(UNIFIED_TEST_ORIGIN),
            Some("localhost"),
        )
        .expect("build rp dispatch");
        dispatch
    }

    /// A user-verified assertion for `rp_id` / `origin` over `challenge`, signed by `key`.
    fn assertion_for(
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        cred_id: &[u8],
        key: &p256::ecdsa::SigningKey,
        counter: u32,
    ) -> PublicKeyCredential {
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};

        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes();
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(0x05); // UP | UV
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig: Signature = key.sign(&signed);
        PublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(cred_id),
            raw_id: cred_id.to_vec(),
            response: webauthn_rs_proto::AuthenticatorAssertionResponseRaw {
                authenticator_data,
                client_data_json,
                signature: sig.to_der().as_bytes().to_vec(),
                user_handle: None,
            },
            extensions: Default::default(),
            type_: "public-key".to_string(),
        }
    }

    /// The login offer names the unified RP unless the legacy RP is asked for.
    /// Needs Redis.
    #[tokio::test]
    async fn authenticate_start_uses_the_unified_rp_by_default_and_the_legacy_rp_on_request() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let n = Uuid::new_v4().simple().to_string();
        let unified = authenticate_start(&dispatch, &redis, &format!("rpd-u{n}"), None, false)
            .await
            .expect("unified start");
        let legacy = authenticate_start(&dispatch, &redis, &format!("rpd-l{n}"), None, true)
            .await
            .expect("legacy start");
        assert_eq!(unified.public_key.rp_id, UNIFIED_TEST_RP);
        assert_eq!(legacy.public_key.rp_id, "localhost");
        assert_ne!(
            unified.public_key.challenge, legacy.public_key.challenge,
            "each offer carries its own challenge"
        );
        for sid in [format!("rpd-u{n}"), format!("rpd-l{n}")] {
            redis
                .take_ceremony_state(Ceremony::Challenge, &sid)
                .await
                .ok();
        }
    }

    /// A legacy-RP assertion takes the stored-blob path and resolves exactly the
    /// DID the old signature resolves, link override included. Needs Redis.
    #[tokio::test]
    async fn a_legacy_rp_assertion_takes_the_stored_path_unchanged() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let cfg = reg_test_webauthn();
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let cred_b64 = URL_SAFE_NO_PAD.encode(&cred_id);
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let own_did = did_of(&key);
        let linked_did = format!("did:key:zLinked{}", Uuid::new_v4().simple());
        register_with(&cfg.webauthn, &redis, &cred_id, &key)
            .await
            .expect("register");
        let link_key = format!("{}/{}", siwx_oidc::db::KV_WEBAUTHN_LINK_PREFIX, cred_b64);
        let link = serde_json::json!({ "primary_did": linked_did, "label": "t" }).to_string();

        let n = Uuid::new_v4().simple().to_string();
        let mut got = Vec::new();
        for (i, counter) in [(0u32, 1u32), (1, 2)] {
            // First pass: no link entry. Second pass: the link overrides the DID.
            if i == 1 {
                redis.set_raw(&link_key, &link).await.expect("seed link");
            }
            let sid = format!("rpd-leg{n}{i}");
            let rcr = authenticate_start(&dispatch, &redis, &sid, None, true)
                .await
                .expect("start");
            let cred = assertion_for(
                "localhost",
                REG_TEST_ORIGIN,
                &rcr.public_key.challenge,
                &cred_id,
                &key,
                counter,
            );
            got.push(verify_credential(&redis, &sid, &dispatch, &cred).await);
        }
        // Control: the old signature, on the same stored state.
        let sid = format!("rpd-ctl{n}");
        let rcr = authenticate_start(&dispatch, &redis, &sid, None, true)
            .await
            .expect("start");
        let cred = assertion_for(
            "localhost",
            REG_TEST_ORIGIN,
            &rcr.public_key.challenge,
            &cred_id,
            &key,
            3,
        );
        let control =
            verify_credential_legacy(&redis, &sid, "localhost", REG_TEST_ORIGIN, &cred).await;

        redis.del_raw(&link_key).await.ok();
        redis
            .del_raw(&format!("{CREDENTIAL_PREFIX}/{cred_b64}"))
            .await
            .ok();
        redis.index_remove_passkey(&own_did, &cred_b64).await.ok();

        let plain = got.remove(0).expect("legacy assertion verifies");
        let linked = got
            .remove(0)
            .expect("legacy assertion verifies when linked");
        let control = control.expect("control verifies");
        assert_eq!(plain.did, own_did);
        assert_eq!(linked.did, linked_did);
        assert_eq!(control.did, linked.did, "the legacy wrapper agrees");
    }

    /// An assertion for an RP the policy does not serve is refused before any
    /// credential-store read; the unified RP answers "not enabled" until it is
    /// wired; a truncated authenticatorData does not panic. Needs Redis.
    #[tokio::test]
    async fn an_assertion_for_a_third_rp_is_rejected() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let n = Uuid::new_v4().simple().to_string();

        // NO blob is stored for `cred_id`: reaching the store read would be
        // VerifyError::UnknownCredential.
        let sid = format!("rpd-third{n}");
        let rcr = authenticate_start(&dispatch, &redis, &sid, None, true)
            .await
            .expect("start");
        let cred = assertion_for(
            "evil.example",
            "https://evil.example",
            &rcr.public_key.challenge,
            &cred_id,
            &key,
            1,
        );
        let err = verify_credential(&redis, &sid, &dispatch, &cred)
            .await
            .err()
            .expect("a third RP must be rejected");
        assert!(
            !matches!(err, VerifyError::UnknownCredential(_)),
            "the store was read before the RP was checked"
        );
        assert!(
            err.to_string().contains("relying party"),
            "the rejection names the cause: {err}"
        );

        let sid = format!("rpd-unif{n}");
        let rcr = authenticate_start(&dispatch, &redis, &sid, None, false)
            .await
            .expect("start");
        let cred = assertion_for(
            UNIFIED_TEST_RP,
            UNIFIED_TEST_ORIGIN,
            &rcr.public_key.challenge,
            &cred_id,
            &key,
            1,
        );
        let err = verify_credential(&redis, &sid, &dispatch, &cred)
            .await
            .err()
            .expect("a hintless first visit asks for a second assertion");
        assert!(err.to_string().contains("second assertion"), "{err}");

        let sid = format!("rpd-short{n}");
        authenticate_start(&dispatch, &redis, &sid, None, true)
            .await
            .expect("start");
        let mut cred = assertion_for("localhost", REG_TEST_ORIGIN, b"x", &cred_id, &key, 1);
        cred.response.authenticator_data.truncate(36);
        assert!(verify_credential(&redis, &sid, &dispatch, &cred)
            .await
            .is_err());
        redis
            .take_ceremony_state(Ceremony::Challenge, &sid)
            .await
            .ok();
    }

    /// With the default configuration the dispatch serves one RP only.
    #[test]
    fn default_config_is_single_rp() {
        // The default `base_url` is an IP literal, which is no valid RP ID.
        let cfg = crate::config::Config {
            base_url: Url::parse("http://localhost:8000").unwrap(),
            ..Default::default()
        };
        let (legacy, dispatch) = build_rp_dispatch(
            &cfg.base_url,
            cfg.rp_id.as_deref(),
            cfg.rp_origin.as_deref(),
            cfg.legacy_rp_id.as_deref(),
        )
        .expect("build rp dispatch");
        assert!(dispatch.unified.is_none());
        assert_eq!(dispatch.policy.entries().len(), 1);
        assert_eq!(dispatch.legacy_rp_id, cfg.base_url.host_str().unwrap());
        assert_eq!(legacy.rp_id, dispatch.legacy_rp_id);
    }

    /// An `rp_id` alone is the one RP, as before the dispatch existed: it never
    /// turns an upgraded deployment into a two-RP one. Two RPs need
    /// `legacy_rp_id` too (the dev shape: RP `inblock.io`, host `dev.siwx...`).
    #[test]
    fn rp_id_alone_stays_single_rp_and_two_rps_need_legacy_rp_id() {
        let base = Url::parse("https://siwx.example.org").unwrap();
        let (cfg, d) = build_rp_dispatch(
            &base,
            Some("example.org"),
            Some("https://example.org"),
            None,
        )
        .expect("rp_id alone");
        assert!(d.unified.is_none(), "rp_id alone must not add a second RP");
        assert_eq!(d.legacy_rp_id, "example.org");
        assert_eq!(cfg.rp_id, "example.org");
        assert_eq!(
            d.legacy_origin, "https://example.org",
            "rp_origin still applies"
        );
        assert_eq!(d.policy.entries().len(), 1);

        let (_cfg, d) = build_rp_dispatch(
            &base,
            Some("example.org"),
            Some("https://example.org"),
            Some("siwx.example.org"),
        )
        .expect("both set");
        assert_eq!(
            d.unified.as_ref().map(|u| u.rp_id.as_str()),
            Some("example.org")
        );
        assert_eq!(d.legacy_rp_id, "siwx.example.org");
        assert_eq!(d.policy.entries().len(), 2);
    }

    // -- store-free unified login ------------------------------------------------

    fn pkc_of(a: &aqua_auth::AssertionJson) -> PublicKeyCredential {
        let d = |s: &str| URL_SAFE_NO_PAD.decode(s).expect("base64url");
        PublicKeyCredential {
            id: a.id.clone(),
            raw_id: d(&a.raw_id),
            response: webauthn_rs_proto::AuthenticatorAssertionResponseRaw {
                authenticator_data: d(&a.response.authenticator_data),
                client_data_json: d(&a.response.client_data_json),
                signature: d(&a.response.signature),
                user_handle: a.response.user_handle.as_deref().map(d),
            },
            extensions: Default::default(),
            type_: "public-key".to_string(),
        }
    }

    fn passkey(seed: u64) -> aqua_auth::SoftPasskey {
        aqua_auth::SoftPasskey::new_seeded(seed, UNIFIED_TEST_RP)
    }

    fn hint_of(did: &str) -> aqua_auth::DidHint {
        aqua_auth::DidHint::parse(did).expect("a did:key hint")
    }

    /// Start a unified login for a fresh session; returns the session id and challenge.
    async fn unified_start(
        dispatch: &RpDispatch,
        redis: &RedisClient,
        tag: &str,
        signup_hint_spki: Option<&str>,
    ) -> (String, Vec<u8>) {
        let sid = format!("{tag}{}", Uuid::new_v4().simple());
        let rcr =
            authenticate_start_with_hint(dispatch, redis, &sid, None, false, signup_hint_spki)
                .await
                .expect("start");
        (sid, rcr.public_key.challenge.to_vec())
    }

    fn assertion_by(
        pk: &aqua_auth::SoftPasskey,
        challenge: &[u8],
        tweak: impl FnOnce(&mut aqua_auth::AssertOpts<'_>),
    ) -> PublicKeyCredential {
        let mut opts = aqua_auth::AssertOpts::new(challenge, UNIFIED_TEST_ORIGIN);
        tweak(&mut opts);
        pkc_of(&pk.assert(&opts))
    }

    fn done_did(step: LoginStep) -> String {
        match step {
            LoginStep::Done { resp, principal } => {
                assert!(principal.is_some(), "a unified login is labelled as such");
                resp.did
            }
            LoginStep::NeedSecondAssertion(_) => panic!("expected a login, got a second prompt"),
        }
    }

    #[tokio::test]
    async fn unified_assertion_with_a_matching_hint_logs_in_as_the_key_did_without_any_store_read()
    {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(11);
        // Nothing is registered for this credential id: a stored-blob lookup
        // would end in UnknownCredential.
        let (sid, ch) = unified_start(&dispatch, &redis, "u1", None).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let hints = [hint_of(&pk.did())];
        let step = verify_credential_step(&redis, &sid, &dispatch, &cred, &hints)
            .await
            .expect("the hinted login verifies");
        assert_eq!(done_did(step), pk.did());
    }

    /// The DID a unified login yields is a P-256 `did:key:zDn...`; `sign_in` Path A
    /// refuses a DID `find_did_method` does not know, so it must be accepted and
    /// map to the `key` method (the method the server enables by default).
    #[test]
    fn a_unified_login_did_is_accepted_by_find_did_method() {
        let did = passkey(13).did();
        assert!(did.starts_with("did:key:zDn"), "{did}");
        let method = aqua_auth::find_did_method(&did).expect("did:key is a known method");
        assert_eq!(method.method_name(), "key");
    }

    #[tokio::test]
    async fn without_hint_or_known_principal_a_second_assertion_is_requested_and_the_intersection_is_the_signer(
    ) {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(12);
        let (sid, ch) = unified_start(&dispatch, &redis, "u2", None).await;
        let first = assertion_by(&pk, &ch, |_| {});
        let step = verify_credential_step(&redis, &sid, &dispatch, &first, &[])
            .await
            .expect("first assertion");
        let LoginStep::NeedSecondAssertion(rcr) = step else {
            panic!("a hintless first visit must ask for a second assertion");
        };
        let allowed: Vec<Vec<u8>> = rcr
            .public_key
            .allow_credentials
            .iter()
            .map(|c| c.id.to_vec())
            .collect();
        assert_eq!(allowed, vec![pk.credential_id.clone()]);
        let second = assertion_by(&pk, &rcr.public_key.challenge, |_| {});
        let step = verify_credential_step(&redis, &sid, &dispatch, &second, &[])
            .await
            .expect("second assertion");
        assert_eq!(done_did(step), pk.did());
    }

    #[tokio::test]
    async fn a_hint_that_is_not_a_candidate_is_never_selected() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(13);
        let other = passkey(14);
        let (sid, ch) = unified_start(&dispatch, &redis, "u3", None).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let hints = [hint_of(&other.did())];
        let step = verify_credential_step(&redis, &sid, &dispatch, &cred, &hints)
            .await
            .expect("verifies");
        assert!(
            matches!(step, LoginStep::NeedSecondAssertion(_)),
            "a foreign hint must not pick a signer"
        );
    }

    #[tokio::test]
    async fn a_signup_spki_hint_selects_the_new_key_in_one_assertion() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(15);
        let spki = URL_SAFE_NO_PAD.encode(pk.spki_der());
        let (sid, ch) = unified_start(&dispatch, &redis, "u4", Some(&spki)).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let step = verify_credential_step(&redis, &sid, &dispatch, &cred, &[])
            .await
            .expect("verifies");
        assert_eq!(done_did(step), pk.did());
        // A malformed hint is ignored, never an error.
        let (sid, ch) = unified_start(&dispatch, &redis, "u4b", Some("not-base64!!")).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let step = verify_credential_step(&redis, &sid, &dispatch, &cred, &[])
            .await
            .expect("verifies");
        assert!(matches!(step, LoginStep::NeedSecondAssertion(_)));
    }

    #[tokio::test]
    async fn unified_negative_controls() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(16);
        let hints = [hint_of(&pk.did())];
        type Tweak = fn(&mut aqua_auth::AssertOpts<'_>);
        let cases: [(&str, Tweak); 5] = [
            ("wrong origin", |o| o.origin = "https://evil.example"),
            ("user not verified", |o| o.flags = 0x01),
            ("cross origin", |o| o.cross_origin = Some(true)),
            ("mutated challenge", |o| o.challenge = &[7u8; 32]),
            ("third rp hash", |o| o.rp_id_override = Some("evil.example")),
        ];
        for (name, tweak) in cases {
            let (sid, ch) = unified_start(&dispatch, &redis, "u5", None).await;
            let cred = assertion_by(&pk, &ch, tweak);
            let got = verify_credential_step(&redis, &sid, &dispatch, &cred, &hints).await;
            assert!(got.is_err(), "{name} must be refused");
        }
    }

    #[test]
    fn unified_registration_offers_es256_resident_only_and_finish_is_gone() {
        let dispatch = two_rp_dispatch();
        let options = unified_registration_options(&dispatch, Some("alice"))
            .expect("options")
            .expect("the unified RP is configured");
        let pk = &options["publicKey"];
        assert_eq!(pk["rp"]["id"], UNIFIED_TEST_RP);
        let algs: Vec<i64> = pk["pubKeyCredParams"]
            .as_array()
            .expect("params")
            .iter()
            .map(|p| p["alg"].as_i64().expect("alg"))
            .collect();
        assert_eq!(algs, vec![-7], "ES256 only");
        assert_eq!(pk["authenticatorSelection"]["residentKey"], "required");
    }

    #[tokio::test]
    async fn the_did_hint_cookie_is_set_only_after_a_verified_unified_login() {
        let Some(redis) = siwx_oidc::test_support::redis().await else {
            return;
        };
        let dispatch = two_rp_dispatch();
        let pk = passkey(17);
        let (sid, ch) = unified_start(&dispatch, &redis, "u7", None).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let hints = [hint_of(&pk.did())];
        let step = verify_credential_step(&redis, &sid, &dispatch, &cred, &hints)
            .await
            .expect("verifies");
        let cookie = login_hint_cookie(&dispatch, &step).expect("set after a unified login");
        assert!(cookie.starts_with("aqua_did_hint="), "{cookie}");
        assert!(cookie.contains(&pk.did()), "{cookie}");

        let legacy = LoginStep::Done {
            resp: AuthenticateFinishResponse {
                ok: true,
                did: pk.did(),
            },
            principal: None,
        };
        assert!(login_hint_cookie(&dispatch, &legacy).is_none());
        let (sid, ch) = unified_start(&dispatch, &redis, "u7b", None).await;
        let cred = assertion_by(&pk, &ch, |_| {});
        let second = verify_credential_step(&redis, &sid, &dispatch, &cred, &[])
            .await
            .expect("first assertion");
        assert!(login_hint_cookie(&dispatch, &second).is_none());
    }
}
