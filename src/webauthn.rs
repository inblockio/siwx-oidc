//! WebAuthn/passkey ceremony — server-layer authentication (Layer 2).
//!
//! This module handles the full WebAuthn ceremony using the `webauthn-rs` safe API.
//! It does NOT extend `DIDMethod` — see PLAN_webauthn.md for rationale.
//!
//! After successful authentication, the verified DID is stored in the Redis session.
//! `sign_in` reads it from there (server-side, trusted).

use anyhow::{anyhow, Result};
use aqua_auth::{verify_webauthn_assertion, WebAuthnAssertionParams};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{AllowCredentials, AuthenticatorSelectionCriteria, ResidentKeyRequirement};

use siwx_oidc::db::RedisClient;

// -- Redis key prefixes for WebAuthn state --

const CHALLENGE_PREFIX: &str = "webauthn:challenge";
const CREDENTIAL_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_CREDENTIAL_PREFIX;
// The same constant the library's credential-identity resolver and the backfill
// read, so a reader and this writer cannot drift onto different key spellings.
// Ownership of the namespace is unchanged: `link_finish` is still the only
// writer.
const LINK_PREFIX: &str = siwx_oidc::db::KV_WEBAUTHN_LINK_PREFIX;
const LINK_CHALLENGE_PREFIX: &str = "webauthn:link_challenge";
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
/// On our side the Redis tombstone (`DBClient::is_user_deactivated`) is a
/// bounded-TTL race guard for the refresh/mint path (S3-4 / H6), not a durable
/// authority, and nothing consulted it at sign-in. The net effect was that
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
        .set_ex_raw(
            &format!("{}/{}", CHALLENGE_PREFIX, session_id),
            &state_json,
            CHALLENGE_TTL,
        )
        .await?;

    info!("webauthn register_start: session={}", session_id);
    Ok(ccr)
}

pub async fn register_finish(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    reg_response: RegisterPublicKeyCredential,
) -> Result<RegisterFinishResponse> {
    // Retrieve and consume the registration state.
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let state_json = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No registration challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)
        .map_err(|e| anyhow!("Failed to deserialize registration state: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow!("WebAuthn registration verification failed: {:?}", e))?;

    let did = did_from_passkey(&passkey)?;
    let cred_id_b64 = URL_SAFE_NO_PAD.encode(passkey.cred_id());

    // Store the credential persistently (no TTL).
    let cred_json = serde_json::to_string(&passkey)
        .map_err(|e| anyhow!("Failed to serialize passkey: {}", e))?;
    redis
        .set_raw(
            &format!("{}/{}", CREDENTIAL_PREFIX, cred_id_b64),
            &cred_json,
        )
        .await?;

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
        did, cred_id_b64
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
pub async fn authenticate_start(
    webauthn: &Webauthn,
    redis: &RedisClient,
    session_id: &str,
    scope_did: Option<&str>,
) -> Result<RequestChallengeResponse> {
    let (mut rcr, _auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| anyhow!("WebAuthn auth start failed: {:?}", e))?;

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
                session_id,
                did,
                rcr.public_key.allow_credentials.len()
            );
        } else {
            info!(
                "webauthn authenticate_start: session={} scope did={} resolved 0 creds -> discoverable fallback",
                session_id, did
            );
        }
    }

    let challenge_b64 = URL_SAFE_NO_PAD.encode(&*rcr.public_key.challenge);
    redis
        .set_ex_raw(
            &format!("{}/{}", CHALLENGE_PREFIX, session_id),
            &challenge_b64,
            CHALLENGE_TTL,
        )
        .await?;

    info!("webauthn authenticate_start: session={}", session_id);
    Ok(rcr)
}

/// Core WebAuthn assertion verification: challenge retrieval, credential lookup,
/// cryptographic verification, counter update, and DID resolution. Shared by
/// both the OIDC login flow and the device approval flow.
pub async fn verify_credential(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: &PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let challenge_key = format!("{}/{}", CHALLENGE_PREFIX, session_id);
    let challenge_b64 = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No auth challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge_b64)
        .map_err(|e| anyhow!("Failed to decode stored challenge: {}", e))?;

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
        expected_challenge: &challenge_bytes,
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
        did, cred_id_b64
    );
    Ok(AuthenticateFinishResponse { ok: true, did })
}

/// Full authenticate-finish for the OIDC login flow: verifies the credential
/// AND stores the verified DID in the Redis session (needed by `sign_in`).
pub async fn authenticate_finish(
    redis: &RedisClient,
    session_id: &str,
    rp_id: &str,
    rp_origin: &str,
    auth_response: PublicKeyCredential,
) -> Result<AuthenticateFinishResponse, VerifyError> {
    let resp = verify_credential(redis, session_id, rp_id, rp_origin, &auth_response).await?;

    let session_key = format!("sessions/{}", session_id);
    let session_json = redis
        .get_raw(&session_key)
        .await?
        .ok_or_else(|| anyhow!("Session not found"))?;
    let mut session: siwx_oidc::db::SessionEntry = serde_json::from_str(&session_json)
        .map_err(|e| anyhow!("Failed to deserialize session: {}", e))?;
    session.verified_did = Some(resp.did.clone());
    let updated_session = serde_json::to_string(&session)
        .map_err(|e| anyhow!("Failed to serialize session: {}", e))?;
    redis
        .set_ex_raw(
            &session_key,
            &updated_session,
            siwx_oidc::db::SESSION_LIFETIME,
        )
        .await?;

    Ok(resp)
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
        .set_ex_raw(
            &format!("{}/{}", LINK_CHALLENGE_PREFIX, session_id),
            &state_json,
            CHALLENGE_TTL,
        )
        .await?;

    info!(
        "webauthn link_start: session={} primary_did={}",
        session_id, primary_did
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
    let challenge_key = format!("{}/{}", LINK_CHALLENGE_PREFIX, session_id);
    let state_json = redis
        .get_raw(&challenge_key)
        .await?
        .ok_or_else(|| anyhow!("No link challenge found (expired or already used)"))?;
    redis.del_raw(&challenge_key).await?;

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
        cred_id_b64, link_state.primary_did
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
        .ok_or_else(|| anyhow!("SIWEOIDC_BASE_URL has no host — cannot derive WebAuthn RP ID"))?
        .to_string();
    let resolved_rp_id = rp_id.unwrap_or(&default_rp_id).to_string();

    let default_origin = base_url.as_str().trim_end_matches('/').to_string();
    let resolved_rp_origin = rp_origin
        .unwrap_or(&default_origin)
        .trim_end_matches('/')
        .to_string();
    let rp_origin_url = Url::parse(&resolved_rp_origin)
        .map_err(|e| anyhow!("Invalid SIWEOIDC_RP_ORIGIN: {}", e))?;

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
    /// Redis. Requires Redis on localhost; skips cleanly when unavailable.
    #[tokio::test]
    async fn forged_user_cookie_yields_usernameless_empty_allow_credentials() {
        let redis = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
        };

        // A localhost RP is valid for WebauthnBuilder (origin must be https OR
        // localhost); this lets the test build a real Webauthn without TLS.
        let base = Url::parse("http://localhost:8000").unwrap();
        let cfg = build_webauthn(&base, None, None).expect("build webauthn");

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
        let rcr = authenticate_start(&cfg.webauthn, &redis, &session_id, scope_did.as_deref())
            .await
            .expect("authenticate_start must succeed");
        assert!(
            rcr.public_key.allow_credentials.is_empty(),
            "forged cookie -> usernameless -> allowCredentials MUST be empty (no enumeration)"
        );
    }

    /// H1/H2 (positive scoping): a VALID `siwx_user` session for DID A makes
    /// `authenticate_start` offer EXACTLY A's credential and NEVER B's. This is the
    /// other half of the forged-cookie test — it proves the scoped path is correct,
    /// not merely safe, and is the server-side twin of the browser two-credential
    /// case. Seeds the `by_did` index directly (the SMEMBERS fast path) so it needs no
    /// real attestation. Requires Redis on localhost; skips cleanly when unavailable.
    #[tokio::test]
    async fn valid_user_session_scopes_allow_credentials_to_its_did_only() {
        let redis = match RedisClient::new(&Url::parse("redis://localhost").unwrap()).await {
            Ok(c) => c,
            Err(_) => return, // no Redis: skip (CI provides one)
        };
        let base = Url::parse("http://localhost:8000").unwrap();
        let cfg = build_webauthn(&base, None, None).expect("build webauthn");

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
        let rcr = authenticate_start(&cfg.webauthn, &redis, &session_id, scope_did.as_deref())
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
}
