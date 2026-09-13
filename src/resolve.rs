//! `GET /resolve` — the DID ↔ MXID directory lookup.
//!
//! Answers the one question the rest of this server does not: *which Matrix
//! account belongs to this DID*, and *which DID does this Matrix account
//! publish*. Everything needed to answer it already exists — the localpart
//! derivation (`mxid`), the grandfathering policy (`localpart`), and the
//! published profile field (`did_assertion`) — but a consumer had no way to ask
//! without reimplementing all three, and a reimplementation is exactly how the
//! localpart bug in siwx-oidc#17 happened (a DID rebuilt from a localpart is a
//! DIFFERENT DID; 17 of 48 base58 characters differed).
//!
//! # A result is a DISCOVERY HINT and NEVER an authorization source
//!
//! This is the same rule the `io.inblock.did` profile field carries, in the
//! same words, deliberately: **authorization MUST resolve the DID from the OIDC
//! `sub` claim of a token this provider issued, or from a fresh signature by the
//! DID's own key.** A DID this endpoint reports tells you what to *look up*,
//! never what to *permit*.
//!
//! `attested: true` says exactly one thing: *the homeserver's profile field for
//! that account currently carries a DID that binds to it*. It does not prove the
//! holder controls the key now, it does not verify the assertion's signature
//! (see [`attested`](ResolveResponse::attested)), and it authorizes nothing.
//!
//! # Why this endpoint is unauthenticated, and why that is not a leak
//!
//! Nothing here is a secret, and gating it would not make anything less
//! discoverable:
//!
//! - The DID → localpart direction is a **pure function of the DID**
//!   (`mxid::localpart_for` / `legacy_localpart`, both `sha2`-only and both in
//!   the public library crate). Anyone holding a DID can compute both candidate
//!   localparts offline, without this server.
//! - The MXID → DID direction reads
//!   `GET /_matrix/client/v3/profile/{mxid}/io.inblock.did`, which Synapse
//!   serves **unauthenticated** by default (`require_auth_for_profile_requests`
//!   defaults to False, 1.159.0 `config/server.py:561`) and which **federates**
//!   via `handlers/profile.py::on_profile_query`. The live probe read it back
//!   with no `Authorization` header at all.
//! - The one thing this server adds is `exists`, which is
//!   `SynapseClient::localpart_status` — whether a localpart is taken. That is
//!   already observable without this server through the same unauthenticated,
//!   federated profile route the bullet above describes: an account that does
//!   not exist cannot answer it.
//!
//!   (This used to cite `GET /_matrix/client/v3/register/available` as "the
//!   same answer any client gets". That route does not exist on this
//!   deployment — registration is delegated via MSC3861, and the live probe
//!   answers `404 M_UNRECOGNIZED`. The conclusion survives by the profile
//!   route; the mechanism originally cited did not, and citing a mechanism
//!   that is not there is how a privacy argument quietly stops being true.)
//!
//! So authentication would buy **rate-limiting, not secrecy**, and it is not
//! implemented here: a rate limiter belongs at the reverse proxy that already
//! fronts this service (Caddy), where it can be shaped per-deployment without a
//! release. Do not add an in-process one here on the theory that it protects
//! privacy — it would protect nothing that is not already public, while making
//! the endpoint useless to the unauthenticated consumers it exists for.
//!
//! This is also why nothing beyond the four documented fields may ever be added
//! to the response. The moment it carries something a caller could not have
//! computed or fetched themselves, the paragraph above stops being true.
//!
//! # Degrade, never 500
//!
//! A deployment with no `SIWEOIDC_MATRIX_SERVER_NAME`, or no Synapse client at
//! all (standalone mode), cannot answer this question — and says so with a 503
//! naming the missing configuration, never a 500 and never a guess. See
//! [`ResolveError`].
//!
//! # Bounded, never open-ended
//!
//! Every answer arrives within [`RESOLVE_DEADLINE`], including the failures.
//! A public route whose duration is chosen by the upstream is a public route
//! whose connection count is chosen by the upstream; overrunning the deadline
//! is a 504 in the same `{"error", "message"}` envelope as every other error
//! here.

use std::time::Duration;

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::warn;

use siwx_oidc::mxid::{canonicalize, legacy_localpart, localpart_for};

use crate::localpart::resolve_identity;
use crate::synapse_client::{matrix_user_id, LocalpartStatus, SynapseClient};

/// Largest `did` this endpoint will consider, in bytes.
///
/// Chosen to be unreachable by any real DID rather than to be tight: see the
/// reasoning at the check in [`resolve`]. Far above Synapse's 255-byte user-ID
/// limit on purpose — a DID longer than that is legitimate and simply has no
/// legacy localpart.
const MAX_DID_LEN: usize = 2048;

/// Wall-clock ceiling on ONE `GET /resolve`, enforced in [`resolve`].
///
/// # Why a per-request deadline exists at all
///
/// `synapse_client::SYNAPSE_REQUEST_TIMEOUT` (8s) bounds each *call*, not the
/// request, and this endpoint makes up to four of them in sequence: the legacy
/// availability probe, the modern one, the profile-field read, and — on a
/// homeserver that demands authentication — one authenticated retry of that
/// read. Against an upstream answering in 7.5s the 2026-09-13 audit measured
/// **22.55s for a single `GET /resolve`**, with a worst case near **4 × 8s =
/// 32s**. On a public, unauthenticated route that is not a slow answer, it is a
/// free way to pin a connection per request.
///
/// # Why ten seconds
///
/// It has to sit strictly between two measured numbers, or it accomplishes
/// nothing:
///
/// - **A healthy request is milliseconds.** Against the in-process mock one
///   full `?did=` lookup — two probes plus the field read — completes in
///   ~1-3ms, and the test
///   `a_healthy_lookup_finishes_far_inside_the_deadline` pins that it stays
///   under a second. Ten seconds is three orders of magnitude of headroom, so
///   this can only fire on a genuinely sick upstream.
/// - **The worst case it is bounding is ~32s.** Ten seconds cuts that to under
///   a third, and turns an unbounded-feeling stall into one honest status code.
///
/// The lower bound is sharper than "comfortably above healthy", though: it is
/// deliberately **above `SYNAPSE_REQUEST_TIMEOUT` (8s)**, so a single slow call
/// is still reported by that call's own timeout — a 502 naming what failed —
/// rather than being cut short by this and reported as a deadline. This fires
/// only when calls CHAIN, which is the shape the finding is about. Dropping it
/// below 8s would start converting ordinary one-call upstream slowness into
/// 504s, which is a worse diagnosis, not a faster one.
///
/// A constant, not a config knob, for the same reason
/// `SYNAPSE_REQUEST_TIMEOUT` is: a timeout nobody sets is a timeout nobody
/// tunes correctly under pressure.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(10);

/// Largest `mxid` this endpoint will consider, in bytes — the Matrix spec's own
/// `MAX_USERID_LENGTH`. Anything longer cannot name an account on any
/// homeserver, so this rejects rather than asking one.
const MAX_MXID_LEN: usize = 255;

/// Query string of `GET /resolve`: **exactly one** of `did` or `mxid`.
///
/// Both or neither is a 400. There is no "resolve whatever you can find" mode
/// on purpose: the two directions answer different questions and return
/// different things in `did`/`mxid`, and a request that does not say which one
/// it wants is a caller bug worth reporting rather than guessing at.
#[derive(Debug, Default, Deserialize)]
pub struct ResolveQuery {
    /// A DID, exact case (`did:key:zDn…`, `did:pkh:eip155:1:0x…`).
    pub did: Option<String>,
    /// A fully-qualified Matrix ID, `@localpart:server_name`.
    pub mxid: Option<String>,
}

/// The `200` body. Four fields, and it stays four fields — see the module doc's
/// note on why nothing may be added.
///
/// Every key is always present, `null` where unknown; none of them is
/// `skip_serializing_if`. A stable shape is worth more to a consumer than a
/// compact one: switching on key presence and switching on `null` are different
/// code paths, and a field that sometimes vanishes forces callers to write both.
/// (The `io.inblock.did` field and the `io.inblock.mxid` claim make the opposite
/// choice, for the opposite reason: there, the *absence* of a key is the honest
/// statement that a provider signature or a homeserver does not exist. Here,
/// `null` and `false` already carry that meaning.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResponse {
    /// The DID, **exact case, never normalised**.
    ///
    /// On the `?did=` path this echoes the caller's input — except when the
    /// account's published field carries the same DID, in which case the
    /// *published* spelling wins, because that is the copy this provider wrote
    /// and the one a consumer will compare against.
    ///
    /// On the `?mxid=` path it is whatever the account publishes, or `null`.
    pub did: Option<String>,
    /// The fully-qualified Matrix ID, `@localpart:server_name`.
    ///
    /// On the `?did=` path this is the localpart
    /// [`crate::localpart::resolve_identity`] resolved — which honours the
    /// grandfathering rule, so a pre-2026-09 account gets its legacy shape, not
    /// the shape a naive `localpart_for(did)` would compute.
    pub mxid: Option<String>,
    /// Whether an account exists on this homeserver for that identity.
    ///
    /// `false` on the `?did=` path means neither the legacy nor the modern
    /// localpart is taken — the DID has never signed in here. It is NOT a
    /// statement about any other homeserver.
    pub exists: bool,
    /// Whether the account's `io.inblock.did` profile field is present AND binds
    /// to this identity.
    ///
    /// **What this does not mean.** No signature is verified. The published
    /// object's `proof` (a compact ES256 JWS) is not checked here, because the
    /// verifier lives in `siwx-oidc-auth`, which is a **dev-dependency only** so
    /// the shipped binary links none of it (`CLAUDE.md`, "Verifying a published
    /// DID"). A caller who needs cryptographic assurance runs
    /// `siwx-oidc-auth --verify-did`, which also re-checks the `mxid` binding
    /// and the issuer. A deployment with an ephemeral signing key publishes a
    /// DID with no `proof` at all, and that account still reports
    /// `attested: true` here — truthfully, because what this flag reports is
    /// what the field says.
    ///
    /// The comparison is method-aware ([`siwx_oidc::mxid::canonicalize`]):
    /// `did:pkh` is case-folded (its case is an EIP-55 checksum), `did:key` is
    /// compared byte-for-byte (its case is key material).
    pub attested: bool,
}

/// Everything `GET /resolve` can answer other than a 200.
///
/// # Why this is not [`crate::oidc::CustomError`]
///
/// `CustomError` has no shape for "this deployment cannot answer" or "the
/// homeserver did not answer": its only non-4xx variant is `Other`, which
/// renders as a **500**. Both of the conditions below are things this endpoint
/// must specifically NOT report as a 500 — one is deployment configuration, the
/// other is an upstream failure — so borrowing that type would mean choosing
/// between a 500 and blaming the caller with a 400.
#[derive(Debug)]
pub enum ResolveError {
    /// The request is wrong, and the caller can fix it: zero or two selectors, a
    /// malformed mxid, or an mxid for a different homeserver. `400`.
    BadRequest(String),
    /// This deployment cannot answer the question at all — no Matrix server name
    /// configured, or no Synapse client (standalone mode). `503`, because
    /// nothing about the request is wrong and a differently-configured
    /// deployment would answer it.
    Unavailable(String),
    /// The homeserver could not be asked, or gave an answer that could not be
    /// read. `502`: the state is UNKNOWN, and reporting a guess as fact is the
    /// one thing this endpoint must never do.
    Upstream {
        /// The mxid already resolved before the failure, when there is one. A
        /// DID → MXID lookup that gets as far as reading the profile field has
        /// a fully resolved, trustworthy mxid in hand; returning it inside the
        /// error is strictly more useful than discarding it, and it is not a
        /// partial 200 pretending to be complete.
        mxid: Option<String>,
        message: String,
    },
    /// The whole request outran [`RESOLVE_DEADLINE`]. `504`.
    ///
    /// **Not a 502 and certainly not a 500.** A 502 says the homeserver gave a
    /// bad answer; here it gave *no* answer in time, and the difference is the
    /// one an operator needs — a 504 on this route means the chain of Synapse
    /// calls is slow, not that any one of them failed. A 500 would claim the
    /// bug is ours, and this route's contract is that it never emits one.
    ///
    /// Rendered as a `ResolveError` rather than by a `tower` `TimeoutLayer`
    /// on purpose: a layer answers with an EMPTY body, which breaks the
    /// `{"error", "message"}` envelope `docs/api/openapi.yaml` declares
    /// required and `tests/e2e_resolve_http.rs` pins on every other error.
    /// (`tower-http` is also built here without its `timeout` feature.)
    Deadline(Duration),
}

impl IntoResponse for ResolveError {
    fn into_response(self) -> Response {
        // This module bypasses `CustomError`, so it logs its own errors — see
        // CLAUDE.md's logging conventions ("modules that bypass CustomError must
        // log their own errors").
        let (status, code, message, mxid) = match self {
            ResolveError::BadRequest(m) => {
                warn!(error = %m, "resolve: bad_request");
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "invalid_request",
                    m,
                    None,
                )
            }
            ResolveError::Unavailable(m) => {
                warn!(error = %m, "resolve: unavailable");
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    m,
                    None,
                )
            }
            ResolveError::Upstream { mxid, message } => {
                warn!(error = %message, "resolve: upstream_error");
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    message,
                    mxid,
                )
            }
            ResolveError::Deadline(waited) => {
                warn!(deadline = ?waited, "resolve: deadline_exceeded");
                (
                    axum::http::StatusCode::GATEWAY_TIMEOUT,
                    "upstream_timeout",
                    format!(
                        "The homeserver did not finish answering within {}s, so this lookup was \
                         abandoned. Nothing is known about this identity — retry, and check the \
                         homeserver's health.",
                        waited.as_secs_f32()
                    ),
                    None,
                )
            }
        };
        let mut body = serde_json::json!({ "error": code, "message": message });
        if let Some(mxid) = mxid {
            body["mxid"] = serde_json::Value::String(mxid);
        }
        (status, Json(body)).into_response()
    }
}

/// Message for a deployment that has no Matrix server name configured.
const NO_SERVER_NAME: &str =
    "This deployment cannot resolve Matrix identities: SIWEOIDC_MATRIX_SERVER_NAME is not set.";
/// Message for a deployment running without a Synapse client (standalone mode).
const NO_SYNAPSE: &str =
    "This deployment cannot resolve Matrix identities: no Synapse homeserver is configured.";

/// Resolve a DID to its Matrix account, or a Matrix account to its published
/// DID.
///
/// # What it does to the homeserver
///
/// It answers from reads: up to two `is_localpart_available` probes and one
/// `GET …/profile/{mxid}/io.inblock.did`. It creates no account, writes no
/// profile, stores no session, and issues the caller nothing.
///
/// One honest caveat, because the previous wording here ("never provisions,
/// never writes, and never mints anything") was measured FALSE and is audit
/// finding F4: on a homeserver that sets `require_auth_for_profile_requests`,
/// the profile read is refused anonymously and
/// [`SynapseClient::read_did_field`] retries it with a minted admin token —
/// and minting provisions the admin service user if its row is missing and
/// writes a token to Redis. That is a side effect on the PROVIDER's own
/// service account, never on the identity being looked up, it happens once per
/// token TTL rather than once per request, and on a stock homeserver (the
/// default, `require_auth_for_profile_requests: false`) it does not happen at
/// all. Nothing here ever touches the queried account.
///
/// # It is bounded
///
/// The whole lookup runs under [`RESOLVE_DEADLINE`]; overrunning it is a 504,
/// not a partial answer. See that constant for why per-call timeouts were not
/// enough.
pub async fn resolve(
    config: &crate::config::Config,
    synapse: Option<&SynapseClient>,
    query: ResolveQuery,
) -> Result<ResolveResponse, ResolveError> {
    resolve_within(config, synapse, query, RESOLVE_DEADLINE).await
}

/// [`resolve`] with the deadline passed in.
///
/// Exists so the timeout can be TESTED. The alternative — a test that waits out
/// the shipped ten seconds — is the kind of test that gets `#[ignore]`d within
/// a month and then guards nothing, and the alternative to that (trusting the
/// constant) is what finding F5 was.
///
/// The deadline wraps the ENTIRE body, validation included. Validation is
/// microseconds and could not plausibly overrun, but excluding it would mean
/// two code paths where one will do, and the cheap one is not the one worth
/// optimising.
async fn resolve_within(
    config: &crate::config::Config,
    synapse: Option<&SynapseClient>,
    query: ResolveQuery,
    deadline: Duration,
) -> Result<ResolveResponse, ResolveError> {
    match tokio::time::timeout(deadline, resolve_uncapped(config, synapse, query)).await {
        Ok(answer) => answer,
        // The in-flight Synapse request is dropped with the future, which
        // closes the connection — the point of bounding the request rather
        // than only answering the caller quickly.
        Err(_elapsed) => Err(ResolveError::Deadline(deadline)),
    }
}

/// The lookup itself, with no bound of its own.
///
/// Private, and called from exactly one place ([`resolve_within`]). Anything
/// that calls this directly is an unbounded public route again.
async fn resolve_uncapped(
    config: &crate::config::Config,
    synapse: Option<&SynapseClient>,
    query: ResolveQuery,
) -> Result<ResolveResponse, ResolveError> {
    // The query is validated BEFORE the deployment is. A malformed request is
    // malformed on every deployment, and a caller who fixes it then gets the
    // honest "this deployment cannot answer" — whereas the other order would
    // tell someone with a two-selector query to go reconfigure a server.
    //
    // An empty value (`?did=`) is treated as absent rather than as an empty DID:
    // it is what a client emits when it forgot to fill the parameter in, and
    // "exactly one selector" is the more useful diagnosis than "that is not a
    // DID".
    let did = query
        .did
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mxid = query
        .mxid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    // Bound the inputs before anything is done with them.
    //
    // This is input validation, NOT the in-process rate limiter the module doc
    // refuses — that refusal stands, and the edge is still where request RATE
    // belongs. What is bounded here is the size of a SINGLE request, which the
    // edge should not have to know the semantics of.
    //
    // Both values are reflected in the response and both become outbound query
    // parameters to Synapse, so without a cap an unauthenticated caller chooses
    // how much work and how much response body one request costs. The HTTP
    // layer does not do it for us: a 20 000-character `did` was answered with a
    // 200 that echoed the whole thing back (`e2e_resolve_http`'s hostile
    // corpus).
    //
    // The limits are deliberately far above anything real, because rejecting a
    // legitimate DID is the worse failure:
    //
    // - A DID has no length limit in the W3C syntax. `did:pkh` and `did:key`
    //   sit near 60 characters; a `did:peer:2` carrying service endpoints is the
    //   only common shape that runs long, and even a pathological one stays
    //   under 2 KiB. Note the cap MUST stay well above Synapse's 255-character
    //   user-ID limit: a DID longer than that is perfectly legitimate — it
    //   simply cannot have a LEGACY localpart, which is exactly the case
    //   `localpart::resolve_identity` now falls through to the modern shape for.
    // - An MXID is bounded by the Matrix spec itself at 255 bytes
    //   (`MAX_USERID_LENGTH`), so anything longer cannot name a real account on
    //   any homeserver. Rejecting it here costs the caller nothing and saves a
    //   round trip that could only ever come back `M_INVALID_USERNAME`.
    if let Some(did) = did {
        if did.len() > MAX_DID_LEN {
            return Err(ResolveError::BadRequest(format!(
                "`did` is {} bytes; the maximum accepted here is {MAX_DID_LEN}.",
                did.len()
            )));
        }
    }
    if let Some(mxid) = mxid {
        if mxid.len() > MAX_MXID_LEN {
            return Err(ResolveError::BadRequest(format!(
                "`mxid` is {} bytes; a Matrix user ID cannot exceed {MAX_MXID_LEN} \
                 (Synapse `MAX_USERID_LENGTH`), so no account can have this ID.",
                mxid.len()
            )));
        }
    }

    let selector = match (did, mxid) {
        (Some(did), None) => Selector::Did(did),
        (None, Some(mxid)) => Selector::Mxid(mxid),
        (Some(_), Some(_)) => {
            return Err(ResolveError::BadRequest(
                "Pass exactly one of `did` or `mxid`, not both: they are two different \
                 questions and the answer's `did`/`mxid` fields mean different things in \
                 each direction."
                    .to_string(),
            ))
        }
        (None, None) => {
            return Err(ResolveError::BadRequest(
                "Pass exactly one of `did=<did>` or `mxid=@localpart:server`.".to_string(),
            ))
        }
    };

    let server_name = config
        .matrix_server_name
        .as_deref()
        .ok_or_else(|| ResolveError::Unavailable(NO_SERVER_NAME.to_string()))?;
    let synapse = synapse.ok_or_else(|| ResolveError::Unavailable(NO_SYNAPSE.to_string()))?;

    match selector {
        Selector::Did(did) => resolve_did(did, server_name, synapse).await,
        Selector::Mxid(mxid) => resolve_mxid(mxid, server_name, synapse).await,
    }
}

/// Which of the two questions was asked. Exists so the "exactly one" check
/// happens once, in one place, and cannot be re-derived (differently) further
/// down.
enum Selector<'a> {
    Did(&'a str),
    Mxid(&'a str),
}

/// `?did=` — DID to Matrix account.
async fn resolve_did(
    did: &str,
    server_name: &str,
    synapse: &SynapseClient,
) -> Result<ResolveResponse, ResolveError> {
    // FALLIBLE `resolve_identity`, never `resolve_identity_or_legacy`. The
    // fail-safe "when the probe fails, guess the legacy shape" rule exists to
    // avoid SEVERING an existing user from their account on a sign-in that has
    // to produce some localpart or fail the login — guessing legacy yields a
    // working (if badly-shaped) account, while guessing modern loses the user's
    // rooms and keys forever with no rename API to undo it.
    //
    // None of that applies to a read-only lookup. There is no account to sever,
    // nothing is provisioned, and the caller is asking us *which* account this
    // is — so a wrong answer is strictly worse than an honest error. A guessed
    // legacy mxid returned here would be indistinguishable, to the caller, from
    // a resolved one, and they would go on to address a Matrix account that may
    // not be this user's. Propagate; do not guess.
    let resolved =
        resolve_identity(did, Some(synapse))
            .await
            .map_err(|e| ResolveError::Upstream {
                mxid: None,
                message: format!(
                    "could not ask the homeserver which account belongs to this DID: {e}"
                ),
            })?;

    let mxid = matrix_user_id(&resolved.localpart, server_name);
    if resolved.is_new {
        // No account exists under either shape, so there is nothing to read a
        // profile field from. Skipping the probe is not an optimisation for its
        // own sake: `read_did_field` on an unknown user answers 404, which is
        // the same 404 as "field unset", and the request would buy nothing.
        return Ok(ResolveResponse {
            did: Some(did.to_string()),
            mxid: Some(mxid),
            exists: false,
            attested: false,
        });
    }

    let published = synapse
        .read_did_field(&resolved.localpart, server_name)
        .await
        .map_err(|e| ResolveError::Upstream {
            // The mxid IS resolved at this point; only the attestation is
            // unknown. Hand it back rather than throwing it away.
            mxid: Some(mxid.clone()),
            message: format!("could not read the published DID of {mxid}: {e}"),
        })?;

    let attested = published
        .as_deref()
        .is_some_and(|p| canonicalize(p) == canonicalize(did));

    Ok(ResolveResponse {
        // When the account publishes this same DID, report the PUBLISHED
        // spelling: that is the copy this provider wrote, the copy a consumer
        // fetches from the homeserver, and the copy an assertion is signed over.
        // Echoing the caller's spelling instead would mean a `did:pkh` queried
        // in one case comes back in that case, and a byte-for-byte comparison
        // against the published value would then fail for no reason.
        did: Some(match published {
            // `attested` is derived from `published` three lines up, so the
            // Some-arm is the only reachable one when it is true. Matched rather
            // than `expect`-ed anyway: this is an unauthenticated endpoint, and
            // a panic here would be a 500 on a route whose whole contract is
            // that it never emits one. A later edit that breaks the local
            // invariant should degrade, not crash.
            Some(published) if attested => published,
            _ => did.to_string(),
        }),
        mxid: Some(mxid),
        exists: true,
        attested,
    })
}

/// `?mxid=` — Matrix account to published DID.
async fn resolve_mxid(
    mxid: &str,
    server_name: &str,
    synapse: &SynapseClient,
) -> Result<ResolveResponse, ResolveError> {
    let (localpart, server) = split_mxid(mxid)?;

    // We can only answer for our OWN homeserver: `exists` comes from this
    // server's user table and the profile read goes to this server. Answering
    // for a foreign server would mean federating the question, which this
    // endpoint deliberately does not do — a consumer that wants a foreign user's
    // DID reads that homeserver's profile route directly (it is unauthenticated
    // and federated), and verifies it against THAT server's issuer.
    if server != server_name {
        return Err(ResolveError::BadRequest(format!(
            "`{mxid}` belongs to the homeserver `{server}`, and this provider can only \
             answer for `{server_name}`. Read a foreign user's DID from their own \
             homeserver's profile route."
        )));
    }

    // `localpart_status`, not the two-valued `is_localpart_available` wrapper.
    //
    // Every OTHER caller hands Synapse a *derived* localpart; this one hands it
    // whatever the caller typed. So this is the one place where "Synapse refuses
    // this localpart outright" is a routine, expected answer rather than an
    // anomaly — and it is a property of the REQUEST, not a failure of the
    // upstream. Reporting it as a 502 would blame the homeserver for a caller's
    // typo, and reporting it as `exists: false` would quietly claim we checked
    // something we could not check. It is a 400.
    let exists =
        match synapse
            .localpart_status(localpart)
            .await
            .map_err(|e| ResolveError::Upstream {
                mxid: Some(mxid.to_string()),
                message: format!("could not ask the homeserver whether {mxid} exists: {e}"),
            })? {
            LocalpartStatus::InUse => true,
            LocalpartStatus::Available => false,
            LocalpartStatus::Unusable { errcode, message } => {
                return Err(ResolveError::BadRequest(format!(
                    "`{mxid}` is not a localpart this homeserver will accept ({errcode}: \
                 {message}), so no account can exist under it."
                )))
            }
        };

    if !exists {
        return Ok(ResolveResponse {
            did: None,
            mxid: Some(mxid.to_string()),
            exists: false,
            attested: false,
        });
    }

    let published = synapse
        .read_did_field(localpart, server_name)
        .await
        .map_err(|e| ResolveError::Upstream {
            mxid: Some(mxid.to_string()),
            message: format!("could not read the published DID of {mxid}: {e}"),
        })?;

    // The binding check, in this direction, is whether the published DID
    // actually DERIVES to this localpart. It is the same property the shipped
    // verifier enforces with the assertion's `mxid` claim, and it exists for the
    // same reason: without it, a value someone copied into their own profile —
    // possible on any homeserver that has not deployed the MSC4133 denylist —
    // would read as this account's DID.
    //
    // Both derivations are accepted because both are legitimate: a grandfathered
    // account keeps its legacy localpart forever (`localpart::resolve_identity`
    // rule 2), so requiring the modern shape would report every pre-2026-09
    // account as unattested.
    let attested = published
        .as_deref()
        .is_some_and(|did| binds_to_localpart(did, localpart));

    Ok(ResolveResponse {
        // Reported even when it does not bind: the caller asked what this
        // account publishes, the value is world-readable anyway, and `attested:
        // false` is the flag that says "do not treat this as this user's DID".
        did: published,
        mxid: Some(mxid.to_string()),
        exists: true,
        attested,
    })
}

/// Split `@localpart:server` into its two halves.
///
/// The server half is everything after the **first** colon, so a server name
/// carrying an explicit port (`@alice:example.com:8448`, which Matrix permits)
/// stays intact instead of being truncated at the port separator.
fn split_mxid(mxid: &str) -> Result<(&str, &str), ResolveError> {
    let rest = mxid.strip_prefix('@').ok_or_else(|| {
        ResolveError::BadRequest(format!(
            "`{mxid}` is not a Matrix ID: it must start with `@` and look like \
             `@localpart:server`."
        ))
    })?;
    let (localpart, server) = rest.split_once(':').ok_or_else(|| {
        ResolveError::BadRequest(format!(
            "`{mxid}` is not a Matrix ID: it must contain a `:` separating the localpart \
             from the server name."
        ))
    })?;
    if localpart.is_empty() || server.is_empty() {
        return Err(ResolveError::BadRequest(format!(
            "`{mxid}` is not a Matrix ID: both the localpart and the server name must be \
             non-empty."
        )));
    }
    // A deliberately narrow syntactic guard, NOT the Matrix localpart grammar.
    //
    // This USED TO BE the only thing standing between a caller-supplied
    // localpart and a fabricated account: `is_localpart_available` mapped ANY
    // 4xx to "taken", so a localpart Synapse refuses as `M_INVALID_USERNAME`
    // came back as an existing account. That is fixed at the source — the probe
    // now returns `LocalpartStatus::Unusable` and the call site above turns it
    // into a 400 — so this guard is no longer load-bearing for correctness. It
    // is kept as a cheap pre-filter that answers the obviously-impossible cases
    // without spending a homeserver round trip on them.
    //
    // It stays narrow for the original reason: the historical grammar is
    // permissive enough (old accounts carry uppercase and other now-deprecated
    // characters) that enforcing the modern spec here would make real accounts
    // unresolvable. So it rejects only what cannot be a Matrix localpart under
    // any reading — whitespace, control characters and non-ASCII — and leaves
    // every remaining judgement to Synapse, which is the authority on it.
    if !localpart.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ResolveError::BadRequest(format!(
            "`{mxid}` is not a Matrix ID: the localpart contains whitespace, control \
             characters or non-ASCII."
        )));
    }
    Ok((localpart, server))
}

/// Whether `did` derives to `localpart` under either localpart scheme.
///
/// Kept as its own function so the "both schemes are legitimate" rule has one
/// home; see the call site in [`resolve_mxid`] for why.
fn binds_to_localpart(did: &str, localpart: &str) -> bool {
    localpart_for(did) == localpart || legacy_localpart(did) == localpart
}

/// Tests for `GET /resolve`.
///
/// # The mock
///
/// Reuses `localpart.rs`'s `spawn_mock_synapse` harness (in-process axum on an
/// ephemeral port, built only from crates already in `[dependencies]`) through
/// its profile-field-aware constructor, rather than standing up a second mock
/// Synapse in this file — two mocks of one homeserver drift, and the drift shows
/// up as a test that passes against a server that does not exist.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::localpart::resolve_identity_tests::{
        spawn_mock_synapse_configured, spawn_mock_synapse_with_did_fields,
    };
    use crate::synapse_client::SynapseClient;
    use std::collections::{HashMap, HashSet};

    /// Mixed case ON PURPOSE: a `did:key` payload is case-sensitive, so a test
    /// using an all-lowercase DID could not tell "exact case preserved" apart
    /// from "lowercased and happened to match".
    const DID: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    /// A second, unrelated identity — the "somebody else's DID" in the
    /// replay-shaped test.
    const OTHER_DID: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
    const SERVER_NAME: &str = "inblock.io";

    fn config(server_name: Option<&str>) -> Config {
        Config {
            matrix_server_name: server_name.map(str::to_string),
            ..Config::default()
        }
    }

    fn query(did: Option<&str>, mxid: Option<&str>) -> ResolveQuery {
        ResolveQuery {
            did: did.map(str::to_string),
            mxid: mxid.map(str::to_string),
        }
    }

    /// The `{did, proof}` object as it is actually stored. The proof is a
    /// placeholder: nothing in this endpoint reads it, and a test carrying a
    /// real JWS would imply otherwise.
    fn published(did: &str) -> serde_json::Value {
        serde_json::json!({ "did": did, "proof": "eyJhbGciOiJFUzI1NiJ9.e30.sig" })
    }

    fn status_of(err: ResolveError) -> axum::http::StatusCode {
        err.into_response().status()
    }

    // -- ?did= ------------------------------------------------------------

    /// The headline case: a returning account, with its DID published. The mxid
    /// must be the one `resolve_identity` resolved, and the DID must come back
    /// in the PUBLISHED spelling.
    #[tokio::test]
    async fn did_resolves_to_the_mxid_and_reports_the_published_did() {
        let localpart = localpart_for(DID);
        let (synapse, handle) = spawn_mock_synapse_with_did_fields(
            HashSet::from([localpart.clone()]),
            HashMap::from([(format!("@{localpart}:{SERVER_NAME}"), published(DID))]),
        )
        .await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert_eq!(
            out.mxid.as_deref(),
            Some(format!("@{localpart}:{SERVER_NAME}").as_str())
        );
        assert_eq!(
            out.did.as_deref(),
            Some(DID),
            "exact case, never normalised"
        );
        assert!(out.exists);
        assert!(out.attested, "the published field carries exactly this DID");
        handle.abort();
    }

    /// A grandfathered account keeps its legacy localpart, and `/resolve` must
    /// report THAT — reporting `localpart_for(did)` would send a caller to an
    /// account the user does not have. This is the failure `resolve_identity`
    /// exists to prevent, observed through the endpoint.
    #[tokio::test]
    async fn a_grandfathered_account_resolves_to_its_legacy_mxid() {
        let legacy = legacy_localpart(DID);
        let (synapse, handle) =
            spawn_mock_synapse_with_did_fields(HashSet::from([legacy.clone()]), HashMap::new())
                .await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert_eq!(
            out.mxid.as_deref(),
            Some(format!("@{legacy}:{SERVER_NAME}").as_str())
        );
        assert_ne!(
            out.mxid.as_deref(),
            Some(format!("@{}:{SERVER_NAME}", localpart_for(DID)).as_str()),
            "a pre-2026-09 account must NOT be reported under the modern shape"
        );
        assert!(out.exists);
        assert!(!out.attested, "this account publishes nothing");
        handle.abort();
    }

    /// A DID that has never signed in here: `exists: false`, and the `did` echoes
    /// the caller's input because there is no published copy to prefer.
    #[tokio::test]
    async fn an_unknown_did_reports_that_no_account_exists() {
        let (synapse, handle) =
            spawn_mock_synapse_with_did_fields(HashSet::new(), HashMap::new()).await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert!(!out.exists);
        assert!(!out.attested);
        assert_eq!(out.did.as_deref(), Some(DID));
        assert_eq!(
            out.mxid.as_deref(),
            Some(format!("@{}:{SERVER_NAME}", localpart_for(DID)).as_str()),
            "the mxid a new identity WOULD get is still worth reporting"
        );
        handle.abort();
    }

    /// An account publishing somebody else's DID is not attested — and the
    /// endpoint still says which DID it found, because the value is
    /// world-readable anyway and hiding it would only make the flag harder to
    /// act on.
    #[tokio::test]
    async fn an_account_publishing_another_identitys_did_is_not_attested() {
        let localpart = localpart_for(DID);
        let (synapse, handle) = spawn_mock_synapse_with_did_fields(
            HashSet::from([localpart.clone()]),
            HashMap::from([(format!("@{localpart}:{SERVER_NAME}"), published(OTHER_DID))]),
        )
        .await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert!(out.exists);
        assert!(
            !out.attested,
            "the field carries a DIFFERENT DID; attested must not be a \
             'the field exists' flag"
        );
        assert_eq!(
            out.did.as_deref(),
            Some(DID),
            "an unattested answer echoes the queried DID, never the foreign one, so a \
             caller cannot mistake the published value for a resolved identity"
        );
        handle.abort();
    }

    // -- ?mxid= -----------------------------------------------------------

    #[tokio::test]
    async fn mxid_resolves_to_the_published_did() {
        let localpart = localpart_for(DID);
        let mxid = format!("@{localpart}:{SERVER_NAME}");
        let (synapse, handle) = spawn_mock_synapse_with_did_fields(
            HashSet::from([localpart.clone()]),
            HashMap::from([(mxid.clone(), published(DID))]),
        )
        .await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some(&mxid)),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert_eq!(
            out.did.as_deref(),
            Some(DID),
            "exact case, never normalised"
        );
        assert_eq!(out.mxid.as_deref(), Some(mxid.as_str()));
        assert!(out.exists);
        assert!(
            out.attested,
            "the published DID derives to this very localpart"
        );
        handle.abort();
    }

    /// The replay case, from the MXID side: a valid-looking published DID that
    /// belongs to a different account must not be reported as attested.
    #[tokio::test]
    async fn a_did_copied_from_another_account_does_not_bind() {
        let localpart = localpart_for(DID);
        let mxid = format!("@{localpart}:{SERVER_NAME}");
        let (synapse, handle) = spawn_mock_synapse_with_did_fields(
            HashSet::from([localpart.clone()]),
            HashMap::from([(mxid.clone(), published(OTHER_DID))]),
        )
        .await;

        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some(&mxid)),
        )
        .await
        .expect("a reachable homeserver must answer");

        assert_eq!(
            out.did.as_deref(),
            Some(OTHER_DID),
            "what is published is reported…"
        );
        assert!(
            !out.attested,
            "…but it does not derive to this localpart, so it is not this account's DID"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn an_mxid_for_another_homeserver_is_rejected() {
        let (synapse, handle) =
            spawn_mock_synapse_with_did_fields(HashSet::new(), HashMap::new()).await;

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some("@alice:matrix.org")),
        )
        .await
        .expect_err("this provider cannot answer for a foreign homeserver");

        let ResolveError::BadRequest(ref msg) = err else {
            panic!("expected a BadRequest, got {err:?}");
        };
        assert!(
            msg.contains("matrix.org") && msg.contains(SERVER_NAME),
            "the message must name BOTH servers so the caller can see the mismatch: {msg}"
        );
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
        handle.abort();
    }

    /// A localpart the homeserver REFUSES is a 400 — never a 502, and never a
    /// `200 {"exists": true}`.
    ///
    /// This is the `/resolve` half of the 2026-09-12 conflation defect (see
    /// `docs/audits/2026-09-12-localpart-availability-conflation.md`). The old
    /// probe mapped every 4xx to "taken", so an mxid Synapse rejects as
    /// `M_INVALID_USERNAME` — an over-length one, say — was reported as an
    /// existing account and the endpoint went on to read a profile field for a
    /// user that cannot exist.
    ///
    /// 400 rather than 502 is the deliberate part: this is the ONE call site
    /// handed a caller-supplied localpart rather than a derived one, so the
    /// refusal is a property of the request, not a failure of the upstream.
    /// Blaming the homeserver for a caller's typo would send whoever is holding
    /// the pager to the wrong system.
    #[tokio::test]
    async fn an_mxid_the_homeserver_refuses_is_a_400_never_a_502_or_a_phantom_account() {
        // A SHORT localpart that Synapse nevertheless refuses: an all-numeric
        // one is reserved for guests and answers `M_INVALID_USERNAME`
        // (`check_username`, 1.159.0). Short ON PURPOSE — an over-long localpart
        // is now caught by `MAX_MXID_LEN` before any probe, which is correct but
        // would leave this test measuring the cap instead of the errcode path it
        // exists for. ASCII-graphic, so it clears `split_mxid`'s syntactic guard
        // and actually reaches the availability probe.
        let refused = "12345";
        let mxid = format!("@{refused}:{SERVER_NAME}");

        let (synapse, handle) = spawn_mock_synapse_configured(
            crate::localpart::resolve_identity_tests::MockSynapseConfig {
                unusable: HashSet::from([refused.to_string()]),
                ..Default::default()
            },
        )
        .await;

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some(&mxid)),
        )
        .await
        .expect_err("a localpart the homeserver refuses has no account to report");

        let ResolveError::BadRequest(ref msg) = err else {
            panic!("a refused localpart is a bad REQUEST, not an upstream failure: {err:?}");
        };
        assert!(
            msg.contains("M_INVALID_USERNAME"),
            "the message must carry Synapse's own errcode so the caller can see WHY: {msg}"
        );
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
        handle.abort();
    }

    /// An oversized `did` is refused without asking the homeserver anything.
    ///
    /// The value is REFLECTED in the response and also becomes an outbound query
    /// parameter to Synapse, so without a cap an unauthenticated caller picks how
    /// much work and how much response body one request costs. Pinned against a
    /// dead port so that "before any probe" is proven by the test hanging or
    /// failing if the order ever changes, not merely asserted.
    #[tokio::test]
    async fn an_oversized_did_is_rejected_before_any_probe() {
        // TEST-NET-1 (RFC 5737): guaranteed non-routable.
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");
        let huge = format!("did:key:z{}", "x".repeat(MAX_DID_LEN));

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(&huge), None),
        )
        .await
        .expect_err("an oversized did must be refused");

        assert!(matches!(err, ResolveError::BadRequest(_)), "got {err:?}");
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    /// The cap must not reject a DID that is merely LONG but legitimate.
    ///
    /// This is the failure that would actually hurt: a `did:peer:2` carrying
    /// service endpoints runs to several hundred characters, is perfectly valid,
    /// and is exactly the shape whose LEGACY localpart exceeds Synapse's
    /// 255-byte user-ID limit — the case `localpart::resolve_identity` falls
    /// through to the modern shape for. A cap tight enough to catch it would
    /// re-break what the 2026-09-12 conflation fix repaired.
    #[tokio::test]
    async fn a_long_but_legitimate_did_is_not_rejected_by_the_cap() {
        let long_peer = format!(
            "did:peer:2.Ez6LS{}.Vz6Mk{}",
            "a".repeat(200),
            "b".repeat(200)
        );
        assert!(
            long_peer.len() > 255,
            "vector must exceed the Matrix user-ID limit"
        );

        let (synapse, handle) =
            spawn_mock_synapse_with_did_fields(HashSet::new(), HashMap::new()).await;
        let resp = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(&long_peer), None),
        )
        .await
        .expect("a long did:peer is legitimate and must resolve, not 400");

        assert!(!resp.exists, "no account exists for this DID in the mock");
        assert_eq!(
            resp.mxid.as_deref(),
            Some(format!("@{}:{SERVER_NAME}", localpart_for(&long_peer)).as_str()),
            "it must resolve to the MODERN 16-char localpart"
        );
        handle.abort();
    }

    /// An `mxid` longer than the Matrix spec's own limit cannot name an account
    /// on any homeserver, so it is refused here rather than asked about.
    #[tokio::test]
    async fn an_mxid_longer_than_the_matrix_limit_is_rejected_before_any_probe() {
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");
        let huge = format!("@{}:{SERVER_NAME}", "z".repeat(MAX_MXID_LEN));

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some(&huge)),
        )
        .await
        .expect_err("an over-long mxid must be refused");

        assert!(matches!(err, ResolveError::BadRequest(_)), "got {err:?}");
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    /// An INDETERMINATE probe answer is a 502, not the 400 that a refused
    /// localpart gets. The two look alike on the wire and mean opposite things.
    ///
    /// A `400 M_INVALID_USERNAME` is Synapse telling us this name can never hold
    /// an account — a fact about the REQUEST, so a 400 (pinned by
    /// `an_mxid_the_homeserver_refuses_is_a_400_never_a_502_or_a_phantom_account`).
    /// A proxy `404`, a `429`, or a non-JSON error body tells us nothing about
    /// the localpart at all — a fact about the UPSTREAM, so a 502.
    ///
    /// Before the 2026-09-13 errcode allowlist (see
    /// `docs/audits/2026-09-12-localpart-availability-conflation.md`) every
    /// non-`M_USER_IN_USE` 4xx became `Unusable` and this answered 400, telling
    /// the caller their mxid was malformed when in fact a proxy was in the way.
    /// Sending whoever is holding the pager to the caller instead of to the
    /// homeserver is the whole cost of conflating these.
    #[tokio::test]
    async fn an_indeterminate_probe_is_a_502_not_the_400_a_refused_localpart_gets() {
        let localpart = "someone";
        let mxid = format!("@{localpart}:{SERVER_NAME}");

        let (synapse, handle) = spawn_mock_synapse_configured(
            crate::localpart::resolve_identity_tests::MockSynapseConfig {
                // A reverse proxy in front of Synapse answering for a route it
                // does not know: a 4xx carrying no Matrix errcode at all.
                probe_faults: std::collections::HashMap::from([(
                    localpart.to_string(),
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        "<html>404 Not Found</html>".to_string(),
                    ),
                )]),
                ..Default::default()
            },
        )
        .await;

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(None, Some(&mxid)),
        )
        .await
        .expect_err("an indeterminate probe cannot answer the question");

        assert!(
            matches!(err, ResolveError::Upstream { .. }),
            "an upstream fault must not be reported as a bad request: {err:?}"
        );
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_GATEWAY);
        handle.abort();
    }

    #[tokio::test]
    async fn a_malformed_mxid_is_rejected_before_any_probe() {
        // TEST-NET-1 (RFC 5737): guaranteed non-routable. If parsing did NOT
        // happen first, this test would hang on a connect timeout instead of
        // failing — which is exactly the property being pinned.
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");
        for bad in ["alice:inblock.io", "@alice", "@:inblock.io", "@alice:"] {
            let err = resolve(
                &config(Some(SERVER_NAME)),
                Some(&synapse),
                query(None, Some(bad)),
            )
            .await
            .expect_err("{bad} is not a Matrix ID");
            assert_eq!(
                status_of(err),
                axum::http::StatusCode::BAD_REQUEST,
                "`{bad}` must be a 400"
            );
        }
    }

    // -- Selector validation ----------------------------------------------

    #[tokio::test]
    async fn both_selectors_is_a_bad_request() {
        let err = resolve(
            &config(Some(SERVER_NAME)),
            None,
            query(Some(DID), Some("@alice:inblock.io")),
        )
        .await
        .expect_err("two selectors is two questions");
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn neither_selector_is_a_bad_request() {
        let err = resolve(&config(Some(SERVER_NAME)), None, ResolveQuery::default())
            .await
            .expect_err("no selector is no question");
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    /// `?did=` with an empty value reads as "no selector", not "empty DID" —
    /// and, being a query problem, it is diagnosed even on a deployment that
    /// could not have answered anyway.
    #[tokio::test]
    async fn an_empty_selector_value_is_treated_as_absent() {
        let err = resolve(&config(Some(SERVER_NAME)), None, query(Some("   "), None))
            .await
            .expect_err("a blank did= is not a selector");
        let ResolveError::BadRequest(_) = err else {
            panic!("a blank selector must be a BadRequest, got {err:?}");
        };
    }

    // -- Deployment degradation -------------------------------------------

    /// Standalone deployment, both flavours: no Matrix server name, and no
    /// Synapse client. Neither may 500, and neither may guess.
    #[tokio::test]
    async fn a_standalone_deployment_degrades_with_503_never_500() {
        let no_server_name = resolve(&config(None), None, query(Some(DID), None))
            .await
            .expect_err("a deployment with no server_name cannot answer");
        assert_eq!(
            status_of(no_server_name),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let no_synapse = resolve(&config(Some(SERVER_NAME)), None, query(Some(DID), None))
            .await
            .expect_err("a deployment with no Synapse client cannot answer");
        let ResolveError::Unavailable(ref msg) = no_synapse else {
            panic!("expected Unavailable, got {no_synapse:?}");
        };
        assert!(
            msg.contains("Synapse"),
            "the message must name what is missing: {msg}"
        );
        assert_eq!(
            status_of(no_synapse),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// THE rule this endpoint is built around: when the homeserver cannot be
    /// asked, answer with an error — never with the legacy-shaped guess
    /// `resolve_identity_or_legacy` would have produced on a sign-in path.
    #[tokio::test]
    async fn an_unreachable_homeserver_is_a_502_never_a_guessed_mxid() {
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");

        let err = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect_err("an unreachable homeserver cannot be answered for");

        let ResolveError::Upstream { ref mxid, .. } = err else {
            panic!("a probe failure must be an Upstream error, got {err:?}");
        };
        assert!(
            mxid.is_none(),
            "nothing was resolved, so nothing may be reported — in particular not the \
             legacy localpart the sign-in path would have fallen back to"
        );
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_GATEWAY);
    }

    // -- The per-request deadline (audit finding F5) -----------------------

    /// A homeserver that accepts the connection and then never answers.
    ///
    /// Deliberately NOT a second mock Synapse — it models no route and has no
    /// wire shape to drift away from the real one (the reason the module doc
    /// above reuses `localpart.rs`'s harness for everything else). It is a
    /// socket that stays open and stays silent, which is the only upstream
    /// behaviour these two tests care about, and it is what distinguishes this
    /// from a dead port: a refused connection fails in microseconds and would
    /// prove nothing about a deadline.
    async fn spawn_black_hole() -> (SynapseClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral black-hole port");
        let addr = listener.local_addr().expect("black-hole local_addr");
        let handle = tokio::spawn(async move {
            // Accepted connections are HELD, never read from and never written
            // to. Dropping them would send a FIN and turn the stall into a
            // prompt connection error.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (
            SynapseClient::new(&format!("http://{addr}"), "secret"),
            handle,
        )
    }

    /// Render an error the way the HTTP layer will, so the envelope can be
    /// asserted on rather than assumed.
    async fn rendered(err: ResolveError) -> (axum::http::StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("an error body must be readable");
        (
            status,
            serde_json::from_slice(&bytes).expect("an error body must be JSON"),
        )
    }

    /// A homeserver that never answers produces a 504 in the documented error
    /// envelope, well before the per-call timeout could have fired.
    ///
    /// This is audit finding F5. `SYNAPSE_REQUEST_TIMEOUT` (8s) bounds each
    /// CALL, and a `?did=` lookup makes up to four in sequence, so one measured
    /// request took **22.55s** against an upstream answering in 7.5s. The
    /// deadline is injected here rather than waiting out the shipped ten
    /// seconds — a twenty-second test is a test that gets `#[ignore]`d.
    ///
    /// The envelope matters as much as the status: the obvious fix, a `tower`
    /// `TimeoutLayer`, answers with an EMPTY body and would silently break the
    /// `{"error", "message"}` contract `tests/e2e_resolve_http.rs` pins on
    /// every other error this route can produce.
    #[tokio::test]
    async fn a_homeserver_that_never_answers_becomes_a_504_in_the_documented_envelope() {
        let (synapse, handle) = spawn_black_hole().await;
        let deadline = std::time::Duration::from_millis(250);

        let started = std::time::Instant::now();
        let err = resolve_within(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
            deadline,
        )
        .await
        .expect_err("a homeserver that never answers cannot be answered for");
        let elapsed = started.elapsed();

        assert!(
            matches!(err, ResolveError::Deadline(_)),
            "a stalled upstream must be a deadline, not {err:?}"
        );
        let (status, body) = rendered(err).await;
        assert_eq!(
            status,
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            "no answer in time is a 504 — not the 502 a BAD answer gets, and never a 500"
        );
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("upstream_timeout"),
            "the envelope's `error` discriminator is required: {body}"
        );
        assert!(
            body.get("message").and_then(|v| v.as_str()).is_some(),
            "the envelope's `message` is required: {body}"
        );

        assert!(
            elapsed < std::time::Duration::from_secs(4),
            "the DEADLINE must be what fired, not the 8s per-call timeout: took {elapsed:?}"
        );
        handle.abort();
    }

    /// A healthy lookup is unaffected by the deadline, and finishes three
    /// orders of magnitude inside it.
    ///
    /// The other half of the bound: a deadline that fires on healthy traffic
    /// is an outage. This runs the SHIPPED [`RESOLVE_DEADLINE`] — not an
    /// injected one — over the full `?did=` path (two availability probes plus
    /// the profile-field read), which is also where the "a healthy request is
    /// milliseconds" number in that constant's doc comes from.
    #[tokio::test]
    async fn a_healthy_lookup_finishes_far_inside_the_deadline() {
        let localpart = localpart_for(DID);
        let (synapse, handle) = spawn_mock_synapse_with_did_fields(
            HashSet::from([localpart.clone()]),
            HashMap::from([(format!("@{localpart}:{SERVER_NAME}"), published(DID))]),
        )
        .await;

        let started = std::time::Instant::now();
        let out = resolve(
            &config(Some(SERVER_NAME)),
            Some(&synapse),
            query(Some(DID), None),
        )
        .await
        .expect("a healthy homeserver must be answered, deadline or no deadline");
        let elapsed = started.elapsed();

        assert!(out.exists && out.attested, "sanity: the lookup really ran");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "a healthy lookup must finish in a fraction of the {RESOLVE_DEADLINE:?} deadline, \
             or the deadline is not comfortably above healthy traffic: took {elapsed:?}"
        );
        eprintln!("healthy ?did= lookup: {elapsed:?} (deadline {RESOLVE_DEADLINE:?})");
        handle.abort();
    }

    // -- Pure helpers ------------------------------------------------------

    #[test]
    fn split_mxid_keeps_a_port_in_the_server_half() {
        let (localpart, server) =
            split_mxid("@alice:example.com:8448").expect("a port is legal in a server name");
        assert_eq!(localpart, "alice");
        assert_eq!(
            server, "example.com:8448",
            "splitting on the LAST colon would truncate the port"
        );
    }

    #[test]
    fn binding_accepts_both_localpart_schemes() {
        assert!(binds_to_localpart(DID, &localpart_for(DID)));
        assert!(
            binds_to_localpart(DID, &legacy_localpart(DID)),
            "a grandfathered account's legacy localpart binds just as well"
        );
        assert!(!binds_to_localpart(DID, &localpart_for(OTHER_DID)));
    }
}
