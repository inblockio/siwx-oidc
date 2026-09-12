//! The grandfathering policy that decides which Matrix localpart derivation a
//! given DID actually gets.
//!
//! The pure derivations themselves — [`legacy_localpart`] and
//! [`localpart_for`], both re-exported here from `siwx_oidc::mxid` — live in
//! the **library** crate (`src/mxid.rs`), because `tests/*.rs` integration
//! tests link only against the library crate and need to call them directly
//! rather than hand-copying them (a hand-copy of `localpart_for` previously
//! diverged from the real algorithm by unconditionally lowercasing every DID;
//! see `src/mxid.rs`'s module doc for the full story). This file keeps the
//! Synapse-dependent half: [`resolve_identity`] and
//! [`resolve_identity_or_legacy`], which decide, per DID, which of the two
//! pure derivations to use.
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
//! rooms, DMs and history. [`resolve_identity`] is the grandfathering policy
//! that reconciles the two: an identity that already has an account keeps
//! whichever localpart it already has (checking the legacy shape first, since
//! that is what every pre-2026-09 account is keyed on); only a genuinely new
//! identity gets the new, policy-server-safe shape. See [`resolve_identity`]'s
//! own doc for the exact rules, and the module-level note on the fail-safe
//! direction a caller must take when Synapse cannot be reached to decide.
//!
//! See `siwx_oidc::mxid`'s module doc for the method-aware canonicalisation
//! rule and the "why 80 bits of hash" rationale — both apply unchanged here,
//! just documented alongside the code that implements them.

use crate::synapse_client::LocalpartStatus;
pub(crate) use siwx_oidc::mxid::{legacy_localpart, localpart_for};
use tracing::{info, warn};

// -- Grandfathering policy ---------------------------------------------------

/// The outcome of [`resolve_identity`]: which localpart a DID should use,
/// whether using it would create a brand-new Synapse account, and — the field
/// that exists purely to stop a guess being laundered into an assertion —
/// whether the answer was actually RESOLVED or merely GUESSED.
pub(crate) struct ResolvedIdentity {
    pub localpart: String,
    /// True when signing in would CREATE a brand-new Synapse account (neither
    /// the legacy nor the modern localpart is taken).
    pub is_new: bool,
    /// True when this identity was NOT resolved but fell back — i.e.
    /// [`resolve_identity_or_legacy`] swallowed a probe error and returned
    /// [`legacy_localpart`] on the fail-safe assumption that the account
    /// predates the modern scheme. `localpart` is then a GUESS, and `is_new` is
    /// a placeholder (`false`) rather than a finding.
    ///
    /// # Why this field exists (2026-09-10 audit, D4)
    ///
    /// The fail-safe fallback is correct and is not changing — guessing legacy
    /// for a modern account yields a working (if badly-shaped) account, while
    /// guessing modern for a legacy account severs the user from their rooms
    /// and keys forever, and Synapse has no rename API. But the DID-publication
    /// feature added a way for that benign guess to become permanent damage:
    /// when the fallback fires for a user whose real account IS modern-shaped,
    /// `oidc::provision_synapse_device` re-probes, finds the legacy shape free,
    /// provisions it, and publishes a **fully valid, correctly-verifying**
    /// `{did, proof}` assertion binding that DID to the new, WRONG mxid. Two
    /// Matrix accounts then carry provider-signed assertions for one DID and no
    /// consumer can tell which is canonical — a signed lie is strictly worse
    /// than no signature, because the signature is exactly what a consumer is
    /// supposed to trust.
    ///
    /// So this flag is threaded to the publication decision and suppresses it.
    /// Publishing nothing costs one login's worth of freshness; the next
    /// healthy sign-in re-asserts (the write is idempotent and unconditional —
    /// see `provision_synapse_device`'s "why re-assert every time" note).
    ///
    /// **Not a general "degraded" flag.** It says one thing: *this localpart
    /// came from the error path.* Do not overload it with "Synapse was slow" or
    /// "the account looked odd"; a caller that widens it will start suppressing
    /// publication for healthy logins, which silently turns the whole feature
    /// off.
    pub degraded: bool,
}

/// Decide which localpart a DID should use, honouring the GRANDFATHER rule
/// (Tim, 2026-09-09): an account that already exists under [`legacy_localpart`]
/// keeps it forever, because Synapse has no user-rename API and switching it
/// would silently give the user a brand-new, empty account. Only an identity
/// with no existing account at all gets the new, policy-server-safe
/// [`localpart_for`] shape.
///
/// # Rules, in order
///
/// 1. `synapse == None` -> `{ legacy_localpart(did), is_new: false }`. No
///    Synapse means no Matrix account, so there is nothing to grandfather and
///    nothing to detect. Returning the LEGACY value here (not `localpart_for`)
///    is deliberate: a standalone deployment has no matrix.org policy-server
///    problem to begin with, and switching its `TokenMetadata.username` would
///    orphan `revoke_all_user_tokens` keying for tokens already sitting in
///    Redis. This also preserves the historical contract of the old
///    `is_new_identity` helper ("no Synapse client -> cannot detect; behave as
///    today").
/// 2. `localpart_status(legacy) == InUse` -> `{ legacy, is_new: false }` — a
///    pre-existing, grandfathered account.
/// 3. `localpart_status(legacy) == Unusable` -> **fall through to the modern
///    probe**, exactly as if the legacy shape had been free. See the section
///    below; this arm is the one that is easy to get wrong.
/// 4. Else (legacy `Available`, or fell through from `Unusable`):
///    `localpart_status(modern) == InUse` -> `{ modern, is_new: false }` —
///    already migrated, or created under the new scheme by a previous sign-in.
/// 5. `localpart_status(modern) == Available` -> `{ modern, is_new: true }` —
///    genuinely new; no account exists under either shape.
/// 6. `localpart_status(modern) == Unusable` -> `Err`, loudly. See below.
///
/// Any `Err` from a probe is propagated, not papered over: a caller that needs
/// a localpart anyway despite the error MUST fall back to [`legacy_localpart`]
/// (never [`localpart_for`]) — see [`resolve_identity_or_legacy`] and the
/// module doc's note on the fail-safe direction. In particular a **rejected MAS
/// shared secret** (401/403) is an `Err` from
/// [`crate::synapse_client::SynapseClient::localpart_status`] and never a
/// verdict, so a rotated secret cannot make every localpart on the homeserver
/// read as taken.
///
/// # Why an UNUSABLE legacy localpart falls through instead of grandfathering
///
/// `Unusable` means Synapse **refuses** the localpart outright
/// (`M_INVALID_USERNAME`, `M_EXCLUSIVE`, …). That is the opposite of "taken":
/// no account can exist under a localpart Synapse will not allow, so there is
/// nothing to grandfather and falling through severs **nobody**. The grandfather
/// rule protects accounts that exist; this is the one case where it is
/// provably impossible for one to exist.
///
/// **The old claim here was falsified — do not reinstate it.** This doc used to
/// state that `is_localpart_available`'s any-4xx-to-`Ok(false)` mapping "cannot
/// misfire here because both `legacy_localpart` and `localpart_for` always
/// produce a syntactically valid Matrix localpart (`[a-z0-9._=/-]`)". That
/// reasoning covered the **character class** only and never considered
/// Synapse's `MAX_USERID_LENGTH` (255). Confirmed live on dev (Synapse 1.159.0):
/// a 252-character `did:peer:2` yields a 252-character legacy localpart, whose
/// user ID is 264 characters, which `check_username` refuses with
/// `M_INVALID_USERNAME` — and the old code read that refusal as "an account
/// exists here" and returned `{ localpart: legacy, is_new: false }`,
/// grandfathering an identity that had no account at all.
///
/// That was not merely a wrong lookup. `is_new` is the input to the
/// new-account gates: `webauthn::reject_if_new_identity` matches
/// `Ok(resolved) if resolved.is_new` -> reject, `Ok(_)` -> **pass**, `Err` ->
/// reject (fail closed). A wrongly-`Ok(false)` legacy probe therefore made the
/// gate **PASS** for a brand-new identity on the QR/device-approval and
/// account-re-auth paths, which are documented to hard-REJECT it.
///
/// The fix is also the proof that the opaque scheme already solved the long-DID
/// problem: [`localpart_for`] is **always** exactly 16 lowercase base36
/// characters, so it is always inside both the length and the charset limits,
/// for every DID of every length. The legacy probe's misreading was *masking*
/// that solution — the identity had a perfectly usable modern localpart waiting
/// the whole time.
///
/// # Why an UNUSABLE modern localpart is a hard `Err`
///
/// It should be unreachable: 16 characters of `[0-9a-z]` cannot violate the
/// charset rule, and cannot approach `MAX_USERID_LENGTH` for any plausible
/// server name. The one theoretical route is Synapse's guest-reserved
/// all-numeric rule — a digest whose base36 encoding happens to be 16 digits,
/// probability ≈ `(10/36)^16` ≈ 3e-9. So an `Err` here is an honest "something
/// is very wrong" (a homeserver with an appservice namespace swallowing the
/// space, a proxy answering for the route, a wildly misconfigured server name),
/// not a case to paper over with a fallback. Failing loudly also fails
/// **closed** at every new-account gate, which is the right direction for a
/// condition nobody has an explanation for.
pub(crate) async fn resolve_identity(
    did: &str,
    synapse: Option<&crate::synapse_client::SynapseClient>,
) -> anyhow::Result<ResolvedIdentity> {
    let synapse = match synapse {
        Some(s) => s,
        None => {
            return Ok(ResolvedIdentity {
                localpart: legacy_localpart(did),
                is_new: false,
                degraded: false,
            });
        }
    };

    // The THREE-valued probe, never the two-valued `is_localpart_available`
    // wrapper: telling `InUse` ("an account holds this") apart from `Unusable`
    // ("Synapse will not allow an account here") is the entire decision being
    // made, and the wrapper cannot express it — see the doc above.
    let legacy = legacy_localpart(did);
    match synapse.localpart_status(&legacy).await? {
        LocalpartStatus::InUse => {
            return Ok(ResolvedIdentity {
                localpart: legacy,
                is_new: false,
                degraded: false,
            });
        }
        // NOT an account: Synapse refuses this localpart, so no account can
        // exist under it and there is nothing to grandfather. Fall through to
        // the modern probe exactly as if it had been free — which severs
        // nobody, and hands the identity the 16-char base36 localpart that was
        // always within Synapse's limits. Reading this as "taken" is the
        // defect this match arm exists to close.
        LocalpartStatus::Unusable { errcode, message } => {
            info!(
                did = %did,
                %errcode,
                %message,
                "legacy localpart is UNUSABLE (not taken) — no account can exist under it, \
                 so there is nothing to grandfather; resolving to the modern shape"
            );
        }
        LocalpartStatus::Available => {}
    }

    let modern = localpart_for(did);
    match synapse.localpart_status(&modern).await? {
        LocalpartStatus::InUse => Ok(ResolvedIdentity {
            localpart: modern,
            is_new: false,
            degraded: false,
        }),
        LocalpartStatus::Available => Ok(ResolvedIdentity {
            localpart: modern,
            is_new: true,
            degraded: false,
        }),
        // Should be unreachable — 16 chars of [0-9a-z] break no Synapse rule.
        // Loud, not papered over: see the doc's "why an UNUSABLE modern
        // localpart is a hard Err".
        LocalpartStatus::Unusable { errcode, message } => anyhow::bail!(
            "resolve_identity: Synapse refuses the MODERN localpart `{modern}` for `{did}` \
             ({errcode}: {message}). That should be impossible — `localpart_for` is always \
             16 lowercase base36 characters — so this is a homeserver-side condition \
             (appservice namespace, misrouted route, guest-reserved all-numeric localpart), \
             not something to fall back from."
        ),
    }
}

/// [`resolve_identity`], but infallible: on any probe error, fall back to
/// `{ legacy_localpart(did), is_new: false }` instead of propagating.
///
/// # The fail-safe direction — this is the most important rule in this module
///
/// The fallback MUST be [`legacy_localpart`], never [`localpart_for`].
/// Guessing legacy for a genuinely new user only yields a suboptimally-shaped
/// MXID (still policy-server-refused, but otherwise a normal working account)
/// — recoverable. Guessing modern for an EXISTING user severs them from their
/// account and everything in it — not recoverable, because Synapse cannot
/// rename a user back onto the localpart their rooms/DMs/keys already live
/// under. When in doubt, assume the account predates this feature (the vast
/// majority do) and let the worst case be a bad-shaped brand-new account
/// rather than a lost one.
///
/// ## That justification is TIME-LIMITED — re-examine it, do not inherit it
///
/// "The vast majority of accounts predate this feature" is an empirical claim
/// about 2026-09-10, not a property of the design, and it decays monotonically:
/// every genuinely-new identity from here on is provisioned under
/// [`localpart_for`], so the modern-shaped population only grows and the
/// legacy-shaped one only shrinks. Once modern-shaped accounts are the
/// majority, "guess legacy" stops being the *likely-right* answer and is merely
/// the *less-catastrophic-when-wrong* answer — still the correct direction (the
/// asymmetry between "badly-shaped new account" and "user severed from their
/// rooms forever" does not decay), but no longer cheap.
///
/// What actually changes with the ratio is the COST of the fallback, not its
/// direction, so the thing to revisit is not this `if` but the surrounding
/// blast radius: how often the fallback fires (i.e. Synapse reachability on the
/// login path — see `synapse_client`'s timeout constants), and what is
/// suppressed while it does (see [`ResolvedIdentity::degraded`]). If a future
/// reader is weighing "should we flip the fallback to modern now that most
/// accounts are modern": no. A wrong-but-working account is recoverable by a
/// later correct sign-in; a severed account is not recoverable at all, at any
/// population ratio.
///
/// ## The fallback can produce an UNUSABLE localpart, and that is the trade
///
/// For a DID whose legacy form is over-length (the 252-character `did:peer:2`
/// case in [`resolve_identity`]'s doc), this fallback hands back a localpart
/// Synapse will **refuse** — `provision_user` then fails with
/// `M_INVALID_USERNAME` instead of quietly creating an account. That is the
/// intended outcome, not a second bug to route around: the fail-safe direction
/// above is decided by the asymmetry between "badly-shaped new account" and
/// "existing user severed from their rooms forever", and that asymmetry does
/// not change just because the bad shape is bad enough to be rejected. The
/// difference is only *where* the failure surfaces — loudly at provisioning,
/// where it can be diagnosed, rather than silently as a wrong identity. Do NOT
/// "fix" this by falling back to [`localpart_for`] when the legacy shape looks
/// too long: that is the severing guess, wearing a length check as a disguise.
/// The real fix is for Synapse to be reachable, so [`resolve_identity`] can
/// answer instead of this function guessing.
///
/// Use this only where the caller must produce SOME localpart and cannot fail
/// the whole request over a transient Synapse hiccup (sign-in provisioning,
/// device-code provisioning, and cosmetic `detected_mxid` displays — all of
/// which historically degraded gracefully rather than hard-failing on a
/// Synapse probe error). A caller that CAN afford to fail the request instead
/// of guessing (e.g. an account-management action, which requires Synapse
/// anyway) should call [`resolve_identity`] directly and propagate the error.
pub(crate) async fn resolve_identity_or_legacy(
    did: &str,
    synapse: Option<&crate::synapse_client::SynapseClient>,
) -> ResolvedIdentity {
    match resolve_identity(did, synapse).await {
        Ok(resolved) => resolved,
        Err(e) => {
            warn!(
                did = %did,
                error = %e,
                "resolve_identity failed; falling back to the legacy localpart \
                 (never the modern one — see the fail-safe direction on \
                 resolve_identity_or_legacy)"
            );
            ResolvedIdentity {
                localpart: legacy_localpart(did),
                is_new: false,
                // THE marker. Everything downstream that would write a durable,
                // externally-verifiable artifact keyed on this localpart must
                // check it and skip — see the field's own doc.
                degraded: true,
            }
        }
    }
}

/// Tests for the grandfathering policy ([`resolve_identity`] /
/// [`resolve_identity_or_legacy`]).
///
/// `resolve_identity` is `pub(crate)` inside the BINARY crate (declared only
/// in `main.rs`'s module tree), so it is invisible to the integration tests
/// under `tests/`, which link against the separate `siwx_oidc` LIBRARY crate
/// (`src/lib.rs`) and can only reach it indirectly, over HTTP, by driving a
/// live server + the `e2e/synapse_mock.py` mock — that mock is real
/// infrastructure gated behind `#[ignore]` and `e2e/up.sh`, not something
/// available to a plain `cargo test --bin siwx-oidc`. These tests instead spin
/// up a tiny in-process HTTP stand-in for the ONE Synapse endpoint
/// `resolve_identity` calls (`GET /_synapse/mas/is_localpart_available`),
/// modeling the exact 200/400 contract `e2e/synapse_mock.py` implements for
/// that endpoint. It is built entirely from crates already in
/// `[dependencies]` (axum, tokio) — no new test dependency, and no docker/live
/// stack required.
///
/// `pub(crate)` so `resolve.rs`'s tests can drive the SAME mock rather than
/// standing up a second one: two hand-written mocks of one homeserver drift,
/// and the drift surfaces as a test that passes against a server that does not
/// exist.
#[cfg(test)]
pub(crate) mod resolve_identity_tests {
    use super::*;
    use crate::synapse_client::SynapseClient;
    use axum::extract::{Query, State};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// The `io.inblock.did` profile field as this mock serves it: the value
    /// stored per **fully-qualified mxid**, because that is the key the real
    /// route is addressed by (`GET /_matrix/client/v3/profile/{mxid}/{field}`)
    /// and keying the mock by localpart instead would hide a missing or wrong
    /// server name in the URL the client builds.
    pub(crate) type DidFields = HashMap<String, serde_json::Value>;

    /// Everything this mock homeserver can be told to do, in one place.
    ///
    /// The original harness modelled only the TWO answers
    /// `is_localpart_available` used to have (200 free / 400 `M_USER_IN_USE`),
    /// which is precisely the blind spot that let the
    /// `Unusable`-read-as-`InUse` defect ship: a mock that cannot produce
    /// `M_INVALID_USERNAME` cannot fail a test about it. The extra levers below
    /// exist so the three-valued
    /// [`crate::synapse_client::LocalpartStatus`] contract — and the credential
    /// failure that must never become a verdict — are all reachable here.
    ///
    /// `pub(crate)` for the same reason [`spawn_mock_synapse_with_did_fields`]
    /// is: `crate::resolve`'s tests need the `unusable` lever to pin that a
    /// localpart the homeserver refuses becomes a 400 there, and a second copy
    /// of this mock would be a second place for the homeserver's behaviour to
    /// drift away from the real one.
    #[derive(Clone, Default)]
    pub(crate) struct MockSynapseConfig {
        /// Localparts that read as "already taken" (existing accounts):
        /// `400 M_USER_IN_USE` -> [`LocalpartStatus::InUse`].
        pub(crate) existing: HashSet<String>,
        /// Published `io.inblock.did` values, by mxid. An mxid with no entry
        /// answers 404, exactly as Synapse does for an unset custom field.
        pub(crate) did_fields: DidFields,
        /// Localparts Synapse REFUSES outright: `400 M_INVALID_USERNAME` ->
        /// [`LocalpartStatus::Unusable`]. Checked BEFORE `existing`, because a
        /// localpart Synapse will not allow cannot simultaneously be an
        /// account — putting one in both sets is a test bug, and this ordering
        /// makes the refusal win rather than silently modelling an impossible
        /// homeserver.
        pub(crate) unusable: HashSet<String>,
        /// Answer every `/_synapse/mas/*` call `403`, as Synapse's
        /// `assert_request_is_from_mas` does for a wrong or rotated shared
        /// secret. Scoped to the MAS route on purpose: the profile read is
        /// reached with an admin token, a different credential entirely.
        pub(crate) reject_secret: bool,
    }

    #[derive(Clone)]
    struct MockState {
        cfg: Arc<MockSynapseConfig>,
    }

    async fn is_localpart_available_handler(
        State(state): State<MockState>,
        Query(params): Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        // Before anything is looked up: a rejected credential says NOTHING
        // about the localpart, and Synapse never reaches `check_username`.
        if state.cfg.reject_secret {
            return (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "errcode": "M_FORBIDDEN",
                    "error": "This endpoint must only be called by MAS",
                })),
            )
                .into_response();
        }
        let localpart = params.get("localpart").cloned().unwrap_or_default();
        if state.cfg.unusable.contains(&localpart) {
            // The live dev shape: a legacy localpart from a long DID whose
            // user ID exceeds Synapse's MAX_USERID_LENGTH (255).
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "errcode": "M_INVALID_USERNAME",
                    "error": "User ID may not be longer than 255 characters",
                })),
            )
                .into_response()
        } else if state.cfg.existing.contains(&localpart) {
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

    /// `GET /_matrix/client/v3/profile/{mxid}/{field}` — MSC4133's custom
    /// profile field read. Answers `{ "<field>": <value> }` on a hit and a 404
    /// with Synapse's `M_NOT_FOUND` shape on a miss.
    async fn profile_field_handler(
        State(state): State<MockState>,
        axum::extract::Path((mxid, field)): axum::extract::Path<(String, String)>,
    ) -> axum::response::Response {
        match state.cfg.did_fields.get(&mxid) {
            Some(value) => (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ field: value })),
            )
                .into_response(),
            None => (
                axum::http::StatusCode::NOT_FOUND,
                Json(serde_json::json!({"errcode": "M_NOT_FOUND", "error": "no such field"})),
            )
                .into_response(),
        }
    }

    /// Spin up an in-process mock of `GET /_synapse/mas/is_localpart_available`
    /// on an ephemeral localhost port, pre-seeded with the set of localparts
    /// that should read as "already taken" (existing accounts). Returns a
    /// `SynapseClient` pointed at it plus the server task's handle (abort it
    /// when the test is done so the port doesn't linger for the rest of the
    /// process).
    async fn spawn_mock_synapse(
        existing: HashSet<String>,
    ) -> (SynapseClient, tokio::task::JoinHandle<()>) {
        spawn_mock_synapse_with_did_fields(existing, HashMap::new()).await
    }

    /// [`spawn_mock_synapse`] plus the MSC4133 profile-field read, for the
    /// `/resolve` tests: the same homeserver, answering the one extra route that
    /// endpoint touches.
    ///
    /// **Keep this signature.** It is `pub(crate)` and called from
    /// `resolve.rs`'s tests; richer scenarios go through
    /// [`spawn_mock_synapse_configured`] instead of widening it, so a mock
    /// feature added for one module cannot force an edit in another.
    pub(crate) async fn spawn_mock_synapse_with_did_fields(
        existing: HashSet<String>,
        did_fields: DidFields,
    ) -> (SynapseClient, tokio::task::JoinHandle<()>) {
        spawn_mock_synapse_configured(MockSynapseConfig {
            existing,
            did_fields,
            ..MockSynapseConfig::default()
        })
        .await
    }

    /// The one real constructor: every other spawn helper above is a
    /// convenience wrapper that fills in a [`MockSynapseConfig`].
    ///
    /// Spins the mock up on an ephemeral localhost port and returns a
    /// `SynapseClient` pointed at it plus the server task's handle (abort it
    /// when the test is done so the port doesn't linger for the rest of the
    /// process).
    pub(crate) async fn spawn_mock_synapse_configured(
        cfg: MockSynapseConfig,
    ) -> (SynapseClient, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mock-synapse port");
        let addr = listener.local_addr().expect("mock-synapse local_addr");
        let app = Router::new()
            .route(
                "/_synapse/mas/is_localpart_available",
                get(is_localpart_available_handler),
            )
            .route(
                "/_matrix/client/v3/profile/{mxid}/{field}",
                get(profile_field_handler),
            )
            .with_state(MockState { cfg: Arc::new(cfg) });
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock-synapse server");
        });
        let client = SynapseClient::new(&format!("http://{addr}"), "secret");
        (client, handle)
    }

    // -- Grandfathering: the three resolve_identity branches --------------------

    /// A DID whose LEGACY localpart already exists (a pre-2026-09 account) must
    /// keep it — is_new must be false, and the localpart must be the legacy
    /// shape, not the modern one, even though nothing stops the modern shape
    /// from also being computable for this DID.
    #[tokio::test]
    async fn existing_legacy_account_keeps_legacy_localpart() {
        let did = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
        let legacy = legacy_localpart(did);
        let (synapse, handle) = spawn_mock_synapse(HashSet::from([legacy.clone()])).await;

        let resolved = resolve_identity(did, Some(&synapse))
            .await
            .expect("resolve_identity must succeed against a reachable mock");

        assert_eq!(resolved.localpart, legacy, "must keep the legacy shape");
        assert_ne!(
            resolved.localpart,
            localpart_for(did),
            "sanity: legacy and modern really differ for this DID"
        );
        assert!(!resolved.is_new, "a pre-existing account is never 'new'");
        handle.abort();
    }

    /// A DID with NO account under either scheme is genuinely new: it must get
    /// the modern base36 shape, and is_new must be true.
    #[tokio::test]
    async fn unknown_did_resolves_to_base36_localpart_and_is_new() {
        let did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
        let (synapse, handle) = spawn_mock_synapse(HashSet::new()).await;

        let resolved = resolve_identity(did, Some(&synapse))
            .await
            .expect("resolve_identity must succeed against a reachable mock");

        assert_eq!(
            resolved.localpart,
            localpart_for(did),
            "an unknown DID must get the modern base36 shape"
        );
        assert!(resolved.is_new, "no account exists yet under either shape");
        handle.abort();
    }

    /// A DID whose MODERN localpart already exists (already migrated, or
    /// created under the new scheme by an earlier sign-in) must resolve to
    /// modern with is_new: false — it is a returning account, not a new one.
    #[tokio::test]
    async fn already_migrated_modern_account_resolves_to_modern_not_new() {
        let did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
        let modern = localpart_for(did);
        let (synapse, handle) = spawn_mock_synapse(HashSet::from([modern.clone()])).await;

        let resolved = resolve_identity(did, Some(&synapse))
            .await
            .expect("resolve_identity must succeed against a reachable mock");

        assert_eq!(resolved.localpart, modern);
        assert!(
            !resolved.is_new,
            "an account that already exists under the modern shape is a returning account"
        );
        handle.abort();
    }

    /// `synapse == None` is not an error case: it is deterministic, matches the
    /// historical `is_new_identity` contract ("cannot detect -> behave as
    /// today"), and always resolves to legacy (never modern) precisely so a
    /// standalone deployment's `TokenMetadata.username` keying is unaffected.
    #[tokio::test]
    async fn no_synapse_client_resolves_to_legacy_and_is_not_new() {
        let did = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
        let resolved = resolve_identity(did, None)
            .await
            .expect("no-Synapse path is infallible");
        assert_eq!(resolved.localpart, legacy_localpart(did));
        assert!(!resolved.is_new);
    }

    // -- Err propagation + the fail-safe fallback direction ---------------------

    /// `resolve_identity` must PROPAGATE a probe failure, not paper over it —
    /// unlike the `synapse == None` case above, an unreachable-but-configured
    /// Synapse is a genuine detection failure the caller must decide how to
    /// handle (see `resolve_identity_or_legacy` below).
    #[tokio::test]
    async fn synapse_unreachable_propagates_err() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable, the
        // same trick webauthn.rs's fail-closed tests use.
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");
        let err = resolve_identity("did:key:zDnUNREACHABLE", Some(&synapse)).await;
        assert!(
            err.is_err(),
            "an unreachable Synapse must propagate an Err, never silently succeed"
        );
    }

    /// THE fail-safe direction (see the module doc / `resolve_identity_or_legacy`'s
    /// doc): when a caller must produce a localpart despite a `resolve_identity`
    /// error, it falls back to the LEGACY shape, never the modern one. Guessing
    /// modern for an existing user would sever them from their account; guessing
    /// legacy for a new user only yields a suboptimally-shaped MXID. This test
    /// pins that direction so a future refactor cannot silently flip it.
    #[tokio::test]
    async fn fail_safe_fallback_is_legacy_never_modern() {
        let did = "did:key:zDnUNREACHABLE_FAILSAFE";
        let synapse = SynapseClient::new("http://192.0.2.1:1", "secret");

        let resolved = resolve_identity_or_legacy(did, Some(&synapse)).await;

        assert_eq!(
            resolved.localpart,
            legacy_localpart(did),
            "on error, the fallback MUST be legacy_localpart"
        );
        assert_ne!(
            resolved.localpart,
            localpart_for(did),
            "on error, the fallback must NEVER be the modern localpart_for shape"
        );
        assert!(
            !resolved.is_new,
            "a fallback must never claim to know an account is new"
        );
        assert!(
            resolved.degraded,
            "a fallback must ANNOUNCE that it guessed — this flag is what stops \
             oidc::provision_synapse_device publishing a signed assertion for a \
             localpart nobody resolved (2026-09-10 audit, D4)"
        );
    }

    /// The other half of the D4 contract: a SUCCESSFUL resolution must never
    /// set `degraded`, or the suppression would fire on healthy logins and
    /// silently turn DID publication off for everyone.
    ///
    /// Covers all three reachable-Synapse branches plus the no-Synapse one, so
    /// a new branch added to `resolve_identity` that forgets the field is
    /// caught here rather than in production by the absence of a feature.
    #[tokio::test]
    async fn a_successful_resolution_is_never_degraded() {
        let legacy_did = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
        let key_did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";

        // Branch 2: existing legacy account.
        let (synapse, handle) =
            spawn_mock_synapse(HashSet::from([legacy_localpart(legacy_did)])).await;
        assert!(
            !resolve_identity(legacy_did, Some(&synapse))
                .await
                .expect("reachable mock")
                .degraded,
            "a grandfathered legacy account is RESOLVED, not guessed"
        );
        // Branch 4: genuinely new identity.
        assert!(
            !resolve_identity(key_did, Some(&synapse))
                .await
                .expect("reachable mock")
                .degraded,
            "a genuinely new identity is RESOLVED, not guessed"
        );
        handle.abort();

        // Branch 3: already-migrated modern account.
        let (synapse, handle) = spawn_mock_synapse(HashSet::from([localpart_for(key_did)])).await;
        assert!(
            !resolve_identity(key_did, Some(&synapse))
                .await
                .expect("reachable mock")
                .degraded,
            "an already-modern account is RESOLVED, not guessed"
        );
        // And the infallible wrapper must agree when nothing went wrong.
        assert!(
            !resolve_identity_or_legacy(key_did, Some(&synapse))
                .await
                .degraded,
            "resolve_identity_or_legacy must only set `degraded` on the error path"
        );
        handle.abort();

        // Branch 1: no Synapse configured at all. Deterministic, not a failure.
        assert!(
            !resolve_identity(legacy_did, None)
                .await
                .expect("no-Synapse path is infallible")
                .degraded,
            "a standalone deployment is not degraded — it has no Matrix account to \
             resolve, which is a different fact from a probe that failed"
        );
    }

    // -- UNUSABLE is not TAKEN (2026-09-12) -------------------------------------

    /// A real-shaped `did:peer:2` (numalgo 2: an `.E` key agreement key, a `.V`
    /// authentication key and an `.S` base64url service block), 252 characters
    /// long. Its legacy localpart is 252 characters, making a 264-character user
    /// ID — past Synapse's `MAX_USERID_LENGTH` of 255. This is the shape that
    /// falsified the old "a 4xx can only mean already-in-use" claim on dev, and
    /// it is written out in full rather than generated so the test data is the
    /// same kind of thing a user actually presents.
    const LONG_PEER_DID: &str = "did:peer:2\
        .Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM7p43Y4rHzY7bLm\
        .Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V\
        .SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlk\
OmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIl19";

    /// THE headline regression. A DID whose LEGACY localpart is too long for
    /// Synapse to accept at all must resolve to the MODERN localpart and be
    /// reported as NEW — because a localpart Synapse refuses cannot have an
    /// account under it, so there is nothing to grandfather.
    ///
    /// Pre-fix, `is_localpart_available` mapped that `M_INVALID_USERNAME` to
    /// `Ok(false)` = "taken" and this returned `{ legacy, is_new: false }`:
    /// an identity with no account anywhere, reported as a pre-existing one,
    /// under a localpart no account can ever occupy.
    ///
    /// It also pins the positive half of the story: the opaque scheme ALREADY
    /// solved the long-DID problem — `localpart_for` is 16 base36 characters for
    /// a 252-character DID exactly as for a 40-character one — and the legacy
    /// probe's misreading was merely masking that solution.
    #[tokio::test]
    async fn a_did_whose_legacy_localpart_is_over_length_resolves_to_the_modern_one_and_is_new() {
        let legacy = legacy_localpart(LONG_PEER_DID);
        assert!(
            format!("@{legacy}:inblock.io").len() > 255,
            "test premise: this DID's legacy user ID must exceed MAX_USERID_LENGTH \
             (got {} characters)",
            format!("@{legacy}:inblock.io").len()
        );

        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            unusable: HashSet::from([legacy.clone()]),
            ..MockSynapseConfig::default()
        })
        .await;

        let resolved = resolve_identity(LONG_PEER_DID, Some(&synapse))
            .await
            .expect("an unusable legacy localpart is a fall-through, never an error");

        assert_eq!(
            resolved.localpart,
            localpart_for(LONG_PEER_DID),
            "the identity must get the modern 16-char base36 shape"
        );
        assert_ne!(
            resolved.localpart, legacy,
            "it must NOT be grandfathered onto the localpart Synapse refuses"
        );
        assert_eq!(
            resolved.localpart.len(),
            16,
            "sanity: the modern shape is a fixed 16 characters however long the DID is"
        );
        assert!(
            resolved.is_new,
            "no account exists under EITHER shape — one of them cannot even hold an account"
        );
        assert!(!resolved.degraded, "this was RESOLVED, not guessed");
        handle.abort();
    }

    /// The security consequence, stated on its own: an `Unusable` legacy probe
    /// must never be read as an existing account, because `is_new` is the input
    /// to the new-account gates.
    ///
    /// `webauthn::reject_if_new_identity` matches `Ok(resolved) if
    /// resolved.is_new` -> reject, `Ok(_)` -> **pass**, `Err` -> reject (fail
    /// closed). So a wrongly-`is_new: false` resolution makes that gate PASS for
    /// a brand-new identity on the QR/device-approval and account-re-auth paths,
    /// which are documented to hard-REJECT it. Asserting `is_new == true` here
    /// is asserting that the gate REJECTS.
    #[tokio::test]
    async fn an_unusable_legacy_localpart_is_never_read_as_an_existing_account() {
        let did = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            unusable: HashSet::from([legacy_localpart(did)]),
            ..MockSynapseConfig::default()
        })
        .await;

        let resolved = resolve_identity(did, Some(&synapse))
            .await
            .expect("reachable mock");

        assert!(
            resolved.is_new,
            "a localpart Synapse REFUSES holds no account, so the identity is new and \
             every new-account gate must reject it"
        );
        assert_eq!(resolved.localpart, localpart_for(did));
        handle.abort();
    }

    /// The fall-through is a fall-through, not a shortcut to "new": when the
    /// legacy shape is unusable but an account ALREADY exists under the modern
    /// shape (the user signed in once before, after the opaque scheme shipped),
    /// the answer is that returning account — modern localpart, `is_new: false`.
    ///
    /// Without this, a second sign-in by a long-DID user would read as a first
    /// sign-in, and `oidc::provision_synapse_device` would treat an established
    /// account as brand-new (re-seeding the displayname alias over a name the
    /// user chose).
    #[tokio::test]
    async fn an_unusable_legacy_localpart_still_yields_the_modern_one_when_that_account_already_exists(
    ) {
        let modern = localpart_for(LONG_PEER_DID);
        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            unusable: HashSet::from([legacy_localpart(LONG_PEER_DID)]),
            existing: HashSet::from([modern.clone()]),
            ..MockSynapseConfig::default()
        })
        .await;

        let resolved = resolve_identity(LONG_PEER_DID, Some(&synapse))
            .await
            .expect("reachable mock");

        assert_eq!(resolved.localpart, modern);
        assert!(
            !resolved.is_new,
            "an account that already exists under the modern shape is RETURNING, and a \
             refused legacy probe says nothing to the contrary"
        );
        assert!(!resolved.degraded);
        handle.abort();
    }

    /// A rejected MAS shared secret (403) is a CREDENTIAL failure: it never
    /// reaches `check_username`, so it carries no information about the
    /// localpart and must not become a verdict about it. `resolve_identity` must
    /// therefore `Err` — which makes every new-account gate fail CLOSED — and
    /// `resolve_identity_or_legacy` must degrade to the legacy shape with
    /// `degraded: true`, suppressing DID publication (2026-09-10 audit, D4).
    ///
    /// Folding 403 into the 4xx branch would make every localpart on the
    /// homeserver read as taken the moment the secret drifted: a total, silent
    /// failure of new-account detection, presented as fact.
    #[tokio::test]
    async fn a_rejected_mas_secret_is_an_error_never_a_resolution() {
        let did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            reject_secret: true,
            ..MockSynapseConfig::default()
        })
        .await;

        assert!(
            resolve_identity(did, Some(&synapse)).await.is_err(),
            "a rejected credential must propagate as Err so the new-account gates fail \
             closed — it is not evidence that the localpart is free OR taken"
        );

        let degraded = resolve_identity_or_legacy(did, Some(&synapse)).await;
        assert_eq!(
            degraded.localpart,
            legacy_localpart(did),
            "the infallible wrapper still falls back to LEGACY, never modern"
        );
        assert!(
            degraded.degraded,
            "and it must announce the guess, so nothing durable is published under it"
        );
        handle.abort();
    }

    /// An `Unusable` MODERN localpart is a hard error, never a fallback.
    ///
    /// It should be unreachable — 16 characters of `[0-9a-z]` break no Synapse
    /// rule, and the only theoretical route is the guest-reserved all-numeric
    /// case at probability ≈ `(10/36)^16` ≈ 3e-9. So reaching it means something
    /// is wrong with the homeserver, not with the DID, and the honest answer is
    /// a loud failure (which also fails closed at every gate) rather than a
    /// guess dressed up as a resolution.
    #[tokio::test]
    async fn an_unusable_modern_localpart_is_a_hard_error() {
        let did = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
        let (synapse, handle) = spawn_mock_synapse_configured(MockSynapseConfig {
            unusable: HashSet::from([legacy_localpart(did), localpart_for(did)]),
            ..MockSynapseConfig::default()
        })
        .await;

        // Not `expect_err`: `ResolvedIdentity` deliberately carries no `Debug`,
        // and the interesting thing to print on failure is the localpart that
        // was wrongly returned anyway.
        let err = match resolve_identity(did, Some(&synapse)).await {
            Err(e) => e,
            Ok(resolved) => panic!(
                "both shapes refused leaves no localpart to return, but got `{}`",
                resolved.localpart
            ),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains(&localpart_for(did)),
            "the error must name the localpart that was refused, so it is diagnosable: {rendered}"
        );
        handle.abort();
    }
}
