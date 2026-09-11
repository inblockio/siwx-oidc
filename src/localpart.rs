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

pub(crate) use siwx_oidc::mxid::{legacy_localpart, localpart_for};
use tracing::warn;

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
/// 2. `is_localpart_available(legacy) == Ok(false)` (taken) ->
///    `{ legacy, is_new: false }` — a pre-existing, grandfathered account.
/// 3. Else, `is_localpart_available(modern) == Ok(false)` (taken) ->
///    `{ modern, is_new: false }` — already migrated, or created under the new
///    scheme by a previous sign-in.
/// 4. Else -> `{ modern, is_new: true }` — genuinely new; neither shape is
///    taken.
///
/// Any `Err` from a probe is propagated, not papered over: a caller that needs
/// a localpart anyway despite the error MUST fall back to [`legacy_localpart`]
/// (never [`localpart_for`]) — see [`resolve_identity_or_legacy`] and the
/// module doc's note on the fail-safe direction.
///
/// Note: [`crate::synapse_client::SynapseClient::is_localpart_available`] maps
/// ANY 4xx response to `Ok(false)` ("taken"), which also covers
/// `M_INVALID_USERNAME`. That cannot misfire here because both
/// [`legacy_localpart`] and [`localpart_for`] always produce a syntactically
/// valid Matrix localpart (`[a-z0-9._=/-]`), so a 4xx on either probe can only
/// mean "already in use", never "malformed".
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

    let legacy = legacy_localpart(did);
    let legacy_available = synapse.is_localpart_available(&legacy).await?;
    if !legacy_available {
        return Ok(ResolvedIdentity {
            localpart: legacy,
            is_new: false,
            degraded: false,
        });
    }

    let modern = localpart_for(did);
    let modern_available = synapse.is_localpart_available(&modern).await?;
    if !modern_available {
        return Ok(ResolvedIdentity {
            localpart: modern,
            is_new: false,
            degraded: false,
        });
    }

    Ok(ResolvedIdentity {
        localpart: modern,
        is_new: true,
        degraded: false,
    })
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
    type DidFields = HashMap<String, serde_json::Value>;

    #[derive(Clone)]
    struct MockState {
        /// Localparts that read as "already taken" (existing accounts).
        existing: Arc<HashSet<String>>,
        /// Published `io.inblock.did` values, by mxid. An mxid with no entry
        /// answers 404, exactly as Synapse does for an unset custom field.
        did_fields: Arc<DidFields>,
    }

    async fn is_localpart_available_handler(
        State(state): State<MockState>,
        Query(params): Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let localpart = params.get("localpart").cloned().unwrap_or_default();
        if state.existing.contains(&localpart) {
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
        match state.did_fields.get(&mxid) {
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
    pub(crate) async fn spawn_mock_synapse_with_did_fields(
        existing: HashSet<String>,
        did_fields: DidFields,
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
            .with_state(MockState {
                existing: Arc::new(existing),
                did_fields: Arc::new(did_fields),
            });
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
}
