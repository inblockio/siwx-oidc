//! Short-TTL, admin-scoped token mint for Synapse's `/_synapse/admin/*` API.
//!
//! # Why this module exists
//!
//! Synapse 1.157 **deleted** the `admin_token` shim that let the OIDC provider
//! call the Synapse admin API by presenting the MAS shared secret directly. In
//! 1.154 `msc3861_delegated.py` carried that shim with an explicit comment
//! calling it *"a temporary solution so that the admin API can be called by the
//! OIDC provider"*. On 1.157+ the shared secret is honoured **only** on
//! `/_synapse/mas/*`; every `/_synapse/admin/*` route answers 401.
//!
//! The replacement path is the delegated-auth scope. In Synapse 1.159
//! (`synapse/api/auth/mas.py`) server-admin authorization is exactly:
//!
//! ```text
//! async def is_server_admin(self, requester: Requester) -> bool:
//!     return "urn:synapse:admin:*" in requester.scope
//! ```
//!
//! and `requester.scope` is taken verbatim from **our own** introspection
//! response. So siwx-oidc, as the delegated auth provider, can mint itself an
//! admin credential. This module does that.
//!
//! # What Synapse 1.159 requires of the minted token
//!
//! All four verified against the 1.159.0 source of
//! `MasDelegatedAuth::get_user_by_access_token`, which rejects the token unless
//! the introspection response satisfies **all** of:
//!
//! 1. `active: true`, and `expires_in` has not elapsed.
//! 2. `scope` contains `urn:matrix:client:api:*` (or the MSC2967 unstable twin
//!    `urn:matrix:org.matrix.msc2967.client:api:*`). This is checked **before**
//!    the admin scope is ever consulted, so an admin-only scope string is
//!    rejected outright with *"Token doesn't grant access to the Matrix C-S
//!    API"*. [`ADMIN_SCOPE`] therefore carries **both** scopes — dropping the
//!    C-S API scope silently breaks admin access.
//! 3. `username` is present **and resolves to an existing Synapse user row**
//!    (`store.get_user_by_id`), else `AuthError(500, "User not found")`. This is
//!    why [`ensure_service_user`] runs before every mint: a token for a
//!    non-existent localpart is dead on arrival.
//! 4. `device_id` is absent/null, **or** names a device that exists. An empty
//!    string is *not* "absent" to Synapse — it is a zero-length device id, which
//!    trips `AuthError(500, "Invalid device ID in introspection result")`. The
//!    admin token carries no device, so `introspect` renders an empty
//!    `device_id` as JSON `null`. Do not "simplify" that back to `""`.
//!
//! # Lifetime policy
//!
//! Minted **on demand** with a **short TTL** — never a static long-lived admin
//! credential sitting in a `.env`. siwx-oidc can already do anything as the auth
//! provider, so minting does not widen its blast radius; a standing admin key on
//! disk would. The TTL is clamped to
//! [`ADMIN_TOKEN_TTL_MIN`]..=[`ADMIN_TOKEN_TTL_MAX`] **in code**, so a
//! misconfigured deployment cannot turn this into a long-lived key by setting a
//! large `SIWEOIDC_ADMIN_TOKEN_TTL_SECS`.
//!
//! # Caller note: Synapse's introspection cache
//!
//! `MasDelegatedAuth` caches an introspection result for **2 minutes with no
//! invalidation mechanism**. A token can therefore keep working *at Synapse* for
//! up to ~2 minutes past its own expiry, if Synapse introspected it while it was
//! still valid. Our introspection response is the authority; the cache is not.
//! Callers must not infer a token's validity from Synapse's behaviour.

use axum::{extract::State, http::StatusCode, Json};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use serde_json::json;
use tracing::{error, info, warn};

use siwx_oidc::db::{DBClient, TokenMetadata};

use super::axum_lib::AdminTokenState;
use super::introspect::{generate_opaque_token, verify_shared_secret};
use super::synapse_client::SynapseClient;

/// Prefix for minted admin tokens.
///
/// Deliberately distinct from the `mat_`/`mcr_` user tokens so an admin
/// credential is identifiable at a glance in logs, in Redis and during incident
/// triage. Nothing in the codebase looks a token up by prefix — the prefix is
/// purely an observability affordance.
pub const ADMIN_TOKEN_PREFIX: &str = "msa_";

/// Scope granted to a minted admin token.
///
/// **Both** entries are load-bearing. `urn:synapse:admin:*` is what
/// `is_server_admin()` tests; `urn:matrix:client:api:*` is what gates the token
/// being accepted at all (see the module docs, requirement 2).
pub const ADMIN_SCOPE: &str = "urn:matrix:client:api:* urn:synapse:admin:*";

/// The stable scope token Synapse tests in `is_server_admin()`.
///
/// Referenced by the tests that pin [`ADMIN_SCOPE`]'s composition rather than by
/// the request path, which uses the pre-joined [`ADMIN_SCOPE`] directly.
#[allow(dead_code)]
pub const SYNAPSE_ADMIN_SCOPE: &str = "urn:synapse:admin:*";

/// The stable MSC2967 C-S API scope Synapse requires before it will accept the
/// token at all.
///
/// Referenced by the tests that pin [`ADMIN_SCOPE`]'s composition rather than by
/// the request path, which uses the pre-joined [`ADMIN_SCOPE`] directly.
#[allow(dead_code)]
pub const MATRIX_API_SCOPE: &str = "urn:matrix:client:api:*";

/// `client_id` recorded on the token, so an admin credential is attributable in
/// introspection output and logs.
const ADMIN_CLIENT_ID: &str = "siwx-oidc-admin";

/// `sub` recorded on the token. Deliberately NOT a DID: no wallet or passkey
/// owns this credential, and it must never be mistaken for a user identity.
const ADMIN_SUBJECT: &str = "urn:siwx:service:admin";

/// Display name set on the admin service user when it is first provisioned.
pub const ADMIN_DISPLAY_NAME: &str = "siwx-oidc service admin";

/// Build the `TokenMetadata` for an admin-scoped token.
///
/// This is the SINGLE definition of the admin credential's claims. It is shared
/// by the HTTP mint endpoint ([`admin_token`], used by shell callers such as
/// `scripts/matrix-storage-controller.sh`) and by the in-process mint that
/// [`crate::synapse_client::SynapseClient`] performs for its own admin-API
/// calls. Sharing it is load-bearing: the four Synapse-1.159 acceptance
/// conditions in the module docs above are properties of THESE FIELDS, so two
/// independent constructions would be two independent chances to drop one.
///
/// In particular `device_id` is the empty string, which `introspect` renders as
/// JSON `null` — see requirement 4. Do not set it to a placeholder.
pub fn admin_token_metadata(localpart: &str, ttl: u64, now: i64) -> TokenMetadata {
    TokenMetadata {
        username: localpart.to_string(),
        // No device. Rendered as JSON `null` by `introspect` — see module docs
        // requirement 4; an empty string on the wire would make Synapse 500.
        device_id: String::new(),
        scope: ADMIN_SCOPE.to_string(),
        client_id: ADMIN_CLIENT_ID.to_string(),
        iat: now,
        exp: now + ttl as i64,
        did: ADMIN_SUBJECT.to_string(),
        name: ADMIN_DISPLAY_NAME.to_string(),
    }
}

/// Floor for the minted-token TTL (seconds). Below this the token is unusable
/// for a real admin operation.
pub const ADMIN_TOKEN_TTL_MIN: u64 = 30;

/// Ceiling for the minted-token TTL (seconds). This is the enforcement point for
/// the "short TTL, minted on demand" invariant: it is applied in code so a
/// deployment cannot promote the mint into a long-lived standing admin key by
/// setting a large TTL in its environment.
pub const ADMIN_TOKEN_TTL_MAX: u64 = 900;

/// Clamp a configured admin-token TTL into the permitted window.
pub fn clamp_admin_token_ttl(configured: u64) -> u64 {
    configured.clamp(ADMIN_TOKEN_TTL_MIN, ADMIN_TOKEN_TTL_MAX)
}

/// Build a machine-readable error body. Every failure path returns a
/// discriminator so a shell caller can branch on it (and so a failure can never
/// be mistaken for a success with an empty token).
fn fail(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(json!({ "error": code, "error_description": message })),
    )
}

/// Ensure the admin service user exists in Synapse.
///
/// Requirement 3 in the module docs: Synapse resolves the introspected
/// `username` against its own `users` table and 500s if the row is missing, so a
/// token minted for a non-existent localpart is useless.
///
/// The existence probe comes first so the common (already-provisioned) path
/// performs **no write**. That is deliberate: `provision_user` also sets a
/// display name, and `set_displayname` is the exact call that 500s against a
/// row-less account on Synapse builds carrying element-hq/synapse#19702.
///
/// Fails **closed**: any error propagates and the caller refuses to mint, rather
/// than handing back a token that will fail confusingly at Synapse later.
async fn ensure_service_user(synapse: &SynapseClient, localpart: &str) -> anyhow::Result<()> {
    if synapse.is_localpart_available(localpart).await? {
        info!(
            localpart,
            "admin_token: provisioning the admin service user"
        );
        synapse
            .provision_user(localpart, ADMIN_DISPLAY_NAME)
            .await?;
    }
    Ok(())
}

/// `POST /oauth2/admin_token` — mint a short-TTL, admin-scoped access token.
///
/// Authentication: `Authorization: Bearer {mas_shared_secret}`, compared in
/// constant time (same secret and same comparison as `/oauth2/introspect`).
/// There is no request body: the interface is deliberately plain so a bash
/// caller — `scripts/matrix-storage-controller.sh` — is a single `curl`.
///
/// Returns an RFC 6749 §5.1-shaped token response:
/// `{ "access_token", "token_type", "expires_in", "scope", "user_id"? }`.
///
/// Every failure is an explicit non-2xx with an `error` discriminator, never a
/// 200 carrying an unusable token. Silent auth failure is the specific outcome
/// this endpoint's consumers must be protected from.
pub async fn admin_token(
    State(state): State<AdminTokenState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let secret = match state.mas_shared_secret.as_deref() {
        Some(s) => s,
        None => {
            warn!("admin_token: called but mas_shared_secret is not configured");
            return Err(fail(
                StatusCode::NOT_FOUND,
                "not_configured",
                "admin token minting requires SIWEOIDC_MAS_SHARED_SECRET",
            ));
        }
    };

    let provided = match bearer.as_ref() {
        Some(b) => b.token(),
        None => {
            warn!("admin_token: missing Authorization: Bearer header");
            return Err(fail(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authorization: Bearer {shared_secret} is required",
            ));
        }
    };

    if !verify_shared_secret(provided.as_bytes(), secret.as_bytes()) {
        warn!("admin_token: invalid shared secret");
        return Err(fail(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid shared secret",
        ));
    }

    let synapse = state.synapse_client.as_deref().ok_or_else(|| {
        error!(
            "admin_token: no Synapse client configured (SIWEOIDC_SYNAPSE_ENDPOINT); refusing to mint"
        );
        fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "synapse_unavailable",
            "no Synapse endpoint configured; an admin token cannot be bound to a user",
        )
    })?;

    let localpart = state.admin_localpart.as_str();

    ensure_service_user(synapse, localpart).await.map_err(|e| {
        error!(
            error = %e,
            localpart,
            "admin_token: could not confirm the admin service user exists; refusing to mint"
        );
        fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_user_unavailable",
            "could not confirm the admin service user exists in Synapse",
        )
    })?;

    let ttl = state.admin_token_ttl_secs;
    let now = Utc::now().timestamp();
    let token = generate_opaque_token(ADMIN_TOKEN_PREFIX);
    // Shared with the in-process mint in `crate::synapse_client` — see
    // `admin_token_metadata`. Do not inline these fields again here.
    let metadata = admin_token_metadata(localpart, ttl, now);

    state
        .redis_client
        .set_token(&token, &metadata, ttl)
        .await
        .map_err(|e| {
            error!(error = %e, "admin_token: failed to store the minted token");
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "failed to store the minted token",
            )
        })?;

    info!(
        localpart,
        ttl_secs = ttl,
        "admin_token: minted an admin-scoped token"
    );

    let mut body = json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": ADMIN_SCOPE,
    });
    if let Some(server_name) = state.server_name.as_deref() {
        body["user_id"] = json!(format!("@{}:{}", localpart, server_name));
    }
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requirement 2: dropping either half of the scope breaks admin access, and
    /// the failure mode is a confusing 401 at Synapse rather than a clear error
    /// here. Pin both.
    #[test]
    fn admin_scope_carries_both_required_scopes() {
        let scopes: Vec<&str> = ADMIN_SCOPE.split(' ').collect();
        assert!(
            scopes.contains(&SYNAPSE_ADMIN_SCOPE),
            "is_server_admin() tests for {SYNAPSE_ADMIN_SCOPE}"
        );
        assert!(
            scopes.contains(&MATRIX_API_SCOPE),
            "Synapse rejects a token without {MATRIX_API_SCOPE} before it looks at the admin scope"
        );
    }

    /// The scope string is split on single spaces by Synapse
    /// (`scope.split(" ")`), so stray/double whitespace would produce empty
    /// tokens and a scope set that does not contain what we think it does.
    #[test]
    fn admin_scope_is_single_space_delimited() {
        assert!(!ADMIN_SCOPE.contains("  "));
        assert_eq!(ADMIN_SCOPE.trim(), ADMIN_SCOPE);
        assert_eq!(ADMIN_SCOPE.split(' ').count(), 2);
    }

    /// The clamp is the enforcement point for "never a static long-lived admin
    /// credential". A deployment asking for 90 days must get 15 minutes.
    #[test]
    fn ttl_clamp_caps_a_long_lived_request() {
        assert_eq!(clamp_admin_token_ttl(7_776_000), ADMIN_TOKEN_TTL_MAX);
        assert_eq!(clamp_admin_token_ttl(901), ADMIN_TOKEN_TTL_MAX);
    }

    #[test]
    fn ttl_clamp_raises_an_unusably_short_request() {
        assert_eq!(clamp_admin_token_ttl(0), ADMIN_TOKEN_TTL_MIN);
        assert_eq!(clamp_admin_token_ttl(1), ADMIN_TOKEN_TTL_MIN);
    }

    #[test]
    fn ttl_clamp_passes_through_a_sane_value() {
        assert_eq!(clamp_admin_token_ttl(300), 300);
        assert_eq!(
            clamp_admin_token_ttl(ADMIN_TOKEN_TTL_MIN),
            ADMIN_TOKEN_TTL_MIN
        );
        assert_eq!(
            clamp_admin_token_ttl(ADMIN_TOKEN_TTL_MAX),
            ADMIN_TOKEN_TTL_MAX
        );
    }

    /// Admin tokens must be distinguishable from user tokens at a glance.
    #[test]
    fn admin_token_prefix_is_distinct_from_user_token_prefixes() {
        assert_ne!(ADMIN_TOKEN_PREFIX, "mat_");
        assert_ne!(ADMIN_TOKEN_PREFIX, "mcr_");
        let token = generate_opaque_token(ADMIN_TOKEN_PREFIX);
        assert!(token.starts_with(ADMIN_TOKEN_PREFIX));
        assert!(!token.starts_with("mat_"));
    }
}
