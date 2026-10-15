//! Matrix legacy compatibility endpoints and OAuth2 token revocation (MSC3861).
//!
//! Provides:
//! - `POST /oauth2/revoke` (RFC 7009)
//! - `GET /_matrix/client/v3/login` (login flows discovery)
//! - `POST /_matrix/client/v3/logout` (single-session logout)
//! - `POST /_matrix/client/v3/logout/all` (bulk sign-out, all sessions)
//! - `DELETE /_matrix/client/v3/devices/{device_id}` and
//!   `POST /_matrix/client/v3/delete_devices` (legacy in-client device sign-out)
//! - `POST /_matrix/client/v3/refresh` (token refresh)
//!
//! ## Session teardown vs. account deactivation
//!
//! Teardown always revokes the *ending* session's OAuth tokens. Whether it also
//! deletes the Synapse device depends on the caller's intent (see
//! [`TeardownPolicy`]): an explicit `POST /_matrix/client/v3/logout` deletes the
//! device; a bare RFC 7009 `POST /oauth2/revoke` is token hygiene and does NOT
//! (clients fire revoke on rotation and on dialog dismissals, where deleting the
//! device strands the user's identity — the 2026-06-12 login incident). That is
//! the default. With `SIWXOIDC_REVOKE_DELETES_DEVICE` (flag 1, off by default) a
//! revoke of a Matrix-credential grant ends the session including its device
//! (MAS parity), and every teardown is strict: Synapse delete, then the
//! deleted-id marker (flag 2), then revoke; a transient Synapse failure answers
//! 503 and revokes nothing; the caller's retry finishes it, unless the caller
//! gives up: the device is then gone while its grant lives, so the owner's
//! client refreshes fine and Synapse refuses every request with
//! `M_UNKNOWN_TOKEN`.
//!
//! Deleting a device that is *ending* (on explicit logout) is distinct from device
//! *recycling* (re-issuing the same `device_id` with new keys), which Synapse
//! cannot do cleanly: its `delete_device` does not drop the device's
//! `e2e_cross_signing_signatures` rows, and the signature-upload handler then
//! skips fresh uploads. Sign-in therefore never deletes-then-reuses a device id;
//! it upserts a fresh `SIWX_{uuid}`, so the explicit-logout delete is safe
//! precisely because the id is not reused. A client may still propose an id of
//! its own (Element keeps one per install): with
//! `SIWXOIDC_REFUSE_DELETED_DEVICE_IDS` (flag 2) every delete plants a
//! deleted-id marker and a sign-in naming that id is refused, never recreated.
//! Flag 1 requires flag 2 (the server refuses to start otherwise). Apart from the Matrix-shaped
//! `refresh`, none of this code touches sign-in or token issuance (`oidc.rs`);
//! see `docs/matrix-integration.md`, "Accounts and devices".

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::Deserialize;
use tracing::{debug, error, info, warn};

// Use the binary crate's own `synapse_client` module (the same one `axum_lib`
// and `account` use) so `CompatState.synapse_client` is type-compatible with
// `AppState.synapse_client`. The lib crate used to re-expose the same file as
// `siwx_oidc::synapse_client`, which was a *distinct* type here; it no longer
// does (see the note in `src/lib.rs`).
use crate::synapse_client::{DeviceDelete, SynapseClient};
use siwx_oidc::db::grant::{
    self, GrantKind, InvalidReason, RefreshPeek, RotateOutcome, RotateRequest,
};
use siwx_oidc::db::{DBClient, RedisClient, TokenKind, ACCESS_TOKEN_TTL};

// -- Shared state for compat endpoints ----------------------------------------

#[derive(Clone)]
pub struct CompatState {
    pub redis_client: RedisClient,
    /// Synapse client for MSC3861 device teardown. `None` in standalone mode,
    /// where teardown degrades to Redis-only token revocation.
    pub synapse_client: Option<Arc<SynapseClient>>,
    /// Matrix `server_name` (e.g. `matrix.inblock.io`), needed to build the
    /// mxid for Synapse admin-API device calls. `None` in standalone mode.
    pub server_name: Option<String>,
    /// `config.require_secret`: whether a client registered without a
    /// `token_endpoint_auth_method` is confidential
    /// (`oidc::client_is_confidential`), for lifting a legacy refresh token.
    pub require_secret: bool,
    /// `oidc::delegated_auth_enabled(config)`: Matrix clients are this
    /// deployment's relying parties, so these routes act on Matrix credentials
    /// only (see [`CompatState::acts_on`]).
    pub delegated_auth: bool,
    /// `config.guest_client_id`: the refresh guard of S5 looks only at its grants.
    pub guest_client_id: Option<String>,
}

impl CompatState {
    /// The state of a deployment configured as `config`: the one place the
    /// configuration decides what these routes do.
    pub fn new(
        redis_client: RedisClient,
        synapse_client: Option<Arc<SynapseClient>>,
        config: &crate::config::Config,
    ) -> Self {
        Self {
            redis_client,
            synapse_client,
            server_name: config.matrix_server_name.clone(),
            require_secret: config.require_secret,
            delegated_auth: crate::oidc::delegated_auth_enabled(config),
            guest_client_id: config.guest_client_id.clone(),
        }
    }

    /// Whether the Matrix client-server routes act on a token whose grant is
    /// of `kind` (`None`: no grant record to judge).
    ///
    /// With delegated auth they act on Matrix credentials only
    /// ([`grant::is_matrix_credential`]): the grant of a generic-class client
    /// (an `oidc` grant) is not a Matrix session, so a mail token can neither
    /// sign the user's Matrix devices out, nor end the user's other sessions,
    /// nor refresh at the Matrix endpoint. Without delegated auth every client
    /// is a relying party and holds `oidc` grants, so there is nothing to
    /// refuse and these routes serve every grant, as they always did.
    fn acts_on(&self, kind: Option<GrantKind>) -> bool {
        !self.delegated_auth || grant::is_matrix_credential(kind)
    }
}

// -- Request/response types ---------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeForm {
    pub token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// -- Session teardown (shared by logout + revoke) -----------------------------

/// Whether a teardown is allowed to delete the ending session's Synapse device.
///
/// Deleting a Synapse device is destructive: it drops the device's E2EE / cross
/// signing state, and if it races an in-flight key upload it strands the user's
/// identity. It must therefore be driven by an explicit "sign this device out"
/// intent, never by transport-level token hygiene.
///
/// - A bare RFC 7009 `POST /oauth2/revoke` is token hygiene: clients fire it on
///   token rotation and on dialog dismissals (Element's forced-recovery loop
///   revoked tokens on every escape). Deleting the device there destroyed devices
///   mid-flight and wedged accounts (2026-06-12 login incident, amplifier B). So
///   revoke is [`TeardownPolicy::TokensOnly`] (with flag 1 off; flag 1 changes
///   this, below).
/// - `POST /_matrix/client/v3/logout` is an explicit sign-out, so it is
///   [`TeardownPolicy::DeleteDevice`]. (The MSC4191 `device_delete` / `session_end`
///   actions in `account.rs` are the other explicit-intent path and delete there.)
///
/// Device ids are never recycled (sign-in upserts a fresh `SIWX_{uuid}`), so in
/// Synapse mode exactly one session references a given device; an explicit logout
/// can delete it safely without racing another live session.
///
/// **Flag 1 (`revoke_deletes_device`, off by default).** On, revoke of a
/// Matrix-credential grant is [`TeardownPolicy::DeleteMatrixDevice`] (MAS
/// parity: a revoke ends the session including its device; other grant kinds
/// keep tokens-only), and every device delete is strict ([`strict_teardown_device`]):
/// Synapse delete, then the deleted-id marker, then revoke. Revoke already ends
/// every token of the device, so no live session loses its device. It is NOT
/// safe on its own against the 2026-06-12 sequence for a client that proposes
/// the same device id again at its next sign-in (Element Web and X keep one per
/// install): the id is recreated, the recycling Synapse cannot do cleanly (see
/// the module doc). Only the refusal of a deleted id (flag 2) closes that, so
/// flag 1 requires flag 2: siwx-oidc refuses to start with flag 1 on and flag 2
/// off (`Config::check_session_end_flags`;
/// `e2e_race_teardown::h4b_replay_forced_recovery_escapes_each_revoke_no_wedge`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TeardownPolicy {
    /// Revoke the session's OAuth tokens only; leave the Synapse device intact.
    TokensOnly,
    /// Revoke tokens AND delete the ending session's Synapse device.
    DeleteDevice,
    /// Flag 1 revoke: [`TeardownPolicy::DeleteDevice`] for a Matrix-credential
    /// grant ([`grant::is_matrix_credential`]), [`TeardownPolicy::TokensOnly`]
    /// for any other.
    DeleteMatrixDevice,
}

impl TeardownPolicy {
    /// Whether a teardown of a token of a `kind` grant deletes the device: an
    /// explicit sign-out always, a flag-1 revoke for a Matrix credential only.
    fn deletes_device(self, kind: Option<GrantKind>) -> bool {
        match self {
            TeardownPolicy::TokensOnly => false,
            TeardownPolicy::DeleteDevice => true,
            TeardownPolicy::DeleteMatrixDevice => grant::is_matrix_credential(kind),
        }
    }

    /// The policy of `POST /oauth2/revoke`: tokens only, unless flag 1 is on.
    fn revoke(strict: bool) -> Self {
        if strict {
            TeardownPolicy::DeleteMatrixDevice
        } else {
            TeardownPolicy::TokensOnly
        }
    }
}

/// Where a strict teardown ([`strict_teardown_device`]) stopped. Each is
/// answered with the retryable 503; every step is idempotent, so the retry runs
/// the whole teardown again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum StrictFault {
    /// Synapse gave a transient answer (5xx, network): nothing was revoked.
    Synapse,
    /// The deleted-id marker could not be written: nothing was revoked.
    Marker,
    /// The device is gone but its grants could not be revoked.
    Revoke,
}

/// The deleted-id marker step of every teardown (8.23 step 2, 8.12), between
/// the Synapse delete (2xx or 404, never a device still listed) and the revoke:
/// with SS4 flag 2 (`refuse_deleted_device_ids`) on, plant
/// `deleted:device/<localpart>/<device_id>` for the configured TTL, so a later
/// sign-in naming the id is refused; with it off, nothing.
pub(crate) async fn plant_deleted_marker(
    redis: &RedisClient,
    synapse: &SynapseClient,
    username: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    match synapse.deleted_marker_ttl() {
        Some(ttl) => {
            redis
                .plant_deleted_device_marker(username, device_id, ttl)
                .await
        }
        None => Ok(()),
    }
}

/// The best-effort device delete (flag 1 off) with the marker (flag 2): with
/// flag 2 off exactly today's `delete_device`, a failure logged at `warn!` and
/// never returned. With flag 2 on, a delete Synapse answered 2xx or 404 plants
/// the marker; a marker that could not be written is
/// [`StrictFault::Marker`], so the caller revokes nothing and answers the
/// retryable 503 (card default: like a transient fault; the retry is idempotent).
pub(crate) async fn best_effort_delete_device(
    redis: &RedisClient,
    synapse: &SynapseClient,
    server_name: &str,
    username: &str,
    device_id: &str,
    ctx: &str,
) -> Result<(), StrictFault> {
    if synapse.deleted_marker_ttl().is_none() {
        if let Err(e) = synapse
            .delete_device(username, device_id, server_name)
            .await
        {
            warn!(error = %e, ctx, username = %username, device_id = %device_id,
                "Synapse delete_device failed (best-effort)");
        }
        return Ok(());
    }
    let device = siwx_oidc::redact::fingerprint(device_id);
    match synapse
        .delete_device_status(username, device_id, server_name)
        .await
    {
        DeviceDelete::Deleted | DeviceDelete::NotFound => {
            plant_deleted_marker(redis, synapse, username, device_id)
                .await
                .map_err(|e| {
                    warn!(error = %e, ctx, device = %device, "deleted-id marker not written; nothing revoked, retryable");
                    StrictFault::Marker
                })
        }
        answer => {
            warn!(ctx, device = %device, ?answer, "Synapse delete_device failed (best-effort); no marker");
            Ok(())
        }
    }
}

/// One device's strict teardown (SS4 flag 1, 8.23): Synapse delete, then the
/// marker ([`plant_deleted_marker`]), then revoke the device's grants, decided by
/// the Synapse answer ([`DeviceDelete`]):
///
/// - deleted or not found (404): plant the marker, revoke; `Ok`.
/// - forbidden (403: wrong MAS shared secret): a configuration fault. No marker,
///   revoke anyway, log at error; `Ok`, so the client can end its session (the
///   device stays for the reaper).
/// - transient (5xx, network): revoke nothing; [`StrictFault::Synapse`].
///
/// A failed marker or revoke is a fault too. Returns the number of grants revoked.
pub(crate) async fn strict_teardown_device(
    redis: &RedisClient,
    synapse: &SynapseClient,
    server_name: &str,
    username: &str,
    device_id: &str,
    ctx: &str,
) -> Result<usize, StrictFault> {
    let device = siwx_oidc::redact::fingerprint(device_id);
    match synapse
        .delete_device_status(username, device_id, server_name)
        .await
    {
        DeviceDelete::Transient => {
            warn!(ctx, device = %device, "strict teardown: Synapse delete failed (transient); nothing revoked, retryable");
            return Err(StrictFault::Synapse);
        }
        DeviceDelete::Forbidden => {
            error!(ctx, device = %device, "strict teardown: Synapse refused the device delete (check the MAS shared secret); revoking anyway, the device stays for the reaper");
        }
        DeviceDelete::Deleted | DeviceDelete::NotFound => {
            if let Err(e) = plant_deleted_marker(redis, synapse, username, device_id).await {
                warn!(error = %e, ctx, device = %device, "strict teardown: deleted-id marker not written; nothing revoked, retryable");
                return Err(StrictFault::Marker);
            }
        }
    }
    redis
        .revoke_device_tokens(username, device_id)
        .await
        .map_err(|e| {
            warn!(error = %e, ctx, device = %device, "strict teardown: revoke failed after the delete; retryable");
            StrictFault::Revoke
        })
}

/// Tear down the single session identified by `token`.
///
/// Two-phase, best-effort, idempotent, and graceful:
/// 1. If `policy` is [`TeardownPolicy::DeleteDevice`] AND the token resolves to
///    [`TokenMetadata`] AND a Synapse client + `server_name` are configured,
///    delete that session's Synapse device (best-effort: a failure is logged at
///    `warn!` and does not abort). [`TeardownPolicy::TokensOnly`] skips this
///    entirely, so a bare RFC 7009 revoke never destroys a device.
/// 2. Always revoke the OAuth tokens for the session: every token for
///    `(username, device_id)` in Redis (access + paired refresh), or just the
///    presented token when there is no device_id / no Synapse integration.
///
/// `required` is the token kind the caller accepts: `Some(Access)` for logout,
/// whose bearer must be an access token, and `None` for RFC 7009 revoke, which
/// accepts either kind. A token of another kind is answered like an unknown
/// token: nothing is torn down and the token itself is left untouched.
///
/// `grants` is whose sessions the route ends: [`Grants::Matrix`] refuses a token
/// of a grant the Matrix routes do not act on ([`CompatState::acts_on`]) with
/// [`Teardown::Refused`], after the kind check and before anything is touched.
///
/// A token-store fault is returned, not swallowed: logout answers it with the
/// retryable 503 and leaves the bearer in place for the retry, while RFC 7009
/// revocation still deletes what it can ([`TeardownFault::fallback`]) and
/// answers 200. Keyed on [`TokenMetadata::username`] (the lowercased localpart
/// Synapse uses), never the raw DID, so revocation is robust to address-case
/// differences between sign-in and re-auth DIDs.
async fn teardown_session(
    state: &CompatState,
    token: &str,
    ctx: &str,
    policy: TeardownPolicy,
    required: Option<TokenKind>,
    grants: Grants,
) -> Result<Teardown, TeardownFault> {
    let meta = match resolve_presented(state, token).await {
        Ok(Some(m)) => m,
        // Unknown token: an idempotent no-op.
        Ok(None) => return Ok(Teardown::Done),
        Err(error) => {
            return Err(TeardownFault {
                error: error.context("token lookup"),
                fallback: Fallback::AnyLayout,
            })
        }
    };
    if required.is_some_and(|kind| meta.kind != Some(kind)) {
        debug!(
            ctx,
            "teardown_session: token of another kind; nothing to tear down"
        );
        return Ok(Teardown::Done);
    }
    let acts = match grants {
        Grants::Matrix => state.acts_on(meta.grant_kind),
        Grants::Any => true,
    };
    if !acts {
        debug!(
            ctx,
            "teardown_session: grant of another relying party; nothing to tear down"
        );
        return Ok(Teardown::Refused);
    }
    // Phase 1: delete the ending session's Synapse device (best-effort) — only for
    // explicit-sign-out callers. A bare RFC 7009 revoke (TokensOnly) must never
    // delete a device: that is what wedged users in the 2026-06-12 login incident.
    if policy.deletes_device(meta.grant_kind) {
        if let (Some(synapse), Some(server_name)) =
            (state.synapse_client.as_ref(), state.server_name.as_deref())
        {
            if meta.device_id.is_empty() {
                debug!(
                    ctx,
                    username = %meta.username,
                    "teardown_session: token has no device_id; skipping Synapse device delete"
                );
            } else if synapse.strict_teardown() {
                // Flag 1: the whole teardown, revoke included, in the 8.23 order.
                return match strict_teardown_device(
                    &state.redis_client,
                    synapse,
                    server_name,
                    &meta.username,
                    &meta.device_id,
                    ctx,
                )
                .await
                {
                    Ok(revoked) => {
                        info!(ctx, username = %meta.username, revoked = revoked as u64, "session torn down (strict)");
                        Ok(Teardown::Done)
                    }
                    Err(fault) => Err(TeardownFault {
                        error: anyhow::anyhow!("strict teardown stopped at {fault:?}"),
                        fallback: Fallback::Retry,
                    }),
                };
            } else if let Err(fault) = best_effort_delete_device(
                &state.redis_client,
                synapse,
                server_name,
                &meta.username,
                &meta.device_id,
                ctx,
            )
            .await
            {
                return Err(TeardownFault {
                    error: anyhow::anyhow!("teardown stopped at {fault:?}"),
                    fallback: Fallback::Retry,
                });
            }
        }
    }
    // Phase 2: revoke the OAuth session's tokens.
    //
    // Single-session semantics: in standalone mode every token carries an empty
    // device_id, so `revoke_device_tokens(username, "")` would match (and revoke)
    // EVERY session of that user. To keep single-session logout / revoke scoped to
    // the presented session (RFC 7009), revoke only the presented credential when
    // there is no device_id: an access token alone, or a refresh token's whole
    // grant (RFC 7009 §2.1; its live access token goes with it). In Synapse mode
    // the device_id is a unique `SIWX_{uuid}`, so revoking by (username,
    // device_id) correctly scopes to this one device's grants.
    if meta.device_id.is_empty() {
        return match delete_presented(state, token, meta.source).await {
            Ok(()) => {
                info!(
                    ctx,
                    username = %meta.username,
                    "session torn down (standalone, presented token only)"
                );
                Ok(Teardown::Done)
            }
            Err(error) => Err(TeardownFault {
                error: error.context("deleting the presented token"),
                fallback: Fallback::Nothing,
            }),
        };
    }
    // Phase 2 (device session): revoke this device's grants (access + refresh).
    match state
        .redis_client
        .revoke_device_tokens(&meta.username, &meta.device_id)
        .await
    {
        Ok(revoked) => {
            info!(
                ctx,
                username = %meta.username,
                device_id = %meta.device_id,
                revoked = revoked as u64,
                "session torn down"
            );
            Ok(Teardown::Done)
        }
        Err(error) => Err(TeardownFault {
            error: error.context("revoke_device_tokens"),
            fallback: Fallback::Presented(meta.source),
        }),
    }
}

/// Whose sessions a teardown route ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grants {
    /// A Matrix route: the grants [`CompatState::acts_on`] allows.
    Matrix,
    /// RFC 7009 revocation: the holder of any token may end it, whatever grant
    /// it belongs to.
    Any,
}

/// What a [`teardown_session`] that found no fault did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Teardown {
    /// The session was ended, or there was nothing to end: an unknown token, or
    /// one of a kind the route does not take.
    Done,
    /// The token belongs to a grant the route does not act on
    /// ([`Grants::Matrix`]); nothing was touched.
    Refused,
}

/// A token-store fault during [`teardown_session`].
struct TeardownFault {
    error: anyhow::Error,
    /// What RFC 7009 revocation may still delete before its 200. Logout
    /// deletes nothing more: it answers 503 so the client retries with the
    /// same bearer, which a deleted access token would turn into a no-op
    /// while the device's refresh token lived on.
    fallback: Fallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fallback {
    /// The token's layout is unknown: delete it from both.
    AnyLayout,
    /// Delete only the presented credential, where it was found.
    Presented(TokenSource),
    /// Nothing more to try.
    Nothing,
    /// A strict teardown (flag 1) stopped: nothing more is deleted, every route
    /// answers the retryable 503 (RFC 7009 revocation too), and the retry runs
    /// the whole teardown again.
    Retry,
}

/// RFC 7009's best effort after a teardown fault: delete the presented
/// credential if possible; the endpoint answers 200 either way.
async fn revoke_fallback(state: &CompatState, token: &str, fault: TeardownFault) {
    warn!(error = %fault.error, "revoke: token store failed; deleting the presented token where possible");
    match fault.fallback {
        Fallback::AnyLayout => {
            let _ = state.redis_client.delete_access_token(token).await;
            if let Err(e) = state.redis_client.delete_token(token).await {
                warn!(error = %e, "revoke: delete_token (fallback) failed");
            }
        }
        Fallback::Presented(source) => {
            if let Err(e) = delete_presented(state, token, source).await {
                warn!(error = %e, "revoke: deleting the presented token (last resort) failed");
            }
        }
        Fallback::Nothing | Fallback::Retry => {}
    }
}

/// Where a presented token is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSource {
    /// A grant's access token (`at/{digest}`).
    GrantAccess,
    /// A grant's refresh token that the refresh endpoints would accept now.
    GrantRefresh,
    /// A `token/{raw}` entry written before the grant record.
    Legacy,
}

/// What teardown needs to know about a presented token.
struct PresentedToken {
    username: String,
    device_id: String,
    kind: Option<TokenKind>,
    /// The kind of the grant behind the token; `None` for a legacy entry.
    grant_kind: Option<GrantKind>,
    source: TokenSource,
}

/// Resolve a token for teardown: a grant's live access token, a grant's refresh
/// token the refresh endpoints would accept (a superseded one is unknown), or a
/// legacy entry.
///
/// A legacy refresh token already lifted counts as its grant's previous token
/// (`resolve_refresh_token` follows the `legacy_rt/…` pointer). The legacy read
/// stays while legacy entries can still be presented: access entries for at
/// most 900 s after the upgrade, refresh entries never presented for up to 90
/// days (`REFRESH_TOKEN_TTL`); remove it one release after that.
async fn resolve_presented(
    state: &CompatState,
    token: &str,
) -> anyhow::Result<Option<PresentedToken>> {
    if let Some(access) = state.redis_client.lookup_access_token(token).await? {
        return Ok(Some(PresentedToken {
            username: access.grant.username,
            device_id: access.grant.device_id,
            kind: Some(TokenKind::Access),
            grant_kind: Some(access.grant.kind),
            source: TokenSource::GrantAccess,
        }));
    }
    if let Some(grant) = state.redis_client.resolve_refresh_token(token).await? {
        return Ok(Some(PresentedToken {
            username: grant.username,
            device_id: grant.device_id,
            kind: Some(TokenKind::Refresh),
            grant_kind: Some(grant.kind),
            source: TokenSource::GrantRefresh,
        }));
    }
    Ok(state.redis_client.get_token(token).await?.map(|m| {
        let kind = [TokenKind::Access, TokenKind::Refresh]
            .into_iter()
            .find(|k| m.is_kind(*k));
        PresentedToken {
            username: m.username,
            device_id: m.device_id,
            kind,
            grant_kind: None,
            source: TokenSource::Legacy,
        }
    }))
}

/// Delete only the presented credential: an access token's entry (its grant
/// stays), a refresh token's whole grant (D-M1-1, RFC 7009 §2.1), or a legacy
/// entry.
async fn delete_presented(
    state: &CompatState,
    token: &str,
    source: TokenSource,
) -> anyhow::Result<()> {
    match source {
        TokenSource::GrantAccess => state
            .redis_client
            .delete_access_token(token)
            .await
            .map(|_| ()),
        TokenSource::GrantRefresh => state
            .redis_client
            .revoke_grant_of_token(token)
            .await
            .map(|_| ()),
        TokenSource::Legacy => state.redis_client.delete_token(token).await,
    }
}

// -- POST /oauth2/revoke (RFC 7009) -------------------------------------------

pub async fn revoke(
    State(state): State<CompatState>,
    axum::extract::Form(form): axum::extract::Form<RevokeForm>,
) -> StatusCode {
    // Flag 1 off: RFC 7009 is token hygiene, not a device sign-out: revoke tokens
    // only, never delete the Synapse device. Flag 1 on: a Matrix-credential
    // grant's revoke ends the session including its device, strictly (see
    // TeardownPolicy).
    // Either kind of token may be revoked, of any grant: the holder of a token
    // may always end it.
    let strict = state
        .synapse_client
        .as_ref()
        .is_some_and(|s| s.strict_teardown());
    if let Err(fault) = teardown_session(
        &state,
        &form.token,
        "revoke",
        TeardownPolicy::revoke(strict),
        None,
        Grants::Any,
    )
    .await
    {
        if fault.fallback == Fallback::Retry {
            // RFC 7009 2.2.1: the server may answer 503; the token is still valid.
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        revoke_fallback(&state, &form.token, fault).await;
    }
    StatusCode::OK
}

// -- GET /_matrix/client/v3/login ---------------------------------------------

pub async fn login_flows() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "flows": [{
            "type": "m.login.sso",
            "identity_providers": [{
                "id": "siwx-oidc",
                "name": "Sign in with Wallet"
            }]
        }]
    }))
}

// -- POST /_matrix/client/v3/logout -------------------------------------------

/// Single-session logout: tears down the session bound to the bearer token
/// (Synapse device + Redis tokens). Returns 200 with `{}` (Matrix expects an
/// empty object), also with no bearer or an unknown token, and the retryable
/// 503 of the refresh and device-deletion routes when the token store fails:
/// a sign-out never reports success while revoking nothing. The same goes for
/// a bearer that is the grant of another relying party
/// ([`CompatState::acts_on`]: a generic-class client's, with delegated auth):
/// it is not a Matrix session, so it is a 401 `M_UNKNOWN_TOKEN` and nothing is
/// torn down; `POST /oauth2/revoke` is where such a token is ended.
pub async fn logout(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    if let Some(TypedHeader(auth)) = bearer {
        // Explicit single-session sign-out: revoke tokens AND delete the device.
        // The bearer must be an access token.
        match teardown_session(
            &state,
            auth.token(),
            "logout",
            TeardownPolicy::DeleteDevice,
            Some(TokenKind::Access),
            Grants::Matrix,
        )
        .await
        {
            Ok(Teardown::Done) => {}
            Ok(Teardown::Refused) => return unknown_token_response(),
            Err(fault) => {
                warn!(error = %fault.error, "logout: token store failed (infrastructure); returning retryable 503");
                return token_store_unavailable();
            }
        }
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- POST /_matrix/client/v3/logout/all ---------------------------------------

/// Bulk sign-out: invalidates EVERY session of the bearer token's user.
///
/// Resolves the user from the bearer token, ends the user's own sessions on
/// this provider (the `siwx_user` picker hints and `acct_session` account
/// sessions), then (when Synapse + `server_name` are configured) lists the
/// user's Synapse devices and deletes each one best-effort (a per-device
/// failure is logged and the loop continues), and finally revokes ALL of the
/// user's OAuth tokens in Redis.
///
/// This is session invalidation, NOT account deactivation: the account stays
/// active and the user can sign in again. It therefore must NEVER call
/// `deactivate_user`. Degrades to Redis-only revocation in standalone mode, is
/// an idempotent 200 no-op when the bearer token is missing or unknown, and
/// answers a token-store fault with the retryable 503. A bearer that is the
/// grant of another relying party ([`CompatState::acts_on`]: a generic-class
/// client's, with delegated auth) is not the user's Matrix session and may not
/// end it: it is a 401 `M_UNKNOWN_TOKEN`, not the 200 of a sign-out that
/// happened, and nothing is touched.
///
/// The order is what makes that 503 retryable: every step is idempotent, and
/// the grants, and with them the bearer, go last. A fault ending the own
/// sessions deletes no grant, so the retry with the same bearer runs the whole
/// sign-out again. Revoking the grants first turned that retry into an unknown
/// token, a 200 that left the own sessions live (an `acct_session` authorizes
/// device deletion, deactivation and erasure for 600 s).
///
/// Residual: a fault in the grant sweep after its script wrote the user epoch
/// (inside the script, which does not roll back, or in the legacy `token/*`
/// loop after it) answers 503, and the epoch already refuses the bearer, so the
/// retry is the 200 no-op. By then the own sessions
/// are ended and the epoch refuses every grant of the user at every endpoint,
/// so nothing the user holds still works; what stays behind are the grants the
/// script did not reach, with their index entries, refused until their TTL, and
/// their back-channel logout tokens: an OIDC grant the sweep did not delete
/// gets one only when its RP next tries to refresh it (the rotation deletes an
/// epoch-refused grant through `drop_grant`), never if it does not.
pub async fn logout_all(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    let Some(TypedHeader(auth)) = bearer else {
        return (StatusCode::OK, Json(serde_json::json!({})));
    };

    let meta = match state.redis_client.check_access_token(auth.token()).await {
        // The bearer must be an access token; any other entry is a no-op like an
        // unknown token.
        Ok(Some(m)) if state.acts_on(m.grant_kind) => m,
        Ok(Some(_)) => return unknown_token_response(),
        Ok(None) => return (StatusCode::OK, Json(serde_json::json!({}))), // idempotent no-op
        Err(e) => {
            warn!(error = %e, "logout_all: token lookup failed (infrastructure); returning retryable 503");
            return token_store_unavailable();
        }
    };
    let username = meta.username;
    let did = meta.did;
    let own_device = meta.device_id;

    // Phase 1: the user's own sessions on this provider, BEFORE any grant is
    // touched, so a fault here leaves the bearer for the retry (see above). A
    // minted admin token carries no DID and has none.
    if !did.is_empty() {
        match state.redis_client.revoke_own_sessions(&did).await {
            Ok(ended) => info!(username = %username, ended = ended as u64, "own sessions ended"),
            Err(e) => {
                warn!(error = %e, username = %username, "logout_all: revoke_own_sessions failed; returning retryable 503");
                return token_store_unavailable();
            }
        }
    }

    // Phase 2: delete every Synapse device for the user (best-effort per device).
    // Flag 1: strict per device (delete, marker, revoke); a failed device does not
    // stop the loop, and any failure answers 503 before phase 3.
    if let (Some(synapse), Some(server_name)) =
        (state.synapse_client.as_ref(), state.server_name.as_deref())
    {
        if synapse.strict_teardown() {
            let devices = match synapse.list_devices(&username, server_name).await {
                Ok(devices) => devices,
                Err(e) => {
                    warn!(error = %e, username = %username,
                        "logout_all: Synapse list_devices failed (strict); nothing revoked, returning retryable 503");
                    return token_store_unavailable();
                }
            };
            let ids: Vec<String> = devices.into_iter().map(|d| d.device_id).collect();
            if !strict_teardown_devices(
                &state,
                synapse,
                server_name,
                &username,
                &ids,
                &own_device,
                "logout_all",
            )
            .await
            {
                return token_store_unavailable();
            }
        } else {
            match synapse.list_devices(&username, server_name).await {
                Ok(devices) => {
                    // Flag 2: a marker that could not be written answers 503
                    // before phase 3 (the loop continues; the retry is idempotent).
                    let mut marked = true;
                    for dev in devices {
                        marked &= best_effort_delete_device(
                            &state.redis_client,
                            synapse,
                            server_name,
                            &username,
                            &dev.device_id,
                            "logout_all",
                        )
                        .await
                        .is_ok();
                    }
                    if !marked {
                        return token_store_unavailable();
                    }
                }
                Err(e) => {
                    warn!(error = %e, username = %username,
                    "logout_all: Synapse list_devices failed; revoking Redis tokens anyway");
                }
            }
        }
    }

    // Phase 3, last: ALWAYS revoke every OAuth token for the user (never
    // deactivate). The script writes the user epoch before it deletes a grant;
    // a fault after that write is the residual described above.
    match state.redis_client.revoke_all_user_tokens(&username).await {
        Ok(revoked) => {
            info!(username = %username, revoked = revoked as u64, "all sessions torn down")
        }
        Err(e) => {
            warn!(error = %e, username = %username, "logout_all: revoke_all_user_tokens failed; returning retryable 503");
            return token_store_unavailable();
        }
    }

    (StatusCode::OK, Json(serde_json::json!({})))
}

// -- Legacy CS-API device management (MSC3861 delegated) ----------------------
//
// Element's in-client "session manager" signs a device out with the legacy CS
// API (`DELETE /_matrix/client/v3/devices/{id}` or `POST .../delete_devices`),
// NOT the MSC4191 account-page deep link. Under MSC3861 the homeserver delegates
// auth, so — when the deployment proxies these specific paths to siwx-oidc — we
// service them here: resolve the user from their bearer token, delete the target
// Synapse device via the MAS API (`/_synapse/mas/delete_device`), and revoke that
// device's OAuth tokens. This is the same safe "delete an ending device" teardown
// as logout (the id is never reused), just initiated by the client's session
// manager.
//
// We accept the bearer as sufficient authorization (no UIA challenge): auth is
// delegated to us, so a valid access token already proves the caller, mirroring
// how MAS makes delegated device deletion UIA-free.

/// Body of `POST /_matrix/client/v3/delete_devices`.
#[derive(Deserialize)]
pub struct DeleteDevicesRequest {
    #[serde(default)]
    pub devices: Vec<String>,
}

/// Resolve the bearer token to its owning localpart (`TokenMetadata.username`).
///
/// `Ok(None)` when the token is missing, unknown, not an access token, or the
/// grant of a relying party these routes do not act for
/// ([`CompatState::acts_on`]): the route answers `M_UNKNOWN_TOKEN`. `Err` when
/// the store could not answer: the route answers the retryable 503
/// (`token_store_unavailable`), never `M_UNKNOWN_TOKEN`, which a Matrix client
/// takes for "signed out".
async fn username_from_bearer(
    state: &CompatState,
    bearer: &Option<TypedHeader<Authorization<Bearer>>>,
) -> anyhow::Result<Option<(String, String)>> {
    let Some(TypedHeader(auth)) = bearer.as_ref() else {
        return Ok(None);
    };
    Ok(state
        .redis_client
        .check_access_token(auth.token())
        .await?
        .filter(|m| state.acts_on(m.grant_kind))
        .map(|m| (m.username, m.device_id)))
}

/// The bearer's owner and its own device id for a device-deletion route, or the
/// response to send: `M_UNKNOWN_TOKEN` for an unknown bearer, the retryable 503
/// for a store fault.
async fn bearer_owner(
    state: &CompatState,
    bearer: &Option<TypedHeader<Authorization<Bearer>>>,
    ctx: &str,
) -> Result<(String, String), (StatusCode, Json<serde_json::Value>)> {
    match username_from_bearer(state, bearer).await {
        Ok(Some(owner)) => Ok(owner),
        Ok(None) => Err(unknown_token_response()),
        Err(e) => {
            warn!(error = %e, ctx, "bearer lookup: token store failed (infrastructure); returning retryable 503");
            Err(token_store_unavailable())
        }
    }
}

/// Strict teardown (flag 1) of each of `username`'s `devices`, the bearer's
/// `own_device` last and only when every other one was torn down, so a 503 leaves
/// the bearer for the retry. One failed device does not stop the loop. Returns
/// whether every device was torn down (the route answers 503 otherwise).
async fn strict_teardown_devices(
    state: &CompatState,
    synapse: &SynapseClient,
    server_name: &str,
    username: &str,
    devices: &[String],
    own_device: &str,
    ctx: &str,
) -> bool {
    let mut all = true;
    let mut own = false;
    for device_id in devices {
        if device_id.is_empty() {
            continue;
        }
        if device_id == own_device {
            own = true;
            continue;
        }
        all &= strict_teardown_device(
            &state.redis_client,
            synapse,
            server_name,
            username,
            device_id,
            ctx,
        )
        .await
        .is_ok();
    }
    if own && all {
        all = strict_teardown_device(
            &state.redis_client,
            synapse,
            server_name,
            username,
            own_device,
            ctx,
        )
        .await
        .is_ok();
    }
    if !all {
        warn!(ctx, username = %username, "strict teardown: a device was not torn down; returning retryable 503");
    }
    all
}

/// Delete one of `username`'s Synapse devices (MAS API) and revoke its tokens.
/// Best-effort, idempotent, never fails the caller — same teardown as logout —
/// except a deleted-id marker that could not be written (flag 2): then nothing
/// is revoked and it answers `false` (the route answers 503).
/// Flag 1 runs [`strict_teardown_devices`] instead (the routes do).
async fn teardown_device(state: &CompatState, username: &str, device_id: &str, ctx: &str) -> bool {
    if device_id.is_empty() {
        return true;
    }
    if let (Some(synapse), Some(server_name)) =
        (state.synapse_client.as_ref(), state.server_name.as_deref())
    {
        if best_effort_delete_device(
            &state.redis_client,
            synapse,
            server_name,
            username,
            device_id,
            ctx,
        )
        .await
        .is_err()
        {
            return false;
        }
    }
    match state
        .redis_client
        .revoke_device_tokens(username, device_id)
        .await
    {
        Ok(revoked) => info!(
            ctx,
            username = %username, device_id = %device_id, revoked = revoked as u64,
            "compat device torn down"
        ),
        Err(e) => warn!(error = %e, ctx, "compat device teardown: revoke_device_tokens failed"),
    }
    true
}

const UNKNOWN_TOKEN: &str = "M_UNKNOWN_TOKEN";

fn unknown_token_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "errcode": UNKNOWN_TOKEN,
            "error": "Invalid or missing access token"
        })),
    )
}

/// `DELETE /_matrix/client/v3/devices/{device_id}` — sign out a single device
/// from the in-client session manager. Scoped to the bearer's user (a foreign
/// device id is a no-op, since the MAS delete is scoped to the user's localpart).
pub async fn delete_device(
    State(state): State<CompatState>,
    Path(device_id): Path<String>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    let (username, own) = match bearer_owner(&state, &bearer, "compat_delete_device").await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    teardown_devices(
        &state,
        &username,
        &[device_id],
        &own,
        "compat_delete_device",
    )
    .await
}

/// The device routes' teardown: strict under flag 1 (503 if a device failed),
/// else best-effort per device and 200.
async fn teardown_devices(
    state: &CompatState,
    username: &str,
    devices: &[String],
    own: &str,
    ctx: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    if let (Some(synapse), Some(server_name)) =
        (state.synapse_client.as_ref(), state.server_name.as_deref())
    {
        if synapse.strict_teardown() {
            if !strict_teardown_devices(state, synapse, server_name, username, devices, own, ctx)
                .await
            {
                return token_store_unavailable();
            }
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    }
    let mut marked = true;
    for device_id in devices {
        marked &= teardown_device(state, username, device_id, ctx).await;
    }
    if !marked {
        return token_store_unavailable();
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /_matrix/client/v3/delete_devices` — bulk sign-out of specific devices.
pub async fn delete_devices(
    State(state): State<CompatState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(body): Json<DeleteDevicesRequest>,
) -> impl IntoResponse {
    let (username, own) = match bearer_owner(&state, &bearer, "compat_delete_devices").await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    teardown_devices(
        &state,
        &username,
        &body.devices,
        &own,
        "compat_delete_devices",
    )
    .await
}

// -- POST /_matrix/client/v3/refresh ------------------------------------------

/// 503 for a token-store fault during a refresh or a bearer lookup: retryable,
/// never `M_UNKNOWN_TOKEN`.
fn token_store_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": "Token store temporarily unavailable; retry"
        })),
    )
}

/// `POST /_matrix/client/v3/refresh` (MSC2918): rotate a refresh token.
///
/// **Public clients only.** The OAuth refresh grant (`oidc::token_refresh`)
/// checks that the request comes from the client the token was issued to and
/// authenticates a confidential one (I7). The Matrix client-server API gives
/// this request no client identity (the body is the refresh token and nothing
/// else), so this endpoint cannot authenticate a client: it refuses, exactly
/// like an unknown token, the refresh token of a grant whose client is
/// confidential (recorded on the grant at issuance by
/// `oidc::client_is_confidential`, the rule the token endpoint applies), and
/// leaves it untouched for `POST /token`. A public client's token needs no
/// authentication, so this endpoint is bound as far as the binding reaches at
/// `POST /token` without a named client. Matrix clients (Element Web, Element
/// X) register as public clients. Do not "fix" the rest by demanding a client
/// here: no Matrix client can send one.
///
/// **Matrix sessions only, with delegated auth.** The refresh token of a grant
/// that is not a Matrix credential ([`CompatState::acts_on`]: a generic-class
/// client's `oidc` grant, or a legacy token the lift would turn into one) is
/// refused exactly like an unknown token before any script runs, and left as it
/// was for `POST /token`, where its client is authenticated and its grant
/// rotates. It is a decision on the kind the grant was issued with, which never
/// changes, so it needs no place in the rotation script.
///
/// Rotation, the replay of a lost response and the refusals are the rotation
/// script's (`RedisClient::rotate_refresh_token`), the same one `POST /token`
/// runs.
pub async fn refresh(
    State(state): State<CompatState>,
    Json(body): Json<RefreshRequest>,
) -> impl IntoResponse {
    // The one rotation script (I3) decides atomically: rotate, replay the
    // unused successor of a lost response (I4), or refuse. No client is named
    // (this endpoint has none), and a confidential client's grant is refused
    // (see above). A legacy refresh token (`token/{raw}`, written before the
    // grant record) is lifted into a grant instead (design 5.8), unless its
    // client is confidential: the same rule, decided by `client_is_confidential`
    // as at every issuance, and the legacy token is left for `POST /token`.
    let request = RotateRequest {
        presented: &body.refresh_token,
        client_id: None,
        refuse_confidential: true,
    };
    let peeked = state
        .redis_client
        .peek_refresh_token(&body.refresh_token)
        .await;
    if let Ok(peek) = &peeked {
        if !state.acts_on(peek.grant_kind()) {
            debug!("refresh refused: grant of another relying party");
            return invalid_refresh_token("Invalid refresh token");
        }
    }
    // S5: the guest refresh guard (deadline, `reaping`, kill switch, unrecorded device):
    // 400 `invalid_grant` so the portal signs out; a read error is a retryable 503.
    if let Ok(RefreshPeek::Grant(grant)) = &peeked {
        match crate::guest::handoff::guest_refresh_allowed(
            state.guest_client_id.as_deref(),
            &state.redis_client,
            grant,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                debug!("refresh refused: guest session ended");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "The guest session has ended.",
                        "errcode": "M_UNKNOWN_TOKEN"
                    })),
                );
            }
            Err(e) => {
                warn!(error = %e, "refresh: guest guard read failed; returning retryable 503");
                return token_store_unavailable();
            }
        }
    }
    // The client the token belongs to, for the lifetime touch after an accepted refresh:
    // never a request field, which this endpoint does not have.
    let bound_client = match &peeked {
        Ok(RefreshPeek::Grant(grant)) => Some(grant.client_id.clone()),
        Ok(RefreshPeek::Legacy(legacy)) => Some(legacy.meta.client_id.clone()),
        Ok(RefreshPeek::Unknown) | Err(_) => None,
    };
    let outcome = match peeked {
        Ok(RefreshPeek::Legacy(legacy)) => {
            match state
                .redis_client
                .get_client(legacy.meta.client_id.clone())
                .await
            {
                Ok(client) => {
                    let confidential =
                        crate::oidc::client_is_confidential(client.as_ref(), state.require_secret);
                    state
                        .redis_client
                        .lift_legacy_refresh_token(&request, &legacy, confidential)
                        .await
                }
                Err(e) => Err(e),
            }
        }
        Ok(RefreshPeek::Grant(_)) | Ok(RefreshPeek::Unknown) => {
            state.redis_client.rotate_refresh_token(&request).await
        }
        Err(e) => Err(e),
    };
    let (pair, expires_in) = match outcome {
        Ok(RotateOutcome::Rotated(pair)) | Ok(RotateOutcome::Replayed(pair)) => {
            let expires_in = pair.expires_in(ACCESS_TOKEN_TTL);
            (pair.pair, expires_in)
        }
        // Reuse (I5, phase A): recorded, and answered like an unknown token.
        Ok(RotateOutcome::Reuse(event)) => {
            event.emit();
            return invalid_refresh_token("Invalid refresh token");
        }
        Ok(RotateOutcome::Invalid(InvalidReason::Revoked)) => {
            debug!("refresh refused: device/account torn down");
            return invalid_refresh_token("Session has been revoked");
        }
        // `NotCurrentFormat`: neither a token in the current format, nor a
        // legacy refresh token (lifted above), nor one already lifted: garbage
        // or another kind of token. `ConfidentialClient`: a client this endpoint cannot authenticate
        // (see above), answered like an unknown token. `ClientMismatch` cannot
        // happen: no client is named.
        Ok(RotateOutcome::Invalid(_))
        | Ok(RotateOutcome::ClientMismatch)
        | Ok(RotateOutcome::ConfidentialClient) => {
            return invalid_refresh_token("Invalid refresh token");
        }
        Err(e) => {
            // Infrastructure failure, NOT an authorization failure. `M_UNKNOWN_TOKEN`
            // is terminal for a Matrix client (it signs out and clears its crypto
            // store, and under MSC3861 Synapse never offers a soft logout), so
            // reporting a Redis error that way would turn a transient fault into
            // permanent session and cryptographic-identity loss. 503 is retryable,
            // and the script either ran entirely or not at all.
            warn!(error = %e, "refresh: token store failed (infrastructure); returning retryable 503");
            return token_store_unavailable();
        }
    };

    debug!("refresh: tokens rotated successfully");
    if let Some(client_id) = &bound_client {
        crate::oidc::touch_client_after_use(&state.redis_client, client_id).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": pair.access_token,
            "expires_in_ms": expires_in * 1000,
            "refresh_token": pair.refresh_token,
        })),
    )
}

/// `M_UNKNOWN_TOKEN` for a refresh token this endpoint refuses.
fn invalid_refresh_token(error: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "errcode": "M_UNKNOWN_TOKEN",
            "error": error
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Form, State};
    use axum::response::IntoResponse;
    use chrono::Utc;
    use siwx_oidc::db::grant::{EpochScope, GrantKind, IssuedGrant, NewGrant};
    use siwx_oidc::db::tokens;
    use siwx_oidc::db::{DBClient, OwnSession, TokenMetadata, REFRESH_TOKEN_TTL};
    use std::collections::HashMap;

    /// The test Redis, or `None` after a loud skip (`siwx_oidc::test_support`).
    async fn redis() -> Option<RedisClient> {
        siwx_oidc::test_support::redis().await
    }

    /// A unique nonce so parallel tests / stale entries never collide on the
    /// shared Redis instance. The nanosecond clock alone can collide across tests
    /// that start in the same instant on different threads, so a process-wide
    /// atomic counter is OR'd in to guarantee uniqueness for any run subset.
    fn nonce() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        (base << 20) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF)
    }

    fn token_meta(username: &str, device_id: &str) -> TokenMetadata {
        TokenMetadata {
            username: username.to_string(),
            device_id: device_id.to_string(),
            scope: "openid".to_string(),
            client_id: "c".to_string(),
            iat: 0,
            exp: i64::MAX,
            // did is stored verbatim from sign-in; revocation keys on username,
            // so the did case here intentionally differs from the username.
            did: format!("did:pkh:eip155:1:0X{}", username.to_uppercase()),
            name: "n".to_string(),
            kind: Some(TokenKind::Access),
            grant_kind: None,
        }
    }

    fn refresh_meta(username: &str, device_id: &str) -> TokenMetadata {
        TokenMetadata {
            kind: Some(TokenKind::Refresh),
            ..token_meta(username, device_id)
        }
    }

    /// Standalone-mode state: Redis only, no Synapse client / server_name.
    fn standalone_state(redis_client: RedisClient) -> CompatState {
        CompatState {
            redis_client,
            require_secret: true,
            synapse_client: None,
            server_name: None,
            delegated_auth: false,
            guest_client_id: None,
        }
    }

    fn bearer(token: &str) -> Option<TypedHeader<Authorization<Bearer>>> {
        Some(TypedHeader(Authorization::bearer(token).unwrap()))
    }

    /// Policy mapping (no Redis needed). Flag 1 off: only an explicit sign-out
    /// deletes the Synapse device; a bare RFC 7009 revoke must not (regression
    /// guard for the 2026-06-12 login incident, where revoke deleted a device on
    /// every dialog escape while a session of it was still live). Flag 1 on: a
    /// revoke of a Matrix-credential grant deletes its device (MAS parity; safe
    /// because the revoke ends every token of the device and device ids are
    /// never reused), any other grant keeps tokens-only.
    #[test]
    fn teardown_policy_only_deletes_device_on_explicit_signout() {
        for kind in [
            None,
            Some(GrantKind::MatrixDevice),
            Some(GrantKind::Service),
            Some(GrantKind::Oidc),
        ] {
            assert!(
                !TeardownPolicy::revoke(false).deletes_device(kind),
                "flag 1 off: RFC 7009 revoke must never delete the Synapse device"
            );
            assert!(
                TeardownPolicy::DeleteDevice.deletes_device(kind),
                "explicit logout must delete the ending session's device"
            );
            assert_eq!(
                TeardownPolicy::revoke(true).deletes_device(kind),
                grant::is_matrix_credential(kind),
                "flag 1 on: revoke deletes the device of a Matrix credential only ({kind:?})"
            );
        }
        assert!(!TeardownPolicy::revoke(true).deletes_device(Some(GrantKind::Oidc)));
    }

    /// H7: standalone (no Synapse) logout still revokes the session's Redis
    /// tokens (access + paired refresh) and returns 200.
    #[tokio::test]
    async fn logout_standalone_revokes_session_tokens() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("logout-user-{n}");
        let dev = format!("DEV_{n}");
        let access = format!("compat_logout_access_{n}");
        let refresh = format!("compat_logout_refresh_{n}");
        let other = format!("compat_logout_other_{n}");

        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        // Same user, different device: must survive a single-session logout.
        client
            .set_token(&other, &token_meta(&user, &format!("OTHER_{n}")), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout(State(state), bearer(&access)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&access).await.unwrap().is_none(),
            "access token of the session must be revoked"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "paired refresh token (same device) must be revoked"
        );
        assert!(
            client.get_token(&other).await.unwrap().is_some(),
            "another device's token must survive a single-session logout"
        );

        client.delete_token(&other).await.ok();
    }

    /// HIGH-defect regression guard: in standalone mode EVERY token carries an
    /// empty device_id, so `revoke_device_tokens(user, "")` would match every
    /// session of that user. A single-session logout must revoke ONLY the
    /// presented token (RFC 7009 / single-session semantics), leaving the user's
    /// other standalone sessions intact.
    #[tokio::test]
    async fn logout_standalone_empty_device_id_revokes_only_presented_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("empty-dev-user-{n}");
        let session_a = format!("compat_empty_a_{n}");
        let session_b = format!("compat_empty_b_{n}");

        // Two distinct standalone sessions for the SAME user, both device_id == "".
        client
            .set_token(&session_a, &token_meta(&user, ""), 120)
            .await
            .unwrap();
        client
            .set_token(&session_b, &token_meta(&user, ""), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout(State(state), bearer(&session_a))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&session_a).await.unwrap().is_none(),
            "the presented session token must be revoked"
        );
        assert!(
            client.get_token(&session_b).await.unwrap().is_some(),
            "a DIFFERENT standalone session of the same user must survive a single logout"
        );

        client.delete_token(&session_b).await.ok();
    }

    /// The bearer of a logout, bulk logout or device deletion must be an access
    /// token. A refresh token there is answered like an unknown token: nothing
    /// is torn down, and the refresh token itself survives.
    #[tokio::test]
    async fn a_refresh_token_as_the_bearer_tears_nothing_down() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("kind-bearer-{n}");
        let dev = format!("KIND_{n}");
        let access = format!("compat_kind_access_{n}");
        let refresh = format!("compat_kind_refresh_{n}");
        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &refresh_meta(&user, &dev), 120)
            .await
            .unwrap();
        let state = standalone_state(client.clone());

        let resp = logout(State(state.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout answers 200");
        let resp = logout_all(State(state.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout/all answers 200");
        let resp = delete_device(State(state.clone()), Path(dev.clone()), bearer(&refresh))
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "device deletion refuses a refresh token as its bearer"
        );

        assert!(
            client.get_token(&access).await.unwrap().is_some(),
            "the session's access token survives"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_some(),
            "the presented refresh token is left untouched"
        );
        client.delete_token(&access).await.ok();
        client.delete_token(&refresh).await.ok();
    }

    /// `POST /_matrix/client/v3/refresh` with a refresh token: status and JSON body.
    async fn matrix_refresh(state: &CompatState, token: &str) -> (StatusCode, serde_json::Value) {
        let response = refresh(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: token.to_string(),
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// S5 on the compat refresh: a guest's session that is over (deadline, `reaping`,
    /// unrecorded device) is `400 invalid_grant`; a read error is a retryable 503; a live,
    /// recorded one and a non-guest client's rotate.
    #[tokio::test]
    async fn st11_the_compat_refresh_applies_the_guest_guard() {
        let Some(client) = redis().await else { return };
        let mut state = standalone_state(client.clone());
        state.guest_client_id = Some("compat-guest".into());
        let now = Utc::now().timestamp();
        let issue = |user: String, dev: String, cid: &'static str| {
            let client = client.clone();
            async move {
                client
                    .issue_grant(&NewGrant {
                        kind: GrantKind::MatrixDevice,
                        username: user.clone(),
                        did: format!("did:key:z{user}"),
                        client_id: cid.into(),
                        confidential_client: false,
                        device_id: dev,
                        scope: "openid".into(),
                        name: user,
                        auth_ms: None,
                        access_ttl: ACCESS_TOKEN_TTL,
                        refresh_inactivity_secs: Some(120),
                        absolute_deadline: None,
                    })
                    .await
                    .unwrap()
                    .refresh_token
                    .unwrap()
            }
        };
        let record = |user: String, st: &'static str, dev: &'static str| {
            let client = client.clone();
            async move {
                client
                    .put_guest_for_test(&user, &format!("did:key:z{user}"), st, 600, &user)
                    .await;
                client
                    .sadd_raw_for_test(&siwx_oidc::db::guest_records::devices_key(&user), dev)
                    .await;
            }
        };
        let u = |p: &str| format!("{p}{}", uuid::Uuid::new_v4().simple());

        // live and recorded
        let user = u("live");
        record(user.clone(), "active", "D1").await;
        let rt = issue(user, "D1".into(), "compat-guest").await;
        assert_eq!(matrix_refresh(&state, &rt).await.0, StatusCode::OK);

        // the deadline has passed
        let user = u("late");
        record(user.clone(), "active", "D1").await;
        client
            .hset_raw_for_test(
                &siwx_oidc::db::guest_invites::guest_account_key(&user),
                "deadline",
                &(now - 5).to_string(),
            )
            .await;
        let rt = issue(user, "D1".into(), "compat-guest").await;
        let (status, body) = matrix_refresh(&state, &rt).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        // reaping, and an unrecorded device
        let user = u("reap");
        record(user.clone(), "reaping", "D1").await;
        let rt = issue(user, "D1".into(), "compat-guest").await;
        assert_eq!(matrix_refresh(&state, &rt).await.0, StatusCode::BAD_REQUEST);
        let user = u("dev");
        record(user.clone(), "active", "D1").await;
        let rt = issue(user, "D9".into(), "compat-guest").await;
        assert_eq!(matrix_refresh(&state, &rt).await.0, StatusCode::BAD_REQUEST);

        // a read error is not an answer about the session
        let user = u("err");
        client
            .sadd_raw_for_test(&siwx_oidc::db::guest_invites::guest_account_key(&user), "x")
            .await;
        let rt = issue(user, "D1".into(), "compat-guest").await;
        assert_eq!(
            matrix_refresh(&state, &rt).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );

        // another client's grant is untouched, with no record at all
        let rt = issue(u("plain"), "D1".into(), "compat-test").await;
        assert_eq!(matrix_refresh(&state, &rt).await.0, StatusCode::OK);
    }

    /// A grant with a refresh token, for the refresh and revoke tests.
    async fn seed_grant(client: &RedisClient, user: &str, dev: &str) -> IssuedGrant {
        seed_grant_for(client, user, dev, false).await
    }

    /// A grant with a refresh token issued to a public or a confidential client.
    async fn seed_grant_for(
        client: &RedisClient,
        user: &str,
        dev: &str,
        confidential_client: bool,
    ) -> IssuedGrant {
        client
            .issue_grant(&NewGrant {
                kind: if dev.is_empty() {
                    GrantKind::Oidc
                } else {
                    GrantKind::MatrixDevice
                },
                username: user.to_string(),
                did: format!("did:key:z{user}"),
                client_id: "compat-test".into(),
                confidential_client,
                device_id: dev.to_string(),
                scope: "openid".into(),
                name: user.to_string(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: Some(120),
                absolute_deadline: None,
            })
            .await
            .unwrap()
    }

    /// `POST /_matrix/client/v3/refresh` carries no client identity, so it
    /// cannot authenticate a confidential client (I7): it refuses that client's
    /// refresh token exactly like an unknown token and leaves it untouched, so
    /// the client can still refresh at `POST /token` with its secret. A public
    /// client's token rotates there as before.
    #[tokio::test]
    async fn the_matrix_endpoint_refuses_a_confidential_clients_refresh_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("conf-user-{n}");
        let dev = format!("CONF_{n}");
        let state = standalone_state(client.clone());

        let never_issued = tokens::new_refresh_token(&tokens::new_grant_handle());
        let (_, unknown) = matrix_refresh(&state, &never_issued).await;
        let confidential = seed_grant_for(&client, &user, &dev, true)
            .await
            .refresh_token
            .unwrap();
        let (status, body) = matrix_refresh(&state, &confidential).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a confidential client's refresh token is refused: {body}"
        );
        assert_eq!(body, unknown, "refused exactly like an unknown token");
        let grant = client
            .resolve_refresh_token(&confidential)
            .await
            .unwrap()
            .expect("the refused token is still the grant's current refresh token");
        assert_eq!(grant.generation, 0, "the refusal rotated nothing");

        let public = seed_grant_for(&client, &user, &dev, false)
            .await
            .refresh_token
            .unwrap();
        let (status, body) = matrix_refresh(&state, &public).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a public client's token rotates: {body}"
        );

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// I5 phase A at `POST /_matrix/client/v3/refresh`, the endpoint every
    /// Matrix session refreshes at: a superseded refresh token (rotated twice,
    /// the first presented again) is answered like an unknown token and logged
    /// as exactly one reuse event that names the grant by its fingerprint and
    /// the branch, with no token in the logs.
    #[tokio::test]
    async fn the_matrix_endpoint_logs_one_reuse_event_for_a_superseded_refresh_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("reuse-user-{n}");
        let dev = format!("REUSE_{n}");
        let state = standalone_state(client.clone());
        let logs = siwx_oidc::test_support::LogCapture::start();

        let grant = seed_grant(&client, &user, &dev).await;
        let first = grant.refresh_token.clone().unwrap();
        let mut issued = vec![grant.access_token.clone(), first.clone()];
        let mut current = first.clone();
        for _ in 0..2 {
            let (status, body) = matrix_refresh(&state, &current).await;
            assert_eq!(status, StatusCode::OK, "the current token rotates: {body}");
            for field in ["access_token", "refresh_token"] {
                issued.push(body[field].as_str().unwrap().to_string());
            }
            current = body["refresh_token"].as_str().unwrap().to_string();
        }

        let (status, body) = matrix_refresh(&state, &first).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "reuse is refused: {body}");
        assert_eq!(
            body["errcode"], "M_UNKNOWN_TOKEN",
            "answered like an unknown token: {body}"
        );
        let output = logs.output();
        let events: Vec<&str> = output
            .lines()
            .filter(|l| l.contains(siwx_oidc::db::grant::REUSE_EVENT_MESSAGE))
            .collect();
        assert_eq!(events.len(), 1, "exactly one reuse event: {output}");
        let event = events[0];
        for field in [
            format!("grant_fp={}", grant.grant_id.fingerprint()),
            "branch=\"superseded\"".to_string(),
        ] {
            assert!(event.contains(&field), "the event carries {field}: {event}");
        }
        for secret in &issued {
            assert!(
                !output.contains(secret.as_str()),
                "no token in the logs: {output}"
            );
        }

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// I5 phase B at `POST /_matrix/client/v3/refresh`, with
    /// `reuse_revokes_grant` on: a superseded refresh token gets exactly the
    /// answer an unknown token gets, the event records the revocation, the
    /// grant is gone (the current token is refused too), and the Synapse
    /// device is never deleted: the homeserver is never contacted.
    #[tokio::test]
    async fn with_reuse_enforcement_the_matrix_endpoint_ends_the_grant_and_never_the_device() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let Some(base) = redis().await else { return };
        let client = base.clone().with_reuse_enforcement(true);
        let n = nonce();
        let user = format!("reuse-on-user-{n}");
        let dev = format!("REUSEON_{n}");

        // A homeserver that counts every connection made to it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let contacted = Arc::new(AtomicUsize::new(0));
        let counter = contacted.clone();
        let homeserver = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let state = CompatState {
            redis_client: client.clone(),
            require_secret: true,
            synapse_client: Some(Arc::new(SynapseClient::new(
                &format!("http://{addr}"),
                "secret",
            ))),
            server_name: Some("example.org".to_string()),
            delegated_auth: true,
            guest_client_id: None,
        };

        let grant = seed_grant(&client, &user, &dev).await;
        let first = grant.refresh_token.clone().unwrap();
        let mut current = first.clone();
        for _ in 0..2 {
            let (status, body) = matrix_refresh(&state, &current).await;
            assert_eq!(status, StatusCode::OK, "the current token rotates: {body}");
            current = body["refresh_token"].as_str().unwrap().to_string();
        }

        let unknown = matrix_refresh(&state, "mcr_not_a_token").await;
        let logs = siwx_oidc::test_support::LogCapture::start();
        let reused = matrix_refresh(&state, &first).await;
        assert_eq!(reused.0, StatusCode::UNAUTHORIZED);
        assert_eq!(reused.1["errcode"], "M_UNKNOWN_TOKEN");
        assert_eq!(reused, unknown, "answered exactly like an unknown token");
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
            client.peek_refresh_grant(&current).await.unwrap().is_none(),
            "the grant is gone"
        );
        assert_eq!(
            matrix_refresh(&state, &current).await,
            unknown,
            "the current holder is refused at its next refresh"
        );
        assert_eq!(
            contacted.load(Ordering::SeqCst),
            0,
            "the Synapse device is never deleted: the homeserver was not contacted"
        );
        homeserver.abort();
        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// Item 10 at the Matrix endpoint: a legacy refresh token (`token/{raw}`,
    /// written before the grant record) of a public client is lifted into a
    /// grant and answered in the current format; a confidential client's is
    /// refused like an unknown token and left as it was, for `POST /token`
    /// (the client registered without a method under `require_secret`).
    #[tokio::test]
    async fn the_matrix_endpoint_lifts_a_public_clients_legacy_token_but_not_a_confidential_ones() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let confidential_client = format!("legacy-conf-{n}");
        client
            .set_client(
                confidential_client.clone(),
                siwx_oidc::db::ClientEntry::new(
                    "s",
                    siwx_oidc::db::SiwxClientMetadata::new(
                        vec![
                            openidconnect::RedirectUrl::new("https://example.com/cb".into())
                                .unwrap(),
                        ],
                        siwx_oidc::db::LogoutClientMetadata::default(),
                    ),
                    None,
                ),
            )
            .await
            .unwrap();
        let seed = |client_id: String| {
            let client = client.clone();
            async move {
                let raw = format!("mcr_legacy{n}{client_id}");
                let mut meta = refresh_meta(&format!("legacy-user-{n}"), "");
                meta.client_id = client_id;
                meta.iat = Utc::now().timestamp();
                meta.exp = meta.iat + REFRESH_TOKEN_TTL as i64;
                client
                    .set_token(&raw, &meta, REFRESH_TOKEN_TTL)
                    .await
                    .unwrap();
                raw
            }
        };
        let (_, unknown) = matrix_refresh(&state, "mcr_never_issued_legacy").await;

        let refused = seed(confidential_client).await;
        let (status, body) = matrix_refresh(&state, &refused).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body, unknown, "refused exactly like an unknown token");
        assert!(
            client.get_token(&refused).await.unwrap().is_some(),
            "the refused legacy token is left for POST /token"
        );

        let public = seed(format!("legacy-unregistered-{n}")).await;
        let (status, body) = matrix_refresh(&state, &public).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a public client's legacy token is lifted: {body}"
        );
        let new_rt = body["refresh_token"].as_str().unwrap();
        assert!(
            tokens::parse_refresh_token(new_rt).is_some(),
            "current format: {body}"
        );
        assert!(
            client.get_token(&public).await.unwrap().is_none(),
            "legacy entry gone"
        );
        let grant = client.peek_refresh_grant(new_rt).await.unwrap().unwrap();
        assert!(
            !grant.confidential_client,
            "an unregistered client is public"
        );
    }

    /// R2 of the promotion plan at the Matrix endpoint: a LEGACY refresh
    /// token of an agent device whose client registered as public and whose
    /// registration is gone (registrations expire after 30 days, refresh
    /// tokens after 90 days unused) is lifted into a grant and answered in the
    /// current format; the grant keeps the device and the client and is
    /// public; the lifted token rotates again here.
    #[tokio::test]
    async fn a_legacy_token_whose_registration_is_gone_is_lifted_at_the_matrix_endpoint() {
        use openidconnect::core::CoreClientAuthMethod;
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let gone = format!("legacy-gone-{n}");
        let device = format!("AQUA_GONE{n}");
        client
            .set_client(
                gone.clone(),
                siwx_oidc::db::ClientEntry::new(
                    "s",
                    siwx_oidc::db::SiwxClientMetadata::new(
                        vec![
                            openidconnect::RedirectUrl::new("https://example.com/cb".into())
                                .unwrap(),
                        ],
                        siwx_oidc::db::LogoutClientMetadata::default(),
                    )
                    .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None)),
                    None,
                ),
            )
            .await
            .unwrap();
        let legacy = format!("mcr_legacygone{n}");
        let mut meta = refresh_meta(&format!("legacy-gone-user-{n}"), &device);
        meta.client_id = gone.clone();
        meta.scope = format!("openid urn:matrix:client:api:* urn:matrix:client:device:{device}");
        meta.iat = Utc::now().timestamp();
        meta.exp = meta.iat + REFRESH_TOKEN_TTL as i64;
        client
            .set_token(&legacy, &meta, REFRESH_TOKEN_TTL)
            .await
            .unwrap();
        client.delete_client(gone.clone()).await.unwrap();

        let (status, body) = matrix_refresh(&state, &legacy).await;
        assert_eq!(status, StatusCode::OK, "the legacy token is lifted: {body}");
        let new_rt = body["refresh_token"].as_str().unwrap().to_string();
        assert!(
            tokens::parse_refresh_token(&new_rt).is_some(),
            "current format: {body}"
        );
        assert!(
            client.get_token(&legacy).await.unwrap().is_none(),
            "legacy entry gone"
        );
        let grant = client.peek_refresh_grant(&new_rt).await.unwrap().unwrap();
        assert_eq!(grant.client_id, gone, "still bound to its client");
        assert_eq!(grant.device_id, device, "the device is kept");
        assert!(
            !grant.confidential_client,
            "a registration that is gone is public"
        );
        let (status, body) = matrix_refresh(&state, &new_rt).await;
        assert_eq!(status, StatusCode::OK, "the lifted token rotates: {body}");
        client
            .revoke_grants_for_device(&meta.username, &device)
            .await
            .ok();
    }

    /// A homeserver that answers `POST /_synapse/mas/delete_device` with 200
    /// and records each request body. Returns its base URL.
    async fn recording_homeserver() -> (
        String,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = bodies.clone();
        let app = axum::Router::new().route(
            "/_synapse/mas/delete_device",
            axum::routing::post(move |Json(body): Json<serde_json::Value>| {
                let recorded = recorded.clone();
                async move {
                    recorded.lock().unwrap().push(body);
                    Json(serde_json::json!({}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), bodies, server)
    }

    /// R3 of the promotion plan at the Matrix routes. An Element X device id
    /// is 43 base64 characters with `/` and `+`; it survives a rotation at
    /// `POST /_matrix/client/v3/refresh`, and it is torn down by a sign-out
    /// with the device's own access token and by `DELETE /devices/{id}` from
    /// another device of the user, sent percent-encoded through the route as
    /// the router declares it. Synapse is asked to delete exactly that id,
    /// byte for byte; the device's grants are refused afterwards; the device
    /// whose id is the Element X id's prefix up to the `/` is untouched.
    #[tokio::test]
    async fn an_element_x_device_id_survives_rotation_logout_and_device_deletion() {
        const EX: &str = "Wd3k+P0/rTq9LmZ8xV2cN7bH1yF6gJ4sA5eU+oQ/iRt";
        let Some(client) = redis().await else { return };
        let (endpoint, deleted, homeserver) = recording_homeserver().await;
        let state = CompatState {
            redis_client: client.clone(),
            require_secret: true,
            synapse_client: Some(Arc::new(SynapseClient::new(&endpoint, "secret"))),
            server_name: Some("example.org".to_string()),
            delegated_auth: true,
            guest_client_id: None,
        };
        let prefix = EX.split('/').next().unwrap();
        let n = nonce();
        let rotate_at_matrix = |rt: String| {
            let state = state.clone();
            async move {
                let (status, body) = matrix_refresh(&state, &rt).await;
                assert_eq!(status, StatusCode::OK, "the device's token rotates: {body}");
                (
                    body["access_token"].as_str().unwrap().to_string(),
                    body["refresh_token"].as_str().unwrap().to_string(),
                )
            }
        };

        // A sign-out with the device's own access token, after a rotation.
        let user = format!("ex-logout-{n}");
        let grant = seed_grant(&client, &user, EX).await;
        let (access, refresh_rt) = rotate_at_matrix(grant.refresh_token.unwrap()).await;
        assert_eq!(
            client
                .peek_refresh_grant(&refresh_rt)
                .await
                .unwrap()
                .unwrap()
                .device_id,
            EX,
            "rotation keeps the device id"
        );
        let neighbour = seed_grant(&client, &user, prefix).await;
        let resp = logout(State(state.clone()), bearer(&access))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            *deleted.lock().unwrap(),
            vec![serde_json::json!({"localpart": user, "device_id": EX})],
            "Synapse is asked to delete exactly the Element X device"
        );
        assert!(client.check_access_token(&access).await.unwrap().is_none());
        let (status, _) = matrix_refresh(&state, &refresh_rt).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the refresh token is refused"
        );
        assert!(
            client
                .check_access_token(&neighbour.access_token)
                .await
                .unwrap()
                .is_some(),
            "the device whose id is the prefix is untouched"
        );

        // DELETE /devices/{id} from the user's other device, over HTTP through
        // the route as `axum_lib` declares it: `/` and `+` percent-encoded.
        deleted.lock().unwrap().clear();
        let user = format!("ex-delete-{n}");
        let target = seed_grant(&client, &user, EX).await;
        let own = seed_grant(&client, &user, prefix).await;
        let (_, target_rt) = rotate_at_matrix(target.refresh_token.unwrap()).await;
        let app = axum::Router::new().route(
            "/_matrix/client/v3/devices/{device_id}",
            axum::routing::delete(delete_device).with_state(state.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let encoded = EX.replace('/', "%2F").replace('+', "%2B");
        let resp = reqwest::Client::new()
            .delete(format!("http://{addr}/_matrix/client/v3/devices/{encoded}"))
            .bearer_auth(&own.access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            *deleted.lock().unwrap(),
            vec![serde_json::json!({"localpart": user, "device_id": EX})],
            "the percent-encoded path names exactly the Element X device"
        );
        let (status, _) = matrix_refresh(&state, &target_rt).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the deleted device's token is refused"
        );
        assert!(
            client
                .check_access_token(&own.access_token)
                .await
                .unwrap()
                .is_some(),
            "the bearer's own device is untouched"
        );
        rotate_at_matrix(own.refresh_token.unwrap()).await;

        server.abort();
        homeserver.abort();
        for user in [format!("ex-logout-{n}"), format!("ex-delete-{n}")] {
            for device in [EX, prefix] {
                client.revoke_grants_for_device(&user, device).await.ok();
            }
        }
    }

    /// A store fault: Redis answers the operation that reads `key` with an
    /// error (`WRONGTYPE`: a string planted where a hash is read). The handler
    /// gets the same `Err` from the store that a lost connection, a timeout or
    /// an out-of-memory refusal gives it. The key expires on its own.
    async fn plant_store_fault(key: &str) {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: () = bb8_redis::redis::cmd("SET")
            .arg(key)
            .arg("planted store fault")
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    /// The retryable answer to a store fault: 503 with `M_UNKNOWN`.
    fn assert_retryable_503(status: StatusCode, body: &serde_json::Value, what: &str) {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{what}: a store fault is a retryable 503: {body}"
        );
        assert_eq!(
            body["errcode"], "M_UNKNOWN",
            "{what}: never M_UNKNOWN_TOKEN, which signs a Matrix client out: {body}"
        );
    }

    /// A store fault during `POST /_matrix/client/v3/refresh` is a retryable
    /// 503, never `M_UNKNOWN_TOKEN`: a Matrix client treats that as "signed
    /// out" and clears its crypto store, so a transient Redis fault would cost
    /// the session and its cryptographic identity.
    #[tokio::test]
    async fn a_store_fault_at_the_matrix_refresh_endpoint_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let rt = tokens::new_refresh_token(&tokens::new_grant_handle());
        let handle = tokens::parse_refresh_token(&rt).unwrap().handle;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_GRANT_PREFIX,
            siwx_oidc::db::grant::GrantId::of_handle(handle).as_str()
        ))
        .await;

        let (status, body) = matrix_refresh(&state, &rt).await;
        assert_retryable_503(status, &body, &format!("refresh {n}"));
    }

    /// A store fault while resolving the bearer of a device-deletion route is
    /// the same retryable 503 as at the refresh endpoint, never the
    /// `M_UNKNOWN_TOKEN` 401 of an unknown token.
    #[tokio::test]
    async fn a_store_fault_on_a_bearer_route_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("fault-user-{n}");
        let dev = format!("FAULT_{n}");
        let state = standalone_state(client.clone());
        let access = seed_grant(&client, &user, &dev).await.access_token;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            tokens::digest(&access)
        ))
        .await;

        let response = delete_device(State(state.clone()), Path(dev.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "DELETE /devices/{id}");

        let response = delete_devices(
            State(state.clone()),
            bearer(&access),
            Json(DeleteDevicesRequest {
                devices: vec![dev.clone()],
            }),
        )
        .await
        .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "POST /delete_devices");

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// The members of the Redis set at `key`, and a function's worth of
    /// restoring them: a planted fault overwrites the set, and the retry after
    /// the fault needs it back.
    async fn set_members(key: &str) -> Vec<String> {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        bb8_redis::redis::cmd("SMEMBERS")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap()
    }

    async fn restore_set(key: &str, members: &[String]) {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: () = bb8_redis::redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: () = bb8_redis::redis::cmd("SADD")
            .arg(key)
            .arg(members)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    /// A store fault during `POST /_matrix/client/v3/logout` is the retryable
    /// 503 of the refresh and device-deletion routes, never a 200 that reports a
    /// sign-out while nothing was revoked: a fault reading the bearer, and a
    /// fault while revoking the device's grants. The second leaves the bearer
    /// in place, so the client's retry tears the whole session down.
    #[tokio::test]
    async fn a_store_fault_during_logout_is_a_retryable_503_and_the_retry_tears_down() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("logout-fault-{n}");
        let state = standalone_state(client.clone());

        // A fault reading the bearer.
        let dev = format!("LOOKUP_{n}");
        let access = seed_grant(&client, &user, &dev).await.access_token;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            tokens::digest(&access)
        ))
        .await;
        let response = logout(State(state.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "logout, bearer lookup fault");
        client.revoke_grants_for_device(&user, &dev).await.ok();

        // A fault revoking the device's grants.
        let dev = format!("REVOKE_{n}");
        let issued = seed_grant(&client, &user, &dev).await;
        let idx = format!(
            "{}/{user}/{dev}",
            siwx_oidc::db::grant::KV_GRANT_DEVICE_IDX_PREFIX
        );
        let members = set_members(&idx).await;
        assert!(!members.is_empty(), "the device index names the grant");
        plant_store_fault(&idx).await;
        let response = logout(State(state.clone()), bearer(&issued.access_token))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "logout, revocation fault");
        assert!(
            client
                .lookup_access_token(&issued.access_token)
                .await
                .unwrap()
                .is_some(),
            "a failed logout leaves the bearer in place for the retry"
        );

        restore_set(&idx, &members).await;
        let response = logout(State(state.clone()), bearer(&issued.access_token))
            .await
            .into_response();
        let (status, _body) = status_and_json(response).await;
        assert_eq!(status, StatusCode::OK, "the retry signs out");
        assert!(
            client
                .lookup_access_token(&issued.access_token)
                .await
                .unwrap()
                .is_none(),
            "the retry ends the access token"
        );
        assert!(
            client
                .peek_refresh_grant(issued.refresh_token.as_deref().unwrap())
                .await
                .unwrap()
                .is_none(),
            "the retry ends the grant"
        );
    }

    /// A store fault during `POST /_matrix/client/v3/logout/all` is the
    /// retryable 503, never a 200 that reports every session ended: a fault
    /// reading the bearer, and a fault in the sweep of the user's grants (the
    /// own sessions are already ended, and the user epoch the sweep wrote
    /// first refuses the bearer). A fault ending the own sessions:
    /// `a_logout_all_retry_after_an_own_session_fault_ends_the_own_sessions_and_the_grants`.
    #[tokio::test]
    async fn a_store_fault_during_logout_all_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());

        let user = format!("logout-all-lookup-{n}");
        let dev = format!("ALL_{n}");
        let access = seed_grant(&client, &user, &dev).await.access_token;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            tokens::digest(&access)
        ))
        .await;
        let response = logout_all(State(state.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "logout/all, bearer lookup fault");
        client.revoke_grants_for_device(&user, &dev).await.ok();

        let user = format!("logout-all-sweep-{n}");
        let access = seed_grant(&client, &user, &dev).await.access_token;
        let hint = client
            .create_user_session(&format!("did:key:z{user}"))
            .await
            .unwrap();
        plant_store_fault(&format!(
            "{}/{user}",
            siwx_oidc::db::grant::KV_GRANT_USER_IDX_PREFIX
        ))
        .await;
        let response = logout_all(State(state.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "logout/all, sweep fault");
        // The sweep script writes the user epoch before the fault (a Redis
        // script does not roll back), so the bearer is already refused and a
        // retry is the idempotent no-op; the own sessions were ended first.
        assert!(
            client.lookup_user_session(&hint).await.unwrap().is_none(),
            "the own sessions end before the grants are revoked"
        );
        assert!(
            client.check_access_token(&access).await.unwrap().is_none(),
            "the user epoch written before the sweep's fault refuses the bearer"
        );
        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// A store fault while `logout/all` ends the user's own sessions (the
    /// DID's index is not a sorted set) is the retryable 503 with nothing
    /// revoked: the own sessions end before the grants are touched, so the
    /// bearer still works and the client's retry, once the fault is gone,
    /// ends the own sessions AND the grants. Revoking the grants first turned
    /// the retry into an unknown token, a 200 that left the `siwx_user` and
    /// `acct_session` sessions live.
    #[tokio::test]
    async fn a_logout_all_retry_after_an_own_session_fault_ends_the_own_sessions_and_the_grants() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let dev = format!("ALL_{n}");
        let user = format!("logout-all-own-{n}");
        let issued = seed_grant(&client, &user, &dev).await;
        let refresh = issued.refresh_token.as_deref().unwrap();
        let did = format!("did:key:z{user}");
        let hint = client.create_user_session(&did).await.unwrap();
        let (account, _csrf) = crate::account::create_account_session(&client, &did)
            .await
            .unwrap();
        let own_idx = format!(
            "{}/{}",
            siwx_oidc::db::KV_OWN_SESSION_IDX_PREFIX,
            tokens::digest(&siwx_oidc::mxid::canonicalize(&did))
        );
        let entries = zset_entries(&own_idx).await;
        assert_eq!(entries.len(), 2, "the DID's index names both own sessions");
        plant_store_fault(&own_idx).await;
        let response = logout_all(State(state.clone()), bearer(&issued.access_token))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "logout/all, own-session fault");
        assert!(
            client
                .check_access_token(&issued.access_token)
                .await
                .unwrap()
                .is_some(),
            "a logout/all whose own-session step faults leaves the bearer working for the retry"
        );
        assert!(
            client.peek_refresh_grant(refresh).await.unwrap().is_some(),
            "a logout/all whose own-session step faults leaves the grant in place"
        );

        restore_zset(&own_idx, &entries).await;
        let response = logout_all(State(state.clone()), bearer(&issued.access_token))
            .await
            .into_response();
        let (status, _body) = status_and_json(response).await;
        assert_eq!(status, StatusCode::OK, "the retry signs out");
        assert!(
            client.lookup_user_session(&hint).await.unwrap().is_none(),
            "the retry ends the picker hint"
        );
        assert!(
            client
                .lookup_own_session(OwnSession::Account, &account)
                .await
                .unwrap()
                .is_none(),
            "the retry ends the account session"
        );
        assert!(
            client
                .check_access_token(&issued.access_token)
                .await
                .unwrap()
                .is_none(),
            "the retry ends the access token"
        );
        assert!(
            client.peek_refresh_grant(refresh).await.unwrap().is_none(),
            "the retry ends the grant"
        );
    }

    /// A sorted set's members with their scores, to put it back after a
    /// planted fault replaced it.
    async fn zset_entries(key: &str) -> Vec<(String, String)> {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        bb8_redis::redis::cmd("ZRANGE")
            .arg(key)
            .arg(0)
            .arg(-1)
            .arg("WITHSCORES")
            .query_async(&mut conn)
            .await
            .unwrap()
    }

    async fn restore_zset(key: &str, entries: &[(String, String)]) {
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: () = bb8_redis::redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let mut zadd = bb8_redis::redis::cmd("ZADD");
        zadd.arg(key);
        for (member, score) in entries {
            zadd.arg(score).arg(member);
        }
        let _: () = zadd.query_async(&mut conn).await.unwrap();
        let _: () = bb8_redis::redis::cmd("EXPIRE")
            .arg(key)
            .arg(600)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    async fn status_and_json(
        response: axum::response::Response,
    ) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The Matrix endpoint's replay follows the rule of the OAuth grant (I4):
    /// it returns the successor pair only while that pair is live and unused.
    /// After the successor was rotated away or its grant revoked, the replay is
    /// answered like an unknown token. (The endpoint cannot bind the replay to
    /// a client: the Matrix API carries none.)
    #[tokio::test]
    async fn a_matrix_refresh_replay_needs_its_successor_live() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("replay-user-{n}");
        let dev = format!("REPLAY_{n}");
        let state = standalone_state(client.clone());

        // Rotated: the client received the successor and has since used it.
        let old = seed_grant(&client, &user, &dev)
            .await
            .refresh_token
            .unwrap();
        let (status, first) = matrix_refresh(&state, &old).await;
        assert_eq!(status, StatusCode::OK, "the rotation succeeds: {first}");
        let successor = first["refresh_token"].as_str().unwrap().to_string();

        let (status, replay) = matrix_refresh(&state, &old).await;
        assert_eq!(status, StatusCode::OK, "a replay with a live successor");
        assert_eq!(
            replay["refresh_token"], first["refresh_token"],
            "while the successor is live the replay returns the same pair"
        );

        let (status, second) = matrix_refresh(&state, &successor).await;
        assert_eq!(status, StatusCode::OK, "the successor rotates: {second}");
        let (status, body) = matrix_refresh(&state, &old).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a replay whose successor was rotated gets no pair: {body}"
        );
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");

        // Revoked: the successor's grant was deleted before the client used it.
        let old = seed_grant(&client, &user, &dev)
            .await
            .refresh_token
            .unwrap();
        let (_, first) = matrix_refresh(&state, &old).await;
        let successor = first["refresh_token"].as_str().unwrap().to_string();
        client
            .revoke_grant_of_token(&successor)
            .await
            .unwrap()
            .expect("the successor's grant is revoked");
        let (status, body) = matrix_refresh(&state, &old).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a replay whose successor was revoked gets no pair: {body}"
        );
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// D-M1-1 (provisional): RFC 7009 revoke of a deviceless grant's refresh
    /// token revokes the whole grant, its live access token included (RFC 7009
    /// §2.1); revoking its access token removes only that access token.
    #[tokio::test]
    async fn revoking_a_deviceless_refresh_token_revokes_its_grant_an_access_token_only_itself() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = standalone_state(client.clone());
        let revoke_token = |token: &str| {
            revoke(
                State(state.clone()),
                Form(RevokeForm {
                    token: token.to_string(),
                    token_type_hint: None,
                }),
            )
        };

        let by_refresh = seed_grant(&client, &format!("grant-revoke-rt-{n}"), "").await;
        let refresh_token = by_refresh.refresh_token.clone().unwrap();
        assert_eq!(revoke_token(&refresh_token).await, StatusCode::OK);
        assert!(
            client
                .check_access_token(&by_refresh.access_token)
                .await
                .unwrap()
                .is_none(),
            "revoking the refresh token takes the grant's access token with it"
        );
        let (status, body) = matrix_refresh(&state, &refresh_token).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the refresh token is gone: {body}"
        );

        let by_access = seed_grant(&client, &format!("grant-revoke-at-{n}"), "").await;
        assert_eq!(revoke_token(&by_access.access_token).await, StatusCode::OK);
        assert!(
            client
                .check_access_token(&by_access.access_token)
                .await
                .unwrap()
                .is_none(),
            "the access token is revoked"
        );
        let (status, body) =
            matrix_refresh(&state, by_access.refresh_token.as_deref().unwrap()).await;
        assert_eq!(status, StatusCode::OK, "the grant itself survives: {body}");
    }

    /// RFC 7009 revoke accepts either kind: a refresh token is revoked.
    #[tokio::test]
    async fn revoke_accepts_a_refresh_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("kind-revoke-{n}");
        let refresh = format!("compat_kind_revoke_{n}");
        client
            .set_token(&refresh, &refresh_meta(&user, ""), 120)
            .await
            .unwrap();
        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: refresh.clone(),
            token_type_hint: None,
        };
        assert_eq!(revoke(State(state), Form(form)).await, StatusCode::OK);
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "revoke removes a refresh token"
        );
    }

    /// I9 at teardown: a refresh token an epoch refuses resolves to nothing
    /// (`resolve_refresh_token`), so revoking it acts like revoking an unknown
    /// token. It must not tear down by its grant's (username, device_id): a
    /// newer grant on the same device, authenticated after the epoch, lives on.
    #[tokio::test]
    async fn revoking_a_refresh_token_an_epoch_refuses_leaves_a_newer_grant_of_the_device() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("epoch-revoke-{n}");
        let dev = format!("EPOCH_{n}");
        let old = seed_grant(&client, &user, &dev)
            .await
            .refresh_token
            .unwrap();
        assert!(
            client.resolve_refresh_token(&old).await.unwrap().is_some(),
            "before the epoch the refresh token resolves to its grant"
        );
        client.set_epoch(EpochScope::User(&user)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        // A later sign-in that proposes the same device id.
        let newer = seed_grant(&client, &user, &dev).await;

        let form = RevokeForm {
            token: old.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(standalone_state(client.clone())), Form(form)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            client
                .resolve_refresh_token(newer.refresh_token.as_deref().unwrap())
                .await
                .unwrap()
                .is_some(),
            "revoking the refused token tore down the device's newer grant"
        );
        assert!(
            client
                .check_access_token(&newer.access_token)
                .await
                .unwrap()
                .is_some(),
            "revoking the refused token revoked the newer grant's access token"
        );
        assert!(
            client.resolve_refresh_token(&old).await.unwrap().is_none(),
            "a refresh token an epoch refuses resolves to nothing"
        );

        client.revoke_grants_for_device(&user, &dev).await.ok();
    }

    /// Same single-session guarantee for RFC 7009 revoke with empty device_id.
    #[tokio::test]
    async fn revoke_standalone_empty_device_id_revokes_only_presented_token() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("empty-dev-revoke-{n}");
        let session_a = format!("compat_empty_rev_a_{n}");
        let session_b = format!("compat_empty_rev_b_{n}");

        client
            .set_token(&session_a, &token_meta(&user, ""), 120)
            .await
            .unwrap();
        client
            .set_token(&session_b, &token_meta(&user, ""), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: session_a.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            client.get_token(&session_a).await.unwrap().is_none(),
            "the presented token must be revoked"
        );
        assert!(
            client.get_token(&session_b).await.unwrap().is_some(),
            "another standalone session of the same user must survive revoke"
        );

        client.delete_token(&session_b).await.ok();
    }

    /// H7: standalone revoke (RFC 7009) revokes the session's tokens and 200s.
    #[tokio::test]
    async fn revoke_standalone_revokes_session_tokens() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("revoke-user-{n}");
        let dev = format!("DEV_{n}");
        let access = format!("compat_revoke_access_{n}");
        let refresh = format!("compat_revoke_refresh_{n}");

        client
            .set_token(&access, &token_meta(&user, &dev), 120)
            .await
            .unwrap();
        client
            .set_token(&refresh, &token_meta(&user, &dev), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let form = RevokeForm {
            token: access.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            client.get_token(&access).await.unwrap().is_none(),
            "revoked access token must be gone"
        );
        assert!(
            client.get_token(&refresh).await.unwrap().is_none(),
            "paired refresh token must be gone"
        );
    }

    /// Idempotency: logout / revoke with a token not in Redis must not panic and
    /// must still return 200.
    #[tokio::test]
    async fn logout_and_revoke_unknown_token_are_idempotent() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let unknown = format!("compat_unknown_{n}");

        let state = standalone_state(client.clone());
        let resp = logout(State(state.clone()), bearer(&unknown))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "logout no-op must 200");

        let form = RevokeForm {
            token: unknown.clone(),
            token_type_hint: None,
        };
        let status = revoke(State(state), Form(form)).await;
        assert_eq!(status, StatusCode::OK, "revoke no-op must 200");
    }

    /// logout with no Authorization header is a 200 no-op.
    #[tokio::test]
    async fn logout_without_bearer_is_noop_200() {
        let Some(client) = redis().await else { return };
        let state = standalone_state(client);
        let resp = logout(State(state), None).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// H3: logout_all revokes EVERY token for the user (across devices) and
    /// leaves other users untouched. Standalone mode (no Synapse): never
    /// deactivates, just revokes Redis tokens.
    #[tokio::test]
    async fn logout_all_revokes_all_user_tokens_standalone() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("logoutall-user-{n}");
        let other_user = format!("logoutall-other-{n}");
        let d1 = format!("DEV1_{n}");
        let d2 = format!("DEV2_{n}");
        let bearer_tok = format!("compat_la_bearer_{n}");
        let t2 = format!("compat_la_t2_{n}");
        let t3 = format!("compat_la_t3_{n}");
        let foreign = format!("compat_la_foreign_{n}");

        // Three tokens for the user across two devices (bearer + two more).
        client
            .set_token(&bearer_tok, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t2, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t3, &token_meta(&user, &d2), 120)
            .await
            .unwrap();
        // A different user's token must survive.
        client
            .set_token(&foreign, &token_meta(&other_user, &d1), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = logout_all(State(state), bearer(&bearer_tok))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        for (tok, label) in [
            (&bearer_tok, "bearer token"),
            (&t2, "same-device second token"),
            (&t3, "other-device token"),
        ] {
            assert!(
                client.get_token(tok).await.unwrap().is_none(),
                "logout_all must revoke the user's {label}"
            );
        }
        assert!(
            client.get_token(&foreign).await.unwrap().is_some(),
            "logout_all must not touch another user's token"
        );

        client.delete_token(&foreign).await.ok();
    }

    /// logout_all with no bearer / an unknown token is an idempotent 200 no-op
    /// and must not revoke unrelated tokens.
    #[tokio::test]
    async fn logout_all_no_bearer_or_unknown_is_noop() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let survivor = format!("compat_la_survivor_{n}");
        client
            .set_token(&survivor, &token_meta(&format!("u-{n}"), "D"), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());

        // No bearer.
        let resp = logout_all(State(state.clone()), None).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        // Unknown bearer.
        let resp = logout_all(State(state), bearer(&format!("compat_la_unknown_{n}")))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&survivor).await.unwrap().is_some(),
            "no-op logout_all must not revoke unrelated tokens"
        );
        client.delete_token(&survivor).await.ok();
    }

    // -- Legacy CS-API device delete (Fix A: client session-manager wiring) ---

    /// H5: `DELETE /devices/{id}` resolves the user from the bearer, revokes the
    /// TARGET device's tokens (standalone: no Synapse), and leaves other devices'
    /// tokens intact. Returns 200.
    #[tokio::test]
    async fn compat_delete_device_revokes_target_and_keeps_others() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("legacy-user-{n}");
        let bearer_tok = format!("compat_dd_bearer_{n}");
        let target_tok = format!("compat_dd_target_{n}");
        let other_tok = format!("compat_dd_other_{n}");

        // Bearer belongs to the user (its own device). Target + other are two of
        // the user's device sessions.
        client
            .set_token(&bearer_tok, &token_meta(&user, &format!("SELF_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&target_tok, &token_meta(&user, &format!("TARGET_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&other_tok, &token_meta(&user, &format!("OTHER_{n}")), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = delete_device(
            State(state),
            axum::extract::Path(format!("TARGET_{n}")),
            bearer(&bearer_tok),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&target_tok).await.unwrap().is_none(),
            "the targeted device's token must be revoked"
        );
        assert!(
            client.get_token(&other_tok).await.unwrap().is_some(),
            "a different device's token must survive"
        );
        // bearer's own session is untouched by deleting a *different* device.
        assert!(
            client.get_token(&bearer_tok).await.unwrap().is_some(),
            "the caller's own session must survive deleting another device"
        );

        client.delete_token(&bearer_tok).await.ok();
        client.delete_token(&other_tok).await.ok();
    }

    /// `DELETE /devices/{id}` with no/unknown bearer must be 401 (M_UNKNOWN_TOKEN).
    #[tokio::test]
    async fn compat_delete_device_unknown_bearer_is_401() {
        let Some(client) = redis().await else { return };
        let state = standalone_state(client);
        let resp = delete_device(
            State(state.clone()),
            axum::extract::Path("ANY".to_string()),
            None,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = delete_device(
            State(state),
            axum::extract::Path("ANY".to_string()),
            bearer("compat_dd_nope"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// H5: `POST /delete_devices` bulk-revokes every named device's tokens.
    #[tokio::test]
    async fn compat_delete_devices_bulk_revokes_each() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("bulk-user-{n}");
        let bearer_tok = format!("compat_bulk_bearer_{n}");
        let d1 = format!("D1_{n}");
        let d2 = format!("D2_{n}");
        let t1 = format!("compat_bulk_t1_{n}");
        let t2 = format!("compat_bulk_t2_{n}");

        client
            .set_token(&bearer_tok, &token_meta(&user, &format!("SELF_{n}")), 120)
            .await
            .unwrap();
        client
            .set_token(&t1, &token_meta(&user, &d1), 120)
            .await
            .unwrap();
        client
            .set_token(&t2, &token_meta(&user, &d2), 120)
            .await
            .unwrap();

        let state = standalone_state(client.clone());
        let resp = delete_devices(
            State(state),
            bearer(&bearer_tok),
            Json(DeleteDevicesRequest {
                devices: vec![d1.clone(), d2.clone()],
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            client.get_token(&t1).await.unwrap().is_none(),
            "D1 token must be revoked"
        );
        assert!(
            client.get_token(&t2).await.unwrap().is_none(),
            "D2 token must be revoked"
        );
        client.delete_token(&bearer_tok).await.ok();
    }

    /// A refresh through the Matrix compat route is a use of the grant's client, so it
    /// restores a dynamic client's lifetime, like the refresh grant at `/token`. The
    /// replay of a lost response is a use too.
    #[tokio::test]
    async fn a_successful_refresh_extends_a_dynamic_client() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let client_id = format!("touch-compat-refresh-{n}");
        let client_key = format!("clients/{client_id}");
        client
            .set_client(
                client_id.clone(),
                siwx_oidc::db::ClientEntry::new(
                    "not-a-secret-test-fixture",
                    siwx_oidc::db::SiwxClientMetadata::new(
                        vec![
                            openidconnect::RedirectUrl::new("https://example.com/cb".into())
                                .unwrap(),
                        ],
                        siwx_oidc::db::LogoutClientMetadata::default(),
                    ),
                    None,
                ),
            )
            .await
            .unwrap();
        let user = format!("refresh-user-{n}");
        let dev = format!("DEV_{n}");
        let refresh_token = client
            .issue_grant(&NewGrant {
                kind: GrantKind::MatrixDevice,
                username: user.clone(),
                did: format!("did:key:z{user}"),
                client_id: client_id.clone(),
                confidential_client: false,
                device_id: dev.clone(),
                scope: "openid".into(),
                name: user.clone(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: Some(120),
                absolute_deadline: None,
            })
            .await
            .unwrap()
            .refresh_token
            .expect("the grant carries a refresh token");
        let state = standalone_state(client.clone());

        client.expire_raw(&client_key, 60).await.unwrap();
        let (status, first) = matrix_refresh(&state, &refresh_token).await;
        assert_eq!(status, StatusCode::OK, "the rotation succeeds: {first}");
        assert!(
            client.ttl_raw(&client_key).await.unwrap() > 60,
            "a refreshed session's dynamic client gets its lifetime back"
        );

        client.expire_raw(&client_key, 60).await.unwrap();
        let (status, replay) = matrix_refresh(&state, &refresh_token).await;
        assert_eq!(status, StatusCode::OK, "the replay is answered: {replay}");
        assert!(
            client.ttl_raw(&client_key).await.unwrap() > 60,
            "the replay of a lost response is a use of the client too"
        );

        client.revoke_device_tokens(&user, &dev).await.ok();
        client.del_raw(&client_key).await.ok();
    }

    // -- The grant of another relying party at the Matrix routes ---------------------------

    /// Delegated-auth state: Redis only, no Synapse client.
    fn matrix_state(redis_client: RedisClient) -> CompatState {
        CompatState {
            delegated_auth: true,
            guest_client_id: None,
            ..standalone_state(redis_client)
        }
    }

    /// The configuration decides whether the Matrix routes refuse the grant of another
    /// relying party: with a MAS shared secret (delegated auth) they do, without one they
    /// serve every grant. A Matrix session, a minted admin token and a token with no grant
    /// record are served either way.
    #[tokio::test]
    async fn the_routes_refuse_other_relying_parties_exactly_when_auth_is_delegated() {
        let Some(client) = redis().await else { return };
        let config = |secret: Option<&str>| crate::config::Config {
            mas_shared_secret: secret.map(str::to_string),
            ..crate::config::Config::default()
        };
        let delegated = CompatState::new(client.clone(), None, &config(Some("mas-secret")));
        let generic_mode = CompatState::new(client.clone(), None, &config(None));

        assert!(delegated.delegated_auth && !generic_mode.delegated_auth);
        for kind in [
            Some(GrantKind::MatrixDevice),
            Some(GrantKind::Service),
            None,
        ] {
            assert!(delegated.acts_on(kind), "{kind:?}, delegated auth");
            assert!(generic_mode.acts_on(kind), "{kind:?}, generic mode");
        }
        assert!(
            !delegated.acts_on(Some(GrantKind::Oidc)),
            "an oidc grant is refused with delegated auth"
        );
        assert!(
            generic_mode.acts_on(Some(GrantKind::Oidc)),
            "and served without it"
        );
    }

    /// A grant of `kind` for `user`, with a refresh token unless it is a `service` grant.
    async fn seed_kind(
        client: &RedisClient,
        kind: GrantKind,
        user: &str,
        device_id: &str,
    ) -> IssuedGrant {
        client
            .issue_grant(&NewGrant {
                kind,
                username: user.to_string(),
                did: format!("did:key:z{user}"),
                client_id: "compat-test".into(),
                confidential_client: false,
                device_id: device_id.to_string(),
                scope: "openid".into(),
                name: user.to_string(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: match kind {
                    GrantKind::Service => None,
                    GrantKind::MatrixDevice | GrantKind::Oidc => Some(120),
                },
                absolute_deadline: None,
            })
            .await
            .unwrap()
    }

    /// The four bearer-authenticated Matrix routes in turn, each answering for `token`.
    async fn at_every_bearer_route(
        state: &CompatState,
        token: &str,
        device_id: &str,
    ) -> Vec<(&'static str, StatusCode, serde_json::Value)> {
        let mut answers = Vec::new();
        for route in [
            "logout",
            "logout/all",
            "DELETE /devices/{id}",
            "POST /delete_devices",
        ] {
            let response = match route {
                "logout" => logout(State(state.clone()), bearer(token))
                    .await
                    .into_response(),
                "logout/all" => logout_all(State(state.clone()), bearer(token))
                    .await
                    .into_response(),
                "DELETE /devices/{id}" => delete_device(
                    State(state.clone()),
                    Path(device_id.to_string()),
                    bearer(token),
                )
                .await
                .into_response(),
                _ => delete_devices(
                    State(state.clone()),
                    bearer(token),
                    Json(DeleteDevicesRequest {
                        devices: vec![device_id.to_string()],
                    }),
                )
                .await
                .into_response(),
            };
            let (status, body) = status_and_json(response).await;
            answers.push((route, status, body));
        }
        answers
    }

    /// In a delegated-auth deployment the grant of a generic-class client (an `oidc` grant)
    /// is not a Matrix session: every bearer route answers it `M_UNKNOWN_TOKEN` and tears
    /// nothing down, neither the Matrix session beside it nor the grant itself.
    #[tokio::test]
    async fn an_oidc_grant_cannot_drive_the_matrix_bearer_routes() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("rp-user-{n}");
        let device = format!("RP_{n}");
        let state = matrix_state(client.clone());
        let session = seed_kind(&client, GrantKind::MatrixDevice, &user, &device).await;
        let mail = seed_kind(&client, GrantKind::Oidc, &user, "").await;

        let unknown = delete_device(
            State(state.clone()),
            Path(device.clone()),
            bearer(&format!("mat_unknown_{n}")),
        )
        .await
        .into_response();
        let (unknown_status, unknown_body) = status_and_json(unknown).await;
        assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);

        for (route, status, body) in
            at_every_bearer_route(&state, &mail.access_token, &device).await
        {
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {body}");
            assert_eq!(
                body, unknown_body,
                "{route}: M_UNKNOWN_TOKEN, as for an unknown bearer"
            );
        }

        assert!(
            client
                .lookup_access_token(&session.access_token)
                .await
                .unwrap()
                .is_some(),
            "the user's Matrix session survives"
        );
        assert!(
            client
                .lookup_access_token(&mail.access_token)
                .await
                .unwrap()
                .is_some(),
            "the refused token survives"
        );
        let grant = client
            .resolve_refresh_token(mail.refresh_token.as_deref().unwrap())
            .await
            .unwrap()
            .expect("the grant's refresh token is still current");
        assert_eq!(grant.generation, 0, "nothing rotated it");

        client.revoke_grants_for_device(&user, &device).await.ok();
    }

    /// The refusal costs a Matrix session nothing: in a delegated-auth deployment the
    /// bearer routes act for `matrix_device` grants and minted admin tokens as before, and
    /// `logout/all` ends the generic client's grant with the rest, as any sign-out of every
    /// session does.
    #[tokio::test]
    async fn a_matrix_session_still_drives_the_bearer_routes_in_a_delegated_deployment() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("rp-matrix-{n}");
        let (d1, d2, d3) = (format!("ONE_{n}"), format!("TWO_{n}"), format!("THREE_{n}"));
        let state = matrix_state(client.clone());
        let s1 = seed_kind(&client, GrantKind::MatrixDevice, &user, &d1).await;
        let s2 = seed_kind(&client, GrantKind::MatrixDevice, &user, &d2).await;
        let s3 = seed_kind(&client, GrantKind::MatrixDevice, &user, &d3).await;
        let mail = seed_kind(&client, GrantKind::Oidc, &user, "").await;
        let admin = seed_kind(&client, GrantKind::Service, &format!("rp-admin-{n}"), "").await;
        let alive = |token: String| {
            let client = client.clone();
            async move { client.lookup_access_token(&token).await.unwrap().is_some() }
        };

        let response = delete_device(
            State(state.clone()),
            Path(d1.clone()),
            bearer(&s1.access_token),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK, "device deletion");
        assert!(!alive(s1.access_token.clone()).await, "the device is gone");
        assert!(alive(s2.access_token.clone()).await, "another device stays");
        assert!(
            alive(mail.access_token.clone()).await,
            "so does the mail client"
        );

        let response = delete_device(
            State(state.clone()),
            Path(format!("NOSUCH_{n}")),
            bearer(&admin.access_token),
        )
        .await
        .into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a minted admin token is served"
        );

        let response = logout(State(state.clone()), bearer(&s2.access_token))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK, "logout");
        assert!(
            !alive(s2.access_token.clone()).await,
            "logout ends this session"
        );
        assert!(alive(s3.access_token.clone()).await, "and no other");
        assert!(alive(mail.access_token.clone()).await);

        let response = logout_all(State(state.clone()), bearer(&s3.access_token))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK, "logout/all");
        assert!(!alive(s3.access_token.clone()).await);
        assert!(
            !alive(mail.access_token.clone()).await,
            "signing out of every session ends the mail client's grant too"
        );
        assert!(
            client
                .resolve_refresh_token(mail.refresh_token.as_deref().unwrap())
                .await
                .unwrap()
                .is_none(),
            "with its refresh token"
        );
    }

    /// Without delegated auth every client is a relying party and holds `oidc` grants, so
    /// the Matrix routes keep serving them: the refusal belongs to a deployment whose
    /// clients are Matrix clients.
    #[tokio::test]
    async fn without_delegated_auth_the_matrix_routes_still_serve_an_oidc_grant() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("rp-generic-{n}");
        let state = standalone_state(client.clone());
        let a = seed_kind(&client, GrantKind::Oidc, &user, "").await;
        let b = seed_kind(&client, GrantKind::Oidc, &user, "").await;
        let c = seed_kind(&client, GrantKind::Oidc, &user, "").await;

        let response = delete_device(
            State(state.clone()),
            Path(format!("ANY_{n}")),
            bearer(&a.access_token),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK, "device deletion");

        let response = logout(State(state.clone()), bearer(&a.access_token))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK, "logout");
        assert!(
            client
                .lookup_access_token(&a.access_token)
                .await
                .unwrap()
                .is_none(),
            "logout ends the presented token"
        );

        let (status, body) = matrix_refresh(&state, c.refresh_token.as_deref().unwrap()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the Matrix refresh endpoint: {body}"
        );

        let response = logout_all(State(state.clone()), bearer(&b.access_token))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK, "logout/all");
        assert!(
            client
                .resolve_refresh_token(b.refresh_token.as_deref().unwrap())
                .await
                .unwrap()
                .is_none(),
            "logout/all ends the user's grants"
        );
    }

    /// RFC 7009 revocation is not a Matrix route: the holder of an `oidc` grant's token may
    /// end it in every deployment.
    #[tokio::test]
    async fn revocation_still_ends_an_oidc_grant_in_a_delegated_deployment() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = matrix_state(client.clone());
        let mail = seed_kind(&client, GrantKind::Oidc, &format!("rp-revoke-{n}"), "").await;
        let refresh_token = mail.refresh_token.clone().unwrap();

        let form = RevokeForm {
            token: refresh_token.clone(),
            token_type_hint: None,
        };
        assert_eq!(revoke(State(state), Form(form)).await, StatusCode::OK);
        assert!(
            client
                .resolve_refresh_token(&refresh_token)
                .await
                .unwrap()
                .is_none(),
            "the grant is revoked"
        );
        assert!(
            client
                .lookup_access_token(&mail.access_token)
                .await
                .unwrap()
                .is_none(),
            "with its access token"
        );
    }

    /// The Matrix refresh endpoint refuses the refresh token of an `oidc` grant in a
    /// delegated-auth deployment exactly like an unknown token and leaves the grant as it
    /// was, for `POST /token`. A legacy token that the lift would turn into one is refused
    /// the same way and stays a legacy entry; one that carries the Matrix API is lifted.
    #[tokio::test]
    async fn the_matrix_refresh_endpoint_leaves_an_oidc_grants_refresh_token_alone() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("rp-refresh-{n}");
        let state = matrix_state(client.clone());
        let never_issued = tokens::new_refresh_token(&tokens::new_grant_handle());
        let (_, unknown) = matrix_refresh(&state, &never_issued).await;

        let mail = seed_kind(&client, GrantKind::Oidc, &user, "").await;
        let refresh_token = mail.refresh_token.clone().unwrap();
        let (status, body) = matrix_refresh(&state, &refresh_token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body, unknown, "refused exactly like an unknown token");
        let grant = client
            .resolve_refresh_token(&refresh_token)
            .await
            .unwrap()
            .expect("the refused token is still the grant's current refresh token");
        assert_eq!(grant.generation, 0, "the refusal rotated nothing");

        let legacy = |raw: String, scope: &str| {
            let client = client.clone();
            let scope = scope.to_string();
            let user = user.clone();
            async move {
                let mut meta = refresh_meta(&user, "");
                meta.scope = scope;
                meta.iat = Utc::now().timestamp();
                meta.exp = meta.iat + REFRESH_TOKEN_TTL as i64;
                client
                    .set_token(&raw, &meta, REFRESH_TOKEN_TTL)
                    .await
                    .unwrap();
                raw
            }
        };
        let mail_legacy = legacy(format!("mcr_legacymail{n}"), "openid io.inblock.mail").await;
        let (status, body) = matrix_refresh(&state, &mail_legacy).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body, unknown, "refused exactly like an unknown token");
        assert!(
            client.get_token(&mail_legacy).await.unwrap().is_some(),
            "the refused legacy token is left for POST /token"
        );

        let matrix_legacy = legacy(
            format!("mcr_legacymatrix{n}"),
            "openid urn:matrix:client:api:*",
        )
        .await;
        let (status, body) = matrix_refresh(&state, &matrix_legacy).await;
        assert_eq!(status, StatusCode::OK, "a Matrix session is lifted: {body}");
        assert!(
            client.get_token(&matrix_legacy).await.unwrap().is_none(),
            "legacy entry gone"
        );
    }

    /// A store fault on the way to each refusal is the retryable 503, never the
    /// `M_UNKNOWN_TOKEN` a Matrix client takes for "signed out": the refusal is a decision
    /// about a grant the store could read, and a store that could not read it decides
    /// nothing.
    #[tokio::test]
    async fn a_store_fault_where_an_oidc_grant_is_refused_is_a_retryable_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let state = matrix_state(client.clone());

        let bearer_grant =
            seed_kind(&client, GrantKind::Oidc, &format!("rp-fault-a-{n}"), "").await;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_ACCESS_TOKEN_PREFIX,
            tokens::digest(&bearer_grant.access_token)
        ))
        .await;
        for (route, status, body) in
            at_every_bearer_route(&state, &bearer_grant.access_token, "ANY").await
        {
            assert_retryable_503(status, &body, route);
        }

        let refresh_grant =
            seed_kind(&client, GrantKind::Oidc, &format!("rp-fault-b-{n}"), "").await;
        let refresh_token = refresh_grant.refresh_token.clone().unwrap();
        let handle = tokens::parse_refresh_token(&refresh_token).unwrap().handle;
        plant_store_fault(&format!(
            "{}/{}",
            siwx_oidc::db::grant::KV_GRANT_PREFIX,
            siwx_oidc::db::grant::GrantId::of_handle(handle).as_str()
        ))
        .await;
        let (status, body) = matrix_refresh(&state, &refresh_token).await;
        assert_retryable_503(status, &body, "POST /_matrix/client/v3/refresh");
    }

    // -- SS4 flag 1: strict teardown (8.23) ------------------------------------

    /// A homeserver for the strict-teardown tests: `delete_device` answers the
    /// status scripted for the device id (200 by default) and records every
    /// call; the admin device list serves `listed` minus what a 200 deleted.
    struct Scripted {
        url: String,
        statuses: Arc<std::sync::Mutex<HashMap<String, u16>>>,
        calls: Arc<std::sync::Mutex<Vec<String>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Scripted {
        fn set(&self, device: &str, status: u16) {
            self.statuses
                .lock()
                .unwrap()
                .insert(device.to_string(), status);
        }
        fn heal(&self) {
            self.statuses.lock().unwrap().clear();
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    async fn scripted_homeserver(listed: Vec<String>) -> Scripted {
        let statuses = Arc::new(std::sync::Mutex::new(HashMap::<String, u16>::new()));
        let calls = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let listed = Arc::new(std::sync::Mutex::new(listed));
        let (st, ca, li) = (statuses.clone(), calls.clone(), listed.clone());
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let (st, ca, li) = (st.clone(), ca.clone(), li.clone());
            async move {
                let path = req.uri().path().to_string();
                if path == "/_synapse/mas/delete_device" {
                    let body = axum::body::to_bytes(req.into_body(), 1 << 16)
                        .await
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let device = v["device_id"].as_str().unwrap().to_string();
                    ca.lock().unwrap().push(device.clone());
                    let code = st.lock().unwrap().get(&device).copied().unwrap_or(200);
                    if code == 200 {
                        li.lock().unwrap().retain(|d| d != &device);
                    }
                    let body = match code {
                        404 => {
                            serde_json::json!({"errcode": "M_NOT_FOUND", "error": "User not found"})
                        }
                        _ => serde_json::json!({}),
                    };
                    return (StatusCode::from_u16(code).unwrap(), Json(body)).into_response();
                }
                if path.ends_with("/devices") {
                    let devices: Vec<serde_json::Value> = li
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|d| serde_json::json!({"device_id": d}))
                        .collect();
                    let total = devices.len();
                    return Json(serde_json::json!({"devices": devices, "total": total}))
                        .into_response();
                }
                if path == "/_synapse/mas/is_localpart_available" {
                    // The admin service user exists (the admin mint asks).
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"errcode": "M_USER_IN_USE", "error": "taken"})),
                    )
                        .into_response();
                }
                (StatusCode::OK, Json(serde_json::json!({}))).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Scripted {
            url: format!("http://{addr}"),
            statuses,
            calls,
            server,
        }
    }

    /// A delegated-auth state against `hs`, with flag 1 `strict` on or off.
    fn strict_state(client: &RedisClient, hs: &Scripted, strict: bool) -> CompatState {
        CompatState {
            redis_client: client.clone(),
            require_secret: true,
            synapse_client: Some(Arc::new(
                SynapseClient::new(&hs.url, "secret")
                    .with_admin_mint(client.clone(), "ss4-admin".into(), 300)
                    .with_strict_teardown(strict),
            )),
            server_name: Some("example.org".to_string()),
            delegated_auth: true,
            guest_client_id: None,
        }
    }

    async fn alive(client: &RedisClient, access: &str) -> bool {
        client.lookup_access_token(access).await.unwrap().is_some()
    }

    async fn revoke_status(state: &CompatState, token: &str) -> StatusCode {
        revoke(
            State(state.clone()),
            Form(RevokeForm {
                token: token.to_string(),
                token_type_hint: None,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn teardown_flag1_transient_synapse_failure_503_revokes_nothing() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-transient-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        hs.set(&dev, 500);
        let response = logout(State(state.clone()), bearer(&access))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "strict logout, Synapse 500");
        assert!(
            alive(&client, &access).await,
            "a transient fault revokes nothing"
        );
        hs.heal();
        let response = logout(State(state.clone()), bearer(&access))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK, "the retry tears down");
        assert!(!alive(&client, &access).await);
        assert_eq!(hs.calls(), [dev.clone(), dev.clone()]);
        hs.server.abort();
    }

    #[tokio::test]
    async fn teardown_flag1_synapse_404_user_not_found_revokes_and_200() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-404-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        hs.set(&dev, 404);
        let response = logout(State(state), bearer(&access)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "nothing to delete is done"
        );
        assert!(
            !alive(&client, &access).await,
            "404: the grants are revoked"
        );
        hs.server.abort();
    }

    #[tokio::test]
    async fn teardown_flag1_synapse_403_revokes_logs_error_200() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-403-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        hs.set(&dev, 403);
        let response = logout(State(state), bearer(&access)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a config fault never strands the client"
        );
        assert!(!alive(&client, &access).await, "403: revoked anyway");
        hs.server.abort();
    }

    #[tokio::test]
    async fn teardown_flag1_revoke_failure_after_delete_503_then_retry_200() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-revfail-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let issued = seed_grant(&client, &user, &dev).await;
        let idx = format!(
            "{}/{user}/{dev}",
            siwx_oidc::db::grant::KV_GRANT_DEVICE_IDX_PREFIX
        );
        let members = set_members(&idx).await;
        assert!(!members.is_empty(), "the device index names the grant");
        plant_store_fault(&idx).await;
        let response = logout(State(state.clone()), bearer(&issued.access_token))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(
            status,
            &body,
            "strict logout, revoke fault after the delete",
        );
        assert_eq!(
            hs.calls(),
            std::slice::from_ref(&dev),
            "the device was deleted first"
        );
        assert!(
            alive(&client, &issued.access_token).await,
            "the bearer stays for the retry"
        );
        // The store recovers: the index is back.
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let _: () = bb8_redis::redis::cmd("DEL")
            .arg(&idx)
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: () = bb8_redis::redis::cmd("SADD")
            .arg(&idx)
            .arg(&members)
            .query_async(&mut conn)
            .await
            .unwrap();
        let response = logout(State(state), bearer(&issued.access_token))
            .await
            .into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the retry finds the device gone and revokes"
        );
        assert!(!alive(&client, &issued.access_token).await);
        hs.server.abort();
    }

    #[tokio::test]
    async fn teardown_flag1_off_best_effort_200() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-off-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![dev.clone()]).await;
        let state = strict_state(&client, &hs, false);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        hs.set(&dev, 500);
        let response = logout(State(state.clone()), bearer(&access))
            .await
            .into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "flag 1 off: best-effort 200"
        );
        assert!(!alive(&client, &access).await, "and the tokens are revoked");
        // The device routes and logout/all too.
        let a = seed_grant(&client, &user, &format!("DEVICE_B{n}"))
            .await
            .access_token;
        hs.set(&format!("DEVICE_C{n}"), 500);
        let c = seed_grant(&client, &user, &format!("DEVICE_C{n}"))
            .await
            .access_token;
        let response = delete_device(
            State(state.clone()),
            Path(format!("DEVICE_C{n}")),
            bearer(&a),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!alive(&client, &c).await);
        let response = logout_all(State(state), bearer(&a)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!alive(&client, &a).await);
        hs.server.abort();
    }

    #[tokio::test]
    async fn logout_all_flag1_one_failed_device_503_others_deleted_and_revoked() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("ss4-all-{n}");
        let [da, db, dc] = ["A", "B", "C"].map(|x| format!("DEVICE_{x}{n}"));
        let hs = scripted_homeserver(vec![da.clone(), db.clone(), dc.clone()]).await;
        let state = strict_state(&client, &hs, true);
        let a = seed_grant(&client, &user, &da).await.access_token;
        let b = seed_grant(&client, &user, &db).await.access_token;
        let c = seed_grant(&client, &user, &dc).await.access_token;
        hs.set(&dc, 500);
        let response = logout_all(State(state.clone()), bearer(&a))
            .await
            .into_response();
        let (status, body) = status_and_json(response).await;
        assert_retryable_503(status, &body, "strict logout/all, one device failed");
        assert!(!alive(&client, &b).await, "the deleted device is revoked");
        assert!(
            alive(&client, &c).await,
            "the failed device keeps its grant"
        );
        assert!(alive(&client, &a).await, "the bearer stays for the retry");
        assert!(!hs.calls().contains(&da), "the bearer's device goes last");
        hs.heal();
        let response = logout_all(State(state), bearer(&a)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK, "the retry finishes");
        assert!(!alive(&client, &a).await && !alive(&client, &c).await);
        assert!(hs.calls().contains(&da));
        hs.server.abort();
    }

    #[tokio::test]
    async fn delete_devices_flag1_partial_failure_503_retry_idempotent() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let user = format!("ss4-bulk-{n}");
        let [da, db, dc] = ["A", "B", "C"].map(|x| format!("DEVICE_{x}{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let a = seed_grant(&client, &user, &da).await.access_token;
        let b = seed_grant(&client, &user, &db).await.access_token;
        let c = seed_grant(&client, &user, &dc).await.access_token;
        hs.set(&dc, 503);
        let call = |state: CompatState| {
            let (a, db, dc) = (a.clone(), db.clone(), dc.clone());
            async move {
                delete_devices(
                    State(state),
                    bearer(&a),
                    Json(DeleteDevicesRequest {
                        devices: vec![db, dc],
                    }),
                )
                .await
                .into_response()
            }
        };
        let (status, body) = status_and_json(call(state.clone()).await).await;
        assert_retryable_503(status, &body, "strict delete_devices, one device failed");
        assert!(!alive(&client, &b).await, "the deleted device is revoked");
        assert!(alive(&client, &c).await, "the failed one is not");
        hs.heal();
        let response = call(state).await;
        assert_eq!(response.status(), StatusCode::OK, "the retry is idempotent");
        assert!(!alive(&client, &c).await);
        assert!(
            alive(&client, &a).await,
            "the bearer's own device is untouched"
        );
        assert_eq!(hs.calls(), [db.clone(), dc.clone(), db, dc]);
        client.revoke_grants_for_device(&user, &da).await.ok();
        hs.server.abort();
    }

    // -- SS4 flag 2: deleted-id markers (8.12) ---------------------------------

    /// [`strict_state`] with flag 2's markers at `ttl` (`None`: flag 2 off).
    fn marker_state(
        client: &RedisClient,
        hs: &Scripted,
        strict: bool,
        ttl: Option<u64>,
    ) -> CompatState {
        let mut state = strict_state(client, hs, strict);
        state.synapse_client = Some(Arc::new(
            SynapseClient::new(&hs.url, "secret")
                .with_admin_mint(client.clone(), "ss4-admin".into(), 300)
                .with_strict_teardown(strict)
                .with_deleted_markers(ttl),
        ));
        state
    }

    async fn marked(client: &RedisClient, user: &str, device: &str) -> bool {
        client.is_deleted_device(user, device).await.unwrap()
    }

    /// Run every compat delete path once against `state`, one device each:
    /// `/logout`, `/logout/all` (two listed devices), `DELETE /devices/{id}`,
    /// `delete_devices`, and revoke (deletes only under flag 1). Returns
    /// `(path, user, device, status)` per deleted device.
    async fn run_compat_delete_paths(
        client: &RedisClient,
        hs: &Scripted,
        strict: bool,
        ttl: Option<u64>,
        tag: &str,
    ) -> Vec<(&'static str, String, String, StatusCode)> {
        let n = nonce();
        let state = marker_state(client, hs, strict, ttl);
        let mut out = Vec::new();
        let (user, dev) = (format!("ss4-mk-lo-{tag}{n}"), format!("DEVICE_A{n}"));
        let a = seed_grant(client, &user, &dev).await.access_token;
        let status = logout(State(state.clone()), bearer(&a))
            .await
            .into_response()
            .status();
        out.push(("logout", user, dev, status));

        let user = format!("ss4-mk-all-{tag}{n}");
        let [da, db] = ["A", "B"].map(|x| format!("DEVICE_{x}{n}"));
        let hs_all = scripted_homeserver(vec![da.clone(), db.clone()]).await;
        let state_all = marker_state(client, &hs_all, strict, ttl);
        let a = seed_grant(client, &user, &da).await.access_token;
        seed_grant(client, &user, &db).await;
        let status = logout_all(State(state_all), bearer(&a))
            .await
            .into_response()
            .status();
        out.push(("logout_all", user.clone(), da, status));
        out.push(("logout_all", user, db, status));
        hs_all.server.abort();

        let user = format!("ss4-mk-del-{tag}{n}");
        let [da, db, dc] = ["A", "B", "C"].map(|x| format!("DEVICE_{x}{n}"));
        let a = seed_grant(client, &user, &da).await.access_token;
        seed_grant(client, &user, &db).await;
        seed_grant(client, &user, &dc).await;
        let status = delete_device(State(state.clone()), Path(db.clone()), bearer(&a))
            .await
            .into_response()
            .status();
        out.push(("DELETE /devices/{id}", user.clone(), db, status));
        let status = delete_devices(
            State(state.clone()),
            bearer(&a),
            Json(DeleteDevicesRequest {
                devices: vec![dc.clone()],
            }),
        )
        .await
        .into_response()
        .status();
        out.push(("delete_devices", user.clone(), dc, status));
        client.revoke_grants_for_device(&user, &da).await.ok();

        if strict {
            let (user, dev) = (format!("ss4-mk-rev-{tag}{n}"), format!("DEVICE_A{n}"));
            let issued = seed_grant(client, &user, &dev).await;
            let status = revoke_status(&state, issued.refresh_token.as_deref().unwrap()).await;
            out.push(("revoke (flag 1)", user, dev, status));
        }
        out
    }

    #[tokio::test]
    async fn marker_planted_on_every_delete_path_flag2_on() {
        let Some(client) = redis().await else { return };
        let hs = scripted_homeserver(vec![]).await;
        // Flag 2 alone (best-effort teardown) and flags 1 + 2 (strict). The
        // account paths (MSC4191, deactivate, erase) and the guest claim have the
        // same-named tests in `account` and `guest::claim`.
        for strict in [false, true] {
            for (path, user, dev, status) in
                run_compat_delete_paths(&client, &hs, strict, Some(600), "on").await
            {
                assert_eq!(status, StatusCode::OK, "{path} (flag 1 {strict})");
                assert!(
                    marked(&client, &user, &dev).await,
                    "{path} (flag 1 {strict}) plants the marker"
                );
            }
        }
        hs.server.abort();
    }

    #[tokio::test]
    async fn marker_not_planted_flag2_off() {
        let Some(client) = redis().await else { return };
        let hs = scripted_homeserver(vec![]).await;
        for (path, user, dev, status) in
            run_compat_delete_paths(&client, &hs, false, None, "off").await
        {
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(
                !marked(&client, &user, &dev).await,
                "{path}: no marker with flag 2 off"
            );
        }
        hs.server.abort();
    }

    #[tokio::test]
    async fn marker_not_planted_when_synapse_delete_failed() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let hs = scripted_homeserver(vec![]).await;
        for (strict, code) in [(false, 500), (true, 500), (false, 403), (true, 403)] {
            let user = format!("ss4-mk-fail-{strict}-{code}-{n}");
            let dev = format!("DEVICE_A{n}{code}");
            hs.set(&dev, code);
            let state = marker_state(&client, &hs, strict, Some(600));
            let a = seed_grant(&client, &user, &dev).await.access_token;
            logout(State(state), bearer(&a)).await;
            assert!(
                !marked(&client, &user, &dev).await,
                "Synapse {code} (flag 1 {strict}): the device may still be listed, no marker"
            );
            client.revoke_grants_for_device(&user, &dev).await.ok();
        }
        hs.server.abort();
    }

    #[tokio::test]
    async fn marker_ttl_is_the_configured_value() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let hs = scripted_homeserver(vec![]).await;
        let (user, dev) = (format!("ss4-mk-ttl-{n}"), format!("DEVICE_A{n}"));
        let state = marker_state(&client, &hs, true, Some(4242));
        let a = seed_grant(&client, &user, &dev).await.access_token;
        assert_eq!(
            logout(State(state), bearer(&a))
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        let raw =
            bb8_redis::redis::Client::open(siwx_oidc::test_support::redis_url().as_str()).unwrap();
        let mut conn = raw.get_multiplexed_async_connection().await.unwrap();
        let key = format!("deleted:device/{user}/{dev}");
        let ttl: i64 = bb8_redis::redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!((4230..=4242).contains(&ttl), "TTL {ttl}");
        let value: String = bb8_redis::redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let ms: i64 = value.parse().unwrap();
        let now = client.server_time_ms().await.unwrap();
        assert!(
            ms <= now && now - ms < 60_000,
            "the value is the delete time in ms"
        );
        hs.server.abort();
    }

    #[tokio::test]
    async fn revoke_matrix_grant_deletes_device_flag_on() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-rev-on-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let issued = seed_grant(&client, &user, &dev).await;
        assert_eq!(
            revoke_status(&state, issued.refresh_token.as_deref().unwrap()).await,
            StatusCode::OK
        );
        assert_eq!(hs.calls(), [dev], "flag 1: revoke deletes the device");
        assert!(!alive(&client, &issued.access_token).await);
        hs.server.abort();
    }

    #[tokio::test]
    async fn revoke_matrix_grant_keeps_device_flag_off() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-rev-off-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, false);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        assert_eq!(revoke_status(&state, &access).await, StatusCode::OK);
        assert!(hs.calls().is_empty(), "flag 1 off: revoke keeps the device");
        assert!(!alive(&client, &access).await);
        hs.server.abort();
    }

    #[tokio::test]
    async fn revoke_non_matrix_grant_keeps_tokens_only() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-rev-oidc-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let issued = client
            .issue_grant(&NewGrant {
                kind: GrantKind::Oidc,
                username: user.clone(),
                did: format!("did:key:z{user}"),
                client_id: "compat-test".into(),
                confidential_client: false,
                device_id: dev.clone(),
                scope: "openid".into(),
                name: user.clone(),
                auth_ms: None,
                access_ttl: ACCESS_TOKEN_TTL,
                refresh_inactivity_secs: Some(120),
                absolute_deadline: None,
            })
            .await
            .unwrap();
        assert_eq!(
            revoke_status(&state, &issued.access_token).await,
            StatusCode::OK
        );
        assert!(
            hs.calls().is_empty(),
            "an oidc grant's revoke never deletes a device"
        );
        assert!(!alive(&client, &issued.access_token).await);
        client.revoke_grants_for_device(&user, &dev).await.ok();
        hs.server.abort();
    }

    #[tokio::test]
    async fn revoke_flag_on_transient_synapse_failure_503() {
        let Some(client) = redis().await else { return };
        let n = nonce();
        let (user, dev) = (format!("ss4-rev-503-{n}"), format!("DEVICE_A{n}"));
        let hs = scripted_homeserver(vec![]).await;
        let state = strict_state(&client, &hs, true);
        let access = seed_grant(&client, &user, &dev).await.access_token;
        hs.set(&dev, 502);
        assert_eq!(
            revoke_status(&state, &access).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            alive(&client, &access).await,
            "a transient fault revokes nothing"
        );
        hs.heal();
        assert_eq!(revoke_status(&state, &access).await, StatusCode::OK);
        assert!(!alive(&client, &access).await);
        hs.server.abort();
    }
}
