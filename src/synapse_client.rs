//! HTTP client for Synapse's management endpoints, as the delegated auth
//! provider for a Synapse homeserver.
//!
//! # Two authentication schemes, and why
//!
//! Synapse **1.157 deleted** the `experimental_features.msc3861.admin_token`
//! shim that made the MAS shared secret usable as a server-admin credential.
//! From 1.157 on (verified live against **1.159.0**) the shared secret is
//! honoured on exactly one surface, and the calls here split accordingly:
//!
//! | Surface | Auth | Calls |
//! |---|---|---|
//! | `/_synapse/mas/*` | `Authorization: Bearer {shared_secret}`, compared for **exact string equality** against `matrix_authentication_service.secret` | `provision_user`, `upsert_device`, `allow_cross_signing_reset`, `is_localpart_available`, `delete_device`, `deactivate_user`, `reactivate_user` |
//! | `/_synapse/admin/*` and the authenticated C-S API | a **minted, admin-scoped access token** ([`crate::admin_token`]) | `list_devices`, `get_device`, `has_cross_signing_keys` |
//!
//! Presenting the shared secret on the second surface answers **401
//! `M_UNKNOWN_TOKEN`** on 1.159 — it is not a token at all there, it is a
//! shared secret. That is why this client can mint itself a real access token;
//! see [`SynapseClient::with_admin_mint`].
//!
//! # The MAS wire format is localpart-scoped
//!
//! `/_synapse/mas/*` routes are **literal path segments** (Twisted `putChild`,
//! `synapse/rest/synapse/mas/__init__.py`) and every identifier travels in the
//! JSON body or a query param as a bare `localpart`. There are no `{mxid}` path
//! parameters and no percent-encoding to get right — unlike the admin API,
//! which does take a percent-encoded mxid path segment. Do not "unify" the two.

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use siwx_oidc::db::{DBClient, RedisClient};

use crate::admin_token::{admin_token_metadata, ADMIN_DISPLAY_NAME, ADMIN_TOKEN_PREFIX};
use crate::introspect::generate_opaque_token;

/// A user's device/session as reported by Synapse's admin API.
///
/// Used to render MSC4191 `devices_list` / `device_view`. All fields beyond
/// `device_id` are best-effort (Synapse returns `null` for never-seen devices).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfo {
    pub device_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub last_seen_ip: Option<String>,
    /// Last-seen timestamp in milliseconds since the Unix epoch.
    #[serde(default)]
    pub last_seen_ts: Option<i64>,
}

/// Build a fully-qualified Matrix user id (`@localpart:server_name`).
fn matrix_user_id(localpart: &str, server_name: &str) -> String {
    format!("@{}:{}", localpart, server_name)
}

/// A human hint appended to admin-scoped error messages so an auth failure is
/// never mistaken for a missing device / absent user. Empty for non-auth
/// failures.
///
/// The 1.154-era wording ("check that the MAS shared secret is also Synapse's
/// `admin_token`") is deliberately gone: on 1.157+ there IS no `admin_token`
/// setting to check, and pointing an operator at it sent them looking for a
/// config key that no longer exists.
fn admin_status_hint(status: reqwest::StatusCode) -> &'static str {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        " — Synapse rejected the minted admin token (its scope must carry both \
         urn:matrix:client:api:* and urn:synapse:admin:*, and its `username` must \
         resolve to a real Synapse user)"
    } else {
        ""
    }
}

/// A cached minted admin token and the instant it stops being safe to reuse.
struct CachedAdminToken {
    token: String,
    /// Unix seconds. Deliberately EARLIER than the token's true `exp` — see
    /// [`ADMIN_TOKEN_REUSE_MARGIN_SECS`].
    reuse_until: i64,
}

/// Safety margin subtracted from a minted token's TTL before it is reused.
///
/// A token handed to Synapse must still be valid when Synapse introspects it,
/// not merely when we picked it off the cache. The margin covers that round
/// trip plus clock skew between the two containers. It is NOT about Synapse's
/// 2-minute introspection cache, which only ever makes a token live *longer*
/// than it should.
const ADMIN_TOKEN_REUSE_MARGIN_SECS: i64 = 15;

/// Everything the client needs to mint itself an admin-scoped access token.
///
/// Present only when siwx-oidc is running with both a Synapse endpoint and a
/// token store; absent in unit tests and in standalone deployments, where the
/// admin-scoped calls degrade to a clear error instead of a panic.
struct AdminMint {
    db: RedisClient,
    /// Localpart the minted token's `username` claim resolves to.
    localpart: String,
    /// Already clamped to the permitted window by the caller.
    ttl: u64,
    cached: Mutex<Option<CachedAdminToken>>,
}

/// Client for Synapse's management endpoints.
///
/// Carries BOTH credentials described in the module docs: the MAS shared secret
/// (for `/_synapse/mas/*`) and, when configured, the ability to mint a
/// short-lived admin-scoped access token (for `/_synapse/admin/*` and the
/// authenticated client-server API).
pub struct SynapseClient {
    endpoint: String,
    shared_secret: String,
    http: Client,
    admin: Option<AdminMint>,
}

impl SynapseClient {
    /// Create a new client targeting the given Synapse base URL.
    ///
    /// `endpoint` is the scheme + host (+ optional port) of the Synapse instance,
    /// e.g. `http://localhost:8008`. Trailing slashes are stripped.
    ///
    /// The client created here can call `/_synapse/mas/*` only. Chain
    /// [`with_admin_mint`](Self::with_admin_mint) to enable the admin-scoped
    /// calls.
    pub fn new(endpoint: &str, shared_secret: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            shared_secret: shared_secret.to_string(),
            http: Client::new(),
            admin: None,
        }
    }

    /// Enable the admin-scoped calls by giving the client a token store to mint
    /// into.
    ///
    /// `ttl` must already be clamped by
    /// [`crate::admin_token::clamp_admin_token_ttl`]; the clamp is the
    /// enforcement point for the "short TTL, minted on demand" invariant and
    /// belongs at the single configuration boundary, not here.
    pub fn with_admin_mint(mut self, db: RedisClient, localpart: String, ttl: u64) -> Self {
        self.admin = Some(AdminMint {
            db,
            localpart,
            ttl,
            cached: Mutex::new(None),
        });
        self
    }

    /// Return a usable admin-scoped bearer token, minting one if the cache is
    /// empty or too close to expiry.
    ///
    /// The mint is idempotent and cheap (one Redis `SET`), so the cache exists
    /// to avoid a Synapse round trip per call, not to avoid a Redis write.
    ///
    /// Fails **closed**: any error propagates and the caller's request is not
    /// attempted, rather than being sent unauthenticated and answering a
    /// confusing 401 from Synapse.
    async fn admin_bearer(&self) -> Result<String> {
        let admin = self.admin.as_ref().context(
            "admin-scoped Synapse call attempted without a token store; \
             siwx-oidc must be configured with SIWEOIDC_REDIS_URL, \
             SIWEOIDC_SYNAPSE_ENDPOINT and SIWEOIDC_MAS_SHARED_SECRET",
        )?;

        let mut cached = admin.cached.lock().await;
        let now = Utc::now().timestamp();
        if let Some(c) = cached.as_ref() {
            if now < c.reuse_until {
                return Ok(c.token.clone());
            }
        }

        // Requirement 3 of `crate::admin_token`: Synapse resolves the
        // introspected `username` against its own `users` table and raises
        // AuthError(500, "User not found") if the row is missing. The existence
        // probe comes first so the common path performs no write.
        if self
            .is_localpart_available(&admin.localpart)
            .await
            .context("admin mint: could not check whether the admin service user exists")?
        {
            info!(
                localpart = %admin.localpart,
                "synapse_client: provisioning the admin service user"
            );
            self.provision_user(&admin.localpart, ADMIN_DISPLAY_NAME)
                .await
                .context("admin mint: could not provision the admin service user")?;
        }

        let token = generate_opaque_token(ADMIN_TOKEN_PREFIX);
        let metadata = admin_token_metadata(&admin.localpart, admin.ttl, now);
        admin
            .db
            .set_token(&token, &metadata, admin.ttl)
            .await
            .context("admin mint: could not store the minted token")?;

        debug!(
            localpart = %admin.localpart,
            ttl_secs = admin.ttl,
            "synapse_client: minted an admin-scoped token for its own use"
        );

        *cached = Some(CachedAdminToken {
            token: token.clone(),
            reuse_until: now + admin.ttl as i64 - ADMIN_TOKEN_REUSE_MARGIN_SECS,
        });
        Ok(token)
    }

    /// Drop the cached admin token so the next call mints a fresh one.
    async fn invalidate_admin_token(&self) {
        if let Some(admin) = self.admin.as_ref() {
            *admin.cached.lock().await = None;
        }
    }

    /// Send an admin-scoped request, re-minting **once** on 401/403.
    ///
    /// The retry is not defensive padding: a cached token can be rejected for
    /// reasons that a fresh mint genuinely fixes — the token store was flushed
    /// out from under us, or the admin service user was deleted (the re-mint
    /// re-provisions it). Retrying once converts those into a self-heal instead
    /// of a user-visible failure, and a second 401 is surfaced honestly.
    ///
    /// `build` is called once per attempt because a `RequestBuilder` is consumed
    /// by `send()`.
    async fn admin_request<F>(&self, build: F) -> Result<reqwest::Response>
    where
        F: Fn(&Client, &str) -> reqwest::RequestBuilder,
    {
        let token = self.admin_bearer().await?;
        let resp = build(&self.http, &token).send().await?;

        let status = resp.status();
        if status != reqwest::StatusCode::UNAUTHORIZED && status != reqwest::StatusCode::FORBIDDEN {
            return Ok(resp);
        }

        warn!(
            %status,
            "synapse_client: admin token rejected; re-minting and retrying once"
        );
        self.invalidate_admin_token().await;
        let token = self.admin_bearer().await?;
        Ok(build(&self.http, &token).send().await?)
    }

    /// Provision (register) a user in Synapse.
    ///
    /// If the user already exists Synapse returns 200 and updates the display name.
    pub async fn provision_user(&self, localpart: &str, display_name: &str) -> Result<()> {
        let url = format!("{}/_synapse/mas/provision_user", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&json!({
                "localpart": localpart,
                "set_displayname": display_name,
            }))
            .send()
            .await
            .context("provision_user: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "provision_user failed");
            anyhow::bail!("provision_user: HTTP {status}");
        }
        Ok(())
    }

    /// Create or update a device for a user.
    ///
    /// If the device already exists its display name is updated.
    pub async fn upsert_device(
        &self,
        localpart: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/_synapse/mas/upsert_device", self.endpoint);
        let mut body = json!({
            "localpart": localpart,
            "device_id": device_id,
        });
        if let Some(name) = display_name {
            body["display_name"] = json!(name);
        }

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&body)
            .send()
            .await
            .context("upsert_device: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            warn!(%status, body = %body_text, "upsert_device failed");
            anyhow::bail!("upsert_device: HTTP {status}");
        }
        Ok(())
    }

    /// Allow the user to reset their cross-signing keys on next login.
    pub async fn allow_cross_signing_reset(&self, localpart: &str) -> Result<()> {
        let url = format!("{}/_synapse/mas/allow_cross_signing_reset", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&json!({ "localpart": localpart }))
            .send()
            .await
            .context("allow_cross_signing_reset: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "allow_cross_signing_reset failed");
            anyhow::bail!("allow_cross_signing_reset: HTTP {status}");
        }
        Ok(())
    }

    /// Read back whether the user currently has a **published master cross-signing
    /// key** server-side (`POST /_matrix/client/v3/keys/query`, reading
    /// `master_keys[user_id]` presence).
    ///
    /// This is the empirically-faithful signal for the `e2e_cross_signing_keys`
    /// master row that gates `keys/device_signing/upload` under MSC3861: Synapse's
    /// upload gate (`rest/client/keys.py`) 401s ONLY when `is_cross_signing_setup`
    /// (a master row exists) AND the UIA-bypass window is not in the future. So the
    /// master-present bit is the load-bearing input to deciding whether a
    /// just-granted reset is effective for the next upload (see
    /// [`account::reset_outcome`]).
    ///
    /// History: removed 2026-06-18 (it had been mis-used as a racy approval-time
    /// pre-flight in `device_auth.rs` that produced a false "no Secure Backup"
    /// warning). Re-introduced 2026-06-24 for POST-grant readback in the
    /// cross-signing-reset reauth path, where it does NOT race the client's
    /// bootstrap (it runs only after the user-initiated reset grant) and is used to
    /// gate the truthful-success signal, never a pre-flight warning. It does NOT
    /// expose the window timestamp (Synapse never returns it on this query); it
    /// reports master-row presence only.
    ///
    /// # Auth (changed for Synapse 1.157+)
    ///
    /// `KeyQueryServlet.on_POST` calls `self.auth.get_user_by_req(...)`
    /// **unconditionally** — there is no config flag that makes `keys/query`
    /// anonymous. Before 1.157 the MAS shared secret satisfied that check via
    /// the `admin_token` shim; on 1.159 it answers
    /// `401 M_UNKNOWN_TOKEN {"error":"Token is not active"}` (verified live).
    ///
    /// That 401 was NOT a loud failure: it surfaced as a `ResetUnconfirmed`
    /// readback, i.e. every cross-signing reset telling the user "we could not
    /// confirm your reset took effect" while the reset had in fact been
    /// granted. The call therefore uses a minted admin token.
    pub async fn has_cross_signing_keys(&self, localpart: &str, server_name: &str) -> Result<bool> {
        let user_id = matrix_user_id(localpart, server_name);
        let url = format!("{}/_matrix/client/v3/keys/query", self.endpoint);
        let body = json!({ "device_keys": { &user_id: [] } });
        let resp = self
            .admin_request(|http, token| http.post(&url).bearer_auth(token).json(&body))
            .await
            .context("has_cross_signing_keys: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "has_cross_signing_keys: query failed");
            anyhow::bail!("has_cross_signing_keys: HTTP {status}{}", admin_status_hint(status));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("has_cross_signing_keys: invalid JSON")?;

        let has_master = body
            .get("master_keys")
            .and_then(|mk| mk.get(&user_id))
            .is_some();

        Ok(has_master)
    }

    /// Check whether a localpart is available for registration.
    ///
    /// Returns `true` if the localpart is free, `false` if it is already taken.
    /// A 4xx response with errcode `M_USER_IN_USE` is treated as "not available"
    /// rather than an error.
    pub async fn is_localpart_available(&self, localpart: &str) -> Result<bool> {
        let url = format!(
            "{}/_synapse/mas/is_localpart_available?localpart={}",
            self.endpoint,
            urlencoding::encode(localpart)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.shared_secret)
            .send()
            .await
            .context("is_localpart_available: request failed")?;

        if resp.status().is_success() {
            return Ok(true);
        }

        // 4xx means the localpart is taken (M_USER_IN_USE or similar).
        if resp.status().is_client_error() {
            return Ok(false);
        }

        // 5xx or other unexpected status is a real error.
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(%status, %body, "is_localpart_available: unexpected response");
        anyhow::bail!("is_localpart_available: HTTP {status}");
    }

    /// Check whether a user's Synapse **profile row** exists
    /// (`GET /_matrix/client/v3/profile/{mxid}`, the unauthenticated client API —
    /// still sent with the shared secret bearer token for consistency with the
    /// rest of this client, though Synapse does not require it for this route).
    ///
    /// This is the half-provisioning discriminator behind the self-heal in
    /// [`crate::oidc::provision_synapse_device`]: the 2026-08-01 dev incident
    /// found an account with a Synapse `users` row but no `profiles` row (because
    /// `provision_user` failed transiently at first sign-in), which then silently
    /// failed every subsequent displayname write. See
    /// `docs/superpowers/plans/2026-08-01-provision-retry-hardening.md`.
    ///
    /// **Discriminator corrected 2026-08-02 (live-falsified on Synapse 1.154.0):**
    /// the original "any 404 means the row is absent" premise was wrong — Synapse
    /// ALSO 404s a row that exists but is empty (displayname AND avatar_url both
    /// null), which made the first version of this heal clobber a
    /// deliberately-cleared displayname back to the DID (observed live). Both 404
    /// shapes were measured live and are discriminated by the JSON `errcode`
    /// field (the primary key — the human-readable `error` string is not part of
    /// any stability contract and may drift across Synapse versions):
    ///
    /// | HTTP | `errcode` | `error` (measured example) | Row state | Heal? |
    /// |------|-----------|------------------------------|-----------|-------|
    /// | 200 | — | — | present (any displayname/avatar, incl. both null) | no |
    /// | 404 | `M_UNKNOWN` | `"No row found"` | **truly absent** | **yes** |
    /// | 404 | `M_NOT_FOUND` | `"Profile was not found"` | present, empty (displayname+avatar both null) | no |
    /// | 404 | anything else / unparseable body | — | unknown — FAIL SAFE | no |
    ///
    /// The fail-safe row exists because healing (re-running `provision_user`) is
    /// the destructive direction: it can clobber a real, empty profile, whereas
    /// wrongly skipping a heal just leaves the account half-provisioned for one
    /// more login (already loud at `error!`). See `profile_404_means_row_absent`
    /// (below) for the pure decision function and its unit tests.
    ///
    /// **Erasure interplay:** a GDPR-erased account (`account::execute_action`'s
    /// `org.matrix.account_erase`, which purges the profile via Synapse admin
    /// `deactivate(erase: true)`) also 404s as "truly absent" by this same
    /// discriminator. If an erased account ever completed sign-in again this
    /// heal would resurrect a bare profile row (`displayname = DID`) — accepted,
    /// since that reveals nothing beyond the mxid the caller already presented.
    ///
    /// Returns `Ok(true)` when the row is present (200, or a 404 the
    /// discriminator reads as present/unknown — the fail-safe default), `Ok(false)`
    /// only for a discriminator-confirmed absent row, `Err` for any non-404 error
    /// response or transport failure.
    pub async fn has_profile_row(&self, localpart: &str, server_name: &str) -> Result<bool> {
        let user_id = matrix_user_id(localpart, server_name);
        let url = format!(
            "{}/_matrix/client/v3/profile/{}",
            self.endpoint,
            urlencoding::encode(&user_id)
        );
        // AUTH (verified live on 1.159, both legs): `ProfileRestServlet.on_GET`
        // authenticates only `if self.hs.config.server.require_auth_for_profile_requests`,
        // which defaults to FALSE. So this endpoint answers 200 with no
        // Authorization header at all, and the shared secret this used to send
        // was simply ignored rather than honoured — it did not break in the
        // 1.157 admin_token removal, and it was never doing anything.
        //
        // A minted admin token is attached when one is available so the call
        // keeps working on a deployment that DOES set
        // `require_auth_for_profile_requests: true`. Best-effort by design: this
        // sits on the login-time provisioning self-heal path, so a mint failure
        // must degrade to the unauthenticated request that works today, never
        // fail the login.
        let mut req = self.http.get(&url);
        if self.admin.is_some() {
            match self.admin_bearer().await {
                Ok(token) => req = req.bearer_auth(token),
                Err(e) => debug!(
                    error = %e,
                    "has_profile_row: no admin token available; sending unauthenticated \
                     (fine unless require_auth_for_profile_requests is set)"
                ),
            }
        }
        let resp = req
            .send()
            .await
            .context("has_profile_row: request failed")?;

        if resp.status().is_success() {
            return Ok(true);
        }
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let body = resp.text().await.unwrap_or_default();
            let row_absent = profile_404_means_row_absent(&body);
            if !row_absent {
                debug!(
                    %body,
                    "has_profile_row: 404 read as a present-but-empty (or unrecognized) profile shape — treating as present, skipping heal"
                );
            }
            return Ok(!row_absent);
        }

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(%status, %body, "has_profile_row: unexpected response");
        anyhow::bail!("has_profile_row: HTTP {status}");
    }

    /// List a user's devices via the Synapse admin API
    /// (`GET /_synapse/admin/v2/users/{user_id}/devices`).
    ///
    /// **There is no MAS equivalent.** `synapse/rest/synapse/mas/devices.py` on
    /// 1.159 exposes only `upsert_device`, `delete_device`,
    /// `update_device_display_name` and `sync_devices` — all POST, all
    /// write-only. `sync_devices` looks list-shaped but is a reconciliation
    /// call: it takes the desired device list and returns `{}`, never the
    /// server's list. So reading devices REQUIRES the admin API, which since
    /// 1.157 requires a real admin-scoped access token.
    ///
    /// Authenticated with a minted admin token ([`crate::admin_token`]), NOT the
    /// shared secret — the shared secret answers 401 on `/_synapse/admin/*`.
    pub async fn list_devices(
        &self,
        localpart: &str,
        server_name: &str,
    ) -> Result<Vec<DeviceInfo>> {
        let user_id = matrix_user_id(localpart, server_name);
        let url = format!(
            "{}/_synapse/admin/v2/users/{}/devices",
            self.endpoint,
            urlencoding::encode(&user_id)
        );
        let resp = self
            .admin_request(|http, token| http.get(&url).bearer_auth(token))
            .await
            .context("list_devices: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "list_devices failed");
            anyhow::bail!("list_devices: HTTP {status}{}", admin_status_hint(status));
        }

        #[derive(Deserialize)]
        struct DevicesResponse {
            #[serde(default)]
            devices: Vec<DeviceInfo>,
        }
        let body: DevicesResponse = resp.json().await.context("list_devices: invalid JSON")?;
        Ok(body.devices)
    }

    /// Fetch a single device belonging to the user, or `None` if no device with
    /// that id is owned by the user.
    ///
    /// Implemented by listing the user's devices and filtering, so it inherently
    /// scopes the lookup to the authenticated user (a foreign `device_id` yields
    /// `None` rather than leaking another user's device).
    pub async fn get_device(
        &self,
        localpart: &str,
        device_id: &str,
        server_name: &str,
    ) -> Result<Option<DeviceInfo>> {
        Ok(self
            .list_devices(localpart, server_name)
            .await?
            .into_iter()
            .find(|d| d.device_id == device_id))
    }

    /// Delete a user's device via the MAS API
    /// (`POST /_synapse/mas/delete_device`, body `{localpart, device_id}`).
    ///
    /// Ported from `DELETE /_synapse/admin/v2/users/{mxid}/devices/{device_id}`,
    /// which answers 401 on 1.157+. The MAS resource resolves the localpart
    /// itself and calls the same `device_handler.delete_devices`, so the
    /// behaviour is unchanged; only the wire format and the credential differ.
    ///
    /// Scoped to the user's own localpart, so a foreign `device_id` cannot
    /// affect another user. Deleting the device invalidates Synapse's cached
    /// access token for it. Answers **204 No Content** on success.
    ///
    /// `server_name` is no longer sent — the MAS API is localpart-scoped — and
    /// is kept only to log the mxid an operator would actually grep for, and so
    /// that every account-management call site keeps one uniform precondition.
    pub async fn delete_device(
        &self,
        localpart: &str,
        device_id: &str,
        server_name: &str,
    ) -> Result<()> {
        let url = format!("{}/_synapse/mas/delete_device", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&json!({ "localpart": localpart, "device_id": device_id }))
            .send()
            .await
            .context("delete_device: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let user_id = matrix_user_id(localpart, server_name);
            warn!(%status, %body, %user_id, %device_id, "delete_device failed");
            anyhow::bail!("delete_device: HTTP {status}{}", mas_status_hint(status));
        }
        Ok(())
    }

    /// Deactivate a user's account via the MAS API
    /// (`POST /_synapse/mas/delete_user`, body `{localpart, erase}`).
    ///
    /// Ported from `POST /_synapse/admin/v1/deactivate/{mxid}`, which answers
    /// 401 on 1.157+.
    ///
    /// # The `erase` flag means exactly what it meant before
    ///
    /// This was the one semantic risk in the port, because the endpoint is named
    /// `delete_user` rather than `deactivate`. It is not a deletion: the
    /// resource is a thin pass-through to the SAME handler the old admin route
    /// used —
    /// `deactivate_account_handler.deactivate_account(user_id, erase_data=erase)`
    /// — with no branching of its own. So the reversible/irreversible
    /// distinction this codebase depends on is preserved:
    ///
    /// * `erase = false` → deactivation only; profile and media are kept, and
    ///   the account is restorable via [`reactivate_user`](Self::reactivate_user).
    ///   This backs `/account?action=org.matrix.account_deactivate`.
    /// * `erase = true` → the same deactivation **plus** GDPR erasure of the
    ///   user's data. Irreversible. This backs
    ///   `/account?action=org.matrix.account_erase`.
    ///
    /// `erase` is a **required** `StrictBool` in the MAS request model (no
    /// default, and no coercion from `"true"` or `1`), so it must be sent as a
    /// real JSON boolean or the request fails validation. Omitting it would NOT
    /// quietly default to the safe value.
    pub async fn deactivate_user(
        &self,
        localpart: &str,
        server_name: &str,
        erase: bool,
    ) -> Result<()> {
        let url = format!("{}/_synapse/mas/delete_user", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&deactivate_body(localpart, erase))
            .send()
            .await
            .context("deactivate_user: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let user_id = matrix_user_id(localpart, server_name);
            warn!(%status, %body, %user_id, erase, "deactivate_user failed");
            anyhow::bail!("deactivate_user: HTTP {status}{}", mas_status_hint(status));
        }
        Ok(())
    }

    /// Reactivate a previously (non-erased) deactivated account via the MAS API
    /// (`POST /_synapse/mas/reactivate_user`, body `{localpart}`).
    ///
    /// Ported from `PUT /_synapse/admin/v2/users/{mxid}` with
    /// `{"deactivated": false}`, which answers 401 on 1.157+. The MAS resource
    /// calls `deactivate_account_handler.activate_account(user_id)` — the same
    /// handler the admin PUT reached — so the semantics carry over, including
    /// the constraint that only an `erase = false` deactivation can be restored.
    ///
    /// The historical worry that reactivation demands a local password does not
    /// apply here at all: the MAS body carries only the localpart, so there is
    /// no `password` key that could be missing. (It did not apply to the old
    /// admin PUT either — live probe, 2026-06-10, section 3 of
    /// `scripts/verify-lifecycle-live.sh`.) This method still surfaces a clear
    /// error on any non-success response.
    pub async fn reactivate_user(&self, localpart: &str, server_name: &str) -> Result<()> {
        let url = format!("{}/_synapse/mas/reactivate_user", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&reactivate_body(localpart))
            .send()
            .await
            .context("reactivate_user: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let user_id = matrix_user_id(localpart, server_name);
            warn!(%status, %body, %user_id, "reactivate_user failed");
            anyhow::bail!("reactivate_user: HTTP {status}{}", mas_status_hint(status));
        }
        Ok(())
    }
}

/// A human hint for a failed `/_synapse/mas/*` call.
///
/// The MAS surface rejects a bad credential with **403** ("This endpoint must
/// only be called by MAS"), not 401, and a 404 there means Synapse has never
/// heard of the localpart — two failures that look nothing alike but are easy
/// to confuse in a log.
fn mas_status_hint(status: reqwest::StatusCode) -> &'static str {
    match status {
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::UNAUTHORIZED => {
            " — Synapse rejected the MAS shared secret (it must equal \
             matrix_authentication_service.secret in homeserver.yaml)"
        }
        reqwest::StatusCode::NOT_FOUND => " — no such user on this homeserver",
        _ => "",
    }
}

/// Build the JSON body for `POST /_synapse/mas/delete_user`.
///
/// `erase` is the GDPR selector (see [`SynapseClient::deactivate_user`]).
/// Factored out so the parameter mapping can be unit-tested without a live
/// homeserver — this is the seam that pins "deactivate" and "erase" to the one
/// endpoint that now serves both.
fn deactivate_body(localpart: &str, erase: bool) -> serde_json::Value {
    json!({ "localpart": localpart, "erase": erase })
}

/// Build the JSON body for `POST /_synapse/mas/reactivate_user`. Factored out
/// so the body shape can be unit-tested.
fn reactivate_body(localpart: &str) -> serde_json::Value {
    json!({ "localpart": localpart })
}

/// Discriminate a 404 response body from `GET /_matrix/client/v3/profile/{mxid}`,
/// distinguishing a truly ABSENT profile row from a row that exists but is
/// empty (both `displayname` and `avatar_url` null — Synapse 1.154.0 also 404s
/// that case). See the table on [`SynapseClient::has_profile_row`] for the
/// live-measured shapes this decodes.
///
/// `errcode` is the primary (and only) signal: `"M_UNKNOWN"` means absent,
/// anything else (including `"M_NOT_FOUND"`, a missing `errcode`, or a body
/// that isn't valid JSON) means "not confirmed absent". The `error` message
/// text is deliberately NOT part of the gate — it is an informal, measured
/// signal only, since Synapse's human-readable strings are not covered by any
/// stability contract and may drift across versions; an `M_UNKNOWN` body with
/// unexpected `error` text still returns `true` here (errcode is primary).
///
/// FAIL-SAFE: any unrecognized shape returns `false` (present — do not heal).
/// Healing (re-running `provision_user`) is the destructive direction: it can
/// clobber a real, empty profile if this is wrong, whereas wrongly skipping a
/// heal only leaves an already-loud (`error!`-logged) half-provisioned account
/// unhealed for one more login.
fn profile_404_means_row_absent(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    value.get("errcode").and_then(|v| v.as_str()) == Some("M_UNKNOWN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_strips_trailing_slash() {
        let client = SynapseClient::new("http://localhost:8008/", "secret");
        assert_eq!(client.endpoint, "http://localhost:8008");
    }

    #[test]
    fn new_preserves_clean_url() {
        let client = SynapseClient::new("https://synapse.example.com", "s3cr3t");
        assert_eq!(client.endpoint, "https://synapse.example.com");
        assert_eq!(client.shared_secret, "s3cr3t");
    }

    #[test]
    fn matrix_user_id_builds_mxid() {
        assert_eq!(
            matrix_user_id("did-pkh-eip155-1-0xabc", "matrix.inblock.io"),
            "@did-pkh-eip155-1-0xabc:matrix.inblock.io"
        );
    }

    #[test]
    fn mxid_url_encoding_escapes_at_and_colon() {
        // The mxid must be percent-encoded for the admin-API path segment.
        let encoded = urlencoding::encode(&matrix_user_id("alice", "example.com")).into_owned();
        assert_eq!(encoded, "%40alice%3Aexample.com");
        assert!(!encoded.contains('@'));
        assert!(!encoded.contains(':'));
    }

    #[test]
    fn deactivate_body_reflects_erase_flag() {
        // `POST /_synapse/mas/delete_user` takes `{localpart, erase}`. The body
        // builder is the testable seam for the erase parameter, and this is the
        // ONE place the reversible/irreversible distinction is expressed:
        // erase=false is a plain deactivation (restorable by reactivate_user),
        // erase=true additionally GDPR-erases. Synapse routes both through the
        // same `deactivate_account(user_id, erase_data=erase)` handler, so the
        // flag is the whole difference.
        assert_eq!(
            deactivate_body("alice", false),
            json!({ "localpart": "alice", "erase": false })
        );
        assert_eq!(
            deactivate_body("alice", true),
            json!({ "localpart": "alice", "erase": true })
        );
    }

    #[test]
    fn deactivate_body_erase_is_a_real_json_bool() {
        // The MAS request model declares `erase: StrictBool` — pydantic strict,
        // so it accepts neither "true" nor 1, and it has NO default, meaning an
        // absent field is a validation error rather than a silent `false`.
        // Serialising it as a string or number would break account_deactivate
        // and account_erase together.
        for erase in [false, true] {
            let body = deactivate_body("alice", erase);
            assert!(
                body["erase"].is_boolean(),
                "erase must serialise as a JSON boolean, got {}",
                body["erase"]
            );
            assert!(body.get("erase").is_some(), "erase must always be present");
        }
    }

    #[test]
    fn mas_bodies_carry_a_bare_localpart_not_an_mxid() {
        // The MAS API is localpart-scoped: routes are literal path segments and
        // identifiers travel in the body. Sending an mxid here would 404 with
        // "no such user". This is the specific mistake the port had to avoid,
        // because the admin API it replaced took a percent-encoded mxid.
        for body in [deactivate_body("alice", false), reactivate_body("alice")] {
            let lp = body["localpart"].as_str().unwrap();
            assert_eq!(lp, "alice");
            assert!(!lp.contains('@'), "must not be an mxid: {lp}");
            assert!(!lp.contains(':'), "must not be an mxid: {lp}");
            assert!(!lp.contains('%'), "must not be percent-encoded: {lp}");
        }
    }

    #[test]
    fn reactivate_body_carries_only_the_localpart() {
        // `POST /_synapse/mas/reactivate_user` takes `{localpart}` and nothing
        // else. In particular there is no `password` key to omit — the old
        // concern that self-service reactivation demands a local password
        // cannot arise on this wire format at all.
        let body = reactivate_body("alice");
        assert_eq!(body, json!({ "localpart": "alice" }));
        assert!(body.get("password").is_none());
    }

    // -- profile_404_means_row_absent (2026-08-02 discriminator fix) --------
    //
    // Live-measured on Synapse 1.154.0. errcode is the primary (only) gate;
    // the error text is documented but not load-bearing.

    #[test]
    fn profile_404_m_unknown_no_row_found_is_absent() {
        // Truly missing row (never provisioned, or purged by account_erase).
        let body = r#"{"errcode":"M_UNKNOWN","error":"No row found"}"#;
        assert!(profile_404_means_row_absent(body));
    }

    #[test]
    fn profile_404_m_not_found_profile_was_not_found_is_present() {
        // Row exists but is empty (displayname AND avatar_url both null) —
        // Synapse 1.154.0 also 404s this shape. Must NOT be read as absent,
        // or the heal clobbers a deliberately-cleared displayname (observed
        // live before this fix).
        let body = r#"{"errcode":"M_NOT_FOUND","error":"Profile was not found"}"#;
        assert!(!profile_404_means_row_absent(body));
    }

    #[test]
    fn profile_404_empty_body_is_present_fail_safe() {
        assert!(!profile_404_means_row_absent(""));
    }

    #[test]
    fn profile_404_garbage_json_is_present_fail_safe() {
        assert!(!profile_404_means_row_absent("not json at all {{{"));
    }

    #[test]
    fn profile_404_m_unknown_unexpected_error_text_is_still_absent() {
        // errcode is the primary (and only) signal — the human-readable
        // `error` string is not part of any stability contract and may
        // drift across Synapse versions, so it must not gate the decision.
        let body = r#"{"errcode":"M_UNKNOWN","error":"some future wording Synapse might use"}"#;
        assert!(profile_404_means_row_absent(body));
    }

    #[test]
    fn profile_404_missing_errcode_is_present_fail_safe() {
        let body = r#"{"error":"something went wrong"}"#;
        assert!(!profile_404_means_row_absent(body));
    }

    #[test]
    fn admin_mint_is_opt_in() {
        // A bare client can call /_synapse/mas/* but must NOT silently pretend
        // it can reach the admin API. Unit tests and standalone deployments
        // build clients this way.
        let client = SynapseClient::new("http://localhost:8008", "secret");
        assert!(client.admin.is_none());
    }

    #[tokio::test]
    async fn admin_scoped_call_without_a_mint_fails_closed_with_a_clear_error() {
        // The failure mode that matters: with no token store configured, an
        // admin-scoped call must refuse locally with an actionable message,
        // NOT fall back to presenting the shared secret (which Synapse 1.157+
        // answers with a bare 401 that reads like a broken deployment).
        let client = SynapseClient::new("http://127.0.0.1:1", "secret");
        let err = client.admin_bearer().await.unwrap_err().to_string();
        assert!(
            err.contains("without a token store"),
            "error must name the missing precondition, got: {err}"
        );
    }

    #[test]
    fn admin_status_hint_no_longer_mentions_the_removed_admin_token_setting() {
        // Regression guard on operator-facing wording. `admin_token` was
        // DELETED in Synapse 1.157; telling an operator to go check it sends
        // them looking for a config key that does not exist.
        let hint = admin_status_hint(reqwest::StatusCode::UNAUTHORIZED);
        assert!(!hint.is_empty(), "a 401 must still be explained");
        assert!(
            !hint.contains("admin_token"),
            "must not point at the removed setting: {hint}"
        );
        assert!(hint.contains("urn:synapse:admin:*"));
        assert!(
            admin_status_hint(reqwest::StatusCode::NOT_FOUND).is_empty(),
            "a 404 is not an auth failure and must not carry the auth hint"
        );
    }

    #[test]
    fn mas_status_hint_distinguishes_a_bad_secret_from_an_unknown_user() {
        // The MAS surface rejects a bad credential with 403 ("This endpoint
        // must only be called by MAS"), NOT 401 — so both must be explained,
        // and a 404 there means the localpart is unknown, not unauthorised.
        for s in [
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::UNAUTHORIZED,
        ] {
            assert!(mas_status_hint(s).contains("matrix_authentication_service.secret"));
        }
        assert!(mas_status_hint(reqwest::StatusCode::NOT_FOUND).contains("no such user"));
        assert!(mas_status_hint(reqwest::StatusCode::INTERNAL_SERVER_ERROR).is_empty());
    }

    #[test]
    fn device_info_deserializes_full_record() {
        let json = r#"{
            "device_id": "ABCDEFGHIJ",
            "display_name": "Element Web",
            "last_seen_ip": "1.2.3.4",
            "last_seen_ts": 1700000000000,
            "last_seen_user_agent": "Mozilla/5.0",
            "user_id": "@alice:example.com"
        }"#;
        let d: DeviceInfo = serde_json::from_str(json).unwrap();
        assert_eq!(d.device_id, "ABCDEFGHIJ");
        assert_eq!(d.display_name.as_deref(), Some("Element Web"));
        assert_eq!(d.last_seen_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(d.last_seen_ts, Some(1700000000000));
    }

    #[test]
    fn device_info_tolerates_nulls_and_missing_fields() {
        // Never-seen devices report null/absent optional fields.
        let d: DeviceInfo =
            serde_json::from_str(r#"{"device_id":"X","display_name":null,"last_seen_ts":null}"#)
                .unwrap();
        assert_eq!(d.device_id, "X");
        assert_eq!(d.display_name, None);
        assert_eq!(d.last_seen_ip, None);
        assert_eq!(d.last_seen_ts, None);
    }

    #[test]
    fn devices_response_extracts_device_array() {
        // Mirrors the wrapper shape Synapse returns from the list endpoint.
        #[derive(serde::Deserialize)]
        struct DevicesResponse {
            #[serde(default)]
            devices: Vec<DeviceInfo>,
        }
        let body: DevicesResponse =
            serde_json::from_str(r#"{"devices":[{"device_id":"A"},{"device_id":"B"}],"total":2}"#)
                .unwrap();
        let ids: Vec<&str> = body.devices.iter().map(|d| d.device_id.as_str()).collect();
        assert_eq!(ids, vec!["A", "B"]);
    }
}
