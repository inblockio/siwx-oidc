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
//! | `/_synapse/mas/*` | `Authorization: Bearer {shared_secret}`, compared for **exact string equality** against `matrix_authentication_service.secret` | `provision_user`, `upsert_device`, `allow_cross_signing_reset`, `is_localpart_available`, `query_user`, `delete_device`, `deactivate_user`, `reactivate_user` |
//! | `/_synapse/admin/*` and the authenticated C-S API | a **minted, admin-scoped access token** ([`crate::admin_token`]) | `list_devices`, `get_device`, `has_cross_signing_keys`, `publish_did_field` |
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

/// What a profile read found.
///
/// `row_present` is the self-heal discriminator (see [`SynapseClient::read_profile`]);
/// `displayname` is the tier-1 alias as it stands right now, `None` when the
/// row has none, when the user cleared it, or when the read could not see one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileState {
    /// Whether Synapse has a `profiles` row for this user. Fail-safe: any
    /// ambiguous answer reads as `true`, because healing is the destructive
    /// direction.
    pub row_present: bool,
    /// The current displayname, if the read actually returned a non-empty one.
    pub displayname: Option<String>,
}

use crate::admin_token::{admin_token_metadata, ADMIN_DISPLAY_NAME, ADMIN_TOKEN_PREFIX};
use crate::did_assertion::DID_PROFILE_FIELD;
use crate::introspect::generate_opaque_token;

/// A user's account status as reported by the MAS query endpoint.
///
/// Mirrors `MasQueryUserResource.Response` in
/// `synapse/rest/synapse/mas/users.py` (verified against 1.159.0). Every field
/// past `user_id` is `#[serde(default)]` so a future Synapse that adds or drops
/// an optional field cannot turn this into a hard parse error on a security
/// gate path.
// Fields beyond `is_deactivated` are parsed for wire fidelity and future use
// (a suspension policy would key on `is_suspended`); they document the contract.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct MasUserInfo {
    pub user_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub is_suspended: bool,
    #[serde(default)]
    pub is_deactivated: bool,
}

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
///
/// `pub(crate)` so `oidc::provision_synapse_device` can build the `mxid` claim
/// of a DID assertion with the SAME function that builds the URL the assertion
/// is published to. A second `format!("@{localpart}:{server_name}")` elsewhere
/// would be a second definition of the binding this whole feature is about, and
/// the two could drift without any test noticing.
pub(crate) fn matrix_user_id(localpart: &str, server_name: &str) -> String {
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

/// Connect timeout for every Synapse call.
///
/// **`reqwest::Client::new()` has NO timeout of any kind** — that was the whole
/// of this client's configuration until 2026-09-10, which meant a black-holed
/// Synapse (SYNs dropped rather than refused) blocked each call until the
/// KERNEL gave up: Linux's `tcp_syn_retries` defaults to 6, i.e. ~127 seconds
/// per connect. "Best-effort, never fails sign-in" was true of Synapse *errors*
/// and false of Synapse *hangs*, and this branch made that much worse by
/// putting new awaits on the login path (`provision_synapse_device`'s profile
/// PUT, and `detected_mxid_for` — which turned
/// `POST /webauthn/authenticate/start`, a route with no Synapse dependency at
/// all before, into one with two `is_localpart_available` probes).
///
/// 2 seconds because every deployment reaches Synapse over loopback, a compose
/// network, or a LAN — `SIWEOIDC_SYNAPSE_ENDPOINT` is an internal address by
/// construction (it presents the MAS shared secret in the clear on the
/// `/_synapse/mas/*` surface, so it must never traverse the public internet).
/// A TCP handshake that has not completed in 2s on such a path is not slow, it
/// is gone.
const SYNAPSE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Total per-request timeout (connect + response + body) for every Synapse call.
///
/// 8 seconds, chosen from BOTH directions rather than picked round:
///
/// - **Upper bound.** Every one of these calls sits on an interactive path a
///   human is waiting on (sign-in, the passkey picker, an account action). The
///   slowest legitimate call is `provision_user` at a first sign-in, which is a
///   real registration + profile write on a possibly-loaded homeserver; 8s
///   leaves generous headroom over that while staying an order of magnitude
///   below the ~127s kernel default this replaces.
/// - **Lower bound.** A timeout SHORTER than a legitimately slow call would
///   manufacture failures rather than surface them. That is survivable here only
///   because every write this client issues is idempotent (`provision_user`,
///   `upsert_device`, `publish_did_field` are all re-run on the next sign-in),
///   but it would still spend a user-visible login on a retry. Do not tighten
///   this without checking that property still holds for every call site.
///
/// **Known residual — this bounds a CALL, not a LOGIN.** A single `/sign_in`
/// can make up to ~8 Synapse calls in sequence (two `is_localpart_available`
/// probes in `localpart::resolve_identity`, one more in
/// `oidc::provision_synapse_device`, `has_profile_row`, the profile PUT and its
/// D1 confirmation probe, `upsert_device`, `allow_cross_signing_reset`), plus
/// the admin mint's own two. Against a Synapse that accepts connections and
/// then never answers, the worst case is therefore ~8 × 8s, not 8s. What this
/// constant buys is that the worst case is BOUNDED and roughly a minute instead
/// of unbounded and roughly twenty; the real fix for the rest is a per-login
/// deadline, which is a larger change and deliberately not attempted here.
/// The black-hole case that actually motivated the finding is bounded by
/// [`SYNAPSE_CONNECT_TIMEOUT`] instead, at ~8 × 2s.
///
/// Deliberately a CONSTANT and not a config knob: a timeout nobody sets is a
/// timeout nobody tunes correctly under pressure, and there is no deployment
/// shape (see the connect-timeout note above) where a Synapse call legitimately
/// takes longer than this.
const SYNAPSE_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// The one place a `reqwest::Client` is built for Synapse traffic.
///
/// Single-sourced so a future second constructor cannot reintroduce the
/// untimed `Client::new()` this replaced. See [`SYNAPSE_REQUEST_TIMEOUT`] for
/// why the values are what they are.
fn build_http_client() -> Client {
    Client::builder()
        .connect_timeout(SYNAPSE_CONNECT_TIMEOUT)
        .timeout(SYNAPSE_REQUEST_TIMEOUT)
        .build()
        // Building a client only fails if the TLS backend cannot initialise,
        // which is a broken process, not a runtime condition. Failing loudly at
        // construction beats silently falling back to an untimed client — the
        // exact defect this function exists to prevent.
        .expect("failed to build the Synapse HTTP client (TLS backend init)")
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
            http: build_http_client(),
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
            anyhow::bail!(
                "has_cross_signing_keys: HTTP {status}{}",
                admin_status_hint(status)
            );
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

    /// A user's account status from the MAS query endpoint
    /// (`GET /_synapse/mas/query_user?localpart=…`,
    /// `synapse/rest/synapse/mas/users.py::MasQueryUserResource`).
    ///
    /// `Ok(None)` means Synapse answered **404 "User not found"** — the account
    /// does not exist. That is the *new identity* case, which
    /// [`crate::webauthn::reject_if_new_identity`] owns; this method deliberately
    /// does not conflate it with a deactivated account.
    ///
    /// Note the response also carries `is_suspended`. Suspension is NOT a login
    /// gate in Synapse (a suspended user may authenticate but not act), so
    /// [`crate::webauthn::reject_if_deactivated`] keys on `is_deactivated` only.
    /// The field is parsed so a future suspension policy has it available.
    pub async fn query_user(&self, localpart: &str) -> Result<Option<MasUserInfo>> {
        let url = format!(
            "{}/_synapse/mas/query_user?localpart={}",
            self.endpoint,
            urlencoding::encode(localpart)
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.shared_secret)
            .send()
            .await
            .context("query_user: request failed")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "query_user: unexpected response");
            anyhow::bail!("query_user: HTTP {status}{}", mas_status_hint(status));
        }

        let info: MasUserInfo = resp
            .json()
            .await
            .context("query_user: could not parse response")?;
        Ok(Some(info))
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
        Ok(self.read_profile(localpart, server_name).await?.row_present)
    }

    /// The same read as [`Self::has_profile_row`], returning the displayname it
    /// already fetched alongside the presence verdict.
    ///
    /// Split out for the alias-tier migration (`oidc::provision_synapse_device`):
    /// deciding whether a displayname was written by US or chosen by the USER
    /// requires seeing its value, and doing that with a second GET would double
    /// the login-path probe count for a value this request already has in hand.
    ///
    /// `displayname` is `Some` only when Synapse returned a 200 carrying a
    /// non-null `displayname`. A present-but-empty profile, a 404 of either
    /// shape, and a row whose displayname the user deliberately CLEARED all
    /// yield `None` — and `None` must never be treated as "safe to overwrite",
    /// because clearing is exactly what the 2026-08-02 live falsification was
    /// about.
    pub async fn read_profile(&self, localpart: &str, server_name: &str) -> Result<ProfileState> {
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
            // A malformed or unreadable 200 body still proves the row exists —
            // degrade to "present, displayname unknown" rather than turning a
            // successful probe into an error that would skip the heal.
            let displayname = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("displayname")?.as_str().map(str::to_string))
                .filter(|d| !d.is_empty());
            return Ok(ProfileState {
                row_present: true,
                displayname,
            });
        }
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let body = resp.text().await.unwrap_or_default();
            let row_absent = profile_404_means_row_absent(&body);
            if !row_absent {
                debug!(
                    %body,
                    "read_profile: 404 read as a present-but-empty (or unrecognized) profile shape — treating as present, skipping heal"
                );
            }
            return Ok(ProfileState {
                row_present: !row_absent,
                displayname: None,
            });
        }

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(%status, %body, "read_profile: unexpected response");
        anyhow::bail!("read_profile: HTTP {status}");
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

    /// Publish the provider-attested DID object into the user's Matrix profile:
    /// `PUT /_matrix/client/v3/profile/{mxid}/io.inblock.did`, body
    /// `{"io.inblock.did": <value>}`.
    ///
    /// # Why this uses a MINTED ADMIN TOKEN and not the shared secret
    ///
    /// This is a `/_matrix/client/*` route, not `/_synapse/mas/*`. The shared
    /// secret is honoured on exactly one surface (see the module docs) and
    /// answers **401 `M_UNKNOWN_TOKEN`** here on 1.157+ — it is not a token at
    /// all on the client API. It also has to be an *admin* token specifically:
    /// `handlers/profile.py:700-704` on v1.159.0 reads
    /// `if not by_admin and target_user != requester.user: raise AuthError(403)`,
    /// and under MAS `by_admin` is literally
    /// `"urn:synapse:admin:*" in requester.scope` (`api/auth/mas.py:274-275`) —
    /// which is the scope [`crate::admin_token`] mints. Writing another user's
    /// profile is only possible through that exemption.
    ///
    /// The same `by_admin` exemption is what lets the provider keep writing a
    /// field the *user* is forbidden to touch. That was verified live, not
    /// inferred: `docs/audits/2026-09-10-msc4133-acl-probe.md` leg 1 (admin PUT
    /// → 200) against legs 2 and 3 (user PUT / DELETE → 403) on one image, with
    /// the `msc4133_key_denylist` config as the only variable.
    ///
    /// # A 500 is only a HYPOTHESIS of "row-less account" — it must be CONFIRMED
    ///
    /// [element-hq/synapse#19702](https://github.com/element-hq/synapse/issues/19702)
    /// is still present in **1.159.0**, on reads *and* writes: both
    /// `_check_profile_size` and `get_profile_field` subscript an unguarded
    /// `txn.fetchone()`, so an account with a `users` row but **no `profiles`
    /// row** raises an uncaught `TypeError` and Synapse answers a bare 500 —
    /// where a healthy account answers 404. 3 of 102 accounts on the dev
    /// homeserver are in that state (erasure artifacts). That is a KNOWN
    /// CONDITION of a known-buggy dependency, reported as
    /// [`PublishOutcome::RowLessAccount`] and logged at `warn!`, not `error!`:
    /// nothing of ours is broken, the write simply could not be attempted and
    /// the field's state is **unknown** (not "absent" — the route cannot tell
    /// us).
    ///
    /// **But the status code alone does not establish it, and until 2026-09-10
    /// this code assumed it did.** #19702's 500 carries Twisted's *generic*
    /// body — `{"errcode":"M_UNKNOWN","error":"Internal server error"}` —
    /// byte-identical to the 500 from an exhausted database connection pool or
    /// any other uncaught exception. So the failure mode of the old code was:
    /// Synapse's database degrades, EVERY sign-in's publication 500s, and the
    /// log asserts a known, bounded, self-resolving condition affecting a
    /// handful of accounts while the publication path is 100% down. A `warn!`
    /// that says "known upstream bug, resolves on the next image bump" is worse
    /// than silence when it is wrong, because it actively spends an operator's
    /// attention budget on not looking.
    ///
    /// This is the SAME MISTAKE CLASS the team already fixed on 2026-08-02 for
    /// the 404 case, and the fix is the same one, in this same file: a status
    /// code is not a diagnosis. So a 500 now triggers a confirmation probe —
    /// [`has_profile_row`](Self::has_profile_row), which carries the JSON
    /// `errcode` discriminator (`M_UNKNOWN` + a whole-profile `GET` 404 =
    /// "truly absent"; re-verified live during the 2026-09-10 audit, where a
    /// row-less account answered
    /// `404 {"errcode":"M_UNKNOWN","error":"No row found (profiles)"}`) — and
    /// only a CONFIRMED-absent row is reported as
    /// [`PublishOutcome::RowLessAccount`]. Anything else is a genuine `Err`.
    ///
    /// **The confirmation fails LOUD, which is the opposite of
    /// `has_profile_row`'s own internal fail-safe — deliberately, and the two
    /// are not in conflict.** Inside `has_profile_row` the risky action is
    /// HEALING (re-running `provision_user`, a write that can clobber a real
    /// profile), so an undecidable answer resolves to "present, do not heal".
    /// Here the risky action is SILENCING, so an undecidable answer resolves to
    /// "genuine error, surface it". Both rules point away from the destructive
    /// outcome; they only look opposite because the destructive outcome is
    /// opposite. Do not "unify" them.
    ///
    /// **Cost:** the probe is on the FAILURE path only. A healthy publication
    /// (2xx, which is the steady state — one idempotent PUT per login) makes
    /// exactly one request and never touches `has_profile_row`. Keep it that
    /// way: pre-probing to "know in advance" would double the login-path
    /// Synapse traffic to buy nothing.
    ///
    /// Do not "simplify" the `RowLessAccount` outcome back into a plain `Err`
    /// either. Sign-in calls this best-effort, so an `Err` is swallowed by the
    /// caller either way — the distinction exists so an operator reading logs
    /// (and the live test) can tell a systemic breakage apart from three
    /// known-bad accounts, and so this stops being special automatically once
    /// the pinned Synapse image is bumped past the upstream fix.
    ///
    /// Every other non-2xx **is** a genuine `Err`, including 404: unlike the
    /// GET twin, a 404 on this PUT does not mean "no such field". The stable v3
    /// profile route is registered unconditionally on 1.159.0
    /// (`rest/client/profile.py:100-103`), so a 404 means the mxid is unknown
    /// to this homeserver or the homeserver predates MSC4133 — both of which an
    /// operator needs to see.
    ///
    /// # Everything written here is world-readable
    ///
    /// The GET twin authenticates only when `require_auth_for_profile_requests`
    /// is set, which defaults to **False** (`config/server.py:561`), and custom
    /// fields federate via `on_profile_query`. See
    /// [`crate::did_assertion::did_profile_value`] — nothing private may ever
    /// enter this value.
    pub async fn publish_did_field(
        &self,
        localpart: &str,
        server_name: &str,
        value: &serde_json::Value,
    ) -> Result<PublishOutcome> {
        let user_id = matrix_user_id(localpart, server_name);
        // The mxid is a PATH SEGMENT here (unlike the localpart-scoped MAS
        // bodies), so it must be percent-encoded: `@` and `:` are both
        // sub-delims that a bare interpolation would leave raw.
        let url = format!(
            "{}/_matrix/client/v3/profile/{}/{}",
            self.endpoint,
            urlencoding::encode(&user_id),
            DID_PROFILE_FIELD
        );

        // MSC4133's PUT body echoes the field name as its single key. Built as
        // a Map rather than with `json!` so the key is unambiguously the
        // shared constant and can never drift into a hard-coded literal that
        // still compiles.
        let mut body = serde_json::Map::new();
        body.insert(DID_PROFILE_FIELD.to_string(), value.clone());
        let body = serde_json::Value::Object(body);

        let resp = self
            .admin_request(|http, token| http.put(&url).bearer_auth(token).json(&body))
            .await
            .context("publish_did_field: request failed")?;

        let status = resp.status();
        match classify_publish_status(status) {
            PublishStatusClass::Written => {
                debug!(%user_id, "publish_did_field: wrote the attested DID object");
                Ok(PublishOutcome::Written)
            }
            // CONFIRM BEFORE EXCUSING. A 500 is only *consistent* with #19702;
            // it does not establish it. See the "A 500 is only a HYPOTHESIS"
            // section on this method for why this probe is mandatory and why it
            // fails LOUD rather than fail-safe.
            PublishStatusClass::MaybeRowLess => {
                let body = resp.text().await.unwrap_or_default();
                match self.has_profile_row(localpart, server_name).await {
                    // Confirmed: the profile row really is absent. This is
                    // #19702 and nothing else.
                    Ok(false) => {
                        warn!(
                            %user_id, %body,
                            "publish_did_field: Synapse answered 500 and the profile-row probe \
                             CONFIRMED the row is absent — this account has a `users` row but no \
                             `profiles` row (element-hq/synapse#19702, unfixed in 1.159.0). The \
                             DID field's state is UNKNOWN for this account; it will be \
                             re-attempted at the user's next sign-in and resolves once the pinned \
                             Synapse image is bumped"
                        );
                        Ok(PublishOutcome::RowLessAccount)
                    }
                    // The row is there (or the probe's own fail-safe says
                    // "assume present"). Whatever made the PUT 500, it was not
                    // the missing row — surface it.
                    Ok(true) => {
                        warn!(
                            %status, %body, %user_id,
                            "publish_did_field failed with 500, but the profile row EXISTS — this \
                             is NOT element-hq/synapse#19702. Treating it as a genuine error"
                        );
                        anyhow::bail!(
                            "publish_did_field: HTTP {status} with a present profile row (not \
                             element-hq/synapse#19702 — a real Synapse-side failure){}",
                            publish_status_hint(status)
                        );
                    }
                    // The confirmation probe itself failed. That is MORE
                    // evidence of a degraded homeserver, not less, so it must
                    // never be resolved in the reassuring direction.
                    Err(e) => {
                        warn!(
                            %status, %body, %user_id, error = %e,
                            "publish_did_field failed with 500 and the profile-row probe could \
                             not confirm the cause — refusing to report it as the known \
                             element-hq/synapse#19702 condition"
                        );
                        anyhow::bail!(
                            "publish_did_field: HTTP {status}, and the profile-row probe that \
                             would distinguish element-hq/synapse#19702 from a real failure also \
                             failed ({e}){}",
                            publish_status_hint(status)
                        );
                    }
                }
            }
            PublishStatusClass::Failed => {
                let body = resp.text().await.unwrap_or_default();
                warn!(%status, %body, %user_id, "publish_did_field failed");
                anyhow::bail!(
                    "publish_did_field: HTTP {status}{}",
                    publish_status_hint(status)
                );
            }
        }
    }
}

/// What a [`SynapseClient::publish_did_field`] call actually achieved.
///
/// A bare `Ok(())` would collapse "the DID is now published" into the same
/// answer as "Synapse crashed on a row-less account and we have no idea what
/// the field holds". Both are non-failures the caller must not abort on, and
/// they are not the same fact — the live test asserts a readback after the
/// first and cannot after the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Synapse accepted the write (2xx). The field now holds the value sent.
    Written,
    /// Synapse answered 500 **and a follow-up profile-row probe confirmed** the
    /// target account has a `users` row but no `profiles` row —
    /// element-hq/synapse#19702, still unfixed in 1.159.0. **The field's state
    /// is unknown**, not absent: the request never reached the storage layer,
    /// and the same bug makes the field-scoped GET twin 500 as well (the
    /// whole-profile GET that [`SynapseClient::has_profile_row`] uses is the
    /// one route that still answers usefully — a 404 with `errcode:
    /// M_UNKNOWN`).
    ///
    /// A bare 500 is NOT enough to produce this variant, and must never again
    /// be: Twisted's generic 500 body is identical for an exhausted DB pool.
    /// See the "A 500 is only a HYPOTHESIS" section on
    /// [`SynapseClient::publish_did_field`].
    RowLessAccount,
}

/// What a `PUT …/profile/{mxid}/{field}` status can be concluded from the
/// STATUS CODE ALONE.
///
/// Note the middle variant is `MaybeRowLess`, not `RowLessAccount`: a status
/// code cannot decide that question, and pretending it can was the defect this
/// type exists to make unrepresentable. See
/// [`SynapseClient::publish_did_field`]'s "confirm before excusing a 500"
/// section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishStatusClass {
    /// 2xx — the field now holds the value sent.
    Written,
    /// Exactly 500 — CONSISTENT with element-hq/synapse#19702 and with nothing
    /// else observable at this layer. Requires confirmation before it may be
    /// reported as [`PublishOutcome::RowLessAccount`].
    MaybeRowLess,
    /// Any other non-2xx — an unambiguous, genuine error.
    Failed,
}

/// Map a `PUT …/profile/{mxid}/{field}` status to what the status alone proves.
///
/// Pure and separate from the request for the same reason
/// [`profile_404_means_row_absent`] is: the interesting decision here is a
/// three-way classification of a status code, and it must be testable without
/// a live homeserver, a Redis instance to mint a token into, or an HTTP mock.
/// The full-path tests below exercise it through a real request as well; this
/// function is what keeps that coverage non-vacuous when they skip.
fn classify_publish_status(status: reqwest::StatusCode) -> PublishStatusClass {
    if status.is_success() {
        return PublishStatusClass::Written;
    }
    // Deliberately exactly 500, not `is_server_error()`. #19702 surfaces as an
    // uncaught `TypeError` → Twisted's generic 500. A 502/503/504 is a proxy or
    // a homeserver that is down, which is a genuine failure an operator must
    // see, and swallowing those as "known condition" would hide a total outage
    // of the publication path behind a `warn!`.
    //
    // KEEP THIS HALF. The 2026-09-10 audit finding (D1) was about what happens
    // AFTER this returns `MaybeRowLess`, not about which statuses reach it; the
    // "exactly 500, never `is_server_error()`" property is correct and was
    // re-affirmed, not relaxed.
    if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        return PublishStatusClass::MaybeRowLess;
    }
    PublishStatusClass::Failed
}

/// A human hint appended to a failed profile-field write.
///
/// Split from [`admin_status_hint`] because this route has a second confusable
/// failure the admin API does not: a 404 that an operator will read as "the
/// field does not exist yet" when it actually means the *user* does not exist,
/// or that this homeserver has no MSC4133 profile route at all.
fn publish_status_hint(status: reqwest::StatusCode) -> &'static str {
    match status {
        reqwest::StatusCode::NOT_FOUND => {
            " — the stable v3 profile route is registered unconditionally on Synapse 1.159.0, so \
             a 404 means this homeserver has never heard of that user (or predates MSC4133), NOT \
             that the field is merely unset"
        }
        _ => admin_status_hint(status),
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

    // -- publish_did_field: the status classifier (pure) --------------------
    //
    // Same discipline as `profile_404_means_row_absent` above: the interesting
    // decision is a three-way classification of a status code, so it is a pure
    // function with its own tests. These run with no Redis, no mock and no
    // network, which is what keeps H2 covered even when the full-path tests
    // below skip.

    /// H1 (classifier half): a 2xx is a real write.
    #[test]
    fn publish_status_2xx_is_written() {
        for code in [200u16, 201, 204] {
            assert_eq!(
                classify_publish_status(reqwest::StatusCode::from_u16(code).unwrap()),
                PublishStatusClass::Written,
                "HTTP {code} must count as a completed write"
            );
        }
    }

    /// H2 (classifier half): a 500 is the *candidate* row-less-account
    /// condition (element-hq/synapse#19702) — `MaybeRowLess`, never
    /// `RowLessAccount`.
    ///
    /// The variant name is the assertion. Since the 2026-09-10 audit (D1) the
    /// classifier is explicitly forbidden from concluding "#19702" from a
    /// status code, because Twisted's generic 500 body is byte-identical for an
    /// exhausted DB pool; only `publish_did_field`'s confirmation probe may
    /// promote this to `PublishOutcome::RowLessAccount`. If a refactor ever
    /// makes this return a settled outcome again, this test is what fails.
    #[test]
    fn publish_status_500_is_only_a_candidate_rowless_account() {
        assert_eq!(
            classify_publish_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            PublishStatusClass::MaybeRowLess,
            "a 500 is a hypothesis, not a diagnosis"
        );
    }

    /// The other 5xx codes must NOT be swallowed as "known condition".
    ///
    /// #19702 surfaces as an uncaught `TypeError` -> Twisted's generic 500. A
    /// 502/503/504 is a dead homeserver or a proxy in front of it, and
    /// classifying those as benign would hide a total outage of the
    /// publication path behind a `warn!` on every single login. This is the
    /// exact reason the classifier compares to 500 rather than calling
    /// `is_server_error()`.
    #[test]
    fn publish_status_other_5xx_is_a_genuine_error() {
        for code in [502u16, 503, 504] {
            assert_eq!(
                classify_publish_status(reqwest::StatusCode::from_u16(code).unwrap()),
                PublishStatusClass::Failed,
                "HTTP {code} is a dead upstream, not a row-less account"
            );
        }
    }

    /// A 404 on the PUT is a genuine error, and its hint must say why.
    ///
    /// This is the one status an operator is most likely to misread: on the GET
    /// twin a 404 means "the field is unset", which is normal. On the PUT it
    /// means the *user* is unknown (or the homeserver has no MSC4133 route at
    /// all), because the stable v3 profile route is registered unconditionally
    /// on 1.159.0.
    #[test]
    fn publish_status_404_is_an_error_with_a_disambiguating_hint() {
        assert_eq!(
            classify_publish_status(reqwest::StatusCode::NOT_FOUND),
            PublishStatusClass::Failed
        );
        let hint = publish_status_hint(reqwest::StatusCode::NOT_FOUND);
        assert!(
            hint.contains("never heard of that user"),
            "a 404 hint must rule out the 'field merely unset' reading: {hint}"
        );
    }

    /// 401/403 keep the shared admin hint, so an auth failure on this route is
    /// diagnosed identically to one on `/_synapse/admin/*`.
    #[test]
    fn publish_status_hint_falls_through_to_the_admin_hint_for_auth_failures() {
        assert_eq!(
            publish_status_hint(reqwest::StatusCode::UNAUTHORIZED),
            admin_status_hint(reqwest::StatusCode::UNAUTHORIZED)
        );
        assert!(!publish_status_hint(reqwest::StatusCode::UNAUTHORIZED).is_empty());
    }

    // -- publish_did_field: the full admin path, against a mock Synapse ------
    //
    // Extends the in-process mock pattern from `localpart.rs`'s
    // `spawn_mock_synapse` (axum on an ephemeral port, built only from crates
    // already in `[dependencies]`).
    //
    // Unlike that one, these need a REAL `RedisClient`: `publish_did_field`
    // goes through `admin_request` -> `admin_bearer`, which mints a token by
    // writing it to the token store, and `AdminMint.db` is the concrete
    // `RedisClient` type rather than a `dyn DBClient`. So these follow the
    // repo's established "skip cleanly when Redis is unavailable" pattern
    // (`db/redis.rs`, `webauthn.rs`). CI provides one; the pure classifier
    // tests above are what keep the classification itself covered when they
    // skip.

    /// What the mock actually received. One PUT is expected, but the whole log
    /// is captured so an unexpected extra request shows up as a failed length
    /// assertion rather than being silently ignored.
    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: String,
        /// The RAW path, still percent-encoded — asserted verbatim, because
        /// getting the encoding of `@` and `:` wrong is precisely the bug an
        /// axum `Path` extractor would hide by decoding it for us.
        path: String,
        authorization: Option<String>,
        body: serde_json::Value,
    }

    /// The `(status, body)` a mock answers the WHOLE-PROFILE
    /// `GET /_matrix/client/v3/profile/{mxid}` with — i.e. what
    /// [`SynapseClient::has_profile_row`] sees when `publish_did_field`
    /// confirms a 500.
    ///
    /// `404 {"errcode":"M_UNKNOWN", …}` is the ONLY shape that reads as "row
    /// truly absent" (see `has_profile_row`'s discriminator table), so it is
    /// the only shape that may promote a 500 to
    /// [`PublishOutcome::RowLessAccount`].
    fn profile_row_absent() -> (axum::http::StatusCode, serde_json::Value) {
        (
            axum::http::StatusCode::NOT_FOUND,
            json!({"errcode": "M_UNKNOWN", "error": "No row found (profiles)"}),
        )
    }

    /// A present profile row: a plain 200.
    fn profile_row_present() -> (axum::http::StatusCode, serde_json::Value) {
        (
            axum::http::StatusCode::OK,
            json!({"displayname": "someone"}),
        )
    }

    /// Spin up a mock Synapse that answers `is_localpart_available` with
    /// "taken" (so the admin mint performs no `provision_user`) and records
    /// every other request, answering it with `reply_status`.
    ///
    /// Defaults the whole-profile GET to "row absent", which is the shape the
    /// pre-2026-09-10 tests implicitly assumed when a 500 needed no
    /// confirmation at all. Use [`spawn_publish_mock_with_profile`] to vary it.
    async fn spawn_publish_mock(
        reply_status: axum::http::StatusCode,
    ) -> (
        SynapseClient,
        std::sync::Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_publish_mock_with_profile(reply_status, profile_row_absent()).await
    }

    /// [`spawn_publish_mock`], with control over what the whole-profile GET
    /// answers.
    ///
    /// That GET is `publish_did_field`'s D1 confirmation probe. Passing
    /// `reply_status` for it too (rather than a separate shape) is what the
    /// mock did before this split, and it is exactly the case that must NOT be
    /// classified as a row-less account: a homeserver 500ing on everything.
    async fn spawn_publish_mock_with_profile(
        reply_status: axum::http::StatusCode,
        profile_reply: (axum::http::StatusCode, serde_json::Value),
    ) -> (
        SynapseClient,
        std::sync::Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::body::Bytes;
        use axum::extract::{Request, State};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::Router;
        use std::sync::{Arc, Mutex};

        let log: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

        #[derive(Clone)]
        struct MockState {
            log: std::sync::Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
            reply_status: axum::http::StatusCode,
            profile_reply: (axum::http::StatusCode, serde_json::Value),
        }

        /// True for the WHOLE-profile GET (`…/profile/{mxid}`) and false for
        /// the field-scoped PUT (`…/profile/{mxid}/io.inblock.did`).
        ///
        /// Matched on the path suffix rather than by a router route so the
        /// request still lands in the same recording fallback — an assertion
        /// on the recorded log is how the tests below prove the confirmation
        /// probe was (or was not) made at all.
        fn is_whole_profile_get(method: &str, path: &str) -> bool {
            method == "GET"
                && path.starts_with("/_matrix/client/v3/profile/")
                && !path.ends_with(DID_PROFILE_FIELD)
        }

        async fn record(State(state): State<MockState>, req: Request) -> axum::response::Response {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let authorization = req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let bytes: Bytes = axum::body::to_bytes(req.into_body(), 64 * 1024)
                .await
                .unwrap_or_default();
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            let whole_profile_get = is_whole_profile_get(&method, &path);
            state.log.lock().unwrap().push(RecordedRequest {
                method,
                path,
                authorization,
                body,
            });
            if whole_profile_get {
                let (status, body) = state.profile_reply.clone();
                return (status, axum::Json(body)).into_response();
            }
            (state.reply_status, "{}").into_response()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mock-synapse port");
        let addr = listener.local_addr().expect("mock-synapse local_addr");
        let app = Router::new()
            // 400 M_USER_IN_USE == "taken", which `is_localpart_available` maps
            // to Ok(false), so `admin_bearer` skips provisioning the service
            // user and goes straight to minting.
            .route(
                "/_synapse/mas/is_localpart_available",
                get(|| async {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(json!({"errcode": "M_USER_IN_USE", "error": "in use"})),
                    )
                }),
            )
            .fallback(record)
            .with_state(MockState {
                log: log.clone(),
                reply_status,
                profile_reply,
            });
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock-synapse");
        });
        let client = SynapseClient::new(&format!("http://{addr}"), "shared-secret");
        (client, log, handle)
    }

    /// Attach a real token store, or return `None` when Redis is unavailable.
    async fn with_redis_mint(client: SynapseClient) -> Option<SynapseClient> {
        let redis = RedisClient::new(&url::Url::parse("redis://localhost").unwrap())
            .await
            .ok()?;
        Some(client.with_admin_mint(redis, "siwx-admin".to_string(), 300))
    }

    fn sample_value() -> serde_json::Value {
        json!({"did": "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB", "proof": "eyJ0ZXN0Ijoi"})
    }

    /// **H1** — the wire shape, asserted field by field.
    ///
    /// Method, raw (percent-encoded) path, `Authorization: Bearer <minted
    /// token>` and the exact `{field: value}` body envelope. Each of these has
    /// its own way of failing silently: a POST would 404, an unencoded `@`/`:`
    /// would address a different (or no) user, the shared secret instead of a
    /// minted token would 401, and a body keyed by anything but the field name
    /// is rejected by Synapse's MSC4133 servlet.
    ///
    /// The expected path is the one that round-tripped live —
    /// `docs/audits/2026-09-10-msc4133-acl-probe.md` leg 1.
    #[tokio::test]
    async fn h1_publish_did_field_wire_shape() {
        let (client, log, handle) = spawn_publish_mock(axum::http::StatusCode::OK).await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!("SKIP h1_publish_did_field_wire_shape: no Redis on localhost");
            handle.abort();
            return;
        };

        let value = sample_value();
        let outcome = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &value)
            .await
            .expect("a 200 from Synapse must be Ok");
        assert_eq!(outcome, PublishOutcome::Written);

        let recorded = log.lock().unwrap().clone();
        assert_eq!(
            recorded.len(),
            1,
            "exactly one request must reach the profile route, got {recorded:?}"
        );
        let req = &recorded[0];

        assert_eq!(req.method, "PUT", "MSC4133 sets a profile field with PUT");
        assert_eq!(
            req.path, "/_matrix/client/v3/profile/%40k3f9x2q7ab4d8m1p%3Ainblock.io/io.inblock.did",
            "the mxid is a path segment and MUST be percent-encoded (@ -> %40, : -> %3A)"
        );

        let auth = req
            .authorization
            .as_deref()
            .expect("the request must carry an Authorization header");
        let token = auth
            .strip_prefix("Bearer ")
            .expect("admin-scoped calls use a bearer token");
        assert!(
            token.starts_with(ADMIN_TOKEN_PREFIX),
            "must present a MINTED admin token ({ADMIN_TOKEN_PREFIX}…), not the shared secret: \
             the shared secret answers 401 M_UNKNOWN_TOKEN on /_matrix/client/* since 1.157"
        );
        assert_ne!(
            token, "shared-secret",
            "the shared secret must never be presented on the client API"
        );

        assert_eq!(
            req.body,
            json!({ "io.inblock.did": value }),
            "the body is the field name mapped to the value, nothing else"
        );

        handle.abort();
    }

    /// **H2** — a 500 is `Ok(RowLessAccount)`, never `Err`.
    ///
    /// element-hq/synapse#19702 is unfixed in 1.159.0 and makes a `users`-row-
    /// without-`profiles`-row account 500 on this route. 3 of 102 dev accounts
    /// are in that state. Returning `Err` here would be *technically* harmless
    /// (the caller is best-effort) but it would report a known dependency bug
    /// as a failure of ours, on every login of those accounts, forever.
    #[tokio::test]
    async fn h2_publish_did_field_500_is_a_rowless_account_not_an_error() {
        let (client, _log, handle) =
            spawn_publish_mock(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!(
                "SKIP h2_publish_did_field_500_is_a_rowless_account_not_an_error: no Redis on localhost"
            );
            handle.abort();
            return;
        };

        let outcome = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect("a CONFIRMED row-less 500 is a KNOWN condition, not an Err");
        assert_eq!(outcome, PublishOutcome::RowLessAccount);
        handle.abort();
    }

    // -- D1 (2026-09-10 audit): a 500 must be CONFIRMED, not assumed ---------
    //
    // The old code classified ANY 500 on the profile PUT as #19702. Synapse's
    // #19702 500 carries Twisted's generic body
    // (`{"errcode":"M_UNKNOWN","error":"Internal server error"}`), which is
    // byte-identical to the 500 from an exhausted DB pool — so a degraded
    // database made every login log a reassuring "known bounded upstream bug,
    // resolves on the next image bump" while the publication path was 100%
    // down. These three tests pin the confirmation probe and BOTH of its
    // non-confirming answers.

    /// D1, the positive half: a 500 whose profile-row probe confirms the row is
    /// absent is still `RowLessAccount` — the fix must not regress the real
    /// #19702 case into a hard error.
    ///
    /// Also asserts the probe actually happened, so a refactor that "optimises"
    /// the confirmation away and reverts to assuming fails here rather than
    /// silently passing on the outcome alone.
    #[tokio::test]
    async fn d1_500_with_a_confirmed_absent_row_is_still_a_rowless_account() {
        let (client, log, handle) = spawn_publish_mock_with_profile(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            profile_row_absent(),
        )
        .await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!(
                "SKIP d1_500_with_a_confirmed_absent_row_is_still_a_rowless_account: no Redis on localhost"
            );
            handle.abort();
            return;
        };

        let outcome = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect("a CONFIRMED row-less 500 must stay a known condition, not become an Err");
        assert_eq!(outcome, PublishOutcome::RowLessAccount);

        let requests = log.lock().unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.method == "GET" && !r.path.ends_with(DID_PROFILE_FIELD)),
            "the whole-profile confirmation probe must have been made: {requests:?}"
        );
        handle.abort();
    }

    /// D1, the finding itself: a 500 on an account whose profile row EXISTS is
    /// not #19702 and must surface as a genuine error.
    ///
    /// This is the shape of the outage the old code hid — a homeserver failing
    /// for some other reason on accounts that are perfectly well-formed.
    #[tokio::test]
    async fn d1_500_with_a_present_profile_row_is_a_genuine_error() {
        let (client, _log, handle) = spawn_publish_mock_with_profile(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            profile_row_present(),
        )
        .await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!(
                "SKIP d1_500_with_a_present_profile_row_is_a_genuine_error: no Redis on localhost"
            );
            handle.abort();
            return;
        };

        let err = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect_err(
                "a 500 on an account that HAS a profile row is not element-hq/synapse#19702 and \
                 must not be excused as one",
            )
            .to_string();
        assert!(
            err.contains("500"),
            "the status must be in the message: {err}"
        );
        assert!(
            err.contains("present profile row"),
            "the message must say WHY this 500 is not the known bug: {err}"
        );
        handle.abort();
    }

    /// D1, the fail-LOUD direction: when the confirmation probe itself fails,
    /// the 500 must NOT be resolved in the reassuring direction.
    ///
    /// This is the literal database-degradation scenario: the homeserver 500s
    /// on everything, including the probe. A probe failure is MORE evidence of
    /// an outage, not less — so it becomes an `Err`, and the message says the
    /// cause could not be distinguished rather than asserting a diagnosis.
    ///
    /// Note this mock (one `reply_status` for every route) is exactly what the
    /// pre-fix `spawn_publish_mock` was, i.e. the old H2 test was passing
    /// against a homeserver that was 500ing on everything and calling it a
    /// known bounded upstream bug.
    #[tokio::test]
    async fn d1_500_with_an_unconfirmable_row_is_a_genuine_error() {
        let (client, _log, handle) = spawn_publish_mock_with_profile(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                json!({"errcode": "M_UNKNOWN", "error": "Internal server error"}),
            ),
        )
        .await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!(
                "SKIP d1_500_with_an_unconfirmable_row_is_a_genuine_error: no Redis on localhost"
            );
            handle.abort();
            return;
        };

        let err = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect_err("an unconfirmable 500 must never be reported as the known condition")
            .to_string();
        assert!(
            err.contains("500"),
            "the status must be in the message: {err}"
        );
        assert!(
            err.contains("also failed"),
            "the message must say the confirmation probe also failed, not assert a diagnosis: {err}"
        );
        handle.abort();
    }

    // -- D1, against a LIVE Synapse -----------------------------------------
    //
    // The mock tests above are only as good as the mock. These two run the real
    // `has_profile_row` — the discriminator the D1 fix rests on — against a
    // real homeserver, on two accounts deliberately put into the two states
    // that produce an INDISTINGUISHABLE 500 from the profile PUT.
    //
    // # What was measured live (2026-09-10, Synapse 1.159.0, e2e stack)
    //
    // | account state | `PUT …/profile/{mxid}/io.inblock.did` | `GET …/profile/{mxid}` |
    // |---|---|---|
    // | `users` row, NO `profiles` row | `500 {"errcode":"M_UNKNOWN","error":"Internal server error"}` | `404 {"errcode":"M_UNKNOWN","error":"No row found (profiles)"}` |
    // | `profiles` row present, writes to it failing | `500 {"errcode":"M_UNKNOWN","error":"Internal server error"}` | `200 {"displayname":…}` |
    //
    // The two PUT bodies are **byte-identical** — that is the finding. The
    // second state was produced by a scoped, reversible SQLite trigger raising
    // `ABORT` on `UPDATE profiles` for one throwaway user, which is a genuine
    // Synapse-side write failure of exactly the class ("the database degraded")
    // that the pre-fix code reported as a reassuring known upstream bug.
    //
    // # Scope, stated honestly
    //
    // These cover the GET leg with the real server. The PUT leg is NOT driven
    // from here: `publish_did_field` needs a minted admin token, whose
    // introspection has to be served by the same siwx-oidc instance Synapse is
    // configured against, and that instance's Redis is not reachable from a
    // `cargo test` on the host. The PUT statuses in the table above were
    // measured with `curl` instead, and `classify_publish_status` is pinned by
    // its own pure unit tests, so the composition is covered — but do not read
    // these two tests as end-to-end.
    //
    // Set up (both accounts, provisioned via `/_synapse/mas/provision_user`):
    //
    // ```sh
    // SIWX_LIVE_SYNAPSE=http://localhost:18448 \
    // SIWX_LIVE_SERVER_NAME=localhost \
    // SIWX_LIVE_ROWLESS_LOCALPART=… SIWX_LIVE_PRESENT_LOCALPART=… \
    //   cargo test --bin siwx-oidc d1_live -- --ignored --nocapture
    // ```

    /// The live environment for the `d1_live_*` probes, or `None` when it is
    /// not configured (so the tests skip in the repo's established style rather
    /// than failing on a developer machine with no stack up).
    fn live_probe_env(localpart_var: &str) -> Option<(SynapseClient, String, String)> {
        let endpoint = std::env::var("SIWX_LIVE_SYNAPSE").ok()?;
        let server_name = std::env::var("SIWX_LIVE_SERVER_NAME").ok()?;
        let localpart = std::env::var(localpart_var).ok()?;
        // No admin mint: `has_profile_row` is unauthenticated on a default
        // Synapse (`require_auth_for_profile_requests` defaults to false — see
        // its own doc), which is exactly why this leg can be driven from here.
        Some((
            SynapseClient::new(&endpoint, "unused-no-admin-mint"),
            server_name,
            localpart,
        ))
    }

    /// D1 live, the CONFIRMING answer: a real row-less account's whole-profile
    /// GET must resolve to "truly absent", which is the only thing that may
    /// promote a 500 to `PublishOutcome::RowLessAccount`.
    #[tokio::test]
    #[ignore = "requires a live Synapse; see the SIWX_LIVE_* setup above"]
    async fn d1_live_rowless_account_is_confirmed_absent() {
        let Some((client, server_name, localpart)) = live_probe_env("SIWX_LIVE_ROWLESS_LOCALPART")
        else {
            eprintln!("SKIP d1_live_rowless_account_is_confirmed_absent: SIWX_LIVE_* not set");
            return;
        };
        let present = client
            .has_profile_row(&localpart, &server_name)
            .await
            .expect("the live probe must answer, not error");
        assert!(
            !present,
            "a row-less account must be CONFIRMED absent, or the real              element-hq/synapse#19702 case regresses into a hard error"
        );
    }

    /// D1 live, the REFUSING answer — this is the finding itself.
    ///
    /// An account whose `profiles` row exists but whose writes fail produces a
    /// PUT 500 byte-identical to #19702's. The discriminator must say "row
    /// present", so `publish_did_field` surfaces it as a genuine error instead
    /// of logging the reassuring "known bounded upstream bug" line while the
    /// publication path is down for everyone.
    #[tokio::test]
    #[ignore = "requires a live Synapse; see the SIWX_LIVE_* setup above"]
    async fn d1_live_account_with_a_row_is_not_confirmed_absent() {
        let Some((client, server_name, localpart)) = live_probe_env("SIWX_LIVE_PRESENT_LOCALPART")
        else {
            eprintln!(
                "SKIP d1_live_account_with_a_row_is_not_confirmed_absent: SIWX_LIVE_* not set"
            );
            return;
        };
        let present = client
            .has_profile_row(&localpart, &server_name)
            .await
            .expect("the live probe must answer, not error");
        assert!(
            present,
            "an account that HAS a profile row must never be read as absent — that reading is              what excuses a real outage as element-hq/synapse#19702"
        );
    }

    /// Mock fidelity: the mock's 500 body must be the LIVE one, verbatim.
    ///
    /// The D1 mock tests are only evidence if the mock reproduces what Synapse
    /// actually sends. The whole finding is that #19702's 500 body and a
    /// degraded-database 500 body are the same bytes, so if this ever stops
    /// being the body Synapse emits, the mock tests are testing a fiction and
    /// the classifier's premise needs re-measuring. Measured live 2026-09-10 on
    /// Synapse 1.159.0, from BOTH account states.
    #[test]
    fn the_generic_500_body_is_indistinguishable_between_both_causes() {
        let live_rowless_500 = json!({"errcode": "M_UNKNOWN", "error": "Internal server error"});
        let live_degraded_db_500 =
            json!({"errcode": "M_UNKNOWN", "error": "Internal server error"});
        assert_eq!(
            live_rowless_500, live_degraded_db_500,
            "if these ever differ, a 500 could be classified from its body alone and the              confirmation probe could be reconsidered — re-measure before assuming so"
        );
        // And the discriminator that DOES separate them, on the GET leg.
        assert!(
            profile_404_means_row_absent(
                &json!({"errcode": "M_UNKNOWN", "error": "No row found (profiles)"}).to_string()
            ),
            "the live row-less 404 body must read as truly absent"
        );
    }

    /// D5 (2026-09-10 audit): a black-holed Synapse must fail fast.
    #[tokio::test]
    #[ignore = "timing probe: takes ~2s by design"]
    async fn d5_a_blackholed_synapse_gives_up_in_about_the_connect_timeout() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed non-routable, so
        // SYNs are dropped rather than refused — the black-hole case, not the
        // connection-refused case. Before the timeouts landed this blocked
        // until the kernel gave up (~127s on Linux defaults).
        let client = SynapseClient::new("http://192.0.2.1:1", "secret");
        let started = std::time::Instant::now();
        let err = client.is_localpart_available("whoever").await;
        let elapsed = started.elapsed();
        assert!(err.is_err(), "a black hole must error, not hang forever");
        assert!(
            elapsed < SYNAPSE_CONNECT_TIMEOUT + std::time::Duration::from_secs(2),
            "must give up near the connect timeout, not at the OS TCP timeout: {elapsed:?}"
        );
        eprintln!("gave up after {elapsed:?} (connect timeout {SYNAPSE_CONNECT_TIMEOUT:?})");
    }

    /// A 404 is a genuine `Err`, carrying the hint that disambiguates it from
    /// the GET twin's benign "field is unset" 404.
    #[tokio::test]
    async fn publish_did_field_404_is_an_error() {
        let (client, _log, handle) = spawn_publish_mock(axum::http::StatusCode::NOT_FOUND).await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!("SKIP publish_did_field_404_is_an_error: no Redis on localhost");
            handle.abort();
            return;
        };

        let err = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect_err("a 404 on the PUT is not a success")
            .to_string();
        assert!(
            err.contains("404"),
            "the status must be in the message: {err}"
        );
        assert!(
            err.contains("never heard of that user"),
            "the 404 hint must be attached: {err}"
        );
        handle.abort();
    }

    /// A real upstream failure (503) is a genuine `Err`.
    #[tokio::test]
    async fn publish_did_field_503_is_an_error() {
        let (client, _log, handle) =
            spawn_publish_mock(axum::http::StatusCode::SERVICE_UNAVAILABLE).await;
        let Some(client) = with_redis_mint(client).await else {
            eprintln!("SKIP publish_did_field_503_is_an_error: no Redis on localhost");
            handle.abort();
            return;
        };

        let err = client
            .publish_did_field("k3f9x2q7ab4d8m1p", "inblock.io", &sample_value())
            .await
            .expect_err("a dead homeserver must not be reported as a benign known condition")
            .to_string();
        assert!(
            err.contains("503"),
            "the status must be in the message: {err}"
        );
        handle.abort();
    }

    /// The field name is the SHARED constant, not a local literal.
    ///
    /// Guards the three-sided wire contract documented on
    /// [`crate::did_assertion::DID_PROFILE_FIELD`]: the URL segment and the
    /// body key must both move if the constant ever moves, and the client
    /// crate's constant of the same name must move with them.
    #[test]
    fn publish_uses_the_shared_field_constant() {
        assert_eq!(DID_PROFILE_FIELD, "io.inblock.did");
        assert_eq!(
            DID_PROFILE_FIELD,
            siwx_oidc_auth::did_assertion::DID_PROFILE_FIELD,
            "the provider and the shipped consumer must name the SAME profile field; \
             a divergence here means every consumer reads 'no published DID'"
        );
    }
}
