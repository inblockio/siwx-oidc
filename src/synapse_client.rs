//! HTTP client for Synapse's `/_synapse/mas/` management endpoints (MSC3861).
//!
//! This module provides provisioning and device management calls that siwx-oidc
//! uses as the delegated auth provider for a Synapse homeserver.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

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

/// A human hint appended to admin-API error messages so an auth failure (the
/// shared secret is not accepted as Synapse's `admin_token`) is never mistaken
/// for a missing device / absent user. Empty for non-auth failures.
fn admin_status_hint(status: reqwest::StatusCode) -> &'static str {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        " — Synapse rejected the admin token (check that the MAS shared secret is also Synapse's admin_token)"
    } else {
        ""
    }
}

/// Client for Synapse's MAS (Matrix Authentication Service) compatibility endpoints.
///
/// All requests use Bearer authentication with a shared secret configured in
/// Synapse's `auth_service.issuer` block.
pub struct SynapseClient {
    endpoint: String,
    shared_secret: String,
    http: Client,
}

impl SynapseClient {
    /// Create a new client targeting the given Synapse base URL.
    ///
    /// `endpoint` is the scheme + host (+ optional port) of the Synapse instance,
    /// e.g. `http://localhost:8008`. Trailing slashes are stripped.
    pub fn new(endpoint: &str, shared_secret: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            shared_secret: shared_secret.to_string(),
            http: Client::new(),
        }
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
    pub async fn has_cross_signing_keys(&self, localpart: &str, server_name: &str) -> Result<bool> {
        let user_id = matrix_user_id(localpart, server_name);
        let url = format!("{}/_matrix/client/v3/keys/query", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&json!({ "device_keys": { &user_id: [] } }))
            .send()
            .await
            .context("has_cross_signing_keys: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "has_cross_signing_keys: query failed");
            anyhow::bail!("has_cross_signing_keys: HTTP {status}");
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

    /// List a user's devices via the Synapse admin API
    /// (`GET /_synapse/admin/v2/users/{user_id}/devices`).
    ///
    /// Authenticated with the shared secret, which doubles as Synapse's
    /// `admin_token` under MSC3861 (`matrix_server.sh` sets them equal).
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
            .http
            .get(&url)
            .bearer_auth(&self.shared_secret)
            .send()
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

    /// Delete a user's device via the Synapse admin API
    /// (`DELETE /_synapse/admin/v2/users/{user_id}/devices/{device_id}`).
    ///
    /// Scoped to the user's mxid, so a foreign `device_id` cannot affect another
    /// user. Deleting the device invalidates Synapse's cached access token for it.
    pub async fn delete_device(
        &self,
        localpart: &str,
        device_id: &str,
        server_name: &str,
    ) -> Result<()> {
        let user_id = matrix_user_id(localpart, server_name);
        let url = format!(
            "{}/_synapse/admin/v2/users/{}/devices/{}",
            self.endpoint,
            urlencoding::encode(&user_id),
            urlencoding::encode(device_id)
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.shared_secret)
            .send()
            .await
            .context("delete_device: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "delete_device failed");
            anyhow::bail!("delete_device: HTTP {status}{}", admin_status_hint(status));
        }
        Ok(())
    }

    /// Build the admin-API deactivation URL for a user's mxid (percent-encoded
    /// path segment). Factored out so the encoding can be unit-tested directly.
    fn deactivate_url(&self, localpart: &str, server_name: &str) -> String {
        format!(
            "{}/_synapse/admin/v1/deactivate/{}",
            self.endpoint,
            urlencoding::encode(&matrix_user_id(localpart, server_name))
        )
    }

    /// Deactivate a user's account via the Synapse admin API
    /// (`POST /_synapse/admin/v1/deactivate/{user_id}`).
    ///
    /// Authenticated with the shared secret (== Synapse `admin_token` under MSC3861).
    /// Deactivation removes the account's access tokens and 3PIDs. The `erase`
    /// flag selects GDPR behaviour: `erase=false` keeps profile/media (a plain
    /// deactivation, reversible via [`reactivate_user`](Self::reactivate_user));
    /// `erase=true` requests irreversible erasure of the user's profile, media,
    /// and room memberships. Scoped to the user's mxid.
    pub async fn deactivate_user(
        &self,
        localpart: &str,
        server_name: &str,
        erase: bool,
    ) -> Result<()> {
        let url = self.deactivate_url(localpart, server_name);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.shared_secret)
            .json(&deactivate_body(erase))
            .send()
            .await
            .context("deactivate_user: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "deactivate_user failed");
            anyhow::bail!(
                "deactivate_user: HTTP {status}{}",
                admin_status_hint(status)
            );
        }
        Ok(())
    }

    /// Build the admin-v2 user-modification URL for a user's mxid (percent-encoded
    /// path segment). Factored out so the encoding can be unit-tested directly.
    fn reactivate_url(&self, localpart: &str, server_name: &str) -> String {
        format!(
            "{}/_synapse/admin/v2/users/{}",
            self.endpoint,
            urlencoding::encode(&matrix_user_id(localpart, server_name))
        )
    }

    /// Reactivate a previously (non-erased) deactivated account via the Synapse
    /// admin API (`PUT /_synapse/admin/v2/users/{user_id}` with
    /// `{ "deactivated": false }`).
    ///
    /// Authenticated with the shared secret (== Synapse `admin_token` under MSC3861).
    /// Only meaningful for accounts deactivated with `erase=false`; an erased
    /// account cannot be restored.
    ///
    /// VERIFIED under MSC3861 (live probe, 2026-06-10): the admin-v2 `PUT users`
    /// endpoint accepts `{"deactivated": false}` WITHOUT a `password` field and
    /// reactivates the account (HTTP 200, `deactivated: false` confirmed on
    /// re-read) on a production MSC3861 deployment (agentic.inblock.io). The
    /// historical concern that reactivation demands a local password does not
    /// apply when no `password` key is sent. Probe: section 3 of
    /// `scripts/verify-lifecycle-live.sh` against a throwaway user. This method
    /// still surfaces a clear error (warn! + bail!) on any non-success response.
    pub async fn reactivate_user(&self, localpart: &str, server_name: &str) -> Result<()> {
        let url = self.reactivate_url(localpart, server_name);
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.shared_secret)
            .json(&reactivate_body())
            .send()
            .await
            .context("reactivate_user: request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "reactivate_user failed");
            anyhow::bail!("reactivate_user: HTTP {status}");
        }
        Ok(())
    }
}

/// Build the JSON body for the admin v1 deactivate endpoint. The `erase` flag
/// is the GDPR selector (see [`SynapseClient::deactivate_user`]). Factored out
/// so the parameter mapping can be unit-tested without a live homeserver.
fn deactivate_body(erase: bool) -> serde_json::Value {
    json!({ "erase": erase })
}

/// Build the JSON body for the admin v2 reactivation PUT (sets `deactivated`
/// back to `false`). Factored out so the body shape can be unit-tested.
fn reactivate_body() -> serde_json::Value {
    json!({ "deactivated": false })
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
        // The admin v1 deactivate endpoint takes `{ "erase": <bool> }`. The body
        // builder is the testable seam for the erase parameter: erase=false keeps
        // GDPR-erasure off (deactivate only), erase=true requests full erasure.
        assert_eq!(deactivate_body(false), json!({ "erase": false }));
        assert_eq!(deactivate_body(true), json!({ "erase": true }));
    }

    #[test]
    fn reactivate_url_encodes_mxid_path_segment() {
        // Reactivation uses the admin v2 user-modification endpoint, which takes
        // the mxid as a path segment, so the mxid must be percent-encoded.
        let client = SynapseClient::new("http://localhost:8008", "secret");
        let url = client.reactivate_url("alice", "example.com");
        assert_eq!(
            url,
            "http://localhost:8008/_synapse/admin/v2/users/%40alice%3Aexample.com"
        );
        let segment = url.rsplit('/').next().unwrap();
        assert!(!segment.contains('@'));
        assert!(!segment.contains(':'));
    }

    #[test]
    fn reactivate_body_sets_deactivated_false() {
        // Reactivation flips `deactivated` back to false via the admin v2 PUT.
        assert_eq!(reactivate_body(), json!({ "deactivated": false }));
    }

    #[test]
    fn deactivate_url_encodes_mxid_path_segment() {
        // The deactivate endpoint takes the mxid as a path segment, so the mxid
        // must be percent-encoded (no raw @ or :) for a well-formed URL.
        let client = SynapseClient::new("http://localhost:8008", "secret");
        let url = client.deactivate_url("alice", "example.com");
        assert_eq!(
            url,
            "http://localhost:8008/_synapse/admin/v1/deactivate/%40alice%3Aexample.com"
        );
        // The encoded segment must not contain raw mxid separators.
        let segment = url.rsplit('/').next().unwrap();
        assert!(!segment.contains('@'));
        assert!(!segment.contains(':'));
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
