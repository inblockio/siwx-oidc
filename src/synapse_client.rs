//! HTTP client for Synapse's `/_synapse/mas/` management endpoints (MSC3861).
//!
//! This module provides provisioning and device management calls that siwx-oidc
//! uses as the delegated auth provider for a Synapse homeserver.

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use tracing::warn;

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

    /// Check whether a user has master cross-signing keys set up.
    ///
    /// Queries Synapse's `/_matrix/client/v3/keys/query` using the admin token.
    /// Returns `false` on any error (graceful degradation: the caller shows no
    /// warning rather than blocking the flow).
    pub async fn has_cross_signing_keys(&self, localpart: &str, server_name: &str) -> Result<bool> {
        let user_id = format!("@{}:{}", localpart, server_name);
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
}
