//! Which identity a stored passkey credential authenticates.
//!
//! One rule, one definition, two callers: the login path
//! (`verify_credential`) and the credential-store backfill
//! ([`crate::credential_migration`]).
//!
//! The rule is that a `webauthn:link/{cred_id_b64}` entry OVERRIDES the
//! `did:key:zDn…` derived from the passkey's own public key. That is why this
//! is not a detail either caller can own privately: a reader that skips the
//! link table silently attributes every linked credential to the wrong
//! principal, and a backfill that disagreed with the login path would record
//! one identity while logins produced another.
//!
//! This module READS `webauthn:link/*` and never writes it. The link namespace
//! is owned by the binary's account-linking ceremony (`link_start`,
//! `link_finish`) and stays there. Reading is not owning.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::info;

use crate::db::{RedisClient, KV_WEBAUTHN_LINK_PREFIX};

/// Read-only projection of the binary's `LinkEntry`.
///
/// Deliberately a separate, deserialize-only type rather than a shared one: this
/// module must be unable to write a link even by accident, and the library crate
/// must not take ownership of a shape the binary owns. Extra fields the binary
/// may add are ignored rather than fatal.
#[derive(Deserialize)]
struct LinkView {
    primary_did: String,
    #[serde(default)]
    label: String,
}

/// The identity a stored credential authenticates, resolved the way the login
/// path resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The DID the credential authenticates as.
    pub did: String,
    /// The link's label, when the credential is linked. `None` for a standalone
    /// passkey-as-identity credential.
    pub label: Option<String>,
    /// Whether a `webauthn:link/*` entry overrode the derived DID.
    pub linked: bool,
}

/// Resolve which identity `cred_id_b64` authenticates: the linked `primary_did`
/// if `webauthn:link/{cred_id_b64}` exists, otherwise `derived_did` (the
/// `did:key:zDn…` computed from the passkey's own P-256 public key).
///
/// This is the single definition of that rule. `verify_credential` calls it on
/// the login path and [`CredentialMigration`] calls it on the backfill path, so
/// the migrated `StoredCredential.did` cannot drift from the DID a login would
/// produce for the same credential.
///
/// Read-only: one `GET` on the link key, no writes.
pub async fn resolve_credential_identity(
    redis: &RedisClient,
    cred_id_b64: &str,
    derived_did: &str,
) -> Result<ResolvedIdentity> {
    let link_key = format!("{}/{}", KV_WEBAUTHN_LINK_PREFIX, cred_id_b64);
    match redis.get_raw(&link_key).await? {
        Some(link_json) => {
            let link: LinkView = serde_json::from_str(&link_json)
                .map_err(|e| anyhow!("Failed to deserialize link entry: {}", e))?;
            info!(
                "webauthn resolve_credential_identity: linked cred={} primary_did={}",
                cred_id_b64, link.primary_did
            );
            Ok(ResolvedIdentity {
                did: link.primary_did,
                label: Some(link.label),
                linked: true,
            })
        }
        None => Ok(ResolvedIdentity {
            did: derived_did.to_string(),
            label: None,
            linked: false,
        }),
    }
}
