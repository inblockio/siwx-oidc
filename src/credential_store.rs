//! Optional aqua-auth credential store, selected at runtime.
//!
//! # The flag
//!
//! `AQUA_WEBAUTHN_REDIS_URL` unset or empty (the default) means nothing here is
//! active: credentials live only in `webauthn:credential/*`, exactly as before.
//! Set it and siwx-oidc additionally reads and writes aqua-auth's credential
//! store at that Redis.
//!
//! It is the same variable aqua-node and aquafier already use to select the
//! shared store, deliberately: one switch across the ecosystem means "use the
//! shared aqua-auth credential store", and a deployment cannot end up with two
//! of the three services pointed at it.
//!
//! # Dual-write, not cut-over
//!
//! With the flag on, every write goes to BOTH namespaces. The legacy namespace
//! is never abandoned, so turning the flag back off loses nothing and needs no
//! restore: it is a flag flip, not a migration back. Removing the legacy write
//! is a separate decision that needs a production soak, and is explicitly not
//! part of this change.
//!
//! Mirror writes are **best-effort**: a failure is logged and the request
//! proceeds. That is the same treatment the `webauthn:by_did` index already
//! gets, and for the same reason: the legacy namespace is still authoritative,
//! reads fall back to it, so a hiccup in the mirror must not fail a
//! registration the user has just completed. It cannot lock anyone out.
//!
//! # Reads
//!
//! Reads are read-through: the aqua-auth store first, the legacy namespace on a
//! miss. That makes flipping the flag safe even if the backfill
//! ([`crate::credential_migration`]) has not run, or has not finished.
//!
//! # What this module does NOT touch
//!
//! Account linking. `webauthn:link/*` is written only by the binary's
//! `link_finish`, and which identity a credential authenticates is still
//! resolved through that table by
//! [`crate::credential_identity::resolve_credential_identity`], for both
//! namespaces. The aqua-auth row's `did` is a snapshot of that resolution, not
//! a second source of truth; see the consistency note in the migration report.

use anyhow::Result;
use aqua_auth::webauthn_store::{
    CredentialId, NewCredential, WebauthnCredentialBackend, WebauthnStoreError,
};
use aqua_auth::RedisWebauthnStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::credential_migration::sign_count_from_blob;
use crate::db::{RedisClient, KV_WEBAUTHN_CREDENTIAL_PREFIX};

/// The runtime flag. Set to a Redis URL to enable the shared store.
pub const ENABLE_ENV: &str = "AQUA_WEBAUTHN_REDIS_URL";

static SHARED: OnceCell<Option<RedisWebauthnStore>> = OnceCell::const_new();

/// The enable decision, split out so it is testable without touching process
/// environment or memoised state: a missing, empty or whitespace-only value
/// means OFF.
fn enabled_url(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|s| !s.is_empty())
}

/// The shared aqua-auth credential store, or `None` when the flag is off.
///
/// Connected once, on first use. A connect failure logs and degrades to `None`
/// for the process lifetime, i.e. to the legacy-only path, which is the safe
/// direction: nobody is locked out of a passkey because a second Redis is down.
pub async fn shared_store() -> Option<&'static RedisWebauthnStore> {
    SHARED
        .get_or_init(|| async {
            let raw = std::env::var(ENABLE_ENV).ok();
            let url = enabled_url(raw.as_deref())?;
            match RedisWebauthnStore::connect(url).await {
                Ok(s) => {
                    info!("webauthn credential store: aqua-auth shared store ENABLED (dual-write)");
                    Some(s)
                }
                Err(e) => {
                    warn!(
                        "{ENABLE_ENV} is set but connect failed ({e}); \
                         staying on the legacy credential namespace"
                    );
                    None
                }
            }
        })
        .await
        .as_ref()
}

fn credential_id(cred_id_b64: &str) -> Option<CredentialId> {
    URL_SAFE_NO_PAD
        .decode(cred_id_b64.trim_end_matches('='))
        .ok()
        .map(CredentialId)
}

fn legacy_key(cred_id_b64: &str) -> String {
    format!("{KV_WEBAUTHN_CREDENTIAL_PREFIX}/{cred_id_b64}")
}

/// Mirror a newly stored credential into the aqua-auth store. No-op when the
/// flag is off. Best-effort: logs and returns on failure.
///
/// `did` must be the identity the credential authenticates as, resolved the
/// same way the login path resolves it (the linked `primary_did` for a linked
/// credential, the derived `did:key` otherwise).
pub async fn mirror_credential(cred_id_b64: &str, blob: &str, did: &str, label: Option<String>) {
    let Some(store) = shared_store().await else {
        return;
    };
    let Some(id) = credential_id(cred_id_b64) else {
        warn!("mirror_credential: {cred_id_b64} is not base64url; not mirrored");
        return;
    };
    // The counter lives inside the blob. Reading it here (rather than passing 0)
    // keeps a mirrored credential's clone detection aligned with the legacy one
    // from the first write, not just from the first login.
    let sign_count = match serde_json::from_str::<serde_json::Value>(blob)
        .ok()
        .as_ref()
        .map(sign_count_from_blob)
    {
        Some(Ok(n)) => n,
        _ => {
            warn!("mirror_credential: {cred_id_b64} has no readable cred.counter; not mirrored");
            return;
        }
    };
    let res = store
        .insert(NewCredential {
            did: did.to_string(),
            credential_id: id,
            public_key: blob.as_bytes().to_vec(),
            sign_count,
            // The legacy layout does not record authenticator transports.
            transports: Vec::new(),
            label,
        })
        .await;
    match res {
        Ok(()) => info!("mirror_credential: {cred_id_b64} -> aqua-auth store (did={did})"),
        Err(e) => warn!("mirror_credential: {cred_id_b64} failed: {e}"),
    }
}

/// Mirror an advanced sign counter. No-op when the flag is off. Best-effort.
///
/// `NotFound` is expected and quiet: it just means this credential predates the
/// flag and has not been backfilled yet.
pub async fn mirror_sign_count(cred_id_b64: &str, new_count: u32) {
    let Some(store) = shared_store().await else {
        return;
    };
    let Some(id) = credential_id(cred_id_b64) else {
        return;
    };
    match store.update_sign_count(&id, new_count).await {
        Ok(()) | Err(WebauthnStoreError::NotFound) => {}
        Err(e) => warn!("mirror_sign_count: {cred_id_b64} failed: {e}"),
    }
}

/// Mirror a credential deletion. No-op when the flag is off. Best-effort.
///
/// Called from the identity purge. Without it an erased identity's passkey
/// would survive in the aqua-auth namespace, which would make erasure
/// incomplete the moment the flag is on.
pub async fn mirror_delete(did: &str, cred_id_b64: &str) {
    let Some(store) = shared_store().await else {
        return;
    };
    let Some(id) = credential_id(cred_id_b64) else {
        return;
    };
    match store.delete(did, &id).await {
        Ok(_) => {}
        Err(e) => warn!("mirror_delete: {cred_id_b64} failed: {e}"),
    }
}

/// Read a credential blob: the aqua-auth store first when the flag is on, the
/// legacy namespace on a miss.
///
/// The fallback is what makes the flag safe to flip before (or without) the
/// backfill: a credential that only exists in the legacy namespace still logs
/// in. A store error also falls back rather than failing the login, for the same
/// reason a mirror-write failure is best-effort.
pub async fn read_blob(redis: &RedisClient, cred_id_b64: &str) -> Result<Option<String>> {
    if let Some(store) = shared_store().await {
        if let Some(id) = credential_id(cred_id_b64) {
            match store.get_by_id(&id).await {
                Ok(Some(row)) => {
                    if let Ok(blob) = String::from_utf8(row.public_key) {
                        return Ok(Some(blob));
                    }
                    warn!("read_blob: {cred_id_b64} in the aqua-auth store is not UTF-8; falling back");
                }
                Ok(None) => {}
                Err(e) => warn!("read_blob: aqua-auth store lookup failed ({e}); falling back"),
            }
        }
    }
    redis.get_raw(&legacy_key(cred_id_b64)).await
}

/// The credential ids registered to `did`, for the passkey picker's
/// `allowCredentials`.
///
/// The aqua-auth store's `did` index first when the flag is on, the legacy
/// `webauthn:by_did` index (with its own scan self-heal) otherwise or on a miss.
/// Both are advisory: an empty result means "usernameless", never "denied", so a
/// wrong answer here degrades the picker rather than blocking a login.
pub async fn list_credential_ids<F>(
    redis: &RedisClient,
    did: &str,
    derive: F,
) -> Result<Vec<String>>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(store) = shared_store().await {
        match store.list_for_did(did).await {
            Ok(rows) if !rows.is_empty() => {
                return Ok(rows
                    .into_iter()
                    .map(|r| URL_SAFE_NO_PAD.encode(&r.credential_id.0))
                    .collect())
            }
            Ok(_) => {}
            Err(e) => warn!("list_credential_ids: aqua-auth store failed ({e}); falling back"),
        }
    }
    redis.get_passkeys_for_did(did, derive).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_id_decodes_padded_and_unpadded() {
        let raw = b"hello-credential";
        let unpadded = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(credential_id(&unpadded).unwrap().0, raw.to_vec());
        // Some clients send the padded spelling; the legacy layer is tolerant of
        // it, so the mirror has to be too or the two namespaces key differently.
        let padded = format!("{unpadded}==");
        assert_eq!(credential_id(&padded).unwrap().0, raw.to_vec());
    }

    #[test]
    fn credential_id_rejects_garbage() {
        assert!(credential_id("!!!not base64!!!").is_none());
    }

    #[test]
    fn legacy_key_matches_the_namespace_the_ceremony_writes() {
        assert_eq!(legacy_key("abc"), "webauthn:credential/abc");
    }

    /// OFF is the default, and a blank value is OFF too. This is the property
    /// that keeps the existing deployment's behaviour unchanged, so pin it.
    #[test]
    fn the_flag_is_off_unless_it_names_a_redis() {
        assert_eq!(enabled_url(None), None, "unset means off");
        assert_eq!(enabled_url(Some("")), None, "empty means off");
        assert_eq!(enabled_url(Some("   ")), None, "whitespace means off");
        assert_eq!(
            enabled_url(Some("  redis://127.0.0.1:6379  ")),
            Some("redis://127.0.0.1:6379"),
            "a URL means on, trimmed"
        );
    }
}
