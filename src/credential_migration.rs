//! Additive backfill of siwx-oidc's passkey credentials into aqua-auth's
//! credential store.
//!
//! siwx-oidc stores a passkey as the raw serialized `webauthn_rs::Passkey` JSON
//! at `webauthn:credential/{cred_id_b64}`, and (when the credential has been
//! linked to a wallet identity) a `{ primary_did, label }` entry at
//! `webauthn:link/{cred_id_b64}`. aqua-auth stores a `StoredCredential` at
//! `aqua:webauthn:cred:{cred_id_b64}` with a `aqua:webauthn:did:{did}` reverse
//! index. This module copies the former into the latter.
//!
//! # Safety properties
//!
//! - **Additive only.** Nothing here deletes, renames or mutates a
//!   `webauthn:credential/*` or `webauthn:link/*` key. Both namespaces are read
//!   with `GET`/`KEYS` and never written, so the old layout stays authoritative
//!   and a rollback is a flag flip, not a restore.
//! - **Idempotent.** A credential already present in the target store is
//!   skipped, not rewritten. Running twice equals running once, including
//!   `created_at`, and a row whose sign counter aqua-auth has already advanced
//!   is never clobbered back to the migration-time value.
//! - **Dry-run by default.** [`CredentialMigration::run`] writes only when
//!   `apply` is set.
//! - **Per-row failures do not abort.** One undecodable credential is recorded
//!   in [`MigrationReport::failures`] and the run continues.
//!
//! # Why this module reads the link table
//!
//! Account linking is owned by the binary's ceremony (`link_start`,
//! `link_finish`) and stays there. But the link table is not an adjacent
//! feature, it is part of the credential **read** path: `verify_credential`
//! resolves the authenticated identity as "the linked `primary_did` if there is
//! one, otherwise the DID derived from the passkey". A migration that ignored
//! the link table would write the derived `did:key` for every linked credential,
//! silently recording the wrong principal for exactly the credentials whose
//! identity was deliberately overridden. So the resolution lives in
//! [`resolve_credential_identity`], and both the login path and this migration
//! call it. Reading is not owning: nothing here writes a link.
//!
//! # Sign counter
//!
//! siwx-oidc keeps the counter INSIDE the blob and rewrites the blob on every
//! authentication; aqua-auth keeps a sidecar `sign_count` field and never
//! rewrites the blob. So the counter is lifted out of `cred.counter` rather than
//! defaulted, which would reset clone detection for every migrated credential.

use anyhow::{anyhow, Context, Result};
use aqua_auth::webauthn_store::{
    CredentialId, NewCredential, WebauthnCredentialBackend, WebauthnStoreError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::credential_identity::resolve_credential_identity;
use crate::db::{RedisClient, KV_WEBAUTHN_CREDENTIAL_PREFIX};

/// Counts from one migration run. A dry run reports `would_write` and leaves
/// `written` at zero; an applied run reports `written` and leaves `would_write`
/// at zero.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// `webauthn:credential/*` keys found.
    pub read: usize,
    /// Rows a dry run would have written.
    pub would_write: usize,
    /// Rows actually written.
    pub written: usize,
    /// Rows already present in the target store.
    pub skipped: usize,
    /// Rows that could not be migrated.
    pub failed: usize,
    /// `(source key, reason)` for every failure, in encounter order.
    pub failures: Vec<(String, String)>,
}

impl MigrationReport {
    fn fail(&mut self, key: &str, reason: impl std::fmt::Display) {
        self.failed += 1;
        self.failures.push((key.to_string(), reason.to_string()));
    }

    /// One-line summary for an operator.
    pub fn summary(&self) -> String {
        format!(
            "read={} would_write={} written={} skipped={} failed={}",
            self.read, self.would_write, self.written, self.skipped, self.failed
        )
    }
}

/// Derives the `did:key:zDn…` a passkey blob authenticates as.
///
/// Boxed so the migration can be driven in tests without pulling `webauthn-rs`
/// into this module. Production passes
/// [`derive_did_from_passkey_blob`].
pub type DidDeriver = dyn Fn(&str) -> Option<String> + Send + Sync;

/// The production DID deriver: parse the blob as a `Passkey`, take its P-256
/// public key, encode it as `did:key:zDn…`.
///
/// This is aqua-auth's derivation, which is byte-identical to the binary's own
/// `did_from_passkey` (asserted by a test against the real 0.6.0-dev fixture
/// blob). Using aqua-auth's is what lets the duplicate helpers go away.
pub fn derive_did_from_passkey_blob(blob: &str) -> Option<String> {
    aqua_auth::p256_compressed_from_passkey_blob(blob.as_bytes())
        .ok()
        .map(|c| aqua_auth::did_key_from_p256_compressed(&c))
}

/// Copies siwx-oidc's credentials into an aqua-auth credential store.
pub struct CredentialMigration<'a> {
    redis: &'a RedisClient,
    store: &'a dyn WebauthnCredentialBackend,
    derive_did: &'a DidDeriver,
    apply: bool,
}

impl<'a> CredentialMigration<'a> {
    /// `apply == false` is a dry run: it reads everything and writes nothing.
    pub fn new(
        redis: &'a RedisClient,
        store: &'a dyn WebauthnCredentialBackend,
        derive_did: &'a DidDeriver,
        apply: bool,
    ) -> Self {
        Self {
            redis,
            store,
            derive_did,
            apply,
        }
    }

    /// Run the backfill.
    ///
    /// Uses `KEYS webauthn:credential/*` to enumerate the source. `KEYS` blocks
    /// the server for the duration of the scan, which is acceptable here because
    /// credentials are low-cardinality (a handful per user) and this is a
    /// one-shot operator tool, not a request path. It is also what
    /// `purge_identity` already does against the same namespace.
    pub async fn run(&self) -> Result<MigrationReport> {
        let pattern = format!("{}/*", KV_WEBAUTHN_CREDENTIAL_PREFIX);
        let keys = self
            .redis
            .keys_raw(&pattern)
            .await
            .with_context(|| format!("enumerate {pattern}"))?;

        let mut report = MigrationReport {
            read: keys.len(),
            ..Default::default()
        };

        for key in keys {
            if let Err(e) = self.migrate_one(&key, &mut report).await {
                report.fail(&key, e);
            }
        }
        Ok(report)
    }

    async fn migrate_one(&self, key: &str, report: &mut MigrationReport) -> Result<()> {
        let prefix = format!("{}/", KV_WEBAUTHN_CREDENTIAL_PREFIX);
        let cred_id_b64 = key
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow!("key does not carry the {prefix} prefix"))?;

        // The credential id is the KEY, decoded. aqua-auth stores raw bytes.
        let cred_id_bytes = URL_SAFE_NO_PAD
            .decode(cred_id_b64.trim_end_matches('='))
            .map_err(|e| anyhow!("credential id is not base64url: {e}"))?;
        let cred_id = CredentialId(cred_id_bytes);

        // Idempotence: a row already in the target store is left exactly as it
        // is. It may carry a sign counter aqua-auth has advanced past the value
        // in the source blob, and rewriting would regress it.
        match self.store.get_by_id(&cred_id).await {
            Ok(Some(_)) => {
                report.skipped += 1;
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => return Err(anyhow!("target store lookup failed: {e}")),
        }

        let blob = self
            .redis
            .get_raw(key)
            .await?
            .ok_or_else(|| anyhow!("credential vanished between KEYS and GET"))?;

        // The blob is copied VERBATIM. aqua-auth stores `public_key` opaquely
        // and never parses it, so re-serializing here could only introduce
        // drift.
        let public_key = blob.clone().into_bytes();

        // The counter lives inside the blob, and siwx-oidc rewrites it there on
        // every authentication. Defaulting to 0 would reset clone detection.
        let blob_json: serde_json::Value = serde_json::from_str(&blob)
            .map_err(|e| anyhow!("stored credential is not JSON: {e}"))?;
        let sign_count = sign_count_from_blob(&blob_json)?;

        // Link-aware identity resolution, shared with the login path.
        let derived_did = (self.derive_did)(&blob);
        let identity = match derived_did {
            Some(ref d) => resolve_credential_identity(self.redis, cred_id_b64, d).await?,
            None => {
                // Not a P-256 passkey we can derive a did:key from. A linked
                // credential is still migratable, because the link supplies the
                // identity outright; an unlinked one is not.
                let probe = resolve_credential_identity(self.redis, cred_id_b64, "").await?;
                if !probe.linked {
                    return Err(anyhow!(
                        "cannot derive a did:key from the passkey blob and no link entry supplies one"
                    ));
                }
                probe
            }
        };

        if !self.apply {
            report.would_write += 1;
            return Ok(());
        }

        // `created_at` is stamped by the backend, so it is the migration
        // timestamp; the source layout carries no creation time.
        self.store
            .insert(NewCredential {
                did: identity.did,
                credential_id: cred_id,
                public_key,
                sign_count,
                // The source layout does not record authenticator transports.
                transports: Vec::new(),
                label: identity.label,
            })
            .await
            .map_err(|e: WebauthnStoreError| anyhow!("target store insert failed: {e}"))?;
        report.written += 1;
        Ok(())
    }
}

/// Lift the WebAuthn signature counter out of a serialized `Passkey` blob.
///
/// `cred.counter` is where webauthn-rs keeps it and where siwx-oidc's
/// `verify_credential` rewrites it. A blob with no `cred` object is not a
/// passkey; a `cred` object with no `counter` is a passkey that has never been
/// used, which is a legitimate 0.
pub fn sign_count_from_blob(blob: &serde_json::Value) -> Result<u32> {
    let cred = blob
        .get("cred")
        .ok_or_else(|| anyhow!("stored credential has no `cred` object"))?;
    match cred.get("counter") {
        None => Ok(0),
        Some(c) => c
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| anyhow!("`cred.counter` is not a u32: {c}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_count_is_read_from_cred_counter_not_defaulted() {
        let blob = serde_json::json!({"cred": {"counter": 42}});
        assert_eq!(sign_count_from_blob(&blob).unwrap(), 42);
    }

    #[test]
    fn a_never_used_passkey_counts_zero() {
        let blob = serde_json::json!({"cred": {}});
        assert_eq!(sign_count_from_blob(&blob).unwrap(), 0);
    }

    #[test]
    fn a_blob_without_cred_is_not_a_passkey() {
        let blob = serde_json::json!({"nope": 1});
        assert!(sign_count_from_blob(&blob).is_err());
    }

    #[test]
    fn a_non_numeric_counter_is_an_error_not_a_silent_zero() {
        let blob = serde_json::json!({"cred": {"counter": "seven"}});
        assert!(sign_count_from_blob(&blob).is_err());
        let negative = serde_json::json!({"cred": {"counter": -1}});
        assert!(sign_count_from_blob(&negative).is_err());
    }

    /// The production deriver must agree with the DID the binary's own
    /// `did_from_passkey` produced for the same blob, or every standalone
    /// credential migrates to the wrong principal. Pinned against the REAL
    /// 0.6.0-dev fixture and the DID the binary's test asserts for it.
    #[test]
    fn derivation_matches_the_binarys_did_from_passkey() {
        const BLOB: &str = include_str!("../tests/fixtures/passkey_webauthn_rs_0_6_0_dev.json");
        assert_eq!(
            derive_did_from_passkey_blob(BLOB).as_deref(),
            Some("did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF"),
        );
    }

    #[test]
    fn derivation_fails_closed_on_garbage() {
        assert_eq!(derive_did_from_passkey_blob(""), None);
        assert_eq!(derive_did_from_passkey_blob("{}"), None);
        assert_eq!(derive_did_from_passkey_blob("not json"), None);
    }

    #[test]
    fn report_summary_names_every_count() {
        let r = MigrationReport {
            read: 5,
            would_write: 3,
            written: 0,
            skipped: 1,
            failed: 1,
            failures: vec![("k".into(), "why".into())],
        };
        assert_eq!(
            r.summary(),
            "read=5 would_write=3 written=0 skipped=1 failed=1"
        );
    }
}
