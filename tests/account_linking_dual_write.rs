//! Gate 4: account linking is unchanged by the credential-store dual-write, and
//! it is unchanged in BOTH modes.
//!
//! Every test here detects the mode from
//! `credential_store::shared_store()` and asserts what that mode must do, so the
//! suite is meaningful whether `AQUA_WEBAUTHN_REDIS_URL` is set or not. The flag
//! is read once per process, so "both modes" means running this binary twice:
//!
//! ```text
//! cargo test --test account_linking_dual_write                                  # flag off
//! AQUA_WEBAUTHN_REDIS_URL=redis://localhost cargo test --test account_linking_dual_write   # flag on
//! ```
//!
//! Uses `redis://localhost` and unique nonces, the convention the other
//! Redis-backed tests here already follow, and cleans up after itself.
//!
//! What is deliberately NOT tested by calling it: `link_start`/`link_finish`
//! live in the binary crate and need a real authenticator to drive. What is
//! tested is the contract they depend on and that this change could have broken:
//! that a link still overrides the derived DID, that no mirror operation writes
//! the link namespace, and that purging an identity clears it from both
//! namespaces.

use aqua_auth::webauthn_store::{CredentialId, WebauthnCredentialBackend};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use url::Url;

use siwx_oidc::credential_identity::resolve_credential_identity;
use siwx_oidc::credential_migration::derive_did_from_passkey_blob;
use siwx_oidc::credential_store;
use siwx_oidc::db::{RedisClient, KV_WEBAUTHN_CREDENTIAL_PREFIX, KV_WEBAUTHN_LINK_PREFIX};

const FIXTURE: &str = include_str!("fixtures/passkey_webauthn_rs_0_6_0_dev.json");
const FIXTURE_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";

async fn redis() -> Option<RedisClient> {
    RedisClient::new(&Url::parse("redis://localhost").unwrap())
        .await
        .ok()
}

fn nonce() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    (base << 20) | u128::from(C.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF)
}

fn cred_key(id: &str) -> String {
    format!("{KV_WEBAUTHN_CREDENTIAL_PREFIX}/{id}")
}

fn link_key(id: &str) -> String {
    format!("{KV_WEBAUTHN_LINK_PREFIX}/{id}")
}

fn cid(id: &str) -> CredentialId {
    CredentialId(URL_SAFE_NO_PAD.decode(id).unwrap())
}

/// The link entries for exactly these credential ids.
///
/// Scoped rather than a whole-namespace snapshot on purpose: these tests share
/// `redis://localhost` with the rest of the suite, so a global snapshot would
/// pick up other tests' keys appearing and disappearing and fail for reasons
/// that have nothing to do with the mirror. Scoped is also the assertion that
/// actually bites: `mirror_credential` could only ever write a link key for the
/// credential it is mirroring.
async fn links_for(r: &RedisClient, ids: &[&str]) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for id in ids {
        out.push((link_key(id), r.get_raw(&link_key(id)).await.unwrap()));
    }
    out
}

/// The mode this process is actually in must be the mode the environment
/// declares.
///
/// `shared_store` degrades to `None` when the flag is set but the connect fails,
/// which is the right production behaviour (nobody is locked out because a
/// second Redis is down) and a terrible gate behaviour: every `Some(store)`
/// assertion below would be skipped and the suite would report a green "flag on"
/// run that never touched the store. This test makes that impossible.
#[tokio::test]
async fn the_declared_mode_is_the_actual_mode() {
    let declared_on = std::env::var(credential_store::ENABLE_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let actual_on = credential_store::shared_store().await.is_some();
    assert_eq!(
        declared_on,
        actual_on,
        "{} is {}, but the shared store is {}",
        credential_store::ENABLE_ENV,
        if declared_on { "set" } else { "unset" },
        if actual_on { "enabled" } else { "disabled" },
    );
}

/// A link overrides the derived `did:key`, in both modes. This is the property
/// account linking exists for, and the one a careless credential-store change
/// would silently break.
#[tokio::test]
async fn a_link_still_overrides_the_derived_did() {
    let Some(r) = redis().await else {
        eprintln!("skip: no Redis on localhost");
        return;
    };
    let n = nonce();
    let id = URL_SAFE_NO_PAD.encode(format!("link-{n}").as_bytes());
    let primary = format!("did:pkh:eip155:1:0xLINK{n}");

    r.set_raw(&cred_key(&id), FIXTURE).await.unwrap();
    let derived = derive_did_from_passkey_blob(FIXTURE).expect("derives");
    assert_eq!(derived, FIXTURE_DID);

    // Unlinked: the derived DID.
    let before = resolve_credential_identity(&r, &id, &derived)
        .await
        .unwrap();
    assert_eq!(before.did, derived);
    assert!(!before.linked);
    assert_eq!(before.label, None);

    // Linked: the primary DID wins, and carries the link's label.
    r.set_raw(
        &link_key(&id),
        &format!(r#"{{"primary_did":"{primary}","label":"linked"}}"#),
    )
    .await
    .unwrap();
    let after = resolve_credential_identity(&r, &id, &derived)
        .await
        .unwrap();
    assert_eq!(after.did, primary, "the link must override the derived DID");
    assert_ne!(after.did, derived);
    assert!(after.linked);
    assert_eq!(after.label.as_deref(), Some("linked"));

    // The credential blob is readable in either mode. With the flag on nothing
    // has been mirrored yet, so this also exercises the legacy fallback that
    // makes flipping the flag safe before the backfill has run.
    let blob = credential_store::read_blob(&r, &id).await.unwrap();
    assert_eq!(blob.as_deref(), Some(FIXTURE));

    let _ = r.del_raw(&cred_key(&id)).await;
    let _ = r.del_raw(&link_key(&id)).await;
}

/// Mirroring a linked credential must write the credential and NOTHING in the
/// link namespace. The mirror stores the resolved principal, so a linked
/// credential lands under its `primary_did`, never under the derived `did:key`.
#[tokio::test]
async fn mirroring_never_writes_the_link_namespace() {
    let Some(r) = redis().await else {
        eprintln!("skip: no Redis on localhost");
        return;
    };
    let n = nonce();
    let id = URL_SAFE_NO_PAD.encode(format!("mirror-{n}").as_bytes());
    // A second credential with NO link, so the test also covers the other
    // direction: mirroring must not INVENT a link entry.
    let unlinked = URL_SAFE_NO_PAD.encode(format!("mirror-unlinked-{n}").as_bytes());
    let primary = format!("did:pkh:eip155:1:0xMIRROR{n}");

    r.set_raw(&cred_key(&id), FIXTURE).await.unwrap();
    r.set_raw(&cred_key(&unlinked), FIXTURE).await.unwrap();
    r.set_raw(
        &link_key(&id),
        &format!(r#"{{"primary_did":"{primary}","label":"linked"}}"#),
    )
    .await
    .unwrap();

    let ids = [id.as_str(), unlinked.as_str()];
    let links_before = links_for(&r, &ids).await;
    credential_store::mirror_credential(&id, FIXTURE, &primary, Some("linked".into())).await;
    credential_store::mirror_credential(&unlinked, FIXTURE, FIXTURE_DID, None).await;
    credential_store::mirror_sign_count(&id, 12).await;
    let links_after = links_for(&r, &ids).await;
    assert_eq!(
        links_before, links_after,
        "no mirror operation may create, change or remove a webauthn:link/* key"
    );
    assert!(
        links_after[1].1.is_none(),
        "mirroring an unlinked credential must not invent a link entry"
    );

    match credential_store::shared_store().await {
        Some(store) => {
            let row = store
                .get_by_id(&cid(&id))
                .await
                .unwrap()
                .expect("flag on: the credential must be mirrored");
            assert_eq!(
                row.did, primary,
                "a linked credential mirrors under its primary_did, not its derived did:key"
            );
            assert_ne!(row.did, FIXTURE_DID);
            assert_eq!(row.label.as_deref(), Some("linked"));
            assert_eq!(String::from_utf8(row.public_key).unwrap(), FIXTURE);

            // The picker must find it under the primary DID.
            let ids = credential_store::list_credential_ids(&r, &primary, |_| None)
                .await
                .unwrap();
            assert!(ids.contains(&id), "primary DID must index the linked cred");

            // The unlinked twin mirrors under the DERIVED did, proving the
            // mirror follows the resolution rather than a fixed choice.
            let twin = store
                .get_by_id(&cid(&unlinked))
                .await
                .unwrap()
                .expect("flag on: the unlinked credential must be mirrored");
            assert_eq!(twin.did, FIXTURE_DID);
            assert_eq!(twin.label, None);

            let _ = store.delete(&primary, &cid(&id)).await;
            let _ = store.delete(FIXTURE_DID, &cid(&unlinked)).await;
        }
        None => {
            assert!(
                r.get_raw(&format!("aqua:webauthn:cred:{id}"))
                    .await
                    .unwrap()
                    .is_none(),
                "flag off: mirroring must be a no-op, nothing in aqua:webauthn:*"
            );
        }
    }

    let _ = r.del_raw(&cred_key(&id)).await;
    let _ = r.del_raw(&cred_key(&unlinked)).await;
    let _ = r.del_raw(&link_key(&id)).await;
}

/// Purging a linked identity must clear it from BOTH namespaces. Without the
/// delete-through, an erased identity's passkey would survive in the aqua-auth
/// namespace as soon as the flag is on, and erasure would be incomplete.
#[tokio::test]
async fn purging_a_linked_identity_clears_both_namespaces() {
    let Some(r) = redis().await else {
        eprintln!("skip: no Redis on localhost");
        return;
    };
    let n = nonce();
    let id = URL_SAFE_NO_PAD.encode(format!("purge-{n}").as_bytes());
    let primary = format!("did:pkh:eip155:1:0xPURGELINK{n}");

    r.set_raw(&cred_key(&id), FIXTURE).await.unwrap();
    r.set_raw(
        &link_key(&id),
        &format!(r#"{{"primary_did":"{primary}","label":"linked"}}"#),
    )
    .await
    .unwrap();
    r.index_add_passkey(&primary, &id).await.unwrap();
    credential_store::mirror_credential(&id, FIXTURE, &primary, Some("linked".into())).await;

    // A no-op resolver so only the link pass (a) runs, matching the existing
    // purge test's isolation.
    let purged = r.purge_identity(&primary, |_| None).await.unwrap();
    assert!(purged >= 2, "the link and its credential were purged");

    assert!(
        r.get_raw(&link_key(&id)).await.unwrap().is_none(),
        "the link entry must be gone"
    );
    assert!(
        r.get_raw(&cred_key(&id)).await.unwrap().is_none(),
        "the legacy credential must be gone"
    );

    if let Some(store) = credential_store::shared_store().await {
        assert!(
            store.get_by_id(&cid(&id)).await.unwrap().is_none(),
            "flag on: the mirrored credential must be gone too, or erasure is incomplete"
        );
        assert!(
            store.list_for_did(&primary).await.unwrap().is_empty(),
            "flag on: the mirrored did index must be empty"
        );
    }
}
