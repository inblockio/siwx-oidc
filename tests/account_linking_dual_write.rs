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

/// ONE runtime for the whole binary.
///
/// # Why this is not cosmetic
///
/// `credential_store::shared_store()` memoises the store in a process-wide
/// `OnceCell`, and the `ConnectionManager` inside it owns a background task
/// bound to whichever tokio runtime happened to initialise it. Under
/// `#[tokio::test]` every test gets its OWN runtime: the first test to touch the
/// store initialises it, that runtime is dropped at the end of that test, and
/// every mirror operation in every LATER test then fails against a dead
/// connection.
///
/// That is invisible, because mirror writes are deliberately best-effort. The
/// tests that assert something is ABSENT from the aqua-auth namespace go on
/// passing -- for the wrong reason -- so the suite reports green while the flag
/// is on and nothing is being mirrored at all. Observed directly: each test in
/// this file passes when run ALONE with the flag on, and three of five fail when
/// run together.
///
/// Production is unaffected (siwx-oidc has one runtime for the process), so the
/// fix belongs here and not in the store: give the whole binary one runtime, and
/// the test topology matches the deployment topology.
fn shared_rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    })
}

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
#[test]
fn the_declared_mode_is_the_actual_mode() {
    shared_rt().block_on(the_declared_mode_is_the_actual_mode_impl());
}

async fn the_declared_mode_is_the_actual_mode_impl() {
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

    // `is_some()` alone is NOT enough, and that gap has already produced a false
    // green here. A store can be present and UNUSABLE -- a dead connection, a
    // Redis that accepted the handshake and then went away. Every mirror write
    // in this suite is deliberately best-effort, so nothing errors; the writes
    // just silently do not happen, and every "the credential is absent"
    // assertion keeps passing for entirely the wrong reason.
    //
    // Prove a real round-trip instead of trusting the handle.
    if declared_on {
        let store = credential_store::shared_store()
            .await
            .expect("declared on, so the store must exist");
        let n = nonce();
        let id = URL_SAFE_NO_PAD.encode(format!("probe-{n}").as_bytes());
        let did = format!("did:key:zProbe{n}");
        credential_store::mirror_credential(&id, FIXTURE, &did, None).await;
        let got = store
            .get_by_id(&cid(&id))
            .await
            .expect("the store must answer, not error");
        assert!(
            got.is_some(),
            "the shared store is enabled but a mirrored credential did not read \
             back: it is present and UNUSABLE, so every absence assertion in this \
             suite would pass vacuously"
        );
        credential_store::mirror_delete(&did, &id).await;
    }
}

/// A link overrides the derived `did:key`, in both modes. This is the property
/// account linking exists for, and the one a careless credential-store change
/// would silently break.
#[test]
fn a_link_still_overrides_the_derived_did() {
    shared_rt().block_on(a_link_still_overrides_the_derived_did_impl());
}

async fn a_link_still_overrides_the_derived_did_impl() {
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
#[test]
fn mirroring_never_writes_the_link_namespace() {
    shared_rt().block_on(mirroring_never_writes_the_link_namespace_impl());
}

async fn mirroring_never_writes_the_link_namespace_impl() {
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
#[test]
fn purging_a_linked_identity_clears_both_namespaces() {
    shared_rt().block_on(purging_a_linked_identity_clears_both_namespaces_impl());
}

async fn purging_a_linked_identity_clears_both_namespaces_impl() {
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

/// The counter the login path reads back must be the ADVANCED one, in both
/// modes.
///
/// # Why this test exists
///
/// aqua-auth stores the blob and the sign count SEPARATELY: `public_key` is the
/// opaque `Passkey` JSON, `sign_count` is a sidecar that `update_sign_count`
/// advances monotonically. `mirror_credential` -- the only writer of the blob --
/// runs at register/link, never on login. So with the flag on, read-through
/// returned a blob whose `cred.counter` was frozen at registration (or, for a
/// backfilled credential, at migration time) and never moved, while the freshly
/// advanced counter went on being written to the legacy namespace that
/// read-through no longer reads.
///
/// `verify_credential`'s cloned-authenticator check reads the counter from
/// INSIDE that blob. Frozen counter => the check compares every future assertion
/// against a constant, i.e. clone detection is silently defeated for every
/// credential the moment the flag is on. That is a security regression the
/// mirror-write assertions in this file could not see, because they assert the
/// mirror WROTE, not that the value read back had moved.
///
/// Flag off, the legacy blob is the only blob and the legacy write keeps it
/// fresh, so the counter must come back untouched at the fixture's 0.
#[test]
fn the_sign_counter_read_back_is_the_advanced_one() {
    shared_rt().block_on(the_sign_counter_read_back_is_the_advanced_one_impl());
}

async fn the_sign_counter_read_back_is_the_advanced_one_impl() {
    let Some(r) = redis().await else {
        eprintln!("skip: no Redis on localhost");
        return;
    };
    let n = nonce();
    let id = URL_SAFE_NO_PAD.encode(format!("counter-{n}").as_bytes());
    let did = format!("did:pkh:eip155:1:0xCOUNTER{n}");

    r.set_raw(&cred_key(&id), FIXTURE).await.unwrap();

    fn counter_in(blob: &str) -> u64 {
        serde_json::from_str::<serde_json::Value>(blob)
            .expect("blob parses")
            .get("cred")
            .and_then(|c| c.get("counter"))
            .and_then(|c| c.as_u64())
            .expect("cred.counter present")
    }

    // The fixture starts at 0; that is the value a naive read-through freezes.
    assert_eq!(counter_in(FIXTURE), 0, "fixture precondition");

    credential_store::mirror_credential(&id, FIXTURE, &did, None).await;
    credential_store::mirror_sign_count(&id, 77).await;

    let blob = credential_store::read_blob(&r, &id)
        .await
        .unwrap()
        .expect("credential is readable");

    if credential_store::shared_store().await.is_some() {
        assert_eq!(
            counter_in(&blob),
            77,
            "flag ON: read_blob must reconcile the store's advanced sign_count \
             into cred.counter, or verify_credential's clone detection compares \
             against a frozen value forever"
        );
        // And the blob must still be a usable credential, not just a counter
        // carrier -- the same bytes feed the P-256 verification.
        assert_eq!(
            derive_did_from_passkey_blob(&blob).expect("reconciled blob still derives"),
            FIXTURE_DID,
            "reconciling the counter must not disturb the key material"
        );
        credential_store::mirror_delete(&did, &id).await;
    } else {
        assert_eq!(
            counter_in(&blob),
            0,
            "flag OFF: the legacy blob is returned verbatim"
        );
    }

    let _ = r.del_raw(&cred_key(&id)).await;
}

/// A partially backfilled user must still be offered EVERY passkey.
///
/// # Why this test exists
///
/// A non-empty `allowCredentials` RESTRICTS the authenticator to exactly the set
/// it names. `list_credential_ids` used to return the aqua-auth store's answer
/// whenever it was non-empty, never unioning it with the legacy index -- so a
/// user whose backfill covered one of two passkeys was offered only that one.
/// An empty list is "usernameless, not denied"; a PARTIAL list is a lockout for
/// the device it omits, with nothing in the flow explaining why.
///
/// Per-row backfill failures do not abort a run, and the flag can be flipped
/// mid-backfill, so the partial state is reachable in normal operation rather
/// than only under fault injection.
#[test]
fn a_partially_backfilled_user_is_offered_every_passkey() {
    shared_rt().block_on(a_partially_backfilled_user_is_offered_every_passkey_impl());
}

async fn a_partially_backfilled_user_is_offered_every_passkey_impl() {
    let Some(r) = redis().await else {
        eprintln!("skip: no Redis on localhost");
        return;
    };
    let n = nonce();
    let did = format!("did:key:zPARTIAL{n}");
    let mirrored = URL_SAFE_NO_PAD.encode(format!("partial-mirrored-{n}").as_bytes());
    let legacy_only = URL_SAFE_NO_PAD.encode(format!("partial-legacy-{n}").as_bytes());

    // Both passkeys belong to the user, and the legacy index knows both.
    r.set_raw(&cred_key(&mirrored), FIXTURE).await.unwrap();
    r.set_raw(&cred_key(&legacy_only), FIXTURE).await.unwrap();
    r.index_add_passkey(&did, &mirrored).await.unwrap();
    r.index_add_passkey(&did, &legacy_only).await.unwrap();

    // The backfill reached exactly one of them.
    credential_store::mirror_credential(&mirrored, FIXTURE, &did, None).await;

    let ids = credential_store::list_credential_ids(&r, &did, |_| None)
        .await
        .unwrap();

    assert!(
        ids.contains(&legacy_only),
        "the passkey the backfill missed vanished from allowCredentials -- that \
         does not degrade the picker, it locks that device out: {ids:?}"
    );
    assert!(
        ids.contains(&mirrored),
        "the mirrored passkey must still be offered: {ids:?}"
    );
    assert_eq!(
        ids.len(),
        2,
        "the two sources must dedupe, not duplicate: {ids:?}"
    );

    credential_store::mirror_delete(&did, &mirrored).await;
    let _ = r.del_raw(&cred_key(&mirrored)).await;
    let _ = r.del_raw(&cred_key(&legacy_only)).await;
    let _ = r.index_remove_passkey(&did, &mirrored).await;
    let _ = r.index_remove_passkey(&did, &legacy_only).await;
}
