//! Gate 3: the additive credential backfill, proved against a real Redis.
//!
//! Set `MIGRATION_TEST_REDIS_URL` to a **disposable, empty** Redis and this
//! suite runs for real. Leave it unset and it skips, matching the convention of
//! the other Redis-backed tests in this repo. If the variable IS set the suite
//! refuses to skip for any reason, so a broken environment can never masquerade
//! as a pass:
//!
//! ```text
//! docker run -d --name siwx-mig-redis -p 127.0.0.1:6398:6379 redis:7-alpine
//! MIGRATION_TEST_REDIS_URL=redis://127.0.0.1:6398 cargo test --test credential_migration_live
//! ```
//!
//! "Disposable and empty" is enforced, not assumed: the migration enumerates
//! `webauthn:credential/*` for the whole keyspace, so a pre-existing credential
//! would make the exact counts meaningless. The suite asserts both namespaces
//! are empty before it seeds anything.

use aqua_auth::webauthn_store::{CredentialId, WebauthnCredentialBackend};
use aqua_auth::RedisWebauthnStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use url::Url;

use siwx_oidc::credential_identity::resolve_credential_identity;
use siwx_oidc::credential_migration::{derive_did_from_passkey_blob, CredentialMigration};
use siwx_oidc::db::{RedisClient, KV_WEBAUTHN_CREDENTIAL_PREFIX, KV_WEBAUTHN_LINK_PREFIX};

/// A REAL serialized `Passkey`, the same fixture the webauthn-rs alignment test
/// uses. Its `cred.counter` is 0; the non-zero-counter case is derived from it.
const FIXTURE: &str = include_str!("fixtures/passkey_webauthn_rs_0_6_0_dev.json");

/// The `did:key` the fixture's P-256 public key derives to.
const FIXTURE_DID: &str = "did:key:zDnaebVfjz61NuRbnMfF2gA6NZM6DRWTeauDnFH1DhG2MFivF";

/// The wallet DID the linked fixture is bound to. Deliberately NOT
/// [`FIXTURE_DID`]: the whole point of the link table is that it overrides the
/// derived identity, so a test where the two coincide proves nothing.
const LINKED_DID: &str = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const LINK_LABEL: &str = "Tim's hardware wallet";

/// Both tests share one Redis namespace and the first asserts it starts empty,
/// so they must not overlap. Same test binary, so a process-wide lock is enough.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Resolve the test Redis, or `None` to skip.
///
/// Deliberately NOT falling back to `redis://localhost` the way the other
/// Redis-backed tests here do. This suite asserts the credential namespace
/// starts empty, so pointing it at a shared dev Redis would fail for
/// environmental reasons rather than for a real defect. It runs only when an
/// operator names a disposable instance, and once named, an unusable Redis is a
/// FAILURE, never a silent skip.
async fn test_redis() -> Option<(RedisClient, String)> {
    let url = std::env::var("MIGRATION_TEST_REDIS_URL").ok()?;
    let parsed = Url::parse(&url).expect("MIGRATION_TEST_REDIS_URL must be a URL");
    match RedisClient::new(&parsed).await {
        Ok(c) => Some((c, url)),
        Err(e) => panic!("MIGRATION_TEST_REDIS_URL={url} is set but unusable: {e:#}"),
    }
}

fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn cred_key(cred_id_b64: &str) -> String {
    format!("{KV_WEBAUTHN_CREDENTIAL_PREFIX}/{cred_id_b64}")
}

fn link_key(cred_id_b64: &str) -> String {
    format!("{KV_WEBAUTHN_LINK_PREFIX}/{cred_id_b64}")
}

/// The fixture blob with `cred.counter` set to `n`, serialized the way
/// `verify_credential`'s counter-update path serializes it.
fn blob_with_counter(n: u64) -> String {
    let mut v: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    v["cred"]["counter"] = serde_json::json!(n);
    serde_json::to_string(&v).expect("serialize")
}

struct Seed {
    /// unlinked, counter 0
    a: String,
    /// unlinked, counter 41 (the non-zero-counter case)
    b: String,
    /// LINKED, counter 3 (the wrong-principal case)
    c: String,
    /// unparseable value (the per-row-failure case)
    d: String,
}

impl Seed {
    fn all(&self) -> [&str; 4] {
        [&self.a, &self.b, &self.c, &self.d]
    }
}

async fn seed(redis: &RedisClient, nonce: u128) -> Seed {
    let s = Seed {
        a: b64(&format!("mig-{nonce}-a")),
        b: b64(&format!("mig-{nonce}-b")),
        c: b64(&format!("mig-{nonce}-c")),
        d: b64(&format!("mig-{nonce}-d")),
    };
    redis
        .set_raw(&cred_key(&s.a), &blob_with_counter(0))
        .await
        .unwrap();
    redis
        .set_raw(&cred_key(&s.b), &blob_with_counter(41))
        .await
        .unwrap();
    redis
        .set_raw(&cred_key(&s.c), &blob_with_counter(3))
        .await
        .unwrap();
    redis
        .set_raw(&cred_key(&s.d), "this is not a passkey")
        .await
        .unwrap();
    // Only C is linked. Written here as raw JSON with exactly the shape
    // `link_finish` writes, so the test exercises the real wire format without
    // this suite ever calling into the linking ceremony.
    redis
        .set_raw(
            &link_key(&s.c),
            &format!(r#"{{"primary_did":"{LINKED_DID}","label":"{LINK_LABEL}"}}"#),
        )
        .await
        .unwrap();
    s
}

async fn cleanup(redis: &RedisClient, store: &RedisWebauthnStore, s: &Seed) {
    for id in s.all() {
        let _ = redis.del_raw(&cred_key(id)).await;
        let _ = redis.del_raw(&link_key(id)).await;
        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(id) {
            let cid = CredentialId(bytes);
            if let Ok(Some(row)) = store.get_by_id(&cid).await {
                let _ = store.delete(&row.did, &cid).await;
            }
        }
    }
}

/// One migrated row from the target store, or `None`.
async fn get_row(
    store: &RedisWebauthnStore,
    id: &str,
) -> Option<aqua_auth::webauthn_store::StoredCredential> {
    let cid = CredentialId(URL_SAFE_NO_PAD.decode(id).unwrap());
    store.get_by_id(&cid).await.unwrap()
}

/// Snapshot every source key this test can see, value included, so "the
/// original keys are byte-identical afterwards" is checked and not asserted.
async fn snapshot_source(redis: &RedisClient) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pattern in [
        format!("{KV_WEBAUTHN_CREDENTIAL_PREFIX}/*"),
        format!("{KV_WEBAUTHN_LINK_PREFIX}/*"),
    ] {
        let mut keys = redis.keys_raw(&pattern).await.unwrap();
        keys.sort();
        for k in keys {
            let v = redis.get_raw(&k).await.unwrap().unwrap_or_default();
            out.push((k, v));
        }
    }
    out
}

#[tokio::test]
async fn backfill_is_additive_link_aware_counter_preserving_and_idempotent() {
    let Some((redis, url)) = test_redis().await else {
        eprintln!(
            "skip: MIGRATION_TEST_REDIS_URL unset (point it at a disposable Redis to run this)"
        );
        return;
    };
    let _serial = SERIAL.lock().await;
    eprintln!("GATE3: running against {url}");

    let store = RedisWebauthnStore::connect(&url)
        .await
        .expect("target store");

    // The migration scans the whole keyspace, so exact counts are only
    // meaningful on a dedicated instance. Enforce that rather than trust it.
    let pre_source = redis
        .keys_raw(&format!("{KV_WEBAUTHN_CREDENTIAL_PREFIX}/*"))
        .await
        .unwrap();
    assert!(
        pre_source.is_empty(),
        "MIGRATION_TEST_REDIS_URL must point at a DISPOSABLE, EMPTY Redis; \
         found {} pre-existing credential(s): {pre_source:?}",
        pre_source.len()
    );
    let pre_target = redis.keys_raw("aqua:webauthn:cred:*").await.unwrap();
    assert!(
        pre_target.is_empty(),
        "target namespace must be empty; found {pre_target:?}"
    );

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let s = seed(&redis, nonce).await;
    let before = snapshot_source(&redis).await;
    assert_eq!(before.len(), 5, "4 credentials + 1 link seeded");

    // ---- dry run: reads everything, writes nothing --------------------------
    let dry = CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, false)
        .run()
        .await
        .expect("dry run");
    assert_eq!(dry.read, 4, "four source credentials");
    assert_eq!(dry.would_write, 3, "three migratable");
    assert_eq!(dry.written, 0, "a dry run writes nothing");
    assert_eq!(dry.skipped, 0);
    assert_eq!(dry.failed, 1, "the unparseable row fails, alone");
    assert_eq!(dry.failures.len(), 1);
    assert!(
        dry.failures[0].0.ends_with(&s.d),
        "the failure must be the unparseable row, got {:?}",
        dry.failures[0]
    );

    let after_dry = redis.keys_raw("aqua:webauthn:cred:*").await.unwrap();
    assert!(
        after_dry.is_empty(),
        "dry run must not write; found {after_dry:?}"
    );

    // ---- apply --------------------------------------------------------------
    let applied = CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, true)
        .run()
        .await
        .expect("apply");
    assert_eq!(applied.read, 4);
    assert_eq!(applied.would_write, 0);
    assert_eq!(applied.written, 3);
    assert_eq!(applied.skipped, 0);
    assert_eq!(applied.failed, 1);

    // A: unlinked, counter 0. The blob is copied verbatim.
    let row_a = get_row(&store, &s.a).await.expect("A migrated");
    assert_eq!(row_a.did, FIXTURE_DID, "unlinked row keeps its derived DID");
    assert_eq!(row_a.label, None, "no link, no label");
    assert_eq!(row_a.sign_count, 0);
    assert_eq!(row_a.transports, Vec::<String>::new());
    assert_eq!(
        String::from_utf8(row_a.public_key.clone()).unwrap(),
        blob_with_counter(0),
        "public_key must be the source blob byte for byte"
    );
    assert!(
        row_a.created_at > 0,
        "created_at is the migration timestamp"
    );

    // B: THE COUNTER CASE. Defaulting to 0 here would silently reset clone
    // detection for every migrated credential.
    let row_b = get_row(&store, &s.b).await.expect("B migrated");
    assert_eq!(
        row_b.sign_count, 41,
        "sign_count must come from cred.counter inside the blob, not default to 0"
    );

    // C: THE LINKED CASE. The link OVERRIDES the derived DID.
    let row_c = get_row(&store, &s.c).await.expect("C migrated");
    assert_eq!(
        row_c.did, LINKED_DID,
        "a linked credential must be stored under its primary_did"
    );
    assert_ne!(
        row_c.did, FIXTURE_DID,
        "if this ever equals the derived DID the linked case is not being tested"
    );
    assert_eq!(row_c.label.as_deref(), Some(LINK_LABEL));
    assert_eq!(row_c.sign_count, 3);

    // D: failed, so nothing was written for it.
    assert!(
        get_row(&store, &s.d).await.is_none(),
        "the unparseable row must not have produced a credential"
    );

    // ---- the equivalence assertion -----------------------------------------
    // Every migrated `did` must equal the DID the login path would resolve for
    // the same credential, i.e. the LINK-AWARE resolution. Comparing against the
    // derived DID alone would pass trivially while being wrong for exactly the
    // linked row.
    for (id, row) in [(&s.a, &row_a), (&s.b, &row_b), (&s.c, &row_c)] {
        let blob = redis.get_raw(&cred_key(id)).await.unwrap().unwrap();
        let derived = derive_did_from_passkey_blob(&blob).expect("derives");
        let resolved = resolve_credential_identity(&redis, id, &derived)
            .await
            .expect("resolve");
        assert_eq!(
            row.did, resolved.did,
            "stored DID must equal the DID a login would resolve for {id}"
        );
        assert_eq!(row.label, resolved.label, "label must follow the same rule");
    }

    // The reverse index has to work too, or the passkey picker sees nothing.
    let listed = store.list_for_did(LINKED_DID).await.unwrap();
    assert_eq!(listed.len(), 1, "linked DID indexes exactly its credential");
    assert_eq!(listed[0].did, LINKED_DID);
    let listed_fixture = store.list_for_did(FIXTURE_DID).await.unwrap();
    assert_eq!(listed_fixture.len(), 2, "A and B share the derived DID");

    // ---- idempotence: a second run changes nothing --------------------------
    let again = CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, true)
        .run()
        .await
        .expect("second apply");
    assert_eq!(again.read, 4);
    assert_eq!(again.written, 0, "a second run writes nothing");
    assert_eq!(again.would_write, 0);
    assert_eq!(again.skipped, 3, "the three migrated rows are skipped");
    assert_eq!(
        again.failed, 1,
        "the unparseable row still fails, as before"
    );

    for (id, before_row) in [(&s.a, &row_a), (&s.b, &row_b), (&s.c, &row_c)] {
        let now = get_row(&store, id).await.expect("still there");
        assert_eq!(now.did, before_row.did);
        assert_eq!(now.label, before_row.label);
        assert_eq!(now.sign_count, before_row.sign_count);
        assert_eq!(now.public_key, before_row.public_key);
        assert_eq!(
            now.created_at, before_row.created_at,
            "created_at must not be restamped by a re-run"
        );
    }

    // ---- additive only: the source is byte-identical ------------------------
    let after = snapshot_source(&redis).await;
    assert_eq!(
        after, before,
        "the migration must not delete, rename or mutate any \
         webauthn:credential/* or webauthn:link/* key"
    );

    cleanup(&redis, &store, &s).await;
}

/// A row already in the target store is never rewritten, even when the source
/// blob's counter is LOWER than the counter aqua-auth has since advanced to.
/// This is the re-run-after-live-traffic case: rewriting would regress clone
/// detection, which is the exact failure the sidecar counter exists to prevent.
#[tokio::test]
async fn a_rerun_never_regresses_a_counter_the_store_has_advanced() {
    let Some((redis, url)) = test_redis().await else {
        eprintln!(
            "skip: MIGRATION_TEST_REDIS_URL unset (point it at a disposable Redis to run this)"
        );
        return;
    };
    let _serial = SERIAL.lock().await;
    eprintln!("GATE3: running against {url}");
    let store = RedisWebauthnStore::connect(&url)
        .await
        .expect("target store");

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = b64(&format!("mig-rerun-{nonce}"));
    let cid = CredentialId(URL_SAFE_NO_PAD.decode(&id).unwrap());
    redis
        .set_raw(&cred_key(&id), &blob_with_counter(5))
        .await
        .unwrap();

    let first = CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, true)
        .run()
        .await
        .unwrap();
    assert!(first.written >= 1, "seeded row migrated");
    assert_eq!(store.get_by_id(&cid).await.unwrap().unwrap().sign_count, 5);

    // A login happens: aqua-auth advances the sidecar counter. The source blob
    // is untouched and still says 5.
    store.update_sign_count(&cid, 99).await.unwrap();

    let second = CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, true)
        .run()
        .await
        .unwrap();
    assert!(second.skipped >= 1, "the existing row is skipped");
    assert_eq!(
        store.get_by_id(&cid).await.unwrap().unwrap().sign_count,
        99,
        "a re-run must not clobber the advanced counter back to the blob's value"
    );

    let _ = redis.del_raw(&cred_key(&id)).await;
    let row = store.get_by_id(&cid).await.unwrap().unwrap();
    let _ = store.delete(&row.did, &cid).await;
}
