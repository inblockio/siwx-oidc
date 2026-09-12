//! End-to-end tests for the MSC4191 account-management flows against a LIVE
//! local stack (siwx-oidc + Synapse mock + Redis). These drive the EXACT HTTP
//! requests the `/account` page JS makes — real EIP-191 wallet signatures, the
//! account-session cookie, `POST /account/action` — so they prove the browser
//! flow end to end at the protocol level (the Playwright suite proves the DOM).
//!
//! Bring the stack up first (`e2e/up.sh`) and run single-threaded:
//!   cargo test --test e2e_account_management -- --ignored --test-threads=1
//!
//! Env overrides: SIWEOIDC_HOST (default http://localhost:8080),
//!                SYNAPSE_MOCK   (default http://localhost:8090).

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use siwx_oidc::mxid::legacy_localpart;

fn oidc() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8080".to_string())
}
fn mock() -> String {
    std::env::var("SYNAPSE_MOCK").unwrap_or_else(|_| "http://localhost:8090".to_string())
}

// -- wallet identity ----------------------------------------------------------

struct Wallet {
    key: SigningKey,
    /// EIP-55 checksummed 0x address.
    address: String,
    did: String,
    /// The legacy-shaped (`siwx_oidc::mxid::legacy_localpart`) mxid. Every
    /// test in this file that uses `mxid` first `mock_seed_device`s (or
    /// `__seed_user`s) THIS exact value, which is what actually makes
    /// `resolve_identity` (`src/localpart.rs`) resolve to it: a legacy-shaped
    /// localpart seeded as existing is found on `resolve_identity`'s FIRST
    /// probe (grandfathering checks legacy before modern), so these tests
    /// model a pre-2026-09 (grandfathered) account by construction, not "the
    /// localpart every DID gets" — a brand-new DID's real first sign-in would
    /// get the modern base36 shape instead (see `tests/e2e_race_teardown.rs`'s
    /// `grandfathered_legacy_account_keeps_legacy_localpart_on_real_signin`
    /// and its use of `siwx_oidc::mxid::localpart_for`).
    mxid: String,
}

fn address_from_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
    }
    out
}

fn new_wallet() -> Wallet {
    let key = SigningKey::random(&mut OsRng);
    let addr = address_from_key(key.verifying_key());
    let address = eip55_checksum(&addr);
    let did = format!("did:pkh:eip155:1:{address}");
    let localpart = legacy_localpart(&did);
    let mxid = format!("@{localpart}:matrix.test");
    Wallet {
        key,
        address,
        did,
        mxid,
    }
}

/// EIP-191 sign an arbitrary message with the wallet key. Returns `0x`-hex sig.
fn eip191_sign(w: &Wallet, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let (sig, rec): (Signature, RecoveryId) = w.key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec) + 27;
    format!("0x{}", hex::encode(bytes))
}

/// Build the exact CAIP-122/EIP-191 message the account page JS signs for
/// `action`, fetching the server-issued single-use nonce first (C1), and sign it.
/// Returns `(message, 0x-hex-signature)`.
async fn sign_account_message(
    c: &Client,
    w: &Wallet,
    base: &str,
    action: &str,
) -> (String, String) {
    let domain = reqwest::Url::parse(base)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let np: Value = c
        .get(format!("{base}/account/nonce?action={action}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = np["nonce"].as_str().unwrap();
    let expiration_time = np["expiration_time"].as_str().unwrap();
    let resources: Vec<String> = np["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\nConfirm account action.\n\nURI: {base}\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-06-14T00:00:00.000Z\nExpiration Time: {expiration_time}\nResources:{res}",
        addr = w.address,
        res = resources.concat(),
    );
    let sig = eip191_sign(w, &message);
    (message, sig)
}

// -- mock helpers -------------------------------------------------------------

async fn mock_reset(c: &Client) {
    c.post(format!("{}/__reset", mock())).send().await.unwrap();
}
async fn mock_seed_device(c: &Client, mxid: &str, device_id: &str) {
    c.post(format!("{}/__seed_device", mock()))
        .json(&json!({ "user_id": mxid, "device_id": device_id, "display_name": "Element" }))
        .send()
        .await
        .unwrap();
}
async fn mock_state(c: &Client) -> Value {
    c.get(format!("{}/__state", mock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
/// Make the mock's ADMIN surface reject every token, leaving the MAS shared
/// secret working.
///
/// Since the Synapse 1.157 port these are two DIFFERENT credentials
/// (`src/synapse_client.rs` module docs): `/_synapse/mas/*` takes the shared
/// secret, `/_synapse/admin/*` and the authenticated C-S API take a minted
/// admin-scoped token (`src/admin_token.rs`). `mock_set_secret` therefore can no
/// longer isolate an admin-token failure — see
/// `admin_token_rejection_is_legible_not_a_500_or_notfound` for why that matters.
async fn mock_reject_admin_token(c: &Client, reject: bool) {
    c.post(format!("{}/__reject_admin_token", mock()))
        .json(&json!({ "reject": reject }))
        .send()
        .await
        .unwrap();
}
async fn mock_set_secret(c: &Client, secret: &str) {
    c.post(format!("{}/__set_secret", mock()))
        .json(&json!({ "secret": secret }))
        .send()
        .await
        .unwrap();
}

fn device_ids(state: &Value, mxid: &str) -> Vec<String> {
    state["devices"]
        .get(mxid)
        .and_then(|d| d.as_array())
        .map(|a| {
            a.iter()
                .map(|d| d["device_id"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the `acct_session` cookie value from a response's Set-Cookie headers.
fn session_cookie(resp: &reqwest::Response) -> Option<String> {
    for v in resp.headers().get_all("set-cookie") {
        let s = v.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("acct_session=") {
            let val = rest.split(';').next().unwrap_or("").to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Is the Set-Cookie a *clearing* cookie (Max-Age=0)?
fn session_cookie_cleared(resp: &reqwest::Response) -> bool {
    resp.headers().get_all("set-cookie").iter().any(|v| {
        v.to_str()
            .map(|s| s.starts_with("acct_session=;") && s.contains("Max-Age=0"))
            .unwrap_or(false)
    })
}

// -- the flows ----------------------------------------------------------------

/// AC1/AC3 + H1/H2/H3: ONE wallet signature (devices_list), then sign out a
/// device AND view the profile via the session — with NO further signature.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn wallet_single_reauth_covers_list_delete_profile() {
    let c = Client::builder().build().unwrap();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    mock_seed_device(&c, &w.mxid, "SIWX_dev_aaa").await;
    mock_seed_device(&c, &w.mxid, "SIWX_dev_bbb").await;

    // --- the ONE and only signature: list sessions ---
    let (message, signature) = sign_account_message(&c, &w, &base, "org.matrix.devices_list").await;
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": "org.matrix.devices_list",
            "did": w.did, "message": message, "signature": signature,
            "device_id": null
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "devices_list re-auth must succeed");
    let cookie = session_cookie(&resp).expect("first re-auth must set the account-session cookie");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "devices");
    assert_eq!(body["devices"].as_array().unwrap().len(), 2);
    let csrf = body["csrf"]
        .as_str()
        .expect("response must carry csrf")
        .to_string();

    // --- sign out device #1 via the SESSION (no signature) ---
    let resp = c
        .post(format!("{base}/account/action"))
        .header("Cookie", format!("acct_session={cookie}"))
        .json(&json!({ "action": "org.matrix.device_delete", "device_id": "SIWX_dev_aaa", "csrf": csrf }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "session-backed delete must succeed without a new signature"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "deleted");
    assert_eq!(body["device_id"], "SIWX_dev_aaa");

    // Server-side state: the device is gone, the other survives.
    let ids = device_ids(&mock_state(&c).await, &w.mxid);
    assert!(
        !ids.contains(&"SIWX_dev_aaa".to_string()),
        "deleted device must be gone in Synapse"
    );
    assert!(
        ids.contains(&"SIWX_dev_bbb".to_string()),
        "the other device must survive"
    );

    // --- view profile via the SAME session (still no signature) ---
    let resp = c
        .post(format!("{base}/account/action"))
        .header("Cookie", format!("acct_session={cookie}"))
        .json(&json!({ "action": "org.matrix.profile", "csrf": csrf }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "profile");
    assert_eq!(body["user_id"], w.mxid);
}

/// AC4 + H4: erase runs deactivate(erase=true) server-side after ONE signature,
/// and clears the account-session cookie (the identity is gone).
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn wallet_erase_runs_erasure_and_clears_session() {
    let c = Client::builder().build().unwrap();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    mock_seed_device(&c, &w.mxid, "SIWX_dev_erase").await;

    let (message, signature) =
        sign_account_message(&c, &w, &base, "org.matrix.account_erase").await;
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": "org.matrix.account_erase",
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "erase re-auth must succeed");
    assert!(
        session_cookie_cleared(&resp),
        "erase must clear the account-session cookie"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "erased");

    let state = mock_state(&c).await;
    let life = &state["lifecycle"][&w.mxid];
    assert_eq!(life["deactivated"], true, "account must be deactivated");
    assert_eq!(
        life["erased"], true,
        "erase MUST request GDPR erasure (erase=true)"
    );
}

/// H2 fail-closed: `/account/action` with no session is rejected.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn account_action_without_session_is_unauthorized() {
    let c = Client::builder().build().unwrap();
    let resp = c
        .post(format!("{}/account/action", oidc()))
        .json(&json!({ "action": "org.matrix.devices_list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// H2 security: a valid session cookie with the WRONG csrf is rejected.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn account_action_csrf_mismatch_is_unauthorized() {
    let c = Client::builder().build().unwrap();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    mock_seed_device(&c, &w.mxid, "SIWX_dev_csrf").await;
    let (message, signature) = sign_account_message(&c, &w, &base, "org.matrix.profile").await;
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": "org.matrix.profile",
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap();
    let cookie = session_cookie(&resp).expect("must set session");

    let resp = c
        .post(format!("{base}/account/action"))
        .header("Cookie", format!("acct_session={cookie}"))
        .json(&json!({ "action": "org.matrix.profile", "csrf": "deadbeefwrongtoken" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong CSRF token must be rejected");
}

/// AC6 + H6: when Synapse rejects the admin token, the action fails *legibly* —
/// a 400 whose message names the admin token, NEVER a misleading "not found" or
/// a 500.
///
/// # Why this drives `__reject_admin_token` and not `__set_secret`
///
/// It used to flip the mock's shared secret, back when ONE credential reached
/// every Synapse surface. The Synapse 1.157 port split that in two (see
/// `src/synapse_client.rs`'s module docs): the shared secret is honoured only on
/// `/_synapse/mas/*`, and `list_devices` now presents a separately minted
/// admin-scoped token. Flipping the shared secret today breaks the MAS surface
/// FIRST — `query_user` 401s, and the deactivated-account gate
/// (`webauthn::reject_if_deactivated`) correctly fails closed with a **401**
/// before any admin call is attempted. That is the product working as designed,
/// so the old set-up could no longer reach the code path this test is named
/// after; it was asserting 400 against a 401 raised three layers earlier.
///
/// `__reject_admin_token` rejects exactly the credential in the test's name and
/// leaves the shared secret alone, which is what restores the original
/// intent — a stricter test than before, not a looser one: the assertions
/// below are unchanged and now actually run against `list_devices`.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn admin_token_rejection_is_legible_not_a_500_or_notfound() {
    let c = Client::builder().build().unwrap();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    // The account must EXIST first, or `reject_if_new_identity` turns the
    // re-auth away for a DIFFERENT (also correct) reason — "not linked to an
    // existing account" — and `list_devices` is never reached, so nothing about
    // admin-token legibility would be exercised. The old wrong-secret set-up got
    // this for free by accident: a 401 from `is_localpart_available` is a 4xx,
    // which the client reads as "localpart taken". With only the admin
    // credential broken, the MAS probe answers honestly and a fresh wallet is
    // genuinely new, so the account has to be seeded on purpose.
    mock_seed_device(&c, &w.mxid, "SIWX_pre_existing").await;
    mock_reject_admin_token(&c, true).await; // siwx's admin calls now 401

    let (message, signature) = sign_account_message(&c, &w, &base, "org.matrix.devices_list").await;
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": "org.matrix.devices_list",
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    // Restore the admin surface for any later tests regardless of assertions.
    mock_reject_admin_token(&c, false).await;

    assert_eq!(
        status, 400,
        "admin-auth failure must be a clean 400, not a 500"
    );
    let lower = text.to_lowercase();
    assert!(
        !lower.contains("not found"),
        "must NOT masquerade as 'device not found': {text}"
    );
    assert!(
        lower.contains("admin token") || lower.contains("failed to list devices"),
        "message must name the admin-token problem legibly: {text}"
    );
}

/// The OTHER half of the two-credential split: when the **MAS shared secret**
/// is wrong, the account re-auth fails CLOSED — it does not fall through to the
/// admin path, and it does not silently succeed.
///
/// This test exists because the behaviour used to be covered by accident.
/// `admin_token_rejection_is_legible_not_a_500_or_notfound` flipped the shared
/// secret back when one credential reached every Synapse surface; after the
/// Synapse 1.157 port that set-up stopped reaching `list_devices` at all and
/// started measuring THIS path instead, while still asserting the admin path's
/// 400. Rather than delete the coverage along with the stale set-up, the two
/// halves are now two tests.
///
/// # Which guard fires changed on 2026-09-12, and the reason is the point
///
/// This asserted **401** until the `is_localpart_available` conflation was fixed
/// (`docs/audits/2026-09-12-localpart-availability-conflation.md`), and it got
/// that 401 the same way the sibling test got its set-up: **by accident.** A
/// wrong shared secret makes Synapse answer `403`, the old probe mapped every
/// 4xx to "the localpart is taken", so the identity looked like a normal
/// returning user, `reject_if_new_identity` passed, and the request travelled on
/// to `reject_if_deactivated`, whose own `query_user` probe was equally broken —
/// and THAT produced the 401.
///
/// A rejected credential is now an `Err`, not a verdict, so the FIRST guard that
/// needs Synapse is the one that fails, and it fails closed by its own
/// documented rule ("detection failed → reject rather than risk silent
/// creation").
///
/// What this test pins is the invariant, not the incidental code: a rejected MAS
/// credential must be rejected, must not mint a session, and must never be a
/// 2xx. Do not "restore" the 401 by reordering the guards — that would be
/// preserving an accident.
///
/// # The status is now 503, and that is the fix, not a regression
///
/// This asserted **400** with a body of `NEW_IDENTITY_REJECT_MSG` — which told
/// the user to create an account when the real cause was a server-side
/// credential misconfiguration. The doc here named that as a known wart and the
/// distinct "detection failed" error as the right follow-up; that follow-up has
/// been done. `webauthn::reject_if_new_identity` now separates the two facts it
/// used to conflate: `Ok(is_new)` still yields `400 NEW_IDENTITY_REJECT_MSG`,
/// while `Err(_)` — this test's case — yields
/// `503 IDENTITY_CHECK_UNAVAILABLE_MSG`, a message that blames the server,
/// invites a retry, points at an administrator, and leaks nothing about which
/// credential failed.
///
/// The old companion assertion `status.is_client_error()` is therefore GONE, and
/// deliberately not replaced with `is_server_error()`: it was never really about
/// the 4xx class, it was standing in for "did not succeed, minted nothing". That
/// invariant is restated below in those terms instead of being weakened — a
/// fail-closed path is one the caller does not get through, not one the caller
/// gets blamed for.
#[tokio::test]
#[ignore = "requires live e2e stack (e2e/up.sh)"]
async fn wrong_mas_shared_secret_fails_closed_not_open() {
    let c = Client::builder().build().unwrap();
    let base = oidc();
    mock_reset(&c).await;
    let w = new_wallet();
    mock_seed_device(&c, &w.mxid, "SIWX_pre_existing").await;
    mock_set_secret(&c, "WRONG-SECRET").await; // the whole MAS surface now 401s

    let (message, signature) = sign_account_message(&c, &w, &base, "org.matrix.devices_list").await;
    let resp = c
        .post(format!("{base}/account/wallet"))
        .json(&json!({
            "action": "org.matrix.devices_list",
            "did": w.did, "message": message, "signature": signature, "device_id": null
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    // Restore the secret for any later tests regardless of assertions.
    mock_set_secret(&c, "testsecret").await;

    assert_eq!(
        status, 503,
        "a rejected MAS credential must fail CLOSED via the first Synapse-dependent \
         guard, and diagnose itself honestly: the check could not be COMPLETED, which \
         is a server fault — see this test's doc for why this is 503 and neither the \
         historical 401 nor the 400 it replaced: {text}"
    );
    // The invariant the status code is only a proxy for, restated rather than
    // weakened (see the doc above): a fail-closed path is one the caller does
    // not get through. Asserted separately so a future change of WHICH guard
    // rejects cannot quietly turn this into a success or a redirect.
    assert!(
        status.is_client_error() || status.is_server_error(),
        "fail-closed means an error response, never a 2xx and never a redirect: {status} {text}"
    );
    // And it must not have handed out an account session on the way through.
    assert!(
        !text.contains("csrf"),
        "a fail-closed re-auth must not mint an account session: {text}"
    );
    // The diagnosis must be the honest one. Telling the user to go and create an
    // account when the SERVER's own credential is wrong is safe but misleading,
    // and it is advice they cannot act on — sign-in is broken by the same fault.
    assert!(
        !text.to_lowercase().contains("create an account"),
        "a server-side credential failure must not be reported as 'you have no \
         account': {text}"
    );
}
