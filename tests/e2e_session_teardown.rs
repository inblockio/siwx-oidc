//! End-to-end tests for session teardown on logout, revocation, and bulk
//! sign-out (Feature 1/2), observed from the Matrix side: after each teardown
//! the session's token must stop authenticating at `account/whoami`, and
//! `/_matrix/client/v3/logout/all` must be a registered route that leaves the
//! account active. A rejected token proves the session ended; it does not by
//! itself prove a Synapse device was deleted, so the logout test also reads the
//! device list: from the Synapse mock's state when `SYNAPSE_MOCK` is set (as in
//! CI), otherwise from the homeserver itself (`GET /_matrix/client/v3/devices`)
//! through a second session of the same identity, signed in after the logout.
//!
//! Each test signs in as a fresh throwaway identity, which creates an account
//! on the target homeserver, and deactivates that account at the end, also when
//! the test failed (`with_throwaway`): against a real deployment the account's
//! key exists only in this process, so an account left active is a leftover
//! nobody can clean up afterwards.
//!
//! Self-contained: copies the auth-flow helpers from `e2e_msc3861.rs` (the same
//! pattern `e2e_msc4191_live.rs` uses) so this file runs on its own and never
//! edits the existing test files.
//!
//! `#[ignore]`d, like the other e2e suites. CI runs it against the mock stack
//! (job `rust-e2e-mock`, with `MATRIX_HOST` pointed at `e2e/synapse_mock.py`).
//! Against a real deployment (set `E2E_STRICT_SKIPS=1` so a skipped assertion
//! fails):
//!
//!   SIWEOIDC_HOST=https://siwx.example.org MATRIX_HOST=https://matrix.example.org \
//!     cargo test --test e2e_session_teardown -- --ignored --nocapture
//!
//! The pure teardown logic (graceful degradation, idempotency, logout_all
//! revoking every token, route handlers returning 200) is covered by the
//! runnable Redis-backed unit tests in `src/compat.rs` (`compat::tests`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers (copied from tests/e2e_msc3861.rs; do NOT edit that file)
// ---------------------------------------------------------------------------

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

fn matrix_host() -> String {
    std::env::var("MATRIX_HOST").unwrap_or_else(|_| "http://localhost:8448".to_string())
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
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            result.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }
    }
    result
}

fn eip191_sign(key: &SigningKey, message: &str) -> String {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };
    let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec_id) + 27;
    format!("0x{}", hex::encode(bytes))
}

fn pkce_pair() -> (String, String) {
    use rand::Rng;
    let verifier: String = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn no_redirect_client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

fn parse_query(url: &str) -> HashMap<String, String> {
    let full = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://dummy{}", url)
    };
    let parsed = reqwest::Url::parse(&full).unwrap();
    parsed.query_pairs().into_owned().collect()
}

/// Perform a full OIDC auth flow with the given key and return
/// `(access_token, device_id, whoami_status)`.
///
/// `device_id` is `None` whenever whoami did not return 200. The CALLER must
/// decide what that means, which is why the raw status is returned alongside:
/// only a 503 (introspection unreachable) is a legitimate environmental skip,
/// while a 401/403/404/5xx is a real defect. Collapsing both into `None` is how
/// a broken teardown path used to report itself as a pass.
async fn login_with_key(
    signing_key: &SigningKey,
    address: &str,
    did: &str,
) -> (String, Option<String>, StatusCode) {
    let base = siweoidc_host();
    let http = Client::new();

    let redirect_uri = format!("{}/callback", base);
    let reg_body = serde_json::json!({
        "redirect_uris": [&redirect_uri],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });
    let reg_resp = http
        .post(format!("{}/register", base))
        .json(&reg_body)
        .send()
        .await
        .unwrap();
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

    let (code_verifier, code_challenge) = pkce_pair();
    let state = "teardown_state";
    let client = no_redirect_client();

    let authorize_url = format!(
        "{}/authorize?client_id={}&redirect_uri={}&scope=openid&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state,
        urlencoding::encode(&code_challenge),
    );
    let auth_resp = client.get(&authorize_url).send().await.unwrap();
    assert_eq!(auth_resp.status(), StatusCode::SEE_OTHER);

    let set_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session_cookie = set_cookie.split(';').next().unwrap().to_string();

    let location = auth_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let query = parse_query(&location);
    let nonce = query.get("nonce").unwrap();
    let domain = query.get("domain").unwrap();

    // The login path now enforces the CAIP-122 Expiration Time (C1 safe subset),
    // matching what the real Svelte frontend already sets — include a future exp.
    let now = Utc::now();
    let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expiration_time =
        (now + chrono::Duration::hours(48)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:\n\
         - {redirect_uri}",
        domain = domain,
        address = address,
        base = base,
        nonce = nonce,
        issued_at = issued_at,
        expiration_time = expiration_time,
        redirect_uri = redirect_uri,
    );

    let signature = eip191_sign(signing_key, &message);
    let siwx_payload = serde_json::json!({
        "did": did,
        "message": message,
        "signature": signature,
    });
    let siwx_cookie_value = serde_json::to_string(&siwx_payload).unwrap();

    let sign_in_url = format!(
        "{}/sign_in?redirect_uri={}&state={}&client_id={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode(&redirect_uri),
        state,
        urlencoding::encode(&client_id),
        urlencoding::encode(&code_challenge),
    );

    let sign_in_resp = client
        .get(&sign_in_url)
        .header(
            "cookie",
            format!(
                "{}; siwx={}",
                session_cookie,
                urlencoding::encode(&siwx_cookie_value)
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sign_in_resp.status(), StatusCode::SEE_OTHER);

    let sign_in_location = sign_in_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_query = parse_query(&sign_in_location);
    let code = callback_query.get("code").unwrap().clone();

    let token_resp = http
        .post(format!("{}/token", base))
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::OK);
    let token_json: Value = token_resp.json().await.unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    let matrix = matrix_host();
    let whoami_resp = http
        .get(format!("{}/_matrix/client/v3/account/whoami", matrix))
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap();
    let whoami_status = whoami_resp.status();
    let device_id = if whoami_status == StatusCode::OK {
        let wj: Value = whoami_resp.json().await.unwrap();
        wj["device_id"].as_str().map(|s| s.to_string())
    } else {
        None
    };

    (access_token, device_id, whoami_status)
}

/// Fresh throwaway Ethereum identity.
fn fresh_identity() -> (SigningKey, String, String) {
    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    (signing_key, address, did)
}

/// Whether `device_id` is currently visible against Matrix for this token.
async fn whoami_status(token: &str) -> StatusCode {
    Client::new()
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

/// Poll `whoami` until the token is rejected (401/403), returning the final
/// status. Synapse caches MSC3861 introspection results for ~2 minutes, so a
/// token whose OAuth session was already torn down server-side (visible in the
/// OIDC logs as "session torn down") still authenticates against Matrix for a
/// short window. The 401 only appears once that cache expires. Bounded at 150s
/// (just past the 2-minute window) with a 5s interval, exiting early on the
/// first 401/403 — mirrors the poll in `msc4191_device_management_live`.
async fn poll_whoami_rejected(token: &str) -> StatusCode {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150);
    let mut last = whoami_status(token).await;
    let mut attempt = 0u32;
    while std::time::Instant::now() < deadline {
        if last == StatusCode::UNAUTHORIZED || last == StatusCode::FORBIDDEN {
            return last;
        }
        attempt += 1;
        eprintln!(
            "[e2e] whoami still {} (introspection cache); retry {attempt} in 5s",
            last
        );
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        last = whoami_status(token).await;
    }
    last
}

/// The Matrix ID a token authenticates as, read from `whoami`.
async fn whoami_user_id(token: &str) -> Option<String> {
    let resp = Client::new()
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .ok()?;
    let body: Value = resp.json().await.ok()?;
    body["user_id"].as_str().map(str::to_string)
}

/// The device ids the Synapse mock holds for `mxid`, or `None` when this run
/// is not against the mock (`SYNAPSE_MOCK` unset, or no `/__state` there).
async fn mock_device_ids(mxid: &str) -> Option<Vec<String>> {
    let base = std::env::var("SYNAPSE_MOCK").ok()?;
    let state: Value = Client::new()
        .get(format!("{base}/__state"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    Some(
        state["devices"]
            .get(mxid)
            .and_then(Value::as_array)
            .map(|devices| {
                devices
                    .iter()
                    .filter_map(|d| d["device_id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The device ids the homeserver lists for the user `token` belongs to, read
/// through the client-server API as that user (`GET /_matrix/client/v3/devices`).
///
/// Panics on anything but a 200 with a `devices` array: this is the assertion's
/// only source on a real homeserver, and an unreadable list must never read as
/// "the device is gone".
async fn homeserver_device_ids(token: &str) -> Vec<String> {
    let resp = Client::new()
        .get(format!("{}/_matrix/client/v3/devices", matrix_host()))
        .bearer_auth(token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("MATRIX_HOST={} is unreachable: {e}", matrix_host()));
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /_matrix/client/v3/devices must answer 200 for a live session"
    );
    let body: Value = resp.json().await.expect("the device list must be JSON");
    body["devices"]
        .as_array()
        .expect("the device list must carry a `devices` array")
        .iter()
        .filter_map(|d| d["device_id"].as_str().map(str::to_string))
        .collect()
}

/// `POST /_matrix/client/v3/logout` at siwx-oidc with the session's token.
async fn logout(token: &str) -> StatusCode {
    Client::new()
        .post(format!("{}/_matrix/client/v3/logout", siweoidc_host()))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

// ---------------------------------------------------------------------------
// Cleanup: every throwaway account is deactivated, also after a failure
// ---------------------------------------------------------------------------

/// CAIP-122 message for an MSC4191 account action, as the account page builds
/// it: a server-issued single-use nonce bound to the action, its expiration
/// time and the action's audience in Resources (copied from
/// `account_action_message` in `e2e_msc4191_live.rs`).
async fn account_action_message(address: &str, action: &str) -> Result<String, String> {
    let base = siweoidc_host();
    let domain = reqwest::Url::parse(&base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| base.clone());
    let np: Value = Client::new()
        .get(format!("{base}/account/nonce?action={action}"))
        .send()
        .await
        .map_err(|e| format!("account/nonce: {e}"))?
        .json()
        .await
        .map_err(|e| format!("account/nonce body: {e}"))?;
    let field = |k: &str| {
        np[k]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("account/nonce carries no {k}"))
    };
    let nonce = field("nonce")?;
    let expiration_time = field("expiration_time")?;
    let resources: String = np["resources"]
        .as_array()
        .ok_or("account/nonce carries no resources")?
        .iter()
        .filter_map(Value::as_str)
        .map(|r| format!("\n- {r}"))
        .collect();
    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok(format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         Confirm account action.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:{resources}"
    ))
}

/// Deactivate the identity's account through the account page's signed
/// re-authentication (`org.matrix.account_deactivate`), the mechanism the
/// cleanup in `e2e_msc4191_live.rs` and in the headless client's
/// `live_deployment.rs` uses. `Ok` only when siwx-oidc answers that the
/// account is deactivated.
async fn deactivate_account(key: &SigningKey, address: &str, did: &str) -> Result<(), String> {
    const ACTION: &str = "org.matrix.account_deactivate";
    let message = account_action_message(address, ACTION).await?;
    let signature = eip191_sign(key, &message);
    let resp = Client::new()
        .post(format!("{}/account/wallet", siweoidc_host()))
        .json(&serde_json::json!({
            "action": ACTION,
            "did": did,
            "message": message,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| format!("account/wallet: {e}"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if status == StatusCode::OK && body["kind"] == "deactivated" {
        Ok(())
    } else {
        Err(format!("deactivation answered {status} {body}"))
    }
}

/// Run one test with a fresh throwaway identity, then deactivate the account
/// its sign-in created, also when the test panicked.
///
/// The body runs as its own task, so a failed assertion comes back here as a
/// `JoinError` instead of unwinding past the cleanup; it is re-raised after the
/// cleanup, so the test still fails with its own message. A cleanup that fails
/// after a passing body fails the test: an account left active breaks the
/// live suites' contract. After a failing body the cleanup's outcome is
/// printed (a body that failed before its first sign-in left no account).
async fn with_throwaway<F, Fut>(test: &str, body: F)
where
    F: FnOnce(SigningKey, String, String) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (key, address, did) = fresh_identity();
    let outcome = tokio::spawn(body(key.clone(), address.clone(), did.clone())).await;
    let cleanup = deactivate_account(&key, &address, &did).await;
    match outcome {
        Ok(()) => {
            if let Err(e) = cleanup {
                panic!("{test}: the throwaway account was not deactivated: {e}");
            }
            eprintln!("[e2e] {test}: the throwaway account is deactivated");
        }
        Err(join) => {
            match &cleanup {
                Ok(()) => eprintln!("[e2e] {test} failed; its throwaway account is deactivated"),
                Err(e) => {
                    eprintln!("[e2e] {test} failed; its throwaway account was not deactivated: {e}")
                }
            }
            match join.try_into_panic() {
                Ok(payload) => std::panic::resume_unwind(payload),
                Err(join) => panic!("{test}: the test task did not complete: {join}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// H1: logout tears down the ending session's Synapse device + tokens
// ---------------------------------------------------------------------------

/// Decide what a missing Synapse device id MEANS, instead of silently passing.
///
/// A test that early-`return`s is reported by cargo as `ok` -- a green pass that
/// asserted nothing, indistinguishable from a real one. Two rules make it honest:
///
///  * Only a 503 (Synapse cannot reach the siwx-oidc introspection endpoint) is a
///    legitimate environmental skip. That is the documented rationale, and it is
///    the condition the sibling suites (`e2e_device_code`, `e2e_msc3861`) actually
///    guard on. ANY other non-200 -- 401/403/404/5xx -- means the login or teardown
///    path is genuinely broken, and MUST fail rather than self-skip.
///  * Even a legitimate skip is never silent: it prints an `E2E_SKIP:` marker the
///    harness greps for, and under `E2E_STRICT_SKIPS=1` (the pipeline's strict
///    mode) it panics outright.
fn skip_or_fail(test: &str, whoami_status: StatusCode) {
    assert_eq!(
        whoami_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{test}: no Synapse device id after a fresh login, and whoami returned {whoami_status}. \
         Only 503 (introspection unreachable) is a legitimate skip; {whoami_status} means the \
         login/teardown path is broken. Refusing to report this as a pass."
    );

    let marker = format!(
        "E2E_SKIP: {test}: Matrix introspection unavailable (whoami 503); \
         Synapse-side assertions NOT exercised"
    );
    assert!(
        std::env::var("E2E_STRICT_SKIPS").as_deref() != Ok("1"),
        "{marker} -- E2E_STRICT_SKIPS=1: an unexercised assertion is a failure, not a pass"
    );
    eprintln!("{marker}");
}

/// After `POST /_matrix/client/v3/logout` with the session's bearer token, the
/// token must no longer authenticate against Matrix, and the ending session's
/// Synapse device must be gone from the user's device list. One-time deletion
/// of the *ending* session is the safe teardown; no device id is recycled.
///
/// The device list comes from the Synapse mock when `SYNAPSE_MOCK` is set.
/// Otherwise it comes from the homeserver: listed with the session's own token
/// before the logout (the device must be there), and after it through a second
/// session of the same identity, whose own device must be listed (so the list
/// can show a live device) while the ended one must not.
#[tokio::test]
#[ignore]
async fn logout_deletes_ending_session_device() {
    with_throwaway(
        "logout_deletes_ending_session_device",
        |key, address, did| async move {
            let (token, device_id, whoami_st) = login_with_key(&key, &address, &did).await;
            eprintln!("[e2e] logged in: device={:?}", device_id);

            let Some(device_id) = device_id else {
                skip_or_fail("logout_deletes_ending_session_device", whoami_st);
                return;
            };
            assert_eq!(
                whoami_status(&token).await,
                StatusCode::OK,
                "fresh token must work before logout"
            );
            let mxid = whoami_user_id(&token)
                .await
                .expect("whoami answered 200, so it names the user");
            let before = match mock_device_ids(&mxid).await {
                Some(ids) => ids,
                None => homeserver_device_ids(&token).await,
            };
            assert!(
                before.contains(&device_id),
                "sign-in must have created the session's device: {before:?}"
            );

            assert_eq!(
                logout(&token).await,
                StatusCode::OK,
                "logout must return 200"
            );

            assert_eq!(
                poll_whoami_rejected(&token).await,
                StatusCode::UNAUTHORIZED,
                "after logout the session token must be rejected"
            );

            match mock_device_ids(&mxid).await {
                Some(after) => assert!(
                    !after.contains(&device_id),
                    "logout must delete the ending session's Synapse device: {after:?}"
                ),
                None => {
                    // A real homeserver lists devices only to a live session of
                    // the user, and the ended one is gone: sign in again.
                    let (token2, device2, whoami_st2) = login_with_key(&key, &address, &did).await;
                    let device2 = device2.unwrap_or_else(|| {
                        panic!("the second sign-in must provision a device (whoami {whoami_st2})")
                    });
                    let after = homeserver_device_ids(&token2).await;
                    let logout2 = logout(&token2).await;
                    assert!(
                        after.contains(&device2),
                        "the homeserver must list the second session's live device {device2}: \
                         {after:?}"
                    );
                    assert!(
                        !after.contains(&device_id),
                        "logout must delete the ending session's Synapse device {device_id}: \
                         {after:?}"
                    );
                    assert_eq!(
                        logout2,
                        StatusCode::OK,
                        "the second session's logout must return 200"
                    );
                }
            }
            eprintln!("[e2e] logout tore down the ending session's device + tokens");
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// H1: revoke (RFC 7009) ends the session's tokens and keeps its device
// ---------------------------------------------------------------------------

/// After `POST /oauth2/revoke`, the revoked access token must no longer
/// authenticate against Matrix.
///
/// Revoke is token hygiene (`TeardownPolicy::TokensOnly`) and must NOT delete
/// the Synapse device; deleting it there wedged cross-signing in the 2026-06-12
/// login incident. This test does not observe the device. The keep-the-device
/// half is pinned at the handler's call site by
/// `e2e_race_teardown::h1_revoke_does_not_delete_device_but_logout_does` (it
/// counts the mock's `delete_device` calls, and fails if `compat::revoke`
/// passes `DeleteDevice`), and the policy itself by the unit test
/// `compat::tests::teardown_policy_only_deletes_device_on_explicit_signout`.
#[tokio::test]
#[ignore]
async fn revoke_invalidates_session_token() {
    with_throwaway(
        "revoke_invalidates_session_token",
        |key, address, did| async move {
            let (token, device_id, whoami_st) = login_with_key(&key, &address, &did).await;
            if device_id.is_none() {
                skip_or_fail("revoke_invalidates_session_token", whoami_st);
                return;
            }

            let revoke_resp = Client::new()
                .post(format!("{}/oauth2/revoke", siweoidc_host()))
                .form(&[("token", token.as_str())])
                .send()
                .await
                .unwrap();
            assert_eq!(
                revoke_resp.status(),
                StatusCode::OK,
                "revoke must return 200"
            );

            assert_eq!(
                poll_whoami_rejected(&token).await,
                StatusCode::UNAUTHORIZED,
                "after revoke the session token must be rejected"
            );
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// H3 + route wiring: logout/all tears down EVERY session, account stays active
// ---------------------------------------------------------------------------

/// The new `/_matrix/client/v3/logout/all` route must be registered (no 404),
/// must invalidate ALL of the user's sessions (each device's token rejected),
/// and must NOT deactivate the account (the user can sign in again afterwards).
#[tokio::test]
#[ignore]
async fn logout_all_invalidates_all_sessions_without_deactivating() {
    with_throwaway(
        "logout_all_invalidates_all_sessions_without_deactivating",
        |key, address, did| async move {
            let oidc = siweoidc_host();
            let http = Client::new();

            // Same identity, two independent sessions (two devices).
            let (token1, device1, whoami_st1) = login_with_key(&key, &address, &did).await;
            let (token2, device2, whoami_st2) = login_with_key(&key, &address, &did).await;
            eprintln!("[e2e] two sessions: d1={:?} d2={:?}", device1, device2);

            // Route-wiring assertion works even without a healthy introspection path:
            // a registered route returns 200, an unregistered one returns 404.
            let bulk = http
                .post(format!("{}/_matrix/client/v3/logout/all", oidc))
                .bearer_auth(&token1)
                .send()
                .await
                .unwrap();
            assert_ne!(
                bulk.status(),
                StatusCode::NOT_FOUND,
                "/_matrix/client/v3/logout/all must be a registered route"
            );
            assert_eq!(bulk.status(), StatusCode::OK, "logout/all must return 200");

            if device1.is_none() || device2.is_none() {
                let st = if device1.is_none() {
                    whoami_st1
                } else {
                    whoami_st2
                };
                skip_or_fail(
                    "logout_all_invalidates_all_sessions_without_deactivating",
                    st,
                );
                return;
            }

            // Both sessions must now be rejected (poll past the introspection cache).
            assert_eq!(
                poll_whoami_rejected(&token1).await,
                StatusCode::UNAUTHORIZED,
                "session 1 must be invalidated by logout/all"
            );
            assert_eq!(
                poll_whoami_rejected(&token2).await,
                StatusCode::UNAUTHORIZED,
                "session 2 (other device) must be invalidated by logout/all"
            );

            // The account must remain ACTIVE: a fresh sign-in with the same identity
            // must still succeed (logout/all must never deactivate).
            let (token3, _device3, _whoami_st3) = login_with_key(&key, &address, &did).await;
            assert!(
                token3.starts_with("mat_"),
                "the account must stay active: re-login after logout/all must succeed"
            );
            eprintln!("[e2e] logout/all invalidated all sessions and the account stayed active");

            // Cleanup: tear down the re-login session too.
            let _ = http
                .post(format!("{}/_matrix/client/v3/logout/all", oidc))
                .bearer_auth(&token3)
                .send()
                .await;
        },
    )
    .await;
}
