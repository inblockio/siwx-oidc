//! H3 live verification: the account-lifecycle actions that Task 3 ported from
//! the Synapse **admin** API onto `/_synapse/mas/*`, each asserted by reading
//! **Synapse's own state back**, not by trusting a 2xx.
//!
//! # Why this file exists
//!
//! Synapse 1.157 deleted the `admin_token` shim, so
//! `POST /_synapse/admin/v1/deactivate/{mxid}` and
//! `PUT /_synapse/admin/v2/users/{mxid}` answer 401. They were ported to
//! `POST /_synapse/mas/delete_user` (carrying the `erase` flag) and
//! `POST /_synapse/mas/reactivate_user`.
//!
//! `delete_user` is the single endpoint behind BOTH `account_deactivate`
//! (`erase:false`, reversible) and `account_erase` (`erase:true`, GDPR,
//! irreversible). A port that collapsed those two into one behaviour would
//! still return 200 for both and would still pass every status-code assertion
//! in the suite — which is exactly why every leg here reads the resulting
//! `deactivated` / `erased` flags back out of Synapse.
//!
//! The existing coverage of these actions is read-only (discovery advertises
//! them; the confirmation page renders). Nothing executed them against a live
//! homeserver and checked the outcome. This does.
//!
//! # Required environment
//!
//! ```text
//!   SIWEOIDC_HOST      base URL of siwx-oidc      (default http://localhost:8081)
//!   MATRIX_HOST        base URL of Synapse        (default http://localhost:8448)
//!   MAS_SHARED_SECRET  the MAS shared secret, used ONLY to mint the short-TTL
//!                      admin token this test needs in order to READ Synapse's
//!                      user record back. Without it the test cannot observe
//!                      Synapse-side state, so it fails loudly rather than
//!                      degrading into a status-code-only check.
//! ```
//!
//! Run:
//! ```text
//!   SIWEOIDC_HOST=http://localhost:19081 MATRIX_HOST=http://localhost:19448 \
//!   MAS_SHARED_SECRET=... \
//!     cargo test --test e2e_account_lifecycle_live -- --ignored --nocapture
//! ```
//!
//! Destructive by construction, on a freshly-minted throwaway wallet identity
//! that exists only for the duration of the test and is erased by its last leg.

#![allow(dead_code)]

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
// Helpers (copied from tests/e2e_msc3861.rs — do NOT edit that file)
// ---------------------------------------------------------------------------

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

fn matrix_host() -> String {
    std::env::var("MATRIX_HOST").unwrap_or_else(|_| "http://localhost:8448".to_string())
}

/// Derive the 20-byte Ethereum address from a k256 verifying key.
fn address_from_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 mixed-case checksum encoding.
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

/// EIP-191 personal sign: prefix + keccak256 hash + secp256k1 recoverable signature.
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

/// Generate a PKCE code_verifier and its S256 code_challenge.
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

/// Build a reqwest client that does NOT follow redirects (so we can inspect 302s).
fn no_redirect_client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

/// Extract query parameters from a URL string (absolute or relative).
fn parse_query(url: &str) -> HashMap<String, String> {
    let full = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://dummy{}", url)
    };
    let parsed = reqwest::Url::parse(&full).unwrap();
    parsed.query_pairs().into_owned().collect()
}

/// Result of a full wallet login: an access token plus the provisioned device id.
struct Login {
    access_token: String,
    device_id: String,
}

/// Execute a full CAIP-122 wallet login against prod, provisioning a Synapse
/// device, and return the access token + the provisioned device_id.
///
/// The device_id is taken from the token-response scope
/// (`urn:matrix:...client:device:<id>`), falling back to `whoami` if needed.
async fn login_with_key(signing_key: &SigningKey, address: &str, did: &str) -> Login {
    let base = siweoidc_host();
    let http = Client::new();

    // Register a fresh OIDC client.
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
        .expect("register request failed");
    assert_eq!(
        reg_resp.status(),
        StatusCode::CREATED,
        "client registration should return 201"
    );
    let reg_json: Value = reg_resp.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

    // Authorize (PKCE).
    let (code_verifier, code_challenge) = pkce_pair();
    let state = "msc4191_live_state";
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
    assert_eq!(
        auth_resp.status(),
        StatusCode::SEE_OTHER,
        "authorize should return 303 redirect"
    );
    let set_cookie = auth_resp
        .headers()
        .get("set-cookie")
        .expect("authorize must set session cookie")
        .to_str()
        .unwrap()
        .to_string();
    let session_cookie = set_cookie.split(';').next().unwrap().to_string();
    let location = auth_resp
        .headers()
        .get("location")
        .expect("authorize must have Location header")
        .to_str()
        .unwrap()
        .to_string();
    let query = parse_query(&location);
    let nonce = query.get("nonce").expect("redirect must contain nonce");
    let domain = query.get("domain").expect("redirect must contain domain");

    // CAIP-122 sign-in message.
    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         You are signing-in to {domain}.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Resources:\n\
         - {redirect_uri}",
        domain = domain,
        address = address,
        base = base,
        nonce = nonce,
        issued_at = issued_at,
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
    assert_eq!(
        sign_in_resp.status(),
        StatusCode::SEE_OTHER,
        "sign_in should redirect with auth code"
    );
    let sign_in_location = sign_in_resp
        .headers()
        .get("location")
        .expect("sign_in must have Location header")
        .to_str()
        .unwrap()
        .to_string();
    let callback_query = parse_query(&sign_in_location);
    let code = callback_query
        .get("code")
        .expect("sign_in redirect must contain code")
        .clone();

    // Token exchange.
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
    assert_eq!(
        token_resp.status(),
        StatusCode::OK,
        "token exchange should succeed"
    );
    let token_json: Value = token_resp.json().await.unwrap();
    let access_token = token_json["access_token"]
        .as_str()
        .expect("response must have access_token")
        .to_string();
    assert!(
        access_token.starts_with("mat_"),
        "access token must have mat_ prefix in MSC3861 mode"
    );

    // Derive the provisioned device_id from the token-response scope.
    let device_id = token_json["scope"].as_str().and_then(device_id_from_scope);

    let device_id = match device_id {
        Some(d) => d,
        None => whoami_device_id(&access_token).await.unwrap_or_default(),
    };
    assert!(
        !device_id.is_empty(),
        "must resolve a provisioned device_id from scope or whoami (scope was {:?})",
        token_json.get("scope")
    );

    Login {
        access_token,
        device_id,
    }
}

/// Extract the device id from a token scope string. Handles both the stable
/// `urn:matrix:client:device:<id>` and the MSC2967
/// `urn:matrix:org.matrix.msc2967.client:device:<id>` forms.
fn device_id_from_scope(scope: &str) -> Option<String> {
    scope.split_whitespace().find_map(|tok| {
        tok.strip_prefix("urn:matrix:client:device:")
            .or_else(|| tok.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
            .map(|s| s.to_string())
    })
}

/// Best-effort whoami device_id lookup (used as a fallback for scope parsing).
async fn whoami_device_id(token: &str) -> Option<String> {
    let http = Client::new();
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .ok()?;
    if resp.status() != StatusCode::OK {
        return None;
    }
    let wj: Value = resp.json().await.ok()?;
    wj["device_id"].as_str().map(|s| s.to_string())
}

/// CAIP-122 message for an MSC4191 account action, matching the format the
/// account page's `authWallet` JS builds. The current server REQUIRES a
/// server-issued single-use nonce (bound to THIS action) from
/// `GET /account/nonce?action=<action>`, an Expiration Time, and the action's
/// Resources audience (`{base}/account?action=<action>`). This mirrors the
/// working reference `sign_account_message` in `tests/e2e_account_management.rs`.
async fn account_action_message(address: &str, action: &str) -> String {
    let base = siweoidc_host();
    let http = Client::new();
    let domain = reqwest::Url::parse(&base)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| base.clone());
    // Fetch the server-issued nonce bound to this action.
    let np: Value = http
        .get(format!("{base}/account/nonce?action={action}"))
        .send()
        .await
        .expect("account/nonce request failed")
        .json()
        .await
        .expect("account/nonce body must be JSON");
    let nonce = np["nonce"].as_str().expect("nonce response must carry nonce");
    let expiration_time = np["expiration_time"]
        .as_str()
        .expect("nonce response must carry expiration_time");
    let resources: Vec<String> = np["resources"]
        .as_array()
        .expect("nonce response must carry resources")
        .iter()
        .map(|r| format!("\n- {}", r.as_str().unwrap()))
        .collect();
    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\n\
         Confirm account action.\n\n\
         URI: {base}\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}\n\
         Resources:{res}",
        domain = domain,
        address = address,
        base = base,
        nonce = nonce,
        issued_at = issued_at,
        expiration_time = expiration_time,
        res = resources.concat(),
    )
}

/// POST an MSC4191 account action to `/account/wallet`, signing a fresh CAIP-122
/// message with `signing_key`. Returns the HTTP status and the raw body text
/// (so callers can assert friendly error bodies on 4xx).
async fn post_account_action(
    signing_key: &SigningKey,
    address: &str,
    did: &str,
    action: &str,
    device_id: Option<&str>,
) -> (StatusCode, String) {
    let base = siweoidc_host();
    let http = Client::new();
    let message = account_action_message(address, action).await;
    let signature = eip191_sign(signing_key, &message);
    let body = serde_json::json!({
        "action": action,
        "did": did,
        "message": message,
        "signature": signature,
        "device_id": device_id,
    });
    let resp = http
        .post(format!("{}/account/wallet", base))
        .json(&body)
        .send()
        .await
        .expect("account/wallet request failed");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

// ---------------------------------------------------------------------------
// H3 helpers: read Synapse's OWN account state back
// ---------------------------------------------------------------------------

/// Emit the harness's skip marker and either skip or hard-fail.
///
/// Mirrors `e2e_session_teardown.rs`: a skip is never silent, and
/// `E2E_STRICT_SKIPS=1` turns it into a failure so a skipped leg can never
/// masquerade as a pass in a verification run.
fn skip_or_fail(what: &str, why: &str) {
    eprintln!("E2E_SKIP: {what} — {why}");
    if std::env::var("E2E_STRICT_SKIPS").is_ok() {
        panic!("E2E_STRICT_SKIPS=1: refusing to skip {what} — {why}");
    }
}

/// Mint a short-TTL admin-scoped token via `POST /oauth2/admin_token`.
///
/// This is the ONLY way to read `/_synapse/admin/*` on 1.157+, and it is the
/// mechanism under test in H2, so a failure here is reported as such rather
/// than being confused with a lifecycle failure.
async fn mint_admin_token(secret: &str) -> String {
    let base = siweoidc_host();
    let http = Client::new();
    let resp = http
        .post(format!("{base}/oauth2/admin_token"))
        .bearer_auth(secret)
        .send()
        .await
        .expect("admin_token mint request failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "minting an admin token must succeed (this is H2, not H3), got {status}: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("admin_token body must be JSON");
    v["access_token"]
        .as_str()
        .expect("admin_token response must carry access_token")
        .to_string()
}

/// Synapse's own view of an account, read through the admin API.
#[derive(Debug)]
struct SynapseAccountState {
    deactivated: bool,
    /// `None` when this Synapse build does not report the field at all, which
    /// must NOT be silently read as "not erased".
    erased: Option<bool>,
    raw: Value,
}

/// `GET /_synapse/admin/v2/users/{mxid}` with a minted admin token.
///
/// This is the ground truth for every assertion in this file: it is Synapse
/// answering about its own database, not siwx-oidc reporting what it believes
/// it did.
async fn synapse_account_state(admin_token: &str, mxid: &str) -> SynapseAccountState {
    let matrix = matrix_host();
    let http = Client::new();
    let url = format!(
        "{matrix}/_synapse/admin/v2/users/{}",
        urlencoding::encode(mxid)
    );
    let resp = http
        .get(&url)
        .bearer_auth(admin_token)
        .send()
        .await
        .expect("admin users GET failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "reading Synapse's user record must succeed, got {status}: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("admin users body must be JSON");
    SynapseAccountState {
        deactivated: v["deactivated"].as_bool().unwrap_or(false),
        erased: v.get("erased").and_then(|e| e.as_bool()),
        raw: v,
    }
}

// ---------------------------------------------------------------------------
// H3: deactivate -> reactivate -> erase, each verified against Synapse state
// ---------------------------------------------------------------------------

/// The full account lifecycle, end-to-end through the real MSC4191 `/account`
/// actions (CAIP-122 re-auth included), with Synapse's own `deactivated` /
/// `erased` flags read back after every leg.
///
/// Legs:
///  1. baseline           — a fresh login leaves `deactivated: false`
///  2. `account_deactivate` (`delete_user erase:false`) — `deactivated: true`
///  3. `account_reactivate` (`reactivate_user`)         — `deactivated: false`
///  4. `account_erase`      (`delete_user erase:true`)  — `deactivated: true`
///                                                        and erased
///
/// Leg 3 is the one that proves the `erase` flag was not collapsed: a port that
/// always erased would make the account unrecoverable here, while still having
/// returned 200 in leg 2.
#[tokio::test]
#[ignore]
async fn account_lifecycle_round_trip_live() {
    let oidc = siweoidc_host();
    let matrix = matrix_host();
    eprintln!("[e2e:lifecycle] SIWEOIDC_HOST={oidc} MATRIX_HOST={matrix}");

    let Ok(secret) = std::env::var("MAS_SHARED_SECRET") else {
        skip_or_fail(
            "account_lifecycle_round_trip_live",
            "MAS_SHARED_SECRET is unset, so Synapse-side state cannot be read back; \
             a status-code-only run would prove nothing about H3",
        );
        return;
    };

    // 1. Fresh throwaway identity + full wallet login.
    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    let login = login_with_key(&signing_key, &address, &did).await;
    let localpart = did
        .replace(':', "-")
        .replace('.', "-")
        .to_lowercase();
    eprintln!("[e2e:lifecycle] did={did}");
    eprintln!("[e2e:lifecycle] device_id={}", login.device_id);

    let admin_token = mint_admin_token(&secret).await;

    // Resolve the mxid Synapse actually stored, rather than re-deriving the
    // localpart rule here (a re-derivation that drifted would silently make
    // every readback below query a non-existent user).
    let http = Client::new();
    let who = http
        .get(format!("{matrix}/_matrix/client/v3/account/whoami"))
        .bearer_auth(&login.access_token)
        .send()
        .await
        .expect("whoami failed");
    let who_status = who.status();
    assert_eq!(
        who_status,
        StatusCode::OK,
        "whoami must succeed for a freshly logged-in user; without it this test \
         cannot address the right account"
    );
    let mxid = who.json::<Value>().await.unwrap()["user_id"]
        .as_str()
        .expect("whoami must carry user_id")
        .to_string();
    eprintln!("[e2e:lifecycle] mxid={mxid} (derived localpart would be {localpart})");

    // -----------------------------------------------------------------------
    // LEG 1 — baseline: a live account is not deactivated.
    // -----------------------------------------------------------------------
    let st = synapse_account_state(&admin_token, &mxid).await;
    eprintln!("[e2e:lifecycle] baseline deactivated={}", st.deactivated);
    assert!(
        !st.deactivated,
        "a freshly provisioned account must not start deactivated: {}",
        st.raw
    );

    // -----------------------------------------------------------------------
    // LEG 2 — account_deactivate  ==  POST /_synapse/mas/delete_user erase:false
    // -----------------------------------------------------------------------
    let (ds, db) = post_account_action(
        &signing_key,
        &address,
        &did,
        "org.matrix.account_deactivate",
        None,
    )
    .await;
    eprintln!("[e2e:lifecycle] account_deactivate -> {ds} {db}");
    assert_eq!(
        ds,
        StatusCode::OK,
        "account_deactivate must return 200, got {ds}: {db}"
    );
    let dj: Value = serde_json::from_str(&db).expect("deactivate body must be JSON");
    assert_eq!(
        dj["kind"], "deactivated",
        "account_deactivate outcome kind must be 'deactivated': {db}"
    );

    // THE ASSERTION THAT MATTERS: Synapse's own record changed.
    let st = synapse_account_state(&admin_token, &mxid).await;
    eprintln!(
        "[e2e:lifecycle] after deactivate: deactivated={} erased={:?}",
        st.deactivated, st.erased
    );
    assert!(
        st.deactivated,
        "H3 VIOLATED: /_synapse/mas/delete_user returned 200 but Synapse still \
         reports deactivated=false — the call did not take effect: {}",
        st.raw
    );
    // erase:false must NOT have erased the account, or leg 3 is meaningless and
    // account_deactivate is silently as destructive as account_erase.
    if let Some(erased) = st.erased {
        assert!(
            !erased,
            "H3 VIOLATED: account_deactivate sent erase:false but Synapse reports \
             erased=true — the reversible/irreversible distinction was lost in the \
             port to /_synapse/mas/delete_user: {}",
            st.raw
        );
    }

    // -----------------------------------------------------------------------
    // LEG 3 — account_reactivate  ==  POST /_synapse/mas/reactivate_user
    //
    // Proves leg 2 really was reversible.
    // -----------------------------------------------------------------------
    let (rs, rb) = post_account_action(
        &signing_key,
        &address,
        &did,
        "org.matrix.account_reactivate",
        None,
    )
    .await;
    eprintln!("[e2e:lifecycle] account_reactivate -> {rs} {rb}");
    assert_eq!(
        rs,
        StatusCode::OK,
        "account_reactivate must return 200 for an erase:false deactivation, \
         got {rs}: {rb}"
    );

    let st = synapse_account_state(&admin_token, &mxid).await;
    eprintln!(
        "[e2e:lifecycle] after reactivate: deactivated={}",
        st.deactivated
    );
    assert!(
        !st.deactivated,
        "H3 VIOLATED: /_synapse/mas/reactivate_user returned 200 but Synapse still \
         reports deactivated=true — the account was not restored: {}",
        st.raw
    );

    // -----------------------------------------------------------------------
    // LEG 4 — account_erase  ==  POST /_synapse/mas/delete_user erase:true
    //
    // Same endpoint as leg 2, opposite flag. Also the throwaway cleanup.
    // -----------------------------------------------------------------------
    let (es, eb) = post_account_action(
        &signing_key,
        &address,
        &did,
        "org.matrix.account_erase",
        None,
    )
    .await;
    eprintln!("[e2e:lifecycle] account_erase -> {es} {eb}");
    assert_eq!(
        es,
        StatusCode::OK,
        "account_erase must return 200, got {es}: {eb}"
    );
    let ej: Value = serde_json::from_str(&eb).expect("erase body must be JSON");
    assert_eq!(
        ej["kind"], "erased",
        "account_erase outcome kind must be 'erased': {eb}"
    );

    let st = synapse_account_state(&admin_token, &mxid).await;
    eprintln!(
        "[e2e:lifecycle] after erase: deactivated={} erased={:?}",
        st.deactivated, st.erased
    );
    assert!(
        st.deactivated,
        "H3 VIOLATED: account_erase returned 200 but Synapse reports the account \
         as still active: {}",
        st.raw
    );
    match st.erased {
        Some(true) => eprintln!("[e2e:lifecycle] erased=true confirmed by Synapse"),
        Some(false) => panic!(
            "H3 VIOLATED: account_erase sent erase:true but Synapse reports \
             erased=false — the GDPR flag did not reach the handler: {}",
            st.raw
        ),
        None => skip_or_fail(
            "account_erase erased-flag readback",
            "this Synapse build's admin user record does not report an `erased` \
             field, so erasure could only be confirmed as far as deactivation",
        ),
    }

    eprintln!(
        "[e2e:lifecycle] H3 PASS: deactivate/reactivate/erase all changed Synapse state \
         via /_synapse/mas/*"
    );
}

// ---------------------------------------------------------------------------
// H3 (delete_device leg): the MAS delete_device really removes the device
// ---------------------------------------------------------------------------

/// `device_delete` through the real MSC4191 action, asserted against Synapse's
/// admin device list rather than against siwx-oidc's own reply.
///
/// `msc4191_device_management_live` covers this too, but it reads the device
/// list back through siwx-oidc's `devices_list`. This one queries Synapse
/// directly with a minted admin token, so a bug that made BOTH the delete and
/// the list agree on a wrong answer cannot hide.
#[tokio::test]
#[ignore]
async fn device_delete_removes_the_device_from_synapse_live() {
    let Ok(secret) = std::env::var("MAS_SHARED_SECRET") else {
        skip_or_fail(
            "device_delete_removes_the_device_from_synapse_live",
            "MAS_SHARED_SECRET is unset, so Synapse's device list cannot be read directly",
        );
        return;
    };

    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let addr_bytes = address_from_key(signing_key.verifying_key());
    let address = eip55_checksum(&addr_bytes);
    let did = format!("did:pkh:eip155:1:{}", address);
    let login = login_with_key(&signing_key, &address, &did).await;
    let device_id = login.device_id.clone();
    eprintln!("[e2e:devdel] did={did} device_id={device_id}");

    let admin_token = mint_admin_token(&secret).await;

    let matrix = matrix_host();
    let http = Client::new();
    let who = http
        .get(format!("{matrix}/_matrix/client/v3/account/whoami"))
        .bearer_auth(&login.access_token)
        .send()
        .await
        .expect("whoami failed");
    assert_eq!(who.status(), StatusCode::OK, "whoami must succeed");
    let mxid = who.json::<Value>().await.unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Ask SYNAPSE (not siwx-oidc) for the device list.
    let device_ids = |token: String, mxid: String| async move {
        let http = Client::new();
        let url = format!(
            "{}/_synapse/admin/v2/users/{}/devices",
            matrix_host(),
            urlencoding::encode(&mxid)
        );
        let resp = http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .expect("admin devices GET failed");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "admin devices GET must succeed with a minted token"
        );
        resp.json::<Value>().await.unwrap()["devices"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|d| d["device_id"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
    };

    let before = device_ids(admin_token.clone(), mxid.clone()).await;
    eprintln!("[e2e:devdel] Synapse devices before = {before:?}");
    assert!(
        before.contains(&device_id),
        "precondition: the provisioned device {device_id} must exist in Synapse: {before:?}"
    );

    let (s, b) = post_account_action(
        &signing_key,
        &address,
        &did,
        "org.matrix.device_delete",
        Some(&device_id),
    )
    .await;
    eprintln!("[e2e:devdel] device_delete -> {s} {b}");
    assert_eq!(s, StatusCode::OK, "device_delete must return 200: {b}");

    let after = device_ids(admin_token.clone(), mxid.clone()).await;
    eprintln!("[e2e:devdel] Synapse devices after = {after:?}");
    assert!(
        !after.contains(&device_id),
        "H3 VIOLATED: /_synapse/mas/delete_device returned 200 but Synapse still \
         lists {device_id}: {after:?}"
    );

    // Clean up the throwaway account.
    let _ = post_account_action(
        &signing_key,
        &address,
        &did,
        "org.matrix.account_erase",
        None,
    )
    .await;

    eprintln!("[e2e:devdel] H3 PASS: the device is gone from Synapse's own device list");
}
