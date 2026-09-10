//! Live verification of the provider-attested DID profile field
//! (`io.inblock.did`) against a running siwx-oidc + patched Synapse.
//!
//! # Why this file exists
//!
//! Four of the plan's hypotheses cannot be closed in-process, because the thing
//! being tested is *another server's* behaviour:
//!
//! | Hypothesis | What only a live run can show |
//! |---|---|
//! | **H1** | Synapse really accepts an admin-scoped write to another user's profile, stores the OBJECT value, and serves it back **unauthenticated** |
//! | **H8** | the shipped `siwx-oidc-auth` verifier accepts a proof minted by the *deployed* server, fetched through its *deployed* JWKS |
//! | **H9** | the backported #19980 guard + `msc4133_key_denylist` really answer 403 to a *user's* PUT and DELETE, while the provider's write still lands |
//! | **H3** | a clobbered value is restored by the next sign-in, with no operator action |
//! | **H11** | a real account's `displayname` is not its DID |
//!
//! The unit suite covers the wire shape (`synapse_client::tests::h1_*`), the
//! mint/verify interop (`did_assertion::interop_with_the_shipped_verifier`) and
//! the alias tier (`oidc::provision_synapse_device_tests::h11_*`). What it
//! cannot cover is Synapse itself — a mock that returns 200 proves the request
//! was well-formed *for the mock*.
//!
//! # Required environment
//!
//! ```text
//!   SIWEOIDC_HOST      base URL of siwx-oidc          (default http://localhost:8081)
//!   MATRIX_HOST        base URL of Synapse            (default http://localhost:8448)
//!   MAS_SHARED_SECRET  the MAS shared secret, used ONLY to mint the short-TTL
//!                      admin token this test needs in order to (a) simulate a
//!                      pre-denylist clobber for the H3 leg and (b) read state
//!                      back. Without it the H3 leg cannot run at all, so it is
//!                      a hard skip rather than a silently weakened check.
//! ```
//!
//! Run:
//! ```text
//!   SIWEOIDC_HOST=http://localhost:19081 MATRIX_HOST=http://localhost:19448 \
//!   MAS_SHARED_SECRET=... \
//!     cargo test --test e2e_did_field_live -- --ignored --nocapture
//! ```
//!
//! Every test here is `#[ignore]`d: it needs the harness (`e2e/up.sh`) and a
//! Synapse built from
//! `../siwx-oidc-matrix-server/patches/synapse/msc4133-profile-field-write-policy.patch`
//! with `experimental_features.msc4133_key_denylist: ["io.inblock.did"]` set.
//! `did_field_user_write_is_forbidden_live` additionally requires that patch to
//! be present — against a stock image it fails, correctly, because on stock the
//! field IS user-writable (that is the vulnerability;
//! `docs/audits/2026-09-10-msc4133-acl-probe.md` measures both columns).
//!
//! Uses a freshly-minted throwaway wallet identity per run, so it never touches
//! an account a human uses.

#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use siwx_oidc_auth::did_assertion::{fetch_and_verify_did, DID_PROFILE_FIELD};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers (copied from tests/e2e_account_lifecycle_live.rs — do NOT edit that
// file; the duplication is deliberate, so a change made for this feature can
// never break the lifecycle suite)
// ---------------------------------------------------------------------------

fn siweoidc_host() -> String {
    std::env::var("SIWEOIDC_HOST").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

fn matrix_host() -> String {
    std::env::var("MATRIX_HOST").unwrap_or_else(|_| "http://localhost:8448".to_string())
}

/// Emit the harness's skip marker and either skip or hard-fail.
///
/// Mirrors `e2e_account_lifecycle_live.rs`: a skip is never silent, and
/// `E2E_STRICT_SKIPS=1` turns it into a failure so a skipped leg can never
/// masquerade as a pass in a verification run.
fn skip_or_fail(what: &str, why: &str) {
    eprintln!("E2E_SKIP: {what} — {why}");
    if std::env::var("E2E_STRICT_SKIPS").is_ok() {
        panic!("E2E_STRICT_SKIPS=1: refusing to skip {what} — {why}");
    }
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

/// Result of a full wallet login.
struct Login {
    access_token: String,
    device_id: String,
}

/// Execute a full CAIP-122 wallet login and return the access token + the
/// provisioned device_id.
async fn login_with_key(signing_key: &SigningKey, address: &str, did: &str) -> Login {
    let base = siweoidc_host();
    let http = Client::new();

    let redirect_uri = format!("{}/callback", base);
    let reg_body = json!({
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

    let (code_verifier, code_challenge) = pkce_pair();
    let state = "did_field_live_state";
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
    let siwx_payload = json!({
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

    let device_id = token_json["scope"]
        .as_str()
        .and_then(device_id_from_scope)
        .unwrap_or_default();

    Login {
        access_token,
        device_id,
    }
}

fn device_id_from_scope(scope: &str) -> Option<String> {
    scope.split_whitespace().find_map(|tok| {
        tok.strip_prefix("urn:matrix:client:device:")
            .or_else(|| tok.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
            .map(|s| s.to_string())
    })
}

/// Resolve the mxid Synapse actually stored, rather than re-deriving the
/// localpart rule here.
///
/// Re-deriving would be a second implementation of `localpart_for` in a test —
/// exactly the hand-copy that once drifted from the real algorithm (see
/// `src/mxid.rs`'s module doc). Asking Synapse is the only answer that cannot
/// drift.
async fn whoami_mxid(token: &str) -> String {
    let http = Client::new();
    let resp = http
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            matrix_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("whoami failed");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "whoami must succeed for a freshly logged-in user"
    );
    resp.json::<Value>().await.unwrap()["user_id"]
        .as_str()
        .expect("whoami must carry user_id")
        .to_string()
}

/// Mint a short-TTL admin-scoped token via `POST /oauth2/admin_token`.
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
        "minting an admin token must succeed, got {status}: {body}"
    );
    serde_json::from_str::<Value>(&body).expect("admin_token body must be JSON")["access_token"]
        .as_str()
        .expect("admin_token response must carry access_token")
        .to_string()
}

// ---------------------------------------------------------------------------
// Profile-field reads/writes
// ---------------------------------------------------------------------------

fn profile_field_url(mxid: &str) -> String {
    format!(
        "{}/_matrix/client/v3/profile/{}/{}",
        matrix_host(),
        urlencoding::encode(mxid),
        DID_PROFILE_FIELD
    )
}

/// Read the DID field **with no Authorization header at all**.
///
/// Deliberately unauthenticated: `require_auth_for_profile_requests` defaults
/// to False (Synapse v1.159.0 `config/server.py:561`), so this is exactly what
/// an arbitrary relying party sees. Sending a token would hide a deployment
/// that had turned that default off, and would also be a different test than
/// "any consumer can read this".
async fn read_did_field_unauthenticated(mxid: &str) -> (StatusCode, Value) {
    let http = Client::new();
    let url = profile_field_url(mxid);
    let resp = http
        .get(&url)
        .send()
        .await
        .expect("profile field GET failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let value = serde_json::from_str::<Value>(&body).unwrap_or(Value::Null);
    (status, value)
}

/// Read the whole profile unauthenticated (used for the displayname leg).
async fn read_profile_unauthenticated(mxid: &str) -> Value {
    let http = Client::new();
    let url = format!(
        "{}/_matrix/client/v3/profile/{}",
        matrix_host(),
        urlencoding::encode(mxid)
    );
    let resp = http.get(&url).send().await.expect("profile GET failed");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a provisioned account must have a readable profile"
    );
    resp.json().await.expect("profile body must be JSON")
}

/// PUT the DID field with an arbitrary bearer token, returning status + body.
async fn put_did_field(token: &str, mxid: &str, value: Value) -> (StatusCode, String) {
    let http = Client::new();
    let resp = http
        .put(profile_field_url(mxid))
        .bearer_auth(token)
        .json(&json!({ DID_PROFILE_FIELD: value }))
        .send()
        .await
        .expect("profile field PUT failed");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

async fn delete_did_field(token: &str, mxid: &str) -> (StatusCode, String) {
    let http = Client::new();
    let resp = http
        .delete(profile_field_url(mxid))
        .bearer_auth(token)
        .send()
        .await
        .expect("profile field DELETE failed");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// A fresh throwaway wallet identity: (signing key, EIP-55 address, DID).
fn throwaway_identity() -> (SigningKey, String, String) {
    let secret_key = k256::SecretKey::random(&mut thread_rng());
    let signing_key = SigningKey::from(&secret_key);
    let address = eip55_checksum(&address_from_key(signing_key.verifying_key()));
    let did = format!("did:pkh:eip155:1:{}", address);
    (signing_key, address, did)
}

// ---------------------------------------------------------------------------
// H1 + H8 + H11: publish, read back unauthenticated, verify, and check the alias
// ---------------------------------------------------------------------------

/// **H1 / H8 / H11** — one sign-in publishes an attested DID that any consumer
/// can read and verify, and the alias tier stays clean.
///
/// Legs:
///  1. H1  — an unauthenticated GET returns `{did, proof}` with the DID exact-case
///  2. H8  — the SHIPPED verifier accepts the proof against the live issuer's JWKS
///  3. H11 — the account's `displayname` is not the DID
#[tokio::test]
#[ignore]
async fn did_field_is_published_verifiable_and_public_live() {
    let oidc = siweoidc_host();
    let matrix = matrix_host();
    eprintln!("[e2e:did-field] SIWEOIDC_HOST={oidc} MATRIX_HOST={matrix}");

    let (signing_key, address, did) = throwaway_identity();
    let login = login_with_key(&signing_key, &address, &did).await;
    let mxid = whoami_mxid(&login.access_token).await;
    eprintln!(
        "[e2e:did-field] did={did} mxid={mxid} device_id={}",
        login.device_id
    );

    // -- LEG 1 (H1): unauthenticated read of the published object ------------
    let (status, body) = read_did_field_unauthenticated(&mxid).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a signed-in account must have a published DID field (a 500 here means the \
         account has a `users` row but no `profiles` row — element-hq/synapse#19702 — \
         and a 404 means publication did not happen at all): {body}"
    );
    let value = &body[DID_PROFILE_FIELD];
    assert!(
        value.is_object(),
        "the field must be an OBJECT, not a bare string: {body}"
    );
    assert_eq!(
        value["did"].as_str(),
        Some(did.as_str()),
        "the published DID must be byte-identical to the one that signed in, mixed case \
         included (MEMORY.md 'MXID to DID is not invertible'): {body}"
    );

    // -- LEG 2 (H8 live): the SHIPPED verifier, end to end -------------------
    //
    // `fetch_and_verify_did` does the read itself and passes the mxid it read
    // FROM as the mxid it verifies AGAINST, so this leg also exercises the
    // binding check on real data rather than on a hand-assembled argument.
    let verified = fetch_and_verify_did(&matrix, &mxid, &oidc)
        .await
        .expect("the shipped verifier must accept the deployed server's proof");
    assert_eq!(
        verified.did, did,
        "the verified DID must be the signed-in DID"
    );
    assert_eq!(verified.mxid, mxid);

    // -- LEG 3 (H11 live): the alias tier carries no DID ---------------------
    let profile = read_profile_unauthenticated(&mxid).await;
    let displayname = profile["displayname"].as_str().unwrap_or_default();
    assert_ne!(
        displayname, did,
        "displayname is USER-WRITABLE (ACL probe leg 5); publishing the DID there would \
         let any user present someone else's DID: {profile}"
    );
    assert!(
        !displayname.to_ascii_lowercase().contains("did:"),
        "no DID in any spelling may sit in the user-writable alias tier: {profile}"
    );
    eprintln!("[e2e:did-field] displayname={displayname:?} (must not be the DID)");
}

// ---------------------------------------------------------------------------
// H9: the field is not user-writable and not user-deletable
// ---------------------------------------------------------------------------

/// **H9** — a user's own token gets 403 on both PUT and DELETE of the DID field.
///
/// # This test only passes against the PATCHED image
///
/// It requires the backport of element-hq/synapse#19980 plus
/// `experimental_features.msc4133_key_denylist: ["io.inblock.did"]`. Against a
/// stock Synapse both legs answer **200** and the user's value replaces the
/// provider's — which is the vulnerability, measured in the "denylist UNSET"
/// column of `docs/audits/2026-09-10-msc4133-acl-probe.md`. A failure here is
/// therefore a real finding ("this deployment is unprotected"), not a flaky
/// test.
///
/// Note the two legs assert DIFFERENT status codes on purpose: upstream's write
/// guard raises 403 while the delete twin historically raised 400
/// (`handlers/profile.py:786-787`). The probe measured 403 for both on the
/// patched image, so 403 is asserted for both — and if a future rebase
/// reintroduces the 400, this test says so instead of silently accepting
/// "some 4xx".
#[tokio::test]
#[ignore]
async fn did_field_user_write_is_forbidden_live() {
    let (signing_key, address, did) = throwaway_identity();
    let login = login_with_key(&signing_key, &address, &did).await;
    let mxid = whoami_mxid(&login.access_token).await;
    eprintln!("[e2e:did-field] H9 did={did} mxid={mxid}");

    // Sanity: the field is there to begin with, so a 403 below cannot be an
    // artifact of writing to something that does not exist.
    let (status, body) = read_did_field_unauthenticated(&mxid).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "precondition: field must exist: {body}"
    );

    let (put_status, put_body) = put_did_field(
        &login.access_token,
        &mxid,
        json!({"did": "did:key:zDnaeATTACKER", "proof": "forged"}),
    )
    .await;
    assert_eq!(
        put_status,
        StatusCode::FORBIDDEN,
        "a user must NOT be able to overwrite their own attested DID. A 200 here means the \
         msc4133_key_denylist is missing or the Synapse image is unpatched: {put_body}"
    );

    let (del_status, del_body) = delete_did_field(&login.access_token, &mxid).await;
    assert_eq!(
        del_status,
        StatusCode::FORBIDDEN,
        "a user must NOT be able to delete their attested DID (deleting it is as good as \
         replacing it — a consumer then sees no published DID at all): {del_body}"
    );

    // And the value is untouched by the two rejected attempts.
    let (status, body) = read_did_field_unauthenticated(&mxid).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body[DID_PROFILE_FIELD]["did"].as_str(),
        Some(did.as_str()),
        "a rejected write must leave the provider's value byte-identical: {body}"
    );
}

// ---------------------------------------------------------------------------
// H3: a clobbered value self-heals at the next sign-in
// ---------------------------------------------------------------------------

/// **H3** — a clobbered `io.inblock.did` is restored by the next sign-in, with
/// no operator action and no janitor process.
///
/// # Why the clobber is written with the ADMIN token
///
/// Because with the denylist in place a *user* cannot clobber it (that is H9,
/// above). The case this leg models is the one the guard cannot cover: a value
/// written **before** the denylist was applied. Upstream's guard is
/// prospective-only and does not validate or migrate existing values —
/// acknowledged in #19980's own review thread (`r3783167037`) — so re-asserting
/// on every sign-in is the only thing that repairs those accounts. Using the
/// admin token to plant the bad value reproduces exactly that state on a
/// protected server.
#[tokio::test]
#[ignore]
async fn clobbered_did_field_is_restored_at_next_signin_live() {
    let Ok(secret) = std::env::var("MAS_SHARED_SECRET") else {
        skip_or_fail(
            "clobbered_did_field_is_restored_at_next_signin_live",
            "MAS_SHARED_SECRET is unset, so a pre-denylist clobber cannot be planted; \
             a run without it would prove nothing about H3",
        );
        return;
    };

    let (signing_key, address, did) = throwaway_identity();
    let login = login_with_key(&signing_key, &address, &did).await;
    let mxid = whoami_mxid(&login.access_token).await;
    eprintln!("[e2e:did-field] H3 did={did} mxid={mxid}");

    // 1. Plant a bogus value, as a pre-denylist write would have left it.
    let admin_token = mint_admin_token(&secret).await;
    let bogus = json!({"did": "did:key:zDnaeCLOBBERED", "proof": "not-a-real-proof"});
    let (status, body) = put_did_field(&admin_token, &mxid, bogus.clone()).await;
    assert!(
        status.is_success(),
        "the admin token must be able to write the field (that is how the provider \
         publishes it at all): {status} {body}"
    );

    // 2. Confirm the clobber actually took. Without this the restore assertion
    //    below could pass on a value that was never overwritten.
    let (_, after_clobber) = read_did_field_unauthenticated(&mxid).await;
    assert_eq!(
        after_clobber[DID_PROFILE_FIELD]["did"].as_str(),
        Some("did:key:zDnaeCLOBBERED"),
        "control: the clobber must have landed, or this test proves nothing: {after_clobber}"
    );

    // 3. Sign in again with the SAME wallet key -> same DID -> same account.
    let _second = login_with_key(&signing_key, &address, &did).await;

    // 4. The provider's value is back, proof and all.
    let (status, restored) = read_did_field_unauthenticated(&mxid).await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert_eq!(
        restored[DID_PROFILE_FIELD]["did"].as_str(),
        Some(did.as_str()),
        "the next sign-in must re-assert the provider's DID over a clobbered value: {restored}"
    );

    let verified = fetch_and_verify_did(&matrix_host(), &mxid, &siweoidc_host())
        .await
        .expect("the restored value must carry a proof that verifies, not just the right string");
    assert_eq!(verified.did, did);
    assert_eq!(verified.mxid, mxid);
}
