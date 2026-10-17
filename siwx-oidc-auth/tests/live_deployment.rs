//! The headless client against a live deployment: a siwx-oidc server in Matrix
//! mode and the homeserver that delegates its authentication to it.
//!
//! One `#[ignore]`d test drives the `siwx-oidc-auth` library end to end with a
//! freshly generated Ed25519 key, so every run signs in as a NEW identity and
//! creates a throwaway account on the target deployment. The test deactivates
//! that account at the end (`org.matrix.account_deactivate` through the account
//! page's signed re-authentication), also when a check failed; it does not
//! deactivate an account whose sign-in never completed, because there is none.
//!
//! The targets come only from the environment, never from this file:
//!
//! ```text
//! SIWX_SERVER=https://siwx.example.org \
//! SIWX_HOMESERVER=https://matrix.example.org \
//!   cargo test -p siwx-oidc-auth --test live_deployment -- --ignored --nocapture
//! ```
//!
//! A missing variable fails the test unless `E2E_STRICT_SKIPS=0` (the live
//! suites' rule: a skipped leg must never read as a pass). Every check runs and
//! prints `ok` or `FAILED`, so a run against an older server names each
//! property it lacks instead of stopping at the first. Tokens are never
//! printed; a token that has the wrong shape is described by its shape.

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::Signer;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use siwx_oidc_auth::{
    authenticate_with_device, code_flow_scope, fetch_and_verify_did, refresh, AuthTokens, SiwxKey,
};

/// Never followed: the client reads the code from the `Location` of
/// `/sign_in` without following it.
const REDIRECT_URI: &str = "https://agent.example.org/callback";
const CLIENT_NAME: &str = "siwx-oidc-auth live test";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Target {
    server: String,
    homeserver: String,
}

/// `E2E_STRICT_SKIPS=0` is the only opt-out; unset or any other value is strict.
fn skip_or_fail(why: &str) {
    eprintln!("E2E_SKIP: live_deployment — {why}");
    if std::env::var("E2E_STRICT_SKIPS").ok().as_deref() != Some("0") {
        panic!(
            "cannot run the live check: {why}. This is a FAILURE, not a skip, because a \
             skipped live check reads as a pass. Set it, or set E2E_STRICT_SKIPS=0 to accept \
             an unverified run."
        );
    }
}

fn target_from_env() -> Option<Target> {
    let var = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())
    };
    match (var("SIWX_SERVER"), var("SIWX_HOMESERVER")) {
        (Some(server), Some(homeserver)) => Some(Target { server, homeserver }),
        _ => {
            skip_or_fail("SIWX_SERVER and SIWX_HOMESERVER must both be set");
            None
        }
    }
}

/// The outcome of every check, printed as it is made.
#[derive(Default)]
struct Checks {
    failed: Vec<String>,
}

impl Checks {
    fn check(&mut self, ok: bool, what: &str, detail: impl std::fmt::Display) {
        if ok {
            eprintln!("ok      {what}");
        } else {
            eprintln!("FAILED  {what}: {detail}");
            self.failed.push(format!("{what}: {detail}"));
        }
    }
}

/// A token's shape with every base62 character replaced, so a report can say
/// what came back without printing a credential.
fn shape(token: &str) -> String {
    token
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { 'x' } else { c })
        .collect()
}

fn base62(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `mat_` + 32 base62.
fn is_access_token(token: &str) -> bool {
    token
        .strip_prefix("mat_")
        .is_some_and(|rest| base62(rest, 32))
}

/// `mcr_` + handle (22 base62) + `_` + secret (32 base62): the handle names the
/// grant, so every token of a chain leads to it.
fn is_refresh_token(token: &str) -> bool {
    token
        .strip_prefix("mcr_")
        .and_then(|rest| rest.split_once('_'))
        .is_some_and(|(handle, secret)| base62(handle, 22) && base62(secret, 32))
}

fn id_token_sub(id_token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode(id_token.split('.').nth(1)?).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sub")?.as_str().map(str::to_string)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("HTTP client")
}

/// Register a public client (no secret at `/token`), as an agent with no
/// pre-provisioned client would.
async fn register_public_client(target: &Target) -> anyhow::Result<String> {
    let resp = http()
        .post(format!("{}/register", target.server))
        .json(&serde_json::json!({
            "redirect_uris": [REDIRECT_URI],
            "client_name": CLIENT_NAME,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    anyhow::ensure!(status.is_success(), "/register answered {status}");
    body.get("client_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("/register answered no client_id"))
}

#[derive(Deserialize)]
struct WhoAmI {
    user_id: String,
    device_id: Option<String>,
}

/// `GET /account/whoami` with `access_token`: the homeserver introspects the
/// token at the provider, which counts as the token's first use.
async fn whoami(target: &Target, access_token: &str) -> anyhow::Result<WhoAmI> {
    let resp = http()
        .get(format!(
            "{}/_matrix/client/v3/account/whoami",
            target.homeserver
        ))
        .bearer_auth(access_token)
        .send()
        .await?;
    let status = resp.status();
    anyhow::ensure!(status.is_success(), "whoami answered {status}");
    Ok(resp.json().await?)
}

fn same_pair(a: &AuthTokens, b: &AuthTokens) -> bool {
    a.access_token == b.access_token && a.refresh_token == b.refresh_token
}

/// The refusal a superseded or revoked refresh token gets at `/token`.
fn is_refused(outcome: &anyhow::Result<AuthTokens>) -> bool {
    matches!(outcome, Err(e) if format!("{e:#}").contains("invalid_grant"))
}

fn describe(outcome: &anyhow::Result<AuthTokens>) -> String {
    match outcome {
        Ok(_) => "a token pair".to_string(),
        Err(e) => format!("{e:#}"),
    }
}

/// What the cleanup needs from a run that got as far as a sign-in.
struct SignedIn {
    client_id: String,
    refresh_token: String,
}

/// Every check that needs the account. Returns `Err` only when a step that
/// later steps depend on failed (no client, no sign-in, no refresh).
async fn exercise(
    target: &Target,
    key: &SiwxKey,
    checks: &mut Checks,
    signed_in: &mut Option<SignedIn>,
) -> anyhow::Result<()> {
    let did = key.did();
    let device_id = format!(
        "SIWXLIVE{}",
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(|b| char::from(b).to_ascii_uppercase())
            .collect::<String>()
    );

    let client_id = register_public_client(target).await?;
    eprintln!("ok      dynamic registration of a public client");

    let scope = code_flow_scope(Some(&device_id));
    let asked: Vec<&str> = scope.split(' ').collect();
    for needed in [
        "offline_access",
        "urn:matrix:client:api:*",
        &format!("urn:matrix:client:device:{device_id}"),
    ] {
        checks.check(
            asked.contains(&needed),
            &format!("the code flow asks for {needed}"),
            &scope,
        );
    }

    let first = authenticate_with_device(
        &target.server,
        &client_id,
        REDIRECT_URI,
        key,
        Some(&device_id),
    )
    .await?;
    let rt0 = first
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the code exchange issued no refresh token"))?;
    *signed_in = Some(SignedIn {
        client_id: client_id.clone(),
        refresh_token: rt0.clone(),
    });
    eprintln!("ok      the code flow issues an access and a refresh token");
    checks.check(
        first.id_token.as_deref().and_then(id_token_sub).as_deref() == Some(did.as_str()),
        "the ID token's sub is the key's DID",
        "sub differs or no ID token",
    );
    checks.check(
        is_access_token(&first.access_token),
        "the access token is mat_ + 32 base62",
        shape(&first.access_token),
    );
    checks.check(
        is_refresh_token(&rt0),
        "the refresh token is mcr_ + handle + _ + secret",
        shape(&rt0),
    );

    let mxid = match whoami(target, &first.access_token).await {
        Ok(me) => {
            checks.check(
                me.device_id.as_deref() == Some(device_id.as_str()),
                "whoami names the proposed device",
                format!("{:?}", me.device_id),
            );
            eprintln!("        throwaway account {}", me.user_id);
            Some(me.user_id)
        }
        Err(e) => {
            checks.check(false, "the access token works at the homeserver", e);
            None
        }
    };

    let second = refresh(&target.server, &client_id, &rt0, &did).await?;
    let rt1 = second
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the refresh issued no refresh token"))?;
    *signed_in = Some(SignedIn {
        client_id: client_id.clone(),
        refresh_token: rt1.clone(),
    });
    checks.check(
        rt1 != rt0 && second.access_token != first.access_token,
        "refresh rotates both tokens",
        "a token came back unchanged",
    );
    checks.check(
        is_refresh_token(&rt1),
        "the rotated refresh token is mcr_ + handle + _ + secret",
        shape(&rt1),
    );
    checks.check(
        rt0.split('_').nth(1) == rt1.split('_').nth(1),
        "the rotated refresh token keeps the grant's handle",
        format!("{} -> {}", shape(&rt0), shape(&rt1)),
    );

    // I4: the previous refresh token, presented again while its successor is
    // unused, is a lost response: it gets the same pair, not a second chain.
    let replay = refresh(&target.server, &client_id, &rt0, &did).await;
    checks.check(
        matches!(&replay, Ok(pair) if same_pair(pair, &second)),
        "a replay while the successor is unused returns the same pair",
        match &replay {
            Ok(_) => "a different pair".to_string(),
            Err(e) => format!("{e:#}"),
        },
    );

    // The homeserver introspects the new access token: its first use, after
    // which the previous refresh token is reuse.
    match whoami(target, &second.access_token).await {
        Ok(me) => checks.check(
            Some(&me.user_id) == mxid.as_ref()
                && me.device_id.as_deref() == Some(device_id.as_str()),
            "the rotated access token works at the homeserver for the same account and device",
            format!("{} {:?}", me.user_id, me.device_id),
        ),
        Err(e) => checks.check(false, "the rotated access token works at the homeserver", e),
    }
    let reuse = refresh(&target.server, &client_id, &rt0, &did).await;
    checks.check(
        is_refused(&reuse),
        "a replay after the successor was used is refused as reuse",
        describe(&reuse),
    );

    match &mxid {
        Some(mxid) => match fetch_and_verify_did(&target.homeserver, mxid, &target.server).await {
            Ok(verified) => checks.check(
                verified.did() == did && verified.mxid() == mxid,
                "the published DID binding verifies for the account",
                format!("{} for {}", verified.did(), verified.mxid()),
            ),
            Err(e) => checks.check(false, "the published DID binding verifies", e),
        },
        None => checks.check(false, "the published DID binding verifies", "no MXID"),
    }
    Ok(())
}

#[derive(Deserialize)]
struct AccountNonce {
    nonce: String,
    expiration_time: String,
    resources: Vec<String>,
}

/// Deactivate the account through the account page's signed re-authentication:
/// a server-issued nonce bound to the action, signed by the account's key.
async fn deactivate(target: &Target, key: &SiwxKey) -> anyhow::Result<()> {
    const ACTION: &str = "org.matrix.account_deactivate";
    let SiwxKey::Ed25519(signing_key) = key else {
        anyhow::bail!("the test signs with an Ed25519 key");
    };
    let http = http();
    let nonce: AccountNonce = http
        .get(format!("{}/account/nonce", target.server))
        .query(&[("action", ACTION)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let did = key.did();
    let resources: String = nonce.resources.iter().map(|r| format!("\n- {r}")).collect();
    let message = format!(
        "{domain} wants you to sign in with your Ed25519 key:\n{address}\n\n\
         Deactivate this throwaway account.\n\n\
         URI: {uri}\nVersion: 1\nNonce: {nonce}\nIssued At: {now}\n\
         Expiration Time: {exp}\nResources:{resources}",
        domain = url::Url::parse(&target.server)?
            .host_str()
            .unwrap_or_default(),
        address = did.strip_prefix("did:key:").unwrap_or(&did),
        uri = nonce.resources.first().map(String::as_str).unwrap_or(""),
        nonce = nonce.nonce,
        now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        exp = nonce.expiration_time,
    );
    let signature = hex::encode(signing_key.sign(message.as_bytes()).to_bytes());
    let resp = http
        .post(format!("{}/account/wallet", target.server))
        .json(&serde_json::json!({
            "action": ACTION,
            "did": did,
            "message": message,
            "signature": signature,
        }))
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    anyhow::ensure!(
        status.is_success() && body.get("kind").and_then(|k| k.as_str()) == Some("deactivated"),
        "deactivation answered {status} {body}"
    );
    Ok(())
}

/// Sign in, use, refresh, replay and verify against a live deployment, then
/// deactivate the throwaway account.
#[tokio::test]
#[ignore = "live: needs SIWX_SERVER and SIWX_HOMESERVER; creates and deactivates a throwaway account"]
async fn the_headless_client_signs_in_refreshes_and_verifies_its_did_against_a_live_deployment() {
    let Some(target) = target_from_env() else {
        return;
    };
    let key = SiwxKey::generate_ed25519();
    eprintln!("        throwaway identity {}", key.did());

    let mut checks = Checks::default();
    let mut signed_in = None;
    let outcome = exercise(&target, &key, &mut checks, &mut signed_in).await;

    // Clean up whatever the checks found: the account exists once the sign-in
    // completed.
    if let Some(SignedIn {
        client_id,
        refresh_token,
    }) = &signed_in
    {
        match deactivate(&target, &key).await {
            Ok(()) => {
                eprintln!("ok      the throwaway account is deactivated");
                let after = refresh(&target.server, client_id, refresh_token, &key.did()).await;
                checks.check(
                    is_refused(&after),
                    "after deactivation the latest refresh token is refused",
                    describe(&after),
                );
            }
            Err(e) => checks.check(false, "the throwaway account is deactivated", e),
        }
    }

    if let Err(e) = outcome {
        panic!(
            "stopped early: {e:#}; failed checks before that: {:?}",
            checks.failed
        );
    }
    assert!(
        checks.failed.is_empty(),
        "{} check(s) failed: {:#?}",
        checks.failed.len(),
        checks.failed
    );
}
