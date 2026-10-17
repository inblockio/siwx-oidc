//! Helpers shared by the live qualification suites (`live_upgrade.rs`) and the
//! population soak (`examples/soak.rs`): targets from the environment, the
//! requests a headless client and a Matrix client make, the token formats,
//! and the deactivation of a throwaway account.
//!
//! Nothing here prints a token. A request that fails is described by its
//! status and error code, never by what was sent.

#![allow(dead_code)]

use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::Signer;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use siwx_oidc_auth::SiwxKey;

/// Never followed: the client reads the code from the `Location` of
/// `/sign_in` without following it.
pub const REDIRECT_URI: &str = "https://agent.example.org/callback";
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub server: String,
    pub homeserver: String,
}

/// `E2E_STRICT_SKIPS=0` is the only opt-out; unset or any other value is strict.
pub fn strict() -> bool {
    std::env::var("E2E_STRICT_SKIPS").ok().as_deref() != Some("0")
}

/// A variable, trimmed and without a trailing `/`; `None` when unset or empty.
pub fn env_url(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

/// The deployment under test, only from `SIWX_SERVER` and `SIWX_HOMESERVER`.
pub fn target_from_env() -> Result<Target, String> {
    match (env_url("SIWX_SERVER"), env_url("SIWX_HOMESERVER")) {
        (Some(server), Some(homeserver)) => Ok(Target { server, homeserver }),
        _ => Err("SIWX_SERVER and SIWX_HOMESERVER must both be set".to_string()),
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client")
}

pub fn now() -> i64 {
    Utc::now().timestamp()
}

/// Why a request did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No answer, or an answer that says "try again": 502, 503 or 504 (the
    /// edge while the server behind it is recreated, or a store fault).
    Unavailable(String),
    /// A refusal: the status and the error code of the body (`error` for
    /// OAuth, `errcode` for Matrix), empty when the body has neither.
    Refused { status: u16, code: String },
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Unavailable(why) => write!(f, "unavailable: {why}"),
            Failure::Refused { status, code } => write!(f, "{status} {code}"),
        }
    }
}

impl Failure {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Failure::Refused { status: 401, .. })
    }
}

/// The body of a successful answer, or the classified failure.
pub async fn classify(
    sent: Result<reqwest::Response, reqwest::Error>,
) -> Result<serde_json::Value, Failure> {
    let resp = sent.map_err(|e| Failure::Unavailable(transport(&e)))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if status.is_success() {
        return Ok(body);
    }
    if matches!(status.as_u16(), 502..=504) {
        return Err(Failure::Unavailable(format!("HTTP {}", status.as_u16())));
    }
    // Matrix answers carry `errcode` (and a message in `error`); OAuth answers
    // carry the code in `error`.
    let code = body
        .get("errcode")
        .or_else(|| body.get("error"))
        .and_then(|c| c.as_str())
        .unwrap_or_default()
        .to_string();
    Err(Failure::Refused {
        status: status.as_u16(),
        code,
    })
}

/// A transport error by its kind; the URL it carries is a deployment's, not
/// a credential, but the kind is all a report needs.
fn transport(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connection refused or reset".to_string()
    } else {
        "transport error".to_string()
    }
}

/// A client registration (RFC 7591): its id and the registration access token
/// that manages it (RFC 7592).
#[derive(Clone, Debug)]
pub struct Registration {
    pub client_id: String,
    pub registration_access_token: String,
}

/// Register a public client (no secret at `/token`), as an agent with no
/// pre-provisioned client would.
pub async fn register_public_client(
    target: &Target,
    client_name: &str,
) -> anyhow::Result<Registration> {
    let body = classify(
        http()
            .post(format!("{}/register", target.server))
            .json(&serde_json::json!({
                "redirect_uris": [REDIRECT_URI],
                "client_name": client_name,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }))
            .send()
            .await,
    )
    .await
    .map_err(|e| anyhow::anyhow!("/register answered {e}"))?;
    let field = |name: &str| {
        body.get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("/register answered no {name}"))
    };
    Ok(Registration {
        client_id: field("client_id")?,
        registration_access_token: field("registration_access_token")?,
    })
}

/// `DELETE /client/{id}` with the registration access token (RFC 7592): the
/// registration is gone, as an expired one is.
pub async fn delete_registration(target: &Target, reg: &Registration) -> anyhow::Result<()> {
    let resp = http()
        .delete(format!("{}/client/{}", target.server, reg.client_id))
        .bearer_auth(&reg.registration_access_token)
        .send()
        .await?;
    anyhow::ensure!(
        resp.status() == reqwest::StatusCode::NO_CONTENT,
        "DELETE /client/{{id}} answered {}",
        resp.status()
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct WhoAmI {
    pub user_id: String,
    pub device_id: Option<String>,
}

/// `GET /account/whoami` on the homeserver, which introspects the token at
/// the provider (and caches the answer for up to two minutes).
pub async fn whoami(target: &Target, access_token: &str) -> Result<WhoAmI, Failure> {
    let body = classify(
        http()
            .get(format!(
                "{}/_matrix/client/v3/account/whoami",
                target.homeserver
            ))
            .bearer_auth(access_token)
            .send()
            .await,
    )
    .await?;
    serde_json::from_value(body).map_err(|_| Failure::Refused {
        status: 200,
        code: "unreadable whoami body".to_string(),
    })
}

/// An access and a refresh token, and the access token's lifetime.
#[derive(Clone, Debug)]
pub struct Pair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: Option<u64>,
}

fn pair_from(body: &serde_json::Value) -> Result<Pair, Failure> {
    let field = |name: &str| body.get(name).and_then(|v| v.as_str()).map(str::to_string);
    match (field("access_token"), field("refresh_token")) {
        (Some(access_token), Some(refresh_token)) => Ok(Pair {
            access_token,
            refresh_token,
            expires_in: body.get("expires_in").and_then(|v| v.as_u64()).or_else(|| {
                body.get("expires_in_ms")
                    .and_then(|v| v.as_u64())
                    .map(|ms| ms / 1000)
            }),
        }),
        _ => Err(Failure::Refused {
            status: 200,
            code: "no token pair in the answer".to_string(),
        }),
    }
}

/// `POST /token` with `grant_type=refresh_token`, naming the client, exactly
/// as `siwx_oidc_auth::refresh` sends it; the answer classified.
pub async fn token_refresh(
    target: &Target,
    client_id: &str,
    refresh_token: &str,
) -> Result<Pair, Failure> {
    let body = classify(
        http()
            .post(format!("{}/token", target.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await,
    )
    .await?;
    pair_from(&body)
}

/// `POST /_matrix/client/v3/refresh` on the homeserver (MSC2918), as a Matrix
/// client sends it: the refresh token and nothing else. The edge routes it to
/// the provider.
pub async fn matrix_refresh(target: &Target, refresh_token: &str) -> Result<Pair, Failure> {
    let body = classify(
        http()
            .post(format!("{}/_matrix/client/v3/refresh", target.homeserver))
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await,
    )
    .await?;
    pair_from(&body)
}

fn base62(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `mat_` + 32 base62 (the same in every build).
pub fn is_access_token(token: &str) -> bool {
    token
        .strip_prefix("mat_")
        .is_some_and(|rest| base62(rest, 32))
}

/// The current refresh token format: `mcr_` + handle (22 base62) + `_` +
/// secret (32 base62). The handle names the grant.
pub fn is_refresh_token(token: &str) -> bool {
    token
        .strip_prefix("mcr_")
        .and_then(|rest| rest.split_once('_'))
        .is_some_and(|(handle, secret)| base62(handle, 22) && base62(secret, 32))
}

/// The format of builds before the grant record: `mcr_` + 32 base62.
pub fn is_legacy_refresh_token(token: &str) -> bool {
    token
        .strip_prefix("mcr_")
        .is_some_and(|rest| base62(rest, 32))
}

/// The grant handle of a current-format refresh token.
pub fn handle(token: &str) -> Option<&str> {
    token.strip_prefix("mcr_")?.split_once('_').map(|(h, _)| h)
}

/// A token's shape with every base62 character replaced, so a report can say
/// what came back without printing a credential.
pub fn shape(token: &str) -> String {
    token
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { 'x' } else { c })
        .collect()
}

/// `n` random upper-case letters and digits.
pub fn random_upper(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(|b| char::from(b).to_ascii_uppercase())
        .collect()
}

/// A device id in the shape Element X mints: 43 characters of standard
/// base64 (32 random bytes, unpadded), here always with at least one `/` and
/// one `+`, the two characters a path or a key must survive.
pub fn element_x_device_id() -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    loop {
        let bytes: [u8; 32] = rand::thread_rng().gen();
        let id = STANDARD_NO_PAD.encode(bytes);
        if id.contains('/') && id.contains('+') {
            return id;
        }
    }
}

#[derive(Deserialize)]
struct AccountNonce {
    nonce: String,
    expiration_time: String,
    resources: Vec<String>,
}

/// Deactivate the account through the account page's signed re-authentication:
/// a server-issued nonce bound to the action, signed by the account's key.
pub async fn deactivate(target: &Target, key: &SiwxKey) -> anyhow::Result<()> {
    const ACTION: &str = "org.matrix.account_deactivate";
    let SiwxKey::Ed25519(signing_key) = key else {
        anyhow::bail!("the live suites sign with an Ed25519 key");
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
        "deactivation answered {status} {}",
        body.get("error")
            .or_else(|| body.get("kind"))
            .cloned()
            .unwrap_or_default()
    );
    Ok(())
}
