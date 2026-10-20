//! The requests the canary makes, shared by `init` and `check`: client
//! registration, the `/authorize` probe, the sign-in through the library, the
//! logout and its proof, the identity tripwire and the signed account erase.
//!
//! Every error is mapped to a reason code at the point it happens; no error
//! text leaves this module.

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::Signer;
use siwx_oidc_auth::{
    authenticate_with_scope_using, code_flow_scope, AuthError, AuthTokens, SiwxKey,
};

use crate::hygiene::Secret;
use crate::identity::LogoutRoute;
use crate::net::{self, send, Reply};
use crate::report::Reason;

/// Never followed: the library reads the code from the `Location` of `/sign_in`
/// without following it.
pub const REDIRECT_URI: &str = "https://agent.example.org/callback";
pub const CLIENT_NAME: &str = "rotation-canary";
pub const DISPLAY_NAME: &str = "rotation-canary";
/// The display name of a device this program's sign-in makes: siwx-oidc names a
/// new device after the registered `client_name` (`device_display_name` in
/// `src/oidc.rs`), which is [`CLIENT_NAME`].
pub const DEVICE_NAME: &str = CLIENT_NAME;
/// The prefix of the id siwx-oidc mints for a device when the client proposes
/// none, which is what this program does.
const MINTED_DEVICE_PREFIX: &str = "SIWX_";
/// RFC 7636 appendix B's challenge: the `/authorize` probe never completes a
/// flow, so it needs no verifier of its own.
const PROBE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ACTION_ACCOUNT_ERASE: &str = "io.inblock.account_erase";

/// The tokens of a sign-in, each in a [`Secret`].
#[derive(Debug)]
pub struct Tokens {
    pub access: Secret,
    pub refresh: Option<Secret>,
    pub id_token: Option<Secret>,
}

impl From<AuthTokens> for Tokens {
    fn from(t: AuthTokens) -> Self {
        Tokens {
            access: Secret::new(t.access_token),
            refresh: t.refresh_token.map(Secret::new),
            id_token: t.id_token.map(Secret::new),
        }
    }
}

/// `POST /register`: a public client. Its registration access token (and a
/// client secret, were one issued) is wrapped, so held by the taint check, and
/// dropped: the canary never manages the registration, it lets it expire.
pub async fn register_client(http: &reqwest::Client, issuer: &str) -> Result<String, Reason> {
    let reply = send(
        http.post(format!("{issuer}/register"))
            .json(&serde_json::json!({
                "redirect_uris": [REDIRECT_URI],
                "client_name": CLIENT_NAME,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
    )
    .await
    .map_err(|_| Reason::RegisterFailed)?;
    if !(200..300).contains(&reply.status) {
        return Err(Reason::RegisterFailed);
    }
    // Credentials of the registration: held by the taint check, then dropped.
    for name in ["registration_access_token", "client_secret"] {
        let _held = reply.str_field(name).map(|t| Secret::new(t.to_string()));
    }
    hold_cookies(&reply);
    reply
        .str_field("client_id")
        .map(str::to_string)
        .ok_or(Reason::RegisterFailed)
}

/// Hold the value of every cookie a reply sets (and the whole `name=value`) in
/// the taint check: a session cookie is a credential.
pub fn hold_cookies(reply: &Reply) {
    for cookie in &reply.set_cookies {
        let pair = cookie.split(';').next().unwrap_or_default();
        let _whole = Secret::new(pair.to_string());
        if let Some((_, value)) = pair.split_once('=') {
            let _value = Secret::new(value.to_string());
        }
    }
}

/// What `GET /authorize` says about the stored client.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    /// 303: the client is known. `date` is the server's clock at this response.
    Valid {
        date: Option<i64>,
    },
    /// 401 "Unrecognised client id."
    ClientRefused,
    Unavailable,
    Unexpected,
}

/// One `GET /authorize` with the client and a challenge whose verifier does not
/// exist. It gives the typed answer the library hides (is the client still
/// registered?) and the server's `Date` for this run. The session it opens
/// expires on its own.
pub async fn probe_authorize(http: &reqwest::Client, issuer: &str, client_id: &str) -> Probe {
    let scope = code_flow_scope(None);
    let request = http.get(format!("{issuer}/authorize")).query(&[
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("scope", scope.as_str()),
        ("response_type", "code"),
        ("state", "canary-probe"),
        ("code_challenge", PROBE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    match send(request).await {
        Ok(r) => {
            // The probe opens a server session and sets its cookie: a
            // credential, held by the taint check like every other one.
            hold_cookies(&r);
            if r.status == 303 {
                Probe::Valid { date: r.date }
            } else if r.status == 401 {
                Probe::ClientRefused
            } else if r.is_unavailable() {
                Probe::Unavailable
            } else {
                Probe::Unexpected
            }
        }
        Err(_) => Probe::Unavailable,
    }
}

/// The PKCE sign-in of the library, with this program's client (no redirects,
/// a timeout). The scope is the library's (`openid profile offline_access
/// urn:matrix:client:api:*`) and proposes no device, so the server mints
/// `SIWX_<uuid>`.
pub async fn sign_in(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    key: &SiwxKey,
) -> Result<Tokens, Reason> {
    match authenticate_with_scope_using(
        http,
        issuer,
        client_id,
        REDIRECT_URI,
        key,
        &code_flow_scope(None),
    )
    .await
    {
        Ok(tokens) => Ok(tokens.into()),
        // The error is typed where the library types it and otherwise opaque:
        // its text can embed a response body, so it is never read.
        Err(e) => Err(match e.downcast_ref::<AuthError>() {
            Some(AuthError::AccessDenied { .. }) => Reason::IdentityUnusable,
            Some(AuthError::DeviceRefused { .. }) => Reason::DeviceRefused,
            Some(AuthError::TemporarilyUnavailable { .. }) => Reason::SignInUnavailable,
            Some(_) => Reason::SignInRefused,
            None => Reason::SignInFailed,
        }),
    }
}

/// `POST /_matrix/client/v3/logout` without a token: siwx-oidc answers 200 `{}`
/// (also for an unknown token), which means the edge routes the path to it. A
/// homeserver that does not route it answers 401, 404 or 405 with a Matrix
/// `errcode` in the body, and then `/oauth2/revoke` is the way out. Anything
/// else (429, a 5xx, a page with no `errcode` from an edge that is not
/// Matrix, no answer) says nothing about the route and is an error, with the
/// status: recording `revoke` on such an answer would pin the weaker route.
pub async fn probe_logout_route(
    http: &reqwest::Client,
    homeserver: &str,
) -> Result<LogoutRoute, (Reason, u16)> {
    let reply = send(
        http.post(format!("{homeserver}/_matrix/client/v3/logout"))
            .json(&serde_json::json!({})),
    )
    .await
    .map_err(|_| (Reason::RouteProbeFailed, 0))?;
    classify_route_probe(reply.status, reply.str_field("errcode").is_some())
}

pub fn classify_route_probe(
    status: u16,
    has_matrix_errcode: bool,
) -> Result<LogoutRoute, (Reason, u16)> {
    match status {
        200 => Ok(LogoutRoute::Matrix),
        401 | 404 | 405 if has_matrix_errcode => Ok(LogoutRoute::Revoke),
        other => Err((Reason::RouteProbeFailed, other)),
    }
}

/// A device as the homeserver lists it (`GET /devices`). The display name and
/// the last-seen time are compared and never printed: they are the server's
/// words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    /// `None` when the field is absent, null or not a string.
    pub display_name: Option<String>,
    /// Whether the device has ever been seen in use: `last_seen_ts` is present
    /// and not null (whatever its value, so an odd value reads as "seen").
    pub seen: bool,
}

impl Device {
    /// Whether the device looks like the one an unfinished sign-in of this
    /// program leaves: an id the server minted, the canary's own display name,
    /// and never used (the sign-in died before it got, or used, a token, and a
    /// device whose token was used has a `last_seen_ts`).
    ///
    /// A device whose naming failed (siwx-oidc names a new device best-effort)
    /// does not match, and nor does one whose `last_seen_ts` is set: both read
    /// as strangers, which is the safe direction.
    pub fn looks_unfinished(&self) -> bool {
        self.id.starts_with(MINTED_DEVICE_PREFIX)
            && self.display_name.as_deref() == Some(DEVICE_NAME)
            && !self.seen
    }
}

/// What the account looks like from its own token: the rooms it has joined and
/// the devices it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct Reading {
    pub rooms: usize,
    pub listed: Vec<Device>,
}

impl Reading {
    pub fn has(&self, id: &str) -> bool {
        self.listed.iter().any(|d| d.id == id)
    }
}

pub async fn read_account(
    http: &reqwest::Client,
    homeserver: &str,
    access: &Secret,
) -> Option<Reading> {
    let get = |path: &str| {
        http.get(format!("{homeserver}/_matrix/client/v3/{path}"))
            .bearer_auth(access.expose())
    };
    let rooms = send(get("joined_rooms")).await.ok()?;
    let devices = send(get("devices")).await.ok()?;
    let rooms = (rooms.status == 200)
        .then(|| {
            rooms
                .json
                .as_ref()?
                .get("joined_rooms")?
                .as_array()
                .map(Vec::len)
        })
        .flatten()?;
    let listed = (devices.status == 200)
        .then(|| {
            devices
                .json
                .as_ref()?
                .get("devices")?
                .as_array()?
                .iter()
                .map(parse_device)
                .collect::<Option<Vec<Device>>>()
        })
        .flatten()?;
    Some(Reading { rooms, listed })
}

/// One entry of the `devices` array; `None` when it has no string `device_id`
/// (the whole reading is then unusable, as it always was).
fn parse_device(entry: &serde_json::Value) -> Option<Device> {
    Some(Device {
        id: entry.get("device_id")?.as_str()?.to_string(),
        display_name: entry
            .get("display_name")
            .and_then(|n| n.as_str())
            .map(str::to_string),
        seen: entry.get("last_seen_ts").is_some_and(|t| !t.is_null()),
    })
}

/// The identity tripwire's verdict. The canary account has never joined a room
/// and holds no device but this run's, with three exceptions that are named and
/// never silent:
///
/// - `leftovers`: devices an earlier run of the canary recorded (`tolerated`).
/// - `survivors`: devices whose logout an earlier run proved (`logged_out`) and
///   that are still listed. The proof was about the grant; the Synapse device is
///   deleted by siwx-oidc best-effort, so it can outlive it. They are the
///   canary's own and are not a stranger, but they are a fault of the server
///   and get their own reason.
/// - `unfinished`: devices nobody recorded that an unfinished sign-in of the
///   canary can explain. The server mints `SIWX_<uuid>` at `/sign_in`, before
///   the token exchange, so a sign-in that failed or was killed after it leaves
///   one. A device is explained only when it looks like that device
///   ([`Device::looks_unfinished`]: a minted id, the canary's own display name,
///   never seen in use), every unexplained device does, and there are no more
///   of them than `attempts`, the live markers of sign-ins started and never
///   finished. One stranger that does not look the part fires the tripwire for
///   all of them.
///
/// Anything else unexplained is a stranger and fires the tripwire.
#[derive(Debug, PartialEq, Eq)]
pub struct Judgement {
    pub fired: bool,
    pub strangers: Vec<String>,
    pub unfinished: Vec<String>,
    pub leftovers: Vec<String>,
    pub survivors: Vec<String>,
}

pub fn judge(
    reading: &Reading,
    own: Option<&str>,
    tolerated: &BTreeSet<String>,
    logged_out: &BTreeSet<String>,
    attempts: usize,
) -> Judgement {
    let mut leftovers = Vec::new();
    let mut survivors = Vec::new();
    let mut others: Vec<&Device> = Vec::new();
    for device in &reading.listed {
        let id = device.id.as_str();
        if Some(id) == own {
            continue;
        }
        if tolerated.contains(id) {
            leftovers.push(device.id.clone());
        } else if logged_out.contains(id) {
            survivors.push(device.id.clone());
        } else {
            others.push(device);
        }
    }
    // Without a whoami there is no telling which device is this run's: one of
    // the others must be it, and it has to look like an unfinished sign-in's
    // like the rest (a run's own device that does not is read as a stranger:
    // stricter, never looser).
    let unexplained = others.len().saturating_sub(usize::from(own.is_none()));
    let ids = |devices: &[&Device]| devices.iter().map(|d| d.id.clone()).collect::<Vec<_>>();
    let (strangers, unfinished) = if unexplained == 0 {
        (Vec::new(), Vec::new())
    } else if attempts >= unexplained && others.iter().all(|d| d.looks_unfinished()) {
        (Vec::new(), ids(&others))
    } else {
        (ids(&others), Vec::new())
    };
    Judgement {
        fired: reading.rooms > 0 || !strangers.is_empty(),
        strangers,
        unfinished,
        leftovers,
        survivors,
    }
}

/// `DELETE /_matrix/client/v3/devices/{id}` with the run's own token: forgets a
/// leftover device of an earlier run of the canary.
pub async fn delete_device(
    http: &reqwest::Client,
    homeserver: &str,
    access: &Secret,
    device_id: &str,
) -> bool {
    send(
        http.delete(format!(
            "{homeserver}/_matrix/client/v3/devices/{}",
            urlencoding::encode(device_id)
        ))
        .bearer_auth(access.expose())
        .json(&serde_json::json!({})),
    )
    .await
    .is_ok_and(|r| (200..300).contains(&r.status))
}

/// What the logout achieved, judged by the refresh token and not by the
/// logout's own answer (`/logout` answers 200 for a token it does not know).
#[derive(Debug)]
pub struct LogoutReport {
    pub reason: Reason,
    pub route: LogoutRoute,
    pub logout_status: Option<u16>,
    /// `refused`, `accepted`, `unknown` or `no_token`.
    pub refresh: &'static str,
    /// `revoked` or `failed` when a refresh that should have been refused
    /// issued a new pair that had to be revoked.
    pub cleanup: Option<&'static str>,
}

async fn revoke(http: &reqwest::Client, issuer: &str, refresh: &Secret) -> Option<u16> {
    send(http.post(format!("{issuer}/oauth2/revoke")).form(&[
        ("token", refresh.expose()),
        ("token_type_hint", "refresh_token"),
    ]))
    .await
    .ok()
    .map(|r| r.status)
}

/// End this run's session by `route`, then try the run's refresh token: only
/// `400 invalid_grant` proves the grant is gone. A refresh that succeeds
/// issued a new pair, which is revoked at once.
pub async fn logout_and_prove(
    http: &reqwest::Client,
    issuer: &str,
    homeserver: Option<&str>,
    route: LogoutRoute,
    client_id: &str,
    tokens: &Tokens,
) -> LogoutReport {
    let logout_status = match (route, homeserver, &tokens.refresh) {
        (LogoutRoute::Matrix, Some(homeserver), _) => send(
            http.post(format!("{homeserver}/_matrix/client/v3/logout"))
                .bearer_auth(tokens.access.expose())
                .json(&serde_json::json!({})),
        )
        .await
        .ok()
        .map(|r| r.status),
        (LogoutRoute::Revoke, _, Some(refresh)) => revoke(http, issuer, refresh).await,
        _ => None,
    };
    let mut report = LogoutReport {
        reason: Reason::Ok,
        route,
        logout_status,
        refresh: "no_token",
        cleanup: None,
    };
    let Some(refresh) = &tokens.refresh else {
        report.reason = Reason::NoRefreshToken;
        return report;
    };
    let attempt = send(http.post(format!("{issuer}/token")).form(&[
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh.expose()),
    ]))
    .await;
    match attempt {
        Ok(reply) if reply.status == 400 && reply.error_code() == Some("invalid_grant") => {
            report.refresh = "refused";
            report.reason = if logout_status == Some(200) {
                Reason::Ok
            } else {
                Reason::LogoutStatus
            };
        }
        Ok(reply) if reply.status == 200 => {
            report.refresh = "accepted";
            report.reason = Reason::LogoutIneffective;
            report.cleanup = Some(clean_up_issued_pair(http, issuer, &reply).await);
        }
        _ => {
            report.refresh = "unknown";
            report.reason = Reason::LogoutUnproven;
        }
    }
    report
}

async fn clean_up_issued_pair(http: &reqwest::Client, issuer: &str, reply: &Reply) -> &'static str {
    let issued = reply
        .str_field("refresh_token")
        .map(|t| Secret::new(t.to_string()));
    // Held by the taint check from here on.
    let _access = reply
        .str_field("access_token")
        .map(|t| Secret::new(t.to_string()));
    match issued {
        Some(refresh) if revoke(http, issuer, &refresh).await == Some(200) => "revoked",
        _ => "failed",
    }
}

#[derive(serde::Deserialize)]
struct AccountNonce {
    nonce: String,
    expiration_time: String,
    resources: Vec<String>,
}

/// Erase the account of `key` through the account page's signed
/// re-authentication (`io.inblock.account_erase`): a server-issued nonce bound
/// to the action, signed by the account's key. Erase, not deactivate: a
/// deactivated account can be reactivated by whoever holds the key. The
/// `Issued At` is the server's clock, not this host's.
pub async fn erase_account(
    http: &reqwest::Client,
    issuer: &str,
    key: &SiwxKey,
) -> Result<EraseOutcome, (Reason, u16)> {
    let failed = |status: u16| (Reason::EraseFailed, status);
    let SiwxKey::Ed25519(signing_key) = key else {
        return Err(failed(0));
    };
    let nonce_reply = send(
        http.get(format!("{issuer}/account/nonce"))
            .query(&[("action", ACTION_ACCOUNT_ERASE)]),
    )
    .await
    .map_err(|_| failed(0))?;
    hold_cookies(&nonce_reply);
    if nonce_reply.status != 200 {
        return Err(failed(nonce_reply.status));
    }
    let nonce: AccountNonce = nonce_reply
        .json
        .clone()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| failed(nonce_reply.status))?;
    let nonce_value = Secret::new(nonce.nonce);
    let issued_at = nonce_reply
        .date
        .and_then(|d| DateTime::<Utc>::from_timestamp(d, 0))
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let did = key.did();
    let url = url::Url::parse(issuer).map_err(|_| failed(0))?;
    let resources: String = nonce.resources.iter().map(|r| format!("\n- {r}")).collect();
    let message = format!(
        "{domain} wants you to sign in with your Ed25519 key:\n{address}\n\n\
         Erase this account.\n\n\
         URI: {uri}\nVersion: 1\nNonce: {nonce}\nIssued At: {issued_at}\n\
         Expiration Time: {exp}\nResources:{resources}",
        domain = url.host_str().unwrap_or_default(),
        address = did.strip_prefix("did:key:").unwrap_or(&did),
        uri = nonce.resources.first().map(String::as_str).unwrap_or(""),
        nonce = nonce_value.expose(),
        exp = nonce.expiration_time,
    );
    // Only the nonce and the signature are credentials; the message around them
    // is made of public strings (the issuer's host among them) that output lines
    // legitimately repeat, so it is not held by the taint check.
    let signature = Secret::new(hex::encode(signing_key.sign(message.as_bytes()).to_bytes()));
    let reply = send(
        http.post(format!("{issuer}/account/wallet"))
            .json(&serde_json::json!({
                "action": ACTION_ACCOUNT_ERASE,
                "did": did,
                "message": message,
                "signature": signature.expose(),
            })),
    )
    .await
    .map_err(|_| failed(0))?;
    // The reply of a re-authentication carries an account session: a CSRF token
    // in the body and a cookie. Held by the taint check.
    hold_cookies(&reply);
    let _csrf = reply.str_field("csrf").map(|t| Secret::new(t.to_string()));
    if (200..300).contains(&reply.status) && reply.str_field("kind") == Some("erased") {
        Ok(EraseOutcome::Erased)
    } else if reply.status == 400 && reply.body_contains(NO_ACCOUNT_REFUSAL) {
        // The server ran the check and found no account for this key (the
        // sign-in that would have made it never got that far): nothing to erase.
        Ok(EraseOutcome::NoAccount)
    } else {
        Err(failed(reply.status))
    }
}

/// What `erase_account` achieved.
#[derive(Debug, PartialEq, Eq)]
pub enum EraseOutcome {
    Erased,
    /// The server refused because the key has no account.
    NoAccount,
}

/// A part of the message `account_wallet` answers (400) when the signature is
/// good but no account exists for the DID (`NEW_IDENTITY_REJECT_MSG` in
/// `src/webauthn.rs`). Compared, never printed. A deactivated or erased account
/// has a different refusal, and stays a failure: it may be reactivatable.
const NO_ACCOUNT_REFUSAL: &str = "is not linked to an existing account";

/// Wait this long between the retries of the discovery fetch.
pub const RETRY_PAUSE: Duration = Duration::from_secs(3);

/// A shared HTTP client for one run.
pub fn http() -> Result<reqwest::Client, Reason> {
    net::client()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device the way an unfinished sign-in of the canary leaves it: named
    /// for the canary's client and never seen in use.
    fn device(id: &str) -> Device {
        Device {
            id: id.to_string(),
            display_name: Some(DEVICE_NAME.to_string()),
            seen: false,
        }
    }

    fn reading(rooms: usize, ids: &[&str]) -> Reading {
        Reading {
            rooms,
            listed: ids.iter().map(|id| device(id)).collect(),
        }
    }

    fn ledger(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn clean() -> Judgement {
        Judgement {
            fired: false,
            strangers: vec![],
            unfinished: vec![],
            leftovers: vec![],
            survivors: vec![],
        }
    }

    #[test]
    fn only_this_runs_device_is_clean() {
        let j = judge(
            &reading(0, &["SIWX_now"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            0,
        );
        assert_eq!(j, clean());
    }

    #[test]
    fn a_device_nobody_recorded_fires_the_tripwire() {
        let j = judge(
            &reading(0, &["SIWX_now", "ATTACKER"]),
            Some("SIWX_now"),
            &ledger(&["SIWX_old"]),
            &ledger(&[]),
            0,
        );
        assert!(j.fired);
        assert_eq!(j.strangers, vec!["ATTACKER".to_string()]);
    }

    #[test]
    fn a_joined_room_fires_the_tripwire_even_with_no_stranger_device() {
        assert!(
            judge(
                &reading(1, &["SIWX_now"]),
                Some("SIWX_now"),
                &ledger(&[]),
                &ledger(&[]),
                0
            )
            .fired
        );
    }

    #[test]
    fn a_leftover_of_an_earlier_canary_run_is_tolerated_and_reported() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_old"]),
            Some("SIWX_now"),
            &ledger(&["SIWX_old"]),
            &ledger(&[]),
            0,
        );
        assert_eq!(
            j,
            Judgement {
                leftovers: vec!["SIWX_old".to_string()],
                ..clean()
            }
        );
    }

    #[test]
    fn without_a_whoami_one_unexplained_device_is_this_runs_and_two_are_not() {
        assert!(
            !judge(
                &reading(0, &["SIWX_x"]),
                None,
                &ledger(&[]),
                &ledger(&[]),
                0
            )
            .fired
        );
        let j = judge(
            &reading(0, &["SIWX_x", "SIWX_y"]),
            None,
            &ledger(&[]),
            &ledger(&[]),
            0,
        );
        assert!(j.fired);
        assert_eq!(j.strangers.len(), 2);
    }

    #[test]
    fn an_unrecorded_siwx_device_with_an_unfinished_attempt_is_reported_not_fired() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_killed"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(!j.fired, "it is explained, but under its own name");
        assert_eq!(j.unfinished, vec!["SIWX_killed".to_string()]);
        assert!(j.strangers.is_empty());
    }

    #[test]
    fn a_device_with_no_attempt_to_match_it_still_fires() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_killed"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            0,
        );
        assert!(j.fired);
        assert!(j.unfinished.is_empty());
    }

    #[test]
    fn more_unrecorded_devices_than_attempts_fire_and_none_is_excused() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_a", "SIWX_b"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(j.fired);
        assert_eq!(j.strangers.len(), 2);
        assert!(j.unfinished.is_empty());
    }

    #[test]
    fn an_attempt_never_explains_a_device_the_server_did_not_mint() {
        // `SIWX_<uuid>` is what the server mints when no device id is proposed,
        // which is what the canary does; a client's own id is not its leftover.
        let j = judge(
            &reading(0, &["SIWX_now", "ELEMENTXDEVICE"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            3,
        );
        assert!(j.fired);
        assert_eq!(j.strangers, vec!["ELEMENTXDEVICE".to_string()]);
    }

    #[test]
    fn a_room_fires_even_when_every_device_is_explained() {
        let j = judge(
            &reading(1, &["SIWX_now", "SIWX_killed"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(j.fired);
        assert_eq!(j.unfinished.len(), 1);
    }

    #[test]
    fn the_logout_route_probe_pins_revoke_only_on_a_matrix_refusal() {
        assert_eq!(classify_route_probe(200, false), Ok(LogoutRoute::Matrix));
        for status in [401, 404, 405] {
            assert_eq!(
                classify_route_probe(status, true),
                Ok(LogoutRoute::Revoke),
                "{status}"
            );
            assert_eq!(
                classify_route_probe(status, false),
                Err((Reason::RouteProbeFailed, status)),
                "an edge that is not Matrix says nothing about the route ({status})"
            );
        }
        for status in [400, 403, 429, 500, 502, 503, 504] {
            assert_eq!(
                classify_route_probe(status, true),
                Err((Reason::RouteProbeFailed, status)),
                "{status}"
            );
        }
    }

    fn reading_of(rooms: usize, listed: Vec<Device>) -> Reading {
        Reading { rooms, listed }
    }

    #[test]
    fn a_stranger_with_a_siwx_id_does_not_pass_as_an_unfinished_sign_in() {
        // A live marker, a minted-looking id: only the device itself can tell.
        let strangers = [
            (
                "another client's name",
                Device {
                    display_name: Some("Element Web".to_string()),
                    ..device("SIWX_stranger")
                },
            ),
            (
                "no name",
                Device {
                    display_name: None,
                    ..device("SIWX_stranger")
                },
            ),
            (
                "the canary's name but seen in use",
                Device {
                    seen: true,
                    ..device("SIWX_stranger")
                },
            ),
            (
                "the canary's name, unseen, but an id the server did not mint",
                device("STRANGER"),
            ),
        ];
        for (what, stranger) in strangers {
            let id = stranger.id.clone();
            let j = judge(
                &reading_of(0, vec![device("SIWX_now"), stranger]),
                Some("SIWX_now"),
                &ledger(&[]),
                &ledger(&[]),
                1,
            );
            assert!(j.fired, "{what}");
            assert_eq!(j.strangers, vec![id], "{what}");
            assert!(j.unfinished.is_empty(), "{what}");
        }
    }

    #[test]
    fn the_canarys_own_unfinished_device_is_still_excused_by_a_marker() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_killed"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(!j.fired);
        assert_eq!(j.unfinished, vec!["SIWX_killed".to_string()]);
    }

    #[test]
    fn one_stranger_among_excusable_devices_fires_for_all_of_them() {
        let j = judge(
            &reading_of(
                0,
                vec![
                    device("SIWX_now"),
                    device("SIWX_killed"),
                    Device {
                        seen: true,
                        ..device("SIWX_stranger")
                    },
                ],
            ),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&[]),
            2,
        );
        assert!(j.fired);
        assert_eq!(j.strangers.len(), 2, "no part of the doubt is excused");
        assert!(j.unfinished.is_empty());
    }

    #[test]
    fn without_a_whoami_a_stranger_cannot_hide_as_this_runs_device() {
        // One of two unexplained devices is this run's. Both must look like an
        // unfinished sign-in's for the marker to cover the other; a seen one
        // could be the stranger, so it fires.
        let seen = Device {
            seen: true,
            ..device("SIWX_b")
        };
        let j = judge(
            &reading_of(0, vec![device("SIWX_a"), seen]),
            None,
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(j.fired);
        let j = judge(
            &reading(0, &["SIWX_a", "SIWX_b"]),
            None,
            &ledger(&[]),
            &ledger(&[]),
            1,
        );
        assert!(!j.fired);
        assert_eq!(j.unfinished.len(), 2);
    }

    #[test]
    fn a_device_whose_logout_was_proven_is_a_survivor_not_a_stranger() {
        let j = judge(
            &reading_of(
                0,
                vec![
                    device("SIWX_now"),
                    // Used by the canary itself: seen, and still not a stranger.
                    Device {
                        seen: true,
                        display_name: None,
                        ..device("SIWX_before")
                    },
                ],
            ),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&["SIWX_before"]),
            0,
        );
        assert_eq!(
            j,
            Judgement {
                survivors: vec!["SIWX_before".to_string()],
                ..clean()
            }
        );
    }

    #[test]
    fn a_survivor_does_not_excuse_a_stranger_beside_it() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_before", "ATTACKER"]),
            Some("SIWX_now"),
            &ledger(&[]),
            &ledger(&["SIWX_before"]),
            5,
        );
        assert!(j.fired);
        assert_eq!(j.strangers, vec!["ATTACKER".to_string()]);
        assert_eq!(j.survivors, vec!["SIWX_before".to_string()]);
    }

    #[test]
    fn a_device_reads_from_the_shape_the_homeserver_lists() {
        use serde_json::json;
        let named = parse_device(&json!({
            "device_id": "SIWX_a", "display_name": "rotation-canary",
            "last_seen_ip": null, "last_seen_ts": null,
        }))
        .unwrap();
        assert_eq!(named, device("SIWX_a"));
        assert!(named.looks_unfinished());
        // Absent and null mean "never seen"; any value means seen.
        let bare = parse_device(&json!({"device_id": "SIWX_b"})).unwrap();
        assert!(!bare.seen);
        assert_eq!(bare.display_name, None);
        assert!(!bare.looks_unfinished(), "no name is not the canary's name");
        for ts in [json!(1_700_000_000_000_i64), json!(0), json!("soon")] {
            let seen = parse_device(&json!({
                "device_id": "SIWX_c", "display_name": "rotation-canary", "last_seen_ts": ts,
            }))
            .unwrap();
            assert!(seen.seen && !seen.looks_unfinished(), "{ts}");
        }
        // A name that is not a string is no name; an entry with no id is no reading.
        let odd = parse_device(&json!({"device_id": "SIWX_d", "display_name": 7})).unwrap();
        assert_eq!(odd.display_name, None);
        assert!(parse_device(&json!({"display_name": "rotation-canary"})).is_none());
        assert!(parse_device(&json!({"device_id": 7})).is_none());
    }
}
