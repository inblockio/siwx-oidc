//! The requests the canary makes, shared by `init` and `check`: client
//! registration, the `/authorize` probe, the sign-in through the library, the
//! logout and its proof, the identity tripwire and the signed account erase.
//!
//! Every error is mapped to a reason code at the point it happens; no error
//! text leaves this module.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::Signer;
use siwx_oidc_auth::{
    authenticate_with_scope_using, code_flow_scope, AuthError, AuthTokens, SiwxKey,
};

use crate::hygiene::Secret;
use crate::identity::{Ledger, LogoutRoute, LAST_SEEN_SLACK_SECS};
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

/// The server's clock as one of its replies told it: the `Date` header (whole
/// seconds) and the moment, on this host's monotonic clock, the reply arrived.
/// [`ServerClock::now`] is the server's time now. The device times the canary
/// keeps (when it retired a device) are compared with `last_seen_ts`, which is
/// the homeserver's clock, so they are taken from here and never from this
/// host's wall clock: the two can be minutes apart, and nothing bounds that
/// (C3's skew is a token's `iat` against the server's `Date`, both the server's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerClock {
    date: i64,
    at: Instant,
}

impl ServerClock {
    pub fn new(date: i64, at: Instant) -> Self {
        ServerClock { date, at }
    }

    /// The clock a reply gave, if it carried a `Date`. Call it as the reply
    /// arrives.
    pub fn of(reply: &Reply) -> Option<Self> {
        reply
            .date
            .map(|date| ServerClock::new(date, Instant::now()))
    }

    /// The server's unix seconds now, rounded up: the `Date` has no fraction, so
    /// the true time is up to a second later than it says, and a time taken after
    /// a request must not fall before a use that request made.
    pub fn now(&self) -> i64 {
        self.date
            .saturating_add(self.at.elapsed().as_secs() as i64)
            .saturating_add(1)
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
    /// `last_seen_ts` (milliseconds) when it is an integer. `None` for a device
    /// never seen and for a value that is not an integer, which reads as "seen
    /// at a time nobody can vouch for".
    pub last_seen_ms: Option<i64>,
}

impl Device {
    /// Whether the device looks like the one an unfinished sign-in of this
    /// program leaves: an id the server minted, the canary's own display name,
    /// and never seen in use (the sign-in died before it got, or used, a token,
    /// and a device whose token was used has a `last_seen_ts`).
    ///
    /// A device whose naming failed (siwx-oidc names a new device best-effort)
    /// does not match, and nor does one whose `last_seen_ts` is set: both read
    /// as strangers, which is the safe direction. `last_seen_ts` is not a record
    /// of every use (Synapse skips some User-Agents and records one token's use
    /// at most every 120 s), so a match is a plausible leftover, not a proof:
    /// the device is deleted in the run that excuses it.
    pub fn looks_unfinished(&self) -> bool {
        self.id.starts_with(MINTED_DEVICE_PREFIX)
            && self.display_name.as_deref() == Some(DEVICE_NAME)
            && !self.seen
    }

    /// Whether the device looks like the one a sign-in of this program that got
    /// as far as using its token holds: an id the server minted, the canary's own
    /// display name, seen in use. This run's own device, when `whoami` did not
    /// name it, is such a device (its token listed the devices).
    pub fn looks_in_use_by_canary(&self) -> bool {
        self.id.starts_with(MINTED_DEVICE_PREFIX)
            && self.display_name.as_deref() == Some(DEVICE_NAME)
            && self.seen
    }

    /// Whether the device was used later than `at` (unix seconds on the server's
    /// clock, the time the canary last used it) plus [`LAST_SEEN_SLACK_SECS`]. A
    /// `last_seen_ts` that is not a number counts as later.
    pub fn used_after(&self, at: i64) -> bool {
        self.seen
            && match self.last_seen_ms {
                Some(ms) => ms > at.saturating_add(LAST_SEEN_SLACK_SECS).saturating_mul(1000),
                None => true,
            }
    }

    /// Whether a device the canary retired at `at` and that is still listed can
    /// be the canary's own: it carries the canary's display name and nobody used
    /// it after the canary did. siwx-oidc lets a client propose a device id and
    /// recreates a deleted one, so the id alone proves nothing; a device that
    /// fails this was made or used by somebody else.
    ///
    /// A device of the canary that siwx-oidc failed to name fails it too: a
    /// false alarm in a double fault, the safe direction.
    pub fn is_survivor(&self, at: i64) -> bool {
        self.display_name.as_deref() == Some(DEVICE_NAME) && !self.used_after(at)
    }
}

/// What the account looks like from its own token: the rooms it has joined and
/// the devices it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct Reading {
    pub rooms: usize,
    pub listed: Vec<Device>,
    /// The homeserver's clock at the device list (its `Date`), the clock its
    /// `last_seen_ts` is in. `None` when the reply had no `Date`.
    pub clock: Option<ServerClock>,
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
    let clock = ServerClock::of(&devices);
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
    Some(Reading {
        rooms,
        listed,
        clock,
    })
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
        last_seen_ms: entry.get("last_seen_ts").and_then(|t| t.as_i64()),
    })
}

/// The identity tripwire's verdict. The canary account has never joined a room
/// and holds no device but this run's, with three exceptions that are named and
/// never silent:
///
/// - `leftovers`: devices an earlier run of the canary recorded (`pending`), and
///   devices that are still on the `unfinished` list (a delete of an earlier run
///   was refused, or an older version of this program left them) and still never
///   seen in use. One of the second kind that has been seen since is not a
///   leftover: it is not known to be ours.
/// - `survivors`: devices the canary retired at a known time (`logged_out`:
///   the logout was proven, or the canary deleted them) that are still listed.
///   The proof was about the grant, and siwx-oidc deletes the Synapse device
///   best-effort, so one can outlive it. It is the canary's own, not a stranger,
///   but a fault of the server with its own reason, only while it looks like the
///   canary's ([`Device::is_survivor`]): siwx-oidc recreates a deleted id for a
///   client that proposes it, so a device on a retired id that carries another
///   name, or was used after the canary's last use, is a stranger's. A device
///   retired at a time unknown passes only while it was never seen in use.
/// - `unfinished`: devices nobody recorded that an unfinished sign-in of the
///   canary can explain. The server mints `SIWX_<uuid>` at `/sign_in`, before
///   the token exchange, so a sign-in that failed or was killed after it leaves
///   one. A device is explained only when it looks like that device
///   ([`Device::looks_unfinished`]: a minted id, the canary's own display name,
///   never seen in use), every unexplained device does, and there are no more
///   of them than `attempts`, the live markers of sign-ins started and never
///   finished. One stranger that does not look the part fires the tripwire for
///   all of them. The canary cannot vouch for such a device, and `last_seen_ts`
///   is not a record of every use, so the run deletes it in the run that excuses
///   it ([`Judgement::deletable_unfinished`]) and does not wait for the next.
///
/// Anything else unexplained is a stranger and fires the tripwire.
///
/// `own_guess` is set when `whoami` did not name this run's device and the
/// listing tells which it is: the one device that is unexplained, or else the
/// one device with a minted id, the canary's name and a use (this run's token
/// was used to list, so its device is in use; an unfinished sign-in's never
/// was). With two such devices, or none and several unexplained, nobody can
/// tell, and one of them is taken to be this run's without a name (the others
/// must all look unfinished). The run records the guess like a device `whoami`
/// named.
#[derive(Debug, PartialEq, Eq)]
pub struct Judgement {
    pub fired: bool,
    pub strangers: Vec<String>,
    pub unfinished: Vec<String>,
    pub leftovers: Vec<String>,
    pub survivors: Vec<String>,
    pub own_guess: Option<String>,
}

impl Judgement {
    /// The excused devices the run may delete: all of them when it knows which
    /// device is its own (`own` from `whoami`, or a guess), none otherwise. When
    /// nobody can tell this run's device from the others, one of the excused
    /// devices may be it, and deleting it with its own token would end the
    /// session before the logout is proven.
    pub fn deletable_unfinished(&self, own: Option<&str>) -> &[String] {
        if own.is_some() || self.own_guess.is_some() {
            &self.unfinished
        } else {
            &[]
        }
    }
}

/// Which of the unexplained devices is this run's when `whoami` did not say:
/// the one with a minted id, the canary's name and a use, if exactly one is; else
/// the only unexplained device, if there is exactly one.
fn guess_own(others: &[&Device]) -> Option<String> {
    let mut in_use = others.iter().filter(|d| d.looks_in_use_by_canary());
    if let (Some(device), None) = (in_use.next(), in_use.next()) {
        return Some(device.id.clone());
    }
    (others.len() == 1).then(|| others[0].id.clone())
}

pub fn judge(reading: &Reading, own: Option<&str>, ledger: &Ledger, attempts: usize) -> Judgement {
    let mut leftovers = Vec::new();
    let mut survivors = Vec::new();
    let mut others: Vec<&Device> = Vec::new();
    for device in &reading.listed {
        let id = device.id.as_str();
        if Some(id) == own {
            continue;
        }
        if ledger.pending.contains(id)
            || (ledger.unfinished.contains(id) && device.looks_unfinished())
        {
            leftovers.push(device.id.clone());
        } else if ledger
            .logged_out
            .at(id)
            .is_some_and(|at| device.is_survivor(at))
        {
            survivors.push(device.id.clone());
        } else {
            others.push(device);
        }
    }
    // Without a whoami there is no telling which device is this run's. If the
    // listing shows it (see `guess_own`), the rest are judged against the
    // markers. If not, one of the others must be it and nobody can say which,
    // so the count excuses one and the others must all look unfinished like
    // the rest (a run's own device that does not is read as a stranger:
    // stricter, never looser).
    let own_guess = if own.is_none() {
        guess_own(&others)
    } else {
        None
    };
    let rest: Vec<&Device> = others
        .iter()
        .copied()
        .filter(|d| Some(d.id.as_str()) != own_guess.as_deref())
        .collect();
    let unexplained = rest
        .len()
        .saturating_sub(usize::from(own.is_none() && own_guess.is_none()));
    let ids = |devices: &[&Device]| devices.iter().map(|d| d.id.clone()).collect::<Vec<_>>();
    let (strangers, unfinished) = if unexplained == 0 {
        (Vec::new(), Vec::new())
    } else if attempts >= unexplained && rest.iter().all(|d| d.looks_unfinished()) {
        (Vec::new(), ids(&rest))
    } else {
        (ids(&rest), Vec::new())
    };
    Judgement {
        fired: reading.rooms > 0 || !strangers.is_empty(),
        strangers,
        unfinished,
        leftovers,
        survivors,
        own_guess,
    }
}

/// Everything the end of a run knows, for [`Closing::next`].
pub struct Closing<'a> {
    pub reading: &'a Reading,
    pub judged: &'a Judgement,
    /// The devices this run deleted (the homeserver answered 2xx): leftovers,
    /// survivors and excused unfinished sign-ins.
    pub cleaned: &'a BTreeSet<String>,
    /// The device `whoami` named for this run.
    pub own: Option<&'a str>,
    /// The logout went through the homeserver's `/logout` and the run's refresh
    /// token was refused afterwards.
    pub logout_proven: bool,
    pub attempt_id: &'a str,
    /// Unix seconds on the server's clock ([`ServerClock::now`]), taken after the
    /// run's last request with a token (the logout), so no use of any device is
    /// later. `None` when no reply of the run carried a `Date`: the devices
    /// retired then are recorded at a time unknown.
    pub now: Option<i64>,
}

impl Closing<'_> {
    /// The ledger after the run:
    ///
    /// - A device leaves a list only when this run's reading shows it gone. An
    ///   answer does not count: siwx-oidc answers a device delete with 200
    ///   whether or not the device went.
    /// - A device this run deleted goes on `logged_out` at `now` (a survivor
    ///   keeps the time it has; one that was an unfinished sign-in's, which the
    ///   canary never used, goes at a time unknown), and so does this run's own
    ///   after a proven logout through `/logout`. A later run that still lists
    ///   it reports it and deletes it again, and tells the canary's own device
    ///   from a stranger's on the same id by its name and its `last_seen_ts`.
    /// - This run's own device stays on `pending` where the logout may leave it
    ///   (`/oauth2/revoke`, or a logout not proven).
    /// - Devices excused as unfinished sign-ins that the run could not delete go
    ///   on `unfinished`, and the markers are spent. While the tripwire is fired
    ///   nothing is excused, recorded or spent: the evidence stays as it was, and
    ///   a kept marker cannot excuse a second device later.
    pub fn next(&self, ledger: &Ledger) -> Ledger {
        let mut next = ledger.clone();
        let listed = |id: &str| self.reading.has(id);
        next.pending.retain(|id| listed(id));
        next.unfinished.retain(|id| listed(id));
        next.logged_out.retain(listed);
        for id in self.cleaned {
            let unfinished = ledger.unfinished.contains(id) || self.judged.unfinished.contains(id);
            next.pending.remove(id);
            next.unfinished.remove(id);
            // A survivor keeps its time: the canary never used its token.
            if !next.logged_out.contains(id) {
                match self.now {
                    Some(now) if !unfinished => next.logged_out.insert(id.clone(), now),
                    _ => next.logged_out.insert_unknown(id.clone()),
                }
            }
        }
        let own = self.own.or(self.judged.own_guess.as_deref());
        if let Some(own) = own {
            next.unfinished.remove(own);
            if self.logout_proven {
                next.pending.remove(own);
                match self.now {
                    Some(now) => next.logged_out.insert(own.to_string(), now),
                    None => next.logged_out.insert_unknown(own.to_string()),
                }
            } else {
                next.pending.insert(own.to_string());
            }
        }
        if !self.judged.fired {
            next.unfinished.extend(
                self.judged
                    .unfinished
                    .iter()
                    .filter(|id| !self.cleaned.contains(*id))
                    .cloned(),
            );
            // The markers were weighed against what the account holds. This
            // run's own stays only while no device could be its own.
            let keep = own.is_none() && self.judged.unfinished.is_empty();
            next.attempts.retain(|a| keep && a.id == self.attempt_id);
        }
        next
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
    /// The server's clock at the last reply of the logout that carried a `Date`,
    /// which is after the last request that used the device's token: the time to
    /// retire the device at.
    pub clock: Option<ServerClock>,
}

async fn revoke(http: &reqwest::Client, issuer: &str, refresh: &Secret) -> Option<Reply> {
    send(http.post(format!("{issuer}/oauth2/revoke")).form(&[
        ("token", refresh.expose()),
        ("token_type_hint", "refresh_token"),
    ]))
    .await
    .ok()
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
    let logout = match (route, homeserver, &tokens.refresh) {
        (LogoutRoute::Matrix, Some(homeserver), _) => send(
            http.post(format!("{homeserver}/_matrix/client/v3/logout"))
                .bearer_auth(tokens.access.expose())
                .json(&serde_json::json!({})),
        )
        .await
        .ok(),
        (LogoutRoute::Revoke, _, Some(refresh)) => revoke(http, issuer, refresh).await,
        _ => None,
    };
    let logout_status = logout.as_ref().map(|r| r.status);
    let mut report = LogoutReport {
        reason: Reason::Ok,
        route,
        logout_status,
        refresh: "no_token",
        cleanup: None,
        clock: logout.as_ref().and_then(ServerClock::of),
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
    report.clock = attempt
        .as_ref()
        .ok()
        .and_then(ServerClock::of)
        .or(report.clock);
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
        Some(refresh) if revoke(http, issuer, &refresh).await.map(|r| r.status) == Some(200) => {
            "revoked"
        }
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
            last_seen_ms: None,
        }
    }

    fn reading(rooms: usize, ids: &[&str]) -> Reading {
        Reading {
            rooms,
            listed: ids.iter().map(|id| device(id)).collect(),
            clock: None,
        }
    }

    /// The time the canary retired its `logged_out` devices at, in these tests.
    const OUT_AT: i64 = 1_800_000_000;

    /// A ledger with these `pending` and `logged_out` ids (the latter retired at
    /// [`OUT_AT`]).
    fn led(pending: &[&str], logged_out: &[&str]) -> Ledger {
        let mut ledger = Ledger {
            pending: pending.iter().map(|s| s.to_string()).collect(),
            ..Ledger::default()
        };
        for id in logged_out {
            ledger.logged_out.insert(id.to_string(), OUT_AT);
        }
        ledger
    }

    fn clean() -> Judgement {
        Judgement {
            fired: false,
            strangers: vec![],
            unfinished: vec![],
            leftovers: vec![],
            survivors: vec![],
            own_guess: None,
        }
    }

    #[test]
    fn only_this_runs_device_is_clean() {
        let j = judge(
            &reading(0, &["SIWX_now"]),
            Some("SIWX_now"),
            &led(&[], &[]),
            0,
        );
        assert_eq!(j, clean());
    }

    #[test]
    fn a_device_nobody_recorded_fires_the_tripwire() {
        let j = judge(
            &reading(0, &["SIWX_now", "ATTACKER"]),
            Some("SIWX_now"),
            &led(&["SIWX_old"], &[]),
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
                &led(&[], &[]),
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
            &led(&["SIWX_old"], &[]),
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
        assert!(!judge(&reading(0, &["SIWX_x"]), None, &led(&[], &[]), 0).fired);
        let j = judge(&reading(0, &["SIWX_x", "SIWX_y"]), None, &led(&[], &[]), 0);
        assert!(j.fired);
        assert_eq!(j.strangers.len(), 2);
    }

    #[test]
    fn an_unrecorded_siwx_device_with_an_unfinished_attempt_is_reported_not_fired() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_killed"]),
            Some("SIWX_now"),
            &led(&[], &[]),
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
            &led(&[], &[]),
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
            &led(&[], &[]),
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
            &led(&[], &[]),
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
            &led(&[], &[]),
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
        Reading {
            rooms,
            listed,
            clock: None,
        }
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
                &led(&[], &[]),
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
            &led(&[], &[]),
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
            &led(&[], &[]),
            2,
        );
        assert!(j.fired);
        assert_eq!(j.strangers.len(), 2, "no part of the doubt is excused");
        assert!(j.unfinished.is_empty());
    }

    #[test]
    fn without_a_whoami_a_stranger_cannot_hide_as_this_runs_device() {
        // One of two unexplained devices is this run's. Both must look like an
        // unfinished sign-in's for the marker to cover the other, unless the
        // listing shows which is this run's.
        let seen = |id: &str, name: Option<&str>| Device {
            seen: true,
            display_name: name.map(str::to_string),
            ..device(id)
        };
        // A seen device that is not the canary's by name could be the stranger,
        // and nothing says it is this run's: it fires.
        let j = judge(
            &reading_of(
                0,
                vec![device("SIWX_a"), seen("SIWX_b", Some("somebody-else"))],
            ),
            None,
            &led(&[], &[]),
            1,
        );
        assert!(j.fired);
        // Two devices that look like this run's (minted, the canary's name, in
        // use): nobody can tell which, and the other one is not an unfinished
        // sign-in's either.
        let j = judge(
            &reading_of(
                0,
                vec![
                    seen("SIWX_a", Some(DEVICE_NAME)),
                    seen("SIWX_b", Some(DEVICE_NAME)),
                ],
            ),
            None,
            &led(&[], &[]),
            1,
        );
        assert!(j.fired);
        assert_eq!(j.own_guess, None);
        let j = judge(&reading(0, &["SIWX_a", "SIWX_b"]), None, &led(&[], &[]), 1);
        assert!(!j.fired);
        assert_eq!(j.unfinished.len(), 2);
        assert_eq!(j.own_guess, None);
    }

    #[test]
    fn without_a_whoami_the_one_device_in_use_is_this_runs_and_the_rest_are_judged_by_the_markers()
    {
        let in_use = Device {
            seen: true,
            ..device("SIWX_now")
        };
        let listed = || vec![device("SIWX_dormant"), in_use.clone()];
        let j = judge(&reading_of(0, listed()), None, &led(&[], &[]), 1);
        assert_eq!(j.own_guess.as_deref(), Some("SIWX_now"));
        assert!(!j.fired, "{j:?}");
        assert_eq!(j.unfinished, vec!["SIWX_dormant".to_string()]);
        // Without a marker the dormant one is a stranger: the guess does not
        // excuse anything.
        let j = judge(&reading_of(0, listed()), None, &led(&[], &[]), 0);
        assert_eq!(j.own_guess.as_deref(), Some("SIWX_now"));
        assert_eq!(j.strangers, vec!["SIWX_dormant".to_string()]);
        // A dormant device that has been seen is no unfinished sign-in's.
        let j = judge(
            &reading_of(
                0,
                vec![
                    Device {
                        seen: true,
                        ..device("SIWX_dormant")
                    },
                    in_use.clone(),
                ],
            ),
            None,
            &led(&[], &[]),
            1,
        );
        assert!(j.fired);
    }

    #[test]
    fn the_excused_devices_are_deleted_only_when_the_run_knows_its_own() {
        let j = judge(
            &reading(0, &["SIWX_a", "SIWX_b"]),
            Some("SIWX_a"),
            &led(&[], &[]),
            1,
        );
        assert_eq!(j.unfinished, vec!["SIWX_b".to_string()]);
        assert_eq!(
            j.deletable_unfinished(Some("SIWX_a")),
            ["SIWX_b".to_string()]
        );
        // Two unexplained, nobody can say which is this run's: one of the
        // excused is its own and must not be deleted with its own token.
        let j = judge(&reading(0, &["SIWX_a", "SIWX_b"]), None, &led(&[], &[]), 1);
        assert_eq!(j.unfinished.len(), 2);
        assert!(j.deletable_unfinished(None).is_empty());
    }

    #[test]
    fn a_server_clock_runs_on_from_the_reply_and_rounds_up() {
        let clock = ServerClock::new(1_800_000_000, Instant::now());
        let now = clock.now();
        assert!((1_800_000_001..=1_800_000_002).contains(&now), "{now}");
        let old = ServerClock::new(1_800_000_000, Instant::now() - Duration::from_secs(90));
        assert!(old.now() >= 1_800_000_091);
    }

    /// A device the canary retired at [`OUT_AT`] and that was last used `ago`
    /// seconds before (negative: after) that time, as the homeserver lists it.
    fn used(id: &str, ago: i64) -> Device {
        Device {
            seen: true,
            last_seen_ms: Some((OUT_AT - ago) * 1000),
            ..device(id)
        }
    }

    #[test]
    fn a_device_whose_logout_was_proven_is_a_survivor_not_a_stranger() {
        let j = judge(
            &reading_of(0, vec![device("SIWX_now"), used("SIWX_before", 5)]),
            Some("SIWX_now"),
            &led(&[], &["SIWX_before"]),
            0,
        );
        assert_eq!(
            j,
            Judgement {
                survivors: vec!["SIWX_before".to_string()],
                ..clean()
            }
        );
        // Never seen in use, or seen within the clock slack past the time: the same.
        for survivor in [
            device("SIWX_before"),
            used("SIWX_before", -(LAST_SEEN_SLACK_SECS)),
        ] {
            let j = judge(
                &reading_of(0, vec![device("SIWX_now"), survivor]),
                Some("SIWX_now"),
                &led(&[], &["SIWX_before"]),
                0,
            );
            assert!(!j.fired);
            assert_eq!(j.survivors, vec!["SIWX_before".to_string()]);
        }
    }

    #[test]
    fn a_retired_id_that_somebody_else_made_or_used_is_a_stranger_not_a_survivor() {
        // siwx-oidc recreates a deleted id for a client that proposes it.
        let strangers = [
            (
                "used after the canary's last use",
                used("SIWX_before", -(LAST_SEEN_SLACK_SECS + 1)),
            ),
            (
                "another client's name",
                Device {
                    display_name: Some("Element Web".to_string()),
                    ..device("SIWX_before")
                },
            ),
            (
                "no name",
                Device {
                    display_name: None,
                    ..device("SIWX_before")
                },
            ),
            (
                "seen at a time nobody can read",
                Device {
                    seen: true,
                    last_seen_ms: None,
                    ..device("SIWX_before")
                },
            ),
        ];
        for (what, stranger) in strangers {
            // With a live marker to hide behind, too: a retired id that fails the
            // check is not a candidate for it either (it is seen, or not the
            // canary's).
            let j = judge(
                &reading_of(0, vec![device("SIWX_now"), stranger]),
                Some("SIWX_now"),
                &led(&[], &["SIWX_before"]),
                3,
            );
            assert!(j.fired, "{what}");
            assert_eq!(j.strangers, vec!["SIWX_before".to_string()], "{what}");
            assert!(j.survivors.is_empty() && j.unfinished.is_empty(), "{what}");
        }
    }

    #[test]
    fn a_device_retired_at_an_unknown_time_passes_only_while_it_was_never_used() {
        let mut ledger = Ledger::default();
        ledger
            .logged_out
            .insert("SIWX_before".to_string(), i64::MIN);
        let judged = |listed: Device| {
            judge(
                &reading_of(0, vec![device("SIWX_now"), listed]),
                Some("SIWX_now"),
                &ledger,
                0,
            )
        };
        assert_eq!(judged(device("SIWX_before")).survivors.len(), 1);
        assert!(judged(used("SIWX_before", 1_000_000)).fired);
    }

    #[test]
    fn a_device_left_on_the_unfinished_list_is_a_leftover_only_while_it_is_never_seen() {
        let mut ledger = Ledger::default();
        ledger.unfinished.insert("SIWX_dormant".to_string());
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_dormant"]),
            Some("SIWX_now"),
            &ledger,
            0,
        );
        assert_eq!(
            j,
            Judgement {
                leftovers: vec!["SIWX_dormant".to_string()],
                ..clean()
            }
        );
        // Seen since: the canary never used its token, so it is not known to be
        // ours.
        let j = judge(
            &reading_of(0, vec![device("SIWX_now"), used("SIWX_dormant", 5)]),
            Some("SIWX_now"),
            &ledger,
            5,
        );
        assert!(j.fired, "a marker does not excuse it either");
        assert_eq!(j.strangers, vec!["SIWX_dormant".to_string()]);
        assert!(j.leftovers.is_empty());
    }

    #[test]
    fn without_a_whoami_the_one_unexplained_device_is_taken_for_this_runs() {
        let j = judge(&reading(0, &["SIWX_x"]), None, &led(&[], &[]), 0);
        assert_eq!(j.own_guess.as_deref(), Some("SIWX_x"));
        // With a whoami, or with two to choose from, nothing is guessed.
        let j = judge(&reading(0, &["SIWX_x"]), Some("SIWX_x"), &led(&[], &[]), 0);
        assert_eq!(j.own_guess, None);
        let j = judge(&reading(0, &["SIWX_x", "SIWX_y"]), None, &led(&[], &[]), 1);
        assert_eq!(j.own_guess, None);
        // A device the ledger knows is not a candidate.
        let j = judge(
            &reading(0, &["SIWX_x", "SIWX_old"]),
            None,
            &led(&["SIWX_old"], &[]),
            0,
        );
        assert_eq!(j.own_guess.as_deref(), Some("SIWX_x"));
    }

    // -- the ledger after a run ----------------------------------------------

    const NOW: i64 = OUT_AT + 600;

    fn closing<'a>(
        reading: &'a Reading,
        judged: &'a Judgement,
        cleaned: &'a BTreeSet<String>,
        own: Option<&'a str>,
        logout_proven: bool,
    ) -> Closing<'a> {
        Closing {
            reading,
            judged,
            cleaned,
            own,
            logout_proven,
            attempt_id: "this-run",
            now: Some(NOW),
        }
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn marker(id: &str) -> crate::identity::Attempt {
        crate::identity::Attempt {
            id: id.to_string(),
            at: NOW,
        }
    }

    #[test]
    fn a_device_leaves_the_ledger_only_when_the_reading_shows_it_gone() {
        let mut ledger = led(
            &["SIWX_p", "SIWX_p_cleaned", "SIWX_gone"],
            &["SIWX_l", "SIWX_l_cleaned"],
        );
        ledger.unfinished = set(&["SIWX_u", "SIWX_u_gone"]);
        let r = reading(
            0,
            &[
                "SIWX_now",
                "SIWX_p",
                "SIWX_p_cleaned",
                "SIWX_l",
                "SIWX_l_cleaned",
                "SIWX_u",
            ],
        );
        let j = judge(&r, Some("SIWX_now"), &ledger, 0);
        let cleaned = set(&["SIWX_p_cleaned", "SIWX_l_cleaned"]);
        let next = closing(&r, &j, &cleaned, Some("SIWX_now"), true).next(&ledger);
        assert_eq!(next.pending, set(&["SIWX_p"]));
        assert_eq!(next.unfinished, set(&["SIWX_u"]));
        assert_eq!(
            next.logged_out.ids(),
            set(&["SIWX_l", "SIWX_l_cleaned", "SIWX_p_cleaned", "SIWX_now"]),
            "a delete the server answered 200 is not a delete"
        );
        assert_eq!(
            next.logged_out.at("SIWX_l"),
            Some(OUT_AT),
            "a stuck one keeps its time"
        );
        assert_eq!(
            next.logged_out.at("SIWX_l_cleaned"),
            Some(OUT_AT),
            "so does a survivor the run deleted: the canary never used its token"
        );
        assert_eq!(next.logged_out.at("SIWX_p_cleaned"), Some(NOW));
        assert_eq!(next.logged_out.at("SIWX_now"), Some(NOW));
    }

    #[test]
    fn a_deleted_leftover_waits_on_the_logged_out_list_not_the_pending_one() {
        let ledger = led(&["SIWX_old"], &[]);
        let r = reading(0, &["SIWX_now", "SIWX_old"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 0);
        let cleaned = set(&["SIWX_old"]);
        let next = closing(&r, &j, &cleaned, Some("SIWX_now"), false).next(&ledger);
        assert_eq!(next.logged_out.ids(), set(&["SIWX_old"]));
        assert_eq!(
            next.pending,
            set(&["SIWX_now"]),
            "this run's own stays where an unproven logout may leave it"
        );
    }

    #[test]
    fn excused_devices_are_recorded_as_unfinished_and_the_markers_are_spent() {
        let ledger = Ledger {
            attempts: vec![marker("earlier"), marker("this-run")],
            ..Ledger::default()
        };
        let r = reading(0, &["SIWX_now", "SIWX_dormant"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 1);
        assert_eq!(j.unfinished, vec!["SIWX_dormant".to_string()]);
        let next = closing(&r, &j, &BTreeSet::new(), Some("SIWX_now"), true).next(&ledger);
        assert_eq!(next.unfinished, set(&["SIWX_dormant"]));
        assert!(next.pending.is_empty());
        assert!(next.attempts.is_empty());
    }

    #[test]
    fn an_excused_device_the_run_deleted_waits_on_logged_out_at_a_time_unknown() {
        use crate::identity::TIME_UNKNOWN;
        let ledger = Ledger {
            attempts: vec![marker("earlier"), marker("this-run")],
            ..Ledger::default()
        };
        let r = reading(0, &["SIWX_now", "SIWX_dormant"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 1);
        let cleaned = set(&["SIWX_dormant"]);
        let next = closing(&r, &j, &cleaned, Some("SIWX_now"), true).next(&ledger);
        assert!(next.unfinished.is_empty(), "deleted, not left excused");
        assert!(next.attempts.is_empty(), "the marker is spent");
        // The canary never used it: a device on that id passes as the canary's
        // own only while nobody has used it.
        assert_eq!(next.logged_out.at("SIWX_dormant"), Some(TIME_UNKNOWN));
        assert_eq!(next.logged_out.at("SIWX_now"), Some(NOW));
        // A delete that did not go through keeps it on the unfinished list.
        let next = closing(&r, &j, &BTreeSet::new(), Some("SIWX_now"), true).next(&ledger);
        assert_eq!(next.unfinished, set(&["SIWX_dormant"]));
    }

    #[test]
    fn a_device_cleaned_from_the_unfinished_list_is_not_retired_at_the_current_time() {
        use crate::identity::TIME_UNKNOWN;
        let mut ledger = led(&["SIWX_gone_with_run"], &[]);
        ledger.unfinished.insert("SIWX_old".to_string());
        let r = reading(0, &["SIWX_now", "SIWX_old", "SIWX_gone_with_run"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 0);
        assert_eq!(j.leftovers.len(), 2);
        let cleaned = set(&["SIWX_old", "SIWX_gone_with_run"]);
        let next = closing(&r, &j, &cleaned, Some("SIWX_now"), true).next(&ledger);
        assert_eq!(next.logged_out.at("SIWX_old"), Some(TIME_UNKNOWN));
        // A leftover of a run that used the device is retired when it is deleted.
        assert_eq!(next.logged_out.at("SIWX_gone_with_run"), Some(NOW));
    }

    #[test]
    fn without_a_server_clock_every_retired_device_is_recorded_at_a_time_unknown() {
        use crate::identity::TIME_UNKNOWN;
        let ledger = led(&["SIWX_left"], &[]);
        let r = reading(0, &["SIWX_now", "SIWX_left"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 0);
        let cleaned = set(&["SIWX_left"]);
        let mut close = closing(&r, &j, &cleaned, Some("SIWX_now"), true);
        close.now = None;
        let next = close.next(&ledger);
        assert_eq!(next.logged_out.at("SIWX_left"), Some(TIME_UNKNOWN));
        assert_eq!(next.logged_out.at("SIWX_now"), Some(TIME_UNKNOWN));
    }

    #[test]
    fn a_fired_tripwire_records_and_spends_nothing_it_excused() {
        // A joined room fires it, and a marker would excuse the dormant device.
        let ledger = Ledger {
            attempts: vec![marker("earlier")],
            ..Ledger::default()
        };
        let r = reading(1, &["SIWX_now", "SIWX_dormant"]);
        let j = judge(&r, Some("SIWX_now"), &ledger, 1);
        assert!(j.fired);
        assert_eq!(j.unfinished, vec!["SIWX_dormant".to_string()]);
        let next = closing(&r, &j, &BTreeSet::new(), Some("SIWX_now"), true).next(&ledger);
        assert!(next.unfinished.is_empty() && next.pending.is_empty());
        assert_eq!(
            next.attempts, ledger.attempts,
            "the marker stays as evidence"
        );
    }

    #[test]
    fn the_guessed_device_is_recorded_like_a_named_one_and_spends_this_runs_marker() {
        let ledger = Ledger {
            attempts: vec![marker("this-run")],
            ..Ledger::default()
        };
        let r = reading(0, &["SIWX_x"]);
        let j = judge(&r, None, &ledger, 0);
        let none = BTreeSet::new();
        let next = closing(&r, &j, &none, None, true).next(&ledger);
        assert_eq!(next.logged_out.ids(), set(&["SIWX_x"]));
        assert!(next.attempts.is_empty());
        let next = closing(&r, &j, &none, None, false).next(&ledger);
        assert_eq!(next.pending, set(&["SIWX_x"]));

        // Nothing to guess (no device listed): the marker stays for a later run.
        let r = reading(0, &[]);
        let j = judge(&r, None, &ledger, 0);
        let next = closing(&r, &j, &none, None, true).next(&ledger);
        assert_eq!(next.attempts, ledger.attempts);
    }

    #[test]
    fn a_survivor_does_not_excuse_a_stranger_beside_it() {
        let j = judge(
            &reading(0, &["SIWX_now", "SIWX_before", "ATTACKER"]),
            Some("SIWX_now"),
            &led(&[], &["SIWX_before"]),
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
