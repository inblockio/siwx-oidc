//! Directory lookups for services: "whom may this person find under this
//! name?", answered the way Element would answer it, with a verified DID for
//! each person who has one.
//!
//! Plan: `docs/directory.md` (contract, caching, revocation). This module is the
//! Rust client of that contract; the TypeScript package runs the same vectors
//! (`tests/vectors/directory/`).
//!
//! # Two transports, one result
//!
//! - [`DirectoryClient::search_for_asker`]: a service that is not the asker.
//!   It signs in with **its own key** ([`ServiceSession`]), no shared secret,
//!   resolves the asker's DID to an MXID at siwx-oidc (`GET /resolve`), and asks
//!   the homeserver's directory module to search *as that asker*, so the answer
//!   is exactly what the asker would see in Element.
//! - [`DirectoryClient::search_as_user`]: an app that holds the user's own
//!   Matrix session. Synapse's standard `user_directory/search` with the user's
//!   token, then each hit's `io.inblock.did` profile field, read without a
//!   credential.
//!
//! Both end in the same proof check and the same [`DirectoryResults`].
//!
//! # What "verified" means
//!
//! A [`DidState::Verified`] DID is the `sub` of a proof that verified against the
//! issuer's keys and named **this** hit's MXID: the rules of
//! [`crate::verify_did_assertion`], run against keys fetched once and cached. The
//! unsigned `did` member next to the proof is never read. Like every published
//! DID it is a discovery hint, not an authorization source (see
//! [`crate::did_assertion`]): it fills a recipient field, and the grant that
//! follows is a fresh signature by the DID's key.
//!
//! The result types derive `Serialize` and not `Deserialize`, for the reason
//! [`crate::VerifiedDid`] does: a deserializable "verified" value is an entrance
//! that skips the check. A `Verified` state can only be made by this module.
//!
//! # Errors
//!
//! An answer that could not be checked is an error, never a state: a network,
//! discovery or key-set failure fails the whole search with a retryable
//! [`DirectoryError`] and nothing of it is stored. Only a proof that was read
//! and does not verify is `invalid`.
//!
//! # Secrets
//!
//! Tokens are held in memory only. Nothing here writes a file or prints a line,
//! the types that hold a credential print none, and after a restart the service
//! signs in again with its key. (`the_module_touches_no_file_and_prints_nothing`
//! scans this file for it.)

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;
use url::Url;

use crate::did_assertion::{
    fetch_issuer_keys, parse_proof, read_at_most, verify_parsed, BodyTooLarge, IssuerKeys,
    DEFAULT_BODY_CAP, DID_PROFILE_FIELD,
};
use crate::{
    authenticate_with_device, refresh, AuthError, SiwxKey, TOKEN_LIFETIME_DEFAULT_SECS,
    TOKEN_LIFETIME_MAX_SECS, TOKEN_LIFETIME_MIN_SECS,
};

/// The shortest and longest search term, in characters after trimming.
const TERM_MIN: usize = 1;
const TERM_MAX: usize = 64;
/// The largest number of rows one search may ask for.
const LIMIT_MAX: u32 = 20;
/// Profile reads in flight at once on the user transport.
const PROFILE_READS_AT_ONCE: usize = 8;

// ---------------------------------------------------------------------------
// The result (plan 4.1)
// ---------------------------------------------------------------------------

/// The people a search found, in the order the homeserver gave them.
///
/// Serializes as `{"results": [...], "limited": bool}`. `limited` is true when
/// the homeserver says more people matched than it returned, or when this
/// client cut the answer to the `limit` that was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryResults {
    pub results: Vec<DirectoryEntry>,
    pub limited: bool,
}

impl DirectoryResults {
    fn empty() -> Self {
        DirectoryResults {
            results: Vec::new(),
            limited: false,
        }
    }
}

/// One person: the MXID, the label they chose, and what is known of their DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryEntry {
    /// `@localpart:server`. The key of the entry; the alias is not.
    pub mxid: String,
    /// The Matrix display name. A search term and a label, never a key; absent
    /// when the person set none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub did: DidState,
}

/// What is known of one person's DID. Serializes as
/// `{"state":"verified","value":"did:..."}`, `{"state":"not_yet_published"}` or
/// `{"state":"invalid"}`. Only `Verified` can be picked as a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum DidState {
    /// A proof from this issuer verified and names this MXID. The value is the
    /// proof's signed `sub`.
    Verified(VerifiedSubject),
    /// No proof from this issuer: the person has no `io.inblock.did` field, the
    /// field has no proof, or the person is on another homeserver.
    NotYetPublished,
    /// A proof is there and does not verify.
    Invalid,
}

impl DidState {
    /// The DID of a `Verified` state; `None` for the other two.
    pub fn verified_did(&self) -> Option<&str> {
        match self {
            DidState::Verified(subject) => Some(&subject.0),
            DidState::NotYetPublished | DidState::Invalid => None,
        }
    }
}

/// The signed `sub` of a verified proof. The field is private and nothing
/// outside this module can construct one, so holding one means a check passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct VerifiedSubject(String);

impl VerifiedSubject {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a search or a sign-in did not produce an answer.
///
/// The messages carry statuses and error codes. They never carry the search
/// term, a token, or a response body.
#[derive(Debug)]
#[non_exhaustive]
pub enum DirectoryError {
    /// The input was refused before any request was made (a term or limit out of
    /// bounds, an empty asker or token, a session of another deployment).
    InvalidInput(String),
    /// The homeserver refused this service: it is not in the module's admitted
    /// services, or its account is locked or deactivated. Not retryable.
    NotAdmitted,
    /// 429. `retry_after` is the server's hint when it gave one.
    RateLimited { retry_after: Option<Duration> },
    /// The token was refused, and (for the service transport) a fresh sign-in
    /// did not help. For `search_as_user`, the user's token is stale.
    Unauthorized,
    /// The service could not sign in. See [`DirectoryError::is_retryable`]. A
    /// refusal the server made is an [`AuthError`] in `source`; a client id the
    /// server does not know is [`DirectoryError::is_unknown_client`].
    SignIn { source: anyhow::Error },
    /// A network, timeout, discovery, key-set or 5xx failure: the state is
    /// unknown, try again later.
    Unavailable(String),
    /// A status this client does not act on, with the homeserver's `errcode`
    /// when it sent a well-formed one.
    UnexpectedStatus {
        status: u16,
        errcode: Option<String>,
    },
    /// An answer that is not what the contract says (malformed JSON, a row
    /// without a user id, a success body over the size cap).
    Protocol(String),
}

impl DirectoryError {
    /// Whether the service could not sign in because the server does not know its
    /// client id: a dynamic client lapses after 30 days without a use (see
    /// [`register_public_client`]). The remedy is to register again and keep the
    /// new id, not to retry, so this is never [`is_retryable`](Self::is_retryable).
    /// Match this (or [`AuthError::UnknownClient`] in the `source`), not the text.
    pub fn is_unknown_client(&self) -> bool {
        match self {
            DirectoryError::SignIn { source } => crate::is_unknown_client(source),
            _ => false,
        }
    }

    /// Whether the call was rate limited: a 429 from the homeserver
    /// ([`DirectoryError::RateLimited`]) or from the sign-in
    /// ([`AuthError::RateLimited`] in the `source` of a
    /// [`DirectoryError::SignIn`]). It is retryable after
    /// [`retry_after`](Self::retry_after), when there is one. Match this, not
    /// the text.
    pub fn is_rate_limited(&self) -> bool {
        match self {
            DirectoryError::RateLimited { .. } => true,
            DirectoryError::SignIn { source } => crate::is_rate_limited(source),
            _ => false,
        }
    }

    /// The wait the server asked for, when the call was rate limited (see
    /// [`is_rate_limited`](Self::is_rate_limited)) and it named one: at most
    /// [`RETRY_AFTER_MAX`](crate::RETRY_AFTER_MAX). `None` otherwise, and the
    /// caller picks its own backoff.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            DirectoryError::RateLimited { retry_after } => *retry_after,
            DirectoryError::SignIn { source } => source
                .downcast_ref::<AuthError>()
                .and_then(AuthError::retry_after),
            _ => None,
        }
    }

    /// Whether the same call may succeed later without a change on the caller's
    /// side. A sign-in is retryable unless the server refused the account
    /// (`access_denied`), the device id (`invalid_scope`) or the request for
    /// another reason; a rate limit at the sign-in is retryable after its hint;
    /// an untyped sign-in fault (a network error) is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            DirectoryError::RateLimited { .. } | DirectoryError::Unavailable(_) => true,
            DirectoryError::SignIn { source } => match source.downcast_ref::<AuthError>() {
                Some(typed) => typed.is_transient(),
                None => true,
            },
            DirectoryError::InvalidInput(_)
            | DirectoryError::NotAdmitted
            | DirectoryError::Unauthorized
            | DirectoryError::UnexpectedStatus { .. }
            | DirectoryError::Protocol(_) => false,
        }
    }
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::InvalidInput(why) => write!(f, "invalid input: {why}"),
            DirectoryError::NotAdmitted => {
                write!(
                    f,
                    "the homeserver does not admit this service to the directory"
                )
            }
            DirectoryError::RateLimited {
                retry_after: Some(after),
            } => write!(f, "rate limited, retry after {} ms", after.as_millis()),
            DirectoryError::RateLimited { retry_after: None } => write!(f, "rate limited"),
            DirectoryError::Unauthorized => write!(f, "the access token was refused"),
            DirectoryError::SignIn { source } => write!(f, "service sign-in failed: {source:#}"),
            DirectoryError::Unavailable(why) => write!(f, "directory unavailable: {why}"),
            DirectoryError::UnexpectedStatus {
                status,
                errcode: Some(code),
            } => write!(f, "unexpected status {status} ({code})"),
            DirectoryError::UnexpectedStatus {
                status,
                errcode: None,
            } => write!(f, "unexpected status {status}"),
            DirectoryError::Protocol(why) => write!(f, "unexpected answer: {why}"),
        }
    }
}

impl std::error::Error for DirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DirectoryError::SignIn { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Time and limits
// ---------------------------------------------------------------------------

/// Where "now" comes from. The system clock unless a test says otherwise: the
/// cache and token lifetimes are measured against it, so a test moves it by
/// hand instead of sleeping.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> Instant + Send + Sync>);

impl Clock {
    pub fn system() -> Self {
        Clock(Arc::new(Instant::now))
    }

    pub fn new(now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Clock(Arc::new(now))
    }

    fn now(&self) -> Instant {
        (self.0)()
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

/// Every lifetime and size bound in one place. The defaults are the contract
/// (plan 4.3); a service has no reason to change them, and the fields are open
/// so a test can.
#[derive(Debug, Clone)]
pub struct Tuning {
    /// Per request, connect to the last byte of the body.
    pub request_timeout: Duration,
    /// The whole headless sign-in, which is several requests.
    pub sign_in_timeout: Duration,
    /// A token is renewed this long before it expires (at most half its life).
    pub token_refresh_margin: Duration,
    /// How long an asker's DID to MXID mapping is kept once found.
    pub resolve_hit_ttl: Duration,
    /// How long "no such account" is kept, so a new account is found soon.
    pub resolve_miss_ttl: Duration,
    /// How long a failed sign-in is answered with the same failure before the
    /// service tries again. Callers that wait for an attempt share its outcome
    /// whatever this is; it bounds how often a service hammers an issuer that is
    /// down. Zero tries on every call that finds the token stale.
    pub failed_sign_in_cooldown: Duration,
    /// How long discovery and the key set are kept.
    pub keys_ttl: Duration,
    /// The least time between two fetches of the key set when a proof names a
    /// `kid` the cached set lacks. A rotation is picked up at once; a stream of
    /// proofs with made-up kids costs the issuer one fetch per interval.
    pub keys_refetch_interval: Duration,
    /// How long a verified `(mxid, proof)` is kept. A key dropped from the key
    /// set stops verifying within `keys_ttl` plus this time.
    pub verified_ttl: Duration,
    /// The most entries each cache holds.
    pub max_cache_entries: usize,
    /// The most bytes of any one response body.
    pub max_body_bytes: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            request_timeout: Duration::from_secs(5),
            sign_in_timeout: Duration::from_secs(30),
            token_refresh_margin: Duration::from_secs(30),
            resolve_hit_ttl: Duration::from_secs(10 * 60),
            resolve_miss_ttl: Duration::from_secs(60),
            failed_sign_in_cooldown: Duration::from_secs(5),
            keys_ttl: Duration::from_secs(5 * 60),
            keys_refetch_interval: Duration::from_secs(30),
            verified_ttl: Duration::from_secs(10 * 60),
            max_cache_entries: 4096,
            max_body_bytes: DEFAULT_BODY_CAP,
        }
    }
}

// ---------------------------------------------------------------------------
// Input checks
// ---------------------------------------------------------------------------

fn invalid(why: impl Into<String>) -> DirectoryError {
    DirectoryError::InvalidInput(why.into())
}

/// What the directory module trims from a term: Python's `str.strip()`, which
/// removes every character `str.isspace()` accepts. That is Rust's whitespace
/// and the four information separators U+001C to U+001F, which Python counts as
/// whitespace and Rust does not.
fn module_trims(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The term as it goes out, held to the module's rules so that a term it would
/// answer with a 400 never costs a request: trimmed as the module trims, then 1
/// to 64 characters (not bytes) and no control character (Unicode category Cc)
/// anywhere. The module strips first and checks after, so a control character
/// that is whitespace at an end is trimmed and one that is not is refused.
fn check_term(term: &str) -> Result<&str, DirectoryError> {
    let term = term.trim_matches(module_trims);
    let n = term.chars().count();
    if !(TERM_MIN..=TERM_MAX).contains(&n) || term.chars().any(char::is_control) {
        return Err(invalid(format!(
            "the search term must be {TERM_MIN} to {TERM_MAX} characters after trimming, \
             without control characters"
        )));
    }
    Ok(term)
}

fn check_limit(limit: u32) -> Result<(), DirectoryError> {
    if !(1..=LIMIT_MAX).contains(&limit) {
        return Err(invalid(format!("the limit must be 1 to {LIMIT_MAX}")));
    }
    Ok(())
}

/// A DID is at most 2048 bytes (the `/resolve` bound) and has no control
/// characters.
fn check_asker(did: &str) -> Result<(), DirectoryError> {
    if did.is_empty() || did.len() > 2048 || did.chars().any(char::is_control) {
        return Err(invalid(
            "the asker DID is empty, too long, or not printable",
        ));
    }
    Ok(())
}

/// A bearer token is visible ASCII only, so it can never reshape a header.
fn check_token(token: &str) -> Result<(), DirectoryError> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid("the access token is empty or not a bearer token"));
    }
    Ok(())
}

/// A base URL as a service configures it: http(s), a host, no credentials, no
/// query, no fragment, and no trailing slash.
fn clean_base(what: &str, raw: &str) -> Result<String, DirectoryError> {
    let url = Url::parse(raw).map_err(|_| invalid(format!("{what} is not a URL")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(invalid(format!(
            "{what} must be an http(s) URL with a host"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(format!(
            "{what} must not carry credentials, a query or a fragment"
        )));
    }
    Ok(raw.trim_end_matches('/').to_string())
}

fn is_mxid(s: &str) -> bool {
    s.strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(local, server)| !local.is_empty() && !server.is_empty())
}

fn http_client(tuning: &Tuning) -> Result<reqwest::Client, DirectoryError> {
    reqwest::Client::builder()
        .timeout(tuning.request_timeout)
        // A redirect would carry a bearer token to wherever it points.
        .redirect(Policy::none())
        .build()
        .map_err(|e| invalid(format!("the HTTP client could not be built: {e}")))
}

// ---------------------------------------------------------------------------
// Client registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Register a public OIDC client at siwx-oidc and return its `client_id`.
///
/// A service does this once, before its first sign-in, and keeps the id. The
/// client is public (`token_endpoint_auth_method: "none"`): the service proves
/// itself with its key, not with a secret, so the `client_secret` and the
/// `registration_access_token` the server also returns are dropped here without
/// being read. The redirect URI must be registered but nothing listens on it.
///
/// A dynamic client lapses after 30 days without a use, so a service that is
/// refused as an unknown client registers again; every sign-in renews it.
pub async fn register_public_client(
    issuer_url: &str,
    redirect_uri: &str,
    client_name: &str,
) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Registered {
        client_id: String,
    }

    let tuning = Tuning::default();
    let base = clean_base("issuer_url", issuer_url)?;
    let resp = http_client(&tuning)?
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [redirect_uri],
            "client_name": client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }))
        .send()
        .await
        .map_err(|e| {
            anyhow!(
                "OIDC client registration request failed: {}",
                e.without_url()
            )
        })?;

    let status = resp.status();
    // An error answer counts by its status even when its body is over the cap.
    let body = read_at_most(resp, tuning.max_body_bytes).await?;
    if !status.is_success() {
        let code = body
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| short_code(v.get("error")?.as_str()?));
        return Err(match code {
            Some(code) => anyhow!("OIDC registration returned {status} ({code})"),
            None => anyhow!("OIDC registration returned {status}"),
        });
    }
    let body = body.ok_or(BodyTooLarge {
        cap: tuning.max_body_bytes,
    })?;
    let registered: Registered = serde_json::from_slice(&body)
        .map_err(|_| anyhow!("the OIDC registration answer has no client_id"))?;
    if registered.client_id.is_empty() {
        return Err(anyhow!(
            "the OIDC registration answer has an empty client_id"
        ));
    }
    Ok(registered.client_id)
}

/// An error code from a server, if it looks like one: short, and only the
/// characters of the OAuth and Matrix error vocabularies.
pub(crate) fn short_code(s: &str) -> Option<String> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    ok.then(|| s.to_string())
}

// ---------------------------------------------------------------------------
// The service's own session
// ---------------------------------------------------------------------------

/// What a [`ServiceSession`] is made from.
#[non_exhaustive]
pub struct ServiceSessionConfig {
    /// The siwx-oidc base URL (the trust anchor for every proof too).
    pub issuer_url: String,
    /// The homeserver's client-API base URL.
    pub homeserver_url: String,
    /// The public client from [`register_public_client`].
    pub client_id: String,
    /// The redirect URI the client was registered with.
    pub redirect_uri: String,
    /// The Matrix device id the service signs in on, fixed so a restart reuses
    /// one device instead of leaving a new one behind each time.
    pub device_id: String,
    /// The service's own key. Its DID is the service's Matrix account.
    pub key: SiwxKey,
    pub tuning: Tuning,
    pub clock: Clock,
}

impl ServiceSessionConfig {
    pub fn new(
        issuer_url: impl Into<String>,
        homeserver_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        device_id: impl Into<String>,
        key: SiwxKey,
    ) -> Self {
        ServiceSessionConfig {
            issuer_url: issuer_url.into(),
            homeserver_url: homeserver_url.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            device_id: device_id.into(),
            key,
            tuning: Tuning::default(),
            clock: Clock::system(),
        }
    }

    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }
}

impl fmt::Debug for ServiceSessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is not printed, only the public DID it stands for.
        f.debug_struct("ServiceSessionConfig")
            .field("issuer_url", &self.issuer_url)
            .field("homeserver_url", &self.homeserver_url)
            .field("client_id", &self.client_id)
            .field("device_id", &self.device_id)
            .field("did", &self.key.did())
            .finish_non_exhaustive()
    }
}

/// The service signed in with its own key.
///
/// [`access_token`](Self::access_token) is the one call a user of this type
/// makes: it returns a token that is good now, renewing it first when it is
/// about to expire. Renewal is single flight: callers that arrive while an
/// attempt is running wait for it and share its outcome, a failure as much as a
/// success, so k callers behind a hanging issuer wait for one timeout, not k. A
/// failed attempt is answered again, without a request, for
/// [`Tuning::failed_sign_in_cooldown`]; after that the next call tries. An
/// attempt tries the refresh token first, and signs in again with the key when
/// that fails.
///
/// Tokens live in this struct's memory and nowhere else: not on disk, not in a
/// log, not in `Debug` output. On a restart the service signs in again; there is
/// no long-lived refresh token to protect at rest.
pub struct ServiceSession {
    issuer_url: String,
    homeserver_url: String,
    client_id: String,
    redirect_uri: String,
    device_id: String,
    key: SiwxKey,
    did: String,
    tuning: Tuning,
    clock: Clock,
    tokens: AsyncMutex<Tokens>,
    /// Renewal attempts that have finished. Kept outside the lock, so that a
    /// caller can read it before it waits and tell, once it holds the lock,
    /// whether an attempt finished in between: that attempt's outcome is its
    /// own.
    settled: AtomicU64,
}

#[derive(Default)]
struct Tokens {
    access: Option<String>,
    refresh: Option<String>,
    /// From here on the access token is renewed.
    renew_at: Option<Instant>,
    /// The latest attempt, when it failed, and when it ended. A success clears it.
    failed: Option<(Instant, Fault)>,
}

/// A failed sign-in, kept to answer every caller that waited for the attempt.
/// [`DirectoryError`] cannot be cloned (its `source` is an `anyhow::Error`), so
/// what the failure said is kept: the server's typed refusal when there was one,
/// and the text.
#[derive(Clone)]
struct Fault {
    typed: Option<AuthError>,
    text: String,
}

impl Fault {
    fn of(source: &anyhow::Error) -> Fault {
        Fault {
            typed: source.downcast_ref::<AuthError>().cloned(),
            text: format!("{source:#}"),
        }
    }

    fn error(&self) -> DirectoryError {
        DirectoryError::SignIn {
            source: match &self.typed {
                Some(typed) => anyhow::Error::new(typed.clone()),
                None => anyhow!("{}", self.text),
            },
        }
    }
}

impl ServiceSession {
    pub fn new(config: ServiceSessionConfig) -> Result<Self, DirectoryError> {
        let ServiceSessionConfig {
            issuer_url,
            homeserver_url,
            client_id,
            redirect_uri,
            device_id,
            key,
            tuning,
            clock,
        } = config;
        if client_id.is_empty() || redirect_uri.is_empty() || device_id.is_empty() {
            return Err(invalid(
                "client_id, redirect_uri and device_id are required",
            ));
        }
        let did = key.did();
        Ok(ServiceSession {
            issuer_url: clean_base("issuer_url", &issuer_url)?,
            homeserver_url: clean_base("homeserver_url", &homeserver_url)?,
            client_id,
            redirect_uri,
            device_id,
            key,
            did,
            tuning,
            clock,
            tokens: AsyncMutex::new(Tokens::default()),
            settled: AtomicU64::new(0),
        })
    }

    /// The service's DID (public).
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// A token that is good now. Signs in on the first call. Never log it.
    pub async fn access_token(&self) -> Result<String, DirectoryError> {
        self.token(None).await
    }

    /// The token to use after the homeserver refused `rejected`. If another
    /// caller already replaced it, theirs; otherwise a fresh sign-in with the
    /// key (a refused access token says nothing good of its refresh token).
    pub(crate) async fn token_after_rejection(
        &self,
        rejected: &str,
    ) -> Result<String, DirectoryError> {
        self.token(Some(rejected)).await
    }

    /// One call for both: a token that is good now, or after `rejected` was
    /// refused. At most one attempt runs; a caller that waited for it takes its
    /// outcome, and one that comes just after a failure takes the failure until
    /// the cooldown has passed.
    async fn token(&self, rejected: Option<&str>) -> Result<String, DirectoryError> {
        let seen = self.settled.load(Ordering::SeqCst);
        let mut tokens = self.tokens.lock().await;
        if rejected.is_none() || tokens.access.as_deref() != rejected {
            if let Some(token) = self.fresh(&tokens) {
                return Ok(token);
            }
        }
        if self.settled.load(Ordering::SeqCst) != seen {
            // An attempt ended while this caller waited: its outcome is the answer.
            match (&tokens.failed, &tokens.access) {
                (Some((_, fault)), _) => return Err(fault.error()),
                (None, Some(token)) => return Ok(token.clone()),
                (None, None) => {}
            }
        }
        if let Some((at, fault)) = &tokens.failed {
            let cooling = at
                .checked_add(self.tuning.failed_sign_in_cooldown)
                .is_none_or(|until| self.clock.now() < until);
            if cooling {
                return Err(fault.error());
            }
        }

        let attempt = match rejected {
            None => self.renew(&mut tokens).await,
            Some(_) => {
                tokens.refresh = None;
                self.sign_in(&mut tokens).await
            }
        };
        self.settled.fetch_add(1, Ordering::SeqCst);
        match attempt {
            Ok(token) => {
                tokens.failed = None;
                Ok(token)
            }
            Err(fault) => {
                let error = fault.error();
                tokens.failed = Some((self.clock.now(), fault));
                Err(error)
            }
        }
    }

    fn fresh(&self, tokens: &Tokens) -> Option<String> {
        let token = tokens.access.as_ref()?;
        (self.clock.now() < tokens.renew_at?).then(|| token.clone())
    }

    async fn renew(&self, tokens: &mut Tokens) -> Result<String, Fault> {
        // A refresh token is single use: it is taken, and replaced by the answer.
        if let Some(refresh_token) = tokens.refresh.take() {
            let attempt = tokio::time::timeout(
                self.tuning.request_timeout,
                refresh(&self.issuer_url, &self.client_id, &refresh_token, &self.did),
            )
            .await;
            if let Ok(Ok(issued)) = attempt {
                return Ok(self.keep(tokens, issued));
            }
        }
        self.sign_in(tokens).await
    }

    async fn sign_in(&self, tokens: &mut Tokens) -> Result<String, Fault> {
        let attempt = tokio::time::timeout(
            self.tuning.sign_in_timeout,
            authenticate_with_device(
                &self.issuer_url,
                &self.client_id,
                &self.redirect_uri,
                &self.key,
                Some(&self.device_id),
            ),
        )
        .await;
        match attempt {
            Ok(Ok(issued)) => Ok(self.keep(tokens, issued)),
            Ok(Err(source)) => Err(Fault::of(&source)),
            Err(_) => Err(Fault::of(&anyhow!(
                "the sign-in did not finish within {:?}",
                self.tuning.sign_in_timeout
            ))),
        }
    }

    /// Keep the new pair. The tokens are stored before anything is computed from
    /// the lifetime, so no `expires_in` can lose them (the refresh token was
    /// already taken to get them); a lifetime is held between
    /// [`TOKEN_LIFETIME_MIN_SECS`] and [`TOKEN_LIFETIME_MAX_SECS`] (the flows
    /// already do that; a caller-built `AuthTokens` may not), none is
    /// [`TOKEN_LIFETIME_DEFAULT_SECS`], and a deadline the clock cannot
    /// represent is "renew on the next call".
    fn keep(&self, tokens: &mut Tokens, issued: crate::AuthTokens) -> String {
        tokens.access = Some(issued.access_token.clone());
        tokens.refresh = issued.refresh_token;
        let life = Duration::from_secs(
            issued
                .expires_in
                .unwrap_or(TOKEN_LIFETIME_DEFAULT_SECS)
                .clamp(TOKEN_LIFETIME_MIN_SECS, TOKEN_LIFETIME_MAX_SECS),
        );
        let margin = self.tuning.token_refresh_margin.min(life / 2);
        let now = self.clock.now();
        tokens.renew_at = Some(now.checked_add(life - margin).unwrap_or(now));
        issued.access_token
    }
}

impl fmt::Debug for ServiceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No token, no key: the DID and the names that identify the deployment.
        f.debug_struct("ServiceSession")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("device_id", &self.device_id)
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Caches
// ---------------------------------------------------------------------------

/// A map whose entries expire and whose size is bounded. When it is full, the
/// expired entries go first, then the ones that would expire soonest.
struct TtlCache<K, V> {
    entries: HashMap<K, (V, Instant)>,
}

impl<K: Hash + Eq + Clone, V: Clone> TtlCache<K, V> {
    fn new() -> Self {
        TtlCache {
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: &K, now: Instant) -> Option<V> {
        match self.entries.get(key) {
            Some((value, expires)) if now < *expires => Some(value.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, key: K, value: V, now: Instant, ttl: Duration, cap: usize) {
        if cap == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= cap {
            self.entries.retain(|_, (_, expires)| now < *expires);
            while self.entries.len() >= cap {
                let soonest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, expires))| *expires)
                    .map(|(k, _)| k.clone());
                match soonest {
                    Some(k) => self.entries.remove(&k),
                    None => break,
                };
            }
        }
        self.entries.insert(key, (value, now + ttl));
    }

    fn live(&mut self, now: Instant) -> usize {
        self.entries.retain(|_, (_, expires)| now < *expires);
        self.entries.len()
    }
}

struct Caches {
    /// Asker DID to the MXID it resolves to; `None` is "no such account".
    resolved: TtlCache<String, Option<String>>,
    /// `(mxid, proof)` to the verified `sub`.
    verified: TtlCache<(String, String), String>,
    keys: Option<(Arc<IssuerKeys>, Instant)>,
}

/// How full the caches are; for a service's own diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub resolved: usize,
    pub verified: usize,
    pub keys_cached: bool,
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// What a [`DirectoryClient`] needs to know about the deployment.
#[non_exhaustive]
pub struct DirectoryConfig {
    /// The siwx-oidc base URL. It resolves askers and it is the trust anchor for
    /// every proof: a proof counts only if this issuer's key signed it.
    pub issuer_url: String,
    /// The homeserver's client-API base URL.
    pub homeserver_url: String,
    /// The homeserver's server name (`example.org` in `@alice:example.org`).
    /// Only its own users carry a proof from this issuer; every other server's
    /// users are `not_yet_published` and their profiles are not read.
    pub server_name: String,
    pub tuning: Tuning,
    pub clock: Clock,
}

impl DirectoryConfig {
    pub fn new(
        issuer_url: impl Into<String>,
        homeserver_url: impl Into<String>,
        server_name: impl Into<String>,
    ) -> Self {
        DirectoryConfig {
            issuer_url: issuer_url.into(),
            homeserver_url: homeserver_url.into(),
            server_name: server_name.into(),
            tuning: Tuning::default(),
            clock: Clock::system(),
        }
    }

    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }
}

/// The directory client. Cheap to clone; clones share their caches. Hold one
/// for the life of the service so the caches do their work.
#[derive(Clone)]
pub struct DirectoryClient {
    inner: Arc<Inner>,
}

struct Inner {
    issuer_url: String,
    homeserver_url: String,
    server_name: String,
    tuning: Tuning,
    clock: Clock,
    http: reqwest::Client,
    caches: Mutex<Caches>,
    /// Held across a fetch of the issuer's keys, so that only one runs.
    key_fetch: AsyncMutex<KeyFetch>,
    /// Fetches that have finished, read before waiting at `key_fetch`: a caller
    /// that finds it changed knows a fetch ran while it waited.
    key_fetches: AtomicU64,
}

#[derive(Default)]
struct KeyFetch {
    /// When the latest fetch began, and why it failed if it did.
    last: Option<(Instant, Option<String>)>,
}

impl fmt::Debug for DirectoryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryClient")
            .field("issuer_url", &self.inner.issuer_url)
            .field("homeserver_url", &self.inner.homeserver_url)
            .field("server_name", &self.inner.server_name)
            .finish_non_exhaustive()
    }
}

/// One row of an answer, before its DID is looked at.
struct Row {
    mxid: String,
    alias: Option<String>,
    /// The raw `io.inblock.did` profile value, when there is one to check.
    field: Option<Value>,
}

struct Rows {
    rows: Vec<Row>,
    limited: bool,
}

/// An answer as it came back.
struct Reply {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<Duration>,
}

impl DirectoryClient {
    pub fn new(config: DirectoryConfig) -> Result<Self, DirectoryError> {
        let DirectoryConfig {
            issuer_url,
            homeserver_url,
            server_name,
            tuning,
            clock,
        } = config;
        if server_name.is_empty() || server_name.contains(|c: char| c.is_whitespace() || c == '@') {
            return Err(invalid("server_name is not a Matrix server name"));
        }
        let http = http_client(&tuning)?;
        Ok(DirectoryClient {
            inner: Arc::new(Inner {
                issuer_url: clean_base("issuer_url", &issuer_url)?,
                homeserver_url: clean_base("homeserver_url", &homeserver_url)?,
                server_name,
                tuning,
                clock,
                http,
                caches: Mutex::new(Caches {
                    resolved: TtlCache::new(),
                    verified: TtlCache::new(),
                    keys: None,
                }),
                key_fetch: AsyncMutex::new(KeyFetch::default()),
                key_fetches: AtomicU64::new(0),
            }),
        })
    }

    /// How full the caches are right now (live entries only).
    pub fn cache_stats(&self) -> CacheStats {
        let now = self.inner.clock.now();
        let mut caches = self.inner.caches.lock().unwrap();
        CacheStats {
            resolved: caches.resolved.live(now),
            verified: caches.verified.live(now),
            keys_cached: caches
                .keys
                .as_ref()
                .is_some_and(|(_, expires)| now < *expires),
        }
    }

    /// Search as the person `asker_did` signed in as.
    ///
    /// Resolves the asker at siwx-oidc (an unknown asker, or a DID no sign-in
    /// could accept, gets the same empty result as no match, and the module is
    /// not called), then asks the directory module with the service's token. A
    /// 401 signs the service in again once and retries once; a 403 is
    /// [`DirectoryError::NotAdmitted`]; a 429 is [`DirectoryError::RateLimited`].
    /// Every hit is then proof-checked.
    ///
    /// `session` must belong to the deployment this client was made for, so its
    /// token is never sent to a homeserver it was not issued for.
    pub async fn search_for_asker(
        &self,
        session: &ServiceSession,
        asker_did: &str,
        term: &str,
        limit: u32,
    ) -> Result<DirectoryResults, DirectoryError> {
        let term = check_term(term)?;
        check_limit(limit)?;
        check_asker(asker_did)?;
        let inner = &self.inner;
        if session.issuer_url != inner.issuer_url || session.homeserver_url != inner.homeserver_url
        {
            return Err(invalid("the service session belongs to another deployment"));
        }

        let Some(asker) = inner.resolve_asker(asker_did).await? else {
            return Ok(DirectoryResults::empty());
        };

        let token = session.access_token().await?;
        let body = match inner.ask_module(&token, &asker, term, limit).await {
            Err(DirectoryError::Unauthorized) => {
                let token = session.token_after_rejection(&token).await?;
                inner.ask_module(&token, &asker, term, limit).await?
            }
            other => other?,
        };
        inner.build_results(&body, limit).await
    }

    /// Search with the user's own Matrix token.
    ///
    /// Synapse's standard `user_directory/search`, then each local hit's
    /// `io.inblock.did` profile field, read without a credential, at most eight
    /// at a time. A 401 is [`DirectoryError::Unauthorized`] (the token is the
    /// caller's to renew). A profile that cannot be read fails the search: its
    /// state is unknown, and `invalid` would be a claim about the person.
    pub async fn search_as_user(
        &self,
        user_token: &str,
        term: &str,
        limit: u32,
    ) -> Result<DirectoryResults, DirectoryError> {
        let term = check_term(term)?;
        check_limit(limit)?;
        check_token(user_token)?;
        let inner = &self.inner;

        let reply = inner
            .send(
                inner
                    .http
                    .post(format!(
                        "{}/_matrix/client/v3/user_directory/search",
                        inner.homeserver_url
                    ))
                    .bearer_auth(user_token)
                    .json(&json!({"search_term": term, "limit": limit})),
            )
            .await?;
        let body = reply.ok_body()?;

        let mut rows = parse_rows(&body)?;
        rows.cut(limit);
        inner.read_profiles(&mut rows).await?;
        inner.assemble(rows).await
    }
}

impl Reply {
    /// The body of a 2xx answer; any other status as its error.
    fn ok_body(self) -> Result<Vec<u8>, DirectoryError> {
        if (200..300).contains(&self.status) {
            Ok(self.body)
        } else {
            Err(self.error())
        }
    }

    /// What a status that is not a success means to a caller.
    fn error(self) -> DirectoryError {
        match self.status {
            401 => DirectoryError::Unauthorized,
            429 => DirectoryError::RateLimited {
                retry_after: self.retry_after.or_else(|| retry_after_ms(&self.body)),
            },
            500..=599 => {
                DirectoryError::Unavailable(format!("the server answered {}", self.status))
            }
            _ => self.unexpected(),
        }
    }

    fn unexpected(&self) -> DirectoryError {
        let errcode = serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| short_code(v.get("errcode")?.as_str()?));
        DirectoryError::UnexpectedStatus {
            status: self.status,
            errcode,
        }
    }
}

/// Synapse's `retry_after_ms` in a 429 body, held to [`crate::RETRY_AFTER_MAX`].
fn retry_after_ms(body: &[u8]) -> Option<Duration> {
    let ms = serde_json::from_slice::<Value>(body)
        .ok()?
        .get("retry_after_ms")?
        .as_u64()?;
    Some(Duration::from_millis(ms).min(crate::RETRY_AFTER_MAX))
}

/// The answer of the directory module or of Synapse's user directory. The two
/// differ only in the optional `did_field`, which the module adds.
fn parse_rows(body: &[u8]) -> Result<Rows, DirectoryError> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        results: Vec<Hit>,
        #[serde(default)]
        limited: bool,
    }
    #[derive(Deserialize)]
    struct Hit {
        user_id: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        did_field: Option<Value>,
    }

    // `{}` is the module's answer when the homeserver's directory is off.
    let answer: Answer = serde_json::from_slice(body)
        .map_err(|_| DirectoryError::Protocol("the answer is not a directory result".into()))?;
    let mut rows = Vec::with_capacity(answer.results.len());
    for hit in answer.results {
        if !is_mxid(&hit.user_id) {
            return Err(DirectoryError::Protocol(
                "a row has no valid user id".into(),
            ));
        }
        rows.push(Row {
            mxid: hit.user_id,
            alias: hit.display_name,
            field: hit.did_field,
        });
    }
    Ok(Rows {
        rows,
        limited: answer.limited,
    })
}

impl Rows {
    /// Never more rows than were asked for; a cut answer is `limited`.
    fn cut(&mut self, limit: u32) {
        if self.rows.len() > limit as usize {
            self.rows.truncate(limit as usize);
            self.limited = true;
        }
    }
}

impl Inner {
    fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Whether the MXID is on this homeserver. Compared exactly, as Synapse and
    /// the MXID binding of a proof compare: `@x:EXAMPLE.org` is not on
    /// `example.org`, and a proof is never looked for on its profile.
    fn is_local(&self, mxid: &str) -> bool {
        mxid.split_once(':')
            .is_some_and(|(_, server)| server == self.server_name)
    }

    /// Send, read the body under the size cap (a success over it is a protocol
    /// fault, an error status over it keeps its status), and map a transport
    /// failure to a retryable error. The URL is left out of the message: it can hold an MXID.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Reply, DirectoryError> {
        let response = request.send().await.map_err(|e| {
            let e = e.without_url();
            DirectoryError::Unavailable(if e.is_timeout() {
                "the request timed out".to_string()
            } else {
                format!("the request failed: {e}")
            })
        })?;
        let status = response.status().as_u16();
        let retry_after = crate::retry_after_hint(response.headers());
        let cap = self.tuning.max_body_bytes;
        let body = match read_at_most(response, cap).await {
            Ok(Some(body)) => body,
            // An error answer counts by its status however long its body: what
            // classifies it (the status, and a code or a hint in a short body)
            // does not need the rest, and a body that is not kept costs nothing.
            Ok(None) if !(200..300).contains(&status) => Vec::new(),
            Ok(None) => return Err(DirectoryError::Protocol(BodyTooLarge { cap }.to_string())),
            Err(_) => {
                return Err(DirectoryError::Unavailable(
                    "reading the answer failed".into(),
                ))
            }
        };
        Ok(Reply {
            status,
            body,
            retry_after,
        })
    }

    /// The MXID of the asker, or `None` when there is no such account. Found
    /// mappings and misses are cached, for different times.
    async fn resolve_asker(&self, did: &str) -> Result<Option<String>, DirectoryError> {
        let now = self.now();
        if let Some(known) = self
            .caches
            .lock()
            .unwrap()
            .resolved
            .get(&did.to_string(), now)
        {
            return Ok(known);
        }
        let reply = self
            .send(
                self.http
                    .get(format!("{}/resolve", self.issuer_url))
                    .query(&[("did", did)]),
            )
            .await?;
        #[derive(Deserialize)]
        struct Resolved {
            exists: bool,
            #[serde(default)]
            mxid: Option<String>,
        }
        let found = match reply.status {
            200 => {
                let resolved: Resolved = serde_json::from_slice(&reply.body).map_err(|_| {
                    DirectoryError::Protocol("/resolve answered something else".into())
                })?;
                match (resolved.exists, resolved.mxid) {
                    (false, _) => None,
                    (true, Some(mxid)) if is_mxid(&mxid) => Some(mxid),
                    (true, _) => {
                        return Err(DirectoryError::Protocol(
                            "/resolve names an account without an MXID".into(),
                        ))
                    }
                }
            }
            // A DID no sign-in could accept has no account: the same answer as
            // an unknown one.
            400 => None,
            _ => return Err(reply.error()),
        };
        let ttl = if found.is_some() {
            self.tuning.resolve_hit_ttl
        } else {
            self.tuning.resolve_miss_ttl
        };
        self.caches.lock().unwrap().resolved.put(
            did.to_string(),
            found.clone(),
            self.now(),
            ttl,
            self.tuning.max_cache_entries,
        );
        Ok(found)
    }

    async fn ask_module(
        &self,
        token: &str,
        asker: &str,
        term: &str,
        limit: u32,
    ) -> Result<Vec<u8>, DirectoryError> {
        let reply = self
            .send(
                self.http
                    .post(format!(
                        "{}/_synapse/client/io.inblock/directory/v1/search",
                        self.homeserver_url
                    ))
                    .bearer_auth(token)
                    .json(&json!({"asker": asker, "term": term, "limit": limit})),
            )
            .await?;
        match reply.status {
            403 => Err(DirectoryError::NotAdmitted),
            _ => reply.ok_body(),
        }
    }

    /// From a module answer to the 4.1 result.
    async fn build_results(
        &self,
        body: &[u8],
        limit: u32,
    ) -> Result<DirectoryResults, DirectoryError> {
        let mut rows = parse_rows(body)?;
        rows.cut(limit);
        self.assemble(rows).await
    }

    /// Read the `io.inblock.did` field of every local row, at most
    /// [`PROFILE_READS_AT_ONCE`] at a time. The first failure ends the search and
    /// aborts the reads still running.
    async fn read_profiles(self: &Arc<Self>, rows: &mut Rows) -> Result<(), DirectoryError> {
        let permits = Arc::new(Semaphore::new(PROFILE_READS_AT_ONCE));
        let mut reads = JoinSet::new();
        for (index, row) in rows.rows.iter().enumerate() {
            if !self.is_local(&row.mxid) {
                continue;
            }
            let (inner, permits, mxid) = (self.clone(), permits.clone(), row.mxid.clone());
            reads.spawn(async move {
                let _permit = permits.acquire_owned().await;
                (index, inner.read_profile(&mxid).await)
            });
        }
        while let Some(done) = reads.join_next().await {
            let (index, field) =
                done.map_err(|_| DirectoryError::Unavailable("a profile read was lost".into()))?;
            rows.rows[index].field = field?;
        }
        Ok(())
    }

    /// `GET /profile/{mxid}/io.inblock.did`, with no credential: the route is
    /// public, and a token would tell every homeserver polled who is asking.
    async fn read_profile(&self, mxid: &str) -> Result<Option<Value>, DirectoryError> {
        let reply = self
            .send(self.http.get(format!(
                "{}/_matrix/client/v3/profile/{}/{DID_PROFILE_FIELD}",
                self.homeserver_url,
                urlencoding::encode(mxid)
            )))
            .await?;
        if reply.status == 404 {
            return Ok(None);
        }
        let body = reply.ok_body()?;
        let mut profile: Value = serde_json::from_slice(&body)
            .map_err(|_| DirectoryError::Protocol("a profile answer is not JSON".into()))?;
        Ok(match profile.get_mut(DID_PROFILE_FIELD).map(Value::take) {
            Some(Value::Null) | None => None,
            Some(value) => Some(value),
        })
    }

    /// Rows to entries: the proof check, one row at a time.
    async fn assemble(&self, rows: Rows) -> Result<DirectoryResults, DirectoryError> {
        let mut results = Vec::with_capacity(rows.rows.len());
        for row in rows.rows {
            let did = self.did_state(&row.mxid, row.field.as_ref()).await?;
            results.push(DirectoryEntry {
                mxid: row.mxid,
                alias: row.alias,
                did,
            });
        }
        Ok(DirectoryResults {
            results,
            limited: rows.limited,
        })
    }

    /// The proof check (plan 4.3).
    ///
    /// - another server's user, no field, no proof (a bare string, an object
    ///   without one, an empty one): `not_yet_published`;
    /// - a verified `(mxid, proof)` still in the cache: `verified`, no key needed;
    /// - a proof that is malformed, or that does not verify under the issuer's
    ///   keys, or that names another MXID: `invalid`, and nothing is kept;
    /// - no key set at all (none cached and none to be fetched): an error, so
    ///   the whole search fails. A proof whose `kid` the cached set lacks is
    ///   `invalid` when the refetch for it is rate limited or fails; that is
    ///   never an error, and the verdict is not kept.
    async fn did_state(
        &self,
        mxid: &str,
        field: Option<&Value>,
    ) -> Result<DidState, DirectoryError> {
        if !self.is_local(mxid) {
            return Ok(DidState::NotYetPublished);
        }
        let Some(proof) = field
            .and_then(|f| f.get("proof"))
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
        else {
            return Ok(DidState::NotYetPublished);
        };

        let cache_key = (mxid.to_string(), proof.to_string());
        if let Some(sub) = self
            .caches
            .lock()
            .unwrap()
            .verified
            .get(&cache_key, self.now())
        {
            return Ok(DidState::Verified(VerifiedSubject(sub)));
        }

        // The header gates need no key, so a malformed proof costs no fetch.
        let Ok(parsed) = parse_proof(proof) else {
            return Ok(DidState::Invalid);
        };
        let mut keys = self.keys().await?;
        if !keys.has_kid(parsed.kid()) {
            // A key the issuer rotated in since the set was fetched: look again
            // (rate limited) before judging the proof against a stale set. The
            // look can fail, and then the stale set stands.
            keys = self.keys_after_unknown_kid(&keys).await;
        }
        match verify_parsed(&keys, &parsed, mxid) {
            Ok(verified) => {
                let sub = verified.did().to_string();
                self.caches.lock().unwrap().verified.put(
                    cache_key,
                    sub.clone(),
                    self.now(),
                    self.tuning.verified_ttl,
                    self.tuning.max_cache_entries,
                );
                Ok(DidState::Verified(VerifiedSubject(sub)))
            }
            Err(_) => Ok(DidState::Invalid),
        }
    }

    /// Discovery and the key set, from the cache or fetched. A failure is never
    /// stored, so the next search asks again.
    async fn keys(&self) -> Result<Arc<IssuerKeys>, DirectoryError> {
        if let Some(keys) = self.cached_keys() {
            return Ok(keys);
        }
        self.fetch_keys(None).await
    }

    /// The key set after a proof named a `kid` that `stale` lacks. A newer set
    /// than `stale` is returned as it is; otherwise the set is fetched again,
    /// unless a fetch began less than [`Tuning::keys_refetch_interval`] ago, in
    /// which case `stale` stands (and the proof is judged `invalid` against it).
    ///
    /// This never fails: `stale` is a set that was usable a moment ago, and a
    /// refetch that fails (or whose failure an earlier caller stored) leaves it
    /// standing, so one row with an unknown `kid` cannot fail a search or hold
    /// the others' answers hostage for the length of the rate limit.
    async fn keys_after_unknown_kid(&self, stale: &Arc<IssuerKeys>) -> Arc<IssuerKeys> {
        match self.fetch_keys(Some(stale)).await {
            Ok(keys) => keys,
            Err(_) => stale.clone(),
        }
    }

    fn cached_keys(&self) -> Option<Arc<IssuerKeys>> {
        let caches = self.caches.lock().unwrap();
        let (keys, expires) = caches.keys.as_ref()?;
        (self.now() < *expires).then(|| keys.clone())
    }

    /// The one place the issuer's discovery document and key set are fetched,
    /// and one fetch at a time.
    ///
    /// Callers queue at `key_fetch`. One that waited while a fetch ran takes that
    /// fetch's outcome, a failure as much as a set (k searches behind a slow
    /// issuer wait for one timeout, not k), and the fetches do not overlap, so
    /// each stores a set that is newer than the one it replaces: an older fetch
    /// cannot land after a newer one. Nothing of a failure is stored; the next
    /// call that finds no usable set fetches again. `stale` is the set a proof's
    /// `kid` was missing from, when that is why the call is made; such a call
    /// is answered with `stale` (not an error) while the rate limit holds after
    /// a failed fetch, and the failure is only ever the answer of a call that has
    /// no set (`stale` is `None`).
    async fn fetch_keys(
        &self,
        stale: Option<&Arc<IssuerKeys>>,
    ) -> Result<Arc<IssuerKeys>, DirectoryError> {
        let seen = self.key_fetches.load(Ordering::SeqCst);
        let mut fetch = self.key_fetch.lock().await;

        let stored = || {
            self.caches
                .lock()
                .unwrap()
                .keys
                .as_ref()
                .map(|(keys, _)| keys.clone())
        };
        if self.key_fetches.load(Ordering::SeqCst) != seen {
            // A fetch ended while this caller waited: its outcome is the answer.
            match (&fetch.last, stored(), stale) {
                // The set a proof's `kid` was missing from is still the one to
                // judge it by when the refetch that ended meanwhile failed.
                (Some((_, Some(_))), current, Some(stale)) => {
                    return Ok(current.unwrap_or_else(|| stale.clone()))
                }
                (Some((_, Some(why))), _, None) => {
                    return Err(DirectoryError::Unavailable(why.clone()))
                }
                (_, Some(keys), _) => return Ok(keys),
                (_, None, _) => {}
            }
        }
        match stale {
            None => {
                if let Some(keys) = self.cached_keys() {
                    return Ok(keys);
                }
            }
            Some(stale) => {
                if let Some(current) = stored().filter(|current| !Arc::ptr_eq(current, stale)) {
                    return Ok(current);
                }
                if let Some((began, _)) = &fetch.last {
                    let limited = began
                        .checked_add(self.tuning.keys_refetch_interval)
                        .is_none_or(|until| self.now() < until);
                    if limited {
                        // A failed fetch limits the next one just as a good
                        // one does, and `stale` stands either way.
                        return Ok(stale.clone());
                    }
                }
            }
        }

        let began = self.now();
        let fetched = fetch_issuer_keys(
            &self.http,
            &self.issuer_url,
            Some(self.tuning.max_body_bytes),
        )
        .await
        .map_err(|e| format!("the issuer's keys: {e:#}"));
        fetch.last = Some((began, fetched.as_ref().err().cloned()));
        self.key_fetches.fetch_add(1, Ordering::SeqCst);
        let keys = Arc::new(fetched.map_err(DirectoryError::Unavailable)?);
        self.caches.lock().unwrap().keys = Some((keys.clone(), self.now() + self.tuning.keys_ttl));
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Tests: the shared vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_assertion::IssuerKeys;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use std::path::{Path, PathBuf};

    const FORMAT: &str = "siwx-oidc-auth.directory-vector/1";

    fn vectors_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/directory")
    }

    /// A client for a vector: no socket is opened, the vector's key set is put
    /// where the fetch would have left it.
    fn client_for(vector: &Value) -> DirectoryClient {
        let issuer = vector["issuer"].as_str().unwrap();
        let client = DirectoryClient::new(DirectoryConfig::new(
            issuer,
            "https://homeserver.example.org",
            vector["server_name"].as_str().unwrap(),
        ))
        .unwrap();
        let keys = IssuerKeys::for_tests(issuer, vector["jwks"].clone());
        let inner = &client.inner;
        inner.caches.lock().unwrap().keys =
            Some((Arc::new(keys), inner.now() + Duration::from_secs(3600)));
        client
    }

    /// Run one vector through the same code the two transports end in.
    async fn run(vector: &Value) -> Value {
        let client = client_for(vector);
        let inner = &client.inner;
        let limit = vector["limit"].as_u64().unwrap() as u32;
        let results = match vector["transport"].as_str().unwrap() {
            "module" => {
                let body = serde_json::to_vec(&vector["module_response"]).unwrap();
                inner.build_results(&body, limit).await.unwrap()
            }
            "user_directory" => {
                let body = serde_json::to_vec(&vector["user_directory_response"]).unwrap();
                let mut rows = parse_rows(&body).unwrap();
                rows.cut(limit);
                // What the profile reads would have left: the stored field of a
                // local user, `null` meaning the route answered 404.
                for row in &mut rows.rows {
                    if inner.is_local(&row.mxid) {
                        row.field = vector["profiles"]
                            .get(&row.mxid)
                            .cloned()
                            .filter(|v| !v.is_null());
                    }
                }
                inner.assemble(rows).await.unwrap()
            }
            other => panic!("unknown transport {other}"),
        };
        serde_json::to_value(&results).unwrap()
    }

    #[tokio::test]
    async fn every_vector_gives_its_expected_result() {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(vectors_dir()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let vector: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(vector["format"], FORMAT, "{}", path.display());
            let name = vector["name"].as_str().unwrap().to_string();
            assert_eq!(
                path.file_stem().unwrap().to_str().unwrap(),
                name,
                "a vector file is named after its `name`"
            );
            assert_eq!(run(&vector).await, vector["expected"], "vector {name}");
            names.push(name);
        }
        // The cases the plan names must all be there; a deleted vector is a failure.
        for required in [
            "verified",
            "not-yet-published-no-field",
            "not-yet-published-no-proof",
            "not-yet-published-remote-user",
            "invalid-proof-for-another-mxid",
            "invalid-tampered-payload",
            "unsigned-did-disagrees-with-sub",
            "mixed-module",
            "user-directory-mixed",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "missing vector {required}"
            );
        }
    }

    // -- the generator -------------------------------------------------------

    fn mint(key: &SigningKey, kid: &str, payload: &Value) -> String {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let input = format!("{h}.{p}");
        let sig: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn tampered(proof: &str, claim: &str, value: Value) -> String {
        let parts: Vec<&str> = proof.split('.').collect();
        let mut payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload[claim] = value;
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("{}.{forged}.{}", parts[0], parts[2])
    }

    /// Makes the vector files with a key generated in memory and dropped at the
    /// end of the test. Only the public key and the finished proofs are written.
    /// Prints every file; with `DIRECTORY_VECTORS_OUT=<dir>` it writes them there.
    ///
    ///     DIRECTORY_VECTORS_OUT=siwx-oidc-auth/tests/vectors/directory \
    ///         cargo test -p siwx-oidc-auth --lib regenerate_directory_vectors -- --ignored
    #[test]
    #[ignore = "writes the committed vector files; run by hand"]
    fn regenerate_directory_vectors() {
        const ISSUER: &str = "https://siwx.example.org";
        const KID: &str = "vector-kid-1";
        const IAT: i64 = 1_757_000_000;
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let jwks = json!({"keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]});

        let mxid = |name: &str| format!("@{name}:example.org");
        let did = |name: &str| format!("did:key:zVectorFixture{name}0000000000000000000000");
        let proof = |sub: &str, mx: &str| {
            mint(
                &key,
                KID,
                &json!({"iss": ISSUER, "sub": sub, "mxid": mx, "iat": IAT}),
            )
        };
        let field = |name: &str| json!({"did": did(name), "proof": proof(&did(name), &mxid(&name.to_lowercase()))});
        let verified = |name: &str| json!({"state": "verified", "value": did(name)});
        let not_yet = || json!({"state": "not_yet_published"});
        let bad = || json!({"state": "invalid"});
        let entry = |name: &str, alias: Option<&str>, state: Value| {
            let mut e = json!({"mxid": mxid(&name.to_lowercase()), "did": state});
            if let Some(a) = alias {
                e["alias"] = json!(a);
            }
            e
        };
        let hit = |name: &str, alias: Option<&str>, field: Option<Value>| {
            let mut h = json!({"user_id": mxid(&name.to_lowercase())});
            if let Some(a) = alias {
                h["display_name"] = json!(a);
            }
            if let Some(f) = field {
                h["did_field"] = f;
            }
            h
        };
        let module = |name: &str, description: &str, hits: Vec<Value>, expected: Vec<Value>| {
            json!({
                "format": FORMAT, "name": name, "description": description,
                "transport": "module",
                "issuer": ISSUER, "server_name": "example.org", "jwks": jwks, "limit": 10,
                "module_response": {"results": hits, "limited": false},
                "expected": {"results": expected, "limited": false},
            })
        };

        let alice_for_bob =
            json!({"did": did("Alice"), "proof": proof(&did("Alice"), &mxid("alice"))});
        let forged = json!({"did": did("Dave"), "proof": tampered(&proof(&did("Dave"), &mxid("dave")), "sub", json!(did("Mallory")))});
        let lying = json!({"did": did("Mallory"), "proof": proof(&did("Bob"), &mxid("bob"))});
        let remote_user = "@remote:other.example";
        let remote_field =
            json!({"did": did("Remote"), "proof": proof(&did("Remote"), remote_user)});

        let mut files: Vec<(String, Value)> = vec![
            ("verified".into(), module(
                "verified",
                "A local user whose proof verifies: the DID is the signed sub.",
                vec![hit("Alice", Some("Alice Example"), Some(field("Alice")))],
                vec![entry("Alice", Some("Alice Example"), verified("Alice"))],
            )),
            ("not-yet-published-no-field".into(), module(
                "not-yet-published-no-field",
                "A local user with no io.inblock.did field, and no display name.",
                vec![hit("Bob", None, None)],
                vec![entry("Bob", None, not_yet())],
            )),
            ("not-yet-published-no-proof".into(), module(
                "not-yet-published-no-proof",
                "The field is there and carries no proof (the issuer's key was ephemeral), or an empty one, or is the legacy bare string: no DID is given.",
                vec![
                    hit("Bob", Some("Bob"), Some(json!({"did": did("Bob")}))),
                    hit("Carol", Some("Carol"), Some(json!({"did": did("Carol"), "proof": ""}))),
                    hit("Dave", Some("Dave"), Some(json!(did("Dave")))),
                ],
                vec![
                    entry("Bob", Some("Bob"), not_yet()),
                    entry("Carol", Some("Carol"), not_yet()),
                    entry("Dave", Some("Dave"), not_yet()),
                ],
            )),
            ("not-yet-published-remote-user".into(), module(
                "not-yet-published-remote-user",
                "A user of another homeserver is not_yet_published even when a field with a valid proof for that MXID is present.",
                vec![json!({"user_id": remote_user, "display_name": "Remote", "did_field": remote_field})],
                vec![json!({"mxid": remote_user, "alias": "Remote", "did": not_yet()})],
            )),
            ("invalid-proof-for-another-mxid".into(), module(
                "invalid-proof-for-another-mxid",
                "Bob copied Alice's genuine proof into his own profile: the signature is good and the binding is not.",
                vec![hit("Bob", Some("Bob"), Some(alice_for_bob))],
                vec![entry("Bob", Some("Bob"), bad())],
            )),
            ("invalid-tampered-payload".into(), module(
                "invalid-tampered-payload",
                "The sub of a signed payload was changed after signing.",
                vec![hit("Dave", Some("Dave"), Some(forged))],
                vec![entry("Dave", Some("Dave"), bad())],
            )),
            ("unsigned-did-disagrees-with-sub".into(), module(
                "unsigned-did-disagrees-with-sub",
                "The plain did member names someone else; only the signed sub counts.",
                vec![hit("Bob", Some("Bob"), Some(lying))],
                vec![entry("Bob", Some("Bob"), verified("Bob"))],
            )),
        ];

        // Everything at once, in the order the homeserver gave it, with `limited` set.
        let mut mixed = module(
            "mixed-module",
            "One answer with every state, in order, and the homeserver's limited flag passed on.",
            vec![
                hit("Alice", Some("Alice Example"), Some(field("Alice"))),
                hit("Bob", None, None),
                hit("Carol", Some("Carol"), Some(json!({"did": did("Carol")}))),
                hit(
                    "Dave",
                    Some("Dave"),
                    Some(json!({"did": did("Dave"), "proof": "not.a.jws"})),
                ),
            ],
            vec![
                entry("Alice", Some("Alice Example"), verified("Alice")),
                entry("Bob", None, not_yet()),
                entry("Carol", Some("Carol"), not_yet()),
                entry("Dave", Some("Dave"), bad()),
            ],
        );
        mixed["module_response"]["limited"] = json!(true);
        mixed["expected"]["limited"] = json!(true);
        files.push(("mixed-module".into(), mixed));

        // The user-directory transport: rows from Synapse's standard search, the
        // field of each local user from the profile route (null is a 404).
        let ud = json!({
            "format": FORMAT, "name": "user-directory-mixed",
            "description": "Rows of the standard user directory plus the profile field of each local user; a remote user's profile is not read.",
            "transport": "user_directory",
            "issuer": ISSUER, "server_name": "example.org", "jwks": jwks, "limit": 10,
            "user_directory_response": {"results": [
                {"user_id": mxid("alice"), "display_name": "Alice Example", "avatar_url": "mxc://example.org/avatar"},
                {"user_id": mxid("bob")},
                {"user_id": mxid("carol"), "display_name": "Carol"},
                {"user_id": remote_user, "display_name": "Remote"},
            ], "limited": false},
            "profiles": {
                mxid("alice"): field("Alice"),
                mxid("bob"): null,
                mxid("carol"): {"did": did("Carol"), "proof": proof(&did("Carol"), &mxid("alice"))},
            },
            "expected": {"results": [
                entry("Alice", Some("Alice Example"), verified("Alice")),
                entry("Bob", None, not_yet()),
                entry("Carol", Some("Carol"), bad()),
                {"mxid": remote_user, "alias": "Remote", "did": not_yet()},
            ], "limited": false},
        });
        files.push(("user-directory-mixed".into(), ud));

        let out = std::env::var_os("DIRECTORY_VECTORS_OUT").map(PathBuf::from);
        for (name, value) in &files {
            let text = serde_json::to_string_pretty(value).unwrap() + "\n";
            println!("=== {name}.json ===\n{text}");
            if let Some(dir) = &out {
                std::fs::create_dir_all(dir).unwrap();
                std::fs::write(dir.join(format!("{name}.json")), text).unwrap();
            }
        }
    }
}
