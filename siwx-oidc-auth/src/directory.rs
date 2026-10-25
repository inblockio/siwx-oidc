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
//! # People of other homeservers
//!
//! No proof of this issuer can stand for a user of another homeserver, so such a
//! person is **never** `Verified`. Their `io.inblock.did` profile field is read
//! through our homeserver (Synapse asks theirs over federation) and a
//! well-formed DID in it is reported as [`DidState::Unconfirmed`]: what they
//! claim, which nobody checked. Anything else (no field, an unreadable one, a
//! value that is not a DID, a server too slow) is `NotYetPublished`, and a
//! remote read never fails a search. A claim is kept briefly and apart from
//! the verified cache. The claimed DID is never logged (this module logs
//! nothing).
//!
//! - **Show a claim as it is.** `%XX` escapes are legal DID syntax and change the
//!   identifier, so a client displays and compares a claimed DID byte for byte,
//!   never percent-decoded.
//! - **Budget for the reads.** They add up to
//!   [`Tuning::remote_profiles_timeout`] (6 s) to a search's critical path; a
//!   host with a deadline of its own for a search sets it above that.
//! - The local people of an answer are read first, so a slow foreign server never
//!   delays their check; the foreign reads have eight places of their own and a
//!   read ends by the earlier of its own bound and the total, keeping what it
//!   found. Searches that want the same person at once share one read.
//!
//! # The server name
//!
//! The split above rests on [`DirectoryConfig::server_name`], which must be the
//! homeserver's own name (the part after the colon of its users' MXIDs), not a
//! delegated host. The asker of a module search and the owner of the token of a
//! user search are the homeserver's own people, so one who is not on the
//! configured name is the error [`DirectoryError::ServerNameMismatch`], never an
//! answer in which every local person looks foreign.
//!
//! Only the homeserver can vouch for the name, and it does so through
//! `GET /account/whoami`, asked once per client by whichever transport searches
//! first: with the service's own token on the module transport (the service
//! account is a local user of the homeserver), with the user's token on the user
//! transport. The asker's MXID alone proves nothing, as the issuer builds it from
//! its own configuration: an issuer and a client that share one wrong name agree
//! on it, and the module answers that unknown asker with a plain empty `200`, so
//! a host would report "ready" and serve empty results. A `whoami` that fails is
//! the error of that search and is not kept. It is [`DirectoryError::Whoami`]
//! with the failure inside, never the plain error of the same status: a 404 from
//! `whoami` says the homeserver URL does not answer the Matrix client API, a 404
//! from the directory module says the module is not registered, and a host must
//! be able to tell the two apart. (A person of another server is not a failure
//! of `whoami`: it answered, and it is [`DirectoryError::ServerNameMismatch`].)
//!
//! # Errors
//!
//! An answer that could not be checked is an error, never a state: a network
//! failure fails the whole search with a retryable [`DirectoryError`], and a
//! discovery or key-set failure with [`DirectoryError::IssuerKeys`] (the issuer's
//! public documents, never the module's word and never the service token), and
//! nothing of either is stored. Only a proof that was read and does not verify
//! is `invalid`. A local person's profile that cannot be read fails a user search
//! as [`DirectoryError::Profile`]: that read is sent without a credential, so its
//! 401 is never the user's token refused, and its 429 is not the rate limit of
//! the directory call, which stays the plain error of its status.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use url::Url;

use crate::did_assertion::{
    fetch_issuer_keys, parse_proof, read_at_most, verify_parsed, BodyTooLarge, IssuerKeys,
    DEFAULT_BODY_CAP, DID_PROFILE_FIELD,
};
use crate::{
    authenticate_with_device_within, refresh_within, request_failed, AuthError, Refusal, SiwxKey,
    FLOW_REQUEST_TIMEOUT, TOKEN_LIFETIME_DEFAULT_SECS, TOKEN_LIFETIME_MAX_SECS,
    TOKEN_LIFETIME_MIN_SECS,
};

/// The shortest and longest search term, in characters after trimming.
const TERM_MIN: usize = 1;
const TERM_MAX: usize = 64;
/// The largest number of rows one search may ask for.
const LIMIT_MAX: u32 = 20;
/// Profile reads in flight at once, local and remote together.
const PROFILE_READS_AT_ONCE: usize = 8;
/// The longest DID taken from anything: an asker's, or a remote person's claim.
const DID_MAX: usize = 2048;

// ---------------------------------------------------------------------------
// The result (plan 4.1)
// ---------------------------------------------------------------------------

/// The people a search found, in the order the homeserver gave them.
///
/// Serializes as `{"results": [...], "limited": bool}`. `limited` is true when
/// the homeserver says more people matched than it returned, or when this
/// client cut the answer to the `limit` that was asked for.
///
/// An empty result is two different things: the homeserver answered and found
/// nobody, or no homeserver was asked at all (the asker is not known to the
/// issuer). [`DirectoryResults::homeserver_answered`] tells them apart; it is
/// not part of the serialized form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryResults {
    pub results: Vec<DirectoryEntry>,
    pub limited: bool,
    /// See [`DirectoryResults::homeserver_answered`]. Private, and skipped by
    /// `Serialize`, so the wire shape is unchanged.
    #[serde(skip)]
    homeserver_answered: bool,
}

impl DirectoryResults {
    /// The result of a search that asked no homeserver.
    fn unasked() -> Self {
        DirectoryResults {
            results: Vec::new(),
            limited: false,
            homeserver_answered: false,
        }
    }

    /// Whether the homeserver itself answered this search: the directory module
    /// for [`DirectoryClient::search_for_asker`], the user directory for
    /// [`DirectoryClient::search_as_user`]. An answer of nobody is still an
    /// answer.
    ///
    /// `false` when no homeserver was asked: `search_for_asker` returns the empty
    /// result, before the service's token and before the module, for an asker the
    /// issuer does not know (or would not sign in). A host that treats a search as
    /// proof that the homeserver is reachable and configured as expected (for
    /// example to clear a backoff it keeps against the service's token) must not
    /// count such a result.
    pub fn homeserver_answered(&self) -> bool {
        self.homeserver_answered
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
/// `{"state":"verified","value":"did:..."}`,
/// `{"state":"unconfirmed","value":"did:..."}`, `{"state":"not_yet_published"}`
/// or `{"state":"invalid"}`. Only `Verified` is confirmed; an `Unconfirmed` DID
/// is what another server's user claims, and a caller that offers it as a
/// recipient must say so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum DidState {
    /// A proof from this issuer verified and names this MXID. The value is the
    /// proof's signed `sub`.
    Verified(VerifiedSubject),
    /// A user of ANOTHER homeserver whose `io.inblock.did` profile field, read
    /// through this homeserver, holds a well-formed DID. The value is what the
    /// field says and nothing vouches for it: a foreign issuer is not ours to
    /// trust, so such a row is never `Verified`, whatever proof it carries.
    Unconfirmed(ClaimedDid),
    /// No proof from this issuer: the person has no `io.inblock.did` field, the
    /// field has no proof, or the person is on another homeserver and gave no
    /// usable claim (no field, an unreadable one, a value that is not a DID, a
    /// server too slow to answer).
    NotYetPublished,
    /// A proof is there and does not verify.
    Invalid,
}

impl DidState {
    /// The DID of a `Verified` state; `None` for the others, an `Unconfirmed`
    /// one included.
    pub fn verified_did(&self) -> Option<&str> {
        match self {
            DidState::Verified(subject) => Some(&subject.0),
            DidState::Unconfirmed(_) | DidState::NotYetPublished | DidState::Invalid => None,
        }
    }

    /// The DID of an `Unconfirmed` state; `None` for the others.
    pub fn unconfirmed_did(&self) -> Option<&str> {
        match self {
            DidState::Unconfirmed(claim) => Some(&claim.0),
            DidState::Verified(_) | DidState::NotYetPublished | DidState::Invalid => None,
        }
    }
}

/// The DID another server's user claims. It passed [`is_did`] and nothing else:
/// no proof of ours stands behind it. Like [`VerifiedSubject`] it has a private
/// field, so a value of this type comes from a profile read in this module.
///
/// `%XX` escapes are legal DID syntax and change the identifier
/// (`did:web:example.com%3A8443` is not `did:web:example.com:8443`): show and
/// compare a claim as it is, byte for byte, never percent-decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ClaimedDid(String);

impl ClaimedDid {
    pub fn as_str(&self) -> &str {
        &self.0
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
    /// A network, timeout or 5xx failure: the state is unknown, try again
    /// later. (A failure to get the issuer's discovery document or key set is the
    /// same text inside [`DirectoryError::IssuerKeys`], and the cause of
    /// that.)
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
    /// The homeserver's own people are not on [`DirectoryConfig::server_name`]:
    /// the asker of a module search, or the owner of the token of a user search.
    /// The configured name is not the homeserver's (a delegated host, a typo),
    /// and answering anyway would show every local person as a foreign one.
    /// Not retryable: the operator corrects the configuration. The message names
    /// neither the person nor either server.
    ServerNameMismatch,
    /// The homeserver's `GET /account/whoami` failed, and the inner error is how.
    /// This is the check of [`DirectoryConfig::server_name`] that comes before
    /// the first search of a client, on either transport (see the module
    /// documentation, "The server name"). It is told apart because the same
    /// inner error means something else when the directory itself answers it: a
    /// 404 here says the homeserver URL does not answer the Matrix client API
    /// (a wrong `homeserver_url`, a proxy), where a 404 from the directory
    /// module says the module is not registered. A 401 is the token refused at
    /// `whoami`, a 429 its rate limit.
    ///
    /// The inner error is one of [`Unauthorized`](DirectoryError::Unauthorized),
    /// [`RateLimited`](DirectoryError::RateLimited),
    /// [`Unavailable`](DirectoryError::Unavailable),
    /// [`UnexpectedStatus`](DirectoryError::UnexpectedStatus) or
    /// [`Protocol`](DirectoryError::Protocol) (an answer without a user id); it
    /// is never another `Whoami`. A `whoami` that answers and names a person of
    /// another server is not this: it is [`DirectoryError::ServerNameMismatch`].
    /// [`is_retryable`](Self::is_retryable), [`is_rate_limited`](Self::is_rate_limited)
    /// and [`retry_after`](Self::retry_after) answer for the inner error; read it
    /// with [`whoami_cause`](Self::whoami_cause). Nothing of the directory was
    /// asked, and nothing of the failure is kept: the next search asks again.
    Whoami(Box<DirectoryError>),
    /// The lookup of the asker at siwx-oidc (`GET /resolve` on the issuer) failed,
    /// and the inner error is how. It is the first request of
    /// [`DirectoryClient::search_for_asker`], and it is told apart because the
    /// same inner error means something else when the homeserver or its
    /// directory module answers it: a 401 here is the issuer's (`/resolve` is
    /// public, so a 401 is a proxy or a wall in front of it), never the service
    /// token refused, and renewing the token cannot help; a 429 is the issuer's
    /// rate limit, not the module's; a 404 is an issuer that has no `/resolve`
    /// (an old build, a wrong `issuer_url`), where a 404 from the directory
    /// module says the module is not registered.
    ///
    /// The inner error is one of [`Unauthorized`](DirectoryError::Unauthorized),
    /// [`RateLimited`](DirectoryError::RateLimited),
    /// [`Unavailable`](DirectoryError::Unavailable),
    /// [`UnexpectedStatus`](DirectoryError::UnexpectedStatus) or
    /// [`Protocol`](DirectoryError::Protocol) (an answer that is not the
    /// contract); it is never another `Resolve` or a [`Whoami`](DirectoryError::Whoami).
    /// An asker who does not exist, or whose DID no sign-in could accept, is not
    /// this: `/resolve` answered, and the result is the empty one. A person of
    /// another server is [`DirectoryError::ServerNameMismatch`].
    /// [`is_retryable`](Self::is_retryable), [`is_rate_limited`](Self::is_rate_limited)
    /// and [`retry_after`](Self::retry_after) answer for the inner error; read it
    /// with [`resolve_cause`](Self::resolve_cause). Neither `whoami` nor the
    /// module was asked, and nothing of the failure is kept: the next search asks
    /// again.
    Resolve(Box<DirectoryError>),
    /// The issuer's discovery document or key set could not be had, and the
    /// inner error is how. It is the last request of a search: after the module
    /// answered, the client fetches `/.well-known/openid-configuration` and the
    /// `jwks_uri` it names (public, no token) to verify the proofs of the rows,
    /// and it is told apart because the same failure means something else when the
    /// homeserver or its module answers it: a 401 here is a proxy or a wall in
    /// front of the issuer's public documents, never the service token refused
    /// (the module has already taken it), and renewing the token cannot help; a
    /// 404 is an issuer without discovery or a wrong `issuer_url`, where a 404
    /// from the module says the module is not registered.
    ///
    /// The inner error is [`Unavailable`](DirectoryError::Unavailable), whatever
    /// the document or the key set did (a status, a body that is not the
    /// document, an issuer that names another issuer, a timeout): its text names
    /// the step and the status, never a body. It is never another stage.
    /// Only a search that has no key set to judge by fails like this. A proof
    /// that is malformed, or that the key set does not verify, or whose `kid` the
    /// held key set lacks while the refetch for it fails, is `invalid` for its
    /// row and fails nothing (see [`DidState::Invalid`]).
    /// [`is_retryable`](Self::is_retryable), [`is_rate_limited`](Self::is_rate_limited)
    /// and [`retry_after`](Self::retry_after) answer for the inner error; read it
    /// with [`issuer_keys_cause`](Self::issuer_keys_cause). The module did answer
    /// and nothing of the failure is kept: the next search asks again.
    IssuerKeys(Box<DirectoryError>),
    /// The read of a local person's `io.inblock.did` profile field failed, and
    /// the inner error is how. It is the failure of
    /// [`DirectoryClient::search_as_user`] to read
    /// `GET /_matrix/client/v3/profile/{mxid}/io.inblock.did` for a hit on this
    /// homeserver, and it is told apart because the same inner error means
    /// something else when the search itself answers it: the profile read is
    /// sent **without a credential**, so a 401 here is a homeserver that refuses
    /// the anonymous read (`require_auth_for_profile_requests`) or a proxy in
    /// front of it, never the user's token refused, and asking the user to sign
    /// in again cannot help; a 429 is the rate limit of the profile route, not of
    /// `user_directory/search`; a 5xx is the profile of that account (an account
    /// with no `profiles` row, element-hq/synapse#19702), not a homeserver that
    /// is down. The `user_directory/search` call itself, which does carry the
    /// token, stays the plain error of its status.
    ///
    /// The inner error is one of [`Unauthorized`](DirectoryError::Unauthorized),
    /// [`RateLimited`](DirectoryError::RateLimited),
    /// [`Unavailable`](DirectoryError::Unavailable),
    /// [`UnexpectedStatus`](DirectoryError::UnexpectedStatus) or
    /// [`Protocol`](DirectoryError::Protocol) (an answer that is not JSON, or a
    /// body over the cap); it is never another stage. Only a **local** profile
    /// that cannot be read fails a search like this, because its state is unknown:
    /// a profile that is absent (404), or whose field is absent, `null` or not a
    /// proof, is that person's `not_yet_published` (or `invalid`) and fails
    /// nothing, and the profile of a person of another server never fails a
    /// search. The module transport ([`DirectoryClient::search_for_asker`]) reads
    /// no local profile, so it never returns this.
    /// [`is_retryable`](Self::is_retryable), [`is_rate_limited`](Self::is_rate_limited)
    /// and [`retry_after`](Self::retry_after) answer for the inner error; read it
    /// with [`profile_cause`](Self::profile_cause). The first failure ends the
    /// search, the reads still running are dropped, and nothing of the failure is
    /// kept: the next search asks again.
    Profile(Box<DirectoryError>),
}

impl DirectoryError {
    /// Whether the failure is the homeserver's `GET /account/whoami`, not the
    /// directory's own answer: [`DirectoryError::Whoami`]. Match this (or
    /// [`whoami_cause`](Self::whoami_cause)) before reading the status of an
    /// [`UnexpectedStatus`](DirectoryError::UnexpectedStatus), which means
    /// something else at `whoami`.
    pub fn is_whoami(&self) -> bool {
        matches!(self, DirectoryError::Whoami(_))
    }

    /// How `GET /account/whoami` failed, when it is what failed
    /// ([`DirectoryError::Whoami`]); `None` for every other error.
    pub fn whoami_cause(&self) -> Option<&DirectoryError> {
        match self {
            DirectoryError::Whoami(cause) => Some(cause),
            _ => None,
        }
    }

    /// Whether the failure is the issuer's `GET /resolve` (the lookup of the
    /// asker), not the homeserver's or its module's answer:
    /// [`DirectoryError::Resolve`]. Match this (or
    /// [`resolve_cause`](Self::resolve_cause)) before reading the status of an
    /// [`Unauthorized`](DirectoryError::Unauthorized), a
    /// [`RateLimited`](DirectoryError::RateLimited) or an
    /// [`UnexpectedStatus`](DirectoryError::UnexpectedStatus), which mean
    /// something else at `/resolve`: the service token was not involved.
    pub fn is_resolve(&self) -> bool {
        matches!(self, DirectoryError::Resolve(_))
    }

    /// How `GET /resolve` failed, when it is what failed
    /// ([`DirectoryError::Resolve`]); `None` for every other error.
    pub fn resolve_cause(&self) -> Option<&DirectoryError> {
        match self {
            DirectoryError::Resolve(cause) => Some(cause),
            _ => None,
        }
    }

    /// Whether the failure is the issuer's discovery document or key set, not the
    /// homeserver's or its module's answer: [`DirectoryError::IssuerKeys`]. Match
    /// this (or [`issuer_keys_cause`](Self::issuer_keys_cause)) before reading
    /// the failure: the service token was not involved, and the module had
    /// already answered.
    pub fn is_issuer_keys(&self) -> bool {
        matches!(self, DirectoryError::IssuerKeys(_))
    }

    /// How the issuer's discovery document or key set failed, when it is what
    /// failed ([`DirectoryError::IssuerKeys`]); `None` for every other error.
    pub fn issuer_keys_cause(&self) -> Option<&DirectoryError> {
        match self {
            DirectoryError::IssuerKeys(cause) => Some(cause),
            _ => None,
        }
    }

    /// Whether the failure is the read of a local person's profile in a user
    /// search, which is sent without a credential:
    /// [`DirectoryError::Profile`]. Match this (or
    /// [`profile_cause`](Self::profile_cause)) before reading a bare
    /// [`Unauthorized`](DirectoryError::Unauthorized) as the user's token being
    /// refused: the profile read carries no token.
    pub fn is_profile(&self) -> bool {
        matches!(self, DirectoryError::Profile(_))
    }

    /// The error inside, when the read of a local person's profile failed
    /// ([`DirectoryError::Profile`]); `None` for every other error.
    pub fn profile_cause(&self) -> Option<&DirectoryError> {
        match self {
            DirectoryError::Profile(cause) => Some(cause),
            _ => None,
        }
    }

    /// Whether the service could not sign in because the server does not know its
    /// client id: a dynamic client lapses after 30 days without a use (see
    /// [`register_public_client`]). The remedy is to register again and keep the
    /// new id, not to retry, so this is never [`is_retryable`](Self::is_retryable).
    /// Match this (or [`AuthError::UnknownClient`] in the `source`), not the text.
    pub fn is_unknown_client(&self) -> bool {
        match self {
            DirectoryError::SignIn { source } => crate::is_unknown_client(source),
            DirectoryError::Whoami(cause)
            | DirectoryError::Resolve(cause)
            | DirectoryError::IssuerKeys(cause)
            | DirectoryError::Profile(cause) => cause.is_unknown_client(),
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
            DirectoryError::Whoami(cause)
            | DirectoryError::Resolve(cause)
            | DirectoryError::IssuerKeys(cause)
            | DirectoryError::Profile(cause) => cause.is_rate_limited(),
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
            DirectoryError::Whoami(cause)
            | DirectoryError::Resolve(cause)
            | DirectoryError::IssuerKeys(cause)
            | DirectoryError::Profile(cause) => cause.retry_after(),
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
            DirectoryError::Whoami(cause)
            | DirectoryError::Resolve(cause)
            | DirectoryError::IssuerKeys(cause)
            | DirectoryError::Profile(cause) => cause.is_retryable(),
            DirectoryError::InvalidInput(_)
            | DirectoryError::NotAdmitted
            | DirectoryError::Unauthorized
            | DirectoryError::UnexpectedStatus { .. }
            | DirectoryError::Protocol(_)
            | DirectoryError::ServerNameMismatch => false,
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
            DirectoryError::ServerNameMismatch => write!(
                f,
                "the homeserver's users are not on the configured server_name"
            ),
            DirectoryError::Whoami(cause) => write!(f, "whoami failed: {cause}"),
            DirectoryError::Resolve(cause) => write!(f, "resolve failed: {cause}"),
            DirectoryError::IssuerKeys(cause) => {
                write!(f, "the issuer's discovery or key set failed: {cause}")
            }
            DirectoryError::Profile(cause) => {
                write!(f, "reading a local person's profile failed: {cause}")
            }
        }
    }
}

impl std::error::Error for DirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DirectoryError::SignIn { source } => Some(source.as_ref()),
            DirectoryError::Whoami(cause)
            | DirectoryError::Resolve(cause)
            | DirectoryError::IssuerKeys(cause)
            | DirectoryError::Profile(cause) => Some(&**cause),
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
///
/// A client or a session made with a tuning holds it to bounds, and never
/// panics on one: every duration is taken at most a year (so `Duration::MAX`
/// for "never" is a year, not an overflow), and
/// [`remote_profiles_timeout`](Self::remote_profiles_timeout) is raised to at
/// least [`remote_profile_timeout`](Self::remote_profile_timeout).
#[derive(Debug, Clone)]
pub struct Tuning {
    /// Per request of the directory client (the asker lookup, the key set, the
    /// directory module, the profiles), connect to the last byte of the body.
    /// The service session's own requests (the sign-in and the refresh) are held
    /// to `flow_request_timeout` instead.
    pub request_timeout: Duration,
    /// The whole headless sign-in, which is several requests. An outer bound is
    /// never shorter than the request it wraps: a value below
    /// `flow_request_timeout` is raised to it, so that a request is ended by its
    /// own typed timeout and never cut off earlier by this one.
    pub sign_in_timeout: Duration,
    /// Per request of the headless sign-in (`/authorize`, `/sign_in`, `/token`)
    /// and of the refresh, connect to the last byte of the answer (the body
    /// included). A request that gets no answer in this time fails the attempt
    /// at once as the transient [`AuthError::TimedOut`], so a server that goes
    /// silent costs this, not `sign_in_timeout`. This is the only clock a
    /// refresh has: nothing shorter wraps it, so a refresh the server answers
    /// within this time is never abandoned for a sign-in.
    pub flow_request_timeout: Duration,
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
    /// One read of a user-of-another-server's profile, connect to the last byte,
    /// counted from when the read gets its place. A foreign server that is
    /// slower costs a search this and no more: that person is
    /// `not_yet_published`, and is remembered as such for `remote_miss_ttl`. Held
    /// below `request_timeout`, which still ends a read that is somehow not ended
    /// by this.
    pub remote_profile_timeout: Duration,
    /// All the remote profile reads of one search together, counted from the
    /// moment the first is started (the local reads of a search come before and
    /// are not part of it), the wait for one of the [`PROFILE_READS_AT_ONCE`]
    /// places included. A read still running at the end is ended there (its
    /// own bound is the earlier of this and `remote_profile_timeout`) and its
    /// person is `not_yet_published`; a row that never got a place is not asked.
    /// So many slow foreign servers cannot stretch a search past this: it is
    /// what remote reads add to a search's critical path, and a host with a
    /// deadline of its own budgets for it.
    ///
    /// Raised to `remote_profile_timeout` when it is shorter: it is a total, and
    /// a total below one read's bound would cut every read before its own bound.
    pub remote_profiles_timeout: Duration,
    /// How long a remote person's claimed DID is kept. Short, because a claim
    /// can change and nothing confirms it; it is kept apart from the verified
    /// cache and never enters it.
    pub unconfirmed_ttl: Duration,
    /// How long "no usable claim" of a remote person is kept (no field, a value
    /// that is not a DID, a server that failed or was too slow, a read the total
    /// ended), so that a dead foreign server costs one wait and not one per
    /// search.
    pub remote_miss_ttl: Duration,
    /// The most entries each cache holds.
    pub max_cache_entries: usize,
    /// The most bytes of any one response body.
    pub max_body_bytes: usize,
}

/// No duration of a [`Tuning`] is taken above this. `Duration::MAX` is the usual
/// spelling of "never", and added to an `Instant` it overflows and panics, so
/// every duration is held to a year when a client is made: a lifetime that long
/// is "never" for a cache, and a timeout that long is no bound a service would
/// notice.
const TUNING_CEILING: Duration = Duration::from_secs(365 * 24 * 60 * 60);

impl Tuning {
    /// The tuning a client works with: every duration held to [`TUNING_CEILING`],
    /// and the total for the remote reads of a search at least as long as one
    /// read (a total below it would cut every read before its own bound).
    fn held_to_bounds(mut self) -> Tuning {
        for duration in [
            &mut self.request_timeout,
            &mut self.sign_in_timeout,
            &mut self.flow_request_timeout,
            &mut self.token_refresh_margin,
            &mut self.resolve_hit_ttl,
            &mut self.resolve_miss_ttl,
            &mut self.failed_sign_in_cooldown,
            &mut self.keys_ttl,
            &mut self.keys_refetch_interval,
            &mut self.verified_ttl,
            &mut self.remote_profile_timeout,
            &mut self.remote_profiles_timeout,
            &mut self.unconfirmed_ttl,
            &mut self.remote_miss_ttl,
        ] {
            *duration = (*duration).min(TUNING_CEILING);
        }
        self.remote_profiles_timeout = self
            .remote_profiles_timeout
            .max(self.remote_profile_timeout);
        self
    }
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            request_timeout: Duration::from_secs(5),
            sign_in_timeout: Duration::from_secs(30),
            flow_request_timeout: FLOW_REQUEST_TIMEOUT,
            token_refresh_margin: Duration::from_secs(30),
            resolve_hit_ttl: Duration::from_secs(10 * 60),
            resolve_miss_ttl: Duration::from_secs(60),
            failed_sign_in_cooldown: Duration::from_secs(5),
            keys_ttl: Duration::from_secs(5 * 60),
            keys_refetch_interval: Duration::from_secs(30),
            verified_ttl: Duration::from_secs(10 * 60),
            remote_profile_timeout: Duration::from_secs(3),
            remote_profiles_timeout: Duration::from_secs(6),
            unconfirmed_ttl: Duration::from_secs(5 * 60),
            remote_miss_ttl: Duration::from_secs(60),
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

/// A DID is at most [`DID_MAX`] bytes (the `/resolve` bound) and has no control
/// characters.
fn check_asker(did: &str) -> Result<(), DirectoryError> {
    if did.is_empty() || did.len() > DID_MAX || did.chars().any(char::is_control) {
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

/// Whether `s` is a DID in the W3C syntax: `did:`, a method name of lowercase
/// letters and digits, `:`, and a method-specific id of letters, digits,
/// `. - _ :` and `%XX` that does not end in `:`. ASCII only, at most
/// [`DID_MAX`] bytes.
///
/// The verified path asks only that a signed `sub` starts with `did:`: it was
/// signed by the issuer. A claim is text another server's user chose, shown to a
/// person and pasted into a grant, so it is held to the whole grammar: no
/// space, control character, markup or look-alike letter gets through.
fn is_did(s: &str) -> bool {
    if s.len() > DID_MAX {
        return false;
    }
    let Some((method, id)) = s.strip_prefix("did:").and_then(|r| r.split_once(':')) else {
        return false;
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || id.is_empty()
        || id.ends_with(':')
    {
        return false;
    }
    let id = id.as_bytes();
    let mut i = 0;
    while i < id.len() {
        match id[i] {
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':') => i += 1,
            b'%' if id
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                i += 3
            }
            _ => return false,
        }
    }
    true
}

/// The DID a remote person's `io.inblock.did` value claims: its `did` member,
/// when that is a well-formed DID. The proof beside it is not looked at (a
/// foreign issuer is not ours to trust), and a bare string, which is the legacy
/// shape without even a member, is no claim.
fn claim_from_field(field: &Value) -> Option<ClaimedDid> {
    let did = field.get("did")?.as_str()?;
    is_did(did).then(|| ClaimedDid(did.to_string()))
}

fn http_client(tuning: &Tuning) -> Result<reqwest::Client, DirectoryError> {
    http_client_within(tuning.request_timeout)
}

fn http_client_within(timeout: Duration) -> Result<reqwest::Client, DirectoryError> {
    reqwest::Client::builder()
        .timeout(timeout)
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
    register_with(&Tuning::default(), issuer_url, redirect_uri, client_name).await
}

/// [`register_public_client`] under the bounds of `tuning` (its request timeout
/// and body cap), which a test sets.
pub(crate) async fn register_with(
    tuning: &Tuning,
    issuer_url: &str,
    redirect_uri: &str,
    client_name: &str,
) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Registered {
        client_id: String,
    }

    let base = clean_base("issuer_url", issuer_url)?;
    let resp = http_client_within(tuning.flow_request_timeout)?
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": [redirect_uri],
            "client_name": client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }))
        .send()
        .await
        .map_err(|e| request_failed(e.without_url(), "OIDC client registration request failed"))?;

    // An error answer is its status and, when the body names one, a short code;
    // a 429 is the typed rate limit of the other endpoints. The body is read
    // under the cap, and its status still counts when it is over.
    if !resp.status().is_success() {
        return Err(Refusal::of(resp).await.into_flow_error("OIDC registration"));
    }
    let body = read_at_most(resp, tuning.max_body_bytes)
        .await
        .map_err(|e| request_failed(e, "reading the OIDC registration answer failed"))?;
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
            tuning: tuning.held_to_bounds(),
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

    /// Make the next [`access_token`](Self::access_token) renew, because the
    /// homeserver refused `rejected`.
    ///
    /// For a host that owns sign-in retries (its own gate and backoff) and so
    /// runs its client with
    /// [`DirectoryConfig::sign_in_again_on_401`] off: it calls this with the
    /// token it sent, then `access_token()` through its gate. The renewal is a
    /// fresh sign-in with the key, as the client's own retry makes: a refused
    /// access token says nothing good of its refresh token, which is dropped.
    ///
    /// Only the token it names is discarded. When another caller has already
    /// renewed (the session now holds a different token), nothing happens, so a
    /// burst of refused requests that all report the same token costs one
    /// renewal, not one each. A failed renewal's cooldown still applies to the
    /// next `access_token()`.
    pub async fn invalidate_access_token(&self, rejected: &str) {
        let mut tokens = self.tokens.lock().await;
        if tokens.access.as_deref() == Some(rejected) {
            tokens.access = None;
            tokens.renew_at = None;
            tokens.refresh = None;
        }
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
            // One clock: the request is held to `flow_request_timeout` by its own
            // client, body included. Nothing shorter wraps it, which would
            // abandon a refresh the server answers in time.
            let attempt = refresh_within(
                self.tuning.flow_request_timeout,
                &self.issuer_url,
                &self.client_id,
                &refresh_token,
                &self.did,
            )
            .await;
            match attempt {
                Ok(issued) => return Ok(self.keep(tokens, issued)),
                // A 429 means the server did not process the refresh: the token
                // is unspent. Put it back, and report the rate limit with its
                // hint, as the sign-in does, instead of signing in at once on top
                // of a server that asked for fewer requests.
                Err(source) if crate::is_rate_limited(&source) => {
                    tokens.refresh = Some(refresh_token);
                    return Err(Fault::of(&source));
                }
                // Refused as invalid (400 or 401 `invalid_grant`), or no answer in
                // time (the server may have rotated the token before the answer
                // was lost), or another failure: the token is not to be trusted
                // any more, and the key signs in.
                Err(_) => {}
            }
        }
        self.sign_in(tokens).await
    }

    async fn sign_in(&self, tokens: &mut Tokens) -> Result<String, Fault> {
        // Never shorter than one request, whose timeout it wraps.
        let bound = self
            .tuning
            .sign_in_timeout
            .max(self.tuning.flow_request_timeout);
        let attempt = tokio::time::timeout(
            bound,
            authenticate_with_device_within(
                self.tuning.flow_request_timeout,
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
                "the sign-in did not finish within {bound:?}"
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
        // A lifetime that overflows the clock keeps nothing: the safe side of a
        // cache. (A client holds its tuning to a year, so this is a backstop.)
        if let Some(expires) = now.checked_add(ttl) {
            self.entries.insert(key, (value, expires));
        }
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
    /// A remote person's MXID to the DID they claim; `None` is "no usable
    /// claim". Not the verified cache: nothing in here was ever checked.
    claims: TtlCache<String, KeptClaim>,
    /// The reads of a remote person's profile that are running now, one per
    /// person: a search that wants one that is running waits for it.
    flights: HashMap<String, Arc<Flight>>,
    /// How many entries were ever stored in `claims`; a read notes it when it
    /// begins (see [`Caches::store_claim`]).
    claim_writes: u64,
    keys: Option<(Arc<IssuerKeys>, Instant)>,
}

/// What `claims` holds for one person.
#[derive(Clone)]
struct KeptClaim {
    claim: Option<ClaimedDid>,
    /// Which store this was, counting from one (`Caches::claim_writes`).
    written: u64,
}

/// A running read: `None` while it runs, then its outcome. The sender is dropped
/// when the read ends without one (its caller went away), which wakes the
/// waiters to look again.
type Flight = watch::Sender<Option<Option<ClaimedDid>>>;

impl Caches {
    fn new() -> Self {
        Caches {
            resolved: TtlCache::new(),
            verified: TtlCache::new(),
            claims: TtlCache::new(),
            flights: HashMap::new(),
            claim_writes: 0,
            keys: None,
        }
    }

    /// Keep what a read of `mxid` found, unless the entry for that person is
    /// newer than the read: one stored after the read began (`began` is the
    /// count of stores when it did) came from a read that began later, and a
    /// slower read that ends last must not put its older, or failed, answer in
    /// its place. Reads of one person do not overlap (see `Inner::claim_of`), so
    /// this is a second line.
    fn store_claim(
        &mut self,
        mxid: &str,
        claim: Option<ClaimedDid>,
        began: u64,
        now: Instant,
        ttl: Duration,
        cap: usize,
    ) {
        if let Some(kept) = self.claims.get(&mxid.to_string(), now) {
            if kept.written > began {
                return;
            }
        }
        self.claim_writes += 1;
        let written = self.claim_writes;
        self.claims.put(
            mxid.to_string(),
            KeptClaim { claim, written },
            now,
            ttl,
            cap,
        );
    }
}

/// How full the caches are; for a service's own diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub resolved: usize,
    pub verified: usize,
    /// Remote people's claims (and their "no usable claim"), kept apart from
    /// `verified`.
    pub remote_claims: usize,
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
    /// The homeserver's server name (`example.org` in `@alice:example.org`):
    /// Synapse's `server_name`, which is the part after the colon in its users'
    /// MXIDs, **not** the host the client API is served from when the two differ
    /// (`matrix.example.org` behind a delegation).
    ///
    /// Only the homeserver's own users carry a proof from this issuer. Every
    /// other server's users are never `verified`: their profile is read through
    /// this homeserver and a well-formed DID in it is `unconfirmed`, otherwise
    /// `not_yet_published`. A name that is not the homeserver's would make that
    /// split wrong for everybody, so the client checks it: the asker of
    /// [`DirectoryClient::search_for_asker`] and the owner of the token of
    /// [`DirectoryClient::search_as_user`] are the homeserver's own people, and
    /// when one is not on this name the search is the error
    /// [`DirectoryError::ServerNameMismatch`] and nothing else is asked. Both
    /// transports also ask the homeserver itself, once per client, through
    /// `GET /account/whoami`: with the user's token on the user transport and
    /// with the service's own token on the module transport. (An asker that does
    /// not exist has no MXID to check, and gets the empty result as before.)
    pub server_name: String,
    /// Whether [`DirectoryClient::search_for_asker`] signs the service in again
    /// itself when the directory module answers 401 (once, then retries once).
    /// `true` by default. A host that owns the sign-in retries (its own gate,
    /// its own backoff) sets `false`: a 401 is then the typed
    /// [`DirectoryError::Unauthorized`] and the host renews through
    /// [`ServiceSession::invalidate_access_token`].
    pub sign_in_again_on_401: bool,
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
            sign_in_again_on_401: true,
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

    /// Set [`sign_in_again_on_401`](Self::sign_in_again_on_401).
    pub fn with_sign_in_again_on_401(mut self, again: bool) -> Self {
        self.sign_in_again_on_401 = again;
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
    sign_in_again_on_401: bool,
    tuning: Tuning,
    clock: Clock,
    http: reqwest::Client,
    caches: Mutex<Caches>,
    /// Held across a fetch of the issuer's keys, so that only one runs.
    key_fetch: AsyncMutex<KeyFetch>,
    /// Fetches that have finished, read before waiting at `key_fetch`: a caller
    /// that finds it changed knows a fetch ran while it waited.
    key_fetches: AtomicU64,
    /// Set once the homeserver itself has vouched for `server_name`: its
    /// `whoami` (with a user's token, or with the service's own) named a person
    /// on it, and nothing else sets it. Never a mismatch, never a failure, never
    /// a string that the issuer built from the same configuration, and never a
    /// module answer: the module answers an asker it does not know with a normal
    /// `200` and no results, so an answer cannot tell the homeserver's own person
    /// from a string that matched. A wrong name is therefore answered with an
    /// error on every search of either transport.
    server_name_confirmed: AtomicBool,
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
    /// The raw `io.inblock.did` profile value, when there is one to check. Only
    /// a local row has one: a remote row's field is never checked for a proof.
    field: Option<Value>,
    /// What a remote row's profile claims, once it was read. Only a remote row
    /// has one.
    claim: Option<ClaimedDid>,
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
            sign_in_again_on_401,
            tuning,
            clock,
        } = config;
        if server_name.is_empty() || server_name.contains(|c: char| c.is_whitespace() || c == '@') {
            return Err(invalid("server_name is not a Matrix server name"));
        }
        let tuning = tuning.held_to_bounds();
        let http = http_client(&tuning)?;
        Ok(DirectoryClient {
            inner: Arc::new(Inner {
                issuer_url: clean_base("issuer_url", &issuer_url)?,
                homeserver_url: clean_base("homeserver_url", &homeserver_url)?,
                server_name,
                sign_in_again_on_401,
                tuning,
                clock,
                http,
                caches: Mutex::new(Caches::new()),
                key_fetch: AsyncMutex::new(KeyFetch::default()),
                key_fetches: AtomicU64::new(0),
                server_name_confirmed: AtomicBool::new(false),
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
            remote_claims: caches.claims.live(now),
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
    /// not called). A lookup that fails is the error of that search, as
    /// [`DirectoryError::Resolve`] with the failure inside (a 401, a 404, a 429, a
    /// 5xx, a timeout or a body that is not the contract), is not kept, and
    /// neither `whoami` nor the module is asked; it is never the plain error of
    /// the same status, which is the module's own. Then the directory module is
    /// asked with the service's token. A
    /// 401 signs the service in again once and retries once (unless the client
    /// was made with [`DirectoryConfig::sign_in_again_on_401`] off: then a 401 is
    /// the typed [`DirectoryError::Unauthorized`] at once, and the host renews
    /// with [`ServiceSession::invalidate_access_token`]); a 403 is
    /// [`DirectoryError::NotAdmitted`]; a 429 is [`DirectoryError::RateLimited`].
    /// Every local hit is then proof-checked; the profile of each hit on another
    /// server is read for a claim ([`DidState::Unconfirmed`]). The proof check
    /// needs the issuer's discovery document and key set, fetched after the
    /// module answered; a fetch that fails with none held is the error of that
    /// search, as [`DirectoryError::IssuerKeys`] with the failure inside (a 401, a
    /// 404, a 5xx, a timeout, a body that is not the document), never the plain
    /// error of the same status, which is the module's own, and never the service
    /// token refused: the module took the token, and the documents are public. It
    /// is not kept. A proof the held key set cannot judge is `invalid` for its row
    /// and fails nothing.
    ///
    /// An asker who is not on [`DirectoryConfig::server_name`] is
    /// [`DirectoryError::ServerNameMismatch`]: the asker is the homeserver's own
    /// person, so the configured name is wrong. Nothing is asked of the module.
    ///
    /// The asker's name is not the homeserver's word, though: the issuer builds
    /// the MXID from its own configuration, so an issuer and a client that share
    /// one wrong (delegated) name agree on it, and the module answers an asker it
    /// does not know with a plain empty `200`. The first search of the client
    /// therefore also asks `GET /account/whoami` with the service's own token
    /// (the service account is a local user of the homeserver, so its real MXID
    /// is on the real name), once per client and before the module; a name that
    /// is not the one configured is [`DirectoryError::ServerNameMismatch`] and the
    /// module is not asked. A `whoami` that fails is the error of that search,
    /// as [`DirectoryError::Whoami`] with the failure inside (a 401 signs in
    /// again and retries once under the same rule as the module's, and with
    /// `sign_in_again_on_401` off it is `Whoami(Unauthorized)` at once), and is
    /// not kept, so the next search asks again. The plain error of the same
    /// status is the module's own answer, so the two are never confused. An asker
    /// that does not exist has no MXID, gets the empty result and asks nothing.
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

        // A failure of this request is the issuer's, and is told as that: the
        // same status from `whoami` or the module means something else.
        let Some(asker) = inner
            .resolve_asker(asker_did)
            .await
            .map_err(|cause| DirectoryError::Resolve(Box::new(cause)))?
        else {
            return Ok(DirectoryResults::unasked());
        };
        // The asker comes from our own issuer, so it is a person of the
        // homeserver itself. One that is not on `server_name` says the name is
        // wrong, and then every local person would be taken for a foreign one.
        // That is a refusal only: the issuer builds the MXID from its own
        // configuration, so a match proves nothing about the homeserver.
        inner.refuse_other_server(&asker)?;

        // Nor is the asker's name the homeserver's word: when the issuer and
        // this client share one wrong (delegated) name, the string matches and
        // the module answers the unknown asker with a plain empty 200. So the
        // homeserver is asked, once per client, who the service itself is (a
        // local user of it), before the module is. A failure is this search's
        // error and is not kept.
        let mut token = session.access_token().await?;
        if !inner.server_name_confirmed.load(Ordering::Acquire) {
            if let Err(e) = inner.confirm_server_name_of_token(&token).await {
                let refused = matches!(e.whoami_cause(), Some(DirectoryError::Unauthorized));
                if !(refused && inner.sign_in_again_on_401) {
                    return Err(e);
                }
                token = session.token_after_rejection(&token).await?;
                inner.confirm_server_name_of_token(&token).await?;
            }
        }
        let body = match inner.ask_module(&token, &asker, term, limit).await {
            Err(DirectoryError::Unauthorized) if inner.sign_in_again_on_401 => {
                let token = session.token_after_rejection(&token).await?;
                inner.ask_module(&token, &asker, term, limit).await?
            }
            other => other?,
        };
        // The answer confirms nothing, whatever its status or content: the
        // module answers an unknown or foreign asker with a plain empty 200.
        inner.build_results(&body, limit).await
    }

    /// Search with the user's own Matrix token.
    ///
    /// Synapse's standard `user_directory/search`, then each hit's
    /// `io.inblock.did` profile field, read without a credential, at most eight
    /// at a time. A 401 is [`DirectoryError::Unauthorized`] (the token is the
    /// caller's to renew), or `Whoami(Unauthorized)` when `whoami` refused it.
    ///
    /// The first search asks `GET /account/whoami` with the token, once, to learn
    /// that its owner is on [`DirectoryConfig::server_name`]; one who is not is
    /// [`DirectoryError::ServerNameMismatch`] and the directory is not asked. A
    /// `whoami` that fails is [`DirectoryError::Whoami`] with the failure inside,
    /// so the first search of a client with a stale token is
    /// `Whoami(Unauthorized)`, and a later one, once the name is confirmed, is
    /// the plain `Unauthorized` of the directory call.
    /// Only `whoami` confirms the name: neither a module answer on the same
    /// client (the module answers an asker it does not know with a normal empty
    /// `200`) nor the asker's name (the issuer builds it from its own
    /// configuration) does. The module transport asks `whoami` too, with the
    /// service's own token, and the one that comes first confirms the name for
    /// both. A local profile that cannot be read fails the search:
    /// its state is unknown, and `invalid` would be a claim about the person. It
    /// is [`DirectoryError::Profile`] with the failure inside (a 401, 403, 429,
    /// 5xx, a timeout, a body that is not JSON), because that read carries no
    /// credential: a `Profile(Unauthorized)` is not the user's token refused, and
    /// only the plain [`Unauthorized`](DirectoryError::Unauthorized) of the
    /// `user_directory/search` call (or of `whoami`) is. A person with no profile,
    /// or no field, or a field that is no proof, fails nothing: it is that
    /// person's `not_yet_published` (or `invalid`). A
    /// profile of another server's user is read for a claim
    /// ([`DidState::Unconfirmed`]) and never fails the search. A failure to get
    /// the issuer's discovery document or key set, with none held, fails it as
    /// [`DirectoryError::IssuerKeys`], never as the plain error of its status.
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
        inner.confirm_server_name_of_token(user_token).await?;

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
        inner.read_profiles(&mut rows, Reads::All).await?;
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
            claim: None,
        });
    }
    Ok(Rows {
        rows,
        limited: answer.limited,
    })
}

/// Which rows' profiles a search has to read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    /// Every row's: the user transport, whose rows carry no field.
    All,
    /// Only the rows of other servers: the module already carries the field of
    /// each local person.
    RemoteOnly,
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

/// What a search finds when it looks for a remote person's claim.
enum Look {
    /// In the cache: a claim, or `None` for "no usable claim".
    Kept(Option<ClaimedDid>),
    /// Another search is reading; the outcome arrives here.
    Running(watch::Receiver<Option<Option<ClaimedDid>>>),
    /// Nothing kept or running, and the caller holds no place yet.
    Idle,
    /// Nothing kept or running: this caller reads.
    Lead(Lead),
}

/// The one read of a remote person's profile that is running. Dropping it, as a
/// cancelled search does, ends the read with no outcome and removes it, so the
/// searches that waited look again instead of waiting for a read nobody runs.
struct Lead {
    inner: Arc<Inner>,
    mxid: String,
    flight: Arc<Flight>,
    /// `Caches::claim_writes` when the read began.
    began: u64,
}

impl Lead {
    /// Keep the outcome (a claim for `unconfirmed_ttl`, "no usable claim" for
    /// `remote_miss_ttl`) and hand it to the searches that waited. The outcome is
    /// kept before the read is removed, so nobody finds neither.
    fn finish(self, claim: Option<ClaimedDid>) {
        let tuning = &self.inner.tuning;
        let ttl = if claim.is_some() {
            tuning.unconfirmed_ttl
        } else {
            tuning.remote_miss_ttl
        };
        let now = self.inner.now();
        self.inner.caches.lock().unwrap().store_claim(
            &self.mxid,
            claim.clone(),
            self.began,
            now,
            ttl,
            tuning.max_cache_entries,
        );
        self.flight.send_replace(Some(claim));
    }
}

impl Drop for Lead {
    fn drop(&mut self) {
        if let Ok(mut caches) = self.inner.caches.lock() {
            if caches
                .flights
                .get(&self.mxid)
                .is_some_and(|running| Arc::ptr_eq(running, &self.flight))
            {
                caches.flights.remove(&self.mxid);
            }
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

    /// The people of the homeserver itself must be on `server_name`. The whole
    /// split between "a local person, whose proof is checked" and "a person of
    /// another server, whose claim is only shown" rests on that name, and a name
    /// that is not the homeserver's (a delegated host, a typo) would turn every
    /// local person into a foreign one: their valid proof ignored, their unsigned
    /// `did` member shown. `local` is a person known to be the homeserver's own.
    ///
    /// Only the homeserver can say so, and only through `GET /account/whoami`
    /// (see `confirm_server_name_of_token`). This check alone is a per-call
    /// refusal and never confirms anything, and neither does a module answer (see
    /// `server_name_confirmed`).
    fn refuse_other_server(&self, local: &str) -> Result<(), DirectoryError> {
        if !self.is_local(local) {
            return Err(DirectoryError::ServerNameMismatch);
        }
        Ok(())
    }

    /// The check by the homeserver's own word: the token's owner
    /// (`GET /account/whoami`) is a person of the homeserver itself. The token is
    /// a user's (the user transport has no asker) or the service's (the module
    /// transport, whose asker string the issuer built). Asked once, with the first
    /// search of either transport, and not again after the name matched; a
    /// mismatch or a failure is never kept.
    ///
    /// A failure to get an answer from `whoami` is [`DirectoryError::Whoami`],
    /// whatever it was (a status, a timeout, a body without a user): the same
    /// status means something else from the directory itself, and a host cannot
    /// tell the two apart otherwise. A person of another server is
    /// [`DirectoryError::ServerNameMismatch`]: `whoami` answered.
    async fn confirm_server_name_of_token(&self, token: &str) -> Result<(), DirectoryError> {
        if self.server_name_confirmed.load(Ordering::Acquire) {
            return Ok(());
        }
        let user = self
            .whoami_user(token)
            .await
            .map_err(|cause| DirectoryError::Whoami(Box::new(cause)))?;
        self.refuse_other_server(&user)?;
        self.server_name_confirmed.store(true, Ordering::Release);
        Ok(())
    }

    /// `GET /account/whoami` with `token`: the MXID it names. Its errors are the
    /// plain ones of the request; [`confirm_server_name_of_token`] marks them as
    /// the `whoami` stage's.
    async fn whoami_user(&self, token: &str) -> Result<String, DirectoryError> {
        let reply = self
            .send(
                self.http
                    .get(format!(
                        "{}/_matrix/client/v3/account/whoami",
                        self.homeserver_url
                    ))
                    .bearer_auth(token),
            )
            .await?;
        let body = reply.ok_body()?;
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("user_id")?.as_str().map(str::to_string))
            .filter(|user| is_mxid(user))
            .ok_or_else(|| DirectoryError::Protocol("whoami names no user".into()))
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
            // A 429 is known by its status and its `Retry-After` header: a body
            // that cannot be read (the connection dropped, a stall) takes
            // neither, so the caller still gets the rate limit and its hint.
            Err(_) if status == 429 => Vec::new(),
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
    /// mappings and misses are cached, for different times. Its errors are the
    /// plain ones of the request; `search_for_asker` marks them as the `resolve`
    /// stage's ([`DirectoryError::Resolve`]).
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

    /// From a module answer to the 4.1 result. The module carries the field of
    /// each local person; the claim of a person on another server is read here.
    async fn build_results(
        self: &Arc<Self>,
        body: &[u8],
        limit: u32,
    ) -> Result<DirectoryResults, DirectoryError> {
        let mut rows = parse_rows(body)?;
        rows.cut(limit);
        self.read_profiles(&mut rows, Reads::RemoteOnly).await?;
        self.assemble(rows).await
    }

    /// Read the `io.inblock.did` profile of the rows: the local people first,
    /// then the people of other servers, each group at most
    /// [`PROFILE_READS_AT_ONCE`] at a time, so the two never are in flight
    /// together.
    ///
    /// Local before remote, so that a foreign server can never delay the check of
    /// a local person: a slow or dead one holds a place for its whole bound, and
    /// reads that queue behind it wait. The local reads are to this homeserver
    /// and are quick; the remote ones are the slow kind and bounded as below.
    async fn read_profiles(
        self: &Arc<Self>,
        rows: &mut Rows,
        which: Reads,
    ) -> Result<(), DirectoryError> {
        if which == Reads::All {
            self.read_local_profiles(rows).await?;
        }
        self.read_remote_profiles(rows).await
    }

    /// The local rows' profiles, whose field is the proof to check. A read can
    /// fail, and then the first failure ends the search and aborts the reads
    /// still running: that person's state is unknown. The failure is
    /// [`DirectoryError::Profile`], so that it is not mistaken for the answer of
    /// the user-directory call, which carries the token this read does not. What
    /// touches one person only (no profile, no field, a field that is no proof)
    /// is not a failure here: it is that row's state.
    async fn read_local_profiles(self: &Arc<Self>, rows: &mut Rows) -> Result<(), DirectoryError> {
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
            let (index, field) = done.map_err(|_| {
                DirectoryError::Profile(Box::new(DirectoryError::Unavailable(
                    "a profile read was lost".into(),
                )))
            })?;
            rows.rows[index].field =
                field.map_err(|cause| DirectoryError::Profile(Box::new(cause)))?;
        }
        Ok(())
    }

    /// The remote rows' profiles, read through this homeserver (which asks the
    /// person's own, over federation) for a claimed DID. It never fails the
    /// search: no field, an unreadable one, a value that is not a DID, a server
    /// that is slow or down, all leave the row without a claim. Each read is held
    /// to [`Tuning::remote_profile_timeout`] and all of them together to
    /// [`Tuning::remote_profiles_timeout`] from the start of this step, the wait
    /// for a place included.
    ///
    /// Eight places and a total of two bounds mean at most sixteen slow servers
    /// are waited out in one search. A row behind them is not asked in that
    /// search and is `not_yet_published`; every server that was waited out is
    /// remembered, so the next search asks the rest.
    async fn read_remote_profiles(self: &Arc<Self>, rows: &mut Rows) -> Result<(), DirectoryError> {
        let permits = Arc::new(Semaphore::new(PROFILE_READS_AT_ONCE));
        let began = tokio::time::Instant::now();
        let remote_deadline = began
            .checked_add(self.tuning.remote_profiles_timeout)
            .unwrap_or(began);
        let mut reads = JoinSet::new();
        for (index, row) in rows.rows.iter().enumerate() {
            if self.is_local(&row.mxid) {
                continue;
            }
            let (inner, permits, mxid) = (self.clone(), permits.clone(), row.mxid.clone());
            reads.spawn(async move {
                (
                    index,
                    inner.claim_of(&mxid, &permits, remote_deadline).await,
                )
            });
        }
        while let Some(done) = reads.join_next().await {
            let (index, claim) =
                done.map_err(|_| DirectoryError::Unavailable("a profile read was lost".into()))?;
            rows.rows[index].claim = claim;
        }
        Ok(())
    }

    /// What the search learns of one remote person: their claim, or `None` for
    /// "no usable claim", whether kept, read now by this call, or read now by
    /// another search that this one waited for. Never fails.
    ///
    /// - A claim in the cache, or a read of this person already running, costs no
    ///   place: concurrent searches for the same person make **one** read, and
    ///   the others take its outcome.
    /// - Otherwise this call needs one of the `permits` (held to `deadline`, the
    ///   end of the search's total) and then leads: it registers the read, so
    ///   that everyone arriving meanwhile waits, reads, keeps the outcome and
    ///   hands it on.
    /// - A leader that is dropped (its search was) ends the read with no outcome;
    ///   the searches that waited look again, and one of them reads.
    async fn claim_of(
        self: &Arc<Self>,
        mxid: &str,
        permits: &Arc<Semaphore>,
        deadline: tokio::time::Instant,
    ) -> Option<ClaimedDid> {
        let mut permit: Option<OwnedSemaphorePermit> = None;
        loop {
            match self.look_for_claim(mxid, permit.is_some()) {
                Look::Kept(claim) => return claim,
                Look::Running(mut outcome) => {
                    // Someone else is reading: this call needs no place.
                    permit = None;
                    match tokio::time::timeout_at(deadline, outcome.wait_for(Option::is_some)).await
                    {
                        Ok(Ok(done)) => return done.clone().flatten(),
                        // The read ended with no outcome: look again.
                        Ok(Err(_)) => {}
                        // The total ended first.
                        Err(_) => return None,
                    }
                }
                Look::Idle => {
                    // The wait for a place is held to the total; the read is
                    // too, but by its own bound (see `read_claim`), so that what
                    // it learns is kept.
                    match tokio::time::timeout_at(deadline, permits.clone().acquire_owned()).await {
                        // `timeout_at` polls the wait first, so a place that is
                        // free is taken even after the deadline. A read that
                        // began there would be cancelled on its first poll and
                        // kept as a miss for a server that was never asked, and
                        // the searches waiting on it would adopt that.
                        Ok(Ok(place)) if tokio::time::Instant::now() >= deadline => {
                            drop(place);
                            return None;
                        }
                        Ok(Ok(place)) => permit = Some(place),
                        _ => return None,
                    }
                }
                Look::Lead(lead) => {
                    let _place = permit;
                    let claim = self.read_claim(mxid, deadline).await;
                    lead.finish(claim.clone());
                    return claim;
                }
            }
        }
    }

    /// One look at the person's entry, under one lock. With `may_lead` (the
    /// caller holds a place) and nothing kept or running, the caller becomes the
    /// one that reads; without it, `Idle` says a place is needed first.
    fn look_for_claim(self: &Arc<Self>, mxid: &str, may_lead: bool) -> Look {
        let now = self.now();
        let mut caches = self.caches.lock().unwrap();
        if let Some(kept) = caches.claims.get(&mxid.to_string(), now) {
            return Look::Kept(kept.claim);
        }
        if let Some(flight) = caches.flights.get(mxid) {
            return Look::Running(flight.subscribe());
        }
        if !may_lead {
            return Look::Idle;
        }
        let flight = Arc::new(watch::channel(None).0);
        caches.flights.insert(mxid.to_string(), flight.clone());
        Look::Lead(Lead {
            inner: self.clone(),
            mxid: mxid.to_string(),
            flight,
            began: caches.claim_writes,
        })
    }

    /// Read a remote person's profile for a claim. It never fails: anything but a
    /// well-formed DID in the field, or no answer within the read's bound, is "no
    /// usable claim". The caller keeps the outcome (see [`Lead::finish`]).
    ///
    /// The bound is the earlier of [`Tuning::remote_profile_timeout`] from now
    /// and `deadline`, the end of the search's total. The read ends by that
    /// bound itself, and does not have the total cut it off from outside: a read
    /// that began late would otherwise be dropped with nothing kept, and a dead
    /// server in the second wave would cost every search the same wait again.
    /// Only a caller that goes away (the search dropped) keeps nothing.
    async fn read_claim(&self, mxid: &str, deadline: tokio::time::Instant) -> Option<ClaimedDid> {
        let now = tokio::time::Instant::now();
        let bound = now
            .checked_add(self.tuning.remote_profile_timeout)
            .map_or(deadline, |own| own.min(deadline));
        let read = tokio::time::timeout_at(bound, self.read_profile(mxid)).await;
        match read {
            Ok(Ok(Some(field))) => claim_from_field(&field),
            _ => None,
        }
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
            let did = self
                .did_state(&row.mxid, row.field.as_ref(), row.claim.as_ref())
                .await?;
            results.push(DirectoryEntry {
                mxid: row.mxid,
                alias: row.alias,
                did,
            });
        }
        Ok(DirectoryResults {
            results,
            limited: rows.limited,
            // `assemble` is only reached with rows the homeserver sent.
            homeserver_answered: true,
        })
    }

    /// The proof check (plan 4.3).
    ///
    /// - another server's user: never `verified`, whatever their field carries.
    ///   `unconfirmed` with the DID they claim (`claim`, read by
    ///   [`Inner::read_profiles`]), else `not_yet_published`;
    /// - a local user with no field, no proof (a bare string, an object
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
        claim: Option<&ClaimedDid>,
    ) -> Result<DidState, DirectoryError> {
        if !self.is_local(mxid) {
            return Ok(claim.map_or(DidState::NotYetPublished, |claim| {
                DidState::Unconfirmed(claim.clone())
            }));
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
    /// stored, so the next search asks again. It is the issuer's, and is told as
    /// that ([`DirectoryError::IssuerKeys`]): the same failure from the module
    /// means something else, and these are public documents that take no token.
    /// (This is the one place a failure to get keys fails a search. A refetch for
    /// an unknown `kid` goes through [`Inner::keys_after_unknown_kid`], which
    /// never fails.)
    async fn keys(&self) -> Result<Arc<IssuerKeys>, DirectoryError> {
        if let Some(keys) = self.cached_keys() {
            return Ok(keys);
        }
        self.fetch_keys(None)
            .await
            .map_err(|cause| DirectoryError::IssuerKeys(Box::new(cause)))
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
        let now = self.now();
        self.caches.lock().unwrap().keys = Some((
            keys.clone(),
            now.checked_add(self.tuning.keys_ttl).unwrap_or(now),
        ));
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

    /// Run one vector through the same code the two transports end in, minus the
    /// profile reads: `profiles` says what they would have left.
    ///
    /// - a local user's stored `io.inblock.did` value (`null` is a 404), which on
    ///   the `user_directory` transport is the field to check;
    /// - a remote user's, which is read for a claim on both transports (`null` or
    ///   a missing entry is a 404).
    async fn run(vector: &Value) -> Value {
        let client = client_for(vector);
        let inner = &client.inner;
        let limit = vector["limit"].as_u64().unwrap() as u32;
        let (body, reads_local) = match vector["transport"].as_str().unwrap() {
            "module" => (&vector["module_response"], false),
            "user_directory" => (&vector["user_directory_response"], true),
            other => panic!("unknown transport {other}"),
        };
        let mut rows = parse_rows(&serde_json::to_vec(body).unwrap()).unwrap();
        rows.cut(limit);
        for row in &mut rows.rows {
            let stored = vector["profiles"].get(&row.mxid).filter(|v| !v.is_null());
            if inner.is_local(&row.mxid) {
                if reads_local {
                    row.field = stored.cloned();
                }
            } else {
                row.claim = stored.and_then(claim_from_field);
            }
        }
        serde_json::to_value(inner.assemble(rows).await.unwrap()).unwrap()
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
            "unconfirmed-remote-user",
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

    // -- the claims cache: a read never puts an older answer over a newer one ---

    #[test]
    fn a_read_never_puts_its_answer_over_one_stored_after_it_began() {
        let mut caches = Caches::new();
        let (now, ttl, cap) = (Instant::now(), Duration::from_secs(300), 16);
        let person = "@a:other.example";
        let claim = |did: &str| Some(ClaimedDid(did.to_string()));
        let kept = |caches: &mut Caches| {
            caches
                .claims
                .get(&person.to_string(), now)
                .map(|kept| kept.claim)
        };

        // A slow read begins; a fresher one begins after it, ends first and is stored.
        let slow = caches.claim_writes;
        let fresh = caches.claim_writes;
        caches.store_claim(person, claim("did:key:zFresh"), fresh, now, ttl, cap);
        assert_eq!(kept(&mut caches), Some(claim("did:key:zFresh")));

        // The slow one ends last. A failure of it is not put over the claim ...
        caches.store_claim(person, None, slow, now, ttl, cap);
        assert_eq!(kept(&mut caches), Some(claim("did:key:zFresh")), "a miss");
        // ... and neither is an older claim.
        caches.store_claim(person, claim("did:key:zOld"), slow, now, ttl, cap);
        assert_eq!(kept(&mut caches), Some(claim("did:key:zFresh")), "a claim");

        // A read that began after the entry was stored does replace it.
        let later = caches.claim_writes;
        caches.store_claim(person, None, later, now, ttl, cap);
        assert_eq!(kept(&mut caches), Some(None));

        // And one entry's age says nothing about another person's.
        let other = "@b:other.example";
        caches.store_claim(other, claim("did:key:zB"), slow, now, ttl, cap);
        assert!(caches.claims.get(&other.to_string(), now).is_some());
    }

    // -- the DID syntax of a claim -------------------------------------------

    #[test]
    fn is_did_takes_the_w3c_syntax_and_nothing_wider() {
        for good in [
            "did:key:z6MkjB72DotVCvtnuvPGeoDY5ejJTk5AkwQCBLUkVUwZpFY4",
            "did:pkh:eip155:1:0x4B23da593596D94035c57Adf6C2454216449B1B2",
            "did:web:example.com:user:alice",
            "did:web:example.com%3A8443",
            "did:ethr:0x1.2-3_4",
            "did:a:b",
        ] {
            assert!(is_did(good), "{good}");
        }
        let at_the_bound = format!("did:key:{}", "z".repeat(DID_MAX - "did:key:".len()));
        assert!(is_did(&at_the_bound));
        assert!(
            !is_did(&format!("{at_the_bound}z")),
            "one byte over the bound"
        );
        for bad in [
            "",
            "did:",
            "did:key",
            "did:key:",
            "did::abc",
            "did:KEY:abc",
            "did:ke y:abc",
            "did:key:ab c",
            "did:key:abc:",
            "did:key:abc\n",
            "did:key:<script>",
            "did:key:\"x\"",
            "did:key:a/b",
            "did:key:a%2",
            "did:key:a%zz",
            "did:key:zÄbc",
            "DID:key:abc",
            " did:key:abc",
            "did:key:abc ",
            "not a did",
            "https://example.org/did:key:abc",
        ] {
            assert!(!is_did(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_claim_is_the_did_member_and_only_that() {
        let claim = |v: Value| claim_from_field(&v).map(|c| c.as_str().to_string());
        assert_eq!(
            claim(json!({"did": "did:key:zA"})).as_deref(),
            Some("did:key:zA")
        );
        assert_eq!(
            claim(json!({"did": "did:key:zA", "proof": "x.y.z"})).as_deref(),
            Some("did:key:zA"),
            "a proof beside it is not looked at"
        );
        for none in [
            json!("did:key:zA"),
            json!(["did:key:zA"]),
            json!({"proof": "x.y.z"}),
            json!({"did": 7}),
            json!({"did": ["did:key:zA"]}),
            json!({"did": null}),
            json!({"did": "nope"}),
            json!(null),
        ] {
            assert_eq!(claim(none.clone()), None, "{none}");
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
                "A user of another homeserver is not_yet_published when their profile gives no claim, even though the module's own did_field for the row carries a valid proof for that MXID (it is not read for a remote row).",
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

        // Other servers' people: an unconfirmed claim, or nothing. `profiles` is
        // what their profile reads leave (null is a 404).
        let claimed_pkh = "did:pkh:eip155:1:0x4B23da593596D94035c57Adf6C2454216449B1B2";
        let remote_entry = |name: &str, state: Value| json!({"mxid": format!("@{name}:other.example"), "alias": name[..1].to_uppercase() + &name[1..], "did": state});
        let remote_hit = |name: &str, field: Option<Value>| {
            let mut h = json!({"user_id": format!("@{name}:other.example"), "display_name": name[..1].to_uppercase() + &name[1..]});
            if let Some(f) = field {
                h["did_field"] = f;
            }
            h
        };
        let mut unconfirmed = module(
            "unconfirmed-remote-user",
            "People of another homeserver are never verified. Their io.inblock.did profile field, read through the homeserver, gives an unconfirmed DID when its did member is a well-formed DID (a proof beside it is not looked at, and the module's own did_field for the row is not the source); no field, a bare string, a value that is not a DID, or a member that is not a string leaves not_yet_published. A local user is judged as before.",
            vec![
                remote_hit("remote", Some(remote_field.clone())),
                remote_hit("claimed", None),
                remote_hit("garbage", None),
                remote_hit("bare", None),
                remote_hit("nofield", None),
                hit("Alice", Some("Alice Example"), Some(field("Alice"))),
            ],
            vec![
                remote_entry("remote", json!({"state": "unconfirmed", "value": did("Remote")})),
                remote_entry("claimed", json!({"state": "unconfirmed", "value": claimed_pkh})),
                remote_entry("garbage", not_yet()),
                remote_entry("bare", not_yet()),
                remote_entry("nofield", not_yet()),
                entry("Alice", Some("Alice Example"), verified("Alice")),
            ],
        );
        unconfirmed["profiles"] = json!({
            "@remote:other.example": remote_field,
            "@claimed:other.example": {"did": claimed_pkh},
            "@garbage:other.example": {"did": "not a did"},
            "@bare:other.example": did("Bare"),
            "@nofield:other.example": null,
        });
        files.push(("unconfirmed-remote-user".into(), unconfirmed));

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
            "description": "Rows of the standard user directory plus the profile field of each local user; a remote user's profile is read for a claim, and this one has none.",
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

    /// The wait for a place is held to the deadline, but tokio polls the inner
    /// future first, so a place that is free is taken even when the deadline has
    /// passed. A read that begins there is cancelled on its first poll: it must
    /// not be started, and no miss may be kept for a server that was never asked.
    #[tokio::test]
    async fn a_place_taken_at_the_deadline_starts_no_read_and_keeps_no_miss() {
        // Nothing listens there: a read that did start would find no one.
        let client = DirectoryClient::new(DirectoryConfig::new(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9",
            "example.org",
        ))
        .unwrap();
        let inner = &client.inner;
        let permits = Arc::new(Semaphore::new(PROFILE_READS_AT_ONCE));
        for ahead in [Duration::ZERO, Duration::from_secs(1)] {
            let deadline = tokio::time::Instant::now()
                .checked_sub(ahead)
                .unwrap_or_else(tokio::time::Instant::now);
            assert!(inner
                .claim_of("@far:other.example", &permits, deadline)
                .await
                .is_none());
            assert_eq!(
                client.cache_stats().remote_claims,
                0,
                "no miss is kept (deadline {ahead:?} past)"
            );
            assert!(
                inner.caches.lock().unwrap().flights.is_empty(),
                "no read is registered"
            );
            assert_eq!(
                permits.available_permits(),
                PROFILE_READS_AT_ONCE,
                "the place is given back"
            );
        }
    }
}
