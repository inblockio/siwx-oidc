//! `remint-did-assertions`: the operator tool that re-signs the DID bindings a key rotation
//! left unverifiable.
//!
//! Every sign-in writes the Matrix profile field `io.inblock.did` = `{"did", "proof"}`. The
//! `proof` is a compact ES256 JWS, signed by the provider key of that day, and it carries no
//! expiry: the JWKS is its only anchor. A rotation that drops the old public key from the JWKS
//! (the right thing to do for an exposed key, see `docs/configuration.md`, "Key rotation")
//! leaves every proof of every person who has not signed in since unverifiable, and a consumer
//! then reports them as having no verified DID. This tool signs those bindings again under the
//! CURRENT key, through the code a sign-in uses ([`did_profile_value`] and
//! [`SynapseClient::publish_did_field`]).
//!
//! ```text
//! remint-did-assertions [--apply] [--limit N] [--delay-ms N]
//! ```
//!
//! It is the `siwx-oidc` binary under a second name: it needs the server's modules (the
//! configuration, the Synapse client, the DID assertion minter), which live in the binary
//! crate and not in the library. `main` runs it when the program is called
//! `remint-did-assertions` (the image links that name to `siwx-oidc`) or when the first
//! argument is `remint-did-assertions`.
//!
//! # Dry run by default
//!
//! Without `--apply` nothing is written. The report then says how many bindings WOULD be.
//!
//! # Where the DID comes from
//!
//! A binding is a statement "this DID controls this Matrix account", and what makes it true is
//! the derivation: an account's localpart is a function of its DID ([`siwx_oidc::mxid::localpart_for`],
//! or [`siwx_oidc::mxid::legacy_localpart`] for an account older than the hash shape), and the sign-in
//! that created or used the account proved the DID. The tool therefore never takes a DID on
//! the word of the profile. [`DidAuthority::confirm`] gets the claims found there (the
//! unsigned `did` member and the `sub` of the old proof, both CLAIMS, since an exposed old key
//! could have signed anything) and returns a DID only when siwx-oidc's own rules bind it to
//! exactly this account: the DID derives to the localpart, and `resolve_identity` (the rule a
//! sign-in uses, which keeps a legacy account on its legacy localpart) picks this localpart for
//! it. A claim that does not derive to the account is dropped, so a tampered profile or a
//! forged proof cannot make the tool sign a DID the account is not derived from. Two different
//! claims that both pass are ambiguous and are left alone. A claim must also be DID text a
//! sign-in writes ([`in_sign_in_form`]): its canonical form, or a `did:pkh:eip155` whose address
//! is the EIP-55 checksum encoding of the canonical one. The text signed is the claim as stored.
//!
//! There is no stored mapping from a Matrix account to its DID in siwx-oidc (the Redis keyspace
//! keys DIDs, never accounts), so the profile is the only place the exact-case DID text
//! survives; the derivation is what is trusted. [`DidAuthority`] is the seam for a stronger
//! source, should one exist.
//!
//! # Idempotent
//!
//! A binding is CURRENT when the profile's `did` equals the confirmed DID byte for byte and its
//! `proof` verifies under the current signing key (the `kid` is the key's own, the signature is
//! valid) with `iss` the issuer, `sub` the confirmed DID and `mxid` this account. Current
//! bindings are skipped, so a rerun after `--apply` writes nothing.
//!
//! # Rate limits
//!
//! The profile read is anonymous, and Synapse limits it per client IP (`rc_profile`, by default
//! a burst of 500 and then one a second), so on a long list every account past the burst is
//! answered 429. The tool waits out a 429 instead of failing the account (see `read_published`):
//! the server's `retry_after_ms` or `Retry-After`, at most 60 seconds, one second when there is
//! none, and the same read again; an account is given up on only after 30 reads in a row were
//! all 429. The waits are counted (`rate_limited_waits`). The shared client does not wait,
//! because the running service uses its read and a live request must not sleep; it only hands
//! the 429 and its hint back (`ProfileRateLimited`). The write needs none of this: Synapse's
//! handler for the profile `PUT` of a custom field calls no rate limiter (read on 1.163).
//!
//! # Output: counts only
//!
//! The report names no DID, no Matrix id, no token and no proof, and neither does any message
//! of this tool: a per-user failure is a class in a counter, never its text (the text of an
//! HTTP error carries the user's id). No tracing subscriber is installed, so the log lines of
//! the library, which do name accounts, go nowhere. Redis is never scanned: the tool uses the
//! lookups the server uses, and no key is listed or printed.

use std::collections::{BTreeMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use siwx_oidc::db::RedisClient;
use siwx_oidc::signing::{EcdsaSigningKey, ProviderSigner};

use crate::config::{self, Config, SigningBackend};
use crate::did_assertion::{did_profile_value, unverified_subject, verify_own_proof};
use crate::synapse_client::{
    matrix_user_id, AdminUserRow, ProfileRateLimited, PublishOutcome, SynapseClient,
};

/// The name the tool is called by.
pub(crate) const TOOL_NAME: &str = "remint-did-assertions";

/// The pause after each write, so a full run does not hammer the homeserver. `--delay-ms`
/// changes it.
const DEFAULT_DELAY_MS: u64 = 250;

/// A run stops after this many failures in a row: a homeserver or a signer that is down fails
/// every account the same way, and going on only repeats it.
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

/// How long to wait when the homeserver rate-limits a profile read and gives no hint of its own.
const RATE_LIMIT_DEFAULT_WAIT: Duration = Duration::from_secs(1);

/// The longest single wait on a rate-limited profile read, whatever the homeserver asks for.
const RATE_LIMIT_MAX_WAIT: Duration = Duration::from_secs(60);

/// An account whose profile read is rate-limited this many times in a row is given up on and
/// counted as a `read_profile` failure.
const RATE_LIMITED_READS_BEFORE_GIVING_UP: u32 = 30;

// -- Arguments --------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Args {
    pub apply: bool,
    /// Stop after this many writes (or, in a dry run, accounts that would be written).
    pub limit: Option<usize>,
    pub delay: Duration,
}

fn usage() -> &'static str {
    "usage: remint-did-assertions [--apply] [--limit N] [--delay-ms N]\n\
     \n\
     Signs again, under the current signing key, the DID bindings (the `proof` in the profile\n\
     field io.inblock.did) that no longer verify, for the accounts of this homeserver. Reads\n\
     the server's own configuration (SIWXOIDC_* / siwx-oidc.toml). Idempotent.\n\
     \n\
       --apply         actually write. Without it this is a dry run.\n\
       --limit N       stop after N writes (or N would-be writes in a dry run), for a staged\n\
                       first run.\n\
       --delay-ms N    pause after each write. Default 250.\n\
     \n\
     The report is counts only; it names no account, DID, token or proof."
}

/// The error for an argument this tool does not know: only the part that looks like an option
/// name is shown, never a value.
fn unknown_argument(arg: &str) -> anyhow::Error {
    let name = arg.split('=').next().unwrap_or_default();
    let looks_like_an_option = name.starts_with('-')
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if looks_like_an_option {
        anyhow!("unknown argument `{name}`\n\n{}", usage())
    } else {
        anyhow!("unknown argument (its text is not shown)\n\n{}", usage())
    }
}

/// What parsing the arguments gave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    Run(Args),
    Help,
}

pub(crate) fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Parsed> {
    let mut apply = false;
    let mut limit: Option<usize> = None;
    let mut delay_ms = DEFAULT_DELAY_MS;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut number = |option: &str| -> Result<u64> {
            inline
                .clone()
                .or_else(|| it.next())
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| anyhow!("{option} needs a whole number"))
        };
        match name {
            "--apply" if inline.is_none() => apply = true,
            "--apply" => bail!("--apply takes no value"),
            "--limit" => {
                let n = number("--limit")?;
                if n == 0 {
                    bail!("--limit needs a number above 0");
                }
                limit = Some(usize::try_from(n).unwrap_or(usize::MAX));
            }
            "--delay-ms" => delay_ms = number("--delay-ms")?,
            "-h" | "--help" => return Ok(Parsed::Help),
            _ => return Err(unknown_argument(&arg)),
        }
    }
    Ok(Parsed::Run(Args {
        apply,
        limit,
        delay: Duration::from_millis(delay_ms),
    }))
}

// -- The DID authority ------------------------------------------------------------------------

/// What an authority made of the claims found in one account's profile.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Confirmation {
    /// siwx-oidc binds exactly this DID to this account.
    Bound(String),
    /// No DID is bound to this account (no claim, or none that derives to it).
    NoMapping,
    /// A claim derives to this localpart, but the account is not the one siwx-oidc keeps for
    /// that DID (a legacy account exists for it, and this is a second one).
    NotCanonical,
    /// Two different claims both pass. Not resolved by guessing.
    Ambiguous,
}

/// The source of truth for "which DID is bound to this account".
#[async_trait]
pub(crate) trait DidAuthority: Send + Sync {
    /// `localpart` is the account on this homeserver; `claims` are the DID texts found in its
    /// profile (unverified, exact case). An implementation backed by a store may ignore them.
    /// An `Err` is a failure to find out, never a verdict.
    async fn confirm(&self, localpart: &str, claims: &[String]) -> Result<Confirmation>;
}

/// Whether `claim` is a DID in a form a sign-in writes.
///
/// `binds_to_localpart` is lenient on purpose (it must find the account whatever the spelling):
/// [`legacy_localpart`](siwx_oidc::mxid::legacy_localpart) folds case and turns `:` into `-`, so
/// a profile claim such as `did:pkh:eip155:1-0x…` or `did:pkh:EIP155:1:0X…` derives to a legacy
/// account although no sign-in can have written it, and signing it would put a binding for a
/// DID nobody holds under the provider's key. So a claim must also be a DID a sign-in accepts
/// ([`crate::resolve::check_did`]: the sign-in's own parsers, run on the canonical form) and
/// be one of the two texts a sign-in writes:
///
/// 1. its canonical form ([`siwx_oidc::mxid::canonicalize`]), byte for byte: a `did:key`,
///    a `did:peer`, a lower-case `did:pkh`; or
/// 2. a `did:pkh:eip155` that is its canonical form everywhere except the address, which is
///    exactly the EIP-55 checksum encoding of the canonical (lower-case) address
///    ([`is_eip55_did_pkh`]). The login page builds the DID from the address the wallet returns,
///    and a wallet returns the checksummed spelling, so this is what most wallet sign-ins write.
///
/// Nothing else: not an upper-case `0X` or `EIP155`, not a changed prefix, not a colon turned
/// into a dash, not an all-upper-case address, not a mixed-case address whose checksum is
/// wrong. No second parser, no second canonicalisation: the parsers and `canonicalize` are the
/// sign-in's, and the checksum is aqua-auth's, the one that builds the wallet DIDs.
///
/// The text that is signed is the claim as stored, so a checksummed DID stays checksummed.
/// For `did:key` and `did:peer` case is key material and is never folded, so a case change that
/// still reads as a valid key passes here; only the retired public keys could tell it from the
/// original (see the module doc).
fn in_sign_in_form(claim: &str) -> bool {
    crate::resolve::check_did(claim).is_ok()
        && (siwx_oidc::mxid::canonicalize(claim) == claim || is_eip55_did_pkh(claim))
}

/// Rule 2 of [`in_sign_in_form`]: `did:pkh:eip155:<reference>:0x<address>` whose text equals
/// `canonicalize(claim)` everywhere except the address digits, and whose address digits are
/// exactly [`aqua_auth::eip55_checksum`] of the address they spell. A lower-case address is
/// rule 1's, and is also accepted here when it has no letter (its checksum is itself).
fn is_eip55_did_pkh(claim: &str) -> bool {
    let Some((head, address)) = claim.rsplit_once(':') else {
        return false;
    };
    let canonical = siwx_oidc::mxid::canonicalize(claim);
    // The prefix (`did:pkh:eip155:<reference>`) is its own canonical text, and the separator
    // and `0x` are exactly as `canonicalize` leaves them.
    if !head.starts_with("did:pkh:eip155:") || canonical.get(..head.len()) != Some(head) {
        return false;
    }
    let Some(digits) = address.strip_prefix("0x") else {
        return false;
    };
    let mut bytes = [0u8; 20];
    digits.len() == 40
        && hex::decode_to_slice(digits, &mut bytes).is_ok()
        && aqua_auth::eip55_checksum(&bytes) == digits
}

/// The production authority: siwx-oidc's own derivation, see the module doc.
pub(crate) struct DerivationAuthority<'a> {
    pub synapse: &'a SynapseClient,
}

#[async_trait]
impl DidAuthority for DerivationAuthority<'_> {
    async fn confirm(&self, localpart: &str, claims: &[String]) -> Result<Confirmation> {
        let mut bound: Vec<&str> = Vec::new();
        let mut not_canonical = false;
        for claim in claims {
            // Cheap and local first: a claim the account is not derived from needs no probe.
            if !crate::resolve::binds_to_localpart(claim, localpart) {
                continue;
            }
            // It derives to this account, but is it text a sign-in writes?
            if !in_sign_in_form(claim) {
                not_canonical = true;
                continue;
            }
            // The rule a sign-in applies, probe included: a legacy account stays on its
            // legacy localpart, and only a DID with no legacy account gets the modern one.
            let resolved = crate::localpart::resolve_identity(claim, Some(self.synapse)).await?;
            if resolved.localpart == localpart {
                bound.push(claim);
            } else {
                not_canonical = true;
            }
        }
        Ok(match (bound.as_slice(), not_canonical) {
            ([one], _) => Confirmation::Bound((*one).to_string()),
            ([], true) => Confirmation::NotCanonical,
            ([], false) => Confirmation::NoMapping,
            _ => Confirmation::Ambiguous,
        })
    }
}

// -- Reading a stored binding -----------------------------------------------------------------

/// The DID texts a profile value claims, in the order found, without repeats: the `did`
/// member (or the whole value, in the pre-object shape) and the `sub` of the `proof`.
///
/// CLAIMS, not facts: see the module doc.
pub(crate) fn claims_of(value: &Value) -> Vec<String> {
    let mut claims: Vec<String> = Vec::new();
    let mut push = |claim: Option<String>| {
        if let Some(c) = claim.filter(|c| !c.is_empty()) {
            if !claims.contains(&c) {
                claims.push(c);
            }
        }
    };
    match value {
        Value::String(did) => push(Some(did.clone())),
        Value::Object(map) => {
            push(map.get("did").and_then(|v| v.as_str()).map(str::to_string));
            push(
                map.get("proof")
                    .and_then(|v| v.as_str())
                    .and_then(unverified_subject),
            );
        }
        _ => {}
    }
    claims
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Whether the stored `value` is a CURRENT binding of `did` to `mxid`: see the module doc.
pub(crate) fn binding_is_current(
    value: &Value,
    signer: &dyn ProviderSigner,
    issuer: &str,
    did: &str,
    mxid: &str,
) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.get("did").and_then(|v| v.as_str()) != Some(did) {
        return false;
    }
    let Some(proof) = map
        .get("proof")
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty())
    else {
        return false;
    };
    match verify_own_proof(proof, signer) {
        Ok(claims) => claims.sub == did && claims.mxid == mxid && same_issuer(&claims.iss, issuer),
        Err(_) => false,
    }
}

// -- The report -------------------------------------------------------------------------------

/// A class of per-account failure. Counted, never described: the text of such a failure names
/// the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ErrorClass {
    /// A listed name that is not an account of this homeserver.
    ForeignName,
    /// The profile field could not be read.
    ReadProfile,
    /// The authority could not find out (the homeserver probe failed).
    IdentityProbe,
    /// The proof could not be signed, or did not verify after signing.
    Sign,
    /// The homeserver refused or failed the write.
    Publish,
}

impl ErrorClass {
    fn label(self) -> &'static str {
        match self {
            ErrorClass::ForeignName => "foreign_name",
            ErrorClass::ReadProfile => "read_profile",
            ErrorClass::IdentityProbe => "identity_probe",
            ErrorClass::Sign => "sign",
            ErrorClass::Publish => "publish",
        }
    }
}

/// Why a run stopped before the end of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Abort {
    ListFailed,
    PaginationLoop,
    ConsecutiveErrors,
}

impl Abort {
    fn label(self) -> &'static str {
        match self {
            Abort::ListFailed => "the user list could not be read",
            Abort::PaginationLoop => "the user list did not advance",
            Abort::ConsecutiveErrors => "too many failures in a row",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Accounts examined.
    pub total: u64,
    pub skipped_current: u64,
    pub skipped_no_mapping: u64,
    pub skipped_not_canonical: u64,
    pub skipped_ambiguous: u64,
    pub skipped_deactivated: u64,
    /// The account has no profile row (element-hq/synapse#19702): its field cannot be read
    /// and a write is refused. Left for the next sign-in, as a sign-in leaves it.
    pub skipped_no_profile_row: u64,
    /// Locked accounts among those processed. Informational: they are signed like any other.
    pub locked_seen: u64,
    pub would_write: u64,
    pub written: u64,
    /// Waits for a rate-limited profile read (HTTP 429), over all accounts: why a run was
    /// slow. A count only; the wait ended in a success or in a `read_profile` failure.
    pub rate_limited_waits: u64,
    pub errors: BTreeMap<ErrorClass, u64>,
    /// The run stopped at `--limit`, so `total` is not the whole list.
    pub limit_reached: bool,
    pub aborted: Option<Abort>,
    /// The outermost message of a failed list request. It comes from the list call, which
    /// names no account.
    pub abort_detail: Option<String>,
}

impl Report {
    pub(crate) fn error_count(&self) -> u64 {
        self.errors.values().sum()
    }

    fn error(&mut self, class: ErrorClass) {
        *self.errors.entry(class).or_insert(0) += 1;
    }

    /// True when the run was clean: nothing failed and it ran to the end of the list or to
    /// its limit.
    pub(crate) fn is_clean(&self) -> bool {
        self.aborted.is_none() && self.error_count() == 0
    }

    /// The lines the tool prints: counts only.
    pub(crate) fn render(&self, apply: bool) -> String {
        let mut out = String::new();
        out.push_str(&format!("  total: {}\n", self.total));
        out.push_str(&format!("  skipped_current: {}\n", self.skipped_current));
        out.push_str(&format!(
            "  skipped_no_mapping: {}\n",
            self.skipped_no_mapping
        ));
        out.push_str(&format!(
            "  skipped_not_canonical: {}\n",
            self.skipped_not_canonical
        ));
        out.push_str(&format!(
            "  skipped_ambiguous: {}\n",
            self.skipped_ambiguous
        ));
        out.push_str(&format!(
            "  skipped_deactivated: {}\n",
            self.skipped_deactivated
        ));
        out.push_str(&format!(
            "  skipped_no_profile_row: {}\n",
            self.skipped_no_profile_row
        ));
        out.push_str(&format!("  locked_seen: {}\n", self.locked_seen));
        if apply {
            out.push_str(&format!("  written: {}\n", self.written));
        } else {
            out.push_str(&format!("  would_write: {}\n", self.would_write));
        }
        out.push_str(&format!(
            "  rate_limited_waits: {}\n",
            self.rate_limited_waits
        ));
        if self.errors.is_empty() {
            out.push_str("  errors: none\n");
        } else {
            let classes: Vec<String> = self
                .errors
                .iter()
                .map(|(class, n)| format!("{}={n}", class.label()))
                .collect();
            out.push_str(&format!("  errors: {}\n", classes.join(" ")));
        }
        out.push_str(&format!(
            "  limit_reached: {}\n",
            if self.limit_reached { "yes" } else { "no" }
        ));
        if let Some(abort) = self.aborted {
            out.push_str(&format!("  ABORTED: {}\n", abort.label()));
            if let Some(detail) = &self.abort_detail {
                out.push_str(&format!("  detail: {detail}\n"));
            }
        }
        out
    }
}

// -- The run ----------------------------------------------------------------------------------

/// A run that did not start. Every message is fixed text: none carries a kid, a key, a URL or
/// anything the server said.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The signing key is ephemeral: no proof would be minted, and a profile would be
    /// rewritten without one.
    EphemeralKey,
    /// The key set the server publishes could not be read.
    KeySetUnreadable,
    /// The key set the server publishes does not hold the key this tool would sign with (no
    /// key with its `kid`, or one with that `kid` and another public key).
    KeyNotPublished,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::EphemeralKey => f.write_str(
                "the signing key is ephemeral, so no proof can be minted and every binding \
                 written would lose its proof. Set SIWXOIDC_SIGNING_KEY_PEM (or use the socket \
                 backend). Nothing was read or written.",
            ),
            Refused::KeySetUnreadable => f.write_str(
                "the key set the server publishes (/jwk under base_url) could not be read, so \
                 it is not known whether the signing key is published. Check base_url and that \
                 the server is reachable from here. Nothing was read or written.",
            ),
            Refused::KeyNotPublished => f.write_str(
                "the signing key this tool loaded is not in the key set the server publishes \
                 (/jwk under base_url): no key with its kid and the same public key. A binding \
                 signed with it would verify nowhere. Run the tool after the new key is live in \
                 /jwk, with the signing settings the server uses. Nothing was read or written.",
            ),
        }
    }
}

/// How long the tool waits for the server's key set.
const KEY_SET_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a key set the tool reads. A set of a few keys is under a kilobyte.
const KEY_SET_MAX_BYTES: usize = 256 * 1024;

/// Refuse unless the key set the server publishes at `jwks_url` holds the key this tool would
/// sign with: a key with the signer's `kid` AND the same public key.
///
/// A binding is worth something only if a consumer can verify it against `/jwk`. The tool's
/// "current key" is whatever its own configuration loads, so with a stale environment, or a run
/// during a rotation before the new key is live, `--apply` would rewrite every valid binding
/// into one nobody can verify. The `kid` is derived from the public key, but a set is trusted
/// by key, never by name: a set that names this `kid` for another key is refused too. Every
/// entry that carries the `kid` must be the signer's key; there must be at least one.
///
/// Nothing the server said is returned or shown: a failure is one of two fixed refusals.
pub(crate) async fn check_key_is_published(
    jwks_url: &str,
    signer: &dyn ProviderSigner,
) -> Result<(), Refused> {
    let set = fetch_key_set(jwks_url)
        .await
        .ok_or(Refused::KeySetUnreadable)?;
    let keys = set
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Refused::KeySetUnreadable)?;
    if key_set_holds(keys, signer) {
        Ok(())
    } else {
        Err(Refused::KeyNotPublished)
    }
}

/// `GET jwks_url`: a 2xx JSON body of bounded size, no redirect followed (the URL is the one
/// the server derives for itself, and a redirect would let another host answer for it).
async fn fetch_key_set(jwks_url: &str) -> Option<Value> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(KEY_SET_TIMEOUT)
        .build()
        .ok()?;
    let mut response = client.get(jwks_url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > KEY_SET_MAX_BYTES {
            return None;
        }
    }
    serde_json::from_slice(&body).ok()
}

/// The members that make a public key: its type, curve and point.
const KEY_MEMBERS: [&str; 4] = ["kty", "crv", "x", "y"];

fn key_set_holds(keys: &[Value], signer: &dyn ProviderSigner) -> bool {
    // The JWK the server itself publishes for this signer: the one function builds it.
    let Ok(ours) = serde_json::to_value(signer.verification_jwk()) else {
        return false;
    };
    let member = |key: &Value, name: &str| key.get(name).and_then(Value::as_str).map(str::to_owned);
    if KEY_MEMBERS.iter().any(|name| member(&ours, name).is_none()) {
        return false;
    }
    let named: Vec<&Value> = keys
        .iter()
        .filter(|key| member(key, "kid").as_deref() == Some(signer.kid()))
        .collect();
    !named.is_empty()
        && named.iter().all(|key| {
            KEY_MEMBERS
                .iter()
                .all(|name| member(key, name) == member(&ours, name))
        })
}

/// How the tool waits out a rate-limited read: a seam, so a test records the waits instead of
/// sitting through them, as `now` lets a test fix the clock.
#[async_trait]
pub(crate) trait Pause: Send + Sync {
    async fn pause(&self, duration: Duration);
}

/// The real wait.
pub(crate) struct SleepPause;

#[async_trait]
impl Pause for SleepPause {
    async fn pause(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

pub(crate) struct Run<'a> {
    pub synapse: &'a SynapseClient,
    pub signer: &'a dyn ProviderSigner,
    pub authority: &'a dyn DidAuthority,
    /// `iss` of the proofs: the server's `base_url`, as a sign-in writes it.
    pub issuer: &'a str,
    /// The homeserver's name; accounts of any other name are not ours to sign.
    pub server_name: &'a str,
    pub apply: bool,
    pub limit: Option<usize>,
    pub delay: Duration,
    /// A fixed `iat`, for tests. `None` reads the clock at each mint, as a sign-in does.
    pub now: Option<i64>,
    /// How a rate-limited profile read is waited out.
    pub pause: &'a dyn Pause,
}

/// What one listed account came to.
enum Outcome {
    Counted,
    /// Counted, and it was a failure (for the consecutive-failure stop).
    Failed,
    /// The limit is reached: stop before this account.
    Stop,
}

/// Walk the homeserver's local accounts and re-sign the stale bindings. See the module doc.
///
/// `Err` only when the run is refused before it reads or writes anything. Every other
/// trouble is in the [`Report`]: a count by class, never a description.
pub(crate) async fn run(run: &Run<'_>) -> Result<Report, Refused> {
    // Hard stop, before any read: an ephemeral key mints no proof, so every account written
    // would lose the proof it has.
    if run.signer.is_ephemeral() {
        return Err(Refused::EphemeralKey);
    }

    let mut report = Report::default();
    let mut planned_writes: usize = 0;
    let mut consecutive_errors: u32 = 0;
    let mut from: Option<String> = None;
    let mut seen_tokens: HashSet<String> = HashSet::new();

    'pages: loop {
        let page = match run.synapse.admin_all_users_page(from.as_deref()).await {
            Ok(page) => page,
            Err(e) => {
                // The outermost message of the list call names no account.
                report.aborted = Some(Abort::ListFailed);
                report.abort_detail = Some(e.to_string());
                break;
            }
        };
        for row in &page.users {
            match process(run, row, &mut report, &mut planned_writes).await {
                Outcome::Counted => consecutive_errors = 0,
                Outcome::Failed => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        report.aborted = Some(Abort::ConsecutiveErrors);
                        break 'pages;
                    }
                }
                Outcome::Stop => {
                    report.limit_reached = true;
                    break 'pages;
                }
            }
        }
        match page.next_token.filter(|t| !t.is_empty()) {
            Some(token) => {
                // A token seen before means the list is not advancing.
                if !seen_tokens.insert(token.clone()) {
                    report.aborted = Some(Abort::PaginationLoop);
                    break;
                }
                from = Some(token);
            }
            None => break,
        }
    }
    Ok(report)
}

/// Why the profile field of an account could not be read.
enum ReadFailure {
    /// Every one of the allowed reads was answered 429.
    RateLimited,
    /// Any other failure; the text of it names the account, so it is not kept.
    Other,
}

/// How long to wait after a 429 that carried this hint: the server's word, at most
/// [`RATE_LIMIT_MAX_WAIT`], and [`RATE_LIMIT_DEFAULT_WAIT`] when it gave none.
fn rate_limit_wait(hint: Option<Duration>) -> Duration {
    hint.unwrap_or(RATE_LIMIT_DEFAULT_WAIT)
        .min(RATE_LIMIT_MAX_WAIT)
}

/// Read the published field of one account, waiting out Synapse's `rc_profile` limit.
///
/// The read is anonymous, so Synapse limits it per client IP (burst 500, then one a second):
/// on a long list every account past the burst is answered 429. Each 429 is waited out (see
/// [`rate_limit_wait`]) and counted in `rate_limited_waits`, and the same read is tried again;
/// a 429 that ends in an answer is no failure. After
/// [`RATE_LIMITED_READS_BEFORE_GIVING_UP`] answers in a row that were all 429, the account is
/// given up on. The shared client does not do this: a live request must not sleep.
async fn read_published(
    run: &Run<'_>,
    localpart: &str,
    report: &mut Report,
) -> Result<Option<Value>, ReadFailure> {
    let mut limited_in_a_row: u32 = 0;
    loop {
        let err = match run.synapse.read_did_value(localpart, run.server_name).await {
            Ok(published) => return Ok(published),
            Err(err) => err,
        };
        let Some(limited) = err.downcast_ref::<ProfileRateLimited>() else {
            return Err(ReadFailure::Other);
        };
        limited_in_a_row += 1;
        if limited_in_a_row >= RATE_LIMITED_READS_BEFORE_GIVING_UP {
            return Err(ReadFailure::RateLimited);
        }
        report.rate_limited_waits += 1;
        run.pause.pause(rate_limit_wait(limited.retry_after)).await;
    }
}

/// One listed account: judge its binding and, with `--apply`, sign it again.
async fn process(
    run: &Run<'_>,
    row: &AdminUserRow,
    report: &mut Report,
    planned_writes: &mut usize,
) -> Outcome {
    report.total += 1;

    if row.deactivated {
        report.skipped_deactivated += 1;
        return Outcome::Counted;
    }
    // A locked account is processed like an active one (signing it again changes nothing it
    // can do); it is only counted, so the operator can see the list did include them.
    if row.locked {
        report.locked_seen += 1;
    }

    // A local account is `@localpart:<our server name>`. Anything else is not ours to sign.
    let localpart = match row
        .name
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
    {
        Some((localpart, server)) if server == run.server_name && !localpart.is_empty() => {
            localpart
        }
        _ => {
            report.error(ErrorClass::ForeignName);
            return Outcome::Failed;
        }
    };

    let published = match read_published(run, localpart, report).await {
        Ok(published) => published,
        // Nothing but a 429 was ever answered: the profile-row probe below asks a route with
        // the same limit, and no 500 is in play, so it would only add to the load.
        Err(ReadFailure::RateLimited) => {
            report.error(ErrorClass::ReadProfile);
            return Outcome::Failed;
        }
        Err(ReadFailure::Other) => {
            // A 500 on this route is also what an account with no profile row answers
            // (element-hq/synapse#19702), and a sign-in cannot publish for it either. The
            // probe says "absent" only when it is sure; any doubt stays a failure.
            if matches!(
                run.synapse
                    .has_profile_row(localpart, run.server_name)
                    .await,
                Ok(false)
            ) {
                report.skipped_no_profile_row += 1;
                return Outcome::Counted;
            }
            report.error(ErrorClass::ReadProfile);
            return Outcome::Failed;
        }
    };
    let claims = published.as_ref().map(claims_of).unwrap_or_default();

    let did = match run.authority.confirm(localpart, &claims).await {
        Ok(Confirmation::Bound(did)) => did,
        Ok(Confirmation::NoMapping) => {
            report.skipped_no_mapping += 1;
            return Outcome::Counted;
        }
        Ok(Confirmation::NotCanonical) => {
            report.skipped_not_canonical += 1;
            return Outcome::Counted;
        }
        Ok(Confirmation::Ambiguous) => {
            report.skipped_ambiguous += 1;
            return Outcome::Counted;
        }
        Err(_) => {
            report.error(ErrorClass::IdentityProbe);
            return Outcome::Failed;
        }
    };

    let mxid = matrix_user_id(localpart, run.server_name);
    if let Some(value) = &published {
        if binding_is_current(value, run.signer, run.issuer, &did, &mxid) {
            report.skipped_current += 1;
            return Outcome::Counted;
        }
    }

    if run.limit.is_some_and(|limit| *planned_writes >= limit) {
        return Outcome::Stop;
    }
    *planned_writes += 1;

    if !run.apply {
        report.would_write += 1;
        return Outcome::Counted;
    }

    // Through the code a sign-in uses, with the clock read now as a sign-in reads it.
    let now = run.now.unwrap_or_else(|| Utc::now().timestamp());
    let value = match did_profile_value(run.signer, run.issuer, &did, &mxid, now).await {
        Ok(value) => value,
        Err(_) => {
            report.error(ErrorClass::Sign);
            return Outcome::Failed;
        }
    };
    // Never write what would not stand: a value that does not verify under the key it was
    // just signed with (a signer answering with a bad signature) or has no proof would
    // replace an old binding with a worse one.
    if !binding_is_current(&value, run.signer, run.issuer, &did, &mxid) {
        report.error(ErrorClass::Sign);
        return Outcome::Failed;
    }

    let outcome = match run
        .synapse
        .publish_did_field(localpart, run.server_name, &value)
        .await
    {
        Ok(PublishOutcome::Written) => {
            report.written += 1;
            Outcome::Counted
        }
        Ok(PublishOutcome::RowLessAccount) => {
            report.skipped_no_profile_row += 1;
            Outcome::Counted
        }
        Err(_) => {
            report.error(ErrorClass::Publish);
            Outcome::Failed
        }
    };
    if !run.delay.is_zero() {
        tokio::time::sleep(run.delay).await;
    }
    outcome
}

// -- The command line ---------------------------------------------------------------------------

/// Whether this process was started as the tool: under the name `remint-did-assertions`, or
/// with it as the first argument. Returns the arguments that are the tool's own.
///
/// This is the one decision `main` makes before the server starts, so it must be total: it
/// reads the arguments as bytes (`OsString`) and compares only the program name and the first
/// argument, never converting the list to text. `std::env::args()` panics on an argument that
/// is not UTF-8, which would have stopped a normal server start for one it never reads.
pub(crate) fn invoked_as_tool(
    argv: impl IntoIterator<Item = std::ffi::OsString>,
) -> Option<Vec<std::ffi::OsString>> {
    let mut argv = argv.into_iter();
    let program = argv.next()?;
    let called_by_name = std::path::Path::new(&program)
        .file_name()
        .is_some_and(|name| name == TOOL_NAME);
    let rest: Vec<std::ffi::OsString> = argv.collect();
    if called_by_name {
        return Some(rest);
    }
    match rest.split_first() {
        Some((first, tail)) if first == TOOL_NAME => Some(tail.to_vec()),
        _ => None,
    }
}

pub(crate) async fn cli_main(args: Vec<std::ffi::OsString>) -> ExitCode {
    // The tool takes no argument that is not text. Refused like any it does not know, and
    // without showing it.
    let Ok(args) = args
        .into_iter()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<String>, _>>()
    else {
        eprintln!("{TOOL_NAME}: an argument is not valid UTF-8");
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let args = match parse_args(args) {
        Ok(Parsed::Run(args)) => args,
        Ok(Parsed::Help) => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{TOOL_NAME}: {e}");
            return ExitCode::from(2);
        }
    };
    match run_cli(&args).await {
        Ok(code) => code,
        // Outermost message only: a deeper cause (a URL, a library error) may carry a
        // setting's value or an account.
        Err(e) => {
            eprintln!("{TOOL_NAME}: {e}");
            ExitCode::from(2)
        }
    }
}

/// The signer the server would use for this configuration, built the same way and never
/// ephemeral: there is no key to generate here.
async fn build_signer(config: &Config) -> Result<Arc<dyn ProviderSigner>> {
    match config.signing_backend().map_err(|e| anyhow!(e))? {
        SigningBackend::Socket { path, timeout } => {
            let signer = siwx_oidc::signing::socket::SocketSigner::connect(path, timeout)
                .await
                .map_err(|e| {
                    anyhow!("signing_backend = socket: asking the signer for its public key failed: {e}")
                })?;
            Ok(Arc::new(signer))
        }
        SigningBackend::Pem => {
            let pem = config
                .signing_key_pem
                .as_deref()
                .ok_or_else(|| anyhow!("signing_key_pem is not set"))?;
            // The error is not shown: it is about key material.
            let key = EcdsaSigningKey::from_pem(pem)
                .map_err(|_| anyhow!("signing_key_pem could not be loaded as an ES256 key"))?;
            Ok(Arc::new(key))
        }
        SigningBackend::Ephemeral => Err(anyhow!(Refused::EphemeralKey)),
    }
}

/// The names of the settings figment could not read, never their values: a value in an error
/// can be a URL with a password.
fn unreadable_settings(error: figment::Error) -> anyhow::Error {
    let mut names: Vec<String> = error.into_iter().map(|e| e.path.join(".")).collect();
    names.sort();
    names.dedup();
    anyhow!(
        "the configuration could not be read (setting: {}). Run the server once to see why.",
        names.join(", ")
    )
}

async fn run_cli(args: &Args) -> Result<ExitCode> {
    let mut config = config::figment()
        .extract::<Config>()
        .map_err(unreadable_settings)?;
    config.read_secret_files().map_err(|e| anyhow!(e))?;

    let server_name = config
        .matrix_server_name
        .clone()
        .ok_or_else(|| anyhow!("matrix_server_name (SIWXOIDC_MATRIX_SERVER_NAME) is not set"))?;
    let (endpoint, secret) = match (&config.synapse_endpoint, &config.mas_shared_secret) {
        (Some(endpoint), Some(secret)) => (endpoint.clone(), secret.clone()),
        _ => bail!(
            "synapse_endpoint and mas_shared_secret are not both set: there is no homeserver to \
             read or write"
        ),
    };
    let grant_lifetime = config.grant_lifetime().map_err(|e| anyhow!(e))?;

    let signer = build_signer(&config).await?;
    if signer.is_ephemeral() {
        return Err(anyhow!(Refused::EphemeralKey));
    }

    // Before anything is read: the key must be the one the server publishes, at the URL the
    // server derives for its own `jwks_uri`.
    let jwks_url = config
        .base_url
        .join(crate::oidc::JWK_PATH)
        .map_err(|_| anyhow!("base_url cannot be joined with the key set path"))?;
    check_key_is_published(jwks_url.as_str(), signer.as_ref())
        .await
        .map_err(|refused| anyhow!(refused))?;

    // The same Redis, token store and admin mint the server uses to talk to Synapse.
    let redis = RedisClient::new(&config.redis_url)
        .await
        .context("could not build the Redis client")?
        .with_grant_lifetime(grant_lifetime)
        .with_reuse_enforcement(config.reuse_revokes_grant);
    let synapse = SynapseClient::new(endpoint.as_str(), &secret).with_admin_mint(
        redis,
        config.admin_token_localpart.clone(),
        crate::admin_token::clamp_admin_token_ttl(config.admin_token_ttl_secs),
    );
    let authority = DerivationAuthority { synapse: &synapse };
    let issuer = config.base_url.as_str();

    println!(
        "{TOOL_NAME}: {}",
        if args.apply {
            "APPLY (writing the profile field io.inblock.did)"
        } else {
            "DRY RUN (nothing is written; pass --apply to write)"
        }
    );
    println!("  issuer: {}", siwx_oidc::redact::redact_url(issuer));
    println!("  signing kid: {} (published at /jwk)", signer.kid());

    let report = run(&Run {
        synapse: &synapse,
        signer: signer.as_ref(),
        authority: &authority,
        issuer,
        server_name: &server_name,
        apply: args.apply,
        limit: args.limit,
        delay: args.delay,
        now: None,
        pause: &SleepPause,
    })
    .await
    .map_err(|refused| anyhow!(refused))?;

    print!("{}", report.render(args.apply));
    Ok(if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_assertion::{test_p256_pem, DID_PROFILE_FIELD};
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use siwx_oidc::mxid;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    const SERVER: &str = "hs.example.org";
    /// A mixed-case `did:key`: its case is part of its meaning.
    const DID_A: &str = "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB";
    const DID_B: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
    const DID_C: &str = "did:pkh:eip155:1:0x7a76a0f2b0d4c3e1a5b9c8d7e6f50413229a8b7c";
    const DID_D: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const ADMIN_LOCALPART: &str = "siwx-admin";
    const IAT: i64 = 1_790_000_000;

    fn key() -> EcdsaSigningKey {
        EcdsaSigningKey::from_pem(&test_p256_pem()).expect("test PEM must load")
    }

    fn mxid_of(localpart: &str) -> String {
        matrix_user_id(localpart, SERVER)
    }

    fn modern(did: &str) -> String {
        mxid::localpart_for(did)
    }

    // -- A homeserver in a box: the admin user list, the profile field, the MAS probe --------

    #[derive(Default)]
    struct UserRec {
        deactivated: bool,
        locked: bool,
        user_type: Option<String>,
    }

    #[derive(Default)]
    struct Hs {
        users: BTreeMap<String, UserRec>,
        /// localpart -> the value of `io.inblock.did`
        profile: HashMap<String, Value>,
        /// every successful PUT of the field, in order: (localpart, value)
        puts: Vec<(String, Value)>,
        /// `deactivated=` the list request carried, per request
        list_flags: Vec<String>,
        /// `locked=` the list request carried, per request
        locked_flags: Vec<String>,
        list_requests: usize,
        profile_gets: usize,
        page_size: usize,
        /// answer every PUT with this status instead of storing
        put_status: Option<StatusCode>,
        put_without_bearer: usize,
        /// accounts with a `users` row and no `profiles` row: the field GET answers 500 and
        /// the whole-profile GET answers 404 `M_UNKNOWN`
        rowless: std::collections::HashSet<String>,
        /// accounts whose field GET answers 500 although the profile row is there
        unreadable: std::collections::HashSet<String>,
        /// accounts whose field GET answers 429 (`rc_profile`) a number of times first
        rate_limited: HashMap<String, Limited>,
    }

    /// A 429 on the field GET, answered `remaining` more times.
    struct Limited {
        remaining: u32,
        /// `retry_after_ms` in the body, as Synapse sends it
        retry_after_ms: Option<u64>,
        /// the `Retry-After` header, in seconds
        retry_after_header: Option<&'static str>,
    }

    type Shared = Arc<Mutex<Hs>>;

    fn localpart_of(user: &str) -> String {
        user.trim_start_matches('@')
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    async fn list_users(
        State(hs): State<Shared>,
        Query(q): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        let mut hs = hs.lock().unwrap();
        hs.list_requests += 1;
        let deactivated = q.get("deactivated").cloned().unwrap_or_default();
        hs.list_flags.push(deactivated.clone());
        let locked = q.get("locked").cloned().unwrap_or_default();
        hs.locked_flags.push(locked.clone());
        let include_deactivated = deactivated == "true";
        // As Synapse's `UsersRestServletV2.on_GET` (`locked = parse_boolean(request, "locked",
        // default=False)`): a locked account is not listed unless the request says so.
        let include_locked = locked == "true";
        let rows: Vec<(&String, &UserRec)> = hs
            .users
            .iter()
            .filter(|(_, u)| include_deactivated || !u.deactivated)
            .filter(|(_, u)| include_locked || !u.locked)
            .collect();
        let from: usize = q.get("from").and_then(|f| f.parse().ok()).unwrap_or(0);
        let size = if hs.page_size == 0 { 100 } else { hs.page_size };
        let page: Vec<Value> = rows
            .iter()
            .skip(from)
            .take(size)
            .map(|(lp, u)| {
                json!({
                    "name": mxid_of(lp),
                    "is_guest": 0,
                    "admin": 0,
                    "user_type": u.user_type,
                    "deactivated": if u.deactivated { 1 } else { 0 },
                    "locked": if u.locked { 1 } else { 0 },
                })
            })
            .collect();
        let next = from + page.len();
        let mut body = json!({ "users": page, "total": rows.len() });
        if next < rows.len() {
            body["next_token"] = json!(next.to_string());
        }
        Json(body)
    }

    async fn get_field(
        State(hs): State<Shared>,
        Path(user): Path<String>,
    ) -> axum::response::Response {
        let mut hs = hs.lock().unwrap();
        hs.profile_gets += 1;
        let lp = localpart_of(&user);
        if let Some(limit) = hs.rate_limited.get_mut(&lp).filter(|l| l.remaining > 0) {
            limit.remaining -= 1;
            let mut body = json!({"errcode": "M_LIMIT_EXCEEDED", "error": "Too Many Requests"});
            if let Some(ms) = limit.retry_after_ms {
                body["retry_after_ms"] = json!(ms);
            }
            let mut reply = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            if let Some(seconds) = limit.retry_after_header {
                reply.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_static(seconds),
                );
            }
            return reply;
        }
        if hs.rowless.contains(&lp) || hs.unreadable.contains(&lp) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"errcode": "M_UNKNOWN", "error": "Internal server error"})),
            )
                .into_response();
        }
        match hs.profile.get(&lp) {
            Some(value) => {
                (StatusCode::OK, Json(json!({ DID_PROFILE_FIELD: value }))).into_response()
            }
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"errcode": "M_NOT_FOUND", "error": "no such field"})),
            )
                .into_response(),
        }
    }

    /// `GET /profile/{user}`, the whole profile: what `has_profile_row` asks.
    async fn get_profile(State(hs): State<Shared>, Path(user): Path<String>) -> impl IntoResponse {
        if hs.lock().unwrap().rowless.contains(&localpart_of(&user)) {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"errcode": "M_UNKNOWN", "error": "No row found"})),
            )
        } else {
            (StatusCode::OK, Json(json!({"displayname": "someone"})))
        }
    }

    async fn put_field(
        State(hs): State<Shared>,
        Path(user): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        let mut hs = hs.lock().unwrap();
        if !headers.contains_key(axum::http::header::AUTHORIZATION) {
            hs.put_without_bearer += 1;
        }
        if let Some(status) = hs.put_status {
            return (status, Json(json!({"errcode": "M_FORBIDDEN"})));
        }
        let lp = localpart_of(&user);
        let value = body.get(DID_PROFILE_FIELD).cloned().unwrap_or(Value::Null);
        hs.profile.insert(lp.clone(), value.clone());
        hs.puts.push((lp, value));
        (StatusCode::OK, Json(json!({})))
    }

    async fn localpart_probe(
        State(hs): State<Shared>,
        Query(q): Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let lp = q.get("localpart").cloned().unwrap_or_default();
        if hs.lock().unwrap().users.contains_key(&lp) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"errcode": "M_USER_IN_USE", "error": "User ID already taken."})),
            )
                .into_response()
        } else {
            (StatusCode::OK, Json(json!({}))).into_response()
        }
    }

    struct Fixture {
        hs: Shared,
        synapse: SynapseClient,
        _server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self._server.abort();
        }
    }

    impl Fixture {
        /// `None` after a loud skip when no Redis is reachable (the admin token is minted
        /// into it, as in production).
        async fn start() -> Option<Self> {
            let redis = siwx_oidc::test_support::redis().await?;
            let hs: Shared = Arc::new(Mutex::new(Hs::default()));
            hs.lock().unwrap().users.insert(
                ADMIN_LOCALPART.to_string(),
                UserRec {
                    deactivated: false,
                    locked: false,
                    user_type: Some("bot".into()),
                },
            );
            let app = Router::new()
                .route("/_synapse/admin/v2/users", get(list_users))
                .route("/_synapse/mas/is_localpart_available", get(localpart_probe))
                .route("/_matrix/client/v3/profile/{user}", get(get_profile))
                .route(
                    &format!("/_matrix/client/v3/profile/{{user}}/{DID_PROFILE_FIELD}"),
                    get(get_field).put(put_field),
                )
                .with_state(hs.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the mock homeserver");
            let addr = listener.local_addr().expect("mock homeserver address");
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("mock homeserver");
            });
            let synapse = SynapseClient::new(&format!("http://{addr}"), "shared-secret")
                .with_admin_mint(redis, ADMIN_LOCALPART.to_string(), 300);
            Some(Self {
                hs,
                synapse,
                _server: server,
            })
        }

        fn add_user(&self, localpart: &str) {
            self.hs
                .lock()
                .unwrap()
                .users
                .insert(localpart.to_string(), UserRec::default());
        }

        fn add_deactivated(&self, localpart: &str) {
            self.hs.lock().unwrap().users.insert(
                localpart.to_string(),
                UserRec {
                    deactivated: true,
                    locked: false,
                    user_type: None,
                },
            );
        }

        fn add_locked(&self, localpart: &str) {
            self.hs.lock().unwrap().users.insert(
                localpart.to_string(),
                UserRec {
                    deactivated: false,
                    locked: true,
                    user_type: None,
                },
            );
        }

        fn set_profile(&self, localpart: &str, value: Value) {
            self.hs
                .lock()
                .unwrap()
                .profile
                .insert(localpart.to_string(), value);
        }

        /// Make the field GET of this account answer 429 `times` times, then normally.
        fn rate_limit(
            &self,
            localpart: &str,
            times: u32,
            retry_after_ms: Option<u64>,
            retry_after_header: Option<&'static str>,
        ) {
            self.hs.lock().unwrap().rate_limited.insert(
                localpart.to_string(),
                Limited {
                    remaining: times,
                    retry_after_ms,
                    retry_after_header,
                },
            );
        }

        fn profile_gets(&self) -> usize {
            self.hs.lock().unwrap().profile_gets
        }

        fn profile(&self, localpart: &str) -> Option<Value> {
            self.hs.lock().unwrap().profile.get(localpart).cloned()
        }

        fn puts(&self) -> Vec<(String, Value)> {
            self.hs.lock().unwrap().puts.clone()
        }
    }

    /// The identity store of the spec, as a fake: a fixed answer per localpart, claims ignored.
    struct StoreFake(HashMap<String, String>);

    impl StoreFake {
        fn of(entries: &[(&str, &str)]) -> Self {
            Self(
                entries
                    .iter()
                    .map(|(lp, did)| (lp.to_string(), did.to_string()))
                    .collect(),
            )
        }
    }

    #[async_trait]
    impl DidAuthority for StoreFake {
        async fn confirm(&self, localpart: &str, _claims: &[String]) -> Result<Confirmation> {
            Ok(match self.0.get(localpart) {
                Some(did) => Confirmation::Bound(did.clone()),
                None => Confirmation::NoMapping,
            })
        }
    }

    async fn mint_value(key: &EcdsaSigningKey, did: &str, mxid: &str) -> Value {
        did_profile_value(key, "https://auth.example.org/", did, mxid, IAT - 1000)
            .await
            .expect("an in-process key signs")
    }

    async fn go(
        fx: &Fixture,
        signer: &dyn ProviderSigner,
        authority: &dyn DidAuthority,
        apply: bool,
    ) -> Report {
        run_with(fx, signer, authority, apply, None).await
    }

    async fn run_with(
        fx: &Fixture,
        signer: &dyn ProviderSigner,
        authority: &dyn DidAuthority,
        apply: bool,
        limit: Option<usize>,
    ) -> Report {
        super::run(&Run {
            synapse: &fx.synapse,
            signer,
            authority,
            issuer: "https://auth.example.org/",
            server_name: SERVER,
            apply,
            limit,
            delay: Duration::ZERO,
            now: Some(IAT),
            pause: &SleepPause,
        })
        .await
        .expect("the run starts")
    }

    /// The waits a run asked for, recorded instead of slept.
    #[derive(Default)]
    struct RecordedPauses(Mutex<Vec<Duration>>);

    impl RecordedPauses {
        fn waits(&self) -> Vec<Duration> {
            self.0.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Pause for RecordedPauses {
        async fn pause(&self, duration: Duration) {
            self.0.lock().unwrap().push(duration);
        }
    }

    async fn go_paused(
        fx: &Fixture,
        signer: &dyn ProviderSigner,
        authority: &dyn DidAuthority,
        apply: bool,
        pauses: &RecordedPauses,
    ) -> Report {
        super::run(&Run {
            synapse: &fx.synapse,
            signer,
            authority,
            issuer: "https://auth.example.org/",
            server_name: SERVER,
            apply,
            limit: None,
            delay: Duration::ZERO,
            now: Some(IAT),
            pause: pauses,
        })
        .await
        .expect("the run starts")
    }

    macro_rules! fixture {
        () => {
            match Fixture::start().await {
                Some(fx) => fx,
                None => return,
            }
        };
    }

    // -- Tests through the public surface: a binding is judged, re-minted or left alone ------

    #[tokio::test]
    async fn a_current_binding_is_skipped() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        fx.set_profile("ann", mint_value(&key, DID_A, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.skipped_current, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "a current binding is not rewritten");
    }

    #[tokio::test]
    async fn a_binding_signed_under_an_old_kid_is_reminted_under_the_current_key() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        assert_ne!(old.kid(), current.kid());
        fx.add_user("ann");
        fx.set_profile("ann", mint_value(&old, DID_A, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        let stored = fx.profile("ann").expect("the field was written");
        assert!(
            binding_is_current(
                &stored,
                &current,
                "https://auth.example.org/",
                DID_A,
                &mxid_of("ann")
            ),
            "the written binding verifies under the current key"
        );
        let claims = verify_own_proof(stored["proof"].as_str().unwrap(), &current).unwrap();
        assert_eq!(claims.iat, IAT);
        assert_eq!(claims.sub, DID_A, "the DID keeps its exact case");
    }

    #[tokio::test]
    async fn a_missing_field_is_minted() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(fx.profile("ann").unwrap()["did"], DID_A);
    }

    /// The profile is not trusted: its `did` disagrees with the store, and the store's DID is
    /// what is signed.
    #[tokio::test]
    async fn a_profile_did_that_disagrees_with_the_store_is_replaced_by_the_stores() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_user("ann");
        // The profile, and a proof from an old key, both name somebody else.
        fx.set_profile("ann", mint_value(&old, DID_B, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        let stored = fx.profile("ann").unwrap();
        assert_eq!(stored["did"], DID_A);
        let claims = verify_own_proof(stored["proof"].as_str().unwrap(), &current).unwrap();
        assert_eq!(claims.sub, DID_A);
        assert!(
            !stored.to_string().contains(DID_B),
            "the foreign DID is gone from the profile"
        );
    }

    /// A proof copied from another account (right DID, right key, wrong `mxid`) is not a
    /// binding for this one.
    #[tokio::test]
    async fn a_proof_with_the_wrong_mxid_is_reminted() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_user("ann");
        fx.add_user("bob");
        // Signed by the CURRENT key and naming bob's account: a replay, valid in every way
        // but the one that matters.
        fx.set_profile("ann", mint_value(&current, DID_A, &mxid_of("bob")).await);
        // And one forged under an old key, with the wrong mxid.
        fx.set_profile("bob", mint_value(&old, DID_B, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B)]);

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.written, 2, "{report:?}");
        for (lp, did) in [("ann", DID_A), ("bob", DID_B)] {
            assert!(
                binding_is_current(
                    &fx.profile(lp).unwrap(),
                    &current,
                    "https://auth.example.org/",
                    did,
                    &mxid_of(lp)
                ),
                "{lp} is bound to its own account"
            );
        }
    }

    #[tokio::test]
    async fn an_account_with_no_mapping_is_skipped_and_counted() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        // The admin service account is in the list too, and has no mapping.
        let store = StoreFake::of(&[]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.total, 2, "{report:?}");
        assert_eq!(report.skipped_no_mapping, 2);
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty());
    }

    #[tokio::test]
    async fn a_deactivated_account_is_skipped_and_counted() {
        let fx = fixture!();
        let key = key();
        fx.add_deactivated("gone");
        // Even one the store knows is left alone.
        let store = StoreFake::of(&[("gone", DID_A)]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.skipped_deactivated, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty());
        assert_eq!(
            fx.hs.lock().unwrap().list_flags,
            vec!["true"],
            "the list is asked to include deactivated accounts, so they can be counted"
        );
    }

    /// Synapse's user list leaves a locked account out unless asked (`locked=true`), so a tool
    /// that does not ask never sees it and its binding goes stale for good. A locked account
    /// is signed like an active one (re-signing it changes nothing it can do), and counted so
    /// the operator can see how many there were.
    #[tokio::test]
    async fn a_locked_account_with_a_stale_binding_is_reminted() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_locked("ann");
        fx.set_profile("ann", mint_value(&old, DID_A, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.locked_seen, 1, "{report:?}");
        assert_eq!(
            report.total, 2,
            "the locked account and the service account"
        );
        let stored = fx.profile("ann").expect("the field was written");
        assert!(binding_is_current(
            &stored,
            &current,
            "https://auth.example.org/",
            DID_A,
            &mxid_of("ann")
        ));
        assert_eq!(
            fx.hs.lock().unwrap().locked_flags,
            vec!["true"],
            "the list is asked to include locked accounts"
        );
    }

    /// The counter is informational: an unlocked account is not in it, and it is printed.
    #[tokio::test]
    async fn the_locked_count_is_reported_and_counts_only_locked_accounts() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        fx.add_locked("bob");
        fx.add_locked("cy");
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B), ("cy", DID_C)]);

        let report = go(&fx, &key, &store, false).await;

        assert_eq!(report.locked_seen, 2, "{report:?}");
        assert_eq!(report.would_write, 3, "locked accounts are processed too");
        assert!(report.render(false).contains("  locked_seen: 2\n"));
        assert!(report.is_clean(), "a locked account is not a failure");
    }

    /// An account with no profile row cannot be read or written (synapse#19702). It is counted
    /// under its own name, not as a failure, so a clean rerun stays clean; a 500 that the
    /// probe cannot explain stays a failure.
    #[tokio::test]
    async fn an_account_with_no_profile_row_is_counted_and_not_a_failure() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        fx.hs.lock().unwrap().rowless.insert("ann".to_string());
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.skipped_no_profile_row, 1, "{report:?}");
        assert_eq!(report.error_count(), 0, "{report:?}");
        assert!(report.is_clean());
        assert!(fx.puts().is_empty());
    }

    #[tokio::test]
    async fn a_read_that_fails_for_another_reason_is_a_failure() {
        let fx = fixture!();
        let key = key();
        fx.add_user("ann");
        fx.hs.lock().unwrap().unreadable.insert("ann".to_string());
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &key, &store, true).await;

        assert_eq!(report.skipped_no_profile_row, 0, "{report:?}");
        assert_eq!(report.errors.get(&ErrorClass::ReadProfile), Some(&1));
        assert!(fx.puts().is_empty());
    }

    // -- A rate-limited profile read (Synapse `rc_profile`) is waited out, not failed -------

    /// A stale binding to re-sign, for an account whose read will be rate limited.
    async fn stale_account(fx: &Fixture, old: &EcdsaSigningKey, localpart: &str, did: &str) {
        fx.add_user(localpart);
        fx.set_profile(localpart, mint_value(old, did, &mxid_of(localpart)).await);
    }

    #[tokio::test]
    async fn a_rate_limited_read_is_waited_out_and_the_account_is_written() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        fx.rate_limit("ann", 3, Some(40), None);
        let store = StoreFake::of(&[("ann", DID_A)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, true, &pauses).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.rate_limited_waits, 3, "{report:?}");
        assert_eq!(report.error_count(), 0, "{report:?}");
        assert!(report.is_clean());
        assert_eq!(
            pauses.waits(),
            vec![Duration::from_millis(40); 3],
            "it waited what the server asked, once per 429"
        );
        assert_eq!(fx.puts().len(), 1);
        assert!(report.render(true).contains("  rate_limited_waits: 3\n"));
    }

    #[tokio::test]
    async fn a_dry_run_waits_out_a_rate_limited_read_too() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        fx.rate_limit("ann", 2, Some(10), None);
        let store = StoreFake::of(&[("ann", DID_A)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, false, &pauses).await;

        assert_eq!(report.would_write, 1, "{report:?}");
        assert_eq!(report.rate_limited_waits, 2, "{report:?}");
        assert_eq!(report.error_count(), 0, "{report:?}");
        assert!(fx.puts().is_empty());
    }

    #[tokio::test]
    async fn thirty_rate_limited_reads_in_a_row_give_up_on_that_account_only() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        stale_account(&fx, &old, "bob", DID_B).await;
        fx.rate_limit("ann", 1000, Some(5), None);
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, true, &pauses).await;

        assert_eq!(
            report.errors.get(&ErrorClass::ReadProfile),
            Some(&1),
            "one account given up on, one error: {report:?}"
        );
        assert_eq!(report.error_count(), 1, "{report:?}");
        assert_eq!(
            report.written, 1,
            "the next account is still done: {report:?}"
        );
        assert_eq!(report.aborted, None);
        assert_eq!(
            report.rate_limited_waits, 29,
            "it read 30 times and waited between them, not after the last"
        );
        assert_eq!(pauses.waits().len(), 29);
        assert_eq!(
            fx.profile_gets(),
            30 + 1 + 1,
            "ann 30 times, bob once, the admin once"
        );
    }

    #[tokio::test]
    async fn twenty_nine_rate_limited_reads_in_a_row_are_still_waited_out() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        fx.rate_limit("ann", 29, Some(1), None);
        let store = StoreFake::of(&[("ann", DID_A)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, true, &pauses).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.rate_limited_waits, 29, "{report:?}");
        assert_eq!(report.error_count(), 0, "{report:?}");
    }

    #[tokio::test]
    async fn a_retry_after_header_alone_is_honoured() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        fx.rate_limit("ann", 2, None, Some("7"));
        let store = StoreFake::of(&[("ann", DID_A)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, true, &pauses).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(pauses.waits(), vec![Duration::from_secs(7); 2]);
    }

    #[tokio::test]
    async fn a_wait_is_capped_and_defaults_to_one_second() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        stale_account(&fx, &old, "ann", DID_A).await;
        stale_account(&fx, &old, "bob", DID_B).await;
        // An hour asked for, and no hint at all.
        fx.rate_limit("ann", 1, Some(3_600_000), None);
        fx.rate_limit("bob", 1, None, None);
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B)]);
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, true, &pauses).await;

        assert_eq!(report.written, 2, "{report:?}");
        assert_eq!(
            pauses.waits(),
            vec![Duration::from_secs(60), Duration::from_secs(1)],
            "ann is listed before bob"
        );
    }

    /// A 429 that ends in a success is not a failure, so it is not one of the ten in a row that
    /// stop the run.
    #[tokio::test]
    async fn rate_limited_accounts_that_succeed_do_not_trip_the_failure_stop() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let n = (MAX_CONSECUTIVE_ERRORS + 2) as usize;
        let mut entries = Vec::new();
        let dids: Vec<String> = (0..n).map(|i| format!("did:key:z6Mk{i:0>44}")).collect();
        for (i, did) in dids.iter().enumerate() {
            let lp = format!("u{i:02}");
            stale_account(&fx, &old, &lp, did).await;
            fx.rate_limit(&lp, 1, Some(1), None);
            entries.push((lp, did.clone()));
        }
        let store = StoreFake::of(
            &entries
                .iter()
                .map(|(lp, did)| (lp.as_str(), did.as_str()))
                .collect::<Vec<_>>(),
        );
        let pauses = RecordedPauses::default();

        let report = go_paused(&fx, &current, &store, false, &pauses).await;

        assert_eq!(report.aborted, None, "{report:?}");
        assert_eq!(report.rate_limited_waits, n as u64, "{report:?}");
        assert_eq!(report.error_count(), 0, "{report:?}");
        assert_eq!(report.would_write, n as u64, "{report:?}");
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_user("ann");
        fx.add_user("bob");
        fx.set_profile("ann", mint_value(&old, DID_A, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B)]);

        let report = go(&fx, &current, &store, false).await;

        assert_eq!(report.would_write, 2, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "a dry run does not write");
        assert!(report.render(false).contains("would_write: 2"));
    }

    #[tokio::test]
    async fn the_second_apply_writes_nothing() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        for lp in ["ann", "bob", "cy", "di", "ed"] {
            fx.add_user(lp);
        }
        fx.set_profile("ann", mint_value(&old, DID_A, &mxid_of("ann")).await);
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B), ("cy", DID_C), ("di", DID_D)]);
        fx.hs.lock().unwrap().page_size = 2;

        let first = go(&fx, &current, &store, true).await;
        assert_eq!(first.written, 4, "{first:?}");
        assert_eq!(first.skipped_no_mapping, 2, "ed and the admin account");
        let writes = fx.puts().len();

        let second = go(&fx, &current, &store, true).await;
        assert_eq!(second.written, 0, "{second:?}");
        assert_eq!(second.skipped_current, 4);
        assert_eq!(fx.puts().len(), writes, "the rerun wrote nothing");
        assert!(second.is_clean());
    }

    #[tokio::test]
    async fn an_ephemeral_key_is_refused_before_anything_is_read_or_written() {
        let fx = fixture!();
        let ephemeral = EcdsaSigningKey::generate();
        assert!(ephemeral.is_ephemeral());
        fx.add_user("ann");
        let store = StoreFake::of(&[("ann", DID_A)]);

        let refused = super::run(&Run {
            synapse: &fx.synapse,
            signer: &ephemeral,
            authority: &store,
            issuer: "https://auth.example.org/",
            server_name: SERVER,
            apply: true,
            limit: None,
            delay: Duration::ZERO,
            now: Some(IAT),
            pause: &SleepPause,
        })
        .await;

        assert_eq!(refused.err(), Some(Refused::EphemeralKey));
        let hs = fx.hs.lock().unwrap();
        assert_eq!(hs.list_requests, 0, "not even the list was read");
        assert!(hs.puts.is_empty());
    }

    #[tokio::test]
    async fn the_list_is_read_page_by_page_to_its_end() {
        let fx = fixture!();
        let key = key();
        for i in 0..7 {
            fx.add_user(&format!("u{i}"));
        }
        fx.hs.lock().unwrap().page_size = 3;
        let store = StoreFake::of(&[]);

        let report = go(&fx, &key, &store, false).await;

        assert_eq!(report.total, 8, "seven users and the admin account");
        assert_eq!(fx.hs.lock().unwrap().list_requests, 3);
    }

    #[tokio::test]
    async fn the_limit_stops_the_run_after_that_many_writes() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        for (lp, did) in [("ann", DID_A), ("bob", DID_B), ("cy", DID_C)] {
            fx.add_user(lp);
            fx.set_profile(lp, mint_value(&old, did, &mxid_of(lp)).await);
        }
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B), ("cy", DID_C)]);

        let first = run_with(&fx, &current, &store, true, Some(2)).await;
        assert_eq!(first.written, 2, "{first:?}");
        assert!(first.limit_reached);
        assert_eq!(fx.puts().len(), 2);

        let rest = go(&fx, &current, &store, true).await;
        assert_eq!(rest.written, 1, "the staged run picks up where it stopped");
        assert!(!rest.limit_reached);
    }

    #[tokio::test]
    async fn a_failed_write_is_a_counted_class_and_never_text() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_user("ann");
        fx.set_profile("ann", mint_value(&old, DID_A, &mxid_of("ann")).await);
        fx.hs.lock().unwrap().put_status = Some(StatusCode::FORBIDDEN);
        let store = StoreFake::of(&[("ann", DID_A)]);

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.written, 0);
        assert_eq!(
            report.errors.get(&ErrorClass::Publish),
            Some(&1),
            "{report:?}"
        );
        assert!(!report.is_clean());
        let shown = report.render(true);
        assert!(shown.contains("errors: publish=1"), "{shown}");
        assert!(!shown.contains("ann"), "{shown}");
    }

    #[tokio::test]
    async fn the_run_stops_after_a_streak_of_failures() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let mut entries: Vec<(String, String)> = Vec::new();
        for i in 0..(MAX_CONSECUTIVE_ERRORS as usize + 5) {
            let lp = format!("u{i:02}");
            fx.add_user(&lp);
            fx.set_profile(&lp, mint_value(&old, DID_A, &mxid_of(&lp)).await);
            entries.push((lp, DID_A.to_string()));
        }
        fx.hs.lock().unwrap().put_status = Some(StatusCode::FORBIDDEN);
        let store = StoreFake(entries.into_iter().collect());

        let report = go(&fx, &current, &store, true).await;

        assert_eq!(report.aborted, Some(Abort::ConsecutiveErrors), "{report:?}");
        assert_eq!(
            report.errors.get(&ErrorClass::Publish),
            Some(&u64::from(MAX_CONSECUTIVE_ERRORS))
        );
    }

    // -- H4: the output is counts only --------------------------------------------------------

    #[tokio::test]
    async fn the_report_names_no_account_did_proof_or_token() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        fx.add_user("ann");
        fx.add_user("bob");
        fx.add_deactivated("gone");
        let proof_a = mint_value(&old, DID_A, &mxid_of("ann")).await["proof"]
            .as_str()
            .unwrap()
            .to_string();
        fx.set_profile("ann", json!({"did": DID_A, "proof": proof_a}));
        fx.hs.lock().unwrap().put_status = None;
        let store = StoreFake::of(&[("ann", DID_A), ("bob", DID_B)]);

        for apply in [false, true] {
            let report = go(&fx, &current, &store, apply).await;
            let mut shown = report.render(apply);
            // The Debug text of the report is what a log line or a panic would show.
            shown.push_str(&format!("{report:?}"));
            for secret in [
                "ann",
                "bob",
                "gone",
                DID_A,
                DID_B,
                &proof_a,
                &mxid_of("ann"),
                SERVER,
                "shared-secret",
            ] {
                assert!(
                    !shown.contains(secret),
                    "the report must not show {} (apply={apply}): {shown}",
                    if secret.len() > 12 {
                        &secret[..12]
                    } else {
                        secret
                    }
                );
            }
        }
    }

    // -- H1: what the tool writes verifies in the shipped verifier ---------------------------

    /// The two documents a consumer fetches: discovery and the JWKS of the CURRENT key only
    /// (the old key is not in it).
    async fn spawn_issuer(key: &EcdsaSigningKey) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let jwks = serde_json::to_value(crate::oidc::jwks(key, &[]).unwrap()).unwrap();
        let discovery = json!({"issuer": issuer, "jwks_uri": format!("{issuer}/jwk")});
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/jwk", get(move || async move { Json(jwks) }));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (issuer, handle)
    }

    #[tokio::test]
    async fn the_written_binding_verifies_in_the_shipped_verifier_against_the_current_jwks() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let (issuer, issuer_task) = spawn_issuer(&current).await;
        fx.add_user("ann");
        // Signed by an old key that the JWKS no longer lists, for this issuer.
        let stale = did_profile_value(&old, &issuer, DID_A, &mxid_of("ann"), IAT - 5000)
            .await
            .unwrap();
        fx.set_profile("ann", stale.clone());
        let before = siwx_oidc_auth::did_assertion::verify_did_assertion(
            &issuer,
            stale["proof"].as_str().unwrap(),
            &mxid_of("ann"),
        )
        .await;
        assert!(
            before.is_err(),
            "the old binding does not verify against the current JWKS"
        );

        let store = StoreFake::of(&[("ann", DID_A)]);
        let report = super::run(&Run {
            synapse: &fx.synapse,
            signer: &current,
            authority: &store,
            issuer: &issuer,
            server_name: SERVER,
            apply: true,
            limit: None,
            delay: Duration::ZERO,
            now: Some(IAT),
            pause: &SleepPause,
        })
        .await
        .unwrap();
        assert_eq!(report.written, 1, "{report:?}");

        let stored = fx.profile("ann").unwrap();
        let verified = siwx_oidc_auth::did_assertion::verify_did_assertion(
            &issuer,
            stored["proof"].as_str().unwrap(),
            &mxid_of("ann"),
        )
        .await
        .expect("the re-minted binding verifies against the current JWKS");
        assert_eq!(verified.did(), DID_A);
        assert_eq!(verified.mxid(), mxid_of("ann"));
        issuer_task.abort();
    }

    // -- The derivation authority: the profile is a claim, the derivation decides ------------

    #[tokio::test]
    async fn a_claim_that_derives_to_the_account_is_confirmed_and_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let lp = modern(DID_A);
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&old, DID_A, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(fx.profile(&lp).unwrap()["did"], DID_A);
    }

    /// H2: a tampered profile cannot change who is bound. The `did` member names somebody
    /// else and the proof is a forgery for that somebody: neither derives to this account, so
    /// nothing is signed.
    #[tokio::test]
    async fn a_tampered_profile_cannot_make_the_tool_sign_a_did_the_account_is_not_derived_from() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let lp = modern(DID_A);
        fx.add_user(&lp);
        let tampered = mint_value(&old, DID_B, &mxid_of(&lp)).await;
        fx.set_profile(&lp, tampered.clone());
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 0, "{report:?}");
        assert_eq!(
            report.skipped_no_mapping, 2,
            "this account and the admin one"
        );
        assert!(fx.puts().is_empty());
        assert_eq!(fx.profile(&lp), Some(tampered), "left as it was");
    }

    /// The `did` member is tampered but the old proof still names the right DID: the right
    /// one is confirmed by the derivation and signed, the foreign one never.
    #[tokio::test]
    async fn the_confirmed_claim_wins_over_a_tampered_one() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let lp = modern(DID_A);
        fx.add_user(&lp);
        let mut value = mint_value(&old, DID_A, &mxid_of(&lp)).await;
        value["did"] = json!(DID_B);
        fx.set_profile(&lp, value);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        let stored = fx.profile(&lp).unwrap();
        assert_eq!(stored["did"], DID_A);
        assert!(!stored.to_string().contains(DID_B));
    }

    /// An account with no field has no claim, so the derivation has nothing to confirm.
    #[tokio::test]
    async fn an_account_with_no_claim_has_no_mapping_under_the_derivation() {
        let fx = fixture!();
        let current = key();
        fx.add_user(&modern(DID_A));
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 0, "{report:?}");
        assert!(fx.puts().is_empty());
    }

    /// A legacy account is signed under its legacy localpart; a modern-shaped second account
    /// for the same DID is not the one siwx-oidc keeps and gets nothing.
    #[tokio::test]
    async fn only_the_canonical_account_of_a_did_is_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let legacy = mxid::legacy_localpart(DID_C);
        let shadow = modern(DID_C);
        fx.add_user(&legacy);
        fx.add_user(&shadow);
        fx.set_profile(&legacy, mint_value(&old, DID_C, &mxid_of(&legacy)).await);
        fx.set_profile(&shadow, mint_value(&old, DID_C, &mxid_of(&shadow)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.skipped_not_canonical, 1);
        assert_eq!(fx.puts().len(), 1);
        assert_eq!(fx.puts()[0].0, legacy);
    }

    /// Two claims that differ only in case, and that both still read as a key a sign-in could
    /// have written, both derive to a legacy localpart: not guessed. (The old proofs cannot
    /// tell them apart: closing this needs the retired public keys, see the module doc.)
    #[tokio::test]
    async fn two_different_claims_that_both_derive_are_left_alone() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        // A P-256 `did:key`: the key is not checked past its multicodec prefix, so a case
        // change further in still reads as a key.
        let legacy = mxid::legacy_localpart(DID_A);
        let variant = format!("{}b", DID_A.strip_suffix('B').expect("DID_A ends in B"));
        assert_ne!(variant, DID_A);
        assert!(
            in_sign_in_form(&variant),
            "the variant reads as a valid key"
        );
        fx.add_user(&legacy);
        let mut value = mint_value(&old, DID_A, &mxid_of(&legacy)).await;
        value["did"] = json!(variant);
        fx.set_profile(&legacy, value);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_ambiguous, 1, "{report:?}");
        assert_eq!(report.written, 0);
    }

    /// A case change that breaks the key (its multicodec prefix) is no key a sign-in could
    /// have written, so it is no competing claim: the real one is signed.
    #[tokio::test]
    async fn a_case_change_that_breaks_the_key_is_not_a_competing_claim() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let legacy = mxid::legacy_localpart(DID_D);
        fx.add_user(&legacy);
        let mut value = mint_value(&old, DID_D, &mxid_of(&legacy)).await;
        value["did"] = json!(DID_D.replace("z6Mk", "z6MK"));
        fx.set_profile(&legacy, value);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.skipped_ambiguous, 0);
        assert_eq!(fx.profile(&legacy).unwrap()["did"], DID_D);
    }

    /// A legacy account's localpart is the DID with ':' turned into '-' and case folded, so a
    /// profile claim spelled that way derives to the account. No sign-in ever writes it, and
    /// signing it would put a binding for a DID nobody holds under the provider's key.
    #[tokio::test]
    async fn a_did_with_a_colon_turned_into_a_dash_is_not_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let legacy = mxid::legacy_localpart(DID_C);
        let variant = DID_C.replacen(":1:0x", ":1-0x", 1);
        assert_ne!(variant, DID_C);
        assert_eq!(mxid::legacy_localpart(&variant), legacy, "it derives");
        fx.add_user(&legacy);
        fx.set_profile(&legacy, mint_value(&old, &variant, &mxid_of(&legacy)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_not_canonical, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "nothing is written");
    }

    /// Upper-case method data in a `did:pkh` (`EIP155`, `0X`) folds to the same legacy
    /// localpart, and is not the text a sign-in writes.
    #[tokio::test]
    async fn an_upper_case_did_pkh_is_not_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let legacy = mxid::legacy_localpart(DID_C);
        let variant = DID_C.replace("eip155", "EIP155").replace(":0x", ":0X");
        assert_ne!(variant, DID_C);
        assert_eq!(mxid::legacy_localpart(&variant), legacy, "it derives");
        fx.add_user(&legacy);
        fx.set_profile(&legacy, mint_value(&old, &variant, &mxid_of(&legacy)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_not_canonical, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "nothing is written");
    }

    /// The EIP-55 checksummed spelling, from the EIP-55 specification's own test vectors.
    const CHECKSUMMED_ADDRESS: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    /// `did:pkh:eip155:1:` plus `address`, the way the login page forms it from the address the
    /// wallet returns.
    fn pkh(address: &str) -> String {
        format!("did:pkh:eip155:1:{address}")
    }

    /// A wallet sign-in writes the DID with the address the wallet returned, and a wallet
    /// returns the EIP-55 checksummed spelling. That is the text the profile holds, and the
    /// text that is signed again: stored, not folded to lower case. A rerun then writes nothing.
    #[tokio::test]
    async fn a_checksummed_did_pkh_is_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let checksummed = pkh(CHECKSUMMED_ADDRESS);
        assert_ne!(mxid::canonicalize(&checksummed), checksummed, "mixed case");
        let lp = modern(&checksummed);
        assert_eq!(lp, modern(&mxid::canonicalize(&checksummed)), "one account");
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&old, &checksummed, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.skipped_not_canonical, 0);
        let stored = fx.profile(&lp).expect("the field was written");
        assert_eq!(
            stored["did"], checksummed,
            "the claim as stored, not folded"
        );
        assert!(
            binding_is_current(
                &stored,
                &current,
                "https://auth.example.org/",
                &checksummed,
                &mxid_of(&lp)
            ),
            "the new proof is for the checksummed text"
        );
        let writes = fx.puts().len();

        let again = go(&fx, &current, &authority, true).await;

        assert_eq!(again.written, 0, "{again:?}");
        assert_eq!(again.skipped_current, 1);
        assert_eq!(fx.puts().len(), writes, "the rerun wrote nothing");
    }

    /// A checksummed binding that already verifies under the current key is current: it is
    /// skipped and nothing is written, through the production authority.
    #[tokio::test]
    async fn a_checksummed_binding_that_verifies_is_skipped_as_current() {
        let fx = fixture!();
        let current = key();
        let checksummed = pkh(CHECKSUMMED_ADDRESS);
        let lp = modern(&checksummed);
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&current, &checksummed, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_current, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert_eq!(report.skipped_not_canonical, 0);
        assert!(fx.puts().is_empty(), "a current binding is not rewritten");
    }

    /// Mixed case is not a spelling, it is a checksum: an address whose case does not encode
    /// its own EIP-55 checksum is no text a wallet returns. (One letter of the specification's
    /// vector changed in case.) Same account, so it waits for the holder's next sign-in.
    #[tokio::test]
    async fn a_mixed_case_did_pkh_with_a_wrong_checksum_is_not_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let wrong = pkh("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_ne!(wrong, pkh(CHECKSUMMED_ADDRESS));
        assert_eq!(
            mxid::canonicalize(&wrong),
            mxid::canonicalize(&pkh(CHECKSUMMED_ADDRESS)),
            "the same account"
        );
        let lp = modern(&wrong);
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&old, &wrong, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_not_canonical, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "nothing is written");
    }

    /// An all-upper-case address is not the checksum encoding of an address whose checksum has
    /// lower-case letters in it, and is not what a wallet returns.
    #[tokio::test]
    async fn an_all_upper_case_address_is_not_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let shouted = pkh(&format!("0x{}", CHECKSUMMED_ADDRESS[2..].to_uppercase()));
        assert_ne!(shouted, pkh(CHECKSUMMED_ADDRESS));
        let lp = modern(&shouted);
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&old, &shouted, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.skipped_not_canonical, 1, "{report:?}");
        assert_eq!(report.written, 0);
        assert!(fx.puts().is_empty(), "nothing is written");
    }

    /// The regression guard: a modern account whose DID is in canonical form is still signed.
    #[tokio::test]
    async fn a_modern_canonical_did_pkh_is_still_signed() {
        let fx = fixture!();
        let (old, current) = (key(), key());
        let lp = modern(DID_C);
        fx.add_user(&lp);
        fx.set_profile(&lp, mint_value(&old, DID_C, &mxid_of(&lp)).await);
        let authority = DerivationAuthority {
            synapse: &fx.synapse,
        };

        let report = go(&fx, &current, &authority, true).await;

        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(report.skipped_not_canonical, 0);
        assert_eq!(fx.profile(&lp).unwrap()["did"], DID_C);
    }

    /// The text rule on its own: a DID that parses the way a sign-in parses it and is either
    /// its own canonical form or a `did:pkh:eip155` whose address is the EIP-55 checksum
    /// encoding of the canonical (lower-case) one.
    #[test]
    fn only_a_did_in_a_sign_in_form_is_signable() {
        for ok in [
            DID_A,
            DID_B,
            DID_C,
            DID_D,
            // the EIP-55 specification's vectors, on chain 1 and on another chain
            "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "did:pkh:eip155:1:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "did:pkh:eip155:1:0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "did:pkh:eip155:1:0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "did:pkh:eip155:137:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            // an address whose own checksum happens to be all upper case is that checksum
            "did:pkh:eip155:1:0x52908400098527886E0F7030069857D2E4169EE7",
        ] {
            assert!(in_sign_in_form(ok), "{ok}");
        }
        for not_ok in [
            // ':' turned into '-'
            "did:pkh:eip155:1-0x7a76a0f2b0d4c3e1a5b9c8d7e6f50413229a8b7c",
            // upper-case method data
            "did:pkh:EIP155:1:0X7a76a0f2b0d4c3e1a5b9c8d7e6f50413229a8b7c",
            // ... also with a checksummed address: only the address may be mixed case
            "did:pkh:EIP155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "did:pkh:eip155:1:0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "DID:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "did:PKH:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            // a mixed-case address whose checksum is wrong
            "did:pkh:eip155:1:0x7a76A0f2B0d4C3e1A5b9c8D7e6f50413229A8b7c",
            "did:pkh:eip155:1:0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "did:pkh:eip155:1:0xFb6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            // an all-upper-case address that is not its own checksum
            "did:pkh:eip155:1:0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
            // a key whose case change broke its multicodec prefix
            "did:key:z6MKmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v",
            // not a method this provider signs in, and not a DID at all
            "did:web:example.org",
            "not a did",
            "",
        ] {
            assert!(!in_sign_in_form(not_ok), "{not_ok}");
        }
    }

    // -- The signing key must be the one the server publishes -------------------------------

    /// A server that answers `GET /jwk` with `body` and `status`, and counts what it was
    /// asked.
    async fn spawn_key_set(
        body: Value,
        status: StatusCode,
    ) -> (String, Arc<Mutex<usize>>, tokio::task::JoinHandle<()>) {
        let asked = Arc::new(Mutex::new(0usize));
        let counter = asked.clone();
        let app = Router::new().route(
            "/jwk",
            get(move || {
                let body = body.clone();
                let counter = counter.clone();
                async move {
                    *counter.lock().unwrap() += 1;
                    (status, Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwk", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, asked, handle)
    }

    fn key_set_of(keys: &[&dyn ProviderSigner]) -> Value {
        json!({"keys": keys.iter().map(|k| serde_json::to_value(k.verification_jwk()).unwrap()).collect::<Vec<_>>()})
    }

    #[tokio::test]
    async fn a_key_set_that_holds_the_signers_key_passes() {
        let current = key();
        let (url, asked, server) = spawn_key_set(key_set_of(&[&current]), StatusCode::OK).await;

        assert_eq!(check_key_is_published(&url, &current).await, Ok(()));

        assert_eq!(*asked.lock().unwrap(), 1);
        server.abort();
    }

    /// Retired keys that are still published sit beside the live one.
    #[tokio::test]
    async fn other_keys_beside_the_signers_key_do_not_matter() {
        let (current, retired) = (key(), key());
        let (url, _, server) =
            spawn_key_set(key_set_of(&[&retired, &current]), StatusCode::OK).await;

        assert_eq!(check_key_is_published(&url, &current).await, Ok(()));
        server.abort();
    }

    /// A stale environment, or a run during a rotation before the new key is live: the key the
    /// tool loaded is not in the set.
    #[tokio::test]
    async fn a_key_set_without_the_signers_kid_is_refused() {
        let (current, published) = (key(), key());
        assert_ne!(current.kid(), published.kid());
        let (url, _, server) = spawn_key_set(key_set_of(&[&published]), StatusCode::OK).await;

        assert_eq!(
            check_key_is_published(&url, &current).await,
            Err(Refused::KeyNotPublished)
        );
        server.abort();
    }

    /// The `kid` is derived from the public key, so a set that names this `kid` for another
    /// key is not this server's set (or is a forged one): refused, not trusted by name.
    #[tokio::test]
    async fn a_key_set_with_the_signers_kid_but_another_public_key_is_refused() {
        let (current, other) = (key(), key());
        let mut set = key_set_of(&[&other]);
        set["keys"][0]["kid"] = json!(current.kid());
        let (url, _, server) = spawn_key_set(set, StatusCode::OK).await;

        assert_eq!(
            check_key_is_published(&url, &current).await,
            Err(Refused::KeyNotPublished)
        );
        server.abort();
    }

    /// Two entries with one `kid` are not a set to pick from: every entry that carries the
    /// `kid` must be the signer's key.
    #[tokio::test]
    async fn a_second_key_under_the_signers_kid_makes_the_set_unusable() {
        let (current, other) = (key(), key());
        let mut set = key_set_of(&[&current, &other]);
        set["keys"][1]["kid"] = json!(current.kid());
        let (url, _, server) = spawn_key_set(set, StatusCode::OK).await;

        assert_eq!(
            check_key_is_published(&url, &current).await,
            Err(Refused::KeyNotPublished)
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_key_set_that_cannot_be_read_is_refused() {
        let current = key();
        // Not found, not a key set, and a server that is not there.
        for (body, status) in [
            (json!({"errcode": "M_NOT_FOUND"}), StatusCode::NOT_FOUND),
            (json!({"keys": []}), StatusCode::INTERNAL_SERVER_ERROR),
            (json!("<html>"), StatusCode::OK),
            (json!({"keys": "no"}), StatusCode::OK),
            (json!({}), StatusCode::OK),
        ] {
            let (url, _, server) = spawn_key_set(body.clone(), status).await;
            assert_eq!(
                check_key_is_published(&url, &current).await,
                Err(Refused::KeySetUnreadable),
                "{status} {body}"
            );
            server.abort();
        }
        assert_eq!(
            check_key_is_published("http://127.0.0.1:1/jwk", &current).await,
            Err(Refused::KeySetUnreadable)
        );
    }

    /// The messages are fixed text: not a kid, a key or a URL in any of them.
    #[test]
    fn a_refusal_names_no_kid_key_or_url() {
        let current = key();
        for refused in [Refused::KeyNotPublished, Refused::KeySetUnreadable] {
            let shown = refused.to_string();
            assert!(!shown.contains(current.kid()), "{shown}");
            assert!(!shown.contains("http"), "{shown}");
            assert!(shown.contains("Nothing was read or written"), "{shown}");
        }
    }

    // -- Which program this process is ------------------------------------------------------

    fn os(parts: &[&[u8]]) -> Vec<std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt;
        parts
            .iter()
            .map(|p| std::ffi::OsString::from_vec(p.to_vec()))
            .collect()
    }

    #[test]
    fn no_arguments_choose_the_server() {
        assert_eq!(invoked_as_tool(Vec::<std::ffi::OsString>::new()), None);
        assert_eq!(invoked_as_tool(os(&[b"siwx-oidc"])), None);
    }

    #[test]
    fn unrelated_arguments_choose_the_server() {
        assert_eq!(invoked_as_tool(os(&[b"siwx-oidc", b"--help"])), None);
        assert_eq!(
            invoked_as_tool(os(&[b"/usr/local/bin/siwx-oidc", b"serve", b"remint"])),
            None
        );
        // The name has to be the whole of it: not a prefix, a suffix or a longer path part.
        assert_eq!(invoked_as_tool(os(&[b"remint-did-assertions-x"])), None);
        assert_eq!(invoked_as_tool(os(&[b"x-remint-did-assertions"])), None);
        assert_eq!(
            invoked_as_tool(os(&[b"siwx-oidc", b"remint-did-assertions-x"])),
            None
        );
    }

    #[test]
    fn an_argument_that_is_not_utf8_chooses_the_server_and_does_not_panic() {
        assert_eq!(invoked_as_tool(os(&[b"siwx-oidc", b"--\xff\xfe"])), None);
        assert_eq!(
            invoked_as_tool(os(&[
                b"siwx-oidc",
                b"--ok",
                b"\xff",
                b"remint-did-assertions"
            ])),
            None,
            "the tool's name is the first argument or nothing"
        );
        // A program name that is not text and is not the tool's name.
        assert_eq!(invoked_as_tool(os(&[b"/opt/\xff/siwx-oidc", b"--x"])), None);
    }

    #[test]
    fn the_program_name_remint_did_assertions_chooses_the_tool() {
        assert_eq!(
            invoked_as_tool(os(&[
                b"remint-did-assertions",
                b"--apply",
                b"--limit",
                b"3"
            ])),
            Some(os(&[b"--apply", b"--limit", b"3"]))
        );
        assert_eq!(
            invoked_as_tool(os(&[b"/usr/local/bin/remint-did-assertions"])),
            Some(Vec::new())
        );
        // A directory that is not text does not hide the basename.
        assert_eq!(
            invoked_as_tool(os(&[b"/opt/\xff/remint-did-assertions", b"--apply"])),
            Some(os(&[b"--apply"]))
        );
    }

    #[test]
    fn the_first_argument_remint_did_assertions_chooses_the_tool() {
        assert_eq!(
            invoked_as_tool(os(&[b"siwx-oidc", b"remint-did-assertions", b"--apply"])),
            Some(os(&[b"--apply"]))
        );
        assert_eq!(
            invoked_as_tool(os(&[b"siwx-oidc", b"remint-did-assertions"])),
            Some(Vec::new())
        );
        // What follows is the tool's, even if it is not text: the tool refuses it itself.
        assert_eq!(
            invoked_as_tool(os(&[b"siwx-oidc", b"remint-did-assertions", b"\xff"])),
            Some(os(&[b"\xff"]))
        );
    }

    // -- Pure pieces ----------------------------------------------------------------------

    #[test]
    fn the_claims_of_a_value_are_its_did_and_its_proofs_subject_without_repeats() {
        let key = key();
        let proof = futures_block(async { mint_value(&key, DID_A, &mxid_of("ann")).await });
        assert_eq!(claims_of(&proof), vec![DID_A.to_string()]);
        let mut other = proof.clone();
        other["did"] = json!(DID_B);
        assert_eq!(
            claims_of(&other),
            vec![DID_B.to_string(), DID_A.to_string()]
        );
        assert_eq!(
            claims_of(&json!(DID_A)),
            vec![DID_A.to_string()],
            "bare string"
        );
        assert!(claims_of(&json!({"proof": "not a jws"})).is_empty());
        assert!(claims_of(&json!(null)).is_empty());
        assert!(claims_of(&json!({"did": ""})).is_empty());
    }

    fn futures_block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_binding_is_current_only_when_every_part_matches() {
        let (key, other) = (key(), key());
        let mint = |k: &EcdsaSigningKey, did: &str, mxid: &str, iss: &str| {
            futures_block(did_profile_value(k, iss, did, mxid, IAT)).unwrap()
        };
        let iss = "https://auth.example.org/";
        let good = mint(&key, DID_A, "@a:hs", iss);
        assert!(binding_is_current(&good, &key, iss, DID_A, "@a:hs"));
        // The issuer is compared without a trailing slash.
        assert!(binding_is_current(
            &good,
            &key,
            "https://auth.example.org",
            DID_A,
            "@a:hs"
        ));
        // Each part, wrong in turn.
        assert!(
            !binding_is_current(&good, &other, iss, DID_A, "@a:hs"),
            "other key"
        );
        assert!(
            !binding_is_current(&good, &key, iss, DID_B, "@a:hs"),
            "other did"
        );
        assert!(
            !binding_is_current(&good, &key, iss, DID_A, "@b:hs"),
            "other mxid"
        );
        assert!(!binding_is_current(
            &good,
            &key,
            "https://evil.example",
            DID_A,
            "@a:hs"
        ));
        let mut unsigned_did_changed = good.clone();
        unsigned_did_changed["did"] = json!(DID_B);
        assert!(!binding_is_current(
            &unsigned_did_changed,
            &key,
            iss,
            DID_A,
            "@a:hs"
        ));
        assert!(!binding_is_current(
            &json!({"did": DID_A}),
            &key,
            iss,
            DID_A,
            "@a:hs"
        ));
        assert!(!binding_is_current(
            &json!({"did": DID_A, "proof": ""}),
            &key,
            iss,
            DID_A,
            "@a:hs"
        ));
        assert!(!binding_is_current(
            &json!(DID_A),
            &key,
            iss,
            DID_A,
            "@a:hs"
        ));
        assert!(!binding_is_current(&json!(null), &key, iss, DID_A, "@a:hs"));
    }

    fn args(a: &[&str]) -> Result<Parsed> {
        parse_args(a.iter().map(|s| s.to_string()))
    }

    #[test]
    fn the_arguments_default_to_a_dry_run() {
        assert_eq!(
            args(&[]).unwrap(),
            Parsed::Run(Args {
                apply: false,
                limit: None,
                delay: Duration::from_millis(DEFAULT_DELAY_MS)
            })
        );
        assert_eq!(
            args(&["--apply", "--limit", "5", "--delay-ms=0"]).unwrap(),
            Parsed::Run(Args {
                apply: true,
                limit: Some(5),
                delay: Duration::ZERO
            })
        );
        assert_eq!(args(&["--help"]).unwrap(), Parsed::Help);
    }

    #[test]
    fn bad_arguments_are_refused_without_echoing_their_values() {
        for bad in [
            &["--apply=yes"][..],
            &["--limit"][..],
            &["--limit", "0"][..],
            &["--limit", "many"][..],
            &["--delay-ms"][..],
        ] {
            assert!(args(bad).is_err(), "{bad:?}");
        }
        let shown = format!("{:#}", args(&["--bogus=secret-value"]).unwrap_err());
        assert!(shown.contains("`--bogus`"), "{shown}");
        assert!(!shown.contains("secret-value"), "{shown}");
        let shown = format!("{:#}", args(&["redis://user:pw@host"]).unwrap_err());
        assert!(!shown.contains("pw"), "{shown}");
    }
}
