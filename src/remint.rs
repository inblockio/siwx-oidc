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
//! claims that both pass are ambiguous and are left alone.
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
use crate::synapse_client::{matrix_user_id, AdminUserRow, PublishOutcome, SynapseClient};

/// The name the tool is called by.
pub(crate) const TOOL_NAME: &str = "remint-did-assertions";

/// The pause after each write, so a full run does not hammer the homeserver. `--delay-ms`
/// changes it.
const DEFAULT_DELAY_MS: u64 = 250;

/// A run stops after this many failures in a row: a homeserver or a signer that is down fails
/// every account the same way, and going on only repeats it.
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

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
    pub would_write: u64,
    pub written: u64,
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
        if apply {
            out.push_str(&format!("  written: {}\n", self.written));
        } else {
            out.push_str(&format!("  would_write: {}\n", self.would_write));
        }
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

/// A run that did not start.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The signing key is ephemeral: no proof would be minted, and a profile would be
    /// rewritten without one.
    EphemeralKey,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::EphemeralKey => f.write_str(
                "the signing key is ephemeral, so no proof can be minted and every binding \
                 written would lose its proof. Set SIWXOIDC_SIGNING_KEY_PEM (or use the socket \
                 backend). Nothing was read or written.",
            ),
        }
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

    let published = match run.synapse.read_did_value(localpart, run.server_name).await {
        Ok(published) => published,
        Err(_) => {
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
pub(crate) fn invoked_as_tool(mut argv: impl Iterator<Item = String>) -> Option<Vec<String>> {
    let program = argv.next()?;
    let called_by_name = std::path::Path::new(&program)
        .file_name()
        .is_some_and(|name| name == TOOL_NAME);
    let rest: Vec<String> = argv.collect();
    if called_by_name {
        return Some(rest);
    }
    match rest.split_first() {
        Some((first, tail)) if first == TOOL_NAME => Some(tail.to_vec()),
        _ => None,
    }
}

pub(crate) async fn cli_main(args: Vec<String>) -> ExitCode {
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
    println!("  signing kid: {}", signer.kid());

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
        let include_deactivated = deactivated == "true";
        let rows: Vec<(&String, &UserRec)> = hs
            .users
            .iter()
            .filter(|(_, u)| include_deactivated || !u.deactivated)
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

    async fn get_field(State(hs): State<Shared>, Path(user): Path<String>) -> impl IntoResponse {
        let mut hs = hs.lock().unwrap();
        hs.profile_gets += 1;
        if hs.rowless.contains(&localpart_of(&user)) || hs.unreadable.contains(&localpart_of(&user))
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"errcode": "M_UNKNOWN", "error": "Internal server error"})),
            );
        }
        match hs.profile.get(&localpart_of(&user)) {
            Some(value) => (StatusCode::OK, Json(json!({ DID_PROFILE_FIELD: value }))),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"errcode": "M_NOT_FOUND", "error": "no such field"})),
            ),
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

    /// Two claims that differ only in case both derive to a legacy localpart: not guessed.
    #[tokio::test]
    async fn two_different_claims_that_both_derive_are_left_alone() {
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

        assert_eq!(report.skipped_ambiguous, 1, "{report:?}");
        assert_eq!(report.written, 0);
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
