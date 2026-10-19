//! The output schema: reason codes, verdicts, line rendering, the summary rule
//! and the exit codes.

use crate::hygiene;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Fail,
    Skip,
}

impl Verdict {
    pub fn word(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
        }
    }
}

/// Every reason code the canary prints: a closed set. Errors from the library,
/// reqwest or the server are mapped to one of these and their text is dropped,
/// because those texts embed response bodies and URLs.
macro_rules! reasons {
    ($($variant:ident => $code:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Reason {
            $($variant),+
        }

        impl Reason {
            pub fn code(self) -> &'static str {
                match self {
                    $(Reason::$variant => $code),+
                }
            }

            #[cfg(test)]
            pub const ALL: &'static [Reason] = &[$(Reason::$variant),+];
        }
    };
}

reasons! {
    Ok => "ok",
    // Usage and local state.
    BadArguments => "bad_arguments",
    BadEnv => "bad_env",
    BadUrl => "bad_url",
    BadKids => "bad_kids",
    KidsOverlap => "kids_overlap",
    NoMatrixNeedsLocal => "no_matrix_needs_env_local",
    NoHome => "no_home",
    CoreLimit => "core_limit_unset",
    NotInitialized => "not_initialized",
    IdentityExists => "identity_exists",
    IdentityUnreadable => "identity_unreadable",
    IdentityWriteFailed => "identity_write_failed",
    PermsUnsafe => "perms_unsafe",
    StoredIssuerDiffers => "stored_issuer_differs",
    LockBusy => "lock_busy",
    LockFailed => "lock_failed",
    // C1 discovery.
    DiscoveryUnreachable => "discovery_unreachable",
    DiscoveryStatus => "discovery_status",
    DiscoveryMalformed => "discovery_malformed",
    IssuerMismatch => "issuer_mismatch",
    JwksOrigin => "jwks_uri_origin",
    // C2 jwks.
    JwksUnreachable => "jwks_unreachable",
    JwksStatus => "jwks_status",
    JwksMalformed => "jwks_malformed",
    JwksUnavailable => "jwks_unavailable",
    DroppedKidPresent => "dropped_kid_present",
    KidSetDiffers => "kid_set_differs",
    KidNotDerived => "kid_not_derived",
    KidDuplicate => "kid_duplicate",
    // C3 sign-in.
    ClientRefused => "client_refused",
    RegisterFailed => "register_failed",
    SignInUnavailable => "sign_in_unavailable",
    AuthorizeUnexpected => "authorize_unexpected",
    IdentityUnusable => "identity_unusable",
    DeviceRefused => "device_refused",
    SignInRefused => "sign_in_refused",
    SignInFailed => "sign_in_failed",
    IdTokenMissing => "id_token_missing",
    IdTokenMalformed => "id_token_malformed",
    AlgMismatch => "alg_mismatch",
    KidMismatch => "kid_mismatch",
    KidNotInJwks => "kid_not_in_jwks",
    JwkUnusable => "jwk_unusable",
    SignatureInvalid => "signature_invalid",
    IssClaimMismatch => "iss_claim_mismatch",
    AudMismatch => "aud_mismatch",
    SubMismatch => "sub_mismatch",
    ServerDateMissing => "server_date_missing",
    ClockSkew => "clock_skew",
    TokenExpired => "token_expired",
    // C4 whoami.
    WhoamiUnreachable => "whoami_unreachable",
    WhoamiStatus => "whoami_status",
    WhoamiMalformed => "whoami_malformed",
    ServerNameMismatch => "server_name_mismatch",
    // C5 did proof.
    ProfileUnreachable => "profile_unreachable",
    ProfileStatus => "profile_status",
    DidFieldAbsent => "did_field_absent",
    DidProofAbsent => "did_proof_absent",
    DidKidMismatch => "did_kid_mismatch",
    DidProofInvalid => "did_proof_invalid",
    DidSubMismatch => "did_sub_mismatch",
    DidProofStale => "did_proof_stale",
    // C6 logout.
    IdentityCompromised => "identity_compromised",
    TripwireUnavailable => "tripwire_unavailable",
    NoRefreshToken => "no_refresh_token",
    LogoutStatus => "logout_status",
    LogoutIneffective => "logout_ineffective",
    LogoutUnproven => "logout_unproven",
    // Skips.
    NoSignIn => "no_sign_in",
    NoMatrix => "no_matrix",
    BlockedByDiscovery => "blocked_by_discovery",
    BlockedByWhoami => "blocked_by_whoami",
    // init.
    EraseFailed => "erase_failed",
    DisplayNameFailed => "display_name_failed",
    RouteProbeFailed => "route_probe_failed",
    // Output and process.
    OutputRefused => "output_refused",
    Internal => "internal_error",
}

/// The checks of `check`, C1 to C6, always all recorded: a check that did not
/// run is recorded as skipped, never left out.
pub const CHECKS: usize = 6;
pub const ENV_LOCAL: &str = "local";

#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub check: &'static str,
    pub verdict: Verdict,
    pub reason: Reason,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub checks_run: usize,
    pub skipped: usize,
    pub ok: bool,
}

/// The pass rule: all six checks recorded, none failed, no output refused, and
/// no skip unless the environment is `local` (only `--no-matrix` skips on
/// purpose, and it is allowed only there).
pub fn summarize(outcomes: &[Outcome], env: &str, taint_tripped: bool) -> Summary {
    let skipped = outcomes
        .iter()
        .filter(|o| o.verdict == Verdict::Skip)
        .count();
    let any_fail = outcomes.iter().any(|o| o.verdict == Verdict::Fail);
    let checks_run = outcomes.len() - skipped;
    Summary {
        checks_run,
        skipped,
        ok: outcomes.len() == CHECKS
            && checks_run > 0
            && !any_fail
            && !taint_tripped
            && (skipped == 0 || env == ENV_LOCAL),
    }
}

/// 0 all ran and passed, 1 a check failed (or an output was refused), 3 logout
/// not proven (tokens may live until they expire), 4 the tripwire fired. Usage
/// errors (2) are decided before any check runs. 4 outranks 3, 3 outranks 1.
pub fn exit_code(outcomes: &[Outcome], summary: &Summary) -> i32 {
    let logout = outcomes
        .iter()
        .find(|o| o.check == "logout" && o.verdict == Verdict::Fail);
    match logout.map(|o| o.reason) {
        Some(Reason::IdentityCompromised) => 4,
        Some(
            Reason::LogoutStatus
            | Reason::LogoutIneffective
            | Reason::LogoutUnproven
            | Reason::NoRefreshToken,
        ) => 3,
        _ if summary.ok => 0,
        _ => 1,
    }
}

/// One check line: `CANARY <check> result=… reason=… key=value…`. Keys are
/// literals of this program; every value passes [`hygiene::value`].
pub fn render(check: &str, verdict: Verdict, reason: Reason, fields: &[(&str, String)]) -> String {
    let mut line = format!(
        "CANARY {check} result={} reason={}",
        verdict.word(),
        reason.code()
    );
    for (key, val) in fields {
        line.push(' ');
        line.push_str(key);
        line.push('=');
        line.push_str(&hygiene::value(val));
    }
    line
}

/// Render a check line and print it through the taint check.
pub fn emit(check: &str, verdict: Verdict, reason: Reason, fields: &[(&str, String)]) {
    hygiene::print_line(render(check, verdict, reason, fields), check);
}

/// The summary line, in the one shape the wrapper gates on.
pub fn render_summary(summary: &Summary) -> String {
    format!(
        "CANARY summary checks_run={} skipped={} result={}",
        summary.checks_run,
        summary.skipped,
        if summary.ok { "ok" } else { "FAIL" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_are_lowercase_words_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for r in Reason::ALL {
            let code = r.code();
            assert!(
                !code.is_empty()
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{code}"
            );
            assert!(seen.insert(code), "duplicate reason code {code}");
        }
    }

    fn outcome(check: &'static str, verdict: Verdict, reason: Reason) -> Outcome {
        Outcome {
            check,
            verdict,
            reason,
        }
    }

    fn all_ok() -> Vec<Outcome> {
        [
            "discovery",
            "jwks",
            "sign_in",
            "whoami",
            "did_proof",
            "logout",
        ]
        .into_iter()
        .map(|c| outcome(c, Verdict::Ok, Reason::Ok))
        .collect()
    }

    fn no_matrix() -> Vec<Outcome> {
        let mut v = all_ok();
        for o in v.iter_mut().skip(3) {
            o.verdict = Verdict::Skip;
        }
        v
    }

    #[test]
    fn lines_have_the_fixed_schema_and_a_clean_charset() {
        let line = render(
            "sign_in",
            Verdict::Fail,
            Reason::KidMismatch,
            &[
                ("got_kid", "abc def\nCANARY summary".to_string()),
                ("client", "reused".to_string()),
            ],
        );
        assert_eq!(
            line,
            "CANARY sign_in result=FAIL reason=kid_mismatch got_kid=abc_def_CANARY_summary client=reused"
        );
        assert_eq!(line.lines().count(), 1);
        assert_eq!(
            render("jwks", Verdict::Ok, Reason::Ok, &[]),
            "CANARY jwks result=ok reason=ok"
        );
        assert_eq!(
            render(
                "logout",
                Verdict::Skip,
                Reason::NoMatrix,
                &[("revoked", String::new())]
            ),
            "CANARY logout result=SKIP reason=no_matrix revoked=<none>"
        );
    }

    #[test]
    fn the_summary_line_is_exactly_the_tabled_shape() {
        let s = summarize(&all_ok(), "dev", false);
        assert_eq!(
            render_summary(&s),
            "CANARY summary checks_run=6 skipped=0 result=ok"
        );
        let s = summarize(&no_matrix(), "local", false);
        assert_eq!(
            render_summary(&s),
            "CANARY summary checks_run=3 skipped=3 result=ok"
        );
        let s = summarize(&no_matrix(), "dev", false);
        assert_eq!(
            render_summary(&s),
            "CANARY summary checks_run=3 skipped=3 result=FAIL"
        );
    }

    #[test]
    fn six_passed_checks_are_a_pass() {
        let s = summarize(&all_ok(), "dev", false);
        assert_eq!(
            s,
            Summary {
                checks_run: 6,
                skipped: 0,
                ok: true
            }
        );
        assert_eq!(exit_code(&all_ok(), &s), 0);
    }

    #[test]
    fn skips_outside_env_local_fail_the_summary() {
        let s = summarize(&no_matrix(), "dev", false);
        assert_eq!((s.checks_run, s.skipped), (3, 3));
        assert!(
            !s.ok,
            "a run with skipped checks must not pass outside env local"
        );
        assert_eq!(exit_code(&no_matrix(), &s), 1);
        let s = summarize(&no_matrix(), "prod", false);
        assert!(!s.ok);
    }

    #[test]
    fn skips_are_allowed_in_env_local_only() {
        let s = summarize(&no_matrix(), "local", false);
        assert_eq!(
            s,
            Summary {
                checks_run: 3,
                skipped: 3,
                ok: true
            }
        );
        assert_eq!(exit_code(&no_matrix(), &s), 0);
    }

    #[test]
    fn a_failed_check_fails_even_in_env_local() {
        let mut o = no_matrix();
        o[2] = outcome("sign_in", Verdict::Fail, Reason::ClientRefused);
        let s = summarize(&o, "local", false);
        assert!(!s.ok);
        assert_eq!(exit_code(&o, &s), 1);
    }

    #[test]
    fn a_tripped_taint_check_fails_the_run() {
        let s = summarize(&all_ok(), "dev", true);
        assert!(!s.ok);
        assert_eq!(exit_code(&all_ok(), &s), 1);
    }

    #[test]
    fn a_summary_that_does_not_cover_six_checks_is_not_a_pass() {
        let short: Vec<Outcome> = all_ok().into_iter().take(5).collect();
        assert!(!summarize(&short, "dev", false).ok);
    }

    #[test]
    fn exit_codes_rank_tripwire_over_logout_over_check() {
        let mut o = all_ok();
        o[5] = outcome("logout", Verdict::Fail, Reason::LogoutUnproven);
        let s = summarize(&o, "dev", false);
        assert_eq!(exit_code(&o, &s), 3);
        o[2] = outcome("sign_in", Verdict::Fail, Reason::ClientRefused);
        let s = summarize(&o, "dev", false);
        assert_eq!(
            exit_code(&o, &s),
            3,
            "unproven logout outranks a failed check: tokens may live"
        );
        o[5] = outcome("logout", Verdict::Fail, Reason::IdentityCompromised);
        let s = summarize(&o, "dev", false);
        assert_eq!(exit_code(&o, &s), 4);
    }
}
