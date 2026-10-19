//! Arguments and their validation. Nothing here echoes an argument back: a
//! rejected command line prints a reason code, never clap's message (which
//! quotes the offending argument).

use std::collections::BTreeSet;
use std::ffi::OsString;

use clap::{Args, Parser, Subcommand};
use url::Url;

use crate::report::{Reason, ENV_LOCAL};

#[derive(Parser)]
#[command(
    name = "rotation-canary",
    about = "Headless post-rotation sign-in check for a siwx-oidc deployment. Prints only \
             `CANARY <check> result=ok|FAIL|SKIP reason=<code> key=value...` lines. Exit codes: \
             0 every check ran and passed, 1 a check failed, 2 usage or local state, 3 logout \
             not proven (tokens may live until they expire), 4 the identity tripwire fired."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the environment's persistent identity: generate a key, register a client, sign
    /// in once, set the display name, log out, and store the public client record.
    Init(InitArgs),
    /// Sign in with the stored identity and run the six checks.
    Check(CheckArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Environment name; the identity lives in `~/.aqua-secrets/rotation-canary/<env>/`.
    #[arg(long)]
    env: String,
    /// The siwx-oidc issuer URL.
    #[arg(long)]
    issuer: String,
    /// The Matrix homeserver (client-server API) URL.
    #[arg(long)]
    homeserver: String,
    /// The Matrix server name that MXIDs end with.
    #[arg(long)]
    server_name: String,
    /// Erase the existing account with its own key (`io.inblock.account_erase`) and make a new
    /// identity. Without it an existing identity is never touched.
    #[arg(long)]
    replace: bool,
}

#[derive(Args)]
struct CheckArgs {
    /// Environment name; the identity lives in `~/.aqua-secrets/rotation-canary/<env>/`.
    #[arg(long)]
    env: String,
    /// The siwx-oidc issuer URL.
    #[arg(long)]
    issuer: String,
    /// The Matrix homeserver (client-server API) URL.
    #[arg(long)]
    homeserver: Option<String>,
    /// The Matrix server name that MXIDs end with.
    #[arg(long)]
    server_name: Option<String>,
    /// Skip the Matrix checks (C4 to C6). Allowed only with `--env local`.
    #[arg(long)]
    no_matrix: bool,
    /// The kid the server signs with now.
    #[arg(long)]
    live_kid: String,
    /// The exact set of kids `/jwk` must publish.
    #[arg(long, value_delimiter = ',', required = true)]
    expect_kids: Vec<String>,
    /// Kids that must not be published (the exposed keys).
    #[arg(long, value_delimiter = ',')]
    dropped_kids: Vec<String>,
    /// The run before a rotation: the only run that may register a new client when the
    /// stored one is refused.
    #[arg(long)]
    baseline: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    pub homeserver: String,
    pub server_name: String,
}

#[derive(Debug)]
pub struct InitConfig {
    pub env: String,
    pub issuer: String,
    pub matrix: Matrix,
    pub replace: bool,
}

#[derive(Debug)]
pub struct CheckConfig {
    pub env: String,
    pub issuer: String,
    pub matrix: Option<Matrix>,
    pub live_kid: String,
    pub expect: BTreeSet<String>,
    pub dropped: BTreeSet<String>,
    pub baseline: bool,
}

#[derive(Debug)]
pub enum Parsed {
    Init(InitConfig),
    Check(CheckConfig),
}

/// Why no command runs.
#[derive(Debug)]
pub enum Early {
    /// `--help`: static text, printed to stdout, exit 0.
    Help(String),
    Usage(Reason),
}

pub fn parse<I, T>(args: I) -> Result<Parsed, Early>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            return Err(match e.kind() {
                clap::error::ErrorKind::DisplayHelp => Early::Help(e.to_string()),
                _ => Early::Usage(Reason::BadArguments),
            })
        }
    };
    match cli.command {
        Command::Init(a) => {
            check_env(&a.env)?;
            Ok(Parsed::Init(InitConfig {
                issuer: origin_url(&a.env, &a.issuer).map_err(Early::Usage)?,
                matrix: Matrix {
                    homeserver: origin_url(&a.env, &a.homeserver).map_err(Early::Usage)?,
                    server_name: server_name(&a.server_name).map_err(Early::Usage)?,
                },
                replace: a.replace,
                env: a.env,
            }))
        }
        Command::Check(a) => {
            check_env(&a.env)?;
            let matrix = match (a.no_matrix, a.homeserver, a.server_name) {
                (true, None, None) => {
                    if a.env != ENV_LOCAL {
                        return Err(Early::Usage(Reason::NoMatrixNeedsLocal));
                    }
                    None
                }
                (false, Some(h), Some(n)) => Some(Matrix {
                    homeserver: origin_url(&a.env, &h).map_err(Early::Usage)?,
                    server_name: server_name(&n).map_err(Early::Usage)?,
                }),
                _ => return Err(Early::Usage(Reason::BadArguments)),
            };
            if !kid(&a.live_kid) {
                return Err(Early::Usage(Reason::BadKids));
            }
            let expect = kids(&a.expect_kids).map_err(Early::Usage)?;
            let dropped = kids(&a.dropped_kids).map_err(Early::Usage)?;
            if expect.is_empty() {
                return Err(Early::Usage(Reason::BadKids));
            }
            if expect.intersection(&dropped).next().is_some() {
                return Err(Early::Usage(Reason::KidsOverlap));
            }
            Ok(Parsed::Check(CheckConfig {
                issuer: origin_url(&a.env, &a.issuer).map_err(Early::Usage)?,
                matrix,
                live_kid: a.live_kid,
                expect,
                dropped,
                baseline: a.baseline,
                env: a.env,
            }))
        }
    }
}

/// The environment names the directory: lowercase letters, digits, `-`, `_`,
/// at most 32, starting with a letter or digit (no `.`, no `/`).
fn check_env(env: &str) -> Result<(), Early> {
    let ok = !env.is_empty()
        && env.len() <= 32
        && env.as_bytes()[0].is_ascii_alphanumeric()
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Early::Usage(Reason::BadEnv))
    }
}

/// A server URL reduced to its origin (`https://host[:port]`, the trailing
/// slash and a default port gone). `https` only, except `http` for `--env
/// local`; no credentials, path, query or fragment.
pub fn origin_url(env: &str, raw: &str) -> Result<String, Reason> {
    let url = Url::parse(raw.trim()).map_err(|_| Reason::BadUrl)?;
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && env == ENV_LOCAL);
    let plain = url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/");
    if scheme_ok && plain && url.host_str().is_some() {
        Ok(url.origin().ascii_serialization())
    } else {
        Err(Reason::BadUrl)
    }
}

/// `example.org`, `matrix.example.org:8448`.
fn server_name(raw: &str) -> Result<String, Reason> {
    let ok = !raw.is_empty()
        && raw.len() <= 255
        && raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b':')
        });
    if ok {
        Ok(raw.to_string())
    } else {
        Err(Reason::BadUrl)
    }
}

/// A kid as the server derives it: 16 lowercase hex characters.
pub fn kid(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn kids(list: &[String]) -> Result<BTreeSet<String>, Reason> {
    list.iter()
        .map(|k| {
            if kid(k) {
                Ok(k.clone())
            } else {
                Err(Reason::BadKids)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "0123456789abcdef";
    const K2: &str = "fedcba9876543210";

    fn check(extra: &[&str]) -> Result<Parsed, Early> {
        let mut args = vec![
            "rotation-canary",
            "check",
            "--env",
            "dev",
            "--issuer",
            "https://siwx.example.org/",
            "--live-kid",
            K1,
            "--expect-kids",
            K1,
        ];
        args.extend_from_slice(extra);
        parse(args)
    }

    fn usage(r: Result<Parsed, Early>) -> Reason {
        match r {
            Err(Early::Usage(reason)) => reason,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn a_full_matrix_check_parses_and_normalizes_the_urls() {
        let Ok(Parsed::Check(c)) = check(&[
            "--homeserver",
            "https://matrix.example.org/",
            "--server-name",
            "example.org",
            "--dropped-kids",
            K2,
        ]) else {
            panic!("should parse");
        };
        assert_eq!(c.issuer, "https://siwx.example.org");
        assert_eq!(c.matrix.unwrap().homeserver, "https://matrix.example.org");
        assert_eq!(c.expect, BTreeSet::from([K1.to_string()]));
        assert_eq!(c.dropped, BTreeSet::from([K2.to_string()]));
        assert!(!c.baseline);
    }

    #[test]
    fn no_matrix_is_allowed_only_in_env_local() {
        assert_eq!(usage(check(&["--no-matrix"])), Reason::NoMatrixNeedsLocal);
        let Ok(Parsed::Check(c)) = parse([
            "rotation-canary",
            "check",
            "--env",
            "local",
            "--issuer",
            "http://localhost:18080",
            "--no-matrix",
            "--live-kid",
            K1,
            "--expect-kids",
            &format!("{K1},{K2}"),
        ]) else {
            panic!("local --no-matrix should parse");
        };
        assert!(c.matrix.is_none());
        assert_eq!(c.issuer, "http://localhost:18080");
        assert_eq!(c.expect.len(), 2);
    }

    #[test]
    fn matrix_flags_and_no_matrix_are_exclusive_and_one_is_required() {
        assert_eq!(usage(check(&[])), Reason::BadArguments);
        assert_eq!(
            usage(check(&["--homeserver", "https://matrix.example.org"])),
            Reason::BadArguments
        );
        assert_eq!(
            usage(parse([
                "rotation-canary",
                "check",
                "--env",
                "local",
                "--issuer",
                "http://localhost:1",
                "--no-matrix",
                "--homeserver",
                "http://localhost:2",
                "--server-name",
                "x",
                "--live-kid",
                K1,
                "--expect-kids",
                K1,
            ])),
            Reason::BadArguments
        );
    }

    #[test]
    fn kids_must_be_derived_form_and_expect_and_dropped_must_not_overlap() {
        let matrix = [
            "--homeserver",
            "https://m.example.org",
            "--server-name",
            "example.org",
        ];
        let with = |extra: &[&str]| {
            let mut v = matrix.to_vec();
            v.extend_from_slice(extra);
            check(&v)
        };
        assert_eq!(usage(with(&["--dropped-kids", "NOTAKID"])), Reason::BadKids);
        assert_eq!(usage(with(&["--dropped-kids", K1])), Reason::KidsOverlap);
        assert_eq!(
            usage(parse([
                "rotation-canary",
                "check",
                "--env",
                "dev",
                "--issuer",
                "https://s.example.org",
                "--homeserver",
                "https://m.example.org",
                "--server-name",
                "example.org",
                "--live-kid",
                "short",
                "--expect-kids",
                K1,
            ])),
            Reason::BadKids
        );
    }

    #[test]
    fn urls_are_https_origins_without_credentials_or_paths() {
        assert_eq!(
            origin_url("dev", "https://siwx.example.org/").unwrap(),
            "https://siwx.example.org"
        );
        assert_eq!(
            origin_url("dev", "https://siwx.example.org:443").unwrap(),
            "https://siwx.example.org"
        );
        assert_eq!(
            origin_url("dev", "https://siwx.example.org:8443").unwrap(),
            "https://siwx.example.org:8443"
        );
        assert_eq!(
            origin_url("dev", "http://siwx.example.org").unwrap_err(),
            Reason::BadUrl
        );
        assert_eq!(
            origin_url("local", "http://localhost:18080/").unwrap(),
            "http://localhost:18080"
        );
        for bad in [
            "https://user:pw@siwx.example.org",
            "https://siwx.example.org/path",
            "https://siwx.example.org/?q=1",
            "https://siwx.example.org/#f",
            "ftp://siwx.example.org",
            "siwx.example.org",
            "",
        ] {
            assert_eq!(origin_url("dev", bad).unwrap_err(), Reason::BadUrl, "{bad}");
        }
    }

    #[test]
    fn env_names_cannot_climb_out_of_the_secrets_directory() {
        for bad in [
            "",
            "..",
            "../x",
            "a/b",
            ".hidden",
            "UPPER",
            "a b",
            &"a".repeat(33),
        ] {
            let r = parse([
                "rotation-canary",
                "init",
                "--env",
                bad,
                "--issuer",
                "https://s.example.org",
                "--homeserver",
                "https://m.example.org",
                "--server-name",
                "example.org",
            ]);
            assert_eq!(usage(r), Reason::BadEnv, "{bad:?}");
        }
        for good in ["dev", "prod", "local", "dev-2", "nuc10_rehearsal"] {
            assert!(parse([
                "rotation-canary",
                "init",
                "--env",
                good,
                "--issuer",
                "https://s.example.org",
                "--homeserver",
                "https://m.example.org",
                "--server-name",
                "example.org",
            ])
            .is_ok());
        }
    }

    #[test]
    fn a_bad_command_line_prints_a_code_and_never_clap_s_message() {
        let r = parse([
            "rotation-canary",
            "check",
            "--secret-looking-flag=abcdefghijkl",
        ]);
        assert_eq!(usage(r), Reason::BadArguments);
        let r = parse(["rotation-canary", "nonsense"]);
        assert_eq!(usage(r), Reason::BadArguments);
        assert!(matches!(
            parse(["rotation-canary", "--help"]),
            Err(Early::Help(_))
        ));
    }

    #[test]
    fn init_replace_is_a_flag_and_defaults_off() {
        let Ok(Parsed::Init(i)) = parse([
            "rotation-canary",
            "init",
            "--env",
            "dev",
            "--issuer",
            "https://s.example.org",
            "--homeserver",
            "https://m.example.org",
            "--server-name",
            "example.org",
            "--replace",
        ]) else {
            panic!("should parse");
        };
        assert!(i.replace);
        assert_eq!(i.matrix.server_name, "example.org");
    }
}
