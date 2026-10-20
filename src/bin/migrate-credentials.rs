//! One-shot operator tool: back-fill siwx-oidc's passkey credentials into
//! aqua-auth's credential store.
//!
//! ```text
//! migrate-credentials [--apply] [--source-redis URL] [--target-redis URL]
//! ```
//!
//! An option takes its value as the next argument or as `--option=value`.
//!
//! **Dry run by default.** Without `--apply` it reads everything, resolves every
//! identity, and reports what it would write, touching nothing.
//!
//! The migration is additive: it only ever writes `aqua:webauthn:cred:*` and
//! `aqua:webauthn:did:*`, and never deletes, renames or mutates a
//! `webauthn:credential/*` or `webauthn:link/*` key. The old namespace stays
//! authoritative until siwx-oidc is flipped over to the new store, so rolling
//! back is a flag flip and nothing has been destroyed. Re-running is safe:
//! credentials already present in the target are skipped, not rewritten.
//!
//! Source and target default to the same instance, which is the normal
//! deployment: the two namespaces do not collide.

use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use aqua_auth::RedisWebauthnStore;
use url::Url;

use siwx_oidc::credential_migration::{derive_did_from_passkey_blob, CredentialMigration};
use siwx_oidc::db::RedisClient;

struct Args {
    apply: bool,
    source: String,
    target: String,
}

fn usage() -> &'static str {
    "usage: migrate-credentials [--apply] [--source-redis URL] [--target-redis URL]\n\
     \n\
     Copies siwx-oidc passkey credentials (webauthn:credential/*, resolved\n\
     through webauthn:link/*) into aqua-auth's credential store\n\
     (aqua:webauthn:cred:*). Additive and idempotent.\n\
     \n\
       --apply               actually write. Without it this is a dry run.\n\
       --source-redis URL    where siwx-oidc's credentials live.\n\
                             Default: $REDIS_URL, else redis://127.0.0.1:6379\n\
       --target-redis URL    where aqua-auth's store lives.\n\
                             Default: $AQUA_WEBAUTHN_REDIS_URL (with the password in the\n\
                             file $AQUA_WEBAUTHN_REDIS_PASSWORD_FILE names, if set), else\n\
                             the source\n\
     \n\
     A URL may carry the Redis password, so it is better given in the environment than\n\
     on the command line; no message of this tool shows one."
}

/// The error for an argument that is not an option of this tool. Only the name of an
/// option is shown (the part before `=`, and only when it looks like one): a value, or a
/// URL given without its option, may carry the Redis password.
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
        anyhow!(
            "unknown argument (its text is not shown, because it may hold a password)\n\n{}",
            usage()
        )
    }
}

fn parse_args() -> Result<Args> {
    parse_args_from(std::env::args().skip(1), |name| std::env::var(name).ok())
}

/// Parses `args` (without the program name); `env` reads the named environment variable.
fn parse_args_from(
    args: impl IntoIterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Args> {
    let mut apply = false;
    let mut source: Option<String> = None;
    let mut target: Option<String> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        // `--option=value`: the value is everything after the first `=`.
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = |option: &str| -> Result<String> {
            inline
                .clone()
                .or_else(|| it.next())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("{option} needs a URL"))
        };
        match name {
            "--apply" if inline.is_none() => apply = true,
            "--apply" => return Err(anyhow!("--apply takes no value")),
            "--source-redis" => source = Some(value("--source-redis")?),
            "--target-redis" => target = Some(value("--target-redis")?),
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => return Err(unknown_argument(&arg)),
        }
    }

    let source = source
        .or_else(|| env("REDIS_URL"))
        .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
    // Same instance by default: the two namespaces do not collide, and that is
    // what a single-Redis deployment looks like.
    let target = match target {
        Some(target) => target,
        None => match env(siwx_oidc::credential_store::ENABLE_ENV) {
            // The credential store's own variables, read the way the server reads them:
            // the password may be in a file, whose rules are `redis_password_file`'s.
            Some(url) => match env(siwx_oidc::credential_store::PASSWORD_FILE_ENV) {
                Some(file) if !file.trim().is_empty() => {
                    siwx_oidc::credential_store::resolve_url(Some(&url), Some(&file))
                        .map_err(|e| anyhow!(e))?
                        .unwrap_or(url)
                }
                _ => url,
            },
            None => source.clone(),
        },
    };

    Ok(Args {
        apply,
        source,
        target,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("migrate-credentials: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args = parse_args()?;

    let source_url = Url::parse(&args.source).context("parse --source-redis")?;
    let redis = RedisClient::new(&source_url)
        .await
        .context("connect to the source Redis")?;
    let store = RedisWebauthnStore::connect(&args.target)
        .await
        .map_err(|e| anyhow!("connect to the target Redis: {e}"))?;

    if args.apply {
        println!("migrate-credentials: APPLY (writing aqua:webauthn:*)");
    } else {
        println!("migrate-credentials: DRY RUN (nothing will be written; pass --apply to write)");
    }
    println!("{}", endpoint_line("source", &args.source));
    println!("{}", endpoint_line("target", &args.target));

    let migration =
        CredentialMigration::new(&redis, &store, &derive_did_from_passkey_blob, args.apply);
    let report = migration.run().await?;

    println!("{}", report.summary());
    for (key, reason) in &report.failures {
        println!("  FAILED {key}: {reason}");
    }

    // A per-row failure is not a crash, but it must not read as success either:
    // exit 1 so an operator's `&&` chain stops.
    Ok(if report.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// The line that names an endpoint: its URL without the user name and password it carries.
fn endpoint_line(role: &str, url: &str) -> String {
    format!("  {role}: {}", siwx_oidc::redact::redact_url(url))
}

#[cfg(test)]
mod tests {
    use super::endpoint_line;
    use siwx_oidc::test_support::{leaked_window, random_secret, redis_url_with_password};

    /// The URLs come from the command line or the environment and carry the Redis password.
    #[test]
    fn the_endpoints_it_prints_never_carry_the_password() {
        let password = random_secret(40);
        let url = redis_url_with_password(&password, "redis.example.org:6379/2");
        for role in ["source", "target"] {
            let line = endpoint_line(role, &url);
            assert_eq!(line, format!("  {role}: redis://redis.example.org:6379/2"));
            assert_eq!(leaked_window(&line, &password), None);
        }
    }

    use super::{parse_args_from, Args};

    fn parse(args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<Args> {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parse_args_from(args.iter().map(|a| a.to_string()), move |name| {
            env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
        })
    }

    /// O-F4: `--source-redis=URL` is parsed like `--source-redis URL`, and a value that
    /// holds `=` (a query) stays whole.
    #[test]
    fn an_option_takes_its_value_after_an_equals_sign_or_as_the_next_argument() {
        let args = parse(
            &[
                "--apply",
                "--source-redis=redis://a.example.org/1?x=y",
                "--target-redis",
                "redis://b.example.org/2",
            ],
            &[],
        )
        .unwrap();
        assert!(args.apply);
        assert_eq!(args.source, "redis://a.example.org/1?x=y");
        assert_eq!(args.target, "redis://b.example.org/2");
        let args = parse(&["--target-redis=redis://b.example.org"], &[]).unwrap();
        assert_eq!(args.target, "redis://b.example.org");
        assert_eq!(args.source, "redis://127.0.0.1:6379", "the default source");
    }

    /// O-F4: an unknown argument is named by its option name at most. The text after `=`,
    /// and an argument that is no option (a URL given alone), may hold the password.
    #[test]
    fn an_unknown_argument_never_echoes_a_value() {
        let password = random_secret(40);
        let url = redis_url_with_password(&password, "redis.example.org:6379/2");
        for arg in [
            format!("--source={url}"),
            format!("--sourc-redis={url}"),
            url.clone(),
            format!("-x={url}"),
            format!("--{url}"),
        ] {
            let error = parse(&[&arg], &[]).err().expect("unknown");
            let shown = format!("{error:#}");
            assert!(shown.contains("unknown argument"), "{shown}");
            assert_eq!(leaked_window(&shown, &password), None, "{shown}");
        }
        // The name is shown, so the operator sees what was not understood.
        let shown = format!("{:#}", parse(&["--source=x"], &[]).err().unwrap());
        assert!(shown.contains("`--source`"), "{shown}");
        // An option that needs a value, and one that takes none.
        for args in [&["--source-redis"][..], &["--target-redis="][..]] {
            let shown = format!("{:#}", parse(args, &[]).err().unwrap());
            assert!(shown.contains("needs a URL"), "{shown}");
        }
        assert!(parse(&["--apply=yes"], &[]).is_err());
    }

    /// The target defaults to the credential store's own variable, and its password may come
    /// from the file the store's other variable names, as the server reads it.
    #[test]
    fn the_default_target_reads_the_password_from_the_file_the_credential_store_names() {
        let password = random_secret(32);
        let path = std::env::temp_dir().join(format!("siwx-migrate-test-{}", random_secret(24)));
        std::fs::write(&path, format!("{password}\n")).unwrap();
        let path_text = path.to_str().unwrap();
        let args = parse(
            &[],
            &[
                ("AQUA_WEBAUTHN_REDIS_URL", "redis://store.example.org:6380"),
                ("AQUA_WEBAUTHN_REDIS_PASSWORD_FILE", path_text),
                ("REDIS_URL", "redis://source.example.org"),
            ],
        );
        std::fs::remove_file(&path).ok();
        let args = args.unwrap();
        assert_eq!(args.source, "redis://source.example.org");
        assert_eq!(
            args.target,
            redis_url_with_password(&password, "store.example.org:6380")
        );
        // Without the file the URL is used as given, and without either it is the source.
        let args = parse(
            &[],
            &[("AQUA_WEBAUTHN_REDIS_URL", "redis://store.example.org")],
        )
        .unwrap();
        assert_eq!(args.target, "redis://store.example.org");
        let args = parse(&[], &[("REDIS_URL", "redis://source.example.org")]).unwrap();
        assert_eq!(args.target, "redis://source.example.org");
        // A file the store would refuse is refused, naming the setting and not the content.
        let error = parse(
            &[],
            &[
                (
                    "AQUA_WEBAUTHN_REDIS_URL",
                    "redis+unix://localhost/run/redis.sock",
                ),
                ("AQUA_WEBAUTHN_REDIS_PASSWORD_FILE", "/nonexistent"),
            ],
        )
        .err()
        .expect("refused");
        assert!(format!("{error:#}").contains("unix-socket"));
    }

    /// Grok F1: the endpoints it prints, for a unix-socket URL whose password is in the
    /// query and for a TCP URL that carries it twice.
    #[test]
    fn the_endpoints_it_prints_never_carry_a_password_from_the_query() {
        let password = random_secret(40);
        for url in [
            format!("redis+unix:///run/redis.sock?db=2&pass={password}"),
            format!(
                "{}?pass={password}",
                redis_url_with_password(&password, "127.0.0.1:6379")
            ),
        ] {
            let line = endpoint_line("source", &url);
            assert_eq!(leaked_window(&line, &password), None, "{line}");
            assert!(line.starts_with("  source: redis"), "{line}");
        }
    }
}
