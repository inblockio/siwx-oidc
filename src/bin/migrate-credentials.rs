//! One-shot operator tool: back-fill siwx-oidc's passkey credentials into
//! aqua-auth's credential store.
//!
//! ```text
//! migrate-credentials [--apply] [--source-redis URL] [--target-redis URL]
//! ```
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
                             Default: $AQUA_WEBAUTHN_REDIS_URL, else the source"
}

fn parse_args() -> Result<Args> {
    let mut apply = false;
    let mut source: Option<String> = None;
    let mut target: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--apply" => apply = true,
            "--source-redis" => {
                source = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--source-redis needs a URL"))?,
                )
            }
            "--target-redis" => {
                target = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--target-redis needs a URL"))?,
                )
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument `{other}`\n\n{}", usage())),
        }
    }

    let source = source
        .or_else(|| std::env::var("REDIS_URL").ok())
        .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
    // Same instance by default: the two namespaces do not collide, and that is
    // what a single-Redis deployment looks like.
    let target = target
        .or_else(|| std::env::var("AQUA_WEBAUTHN_REDIS_URL").ok())
        .unwrap_or_else(|| source.clone());

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
    println!("  source: {}", args.source);
    println!("  target: {}", args.target);

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
