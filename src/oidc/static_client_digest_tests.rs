//! A static client configured only by `secret_digest`, so that no raw secret sits in the
//! configuration: it is accepted at start-up, written to Redis as it is, and the token
//! endpoint's client authentication (the function the code exchange and the refresh grant
//! both call) takes the raw secret and refuses every other. Needs Redis.

use super::*;
use crate::config::Config;
use siwx_oidc::client_policy::{parse_static_clients, Deployment};
use siwx_oidc::db::tokens::digest;
use siwx_oidc::test_support::random_secret;
use std::collections::HashMap;

fn refusal(outcome: Result<(), CustomError>) -> String {
    match outcome {
        Ok(()) => "accepted".to_string(),
        Err(CustomError::Unauthorized(message)) => message,
        Err(other) => format!("{other:?}"),
    }
}

#[tokio::test]
async fn a_static_client_configured_only_by_digest_authenticates_with_the_raw_secret() {
    let Some(db) = siwx_oidc::test_support::redis().await else {
        return;
    };
    let raw = random_secret(40);
    let id = format!("digest-only-{}", Uuid::new_v4().simple());
    let stored_digest = digest(&raw);
    let entry = format!(
        r#"{{"secret_digest":"{stored_digest}","metadata":{{"redirect_uris":["https://app.example.org/cb"]}}}}"#
    );
    // The start-up path: parse and validate the configured map, then write it.
    let clients = parse_static_clients(
        &HashMap::from([(id.clone(), entry)]),
        Deployment {
            mail_domain: None,
            delegated_auth: false,
            synapse_configured: false,
        },
    )
    .unwrap_or_else(|e| panic!("start-up refuses the entry: {e}"));
    db.sync_static_clients(clients).await.unwrap();

    // `require_secret` is on by default and the entry names no auth method: confidential.
    let config = Config::default();
    assert!(config.require_secret);
    let wrong = random_secret(40);
    for (what, presented, expected) in [
        ("the raw secret", Some(raw.as_str()), "accepted"),
        ("a wrong secret", Some(wrong.as_str()), "Bad secret."),
        (
            "the digest of the secret",
            Some(stored_digest.as_str()),
            "Bad secret.",
        ),
        (
            "the secret and a newline",
            Some(&*format!("{raw}\n")),
            "Bad secret.",
        ),
        ("no secret", None, "Secret required."),
    ] {
        let code = authenticate_code_client(&id, None, presented, &config, &db)
            .await
            .map(|_| ());
        assert_eq!(refusal(code), expected, "code exchange, {what}");
        let refresh = authenticate_refresh_client(&id, None, presented, &config, &db).await;
        assert_eq!(refusal(refresh), expected, "refresh grant, {what}");
    }

    // Redis holds the digest and never the raw secret.
    let stored = db.get_raw(&format!("clients/{id}")).await.unwrap().unwrap();
    assert!(
        stored.contains(&stored_digest) && !stored.contains(&raw),
        "{stored}"
    );

    // Dropping it from the map deletes it (this client's own static set): clean up.
    db.sync_static_clients(Vec::new()).await.unwrap();
}
