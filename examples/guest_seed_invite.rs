//! Seed one guest invite straight into Redis and print it as JSON, for the browser
//! E2E (`e2e/browser/guest-join.spec.mjs`): it needs a link, not the host API's
//! token plumbing. Usage: `guest_seed_invite <redis-url> [single|open] [max_guests]`.
//! Not part of the service; it writes through the same `create_guest_invites` the
//! host API uses, so the stored invite is the real shape.

use siwx_oidc::db::guest_invites::{NewBatch, NewInvite, QuotaLimits};
use siwx_oidc::db::RedisClient;
use siwx_oidc::guest_invite::{new_invite_id, new_secret, secret_hash, Kind};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .expect("usage: guest_seed_invite <redis-url> [single|open] [max]");
    let kind = match args.next().as_deref() {
        None | Some("single") => Kind::Single,
        Some("open") => Kind::Open,
        Some(other) => panic!("kind must be single or open, not {other}"),
    };
    let max: u64 = args.next().map_or(1, |m| m.parse().expect("max_guests"));
    let redis = RedisClient::new(&url.parse().expect("redis url"))
        .await
        .expect("redis client");
    let (id, secret) = (new_invite_id(), new_secret());
    let list = [NewInvite {
        id: id.clone(),
        secret_hash: secret_hash(&secret),
        label: "e2e".into(),
    }];
    let host = format!("e2ehost{}", id[..6].to_lowercase());
    redis
        .create_guest_invites(
            &NewBatch {
                host: &host,
                host_did: "did:key:zHost",
                room_id: "!room:example.org",
                kind,
                max_guests: max,
                expires_in: 3600,
                session_secs: 7200,
                recording_expected: true,
                invites: &list,
            },
            &QuotaLimits {
                max_invites: 1000,
                max_open_invites: 1000,
                per_hour: 1_000_000,
                session_max_secs: 7200,
            },
        )
        .await
        .expect("create invite");
    println!(
        "{}",
        serde_json::json!({ "invite_id": id, "secret": secret, "host": host })
    );
}
