//! Guest audit events and alerts (S6, GP-SEC-46/47).
//!
//! Every event is a `tracing` event with `target: "guest_audit"` and an `event` field; an
//! alert is the same target at level `error` with an `alert` field. Nothing here takes a
//! name, an e-mail, a secret or a token: the fields are counts, reason classes, routes and
//! the opaque host and guest identifiers. Events:
//!
//! | `event` | Emitted by | Fields |
//! |---|---|---|
//! | `guest_invite_created` | `POST /guest/invites` | `count` |
//! | `guest_minted` | redeem | |
//! | `guest_signin` | the hand-off, once a code is issued | |
//! | `guest_refused` | a refused guest request: the host checks (`invites`), `peek` and `redeem` (`disabled`, `invalid_link`, the redeem classes), `authorize`, `refresh`, `continue` (the error code), `claim_start` and `claim_finish` (the error code) | `route`, `reason` |
//! | `guest_reap` | the reaper, per teardown | `reason`, `outcome`, `attempts` |
//! | `guest_control_changed` | the reaper, when `guest:control` or `guest:banned_hosts` differ from the last tick | `disabled`, `reap_before`, `banned_hosts` |
//! | `guest_orphan` | the orphan scan | `localpart` |
//!
//! | `guest_claimed` | `POST /guest/claim/finish`, at the commit | `localpart`, `invite_id`, `credential` (fingerprint) |
//!
//! Alerts: `reaping_stuck`,
//! `live_guests_high`, `daily_mints_high`, `refusal_burst`.

use siwx_oidc::db::RedisClient;
use tracing::{debug, info};

pub fn invite_created(count: usize) {
    info!(target: "guest_audit", event = "guest_invite_created", count);
}

pub fn minted() {
    info!(target: "guest_audit", event = "guest_minted");
}

pub fn signin() {
    info!(target: "guest_audit", event = "guest_signin");
}

/// A refused guest request: logged, and counted in the instance-wide per-minute counter
/// the refusal-burst alert reads. A counter fault never changes the answer.
pub async fn refused(redis: &RedisClient, route: &'static str, reason: &str) {
    info!(target: "guest_audit", event = "guest_refused", route, reason);
    if let Err(e) = redis.count_guest_refusal().await {
        debug!(error = %e, "guest audit: refusal counter unavailable");
    }
}

/// The claim committed (GP-CLM-21): who (opaque localpart), which invite, a credential
/// fingerprint. No name, no e-mail.
pub fn claimed(localpart: &str, invite_id: &str, credential: &str) {
    info!(target: "guest_audit", event = "guest_claimed", localpart, invite_id, credential);
}

pub fn reap(reason: &'static str, outcome: &'static str, attempts: u64) {
    info!(target: "guest_audit", event = "guest_reap", reason, outcome, attempts);
}

pub fn control_changed(disabled: &str, reap_before: &str, banned_hosts: &str) {
    info!(target: "guest_audit", event = "guest_control_changed", disabled, reap_before, banned_hosts);
}
