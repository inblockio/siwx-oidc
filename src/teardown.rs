//! The shared, idempotent erase sequence (S5, design D2): one function for account erasure
//! (`account::Action::AccountErase`) and for the guest reaper ([`crate::guest::teardown`]).
//!
//! Steps, in this order. Each one is safe to run again after a crash at any point, and an
//! error is returned to the caller, never swallowed: the caller decides (an account action
//! answers the user, the reaper backs off and retries the whole sequence).
//!
//! | # | [`Step`] | What | Why a re-run is safe |
//! |---|---|---|---|
//! | 1 | `Revoke` | user epoch, then every grant of the user, then the DID's own login sessions | the epoch is a timestamp, deletes of absent keys are no-ops |
//! | 2 | `Devices` | `delete_device` for each recorded device | a device that is gone is a no-op (a 404 is tolerated when `missing_account_ok`) |
//! | 3 | `Markers` | `erased:user/<localpart>` and `erased:did/<hash>` (no TTL) | `SET`, overwritten with a fresh timestamp |
//! | 4 | `Synapse` | `delete_user` with `erase: true` | Synapse deactivates an already deactivated user again; a 404 (no Synapse account was ever made) is tolerated when `missing_account_ok` |
//! | 5 | `Purge` | passkeys and links of the DID (`purge_identity`), when asked for | scan and delete |
//!
//! Markers come before Synapse on purpose: the erasure of a Synapse account that cannot be
//! recorded must not happen (`reactivation_gate` reads the markers).

use anyhow::anyhow;
use siwx_oidc::db::RedisClient;

use crate::synapse_client::SynapseClient;

#[cfg_attr(not(test), allow(dead_code))] // `Mark` and `Record` are the guest reaper's (S5b)
/// A step of the sequence; [`TeardownError`] names the one that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Guest only: the CAS to `reaping`.
    Mark,
    Revoke,
    Devices,
    Markers,
    Synapse,
    Purge,
    /// Guest only: dropping the record, the last step.
    Record,
}

impl Step {
    pub fn name(self) -> &'static str {
        match self {
            Step::Mark => "mark",
            Step::Revoke => "revoke",
            Step::Devices => "devices",
            Step::Markers => "markers",
            Step::Synapse => "synapse",
            Step::Purge => "purge",
            Step::Record => "record",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("teardown failed at step {}: {source:#}", step.name())]
pub struct TeardownError {
    pub step: Step,
    #[source]
    pub source: anyhow::Error,
}

fn at(step: Step) -> impl FnOnce(anyhow::Error) -> TeardownError {
    move |source| TeardownError { step, source }
}

/// What to erase.
pub struct Erasure<'a> {
    pub redis: &'a RedisClient,
    pub synapse: &'a SynapseClient,
    pub server_name: &'a str,
    pub localpart: &'a str,
    pub did: &'a str,
    /// Devices to delete one by one (a guest's `guest:devices/<lp>`); empty for an
    /// account, whose devices Synapse drops with the account.
    pub devices: &'a [String],
    /// Write the guest flavour of the DID tombstone (`mark_guest_erased`).
    pub guest: bool,
    /// Tolerate a 404 from Synapse (no account was ever provisioned): guests only.
    pub missing_account_ok: bool,
    /// Step 5, when set: purge the DID's passkeys with this derivation (accounts only).
    pub purge_with: Option<fn(&str) -> Option<String>>,
}

fn is_not_found(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("HTTP 404")
}

/// Run steps 1 to 5.
pub async fn erase_account(e: &Erasure<'_>) -> Result<(), TeardownError> {
    run(e, None).await
}

/// [`erase_account`], stopping after `until` as if the process died there. Tests only
/// reach for `Some`; production passes `None`.
pub(crate) async fn run(e: &Erasure<'_>, until: Option<Step>) -> Result<(), TeardownError> {
    let done = |s: Step| until == Some(s);

    // 1. The epoch first (a refresh racing the sweep is refused whichever runs first),
    // then every grant, then the DID's own login sessions.
    e.redis
        .set_user_epoch(e.localpart)
        .await
        .map_err(at(Step::Revoke))?;
    e.redis
        .revoke_all_user_tokens(e.localpart)
        .await
        .map_err(at(Step::Revoke))?;
    e.redis
        .revoke_own_sessions(e.did)
        .await
        .map_err(at(Step::Revoke))?;
    if done(Step::Revoke) {
        return Ok(());
    }

    // 2. The devices.
    for device in e.devices {
        if let Err(err) = e
            .synapse
            .delete_device(e.localpart, device, e.server_name)
            .await
        {
            if !(e.missing_account_ok && is_not_found(&err)) {
                return Err(at(Step::Devices)(err));
            }
        }
    }
    if done(Step::Devices) {
        return Ok(());
    }

    // 3. The tombstones, before Synapse is asked to erase.
    let marked = if e.guest {
        e.redis.mark_guest_erased(e.localpart, e.did).await
    } else {
        e.redis.mark_account_erased(e.localpart, e.did).await
    };
    marked.map_err(at(Step::Markers))?;
    if done(Step::Markers) {
        return Ok(());
    }

    // 4. Synapse: deactivate with erasure.
    if let Err(err) = e
        .synapse
        .deactivate_user(e.localpart, e.server_name, true)
        .await
    {
        if !(e.missing_account_ok && is_not_found(&err)) {
            return Err(at(Step::Synapse)(err));
        }
    }
    if done(Step::Synapse) {
        return Ok(());
    }

    // 5. Passkeys and links, so the DID cannot be re-derived from a leftover credential.
    if let Some(derive) = e.purge_with {
        e.redis
            .purge_identity(e.did, derive)
            .await
            .map_err(|err| at(Step::Purge)(anyhow!(err)))?;
    }
    Ok(())
}
