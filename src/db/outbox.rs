//! The back-channel logout outbox (OpenID Connect Back-Channel Logout 1.0;
//! design 5.6, D4).
//!
//! Every script that deletes a grant does so through `drop_grant`
//! ([`super::grant`]), and for an `oidc` grant that function also adds one
//! [`LogoutEntry`] to the sorted set [`KV_BACKCHANNEL_OUTBOX`], scored by the
//! instant it is due (Unix milliseconds, Redis `TIME`), in the same script as
//! the deletion: no deletion can happen without its entry, and no entry
//! without its deletion. A `matrix_device` or `service` grant queues nothing
//! (Synapse is not a relying party here). A grant whose key simply expires
//! runs no script and queues nothing: nothing observes it, and the RP's own
//! refresh token has expired with it.
//!
//! The entry carries claims data only (client, `sub`, `sid`, the grant id);
//! the logout token is signed by the worker at each attempt. A worker claims
//! due entries with [`RedisClient::claim_logout_entries`], which moves their
//! score one lease into the future in the same script, so two instances
//! never deliver one entry at once and an instance that dies mid-delivery
//! leaves the entry to be claimed again when the lease ends. After an attempt
//! the worker removes the entry ([`RedisClient::complete_logout_entry`]) or
//! re-queues it with its attempt count raised
//! ([`RedisClient::retry_logout_entry`]).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::RedisClient;

/// The outbox: a sorted set of JSON [`LogoutEntry`] members scored by the
/// Unix millisecond they are due.
pub const KV_BACKCHANNEL_OUTBOX: &str = "outbox:backchannel_logout";

/// One queued logout: which RP session ended. Not a credential: the `sid` and
/// the `sub` are in the RP's ID token, the grant id is a digest.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogoutEntry {
    pub client_id: String,
    /// The user's DID, the ID token's `sub`.
    pub sub: String,
    /// The grant's `sid`; empty for a grant issued before it existed.
    #[serde(default)]
    pub sid: String,
    /// The grant id (a digest); logged only as [`LogoutEntry::grant_fingerprint`].
    pub grant: String,
    /// Delivery attempts already made.
    #[serde(default)]
    pub attempt: u32,
}

impl LogoutEntry {
    /// The `sid`, `None` when the grant had none.
    pub fn sid(&self) -> Option<&str> {
        (!self.sid.is_empty()).then_some(self.sid.as_str())
    }

    /// What a log line may say about the grant: the prefix
    /// `GrantId::fingerprint` logs elsewhere.
    pub fn grant_fingerprint(&self) -> &str {
        &self.grant[..crate::redact::FINGERPRINT_HEX_LEN.min(self.grant.len())]
    }
}

/// An entry a worker holds: the member exactly as stored, and its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedEntry {
    pub member: String,
    pub entry: LogoutEntry,
}

/// Claim due entries. KEYS: 1 the outbox. ARGV: 1 lease (ms), 2 limit.
/// Returns the claimed members; each one's score is now + lease.
const CLAIM_LUA: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', string.format('%.0f', now),
  'LIMIT', 0, tonumber(ARGV[2]))
local until_ms = string.format('%.0f', now + tonumber(ARGV[1]))
for _, member in ipairs(due) do
  redis.call('ZADD', KEYS[1], 'XX', until_ms, member)
end
return due
"#;

/// Re-queue a claimed entry. KEYS: 1 the outbox. ARGV: 1 the claimed member,
/// 2 its successor (attempt + 1), 3 delay (ms). Returns 0 when the claimed
/// member is gone, else 1.
const RETRY_LUA: &str = r#"
if redis.call('ZREM', KEYS[1], ARGV[1]) == 0 then
  return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZADD', KEYS[1], string.format('%.0f', now + tonumber(ARGV[3])), ARGV[2])
return 1
"#;

impl RedisClient {
    /// Claim up to `limit` due entries for `lease_ms`: each one's score moves
    /// to now + `lease_ms` in one script, so no other worker claims it until
    /// then. A member that does not parse is removed with an error log naming
    /// its length only, so it cannot block the queue.
    pub async fn claim_logout_entries(
        &self,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedEntry>> {
        let members: Vec<String> = self
            .eval(
                CLAIM_LUA,
                &[KV_BACKCHANNEL_OUTBOX],
                &[&lease_ms.to_string(), &limit.to_string()],
            )
            .await?;
        let mut claimed = Vec::with_capacity(members.len());
        for member in members {
            match serde_json::from_str::<LogoutEntry>(&member) {
                Ok(entry) => claimed.push(ClaimedEntry { member, entry }),
                Err(e) => {
                    tracing::error!(
                        len = member.len(),
                        error = %e,
                        "back-channel logout outbox: unreadable entry removed"
                    );
                    self.zrem(&member).await?;
                }
            }
        }
        Ok(claimed)
    }

    /// Remove a delivered (or dropped) entry.
    pub async fn complete_logout_entry(&self, claimed: &ClaimedEntry) -> Result<()> {
        self.zrem(&claimed.member).await
    }

    /// Re-queue a claimed entry with its attempt count raised, due `delay_ms`
    /// from now. `false` when the entry was no longer there (another worker
    /// completed it after this one's lease ran out).
    pub async fn retry_logout_entry(&self, claimed: &ClaimedEntry, delay_ms: u64) -> Result<bool> {
        let next = LogoutEntry {
            attempt: claimed.entry.attempt + 1,
            ..claimed.entry.clone()
        };
        let successor = serde_json::to_string(&next)?;
        let moved: i64 = self
            .eval(
                RETRY_LUA,
                &[KV_BACKCHANNEL_OUTBOX],
                &[&claimed.member, &successor, &delay_ms.to_string()],
            )
            .await?;
        Ok(moved == 1)
    }

    /// Every queued entry with the Unix millisecond it is due, soonest first.
    pub async fn pending_logout_entries(&self) -> Result<Vec<(LogoutEntry, i64)>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let raw: Vec<(String, f64)> = bb8_redis::redis::cmd("ZRANGE")
            .arg(KV_BACKCHANNEL_OUTBOX)
            .arg(0)
            .arg(-1)
            .arg("WITHSCORES")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("outbox: {e}"))?;
        raw.into_iter()
            .map(|(member, due)| Ok((serde_json::from_str(&member)?, due as i64)))
            .collect()
    }

    async fn zrem(&self, member: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow!("Redis pool: {e}"))?;
        let _: i64 = bb8_redis::redis::cmd("ZREM")
            .arg(KV_BACKCHANNEL_OUTBOX)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow!("outbox: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Redis-backed. Tests that claim entries each use their own Redis
    //! database ([`crate::test_support::redis_db`]): a claim takes every due
    //! entry in the database, whoever queued it.

    use super::*;
    use crate::db::grant::{EpochScope, GrantKind, NewGrant, RotateOutcome, RotateRequest};
    use crate::db::{ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL};
    use bb8_redis::redis;

    async fn raw<T: redis::FromRedisValue>(client: &RedisClient, args: &[&str]) -> T {
        let mut conn = client.pool.get().await.expect("pool");
        let mut cmd = redis::cmd(args[0]);
        for a in &args[1..] {
            cmd.arg(*a);
        }
        cmd.query_async(&mut *conn).await.expect("redis command")
    }

    fn unique(tag: &str) -> String {
        format!("{tag}{}", crate::db::tokens::new_session_id())
    }

    fn grant(kind: GrantKind, user: &str, client_id: &str, device_id: &str) -> NewGrant {
        NewGrant {
            kind,
            username: user.to_string(),
            did: format!("did:key:z6Mk{user}"),
            client_id: client_id.to_string(),
            confidential_client: false,
            device_id: device_id.to_string(),
            scope: "openid offline_access".to_string(),
            name: "n".to_string(),
            auth_ms: None,
            access_ttl: ACCESS_TOKEN_TTL,
            refresh_inactivity_secs: Some(REFRESH_TOKEN_TTL),
        }
    }

    async fn entries_of(client: &RedisClient, client_id: &str) -> Vec<LogoutEntry> {
        client
            .pending_logout_entries()
            .await
            .expect("pending_logout_entries")
            .into_iter()
            .map(|(e, _)| e)
            .filter(|e| e.client_id == client_id)
            .collect()
    }

    /// Every active deletion of an `oidc` grant queues exactly one entry naming
    /// its client, `sub`, `sid` and grant; a `matrix_device` grant deleted the
    /// same ways queues none.
    #[tokio::test]
    async fn every_active_deletion_of_an_oidc_grant_queues_one_logout_entry() {
        let Some(client) = crate::test_support::redis().await else {
            return;
        };
        let rp = unique("bcl-rp-");
        let mut expected = Vec::new();
        let mut matrix_users = Vec::new();

        // 1 RFC 7009 revocation of the refresh token.
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        client
            .revoke_grant_of_token(g.refresh_token.as_deref().unwrap())
            .await
            .unwrap()
            .expect("the refresh token names its grant");
        expected.push((g.grant_id.as_str().to_string(), g.sid.clone(), user));

        // 2 RP-initiated logout.
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        let sid = g.sid.clone().expect("an oidc grant has a sid");
        client
            .end_grant_by_sid(&sid, &rp, &format!("did:key:z6Mk{user}"))
            .await
            .unwrap();
        expected.push((g.grant_id.as_str().to_string(), g.sid.clone(), user));

        // 3 logout/all, deactivation and erasure (every grant of the user).
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        client.revoke_grants_for_user(&user).await.unwrap();
        expected.push((g.grant_id.as_str().to_string(), g.sid.clone(), user));

        // 4 an epoch refusal that deletes the grant at its next rotation.
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        client.set_epoch(EpochScope::User(&user)).await.unwrap();
        let outcome = client
            .rotate_refresh_token(&RotateRequest {
                presented: g.refresh_token.as_deref().unwrap(),
                client_id: None,
                refuse_confidential: false,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, RotateOutcome::Invalid(_)), "{outcome:?}");
        expected.push((g.grant_id.as_str().to_string(), g.sid.clone(), user));

        // 5 an inactivity refusal that deletes the grant at its next rotation.
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        let key = format!("grant/{}", g.grant_id.as_str());
        let back = format!("-{}", REFRESH_TOKEN_TTL + 10);
        let _: i64 = raw(&client, &["HINCRBY", &key, "last_used", &back]).await;
        let outcome = client
            .rotate_refresh_token(&RotateRequest {
                presented: g.refresh_token.as_deref().unwrap(),
                client_id: None,
                refuse_confidential: false,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, RotateOutcome::Invalid(_)), "{outcome:?}");
        expected.push((g.grant_id.as_str().to_string(), g.sid.clone(), user));

        // A Matrix device grant deleted by device revocation, user revocation
        // and end-session queues nothing.
        for how in 0..3 {
            let user = unique("m");
            let g = client
                .issue_grant(&grant(GrantKind::MatrixDevice, &user, &rp, "DEV1"))
                .await
                .unwrap();
            match how {
                0 => {
                    client
                        .revoke_grants_for_device(&user, "DEV1")
                        .await
                        .unwrap();
                }
                1 => {
                    client.revoke_grants_for_user(&user).await.unwrap();
                }
                _ => {
                    let did = format!("did:key:z6Mk{user}");
                    client
                        .end_grant_by_sid(g.sid.as_deref().unwrap(), &rp, &did)
                        .await
                        .unwrap();
                }
            }
            matrix_users.push(format!("did:key:z6Mk{user}"));
        }

        let queued = entries_of(&client, &rp).await;
        assert_eq!(
            queued.len(),
            expected.len(),
            "one entry per oidc deletion and none for a Matrix grant: {queued:?}"
        );
        for (grant_id, sid, user) in expected {
            let e = queued
                .iter()
                .find(|e| e.grant == grant_id)
                .unwrap_or_else(|| panic!("no entry for grant {}: {queued:?}", &grant_id[..8]));
            assert_eq!(e.sub, format!("did:key:z6Mk{user}"));
            assert_eq!(e.sid(), sid.as_deref(), "the entry carries the grant's sid");
            assert!(sid.is_some(), "every oidc grant has a sid");
            assert_eq!(e.attempt, 0);
        }
        assert!(queued.iter().all(|e| !matrix_users.contains(&e.sub)));
    }

    /// A claim leases an entry: a second claim within the lease gets nothing; a
    /// retry re-queues it with the attempt count raised and a later due time;
    /// completing it removes it; a lease that runs out makes it claimable again.
    #[tokio::test]
    async fn the_outbox_leases_retries_and_completes_an_entry() {
        let Some(client) = crate::test_support::redis_db(9).await else {
            return;
        };
        let _: i64 = raw(&client, &["DEL", KV_BACKCHANNEL_OUTBOX]).await;
        let rp = unique("bcl-lease-");
        let user = unique("u");
        let g = client
            .issue_grant(&grant(GrantKind::Oidc, &user, &rp, ""))
            .await
            .unwrap();
        client.revoke_grants_for_user(&user).await.unwrap();

        let claimed = client.claim_logout_entries(60_000, 10).await.unwrap();
        assert_eq!(claimed.len(), 1, "the one due entry is claimed");
        assert_eq!(claimed[0].entry.grant, g.grant_id.as_str());
        assert!(
            client
                .claim_logout_entries(60_000, 10)
                .await
                .unwrap()
                .is_empty(),
            "a leased entry is not claimed twice"
        );

        assert!(client.retry_logout_entry(&claimed[0], 0).await.unwrap());
        let again = client.claim_logout_entries(60_000, 10).await.unwrap();
        assert_eq!(again.len(), 1, "a retry due now is claimable");
        assert_eq!(again[0].entry.attempt, 1, "a retry counts the attempt");
        assert!(
            !client.retry_logout_entry(&claimed[0], 0).await.unwrap(),
            "the superseded member is gone"
        );

        assert!(client.retry_logout_entry(&again[0], 60_000).await.unwrap());
        let (pending, due) = client.pending_logout_entries().await.unwrap()[0].clone();
        assert_eq!(pending.attempt, 2);
        let now_ms = client.redis_time_ms().await.unwrap();
        assert!(due > now_ms + 50_000, "the retry is due after its delay");
        assert!(client
            .claim_logout_entries(60_000, 10)
            .await
            .unwrap()
            .is_empty());

        let _: i64 = raw(
            &client,
            &[
                "ZADD",
                KV_BACKCHANNEL_OUTBOX,
                "XX",
                "0",
                &serde_json::to_string(&pending).unwrap(),
            ],
        )
        .await;
        let expired_lease = client.claim_logout_entries(1, 10).await.unwrap();
        assert_eq!(
            expired_lease.len(),
            1,
            "an entry whose lease ran out is claimable"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reclaimed = client.claim_logout_entries(60_000, 10).await.unwrap();
        assert_eq!(reclaimed.len(), 1, "a 1 ms lease runs out");
        client.complete_logout_entry(&reclaimed[0]).await.unwrap();
        assert!(client.pending_logout_entries().await.unwrap().is_empty());
    }
}
