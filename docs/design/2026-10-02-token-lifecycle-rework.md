# Token lifecycle rework: security-first plan

**Date:** 2026-10-02
**Code reviewed:** `3547bd2`
**Status:** proposed; every decision is open for the maintainers
**Tracking issue:** [#30](https://github.com/inblockio/siwx-oidc/issues/30)
**Evidence base:** [2026-10-02-token-handling-prior-art.md](2026-10-02-token-handling-prior-art.md)

## 1. Goal

One credential model that serves the Matrix deployment (MSC3861 delegation, Synapse
introspection) and every other OIDC relying party (RP) that connects to siwx-oidc, such that:

- a stolen credential is bounded in time;
- its use alongside the legitimate holder is detected and, once enforced, ends the grant;
- nothing in the store or the logs is a usable credential;
- revocation reaches every relying party within a stated bound.

The design is ordered security first: each phase removes a risk on its own and ships on its own,
and no phase depends on a later one to be safe.

## 2. Current state (at `3547bd2`)

| Area | Matrix mode (`mas_shared_secret` set) | Generic OIDC mode |
|---|---|---|
| Access token | opaque `mat_`, 300 s | opaque, no prefix, 300 s |
| Refresh token | opaque `mcr_`, sliding 90 d, rotated, 60 s grace pointer | same, always issued with the code grant (no `offline_access`) |
| Storage | raw token as Redis key `token/{raw}`; grace pointer holds the raw successor pair | same |
| State and revocation unit | per token, plus a per-device index and device/user tombstones | per token only; revoking an access token leaves its refresh token alive and the reverse |
| Revocation reaching the RP | Synapse introspects (cached up to two minutes) | nothing: no `sid`, no back-channel or RP-initiated logout |
| Client binding on refresh | none | none |
| Lifetime bound | 90-day inactivity only | same |

The individual gaps are listed in issue #30 and in section 2 of the prior-art record.

## 3. Threat model

| Id | Adversary | Example | Bounded by |
|---|---|---|---|
| A1 | Holder of a copy of a client's token store | copied browser profile, infostealer, device backup | I6 lifetime, I5 reuse detection, I8 propagation |
| A2 | Reader of the Redis store | dump, backup, monitoring export, operator mistake | I1 |
| A3 | Reader of logs | debug logging left on, log shipping | I1 |
| A4 | Attacker on the authorization front channel | code interception, redirect manipulation | PKCE (S256), I7 |
| A5 | Malicious or compromised RP, registered through open dynamic client registration | uses a token issued to another client | I7, I10 |

Out of scope: code execution on the server, theft of the ID-token signing key, breaking TLS.
Prevention of A1 needs keys held in hardware; section 9 records why that is deferred.

## 4. Security invariants

Each invariant is pinned by tests that fail against `3547bd2` before the change lands.

| Id | Invariant |
|---|---|
| I1 | **No credential at rest or in logs.** Every key and stored value that could authenticate a request is a SHA-256 digest, or is encrypted under a key that only the presenter of a credential can derive. Logs carry fingerprints (a short digest prefix), never a token, code or cookie value. |
| I2 | **The grant is the unit.** Every access and refresh token belongs to exactly one grant. Lifetime, revocation and reuse act on grants. |
| I3 | **One live refresh chain per grant**, enforced by one atomic Redis script; concurrent refreshes cannot fork it. |
| I4 | **Lost responses recover without forking.** A replay of the immediately previous refresh token returns the same successor pair if, and only if, the successor is unused. |
| I5 | **Reuse is always recognised.** Any superseded refresh token of a live grant is detected, with no time limit. Response: phase A records a security event; phase B revokes the grant. |
| I6 | **Lifetime is bounded.** A grant ends at the earlier of its inactivity expiry and its absolute expiry, measured from the original authentication. Rotation never extends the absolute expiry; it can only move earlier. All deadline arithmetic uses Redis `TIME`, never an instance clock. |
| I7 | **Refresh tokens are bound to their client.** Only the client a grant was issued to can refresh it; confidential clients authenticate. |
| I8 | **Revocation reaches every RP within a stated bound.** Matrix: introspection answers inactive at once (Synapse's cache adds at most two minutes). Generic RPs: back-channel logout on grant revocation, and access tokens of at most 300 s. |
| I9 | **Mass revocation needs no enumeration.** A not-before epoch per scope (global, client, user) refuses every grant authenticated before it, set with a single write. |
| I10 | **Generic RPs get least privilege.** Refresh tokens only when requested (`offline_access`) and allowed for the client; the issued scope reflects what was requested and granted; discovery advertises only what is implemented. |

## 5. Target design

### 5.1 The grant record

One Redis hash per grant, keyed by the digest of a random grant handle:

| Field | Purpose |
|---|---|
| `kind` | `matrix_device`, `oidc`, `guest` (section 8) |
| `username`, `did`, `client_id` | owner and client (revocation keys on `username`, as today) |
| `device_id` | Matrix device for `matrix_device` grants; empty otherwise (still JSON `null` on the wire) |
| `sid` | OIDC session id for `oidc` grants, also emitted in the ID token |
| `auth_time` | original authentication, the base of the absolute expiry |
| `absolute_exp`, `inactivity_secs`, `last_used` | I6 |
| `generation` | increments on every rotation |
| `current_rt`, `previous_rt` | digests of the live refresh token and its immediate predecessor |
| `successor_used` | false from rotation until the new pair is first used (5.4) |
| `successor_sealed` | the current pair encrypted under a key derived from `previous_rt`'s plaintext (HKDF, then AES-GCM), so only a presenter of the previous token can read it |

Access tokens are stored as `at/{sha256(token)}` with the grant handle digest, the generation
and the expiry. Deleting a grant makes all its tokens inert at once: the access-token check
reads the grant.

### 5.2 Token formats

- Access token: prefix plus 32 base62 characters (about 190 bits, as today).
- Refresh token: prefix, grant handle (128 random bits), separator, secret (about 190 bits).
  The handle lets the server find the grant for any token of the chain, current or superseded
  (RFC 9700 §4.14.2 implementation note). It is never derived from the Matrix device id, which
  other users can see.
- The same format in both modes. Distinct prefixes per kind keep leaked tokens recognisable to
  secret scanners.

### 5.3 The rotation script

One Lua script replaces the two hand-written refresh paths (`oidc::token_refresh` and
`compat::refresh`). The caller parses the handle, mints a candidate pair, and calls the script
with the digests and the sealed candidate. Inside the script, with `now` from Redis `TIME`:

| Grant state | Presented token | Result |
|---|---|---|
| missing, or refused by an epoch (I9), or past `absolute_exp` or inactivity expiry | any | `invalid_grant`; an expired grant is deleted |
| live, client mismatch | any | `invalid_client` (I7) |
| live | digest equals `current_rt` | rotate: `previous_rt` takes the old value, `current_rt` the candidate, `generation` + 1, `successor_used` false, store the sealed candidate, update `last_used`; return the candidate |
| live | digest equals `previous_rt` and `successor_used` false | lost response or concurrent loser: discard the candidate, return `successor_sealed` for the caller to open (I4) |
| live | anything else carrying this handle | reuse (I5): record the event; in phase B delete the grant and its access tokens |

Because the whole decision is one script, the current check-mint-recheck sequence, the
tombstone fail-open reasoning and the grace pointer all disappear: no interleaving can mint
tokens for a grant that is being revoked, and two concurrent refreshes converge on one chain.

### 5.4 When a successor counts as used

`successor_used` becomes true the first time the new access token is accepted by introspection
or `/userinfo`, or when the new refresh token is itself rotated. Synapse caches introspection,
but its first call for a new token always reaches siwx-oidc, which is all the flag needs. This
replaces the 60-second timer: a client that lost a response recovers however late it retries,
and a replay after the new pair has been used is reuse. Matrix Authentication Service uses the
same rule (prior-art record, section 3).

### 5.5 Lifetime

- Inactivity: 90 days, as today.
- Absolute: per-client setting with a global default (decision D1). The guest deadline is a
  grant's absolute expiry.
- Agents that hold their own signing key (`siwx-oidc-auth`) can re-authenticate without a user,
  so a short absolute expiry costs them nothing.

### 5.6 Revocation and its propagation

| Trigger | Effect |
|---|---|
| `POST /oauth2/revoke` with a refresh token | deletes its grant (RFC 7009 §2.1: revoking a refresh token should revoke the grant's access tokens) |
| `POST /oauth2/revoke` with an access token | deletes that access token only |
| Matrix `logout`, MSC4191 device deletion | deletes the device's grant, then the Synapse device (teardown policy unchanged: revoke never deletes a device) |
| Matrix `logout/all`, deactivate, erase | sets the user epoch (I9), which also replaces the user tombstone |
| Reuse in phase B | deletes the grant, not the Synapse device (as with revoke) |
| Any grant deletion for an `oidc` grant | back-channel logout token (OIDC Back-Channel Logout 1.0, with `sid` and `sub`) to the client's registered `backchannel_logout_uri` |
| RP-initiated logout (`end_session_endpoint`) | deletes the grant named by `id_token_hint` and `sid` |

Epochs replace the tombstones' time-to-live reasoning: an epoch is a persistent not-before
timestamp, so a new sign-in after `logout/all` is unaffected, while every older grant is refused.

### 5.7 siwx-oidc's own sessions

The `siwx_user` and `acct_session` cookies get the same treatment: digest-keyed storage,
revocation on `logout/all`, deactivation and erasure, and an explicit sign-out on the account
page.

### 5.8 Migration

- Access tokens: legacy raw-keyed tokens expire within 300 s; the new code reads both layouts
  for that window only.
- Refresh tokens: a legacy token presented at the token endpoint is lifted into a new grant and
  answered with new-format tokens. No user signs in again. Legacy keys that are never presented
  expire on their own within 90 days, or can be swept once by count without printing key names.
- The AGENTS.md invariant "Refresh rotation keeps a 60 s grace pointer" is replaced by I4, with
  new pins (section 7) replacing `refresh_grace_window_tolerates_replay`.

## 6. Phases

| Phase | Content | Invariants | Depends on |
|---|---|---|---|
| 0 | Security fixes handled privately under [SECURITY.md](../../SECURITY.md). Scope published with the fix | (published with the fix) | nothing; lands first |
| 1 | Small independent fixes: fingerprints instead of raw values in logs (AGENTS.md already forbids logging tokens); client binding on refresh; correct `subject_types_supported` in discovery; refresh tokens in generic mode only with `offline_access` | I1 (logs), I7, I10 | 0 |
| 2 | Grant record, token formats, rotation script, digest-keyed storage, state-based lost-response handling, reuse detection in log-only mode, migration, AGENTS.md invariant replaced | I1, I2, I3, I4, I5 (phase A) | 1 |
| 3 | Absolute expiry and epochs; guest deadlines expressed as grant expiry | I6, I9 | 2 |
| 4 | Generic RP propagation: `sid` claim, back-channel logout, RP-initiated logout, grant-level RFC 7009 semantics; siwx-oidc's own sessions | I8, 5.7 | 2 |
| 5 | Reuse enforcement: revoke the grant | I5 (phase B) | 2, plus the exit criteria in D2 |

Every phase updates `docs/matrix-integration.md` (token model) and `docs/architecture.md`
(Redis keyspace) in the same change.

## 7. Hypotheses and how each is tested

| Id | If | Then | Test |
|---|---|---|---|
| H1 | rotation is one script | N parallel refreshes of one token leave exactly one live chain | mock stack, N = 50 concurrent requests, both endpoints |
| H2 | the lost-response window is state-based | a replay of the previous token returns the same pair at any delay while the successor is unused, and is reuse after first use | mock stack, replay at 1 s, 2 min and 1 h, before and after introspecting the new access token |
| H3 | grants carry handles | every superseded token of a live grant is recognised, with storage that does not grow with the number of rotations | unit test over 1,000 rotations; key count per grant stays constant |
| H4 | storage is digest-keyed | after a full sign-in, refresh, introspect and revoke cycle, no Redis key or value contains a string handed to a client | mock stack keyspace scan inside the test |
| H5 | the absolute expiry is fixed at authentication | no sequence of refreshes yields a token valid past `auth_time` + cap | property test with a controlled Redis `TIME` |
| H6 | single holders never trip reuse | phase A records zero reuse events for sessions with a single holder | production telemetry: every event is checked for evidence of a second holder before phase 5 |
| H7 | back-channel logout is sent on grant deletion | a registered RP receives a valid logout token within the delivery bound | integration test with a stub RP |

Assumptions to verify before phase 2 relies on them:

- Synapse's first introspection of a new access token reaches siwx-oidc (cache keyed by token).
- Synapse does not recreate a deleted device when it introspects a token that still names it.
- The Element X iOS notification extension uses the same cross-process refresh lock as the app.

## 8. Grant kinds

| Kind | Created by | Revocation | Notes |
|---|---|---|---|
| `matrix_device` | code or device-code grant in Matrix mode | device sign-out, `logout/all`, account actions, reuse | one grant per Synapse device; `device_id` unchanged on the wire |
| `oidc` | code grant for any other RP | RFC 7009, RP-initiated logout, epochs, reuse | `sid` in the ID token; back-channel logout |
| `guest` | the guest flow (guest portal design, separate branch) | deadline, host or guest end, kill switch, claim | the deadline is `absolute_exp`; a claim deletes the pre-claim grants; the guest kill-switch epoch is an I9 epoch; the guest design already requires Redis `TIME` for deadlines |

## 9. Deferred, with reasons

- **DPoP for browser clients:** a non-exportable WebCrypto key is still on disk, so it does not
  stop a profile copy (browser-based apps BCP §8.6).
- **DPoP for native clients:** useful when the key lives in a hardware keystore; needs client
  support in matrix-rust-sdk first.
- **DBSC for siwx-oidc's own cookies:** binds cookies to a TPM-held key; available in Chrome on
  Windows only so far. Revisit after phase 4.
- **Pairwise subjects:** `sub` is the user's DID by design (`docs/identity-model.md`), so
  subjects stay public; phase 1 corrects discovery to say so.

## 10. Decisions for the maintainers

| Id | Decision | Recommendation |
|---|---|---|
| D1 | Absolute expiry default, and per-client overrides | Set per client. In Matrix, a forced re-login usually means a new device, with re-verification and key-backup restore, unless the client re-authorises with its existing device scope; weigh that cost before choosing a short value for Element clients |
| D2 | Exit criteria for phase 5 | At least 30 days of phase A telemetry from Element Web and Element X with every reuse event explained, and no unexplained single-holder event |
| D3 | Whether dynamic client registration stays open for generic RPs | Keep it open for Matrix clients; require an initial access token for clients that ask for `offline_access` or a back-channel logout URI |
| D4 | Back-channel logout required or optional for generic RPs | Required for RPs that receive refresh tokens |

## 11. Acceptance criteria

- [ ] Every invariant I1 to I10 has at least one pinned test that fails against `3547bd2`.
- [ ] H1 to H5 and H7 pass in CI; H6 has a telemetry query and a recorded result before phase 5.
- [ ] No user signs in again because of the migration.
- [ ] AGENTS.md invariants and the token-model guide describe the new behaviour.
- [ ] Issue #30 closes when phases 1 to 4 have landed; phase 5 is tracked separately.
