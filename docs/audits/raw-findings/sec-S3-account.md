# Security Audit S3 — Account-Management Authorization, Device Lifecycle & Race Conditions

Target: `/home/waldknoten-01/siwx-oidc` (siwx-oidc). Dimension: account-management
authorization (not just authN), device lifecycle, and **race conditions** (the
audit's primary concern). READ-ONLY review; no files modified.

## Summary

The account-management surface is, on the **authorization** axis, largely sound:
every account action is bound to a freshly *verified DID* (wallet CAIP-122 or
passkey assertion), and Synapse device reads/deletes are mxid-scoped, so the
classic cross-user IDOR ("act on user Y's device with user X's session") does not
hold — a foreign `device_id` resolves to "not among your sessions" because
`get_device` lists only the authenticated user's devices. CSRF is required and
checked on `/account/action`, the cookie is `HttpOnly; SameSite=Strict;
Path=/account`, and terminal actions (erase/deactivate) correctly destroy the
server-side session and clear the cookie.

The **race-condition** axis is where this code is materially weak, and it matters
here precisely because the project's own history (the 2026-06-12 login incident)
shows that device-deletion races wedge users' cross-signing identity. Three
confirmed concurrency defects stand out: (1) the MSC4191 `device_delete` is a
**check-then-act TOCTOU** (`get_device` ownership check, then `delete_device`,
then a *separate* token-revoke that scans the keyspace non-atomically); (2) the
RFC 8628 **device-code `Approved` branch can be redeemed by two concurrent polls**
because the code is only deleted *after* token issuance (no atomic claim — in
stark contrast to `try_consume_code`/`try_mark_session_signed_in`, which DO use
SETNX); and (3) the **device-approval write is itself a non-atomic
read-check-write**, enabling the H9 double-approval split-brain where a
wallet-approve and a passkey-approve race and the last writer wins the DID that
gets baked into tokens. Layered on top, all bulk token operations
(`revoke_device_tokens`, `revoke_all_user_tokens`, `purge_identity`) are
`KEYS`+`GET`+`DEL` scans with no atomicity, so a token refresh or passkey login
concurrent with erase/deactivate can resurrect access or re-create an artifact
the purge already removed.

Net: no confirmed cross-user privilege escalation, but several confirmed
atomicity gaps that produce duplicate sessions, orphaned tokens/identity
artifacts, and (under the documented Synapse signature-upload pathology) the
exact cross-signing corruption class this codebase was refactored to avoid.

## Severity counts

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 0 | — |
| HIGH     | 4 | S3-1, S3-2, S3-3, S3-4 |
| MEDIUM   | 5 | S3-5, S3-6, S3-7, S3-8, S3-9 |
| LOW      | 4 | S3-10, S3-11, S3-12, S3-13 |
| INFO     | 3 | S3-14, S3-15, S3-16 |

---

## HIGH

### S3-1 — Device-code `Approved` branch is double-redeemable (concurrent polls each mint a token pair + a device) — CONFIRMED
**File:** `src/oidc.rs:608-720` (`token_device_code`, `DeviceCodeStatus::Approved`); cleanup at `src/oidc.rs:701-702`.

**Why it's a race, not just style:** the auth-code grant uses an atomic SETNX
claim (`db_client.try_consume_code`, `src/db/redis.rs:367-409`, used at
`oidc.rs:738`). The device-code grant does **not**. The Approved branch:
1. `get_device_code(&dc)` — read (line 565).
2. matches `status == Approved` (line 608).
3. provisions the Synapse device, builds claims, issues access+refresh tokens
   (`set_token`, lines 663-680).
4. only **then** `delete_device_code` + `delete_user_code_mapping` (lines 701-702).

There is no compare-and-set between steps 2 and 4.

**Attacker / timing scenario:** the polling client (or any party who learns the
`device_code` + `client_id` — the device_code is a bearer secret, but Element X
clients poll aggressively and a proxy/log could expose it) fires two `POST /token`
device-code requests within the same `DEVICE_CODE_INTERVAL` window after approval.
Note the interval rate-limit (lines 578-589) keys on `entry.last_poll` and is
itself read-modify-write, so two requests interleaved before either writes
`last_poll` both pass. Both reach the Approved branch, both pass `status ==
Approved`, both call `provision_synapse_device` and both issue a **distinct**
`mat_`/`mcr_` token pair for the same DID.

**Impact:** two live, independent OAuth sessions (two access+refresh pairs) from a
single user approval — the second pair is never surfaced to the user and survives
the user "logging out" of the first. With a client-proposed device_id in scope
both pairs share one device_id (one device, two token families → revoking one
device's tokens via `revoke_device_tokens` actually kills both, but a *refresh*
re-forks them); with the generated-`SIWX_{uuid}` path the two requests mint
**different** device ids (line 626, fresh UUID each), creating a phantom second
device the user cannot see in a single approval. This is a session-fixation /
duplicate-session defect and an unaudited token surface.

**Fix:** claim the approval atomically before issuing. Add a
`try_claim_device_code(dc) -> bool` on `DBClient` implemented with `SET
device_codes/{dc}/redeemed 1 NX EX <ttl>` (mirroring `try_consume_code`), and in
the Approved branch return `expired_token`/`invalid_grant` if the claim is lost.
Alternatively `GETDEL` the entry, or transition status to a terminal `Redeemed`
via a Lua CAS, before any `set_token`.

---

### S3-2 — Device approval write is a non-atomic read-check-write → H9 double-approval split-brain — CONFIRMED
**File:** `src/device_auth.rs:835-917` (`device_approve`) and `src/device_auth.rs:921-950` (`device_approve_passkey`); also `device_verify` `src/device_auth.rs:811-823`.

**Interleaving:** both approval paths do: read entry (`get_device_code_by_user_code`),
assert `status == Pending`, then `entry.status = Approved; entry.did = Some(...)`
and `update_device_code` (a blind overwrite via `set_device_code`,
`src/db/redis.rs:507-514`). No SETNX/CAS guards the Pending→Approved transition.

Two approvers race on the same `user_code`:
- T1 (wallet, DID-A): reads Pending → verifies sig → about to write Approved/DID-A.
- T2 (passkey, DID-B): reads Pending (T1 hasn't written yet) → verifies → writes Approved/DID-B.
- T1 writes Approved/DID-A.
- Last writer wins. The token grant (S3-1) then bakes whichever DID survived into
  the device's tokens — possibly **not** the DID the human who controls the
  polling client intended.

**Attacker scenario:** the `user_code` has ~25.9 bits of entropy
(`generate_user_code`, 6 consonants) and `/device/verify` is an **unauthenticated
oracle** that confirms a code is valid+Pending (`device_verify`, returns 200 vs
"not found"). An attacker who guesses/learns a pending user_code (shoulder-surf,
shared screen during QR onboarding, or brute force within the 1800s lifetime —
2^25.9 is large but the verify oracle gives a cheap online check) can approve the
victim's device-login with the **attacker's** DID. If the attacker's write lands
last, the victim's Element X session is provisioned under the attacker's identity
(account takeover of the new device session); if it lands first, it's a DoS /
confusion. Either way it is split-brain device ownership (H9).

**Impact:** identity confusion / device-session hijack on the device-code flow.

**Fix:** make Pending→Approved an atomic CAS: `SET
device_codes/{dc}/approved <did> NX` (or a Lua check-and-set on the JSON status),
and reject the second approver with "code already used". Additionally bind the
approval to the browser that ran `/device/verify` (a per-approval CSRF/nonce
cookie set on verify and required on the approve POST) so a stranger who only
knows the user_code cannot approve.

---

### S3-3 — MSC4191 `device_delete` is check-then-act (TOCTOU) and its token-revoke is a non-atomic keyspace scan — CONFIRMED
**File:** `src/account.rs:399-442` (`execute_action`, `Action::DeviceDelete`); revoke in `src/db/redis.rs:115-124` + `src/db/redis.rs:222-243` (`revoke_tokens_where`).

**The interleaving the codebase explicitly fears.** `device_delete` does:
1. `get_device` ownership pre-check (lines 405-419).
2. `delete_device` on Synapse admin API (lines 420-426).
3. *separately*, best-effort `revoke_device_tokens(localpart, device_id)` (lines
   431-437), which `KEYS token/*` → per-key `GET` → `DEL` (no Lua, no WATCH/MULTI).

Concurrency problems, all confirmed by reading the code:

- **Double-delete on the same device:** two account sessions for the same DID (the
  session TTL is 10 min and nothing prevents two live `acct_session`s — see S3-6)
  both pass the `get_device` check, then both `delete_device`. Synapse's admin
  delete of an already-gone device returns non-2xx; `delete_device`
  (`synapse_client.rs:307-312`) `bail!`s, and `execute_action` maps that to
  `BadRequest("Failed to sign out device")` (account.rs:423-426) — so the loser
  gets a spurious error on an operation that *did* succeed. Not a 500, but a
  confusing/incorrect result and wasted admin calls.

- **device_delete racing a token refresh (token resurrection):** `revoke_device_tokens`
  enumerates keys with `KEYS` then deletes them one by one. `compat::refresh`
  (`src/compat.rs:441-543`) concurrently mints a NEW `mat_`/`mcr_` pair for the
  same `(username, device_id)` and deletes the old refresh token. Interleaving:
  revoke does `KEYS` (snapshots the old tokens) → refresh writes new tokens (not in
  the snapshot) → revoke deletes only the snapshotted old tokens. **The freshly
  minted access+refresh pair survives the device sign-out.** The device is gone
  from Synapse but the OAuth session keeps introspecting active until TTL. This is
  the "one operation's revoke misses tokens created by a concurrent op" failure.

- **device_delete racing a cross-signing key upload:** deleting the Synapse device
  while the client is mid key-upload is exactly amplifier B of the 2026-06-12
  incident (documented in `compat.rs:82-100` and CLAUDE.md). The account-page
  `device_delete` is an explicit-intent path so deletion is *intended*, but there
  is no interlock with an in-flight upload; under the documented Synapse pathology
  (delete leaves `e2e_cross_signing_signatures`, upload handler skips when a stale
  row exists) a delete that races a re-login on the same proposed device_id can
  still wedge verification.

**Impact:** stale-but-active tokens after an explicit sign-out (security-relevant:
sign-out does not fully sign out); spurious errors on concurrent deletes;
residual cross-signing-corruption risk.

**Fix:** (a) revoke tokens **before** (or transactionally with) the Synapse delete,
and make revocation atomic — a Lua script that scans+deletes in one round trip, or
maintain a secondary index `idx:user_device/{username}/{device_id}` (a Redis SET of
token keys) updated on `set_token`/`delete_token` so revoke is an O(members) SMEMBERS+DEL,
not a racy keyspace `KEYS`. (b) Treat an already-deleted Synapse device (404/not
found) as success, not `BadRequest`. (c) Consider a short per-(user,device) lock
during delete to serialize against refresh.

---

### S3-4 — `revoke_all_user_tokens` / `purge_identity` race a concurrent login or refresh on deactivate/erase (H5/H6 token & identity resurrection) — CONFIRMED
**File:** `src/account.rs:443-504` (`AccountDeactivate`, `AccountErase`); `src/db/redis.rs:134-143` (`revoke_all_user_tokens`), `src/db/redis.rs:167-213` (`purge_identity`), scan engine `src/db/redis.rs:222-243`.

**H6 — in-flight refresh resurrects access after deactivate.** `account_deactivate`
does `deactivate_user` (Synapse) then best-effort `revoke_all_user_tokens(localpart)`
(account.rs:455-461). `revoke_all_user_tokens` is the same `KEYS`+`GET`+`DEL` scan.
Interleaving: revoke snapshots keys via `KEYS` → a concurrent `POST
/_matrix/client/v3/refresh` (compat.rs:441) writes a brand-new access+refresh pair
(not in the snapshot) → revoke deletes only the snapshot. The new pair survives.
Synapse-side the account is deactivated so the access token *should* fail
introspection at Synapse, but siwx-oidc's own `/oauth2/introspect` resolves tokens
from Redis (`introspect.rs`), so the resurrected token introspects **active** until
its 24h refresh TTL — a deactivated user can keep refreshing. The code comment
calls revoke "best-effort", which understates that it is also non-atomic vs.
concurrent writers.

**H5 — concurrent passkey login re-creates an artifact erase just purged.**
`account_erase` calls `purge_identity(did, derive)` (account.rs:490-496), which in
pass (a) scans `webauthn:link/*` and in pass (b) scans `webauthn:credential/*`.
These keys are written by the WebAuthn register/link finish handlers
(`webauthn:credential/{cred_id}` has **no TTL**, per CLAUDE.md). Interleaving: erase's
pass-(a) `KEYS webauthn:link/*` snapshots links → a concurrent `link_finish`
writes a *new* `webauthn:link/{cred}` + `webauthn:credential/{cred}` for the same
primary_did → purge never sees it. Result: an **orphan link/credential survives
erasure**, and because passkey auth substitutes `primary_did` from the link
(CLAUDE.md "Account linking"), the "erased" DID can be **silently re-derived** from
the leftover passkey — defeating the stated GDPR guarantee ("the DID cannot be
silently re-derived from a leftover passkey", account.rs:486-489). Also:
`purge_identity` returns early-`?` on any Redis error mid-scan (e.g.
`self.del_raw(&cred_key).await?`, redis.rs:192/194/207) → a **partial purge** that
the caller logs as `purged=N` and still reports `Erased` success to the user
(account.rs:490-503). Erasure can be claimed done while artifacts remain.

**Impact:** deactivated/erased accounts retain a usable token or a re-derivable
identity → incomplete account termination, GDPR-erasure incompleteness, and a
"success reported, not fully done" partial-failure.

**Fix:** (a) revoke tokens **and** block new issuance for the user before/while
deactivating — set a `deactivated/{username}` tombstone (checked by sign_in,
device_code grant, and refresh) so no concurrent flow can mint or rotate tokens
during/after the sweep; loop the revoke until a scan finds zero. (b) For erase,
set the tombstone first so `link_finish`/`register_finish`/sign_in refuse the DID,
then purge; make purge resilient (don't `?`-abort the whole sweep on one key
error — accumulate and report a *partial* result so the handler does not claim
full erasure on partial success).

---

## MEDIUM

### S3-5 — CSRF token comparison on `/account/action` is not constant-time — CONFIRMED
**File:** `src/account.rs:661-663`.

```rust
if req.csrf.as_deref() != Some(session.csrf.as_str()) {
    return Err(CustomError::Unauthorized("CSRF token mismatch".to_string()));
}
```
The doc comment claims "constant work either way", but `str`/`!=` short-circuits
on the first differing byte. The repo already has `oidc::constant_time_eq`
(oidc.rs:46) and uses `subtle::ConstantTimeEq` for the client secret, the PKCE
challenge, and the introspection secret — the CSRF compare is the one secret
compare that was left timing-variable. The CSRF token is a 32-hex-char UUID; with
SameSite=Strict the practical exploitability is low (an attacker needs to drive
the timing oracle cross-site, which SameSite blocks), hence MEDIUM not HIGH, but
it is an inconsistency that contradicts its own comment.

**Fix:** compare with `constant_time_eq(req.csrf.as_deref().unwrap_or(""), &session.csrf)`.

### S3-6 — Multiple concurrent `acct_session`s per DID; no single-session invariant; H10-adjacent reuse window — CONFIRMED
**File:** `src/account.rs:55-75` (`create_account_session`), `src/axum_lib.rs:583-601` (`authed_action_response`).

Every wallet/passkey re-auth mints a **new** random session token
(`create_account_session`) with a 600s TTL and stores it independently; nothing
invalidates prior sessions for the same DID. So a single DID can hold many live
`acct_session`s simultaneously. This is the enabling condition for the
double-delete in S3-3 and means a leaked/old cookie remains valid for up to 10
minutes even after the user "did something" in another tab. On the H10 question
("can the session be reused after a terminal action?"): terminal actions performed
via `/account/action` **do** destroy the server-side session and clear the cookie
(axum_lib.rs:655-664) — good. **But** if erase/deactivate is performed via the
*fresh-re-auth* handlers (`account_wallet_handler` / `account_passkey_finish_handler`),
those handlers never read the cookie, so any **pre-existing** `acct_session` cookie
for that DID is left live in Redis (only the response's own Set-Cookie clears the
caller's cookie). A second tab with an older session can still hit `/account/action`
for ~10 min after the identity is erased/deactivated — its actions will then fail
at the Synapse layer (account gone), but the authenticated session itself was not
invalidated.

**Impact:** session-lifetime hygiene gap; concurrency enabler for S3-3; minor H10
residue (session not globally revoked on terminal action via the re-auth path).

**Fix:** key sessions by DID (or maintain `acct_sessions/{did}` set) and revoke all
of a DID's account sessions on any terminal outcome, regardless of which handler
executed it; consider single-active-session-per-DID.

### S3-7 — Account passkey ceremony does not bind the action to the challenge (destructive-action confirmation is generic proof-of-presence) — CONFIRMED
**File:** `src/axum_lib.rs:668-682` (`account_passkey_start_handler`), `src/webauthn.rs:197-234` (`authenticate_start` stores only the challenge), `src/account.rs:595-633` (`account_passkey_finish` reads `action` from the request body).

`/account/passkey/start` accepts an `action` but only checks it is non-empty
(axum_lib.rs:672-674); the stored challenge (`webauthn:challenge/{session_id}`)
contains **no action binding**. At `finish`, the action is taken from the request
body and executed. So a passkey assertion is a generic "this DID is present"
proof; the specific destructive action (`account_erase`) is not cryptographically
or server-side bound to what the user was prompted to confirm. Because it is the
same DID, this is not cross-user, but it weakens the "confirm THIS action"
property: a malicious page that obtained a started session_id, or a confused-deputy
in the page JS, could finish a *different* action than the one the user believed
they were authorizing. (The wallet path is better: the CAIP-122 message text is
generic too — "Confirm account action." — so it shares the weakness.)

**Fix:** store the requested `action` (and `device_id`) alongside the challenge at
`start`, and at `finish` require the submitted action to equal the stored one.

### S3-8 — Compat CS-API `delete_device` / `delete_devices` revoke tokens by attacker-supplied device_id without an ownership read — CONFIRMED (low exploitability)
**File:** `src/compat.rs:412-437` (`delete_device`, `delete_devices`) → `teardown_device` `src/compat.rs:368-395`.

These resolve the user from the bearer (`username_from_bearer`) then call
`synapse.delete_device(username, device_id, ...)` and
`revoke_device_tokens(username, device_id)` with the **client-supplied** device_id
and **no** `get_device` ownership check (unlike the account-page path, which
pre-checks). Authorization is delegated entirely to "the Synapse admin delete is
mxid-scoped" and "the Redis revoke is keyed on the bearer's username". That holds
for *cross-user* safety (you can only ever name your own mxid's device). The
residual issue is purely intra-user: a caller can name any device_id string and
`revoke_device_tokens(self, that_id)` scans+deletes any of *their own* tokens
matching it — harmless for the owner, but it means the compat path has weaker
defence-in-depth than the account path and inherits the same non-atomic-scan race
as S3-3 for the targeted tokens.

**Impact:** no cross-user impact; inconsistent (weaker) validation + same revoke-race
as S3-3.

**Fix:** for parity, ownership-check the device via `get_device` before deleting,
and share the atomic-revoke fix from S3-3.

### S3-9 — Synapse failures are swallowed in best-effort paths; partial teardown reported as success — CONFIRMED
**File:** `src/oidc.rs:1234-1263` (`provision_synapse_device` — all sub-calls `warn!` and continue), `src/compat.rs:153-217` & `274-326` (delete_device/list_devices failures only `warn!`), `src/account.rs:431-437`/`455-461`/`479-496` (revoke/purge `unwrap_or_else(0)` and continue).

The deliberate "never 500, best-effort" design means a Synapse admin call that
fails (network, or — critically — the `admin_token == mas_shared_secret`
assumption being wrong so Synapse returns 401/403) is logged at warn and the
operation reports success. Examples with security weight: `logout_all` whose
`list_devices` 401s will skip Synapse device deletion entirely yet still return
200 `{}` (compat.rs:308-312) — the user believes every device was signed out;
`account_erase` whose `revoke_all_user_tokens`/`purge_identity` partially fail
still returns `Erased`. The `admin_status_hint` (synapse_client.rs:36-42) shows
the team anticipated the 401-on-shared-secret case, but it only annotates the log,
not the user-facing result. (Note: the device-management calls themselves do NOT
report a Synapse failure as success on the *account page* delete path —
`delete_device` there `bail!`s and surfaces a BadRequest — but the *revoke* half
and all *bulk/compat* paths do.)

**Impact:** users (and admins) can be told a sign-out/erasure/deactivation
completed when Synapse-side it did not.

**Fix:** distinguish "device not found / already gone" (treat as success) from
"Synapse rejected/unreachable" (surface a partial-failure status to the caller, or
queue a retry); never report `Erased`/all-signed-out on a swept-with-errors run.

---

## LOW

### S3-10 — `did_to_localpart` is lossy → distinct DIDs can collide onto one localpart/account — CONFIRMED
**File:** `src/oidc.rs:1198-1200`: `did.replace(':', "-").to_lowercase()`.

Lowercasing + `:`→`-` is not injective. Two DIDs differing only in case (e.g. an
EIP-55 mixed-case address vs. its lowercase form) map to the **same** localpart and
therefore the same Synapse account and the same token-revocation key space. The
codebase leans into this intentionally for revocation robustness ("robust to
address-case differences", redis.rs:107-109), but it also means an attacker who
controls a DID that case-folds onto a victim's localpart shares the victim's
account namespace. For `did:pkh:eip155` an address is a single canonical key, so
practical collision requires controlling the same key; hence LOW. Worth an
explicit canonicalization/uniqueness assertion rather than relying on
case-folding.

**Fix:** canonicalize DIDs to a single normal form at sign-in and reject
non-canonical encodings, so the localpart mapping is provably 1:1.

### S3-11 — Device-code interval rate-limit is read-modify-write (bypassable under concurrency) — CONFIRMED
**File:** `src/oidc.rs:576-593`.

`last_poll` is read, compared, then written via `update_device_code` (blind
overwrite). Two concurrent polls both read the old `last_poll` and both pass the
interval check before either writes — defeating the `slow_down` throttle and
feeding S3-1. Minor on its own (the interval is anti-abuse, not security-critical),
but it is the same non-atomic-RMW family.

**Fix:** enforce the interval with an atomic `SET .../poll_gate 1 NX EX <interval>`.

### S3-12 — Account-page CAIP-122 / passkey re-auth has no replay/nonce binding to the server — CONFIRMED
**File:** `src/account.rs:535-590` (`account_wallet`): the nonce in the signed
message is generated **client-side** (account page JS, account.rs:1371) and the
server never issues or checks it; `did_method.verify` only checks the signature
over the message.

A captured `/account/wallet` body (action+did+message+signature) can be **replayed**
to re-establish an account session for that DID — there is no server-side nonce
store binding the signature to a one-time challenge, and no timestamp window
enforced server-side. SameSite/Origin do not protect a server-to-server replay of
a captured body. Exploitability needs capture of a signed body, so LOW, but the
sign-in flow (by contrast) does bind a server-issued nonce in the session.

**Fix:** issue a server-side nonce for account re-auth (as sign_in does) and
verify+consume it, so each signature is single-use.

### S3-13 — `try_consume_code` consumed-flag and signed-in flag can outlive / desync the entry; `purge_identity` aborts whole sweep on first error — CONFIRMED (robustness)
**File:** `src/db/redis.rs:367-431` (SETNX flags expire independently of the code/session) and `src/db/redis.rs:167-213` (`?`-propagation mid-scan).

The atomic-claim helpers store their flag with a *separate* `expire` that is best-
effort (`.unwrap_or(())`, redis.rs:385-386/427-428); if the EXPIRE call is lost the
flag can persist. And `purge_identity` returns `Err` (via `?`) on the first Redis
error during a multi-key sweep, leaving the purge half-done (see S3-4). Both are
resilience issues rather than direct vulns.

**Fix:** set value+TTL atomically (`SET ... NX EX`); make `purge_identity`
accumulate per-key errors and continue.

---

## INFO / Confirmations (things that are CORRECT or need-verification)

### S3-14 — No cross-user IDOR on account device actions — CONFIRMED CORRECT
`device_view`/`device_delete` resolve the device via `get_device` =
`list_devices(localpart).find(id)` (synapse_client.rs:268-279), scoped to the
authenticated DID's localpart; a foreign device_id yields `None` → "not among your
active sessions". `delete_device`/`revoke_device_tokens` are mxid/username-scoped.
An `acct_session` for user X cannot act on user Y's devices. This is the audit's
top IDOR concern and it holds.

### S3-15 — Sign-in never recycles a device id — CONFIRMED CORRECT
`provision_synapse_device`/`_additive` only **upsert** (`upsert_device`,
synapse_client.rs:96-127); no delete-then-reuse. The generated id is a fresh
`SIWX_{uuid8}` (oidc.rs:626, 1218-1223). Explicit-logout/device_delete deletion of
an *ending* device is distinct from recycling and is safe because the id is not
reissued. The cross-signing-corruption-by-recycling class is avoided as designed.
(Minor note: `SIWX_{uuid8}` truncates to 8 hex chars ≈ 32 bits; collision across a
very large device population is astronomically unlikely but not impossible — INFO.)

### S3-16 — `admin_token == mas_shared_secret` and SSRF posture — need-verification / acceptable
The Synapse endpoint is operator-configured (`SIWEOIDC_SYNAPSE_ENDPOINT`, a parsed
`Url`, config.rs:44; client built once at startup, axum_lib.rs:804-807) and is not
attacker-influenced, so URL-construction SSRF does not apply. The mxid path
segments and `device_id` are percent-encoded (`urlencoding::encode`,
synapse_client.rs:236/297/322/369), preventing path-segment injection (note:
`localpart`/`server_name` come from config + a lossy-but-bounded transform, and
the deactivate/reactivate URLs encode the full mxid). The single shared secret
doubling as the Synapse admin token (per CLAUDE.md and the s2-account memory) means
**any** holder of the MAS introspection secret also holds full Synapse admin — a
broad blast radius that is a known accepted caveat ("admin_token==MAS shared
secret", per the deployment memo) rather than a code bug. Recommend tracking the
split of these two credentials as hardening, but no in-code defect here.
