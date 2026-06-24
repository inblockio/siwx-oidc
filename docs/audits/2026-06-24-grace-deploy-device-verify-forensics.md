# Forensic root-cause: device verification / device-auth failure during the grace-fix prod window

**Date:** 2026-06-24
**Component:** `siwx-oidc` (MSC3861 delegated auth for `matrix.inblock.io`) + Synapse + Element Web
**Window investigated:** prod ran `ghcr.io/inblockio/siwx-oidc:sha-3f40485` (the refresh-token
GRACE fix) for ~7 min, **05:34:25 to 05:41:23 UTC**, then rolled back to `sha-db79e75`.
**Affected user:** `@did-pkh-eip155-1-0x23d673b759550969cc5e325780048738d83ae4c6:matrix.inblock.io`
(Element WEB, Chrome 147 / Windows, IP 185.213.83.254).
**Reported symptoms:** (1) device verification of the session FAILED using the recovery key;
(2) the retry for device authentication FAILED; (3) request for any other "not fully functional"
findings.

**Log availability caveat:** the grace `siwx-oidc` container was removed by `--force-recreate`
under the `json-file` driver, so **siwx-oidc-side logs for this session are GONE**. This analysis
reasons from the surviving **Synapse access logs** plus the **siwx-oidc source code** at
`main`/`eff6044` (which includes the grace fix). Synapse-only logs are sufficient here because the
decisive failure (`POST .../keys/device_signing/upload` -> 401) and the missing remediation step
both have observable Synapse-side signatures.

Forensic inputs (local to the investigation box):
- `/tmp/forensic-synapse-did.log` — 192 Synapse request lines for this user, 05:30-05:50 UTC.
- `/tmp/forensic-did-nonok.log` — the 24 non-2xx lines.
- `/tmp/forensic-synapse-full.log` — full Synapse window, all users (~3123 lines).

---

## TL;DR

- **Root cause:** Element Web performed a **cross-signing + 4S RESET**, not an unlock. Resetting
  cross-signing under MSC3861 requires the client to obtain an out-of-band reset authorization via
  `GET /account?action=org.matrix.cross_signing_reset` and *then* retry `keys/device_signing/upload`.
  **Element Web never opened that reauth path during the window**, so all 14
  `POST /_matrix/client/v3/keys/device_signing/upload` attempts returned `401` and the cross-signing
  public keys were never published. The session was left in a half-reset state: new 4S + new key
  backup (v4) written, but **no cross-signing identity uploaded** -> the device cannot be verified.
- **Grace-causation verdict:** **NO — this is PRE-EXISTING, not caused by the grace deploy.**
  Confidence: **HIGH.** The deployed delta (`db79e75..main`) touches only refresh-token rotation and
  a WebAuthn `methods`-prediction revert. It does not touch the device-signing / cross-signing / UIA /
  keys-upload / device-provisioning path in any way. The failing endpoint (`keys/device_signing/upload`)
  is served by **Synapse/MAS**, not siwx-oidc, and its 401 is governed by whether
  `allow_cross_signing_reset` has been granted — logic identical on `db79e75`. The same failure would
  reproduce on the rolled-back build. The team's own grace audit reaches the same orthogonality
  conclusion: `docs/audits/2026-06-23-elementx-refresh-rotation-signout.md:106` lists
  "OIDC-discovery / cross-signing bootstrap regression" as **"Not implicated."**
- **Systemic check:** **User-specific.** Across the entire 3123-line full window, **only this one
  DID** issued any `keys/device_signing/upload` (14 lines, all `401`). No other user was affected.

---

## 1. Reconstructed timeline (Synapse access log, `/tmp/forensic-synapse-did.log`)

All times UTC. The session is a **pre-existing, already-logged-in** Element Web session — the log
opens mid-`/sync` (`since=s13835...`) with **no `/login`, `/authorize`, `/token`, or `/refresh`
anywhere in the window**. That matters: no fresh login occurred during the grace window, so the
login-path `allow_cross_signing_reset` (which siwx-oidc fires unconditionally on sign-in,
`oidc::provision_synapse_device`) did **not** run either.

| Time | Event | Status | Meaning |
|---|---|---|---|
| 05:36:01.766 | `GET /room_keys/version` | 200 (513B) | Existing megolm key backup present (version 3). |
| 05:36:03.280 | `GET .../account_data/m.secret_storage.default_key` | **200 (42B)** | **A 4S default key ALREADY EXISTS** — non-empty body. The account had working Secure Backup before the reset. |
| 05:36:04.900 | `GET /sync` (filter=0,timeout=0) | 200 | Initial catch-up sync. |
| 05:36:06.067 | `POST /keys/upload` | 200 | Device (one-time/identity) keys uploaded — normal. |
| 05:36:06.962 | `POST /keys/query` (11951B) | 200 | Client queries cross-signing/device keys for the room. |
| 05:36:14.251 | `GET /room_keys/version` | 200 | Re-reads backup version 3 immediately before deleting it. |
| **05:36:14.824** | **`DELETE /room_keys/version/3`** | **200** | **Element DELETES the existing megolm key backup** — the unambiguous opening move of a RESET (not an unlock). |
| 05:36:15.069 | `GET /room_keys/version` | **404** | Backup now gone, as expected post-delete. |
| 05:36:15.624 | `PUT .../account_data/m.cross_signing.master` | 200 | Writes NEW (re-encrypted) cross-signing master private half to 4S. |
| 05:36:16.151 | `PUT .../account_data/m.cross_signing.self_signing` | 200 | NEW self-signing private half. |
| 05:36:16.692 | `PUT .../account_data/m.cross_signing.user_signing` | 200 | NEW user-signing private half. |
| 05:36:17.215 | `PUT .../account_data/m.megolm_backup.v1` | 200 | New backup-decryption key stashed in 4S. |
| 05:36:17.816 | `PUT .../account_data/m.secret_storage.key.1Xcfx...` | 200 | NEW 4S key descriptor (new recovery key). |
| 05:36:18.353 | `PUT .../account_data/m.secret_storage.default_key` | 200 | Points default 4S at the new key — **4S fully re-created.** |
| 05:36:18.745 | `GET /room_keys/version` | 404 | No backup version yet (created later at 05:37). |
| **05:36:19.031** | **`POST /keys/device_signing/upload`** | **401** | **First attempt to publish the NEW cross-signing PUBLIC keys — REJECTED.** (MSC3861: a reset upload needs a reset authorization first.) |
| 05:36:19.308 | `POST /keys/device_signing/upload` | 401 | Retry #2 — rejected. |
| 05:37:03.375 ... 05:37:09.926 | `POST /keys/device_signing/upload` ×12 | 401 ×12 | Retries #3-#14, all rejected. **14 total.** |
| 05:37:23.303 | `GET /room_keys/version` | 404 | About to create a fresh backup. |
| **05:37:23.660** | **`POST /room_keys/version`** | **200 (returns "4")** | **New megolm key backup v4 created.** |
| 05:37:24.154 | `POST /keys/claim` | 200 | Claims one-time keys (re-establish Olm sessions). |
| 05:37:24.665 | `PUT .../account_data/m.megolm_backup.v1` | 200 | Backup key recorded. |
| 05:37:25.5-28.8 | `GET /room_keys/keys/!.../<sessionId>?version=4` ×7 | **404 ×7** | **Old room session keys are NOT in the new backup** — history keys lost (see Q3). |
| 05:37:20-22 | A SECOND 4S/cross-signing PUT burst (`m.secret_storage.key.73u9...`, default_key, master/self/user_signing again) | 200 | Element re-ran 4S setup a second time (new key `73u9...`) — consistent with a UI "set up recovery again" loop, still with no `device_signing/upload` success. |
| 05:38:11.900 / 05:38:36.087 | `GET /room_keys/version/4` | 200 | New backup readable. |
| 05:38:10 / 05:38:34 | `PUT .../account_data/m.megolm_backup.v1` | 200 | Backup wiring confirmed. |
| 05:39:18.554 | `PUT /room_keys/keys?version=4` | 200 | Begins backing up current session keys into v4. |
| 05:39:21.607 | `PUT /rooms/!.../send/m.room.encrypted/...` | 200 | **User successfully SENDS an encrypted message** — messaging works. |
| 05:40:00 / 05:40:39 | `GET /devices` | 200 | Device list views (likely the Sessions/verification UI). |
| 05:41:xx onward | `GET /sync ... set_presence=unavailable` (repeating) | 200 | Tab backgrounded; **no further `device_signing/upload` ever** — the client gave up after 14 tries and never retried post-reauth. |
| ...05:49:39 | final `/sync` | 200 | Session idles out the window. |

**Net:** A full cross-signing+4S **RESET** that succeeded on the private/4S/backup side
(account-data writes all 200, new backup v4 created, encrypted send works) but **failed on the one
step that publishes the new identity** — `keys/device_signing/upload` (14×401) — because the reset
was never authorized. The reset window (deletes/PUTs/401s, 05:36:14-05:37:09) sits entirely inside
the grace deploy window (05:34:25-05:41:23), which is why it was attributed to the deploy by timing
alone.

---

## 2. (Q1) Why did device verification with the recovery key fail?

**Answer (one line):** Element Web did not *unlock* with the recovery key; it ran a **RESET** that
**deleted** the existing backup and wrote brand-new cross-signing/4S secrets, and the reset's public
key-publish step (`device_signing/upload`) was rejected, so the new identity never came into
existence to verify against.

**Evidence it was a reset, not an unlock:**
- `DELETE /room_keys/version/3` at 05:36:14.824 (200) — an *unlock* never deletes the backup; only a
  reset does.
- Immediately followed by NEW `PUT m.cross_signing.{master,self_signing,user_signing}`, a NEW
  `m.secret_storage.key.1Xcfx...`, and `m.secret_storage.default_key` — i.e. a freshly generated 4S,
  not a decrypt of the existing one.
- The pre-existing `m.secret_storage.default_key` **was** present and non-empty at session start
  (05:36:03, 200/42B), so a valid 4S existed to unlock — Element chose reset anyway.

**Client-side vs server-side split:**
- **Client-side (Element Web) decision.** Whether Element *unlocks* (consume recovery key) or
  *resets* (discard + regenerate) is purely a client decision. Element Web carries a vendored
  **`force-first-device-recovery`** patch (referenced in this repo at `CLAUDE.md:590`,
  `docs/design/2026-06-18-passkey-scoping-and-new-user-gate.md:104`,
  `docs/superpowers/plans/2026-06-18-passkey-scoping-new-user-gate.md:33`) whose behavior is
  `forceReset: !hasExisting4S`. The DELETE-then-regenerate pattern in the log is exactly a forced
  reset path. Two readings, both consistent with the log:
  (a) the user clicked a "Reset" affordance rather than "Enter recovery key"; or
  (b) the recovery key the user typed did not validate against the existing 4S, so Element fell back
  to reset. The Synapse log cannot disambiguate the keystrokes (recovery-key validation is local,
  in-browser, and produces no server request), **but it proves the recovery key was never used to
  successfully unlock** — a successful unlock leaves the existing backup in place; here it was
  deleted. So either the key was wrong/rejected client-side, or reset was chosen outright.
- **Server-side (this is the load-bearing failure).** Even though Element produced new secrets, the
  reset could not *land* because publishing the new public cross-signing keys requires a reset
  authorization that was never obtained (Q2). So "verification failed" is the downstream symptom of
  "the new identity was never published."

**Why the symptom reads as "verification failed with the recovery key":** the user experiences
"reset my identity / verify this session" and "enter recovery key" as one flow; the actual breakage
is the silent 401 on the public-key publish, which Element surfaces as a generic verification/identity
failure (matrix-rust-sdk and Element are documented to swallow this class of error;
`CLAUDE.md` "Lesson learned" + element-meta #2410 "account is totally broken").

---

## 3. (Q2) Why did the device-auth retry fail — the 14× 401 on `keys/device_signing/upload`?

**Answer (one line):** Under MSC3861, uploading **reset** cross-signing keys requires a prior reset
authorization that the user must perform at the provider's account page
(`GET /account?action=org.matrix.cross_signing_reset`); **the client never opened that path during
the window**, so siwx-oidc never called `allow_cross_signing_reset`, and Synapse kept returning 401.

**The required contract (from this repo's own docs):**
- `CLAUDE.md` ("For cross-signing key RESET"): *"When Element Web encounters a cross-signing reset
  needing user confirmation, it reads `account_management_uri` from OIDC discovery and opens
  `/account?action=org.matrix.cross_signing_reset`. The user re-authenticates (wallet or passkey),
  siwx-oidc calls `allow_cross_signing_reset`, and Element Web retries the upload."*
- `skills/cross-signing-bootstrap-and-debug.md:30-32`:
  `POST keys/device_signing/upload --> 401 m.oauth --> redirect to account_management_url?action=org.matrix.cross_signing_reset --> user confirms --> siwx-oidc calls allow_cross_signing_reset --> retry`.

**Where the 401 comes from (code path):**
- The endpoint `POST /_matrix/client/v3/keys/device_signing/upload` is served by **Synapse**, not
  siwx-oidc (it does not appear in any siwx-oidc route table; siwx-oidc's compat surface is
  `/token`, `/refresh`, `/oauth2/*`, `/account*`, `/webauthn/*`, `/device*`). First-time cross-signing
  upload is allowed UIA-free via MSC3967, but a **re-upload over existing keys (a reset)** is gated:
  Synapse returns `401` until MAS/siwx-oidc has flagged the user via the MAS hook.
- siwx-oidc grants that flag in exactly two places, neither of which ran in the window:
  1. **On login** — `oidc::provision_synapse_device` calls
     `SynapseClient::allow_cross_signing_reset` unconditionally (`src/synapse_client.rs:130`,
     hitting `POST /_synapse/mas/allow_cross_signing_reset`). **No login happened in the window**
     (no `/authorize`/`/token`/`/sign_in` in the log), so this did not fire.
  2. **Via the account page** — `account::execute_action` `Action::CrossSigningReset`
     (`src/account.rs:364-374`) calls the same `allow_cross_signing_reset`, reached only through
     `GET /account?action=org.matrix.cross_signing_reset` followed by a wallet/passkey re-auth
     (`POST /account/wallet` or `/account/passkey/finish`). **None of these were requested.**

**Did the client ever attempt the reauth path? NO.**
- Grep of `/tmp/forensic-synapse-did.log` for `/account`, `cross_signing_reset`, or `org.matrix`
  returns no account-management request (only `room_keys` / MSC4222 / MSC4143 noise).
- The siwx-oidc `/account` page is served on the **siwx-oidc host**, not Synapse, so an account-page
  GET would not appear in the Synapse access log *per se*. **However**, the proof is in the outcome:
  if the reauth had succeeded, a *subsequent* `device_signing/upload` would have returned **200**.
  After the last 401 at 05:37:09, there were **zero** further `device_signing/upload` requests of any
  status (`awk '$2>"05:37:09"' | grep device_signing` = 0). So the client did not complete reauth and
  retry — it abandoned the publish after 14 attempts. The reset never authorized; the 401 never
  cleared.

**Is the 401 a bug, or by-design-but-UX-broken?**
- **By design on the siwx-oidc side, but the end-to-end UX is broken for this case.** The 401 is the
  intended MSC4312 challenge: "authorize this reset out-of-band, then retry." siwx-oidc implements the
  authorization endpoint correctly. The breakdown is that **Element Web did not follow the 401 into
  the `account_management_uri` reset flow** — it retried the bare upload 14× and gave up. This is the
  long-standing Element/rust-sdk silent-failure class documented in `CLAUDE.md`
  ("matrix-rust-sdk silently swallows cross-signing bootstrap errors"; element-meta #2410,
  matrix-rust-sdk #1641). It is NOT a siwx-oidc regression and NOT introduced by the grace deploy.
  (A possible secondary contributor — not observable here — is OIDC-discovery
  `account_management_uri` parity, but discovery is unchanged by the deploy and the same 2026-05-25
  fixes remain in place.)

---

## 4. (Q3) Other "not fully functional" findings

1. **Lost message-history keys (megolm).** `DELETE /room_keys/version/3` (05:36:14) destroyed the
   old key backup; the new v4 backup does **not** contain the prior room session keys —
   `GET /room_keys/keys/!.../<sessionId>?version=4` returned **404 seven times** (05:37:25-28) for
   sessions in rooms `!AyOmlkUYoakJFAGetw` and `!JQqjWyAqOcDAGSktqv`. Net effect: history encrypted
   with those sessions is **undecryptable** unless another verified device still holds the keys, or the
   user later restores them. This is collateral damage of choosing reset (which deletes the backup)
   over unlock (which would have preserved it).

2. **Orphaned / half-reset cross-signing identity (the core inconsistency).** The PRIVATE halves and
   4S were written to account-data (all 200) and a new recovery key + backup exist, but the **PUBLIC
   cross-signing keys were never published** (14×401, no success). The account is now in the
   "private secrets exist, public identity missing" split state — exactly the element-meta #2410
   "no further attempt to publish public keys, account is totally broken" condition. The device
   remains **cross-signing-unverified**; other users see this user/device as unverified; the user
   cannot self-verify this session against a cross-signing identity that was never uploaded.

3. **Double 4S setup.** Two distinct 4S key descriptors were created in one session
   (`m.secret_storage.key.1Xcfx...` at 05:36:17, then `...73u9pMpILtiRVV1YbggHbcn99lVXNtvg` at
   05:37:20), with `default_key` rewritten both times. Consistent with the user being bounced back
   through "set up recovery" because the identity never verified — churns the recovery key (any
   recovery key the user wrote down between the two may already be stale).

4. **Messaging itself is fine.** Encrypted send succeeded (05:39:21, 200) and the new backup is
   readable/writable (v4 GET/PUT 200). So the failure is **scoped to cross-signing verification and
   pre-reset history**, not to day-to-day E2EE send/receive on go-forward sessions.

---

## 5. Causation verdict: grace deploy vs pre-existing

**Verdict: PRE-EXISTING. The grace deploy did NOT cause this, and the rollback did NOT fix it.
Confidence: HIGH.**

**Evidence A — the deployed delta does not touch the failing path.**
`git diff db79e75..main -- src/` is six files, and every hunk is in one of two unrelated areas:

| File | What changed | Touches device_signing / cross-signing / UIA / keys-upload / provisioning? |
|---|---|---|
| `src/oidc.rs` | `token_refresh`: grace-replay branch (`get_rotated_token`) + write `set_rotated_token` after rotation | **No** — refresh-token grant only. |
| `src/compat.rs` | `refresh` (`POST /_matrix/client/v3/refresh`): same grace-replay + write | **No** — refresh-token grant only. |
| `src/db/mod.rs` | Adds `RotatedToken` struct, `REFRESH_GRACE_TTL=60`, `KV_ROTATED_PREFIX`, trait methods | **No** — token-storage types. |
| `src/db/redis.rs` | Implements `set_rotated_token`/`get_rotated_token`; one rustfmt nit | **No** — Redis impl of the above. |
| `src/axum_lib.rs` | **Removes** the `methods` field from `AuthenticateStartResponse` (passkey method-prediction revert) | **No** — WebAuthn login picker only. |
| `src/webauthn.rs` | **Removes** `methods_for_did` / `MethodsForDid` (same revert) | **No** — WebAuthn login picker only. |

There is **zero** change to `account.rs` (cross-signing reset handler is untouched — empty in the
diff), `synapse_client.rs` (`allow_cross_signing_reset` untouched), or any keys/device-signing code.
The grace fix is confined to refresh-token rotation; the revert is confined to the passkey picker.

**Evidence B — the failing endpoint is not even siwx-oidc's.** `keys/device_signing/upload` is a
Synapse endpoint; its 401 depends on the MAS `allow_cross_signing_reset` flag, set by siwx-oidc only
on login or via the account page. None of that logic differs between `db79e75` and `main`. On the
rolled-back `db79e75` build the same user doing the same reset-without-reauth would get the same
14×401.

**Evidence C — the team's own grace analysis agrees.** The refresh-grace audit explicitly scopes the
two concerns apart: `docs/audits/2026-06-23-elementx-refresh-rotation-signout.md:106` lists the
"OIDC-discovery / cross-signing bootstrap regression (the 2026-05-25 class)" as **"Not implicated …
breaks login/bootstrap, not a steady-state sign-out."** Conversely, cross-signing reset is not a
refresh-token concern.

**Evidence D — timing is the only link, and it's coincidental.** The reset (05:36:14-05:37:09) fell
inside the grace window (05:34:25-05:41:23) purely because that is when the user happened to test. No
login/refresh occurred in the window, so the grace code path was not even exercised for this user's
verification attempt.

**Caveat (stated for completeness):** siwx-oidc logs for the grace container are gone, so we cannot
re-read siwx-oidc's own emission of `allow_cross_signing_reset`. This does not weaken the verdict:
the *absence* of any `/account?action=cross_signing_reset` round-trip (no successful retry afterward)
is sufficient to show the reset was never authorized, independent of which siwx-oidc build was
running, and the code delta provably cannot affect that path.

---

## 6. Systemic vs user-specific

**User-specific.** In the full 3123-line window across all users
(`/tmp/forensic-synapse-full.log`), `keys/device_signing/upload` appears **14 times total, all from
this one DID, all 401**. No other user issued a single cross-signing upload (success or failure) in
the window. There is no fleet-wide signature; this is one user running one reset without completing
the reauth.

```
grep device_signing/upload forensic-synapse-full.log | <count by user>
  14  {@did-pkh-eip155-1-0x23d673...:matrix.inblock.io}   (all 401)
# no other user present
```

---

## 7. Recommendations

**Re-deploying the grace fix is SAFE with respect to this incident.** The grace delta is orthogonal
to cross-signing/verification; this failure would occur on either build. The grace fix should be
re-cut on its own merits (it fixes the Element-X mobile sign-out). Confidence: HIGH.

**Help this specific user recover their identity now (ordered):**
1. The clean fix is to make Element Web complete the reset authorization: have the user **trigger the
   cross-signing reset again and follow the prompt to the account page** — Settings ->
   Security & Privacy -> reset identity; Element should open
   `account_management_uri` (`https://siwx-oidc.inblock.io/account?action=org.matrix.cross_signing_reset`),
   re-auth with wallet/passkey, then the upload succeeds. If Element does not auto-open it, the user
   can navigate directly to that URL, complete re-auth, then re-run the reset so
   `keys/device_signing/upload` retries with the grant in place.
2. Operationally, an admin can pre-arm the grant so the very next upload succeeds:
   `POST {synapse}/_synapse/mas/allow_cross_signing_reset` for this user (the exact call
   `synapse_client.rs:130` makes), or simply have the user **log out and log back in** — siwx-oidc
   fires `allow_cross_signing_reset` unconditionally on every login
   (`oidc::provision_synapse_device`), after which Element's pending reset upload will be accepted.
3. **History keys:** the pre-reset megolm backup (v3) was deleted; messages encrypted before
   05:36:14 are unrecoverable from backup. If the user has any **other still-verified device** that
   holds those room keys, verify the new session from it to transfer keys before that device is lost.
   Otherwise that history is gone — set expectations.
4. Warn the user the **recovery key was rotated** during this session (and twice, given the double 4S
   setup): they must save the *latest* recovery key from the completed reset and discard any earlier
   one written down mid-session.

**Product/UX (the actual root cause to fix, upstream of siwx-oidc):**
5. The real defect is **Element Web retrying `device_signing/upload` 14× into a 401 instead of
   following the MSC4312 reset flow to `account_management_uri`.** Confirm Element Web's version is at
   or past the `force-first-device-recovery` / reset-redirect handling and that OIDC discovery still
   advertises `account_management_uri` + the `org.matrix.cross_signing_reset` action verbatim (it is
   sourced from `account::SUPPORTED_ACTIONS` and forwarded by Synapse). A discovery-parity regression
   here would silently degrade every reset to this 14×401 dead-end. This is the 2026-05-25 silent-
   bootstrap-failure class; keep MAS-parity discovery checks in the deploy gate.
6. Consider a defensive log/alert: a user emitting N consecutive `device_signing/upload` 401s with no
   intervening `allow_cross_signing_reset` is the exact signature of this stuck-reset state and should
   page before the user reports "verification failed."

---

## Appendix — key log line citations

```
05:36:03.280  200  GET  .../account_data/m.secret_storage.default_key   (42B = existing 4S present)
05:36:14.824  200  DELETE /_matrix/client/v3/room_keys/version/3        (RESET: old backup deleted)
05:36:15.624  200  PUT  .../account_data/m.cross_signing.master         (new private halves...)
05:36:18.353  200  PUT  .../account_data/m.secret_storage.default_key   (...new 4S wired)
05:36:19.031  401  POST /_matrix/client/v3/keys/device_signing/upload   (#1 of 14 — public-key publish rejected)
...           401  POST .../keys/device_signing/upload   ×13 more, through
05:37:09.926  401  POST .../keys/device_signing/upload   (#14, last)
05:37:23.660  200  POST /_matrix/client/v3/room_keys/version            (new backup v4 created)
05:37:25-28   404  GET  .../room_keys/keys/!.../<sessionId>?version=4    ×7 (old history keys absent)
05:39:21.607  200  PUT  .../rooms/!.../send/m.room.encrypted/...         (encrypted send works)
(no device_signing/upload after 05:37:09 — client abandoned the publish; reset never authorized)
```

Full-window systemic check: `keys/device_signing/upload` = 14 lines, 100% this DID, 100% 401.

---

# UPDATE: reauth executed, grant not delivered — root cause

**Date appended:** 2026-06-24 (later same day).
**Supersedes** the §3 conclusion ("the client never opened the reauth path"). **New
operator evidence** from the affected user (`@did-pkh-eip155-1-0x23d673…`): they *did*
open `GET /account?action=org.matrix.cross_signing_reset`, completed the wallet/passkey
re-auth, and **the account page showed a SUCCESS message** — yet a subsequent
`POST /_matrix/client/v3/keys/device_signing/upload` **still returned 401**. So the
question is no longer "did they reauth?" (they did) but "why did a *successful* reauth
not produce a grant Synapse honors for the next upload?" This section answers that with
file:line evidence and corrects the record.

> Note on the surviving Synapse log: the 14×401 burst at 05:36–05:37 in §1 with **no
> later retry** is consistent with the reauth happening *after* the user gave up the
> first burst (the `/account` round-trip is on the siwx-oidc host and is invisible to the
> Synapse access log; only a *post-reauth* `device_signing/upload` would show, and the
> user reports that one ALSO 401'd, off the captured window). The mechanism below is
> independent of which build was running and explains the 401-after-success directly.

## A. The exact end-to-end mechanism (read from source)

**1. siwx-oidc side — what "success" actually means.**
The reauth POSTs to `/account/wallet` (`account::account_wallet`,
`src/account.rs:597`) or `/account/passkey/finish` (`account::account_passkey_finish`,
`src/account.rs:693`). Both verify the signature/assertion + single-use nonce, then call
the SAME `execute_action(Action::CrossSigningReset, …)` (`src/account.rs:354`). The
reset arm is `src/account.rs:364-375`:

```rust
Action::CrossSigningReset => {
    let synapse = require_synapse(synapse_client)?;
    synapse
        .allow_cross_signing_reset(&localpart)            // src/account.rs:366-368
        .await
        .map_err(|e| { warn!(…); CustomError::BadRequest("Failed to reset cross-signing keys"…) })?;
    info!(did = %did, "cross-signing reset allowed via account management page");
    Ok(ActionOutcome::Completed)                          // src/account.rs:374
}
```

`ActionOutcome::Completed` flows back as `status:"completed"` and the page JS renders the
green terminal banner **"Encryption keys reset / Your client can now set up new
encryption keys. You can close this page."** (`renderOutcome` `case 'completed'`,
`src/account.rs:1608-1610`).

`allow_cross_signing_reset` (`src/synapse_client.rs:130-148`) does exactly one thing:

```rust
let url = format!("{}/_synapse/mas/allow_cross_signing_reset", self.endpoint);  // :131
let resp = self.http.post(&url).bearer_auth(&self.shared_secret)
    .json(&json!({ "localpart": localpart })).send().await …;                   // :132-139
if !resp.status().is_success() { … bail!("…: HTTP {status}"); }                 // :141-146
Ok(())
```

So **siwx-oidc's notion of "success" is precisely: the MAS admin endpoint
`POST /_synapse/mas/allow_cross_signing_reset` returned a 2xx for this `localpart`.**
Nothing more is checked.

**2. Synapse side — what gates `device_signing/upload`, and what the MAS call sets.**
From the grounded source citations in
`../siwx-oidc-matrix-server/docs/2026-05-29-cross-signing-identity-stability-handover.md:29-30`
(Synapse v1.153.0) and `skills/siwx-matrix-device-verify.md:249-273`:

- The upload gate is `rest/client/keys.py:403`: `device_signing/upload` is rejected
  (the MSC3861 out-of-band-auth challenge, observed here as **401**) **iff**
  `is_cross_signing_setup AND NOT master_key_updatable_without_uia`.
- `master_key_updatable_without_uia` is true **iff** the master row's
  `updatable_without_uia_before_ms` is in the future. That is a **per-user, time-boxed,
  master-key-row-scoped** flag on `e2e_cross_signing_keys WHERE keytype='master'`
  (verify query in `skills/siwx-matrix-device-verify.md:255-268`).
- The MAS `allow_cross_signing_reset` admin endpoint sets that column to
  `now + REPLACEMENT_PERIOD_MS`, where **`REPLACEMENT_PERIOD_MS = 10 min`**
  (`rest/admin/users.py:1290-1318`). It does so with an **UPDATE … WHERE keytype='master'**
  on the storage path (`storage/databases/main/end_to_end_keys.py:1679-1716`).

**The contract, stated exactly:** siwx-oidc *pushes* a grant; it does NOT get called back.
The grant is **a 10-minute, per-USER (localpart), master-key-row-scoped UIA-bypass window**
(`updatable_without_uia_before_ms`). It is **not** keyed to the upload's access
token/device/session — any `device_signing/upload` from that user within 10 min passes the
gate. Crucially, the write is an **UPDATE of an existing master row**: if there is **no
published master-key row** for the user at the instant the MAS call runs, the UPDATE
matches `rowcount == 0` — the window is **not** planted on a row the upload gate will read.

## B. The gap — why SUCCESS is shown but the grant is not effective

Put the two halves together against the §1 timeline and the failure is structural, not a
typo. **At the moment the user completes reauth, the relevant master-key row is in a state
where the MAS UPDATE does not produce an effective bypass for the upload that follows** —
and siwx-oidc reports success anyway because it only inspects the *HTTP status of its own
push*, never the *resulting gate state the client's upload will hit*.

Two concrete, code-confirmed contributors, either of which alone yields "success shown,
401 persists":

**(b) + (a) The success banner is decoupled from the gate's effectiveness
(PRIMARY — confirmed).** `execute_action` renders `Completed` (→ "Encryption keys reset")
**purely** from `allow_cross_signing_reset` returning `Ok(())`
(`src/account.rs:366-374` + `src/synapse_client.rs:141-147`), i.e. purely from the MAS
endpoint's 2xx. siwx-oidc performs **zero** post-grant verification that
`updatable_without_uia_before_ms` is now in the future on a master row, and **zero**
confirmation that a publishable master key even exists. So whenever the MAS endpoint
returns 2xx **without** actually arming an honored window (see (f)), the user is shown an
unconditional "you can now set up new encryption keys," while Synapse's gate is unchanged
and the very next `device_signing/upload` 401s. **This is the bug: the reauth-success
signal does not measure the thing it claims** (`src/account.rs:374`, `src/account.rs:1609-1610`).

**(f) The MAS UPDATE is a no-op against the master row the *reset* needs
(MECHANISM — confirmed by the timeline).** This incident is a **reset that DELETED the old
identity and never republished a new public master**: §1 shows
`DELETE /room_keys/version/3` then private-half writes to account-data, with
`device_signing/upload` 401ing 14× — i.e. **the new public master key was never landed**,
and the old one is being replaced. In that window the `allow_cross_signing_reset` UPDATE
`WHERE keytype='master'` has **no current/target master row to flip into the future** (the
handover doc's "virgin account" no-op is the same code path:
`…handover.md:30`, "with no master key `rowcount==0`"). The grant therefore does not become
effective for the pending upload even though the admin call may return 2xx. Because of (b),
this is invisible to the user.

**Failure modes ruled out (so the report is precise):**
- *(c) wrong localpart/case scope* — RULED OUT for this user. The grant keys on
  `did_to_localpart(did)` = `did.replace(':','-').to_lowercase()` (`src/oidc.rs:1513-1515`);
  this DID is already all-lowercase, so the localpart is identical between any sign-in and
  the reauth. (It remains a latent hazard for mixed-case wallet addresses, but it is not
  what bit here.)
- *(c') wrong token/device scope* — N/A by contract: the grant is per-USER, not per-token
  or per-device (§A.2). The upload not "carrying" the grant is not the failure; a per-user
  window would cover any of the user's uploads.
- *(d) TTL expiry / one-shot consumption* — POSSIBLE as a *secondary* aggravator (the
  window is 10 min and the user retried/looped through two 4S setups), but it is **not the
  primary cause**: even a freshly-issued window is ineffective under (f) because there is no
  master row to carry it, and (b) hides that regardless of TTL.
- *(e) account-session vs upload token mismatch* — N/A for the same reason as (c'): the
  bypass is not token-scoped.
- The earlier §3 verdict *"the client never called reauth"* — **CORRECTED**: the operator
  evidence is that reauth ran and reported success; the defect is in grant
  delivery/effectiveness + an unverified success signal, not in the client failing to
  navigate.

**One-line root cause:** siwx-oidc shows an unconditional cross-signing-reset SUCCESS the
moment its `POST /_synapse/mas/allow_cross_signing_reset` returns 2xx
(`src/account.rs:366-374`, `src/synapse_client.rs:141-147`, banner at
`src/account.rs:1609-1610`), but that admin call only arms an **honored** UIA-bypass window
when a **published master-key row already exists** (it is an `UPDATE … WHERE
keytype='master'`); during a destructive *reset* — exactly this incident — no current
master row is present, so the window is never planted on the row the upload gate reads, the
grant is not effective, and the next `device_signing/upload` keeps 401ing while the user has
been told it succeeded.

## C. Recommended FIX shape (analysis only — not implemented here)

The fix must make a rendered reset-SUCCESS **imply** an effective, upload-honored grant.
Smallest correct change, in two parts:

1. **Make "success" measure the gate, not the push (closes (b)).** After
   `allow_cross_signing_reset` returns `Ok(())`, do **not** immediately return
   `Completed`. Confirm the grant is effective for the user before claiming success — e.g.
   read back the master row's `updatable_without_uia_before_ms` and require it to be in the
   future (preferred: add a tiny MAS/admin read, or reuse the admin `GET users/{mxid}` key
   info), OR have the MAS endpoint return a typed result that distinguishes "window armed
   on an existing master" from "no master to arm." If it is not effective, render an
   actionable non-success state instead of the green banner.

2. **Handle the no-current-master reset case explicitly (closes (f)).** A reset that has
   no published master (deleted/never-republished) cannot be "allowed" by flipping a
   non-existent row. The grant for that case must arm a window that the *first publish* of a
   brand-new master will honor (i.e. the bypass must apply to the upcoming
   `device_signing/upload` even when `is_cross_signing_setup` is currently false/empty), or
   the flow must drive the client to publish first then authorize. This is partly a
   Synapse/MAS-contract question: confirm whether `allow_cross_signing_reset` (the
   `REPLACEMENT_PERIOD` window) can be armed **pre-publish** for a user whose master row is
   absent; if the upstream endpoint cannot, siwx-oidc must detect the no-master case and
   surface "your client will publish a new identity; keep this page open" rather than a
   false "done." Either way, **the success banner must be gated on the grant actually being
   honored**, per part 1.

   *Belt-and-suspenders (cheap, do it too):* lowercase-normalize is already correct, but
   add a regression assertion that the localpart used for `allow_cross_signing_reset`
   byte-matches the localpart Synapse stores, so the latent mixed-case (c) hazard cannot
   regress into this same symptom.

**Behavioral acceptance:** after the fix, completing reauth either (i) yields a state where
the immediately following `device_signing/upload` returns **200**, or (ii) shows a truthful
non-success message — but it never shows "Encryption keys reset" while the upload still
401s.

## D. How to TEST it end-to-end (reset → reauth → `device_signing/upload` 200)

Use the project's real-Synapse harness, not mocks (the gate lives in Synapse). The
matrix-server e2e stack already has a live round-trip slot:
`../siwx-oidc-matrix-server/e2e-harness/run.sh:115`
(`siwx-oidc.msc4191_live.cross_signing_reset_round_trip_live`) and the ignored AC test
`cargo test --test e2e_msc4191_live cross_signing_reset_round_trip_live -- --ignored`.
Extend it to assert the **upload-honored** property, covering BOTH master states:

1. **Bootstrapped-master case (must stay green):** provision a user, publish a master via a
   first `device_signing/upload` (200, MSC3967 no-UIA), then attempt a *second*
   `device_signing/upload` (the reset) → expect **401**. Drive the siwx-oidc reset reauth
   (`/account/wallet` or `/account/passkey/finish` with a valid single-use nonce) → assert
   the JSON outcome is `completed`. Then re-issue `device_signing/upload` within 10 min →
   **assert 200** (today's gap: this leg is what currently regresses to 401). Also assert,
   via the admin/DB probe in `skills/siwx-matrix-device-verify.md:255-268`, that
   `updatable_without_uia_before_ms` is in the future for that user's master row.

2. **Destructive-reset / no-current-master case (the actual incident — currently red):**
   reproduce the §1 sequence — delete the key backup + master and leave the public master
   unpublished — then call the siwx-oidc reset reauth. **Assert the contract:** the page
   must NOT render `completed`/"Encryption keys reset" unless a following
   `device_signing/upload` actually returns **200**. (Pre-fix this test FAILS: siwx-oidc
   returns `completed` while the upload still 401s — that failing assertion is the bug
   captured as a test.)

3. **Negative/keying guard:** run the reset reauth with a mixed-case wallet DID and assert
   the localpart sent to `/_synapse/mas/allow_cross_signing_reset` equals the lowercased
   localpart Synapse uses (regression lock for (c)).

Local stack to run against: the hermetic `docker-compose.e2e.yml` Synapse + siwx-oidc in
`../siwx-oidc-matrix-server` (see that repo's CLAUDE.md "Build and deployment model" and
`e2e-harness/`), with `SIWEOIDC_MATRIX_SERVER_NAME` + a Synapse client configured so
`execute_action` reaches the live MAS endpoint rather than the standalone `BadRequest`
degrade path.

## E. Citations (this section)

```
siwx-oidc (eff6044):
  src/account.rs:354-375      execute_action → Action::CrossSigningReset (success = MAS 2xx only)
  src/account.rs:374          Ok(ActionOutcome::Completed)               ← unconditional success
  src/account.rs:597-688      account_wallet  (reauth path → execute_action)
  src/account.rs:693-742      account_passkey_finish (reauth path → execute_action)
  src/account.rs:1608-1610    renderOutcome 'completed' → "Encryption keys reset" banner
  src/synapse_client.rs:130-148  allow_cross_signing_reset → POST /_synapse/mas/allow_cross_signing_reset {localpart}
  src/synapse_client.rs:141-146  only the HTTP status is inspected; no gate read-back
  src/oidc.rs:1513-1515       did_to_localpart = replace(':','-').to_lowercase()  (grant key)

Synapse v1.153.0 contract (cited in matrix-server docs, not vendored here):
  rest/client/keys.py:403                       upload gate: reject iff is_cross_signing_setup AND NOT master_key_updatable_without_uia
  rest/admin/users.py:1290-1318                 REPLACEMENT_PERIOD_MS = 10 min; sets updatable_without_uia_before_ms
  storage/databases/main/end_to_end_keys.py:1679-1716  UPDATE … WHERE keytype='master' (rowcount==0 if no master)
  → ../siwx-oidc-matrix-server/docs/2026-05-29-cross-signing-identity-stability-handover.md:29-30
  → ../siwx-oidc-matrix-server/skills/siwx-matrix-device-verify.md:249-273 (403/401 window-expiry symptom + DB probe)

Test slots:
  ../siwx-oidc-matrix-server/e2e-harness/run.sh:115   cross_signing_reset_round_trip_live
```

## F. Design-doc cross-check (did the code drift?)

- `docs/superpowers/plans/2026-05-29-cross-signing-identity-stability.md` (H3) and the
  matrix-server CLAUDE.md "Device lifecycle" deliberately moved `allow_cross_signing_reset`
  to be fired **only** on the explicit `account.rs` reset path (removing per-login resets).
  The code matches that intent — the single caller is `execute_action`
  (`src/account.rs:367`). **No drift there.**
- What the design docs **never specified** is a *post-grant effectiveness check* or the
  *no-current-master reset* case. The MAS-compat design
  (`docs/superpowers/specs/2026-05-18-msc3861-siwx-oidc-mas-compat-design.md:112,209`) and
  the handover both describe `allow_cross_signing_reset` only as "called → no verification
  prompt," implicitly assuming an already-bootstrapped master. The implementation faithfully
  encodes that optimistic assumption (success = MAS 2xx), so this is a **design gap carried
  verbatim into code**, not a regression from the documented design. The grace deploy
  (`db79e75..main`) does not touch any of these lines (confirmed in §5), so the bug is
  pre-existing and build-independent — consistent with the original causation verdict.
