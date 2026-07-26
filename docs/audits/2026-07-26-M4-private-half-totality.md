# M4 private half — closing the totality hole (T-M4)

**Date:** 2026-07-26
**Task:** Finding **T-M4** — `S4_Absent`, `S4_Present`, `S4_Rotated`, `Backup_Vn`, `Backup_Deleted`
are declared in the map's §M4 with **no transition table, no events, and no terminals**. The machine
is not total. This document makes it total.
**Branch / worktree:** `feat/session-durability-marathon` @ **`10c9494`**, `~/wt/siwx-durability`.
**Companion repo:** `siwx-oidc-matrix-server` `main` @ **`cd17c90`** (vendored Element patches).
**Authority:** `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md` §M4/§M4c
(notation, completeness criteria) · `docs/audits/2026-07-25-state-machine-coverage-matrix.md`
§5.7/§6/§10 · `docs/2026-07-26-FINISH-LINE-goal-confirmed-and-remaining-work.md` §1/§4 (task **A2**).
**Mode:** design/documentation only. **No code changed. No test run. No container touched. Nothing
committed.**

> **Labelling contract (inherited from the coverage matrix).**
> **VERIFIED** = backed by a `file:line`, a patch hunk, or a log line reproduced in a document named
> above. **ASSUMED** = a link in the chain I did not test; every one is in §11 with the single
> observation that would settle it. Matrix protocol behaviour I did not observe in this repo's
> evidence is **never** stated as fact. Where the map or an existing audit is the source, it is
> cited as such rather than re-derived.

---

## 1. Why the private half needs three regions, not one list

The map lists five private-half states in one column. They are not one machine: they are three
**orthogonal regions** (Harel-statechart sense) that a single event is broadcast to, and the bugs
this workstream exists to fix are precisely *disagreements between the regions*.

| Region | What it is | Owned by | Why it must be separate |
|---|---|---|---|
| **S** — secret storage (4S), server truth | which 4S key the account currently has, and which secrets are encrypted under it | Synapse `account_data` | This is the only durable truth. It survives every client wipe. |
| **B** — megolm key backup, server truth | which backup version exists and whether its key is reachable from 4S | Synapse `room_keys` API | A *different artifact* from 4S. Conflating the two is a recorded, expensive error (recovery-entry audit §3.3: `room_keys/version` 200 was cited as proof 4S was healthy; it is not). |
| **D** — this device's view of 4S | locked / unlocked / **indeterminate** | client crypto store + probe | Every destructive bug in the register (U3′) is region D mis-reading region S. The indeterminate value has to be a *state*, not an error path, or the invariant in §9 cannot be stated. |

Collapsing these into one column is what produced the map's hole: an event like
`backup_deleted_with_XS_present` has a different answer in each region, so it has no answer at all
in a single-column model.

**Composite state** of the private half is therefore the triple `(S, B, D)`. Terminals are emitted
by the composite, not by a region — that is why §5's terminals are listed once and referenced from
all three tables.

---

## 2. State table — Region S (secret storage, server truth)

Observable via a **raw authed** `GET /_matrix/client/v3/user/{userId}/account_data/{type}` — the
same request `e2e/element/ew-recovery-entry.spec.mjs:130-141` issues and the same one the vendored
patch issues (`force-first-device-recovery.patch`, `client.http.authedRequest("GET", …)`). The raw
form is load-bearing: js-sdk 41.6.0's `getAccountDataFromServer` short-circuits to the local store
once the persisted store reports initial-sync complete and never touches the network
(VERIFIED — `00e76f4` commit message, reproduced in coverage matrix §6.3).

| State | Meaning | Observable (concrete) |
|---|---|---|
| **`S4_Absent`** | no secret storage at all | `m.secret_storage.default_key` → **404 `M_NOT_FOUND`** |
| **`S4_Present`** | recovery key usable **and it unlocks the identity** | `m.secret_storage.default_key` → 200 `{"key":"<keyId>"}`; `m.secret_storage.key.<keyId>` → 200; **and** `m.cross_signing.master` → 200 with `encrypted["<keyId>"]` present |
| **`S4_MasterUnstored`** *(NEW — see §10.3)* | a recovery key exists but recovers nothing | `default_key` → 200, `m.secret_storage.key.<keyId>` → 200, **but** `m.cross_signing.master` → 404, **or** 200 whose `encrypted` map has no entry for the current `<keyId>` |
| **`S4_Rotated`** | `default_key` now names a **different** key id than the one the user was issued | `default_key.key` ≠ the key id recorded at the last issuance/successful unlock. **Not observable from a single read** — see §10.1 |

Also read by the same mechanism and referenced below: `m.cross_signing.self_signing`,
`m.cross_signing.user_signing`, `m.megolm_backup.v1` (the backup **decryption key**, stashed in 4S —
VERIFIED as an account_data type by the 2026-06-24 forensic access log, `PUT …/account_data/m.megolm_backup.v1` 200).

## 3. State table — Region B (megolm key backup, server truth)

| State | Meaning | Observable (concrete) |
|---|---|---|
| **`Backup_None`** | no backup version has ever existed | `GET /_matrix/client/v3/room_keys/version` → **404**, no prior 200 on record |
| **`Backup_Vn`** | version *n* exists **and is reachable** | `GET …/room_keys/version` → 200 (`version`, `algorithm`, `auth_data`, `etag`) **and** `m.megolm_backup.v1` → 200 with `encrypted["<current default keyId>"]` |
| **`Backup_VnUnreadable`** *(NEW)* | version exists, its key is not reachable from the current 4S | `GET …/room_keys/version` → 200 **and** `m.megolm_backup.v1` → 404, or 200 with no `encrypted` entry for the current key id |
| **`Backup_Deleted`** | a version existed and was destroyed | `GET …/room_keys/version` → **404** *plus a recorded prior 200 or a `DELETE …/room_keys/version/{n}` in the log*. **Observationally identical to `Backup_None` at a single point in time** — see §10.2 |

All four API shapes are VERIFIED from the 2026-06-24 forensic access log: `GET /room_keys/version`
200 (513 B) → `DELETE /room_keys/version/3` 200 → `GET /room_keys/version` **404** →
`POST /room_keys/version` 200 (returns `"4"`) → `GET /room_keys/keys/!…/<sessionId>?version=4`
**404 ×7** (the old sessions are not in the new version).

## 4. State table — Region D (this device's view of 4S)

| State | Meaning | Observable (concrete) |
|---|---|---|
| **`S4_DevLocked`** | server 4S read **definitively** (200 or 404), key not held locally | `crypto.isSecretStorageReady()` → `false`; patch log line `shouldForceVerification: crossSigningReady=… secretStorageReady=false hasServer4S=<true\|false>` |
| **`S4_DevUnlocked`** | 4S key held/cached on this device | `crypto.isSecretStorageReady()` → `true`; `SetupEncryptionStore.keyInfo` non-null (`keyId` set); `window.mxSetupEncryptionStore` sampled by `ew-recovery-entry.spec.mjs::gateState` |
| **`S4_DevIndeterminate`** *(NEW)* | the server probe **errored** (not a 404) — existence unknown | the raw authed GET rejected with `e?.errcode !== "M_NOT_FOUND"`; same patch log line with `hasServer4S=false` **while no 404 was received** |

`S4_DevIndeterminate` is the state the whole U3′ incident class lives in. Naming it is what lets
§9's invariant be checked mechanically instead of argued.

**The patch log line is a real, greppable observable** (VERIFIED — `force-first-device-recovery.patch`
adds `logger.info("shouldForceVerification: crossSigningReady=… secretStorageReady=… hasServer4S=…")`,
described in its own comment as an "ops breadcrumb"). It satisfies the map's §0 criterion 1
("log field") for region D.

---

## 5. Terminals

Every terminal names what the **user** sees and what action they have. Naming convention follows
the map (`T_` prefix); the `OK_/FAIL_/RECOVER_` kind from §0 criterion 3 is given in the Kind column.

| Terminal | Kind | What the user sees | Action available to the user |
|---|---|---|---|
| **`T_S4_KeyIssued`** | OK | Recovery-key creation wizard completed; the key is displayed once | Save it. **Required:** the wizard must not report success until `m.cross_signing.master` is stored under the new key (see §10.3) |
| **`T_S4_Ready`** | OK | App shell, verified session, history decrypts | none needed |
| **`T_S4_UnlockOk`** | OK | "Device verified" | Click **Done** → hands to M4c `T_C_OkAwaitAck` → `T_C_App` |
| **`T_S4_UnlockRefused`** | FAIL (recoverable, **non-destructive**) | "That recovery key didn't work" | Retry; try another key; use another device. **Required:** must never auto-escalate to a reset, and must never write to the server |
| **`T_S4_NoEntry`** | **FAIL (stuck) — BREACH** | Verify gate with **no recovery-key field**, even though the user holds a key | None non-destructive. This is **U6**'s terminal (`store.keyInfo == null`). It breaches the map's §0 crit. 3 and the FINISH-LINE "exit-bearing" property, the same way `T_C_Wedged` does for M4c |
| **`T_S4_Orphaned`** | **FAIL (silent + destructive) — BREACH** | *Success.* A new recovery key was minted; the one in the user's hand is now stale | None, unless they saved the new key at the moment it was shown. This is **U3′**'s terminal |
| **`T_S4_HistoryLost`** | DESTRUCTIVE, irreversible | Old messages show "Unable to decrypt" | Only a device that still holds those megolm sessions locally can re-upload them into the current version (**ASSUMED — A5**). Otherwise none |
| **`T_S4_BackupUnreadable`** | FAIL (recoverable) | Backup exists; messages still won't decrypt | Unlock 4S on a device that holds `m.megolm_backup.v1`, or re-store the backup key into the current 4S |
| **`T_S4_ResetIsOnlyExit`** | RECOVER-with-loss | Gate offering "Can't confirm? → reset identity" and "Sign out" | (1) Reset, accepting the loss — **required:** only after an honest destruction preview; (2) sign out and use a device that still has a live session; (3) contact an admin. Nothing else exists |
| **`T_S4_Abandoned`** | FAIL (clean) | Signed out at the gate | Sign in again. **Required:** signing out at the gate must never delete 4S or the backup |
| **`T_S4_IllegalEvent`** | explicit rejection | nothing (the operation is refused) | Retry the correct operation. **Required:** logged as `s4_illegal_transition` with `{state, event}`. **This is a defined rejection, never a silent ignore** |

`T_S4_NoEntry` and `T_S4_Orphaned` are marked BREACH deliberately: they are named so they can be
**eliminated**, exactly as `T_C_Wedged` was. A total machine is allowed to contain named bad
terminals; it is not allowed to contain unnamed ones.

---

## 6. Event alphabet (13)

Broadcast to all three regions. Every event is user-reachable.

| # | Event | Trigger / observable |
|---|---|---|
| e1 | `first_device_bootstrap` | forced recovery wizard on a first device (patch hunk 2 loop) |
| e2 | `unlock_with_recovery_key_ok` | user types the correct key into `AccessSecretStorageDialog` |
| e3 | `unlock_with_recovery_key_wrong` | user types a key that fails the client-side check |
| e4 | `probe_4s_indeterminate` | the raw authed GET for `m.secret_storage.default_key` rejects with a non-`M_NOT_FOUND` error |
| e5 | `reset_identity_confirmed` | `ResetIdentityDialog` completed / `accessSecretStorage(…, {forceReset:true})` |
| e6 | **`4S_key_rotated_while_master_stale`** ★ | a new `m.secret_storage.default_key` is written while the server's **public** cross-signing master is absent or does not correspond to the private master now being encrypted (i.e. `device_signing/upload` not yet accepted) |
| e7 | **`backup_deleted_with_XS_present`** ★ | `DELETE /room_keys/version/{n}` → 200 while the public half is `XS_Present` |
| e8 | **`recovery_key_lost_with_no_second_device`** ★ | user reaches the gate, has no recovery key, and has no other live verified session |
| e9 | `backup_version_created` | `POST /room_keys/version` → 200 |
| e10 | `verify_from_second_device_sas` | SAS/emoji verification completes from a live session (the `EW-V1` path) |
| e11 | `xs_upload_rejected_401` | `POST /keys/device_signing/upload` → 401 |
| e12 | `hard_logout_crypto_wipe` | the L1→L4 chain: introspection inactive → `M_UNKNOWN_TOKEN` → Element wipes the crypto store |
| e13 | `gate_signout` | user chooses "Sign out" at the verify gate (or dismisses the patch's Retry/Sign-out dialog) |

---

## 7. Total transition tables

**11 non-terminal states × 13 events = 143 cells, all filled.** Notation: `→ X` next state within
the region; `⟳` self-loop with **no server write** (a *defined* no-op, explicitly not "ignored");
`⟹ T_x` terminal emitted by the composite; `⊘` explicit rejection → `T_S4_IllegalEvent`, logged.
Rows marked **REQ** state required behaviour that current code does **not** implement; they are
collected in §10.4.

### 7.1 Region S — 4 states × 13 = 52 cells

| Event | `S4_Absent` | `S4_Present` | `S4_MasterUnstored` | `S4_Rotated` |
|---|---|---|---|---|
| e1 `first_device_bootstrap` | → `S4_Present` ⟹ `T_S4_KeyIssued` | ⊘ (4S already exists — creating here **is** U3′) | → `S4_Present` (**repair**: store master under the *existing* key; **REQ** must not mint a new key) | ⊘ |
| e2 `unlock_ok` | ⊘ (nothing to unlock; a client claiming success here is lying) | ⟳ ⟹ `T_S4_UnlockOk` | ⟳ — key opens, identity does **not** restore → route to e10, else ⟹ `T_S4_ResetIsOnlyExit` | ⟳ ⟹ `T_S4_UnlockOk` (new key only) |
| e3 `unlock_wrong` | ⟳ ⟹ `T_S4_UnlockRefused` (**REQ** reason must be "no secret storage on this account", never "wrong key") | ⟳ ⟹ `T_S4_UnlockRefused` | ⟳ ⟹ `T_S4_UnlockRefused` | ⟳ ⟹ `T_S4_UnlockRefused` (**REQ** reason must name the rotation, see §8.1) |
| e4 `probe_4s_indeterminate` | ⟳ | ⟳ | ⟳ | ⟳ — server truth is unaffected by a failed read; the decision belongs to region D |
| e5 `reset_identity_confirmed` | → `S4_Present` ⟹ `T_S4_KeyIssued` (nothing to lose) | → `S4_Rotated` ⟹ `T_S4_Orphaned` **+** region B loss (§7.2) | → `S4_Rotated` ⟹ `T_S4_KeyIssued` (here reset is the *correct* identity remedy) | → `S4_Rotated` ⟹ `T_S4_Orphaned` — **the observed U3 churn** |
| e6 **`4S_rotated_while_master_stale`** ★ | → `S4_Present` ⟹ `T_XS_HalfReset` | → `S4_Rotated` ⟹ `T_S4_Orphaned` **+** `T_XS_HalfReset` | → `S4_Rotated` ⟹ `T_XS_HalfReset` | → `S4_Rotated` ⟹ `T_XS_HalfReset`; **REQ** a second rotation with the master still stale must be **refused** |
| e7 **`backup_deleted_with_XS_present`** ★ | ⟳ | ⟳ — 4S untouched, but `m.megolm_backup.v1` now points at a version that no longer exists | ⟳ (same) | ⟳ (same) |
| e8 **`recovery_key_lost_with_no_second_device`** ★ | ⟳ ⟹ `T_S4_ResetIsOnlyExit` (cheap — nothing to lose in S) | ⟳ ⟹ `T_S4_ResetIsOnlyExit` | ⟳ ⟹ `T_S4_NoEntry` **then** `T_S4_ResetIsOnlyExit` (**REQ** the two must be told apart in the message) | ⟳ ⟹ `T_S4_ResetIsOnlyExit`, message naming the rotation |
| e9 `backup_version_created` | ⟳ (backup key cannot be stored — see B) | ⟳ | ⟳ | ⟳ **REQ** `m.megolm_backup.v1` must be re-encrypted under the current key id |
| e10 `verify_from_second_device_sas` | ⟳ ⟹ `T_S4_Ready` (cross-signed with **no 4S at all**) | ⟳ ⟹ `T_S4_Ready` | → `S4_Present` (**repair**: the device now holds the master privately and can store it) | ⟳ ⟹ `T_S4_Ready` |
| e11 `xs_upload_rejected_401` | ⟳ | ⟳ | ⟳ | ⟳ — couples to public `XS_UploadRejected`; **REQ** alert after N=3 consecutive (plan P4) |
| e12 `hard_logout_crypto_wipe` | ⟳ | ⟳ | ⟳ | ⟳ — **server 4S survives a client wipe**; only region D resets |
| e13 `gate_signout` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` |

### 7.2 Region B — 4 states × 13 = 52 cells

| Event | `Backup_None` | `Backup_Vn` | `Backup_VnUnreadable` | `Backup_Deleted` |
|---|---|---|---|---|
| e1 `first_device_bootstrap` | → `Backup_Vn` | ⊘ (a backup already exists) | → `Backup_Vn` (**repair**: re-store the key; **REQ** not re-create) | → `Backup_Vn` (fresh version; the deleted history is already gone) |
| e2 `unlock_ok` | ⟳ | ⟳ — becomes readable *on this device* (region D) | ⟳ → readable iff the key is under the unlocked 4S | ⟳ |
| e3 `unlock_wrong` | ⟳ | ⟳ | ⟳ | ⟳ |
| e4 `probe_4s_indeterminate` | ⟳ | ⟳ | ⟳ | ⟳ |
| e5 `reset_identity_confirmed` | → `Backup_Vn` (created fresh) | → **`Backup_Deleted`** ⟹ **`T_S4_HistoryLost`**, then → `Backup_Vn′` | → `Backup_Deleted` ⟹ `T_S4_HistoryLost` (loss is real: a later unlock could have recovered it) | ⟳ |
| e6 **`4S_rotated_while_master_stale`** ★ | ⟳ | → `Backup_Vn` re-wired to the **new** key — reachable only with the **new** recovery key, so ⟹ `T_S4_BackupUnreadable` **for a user holding the old one** | ⟳ | ⟳ |
| e7 **`backup_deleted_with_XS_present`** ★ | ⊘ (nothing to delete) | → **`Backup_Deleted`** ⟹ **`T_S4_HistoryLost`** | → `Backup_Deleted` ⟹ `T_S4_HistoryLost` | ⟳ (idempotent no-op) |
| e8 **`recovery_key_lost_with_no_second_device`** ★ | ⟳ (nothing to lose) | ⟳ — backup intact but **unreachable in practice**; **REQ** its size must be quoted in the reset preview | ⟳ | ⟳ |
| e9 `backup_version_created` | → `Backup_Vn` if the key is stored in 4S, else → `Backup_VnUnreadable` | → `Backup_Vn′`; **REQ** creating a version while one exists must be refused or explicitly confirmed (this is the churn shape) | → `Backup_Vn′` | → `Backup_Vn` |
| e10 `verify_from_second_device_sas` | ⟳ | ⟳ — backup key may arrive by secret gossip (**ASSUMED — A4**) | ⟳ → `Backup_Vn` if the key gossips in | ⟳ |
| e11 `xs_upload_rejected_401` | ⟳ | ⟳ | ⟳ | ⟳ |
| e12 `hard_logout_crypto_wipe` | ⟳ | ⟳ | ⟳ | ⟳ — **the server-side backup survives** |
| e13 `gate_signout` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` | ⟳ ⟹ `T_S4_Abandoned` |

### 7.3 Region D — 3 states × 13 = 39 cells

| Event | `S4_DevLocked` | `S4_DevUnlocked` | `S4_DevIndeterminate` |
|---|---|---|---|
| e1 `first_device_bootstrap` | → `S4_DevUnlocked` | ⊘ | ⊘ **INVARIANT** — must resolve the probe first (§9) |
| e2 `unlock_ok` | → `S4_DevUnlocked` | ⟳ | → `S4_DevUnlocked` — a successful unlock is itself definitive proof 4S exists |
| e3 `unlock_wrong` | ⟳ ⟹ `T_S4_UnlockRefused` | ⊘ | ⟳ ⟹ `T_S4_UnlockRefused` — **REQ** a wrong key is **not** evidence of absence and must never flip the branch to "create" |
| e4 `probe_4s_indeterminate` | → **`S4_DevIndeterminate`** | ⟳ (key already held; the probe is irrelevant) | ⟳ |
| e5 `reset_identity_confirmed` | → `S4_DevUnlocked` (new key) | → `S4_DevUnlocked` (new key) | ⊘ **INVARIANT — the load-bearing cell.** A destructive branch on an indeterminate probe is forbidden (§9). Current code satisfies this: `.catch(e => e?.errcode !== "M_NOT_FOUND")` resolves indeterminate to *4S exists* ⇒ **unlock** (VERIFIED, `cb75cce` + `00e76f4`) |
| e6 **`4S_rotated_while_master_stale`** ★ | ⟳ (rotated elsewhere) / → `S4_DevUnlocked` (this device rotated) | → `S4_DevLocked` if another device rotated — the cached key is no longer the current default (**ASSUMED — A2**) | → `S4_DevLocked` |
| e7 **`backup_deleted_with_XS_present`** ★ | ⟳ | ⟳ | ⟳ (4S key cache unaffected) |
| e8 **`recovery_key_lost_with_no_second_device`** ★ | ⟳ ⟹ `T_S4_ResetIsOnlyExit` | ⟳ — **not** a dead end: **REQ** offer "create a new recovery key" from this healthy session (`ChangeRecoveryKey.tsx` is present in the build, recovery-entry audit C9). This is the pre-emptive fix | resolve probe, then as `S4_DevLocked` |
| e9 `backup_version_created` | ⟳ | ⟳ | ⟳ |
| e10 `verify_from_second_device_sas` | → **`S4_DevUnlocked`** (VERIFIED, §8.3) | ⟳ | ⟳ (probe unresolved; do not act on it) |
| e11 `xs_upload_rejected_401` | ⟳ | ⟳ | ⟳ |
| e12 `hard_logout_crypto_wipe` | ⟳ | → `S4_DevLocked` | → `S4_DevLocked` |
| e13 `gate_signout` | ⟳ ⟹ `T_S4_Abandoned` | → `S4_DevLocked` ⟹ `T_S4_Abandoned` | → `S4_DevLocked` ⟹ `T_S4_Abandoned` |

---

## 8. The three named events — explicit answers

### 8.1 `4S_key_rotated_while_master_stale`

**Definition.** A new `m.secret_storage.default_key` is written while the account's **public**
cross-signing master on Synapse is absent, or does not correspond to the private master now being
encrypted into the new 4S — operationally, while `POST /keys/device_signing/upload` is being
rejected (401) or has not been attempted.

**This is the 2026-06-24 production incident, exactly.** VERIFIED from the forensic access log:
`DELETE /room_keys/version/3` → new `m.cross_signing.{master,self_signing,user_signing}` PUTs → new
`m.secret_storage.key.1Xcfx…` → new `default_key` → **`device_signing/upload` 401 ×14**. A second
rotation (`m.secret_storage.key.73u9…`) followed in the same session.

**Answer (machine).**

| Region | Result |
|---|---|
| S | `S4_Present` → `S4_Rotated`; emits **`T_S4_Orphaned`** *and* **`T_XS_HalfReset`** (public half) |
| B | `Backup_Vn` → re-wired to the new key ⇒ **`T_S4_BackupUnreadable`** for a user holding the old key; if the rotation was part of a reset, `Backup_Vn` → `Backup_Deleted` ⇒ **`T_S4_HistoryLost`** first |
| D | this device → `S4_DevUnlocked` under the **new** key; every other device → `S4_DevLocked` |
| Second occurrence | **refused** (`⊘`, logged `s4_illegal_transition`) — the churn in the forensic is a defect, not a retry |

**What the user sees.** Nothing wrong at first: encrypted sending keeps working (VERIFIED — the
forensic user sent an encrypted message at 05:39:21 while in this state). The damage surfaces later
as (a) other devices/users cannot verify this identity, (b) the recovery key in their hand no longer
opens 4S, (c) old messages do not decrypt.

**What the user can do.** Exactly one non-destructive path exists and it is a server action, not a
client one: re-authenticate at `/account?action=org.matrix.cross_signing_reset` so the reset is
effectively authorised, then let the client retry `device_signing/upload` → 200 → `T_XS_OK`. If that
grant is ineffective, `reset_outcome` must report `ResetUnconfirmed`, never `Completed`
(invariant **I4**; `src/account.rs:430`).

**Required guards (none implemented today).**
1. The client must not rotate 4S until the public upload has been **accepted**, or must roll the
   rotation forward on the next successful upload rather than minting a second key.
2. `xs_upload_rejected_401` ×3 consecutive for one user ⇒ alert + steer the client to the account
   management URI (plan **P4**, unwritten).
3. `T_S4_UnlockRefused` in `S4_Rotated` must say *"your recovery key was replaced"*, not *"wrong
   key"* — this is the only signal that makes `T_S4_Orphaned` visible to the person it happened to.

### 8.2 `backup_deleted_with_XS_present`

**Definition.** `DELETE /_matrix/client/v3/room_keys/version/{n}` → 200 while the public half is
`XS_Present` (a valid published master exists).

**Answer (machine).**

| Region | Result |
|---|---|
| B | `Backup_Vn` → **`Backup_Deleted`**, emits **`T_S4_HistoryLost`** (irreversible) |
| S | ⟳ — 4S is untouched, but `m.megolm_backup.v1` now names a version that does not exist |
| D | ⟳ |
| From `Backup_None` | `⊘` — nothing to delete |
| From `Backup_Deleted` | ⟳ — idempotent no-op, not an error |

**The key judgement: with `XS_Present` this deletion buys nothing.** The identity is already
published and valid, so there is no cross-signing problem for the deletion to solve. It is pure loss.
That makes it the clearest case in the whole private half for the **C4 prefer-unlock-over-reset**
guard: `reset_identity` must decompose into `reset_cross_signing` / `reset_secret_storage` /
`delete_backup`, and when the public master is present and healthy, `delete_backup` must not be part
of the default bundle. Element 1.12.20 bundles them — VERIFIED by the forensic ordering, where the
`DELETE` is the *opening* move, before any new secret is written.

**What the user sees.** Immediately: nothing. Later: "Unable to decrypt" on messages that predate the
deletion, and `GET /room_keys/keys/…?version=<new>` → 404 for those sessions (VERIFIED, 7× in the
forensic).

**What the user can do.** After the fact, essentially nothing: a deleted version is gone. The only
recovery is a device that still holds those megolm sessions in its local store re-uploading them into
the current version (**ASSUMED — A5**). **Therefore the whole remedy has to be preventive:** an
honest destruction preview *before* the DELETE, quoting how many sessions are about to become
unreachable, and a confirmation that is not the default action.

### 8.3 `recovery_key_lost_with_no_second_device`

**Definition.** The user is at the verify gate, cannot supply a recovery key, and has no other live
verified session. This is context **C5** of the recovery-entry audit — the R5/R6 row.

**Answer (machine).** Nothing changes on the server (⟳ in S and B; ⟳ in D). The event resolves to a
**terminal choice**, and which terminals fire depends on region S:

| Region S | Terminal(s) | Honest message the user must get |
|---|---|---|
| `S4_Absent` | `T_S4_ResetIsOnlyExit` | "No recovery key was ever set up for this account. Setting one up now protects you next time." Cost: **none** in S |
| `S4_Present` | `T_S4_ResetIsOnlyExit` | "A recovery key exists but you don't have it. Resetting will replace it and **make N backed-up conversations unreadable**." |
| `S4_MasterUnstored` | `T_S4_NoEntry` **then** `T_S4_ResetIsOnlyExit` | "Your recovery key cannot restore this identity — the master key was never stored in it." **This must not be shown as 'wrong key'** |
| `S4_Rotated` | `T_S4_ResetIsOnlyExit` | "Your recovery key was replaced on `<date>`; the one you hold is no longer current." |

**What the user can do — the complete, closed set (three options, nothing else exists):**
1. **Reset**, accepting the loss — permitted **only** after the destruction preview above, and
   **only** from `S4_DevLocked` or `S4_DevUnlocked`, never from `S4_DevIndeterminate` (§9).
2. **Sign out** and return from a device that still has a live verified session, then use SAS
   (`verify_from_second_device_sas`) — non-destructive, and it needs no phrase at all.
3. **Ask an admin.** No server-side recovery exists and none should: `/account`'s action set is
   identity re-auth, not E2EE recovery (recovery-entry audit C7/C8 — a recovery phrase on those
   pages would be a category error).

**The current defect at this exact terminal, and it is upside-down.** `SetupEncryptionBody.tsx:139`
reaches `ResetIdentityDialog` with `variant: store.lostKeys() ? "no_verification_method" : "confirm"`
(cited in coverage matrix §6.1) — i.e. the destructive branch is offered **more readily precisely
when the user has least to fall back on**. That is the inverse of what this terminal requires.

**One measured fact that keeps option 2 real.** After SAS from a live session, the joining device
measured `crossSigningReady && secretStorageReady`, `privateKeysCachedLocally {master,self,user} =
true`, with a to-device tally of 7 `m.secret.request` answered by 4 encrypted sends
(VERIFIED — `e2e/element/ew-verify-sas.spec.mjs` header, three consecutive runs). So option 2 really
does reach `S4_DevUnlocked` with **no phrase typed**; it is the single most valuable non-destructive
exit in the private half, and it is the reason this terminal is `RECOVER-with-loss` rather than
`FAIL`.

---

## 9. Invariants (one inherited, three new)

- **I-S1 (inherited, from coverage matrix §10).** *"Fail toward enforcement" is safe for a **gate**
  and unsafe for a **destructive action**.* Formally, on the now-total machine:
  **no transition out of `S4_DevIndeterminate` may be destructive.** Cells `D×e1`, `D×e5` are `⊘`
  for exactly this reason. Current code satisfies it (`cb75cce`, `00e76f4`); it is **unwatched**
  (FINISH-LINE §3 #1 — task **B2**).
- **I-S2 (new).** *`T_S4_UnlockRefused` never writes to the server.* A wrong key is a client-side MAC
  failure; it must not be an input to any create/rotate/delete decision.
- **I-S3 (new).** *No terminal in the private half may leave the user with zero non-destructive
  options while region S is `S4_Present`.* `T_S4_NoEntry` is the name for breaching it — the private
  half's analogue of **I-C1**.
- **I-S4 (new).** *Any transition that makes previously-backed-up sessions unreachable must be
  preceded by a preview that quantifies the loss.* Covers `e5` and `e7`. Without it, `T_S4_HistoryLost`
  is silent, and §10.2 shows the user cannot detect it afterwards either.

---

## 10. Where the map is now wrong, contradictory, or incomplete

### 10.1 `S4_Rotated` fails the map's own observability criterion

Map §0 criterion 1 requires every state to be observable. `S4_Rotated` is **not observable from a
single point-in-time read**: `m.secret_storage.default_key` returns a key id, and nothing in the
response says whether that id is the one the user was issued. Detecting rotation requires a recorded
prior value.

**Cheap fix, already half-built:** `ew-recovery-entry.spec.mjs:167` already captures
`default_key_id`. Persisting the issued key id (client-side at issuance, and/or as an ops log line at
each `PUT …/default_key`) makes `S4_Rotated` observable and makes the §8.1 "your key was replaced"
message possible. Until then the state is **inferable, not observable**, and the map overstates it.

### 10.2 `Backup_Deleted` is indistinguishable from `Backup_None`

Both are `GET /room_keys/version` → 404. The map lists `Backup_Deleted` as a state with the
observable "DELETE room_keys/version", which is an **event**, not a state observable. A user (or a
support engineer) who arrives after the fact **cannot tell "you never had a backup" from "your backup
was destroyed"**. That is the precise mechanism by which **U4 is silent**, and it is why §9's I-S4
puts the whole remedy before the deletion.

### 10.3 `S4_Present` conflates two states with opposite user outcomes

The map's `S4_Present` ("recovery key usable") covers both "master stored under the key" and "master
not stored". Those differ in the only way that matters at the gate: the "Use recovery key" button
renders **iff** `store.keyInfo != null`, and `keyInfo` comes from
`secretStorage.isStored("m.cross_signing.master")` (`SetupEncryptionStore.ts:90-100`, and the shipped
js-sdk 41.6.0 `isStored` is a **server** read — VERIFIED by verbatim extraction from the live lab
bundle, recovery-entry audit §3.2). One sub-state ends in `T_S4_UnlockOk`; the other ends in
`T_S4_NoEntry`, a stuck terminal.

**This is the same class of error M4c was created to fix** — two states with opposite kinds sharing
one name, so a success and a trap are the same observation.

Honesty note on reachability: `EW-R1-0` **passed**, i.e. after the mandatory first-device wizard the
master **is** stored in 4S (`2026-07-25-verify-gate-root-cause-SETTLED.md:175`). So
`S4_MasterUnstored` is **not** the normal outcome of the C1 wizard. It stays in the machine because
(a) the wizard's success condition still only proves a default key exists
(`recoverySetUp = !(await this.shouldForceVerification())` — VERIFIED in the patch), so nothing
*prevents* it, and (b) it is the only state in which `T_S4_NoEntry` can legitimately fire, and that
terminal needs a home.

### 10.4 The map's M4 private half has no `REQ` for the client's unlock-vs-reset choice

The map's only private-half-adjacent row is
`XS_Present | unlock with recovery key | stay XS_Present, secrets local`. Two problems:
it never states that an unlock is a **no-server-write** operation (which is what makes
`T_S4_UnlockRefused` safe), and it has **no event at all** for the case the forensic actually
recorded — a client with a valid 4S present choosing **reset** anyway. Event `e5`/`e6` now cover it.

### 10.5 `U3` is an event, not a state

Coverage matrix §6.1 lists U3 "double 4S churn mid-loop" in the undefined-**states** register. It is a
second occurrence of `e6`. It is now the `S4_Rotated × e6` cell, with the required behaviour
("refuse the second rotation") attached to it.

### 10.6 Counts in the coverage matrix are now understated

§5.7 counts 13 M4 states, of which 6 are Uncovered — and of those 6, **4** are in the private half
(`S4_Absent`, `S4_Rotated`, `Backup_Vn`, `Backup_Deleted`; `S4_Present` is Partial, not Uncovered).
The task brief's "six of the sixteen uncovered states live here" is right about M4 as a whole and
slightly generous about the private half specifically.

This document adds **6 non-terminal states** (`S4_MasterUnstored`, `Backup_None`,
`Backup_VnUnreadable`, `S4_DevLocked`, `S4_DevUnlocked`, `S4_DevIndeterminate`) and **11 terminals**
where the map named zero. The matrix's headline "72 states" becomes ~**89**, and every one of the 17
additions is currently **Uncovered**. Per the M4c precedent, this should be **appended** as a dated
section rather than merged into §5.7, whose provenance is pinned to `dd34e3f`.

---

## 11. U2 and U4 on the now-total machine

### U2 — private 4S reset without public publish (the half-reset)

| | Mapping |
|---|---|
| **Composite state** | `S = S4_Rotated` · `B = Backup_Deleted → Backup_Vn′` · `D = S4_DevUnlocked (new key)` × public `XS_UploadRejected` |
| **Reached by** | `e6 4S_key_rotated_while_master_stale`, then `e11 xs_upload_rejected_401` ×N |
| **Terminal** | `T_XS_HalfReset` (public half) + `T_S4_Orphaned` + `T_S4_HistoryLost` |
| **Defined recovery transition (this was missing)** | `/account?action=org.matrix.cross_signing_reset` → effective allow → `device_signing/upload` **200** → `T_XS_OK`. If the allow is not effective, `reset_outcome` ⇒ `ResetUnconfirmed`, and the user is told to ask an admin — never a success banner (**I4**) |
| **Detection (unwritten)** | `e11` ×3 consecutive for one user ⇒ alert (plan **P4**) |
| **Guards** | §8.1 REQ 1–3 |
| **Status** | Was "CONFIRMED — fully open" with *no constructor test, no recovery transition, no alert* (matrix §6.1). The recovery transition and the detection rule are now **specified**; the constructor test remains FINISH-LINE task **C3** |

### U4 — history keys destroyed by reset

| | Mapping |
|---|---|
| **Transition** | Region B: `Backup_Vn --e5 reset_identity_confirmed--> Backup_Deleted`, and equally `--e7 backup_deleted_with_XS_present-->` |
| **Terminal** | `T_S4_HistoryLost` — irreversible |
| **Why it is silent** | §10.2 — `Backup_Deleted` and `Backup_None` are the same observation afterwards |
| **Why it is over-offered** | `variant: store.lostKeys() ? "no_verification_method" : "confirm"` — the destructive dialog is presented most readily in exactly the state (`e8`) where the user has least to fall back on |
| **Guards (now stated as invariants)** | **I-S4** (quantified preview before any history-destroying transition) and the §8.2 decomposition of `reset_identity`: with `XS_Present`, `delete_backup` must not be in the default bundle |
| **Status** | Was "CONFIRMED — fully open". Now has a named terminal, a defined trigger set (`e5`, `e7`), an invariant, and a product guard specification — FINISH-LINE task **C4** |

---

## 12. Assumptions register

| ID | Assumption | Status | Settled by |
|---|---|---|---|
| **A1** | A recovery key derived for key id *X* cannot open a 4S key id *Y* (so `S4_Rotated` really does strand the held key) | **ASSUMED** — follows from distinct key descriptors with distinct MAC data, not observed here | Lab: rotate 4S, then enter the *old* key; expect the client-side MAC check to reject |
| **A2** | After another device rotates 4S, this device's `isSecretStorageReady()` goes false (Region D `e6`) | **ASSUMED** | Two-context lab: rotate from B, sample `isSecretStorageReady()` on A |
| **A3** | `POST /room_keys/version` while a version exists creates a *new* version and leaves the old one queryable by id until deleted | **ASSUMED** | Lab: `POST` twice, then `GET /room_keys/version/{first}` |
| **A4** | Secret gossip after SAS carries the **megolm backup key** (`m.megolm_backup.v1`), not only the cross-signing secrets | **ASSUMED** — `EW-V1` measured `secretStorageReady=true` and cached cross-signing private keys, but did not isolate the backup key | Extend `EW-V1`: after SAS, assert device B can read a pre-existing backed-up session |
| **A5** | A device still holding megolm sessions locally can re-upload them into a new backup version (the only stated exit from `T_S4_HistoryLost`) | **ASSUMED** | Lab: delete the version from device B, create a new one from device A, assert the old sessions appear in it |
| **A6** | `GET /room_keys/version` carries a session **count** usable for the I-S4 destruction preview | **ASSUMED** — the forensic records a 513-byte 200 body but not its fields | One authenticated `GET /room_keys/version` in the lab; read the body |
| **A7** | `bootstrapSecretStorage` without `forceReset` reuses an existing key and stores missing secrets under it (Region S `e1` from `S4_MasterUnstored` = repair, not re-create) | **ASSUMED** | Lab: delete `m.cross_signing.master` account_data, re-run the wizard, assert `default_key.key` is unchanged |
| **A8** | `S4_MasterUnstored` is reachable in production at all | **ASSUMED, and partly refuted** — `EW-R1-0` PASS shows the C1 wizard does store the master; nothing *prevents* the state, so it remains in the machine | An `S4_MasterUnstored` constructor test (delete the master account_data, then open the gate) — also the constructor for `T_S4_NoEntry` |
| **A9** | Element 1.12.20 bundles reset + backup-delete (the basis for the §8.2 decomposition requirement) | **VERIFIED for the observed instance** (forensic ordering: DELETE is the opening move); **ASSUMED as invariant client behaviour** | Read `ResetIdentityDialog` / `resetEncryption` in the vendored tree |

---

## 13. What this document does not do

- It defines **no new code and changes none.** Every `REQ` row is a specification for FINISH-LINE
  Phase C (C3, C4) or Phase B (B2), not an applied change.
- It **runs no test.** `e2e/element` and `e2e/browser` were not invoked (the Element lab is a shared
  singleton serialized by the orchestrator).
- It does **not** close the coverage gap. All 17 added states/terminals are **Uncovered** in the
  §5.7 sense; per **C-0** none of the private half is guarded by CI regardless.
- It does **not** re-adjudicate the public half. `XS_*` and `T_XS_*` are referenced where the private
  half couples into them and are otherwise left as the map has them.

---

## Summary

| | Count |
|---|---|
| Non-terminal states defined (with concrete observables) | **11** (S: 4 · B: 4 · D: 3) |
| Named terminals defined | **11** |
| Total named states | **22** (map had 5, all non-terminal, none with an observable that survives §10.1/§10.2) |
| Events in the alphabet | **13** |
| Transition cells, all filled | **143** (52 + 52 + 39) |
| Cells that are explicit rejections (`⊘ → T_S4_IllegalEvent`) | **9** |
| Cells that are defined no-ops (`⟳`, no server write) | **96** (S 38 · B 37 · D 21; hybrid cells counted by primary effect) |
| New invariants | **3** (I-S2, I-S3, I-S4) + 1 inherited restated formally (I-S1) |
| Map corrections raised | **6** (§10.1–§10.6) |
