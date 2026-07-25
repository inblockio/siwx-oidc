# Session & Onboarding — State-Machine Coverage Matrix

**Date:** 2026-07-25
**Method:** `/logic-model` (CONTEXT → GOAL → INPUTS → ACTIVITIES/OUTPUTS → BOUNDARY CONDITIONS)
**Mode:** Read-only analysis. No source, config, or container was modified. No container was
started, stopped, or removed. This file is the only artifact written.
**Authority document:** `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md`
(machines M0–M5, undefined states U1–U4, QR terminals Q1–Q5).

> **Labelling contract.** **VERIFIED** = backed by a `file:line` in a tree named below, or a
> command reproduced here. **ASSUMED** = a plausible link in the chain that I did not test; every
> one is in the assumptions register (§9) with the test that would settle it.

> **Snapshot pin — the tree moved under this audit.** Analysis is pinned to
> `/home/waldknoten-01/wt/siwx-durability` @ **`dd34e3f`** (branch
> `feat/session-durability-marathon`). At task start it was `d21329e`; a parallel agent committed
> `dd34e3f` ("fix(refresh): distinguish infrastructure failure from revocation") mid-audit. §5's M2
> rows reflect `dd34e3f`. Element-client claims are pinned to element-web **v1.12.20** +
> `patches/element-web/force-first-device-recovery.patch` @ `siwx-oidc-matrix-server` **`b7e594f`**.

---

## 1. CONTEXT

### 1.1 What the coverage base actually is

| Surface | Files | Tests | Runs in CI? |
|---|---|---|---|
| In-crate unit tests (`src/**/*.rs` `#[cfg(test)]`) | 10 modules | **131** | **YES** — `cargo test` (`.github/workflows/ci.yml:27`, Redis only) |
| Rust integration (`tests/*.rs`) | 8 | **43** | **NO — every single one is `#[ignore]`** (verified: ignore-count == test-count in all 8 files) |
| Playwright mock suite (`e2e/browser/*.spec.mjs`) | 4 | 26 | **NO** — needs `e2e/up.sh` (siwx :8080 + **Synapse mock** :8090 + Redis) |
| Playwright Element suite (`e2e/element/*.spec.mjs`) | 6 | 17 | **NO** — needs the Element lab (28080/28081/28088) |

> **FINDING C-0 (VERIFIED).** CI runs `cargo build`, `clippy`, `fmt`, `cargo test` against Redis
> only (`ci.yml:17-27`). **Every** test that touches Synapse, cross-signing, devices, or a browser
> is opt-in and manual. The entire M4/M5 evidence base is therefore un-regressed by default: a
> change can break every cross-signing terminal in this document and CI stays green. Treat all
> "Covered" verdicts below as *"a test exists that genuinely asserts this"*, **not** *"this is
> guarded"*.

### 1.2 Two corrections to the authority document

| Map claim | Status now | Evidence |
|---|---|---|
| `f0d991d` XS-reset honesty is "**NO**" in prod / durability-plan F13 says "branch-only, not on main" | **STALE — it IS on main** | `git merge-base --is-ancestor f0d991d main` → true (VERIFIED). `src/account.rs:430` `reset_outcome` present, 15 references, 5 unit tests |
| H-P9 "login-time `allow_cross_signing_reset` is NOT implemented" | **Correct for main/prod; implemented on THIS branch** | `src/oidc.rs:1595` (branch); durability-plan F14 confirms absent on main |

Both matter for prioritisation: U1's fix has landed further than the map says, and the "3B" login
allow is a branch-local behaviour that the coverage below depends on.

---

## 2. GOAL

> Produce a total state × transition × coverage matrix for M0–M5 that names every state a real
> user can reach, marks each as covered / partial / uncovered against a specific `file:test-name`
> judged by what it *asserts*, and registers every state with no defined next step or a false
> user-facing claim.

**Acceptance:** every state has a coverage verdict with a citation or an explicit "none"; every
undefined state has (how reached → what the user sees → what the defined behaviour should be);
the gap list is ordered by reachability × severity with the ranking justified.

**Out of scope:** implementing anything; running the lab; prod probes.

---

## 3. INPUTS

| Class | Item | Consumed by |
|---|---|---|
| Authority | `…/2026-07-25-session-onboarding-state-machine-map.md` | §5 skeleton |
| Plan | `…/2026-07-25-session-durability-no-forced-logins.md` (R1–R6, F1–F17, H-D1–H-D11) | §6, §8 |
| Prior audit | `docs/audits/2026-07-25-verify-with-other-device-gap-evaluation.md` | M5, §7.2 |
| Prior audit | `docs/audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md` | §7.3 |
| Code (siwx) | `src/{oidc,account,device_auth,compat,introspect,webauthn}.rs`, `src/db/{mod,redis}.rs` | all |
| Code (Element v1.12.20) | `SetupEncryptionStore.ts`, `SetupEncryptionBody.tsx`, `useOwnDevices.ts`, `LoginWithQRSection.tsx` | M4, M5, §7.1, §7.2 |
| Patch | `siwx-oidc-matrix-server/patches/element-web/force-first-device-recovery.patch` @ `b7e594f` | §7.1 |
| Branch (read-only) | `fix/finding3-fragment-response-mode` @ `3018ffe` in `/home/waldknoten-01/siwx-oidc` | §7.3 |
| Tests | `tests/*.rs` (8), `e2e/browser/*.spec.mjs` (4), `e2e/element/*.spec.mjs` (6) | §5 |

---

## 4. Method — how a coverage verdict was assigned

Names were ignored; assertions were read. The rubric:

| Verdict | Rule |
|---|---|
| **Covered** | A test drives the system *into* the state and asserts the state's **defining side effect**, at a layer where that side effect is real. |
| **Partial** | Asserted at one layer only (mock Synapse where the state is a real-Synapse fact), or the assertion admits **either** outcome (a disjunction is not a discriminator), or a soft/fallback path lets a wrong result pass. |
| **Uncovered** | No test, **or the test only asserts an affordance exists** (renders / is visible / is advertised) without exercising it. Name-only coverage is uncovered. |

Three concrete applications of the rubric, all confirming the brief:

* **`EW-D1`** (`e2e/element/ew-device-link.spec.mjs:39`) — despite the file name "device-link", it is
  `/device_authorization` → `authorization_pending` → wallet CAIP-122 approve → `POST /token` →
  `whoami`. **Zero crypto, no rendezvous, no Element client.** It covers M1c/M2, and contributes
  **nothing** to M5. (The file *imports* `buildCrossSigningUpload`/`keysQuery` — those are used by
  EW-D2, not D1.) **CONFIRMED.**
* **`EW-L1b`** (`e2e/element/ew-login.spec.mjs:135-136`) — asserts
  `getByRole('button', {name:/use another device/i})` and `/remove this device/i` are
  **`toBeVisible()`**. Neither is ever clicked. Under the rubric the verify-gate exits are
  **uncovered**; what *is* covered (and well) is auth-session restore: `authorizeHits` length 0 +
  `mx_user_id`/`mx_device_id` stability (`:118-125`). **CONFIRMED.**
* **`EW-X2`** (`e2e/element/ew-crypto.spec.mjs:118`) — asserts
  `['completed','reset_unconfirmed']).toContain(kind)`. Both branches pass, so it cannot
  distinguish an effective reset from a refused one. It is a **no-500 + well-formed-terminal**
  test, not an effectiveness test → **Partial** for `T_XS_HonestFail`.

Two more structural discounts:

* `e2e/browser/*` runs against **`e2e/synapse_mock.py`** (`device-lifecycle.spec.mjs:27` `SYNAPSE_MOCK`).
  It can prove *siwx-oidc called the endpoint*; it cannot prove Synapse honoured it. Anything whose
  truth lives in Synapse is capped at **Partial** on mock evidence alone.
* `EW-X1` (`ew-crypto.spec.mjs:69-82`) asserts only `.not.toBe(401)` and falls back to a
  `console.warn` soft path if the upload is any other non-200. A 500 passes → **Partial**.

---

## 5. THE MATRIX — states, transitions, coverage

**72 states enumerated. 46 Covered · 10 Partial · 16 Uncovered.**

### 5.1 M0 — Identity binding (DID ↔ Matrix user) — 8 states

| State | Observable (VERIFIED) | Coverage | Evidence / gap |
|---|---|---|---|
| `IdUnknown` | no verified session | **Covered** | `ew-clickpath.spec.mjs` EW-C1 (real logged-out SPA entry) |
| `IdProven` | `session.verified_did` | **Covered** | EW-C1; `ew-passkey.spec.mjs` EW-P1 |
| `MxUserExists` | `is_localpart_available == false` | **Covered** | EW-P2 `expect(second.new_user).toBe(false)`; EW-P3 (2nd context) |
| `MxUserAbsent` | `is_localpart_available == true` | **Covered** | EW-P1 `expect(s.new_user).toBe(true)` |
| `T_GatePending` | finish returns `{new_user:true, mxid}`, nothing provisioned | **Partial** | API layer covered (EW-P1; `passkey-scoping.spec.mjs:424` H4). **The DOM confirm/cancel gate is never clicked** — grep for a click on the confirm/cancel affordance returns nothing. **L3 (cancel ⇒ zero Synapse state) is unproven.** |
| `T_Bound` | whoami 200 | **Covered** | EW-P1, EW-C1, `ew-sessions.spec.mjs` EW-S2 |
| `T_RejectedNew` | 400 `NEW_IDENTITY_REJECT_MSG` | **Partial** | `passkey-scoping.spec.mjs:526` (account) + `:560` (device) — **mock Synapse only**; no real-Synapse leg. EW-D1 *relies* on this behaviour (`:44` comment) but never asserts it |
| `T_CreateFailed` | provision failed, no half user | **Uncovered** | none |

**Transition-totality finding T-M0.** The map's login row `T_GatePending --user_cancel--> IdUnknown`
is defined on paper and implemented, but is the one M0 edge with **no test at any layer**. It is
also the edge that protects invariant I5 (new identity only behind the gate).

**L4 (wrong account's passkey → bound as that account)** remains an accepted residual with no test;
**L5 (stale passkey)** is well covered — `stale-credential.spec.mjs:154` (401 discriminator +
`signalUnknownCredential`), `:180` (unsupported-signal fallback), `:196` (trigger isolation: a valid
passkey never fires the signal).

### 5.2 M1a — Wallet ceremony (CAIP-122) — 10 states

| State | Coverage | Evidence / gap |
|---|---|---|
| `W_Idle` | **Covered** | EW-C1 clicks the real `Sign in with Ethereum` button (`helpers/element-login.mjs`) |
| `W_NonceIssued` | **Covered** | `tests/e2e_oauth_binding.rs::authorize_session` |
| `W_Signed` | **Covered** | EW-C1; `helpers/oidc-login.mjs` |
| `W_Verified` | **Covered** | EW-L1, EW-C1 |
| `T_CodeIssued` | **Covered** | `e2e_msc3861.rs::full_lifecycle` |
| `T_FailNonce` | **Covered** | `e2e_oauth_binding.rs::device_approval_without_server_nonce_is_rejected`, `::account_action_without_server_nonce_is_rejected`, `::account_action_nonce_replay_is_rejected`, `::device_approval_replay_is_rejected_fresh_succeeds` |
| `T_FailSig` | **Uncovered** | **Replay and expiry are covered; forgery is not.** No test presents a signature that is well-formed, unexpired, unreplayed, and simply *wrong for the DID*. (VERIFIED by exhaustive grep over `tests/`, `e2e/`.) |
| `T_FailResource` | **Covered** | `e2e_oauth_binding.rs::unregistered_redirect_uri_at_sign_in_is_rejected` |
| `T_FailSession` | **Partial** | expiry inferred from TTL; no test lets a session lapse between authorize and sign_in |
| `T_FailMethod` | **Uncovered** | `device_auth.rs:971` "DID method '…' is not enabled" — no test |

### 5.3 M1b — Passkey ceremony (WebAuthn) — 11 states

| State | Coverage | Evidence / gap |
|---|---|---|
| `P_Idle` | **Covered** | EW-P1 |
| `P_Challenge` | **Covered** | `device-lifecycle.spec.mjs:460` H11 (cross-session replay rejected) |
| `P_Asserted` | **Covered** | EW-P1 (CDP virtual authenticator, CTAP2 resident key) |
| `P_Verified` | **Covered** | EW-P1 `expect(s.registered_did).toMatch(/^did:key:zDn/)` |
| `P_ScopedOffer` | **Covered** | EW-P2 `allow_count === 1` + `detected_mxid`; `passkey-scoping.spec.mjs:167,234,279,346,383` (login/account/device × API + DOM) |
| `P_UsernamelessOffer` | **Covered** | `device-lifecycle.spec.mjs:319` R-C4 (no enumeration); EW-P1 `allow_count === 0`; EW-P3 (forged/absent cookie in a 2nd context) |
| `T_VerifiedDidInSession` | **Covered** | EW-P1 → whoami |
| `T_FailUnknownCred` | **Covered** | `stale-credential.spec.mjs:154,180,196` |
| `T_FailChallenge` | **Covered** | `device-lifecycle.spec.mjs:460` H11, `:522` H11b (single-use within own session) |
| `T_FailCounter` | **Uncovered** | sign-count regression never exercised |
| `T_FailRP` | **Uncovered** | RP-ID / origin mismatch never exercised |

**M1b is the strongest-covered ceremony**, and notably the enumeration-safety invariant is proven
in both directions (scoped and forged-cookie fallback).

### 5.4 M1c — Device approval (RFC 8628) — 8 states

| State | Observable (VERIFIED) | Coverage | Evidence / gap |
|---|---|---|---|
| `D_Issued` | `device_codes/*` | **Covered** | EW-D1 (`dvc_` prefix, `verification_uri`); `e2e_device_code.rs::device_code_grant_end_to_end` |
| `D_Pending` | `authorization_pending` | **Covered** | EW-D1 pre-approval poll (`:84-86`) |
| `D_SlowDown` | `src/oidc.rs:694` | **Uncovered** | Both pollers *tolerate* `slow_down` (`e2e_device_code.rs:611`, `helpers/device-code.mjs:166`); **no test polls fast enough to force it and assert it is emitted** |
| `D_Approved` | status `Approved` (`device_auth.rs:1029`, `:1072`) | **Covered** | EW-D1, EW-D2 |
| `D_Denied` | status `Denied` (`device_auth.rs:933`) | **Partial** | unit-only: `device_auth.rs:1168` asserts the terminal *page renders*. No e2e drives a user denial to a poll result |
| `D_Expired` | `expired_token` (`src/oidc.rs:676`) | **Uncovered** | none |
| `T_TokensIssued` | `mat_`/`mcr_` + scope | **Covered** | EW-D1 asserts the requested `urn:matrix:client:device:{id}` round-trips and differs from the seed device |
| `T_FailDoubleRedeem` | second poll fails | **Covered** | `e2e_race_teardown.rs::h9_device_code_approved_no_double_redemption` |

### 5.5 M2 — OIDC session & tokens — 11 states

| State | Coverage | Evidence / gap |
|---|---|---|
| `O_Authorize` | **Covered** | `e2e_msc3861.rs::full_lifecycle` |
| `O_Code` | **Covered** | ditto |
| `O_Active` | **Covered** | `e2e_race_teardown.rs::rf2_rf3_rf4_introspection_active_inactive_and_auth` |
| `O_Refreshing` | **Covered** | `e2e_msc3861.rs::refresh_token_flow` |
| `O_GraceReplay` | **Covered** | `e2e_race_teardown.rs::refresh_grace_window_tolerates_replay` (`:1496`) — covers both `/token` and `compat::refresh` |
| `O_RefreshIndeterminate` **(NEW — added by `dd34e3f`)** | **Partial** | 7 unit tests on `RevocationState`/`collapse_revocation` (`src/db/mod.rs`) incl. 3 tombstone-fails-closed guards, + 4 `render_introspection` guards (`src/introspect.rs`). **No fault-injection e2e exists** (plan task T4 unwritten) — the claim "a 2s Redis outage does not sign anyone out" is unit-reasoned, never observed |
| `O_Revoked` | **Covered** | `e2e_session_teardown.rs::logout_deletes_ending_session_device`; EW-S4 (uncached whoami 401) |
| `T_FailInvalidGrant` | **Covered** | `e2e_race_teardown.rs::h6_deactivate_racing_refresh_no_resurrection` |
| `T_FailPkce` | **Covered** | `e2e_oauth_binding.rs::plain_pkce_is_rejected`, `::authorize_without_pkce_is_rejected` |
| `T_FailClient` | **Covered** | `e2e_oauth_binding.rs::mismatched_client_id_at_token_is_rejected` |
| `T_FailCodeReplay` | **Covered** | `e2e_race_teardown.rs::h8_concurrent_auth_code_exchange_exactly_one_wins` |

**Transition-totality finding T-M2.** `dd34e3f` makes the machine *more* total (an indeterminate
probe is now a named third outcome rather than a coin-flip `.unwrap_or(true)`), and adds a
compile-time assertion binding `TOMBSTONE_TTL_SECS` to `2 * ACCESS_TOKEN_TTL`. The residual is
evidential, not structural: **R1 (restart survival) and R3 (Redis hiccup) have no test at all.**

### 5.6 M3 — Matrix device lifecycle — 5 states

| State | Coverage | Evidence |
|---|---|---|
| `Dev_None` | **Covered** | `e2e_race_teardown.rs::h2_sequential_signins_mint_distinct_device_ids` |
| `Dev_Provisioned` | **Covered** | EW-S2, EW-P2 (2 distinct devices, no recycling) |
| `Dev_TokenBound` | **Covered** | EW-D1 (`whoami.device_id == requested`) |
| `Dev_Deleted` | **Covered** | `::h1_revoke_does_not_delete_device_but_logout_does` (the policy discriminator), `::h12_device_delete_targets_only_requested_device`, `::h3_concurrent_same_device_delete_revokes_all_tokens`, `::h4_concurrent_delete_different_devices_no_crosstalk`, EW-S3, EW-C2 |
| `T_FailSynapse` | **Covered** | `::h14_synapse_delete_failure_is_surfaced_not_500` |

> **M3 is the only machine that is complete and genuinely covered end to end.** It is also the one
> with a real DOM click-path for teardown (EW-C2 records *which* endpoint Element fires and asserts
> the matching policy branch, rather than assuming one).

### 5.7 M4 — Cross-signing + Secure Backup — 13 states (the machine with undefined states)

| State | Coverage | Evidence / gap |
|---|---|---|
| `XS_Absent` | **Covered** | `e2e_msc4191_live.rs::cross_signing_reset_no_master_completed_live` |
| `XS_Present` | **Covered** | `::cross_signing_reset_leg_a_roundtrip_completed_live` step 1 (upload 200) |
| `XS_ResetArmed` | **Partial** | Never directly observable (MAS never returns the window timestamp — `src/account.rs:374`). Inferred only from "upload 401 → reset → upload 200" (leg A step 4) |
| `XS_ResetArmedIneffective` | **Uncovered** | **Now unconstructible by contract:** `reset_outcome(true, NoMaster) == Completed` (`account.rs:437`) on the reasoning that Synapse skips the gate. If that reasoning is wrong the state is silent and untested |
| `XS_UploadRejected` | **Covered** | leg A step 2 asserts 401 **and** that the body advertises `org.matrix.cross_signing_reset` + `/account` (`e2e_msc4191_live.rs:1176-1182`) |
| `T_XS_OK` | **Covered** | leg A step 4; `no_master` leg |
| `T_XS_HalfReset` | **Uncovered** | **No test ever constructs the state** (private 4S rewritten + public master missing/stale) or exercises recovery from it. This is the prod failure mode of record (2026-06-24 forensics; 14× 401) |
| `T_XS_HonestFail` | **Partial** | Unit: `account.rs:3061` `reset_outcome_indeterminate_readback_is_truthful_non_success`, `:3086` failed-allow-never-Completed, `:3106` wire tag, `:3123` page JS renders it. E2E: **EW-X2 accepts either kind** → not a discriminator |
| `S4_Absent` | **Uncovered** | none |
| `S4_Present` | **Partial** | `helpers/element-login.mjs::completeSecureBackupWizard` *creates* a recovery key on every Element login but **asserts nothing about it** — it is a click-through, not a check |
| `S4_Rotated` | **Uncovered** | none — and see U3, where a code path can rotate it destructively |
| `Backup_Vn` | **Uncovered** | none |
| `Backup_Deleted` | **Uncovered** | none |

**Transition-totality finding T-M4 (the central structural gap).** The map's M4 table is total on
paper for the *public* half and **not total at all for the private half**. `S4_*` and `Backup_*` are
declared as states but have **no transition table, no events, and no terminals** — there is no row
saying what happens on `4S_key_rotated_while_master_stale`, on `backup_deleted_with_XS_present`, or
on `recovery_key_lost_with_no_second_device`. Every one of those is user-reachable. Six of the
sixteen uncovered states in this document are in M4's private half.

### 5.8 M5 — Multi-device trust — 6 terminals

| Terminal | Coverage | Evidence / gap |
|---|---|---|
| **`Q0` / `T_OfferWithheld`** **(NEW — not in the map)** | **Uncovered** | Approver not cross-signing-ready ⇒ `shouldShowQrForLinkNewDevice` false ⇒ button disabled and labelled *"Not supported by your account provider"*. Proposed in the 2026-07-25 verify-with-other-device evaluation §6.1; **adopted here as a first-class terminal.** No test |
| `Q1` `T_NewDeviceOK` | **Uncovered** | **The load-bearing gap.** Plan `H-D8`/`AC4`/task T11 specify exactly this two-context test; it does not exist. Nothing at any layer has ever demonstrated a second device being verified from a first live session |
| `Q2` `T_ApprovedButDead` | **Covered (as a failure) / Uncovered (as recovery)** | `ew-device-link.spec.mjs:160` EW-D2 asserts the server fabricates no crypto claim (`warning ?? null` is null) and the dead end stays externally detectable (`master_keys[user]` undefined), with a contrast leg proving the discriminator discriminates. **It certifies the dead end; it does not exit it.** |
| `Q3` (XS present, no Secure Backup) | **Uncovered** | none |
| `Q4` `T_NoTokens` (denied/expired) | **Partial** | see `D_Denied`/`D_Expired` above |
| `Q5` `T_RejectedNew` | **Covered** | `passkey-scoping.spec.mjs:560` (device path, mock) |

**SAS / emoji verification: zero coverage, and the words do not appear in the tree.** A
case-insensitive search for `m.key.verification | sendToDevice | to_device | secret.send | SAS |
emoji | requestVerification | startVerification` over `src/`, `tests/`, `e2e/` returns **zero**
matches (reproduced from the 2026-07-25 verify-with-other-device evaluation §4.5, whose method I
re-checked against the specs above and confirm). See §7.2 for the reachability gate.

---

## 6. UNDEFINED-STATES REGISTER

A state qualifies if a real user can reach it and **either** no next step is defined **or** the UI
asserts something untrue.

### 6.1 U1–U4 adjudicated against the current tree

| ID | Map claim | Verdict now | Reasoning |
|---|---|---|---|
| **U1** — success banner while grant is a no-op | **REFUTED on `main`, STILL LIVE IN PROD** | `reset_outcome` is on main (VERIFIED, §1.2). `Indeterminate ⇒ ResetUnconfirmed` (`account.rs:440`) makes the lie impossible for the readback-failure case; `NoMaster ⇒ Completed` reclassifies the original incident shape as *genuinely effective* rather than *honestly refused*. Prod runs `sha-db79e75`, which predates this → **the lying state is still reachable by every production user today.** Residual on main: `MasterPresent ⇒ Completed` is a **contract inference**, not an observation (the window timestamp is unreadable, `account.rs:374`); if the window expires before the client's upload the user still sees success then 401. |
| **U2** — private 4S reset without public publish (half-reset) | **CONFIRMED — fully open** | The honesty gate governs what the *reset action reports*; it neither prevents nor detects the half-reset **state**. `T_XS_HalfReset` has no constructor test, no recovery transition, and no alert. Plan item P4 (alert on N consecutive 401) is unwritten. |
| **U3** — double 4S churn mid-loop | **CONFIRMED — and now root-caused to a specific line** | See §7.1 / **U3′** below. This is the most important upgrade in this register. |
| **U4** — history keys destroyed by reset | **CONFIRMED — fully open** | `Backup_Deleted` uncovered; no product guard prefers unlock over reset; `ResetIdentityDialog` is reached with `variant: store.lostKeys() ? "no_verification_method" : "confirm"` (`SetupEncryptionBody.tsx:139`), i.e. the destructive path is *offered more readily* precisely when the user has least to fall back on. |

### 6.2 New undefined states

| ID | State | How a real user gets there | What they see | Defined behaviour it should have |
|---|---|---|---|---|
| **U3′** | **`accessSecretStorage(forceReset:true)` fires on a cold cache and orphans an existing 4S key** | Any path into `onCompleteSecurityE2eSetupFinished` where the *server* 4S probe fails (network blip) → the patch falls back "toward enforcing", entering the loop. Inside the loop the discriminator is `const hasExisting4S = await cli.secretStorage.hasKey()` → `accessSecretStorage(…, { forceReset: !hasExisting4S })` (patch @ `b7e594f`). **`b7e594f`'s own commit message VERIFIES that `hasKey()` reads the cold LOCAL cache** and is exactly as unreliable as the probe it replaced elsewhere. | A recovery-key **creation** wizard where an **unlock** was correct; the previous recovery key and message-key backup are silently orphaned | The loop must use the same server-truth probe `b7e594f` introduced for the gate (`getAccountDataFromServer("m.secret_storage.default_key")`), and must **never** default to `forceReset` on an indeterminate read. **Fail-safe here is "unlock", not "enforce" — enforcement is the destructive direction.** |
| **U5** | **`Q0` / `T_OfferWithheld`** | Desktop session that is not cross-signing-ready opens Settings → Sessions | "Show QR code" greyed out, labelled **"Not supported by your account provider"** — false: the OP supports it; the user's own crypto state is the cause | A truthful disabled-reason, plus a route to the fix ("this session isn't verified yet") |
| **U6** | **Verify gate with no recovery-key entry** (`lostKeys()`-adjacent) | Any entry into `COMPLETE_SECURITY` with `store.keyInfo == null` | Only "Use another device" (possibly self-counting, A7) and destructive reset. **No recovery-key field, even when 4S exists server-side.** | `keyInfo` must be derived from server truth, not the local cache — see §7.1 |
| **U7** | **Unverified current device cannot initiate verification from Settings** | Reloaded / freshly-restored session, current device unverified | The per-session "Verify session" affordance is simply **absent** (not disabled, not explained) | Correct-by-design that it cannot *vouch*; the undefined part is that no alternative is offered, so U5+U6+U7 compose into "reset is the only visible exit" |
| **U8** | **Silent legacy-SSO 404 on Element ≥ 1.12.24** | Any Element Web upgrade past 1.12.23 | Login dead-ends with no error; QR device-link silently degrades to "Not supported by your account provider" (same `try/catch` swallows it) | Advertise **and honour** `response_mode` — see §7.3 |
| **U9** | **Infrastructure fault rendered as authorization failure** | Redis blip / restart, against **prod** (pre-`dd34e3f`) | Hard logout, crypto store wiped, user pushed to the recovery phrase (chain L1→L7) | Fixed on branch (`RevocationState`, `render_introspection`); **unproven by any e2e and undeployed** |

> **Worst undefined state: U3′.** It is the only one in this register whose failure mode is
> **silent and destructive** — it does not block the user or lie to them, it *succeeds* while
> orphaning the recovery key and message-key backup that U4, U6, R5 and R6 all depend on existing.
> Every other undefined state costs the user a session; U3′ costs them their history.

---

## 7. THE FOUR NAMED FINDINGS, LOCATED IN THE MACHINE

### 7.1 Reload verify-gate with no recovery-key entry — post-fix assessment

**Location in the machine:** the transition `M2:O_Active --page_reload--> M4:COMPLETE_SECURITY` with
terminal set `{use_another_device, destructive_reset}` — i.e. **U6**, feeding **U4**.

**Root cause (VERIFIED, and it was this deployment's own patch).** Pre-fix, the vendored patch made
`shouldForceVerification()` return `!crossSigningReady || !secretStorageReady`. That predicate also
runs on session **restore**, where `isSecretStorageReady()` is transiently false before account_data
re-hydrates. `9ec414d`'s message records the falsification method: parallel containers, vanilla
1.12.20/1.12.24 never gate, only the patched build does.

**What the fix actually changed.** `9ec414d` widened the predicate with `secretStorage.hasKey()`;
**that attempt failed on its own validation** — `b7e594f`'s message states plainly that `hasKey()`
reads the same cold local cache and *"the reload gate still fired (EW-L1b red on image 16c8f6d)"*.
`b7e594f` replaced it with a genuine server read:

```
const hasServer4S = !secretStorageReady &&
    !!(await client.getAccountDataFromServer("m.secret_storage.default_key").catch(() => null));
return !crossSigningReady || !(secretStorageReady || hasServer4S);
```

**State of the machine after the fix — three findings:**

1. **The reload edge is repaired *in intent*, but the fix is UNVALIDATED.** `b7e594f` is the tip of
   `siwx-oidc-matrix-server/main`; its message documents only `git apply --check` against a pristine
   v1.12.20 tree. **There is no recorded EW-L1b green run after `b7e594f`** (VERIFIED: no reference
   to `b7e594f` in any repo doc; the only recorded EW-L1b result is the *red* one that killed
   `9ec414d`). Given that the immediately preceding attempt at this exact fix was falsified by its
   own validation, treating this one as landed without a run is unsafe.
2. **The gate itself is untouched, and `U6` survives.** The fix changes only *whether the gate is
   entered on reload*. Whenever the gate is legitimately entered — `crossSigningReady == false`,
   which is exactly the L1→L4 hard-logout chain the durability plan targets — the recovery-key
   button is still governed by `if (store.keyInfo)` (`SetupEncryptionBody.tsx:182`), and `keyInfo`
   still comes from `cli.secretStorage.isStored("m.cross_signing.master")`
   (`SetupEncryptionStore.ts:164`) — **the same local-cache class of read that `b7e594f` proved
   unreliable.** The empirical proof it can be wrong is the original F16 report itself: 4S had
   completed seconds earlier and the button was still absent.
   There is also a *second, non-timing* cause with the same symptom: `isStored` asks whether the
   **master secret is stored in 4S**, so a half-reset user (U2) legitimately has 4S with no master
   secret in it → `keyInfo == null` → no recovery-key entry, correctly. **Two different causes,
   one indistinguishable dead end.**
3. **`b7e594f`'s fail-safe direction is right for the gate and wrong for the loop.** "Falls back
   toward enforcing, never toward skipping" is correct for *entering* the wizard. But the same
   fallback carries the user into the retry loop whose `forceReset` discriminator is the cold
   `hasKey()` — **U3′**. The fix therefore slightly *raises* the probability of the destructive
   path conditional on a network blip.

**What remains:** validate `b7e594f` with an EW-L1b run; fix `keyInfo` derivation (or add a
server-truth "I have a recovery key" escape hatch to the gate); fix the `forceReset` discriminator.

### 7.2 SAS / emoji verification — zero coverage, and gated

**Location:** M5, alongside `Q1`. It is the *non-QR* route to `T_NewDeviceOK`, and the only route
that does not depend on the rendezvous channel at all.

**Reachability (VERIFIED).** `useOwnDevices.ts:184-191`:

```ts
const isCurrentDeviceVerified = !!devices[currentDeviceId]?.isVerified;
const requestDeviceVerification =
    isCurrentDeviceVerified && userId
        ? async (deviceId) => matrixClient.getCrypto()!.requestDeviceVerification(userId, deviceId)
        : undefined;
```

The affordance exists at Settings → Sessions → "Verify session" and is gated *only* on
`isCurrentDeviceVerified && userId` — no server capability check, nothing MSC3861 can break. It is
genuinely reachable for a healthy session, which makes the absence of coverage a live risk rather
than a theoretical one.

**Coverage: zero, confirmed two ways.** (a) The keyword search in §5.8 returns no matches anywhere
in `src/`, `tests/`, `e2e/`. (b) Reading the specs that sound like they cover it: EW-D1 is
HTTP-only; EW-D2 asserts the dead end; EW-L1b asserts button *visibility* only; EW-P2/P3 "second
device" means a second OIDC session with no Matrix crypto.

**Compounding with §7.1:** `isCurrentDeviceVerified == false` withholds this affordance (U7) at the
same moment `isCrossSigningReady == false` withholds the QR button (U5) and `keyInfo == null`
withholds recovery-key entry (U6). All three predicates are false together in the reloaded /
hard-logged-out state. **The three non-destructive exits fail as a correlated set, leaving reset.**
That correlation — not any single missing feature — is the mechanism behind the prod "verify session
loop / half-reset" forensics.

### 7.3 `response_modes_supported` absent from OP metadata

**Location:** M2 upstream of `O_Authorize` — a *pre-state* failure. The user never reaches a named
state; the SPA falls back to `/_matrix/client/v3/login/sso/redirect`, which 404s under MSC3861. That
is **U8**, and it is the same silent-dead-end class as the auth_metadata finding.

**Current tree (VERIFIED).** `grep response_modes_supported src/oidc.rs` in the audited worktree →
**no match** (only `grant_types_supported` at `:289`). Latent: matrix-js-sdk 41.6.0 has zero
references to the field, so Element 1.12.20 is unaffected today.

**Fix in flight (read-only, NOT modified).** `fix/finding3-fragment-response-mode` @ `3018ffe` in
`/home/waldknoten-01/siwx-oidc`, `+223` lines in `src/oidc.rs`. It does the two things the finding
doc says must ship together:

* advertises `value["response_modes_supported"] = ["query","fragment"]` — with a code comment
  explicitly tying it to `/sign_in` honouring fragment (i.e. it refuses to advertise a mode it does
  not implement, which the finding doc flags as *strictly worse* than omission);
* threads `response_mode` from `/authorize` (strict validation: anything but `query`/`fragment`
  is a 400) through the session to `sign_in`, which sets **all** response params in the fragment via
  `url.set_fragment`, preserving any query the registered `redirect_uri` already carries.

It ships a unit test `e2e_flow_fragment_response_mode` **and** a negative guard asserting the
default path emits no fragment. **Assessment: this is the right shape and is unit-covered.** What it
does not yet have is a 1.12.24 parallel-container run (the finding doc's step 3) — so the *latency*
of U8 is removed on that branch, but the *upgrade* is still unproven.

**Second-order impact worth carrying:** `isSignInWithQRAvailable()` obtains metadata through the
same validated path inside a `try/catch` that returns `false` on any throw. So U8 is simultaneously
a login blocker and a silent **Q0** producer.

### 7.4 Where the map's own claims need updating

| Map text | Correction |
|---|---|
| §4 M5 table has no row for "capability present, never exercised" | Add **Q0 / `T_OfferWithheld`** (U5) — the terminal a reloaded desktop actually hits |
| U1 "Fix class: deploy `f0d991d`" | `f0d991d` is **on main** (§1.2); the open item is the **prod deploy**, plus the `MasterPresent` contract inference |
| §4 M4 lists `S4_*`/`Backup_*` as states | They have **no transition table** — this is the largest totality hole (T-M4) |
| H-P9 | Correct for main/prod; the branch *does* implement login-time allow (`src/oidc.rs:1595`) |

---

## 8. PRIORITIZED GAP LIST

Ranked by **(a) likelihood a real user reaches the state × (b) severity of the outcome**. Severity
is weighted by irreversibility: silent data loss > stuck-with-no-exit > forced re-login > cosmetic.

| # | Gap | Reach | Severity | Why it ranks here | First action |
|---|---|---|---|---|---|
| **1** | **U3′ — `forceReset` decided by a cold-cache probe** (patch @ `b7e594f`; discriminator `cli.secretStorage.hasKey()`) | Medium — needs the server probe to fail, but that fallback is *by design* on any network blip | **Critical, silent, irreversible** | Only gap that destroys the artifact every other recovery path depends on (4S key + message-key backup), while reporting success. Also invalidates R5/R6, which assume a recovery key exists to be typed. `b7e594f` marginally *increases* its reach | Replace the discriminator with the server read `b7e594f` already introduced; default indeterminate → **unlock**, never reset. Then a lab test: blip the probe, assert no new default key |
| **2** | **U6 — no recovery-key entry at the verify gate** (`keyInfo` from local `isStored`) | **High** — every hard logout (L1→L4) and every genuinely new device enters this gate | **Critical, stuck-with-no-exit** | `b7e594f` closed the *reload* door; the gate is unchanged and is still entered on the far more consequential path. With U5+U7 also false (§7.2), reset is the only visible exit — the exact prod loop. Makes plan requirement **R5/R6 "and must be enterable" FALSE** | Derive `keyInfo` from server truth (mirror the `getAccountDataFromServer` pattern), and **validate `b7e594f` with an EW-L1b run** before assuming §7.1 is closed |
| **3** | **Q1 / `T_NewDeviceOK` never demonstrated (`H-D8`/`AC4`/T11)** — and SAS has zero coverage | **High** — this is the normal "add my phone" journey | High | R4 cannot be asserted at all: nothing at any layer has shown a second device verified from a live first session. It is also the *mitigation* for gaps 1 and 2 — if verify-from-live-session works reliably, the destructive gate is rarely reached. Ranked below them because it is missing *evidence*, whereas 1–2 are missing *correctness* | Build the two-context Playwright leg: login A → wizard → login B → verify B from A → assert B cross-signed **and zero 4S prompts fired**. Add the SAS leg via Settings → Sessions (gate at `useOwnDevices.ts:184-191`) |
| **4** | **U9 / R1+R3 — infra fault ⇒ hard logout: fixed on branch, unproven and undeployed** | **Very high in prod** (~548 `invalid_grant`/72h baseline; any restart) | High but **recoverable** | Highest raw reach of anything here, and `dd34e3f` addresses the mechanism well (named `RevocationState`, compile-time TTL assertion). Ranks 4th only because the outcome is a forced re-login, not data loss — *except* that under MSC3861 a forced re-login **is** a crypto-store wipe, which is what feeds gaps 1–3. Fixing 4 shrinks the population exposed to 1–3 | Write the T4 fault-injection harness (pause Redis → assert 5xx on `/oauth2/introspect`, `/token` refresh, `compat::refresh`; restore → same refresh token still works) and the T5 restart-survival leg |
| **5** | **U1 residual — prod still runs the lying reset (`sha-db79e75`)** | Medium — only users who hit a reset | High while it lasts (**false success**, invariant I4) | The code fix is on `main` (§1.2); the gap is purely deployment. Cheap to close relative to everything above. Residual after deploy: `MasterPresent ⇒ Completed` is inferred, not observed | Deploy; then make EW-X2 a **discriminator** (assert `completed` for the healthy path, `reset_unconfirmed` for a forced-indeterminate readback) instead of accepting either |

**Below the line, in order:** U8 / `response_modes_supported` (fix is written and unit-tested on
`fix/finding3-fragment-response-mode`; zero user reach until an Element bump, so it is a *release
gate*, not a defect to schedule); **T_XS_HalfReset** having no constructor test (U2) and no
N×401 alert (plan P4); M0 `T_GatePending` cancel-branch untested; `D_SlowDown` / `D_Expired` /
`D_Denied` e2e; `T_FailSig` (forgery) and `T_FailMethod`; `T_FailCounter` / `T_FailRP`;
`T_CreateFailed`.

**One cross-cutting recommendation that is cheaper than any item above:** promote a subset of the
43 `#[ignore]` integration tests into CI behind the existing mock stack (C-0). Today every verdict
in §5 marked "Covered" is guarded by nothing automated.

---

## 9. ASSUMPTIONS REGISTER

| ID | Assumption | Status | Test that settles it |
|---|---|---|---|
| **B1** | The audited worktree @ `dd34e3f` is the intended base for implementation | **ASSUMED** — the tree advanced from `d21329e` mid-audit; it may advance again | `git log` at implementation start; re-run §5's M2 rows |
| **B2** | `siwx-oidc-matrix-server` @ `b7e594f` repairs the reload gate in practice | **ASSUMED — explicitly unvalidated.** The prior attempt (`9ec414d`) was falsified by its own EW-L1b run; no post-`b7e594f` run is recorded anywhere in either repo | Run EW-L1b against an image built from `b7e594f`; assert `.mx_MatrixChat` (the spec's improved branch) |
| **B3** | `SetupEncryptionStore.ts` / `SetupEncryptionBody.tsx` / `useOwnDevices.ts` as read (container overlay `1908887b…` and session scratchpad `ew/`) match the deployed build | **ASSUMED** — same v1.12.20 tag, but I did not diff against the running bundle | Diff the deployed bundle, or read the sources from the built image |
| **B4** | `cli.secretStorage.isStored()` reads the local cache with the same cold-start behaviour `b7e594f` proved for `hasKey()` | **STRONGLY INFERRED, not directly verified** — both are `secretStorage` account-data reads and the F16 field report matches. This is the load-bearing link under gap #2 | Instrument the gate: log `isStored` result + a server `getAccountDataFromServer` at the same instant, on reload with known-good 4S |
| **B5** | `reset_outcome(true, MasterPresent) ⇒ Completed` is truthful, i.e. the MAS `UPDATE … WHERE keytype='master'` really planted a live window | **ASSUMED (contract inference)** — `account.rs:374` states the window is unreadable | `cross_signing_reset_leg_a_roundtrip_completed_live` proves it for an *immediate* retry; a delayed-upload variant would test window lifetime |
| **B6** | `reset_outcome(true, NoMaster) ⇒ Completed` is truthful because Synapse skips the gate | **VERIFIED for the immediate path** | `cross_signing_reset_no_master_completed_live` |
| **B7** | The `e2e/browser` Synapse mock faithfully models the real admin/MAS API for the paths it stands in for | **ASSUMED** | Cross-run the same assertions against the Element lab (real Synapse) |
| **B8** | matrix-js-sdk v42 hard-requires `response_modes_supported` | **REPO-SOURCED** (`2026-07-25-element-jssdk-v42-oauth-compat-finding.md`), reproduced via client-side shims; v42 sources not re-derived here | Read `matrix-js-sdk@42.0.0/src/oauth/discover.ts` from npm |
| **B9** | `hasDevicesToVerifyAgainst` counts the current device, so "Use another device" can render with no peer | **Source-VERIFIED** (`SetupEncryptionStore.ts:104-119` has no self-exclusion); consequence **INFERRED** | Single-device lab session: reload, click it, observe whether any peer responds. **EW-L1b asserts this button visible on a single-device account — consistent with the inference** |
| **B10** | Prod is still `sha-db79e75` | **ASSUMED** — carried from the map; not re-probed (no prod access used in this audit) | `grep SIWX_OIDC_TAG /home/deploy/matrix/stack/.env` |
| **B11** | No test clicks the new-user confirm/cancel gate | **VERIFIED by absence** across `e2e/browser` + `e2e/element` | — |

---

## 10. BOUNDARY CONDITIONS

**Respected during this audit:** read-only; no container touched; nothing in
`/home/waldknoten-01/siwx-oidc` or `/home/waldknoten-01/siwx-oidc-matrix-server` modified; exactly
one new file written; no commit; no sub-subagents.

**Invariants this matrix must not be used to weaken:**

* **I4 — never render success when the effect is unconfirmed.** Gap #5 is a deployment gap, not a
  licence to relax `reset_outcome`.
* **I1 / I1a — verification is never shortcut.** Gaps #2 and #3 must be closed by making the
  *client's* recovery affordances honest, never by having the server vouch for a device or derive
  key material.
* **I8 — fail-open only on indistinguishable I/O errors, never on a definite tombstone.** `dd34e3f`
  preserves this with three explicit regression guards; gap #4's harness must not weaken them to go
  green.
* **U3′'s corollary, new here:** *"fail toward enforcement"* is the safe default for a **gate** and
  the unsafe default for a **destructive action**. Any future patch that reaches
  `accessSecretStorage(..., {forceReset})` must fail toward **unlock**.

**Loop exit for the implementation this matrix orders:** every state in §5 marked Uncovered is
either covered, or explicitly accepted with a named terminal and a runbook; U3′, U6 and Q1 cannot
be waived — they are the three that jointly make R4/R5/R6 false.

---

## Orchestrator verification pass (2026-07-25, post-authoring)

The C-0 caveat above was independently re-checked. **One half is confirmed and is the
more important half; the other is overstated and is corrected here** so the inaccurate
form does not propagate into the plan or the audit.

| Claim | Verdict | Evidence |
|---|---|---|
| Neither Playwright suite runs in CI | **CONFIRMED** | `grep -rln 'playwright\|e2e/element\|e2e/browser\|run-element' .github/workflows/` → no matches. Only `ci.yml` and `docker.yml` exist. |
| CI stands up Redis only | **CONFIRMED** | `ci.yml:17-18` — `docker compose -f test/docker-compose.yml up -d redis`. No Synapse, no Element, no Caddy. |
| "All 43 Rust integration tests are `#[ignore]`; ignore-count == test-count in all 8 files" | **OVERSTATED** | Counted per file: 38 test attributes, 13 `#[ignore]` markers. `e2e_account_management.rs` (5/0), `e2e_device_code.rs` (1/0) and `e2e_oauth_binding.rs` (11/0) have **zero** ignores. `e2e_session_teardown.rs` reports more `#[ignore]` greps than test attributes, so the raw counts on both sides are approximate. |

**What survives, and why it matters more than the arithmetic:** the entire Element-layer
evidence base — every EW-* spec, i.e. every assertion about the states this workstream
exists to fix — has **no automated enforcement whatsoever**. "All Playwright passing" is
today a local, manual, point-in-time claim with zero regression protection. Any state we
prove green can silently regress on the next commit and nothing will notice.

**Consequence for the definition of done.** The stated completion bar ("all Playwright
passing for all states") is not meaningfully satisfiable while the suites run only by
hand. Reaching it requires a CI job that stands up the full stack (Synapse + siwx-oidc +
Element + Caddy edge) and runs `e2e/element` and `e2e/browser`. That is a substantial
piece of work in its own right and should be planned as such, not folded silently into a
remediation round.

**Correction is directional, not exculpatory:** the smaller ignore count does not soften
C-0. Rust integration tests were never the Element-layer evidence; the gap C-0 identifies
is real and is arguably the single largest structural risk in this audit.
