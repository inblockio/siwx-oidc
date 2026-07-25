# Session & Onboarding State-Machine Map — element.inblock.io path

**Date:** 2026-07-25  
**Mode:** Process-pipeline **Phase 1 PLAN only** (no implementation until plan is confirmed)  
**Method:** Kellogg Logic Model + closed-case matrices + total hierarchical state machines  
**Primary path:** `https://element.inblock.io` → `siwx-oidc.inblock.io` → `matrix.inblock.io` (MSC3861)  
**Repo branch (local work):** `audit/siwx-oidc-functional-harness` (≠ prod, ≠ main — see audit)  
**Prod image (verified live):** `ghcr.io/inblockio/siwx-oidc:sha-db79e75` (container up ~3 weeks)

> **AUDITED PROPOSAL (authoritative for execution):**  
> `docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md`  
> That document supersedes this map on: (1) **mandatory local container + thorough Playwright Phase 2.0**,  
> (2) **code assumption verdicts** (notably: login-time `allow_cross_signing_reset` is **NOT implemented**),  
> (3) Matrix MSC scope, (4) skills correctness, (5) revised phase order.  
> Keep this file as the long-form M0–M5 catalog; use the audited proposal as the execution contract.

---

## 0. How we will solve this (methodology)

This is not a “fix the bugs we notice” problem. The onboarding surface is a **composed system** of five coupled state machines (identity, ceremony, OIDC tokens, Matrix devices, cross-signing/4S). Failures appear as “undefined states” when a transition is missing, partial, or lied about (success UI without effective grant).

### Methodology stack (chosen, not invented)

| Layer | Method | Why it fits |
|-------|--------|-------------|
| **Causal planning** | W.K. Kellogg Logic Model (`/logic-model`, `/process-pipeline`) | Every change is an if-then hypothesis with verification |
| **Case closure** | Closed-case matrices (already used in passkey design docs 2026-06-18/19) | Every (input × path) cell has exactly one terminal outcome — no “and then…?” |
| **Control theory** | Ashby’s law of requisite variety | Controller (siwx-oidc + our tests) must match the variety of auth × device × crypto outcomes |
| **State machines** | Hierarchical FSMs with **total** transition functions | No open ends: every state + event has a defined next state and a user-visible terminal |
| **Spec orientation** | Matrix MSCs + repo skills as the capability contract | We implement what MSC3861/4191/4312/3967/4108/4341 require, not ad-hoc UX |

### Definition of “complete” for a machine

A machine is complete iff:

1. **Finite states** — each state is observable (Redis key, Synapse row, client UI, or log field).
2. **Total transitions** — for every (state, event) pair, either a next state is defined or the event is **rejected** with a terminal error (never silently ignored).
3. **Terminals only** — every path ends in a named terminal: `OK_*` or `FAIL_*` or `RECOVER_*` (user can act).
4. **No false success** — UI “success” is allowed only when the load-bearing side effect is verified (or honesty fix reports non-success).
5. **Falsifiable** — each critical edge has a test or prod log signature that would go red if the edge breaks.

### Session discipline

```
Phase 1 PLAN  ← we are here (this document + AUDITED PROPOSAL)
  Gate: you confirm goal, machines, priorities, deploy policy, lab-first constraint
Phase 2.0 LAB  — unify local stacks + thorough Playwright (mandatory before product code)
Phase 2.1+ EXECUTE — product transitions only on green lab; subagent-driven
Phase 3 AUDIT    — hypothesis trace + acceptance criteria with evidence
```

### Non-negotiable lab constraint

All development for this workstream runs on **this machine** against **container-spawned**
stacks (mock and/or real Synapse). Product changes require **Playwright (and Rust e2e)
coverage of the affected M0–M5 states** before any prod deploy. Details: audited proposal §1.

---

## 1. CONTEXT (where we are)

### 1.1 Topology (element.inblock.io path)

```
Browser / Element Web (element.inblock.io)
        │  OIDC redirect (MSC3861)
        ▼
siwx-oidc (siwx-oidc.inblock.io)  ── Redis (sessions, tokens, webauthn, device codes)
        │  provision / allow_cross_signing_reset / introspect
        ▼
Synapse (matrix.inblock.io)  ── devices, cross-signing public keys, 4S account_data, megolm backup
```

siwx-oidc **replaces MAS**. There is no Matrix Authentication Service in this path.

### 1.2 Prod vs main vs experimental branches (do not trust “fixed on main”)

| Ref | What it is | In prod? | Trust for planning |
|-----|------------|----------|--------------------|
| **`sha-db79e75`** | PR#13: cookie-scoped passkey picker + login-only new-user gate + Secure Backup wording | **YES (live)** | Ground truth of live behavior |
| **`origin/main` @ f0d991d** | + refresh grace (3f40485), method-prediction revert (a074795), **cross-signing-reset honesty gate** (f0d991d), forensics | **NO** | Source of candidate fixes; must re-verify |
| **`feat/passkey-offer-scoping` @ 8e7fcfe** | identity-scope account+device pickers via `siwx_user` cookie | **NO** (was briefly user-tested, rolled back) | Treat as experimental; may help or backfire |
| **`feat/passkey-scoping-new-user-gate`** | earlier variant of cookie scoping | NOT in main as tip | Superseded by db79e75 lineage |
| **`rollback/passkey-method-prediction`** | grey-out revert lineage | merged into main | Grey-out was correctly reverted |
| **`fix/refresh-token-grace`** | Element X refresh race | on main, **not live** | Safe to redeploy (forensics: orthogonal to XS reset) |

**Memory note:** `passkey-offer-scoping-cookie` memory said prod was pinned to `feat-passkey-offer-scoping` for user testing; **live check 2026-07-25** shows rollback to `SIWX_OIDC_TAG=sha-db79e75`. Memory is stale; prod tag is source of truth.

### 1.3 What skills say we must support (spec capability set)

| Skill / MSC | Capability required |
|-------------|---------------------|
| `authenticate-siwe-matrix` | Wallet CAIP-122 + passkey → auth code → tokens → whoami |
| `cross-signing-bootstrap-and-debug` | MSC3967 first upload; login-time `allow_cross_signing_reset`; MSC4312 reauth for **reset** |
| `element-x-qr-code-specialist` + protocol doc | RFC 8628 device grant + MSC4108 **2024** rendezvous + Phase-4 secret transfer |
| MSC4191 | Account management actions (profile, devices, delete, deactivate, erase, reactivate, **cross_signing_reset**) |
| MSC3861 | Opaque tokens, introspection, device-scoped scope, no native CS-API UIA |
| aqua-auth | All configured DID methods/namespaces at sign-in (pkh + opt-in key/peer; wallets + passkeys) |

### 1.4 Live log evidence (matrix.inblock.io / siwx, pulled 2026-07-25)

**A. Refresh-token storm (systemic, ongoing)**  
- Last 72h on siwx: **~548** `bad_request_token` / `invalid_grant` “Unknown or expired refresh token.”  
- This is the Element X dual-refresh race that **`3f40485` grace window** was written for — **not deployed**.

**B. Fresh passkey onboarding half-stuck (2026-07-25 ~02:15–02:25 UTC, Mac Chrome)**  
Identity: `@did-key-zdnaehrpvanpx1fz6ot1h3vzarehz2zxuw9t9n8zqtz6xaqeg:matrix.inblock.io`

| Time | Event |
|------|--------|
| 02:16:55 | `webauthn register_finish` → `did:key:zDnaehRP…` |
| 02:17:23 | `authenticate_finish` same cred |
| 02:17:27 | `sign_in` server-verified |
| 02:17:39 | `POST keys/device_signing/upload` **200** (first-time / MSC3967 path) |
| 02:21:19–20 | PUT private cross-signing halves + 4S-related account_data |
| 02:21:22–23 | `device_signing/upload` **401 ×2** |
| 02:20–02:24 | Repeated scoped passkey login (cookie scoping active: `scoped did=… creds=1`) |

Interpretation: first publish can succeed; a subsequent **reset-shaped** upload is rejected without an effective grant → classic half-identity / “verify session” loop class.

**C. Device-code (“authenticate other device”) partially works**  
- 2026-07-22 and 2026-07-24: `device_authorization` issued + **approved** for wallet DID `did:pkh:…0x530554…`.  
- So RFC 8628 approval itself is not dead; residual failures are likely **post-token** (cross-signing transfer / Secure Backup missing on approver), not “endpoint 500.”

**D. 7d `device_signing/upload` status mix (Synapse access log)**  
- Sparse traffic; both **200** and **401** present for passkey (`did:key:zDn…`) users.  
- Matches “some onboardings land; some wedge on reset/re-upload.”

**E. Prior forensic (2026-06-24) still the reference failure mode**  
- User `@did-pkh-…0x23d6…`: destructive 4S+XS **RESET**, 14× `device_signing/upload` 401.  
- Later: reauth **showed SUCCESS** but grant ineffective (master-row UPDATE no-op) — fixed on **main** (`f0d991d`), **not in prod**.

---

## 2. GOAL (one sentence)

> Deliver a **complete, closed state-machine map** of Matrix session & onboarding via element.inblock.io, grounded in prod forensics and MSC capability, such that every observed failure maps to a named bad state and every remediation path has a verified transition — then (only after plan confirmation) implement and deploy the minimal set of transitions that eliminate undefined / lying states for wallet + all aqua-auth keys + passkeys.

**Measurable done (for the plan artifact):**  
- Machines M0–M5 defined with total transitions and terminals.  
- Each user-reported defect (a–d) mapped to states + live evidence + candidate fix class.  
- Hypothesis register with verification commands.  
- Prioritized execution backlog (deploy vs code vs client-upstream) for Phase 2.

**Out of scope for Phase 1:** code changes, prod deploy, Element Web forks (unless later as an explicit decision).

---

## 3. INPUTS

| Input | Path / source | Consumed by |
|-------|---------------|-------------|
| Live prod tag + logs | `deploy@agentic.inblock.io:8022`, stack `/home/deploy/matrix/stack` | Evidence of undefined states |
| Forensics | `docs/audits/2026-06-24-grace-deploy-device-verify-forensics.md` (main) | XS reset mechanism |
| Fix model | `docs/audits/2026-06-24-cross-signing-reset-fix-logic-model.md` | Honesty-gate design |
| Requirement map | `docs/audits/2026-06-14-siwx-oidc-requirement-map.md` | R-A…R-K / H1…H14 |
| Passkey case matrices | `docs/design/2026-06-18-…`, `2026-06-19-…` | Offer scoping + new-user gate |
| Skills | `skills/{authenticate-siwe-matrix,cross-signing-bootstrap-and-debug,element-x-qr-code-specialist}.md` | Spec capability |
| Code (prod-equivalent) | `db79e75` tree for live behavior; `main` for candidate fixes | Transition implementation |
| aqua-auth | DID methods / CAIP-122 / WebAuthn assertion | Ceremony truth |

---

## 4. THE FIVE COUPLED STATE MACHINES (complete)

Notation:

- **States** in `PascalCase`
- **Events** in `snake_case`
- **Terminals** prefixed `T_`
- **Observability:** how we know we are in that state (Redis / Synapse / client / log)

Cross-cutting invariant: **device IDs never recycled** (R-I1). **RFC 7009 revoke ≠ device delete** (H1).

---

### M0 — Identity binding (DID ↔ Matrix user)

**Purpose:** Map a proven crypto identity to exactly one Matrix localpart/mxid.

| State | Meaning | Observable |
|-------|---------|------------|
| `IdUnknown` | No proven DID yet | No verified session / no siwx cookie |
| `IdProven` | Ceremony produced DID | `session.verified_did` or verified `siwx` cookie |
| `MxUserExists` | Localpart already provisioned | `is_localpart_available == false` |
| `MxUserAbsent` | Localpart free | `is_localpart_available == true` |
| `T_Bound` | Synapse user exists for DID | `provision_user` done / whoami works |
| `T_RejectedNew` | New identity forbidden on this path | 4xx on account/QR paths |
| `T_GatePending` | Login new-user gate awaiting confirm | UI gate (prod db79e75) |
| `T_CreateFailed` | Provision failed | logs; no half user if best-effort clean |

**Transitions (total for login / account / QR):**

| From | Event | Login path | Account re-auth | QR / device approve |
|------|-------|------------|-----------------|---------------------|
| `IdUnknown` | `ceremony_ok(did)` | → `IdProven` | → `IdProven` | → `IdProven` |
| `IdProven` | `check_localpart` → exists | → `MxUserExists` → provision device → `T_Bound` | must match session DID → action | must exist else `T_RejectedNew` |
| `IdProven` | `check_localpart` → free | → `T_GatePending` (new-user gate) | **`T_RejectedNew`** | **`T_RejectedNew`** |
| `T_GatePending` | `user_confirm_create` | → provision → `T_Bound` | n/a | n/a |
| `T_GatePending` | `user_cancel` | → `IdUnknown` (no Synapse write) | n/a | n/a |
| any | `erase_identity` | → credentials purged; mxid deactivated | same | same |

**Closed cases (login only — birth is exclusive to login):**

| # | Proven DID | Localpart | User action | Terminal |
|---|------------|-----------|-------------|----------|
| L1 | existing | taken | continue | `T_Bound` same mxid |
| L2 | new | free | confirm | `T_Bound` new mxid |
| L3 | new | free | cancel | no mxid |
| L4 | wrong account’s passkey | taken by other | continue | `T_Bound` as **that** account (recoverable by logout) — residual risk, documented |
| L5 | stale passkey | n/a | pick dead cred | `FAIL_unknown_credential` + signal prune |

**Undefined state we hit historically:** silent create on unrecognized passkey (pre-gate). **Mitigation on prod:** new-user gate (db79e75). **Residual:** L4 intentional.

---

### M1 — Auth ceremony (wallet | passkey | device-approve)

#### M1a Wallet (CAIP-122)

| State | Observable |
|-------|------------|
| `W_Idle` | login page |
| `W_NonceIssued` | OIDC session + `siwe_nonce` (TTL 300s) |
| `W_Signed` | `siwx` cookie present (untrusted) |
| `W_Verified` | `/sign_in` signature+nonce+resource OK |
| `T_CodeIssued` | auth code in Redis |
| `T_FailNonce` / `T_FailSig` / `T_FailResource` / `T_FailSession` / `T_FailMethod` | typed rejects |

Passkeys across Apple devices: **not this machine** — wallet is device-local provider injection.  
Passkey roaming is M1b.

#### M1b Passkey (WebAuthn)

| State | Observable |
|-------|------------|
| `P_Idle` | login / account / device page |
| `P_Challenge` | `webauthn:challenge/{sid}` TTL 120s |
| `P_Asserted` | browser returned assertion |
| `P_Verified` | `verify_credential` OK; DID resolved (link or did:key) |
| `P_ScopedOffer` | `allowCredentials` non-empty from cookie scope |
| `P_UsernamelessOffer` | empty allow list (discoverable) |
| `T_VerifiedDidInSession` | `session.verified_did` set |
| `T_FailUnknownCred` | 401 `unknown_credential` + optional Signal API |
| `T_FailChallenge` / `T_FailCounter` / `T_FailRP` | other failures (no prune) |

**Cross-device (Apple iCloud Keychain):** same credential id → same DID → same Matrix account. This is **supported and desired** when the user intends one account. The danger is only **wrong-account pick** (M0 L4) or **stale cred** (L5).

**Offer scoping policy (canonical, from 2026-06-19 design):**

| Path | Identity known? | Offer rule | Create allowed? |
|------|-----------------|------------|-----------------|
| Login | maybe (cookie) | scope if cookie; always escape hatch to usernameless | yes, behind gate |
| Account | yes (`acct_session`) | **only this DID’s keys** | never |
| Device / QR | ideally yes | **only this DID’s keys** when carrier exists | never |

**Branch risk (`feat/passkey-offer-scoping`):** improves account/device offer honesty; not live. Must not re-open credential enumeration (opaque cookie only).

#### M1c Device approval (RFC 8628)

| State | Observable |
|-------|------------|
| `D_Issued` | `device_codes/*` + `user_codes/*` |
| `D_Pending` | poll → `authorization_pending` |
| `D_SlowDown` | poll too fast |
| `D_Approved` | status Approved + DID + device_id |
| `D_Denied` / `D_Expired` | terminal no tokens |
| `T_TokensIssued` | device_code grant redeemed once |
| `T_FailDoubleRedeem` | second poll after consume fails (H9) |

**Post-token (client, not siwx):** MSC4108 Phase 4 secret transfer. If approver has no cross-signing private keys in Secure Backup → Element X fails **after** “Device approved.” That is **M4**, not M1c.

---

### M2 — OIDC session & tokens

| State | Observable |
|-------|------------|
| `O_Authorize` | session cookie + SessionEntry |
| `O_Code` | CodeEntry (single-use) |
| `O_Active` | access `mat_*` + refresh `mcr_*` in Redis |
| `O_Refreshing` | refresh grant in flight |
| `O_GraceReplay` | **main only** rotated-token grace window (60s) |
| `O_Revoked` | introspection `active:false` |
| `T_FailInvalidGrant` | unknown/expired refresh (prod storm) |
| `T_FailPkce` / `T_FailClient` / `T_FailCodeReplay` | binding rejects |

**Prod defect:** without grace, concurrent Element X refresh → first wins, second `invalid_grant` → session death / sign-out loops. **Fix on main, not live.**

---

### M3 — Matrix device lifecycle

| State | Observable |
|-------|------------|
| `Dev_None` | no SIWX device yet |
| `Dev_Provisioned` | `upsert_device` SIWX_{uuid} or client device_id |
| `Dev_TokenBound` | TokenMetadata.device_id set |
| `Dev_Deleted` | Synapse device gone + tokens revoked (explicit intent only) |
| `T_FailSynapse` | best-effort fail, never 500 user path; retry converges (H14) |

**Teardown policy (intent, not transport):**

| Intent | Endpoint family | Device | Tokens |
|--------|-----------------|--------|--------|
| Token hygiene | `/oauth2/revoke` | keep | revoke |
| Explicit sign-out | `/logout`, `device_delete` | delete | revoke |
| Sign out all | `/logout/all` | delete all | revoke all |
| Deactivate / erase | account actions | (via Synapse deactivate) | revoke all |

---

### M4 — Cross-signing + Secure Backup (THE machine with undefined states)

This is where “session authentication / reset loops” live. Split **public** (Synapse) and **private** (client account_data / 4S).

#### Public cross-signing (Synapse)

| State | Meaning | Observable |
|-------|---------|------------|
| `XS_Absent` | no master public key | `has_cross_signing_keys == false` |
| `XS_Present` | master (+ usually SSK/USK) published | keys query |
| `XS_ResetArmed` | UIA-bypass window planted on master row | Synapse internal `updatable_without_uia_before_ms` |
| `XS_ResetArmedIneffective` | allow API 2xx but **0 rows updated** (no master) | **prod lying success** |
| `XS_UploadRejected` | `device_signing/upload` 401 | access log |
| `T_XS_OK` | public identity consistent with client | upload 200 + keys query |
| `T_XS_HalfReset` | private 4S rewritten, public missing/stale | account_data 200 + upload 401 |
| `T_XS_HonestFail` | siwx reports non-success when grant ineffective | **main f0d991d** `ResetUnconfirmed` |

#### Private secrets / 4S (client-side, Synapse account_data)

| State | Meaning |
|-------|---------|
| `S4_Absent` | no default 4S key |
| `S4_Present` | recovery key usable |
| `S4_Rotated` | new 4S key written (possibly mid-loop) |
| `Backup_Vn` | megolm backup version n |
| `Backup_Deleted` | DELETE room_keys/version |

#### Critical transition table (must be total)

| From | Event | Intended next | Failure / honesty |
|------|-------|---------------|-------------------|
| `XS_Absent` | first `device_signing/upload` (MSC3967) | `T_XS_OK` | if 401 → config/discovery bug (not UIA) |
| `XS_Present` | unlock with recovery key | stay `XS_Present`, secrets local | wrong key → client-local fail (no server) |
| `XS_Present` | **reset** (DELETE backup + new secrets) | needs arm → upload | without arm → `XS_UploadRejected` → **`T_XS_HalfReset`** |
| any | `allow_cross_signing_reset` HTTP 2xx + master exists | `XS_ResetArmed` | |
| any | `allow_…` 2xx + **no master** | prod: false `Completed`; main: `T_XS_HonestFail` / special case | **must not say success** |
| `XS_ResetArmed` | `device_signing/upload` within window | `T_XS_OK` | after window expiry → 401 again |
| `T_XS_HalfReset` | login (login-time allow) + retry upload | `T_XS_OK` if master row can be armed | may need logout/login |
| `T_XS_HalfReset` | reauth account page | same as allow | honesty gate on main |

**Undefined / lying states observed in prod (must be eliminated):**

| ID | Bad state | Evidence | Fix class |
|----|-----------|----------|-----------|
| U1 | Success banner while grant no-op | 2026-06-24 forensic update | Deploy `f0d991d` honesty gate; ideally functional arm for no-master |
| U2 | Private 4S reset without public publish | 14×401; 2026-07-25 401 after 4S PUTs | Client must follow MSC4312; server must not lie; optional alert on N×401 |
| U3 | Double 4S churn mid-loop | two default keys in one session | UX: stop loop; recover path |
| U4 | History keys destroyed by reset | DELETE backup v3 | Product: prefer unlock over reset; set expectations |

---

### M5 — Multi-device trust (“authenticate with other device”)

User defect **(a)**. Two distinct protocols often conflated in UI:

| Flow | Protocol | siwx role | Success condition |
|------|----------|-----------|-------------------|
| **QR login new device** | MSC4108 + RFC 8628 | device_code + approve + tokens | Tokens + **secret transfer** from approver |
| **Interactive verification** | SAS / emoji (Matrix crypto) | none (Synapse + clients) | Both devices share XS trust |
| **Recovery key unlock** | 4S | none | Decrypt private XS + backup |
| **Cross-signing reset reauth** | MSC4312 | `/account?action=cross_signing_reset` | Effective allow + upload 200 |

**Closed terminals for QR login:**

| # | Approver XS private keys | Approver Secure Backup | Device approve | Token poll | Phase-4 transfer | Terminal |
|---|--------------------------|------------------------|----------------|------------|------------------|----------|
| Q1 | present | present | OK | OK | OK | `T_NewDeviceOK` |
| Q2 | missing | n/a | OK | OK | **fail / timeout** | `T_ApprovedButDead` (user sees login fail after 30–60s) |
| Q3 | present | missing (keys only local) | OK | OK | may fail | `T_ApprovedButDead` or partial |
| Q4 | n/a | n/a | denied/expired | — | — | `T_NoTokens` |
| Q5 | n/a | n/a | approve with **new** DID | — | — | `T_RejectedNew` (policy) |

**Prod evidence:** Q1-class approvals exist (wallet DID). Q2 is the documented Element X failure mode when Secure Backup never set up.

---

## 5. Mapping user defects → machines

### (a) “Authenticate with other device seems not to work”

| Likely state | Machine | Evidence | Direction |
|--------------|---------|----------|-----------|
| `T_ApprovedButDead` (Q2) | M5 + M4 | skill + CLAUDE.md; approvals succeed in logs | Ensure approver has XS+backup; pre-flight warning; don’t promise QR without M4 `T_XS_OK` |
| Interactive verification fails | M5 (client) | half-reset identity | Fix M4 first |
| Device page offer wrong keys | M1b | offer-scoping branch not live | Evaluate `8e7fcfe` carefully |

### (b) “Authenticating your session (reset) fails — loop”

| State | Machine | Evidence | Direction |
|-------|---------|----------|-----------|
| `T_XS_HalfReset` | M4 | 2026-06-24 forensic; 2026-07-25 401 after 4S | Deploy honesty fix; recovery runbook; alert |
| `XS_ResetArmedIneffective` | M4 | allow 2xx, no master row | f0d991d + possible Synapse limitation |
| Element retries upload, never opens account URI | M4/M5 client | 14×401 no reauth | Discovery parity + Element behavior; server-side can’t fully fix |

### (c) Branch that tried to fix things — live or not? backfire?

| Branch / commit | Live? | Assessment |
|-----------------|-------|------------|
| `db79e75` (passkey cookie scope + new-user gate) | **YES** | Mostly good; residual L4; scoping logs show `scoped did=… creds=1` working |
| `3f40485` refresh grace | NO | **Should deploy**; orthogonal to XS; fixes invalid_grant storm |
| `f0d991d` XS reset honesty | NO | **Should deploy**; stops lying success; may still need no-master functional path |
| `8e7fcfe` offer-scoping account/device | NO (rolled back) | Re-evaluate under closed cases; do not assume safe |
| Method grey-out prediction | reverted on main | Correctly rejected (predicting passkey reachability is wrong) |

### (d) Skills / MSC conformance

Skills already encode the capability matrix in §1.3. Implementation debt is not “missing MSC4191 listing” (discovery has full action set live) but **effectiveness of actions** (reset grant) and **token lifecycle** (grace) and **post-approve crypto** (M4/M5).

---

## 6. Hypothesis register (planning → Phase 2)

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H-P1 | Prod is `sha-db79e75` | Live behavior ≠ main for grace + XS honesty | Tag not flipped mid-session | `docker inspect` / `.env SIWX_OIDC_TAG` |
| H-P2 | Concurrent refresh without grace | `invalid_grant` storms and mobile sign-out | Element X dual refresh | 72h log count; e2e refresh race |
| H-P3 | XS reset allow without master row | HTTP 2xx but upload still 401 | Synapse 1.15x contract | real-Synapse e2e legs (main tests) |
| H-P4 | Honesty gate deployed | False success banner impossible | f0d991d semantics | unit `reset_outcome` + e2e |
| H-P5 | New-user gate on login | Accidental account create requires confirm | gate UI wired in db79e75 | browser e2e |
| H-P6 | QR approve without approver XS secrets | Tokens issue but Element X fails after | MSC4108 Phase 4 | skill repro; logs show approve + client fail |
| H-P7 | Same Apple passkey on two devices | Same DID / same mxid | iCloud sync resident key | manual + logs (already seen multi sign_in same did:key) |
| H-P8 | Offer-scoping branch | Account/device only own keys; no enum leak | opaque cookie only | security review + browser e2e before any redeploy |
| H-P9 | Login-time `allow_cross_signing_reset` | ~~Softens first post-login upload~~ | **INVALIDATED (2026-07-25 code audit):** not called from provision/sign_in on prod or main. First upload = MSC3967 only. | do not plan recovery on “log in again” |
| H-P10 | Deploy grace + honesty together | Refresh storm drops; reset loops become honest/recoverable | no unrelated regressions; grace also matches Matrix OAuth “old refresh valid until new used” | staged deploy + 48h metrics |

---

## 7. Logic-model chain (plan → impact)

```
Inputs (prod logs, MSCs, skills, main fixes, aqua-auth)
  → Activities
      A1 freeze live baseline (tag, discovery, well-known)
      A2 close state machines M0–M5 (this doc; refine with you)
      A3 rank remediation: deploy-only vs code vs client-upstream
      A4 [Phase 2] implement missing transitions only
      A5 [Phase 2] harness tests per hypothesis
      A6 [Phase 2] staged prod deploy + watch invalid_grant + device_signing 401 rates
  → Outputs
      complete map; hypothesis register; ordered backlog; (later) green tests + deployed bits
  → Outcomes
      no lying success; no undefined half-reset; refresh stable; QR only offered when M4 allows;
      wallet + all aqua-auth DIDs + passkeys complete closed paths
  → Impact
      element.inblock.io onboarding is robust and operable
```

---

## 8. Proposed Phase-2 backlog (not started — needs your confirmation)

Priority is **eliminate undefined/lying states first**, then **deploy known-good main fixes**, then **optional offer-scoping**.

| Pri | Work | Type | Machines | Hypotheses |
|-----|------|------|----------|------------|
| P0 | Recovery runbook for half-reset users: **account `cross_signing_reset` reauth** or **admin allow** + retry upload — **not** “log in again arms allow” (that is false in code) | ops | M4 | H-P3 |
| P1 | Deploy **refresh grace** (`3f40485` / main) to prod | deploy | M2 | H-P2, H-P10 |
| P2 | Deploy **XS reset honesty** (`f0d991d`) to prod | deploy | M4 | H-P3, H-P4, H-P10 |
| P3 | Product decision: no-master functional arm (Synapse limitation) vs honest-only | design spike | M4 | H-P3 |
| P4 | Observability: alert on N consecutive `device_signing/upload` 401 per user without allow | code+ops | M4 | H-P6 |
| P5 | QR pre-flight: refuse/warn hard if approver has no published XS (not only public key race) | code | M5 | H-P6 |
| P6 | Re-evaluate `feat/passkey-offer-scoping` against M1 closed cases; only then consider | branch review | M1b | H-P8 |
| P7 | Expand e2e: half-reset recovery, multi-device passkey same DID, refresh race under prod-like concurrency | test | M0–M5 | all |
| P8 | Discovery/well-known audit: nested `m.authentication.account` vs top-level key — client follow behavior | probe | M4/M5 | Element follow MSC4312 |

**Explicit non-goals until map confirmed:** large refactors; inventing new DID methods; forking Element Web; promoting unreviewed offer-scoping to prod.

---

## 9. BOUNDARY CONDITIONS

**Invariants**

1. Never recycle device IDs.  
2. Revoke ≠ delete device.  
3. Never render success when grant/effect is unconfirmed.  
4. New Matrix identity **only** on login path behind gate.  
5. No credential enumeration via forgeable identity hints.  
6. No prod deploy without your explicit go-ahead.  
7. aqua-auth remains pure crypto; ceremonies stay server-side.

**Assumptions**

- A1: Synapse prod gates `device_signing/upload` like the documented MAS allow contract.  
- A2: Element Web may not follow 401 → account_management_uri (upstream).  
- A3: Passkeys that roam (Apple) are one credential / one DID (desired).  
- A4: Manual deploys only (`SIWX_OIDC_TAG`).

**Risks (top 3)**

1. Deploy honesty-only fix without recovery UX → users still stuck but no longer lied to (better, still incomplete).  
2. Redeploy offer-scoping without enum review → security regression.  
3. Treat client Phase-4 failures as siwx bugs → wasted fix cycles.

**Loop exit (planning):** you confirm §2 goal, §4 machines, §8 priority order (or amend).  
**Loop exit (execution later):** every U1–U4 either eliminated or accepted with documented terminal + runbook; H-P* confirmed with evidence.

---

## 10. Decisions needed from you (gate before Phase 2)

1. **Goal confirmation:** Is §2 the right one-sentence goal, or should we narrow (e.g. “only XS half-reset + refresh”) before multi-device QR polish?  
2. **Deploy appetite:** Are P1+P2 (grace + honesty from main) acceptable as the first execution slice after a dry-run on the local real stack?  
3. **Offer-scoping branch:** Keep **out** of the first slice (recommended) or force-evaluate now?  
4. **Affected users:** Do you want an operator recovery pass on known half-reset mxids before/during deploy?  
5. **Passkey multi-device:** Confirm desired policy: **one Apple passkey → one account on all devices** (recommended, matches WebAuthn) vs any restriction.

---

## Appendix A — Quick prod commands (forensic)

```bash
ssh -p 8022 deploy@agentic.inblock.io
cd /home/deploy/matrix/stack
grep SIWX_OIDC_TAG .env
docker logs matrix-siwx-oidc-1 --since 24h 2>&1 | grep -E 'invalid_grant|sign_in|webauthn|allow_cross|unknown_credential'
docker logs matrix-matrix_synapse-1 --since 24h 2>&1 | grep 'device_signing/upload'
```

## Appendix B — Related artifacts

- `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`  
- `docs/audits/2026-06-24-grace-deploy-device-verify-forensics.md` (main)  
- `docs/audits/2026-06-24-cross-signing-reset-fix-logic-model.md` (main)  
- `docs/design/2026-06-18-passkey-scoping-and-new-user-gate.md`  
- `docs/design/2026-06-19-passkey-offer-scoping-minimal-behavior.md`  
- Skills under `skills/`

---

*End of Phase-1 plan artifact. No implementation until you confirm the gate decisions in §10.*
