# Audited Proposal — Session & Onboarding State Machines

**Date:** 2026-07-25  
**Parent map:** `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md`  
**Status:** Phase-1 PLAN — **audited + decisions locked** (except optional product flag in §12). No implementation until Phase 2.0 starts.  
**Process:** process-pipeline Phase 1; three read-only subagents + Matrix MSC research + owner gate answers.

### Locked owner decisions (2026-07-25)

| # | Decision | Lock |
|---|----------|------|
| 1 | **Base branch** | Work from **`origin/main`** (tip currently includes grace + XS honesty). |
| 2 | **Harness before product** | **YES.** Phase 2.0 lab (unified stack + complete Playwright) before feature PRs. |
| 3 | **Login-time allow_cross_signing_reset** | **LOCKED 3B** — restore allow on every successful login (best-effort). |
| 4 | **Element Web** | **MUST** test against a **real Element Web instance** in the local container stack (not only siwx HTML). |
| 5 | **Prod deploy** | **Wait until complete** — no staged partial deploy of grace/honesty alone. Ship only when lab + Element Playwright suite + product work are done and green. |

---

## 1. Non-negotiable development constraint (your requirement)

> **All product development for this workstream MUST be done against a complete local stack on this machine**, with **thorough Playwright coverage of the state machines**, using **container-spawned** Redis + siwx-oidc + Synapse (mock and/or real) and related edge services. Prod is for forensics and staged deploy only — never the primary lab.

### 1.1 What “thorough” means (acceptance for the test system itself)

| Criterion | Definition |
|-----------|------------|
| **Per-state observability** | Every M0–M5 state either is exercised by a named test or is explicitly marked OUT-OF-SCOPE with rationale |
| **Per-terminal assertion** | Every terminal (`OK_*` / `FAIL_*` / `RECOVER_*`) has at least one falsifying test |
| **Containerized listeners** | No host-bound listeners outside podman/docker (existing sandbox rule) |
| **One orchestrator entrypoint** | A single local command (or documented pair: mock + hermetic) runs the full gate |
| **No green-on-mock-only for crypto** | M4 public XS paths that depend on Synapse `device_signing/upload` run against **real Synapse** |
| **Playwright is first-class for UI paths** | Login, `/account`, `/device`, passkey/wallet ceremonies that have HTML must have browser specs |
| **Real Element Web** | Local stack **must** include a running Element Web container; Playwright drives **Element’s** UI for session/onboarding flows that users actually use (manage sessions, remove device, verify/reset, link new device), not only siwx-oidc’s standalone pages |

### 1.2 Local stack variants (inventory — audited)

| ID | Stack | Bring-up | Containers | Role in M0–M5 |
|----|-------|----------|------------|---------------|
| **S-mock** | Mock Synapse | `bash e2e/up.sh` | `siwx-e2e-{redis,mock,oidc}` :6379/:8090/:8080 | Fast: M0–M3, M1c surface, races, Playwright account/login |
| **S-hermetic** | Real Synapse unified | `~/siwx-oidc-matrix-server/e2e-harness/up.sh` → `run.sh` | `siwx-e2eh-*` (+ Caddy, optional LiveKit) | M2 refresh, M4 XS legs, M5 device_code tokens |
| **S-real** | Hand-rolled real | CLAUDE real-stack recipe | `siwx-real-*` + optional edge `:8450` | Prod-like edge logout; connector E2EE |
| **S-element** | Dev compose Element Web | `siwx-oidc-matrix-server` docker-compose.local | **element-web** + caddy `:8088` client, siwx `:8081`, matrix `:8080` | Manual today; **must become automated Playwright target** |
| **S-hermetic+EW** *(target)* | Hermetic + Element Web | extend `e2e-harness/up.sh` | current `siwx-e2eh-*` **+** `siwx-e2eh-element` (+ edge) | **Required Phase 2.0 target stack** for Element-driven specs |

**Critical fragmentation (must fix in Phase 2.0 before product code):**

| Problem | Impact |
|---------|--------|
| Thorough suites live partly in **`~/siwx-oidc-e2eh`**, not this workspace | `e2e/run-all.sh` green ≠ full coverage |
| Mock `is_localpart_available` always returns available | New-user gate / reject-new-identity **untestable** on mock |
| **No Element Web** in any automated harness | Cannot Playwright “verify session” / full Element bootstrap / QR UI |
| Working tree `audit/siwx-oidc-functional-harness` ≠ prod `db79e75` ≠ `origin/main` | Wrong baseline if we develop here without pin |

### 1.3 Required harness expansion (Phase 2.0 — **before** feature work)

**Goal:** One developer can run, on this machine:

```text
# A — in-provider UI + policy (Playwright + mock)
bash e2e/up.sh && bash e2e/run-all.sh          # must include expanded specs

# B — real Synapse crypto + device_code + refresh grace
# (pin single siwx-oidc tree; no e2eh fork drift)
bash <hermetic>/run.sh full
```

| Work item | Closes | Stack |
|-----------|--------|-------|
| **H0** Unify test source: port e2eh-only suites into primary tree (`e2e_device_code`, `e2e_oauth_binding`, XS legs, `passkey-scoping.spec.mjs`, refresh-grace race) | Fragmentation | S-mock + S-hermetic |
| **H1** Seedable mock: `is_localpart_available`, optional `has_cross_signing_keys`, device seeds | M0 gate, M1c reject-new | S-mock |
| **H2** Playwright `login-gate.spec.mjs` — new user confirm/cancel; wrong-account residual documented | M0 L1–L5 | S-mock |
| **H3** Playwright `device-approval.spec.mjs` — `/device` wallet + passkey, pending poll, reject new DID, XS warning copy | M1c | S-mock |
| **H4** Playwright `link-passkey.spec.mjs` | M1b link | S-mock |
| **H5** Playwright account menu / deactivate / CSRF (extend existing) | M3/G | S-mock |
| **H6** Real-Synapse Rust (or thin browser) XS legs: first upload, reset+honesty, no-master | M4 | S-hermetic |
| **H7** Refresh dual-call grace race test | M2 | S-mock or hermetic |
| **H8** **REQUIRED:** Element Web container in local stack + Playwright against Element UI | Element path | S-hermetic+EW or docker-compose.local |
| **H9** MSC4108 Phase-4 / Q2 “approved but dead” | Element “Link new device” / QR where automatable; else connector + named manual | S-hermetic+EW |

### 1.4 Element Web Playwright suite (mandatory — owner decision #4)

**Principle:** Users do not live on bare `siwx-oidc.inblock.io` pages alone. They live on **Element** (`element.inblock.io` prod / local Element container). Account management, session list, remove device, verify/reset encryption, and “authenticate other device / link new device” must be proven **through Element’s UI**, with real local Synapse + siwx-oidc behind it.

**Base stack pieces already exist:**

- `siwx-oidc-matrix-server/docker-compose.local.yml` → `element-web` (Dockerfile.element + patches) + siwx-oidc + Synapse + Caddy (`CLIENT_HOST_PORT` default **8088**).
- Hermetic `e2e-harness` today has Synapse + OIDC + edge **but no Element** — **add** Element (or run Element compose as the primary lab and wire Playwright there).
- Wallet: inject mock `window.ethereum` (existing `wallet-helper.mjs` patterns) into pages that hit siwx origin during OIDC redirect.
- Passkey: CDP WebAuthn virtual authenticator (existing `webauthn-helper.mjs`).

#### Required Playwright scenarios (Element-driven)

| ID | User journey (Element UI) | Machines | Assert (server-side / UI terminal) |
|----|---------------------------|----------|-------------------------------------|
| **EW-L1** | First wallet login via Element → lands in app (whoami / room list) | M0–M3 | Session active; device provisioned |
| **EW-L2** | First passkey register+login via Element OIDC | M0–M1b–M3 | Same DID/mxid stable; device provisioned |
| **EW-L3** | Returning login (same identity, second Element “session”) | M0, M3 | New device id; no recycle of previous |
| **EW-S1** | Element “Manage account” / sessions → opens account_management_uri | M3, G | Lands on siwx `/account` (or deep-link action) |
| **EW-S2** | List sessions/devices from Element path | M3 | Devices match Synapse list |
| **EW-S3** | **Remove / sign out a device** (Element session manager → OP or edge CS-API) | M3, H1/H2 | Device gone on Synapse; tokens for that device inactive; **other** device still works |
| **EW-S4** | Sign out **this** session (logout) | M3 | This device deleted/revoked; Element soft-logged out |
| **EW-S5** | Sign out **all** other sessions if exposed | M3 | All but current (or all) per product UI |
| **EW-X1** | First-time encryption setup (bootstrap) after login | M4 | `device_signing/upload` 200; keys/query shows master |
| **EW-X2** | Reset / re-verify encryption identity flow that hits MSC4312 | M4 | Account reauth; **no false success**; upload 200 or honest fail |
| **EW-X3** | Stuck half-reset recovery path (documented steps driven in UI) | M4 | Leaves `T_XS_OK` or clear fail |
| **EW-D1** | **Link new device / authenticate other device** (desktop Element displays QR or device-code approval) | M5, M1c | Device code approved; new session tokens; device present |
| **EW-D2** | Same flow when approver has **no** Secure Backup / no XS secrets | M5 Q2 | Named terminal `T_ApprovedButDead` or pre-flight warning — **must not** look like success |
| **EW-A1** | Account deactivate / erase (if Element deep-links; else OP page opened from Element) | G5/G6 | Synapse deactivated; tokens dead; erase purges passkeys |
| **EW-C1** | CSRF / unauth cannot manage another user’s devices (negative) | G8/G9 | 401/reject |

**Still out of scope for local Element Web Playwright (named elsewhere):**

| Item | Why | Alternate |
|------|-----|-----------|
| Element X **mobile** camera QR | No mobile in podman | Device-code HTTP + desktop “link new device”; manual EX note |
| Real Apple iCloud passkey multi-device | No real Secure Enclave in CI | CDP virtual authenticator + same-cred two browser contexts as proxy |
| Full megolm history after intentional destructive reset | Client-local | Assert backup deleted + public keys state |

**Orchestration target:**

```text
# Preferred single entry (to build in Phase 2.0)
bash e2e-harness/up.sh          # redis + synapse + siwx-oidc + caddy edge + ELEMENT WEB
bash e2e-harness/run.sh full    # existing Rust/adapters
bash e2e/browser/run-element.sh # NEW: Playwright vs Element :8088 (or hermetic port)
```

**Exit for Phase 2.0 (updated):** EW-* suite green on local Element + real Synapse + siwx from **main**, in addition to H0–H7 in-provider tests.

---

## 2. Assumption audit (code)

Legend: **CONFIRMED** / **PARTIAL** / **FALSE** / **BRANCH-DEPENDENT**.

| ID | Plan claim | Verdict | Evidence / correction |
|----|------------|---------|------------------------|
| A1 | Device IDs never recycled on sign-in | **CONFIRMED** (nuance) | `provision_synapse_device` upsert only; client-proposed scope device_id allowed — not always new `SIWX_*` |
| A2 | RFC 7009 revoke ≠ delete device | **CONFIRMED** | `TeardownPolicy::TokensOnly` |
| A3 | logout / device_delete delete + revoke | **CONFIRMED** | `compat` / `account` |
| A4 | `allow_cross_signing_reset` on **every login** | **FALSE** | **Not called** from provision/sign_in on working tree **or** `origin/main`. Only MSC4191 account action. Skills + CLAUDE + original plan **wrong** |
| A5 | Prod-like reset = Completed on allow 2xx, no readback | **CONFIRMED** | `account.rs` arm → `ActionOutcome::Completed` |
| A6 | main has honesty gate | **CONFIRMED** | `f0d991d` `reset_outcome` / `ResetUnconfirmed` |
| A7 | main has refresh grace 60s | **CONFIRMED** | `REFRESH_GRACE_TTL`; **absent** from audit working tree |
| A8 | New-user gate on login | **PARTIAL** | db79e75/main: detect + **frontend** confirm; server hard-reject only account/QR |
| A9 | New identity rejected on account/QR | **CONFIRMED** on db79e75/main; **FALSE** on audit tree | |
| A10 | Passkey link → primary_did | **CONFIRMED** | |
| A11 | Login allow is best-effort | **N/A / FALSE** | Login allow does not exist |
| A12 | device_code additive provision | **CONFIRMED** | Same `provision_synapse_device`; no `*_additive` function |
| A13 | Unknown credential → 401 structured | **CONFIRMED** | |
| A14 | DID defaults | **PARTIAL** | Code default `["pkh","key"]`; CLAUDE still says `["pkh"]` |
| A15 | SUPPORTED_ACTIONS ↔ discovery | **CONFIRMED** | |
| A16 | `siwx_user` cookie scoping | **BRANCH-DEPENDENT** | On db79e75/main; not on audit tree |

### Plan corrections (must rewrite in parent map mentally)

1. **Delete H-P9 / M4 transition “login arms reset window.”** First-time public XS relies on **MSC3967** only. Reset relies on **MSC4312/4191 account reauth** (or manual admin allow).  
2. **Honesty gate residual:** main maps `NoMaster` → still `Completed` (upload allowed without window). Fail-closed only on `Indeterminate` readback — does **not** detect “HTTP 2xx but UPDATE 0 rows while master exists.”  
3. **Working tree is not prod.** Develop against a pin: **prod baseline `db79e75`** or **main `f0d991d`**, not silent drift on audit branch.

---

## 3. Matrix capability scope (online docs — audited)

Source of truth for “next-gen auth” tracking: [areweoidcyet.com](https://areweoidcyet.com/) (updated 2026-01-30) + Matrix CS API v1.15+ OAuth sections + MSC umbrella.

### 3.1 Spec family we must orient to

| MSC / API | Status (tracker) | siwx-oidc role |
|-----------|------------------|----------------|
| **MSC3861** umbrella | Merged | We **are** the OP (replace MAS), not upstream-of-MAS |
| **MSC2964** auth code + refresh | Merged | `/authorize`, `/token` |
| **MSC2965** discovery | Merged | OIDC metadata + well-known |
| **MSC2966** dynamic client registration | Merged | `/register` |
| **MSC2967** scopes | Merged | device + api scopes |
| **MSC4254** RFC7009 revoke for logout | Merged | `/oauth2/revoke` — **tokens only** |
| **MSC3824** OIDC-aware clients | Merged | Element Web path |
| **MSC4191** account management deep-links | Merged | `/account?action=…` |
| **MSC4190** AS device APIs | Merged | Out of scope for human onboarding |
| **MSC4108** QR + E2EE setup | **Rework in progress** | Device code + Phase-4 client secrets |
| **MSC3967** first XS upload no UIA | Stable in Synapse | Homeserver gate — not siwx |
| Cross-signing **reset** | CS API + OP account action | `org.matrix.cross_signing_reset` deep link; Synapse MAS allow hook |
| **RFC 8628** device authorization | Used by MSC4108 | Implemented |
| **MSC4388** (2025 HPKE rendezvous) | Unstable / MAS-era | **INCOMPATIBLE** with `experimental_features.msc3861` — do not enable |

### 3.2 Spec facts that change our plan

| Spec fact | Plan impact |
|-----------|-------------|
| **Refresh:** Matrix OAuth API: *“The old refresh token remains valid until the new access token or refresh token is used”* ([CS API](https://spec.matrix.org/v1.18/client-server-api/)) | Prod’s immediate invalidation of old refresh is **spec-hostile**. Grace (`3f40485`) is not only Element-X UX — it is **conformance**. Raise priority of P1 deploy. |
| **First XS upload** = MSC3967 on Synapse; no UIA | Login-time allow is **not required** for first bootstrap. Explains why first `device_signing/upload` 200 can still happen without allow. |
| **Reset XS** = needs OP authorization (account deep-link) then re-upload | M4 reset loop is real; honesty of allow is product-critical |
| **QR login** = device grant + MSC4108 rendezvous + **client-side** secret transfer | siwx cannot “fix QR” alone if approver has no private XS keys |
| **E2EE vs OP:** OP authenticates; client owns E2EE | Half-reset (private secrets vs public keys) is a **distributed** failure mode |
| Official stack is **MAS + Synapse**; we are a **MAS replacement** | MAS docs are reference for hooks (`allow_cross_signing_reset`, introspection), not for shipping MAS |

### 3.3 Prod well-known note

Live `/.well-known/matrix/client` uses:

```json
"m.authentication": { "issuer": "https://siwx-oidc.inblock.io/" },
"m.authentication.account": "https://siwx-oidc.inblock.io/account"
```

MSC2965-style nested `m.authentication.account` **inside** the object is also common. Element X historically needed the account URL (May 2025 fix). **Probe both shapes** before changing; do not “fix” without client verification.

---

## 4. Skills audit (correctness)

| Skill | Health | Highest issues |
|-------|--------|----------------|
| **authenticate-siwe-matrix** | **Stale / dangerous** | Claims sign-in **deletes** old device; revoke **deletes** device; login **allow_cross_signing_reset**; refresh TTL **24h**; phantom `device_ids/{did}` |
| **cross-signing-bootstrap-and-debug** | Mixed | MSC3967/4312 concept OK; code table still “replacement mode” + login allow; flowchart diamond wrong |
| **element-x-qr-code-specialist** | Mixed | 2024 vs 2025 MSC4108 guidance **correct and critical**; still “implement RFC 8628” narrative; wrong Redis key names; claim allow on device provision |
| **CLAUDE.md** | Better on teardown | Still claims unconditional login allow + `provision_synapse_device_additive` |

**Phase-2.0 skill hygiene (same PR train as harness, before product):** rewrite the three skills + CLAUDE claims listed HIGH in the subagent report. Wrong mental models will reintroduce the 2026-06-12 revoke/delete class of bug.

---

## 5. Revised state machines (corrections only)

Parent map M0–M5 remain the structure. **Edits:**

### M4 — remove false transition

| Was (wrong) | Is (code + MSC3967) |
|-------------|---------------------|
| Login → `allow_cross_signing_reset` → `XS_ResetArmed` | Login → provision only. First upload: `XS_Absent` → MSC3967 → `T_XS_OK` without siwx arm |
| | Reset: client private rewrite → needs account `cross_signing_reset` → allow → upload |

### M2 — raise grace to conformance

| Terminal | Meaning |
|----------|---------|
| `T_FailInvalidGrant` storm on dual refresh | Spec violation on prod (immediate kill of predecessor refresh) |
| `O_GraceReplay` | Spec-aligned dual-refresh tolerance (main only) |

### M0 — clarify gate

| Path | New identity |
|------|----------------|
| Login | UI gate (confirm) after server `new_user` signal — **not** hard server block on login |
| Account / QR | **Hard reject** (db79e75/main) |

---

## 6. Revised hypothesis register

| ID | If | Then | Status after audit | Verification |
|----|-----|------|--------------------|--------------|
| H-P1 | Prod tag `sha-db79e75` | Live ≠ main | **Confirmed** (live inspect) | `.env` + `docker inspect` |
| H-P2 | Dual refresh without grace | invalid_grant storms | **Confirmed** (~548/72h) | logs; dual-refresh test |
| H-P2b | Grace implements Matrix “old refresh valid until new used” | Conformance + fewer storms | **Likely** (spec text) | deploy main grace; metric drop |
| H-P3 | allow 2xx without effective window | upload 401 after success UI | **Confirmed** forensics + code A5 | honesty e2e on real Synapse |
| H-P4 | Honesty gate on main | No false Completed on Indeterminate | **Confirmed** in main code | unit + live legs |
| H-P4b | Honesty detects all Synapse no-ops | **Weak / residual** | NoMaster still Completed by design | spike |
| H-P5 | New-user UI gate | Accidental create needs confirm | **Partial** (frontend) | Playwright login-gate |
| H-P6 | QR without approver XS secrets | Tokens OK, client fail | **Doc+skill confirmed** | connector / manual |
| H-P7 | Same Apple passkey multi-device | Same DID/mxid | **Observed** prod logs | keep |
| H-P8 | Offer-scoping branch | Own keys only; no enum | **Unproven live** | security review + tests before any redeploy |
| H-P9 | Login-time allow softens upload | — | **INVALIDATED** | remove; optional future feature if product wants it |
| H-P10 | Deploy grace+honesty | Storms drop; reset honesty | Untested until deploy | staged + 48h metrics |
| H-H0 | Unified harness | One green command set covers M0–M5 gates | Pending Phase 2.0 | run-all + hermetic full |

---

## 7. Audited execution proposal (phased)

### Phase 2.0 — Lab foundation (this machine only)

**No product feature merges until H0–H9 and EW-* Element suite are green.**  
(Product flag 3A/3B/3C only after you choose §12.)

1. Branch from **`origin/main`**.  
2. Local stack = real Synapse + siwx-oidc (main) + **Element Web** + edge/Caddy.  
3. Unify e2eh suites into primary tree; seedable mock for fast in-provider tests.  
4. Expand siwx-page Playwright (H2–H5) **and** Element Playwright (§1.4 EW-*).  
5. Hermetic XS + device_code + refresh-grace on real Synapse.  
6. Rewrite HIGH skill falsehoods.  

**Exit:** Element EW-* green + hermetic `run.sh full` green + mock `run-all` green; M0–M5 no silent MISSING for in-scope cells.

### Phase 2.1 — Product transitions (still local-first)

| Order | Change | Machine | Tests first |
|-------|--------|---------|-------------|
| 1 | Ensure refresh grace present + race test | M2 | H7 |
| 2 | Ensure XS honesty gate present + real Synapse legs | M4 | H6 |
| 3 | Decide: restore **login-time allow** as product feature? (currently absent) | M4 | new e2e; **not** assume CLAUDE is truth |
| 4 | QR pre-flight / hard warning when no published XS | M5 | H3 |
| 5 | Offer-scoping re-eval only after enum review | M1b | security + passkey-scoping specs |

### Phase 2.2 — Prod (only when complete — decision #5)

Single complete cut (or one documented multi-service cut) after full green lab:

1. Everything on main that the suite already proved (grace, honesty, any 3B/3C).  
2. Element-path behaviors proven by EW-*.  
3. Watch after deploy: `invalid_grant`, `device_signing/upload` 401, allow_cross logs.  
4. Recovery runbook aligned with §12 choice (not “log in again” unless 3B/3C).

### Phase 2.3 — Extra depth (after complete ship if needed)

- Element X mobile camera path (manual / device farm).  
- Connector E2EE R-K1/R-K2 regressions as continuous gate.  
- MSC4108 Phase-4 automation beyond device-code tokens.

---

## 8. Coverage matrix (current vs required)

| Machine | Today (this workspace mock Playwright) | Required before feature ship |
|---------|----------------------------------------|------------------------------|
| M0 Identity | PARTIAL (no gate/localpart truth on mock) | H0–H2 green |
| M1a Wallet | PARTIAL happy path | + oauth_binding negatives |
| M1b Passkey | PARTIAL (no link, limited scoping) | + link + scoping specs |
| M1c Device approve | **MISSING** Playwright | H3 green |
| M2 Tokens | PARTIAL (no grace here) | H7 + main grace |
| M3 Devices | COVERED mock policy | keep race suite |
| M4 XS/4S | WEAK mock; PARTIAL real elsewhere | H6 hermetic mandatory |
| M5 Multi-device/QR | PARTIAL tokens only (other tree) | H3 + device_code; Phase-4 out-of-band |

---

## 9. Boundary conditions (updated)

**Invariants**

1. Develop only against local container stacks; prod deploy only after green H0–H7 + your OK.  
2. Never recycle device IDs; revoke ≠ delete.  
3. Never render success without verified effect (honesty).  
4. New Matrix identity creation: login path only (UI gate); hard reject account/QR.  
5. No credential enumeration via forgeable DID.  
6. Never enable MSC4388 / `matrix_authentication_service` block with this msc3861 stack.  
7. Skills must match code after Phase 2.0 (no knowingly false ops advice).

**Assumptions (remaining)**

| ID | Assumption | Risk if wrong |
|----|------------|---------------|
| AS1 | Hermetic Synapse version ≈ prod for XS gates | Green hermetic, red prod |
| AS2 | Element follows account_management_uri for reset (partially unreliable) | Users stuck even if OP is perfect |
| AS3 | CDP WebAuthn ≈ production passkey server paths | UI-only gaps |
| AS4 | Mock hooks sufficient for policy tests | False confidence on M4 |

**Top risks**

1. Developing on audit tree without main’s grace/honesty → shipping non-fixes.  
2. Calling mock Playwright “all states” without hermetic M4.  
3. Re-teaching login-time allow from skills → wrong recovery runbooks.

---

## 10. Decisions (status)

| # | Status |
|---|--------|
| 1 Base = **main** | **Locked** |
| 2 Phase 2.0 harness first | **Locked** |
| 3 Login-time allow | **Awaiting your choice after §12** |
| 4 Real Element Web in local Playwright | **Locked** (see §1.4 EW-* suite) |
| 5 Prod only when complete | **Locked** |

---

## 11. Summary verdict

| Area | Verdict |
|------|---------|
| Original state-machine map structure (M0–M5) | **Keep** |
| Login-time allow_reset (as “already live”) | **False** — open product choice §12 |
| Refresh grace | **Required for complete ship** (spec + storms); not a partial prod deploy alone |
| Local thorough Playwright + **Element Web** | **Mandatory Phase 2.0** (§1.4) |
| Matrix MSC orientation | OP side of 3861 family + 4191 + 8628; never MSC4388 |
| Ready for product implementation? | **Not yet** — Phase 2.0 lab first; only §12 open |

---

## 12. Clarify: what is “login-time allow_cross_signing_reset”? (decision #3)

This is **not** a separate login method (not passkey, not wallet). It is a **one-line side effect** that some docs claimed happened **every time someone signs in**.

### What the allow API does

Synapse (under MSC3861) sometimes **blocks** clients from publishing **new** cross-signing public keys (`POST /_matrix/client/v3/keys/device_signing/upload`) when the user is doing a **reset** (replacing an existing identity), not a first-time setup.

To allow that upload for a short window (~10 minutes), the OP (siwx-oidc, acting as MAS) can call:

```http
POST /_synapse/mas/allow_cross_signing_reset
{ "localpart": "<user>" }
```

That plants a temporary “UIA bypass” flag on the user’s cross-signing master key row. After that, Element’s retry of `device_signing/upload` can return **200**.

### Two different situations people mix up

| Situation | What should happen | Does login need `allow_…`? |
|-----------|--------------------|----------------------------|
| **A. Brand-new user / never published XS keys** | First upload allowed by **MSC3967** (Synapse rule: no UIA if not set up yet) | **No** — works without siwx calling allow |
| **B. Reset / replace existing cross-signing** | User must re-auth at OP (`/account?action=org.matrix.cross_signing_reset`), then allow, then upload | **Yes — but via account page**, not via login (current code) |

### What docs claimed vs what code does

| Source | Claim |
|--------|--------|
| CLAUDE.md / some skills / old plan | “On **every sign-in**, siwx calls `allow_cross_signing_reset`” so a pending reset upload would succeed after re-login |
| **Actual code (main and prod)** | `provision_synapse_device` **only** creates/upserts the Matrix device. It **does not** call `allow_cross_signing_reset`. Allow is **only** from the account management action after wallet/passkey re-auth |

### Why it might still be useful (if we restore it)

If Element gets into a **half-reset** (private keys rewritten, public upload stuck 401) and **fails to open** the account page, an operator work-around used to be: “log out and log in again” — **that only works if login calls allow**. Today that advice is **wrong**.

Restoring login-time allow would mean:

- **After every successful OIDC sign-in**, siwx also fires `allow_cross_signing_reset` (best-effort, don’t fail login if Synapse errors).
- Effect: for ~10 minutes after login, a stuck Element can publish replacement cross-signing keys **without** visiting `/account?action=cross_signing_reset`.
- Risk: slightly looser reset authorization (any fresh login = temporary reset arm). That is what MAS-style “arm on login” docs assumed; it is a **product/security tradeoff**, not free.

### Your choices for #3

| Option | Meaning | When to pick |
|--------|---------|--------------|
| **3A — Leave absent (document truth)** | First setup = MSC3967 only. Resets **must** go through account reauth (or admin API). Fix skills/recovery runbooks. | Prefer strict “reset is explicit reauth only” |
| **3B — Restore login-time allow** | Re-add call in `provision_synapse_device` (or right after), best-effort; cover with e2e + Element EW-X2/X3 | Prefer “login unsticks half-reset without account deep-link” |
| **3C — Hybrid** | Login-time allow **only if** Synapse already has a master key (reset path), not for brand-new users | Middle ground; needs a `has_cross_signing_keys` check before allow |

**No code change until you pick 3A / 3B / 3C.**  
Honesty gate (main) is separate: it only fixes **false success UI** when allow is a no-op; it does not replace this decision.

---

## 13. Phase 2 execution log

| Item | Status |
|------|--------|
| Branch `phase2/session-onboarding-lab` from `origin/main` | **Done** |
| 3B login-time `allow_cross_signing_reset` in `provision_synapse_device` | **Done** |
| Playwright R-A1 allow assert + full mock browser suite (22) | **Done green** |
| Element compose stack (ports 2808x on this host) | **Done** |
| Caddy MSC3861 device routes + issuer_metadata | **Done** (matrix-server) |
| Skills HIGH fixes (3B + teardown) | **Done** |
| **EW-L0** Element shell + discovery | **Green** |
| **EW-L1** wallet OIDC → whoami | **Green** (hard pass) |
| **EW-S1–S4** account URI, list devices, delete second device, logout | **Green** |
| **EW-X1–X2** XS upload + account reset honesty | **Green** |
| **EW-D1** device_code grant + approve + whoami | **Green** |
| EW-L1b Element SPA room-list restore | Skipped (IndexedDB; not mx_* localStorage) |
| EW Element DOM click-paths (SSO button, Settings UI) | Pending polish |
| Prod deploy | **Blocked until complete** |

---

*Audited proposal end. Parent map remains the long-form machine catalog; this document is the corrected execution contract.*
