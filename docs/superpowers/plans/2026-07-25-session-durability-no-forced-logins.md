# Session Durability — "No Forced Logins" (Phase 1 PLAN ONLY)

**Status:** **EXECUTING.** Gate cleared 2026-07-25; `phase2/session-onboarding-lab` merged to
`main` (`d21329e`), so the blocking dependency is gone. Work proceeds on
`feat/session-durability-marathon` (worktree `~/wt/siwx-durability`) off that merge.

---

## AMENDMENT LOG — read before the body below

The body was written before two adversarial re-checks. Where they conflict, **this log wins.**

| # | Change | Source |
|---|---|---|
| A1 | **R3's premise is REFUTED.** "A 2s Redis blip terminates the session" is false — `RedisClient::new` takes bb8's defaults (`connection_timeout 30s`, `retry_connection true`, `test_on_check_out true`, `src/db/redis.rs:48-51`), which absorb a 2s fault and return `Ok`. Synapse absorbs it a second time via a 2-minute introspection cache that does not cache failures. **R3 is adopted only in its narrowed form:** the post-mint recheck's unrecoverable rollback. | `docs/audits/2026-07-25-R3-recheck-verdict.md` |
| A2 | **D1 is not on a live path.** `compat::refresh` is routed but unreachable: a CS-API refresh token requires `POST /_matrix/client/v3/login`, Synapse unregisters `LoginRestServlet` under MSC3861 (`login.py:730-732`), and siwx-oidc registers only `GET` (`axum_lib.rs:1258`). Fixed as hygiene, **not** counted as a live defect. **T1 demoted to hygiene.** | same |
| A3 | **D2 is four `unwrap_or(true)` calls, not two** — `compat.rs` pre-mint has two. Structurally rare (a Redis *outage* cannot reach it; it needs five healthy ops then a failure on the sixth in one request, ≈1 in 9,000 per fault at ~10 clients). Shipped on **asymmetry, not frequency**: the failure is unrecoverable. | same |
| A4 | **T4 (fault-injection harness) is CUT.** Its hypothesis was answered statically by A1; building it would be theatre. | same |
| A5 | **New defect found during implementation:** the const assertion added by T2 **fired on first compile**. `TOMBSTONE_TTL_SECS` (600) vs `2 * ACCESS_TOKEN_TTL` (600) — the fail-open safety margin was exactly **zero**, not positive. The R3 audit asserted a strict inequality that does not hold. Fixed by raising the tombstone TTL to 900s. Fail-open is only sound while the tombstone outlives the window it opens. | this session |
| A6 | **New risk outranking D2:** Synapse caches a **negative** introspection for 2 minutes with no invalidation, and inactive == hard logout. `introspect` correctly returns 500 on a store error, but nothing pinned it. Now pinned by `store_error_is_5xx_never_inactive`. | `R3-recheck-verdict.md` |
| A7 | **R4 effectively HOLDS today via SAS; it lacks proof, not capability.** Element 1.12.20 exposes Settings → Sessions → "Verify session", gated only on `isCurrentDeviceVerified && userId` (`useOwnDevices.ts:184-191`) — not on `isCrossSigningReady`, 4S, MSC4108, or OIDC metadata. **R4 is narrowed to SAS and reclassified as a proof task; the QR arm is deferred** (upstream-by-design, latent, unproven). | `docs/audits/2026-07-25-R4-recheck-verdict.md` |
| A8 | **My R4/R5 conflation was wrong.** The body claims R4 is "one of two non-destructive exits" for a reloaded single-device user. R4 *requires* a second live session, so it does **nothing** for a single-device user. That is R5. The body's F16 consequence paragraph is corrected accordingly. | same |
| A9 | **F16's root cause is OUR vendored Element patch, not upstream — and it is FIXED.** `9ec414d` + `b7e594f` are merged to `main` of `../siwx-oidc-matrix-server` (patch `patches/element-web/force-first-device-recovery.patch`). Not deployed (decision 2). | this session |
| A10 | **`response_modes_supported` is latent, not live** (deployed js-sdk 41.6.0 has zero references) and needs a **two-part** fix — v42 also removed the query fallback and reads `code`/`state` from the fragment only, so advertising the field alone makes things worse. Tracked as an **Element-upgrade blocker**. A fix is in flight on `fix/finding3-fragment-response-mode`. | `R4-recheck-verdict.md` |
| A11 | **`H-D5`'s baseline is contradictory** — ~548/72h (map §1.4) vs ~7/4 days back-solved from the same source. A 200× discrepancy. **`H-D5` cannot be evaluated until this is reconciled.** | `R3-recheck-verdict.md` |
| A12 | **Decision 5' dissolved.** It asked whether W3 needed the honesty gate deployed. Per A7 the SAS path is not gated on `isCrossSigningReady`, so W3-as-SAS has no such prerequisite. No deadlock. | this session |
| A13 | **Assumption A2 gap:** Synapse 1.154 adds a preferred `MasDelegatedAuth` backend; the "no soft_logout under MSC3861" invariant must be re-verified against it, not only `msc3861_delegated.py`. | `R3-recheck-verdict.md` |

**Round 1 status:** A5/A6/A3/A2 shipped in `dd34e3f` (7 revocation-policy tests incl. 3
fails-closed guards, 4 introspect guards; `--lib` 24 passed, `--bin` 119 passed, 0 failed).
A9 merged. Remaining: A7 proof, R5 recovery-entry coverage, state-machine completeness.

**Pipeline:** `process-pipeline` Phase 1 (logic-model → hypothesis register → plan → gate).
**Entry mode:** Goal mode (one goal, decomposed into four workstreams).
**Branch of record:** `phase2/session-onboarding-lab` (this doc), base `main`.

---

## 0. Relationship to existing artifacts (do not duplicate)

This plan **extends**, and does not replace:

- `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md` — machines M0–M5,
  hypothesis register `H-P1…H-P10`, backlog `P0…P8`.
- `docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md` — assumption audit,
  EW-* Element Web suite.
- `docs/audits/2026-06-24-grace-deploy-device-verify-forensics.md` — half-reset forensics.

The map's backlog covers **M4 (cross-signing correctness)** and **M2 refresh grace**. It does
**not** cover the axis this plan owns: **why a session ends involuntarily in the first place**
(the `L1→L4` chain below). New hypotheses therefore use a **separate namespace `H-D*`** so the
map's register stays immutable (process-pipeline invariant 4).

Cross-references, not re-litigations: `H-D5` ≙ map `P1`/`H-P2`/`H-P10`; `H-D8` depends on map
`P0`/`P2`/`H-P3`/`H-P4` landing.

---

## 1. CONTEXT

### 1.1 The chain this plan attacks

```
L1  restart / flush / Redis fault → token entries absent or unreadable
L2  → siwx introspect returns {"active": false}                     src/introspect.rs:120
L3  → Synapse raises InvalidClientTokenError(soft_logout=False)     msc3861_delegated.py:521
L4  → 401 M_UNKNOWN_TOKEN → HARD logout → Element wipes crypto store
L5  → re-login mints a NEW Matrix device (new device keys)          src/oidc.rs:1755
L6  → new device has no cross-signing private keys; no live verified session to ask
L7  → only remaining unlock path is 4S → recovery phrase
```

**L5–L7 is correct protocol and is explicitly out of scope to "fix"** (see §9 invariant I1).
This plan targets **L1–L4** (make involuntary logins not happen) and, separately, makes the
**verify-from-a-live-session** path reliable so that when a login is legitimate the phrase is
not the only option.

### 1.2 Verified facts (evidence at plan time, 2026-07-25)

| # | Fact | Evidence |
|---|---|---|
| F1 | Under MSC3861 Synapse **never** sets `soft_logout`; the only `soft_logout=True` in the tree is the *native* token path | `synapse/api/auth/internal.py:229`; absent from `msc3861_delegated.py` |
| F2 | Introspection transport failure → `SynapseError(503)`, retryable | `msc3861_delegated.py:514` |
| F3 | Introspection `active:false` → `InvalidClientTokenError` (hard) | `msc3861_delegated.py:521`, `api/errors.py:474-486` |
| F4 | siwx introspect: Redis error → 500 (correct); missing token → `active:false` | `src/introspect.rs:98,120` |
| F5 | **`compat::refresh` maps a Redis error to `401 M_UNKNOWN_TOKEN`** | `src/compat.rs:479` |
| F6 | **Post-mint recheck `.unwrap_or(true)` treats an I/O error as a tombstone** and rolls back the freshly minted pair, after the old refresh was already deleted (`oidc.rs:576`) and before the grace pointer is written | `src/oidc.rs:585-591`, `src/compat.rs:605-612` |
| F7 | **`/health` is `async fn healthcheck() {}`** — never probes Redis | `src/axum_lib.rs:362` |
| F8 | No `id_token` is issued on refresh, so an ephemeral signing key does **not** break live sessions (the code comment at `axum_lib.rs:1058` claiming "sessions break on restart" is misleading) | `src/oidc.rs:504`, `src/oidc.rs:622` |
| F9 | Prod Redis is durable (`--appendonly yes` + **named** volume `redis_data`, `depends_on: service_healthy`) | `../siwx-oidc-matrix-server/docker-compose.yml:29-41,51-52` |
| F10 | `e2e/up.sh` Redis has **no volume and no appendonly**; every `up.sh` destroys all session state | `e2e/up.sh:14-17` |
| F11 | `siwx-real-redis` runs `--appendonly yes` on an **anonymous** volume → a `podman rm`+`run` recreate silently starts with an empty AOF | `podman inspect siwx-real-redis` |
| F12 | `3f40485` refresh grace **is on main**; **not deployed** to prod | `git merge-base --is-ancestor 3f40485 main` |
| F13 | `f0d991d` XS-reset honesty is **branch-only**, not on main | `git log main..HEAD` |
| F14 | Login-time `allow_cross_signing_reset` exists **only on this branch** (`src/oidc.rs:1585`); absent on main. CLAUDE.md's "fires unconditionally on sign-in" is **stale for main/prod** | `git grep allow_cross_signing_reset main -- src/` |
| F15 | `CLAUDE.md` documents Redis flush as a routine deploy step **twice** ("recommended", "**required**") | `CLAUDE.md`, Token-model + MSC3861-compliance sections |
| F16 | **The reload verify gate offers no recovery-key entry.** Element 1.12.20 + `force_verification`: only exits are "Use another device" or destructive RESET. 4S/backup setup had succeeded and the backup still exists at gate time — an Element-build UX gap, not a siwx/lab failure. Single-device users get a reload → verify-gate → forced-reset loop | `AUDITED-PROPOSAL.md:456` (**Open**, P0-class), EW-L1b sentinel |
| F17 | Every passkey here is bound to RP ID `siwx-oidc.inblock.io` — the auth provider's own origin — so anything derived from the login credential is computable by siwx-oidc during a normal login | `src/webauthn.rs:671-707`; `docs/design/2026-07-25-webauthn-prf-4s-unlock-evaluation.md` |

### 1.3 Composite finding that reframes deploy practice

F1 + F3 + F15: under MSC3861 there is no cheap logout. Therefore **"flush Redis on upgrade" is
not a cache clear — it is a fleet-wide hard logout that destroys every user's client-side
cryptographic identity simultaneously**, and every affected user is then pushed onto the 4S
recovery path at once. Given the half-reset/recovery-key-churn population documented in the
2026-06-24 forensics, a meaningful fraction of them will not have a working recovery key.

---

## 2. GOAL (one sentence)

> Make every row of the session-durability target table true end-to-end: no session ends
> involuntarily, and when a login is legitimate the user verifies from a live session — while
> the recovery phrase remains **mandatory and unshortcut** in exactly the two cases where it is
> the correct answer.

### Measurable done

The recovery phrase is entered **only** when no other verified session exists. Operationally:
`invalid_grant` rate falls to the level explainable by genuine client-side token loss; a full
stack restart produces **zero** new device provisions; and the two negative cases (§9 I1) still
demand the phrase, proven by test.

### Target table (the requirement)

| # | Scenario | Today | Required |
|---|---|---|---|
| R1 | Server restarted / upgraded | Everyone logged out, everyone needs the phrase | Nobody notices |
| R2 | Two refresh calls race | One client signed out | Grace replay, session survives |
| R3 ~~as written~~ **(see A1)** | ~~Redis hiccups for ~2s~~ → **an I/O error at the post-mint recheck** | ~~Session terminated~~ → **tokens rolled back with the old one already deleted: unrecoverable sign-out** | Commit on an indeterminate probe; fail closed only on a definite tombstone. **SHIPPED `dd34e3f`** |
| R4 **(see A7)** | User adds a phone, desktop still signed in | **Capability present via SAS; unproven** (not "recovery phrase") | Emoji-verify from the desktop, **no phrase typed** — narrowed to SAS, QR arm deferred |
| R5 | User adds a phone, **nothing else signed in** | Recovery phrase | Recovery phrase — **must remain, and must be enterable** |
| R6 | User lost every device | Recovery phrase | Recovery phrase — **must remain, and must be enterable** |

**R5 and R6 are negative requirements.** Any change that makes them stop asking for the phrase
is a security regression, not progress. See §9 I1 and task T13/T14.

> **CORRECTION (A8/A9).** The paragraph below concluded that R4 and recovery-key entry are the
> two non-destructive exits for a reloaded single-device user, so losing R4 leaves only the
> destructive reset. **That reasoning was wrong:** R4 requires a *second live session*, which a
> single-device user by definition does not have — that scenario is R5, not R4. Separately, F16's
> root cause was this deployment's **own vendored Element patch**, and it is now **fixed and merged**
> (`9ec414d` + `b7e594f` on `main` of `../siwx-oidc-matrix-server`), not deployed. What remains is to
> prove, per context, that a recovery-phrase entry path exists wherever R5/R6 require one.

**"and must be enterable" is not pedantry — it was FALSE (F16), now fixed but unproven.** The branch's own EW-L1b
work records an **Open, P0-class** finding: on reload, Element 1.12.20 with `force_verification`
restores the auth session but not crypto, landing on "Confirm your digital identity" whose **only two
exits are "Use another device" or identity RESET — there is no recovery-key entry field**
(`docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md:456`). Diagnostics confirm
the 4S/backup setup had fully succeeded and the backup still exists at gate time, so this is an
Element-build UX gap, not a siwx or lab-storage failure.

Consequence for this plan: the two non-destructive exits from that gate are **R4** (verify from
another device) and **recovery-key entry**. Today the second is absent, so if R4 is also unavailable a
single-device user has **only the destructive reset path** — which is precisely the lab reproduction of
the prod "verify session loop / half-reset" forensics. This makes R4 and the verify-with-other-device
evaluation load-bearing for R5/R6, not merely adjacent to them.

---

## 3. INPUTS

| Class | Item |
|---|---|
| Code | `src/compat.rs` (refresh, teardown), `src/oidc.rs` (token_refresh, sign_in, provision), `src/introspect.rs`, `src/axum_lib.rs` (health/state), `src/db/redis.rs` |
| Infra | `../siwx-oidc-matrix-server/docker-compose.yml`, `e2e/up.sh`, real-stack scripts, `e2e/real-stack/Caddyfile` |
| Test surfaces | `tests/e2e_*.rs` (8 suites), `e2e/browser/*.spec.mjs` (Playwright), `e2e/run-all.sh`, EW-* suite from the audited proposal |
| Knowledge | Synapse MSC3861 auth module (image overlay, read-only), map M0–M5, 2026-06-24 forensics, `skills/deploy-check.md`, `skills/cross-signing-bootstrap-and-debug.md` |
| Access | Prod `deploy@agentic.inblock.io` (manual deploy only, `SIWX_OIDC_TAG`), prod logs |
| Constraint | Memory governance: subagent spawns may be denied by admission control → run inline (see `~/.claude/CLAUDE.md`) |

---

## 4. Hypothesis register (`H-D*`)

Immutable once Phase 2 starts. Discoveries go to the audit's "Discovered During Execution".

| ID | If | Then | Assumptions | Verification (must actually be run) |
|----|----|------|-------------|--------------------------------------|
| **H-D1** | Session state survives a full stack restart (durable AOF, **named** volume, verified replay) | A client holding a valid refresh token stays logged in with the **same** `device_id`; zero new device provisions | Client refreshes within refresh TTL; Synapse device row untouched | New e2e leg: capture `device_id` → restart stack → assert introspection `active:true`, same `device_id`, Synapse device count unchanged |
| **H-D2** | Infrastructure failure is reported as infrastructure failure (Redis error → 503, never 401 / `invalid_grant`) | A transient Redis outage yields client retries, not sign-outs | Element/matrix-sdk retries 5xx and does not wipe on it | Fault injection: pause Redis → hit `/oauth2/introspect`, `POST /token` (refresh), `POST /_matrix/client/v3/refresh` → assert 5xx on all three → restore → assert the **same** refresh token still works |
| **H-D3** | The post-mint recheck fails **open** on I/O error and **closed** only on a definite tombstone | A Redis error during rotation cannot destroy both old and new refresh tokens | Tombstone read is distinguishable from an I/O error at the DB trait | Two unit tests with a DB double: (a) error at recheck → tokens survive + grace pointer written; (b) real tombstone → rollback still happens (regression guard for H3/H6) |
| **H-D4** | Readiness actually probes Redis (`/ready`, distinct from liveness) | An instance that would 401 clients is never declared ready | Orchestrators honor the probe | Start siwx-oidc with Redis down → assert `/ready` fails while `/health` may pass; `e2e/up.sh` and compose gate on `/ready` |
| **H-D5** | Refresh grace (`3f40485`, on main) is deployed to prod | `invalid_grant` volume drops materially from the ~548/72h baseline | No unrelated regression in the same deploy | 72h prod log counts before/after, same grep, same window length |
| **H-D6** *(amended in planning, owner decision 2026-07-25)* | Prod already stores the current `TokenMetadata` shape, so the standing "flush required" instruction is **stale** and can be deleted rather than migrated around | A binary upgrade does not mass-invalidate tokens; no flush required; no migration code needed in this pass | No proposed change alters the shape (true for T1/T2); prod was not rolled back to an older binary | Prod read of a stored token entry → assert current-shape fields (`did`, `name`) present. **If this FAILS, the dual-read migration becomes mandatory and this decision re-opens** |
| **H-D7** | The deploy docs state the true blast radius and prescribe a drain | An operator cannot reach "flush Redis" without seeing "fleet-wide crypto-identity wipe" | Operators read the doc they follow | Doc review against `CLAUDE.md` + `skills/deploy-check.md` diff. **This is a review gate, not a test — labelled as such** |
| **H-D8** | First login reliably reaches published cross-signing + working 4S | A second device verifies from the first with **no** 4S unlock prompt | Map `P0`/`P2` landed; Synapse honors MSC3967 first-upload | Real-stack two-context Playwright: login A → bootstrap → login B → verify B from A → assert B cross-signed **and** no 4S prompt fired |
| **H-D9** | *(negative)* No live verified session exists | The recovery phrase **is** still required, and no code path bypasses it | — | Negative e2e: terminate all sessions → fresh login → assert 4S unlock demanded. Plus static check (T14) |
| **H-D10** | *(standing constraint, already CONFIRMED)* Synapse under MSC3861 never emits `soft_logout` | Every token-visibility gap is a full crypto-store wipe; there is no cheap logout | Synapse version stays on this contract | **CONFIRMED at plan time:** `grep soft_logout synapse/api/auth/*.py` → only `internal.py:229`. Re-assert on Synapse upgrade |
| **H-D11** | Element Web hard-logout wipes the crypto store | The device's cross-signing secrets are unrecoverable after a 401, which is why L4→L7 completes | Element version-dependent | Real-stack Playwright: snapshot IndexedDB → force a 401 → snapshot again → assert crypto store cleared. **Converts the prior ASSUMPTION into evidence** |

---

## 5. Logic-model chain

```
Inputs (F1–F15, prod logs, test surfaces, map M0–M5)
  → Activities
      W1 error-class correctness + durability in siwx-oidc      (T1–T5)
      W2 lab + deploy durability, migration, doc truth pass     (T6–T9)
      W3 first-login bootstrap → verify-from-live-session       (T10–T12)
      W4 guard rails proving R5/R6 still hold                   (T13–T14)
  → Outputs
      code changes; fault-injection + restart-survival harness; migration;
      corrected deploy docs; two-session verification e2e; negative tests
  → Outcomes
      R1–R4 true; R5–R6 provably preserved; invalid_grant falls to genuine-loss floor
  → Impact
      the recovery phrase becomes a once-in-a-lifetime disaster path, not a login step
```

---

## 6. Tasks (tagged with hypotheses)

Ordering is dependency-driven. **W1 before W2 deploys; W3 depends on map `P0`/`P2`.**

### W1 — Error-class correctness & durability (code)

#### Task T1: Separate infrastructure failure from authorization failure
**Hypotheses:** H-D2
**Files:** `src/compat.rs` (refresh `Err(_)` arm ~:479, teardown paths), `src/oidc.rs` (token paths), `src/introspect.rs` (reference impl)
- [ ] Audit **every** `Err(_) =>` / `?`-to-401 / `→ invalid_grant` path; classify each as auth-terminal vs infra-retryable
- [ ] `compat::refresh` Redis error → 503 (`M_UNKNOWN` or a retryable errcode), never `M_UNKNOWN_TOKEN`
- [ ] Add a single helper so the classification cannot drift per-call-site
- [ ] Unit tests per path asserting the status class

#### Task T2: Fail open on I/O error at the post-mint recheck
**Hypotheses:** H-D3
**Files:** `src/oidc.rs:583-591`, `src/compat.rs:605-612`
- [ ] Replace `.unwrap_or(true)` with an explicit three-way: `Revoked` → rollback; `NotRevoked` → commit; `Unknown(io)` → commit + `warn!`
- [ ] Ensure the grace pointer is written on the `Unknown` path too
- [ ] Regression test that a **real** tombstone still rolls back (do not weaken H3/H6)

#### Task T3: Real readiness probe
**Hypotheses:** H-D4
**Files:** `src/axum_lib.rs:362` + routes
- [ ] Keep `/health` as liveness; add `/ready` that round-trips Redis (`PING` or a cheap GET)
- [ ] Wire `/ready` into `e2e/up.sh`, real-stack scripts, and the prod compose healthcheck
- [ ] Correct the misleading ephemeral-signing-key comment at `axum_lib.rs:1058` (F8)

#### ~~Task T4: Fault-injection harness~~ — **CUT (A4)**
**Hypotheses:** H-D2, H-D3
Cut 2026-07-25. Its hypothesis was answered **statically**: bb8's defaults absorb a transient
fault (A1), and a Redis *outage* cannot reach the post-mint recheck at all because the five
preceding operations fail first. Injecting faults to observe a path the code cannot take is
theatre. The property that *does* matter is covered by pure unit tests over
`collapse_revocation` (all nine probe combinations) and `render_introspection`.

#### Task T5: Restart-survival e2e leg
**Hypotheses:** H-D1
**Files:** `e2e/` + `tests/`
- [ ] Capture `device_id` → restart the whole stack → assert active, same `device_id`, **zero** new device provisions

### W2 — Lab & deploy durability (infra / ops / docs)

#### Task T6: Make both labs actually durable
**Hypotheses:** H-D1
**Files:** `e2e/up.sh`, real-stack bring-up
- [ ] `e2e/up.sh`: named volume + `--appendonly yes`; stop `rm -f`-ing the data volume
- [ ] Real stack: replace the **anonymous** volume with a named one (F11 — the current flag advertises durability it does not have)
- [ ] Gate siwx-oidc start on Redis readiness, not a bare `/health` poll

#### Task T7: Disarm the flush instruction (owner decision, 2026-07-25 — reframed from "build the migration")
**Hypotheses:** H-D6
**Files:** `CLAUDE.md`, `skills/deploy-check.md`; `src/db/mod.rs`, `src/db/redis.rs` only if the check fails
- [ ] **Verify staleness first.** Both flush instructions describe upgrades that already happened
      (pre-refresh-token → refresh-token; the MSC3861 `TokenMetadata` shape). Confirm prod's stored
      entries already carry the current shape (required `did` / `name` fields present). **Needs a prod
      read — gated on owner go-ahead, do not run unprompted**
- [ ] If stale: **delete** the instruction rather than migrate around it. A standing "flush required"
      line is advice an operator can follow catastrophically (§1.3 + F16)
- [ ] Replace with the blast-radius warning + drain procedure
- [ ] **Do NOT build the dual-read migration in this pass.** No proposed change alters `TokenMetadata`
      (T1/T2 do not). Build it when a shape change is actually proposed — track as a conditional, not a task
- [ ] If the staleness check FAILS (prod holds old-shape entries), stop and re-open this decision: the
      migration becomes necessary, not optional

#### Task T8: Deploy-doc truth pass
**Hypotheses:** H-D7
**Files:** `CLAUDE.md`, `skills/deploy-check.md`
- [ ] Fix stale claims: login-time `allow_cross_signing_reset` is **branch-only** (F14); ephemeral-key "sessions break on restart" is misleading (F8)

#### Task T9: Staged prod deploy of refresh grace + metric watch
**Hypotheses:** H-D5 *(≙ map P1)*
- [ ] Dry-run on the local real stack, then prod via `SIWX_OIDC_TAG`
- [ ] 72h `invalid_grant` count, same grep/window as the baseline

### W3 — First-login bootstrap → verify from a live session

**HARD GATE (owner decision, 2026-07-25):** W3 does **not** start until map `P0` (half-reset recovery
runbook) and `P2` (`f0d991d` honesty gate) have landed. Rationale: while the account page can still
report success for an ineffective reset, and while a half-reset user population exists, any W3 result is
unattributable — a failure could be the bootstrap, the stuck population, or the false success. Running
W3 early buys code but not evidence.

#### Task T10: Measure first-login XS/4S bootstrap outcome
**Hypotheses:** H-D8
- [ ] Per-identity trace of the `device_signing/upload` sequence; quantify the 200-then-401 population seen in map §1.4 B/D

#### Task T11: Two-session verification e2e
**Hypotheses:** H-D8
- [ ] Real stack, two browser contexts: verify B from A; assert cross-signed **and** no 4S prompt

#### Task T12: Element hard-logout crypto-store probe
**Hypotheses:** H-D11
- [ ] IndexedDB before/after a forced 401 — turn the standing assumption into evidence

### W4 — Guard rails (prove R5/R6 survive)

#### Task T13: Negative test — no live session ⇒ phrase still required **and enterable**
**Hypotheses:** H-D9
- [ ] Terminate all sessions → fresh login → assert 4S unlock is demanded and cannot be skipped
- [ ] **Also assert the phrase can actually be entered.** Per F16 this currently FAILS: the gate's only
      exits are "Use another device" or destructive reset. A test that only asserts "the phrase was
      demanded" would pass while the user is stuck — assert the entry affordance exists
- [ ] Where the missing affordance is an Element-build gap, record it as such and route it to the
      Element patch already maintained for this deployment; do not attempt a server-side workaround (I1)

#### Task T14: Static guard — no server path carries key material
**Hypotheses:** H-D9
- [ ] Assert no siwx-oidc/Synapse path transmits cross-signing private keys or the 4S key
- [ ] Add to `skills/security-review` checklist so it is re-checked on every future change

---

## 7. Acceptance criteria

Every "Met" requires a verification command **that was actually run**, with its output pasted
into the Phase-3 audit. No exceptions (process-pipeline invariant 2).

| # | Criterion | Hypotheses | Verification |
|---|---|---|---|
| AC1 (R1) | Full stack restart → zero forced logins, zero new device provisions | H-D1, H-D4, H-D6 | T5 leg output + Synapse device count diff |
| AC2 (R2) | Concurrent refresh race → both clients survive | H-D5 | existing grace tests + prod 72h delta |
| AC3 (R3) | ~2s Redis outage → no 401, session recovers | H-D2, H-D3 | T4 fault-injection output |
| AC4 (R4) | Second device verifies from a live first session, no phrase typed | H-D8 | T11 Playwright run |
| AC5 (R5/R6) | **No live session ⇒ phrase still required, unbypassable** | H-D9 | T13 negative run + T14 static guard |
| AC6 | Upgrade path requires no Redis flush | H-D6 | T7 seed-and-upgrade test |
| AC7 | Deploy docs state the real blast radius | H-D7 | doc review gate (**not** a test) |
| AC8 | Element hard-logout wipe behavior is evidence, not assumption | H-D11 | T12 IndexedDB snapshots |

---

## 8. Verification discipline — DO NOT SHORTCUT VERIFICATION

Standing rules for Phase 2/3 on this plan:

1. No hypothesis is "Confirmed" without a command that was run and whose output is recorded.
2. **Never weaken a check to make a test pass.** T2 explicitly ships a regression test proving
   the tombstone path still fails closed; a green suite achieved by making revocation lenient is
   a failed task, not a passed one.
3. `H-D7` and `AC7` are **review gates**, labelled as such — they must not be reported as tests.
4. `H-D9`/`AC5` are **negative** criteria. If they ever start passing "trivially" (no prompt
   appeared), that is a **failure**, not a success.
5. Prod metrics (`H-D5`) need matched before/after windows; a smaller window is not evidence.
6. Any hypothesis the work cannot exercise is reported **Untested** and flagged as a gap.

---

## 9. BOUNDARY CONDITIONS

### Invariants (violating any of these fails the work)

- **I1 — Verification is never shortcut.** No design in which siwx-oidc, Synapse, or any server
  component can obtain cross-signing private keys or the 4S key. R5/R6 must keep demanding the
  phrase. If a proposal reaches "the server vouches for the device", it is rejected, not refined.
  - **I1a — the test is CAPABILITY, not transmission.** It is not sufficient that a design avoids
    *sending* key material to the server; it must be impossible for the server to *derive or obtain*
    it. Established 2026-07-25 by the PRF evaluation: every passkey in this deployment is bound to
    RP ID `siwx-oidc.inblock.io` (`src/webauthn.rs:671-707`) — the auth provider's own origin — so
    anything derived from the login passkey is computable by siwx-oidc during any ordinary login,
    using a gesture the user already performs. **Never derive the 4S key from the login credential.**
  - **I1b — hygiene flags are not controls.** Not requesting `hmac-secret` at registration does not
    make existing credentials non-PRF-capable: CTAP 2.1 §12.5 says authenticators SHOULD mint
    `CredRandom` regardless. The invariant is the control; the flag is not.
- **I2** Never recycle device IDs *(map invariant 1)*.
- **I3** Revoke ≠ delete device *(map invariant 2)*.
- **I4** Never render success when the grant/effect is unconfirmed *(map invariant 3)*.
- **I5** New Matrix identity only on the login path behind the gate *(map invariant 4)*.
- **I6** No credential enumeration via forgeable identity hints *(map invariant 5)*.
- **I7** No prod deploy without explicit owner go-ahead *(map invariant 6)*.
- **I8** Fail-open applies **only** to indistinguishable I/O errors — never to a definite tombstone.

### Exclusions (out of scope)

- Fixing L5–L7 (a fresh device needing secrets) — correct protocol.
- Forking or patching Element Web.
- WebAuthn-PRF-derived 4S keys — **evaluated and REJECTED** for this deployment, 2026-07-25. See
  `docs/design/2026-07-25-webauthn-prf-4s-unlock-evaluation.md`. Killing argument is now invariant I1a.
  Upstream absence is confirmed, not merely unverified: no MSC exists, zero implementation in
  element-web / matrix-js-sdk / matrix-rust-sdk / Element X, and Element's roadmap moves the other way
  (ER-233 re-introduces typed passphrases). Do not re-open without new upstream facts.
- New DID methods, new ceremonies, large refactors.
- Map items `P3`, `P5`, `P6`, `P8` — tracked there, not here.

### Assumptions (outside our control)

- **A1** Element / matrix-sdk retries 5xx rather than treating it as a sign-out *(H-D2 depends on this; T4 must confirm, not presume)*.
- **A2** Synapse keeps the F1 contract (no `soft_logout` under MSC3861) across upgrades — re-assert on upgrade.
- **A3** Map `P0`/`P2` land before W3, else H-D8 is untestable.
- **A4** Manual deploys only (`SIWX_OIDC_TAG`).
- **A5** Memory governance may deny subagent spawns → execute inline, do not retry.

### Risks (top 3)

1. **Fail-open done carelessly resurrects revoked sessions.** Mitigation: I8 + T2's explicit
   tombstone regression test. This is the highest-severity risk in the plan.
2. **W2 durability fixes mask W1 bugs.** A durable lab stops reproducing the fault-injection
   class. Mitigation: T4 injects faults explicitly rather than relying on lab fragility.
3. **Deploying grace + honesty together muddies attribution** if the `invalid_grant` metric moves.
   Mitigation: stage them, one metric window each *(consistent with map H-P10)*.

### Loop exit

Every R1–R6 row either Met with cited evidence, or explicitly accepted as a gap by the owner.
`H-D9`/`AC5` **cannot** be waived.

---

## 10. Gate — decisions needed before Phase 2

1. ~~**Blocking dependency**~~ — **DECIDED (owner, 2026-07-25):** base is **`main`**, but implementation
   **MUST NOT** start until `phase2/session-onboarding-lab` is **merged**. Rebase onto `main` after that merge.
2. ~~**Slice order**~~ — **DECIDED (owner, 2026-07-25):** **W1 first** (error-class correctness, T1–T5).
   **No prod release until the final audit** (Phase 3) **and all additional changes from this session** are
   in. This supersedes any "deploy grace early for fast relief" option: T9 moves behind the audit gate.
3. ~~**W3 dependency**~~ — **DECIDED (owner, 2026-07-25):** **sequence W3 inside this plan.** Map `P0`
   (half-reset recovery runbook) and `P2` (`f0d991d` honesty gate) are hard prerequisites: W3 does not
   start until both have landed, so `H-D8` yields an interpretable result rather than an unattributable
   one. R4 is proven in this pass, not deferred.
4. ~~**Migration appetite (T7)**~~ — **DECIDED (owner, 2026-07-25):** **verify the flush instruction is
   stale, then delete it** and replace with the blast-radius warning + drain procedure. Do **not** build
   the dual-read migration in this pass; it becomes mandatory only if the staleness check fails. T7 and
   H-D6 reframed accordingly.
5. ~~**`f0d991d`**~~ — **RESOLVED by decision 1, not a separate choice.** `f0d991d` is an ancestor of
   `phase2/session-onboarding-lab`, so merging that branch to `main` carries the honesty gate with it.
   **Superseded by decision 5' below**, which is the real question it exposed.
5'. **P2 prerequisite semantics — a scheduling cycle to break.** Decision 3 makes map `P2` (the honesty
   gate) a hard prerequisite for W3. Decision 2 puts every prod release behind the Phase-3 final audit.
   If "P2 has landed" is read as "P2 is deployed to prod", then W3 waits on a prod deploy that waits on
   an audit that waits on W3 — **a deadlock**. Choose the reading (see options presented to owner).
6. **Prod fault-injection:** T4 on the local real stack only, or also a controlled prod window?

**No task starts until these are answered.**
