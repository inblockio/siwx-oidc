# Handover: Phase 2 session/onboarding lab (continue in new session)

**Date:** 2026-07-25  
**Author session:** planning → audited proposal → Phase 2.0 execution with subagents  
**Status:** Mid Phase 2.0 — **lab largely green**; **not ready for prod deploy**

---

## 1. One-paragraph goal

Make **siwx-oidc** robust for Matrix session & onboarding via **element.inblock.io**, with a **complete state-machine map**, **local container stacks**, and **thorough Playwright** (including a **real Element Web** instance). Product change already in flight: **3B** — best-effort `allow_cross_signing_reset` on every login. **No production deploy** until the owner says the work is complete.

---

## 2. Locked owner decisions (do not re-litigate)

| # | Decision |
|---|----------|
| 1 | Develop from **`origin/main`** lineage |
| 2 | **Harness first** (Phase 2.0) before more product PRs beyond 3B |
| 3 | **3B** — restore login-time `allow_cross_signing_reset` (best-effort, non-fatal) |
| 4 | **Must** test against **real Element Web** in local containers |
| 5 | **Prod only when complete** — no grace-only / honesty-only partial deploy |

### What 3B is (plain language)

Synapse can block cross-signing **reset** uploads with 401 until the OP calls  
`POST /_synapse/mas/allow_cross_signing_reset`.  
**First-time** upload is MSC3967 (no allow needed).  
**Reset** needs an allow window.  
Account page reauth still does that (with honesty gate on main).  
**3B also arms allow after every successful login provision** so “log in again” can unstick half-reset clients without visiting `/account`. Failures are `warn!` only.

---

## 3. Where to resume (git)

### Primary repo: `~/siwx-oidc`

```text
Branch:  phase2/session-onboarding-lab
Tracks:  origin/main (ahead by 7 commits, NOT pushed as of handover)
HEAD:    bd0cc42 docs(plan): update Phase 2 execution log — EW-L/S/X/D green
```

| Commit | Summary |
|--------|---------|
| `1094efe` | **3B** login-time allow + Element scaffold + mock port 18080 |
| `6d7166f` | Element lab ports 2808x + EW-L0 |
| `08d8130` | ignore element test-results |
| `18f9a71` | **EW-L1 hard-pass** via `loginWalletToTokens` |
| `9a78f73` | **EW-S1–S4** sessions / delete device / logout |
| `9c0a200` | **EW-X1/X2** crypto + **EW-D1** device-link |
| `bd0cc42` | plan execution log update |

```bash
cd ~/siwx-oidc
git checkout phase2/session-onboarding-lab
git status   # expect clean except optional untracked docs / test-results
```

### Matrix server lab fixes: `~/siwx-oidc-matrix-server`

```text
Branch:  feat/unified-e2e-harness-mvp (ahead of origin; lab commits local)
Key commit: 1c805df fix(local): MSC3861 edge routes + issuer_metadata for Element lab
```

Also edited (may be in that commit or working tree):

- `Caddyfile.local` — logout/all, delete_devices, devices/* → siwx; env-based public URLs in well-known  
- `docker-compose.local.yml` — `MATRIX_PUBLIC_*` / `SIWX_PUBLIC_*` for Caddy; ensure `SIWEOIDC_MATRIX_SERVER_NAME`  
- `.env.local` — **not in git** (secrets); remapped host ports for this machine  

**Do not push either repo without owner OK.**

---

## 4. Planning docs (read first)

| Doc | Role |
|-----|------|
| `docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md` | **Execution contract** — decisions, MSC scope, harness requirements, §13 progress log |
| `docs/superpowers/plans/2026-07-25-session-onboarding-state-machine-map.md` | Long-form M0–M5 machines (corrected for no false login-allow in old plan; 3B now restores it) |
| `docs/audits/2026-06-24-grace-deploy-device-verify-forensics.md` | (on main) half-reset / 14×401 forensic |
| `docs/audits/2026-06-24-cross-signing-reset-fix-logic-model.md` | (on main) honesty gate design |
| Skills: `skills/authenticate-siwe-matrix.md`, `cross-signing-bootstrap-and-debug.md` | Partially updated for 3B + teardown; still scrub for residual staleness |

---

## 5. Local stacks on this machine (port map)

**Host conflicts:** `portal-e2e-portal-1` owns **:8080**. Do not fight it.

| Stack | Bring-up | Ports | Use |
|-------|----------|-------|-----|
| **S-mock** | `bash e2e/up.sh` | siwx **:18080**, mock Synapse **:8090**, Redis **:6379** | Fast Playwright OP suite |
| **S-element** | `bash e2e/element/stack-up.sh` or compose in matrix-server | Element **:28088**, Matrix edge **:28080**, siwx **:28081** | EW-* suite |

### S-mock

```bash
cd ~/siwx-oidc
bash e2e/up.sh
# expect: stack up (http://localhost:18080)
bash e2e/browser/run.sh
# last known: 22 passed
```

Env: `e2e/env.sh` defaults `SIWEOIDC_PORT=18080`.

### S-element (compose.local)

```bash
cd ~/siwx-oidc-matrix-server
# .env.local must include (example used in session):
#   MATRIX_HOST_PORT=28080
#   SIWEOIDC_HOST_PORT=28081
#   CLIENT_HOST_PORT=28088
#   MATRIX_BASE_URL=http://localhost:28080
#   SIWEOIDC_BASE_URL=http://localhost:28081
#   SIWEOIDC_MATRIX_SERVER_NAME=localhost   # required for real device_delete
#   MAS_SHARED_SECRET + SIWEOIDC_SIGNING_KEY_PEM
docker compose -f docker-compose.local.yml --env-file .env.local up -d
# or from siwx-oidc:
bash e2e/element/stack-up.sh

ELEMENT_URL=http://localhost:28088 \
MATRIX_URL=http://localhost:28080 \
SIWX_URL=http://localhost:28081 \
  bash e2e/element/run.sh
# last known: 9 passed, 1 skipped (EW-L1b)
```

Health checks:

```bash
curl -sf http://localhost:28081/health
curl -sf http://localhost:28080/_matrix/client/versions
curl -sf http://localhost:28088/ | head -c 20
curl -s http://localhost:28080/.well-known/matrix/client
# issuer must be http://localhost:28081/  (NOT prod siwx-oidc.inblock.io)
```

---

## 6. Test inventory (green at handover)

### Mock browser (`e2e/browser/`) — 22 green

Includes: account, device-lifecycle (R-A1 with **3B allow assert**), passkey-scoping, stale-credential.  
R-G4 still only counts account-path allow (does not OIDC-login first after mockReset).

### Element suite (`e2e/element/`) — 9 pass / 1 skip

| ID | Spec file | What it proves |
|----|-----------|----------------|
| EW-L0 | `ew-login.spec.mjs` | Element loads; discovery OK |
| EW-L1 | `ew-login.spec.mjs` | Wallet OIDC → mat_ + whoami (**hard pass**) |
| EW-L1b | skipped | SPA restore from `mx_*` localStorage — Element needs IndexedDB |
| EW-S1 | `ew-sessions.spec.mjs` | account_management_uri + `/account` HTML |
| EW-S2 | `ew-sessions.spec.mjs` | list devices after login |
| EW-S3 | `ew-sessions.spec.mjs` | **delete second device** via edge; survivor works |
| EW-S4 | `ew-sessions.spec.mjs` | logout → whoami 401 (`whoami:false` on login avoids introspect cache) |
| EW-X1 | `ew-crypto.spec.mjs` | first `device_signing/upload` not permanent 401 |
| EW-X2 | `ew-crypto.spec.mjs` | account XS reset → completed \| reset_unconfirmed |
| EW-D1 | `ew-device-link.spec.mjs` | device_code → approve → tokens → whoami |

### Helpers (reuse these)

| File | API |
|------|-----|
| `e2e/element/helpers/oidc-login.mjs` | `loginWalletToTokens(page, { siwxUrl, matrixUrl, wallet, whoami? })` |
| `e2e/element/helpers/sessions.mjs` | device list/delete/logout helpers |
| `e2e/element/helpers/crypto.mjs` | XS upload + account wallet reauth for reset |
| `e2e/element/helpers/device-code.mjs` | RFC 8628 issue / approve / poll |
| `e2e/element/helpers/element.mjs` | stack health, open Element |
| `e2e/browser/wallet-helper.mjs` | mock ethereum + ethers wallet |
| `e2e/browser/webauthn-helper.mjs` | CDP virtual authenticator |

---

## 7. Product code change (3B) — location

**File:** `src/oidc.rs` — `provision_synapse_device`  
After `upsert_device`, best-effort:

```rust
synapse.allow_cross_signing_reset(&localpart).await  // warn on err; info on ok
```

Also used by auth-code **and** device_code grants (single provision path).  
Honesty gate for **account** reset remains on main (`reset_outcome` / `ResetUnconfirmed` in `account.rs`).

Compose **siwx-oidc image** may lag the branch until rebuild — Element lab was rebuilt from `../siwx-oidc` context during session; after more code changes, rebuild:

```bash
cd ~/siwx-oidc-matrix-server
docker compose -f docker-compose.local.yml --env-file .env.local up --build -d siwx-oidc
```

---

## 8. Critical gotchas (will waste hours if ignored)

1. **Port 8080 is portal-e2e** — mock uses **18080**, Element lab uses **2808x**.  
2. **Synapse data volume** can keep **production MSC3861 issuer** (`https://siwx-oidc.inblock.io`) from first boot → introspect fails with lab tokens. Fix: align `homeserver.yaml` issuer + `MAS_SHARED_SECRET`, or wipe volume with care, or use `issuer_metadata` internal URL pattern (see matrix-server commit `1c805df`).  
3. **Synapse introspect cache ~120s** — after logout, immediate whoami can still 200 if token was introspected before logout. EW-S4 uses `whoami: false` at login so first post-logout whoami is cold.  
4. **Device delete needs `SIWEOIDC_MATRIX_SERVER_NAME`** on siwx container or Synapse delete may be skipped (tokens only).  
5. **Caddy must route** `/_matrix/client/v3/logout`, `logout/all`, `devices/*`, `delete_devices`, `refresh` → siwx (not Synapse).  
6. **well-known base_url/issuer** must match **host-published** ports (env-substituted Caddyfile).  
7. **Skills were partly wrong** (delete-on-login, revoke=delete, “allow only never on login”). Partially fixed; CLAUDE.md may still claim unconditional allow as if always historic — now 3B makes it true again, but “delete on login” is still false.  
8. **Working tree on audit branch ≠ main** earlier; always use `phase2/session-onboarding-lab`.  
9. **Do not deploy to prod** until owner complete gate.

---

## 9. What is NOT done (next session backlog)

Priority order recommended:

| Pri | Work | Notes |
|-----|------|-------|
| P1 | **Passkey EW paths** | Virtual authenticator through OIDC against Element lab; multi-device same passkey |
| P2 | **Element DOM click-paths** | Real “Continue”/SSO, Settings → Sign out this session, Manage account deep-link from Element chrome |
| P3 | **EW-D2** | Approve device when no Secure Backup / no XS secrets → honest terminal (not silent success) |
| P4 | **EW-L1b** | Element session restore via correct storage (or document permanent skip) |
| P5 | Rebuild siwx image from branch tip + re-run full EW suite | Ensure 3B in running lab container |
| P6 | Hermetic `e2e-harness` (`~/siwx-oidc-matrix-server/e2e-harness`) against this branch | Real Synapse XS legs already exist in e2eh tree |
| P7 | Skill/CLAUDE/README full truth pass | No residual delete-on-login |
| P8 | Owner complete gate → **single prod ship** | grace + honesty already on main; 3B + any remaining fixes; tag deploy manual |

Out of scope unless owner expands:

- Element X mobile camera QR  
- Real Apple iCloud passkey  
- Partial prod deploys  

---

## 10. Suggested first 30 minutes in the new session

```bash
# 1. Resume branch
cd ~/siwx-oidc && git checkout phase2/session-onboarding-lab && git log -3 --oneline

# 2. Health-check stacks (or bring up)
curl -sf http://localhost:18080/health || bash e2e/up.sh
curl -sf http://localhost:28081/health || bash e2e/element/stack-up.sh
curl -s http://localhost:28080/.well-known/matrix/client | python3 -m json.tool | head

# 3. Re-confirm green
bash e2e/browser/run.sh -g "R-A1"
ELEMENT_URL=http://localhost:28088 MATRIX_URL=http://localhost:28080 SIWX_URL=http://localhost:28081 \
  bash e2e/element/run.sh

# 4. Pick next backlog item (P1 passkey or P2 Element DOM)
```

Read:

1. This handover  
2. `docs/superpowers/plans/2026-07-25-session-onboarding-AUDITED-PROPOSAL.md` §1, §12–13  
3. `e2e/element/helpers/oidc-login.mjs` + `ew-sessions.spec.mjs`  

---

## 11. Prod context (read-only reference)

| Fact | Value |
|------|--------|
| Live prod image (as of session start) | `ghcr.io/inblockio/siwx-oidc:sha-db79e75` |
| Main tip (base) | `f0d991d` honesty gate + grace on main (not in prod db79e75) |
| Prod SSH | `deploy@agentic.inblock.io` port **8022**, stack `/home/deploy/matrix/stack` |
| Deploy | Manual `SIWX_OIDC_TAG`; watchtower does **not** auto-deploy siwx |
| **Do not deploy** from this work until owner complete | Decision #5 |

Prod symptoms that motivated the work:

- Half-reset / verify session loops (`device_signing/upload` 401)  
- `invalid_grant` refresh storms (grace on main, not prod)  
- Device-code OK but Element X may still fail Phase-4 without Secure Backup  

---

## 12. Subagent pattern that worked

Parallel general-purpose agents:

1. OIDC login helper + EW-L1  
2. EW-S sessions/delete/logout  
3. Mock suite green  
4. EW-X crypto + EW-D device-link  

Orchestrator re-ran full Element suite after merges. Memory admission was GREEN; prefer sequential if `resource-guard` is AMBER/RED.

---

## 13. Success criteria for “Phase 2 complete” (before prod)

- [ ] Full mock `e2e/browser/run.sh` green on branch tip  
- [ ] Full Element `e2e/element/run.sh` green (P1–P3 items either green or explicitly accepted skips)  
- [ ] 3B present in lab **container** image (rebuild verified)  
- [ ] Skills/CLAUDE match code  
- [ ] Owner sign-off for complete ship  
- [ ] Manual prod tag deploy plan (main + 3B + any remaining), Redis notes if needed  

---

*End handover. New session: checkout `phase2/session-onboarding-lab`, re-green suites, continue backlog §9.*

---

## 14. Continuation addendum (same day, follow-up session)

Backlog §9 execution status after the continuation session of 2026-07-25:

| Pri | Work | Status |
|-----|------|--------|
| P1 | Passkey EW paths | **Done** — `ew-passkey.spec.mjs` EW-P1–P3 (new-user gate, scoped picker + second device, synced-key second context) |
| P2 | Element DOM click-paths | **Done** — `ew-clickpath.spec.mjs` EW-C1–C3 (real SSO click-login + Secure Backup wizard, Settings→Sessions "Remove this session" sign-out, Manage-account deep-link) |
| P3 | EW-D2 | **Done** — honest terminal in `ew-device-link.spec.mjs` (tokens granted, no fabricated crypto claim, dead-end detectable via keys/query; contrast leg) |
| P4 | EW-L1b | **Done** — un-skipped as a real-DOM sentinel: reload restores AUTH (no OIDC round-trip); crypto gate documented (see finding below) |
| P5 | 3B in lab container | **Verified** — `allow_cross_signing_reset armed after login provision` in container logs; compose image = branch tip |
| P7 | Skills/CLAUDE/README truth pass | **Done** — README no delete-on-login + 90d refresh TTL; cross-signing skill pre-flight removal documented |
| P6 | Hermetic e2e-harness vs branch | **Done — PASS** (run `20260725-174923`: 16 pass / 0 fail / 1 known-flagged msc4191-metadata re-export). Branch image retagged `localhost/siwx-oidc:local-grace`; LiveKit UDP range moved to 20100–20200 (below the ephemeral floor — 501xx collides with rootless containers' ephemeral sockets) |
| P8 | Owner complete gate → prod ship | **Still blocked on owner** |

**Element suite: 17 passed / 0 skipped** (was 9/1 at handover). Mock suite still 22 green.

### Two significant findings (owner attention)

1. **Lab fix with prod relevance:** Synapse forwards `msc3861.issuer_metadata` VERBATIM to browsers (`/_matrix/client/v1/auth_metadata`). The lab's endpoints-only dict (internal docker URLs, no capability fields) failed matrix-js-sdk issuer validation → Element silently fell back to legacy `/login/sso/redirect` → 404 dead-end. Fixed in matrix-server `entrypoints/matrix_server.sh` (full OP metadata + internal introspection only; first-boot-guard means existing volumes need a one-time patch — Element lab volume patched live). Prod metadata is all-public and unaffected, but keep MAS parity as a deploy check: ANY future auth_metadata regression re-opens this dead-end because prod also 404s the legacy route and prod Element also sets `sso_redirect_options.immediate`.
2. **Reload → verify gate → reset loop — ROOT-CAUSED:** not an Element bug at any version; introduced by our vendored `force-first-device-recovery.patch` (its `shouldForceVerification` extension also fires on session restore). Vanilla 1.12.20 and 1.12.24 never gate. Fix scoped to the patch (matrix-server). See §13 FINDING 2.
3. **NEW Finding 3:** Element ≥ 1.12.24 (js-sdk v42) cannot log in against siwx at all (`response_modes_supported` missing + no fragment response-mode support). Do not bump Element past 1.12.23 until siwx implements fragment delivery. See `docs/audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md`.
