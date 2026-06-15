# Handover — Resolving the Deferred CRITICALs (C1 nonce-binding, C2 redirect@/token)

**Date:** 2026-06-15 · **Branch:** `audit/siwx-oidc-security-review` (LOCAL-ONLY — do not push; repo is PUBLIC and this file details an unfixed live vuln)
**Audience:** whoever (with the owner) finishes the two coordinated security changes that were deliberately not shipped in the 2026-06-15 deploy.
**Detail reference:** exact file:line steps are in `2026-06-14-remediation-spec-criticals.md` (same dir). This is the actionable, prioritized wrapper + the new client-lib coordination learned during deploy.

> ⚠️ **Responsible disclosure:** `inblockio/siwx-oidc` is PUBLIC and prod is LIVE. Keep this file, `2026-06-14-remediation-spec-criticals.md`, `2026-06-14-siwx-oidc-security-review.md`, and `raw-findings/*` OUT of any public push until C1 is fixed. The 2026-06-15 deploy was code-only for exactly this reason.

---

## Where we are (2026-06-15)

**Deployed to prod** (image `…@sha256:02641af845f0`, `main` `1022ac1`; rollback `sha256:14f6176889af`): the device/session **race fixes** (H3/H6/H9), key-log redaction, constant-time CSRF, dep CVE bumps, and the **safe subset** of both CRITICALs — C2 (auth-code↔client binding at `/token`, `redirect_uri` re-validation at `/sign_in` = open redirect closed, **mandatory S256 PKCE**, `plain` rejected) and **C1-login** (Expiration-Time enforced *only when present*).

**Two items remain.** Both change a wire contract / require the in-house client + the agent fleet to move in lockstep — that's why they need supervision, not because they're hard.

---

## DEFERRED #1 — C1: full account-takeover fix (server nonce on device-approval + account paths)

**The hole (still live).** `device_approve` (`src/device_auth.rs:895`) and `account_wallet` (`src/account.rs:575`) authorize on a *bare* valid CAIP-122 signature — no server nonce, no expiry, no resource/operation binding. A captured/replayed victim signature can approve an attacker's device login *as the victim*, or drive `account_erase`/`deactivate`/`device_delete`. (The login path `sign_in` is the reference implementation that does bind nonce + resources + — now — expiry.) This is **our wiring**, not an aqua-auth limitation: `aqua-auth::verify_caip122` is a pure signature check by design; envelope/replay security is the caller's job.

**Resolution (coordinated, 4 parts — all must land together):**
1. **Server — mint + verify a single-use nonce.** Add a Redis-backed, short-TTL, single-use nonce per device-approval (`GET /device` issues it, keyed to the `user_code`/device session) and per account session (`GET /account` issues it, keyed to the account session). On submit, require the signed CAIP-122 message to contain that exact nonce; verify + consume (SETNX/Lua, mirror `try_consume_code`). Also enforce Expiration-Time + bind the **operation** (so a `cross_signing_reset` signature can't be replayed as `account_erase`) + the domain/resources. Factor a single shared CAIP-122 envelope validator and call it from all four CAIP-122 callers (`sign_in` ×2, `device_approve`, `account_wallet`).
2. **Frontend — embed the server nonce.** The device + account pages are **HTML/JS string literals embedded in `src/device_auth.rs` (~:557-586)** and `src/account.rs (~:1376-1409)` (NOT the Svelte app — they recompile with `cargo build`, no JS build). Today they sign a client `Math.random()` nonce with no exp. Change them to fetch the server nonce and put it (+ an Expiration-Time + Resources) into the signed message.
3. **In-house client lib `siwx-oidc-auth` — emit nonce + exp.** `build_message` (`siwx-oidc-auth/src/lib.rs:172-184`) currently emits NO Expiration-Time and uses no server nonce. For any flow the agents drive through these paths, the lib must fetch + include the server nonce + an Expiration-Time. **This is the crux** — and it's why C1-login was only made lenient on deploy (the lib omits exp; mandatory exp would have bricked the fleet — see the deploy gate). Once the lib emits exp, login-exp can also be flipped to **mandatory** (tighten `enforce_login_expiration`).
4. **Tests + agent fleet.** Update the message builders in `tests/e2e_account_management.rs` (`sign_account_message`), `tests/e2e_msc3861.rs`, `tests/e2e_race_teardown.rs`, `tests/e2e_session_teardown.rs`, and `e2e/browser/account.spec.mjs`/`device-lifecycle.spec.mjs` to fetch+sign the server nonce. Add a NEW negative test: a replayed/old-nonce device-approval and account signature is rejected. Then **redeploy the 7 `aqua-agent-*` containers** (they embed `siwx-oidc-auth`) in the same window as the server — they will not authenticate against a nonce-requiring server until they carry the nonce-emitting lib.

**Risk if mis-sequenced:** server requires nonce before the agents/pages emit it → fleet + Element device-approval login breaks (same class as the deploy landmine). Sequence: ship lib + pages + server behind a brief compat window, or deploy server + agents together.

---

## DEFERRED #2 — C2 step 2: mandatory `redirect_uri` at `/token`

**Gap.** RFC 6749 §4.1.3 wants `redirect_uri` echoed + matched at the token call. Today `TokenForm` has no `redirect_uri` field and `CodeEntry` doesn't persist one, so it can't be matched. (The safe subset already closed the *open-redirect* half at `/sign_in` and bound the code to the client.)

**Resolution:** persist `redirect_uri` on `CodeEntry` at `/sign_in`; add `redirect_uri` to `TokenForm`; at `/token` require it and compare to the stored value. **Breaking for any client not sending it** — and the in-house `siwx-oidc-auth` does NOT currently send `redirect_uri` at `/token` (verify + update it, then redeploy agents, same lockstep as C1). Element clients send it per OAuth norms. Add a negative test (mismatched/absent `redirect_uri` → `invalid_grant`).

---

## Canonical verification recipe (proven this round — use for ANY auth change)

The deploy gate is the safety net. Before shipping an auth change:
1. Bring up the mock stack (`cd ~/siwx-oidc-sec && bash e2e/up.sh`) and run `e2e_race_teardown` + `e2e_oauth_binding` + `e2e_account_management` + `cargo test --bin` (+ fmt/clippy).
2. **Decisive:** rebuild the real stack on the candidate binary (mount `~/siwx-oidc-sec` into `siwx-real-oidc`) and run the **connector E2EE test** (`~/aqua-matrix-agent-e2ee`, the agents' exact `siwx-oidc-auth` login path) via the edge — it MUST authenticate. This is what caught the Expiration-Time landmine. Add the device-approval/account replay-rejection checks here too.
3. Live suites vs the real stack (`e2e_msc3861`, `e2e_msc4191_live`).
4. Device sign-out via the edge (`e2e/real-stack-edge.sh`) — native `logout()` → siwx-oidc.

## Acceptance criteria (done when)
- A replayed device-approval signature and a replayed account-action signature are both rejected (new negative tests green).
- The in-house client + all 7 agents authenticate against the nonce-requiring server (connector gate green) and the fleet is redeployed.
- Login-exp flipped to mandatory once the lib emits exp.
- `redirect_uri` matched at `/token`; mismatch rejected; in-house client updated + agents redeployed.
- Re-run the full harness green; deploy code-only (findings stay private); update the audit memory + this handover to "DONE".

## Rollback (any deploy)
Old image still on prod: `docker tag 14f6176889af ghcr.io/inblockio/siwx-oidc:main && cd /home/deploy/matrix/stack && docker compose up -d siwx-oidc`. Never flush Redis (wipes no-TTL WebAuthn credentials + logs out the fleet).
