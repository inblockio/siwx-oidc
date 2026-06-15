# siwx-oidc — Overnight Resilience & Security Audit — Morning Summary

**Date:** 2026-06-14 (overnight, autonomous) · **For:** Tim
**Method:** `/logic-model` for assessment, `/process-pipeline` for execution, operated in rounds, all work on **separate branches** (nothing pushed, nothing deployed).

---

## TL;DR

You asked for a functional + security audit of the siwx-oidc provider focused on **resilience and correctness — especially race conditions on device removal and session cleanup** — plus a complete headless test harness and a multi-participant E2E messaging regression. Here's what landed while you slept:

1. ✅ **Full requirement map** — every wallet/WebAuthn/device flow decomposed into falsifiable hypotheses (R-A1…R-K2) + a race/cleanup hazard register (H1…H14).
2. ✅ **Headless test harness, green & committed** — a deterministic Rust race/teardown suite (mock + Redis, forced interleavings) **and** a Playwright browser suite (real EIP-191 mock wallet + CDP WebAuthn virtual authenticator).
3. ✅ **Security review (separate)** — 4 independent auditors → **2 CRITICAL, 9 HIGH, ~12 MEDIUM**, deduplicated and cross-corroborated.
4. ✅ **Your instinct was right + then some** — the device-removal/cleanup **races are real** (proven with reproducers) **and** there's a more severe **replayable-signature account-takeover** class.
5. ✅ **Fixes applied & verified** (on the security branch): the **three race conditions** (device-removal/session-cleanup — your primary goal); **the open redirect at `/sign_in` + cross-client code redemption + `plain`-PKCE downgrade + login-signature expiry** (the verified-safe subset of the two CRITICALs); the **private-key log leak**; **constant-time CSRF**; and **dependency CVEs** (cargo audit 5→1).
6. ✅ **Real local Matrix stack stood up** — validated the device-lifecycle, cross-signing-reset, and **two-participant messaging** end-to-end against a *real Synapse*.
7. ⏳ **Needs your decision:** the *remaining, breaking* parts of the CRITICALs (CAIP-122 nonce binding on the device-approval + account paths; mandatory `redirect_uri` at `/token`; mandatory PKCE) change the wire contract and need coordinated frontend+test edits + review — **specced ready-to-apply, not shipped unattended.**

**Nothing was pushed or deployed. Production (matrix.inblock.io) was never touched.**

---

## Branches (local only — review, then push if you approve)

| Branch | Worktree | Contents |
|---|---|---|
| `audit/siwx-oidc-functional-harness` | `~/siwx-oidc` | Requirement map, R2 plan, **test harness** (Rust race suite + browser lifecycle suite) |
| `audit/siwx-oidc-security-review` | `~/siwx-oidc-sec` | Consolidated findings + raw reports, **Tier-1 fixes**, **race fixes**, CRITICAL remediation spec |

Kept separate per your instruction. The security branch is off `main`; the harness branch is off `main`. They share the race-suite commit (cherry-picked) so the security branch can self-verify its fixes.

---

## R1 — Requirement map  →  `docs/audits/2026-06-14-siwx-oidc-requirement-map.md`
Canonical "what must work" for the Synapse-side contract: flow families A–K (wallet login, WebAuthn reg/login, passkey↔wallet linking, RFC 8628 device auth, token lifecycle, MSC4191 account mgmt, Matrix compat, cross-signing stability, Synapse outcomes, **multi-participant E2E messaging**), each as falsifiable if-then hypotheses, plus the **H1–H14 race/cleanup hazard register** that drove everything.

## R2 — Headless test harness (green, committed)
**Run it:** `cd ~/siwx-oidc && bash e2e/up.sh && cargo test --test e2e_race_teardown -- --ignored --test-threads=1 && bash e2e/browser/run.sh`

- **`tests/e2e_race_teardown.rs`** (Rust, mock+Redis, deterministic interleavings) — **11/11 green**, guarding H1 (revoke≠delete), H2 (no device-id recycling), H4/H8/H12/H14 + introspection. Mock gained a `/__fail` fault-injector + `effective_deletes` accounting.
- **`e2e/browser/device-lifecycle.spec.mjs`** + extracted `wallet-helper.mjs`/`webauthn-helper.mjs` — **13/13 green** (passkey register→login→token, one-re-auth-covers-many, base64 device_view, **H13 erase purges WebAuthn creds from Redis**, **H11 challenge session-binding**, R-G4 cross-signing-reset, R-G8 CSRF).

## R3 — Security review (separate branch)
**Consolidated:** `~/siwx-oidc-sec/docs/audits/2026-06-14-siwx-oidc-security-review.md` (raw per-dimension reports under `docs/audits/raw-findings/`).

**What's solid:** crypto primitives (EIP-191/Ed25519/P-256), the WebAuthn assertion verifier, the cookie-login nonce/resource binding, atomic auth-code consumption, constant-time secret compare, ownership-gated passkey linking, no JWT alg-confusion, `TeardownPolicy` (revoke=tokens-only) already correct, no device-id recycling.

**Headline findings:**

| ID | Severity | Finding | Status |
|---|---|---|---|
| C1 | **CRITICAL** | Replayable CAIP-122 sigs on device-approval + account-mgmt (no nonce/expiry/resource binding) → account takeover (corroborated ×3) | ⚠️ **PARTIAL: login-path expiry FIXED**; device/account nonce binding **specced** (breaking) |
| C2 | **CRITICAL** | OAuth code not bound to client/redirect; open redirect at `/sign_in`; PKCE optional | ⚠️ **PARTIAL: open-redirect + code↔client + plain-PKCE FIXED**; require-redirect@`/token` + mandatory-PKCE **specced** (breaking) |
| H-d/H9 | HIGH | Device-code Approved branch double-redeemable | ✅ **FIXED** |
| H-e/H3 | HIGH | `device_delete` TOCTOU + KEYS-scan revoke races refresh → stale tokens survive sign-out | ✅ **FIXED** |
| H-f/H6/H5 | HIGH | deactivate/erase non-atomic sweep → refresh resurrects access; orphan credential | ✅ **FIXED** (H6 resurrection; purge completeness improved) |
| H-a | HIGH | ES256 private signing key logged at INFO → ID-token forgery | ✅ **FIXED** |
| M1 | MED | `cargo audit` 5 vulns (incl. rustls-webpki CRL panic on TLS path) | ✅ **FIXED** (→1; lone `rsa` Marvin has no upstream fix) |
| M2 | MED | Non-constant-time CSRF compare | ✅ **FIXED** |
| H-b/H-c | HIGH | CAIP-122 Expiration-Time never enforced; resource binding only on login path | ⚠️ login-path exp ✅ **FIXED**; device/account exp+resource in C1 spec |
| C2 negatives | — | New regression suite `tests/e2e_oauth_binding.rs` (expired-sig, client mismatch, bad redirect, plain-PKCE) | ✅ **4/4 green** |
| H-g | HIGH | Token-type confusion + 90-day refresh TTL vs 24h documented | In spec (recommend) |
| H-h/H-i | HIGH | Unauthenticated unbounded client + no-TTL credential growth (DoS) | In spec (recommend) |
| S3-2 | HIGH | Device-approval Pending→Approved write split-brain (separate from the redemption fix) | Documented (follow-up) |

## R4 — Real-Synapse validation + messaging regression
Stood up a **real local stack** (Synapse 1.154 + MSC3861 + siwx-oidc from local source) as `siwx-real-*` on `localhost:8081`/`:8448`.

- `e2e_msc4191_live` **3/3**, `e2e_msc3861` **3/4** → real-homeserver backing for R-A3/A4, R-E4, R-I1/I2/I3 (**cross-signing reset round-trips**), R-J1.
- **Messaging regression `two_client_messaging` PASS** — two distinct `did:pkh` identities provisioned as real Synapse users, share a room, exchange messages **both ways**. ✅ R-K1/K2 for provisioning+delivery.
- The `e2e_session_teardown` "failures" are **NOT bugs** — a Synapse ~120s introspection-cache timing gap in the tests (proven: siwx-oidc revokes instantly per logs; a sibling polling test flips 200→401 at exactly t+120s). The one msc3861 fail is a local-stack metadata-config gap, not provider code.

---

## ⚠️ What needs your decision

1. **CRITICAL C1 & C2 — remaining (breaking) parts** — the verified-safe subset is already fixed (`6e16b47`). What's LEFT needs your review because it changes the CAIP-122 message shape / OAuth contract and requires coordinated frontend (device/account embedded pages) + test edits: (a) **C1** server-issued single-use nonce binding on the device-approval + account-management paths (the full account-takeover fix — login path is already mitigated by expiry); (b) **C2** make `redirect_uri` mandatory at `/token` and PKCE mandatory for public clients. Full ready-to-apply detail (files, frontend, tests, verification, effort/risk): `~/siwx-oidc-sec/docs/audits/2026-06-14-remediation-spec-criticals.md`.
2. **Push the branches?** Both are local + committed, nothing pushed. Say the word and I'll push + open PRs.
3. **HIGH recommendations — OWNER TRIAGE (2026-06-14):**
   - **Refresh-TTL: RESOLVED.** The 90-day TTL (`REFRESH_TOKEN_TTL = 7_776_000` s) is the
     **intended** behavior; the old "24h" documentation was simply wrong. Docs corrected
     (`CLAUDE.md` token model + refresh-tokens prose). No code change.
   - **Token-type tagging** (access/refresh interchangeable; no `mat_`/`mcr_`/type check on
     the refresh & bearer paths) remains an **optional recommendation** worth applying.
   - **Dynamic client registration (DCR): ACCEPTED — left open intentionally by owner
     decision.** Do **not** gate it now; revisit if/when abused.
   - **No-TTL WebAuthn-credential growth (H-i)** is related to the DCR decision —
     **accepted-for-now** alongside DCR, but worth **monitoring** (Redis storage growth).
4. **E2EE messaging (R6 stretch):** the plaintext regression (`two_client_messaging`) proves
   provisioning + delivery. The true **E2EE** two-client test is now being **executed via the
   aqua-matrix-connector** (matrix-sdk e2e, logs in through siwx-oidc) pointed at the local
   real stack (`:8081`/`:8448`); the cross-signing half is already covered by `msc4191_live`.
5. **Teardown tests** should poll past the 120s Synapse introspection cache (currently assert immediately). One-line-ish improvement — want it?

---

## How to run / stack state

Stack state (memory GREEN throughout):
- Mock stack `siwx-e2e-*` — **torn down** after the last fix run. Recreate from either worktree with `bash e2e/up.sh`.
- Real stack `siwx-real-{redis,oidc,synapse}` on `:8081`/`:8448` — **left running** for your inspection (recipe in `/tmp/track2-real-stack.md`). Note its siwx-oidc runs the *pre-fix* binary built from `~/siwx-oidc`; rebuild from `~/siwx-oidc-sec` to exercise the fixes against real Synapse.
- **Teardown real stack when done:** `podman rm -f siwx-real-redis siwx-real-oidc siwx-real-synapse && podman network rm siwx-real-net`.
- Your 7 `aqua-agent-*` production containers were never touched.

Re-run the security branch's own verification:
`cd ~/siwx-oidc-sec && bash e2e/up.sh && cargo test --test e2e_race_teardown -- --ignored --test-threads=1` (the un-gated reproducers are now permanent regression guards).

---

## Commit index
- functional: `b25be55` req-map · `1d7641d` race suite · `ef1469a` browser suite · `8f84780` R2 plan
- security: `80b7e2c` findings · `91959c9` tier-1 fixes · `38395f1` race suite (cherry-pick) · `078894d` race fixes · `38d06dc` C1/C2 remediation spec · `6e16b47` safe-subset C1/C2 fixes + `e2e_oauth_binding.rs`
