# siwx-oidc — Functional & Security Requirement Map (Logic Model)

**Date:** 2026-06-14
**Branch:** `audit/siwx-oidc-functional-harness`
**Method:** W.K. Kellogg Logic Model (Inputs → Activities → Outputs → Outcomes → Impact); every edge is a falsifiable if-then hypothesis.
**Primary goal:** Resilience + correctness of the provider, with special focus on **race conditions in device removal** and **correct session / cross-signing cleanup**.
**Secondary deliverable:** Complete headless browser suite (MetaMask + WebAuthn) covering every function that must work on the Synapse side, plus multi-participant E2E messaging as regression protection.

---

## 0. CONTEXT (where we are)

- Provider: Rust/Axum `siwx-oidc`, a fork of `siwe-oidc`, supporting wallet (SIWE / CAIP-122) **and** WebAuthn passkey login. Acts as upstream OIDC provider for a Matrix stack: **siwx-oidc → MAS (MSC3861 delegated auth) → Synapse**.
- State store: **Redis** (sessions, codes, tokens, webauthn challenges/credentials, device codes, account sessions). Single-threaded Redis; some atomicity via Lua (`try_consume_code`, `try_mark_session_signed_in`).
- Prod: `matrix.inblock.io`, manual deploy of GHCR image behind Caddy.
- Existing tests: Rust unit (~65–91), Rust HTTP E2E (`tests/e2e_*.rs`), Playwright browser E2E (`e2e/browser/account.spec.mjs` — mock `window.ethereum` + CDP virtual authenticator), Synapse mock (`e2e/synapse_mock.py`), pipeline `e2e/run-all.sh`, CI fmt/clippy/test.
- Recent history (correctness-relevant): PR#6 single re-auth session + legacy CS-API delete; PR#7 device button styling; PR#8 base64 device-id preservation. Incident 2026-06-12: RFC 7009 revoke wrongly deleted a Synapse device mid key-upload → `TeardownPolicy` split (revoke=TokensOnly, logout=DeleteDevice).

## GOAL (one sentence)

> Prove, by an automated headless suite and a security review, that every wallet/WebAuthn auth and device-management flow exposed by siwx-oidc produces the correct, race-free state on the Synapse side — devices provisioned and torn down exactly once, sessions and cross-signing identity cleaned up correctly, and that real encrypted messaging between two participants still works after these flows.

**Acceptance criterion:** Each requirement R# below has at least one automated, falsifiable test that is green; each identified race/cleanup hazard (H#) has a test that would go red if the hazard regressed; the security review produces a findings list with each HIGH finding fixed or explicitly accepted by the user.

**Out of scope (this round):** real MetaMask browser-extension automation if the mock-provider path already exercises identical server logic (decision recorded in R2); passkey recovery/backup-code UX; production deploy (deploys are manual and the user's call).

---

## 1. THE CANONICAL "WHAT MUST WORK" LIST

Flow families A–K. Each requirement is phrased as the **Outcome** (state change), not the Output (bytes returned), per OECD-DAC. `S:` = Synapse-side outcome that must hold.

### A. Wallet (SIWE / CAIP-122) login
- **R-A1** A valid CAIP-122 signature over the session nonce + correct `redirect_uri` yields a single-use auth code. *(IF nonce matches session AND sig verifies AND redirect_uri ∈ message.resources THEN code issued.)*
- **R-A2** Auth code exchanges once for tokens; a second exchange fails. *(atomic `try_consume_code`.)*
- **R-A3** S: On token issuance in MSC3861 mode, Synapse user is provisioned (`/_synapse/mas/provision_user`) and a fresh device `SIWX_{uuid8}` is upserted (`/_synapse/mas/upsert_device`).
- **R-A4** Issued scope carries `urn:matrix:client:device:{device_id}` matching the upserted device.
- **R-A5** Replay of a stale/wrong nonce, expired session (>300s), or mismatched redirect_uri is rejected.
- **R-A6** PKCE: if `code_challenge` present, token exchange without matching `code_verifier` fails.

### B. WebAuthn passkey registration
- **R-B1** `register/start` issues a challenge bound to the session (Redis, 120s TTL).
- **R-B2** `register/finish` verifies attestation, derives a deterministic `did:key:zDn…` from the P-256 pubkey, stores the credential (no TTL).
- **R-B3** A second registration of the same authenticator/user is handled without corrupting the stored credential.
- **R-B4** Challenge reuse / expiry (>120s) is rejected.

### C. WebAuthn passkey login
- **R-C1** `authenticate/start` → `authenticate/finish` verifies the assertion, resolves the stored credential, and writes `verified_did` server-side into the session.
- **R-C2** `/sign_in` consumes `verified_did` (no CAIP-122 sig needed) and issues a code; subsequent token exchange provisions the device (as A3/A4).
- **R-C3** Same passkey ⇒ same DID across logins (deterministic).
- **R-C4** Sign-count regression (cloned authenticator) is rejected by webauthn-rs.
- **R-C5** Login with `did:key` only succeeds if `key` ∈ `SUPPORTED_DID_METHODS`.

### D. Passkey ↔ wallet linking
- **R-D1** `link/webauthn/start` requires a verified wallet `siwx` cookie (prevents cross-user linking).
- **R-D2** After linking, a passkey login resolves to the **wallet** primary DID, not the raw `did:key` ⇒ same Matrix account.

### E. RFC 8628 device authorization (QR / Element X)
- **R-E1** `/device_authorization` issues device_code + user_code (entropy adequate), with interval + expiry.
- **R-E2** Polling faster than `interval` returns `slow_down`; before approval returns `authorization_pending`.
- **R-E3** Approval (wallet or passkey) sets status=Approved and binds DID + negotiated device_id.
- **R-E4** S: On approved token issuance, device upserted with negotiated id and `allow_cross_signing_reset` called.
- **R-E5** Denied / expired device codes never yield tokens.

### F. Token lifecycle
- **R-F1** Refresh: `/token` grant_type=refresh_token rotates tokens; old refresh token invalid afterward.
- **R-F2** S: Introspection (`/oauth2/introspect`) of a live access token returns `active:true` with the correct `username`, `device_id`, `scope`, `sub`.
- **R-F3** Introspection of a revoked/expired/unknown token returns `active:false`.
- **R-F4** Introspection auth: a wrong shared secret / missing auth is rejected.
- **R-F5** Revocation (`/oauth2/revoke`, RFC 7009) is idempotent and always 200.

### G. MSC4191 account management
- **R-G1** `/account/wallet` (or passkey) re-auth mints a 600s `acct_session` + CSRF; one re-auth covers multiple subsequent `/account/action` calls.
- **R-G2** `devices_list` / `device_view` return the user's Synapse devices; `device_view` resolves **base64 device ids** (the `/`-containing ids fixed in PR#8).
- **R-G3** `device_delete` / `session_end`: S: deletes the Synapse device **and** revokes that device's tokens.
- **R-G4** `cross_signing_reset`: S: calls `allow_cross_signing_reset(localpart)`.
- **R-G5** `account_deactivate`: S: deactivates (erase=false) **and** revokes ALL user tokens.
- **R-G6** `account_erase`: S: deactivates (erase=true) + revokes ALL tokens + **purges WebAuthn credentials** for the DID (no silent re-derivation).
- **R-G7** `account_reactivate`: S: clears deactivated flag (or fails closed with a legible "ask an admin" message, never 500).
- **R-G8** CSRF: `/account/action` without/with wrong CSRF token is rejected; `acct_session` is scoped/HttpOnly.
- **R-G9** `acct_session` for user X cannot act on user Y's devices (authorization, not just authentication).

### H. Matrix compat (legacy CS-API for in-client session manager)
- **R-H1** `GET /_matrix/client/v3/login` advertises the MSC3861 flow.
- **R-H2** `POST /_matrix/client/v3/logout`: S: deletes the device (explicit intent) + revokes its tokens.
- **R-H3** `POST /_matrix/client/v3/logout/all`: S: revokes all tokens / removes all devices for the user.
- **R-H4** `DELETE /_matrix/client/v3/devices/{id}` and `POST /delete_devices`: S: delete the named device(s).
- **R-H5** `POST /_matrix/client/v3/refresh` rotates tokens (legacy path parity with R-F1).

### I. Cross-signing identity stability
- **R-I1** Device ids are **never recycled**: each sign-in upserts a fresh `SIWX_{uuid}`; no delete-then-reuse.
- **R-I2** On login, `allow_cross_signing_reset` is called so MSC3967 first key upload bypasses UIA.
- **R-I3** S: After any device deletion, the **user's cross-signing identity for remaining devices is unaffected** (no collateral signature loss).

### J. Synapse-side consolidated outcomes (the contract)
- **R-J1** Every "must work" Synapse call uses the agreed admin/MAS path & secret; a wrong secret fails legibly (not opaque 500). (`admin_token == mas_shared_secret` assumption — flagged.)
- **R-J2** All Synapse interactions are best-effort/idempotent and never 500 the user-facing endpoint, but **do** surface failure in logs/outcome payload.

### K. Multi-participant E2E messaging (regression protection)
- **R-K1** Two distinct identities can each complete login (wallet and/or passkey), be provisioned on Synapse, join a shared **encrypted** room, and exchange a message each that the other decrypts.
- **R-K2** After one participant signs out a device (G3/H2) the other participant's session and the room's E2EE continue to work (no collateral cross-signing damage — ties to R-I3).

---

## 2. RACE-CONDITION & CLEANUP HAZARD REGISTER (PRIMARY FOCUS)

Each hazard H# is a falsifiable failure hypothesis. The suite must include a test that **goes red if the hazard is real / regresses**. These are the heart of the audit.

| ID | Hazard (the bad state) | Falsifiable test hypothesis |
|----|------------------------|------------------------------|
| **H1** | RFC 7009 revoke deletes the Synapse device (the 2026-06-12 incident) | IF a token is revoked via `/oauth2/revoke`, THEN the Synapse device still exists (only `/logout` & `device_delete` delete it). Assert `DELETE /devices` NOT called on revoke. |
| **H2** | Device-id recycling corrupts cross-signing | IF N sequential sign-ins for one DID occur, THEN N distinct `SIWX_*` ids are upserted and none is reused after deletion. |
| **H3** | Concurrent device_delete on the **same** device double-deletes / errors | IF two `device_delete` for the same id race, THEN exactly one delete reaches Synapse OR both are idempotent-safe; endpoint never 500s; tokens end revoked. |
| **H4** | Concurrent device_delete on **different** devices of same user clobbers state | IF deletes of dev-A and dev-B race, THEN both deleted, neither's revoke wipes the other's tokens, remaining devices intact. |
| **H5** | account_erase races a concurrent login (credential re-derivation) | IF erase (purges credentials) races a passkey `authenticate/finish`, THEN no post-erase credential survives and no usable token is minted for the erased identity. |
| **H6** | account_deactivate races an in-flight token refresh | IF deactivate (revoke ALL) races a `/token` refresh, THEN the refreshed token is NOT active on introspection (no resurrection). |
| **H7** | Token revoke races an in-flight cross-signing key upload | IF revoke/delete races MSC3967 key upload, THEN either upload completes before delete or fails cleanly; device's cross-signing rows are never orphaned (root cause of the incident). |
| **H8** | Auth-code double-spend under concurrency | IF the same code is exchanged twice concurrently, THEN exactly one succeeds (Lua `try_consume_code`), the other errors. |
| **H9** | Device-code double-approval with different DIDs | IF a device_code is approved twice with different DIDs concurrently, THEN the token minted binds a single coherent (DID, device_id); no split-brain device owned by two DIDs. |
| **H10** | acct_session reuse after terminal action | IF a terminal action (erase/deactivate) completes, THEN the `acct_session` cookie is cleared and cannot drive a further `/account/action`. |
| **H11** | WebAuthn challenge replay across sessions | IF a challenge captured in session S1 is replayed in S2, THEN finish fails (challenge bound to session_id). |
| **H12** | Stale/duplicate session leads to wrong device teardown | IF multiple sessions exist for a DID, THEN device_delete targets exactly the requested device_id, not a sibling. |
| **H13** | Redis key without TTL leaks (credentials/links) vs. erase purge completeness | IF identity erased, THEN `webauthn:credential/*` and `webauthn:link/*` for that DID are gone (no orphan). |
| **H14** | Synapse unreachable mid-flow leaves partial state | IF Synapse is down during device_delete, THEN tokens are still revoked locally, the failure is surfaced, and a retry converges (no silent half-delete claimed as success). |

---

## 3. LOGIC-MODEL CHAIN (Inputs → Activities → Outputs → Outcomes → Impact)

**Inputs**
- Code: `src/{oidc,webauthn,device_auth,account,compat,introspect,synapse_client}.rs`, `src/db/redis.rs`.
- Test assets: `e2e/up.sh`, `e2e/synapse_mock.py` (+ `/__seed_device`,`/__reset`,`/__state`,`/__set_secret` hooks), `e2e/browser/*`, `tests/e2e_*.rs`.
- Knowledge: Matrix MSC3861/4191/4312/3967/8628, this map, repo CLAUDE.md.
- External: Redis, Playwright container w/ CDP virtual authenticator, ethers.js mock wallet; (optional) real Synapse for live probes.

**Activities → Outputs**
1. Modularize browser helpers (`wallet-helper.mjs`, `webauthn-helper.mjs`, `synapse-mock-helpers.mjs`) → reusable ceremony+sig primitives.
2. Extend Synapse mock to record per-call ordering & expose cross-signing/key-upload counters → observable Synapse-side outcomes for H1–H14.
3. Author tests per requirement R-* and hazard H-* (browser where a UI path exists; Rust HTTP E2E for concurrency/races that need precise timing) → test files.
4. Run `e2e/run-all.sh` + new suites; capture pass/fail + mock `/__state` evidence → audit result table.
5. Multi-participant E2E messaging test (K) → regression artifact.
6. Security review (separate branch) → findings list + fixes.

**Outcomes (what becomes true)**
- Every R-* has a green falsifiable test; every H-* has a guard test.
- All audited paths confirmed working against the mock (and, where safe, a live probe).
- Security findings triaged; HIGH fixed or accepted.

**Impact**
- The provider's device/session/cross-signing lifecycle is provably race-free and spec-compliant; regressions are caught by CI; encrypted messaging between participants is protected.

---

## 4. BOUNDARY CONDITIONS

**Assumptions (outside our control — each inversion is a risk):**
- A1: `admin_token == mas_shared_secret` on the real Synapse (R-J1). *Risk: all device actions fail in prod if untrue.*
- A2: Synapse mock faithfully mirrors real Synapse semantics for device delete / cross-signing rows. *Risk: green mock, red prod.*
- A3: CDP virtual authenticator + ethers mock exercise the **same server code** as real MetaMask/passkey. *Risk: UI-only gaps.*
- A4: Redis single-threaded atomicity holds for our Lua scripts under concurrency. *Risk: race tests give false-green if timing not forced.*

**Exclusions:** real MetaMask extension automation (decide in R2 if mock parity suffices); passkey recovery; prod deploy.

**Invariants (must never be violated):**
- Device ids never recycled (R-I1/H2).
- Revoke ≠ device delete (H1).
- Erase purges credentials (R-G6/H13).
- No endpoint 500s on Synapse failure; failure still surfaced (R-J2/H14).
- Memory governance: if subagent admission is denied, run inline/sequentially — do not bypass.

**Top 3 risks:** (1) mock/prod divergence on cross-signing (A2) — mitigate with at least one live read-only probe; (2) false-green race tests (A4) — mitigate by forcing interleavings, not wall-clock sleeps; (3) admin/secret mismatch (A1) — mitigate with an explicit negative test (R-F4/R-J1).

**Loop exit criterion:** Rounds end when every R-* test is green, every H-* guard exists and is green, security HIGHs are resolved/accepted, and the K regression passes. Track via task list R1–R5.
