# Plan: passkey scoping + new-user gate + Secure Backup fix

**Date:** 2026-06-18
**Branch:** `feat/passkey-scoping-new-user-gate` (off origin/main e64e606)
**Spec:** docs/design/2026-06-18-passkey-scoping-and-new-user-gate.md
**Skill:** process-pipeline (plan -> execute -> audit -> deploy w/ rollback)

## Goal

Make the passkey picker show only the relevant account for returning users, gate
accidental new-account creation at login, forbid new-account creation in
account/QR flows, and fix the Secure Backup false positive — without re-opening the
enumeration leak or regressing the shipped hardening.

## Load-bearing invariant

The identity hint MUST be an opaque server-side token (acct_session pattern). Never
a plaintext DID cookie, never a free-form identifier. Forged/guessed token -> Redis
miss -> usernameless fallback.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | a VALID opaque user-cookie (token->Redis->DID) is present at authenticate_start | allowCredentials is scoped to that DID's credentials only | webauthn-rs start_passkey_authentication populates allow list | browser e2e: login X -> cookie -> re-login -> assert allowCredentials == X's cred ids only |
| H2 | a forged/guessed user-cookie token is presented | Redis miss -> empty allowCredentials (usernameless), zero credential ids leaked | opaque token, DID not in cookie | rust/e2e: random token -> authenticate_start allowCredentials empty |
| H3 | a DID has linked (webauthn:link) and/or derived credentials | get_passkeys_for_did returns exactly those cred ids (incl. wallet-linked), via webauthn:by_did index | index maintained at register_finish/link_finish | rust unit + e2e: register+link, assert set; index == scan |
| H4 | a passkey/wallet at LOGIN resolves a NEW identity (is_localpart_available==true) | finish returns is_new; NO Synapse user provisioned until confirm; cancel => zero Synapse state | is_localpart_available is read-only & accurate | e2e: new passkey login -> gate, Synapse user absent; confirm -> provisioned |
| H5 | a NEW identity is presented in ACCOUNT re-auth OR QR/device approval | request is REJECTED (clear error), nothing provisioned | same detector | e2e: new passkey on /account/passkey/finish & /device/passkey/finish -> rejected, user absent |
| H6 | login (passkey/wallet) or account re-auth succeeds | an opaque user-cookie mapping to the DID is Set-Cookie'd (Path=/, HttpOnly, SameSite, Secure) | DID in hand at finish seams | e2e: assert Set-Cookie; next authenticate_start scopes |
| H7 | the user-cookie is present on the login page | the detected account is shown (detected-accounts UI) | App.svelte bundle built by CI | browser e2e on server-rendered parity / CI build |
| H8 | a known-identity context's DID lacks a method (wallet-only or passkey-only) | that method is greyed out / disallowed | methods_for_did correct | e2e: methods_for_did + UI/endpoint assertion |
| H9 | the racy approval-time cross-signing check is dropped (or race-tolerant) | no false "no Secure Backup" warning for a mid/post-bootstrap user | force-first-device-recovery enforces the real prereq | code/e2e: warning no longer fires unconditionally |
| H10 | all changes applied | discoverable fix + stale-key prune + #9/#10/#11 hardening still pass | branch off current main | full browser suite + cargo tests green |
| H11 | user chooses "use a different passkey" when cookie-scoped | authenticate_start re-runs usernameless (all keys) | escape param wired | e2e: escape -> empty allowCredentials |

## Acceptance Criteria

AC1 (H1,H11): returning-user login with valid cookie shows ONLY that account's keys; escape -> usernameless.
AC2 (H4): login new identity -> gate, nothing provisioned until confirm; cancel clean.
AC2b (H5): new identity in account/QR -> REJECTED, nothing provisioned. Creation only at login.
AC3 (H2): forged cookie -> usernameless, no enumeration.
AC4 (H3): wallet-then-link-passkey is in scope for the wallet DID; index == scan.
AC5 (H6,H7,H8): account flow scopes + sets cookie; detected-accounts UI shows; unavailable methods greyed.
AC6 (H9): Secure Backup false positive gone.
AC7 (H10): no regression (full suite green).

## Tasks

### Task 1: Redis layer — user-session, by_did index, resolvers
**Hypotheses:** H1,H2,H3,H6 (+ H4/H5 detection)
**Files:** src/db/redis.rs, src/db/mod.rs, src/webauthn.rs
- [ ] `webauthn:by_did/{did}` SET maintained at register_finish + link_finish (and removed on purge_identity).
- [ ] `get_passkeys_for_did(did) -> Vec<cred_id_b64>` reading the index (fallback to scan if index empty).
- [ ] opaque login user-session: `create_user_session(did) -> token`, `lookup_user_session(token) -> Option<did>` (Redis `user:session/{token}` w/ TTL), mirroring create/lookup_account_session.
- [ ] `is_new_identity(did)` wrapper over SynapseClient::is_localpart_available(did_to_localpart(did)).
- [ ] cargo build + unit test get_passkeys_for_did and index==scan equivalence.

### Task 2: webauthn.rs — scope authenticate_start + methods_for_did
**Hypotheses:** H1,H3,H8,H11
**Files:** src/webauthn.rs, src/axum_lib.rs
- [ ] authenticate_start gains an optional scoped path: when given a DID (from a valid user-cookie), call start_passkey_authentication(&passkeys) -> populated allowCredentials; persist the PasskeyAuthentication state; else keep start_discoverable_authentication.
- [ ] escape hatch: a request flag (e.g. `?all=1` / body field) forces usernameless even when a cookie is present (H11).
- [ ] `methods_for_did(did) -> {wallet,passkey}` (wallet = did:pkh prefix; passkey = !get_passkeys_for_did.is_empty()).
- [ ] cargo build clean.

### Task 3: New-user handling — login GATE + account/QR REJECT
**Hypotheses:** H4,H5
**Files:** src/webauthn.rs, src/axum_lib.rs, src/account.rs, src/device_auth.rs, src/oidc.rs
- [ ] Login: webauthn_authenticate_finish detects is_new (after verify, before sign_in) and returns `{ok:false, new_user:true, mxid}` instead of finalizing; a confirm step (cookie/flag) lets sign_in proceed. NO provisioning until confirm. Wallet login path likewise gated where it resolves a new identity.
- [ ] Account: account_passkey_finish + account_wallet REJECT when is_new -> CustomError (clear "no existing account; create one at sign-in").
- [ ] QR/device: device_approve_passkey + device_approve REJECT when is_new -> clear error.
- [ ] cargo build + unit tests on the gate/reject mapping.

### Task 4: Cookie wiring (set-on-success, read-on-start, re-inject)
**Hypotheses:** H6,H1,H11
**Files:** src/axum_lib.rs, src/oidc.rs, src/account.rs
- [ ] Set user-cookie at: webauthn_authenticate_finish (after confirm), sign_in handler (wallet), account authed_action.
- [ ] Read user-cookie at authenticate_start handler -> resolve DID -> scope (unless escape).
- [ ] cargo build clean.

### Task 5: Frontends — detected-accounts UI, new-user gate UI, grey-out, escape
**Hypotheses:** H7,H8,H4,H11
**Files:** js/ui/src/App.svelte, src/account.rs (JS), src/device_auth.rs (JS)
- [ ] App.svelte login: show detected account when cookie present; "use a different passkey" escape; render the new-user gate (confirm/cancel); grey out unavailable method.
- [ ] account.rs/device_auth.rs JS: reject-new error rendering; grey-out where identity known.
- [ ] cargo build clean (server-rendered JS); App.svelte built by CI.

### Task 6: Secure Backup false-positive fix
**Hypotheses:** H9
**Files:** src/device_auth.rs (check_cross_signing), CLAUDE.md
- [ ] Drop the approval-time check_cross_signing call (preferred) OR reword to "no published cross-signing identity yet" + make race-tolerant (short retry, non-blocking).
- [ ] cargo build clean.

### Task 7: Tests (Rust + browser e2e) + regression
**Hypotheses:** H2,H3,H4,H5,H10,H11
**Files:** src/* tests, e2e/browser/*.spec.mjs
- [ ] Rust: enumeration-safety (forged cookie empty), get_passkeys_for_did/index, is_new mapping, account/QR reject.
- [ ] Browser e2e (server-rendered account/device + harness): cookie-scoped picker, escape, login gate, account/QR reject, false-positive gone.
- [ ] Regression: e2e/up.sh + e2e/browser/run.sh full suite green; cargo test --bin siwx-oidc.

### Task 8: Docs
- [ ] CLAUDE.md: user-cookie scoping, new-account creation policy (login-only), webauthn:by_did index, Secure Backup fix.

## Boundary conditions
- Enumeration-safety invariant (opaque token only).
- Branch MUST stay off current origin/main (preserve hardening).
- App.svelte not locally buildable (npm absent) -> CI builds; verify server-rendered parity locally.
- New-account creation reachable ONLY from login (account/QR reject).
- Deploy: merge to main -> CI -> prod pull/up with captured rollback tag; gate at plan + audit.
