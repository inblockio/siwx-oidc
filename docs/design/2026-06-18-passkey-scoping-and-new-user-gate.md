# Passkey picker scoping + new-user gate — design (closed-case)

**Date:** 2026-06-18
**Status:** DESIGN / checkpoint artifact (pre-implementation gate)
**Reviewed with:** logic-model (case closure) + elon-method (delete/simplify)
**Targets deployed code:** main @ e64e606

## Problem

Usernameless/discoverable login sends empty `allowCredentials`, so the OS passkey
picker shows EVERY resident passkey for the RP (the "Pass_Key_Madness" screenshot).
A user logging into one account sees unrelated accounts' passkeys, and with no
identity hint can pick a passkey that logs them into, or silently CREATES, a
different Matrix account.

## Identity model (confirmed, with code)

- A passkey resolves to a DID at `verify_credential` (`webauthn.rs:335-351`): a
  `webauthn:link/{cred_id}` mapping yields the linked wallet `primary_did`; no link
  yields the derived `did:key:zDn…`.
- `sign_in` -> `provision_synapse_device` (`oidc.rs:1511-1540`) branches on
  `is_localpart_available`: a FREE localpart calls `provision_user` and **creates a
  brand-new Matrix account**; a taken one is reused. So authenticating with an
  unrecognised passkey silently creates/enters a different identity.
- "New" is detectable BEFORE any Synapse write via the same `is_localpart_available`
  call. The gate seam is `authenticate_finish` (return `is_new`) BEFORE the
  `/sign_in` redirect, so the single-use `try_mark_session_signed_in` guard
  (`oidc.rs:1565`) is not tripped and no user is provisioned until the user confirms.

## Enumeration-safety invariant (load-bearing)

The discoverable fix (e64e606) closed an unauthenticated credential-enumeration
leak. Any identity hint that a client can FORGE or freely supply re-opens it
(`did:pkh` DIDs are public wallet addresses; there is no cookie-signing facility).
Therefore:

> **INVARIANT:** the identity hint used to scope `allowCredentials` MUST be an
> opaque server-side token (the `acct_session` pattern: random token -> Redis -> DID),
> never a plaintext DID cookie and never a free-form typed identifier. A forged or
> guessed token is a Redis miss -> safe fallback to usernameless.

## The closed case matrix (login flow)

| # | Cookie | Picker | User action | Closure |
|---|--------|--------|-------------|---------|
| 1 | valid (DID X has keys) | only X's keys (scoped) | picks X's key | login as X |
| 2 | valid, but wants another account | X's keys + "use a different passkey" | escape -> usernameless | falls to 5/6 (escape hatch REQUIRED) |
| 3 | present but stale (X has no usable key) | scoped empty -> behaves usernameless | picks any | falls to 5/6/7 |
| 4 | absent, 0 passkeys | usernameless (nothing) | register / use wallet | intentional new identity |
| 5 | absent, 1 passkey | usernameless (that one) | picks it | existing -> login; new -> **new-user gate** |
| 6 | absent, MANY passkeys (critical) | usernameless (all) | picks one | existing -> login; new -> **new-user gate** |
| 7 | any | picks a STALE key (no server record) | — | 401 unknown_credential + signalUnknownCredential prune (SHIPPED) |

Closures:
- **Cookie-scoping** closes 1, 3 (returning user sees only their keys).
- **Escape hatch** ("use a different / new passkey" -> usernameless) closes 2.
- **New-user gate** closes 5, 6 (accidental new-account creation). This is the
  single most important addition and the user's explicitly-flagged critical case.
- **signalUnknownCredential** (already shipped) closes 7.
- **Recovery key (Matrix-native, 4S/Secure Backup)** closes message-recovery when a
  user proceeds with a new/other passkey. No siwx-oidc code; surfaced in the gate copy.

Residual (lower severity): no-cookie pick of a DIFFERENT EXISTING account logs into
that account (recoverable by logout). The new-user gate intentionally fires only on
account CREATION (the dangerous, irreversible-feeling case). Showing the resolved
Matrix id in the gate also helps here.

## Other flows

- **Device / QR approval:** stays usernameless (scoping there is unsafe: the page
  has no siwx-oidc identity, and Element X opens it in a fresh browser; typed-address
  scoping re-opens the leak). New-account creation is **REJECTED** here (see policy
  below): a passkey/wallet resolving to a non-existent account is refused; QR linking
  is for an existing account only. Plus the false-positive fix below.
- **Account / session management:** DID is known (`acct_session.did`). Scope the
  account passkey picker to that DID, and set/re-inject the login user-cookie so
  future logins are scoped. New-account creation is **REJECTED** here too (account
  management operates on an existing account).

## New-account creation policy (owner correction 2026-06-18)

Creating a new Matrix identity is permitted **ONLY at the login screen**, behind the
new-user gate (confirm-then-create). In the account-management and QR/device-approval
flows it is **IMPOSSIBLE**: if the authenticated DID has no existing account
(`is_localpart_available(did_to_localpart(did)) == true`), the request is REJECTED
with a clear error and NOTHING is provisioned. Detection is the same
`is_localpart_available` check at all sites; only the response differs:

| Flow | New identity (is_localpart_available == true) |
|------|-----------------------------------------------|
| Login (passkey + wallet) | new-user GATE: confirm -> create |
| Account re-auth (passkey + wallet) | REJECT (no provision) |
| QR / device approval (passkey + wallet) | REJECT (no provision) |
- **Wallet-login-then-link-passkey:** the linked passkey resolves to the wallet DID
  (`webauthn:link`), so `get_passkeys_for_did(wallet_did)` includes it; method
  detection sees both wallet (did:pkh) and passkey (link exists). Closed.

## Secure Backup warning false positive (incorporated)

`check_cross_signing` (`device_auth.rs:821`) runs at approval time and probes the
**cross-signing master PUBLIC key** (`master_keys`, `synapse_client.rs:179`), which
races the client's first-time bootstrap and mislabels it "Secure Backup." Auth and
localpart derivation are correct. Fix: **drop** the racy approval-time check (the
matrix-server force-first-device-recovery patch already enforces the real
prerequisite), or if kept, reword to "no published cross-signing identity yet" and
make it race-tolerant (retry/grace, non-blocking).

## elon-method decisions

KEEP (survived deletion): opaque cookie-scoping on login; new-user gate;
account-flow scoping + cookie re-inject; the shipped stale-key prune; the
false-positive fix.

DELETE / DEFER (surfaced for owner decision):
- "Detected accounts" custom UI -> DELETE: silent `allowCredentials` scoping already
  shrinks the OS picker; the OS picker IS the account list. Add back only if a
  visible affordance is wanted.
- Grey-out of uninitialised methods -> DEFER: UX polish, not a case-closure. (One
  edge it would help: a wallet-only DID whose cookie-scope yields zero passkeys; see
  residual above.)
- Device-flow identity scoping -> DELETE: unsafe/infeasible.
- `webauthn:by_did` reverse index -> DEFER unless the per-login `KEYS` scan in
  `get_passkeys_for_did` becomes a latency problem (login is a hot path; build the
  index if volume warrants — it is maintained at `register_finish`/`link_finish`).

## New helpers required (implementation)

1. `get_passkeys_for_did(did) -> Vec<cred_id_b64>` — read-only twin of
   `purge_identity`'s two scans (link `primary_did == did` + derived `did:key` match).
2. `is_new_identity(did)` — wrapper over `is_localpart_available(did_to_localpart(did))`.
3. opaque login user-session: `create_user_session(did)` + `set/clear_user_cookie`
   (Path=/), cloning `create_account_session` + `account_cookie_set`.
4. wire cookie-set at the two finish seams (`webauthn_authenticate_finish` ->
   `(HeaderMap, Json)`, `sign_in` handler -> `(HeaderMap, Redirect)`); scope at
   `authenticate_start` when a valid user cookie is present; new-user gate in
   `authenticate_finish` / `device_approve_passkey`.
5. (deferred) `methods_for_did`, `webauthn:by_did` index.

## Acceptance criteria (for the eventual pipeline)

- AC1: returning-user login with a valid user-cookie shows ONLY that account's
  passkeys; "use a different passkey" falls back to usernameless. (Cases 1,2,3)
- AC2: no-cookie passkey login that resolves a NEW identity shows the new-user gate
  and provisions NOTHING until confirmed; cancel leaves no Synapse user. (Cases 5,6)
- AC2b: a NEW identity presented in the account re-auth OR QR/device-approval flow is
  REJECTED (clear error, nothing provisioned). New-account creation is reachable ONLY
  from the login screen.
- AC3: a forged/guessed user-cookie does NOT scope (Redis miss -> usernameless); no
  enumeration. (Invariant)
- AC4: wallet login then link-passkey: the linked passkey is in scope for that
  wallet DID. (R5)
- AC5: account flow scopes its picker and sets the user-cookie.
- AC6: Secure Backup false positive no longer fires for a user mid/post-bootstrap.
- AC7: no regression to the shipped discoverable fix / stale-key prune / hardening.
