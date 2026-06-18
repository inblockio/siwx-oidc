# Plan: Fix WebAuthn passkey login showing ALL server credentials

**Date:** 2026-06-15
**Branch:** `audit/siwx-oidc-functional-harness`
**Skill:** process-pipeline (logic-model → execute → audit)

## Problem (grounded)

`authenticate_start` (`src/webauthn.rs:197`) starts a **discoverable** ceremony —
`start_discoverable_authentication()` returns an *empty* `allow_credentials` by
definition — then overwrites it (`webauthn.rs:206-220`) with **every** credential
stored in Redis (`webauthn:credential/*`, i.e. all users):

```rust
let (mut rcr, _auth_state) = webauthn.start_discoverable_authentication()?; // []
let credential_keys = redis.keys_raw("webauthn:credential/*").await?;       // ALL users
// ...build AllowCredentials for each...
rcr.public_key.allow_credentials = allow_list;                              // stuff them in
```

The browser is handed every passkey on the server and, on a fresh profile, shows
the full account picker ("all the different webauthn keys"). Two harms:
1. Confusing credential picker on login (the reported symptom).
2. Unauthenticated credential-ID enumeration leak (`POST /webauthn/authenticate/start`
   needs no auth).

Verification does **not** need the list: `verify_credential` (`webauthn.rs:256-264`)
looks the credential up by the `rawId` the browser returns. Every credential is a
discoverable resident-key passkey (`start_passkey_registration`, `webauthn.rs:133`,
`:387`), so the authenticator surfaces the user's own passkeys without an allow-list.

## Blast radius (grounded)

`authenticate_start` is the single shared entrypoint for **three** endpoints, so one
backend edit fixes all three:
- `webauthn_authenticate_start` — main login (`axum_lib.rs:455`)
- `device_passkey_start_handler` — device/QR approval (`axum_lib.rs:372`)
- `account_passkey_start_handler` — account re-auth (`axum_lib.rs:677`)

The all-credentials construction exists in exactly one place (`webauthn.rs:206-220`);
grep confirms no second copy. The device/account inline JS already tolerate an empty
`allowCredentials` (they only iterate it). Only `App.svelte handlePasskeySignIn`
(`js/ui/src/App.svelte:232-239`) has a throwing `allowCredentials.length === 0` guard
that would mis-fire once the list is empty.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | `authenticate_start` no longer overwrites `allow_credentials` | `POST /webauthn/authenticate/start` returns empty `allowCredentials` even with ≥2 creds registered | `start_discoverable_authentication()` yields empty allow list (webauthn-rs 0.6.0-dev definition) | NEW browser-E2E assertion: register 2 passkeys → call start → assert `allowCredentials.length === 0` |
| H2 | the allow-list is removed | a registered discoverable passkey still completes login → token (resolved by `rawId`) | registered creds are discoverable resident keys | EXISTING `device-lifecycle.spec.mjs` R-C1/R-C2/R-C3 (passkey register→login→token) passes on rebuilt binary |
| H3 | the allow-list is removed | account/device passkey re-auth (shares `authenticate_start`) still resolves the DID + completes its action | device endpoint shares the identical fn | EXISTING `device-lifecycle.spec.mjs` account-erase-via-passkey (`#btn-passkey`) passes |
| H4 | the `allowCredentials.length===0` guard is removed from `App.svelte` | frontend compiles; discoverable login no longer throws the spurious "No passkeys registered" on an empty list | App.svelte login handler has NO automated runtime test (KNOWN GAP) | `npm run build` (svelte) succeeds + code review confirms throw removed |
| H5 | grep for AllowCredentials/allow-list construction | the only occurrence is `webauthn.rs:206-220` (nothing else to fix) | — | grep — **already Confirmed in planning** |

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|-----------|-----------|
| AC1 | Server returns empty `allowCredentials` from `/webauthn/authenticate/start` with multiple creds registered (bug gone) | H1 |
| AC2 | Passkey login → token still works (no regression) | H2 |
| AC3 | Account/device passkey re-auth still works | H3 |
| AC4 | Frontend builds; spurious empty-list error removed | H4 |
| AC5 | `cargo build --bin siwx-oidc` + `cargo test --bin siwx-oidc` green | H2 |

## Tasks

### Task 1: Backend — drop the allow-list override (H1, H5)
- Edit `src/webauthn.rs` `authenticate_start`: remove lines 206-220 (the
  `keys_raw` scan, `allow_list` build, and `rcr.public_key.allow_credentials = …`).
  Remove the now-unused `use webauthn_rs_proto::AllowCredentials;` import.
- Keep the empty list from `start_discoverable_authentication()` and the existing
  challenge storage.

### Task 2: Frontend — drop the empty-list guard (H4)
- Edit `js/ui/src/App.svelte` `handlePasskeySignIn` (~232-239): remove the
  `allowCredentials.length === 0` throw; keep base64→buffer conversion guarded by
  presence so an empty/absent list is a no-op.

### Task 3: Regression test — assert empty allowCredentials (H1)
- Add a case to `e2e/browser/device-lifecycle.spec.mjs`: register two passkeys, call
  `/webauthn/authenticate/start`, assert the returned `allowCredentials` is empty.

### Task 4: Validate (H1, H2, H3, H4, AC1-5)
- `cargo build --bin siwx-oidc`; `cargo test --bin siwx-oidc` (Redis :6379 up).
- Rebuild+recreate e2e stack (`e2e/up.sh`) to load the new binary.
- `npm run build` in `js/ui` (frontend compiles).
- `bash e2e/browser/run.sh` — passkey register→login→token, account-erase-via-passkey,
  and the new empty-allowCredentials assertion all green.

## Boundary conditions

- **Out of scope:** whether account passkey re-auth additionally binds the resolved
  DID to the acting account (pre-existing behavior; the old allow-list contained all
  users anyway, so this change is security-neutral — does not weaken it).
- **Invariant:** no credential-ID list may be returned to unauthenticated callers.
- **Known validation gap:** `App.svelte`'s login handler is not covered by an
  automated runtime test; H4 is build + inspection only. Surfaced in the audit.
- **No commit/push** unless the user asks.

## AUDIT OUTCOME (2026-06-15) — planned approach INVALIDATED

The planned fix (drop the allow-list) **breaks all passkey login** and was reverted.
Evidence:
- Browser E2E with the empty-list change: **5 failures**, every one a discoverable
  `navigator.credentials.get()` → `NotAllowedError` (R-C login, account passkey,
  H11/H11b, R-G6+H13 erase). Wallet + registration tests passed.
- After `git checkout` revert: **13/13 green** → causation attributed to the change.

Root cause (corrected): the credentials are **non-discoverable**. Live `register/start`
returns `residentKey:"discouraged", requireResidentKey:false`; `webauthn-rs`
`start_passkey_registration` hardcodes `.require_resident_key(false)`
(`webauthn-rs-0.6.0-dev/src/lib.rs:566`). With non-resident credentials, the
authenticator cannot find a credential on its own, so the server MUST enumerate all
credential ids — the all-credentials `allow_credentials` list is **load-bearing for
login**, not cosmetic. H2/H3 assumption ("creds are discoverable resident keys") was
FALSE.

Real fix = make credentials discoverable (request resident keys at registration), then
auth can use an empty allow-list. Carries a migration question: existing non-resident
passkeys may need re-registration.

### Decision: probe a real authenticator first (chosen)

Before committing to a migration, test whether EXISTING passkeys are already
discoverable on real platform authenticators (iOS/macOS/Android often store
discoverable even when the RP says "discouraged"; Windows Hello historically did not).
Client-only probe (no server change, no prod writes): on the passkey-login origin,
`navigator.credentials.get({ publicKey: { challenge, rpId: location.hostname,
allowCredentials: [], userVerification: 'required' } })` — if the authenticator
surfaces and returns a credential, existing creds ARE discoverable (Option A is
transparent, no migration); if it throws NotAllowedError/"no passkeys", they are not
(migration needed). Test each device type the userbase actually uses.

## OPTION A IMPLEMENTED + VALIDATED (2026-06-15)

Pivoted to making credentials **discoverable** so an empty `allow_credentials` is
correct. Changes (diff: 5 files, +68/-31):
- `src/webauthn.rs`: new `require_resident_key(&mut ccr)` post-processes the
  registration challenge to `residentKey=required` + `requireResidentKey=true`; called
  in BOTH `register_start` and `link_start`. `authenticate_start` no longer enumerates
  credentials (empty discoverable allow-list).
- `js/ui/src/App.svelte`, `src/account.rs`, `src/device_auth.rs`: removed the
  `allowCredentials.length===0` "No passkeys registered" guard (it bailed before
  `get()` once the list is empty). **The guard was triplicated** — App.svelte + two
  Rust-embedded HTML pages.
- `e2e/browser/device-lifecycle.spec.mjs`: R-C4 leak guard. New
  `e2e/browser/probe-discoverability.spec.mjs`: asserts registration yields a resident
  credential, `authenticate/start` returns 0 creds, and an empty-allow `get()` resolves.

### Local probe evidence (CDP virtual authenticator)
| | isResidentCredential | server allowCredentials len | empty-allow get() |
|---|---|---|---|
| BEFORE (current) | `false` | `5` (leak) | `NotAllowedError` |
| AFTER (Option A) | `true` | `0` | `OK` |

### Validation
- `cargo build` clean; `cargo test --bin siwx-oidc` → **93 passed / 0 failed**.
- Frontend `npm run build` → compiled, 0 errors.
- Browser E2E → **15/15 passed** (incl. the two account-page passkey tests that
  regressed mid-execution until the triplicated guard was found, R-C login, R-C4 leak
  guard, account/device re-auth, erase, challenge-binding).

### Hypothesis trace (final)
| H | Status | Evidence |
|---|--------|----------|
| H1 — empty `allowCredentials` from start | Confirmed | R-C4 + probe (`serverAllowLen=0`) |
| H2 — login still works | Confirmed (via Option A) | R-C1/2/3 + probe (`get OK`); FALSE under naive delete-only |
| H3 — account/device re-auth works | Confirmed | account.spec:124, R-G6/H13 green after guard triplication fix |
| H4 — frontend compiles, guard gone | Confirmed | webpack 0 errors |
| H5 — single source of the bug | **VIOLATED** | guard was in 3 files; allow-list assumption (discoverable) also false |

### Acceptance criteria (final)
AC1 no enumeration — MET (probe `serverAllowLen=0`, R-C4). AC2 login works — MET
(R-C, probe). AC3 account/device re-auth — MET. AC4 frontend builds — MET. AC5 cargo
build+test — MET (93/0).

### Discovered during execution (NOT in original register)
1. **Credentials were non-discoverable** (`residentKey:discouraged`,
   `webauthn-rs start_passkey_registration` → `require_resident_key(false)`). The
   all-credentials allow-list was load-bearing; the original plan's delete-only fix
   broke every passkey auth (5 E2E failures, reverted). Real fix = request resident keys.
2. **The login guard was triplicated** (App.svelte + account.rs + device_auth.rs), not
   single-source as H5 assumed. Found via a mid-execution regression (2 account tests),
   then an exhaustive grep.

### Residual unknown (cannot be settled locally)
The CDP virtual authenticator honours `residentKey` strictly, so it proves the fix and
the worst-case (a strict authenticator's existing creds are non-resident → need
re-registration). It CANNOT tell us whether existing **real** iOS/macOS/Android
passkeys are already discoverable (those platforms often store discoverable despite
"discouraged"). Migration blast radius for existing users still needs a real-device
check before/at deploy. New registrations are discoverable regardless.

## Execution note

Executed **inline/sequentially** (not via parallel subagents): the change is 3 small
edits + one observe-the-output validation loop. Memory is GREEN but the work is small
and serial (edit→build→restart→test), where inline is lower-risk than delegation.
