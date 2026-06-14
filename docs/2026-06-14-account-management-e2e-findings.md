# Account management — audit findings & fixes (2026-06-14)

**Branch:** `fix/account-management-e2e`
**Scope:** account erasure + device/session deletion working end-to-end *in the
browser*, with a single re-authentication. Built a headless browser test suite
(Ethereum wallet + passkey) + a local stack to prove it.

## TL;DR

The account-erase and device-delete *server logic* was essentially correct, but
the **browser experience was broken in two concrete ways** that match exactly
what you hit:

1. **Multiple authentications.** `/account` was *stateless*: every action POST
   required a fresh wallet/passkey signature, and the device list's *View* /
   *Sign out* were full-page `<a href>` navigations — so each click re-prompted.
   List → sign-out = two signatures; manage three devices = four signatures.
2. **In-client "session manager" sign-out was never wired.** Element's Settings →
   Sessions calls the legacy CS API (`DELETE /_matrix/client/v3/devices/{id}` /
   `POST /delete_devices`). siwx-oidc implemented `logout`/`revoke`/`refresh` but
   **not** those, so that path dead-ended — which is why devices only ever got
   removed by going onto the server directly, never "through the proposed paths".

Your skepticism about "already proven working in the browser" was justified: the
two erasures cited as proof were server-side admin calls, and there was **no
end-to-end browser test** of the `/account` path. There is now (wallet + passkey,
headless).

The wallet message format was **not** the problem: `did:pkh:eip155` verification
(`aqua-auth`) is pure EIP-191 ecrecover + address compare, so the hand-rolled
account-page message verifies fine.

## What "device ID not found" was

`/account` device-delete returns "Device not found" only when the Synapse admin
device **list succeeded but the id wasn't in it** — i.e. an identity/mxid
mismatch (e.g. the device belongs to a passkey `did:key` mxid but you re-auth'd
with the wallet `did:pkh`, or vice-versa), or a stale entry. An admin-token
*rejection* took a different, vaguer path. Both are now legible (see Fix 4), and
the in-client path that most likely produced your error is now wired (Fix 2).

## Fixes (all on the branch)

| # | Fix | Files |
|---|-----|-------|
| 1 | **Single re-auth account session.** First wallet/passkey re-auth mints a short-lived (10 min) signed, HttpOnly, SameSite=Strict, CSRF-bound cookie. Subsequent actions run via new `POST /account/action` with no fresh signature. Page JS is session-aware: device View/Sign-out are in-page session calls; read actions auto-run; destructive actions are one click (still gated by the confirm checkbox). Terminal actions (erase/deactivate) clear the cookie. | `src/account.rs`, `src/axum_lib.rs` |
| 2 | **Legacy CS-API device delete wired.** `DELETE /_matrix/client/v3/devices/{id}` and `POST /_matrix/client/v3/delete_devices` resolve the user from the bearer, delete the Synapse device (admin API) and revoke its tokens. | `src/compat.rs`, `src/axum_lib.rs` |
| 3 | **Robust device delete / erase** validated end-to-end against a faithful Synapse mock. | tests |
| 4 | **Legible admin-auth failures.** A rejected admin token now yields a 400 that names the admin-token problem — never a misleading "device not found" or a 500. | `src/synapse_client.rs`, `src/account.rs` |

Security of Fix 1: the session is bound to one verified DID, 10-min TTL,
HttpOnly + SameSite=Strict + a CSRF token echoed on every action POST; it never
grants cross-user access and fails closed (missing/expired/bad-CSRF → 401).

## Hypothesis trace (evidence)

| ID | Claim | Status | Evidence |
|----|-------|--------|----------|
| H1 | Stateless page ⇒ a signature per action | **Confirmed → fixed** | code; browser test asserts exactly 1 `personal_sign` / 1 `credentials.get` for list+delete |
| H2 | Account session ⇒ later actions need no signature | **Confirmed** | `e2e_account_management` (list→delete→profile, one sig); unit tests for create/lookup/CSRF; `/account/action` 401 w/o session |
| H3 | Device delete removes Synapse device + revokes tokens | **Confirmed** | mock asserts DELETE; Rust+browser assert device gone; compat unit tests revoke tokens |
| H4 | Erase ⇒ `deactivate(erase=true)` + purge + session cleared | **Confirmed** | mock lifecycle `erased:true`; cookie cleared; browser "Account erased" |
| H5 | Legacy CS-API delete wired & effective | **Confirmed** | `legacy-cs-api-probe.sh` (200 + device gone); compat unit tests |
| H6 | Admin-token rejection is legible, never "not found"/500 | **Confirmed** | `admin_token_rejection_is_legible…` (400, no "not found", names admin token) |
| H7 | Real binary drives both auth methods E2E against a faithful mock | **Confirmed** | full `run-all.sh` green: 91 unit + 5 HTTP + legacy + 3 browser |

## Acceptance criteria

| # | Criterion | Met | Evidence |
|---|-----------|-----|----------|
| AC1 | Wallet: one sign-in, then list+delete+profile, no 2nd prompt | ✅ | browser `wallet: one signature…`; Rust `wallet_single_reauth…` |
| AC2 | Passkey: same, single ceremony | ✅ | browser `passkey: one ceremony…` (virtual authenticator) |
| AC3 | Device delete removes device + revokes tokens | ✅ | H3 |
| AC4 | Erase runs erase=true + purge + terminal UI | ✅ | browser `wallet: erase…`; Rust `wallet_erase…` |
| AC5 | Legacy CS-API delete wired | ✅ | H5 |
| AC6 | Admin-auth failure legible, never "not found"/500 | ✅ | H6 |
| AC7 | No regression | ✅ | `cargo test --bin siwx-oidc` 91 passed |

## How to reproduce

```bash
bash e2e/run-all.sh   # stack up + unit + HTTP E2E + legacy probe + browser E2E
```

See `e2e/README.md`. The whole stack (Redis + Synapse mock + siwx-oidc + the
headless browser) runs in podman.

## Caveats / deploy notes

- The browser proof runs against a **faithful mock** of Synapse's admin/MAS API,
  not a live Synapse. The fixes are server-side in siwx-oidc; a real-Synapse run
  is a config change (`SIWEOIDC_SYNAPSE_ENDPOINT` + admin token).
- **The legacy CS-API delete (Fix 2) only helps if the reverse proxy routes those
  paths to siwx-oidc.** In the MAS model the proxy sends auth/account paths to the
  auth service and everything else to Synapse; route `DELETE /_matrix/client/v3/
  devices/{id}` and `POST /_matrix/client/v3/delete_devices` to siwx-oidc (Caddy
  can match by method so `GET /devices` still lists via Synapse). The MSC4191
  `/account` deep-link path (Fix 1) works regardless and is the primary path.
- **Load-bearing assumption to verify on the box:** siwx-oidc's admin calls use
  the MAS shared secret as Synapse's `admin_token`. If they are not equal, every
  admin-backed action fails — now *legibly* (Fix 4), but still fails. Confirm
  `matrix_server.sh` sets them equal, or set a dedicated admin token.
- The login page (`/`, Svelte) still needs a node build; the `/account` page is
  fully server-rendered, so the browser suite needs no node build of the app.
