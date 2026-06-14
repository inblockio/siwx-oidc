# Account management E2E — fix plan + hypothesis register

**Branch:** `fix/account-management-e2e`
**Date:** 2026-06-14
**Goal (one sentence):** Make account erasure and device/session deletion work
end-to-end *in the browser* against `/account`, requiring only a single wallet/passkey
re-authentication per session, and prove it with a headless browser E2E suite.

## Context (ground truth from the code, not the docs)

- `/account` (`src/account.rs`) renders a server-side page with embedded JS. Actions:
  profile, devices_list, device_view, device_delete, cross_signing_reset,
  account_deactivate, account_erase, account_reactivate.
- Re-auth is **stateless**: every action POST (`/account/wallet` or
  `/account/passkey/finish`) requires a fresh signature. Device-list `View`/`Sign out`
  are full-page `<a href="/account?action=…">` navigations, so each click re-prompts.
- Wallet verify (`aqua-auth` `Eip155Suite::verify`) is pure EIP-191 ecrecover + address
  compare — it does **not** parse SIWE fields, so the hand-rolled account-page message
  verifies fine. Wallet message format is NOT the bug.
- Device/account actions call the **Synapse admin API** (`/_synapse/admin/v1|v2/...`)
  with `bearer_auth(shared_secret)`, assuming `shared_secret == admin_token`.
- `get_device` = filtered `list_devices`; "Device not found" means the admin list
  *succeeded* but the id was absent (identity/mxid mismatch), NOT an auth failure.
- `compat.rs` wires `/oauth2/revoke`, `/_matrix/client/v3/logout`, `/logout/all`,
  `/refresh` — but NOT `DELETE /_matrix/client/v3/devices/{id}` or
  `POST /_matrix/client/v3/delete_devices` (what an in-client session manager calls).

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | The account page is stateless and device-list actions are `<a href>` navigations | Each device/account action re-prompts for a wallet/passkey signature (the "multiple authentications" defect) | none (in our control) | Browser E2E: list→delete requires exactly ONE re-auth after the fix |
| H2 | We issue a short-lived signed account-session cookie on first re-auth and add `POST /account/action` | Subsequent actions in the window execute without a new signature | cookie is HttpOnly+SameSite=Strict+CSRF-bound; TTL short | Rust E2E + browser E2E: second action sends no signature, succeeds |
| H3 | A device shown by `devices_list` is signed out via `/account?action=device_delete` after one re-auth | The Synapse device is deleted and its OAuth tokens revoked (introspection inactive) | admin API reachable; mxid matches the re-auth DID | Mock asserts DELETE called; token gone from Redis; browser shows "Session signed out" |
| H4 | A user erases via `/account?action=account_erase` after one re-auth | Synapse `deactivate(erase=true)` runs, all tokens revoked, WebAuthn identity purged; page shows "Account erased" | admin API reachable | Mock asserts deactivate erase:true; browser shows terminal "erased" |
| H5 | An in-client session manager calls `DELETE /_matrix/client/v3/devices/{id}` (or `/delete_devices`) | siwx-oidc deletes the device via admin API + revokes tokens and returns 200 (no longer a dead end) | the deployment proxies these CS-API paths to siwx-oidc (documented) | Rust E2E hits the endpoint with a bearer token; mock sees the DELETE; 200 returned |
| H6 | The Synapse admin token is rejected (shared_secret != admin_token) | The action fails with a *legible* error that names admin-auth, never a misleading "Device not found" or a 500 | none (in our control) | Unit/integration: a 401 from the mock admin API yields a distinct error string |
| H7 | A mock Synapse admin/CS API faithfully mirroring `synapse_client.rs` is driven by the real siwx-oidc binary | The full browser flow (wallet + passkey) completes against it | mock parity with the real contract | E2E green end-to-end with both auth methods |

## Acceptance criteria

- AC1 (H1,H2): Browser E2E — wallet path: sign in once, then list + delete a device +
  view profile with **no second signature prompt**.
- AC2 (H1,H2): Browser E2E — passkey path (virtual authenticator): same, single ceremony.
- AC3 (H3): Device delete removes the device server-side and revokes its tokens.
- AC4 (H4): Erase runs deactivate(erase=true) + token revoke + identity purge, terminal UI.
- AC5 (H5): Legacy CS-API device delete + bulk delete wired and effective.
- AC6 (H6): Admin-auth failure is legible, never a silent "not found"/500.
- AC7: No regression — existing `cargo test --bin siwx-oidc` and aqua-auth tests stay green.

## Boundary conditions / invariants

- Never recycle a device_id (sign-in still upserts a fresh `SIWX_{uuid}`); we only ever
  *delete* ending devices. (CLAUDE.md device-lifecycle invariant.)
- The account session must be cryptographically bound to a verified DID, short TTL,
  HttpOnly, SameSite=Strict, CSRF-protected; it must never grant cross-user access.
- Do not weaken existing stateless behaviour when no cookie is present (back-compat).
- Out of scope: standing up a real Synapse; we mock its admin + CS API faithfully so a
  real-Synapse run is a config change.

## Execution phases

1. Local stack: Redis (podman), Python Synapse mock, native siwx-oidc; baseline probe.
2. Fix C (H1,H2): account session + `/account/action` + session-aware page/JS.
3. Fix A/B (H3,H4,H5,H6): legacy CS-API wiring, legible errors, robust delete/erase.
4. E2E: Rust HTTP-level backbone + Playwright browser (wallet + virtual authenticator).
5. Audit (hypothesis trace + AC check) + short report.
