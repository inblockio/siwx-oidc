# Passkey offer-scoping — account + device pickers (CORRECTED plan)

**Base:** `a074795` (origin/main; the revert that dropped server-side method
prediction + grey-out but KEPT identity-scoped `allowCredentials`).
**Branch:** `feat/passkey-offer-scoping` (worktree `~/siwx-oidc-passkey-scope`).
**Written:** 2026-06-19.

## Why this corrects the handover

The handover plan (`~/.claude/plans/use-logic-model-to-derrive-wobbly-noodle.md`)
proposed a **Matrix Bearer token** on the picker-start request as the identity
carrier, and treated the `webauthn:by_did` index + `credentials_for_did` reader +
`authenticate_start(allow_credentials)` as greenfield. Grounding against a074795
(three read-only subagents, file:line-cited) found:

1. **Steps 1 + 2 already shipped** (db79e75, survived the revert): `webauthn:by_did`
   SET + `index_add_passkey`/`index_remove_passkey`, `get_passkeys_for_did()` with a
   self-healing scan/back-fill (== the plan's "credentials_for_did + lazy backfill"),
   purge maintenance, and `authenticate_start(scope_did: Option<&str>)` already
   populates `allowCredentials`. **Reuse, do not rebuild.**
2. **The Bearer carrier is infeasible and forbidden.** `/account` and `/device` are
   standalone siwx-oidc pages opened *from within* Element (X + Web); they hold **no
   Matrix access token** (the start fetches send only `{action}` / `{user_code}`).
   Per the owner: **no client changes** (Element X is uncontrollable) — so nothing can
   attach a Bearer header. Bearer-only would be a permanent no-op.
3. **The only self-contained carrier is the `siwx_user` cookie.** Already minted at
   login + account re-auth, `Path=/`, `HttpOnly`, `SameSite=Strict`, 30-day, opaque →
   DID via `lookup_user_session`. `Path=/` + the same-origin `…/passkey/start` fetch
   means the browser sends it automatically — zero client cooperation. Adversarial
   hunt found no alternative (`DeviceCodeEntry.did` is `None` pre-approval;
   `id_token_hint` is dead `#[allow(dead_code)]`; `acct_session` is `Path=/account`).
4. This is exactly what the in-code "Task 6" TODOs anticipated
   (axum_lib.rs:419, 941: "the cookie/known-identity DID").

**Scope (final):** wire the `siwx_user` cookie into the two start handlers (mirror
login), with the `{"all":true}` escape hatch + `detected_mxid`, degrade-open; add the
matching escape/affordance to the two served frontends; tests. Login is untouched.

## Hypothesis register

| ID | If | Then | Verification |
|----|----|------|--------------|
| H1 | `device_passkey_start_handler` reads `siwx_user` → `lookup_user_session` → DID and passes it as `scope_did` | the device-approval picker offers only the approver's own passkeys when a valid cookie is present | unit: seeded user-session + by_did → `allowCredentials` == that DID's creds; browser e2e two-cred case |
| H2 | `account_passkey_start_handler` does the same | the account re-auth picker offers only the owner's passkeys | unit + browser e2e |
| H3 | either handler gets no cookie / forged / expired / `{"all":true}` / `?all` | it degrades open to usernameless (empty `allowCredentials`), never errors (no 500) | unit: absent/forged/all → empty; reuse forged-cookie invariant |
| H4 | the cookie DID resolves to zero creds (wallet-only) | `authenticate_start` leaves `allowCredentials` empty (discoverable), not a broken empty picker | existing authenticate_start behavior + unit |
| H5 | the served account/device frontends gain a "use a different passkey" affordance re-requesting `{"all":true}` | a wrongly-scoped same-browser multi-account user can still reach other keys | browser e2e escape case + DOM presence |
| H6 | the picker is scoped but `verify_credential` + `reject_if_new_identity` still run under the PROVEN DID | security is unchanged (offer ≠ authorization) | no change to verify/finish handlers; existing finish tests stay green |
| H7 | the server populates `allowCredentials` | the existing base64→buffer mapping in account.rs/device_auth.rs consumes it unchanged | grounded (account.rs:1534, device_auth.rs:623); browser e2e |

## Acceptance criteria

- AC1: `/account/passkey/start` with a valid `siwx_user` cookie → `allowCredentials`
  == the cookie-DID's creds + `detected_mxid` set; no/forged cookie → empty + no mxid. (H2,H3)
- AC2: `/device/passkey/start` same. (H1,H3)
- AC3: two-credential browser case — scoped to A, B's key not offered; escape → all. (H1,H2,H5,H7)
- AC4: login behavior unchanged. (H6)
- AC5: `cargo build --workspace` + `cargo test --bin siwx-oidc` green, no new warnings. (all)
- AC6: degrade-open — no 500 on any cookie/token/index issue. (H3)

## Build order (compile + tests green between steps)

1. Server: `payload_force_all`, `user_session_scope_did`, `detected_mxid_for` helpers
   + wire both start handlers (reuse `AuthenticateStartResponse` for device; Value +
   `session_id` + `detected_mxid` for account). `cargo build`.
2. Unit tests: scope-with-cookie / fall-open (absent/forged/all) for both handlers.
   `cargo test --bin siwx-oidc` (Redis via e2e/up.sh).
3. Frontend (served JS only): escape affordance + `detected_mxid` display + friendly
   no-key fallback in account.rs + device_auth.rs inline JS.
4. Browser e2e: extend `passkey-scoping.spec.mjs` (account + device scoping + escape).
5. Full verify: `cargo build --workspace`, `cargo test --bin siwx-oidc`, e2e.

## Out of scope / flagged
- Bearer-token carrier: removed (infeasible + forbidden).
- `id_token_hint`: dead `#[allow(dead_code)]` — removable cleanup, done last if clean.
- Wallet grey-out: stays reverted (a074795); not re-added.
