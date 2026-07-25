# Passkey scoping + new-user gate — follow-up test plan & handoff

**Purpose:** manually verify the SHIPPED outcome on prod, and give a cold follow-up
session the entry points for what is done vs still open.
**Written:** 2026-06-18 (end of the build+deploy session).

---

## 0. What shipped (deployed, live, verified)

- **Branch/commit:** `feat/passkey-scoping-new-user-gate` -> squash-merged to `main` as
  `db79e75` (PR #13). Prior related deploy: `e64e606` (PR #12: discoverable fix +
  stale-passkey signalUnknownCredential).
- **Prod image:** `ghcr.io/inblockio/siwx-oidc:main` = `sha256:c4d865236e99…` (healthy).
- **Login UI is live:** `siwx-oidc.inblock.io/build/bundle.js` confirmed to contain the
  new strings ("Create a new account", "Signing in as", "Use a different passkey",
  "detected_mxid", "recovery key"). The Dockerfile rebuilds the webpack bundle in CI.
- **Rollback (seconds, offline):** on `ssh -p 8022 deploy@agentic.inblock.io`,
  `cd /home/deploy/matrix/stack && SIWX_OIDC_TAG=rollback-pre-passkey-scoping-20260618 docker compose up -d --pull never siwx-oidc`
  (that tag = the prior image `sha256:78d76ba0…`). Roll forward: unset the tag (defaults
  to `:main`) and `docker compose up -d siwx-oidc`.

**Architecture reminder:** the login page is served by **siwx-oidc**
(`siwx-oidc.inblock.io`). element.inblock.io (Element Web) redirects there for auth; it
was NOT changed and does not need to be.

**Source of truth for "correct outcome":**
- `docs/design/2026-06-18-passkey-scoping-and-new-user-gate.md` (case matrix + creation policy + ACs)
- `docs/superpowers/plans/2026-06-18-passkey-scoping-new-user-gate.md` (hypothesis register H1-H11 + ACs)

---

## 1. Manual test plan (run on element.inblock.io / siwx-oidc.inblock.io)

Use a **fresh incognito window** per scenario (browser caches `bundle.js`; the OS/Windows
Hello passkey store is shared across profiles, which is the whole reason for scoping).

### T1 — Returning-user scoping (AC1)  [the headline fix]
1. Incognito. Log into element.inblock.io with passkey **A** (account A). Complete login.
2. Log out / new incognito-but-same-profile is NOT enough (cookie is per profile); instead
   in the SAME window, start a second login.
3. **Expect:** the page shows "Signing in as @<A>:matrix.inblock.io" and the OS picker
   offers ONLY A's passkey(s), plus a "Use a different passkey" link.
   - NOTE: scoping appears on the **2nd** login. The `siwx_user` cookie is minted on the
     1st successful sign-in. First-ever login in a clean profile is usernameless (all keys).

### T2 — Escape hatch (AC1/H11)
1. From the scoped state in T1, click **"Use a different passkey"**.
2. **Expect:** the picker reverts to showing ALL resident passkeys (usernameless).

### T3 — New-user gate at login (AC2)  [creation allowed ONLY here, behind a gate]
1. Fresh incognito. Begin passkey login and pick a passkey whose identity has **no
   existing account** (e.g. a throwaway test passkey).
2. **Expect:** a gate: "This passkey will create a NEW account (@…). Continue, or try
   another passkey? You can restore your messages with your recovery key."
3. Click **Try another** -> back to picker, **no account created**.
4. Click **Continue** -> proceeds, account is created. (This is the only path that creates.)

### T4 — Account flow REJECTS new identity (AC2b)  [creation impossible here]
1. Open the account page `siwx-oidc.inblock.io/account?action=org.matrix.profile` (or via
   Element "manage account"). Re-auth with a passkey/wallet for a **non-existent** identity.
2. **Expect:** a 400 error "…not linked to an existing account. Create an account at
   sign-in first." NOTHING created.

### T5 — QR/device approval REJECTS new identity (AC2b)
1. Start a QR/device login (Element X "link new device" / device code), open the `/device`
   approval page, approve with a passkey/wallet for a **non-existent** identity.
2. **Expect:** rejected with the same message; device NOT approved, nothing created.

### T6 — Secure Backup false-positive GONE (AC6)
1. Do a QR/device approval for an **existing** account that already has E2EE set up.
2. **Expect:** the "Device approved" page shows NO "Your account has no Secure Backup set
   up" warning. (That warning is removed entirely.)

### T7 — Enumeration-safety (AC3)  [already verified live via curl, re-confirm if desired]
- A forged/garbage `siwx_user` cookie -> login is usernameless (all keys), no detected
  account. (Verified at deploy: forged cookie -> empty allowCredentials + null detected_mxid.)

### T8 — Wallet-then-link-passkey in scope (AC4)
1. Log in with a **wallet**, link a passkey to it. Log out.
2. 2nd login in the same profile -> the linked passkey is offered under the wallet identity.

### T9 — No regression (AC7)
- Plain passkey login, wallet login, stale-key prune (a revoked key disappears from the
  picker after a failed attempt), account device-list/sign-out all still work.

---

## 2. Open items / things still to fix (entry points)

### Must manually confirm (not provable locally)
- **A) The login-page UI itself** (gate dialog, detected-account chip, grey-out, escape
  link). It was built by CI and bundle-grep-verified, but NOT pixel-tested. Run T1-T3, T6.
  Entry: `js/ui/src/App.svelte` (handlePasskeySignIn, confirmNewUser, gateTryAnother,
  the `{#if newUserGate}` markup).
- **B) Edge cache:** if the new UI does NOT appear even in incognito, suspect a Caddy/CDN
  cache in front of `siwx-oidc.inblock.io`. Entry: portal Caddy `/home/portal/portal/Caddyfile`
  (cache headers on `/build/*`).

### Known design limitations (by choice; revisit only if needed)
- **C) Login new-user gate is FRONTEND-enforced.** A non-browser client could POST
  `/sign_in` directly and create an account without the dialog. This is acceptable (it is
  the user's own identity; the gate prevents ACCIDENTAL creation in the browser picker).
  The account/QR reject is SERVER-enforced. Entry: `src/axum_lib.rs` webauthn_authenticate_finish
  (reports new_user) vs `src/oidc.rs` sign_in (provisions).
- **D) Device/QR picker stays usernameless** (not identity-scoped). Scoping there is unsafe
  (no server-side identity; typed address would re-open enumeration). So the "many keys in
  picker" still happens on the `/device` approval page. By design. Entry: design doc
  "Other flows".
- **E) Wallet-only account on 2nd login:** if the cookie's DID has no passkeys,
  `authenticate_start` falls back to usernameless (so the picker is not broken-empty). The
  grey-out should steer to wallet. Verify the grey-out actually shows. Entry:
  `webauthn::methods_for_did`, App.svelte grey-out.

### Carried over from the PRIOR deploy's code review (NOT addressed this session)
These were found reviewing `e64e606` and still apply on `db79e75`:
- **F) `require_resident_key` is not enforced server-side.** Registration sets the
  resident-key hint on the client options only; webauthn-rs `finish_passkey_registration`
  does not enforce discoverability, so a non-cooperating authenticator could store a
  non-resident credential that never surfaces in the discoverable picker. Mitigated in
  practice (platform authenticators honor `required`). Entry: `src/webauthn.rs`
  `require_resident_key` + register_finish; webauthn-rs 0.6.0-dev limitation.
- **G) The login->token PKCE e2e helper is cosmetic** (sends code_challenge to /authorize
  but not /sign_in, so the verifier is never validated -> a PKCE regression at /token would
  not be caught). Entry: `e2e/browser/device-lifecycle.spec.mjs` loginToToken.
- **H) Corrupt/revoked-but-present credential** bypasses the stale-passkey discriminator
  (returns 500/400, no prune). Entry: `src/webauthn.rs` verify_credential (the from_str
  paths). Low likelihood.
- **I) Login Other-failure returns 500** (raw Debug body) while account/QR return 400 -
  pre-existing per-flow inconsistency. Entry: `src/oidc.rs` From<VerifyError>, App.svelte
  finish error path.
(Full list: this session's `/code-review ultra`-style output is not in a repo file; the
13 findings live only in the chat transcript. If needed, re-run a review on `main`.)

### Housekeeping
- **J) Throwaway OAuth clients** were registered on prod during live smoke tests (dynamic
  client registration is open). Harmless; prune if you want. Entry: Redis client entries on
  the prod stack.
- **K) `signalAllAcceptedCredentials` + identifier-first allowCredentials** remain HELD IN
  RESERVE (not implemented) for hard prevention. Only revisit if scoping-by-cookie proves
  insufficient.

---

## 3. Context entry points (files / infra / commands)

**Code (all on `main` @ db79e75):**
- `src/webauthn.rs` — authenticate_start scoping (`scope_did`), `get_passkeys_for_did`,
  `is_new_identity`, `reject_if_new_identity`, `methods_for_did`, register/link by_did index.
- `src/axum_lib.rs` — `webauthn_authenticate_start` (cookie read + scope + escape `all`),
  `webauthn_authenticate_finish` (new_user/mxid), `sign_in` handler (mints `siwx_user`),
  `user_cookie_set`, account re-inject.
- `src/db/redis.rs` — `create_user_session`/`lookup_user_session`, `webauthn:by_did` index,
  `get_passkeys_for_did`.
- `src/account.rs`, `src/device_auth.rs` — `reject_if_new_identity` call sites; device
  Secure-Backup check REMOVED.
- `src/synapse_client.rs` — `is_localpart_available` (the new/existing detector);
  `has_cross_signing_keys` REMOVED.
- `js/ui/src/App.svelte` — login UI (gate, detected account, grey-out, escape).

**Tests:** `e2e/browser/passkey-scoping.spec.mjs` (+ `stale-credential.spec.mjs`,
`device-lifecycle.spec.mjs`); `cargo test --bin siwx-oidc`. Harness: `bash e2e/up.sh`
then `bash e2e/browser/run.sh`. `e2e/synapse_mock.py` now models existing-vs-new accounts.

**Docs:** design + plan (section 0); CLAUDE.md sections "Passkey-picker scoping
(`siwx_user` cookie)" and "New-account creation policy (login-only gate)".

**Infra:** prod `ssh -p 8022 deploy@agentic.inblock.io`, stack `/home/deploy/matrix/stack`.
siwx-oidc public = `https://siwx-oidc.inblock.io`. Synapse server_name = `matrix.inblock.io`.

**Redis keys (new):** `user:session/{token}` (TTL 30d, opaque->DID),
`webauthn:by_did/{did}` (SET of cred_id_b64).
</content>
