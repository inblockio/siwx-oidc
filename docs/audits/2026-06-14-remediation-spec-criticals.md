# siwx-oidc — Ready-to-Apply Remediation Spec: CRITICAL findings C1 & C2

**Date:** 2026-06-14
**Branch:** `audit/siwx-oidc-security-review` (isolated worktree)
**Status:** DOCUMENTATION ONLY — no code changed by this document. These are
auth-protocol changes; **do not ship unattended.** This spec is written so a
human can either (a) approve a follow-up implementation, or (b) apply the
clearly-marked *safe subset* immediately.

Source findings: `2026-06-14-siwx-oidc-security-review.md` (C1, C2, H-b, H-c,
S4-1) and the raw dimension reports `raw-findings/sec-S1-auth.md`,
`raw-findings/sec-S2-tokens.md`, `raw-findings/sec-S4-input.md`.

All line anchors below were re-read against the source in THIS worktree on
2026-06-14 and are exact at the time of writing.

---

## 0. Orientation — three things that drive every "frontend" decision below

The repo has **three distinct frontends**, served two different ways. This
matters because "change the frontend" means different work for each.

| Flow | UI source | How it ships | Rebuild step |
|---|---|---|---|
| **Login** (`GET /`) | `js/ui/src/App.svelte` (Svelte) | Built by Docker `node_builder` stage (`Dockerfile:18-23`, `npm run build`) into `static/build/` (publicPath `/build/`, `js/ui/webpack.config.js:35-38`). **`static/build/` is NOT in the git tree** (built at image time; only `static/index.html` + assets are committed). | `cd js/ui && npm run build` (or just rebuild the Docker image). |
| **Device approval** (`GET/POST /device`) | HTML+JS **string literals embedded in Rust** (`src/device_auth.rs`, message built at `device_auth.rs:557-586`) | Compiled into the binary | `cargo build` (the page IS the Rust source) |
| **Account mgmt** (`GET /account`, `POST /account/wallet`) | HTML+JS **string literals embedded in Rust** (`src/account.rs`, message built at `account.rs:1376-1409`) | Compiled into the binary | `cargo build` |

Consequence: **device/account "frontend" edits are Rust edits** (recompiled with
the server, no separate JS toolchain). Only **login** edits touch the Svelte
build.

**Verified frontend message contents (load-bearing for the safe-subset call):**

- Login (`App.svelte:112-126`): `createSiweMessage({ ... nonce, expirationTime, resources:[redirect], domain, uri ... })` — **already sets a server-issued `nonce`, an `Expiration Time` (48h, line 112-114), and `Resources: [redirect]`.**
- Device approval (`device_auth.rs:566-570`): nonce is `Math.random().toString(36)`; message has `Nonce:` + `Issued At:` only. **No `Expiration Time`. No `Resources`. No server nonce.**
- Account (`account.rs:1385-1389`): identical shape — `Math.random()` nonce, `Nonce:` + `Issued At:` only. **No `Expiration Time`. No `Resources`. No server nonce.**

Server side, `extract_nonce` (`oidc.rs:1146-1151`) and `extract_resources`
(`oidc.rs:1153+`) exist; **there is NO `extract_expiration_time` / no timestamp
parsing anywhere**, so even the login path that *carries* an Expiration Time
never enforces it.

---

# C1 — Replayable CAIP-122 signatures on device-approval & account-management

(Consolidated C1 = raw S1-1 + corroborating S2-2, S3-2; pulls in H-b "Expiration
not enforced" and H-c "resource binding only on login path".)

## C1.1 — Vulnerability restatement + concrete attack (with anchors)

Four CAIP-122 callers authorize on a **bare** `did_method.verify(did, message,
signature)` with no envelope checks:

| Caller | Anchor | What it checks | What it is MISSING |
|---|---|---|---|
| `sign_in` Path B (login, cookie) | `src/oidc.rs:1382-1452` | server nonce (`oidc.rs:1437-1441`) + resource/redirect (`oidc.rs:1443-1449`) | Expiration Time (H-b) |
| `sign_in` Path A (WebAuthn login) | `src/oidc.rs:1356-1381` | DID method allow-list | **redirect/resource binding (H-c)** |
| `device_approve` (wallet) | `src/device_auth.rs:835-917`, verify at `:894-901` | method allow-list only | **server nonce, expiry, resource/operation binding** |
| `device_approve_passkey` | `src/device_auth.rs:921-950` | passkey ceremony challenge | **binding of the ceremony to the initiating browser session** (see S1-5) |
| `account_wallet` | `src/account.rs:547-602`, verify at `:574-581` | method allow-list only | **server nonce, expiry, resource/operation binding** |
| `account_passkey_finish` | `src/account.rs:607-645` | passkey ceremony challenge | session-id is client-echoed (`account.rs:1422,1439`) |

Root cause (S1-4): `aqua-auth`'s `DIDMethod::verify()` is a pure byte-level
signature check — "did the holder of this key sign these exact bytes?" — it
parses **no** nonce/domain/URI/timestamp. Envelope security is the caller's job;
only `sign_in` Path B does any of it.

The `DeviceCodeEntry` struct has **no nonce field** (`src/db/mod.rs:92-101`), and
there is **no account-challenge store at all** — so there is nothing server-side
to compare a message nonce against. The nonce shown to the wallet is invented
client-side (`device_auth.rs:566`, `account.rs:1385`) and never leaves the
browser.

**Concrete attack A — device-login session hijack (CRITICAL).**
1. Victim starts a QR/device login (Element X) → a low-entropy `user_code`
   (~25.9 bits, `device_auth.rs:26-44`) is displayed.
2. Attacker learns/guesses the pending `user_code` (no rate limit, S4-8).
3. Attacker POSTs `/device` `{user_code:<victim's>, action:"approve",
   did:<attacker DID>, message:<anything attacker signed>, signature}`.
   `device_approve` (`device_auth.rs:894-907`) verifies it as a valid
   self-signature and sets `entry.status=Approved`, `entry.did=<attacker DID>`.
   The victim's polling device receives tokens **for the attacker's identity**
   (or, symmetrically, a victim's signature over *any* EIP-191 message approves
   the attacker's device under the *victim's* DID).

**Concrete attack B — account takeover / irreversible erasure (CRITICAL).**
`account_wallet` (`account.rs:547`) is the re-auth gate for `device_delete`,
`account_deactivate`, and `account_erase` (dispatched via `execute_action`,
`account.rs:583-591`). **Any** EIP-191 signature the victim ever produced over
**any** message (another dapp, a leaked log, a prior siwx interaction) is
accepted as proof-of-control, because no nonce/freshness/domain is required.
One replayed victim signature ⇒ attacker erases/deactivates the victim's Matrix
account or signs out their devices. (`SameSite=Strict` on `acct_session` does
**not** help: the very first `account_wallet` POST carries the signature in the
body and needs no session cookie.)

**H-b amplifier:** because no caller parses `Expiration Time`, a captured
signature is valid **forever** (only the login path's 300s session-nonce window
bounds replay there; device/account have no window at all).

## C1.2 — Fix mechanism (server), step by step

The fix is one shared validator plus per-flow nonce issuance. Do it in this
order.

**Step 1 — add a single shared envelope validator.** New function (suggested
home: `src/oidc.rs`, exported, e.g. `pub fn validate_caip122_envelope(message:
&str, expected: &Caip122Expectation) -> Result<(), CustomError>`), where
`Caip122Expectation { nonce: &str, now: DateTime<Utc>, resources:
Option<&[Url]> }`. It must:
  - parse `Nonce:` via existing `extract_nonce` (`oidc.rs:1146`) and require it
    `== expected.nonce`;
  - parse `Issued At:` and `Expiration Time:` (new parse helpers — RFC3339);
    reject if `Expiration Time` is **absent**, if `now >= expiration_time`, or if
    `now < issued_at - SKEW` (suggest `SKEW = 120s`);
  - when `resources` is `Some`, require the message `Resources:` list (existing
    `extract_resources`, `oidc.rs:1153`) contains every expected URL.
  Refactor `sign_in` Path B (`oidc.rs:1437-1449`) and `verify_siwx_cookie`
  (`oidc.rs:1230-1234`) to call this so all four callers share identical logic.

**Step 2 — issue a server nonce for the device flow.** In
`device_authorization` (`src/device_auth.rs:57-114`) generate a single-use nonce
and store it in `DeviceCodeEntry`. This requires a new field on
`DeviceCodeEntry` (`src/db/mod.rs:92-101`, e.g. `pub approval_nonce: String`)
and serializing it (it already round-trips through `set_device_code`/
`get_device_code_by_user_code`). Expose the nonce to the approval page via the
`GET /device` render (the page already has `currentUserCode`; add
`data-nonce`). In `device_approve` (`device_auth.rs:835`), after fetching the
entry, call `validate_caip122_envelope` with `expected.nonce =
entry.approval_nonce` and `resources = Some(&[<base_url + user_code or a stable
device-approval audience>])`, then **delete/blank the nonce** (single-use) in
the same `update_device_code` write that sets `Approved`.

**Step 3 — issue a server nonce for the account flow.** There is no account
challenge today. Add an account-challenge store keyed to the account session
(or to a fresh server-issued id returned by a new `GET /account` render value),
TTL ~300s. `account_wallet` (`account.rs:547`) then requires the message nonce
to equal it (single-use) plus an `Expiration Time` plus a resource that names
the account operation (e.g. `Resources: - <base_url>/account?action=<action>`).
Bind the message to the requested `action` so a signature for `cross_signing_
reset` cannot be replayed for `account_erase`.

**Step 4 — fix the passkey ceremony fixation (S1-5/S3-7, in scope for C1).**
Derive the device passkey ceremony session-id from a server-issued high-entropy
HttpOnly cookie tied to `GET /device/verify`, **not** from the public
`user_code` (`axum_lib.rs:371,387` build `device_passkey_{user_code}`). For the
account passkey path, store `session_id` server-side against `acct_session`
rather than trusting the client to echo it (`account.rs:1422,1439`).

## C1.3 — Frontend changes required

| Flow | File | Change | Ships via |
|---|---|---|---|
| Device approval | `src/device_auth.rs` (message build `:566-570`; page render that emits `data-*`) | Read the **server nonce** from a page-injected value (e.g. `document.body.dataset.nonce`) instead of `Math.random()`; **add `Expiration Time:` line**; **add `Resources:` block** naming the device-approval audience. | `cargo build` (Rust string literal) |
| Account | `src/account.rs` (message build `:1385-1389`; page render `account_page_inner` `:883-1010` to inject the challenge nonce) | Same: server nonce instead of `Math.random()`, add `Expiration Time`, add `Resources:` naming `<base>/account?action=<action>`. | `cargo build` |
| Login | `js/ui/src/App.svelte:112-126` | **No change needed for C1** — it already carries server `nonce`, `expirationTime`, and `resources:[redirect]`. (See C1.5 safe subset.) | `npm run build` only if touched |

Note the device/account pages are NOT Svelte; **these are Rust edits and need no
JS build**, only `cargo build`.

## C1.4 — Test changes required

| File | Test / helper | Change |
|---|---|---|
| `tests/e2e_account_management.rs` | `sign_account_message` (`:84-107`) and its callers `wallet_single_reauth_covers_list_delete_profile` (`:180`), `wallet_erase_runs_erasure_and_clears_session` (`:256`), `account_action_csrf_mismatch_is_unauthorized` (`:307`), `admin_token_rejection_is_legible...` (`:339`) | Helper currently hardcodes `Nonce: testnonce0001` + a fixed `Issued At` and **no Expiration Time** (`:92-94`). Update to: (1) first fetch the server-issued account challenge nonce from the new `GET /account` render / start endpoint; (2) embed it as `Nonce:`; (3) add a fresh `Expiration Time:` in the future; (4) add the `Resources:` line. |
| `tests/e2e_session_teardown.rs`, `tests/e2e_race_teardown.rs` | device-flow + login helpers (`eip191_sign` `:76`, message `:181-198`) | These exercise the **device approval path**. Add the server nonce fetched from `device_authorization`/`GET /device`, an `Expiration Time`, and `Resources` to the device-approval message they sign. |
| `e2e/browser/account.spec.mjs` | mock-wallet `personal_sign` flow (`injectWallet` `:56-73`) | The page now builds the message from server-injected `data-nonce` + `Expiration Time`; the assertion of "exactly ONE personal_sign" still holds, but confirm the in-page message construction reads the injected nonce. |
| **NEW negative tests (add)** | — | See C1.6. |

## C1.5 — Breaking vs non-breaking + SAFE SUBSET

| Sub-change | Class | Why |
|---|---|---|
| **Enforce `Expiration Time` on the LOGIN path** (server-only) | **SAFE / NON-BREAKING — apply immediately** | **Precondition VERIFIED:** `App.svelte:112-126` already emits `expirationTime` (48h). So `sign_in` Path B / `verify_siwx_cookie` can start parsing+rejecting on missing/expired `Expiration Time` with **zero frontend change**. This closes the H-b "valid forever" gap for login. Use a generous skew (120s) to avoid clock-skew false rejects. |
| Enforce `Resources`/redirect on login Path A (WebAuthn) | Breaking-ish — needs care | Path A has no resource binding today (H-c). Folding `redirect_uri` into the session at the ceremony and checking at code issuance is server-only **but** is also handled more directly by C2's `sign_in` redirect re-validation — do it as part of C2, not C1. |
| Server nonce + expiry + resource on **device** approval | **BREAKING** | Requires the new `DeviceCodeEntry.approval_nonce`, page change, and message change. Old clients/pages that send a `Math.random()` nonce + no Expiration Time will be rejected. Must ship server+page together. |
| Server nonce + expiry + resource on **account** approval | **BREAKING** | Same — needs the new account-challenge store + page change + message change. |
| Passkey ceremony session-id hardening (S1-5) | Mostly non-breaking | Server-side keying change; the page already echoes a `session_id` for the account path, so binding it server-side is transparent. The device path moves from `user_code`-derived to cookie-derived id — needs the `GET /device/verify` to set the cookie. |

**Recommended immediate (tonight) safe subset for C1:** enforce `Expiration
Time` (+ issued-at skew) on the **login** CAIP-122 path only, because the login
frontend already sets it. Leave the device/account nonce binding for the
attended follow-up (it is breaking).

## C1.6 — Verification plan (C1)

Stacks: local mock stack = **Redis 6379 + Synapse-mock 8090 + siwx-oidc 8080**,
brought up by `e2e/up.sh` and exercised by `e2e/run-all.sh` (5 stages incl. the
Playwright browser run). The "real" prod-like stack referenced in team memory is
on **8081/8448**; run the same checks there once the mock stack is green.

1. **Regression (must still pass):** `cargo test --bin siwx-oidc`;
   `bash e2e/run-all.sh` (login + account wallet/passkey + device flow + browser).
   `cargo test --test e2e_account_management` and `--test e2e_session_teardown`
   after updating the message builders (C1.4).
2. **NEW negative — replay rejected (device):** with the mock stack, capture a
   valid device-approval `{message,signature}` for a DID, POST it to `/device`
   once (succeeds), then POST the **same** body again (or against a second
   `user_code`) → must be rejected `invalid_grant`/400 (single-use nonce
   consumed / nonce-mismatch).
3. **NEW negative — cross-context replay rejected (account):** sign a generic
   EIP-191 message (no server nonce), POST to `/account/wallet` with
   `action=org.matrix.account_erase` → must be rejected (nonce missing/mismatch),
   NOT executed.
4. **NEW negative — expired signature rejected (login, safe subset):** build a
   login message with `Expiration Time` in the past → `/sign_in` must reject.
   Add as a unit/integration test next to `perform_auth_flow`.
5. **NEW negative — operation binding (account):** sign for
   `action=cross_signing_reset`, replay the same signature against
   `account_erase` → rejected.

---

# C2 — Auth code not bound to client/redirect; open redirect at `/sign_in`; PKCE optional

(Consolidated C2 = raw S2-1 + S4-1 + S2-3.)

## C2.1 — Vulnerability restatement + concrete attack (with anchors)

Three independent gaps compose into cross-client code theft:

**(a) Code not bound to client at /token.** In `token_authorization_code`
(`src/oidc.rs:779`), the request's `client_id` is **preferred** over the code's
stored client and **never compared**:
```
// src/oidc.rs:800-804
let client_id = if let Some(c) = form.client_id.clone() { c }
                else { code_entry.client_id.clone() };
```
`code_entry.client_id` (set in `sign_in` at `oidc.rs:1471`) is only a fallback;
the subsequent secret/auth-method check (`oidc.rs:806-833`) runs against the
*request's* client_id. So a confidential client A's leaked code is redeemable by
presenting a different public client B (`token_endpoint_auth_method=none`).

**(b) redirect_uri never validated at /token.** `TokenForm` (`src/oidc.rs:417-429`)
has **no `redirect_uri` field** → RFC 6749 §4.1.3 matching is absent. `CodeEntry`
(`src/db/mod.rs:42-58`) does **not** store the authorize-time redirect_uri either.

**(c) /sign_in never re-validates redirect_uri.** `authorize` validates
redirect_uri against the client's registered set (`oidc.rs:1000-1015`), but
`sign_in` takes `redirect_uri` again as a query param (`SignInParams`,
`oidc.rs:1239-1244`) and **never calls `get_client` / never re-checks it**; it
appends the code to whatever URL was supplied (`oidc.rs:1481-1484`). **Path B**
(wallet) has a partial guard via the signed `Resources:` list
(`oidc.rs:1443-1449`), but **Path A (every WebAuthn/passkey login) has NO
redirect_uri check whatsoever** (`oidc.rs:1356-1381`).

**(d) PKCE optional + `plain` accepted.** PKCE is enforced only *if* a challenge
was stored: `if let Some(ref challenge) = code_entry.code_challenge { ... }`
(`oidc.rs:836`). A client that omits `code_challenge` gets a code with no PKCE
binding. The verifier also accepts `method == "plain"` (`oidc.rs:847-853`) even
though discovery advertises only `S256` (`oidc.rs:261`).

**Concrete attack (account takeover / open redirect).** Victim authenticates to
confidential client A; the `code` leaks (Referer, open redirect on A, proxy
log, OAuth mix-up). Attacker registers a public client B via the **open,
unauthenticated `POST /register`** (`oidc.rs:1494`, no auth — H-h) with
`token_endpoint_auth_method=none`, then POSTs
`grant_type=authorization_code&code=<leaked>&client_id=B`. Because (a) the code
is not bound to A, (b) redirect_uri is unchecked, and (d) no PKCE backstop for
B, **B receives A's user's access+refresh tokens (full Matrix session under
MSC3861).** Separately, a crafted `/sign_in?...&redirect_uri=https://attacker/cb`
on the WebAuthn path delivers the code straight to the attacker's origin.

## C2.2 — Fix mechanism (server), step by step

**Step 1 — bind code↔client at /token.** In `token_authorization_code`
(`oidc.rs:779`), after `try_consume_code` (`oidc.rs:793`), if `form.client_id`
is present require `form.client_id == code_entry.client_id` (else
`invalid_grant`); then bind the **rest of the function to
`code_entry.client_id`** (do the secret/auth-method check, `oidc.rs:806-833`,
against the *code's* client, not the request's). Remove the
"prefer-request-client_id" fallback at `oidc.rs:800-804`.

**Step 2 — persist + check redirect_uri.**
  - Add `redirect_uri: String` to `CodeEntry` (`src/db/mod.rs:42-58`).
  - In `sign_in`, set it from `params.redirect_uri` when building the entry
    (`oidc.rs:1467-1476`).
  - Add `redirect_uri: Option<String>` to `TokenForm` (`oidc.rs:417-429`).
  - In `token_authorization_code`, require `form.redirect_uri ==
    code_entry.redirect_uri` (constant-time / exact, query-stripped to match the
    `authorize` normalization at `oidc.rs:1000-1010`); reject on mismatch/absence.

**Step 3 — re-validate redirect_uri in /sign_in (closes S4-1, both paths).** In
`sign_in` (`oidc.rs:1320`), before issuing the code, call
`get_client(params.client_id)` and reject if `params.redirect_uri`
(query-stripped) is not in `metadata.redirect_uris()` — i.e. mirror the exact
check from `authorize` (`oidc.rs:1000-1015`). Apply it on **both Path A and Path
B** (place it after the DID is resolved, before `set_code` at `oidc.rs:1479`).
This is the single change that also gives Path A the redirect binding H-c asks
for.

**Step 4 — make PKCE mandatory for public clients; reject `plain`.**
  - In `token_authorization_code` (`oidc.rs:847-859`), drop the `"plain"` arm —
    return an error for any method != `"S256"`.
  - When the resolved client's `token_endpoint_auth_method` is `None` (public),
    require `code_entry.code_challenge.is_some()` (else `invalid_grant`). Do this
    at the top of the PKCE block (`oidc.rs:836`).
  - In `authorize` (`oidc.rs:1113-1117`) reject `code_challenge_method=plain` up
    front so a `plain` challenge is never stored.

## C2.3 — Frontend changes required

| Sub-change | Frontend impact |
|---|---|
| Step 1 (code↔client at /token) | **None.** The token POST already carries `client_id` (`e2e_msc3861.rs:297` confirms real clients send it). |
| Step 2 (require `redirect_uri` at /token) | **Login: none required** if the client library already sends `redirect_uri` at exchange — **VERIFY in the headless client `siwx-oidc-auth/src/lib.rs` and in each RP**. The test `perform_auth_flow` (`e2e_msc3861.rs:293-301`) currently does **NOT** send `redirect_uri` at /token, so at minimum tests + any first-party client must add it. This is the one sub-change with real RP-compat surface. |
| Step 3 (`/sign_in` redirect re-validation) | **None** — it only rejects redirect_uris that were never registered, which a correct client never sends. The login Svelte `buildSignInUrl` (`App.svelte:52`) and the device/account pages already use the registered redirect. |
| Step 4 (mandatory PKCE / no `plain`) | **None for compliant clients** (Element X uses PKCE S256; the login flow + tests use S256). Only public clients that currently skip PKCE or use `plain` break (intended). |

No Svelte rebuild is strictly required for C2 (login already sends `nonce`,
`client_id`, S256 challenge). Confirm the headless client sends `redirect_uri`
at /token before flipping Step 2 to mandatory.

## C2.4 — Test changes required

| File | Test / helper | Change |
|---|---|---|
| `tests/e2e_msc3861.rs` | `perform_auth_flow` token POST (`:293-301`) | **Add `("redirect_uri", redirect_uri)` to the `/token` form** once Step 2 is enforced. The flow already sends `client_id`, `client_secret`, and S256 `code_verifier`, so client-binding (Step 1) and PKCE (Step 4) already pass for this confidential client. |
| `tests/e2e_msc3861.rs` | `perform_auth_flow` (whole) | No change for Steps 1/3/4 (already PKCE-S256, registered redirect). |
| `tests/e2e_session_teardown.rs`, `tests/e2e_race_teardown.rs` | their token-exchange helpers | Add `redirect_uri` to `/token` if they exchange an auth code (they primarily use the device-code grant — verify; device-code grant is unaffected by redirect_uri binding). |
| **NEW negative tests (add)** | — | See C2.6. |

## C2.5 — Breaking vs non-breaking + SAFE SUBSET

| Sub-change | Class | Notes |
|---|---|---|
| **Step 1 — compare `form.client_id == code_entry.client_id`** | **SAFE / NON-BREAKING — apply immediately** | A correct client always presents the same `client_id` at `/authorize` and `/token`. **Precondition VERIFIED:** real clients send `client_id` at /token (`e2e_msc3861.rs:297`). This closes the worst half of S2-1 (cross-client redemption) server-only, no frontend change. |
| **Step 3 — `/sign_in` redirect re-validation against registered URIs** | **SAFE / NON-BREAKING — apply immediately** | Only rejects unregistered redirect_uris, which a legitimate flow never produces (it mirrors the already-active `authorize` check). Closes the open-redirect (S4-1) including the unguarded Path A. Server-only. |
| **Step 4b — reject `code_challenge_method=plain`** | **SAFE / NON-BREAKING — apply immediately** | Discovery already advertises S256-only (`oidc.rs:261`); no compliant client sends `plain`. Server-only. |
| Step 4a — **require** PKCE for public clients | Potentially breaking | Breaks any public client that currently omits `code_challenge`. Low risk for Element X (uses PKCE) but unknown for other registered public clients — flag for review. |
| Step 2 — require `redirect_uri` at /token | **BREAKING until clients comply** | RFC-correct, but any client/first-party library that does not send `redirect_uri` at exchange breaks. **Must verify `siwx-oidc-auth` + all RPs send it first.** Ship after confirming, or ship in two phases (store+log-mismatch first, then enforce). |

**Recommended immediate (tonight) safe subset for C2:** apply **Step 1**
(code↔client comparison) + **Step 3** (`/sign_in` redirect re-validation, both
paths) + **Step 4b** (reject `plain`). Together these kill cross-client
redemption and the open redirect with **no frontend change and no client-compat
risk**. Defer Step 2 (require redirect_uri at /token) and Step 4a (mandatory
PKCE for public clients) to the attended follow-up after a client-compat audit.

## C2.6 — Verification plan (C2)

Same stacks as C1 (mock 8080/8090/6379 via `e2e/run-all.sh`; real 8081/8448).

1. **Regression:** `cargo test --bin siwx-oidc`; `cargo test --test
   e2e_msc3861` (after adding `redirect_uri` to its `/token` form for Step 2, or
   leave as-is if only the safe subset is applied); `bash e2e/run-all.sh`.
2. **NEW negative — mismatched client_id rejected (Step 1):** run the normal
   flow to obtain a code for client A, then POST `/token` with the same `code`
   but `client_id=B` (a second registered client) → must be `invalid_grant`.
3. **NEW negative — mismatched redirect_uri rejected (Step 2, once enabled):**
   obtain a code for `redirect_uri=R1`, exchange with `redirect_uri=R2` →
   `invalid_grant`.
4. **NEW negative — open redirect blocked at /sign_in (Step 3):** drive
   `/sign_in?...&redirect_uri=https://attacker.example/cb` (both a wallet/Path-B
   and a WebAuthn/Path-A session) → must reject (unregistered redirect), NOT emit
   a code to the attacker origin.
5. **NEW negative — `plain` PKCE rejected (Step 4b):** `/authorize` with
   `code_challenge_method=plain` → rejected; and `/token` with a stored `plain`
   challenge → rejected.
6. **NEW negative — public client without PKCE rejected (Step 4a, once enabled):**
   register a `none`-auth client, authorize without `code_challenge`, exchange →
   `invalid_grant`.
7. **Positive:** the standard Element-flow style test (`perform_auth_flow`) still
   succeeds end-to-end (PKCE S256, registered redirect, matching client_id).

---

# Effort / risk estimate & recommended order

| Item | Effort | Risk if applied carefully | Frontend rebuild? |
|---|---|---|---|
| **C2 Step 1** (code↔client compare) | XS (~10 lines) | Very low | No |
| **C2 Step 3** (/sign_in redirect re-validate, both paths) | S (~25 lines) | Very low | No |
| **C2 Step 4b** (reject `plain`) | XS | Very low | No |
| **C1 login Expiration-Time enforcement** | S (parse + check + skew) | Low (frontend already sets exp; use 120s skew) | No |
| C2 Step 2 (redirect_uri at /token) | S–M (struct + form + check + tests + client audit) | Medium (client compat) | Maybe (clients/lib) |
| C2 Step 4a (mandatory PKCE public) | XS server, but compat audit | Medium | No |
| C1 device nonce binding | M (struct field + page + msg + tests) | Medium-high (breaking, attended) | Rust recompile |
| C1 account nonce binding | M–L (new challenge store + page + msg + tests) | Medium-high (breaking, attended) | Rust recompile |
| C1 passkey ceremony fixation (S1-5) | S–M | Medium | Rust recompile |

**Recommended order:**

1. **Tonight, safe & server-only (no frontend, low compat risk):**
   C2 Step 1 + C2 Step 3 + C2 Step 4b, and C1 login Expiration-Time enforcement.
   Each with its NEW negative test from §C2.6 / §C1.6. These remove the
   open-redirect, cross-client code redemption, the `plain` downgrade, and the
   "valid-forever login signature" gap **without touching any frontend**.
2. **Attended follow-up, client-compat first:** C2 Step 2 (redirect_uri at
   /token) — verify `siwx-oidc-auth/src/lib.rs` and RPs send it, or do the
   two-phase (log-then-enforce) rollout; then C2 Step 4a (mandatory PKCE for
   public clients).
3. **Attended follow-up, breaking auth-protocol (ship server+page together):**
   C1 device nonce binding, then C1 account nonce binding (new challenge store),
   then C1 passkey ceremony fixation. These are the highest security value but
   require coordinated server + embedded-page changes and updated message
   builders in `e2e_account_management.rs` / `e2e_session_teardown.rs` /
   `e2e/browser/account.spec.mjs`, plus the new replay-rejection tests.

**Hard rule:** the C1 device/account nonce sub-changes and C2 Step 2 are
auth-protocol changes — **do not ship them unattended.** The safe subset in
step 1 above is the only part recommended for immediate application.
