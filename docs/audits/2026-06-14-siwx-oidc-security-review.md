# siwx-oidc — Security Review (consolidated)

**Date:** 2026-06-14
**Branch:** `audit/siwx-oidc-security-review` (isolated worktree, off `main`)
**Method:** 4 independent read-only auditors over disjoint dimensions, then dedup + cross-corroboration. Full per-dimension findings: `/tmp/sec-S1-auth.md`, `/tmp/sec-S2-tokens.md`, `/tmp/sec-S3-account.md`, `/tmp/sec-S4-input.md`.
**Scope:** the provider only (siwx-oidc). Synapse/MAS config out of scope except the contract.

> Bottom line: the **crypto primitives and the WebAuthn assertion verifier are sound**, and the cookie-login path is well built (server nonce, resource binding, atomic SETNX code consumption, constant-time secret compare). The problems are in **(a) CAIP-122 envelope validation on the non-login paths (replay → account takeover), (b) OAuth code↔client↔redirect binding, (c) concurrency on device/token teardown (the user's primary concern), and (d) a private-key log leak + stale dependencies.**

---

## Severity tally (deduplicated)

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 2 | C1, C2 |
| HIGH | 9 | H-a … H-i |
| MEDIUM | ~12 | see table |
| LOW/INFO | ~10 | see source files |

Cross-corroboration is noted because three agents independently converged on the CAIP-122 replay issue — high confidence it is real.

---

## CRITICAL

### C1 — Replayable CAIP-122 signatures on device-approval & account-management (auth bypass / account takeover)
**Corroborated by S1-1, S2-2, S3-2.** `device_approve` (`src/device_auth.rs:835`) and `account_wallet` (`src/account.rs`) authorize on a *bare* `did_method.verify(did,message,signature)` — **no server nonce, no Expiration-Time, no domain/resource binding, no session consultation.** The nonce shown to the wallet is generated client-side (`Math.random()`) and never stored/compared server-side. Root cause (S1-4): `aqua-auth`'s `DIDMethod::verify()` is a pure byte-level signature check; envelope security is the caller's job, and only the cookie-login path (`sign_in` Path B) does it.
**Exploit:** capture/replay any victim EIP-191 signature → (a) approve an attacker's pending QR/device login *as the victim* (full Matrix session), or (b) drive `account_erase`/`account_deactivate`/`device_delete` against the victim.
**Fix:** introduce a server-issued, single-use, time-boxed nonce for the device and account flows (store in Redis keyed to the device/account session; embed in the CAIP-122 message; verify + consume on submit). Enforce Expiration-Time and a domain/resource binding identical to the login path. Centralize CAIP-122 envelope validation in one helper so all four callers share it.

### C2 — OAuth code not bound to client/redirect; open redirect at `/sign_in`; PKCE optional
**Corroborated by S2-1, S4-1, S2-3.** In `token_authorization_code` (`src/oidc.rs:745`) the request `client_id` is *preferred* over the code's stored client and never compared; `TokenForm` has no `redirect_uri` (`src/oidc.rs:414`) so RFC 6749 §4.1.3 matching is absent. `GET /sign_in` (`src/oidc.rs:1426`) never re-validates the attacker-supplied `redirect_uri` against the registered client, and the WebAuthn/verified-DID path has **no** redirect constraint at all. PKCE is only enforced if a challenge was stored, and `plain` is accepted though discovery advertises S256-only.
**Exploit:** a leaked/intercepted auth code is redeemable by a different (public, secret-less) client; a crafted `redirect_uri` delivers the code to an attacker origin; no PKCE backstop.
**Fix:** persist `client_id` + `redirect_uri` with the code; require both at `/token` and compare exactly; re-validate `redirect_uri` against the registered client at `/sign_in` for **all** paths (wallet and WebAuthn); make PKCE mandatory for public clients and reject `plain`.

---

## HIGH

| ID | Finding | Source | Fix sketch |
|---|---|---|---|
| H-a | **ES256 private signing key logged in full at INFO** when auto-generated (`src/axum_lib.rs:792`) — default path; log read ⇒ ID-token forgery | S4-2 | Never log private key material; log a fingerprint/kid only. Persist key out of band. |
| H-b | **CAIP-122 Expiration-Time never enforced** anywhere ⇒ signatures valid forever | S1-2 | Enforce exp + issued-at skew in the shared envelope validator (part of C1). |
| H-c | **redirect_uri/resource binding only on cookie-login path**; absent from WebAuthn login, device approval, account re-auth | S1-3 | Same shared validator (C1/C2). |
| H-d | **Device-code Approved branch double-redeemable** — code deleted only *after* token issuance, no atomic claim (cf. the SETNX used elsewhere) ⇒ concurrent polls each mint tokens (H9) | S3-1 | Atomic claim (SETNX/Lua CAS) before issuance; idempotent thereafter. |
| H-e | **`device_delete` TOCTOU + `KEYS`-scan revoke races a token refresh** ⇒ stale-but-active tokens survive an explicit sign-out (H3) | S3-3 | Per-(user,device) token secondary index; atomic revoke; no read-modify-delete gap. |
| H-f | **deactivate/erase non-atomic sweep** ⇒ concurrent refresh resurrects access (H6); concurrent `link_finish` leaves an orphan credential so an "erased" DID is silently re-derivable (H5); `purge_identity` aborts mid-sweep yet reports `Erased` | S3-4 | Deactivation tombstone that blocks token minting during the sweep; make purge complete + report partial failures. |
| H-g | **Token-type confusion** (access vs refresh interchangeable; no `mat_`/`mcr_`/type check on refresh & bearer paths) + **REFRESH_TOKEN_TTL = 90 days** vs 24h documented | S2-4, S2-5 | Tag + check token type on every use; set refresh TTL to the intended value. |
| H-h | **Unauthenticated, unbounded dynamic client registration** (`POST /register`, no auth/rate-limit, 30-day TTL) ⇒ Redis exhaustion + arbitrary redirect_uris feeding C2 | S4-3 | Gate DCR (initial access token or allow-list) and/or cap+rate-limit; constrain redirect_uris. |
| H-i | **WebAuthn credentials & links stored with NO TTL**, creatable from a free anonymous session ⇒ permanent Redis growth + inflates the per-login `KEYS` scan into a login-time DoS | S4-4 | Gate registration (tie to C1's session); replace `KEYS` with an index; consider sweeping unlinked anon credentials. |

---

## MEDIUM (condensed — detail in source files)

| ID | Finding | Source |
|---|---|---|
| M1 | `cargo audit`: 5 vulns + 5 warnings — **rustls-webpki 0.103.9** reachable CRL-parse panic (RUSTSEC-2026-0104, fix ≥0.103.13, on live TLS path); **rsa 0.9.10** Marvin timing side-channel | S4-5 |
| M2 | Non-constant-time CSRF token compare (contradicts its own comment; `constant_time_eq` already in tree) | S3-5 |
| M3 | Device/account passkey challenge stored under key derived from the public low-entropy `user_code` (`device_passkey_{user_code}`) ⇒ challenge fixation | S1-5, S3-7 |
| M4 | Session-cookie `Secure` flag keyed on client `redirect_uri` scheme, not server transport | S1-7, S2-7 |
| M5 | `verified_did` written non-atomically (GET+SET) and trusted full 300s, not single-use | S1-8 |
| M6 | `try_consume_code` sets SETNX flag but never deletes the code entry; legacy `get_code` userinfo path can still resolve a consumed code | S2-6 |
| M7 | Multiple concurrent `acct_session`s per DID + H10 residue on the re-auth path (terminal-action cookie clear incomplete on one path) | S3-6, H10 |
| M8 | App-level wildcard CORS allowing `Authorization` cross-origin (relies on Caddy to strip in prod) | S4-6 |
| M9 | No HTTP security headers (HSTS/X-CTO/frame/referrer/CSP) | S4-7 |
| M10 | No brute-force limiter on the device `user_code` flow; `/device/verify` is an unauth pending-code oracle | S4-8, S3-2 |
| M11 | Internal anyhow/Redis/Synapse error strings leaked to clients | S4-9 |
| M12 | `KEYS` full-keyspace scans on logout/revoke/login hot paths (O(N), blocks single-threaded Redis) | S2-10, S4-10 |
| M13 | `find_did_method` resolves against all registered methods incl. `did:peer`; allow-list checked only after resolution | S1-6 |
| M14 | Latent unescaped Redis key-suffix interpolation; `sanitize_user_code` applied to HTML path but not the `device_passkey_{user_code}` Redis key | S4-11 |
| M15 | Synapse failures swallowed ⇒ partial teardown reported as success (ties to H14) | S3-9 |

## Confirmed-OK (so the team isn't misled)
- Crypto primitives correct (EIP-191/Ed25519/P-256 bind sig↔msg↔DID; tamper/wrong-key rejected) — S1.
- WebAuthn assertion verifier checks rpIdHash, origin, challenge equality, UP+UV, sign-count regression — S1.
- Login nonce server-generated + bound; auth-code & double-sign-in SETNX-atomic; secrets constant-time compared; opaque-token CSPRNG entropy sound — S1/S2/S4.
- Passkey→wallet linking correctly ownership-gated (`link_start`) — S1.
- No JWT alg-confusion (ES256-only, no client-chosen alg, no inbound JWT verification) — S2.
- Introspection auth constant-time, no expired-vs-unknown leak — S2.
- No classic SSRF (ENS/Synapse/eth targets are operator config; address signature-verified); JAR/PAR `request`/`request_uri` rejected; base64url cred IDs contain no `/` (no key-confusion) — S4.
- `TeardownPolicy` correctly keeps RFC 7009 revoke as TokensOnly (H1 already correct); no device-id recycling (H2 already correct) — S2/S3.

---

## Prioritized fix plan (this branch)

**Tier 1 — apply tonight, low-risk + high-impact, each with a regression test:**
1. **H-a** stop logging the private key (one-line; critical impact).
2. **M1** `cargo update` rustls-webpki ≥0.103.13 and the other `cargo audit` advisories; re-run `cargo audit`.
3. **M2** constant-time CSRF compare (swap to `constant_time_eq`).
4. **C1/H-b/H-c** shared CAIP-122 envelope validator: server nonce (single-use, Redis-bound) + Expiration-Time + domain/resource binding, applied to device-approval and account re-auth. *(Highest security value; moderate size — do carefully with tests.)*

**Tier 2 — apply if time permits, verify against mock + (if up) real stack:**
5. **H-d/H9** atomic device-code redemption claim.
6. **H-e/H3 + H-f/H6/H5** per-(user,device) token index + deactivation tombstone; complete purge. *(Biggest change; the core race fix.)*
7. **C2** code↔client↔redirect binding + mandatory PKCE for public clients.

**Tier 3 — recommend, flag tradeoffs for user decision (do not silently change behavior):**
8. **H-g** refresh TTL value + token-type tagging (confirm intended TTL first).
9. **H-h/H-i** gate dynamic client registration + WebAuthn registration (UX/compat implications).
10. M4, M8, M9, M11, M12 hardening.

Each applied fix gets a focused regression test (reuse the functional branch's reproducers where they exist) and is verified by running before commit. Anything not applied is left as an explicit recommendation in the morning summary for the user to approve.
