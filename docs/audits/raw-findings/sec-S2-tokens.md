# Security Audit — Dimension S2: Session & Token Lifecycle

Target: `siwx-oidc` (Rust OIDC provider, wallet + WebAuthn, Matrix via MAS/MSC3861, Redis state).
Scope: cookies, OAuth tokens (opaque + JWT), introspection, revocation, JWT signing, Redis TTLs.
Method: static read of `src/oidc.rs`, `src/introspect.rs`, `src/compat.rs`, `src/db/redis.rs`,
`src/db/mod.rs`, `src/config.rs`, `src/account.rs`, `src/axum_lib.rs`, `src/device_auth.rs`.
All findings are CONFIRMED from source unless explicitly marked *needs-verification*.

## Summary

The token plumbing is mostly careful: opaque tokens are 32 base62 chars from `thread_rng`
(~190 bits), client-secret / shared-secret / PKCE / client-access-token comparisons use a
constant-time helper, refresh rotation deletes the old refresh token, and the
`TeardownPolicy` split correctly keeps RFC 7009 revoke from deleting Synapse devices. The
session cookie is `HttpOnly` + `SameSite=Strict` and a fresh session id is minted on each
`/authorize`, so classic fixation is avoided.

The serious problems are in **binding and lifecycle**, not entropy:

1. The **authorization code is never bound to the client at the token exchange** — the
   token endpoint trusts the attacker-supplied `client_id` over the value stored with the
   code, and **`redirect_uri` is not revalidated at all** (it is not even a field of the
   token request). With public clients (PKCE optional), a leaked code is redeemable by any
   client id.
2. The **device-flow CAIP-122 approval verifies a signature with a client-chosen,
   server-unvalidated nonce** and no domain/resource binding — a previously captured (or
   socially-engineered) wallet signature for the victim's DID approves an attacker's device
   login. This is the highest-impact issue because it grants a full Matrix session.
3. **PKCE is optional and `plain` is accepted**, and there is no `code_challenge` required
   for public clients — a downgrade/strip is possible for any non-PKCE client.
4. **Refresh endpoints do not check token type** — an access token (`mat_`) is accepted as
   a refresh token, and a refresh token is accepted as a bearer access token elsewhere.
5. **Access tokens are not revoked on refresh rotation** (old access token lives its full
   TTL) and the **refresh token TTL is 90 days** while CLAUDE.md/discovery imply 24h — a
   long-lived, replayable credential window.

## Severity counts

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 1 | S2-1 |
| HIGH     | 4 | S2-2, S2-3, S2-4, S2-5 |
| MEDIUM   | 5 | S2-6, S2-7, S2-8, S2-9, S2-10 |
| LOW      | 4 | S2-11, S2-12, S2-13, S2-14 |
| INFO     | 3 | S2-15, S2-16, S2-17 |

---

## CRITICAL

### S2-1 — Authorization code not bound to client_id (and redirect_uri never validated) at token exchange
- **Severity:** CRITICAL
- **File:** `src/oidc.rs:738-778` (`token_authorization_code`); `src/oidc.rs:414-426` (`TokenForm`)
- **Status:** CONFIRMED

`TokenForm` has no `redirect_uri` field, so RFC 6749 §4.1.3 redirect_uri matching is
**never performed** at the token endpoint. Worse, the client binding is inverted:

```rust
let client_id = if let Some(c) = form.client_id.clone() {
    c                          // attacker-controlled
} else {
    code_entry.client_id.clone()
};
```

`code_entry.client_id` (the client the code was actually issued to in `sign_in`,
`src/oidc.rs:1417`) is only used as a *fallback*; the request's `client_id` is preferred and
**never compared** to it. The subsequent secret/auth-method check is performed against the
*request's* `client_id`, not the code's. So a confidential client's leaked code can be
redeemed by presenting a *different* public client id (auth method `none`, or `require_secret`
left default but the client registered as public), and PKCE only blocks this when a
`code_challenge` was set (it is optional — see S2-3).

- **Attacker scenario:** Victim authenticates to confidential client A; the `code` leaks
  (Referer header, open-redirect on A's registered URI, proxy log, mix-up attack). Attacker
  registers/uses public client B (`token_endpoint_auth_method = none`) and POSTs
  `grant_type=authorization_code&code=<leaked>&client_id=B`. Because the code carries no PKCE
  challenge for many clients and redirect_uri is not checked, B receives A's user's
  access + refresh tokens (a full Matrix session under MSC3861).
- **Impact:** Account takeover / cross-client token theft; OAuth mix-up attack surface.
- **Fix:** In `token_authorization_code`, after `try_consume_code`, require
  `form.client_id == code_entry.client_id` (reject `invalid_grant` on mismatch) and bind the
  rest of the function to `code_entry.client_id`. Add `redirect_uri` to `TokenForm`, store the
  authorize-time `redirect_uri` in `CodeEntry`, and require an exact match at exchange. Make
  PKCE mandatory for public clients (S2-3).

---

## HIGH

### S2-2 — Device-flow approval verifies a CAIP-122 signature with an unvalidated client nonce (no challenge binding, no domain/resource binding)
- **Severity:** HIGH
- **File:** `src/device_auth.rs:835-917` (`device_approve`); message built client-side at `src/device_auth.rs:566-571`
- **Status:** CONFIRMED

`device_approve` takes `did`, `message`, `signature` from the request body and only checks
`did_method.verify(did, message, &sig_bytes)`. Unlike the wallet sign-in path
(`verify_siwx_cookie` / `sign_in`, which checks `extract_nonce(message) == session.siwe_nonce`
at `src/oidc.rs:1382-1386` and binds the redirect_uri to the message `Resources:` at
`src/oidc.rs:1389-1393`), the device flow:
- does **not** issue a server-side challenge,
- does **not** validate the `Nonce:` line (the page invents it with `Math.random()`),
- does **not** check the message domain or any resource/audience,
- does **not** bind the signature to the `user_code` / `device_code`.

Any structurally valid CAIP-122 message+signature pair for the victim's DID is accepted and
sets `entry.status = Approved`, `entry.did = victim`. The token grant
(`token_device_code`, `src/oidc.rs:608-720`) then mints a full Matrix session for the victim's
DID on the attacker's device.

- **Attacker scenario:** Attacker starts a device flow (gets `device_code` + `user_code`),
  then obtains *any* CAIP-122 signature from the victim — e.g. a sign-in the victim performed
  on a phishing site, a "verify your wallet" prompt on an attacker site, or a replayed prior
  device-approval message (nonce reuse is not detected). Attacker POSTs `/device`
  `{user_code, action:"approve", did:victim, message, signature}`. Approval succeeds; attacker
  polls `/token` and receives the victim's access + refresh tokens.
- **Impact:** Full account/session takeover via signature replay / cross-context signature
  reuse. No phishing of the OIDC site itself is required.
- **Fix:** Issue a server-side nonce per device flow (store it in `DeviceCodeEntry`), require
  the CAIP-122 message `Nonce:` to equal it, enforce single-use, and require the message
  domain to be this server and a resource/audience that names the device authorization.
  Mirror the binding already done in `sign_in` for the wallet path.

### S2-3 — PKCE optional and `plain` challenge method accepted (downgrade / no protection for public clients)
- **Severity:** HIGH
- **File:** `src/oidc.rs:780-811` (verification); `src/oidc.rs:1058-1062` (`authorize` defaulting); `src/oidc.rs:253-284` discovery advertises only `S256`
- **Status:** CONFIRMED

PKCE is only enforced *if* `code_entry.code_challenge` is `Some`:
`if let Some(ref challenge) = code_entry.code_challenge { ... }`. A client that simply omits
`code_challenge` at `/authorize` gets a code with **no PKCE binding**, and the token endpoint
does not require one. Combined with S2-1 (no client/redirect binding), a stolen code from a
non-PKCE public client is freely redeemable. Additionally the verifier accepts
`method == "plain"` (`src/oidc.rs:798`), even though discovery advertises only
`code_challenge_methods_supported: ["S256"]` (`src/oidc.rs:261`) — an attacker who can inject
`code_challenge_method=plain` defeats the SHA-256 protection (the challenge equals the
verifier in plaintext, observable wherever the code is observable).

- **Attacker scenario:** Public client (Element X uses PKCE, but any registered public client
  or a mix-up target may not). Attacker strips `code_challenge` (or sets `plain`) in the
  authorize request it controls, then redeems the resulting code without proving possession of
  a verifier.
- **Impact:** Defeats the only remaining defense against code interception for public clients.
- **Fix:** Reject `code_challenge_method=plain` (return error; only `S256`). Require a
  `code_challenge` for any client whose `token_endpoint_auth_method` is `none` (and ideally
  for all clients). Persist the negotiated method and reject `plain` even if stored.

### S2-4 — Refresh endpoints do not check token type; access tokens are usable as refresh tokens (and vice-versa)
- **Severity:** HIGH
- **File:** `src/oidc.rs:454-528` (`token_refresh`); `src/compat.rs:441-543` (`refresh`); also `userinfo`/introspect accept any token
- **Status:** CONFIRMED

Both refresh paths do `db_client.get_token(&rt)` and accept *any* live `TokenMetadata`,
without checking the token's prefix (`mat_` vs `mcr_`) or a stored type discriminator
(`TokenMetadata` has no `token_type` field — `src/db/mod.rs:92-110`). Therefore:
- An **access token** can be presented at `/token` (`grant_type=refresh_token`) or
  `/_matrix/client/v3/refresh` and will mint a *fresh access + refresh pair* — i.e. an access
  token silently grants indefinite renewal, equivalent to a refresh token. The original access
  token is then `delete_token`'d (`src/oidc.rs:518`, `src/compat.rs:528`).
- A **refresh token** (90-day TTL) is equally accepted by `get_token` at `/userinfo`
  (`src/oidc.rs:1575`) and `/oauth2/introspect` (`src/introspect.rs:96`), so introspection
  reports a refresh token as an `active` bearer access token — Synapse would accept a refresh
  token as an API credential.
- **Attacker scenario:** A short-lived access token leaked via a log/Referer/XSS can be
  upgraded into a 90-day refresh chain by calling the refresh endpoint, escaping the 300s
  access TTL. Conversely a captured refresh token works directly as an API access token.
- **Impact:** Privilege/lifetime escalation and token-type confusion; defeats the short
  access-TTL design.
- **Fix:** Add a `token_type` (Access/Refresh) field to `TokenMetadata`; in `token_refresh` /
  `compat::refresh` require `metadata.token_type == Refresh`; in `userinfo` / `introspect`
  require `Access`. Cheaply, gate on the prefix in MSC3861 mode (`mcr_` only for refresh,
  `mat_` only for bearer), but a stored type is more robust.

### S2-5 — Old access token survives refresh rotation; refresh TTL is 90 days (replay window)
- **Severity:** HIGH
- **File:** `src/oidc.rs:486-518` and `src/compat.rs:471-528` (rotation only deletes the old *refresh* token); `src/db/mod.rs:22` `REFRESH_TOKEN_TTL = 7_776_000` (90d)
- **Status:** CONFIRMED

On refresh, only the **old refresh token** is deleted (`delete_token(&rt)`); the previously
issued **access token is left valid** for the remainder of its 300s TTL. More importantly, the
refresh token is rotated but the system keeps a **90-day** refresh TTL
(`REFRESH_TOKEN_TTL = 7_776_000`), contradicting the CLAUDE.md "Refresh token TTL 86400s (24h)"
table and the `compat::refresh` response `expires_in_ms` semantics. A 90-day bearer credential
that is also accepted by introspection (S2-4) is a large standing replay surface.

Refresh rotation is also **not atomic / not replay-detecting**: there is no "used refresh
token" detection. If two requests race (or an attacker replays the old refresh token before
the legitimate client does, in a network with reordering), the design relies solely on
`delete_token` having run; there is no rotation-family invalidation (RFC 6819 §5.2.2.3 / OAuth
2.1 recommends invalidating the whole token family on reuse detection).

- **Attacker scenario:** Attacker captures a refresh token; uses it directly as an API token
  (S2-4) for up to 90 days, or replays it in the rotation gap to fork a parallel,
  legitimate-looking token chain that survives the victim's next rotation.
- **Impact:** Long-lived credential theft; no breach containment via rotation.
- **Fix:** Set refresh TTL to the documented 24h (or shorter idle + absolute caps). On refresh,
  detect reuse of an already-rotated refresh token and revoke the entire `(username, device_id)`
  family (`revoke_device_tokens`). Consider revoking the paired access token on rotation.

---

## MEDIUM

### S2-6 — Authorization code entry is not deleted on consume; only a SETNX flag enforces single-use
- **Severity:** MEDIUM
- **File:** `src/db/redis.rs:367-409` (`try_consume_code`)
- **Status:** CONFIRMED

`try_consume_code` does `SET NX codes/{code}/consumed 1` and, on win, reads but **does not
delete** `codes/{code}`. The code entry (with the DID, nonce, PKCE challenge) lingers in Redis
for the full `ENTRY_LIFETIME` (300s). Single-use is enforced only by the separate consumed
flag. If the `EXPIRE` on the consumed flag fails (`.unwrap_or(())` at `src/db/redis.rs:386`
swallows the error) the flag could in principle outlive or, if a deployment ever uses a Redis
without persistence guarantees / a flush, the decoupling of "entry" and "consumed flag" is
fragile. The code value itself is also still GET-able via `get_code` (used by the legacy
userinfo fallback at `src/oidc.rs:1599`), so a consumed-but-not-deleted code remains usable on
that path until TTL.

- **Impact:** Sensitive auth-code material persists post-use; legacy `get_code` path can
  resolve a consumed code to a userinfo response.
- **Fix:** Delete `codes/{code}` (and the consumed flag) atomically inside the winning branch
  of `try_consume_code` (e.g. a Lua `GETDEL`-style script that returns the entry and removes
  it in one round-trip), instead of leaving the entry to expire.

### S2-7 — `is_https` (cookie `Secure`) derives from the redirect_uri scheme, not the server transport
- **Severity:** MEDIUM
- **File:** `src/oidc.rs:1037-1045` (`authorize`); compare `src/axum_lib.rs:533-560` for the account cookie
- **Status:** CONFIRMED

The session cookie's `Secure` attribute is set from `params.redirect_uri.url().scheme() ==
"https"`, i.e. the *client's* redirect target, not the actual scheme the browser used to reach
siwx-oidc. A confidential deployment behind a TLS-terminating proxy where a client legitimately
registers an `http://localhost/...` redirect (common for native clients) would mint a
**non-Secure** session cookie even though the user's browser is on HTTPS, allowing the session
cookie to be sent over a downgraded/cleartext request. Conversely it does not reflect
`X-Forwarded-Proto`. The account cookie (`account_cookie_set`) at least keys off
`base_url.scheme()`, which is more correct — the two paths are inconsistent.

- **Impact:** Session cookie may lack `Secure`, enabling MITM capture on a downgraded request;
  inconsistent with the account cookie.
- **Fix:** Derive `Secure` from `config.base_url.scheme()` (and/or trusted `X-Forwarded-Proto`),
  not from the redirect_uri. Make both cookie paths use the same rule.

### S2-8 — Public clients bypass authentication: discovery advertises `none` and code exchange honors it
- **Severity:** MEDIUM
- **File:** `src/oidc.rs:763-778` (auth-method handling); `src/oidc.rs:273-274` discovery `token_endpoint_auth_methods_supported = ["client_secret_post","none"]`
- **Status:** CONFIRMED (severity depends on registration policy — partly needs-verification)

When no secret is presented, the exchange allows the request through if the client's
`token_endpoint_auth_method` is `None`, OR if it is unset and `config.require_secret` is false.
`require_secret` defaults to `true` (`src/config.rs:67`), which is good, but `/register` is open
(any caller can DCR a client — `src/oidc.rs:1439`) and a client can register itself with
`token_endpoint_auth_method = none`. Combined with S2-1 (no code↔client binding) and S2-3 (PKCE
optional), a self-registered public client is a ready vehicle for redeeming codes that belong to
other clients.
- **Impact:** Lowers the bar for S2-1/S2-3 exploitation; open DCR + public clients + no code
  binding is a dangerous combination.
- **Fix:** If public clients are supported, mandate PKCE S256 for them (S2-3) and bind the code
  to the exact client (S2-1). Consider authenticating/registering-policy on `/register`
  (*needs-verification:* whether DCR is exposed unauthenticated in the deployed Caddy routing).

### S2-9 — No `at_hash` in id_token, and device-flow id_token omits `nonce` / `auth_time`
- **Severity:** MEDIUM
- **File:** `src/oidc.rs:874-892` (auth-code id_token, no `at_hash`); `src/oidc.rs:682-698` (device id_token: no `set_nonce`, no `set_auth_time`)
- **Status:** CONFIRMED

The auth-code id_token sets `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time` but passes the
access token to `CoreIdToken::new(..., Some(&access_token), None)` — whether `at_hash` is
emitted depends on the openidconnect crate (*needs-verification* that `at_hash` actually lands
in the JWT). The device-flow id_token (`src/oidc.rs:682-698`) does **not** set a nonce or
`auth_time`. If any RP validating the device-flow id_token expects a nonce, it cannot bind it;
and missing `auth_time` weakens `max_age`/re-auth enforcement. (Device flow legitimately has no
OIDC nonce, so this is a minor correctness gap, not a direct token-theft vector.)
- **Impact:** Weakened id_token-to-access-token binding and replay/freshness assurances for RPs.
- **Fix:** Confirm `at_hash` is emitted for code flow; set `auth_time` on the device-flow
  id_token; document that device flow carries no nonce.

### S2-10 — Token-revocation scans the entire token keyspace with `KEYS` (DoS / latency)
- **Severity:** MEDIUM
- **File:** `src/db/redis.rs:215-243` (`revoke_tokens_where` → `keys_raw("token/*")`); used by `revoke_device_tokens`, `revoke_all_user_tokens`; also `purge_identity` (`keys_raw("webauthn:*")`)
- **Status:** CONFIRMED

Every single-session logout / RFC 7009 revoke / device_delete triggers a full `KEYS token/*`
scan plus a `GET` per key and JSON parse (no secondary index on `(username, device_id)`). `KEYS`
is O(N) and blocks the Redis event loop. With many live sessions (or an attacker minting many
tokens via open DCR + device flow), each logout/revoke becomes expensive and can stall the
whole instance. The code comment claims volume is "bounded" by short access TTLs, but 90-day
refresh tokens (S2-5) keep the keyspace large, and revoke is called on *every* token rotation /
dialog dismissal (the very behavior that motivated the TeardownPolicy split).
- **Impact:** Redis-blocking O(N) operations on a hot path → latency / DoS amplification.
- **Fix:** Maintain a secondary index set per `(username, device_id)` and per `username`
  (Redis SET of token keys) updated in `set_token`/`delete_token`; revoke by reading the set.
  At minimum replace `KEYS` with `SCAN`.

---

## LOW

### S2-11 — CSRF token compared with non-constant-time `!=` despite the "constant work" comment
- **Severity:** LOW
- **File:** `src/account.rs:661-663`
- **Status:** CONFIRMED

`if req.csrf.as_deref() != Some(session.csrf.as_str())` is an ordinary short-circuiting string
comparison; the comment "Constant work either way" is inaccurate. The CSRF token is a random
UUID (`src/account.rs:60`), so a timing oracle is low-value, but it is inconsistent with the
codebase's own `constant_time_eq` used for every other secret. (`acct_session` is also not
constant-time-looked-up, but it is a Redis key, not a compare.)
- **Impact:** Theoretical timing side-channel on a UUID; low practical value.
- **Fix:** Use `constant_time_eq` (already imported in `oidc.rs`; expose it) for the CSRF check.

### S2-12 — Session secret and SIWE nonce are 16 alphanumeric chars (~95 bits); session/CSRF secret appears unused
- **Severity:** LOW
- **File:** `src/oidc.rs:939-943` (SIWE nonce, 16 chars), `src/oidc.rs:1019-1023` (session secret, 16 chars); `SessionEntry.secret`/`signin_count` (`src/db/mod.rs:59-60`)
- **Status:** CONFIRMED (entropy fine; unused-field is a smell)

16 alphanumeric chars ≈ 95 bits — adequate. However `SessionEntry.secret` and `signin_count`
are stored but I found no code path that *reads/validates* `secret` or increments/checks
`signin_count` (sign-in races are guarded instead by `try_mark_session_signed_in`'s SETNX flag,
`src/db/redis.rs:411-431`). Dead security-relevant fields invite a future "validate the secret"
assumption that is not actually enforced.
- **Impact:** None directly; misleading state that could mask a future regression.
- **Fix:** Either bind and verify `session.secret` (e.g. as a confirmation parameter) or remove
  the unused fields to avoid false assurance.

### S2-13 — `acct_session` cookie not marked Secure on http; broad `Path=/account` but fine; no SameSite for client-set `siwx`
- **Severity:** LOW
- **File:** `src/axum_lib.rs:533-560` (`acct_session`); the `siwx` cookie is set client-side (frontend), so server cannot set HttpOnly/SameSite
- **Status:** CONFIRMED

`acct_session` is `HttpOnly; SameSite=Strict; Path=/account`, `Secure` only when
`base_url.scheme()=="https"` — correct for prod (https) but on any http deployment it is
non-Secure. The `siwx` cookie carrying `{did, message, signature}` is **set by the browser
frontend**, so it is necessarily JS-readable (not HttpOnly) and its SameSite/Secure flags are
whatever the frontend sets (out of this server's control). It is consumed server-side and the
signature is re-verified, so XSS-readability of `siwx` is not a direct token leak, but it does
mean an XSS on the login origin can forge/replace the wallet proof presented at `sign_in` (the
nonce check still binds it to the session, limiting blast radius).
- **Impact:** Minor; depends on deployment transport and frontend cookie flags.
- **Fix:** Document that `siwx` must be `Secure`/`SameSite=Lax|Strict` in the frontend; keep
  prod on https so `acct_session`/`session` are always Secure.

### S2-14 — Introspection `active:false` is returned for both expired and unknown tokens (good) but `expires_in` can be tiny/negative race; client_secret_post `client_id` accepted-not-validated
- **Severity:** LOW
- **File:** `src/introspect.rs:67-122`
- **Status:** CONFIRMED

The endpoint correctly auths with a constant-time compare of the shared secret
(`src/introspect.rs:87-91`) and returns a flat `{"active": false}` for missing/expired/unknown
tokens (no info leak distinguishing the cases — good). Two minor notes: (a) `expires_in` is
computed as `m.exp - now` with `now` sampled after the `exp > now` check, so it can be `0` or
slightly negative under clock skew/raciness; (b) the `client_id` form field is explicitly
"accepted but not validated" (`src/introspect.rs:49-52`) — acceptable for a shared-secret model
but means the secret is the only credential (and it equals the MAS shared secret /
`admin_token`, per the memory note — a single point of compromise).
- **Impact:** Negligible info leak; concentration of trust in one shared secret.
- **Fix:** Clamp `expires_in` to `>= 0`. Track the long-term goal of separating the
  introspection secret from the Synapse admin token (noted elsewhere as a known caveat).

---

## INFO / Observations

### S2-15 — JWT alg confusion: no `none`/HS path; only ES256 advertised and signed
- **File:** `src/oidc.rs:66, 196, 209`, signing in `src/oidc.rs:691-698, 885-892`, JWK at `src/oidc.rs:123-141`
- **Status:** CONFIRMED (positive finding)

`SIGNING_ALG` is fixed to `[EcdsaP256Sha256]`; id_token / userinfo JWTs are always signed with
the server's ES256 key via `CoreIdToken::new(..., signing_key, EcdsaP256Sha256, ...)`. There is
no code path that selects the algorithm from client input, and the server does not *verify*
inbound JWTs (it issues opaque tokens for MSC3861 and verifies wallet signatures via aqua-auth,
not JWTs), so classic `alg:none` / RS↔HS confusion does not apply here. Userinfo signing alg is
taken from the client's `userinfo_signed_response_alg` but only the server's own key/alg is used
to sign, which is fine. No action required; verify no future endpoint starts trusting a
client-supplied JWT header alg.

### S2-16 — Signing key: generated-if-absent means ephemeral keys across restarts/replicas
- **File:** `src/axum_lib.rs:786-791`; `src/config.rs:14-15`
- **Status:** CONFIRMED

If `SIGNING_KEY_PEM` is unset, a fresh ES256 key is generated on each startup
(`EcdsaSigningKey::generate`). All issued id_tokens become unverifiable after a restart, and a
multi-replica deployment would serve inconsistent JWKs. This is operational rather than a direct
token-theft bug, but a missing key in prod silently degrades id_token validation. Ensure
`SIGNING_KEY_PEM` is always set in production (the README implies this).

### S2-17 — Redis TTL coverage: device-code rate-limit `update_device_code` re-sets full TTL on every poll (TTL extension)
- **File:** `src/oidc.rs:580-593` (`update_device_code(..., DEVICE_CODE_LIFETIME)` on each poll); `src/db/redis.rs:507-514`
- **Status:** CONFIRMED (minor)

Every device-code poll calls `update_device_code(dc, entry, DEVICE_CODE_LIFETIME)`, which
re-applies a *full* 1800s TTL via `SET EX`. A client polling indefinitely keeps the device code
(and the `last_poll` rate-limit state) alive far beyond the advertised `expires_in`, defeating
the absolute device-code lifetime. Use `created_at` (already stored, `src/db/mod.rs:88`) to
enforce an absolute expiry, or persist with a TTL computed from `created_at` rather than a fixed
re-set. WebAuthn `credential`/`link` keys are intentionally TTL-less (documented). Account
sessions, codes, sessions, tokens, device/user codes all have TTLs — coverage is otherwise good.

---

## Confirmed vs needs-verification

- **CONFIRMED from source:** S2-1, S2-2, S2-3, S2-4, S2-5, S2-6, S2-7, S2-8 (code path; the
  *registration exposure* is partly deployment-dependent), S2-10, S2-11, S2-12, S2-13, S2-14,
  S2-15, S2-16, S2-17.
- **NEEDS-VERIFICATION:**
  - S2-9: whether the openidconnect crate actually emits `at_hash` in the code-flow id_token.
  - S2-8: whether `/register` (DCR) is reachable unauthenticated in the deployed Caddy routing
    (controls how easily an attacker can create the public client used in S2-1/S2-3).
  - S2-5: confirm the *deployed* refresh TTL — source says 90 days (`REFRESH_TOKEN_TTL`), docs
    say 24h; the discrepancy itself is a finding.

## Highest-priority remediation order
1. S2-1 (bind code↔client + redirect_uri at exchange) and S2-3 (mandatory PKCE S256, drop
   `plain`) — together they close cross-client code redemption.
2. S2-2 (device-flow challenge/nonce binding) — closes signature-replay account takeover.
3. S2-4 (token-type checks) and S2-5 (refresh TTL + reuse detection) — close lifetime/type
   confusion and the standing 90-day replay window.
