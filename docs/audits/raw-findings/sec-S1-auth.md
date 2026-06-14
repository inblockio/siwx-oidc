# Security Audit S1 — Authentication & Cryptographic Signature Verification

**Target:** `/home/waldknoten-01/siwx-oidc` (siwx-oidc: SIWE/CAIP-122 + WebAuthn → OIDC → Matrix MSC3861)
**Dimension:** Authentication & cryptographic signature verification
**aqua-auth pin reviewed:** `git+https://github.com/inblockio/aqua-rs-auth#056cb34` (the exact commit in `Cargo.lock`, source read from `~/.cargo/git/checkouts/aqua-rs-auth-db083fa82495f6e1/056cb34/`)
**Date:** 2026-06-14 · **Scope:** READ-ONLY

## Summary

The cryptographic primitives in `aqua-auth` (EIP-191 ecrecover, Ed25519/P-256 `did:key`, and the WebAuthn assertion verifier) are correctly implemented: they bind the signature to the exact message bytes and to the claimed DID, and the WebAuthn verifier properly checks rpIdHash, origin, challenge equality, and the UP flag. The OIDC `/authorize → /sign_in → /token` core flow is also largely sound: the SIWE nonce is server-generated, stored in the session, bound to the session cookie, and the auth code is consumed atomically (`SETNX`). **However, the message-level binding around those primitives is inconsistent and incomplete.** `DIDMethod::verify()` is a pure signature check — it does **not** parse or validate the message's domain, URI, `Issued At`, or `Expiration Time` — so every binding (nonce, redirect_uri, freshness) must be enforced by the caller, and two of the three CAIP-122 callers enforce *nothing*. The most serious confirmed issues are: (S1-1) the device-approval and account-management wallet flows accept a signature over an **attacker-chosen message with a client-generated nonce that is never checked**, making those signatures replayable and (for device approval) usable to hijack another user's QR-login session; (S1-2) CAIP-122 messages carry an `Expiration Time` that is never enforced, so a captured wallet signature is valid indefinitely; (S1-3) the `redirect_uri`/resource binding is enforced only on the cookie (`Path B`) login path and is absent from device approval and account re-auth. Several medium issues around WebAuthn challenge/session fixation and a global "any registered DID method" verify dispatch round out the report.

## Severity counts

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 1 | S1-1 |
| HIGH | 3 | S1-2, S1-3, S1-4 |
| MEDIUM | 4 | S1-5, S1-6, S1-7, S1-8 |
| LOW | 2 | S1-9, S1-10 |
| INFO | 2 | S1-11, S1-12 |

---

## S1-1 — Device-approval & account re-auth accept a fully attacker-chosen CAIP-122 message (no nonce/session binding); device approval is cross-session-hijackable
**Severity: CRITICAL** (device approval) / HIGH (account re-auth)
**Files:**
- `src/device_auth.rs:835-917` (`device_approve`)
- `src/account.rs:535-590` (`account_wallet`)
- crypto: `~/.cargo/.../056cb34/src/pkh/eip155.rs:21-55` (`verify` is pure ecrecover, no message parsing)

**What the code does.** `device_approve` and `account_wallet` take `{ did, message, signature }` straight from the JSON body, hex-decode the signature, look up the DID method, check the method/namespace allow-list, then call `did_method.verify(did, message, &sig)`. On `Ok(true)` they proceed. **There is no `extract_nonce` call, no comparison to any server-stored value, no `extract_resources`/redirect check, and no session lookup** (confirmed: `grep nonce|session|extract_*` over `device_approve`'s body returns nothing). The CAIP-122 `Nonce` shown to the wallet is generated client-side by `Math.random().toString(36)` (`device_auth.rs:566`, `account.rs:1371`) and the server never sees or stores it. `verify()` itself only ecrecovers the signer and compares the address to the DID — it ignores the domain/URI/nonce/timestamps entirely.

**Attacker scenario (device approval — session hijack):**
1. Victim starts a QR/device login (Element X). A `device_code`/`user_code` pair is created; `user_code` is short (≈26 bits) and is displayed/visible.
2. Attacker, controlling **their own** wallet `did:pkh:eip155:1:0xATTACKER`, learns or guesses the pending `user_code` (it is the only thing tying the approval to the session, and it is low-entropy and transmitted to the device/UI).
3. Attacker POSTs `/device` with `{ user_code: <victim's>, action: "approve", did: 0xATTACKER, message: <any string the attacker signed>, signature }`. The message can be anything — the attacker signs `"x"` with their own key.
4. `device_approve` verifies the signature is a valid self-signature for `0xATTACKER` (it is), sets `entry.status = Approved`, `entry.did = 0xATTACKER`, and the victim's polling device receives tokens **for the attacker's identity** — or, symmetrically, an attacker who phishes a victim into signing *any* message can approve the attacker's own pending device with the **victim's** DID. Because the message content is unconstrained, a signature the victim produced for an unrelated purpose (any dapp, any "sign this to log in" prompt that uses EIP-191 personal_sign) is a valid approval.

**Attacker scenario (account re-auth — replay / cross-context):** `account_wallet` is the re-auth gate for `device_delete`, `account_deactivate`, and `account_erase`. Any EIP-191 signature the victim ever produced over any message (collected from another dapp, a leaked log, or a prior siwx interaction) is accepted as proof-of-control here, because no nonce/freshness/domain is required. One valid victim signature ⇒ attacker can erase/deactivate the victim's Matrix account or sign out their devices. (Mitigated only by `SameSite=Strict` on the *account session* cookie, which does not apply to the first `account_wallet` POST that carries the signature in the body.)

**Impact.** Authentication bypass / account takeover on the device-login and account-management surfaces: issuance of Matrix tokens for a DID the caller doesn't control, and irreversible account erasure/deactivation triggered by any replayed wallet signature.

**Fix.**
1. Server-generate a single-use nonce when the device/account flow begins (store it in the `DeviceCodeEntry` / an account-challenge entry in Redis), embed it in the message the page asks the wallet to sign, and on approval require `extract_nonce(message) == stored_nonce` then delete it (single-use), exactly as the cookie login path does (`oidc.rs:1382-1386`).
2. Bind the message to the operation: for device approval require the message's URI/resource to reference this server and ideally the `user_code`; for account actions require the message to name the action.
3. Enforce `Issued At`/`Expiration Time` (see S1-2). Until a nonce is bound, do not treat a bare valid signature as authorization.

---

## S1-2 — CAIP-122 `Expiration Time` is never validated; wallet signatures are valid forever
**Severity: HIGH**
**Files:** `src/oidc.rs:1116-1182` (`verify_siwx_cookie`), `src/oidc.rs:1327-1396` (`sign_in` Path B), `~/.cargo/.../056cb34/src/pkh/eip155.rs`, `key/mod.rs` (verify ignores all timestamps)

**What the code does.** The server only ever extracts and checks the `Nonce` line (`extract_nonce`) and (on the cookie path) the `Resources` list. It never parses `Issued At` or `Expiration Time`. `verify()` in aqua-auth does not look at them either. The only time-bound is the Redis session TTL (300s) holding the nonce — but that protects the *login* code path, not the device/account paths (S1-1) which have no nonce at all, and even on the login path nothing asserts the signed message's own claimed expiry.

**Attacker scenario.** A wallet signature captured in transit (or via a malicious/over-broad client, or from logs) remains a valid CAIP-122 proof for any flow that lacks an independent nonce binding. On the cookie login path the 300s session window limits replay; on the device/account paths (S1-1) there is no window at all — the signature is eternal. Even on the login path, an attacker who can re-fixate a session nonce (see S1-7) plus a captured signature could relay it.

**Impact.** Removes the freshness guarantee CAIP-122 is supposed to provide; amplifies S1-1 and S1-3 into long-lived replay.

**Fix.** Parse `Issued At` and `Expiration Time` from the message and reject if `now < issued_at - skew` or `now >= expiration_time`. Make `Expiration Time` mandatory (reject messages lacking it). Consider doing this centrally in `aqua-auth` `verify` or in a shared server-side `validate_caip122_envelope()` used by all three callers.

---

## S1-3 — `redirect_uri`/resource binding enforced only on the cookie login path; absent from WebAuthn login, device approval, and account re-auth
**Severity: HIGH**
**Files:**
- `src/oidc.rs:1388-1394` (resource check exists — Path B / cookie only)
- `src/oidc.rs:1301-1326` (Path A / `verified_did` — **no** resource check)
- `src/device_auth.rs` (`device_approve` — none), `src/account.rs` (`account_wallet` — none)

**What the code does.** Only the CAIP-122 *cookie* login branch checks `extract_resources(message)` contains the `params.redirect_uri` (`oidc.rs:1388`). The WebAuthn login branch (Path A) trusts `session.verified_did` and never ties the assertion to the requested `redirect_uri`. The `redirect_uri` is validated against the client's registered list in `authorize` (`oidc.rs:945-960`, query stripped) — good — but the per-signature resource binding the prompt advertises ("Missing or mismatched resource") simply doesn't exist for three of four entry points.

**Attacker scenario.** The resource binding is meant to prevent a signature obtained for one RP/redirect from being used to mint a code for a different RP. Because (a) WebAuthn login derives a code with no redirect binding beyond the registered-URI check, and (b) device/account flows have none, a signature/assertion is not pinned to the relying party context it was produced in. Combined with multiple registered redirect URIs on a single client, or a permissive client, this widens the blast radius of any captured proof. (On its own, lower severity because `authorize` still restricts `redirect_uri` to the registered set; rated HIGH because it is the documented control and it silently does not apply to most flows.)

**Fix.** Apply a uniform resource/audience binding to every flow that issues a code or approves a session. For WebAuthn, fold the requested `redirect_uri`/client_id into the challenge or session and verify at code issuance. For device/account flows, bind the message to the operation as in S1-1.

---

## S1-4 — `DIDMethod::verify()` performs no message-structure validation; all envelope security is delegated to callers that mostly don't do it
**Severity: HIGH (design root cause behind S1-1/2/3)**
**Files:** `~/.cargo/.../056cb34/src/did_method.rs:43-46` (trait contract), `pkh/method.rs:69-79`, `pkh/eip155.rs:21-55`, `key/mod.rs:127-133`

**What the code does.** `verify(did, canonical_msg, signature)` recovers/loads the key and checks the signature over `canonical_msg`'s raw bytes. It does **not** assert that `canonical_msg` is a well-formed CAIP-122/SIWE message, nor that its embedded `did`/address matches `did` (for eip155 the recovered address is compared to the DID, which is good; but for `did:key` the message body is entirely free — only the signature-key/DID link is checked). There is no domain check, no URI check, no timestamp check, no nonce check. The doc comment calls the input "the canonical CAIP-122 message" but nothing enforces that it is one.

**Attacker scenario.** This is the enabling primitive for S1-1/S1-2/S1-3: because `verify` is "did the holder of this key sign these exact bytes?", any caller that forwards attacker-controlled bytes and then doesn't independently bind nonce/domain/expiry/audience accepts a self-authored proof. The cookie login path happens to bind nonce+resource; the other three callers don't.

**Impact.** Systemic: makes correctness depend on every caller re-implementing envelope validation, which they demonstrably do inconsistently.

**Fix.** Either (a) add a `verify_caip122(did, msg, sig, expected: {domain, uri/audience, nonce, now})` that parses and enforces the envelope and have all callers use it, or (b) keep `verify` low-level but introduce a single mandatory server-side `validate_caip122_message()` that every CAIP-122 caller must run *before* trusting the DID. Document that bare `verify` is not sufficient for authorization.

---

## S1-5 — Device/account passkey ceremony session-id is derived from a public, low-entropy value (challenge fixation / cross-tab)
**Severity: MEDIUM**
**Files:** `src/axum_lib.rs:371,387` (`session_id = format!("device_passkey_{}", user_code)`), `src/webauthn.rs:197-233` (`authenticate_start` stores challenge at `webauthn:challenge/{session_id}`), `verify_credential` (`webauthn.rs:238-340`)

**What the code does.** For device-approval passkey auth, the WebAuthn challenge is stored under a key derived purely from the **public** `user_code` (`device_passkey_{user_code}`). Anyone who knows the `user_code` can call `/device/passkey/start` for it (it only requires the code be pending) and thereby overwrite/seed the challenge slot, and the challenge is the only freshness binding (the credential's DID is taken from the stored passkey/link, not the requester). The account passkey path uses a random `account_passkey_{uuid}` returned to the client (`axum_lib.rs:676-681`) — better, but the `session_id` is then echoed back by the client in `finish`, so it is client-asserted.

**Attacker scenario.** An attacker who knows a victim's pending `user_code` can drive `/device/passkey/start` and `/device/passkey/finish` for that code with *their own* registered passkey, approving the victim's device session under the attacker's DID (a passkey-flavored variant of S1-1). The deterministic, guessable challenge key removes any per-requester isolation.

**Impact.** Device-login session takeover via the passkey branch; challenge-slot interference between concurrent ceremonies sharing a `user_code`.

**Fix.** Derive the ceremony session id from a server-issued, high-entropy, HttpOnly cookie (as the OIDC login flow does with `SESSION_COOKIE_NAME`), not from the user_code. Bind the device approval to the same browser session that initiated `/device/verify`. For the account path, store the `session_id` server-side against the auth cookie rather than trusting the client to echo it.

---

## S1-6 — `sign_in` verifies the DID method allow-list but `verify()` dispatch (`find_did_method`) runs against ALL registered methods, including disabled ones, before the allow-list rejects
**Severity: MEDIUM**
**Files:** `src/oidc.rs:1141-1168` (`verify_siwx_cookie`), `src/oidc.rs:1346-1380` (sign_in Path B), `did_method.rs:51-66` (`all_did_methods` always includes pkh, key, peer)

**What the code does.** The allow-list check (`allowed_did_methods.contains(method_name)`) happens *before* `verify`, so a disabled method is rejected — this part is correct and is applied on all CAIP-122 paths and on the `verified_did` path. **However**, `find_did_method` resolves against the full static registry (`pkh`, `key`, `peer`) regardless of config; `did:peer` is registered and resolvable even though it is not in the default `supported_did_methods`. The protection is therefore purely the string allow-list. Two concrete weak spots: (1) the `did:pkh` namespace allow-list is checked via a manual `strip_prefix("did:pkh:").split(':').next()` (`oidc.rs:1153-1163`) rather than via the method, so any future method whose name is allow-listed but which embeds a sub-namespace would bypass namespace gating; (2) startup validation (`axum_lib.rs:747-771`) only asserts configured methods are *registered*, not that dangerous ones are excluded.

**Attacker scenario.** Mostly defense-in-depth today (the allow-list does reject), but the design means a misconfiguration (`supported_did_methods` accidentally including `peer`, or a new method added to the registry) immediately becomes reachable with no second gate. `did:peer` verification was not deeply reviewed here (out of the default config) and represents latent attack surface that is one config line away from live.

**Impact.** Fragile allow-listing; a single config/registry change can expose an unaudited verifier.

**Fix.** Make the allow-list authoritative at dispatch: filter `all_did_methods()` by `supported_did_methods` and resolve only within that subset, so disabled methods are unreachable, not merely rejected after resolution. Keep namespace checks inside the method.

---

## S1-7 — SIWE nonce is bound to the session but the session cookie is `Secure` only when the *redirect_uri* is https; over plaintext deployments the nonce/session is exposed
**Severity: MEDIUM**
**Files:** `src/oidc.rs:1037-1045` (`is_https = redirect_uri.scheme()=="https"`; cookie `.secure(is_https)`)

**What the code does.** The session cookie's `Secure` flag is keyed on the *client's redirect_uri* scheme, not on the server's own `base_url` scheme. A client legitimately registered with an `http://localhost` redirect (common for native/dev clients) causes the session cookie to be set without `Secure` even when the OIDC server is served over https — and the SIWE nonce lives in that session.

**Attacker scenario.** On a mixed deployment, an attacker who can observe cleartext (or via a non-secure subresource) captures the `session` cookie, and with it the ability to act within the victim's authorize→sign_in window. Combined with the lack of expiry checks (S1-2), this aids nonce/session relay.

**Impact.** Session/nonce cookie disclosure on deployments that have any non-https registered redirect.

**Fix.** Key `Secure` on `config.base_url.scheme() == "https"` (the channel the cookie actually travels on), not on the redirect_uri. Always set `Secure` in production.

---

## S1-8 — WebAuthn `verified_did` is server-trusted but not consumed atomically with sign-in; the verified-DID slot is mutable and not bound to the assertion's freshness
**Severity: MEDIUM**
**Files:** `src/webauthn.rs:344-372` (`authenticate_finish` writes `session.verified_did`), `src/oidc.rs:1287-1326` (`sign_in` reads it after `try_mark_session_signed_in`)

**What the code does.** `authenticate_finish` does a read-modify-write of the session JSON to set `verified_did` (`webauthn.rs:353-369`) — this is **not atomic** (GET then SET_EX), unlike the auth-code/sign-in flags which use `SETNX`. `sign_in` then trusts `verified_did` for the lifetime of the session (300s) and the `try_mark_session_signed_in` SETNX guard only prevents *double* sign-in; it does not prevent the verified_did from being (re)written between ceremony and sign-in, nor does it tie the verified_did to the specific assertion challenge (the challenge is already deleted by then).

**Attacker scenario.** (1) Race: two concurrent ceremonies / a ceremony concurrent with another write on the same session could interleave and leave a `verified_did` the user did not just prove (low practicality — needs the same session cookie). (2) More importantly, once `verified_did` is set, *any* redirect to `/sign_in` with that cookie mints a code for that DID with no further proof, for up to 300s; there is no nonce tying the code issuance to the specific assertion. This is acceptable only because the session cookie is the bearer — but it means a stolen session cookie post-ceremony is a full code-minting capability.

**Impact.** Stolen/relayed session cookie after a passkey ceremony yields code issuance without re-proof; non-atomic write is a latent correctness/race issue.

**Fix.** Set `verified_did` atomically (Lua/compare-and-set), clear it immediately after `sign_in` consumes it (single-use), and bind it to a one-time token rather than the whole session lifetime.

---

## S1-9 — Passkey→wallet link mapping is created after siwx-cookie proof, but the link substitution at auth time is not re-checked against current method allow-list / DID validity
**Severity: LOW**
**Files:** `src/webauthn.rs:298-312` (link substitution in `verify_credential`), `src/webauthn.rs:414-468` (`link_finish`), `src/axum_lib.rs:480-510` (`webauthn_link_start` verifies siwx cookie via `verify_siwx_cookie`)

**What the code does.** `link_start` correctly proves ownership of the `primary_did` via `verify_siwx_cookie` before storing `webauthn:link/{cred_id} → primary_did` (good — this is the cross-user-linking guard and it is present). At authentication time, `verify_credential` blindly substitutes `link_entry.primary_did` for the passkey's own DID **without** re-running the `supported_did_methods` / `supported_pkh_namespaces` allow-list on that primary_did. The allow-list is re-applied later in `sign_in` for the OIDC path, but `device_approve_passkey` and `account_passkey_finish` consume `resp.did` directly and do **not** re-check the method allow-list on the substituted DID.

**Attacker scenario.** Narrow: a user who legitimately linked a passkey to a `did:pkh` while that method was enabled retains a working link even after an admin disables that method; the device/account passkey paths would then act on a now-disallowed DID. Requires prior legitimate link + later config change. Not a cross-user takeover (the link itself is ownership-gated).

**Impact.** Allow-list drift / stale authorization through a previously-created link on the device & account passkey surfaces.

**Fix.** Re-validate the resolved DID (method + namespace allow-list) wherever `verify_credential`'s `resp.did` is consumed, not only in `sign_in`.

---

## S1-10 — `siwx` cookie is parsed from a client-set, URL-decoded JSON blob with no size/shape limits; DID/message/signature fully attacker-controlled
**Severity: LOW**
**Files:** `src/oidc.rs:1122-1132` and `1329-1337` (`serde_json::from_str(&decode(c))`)

**What the code does.** The `siwx` cookie is `urlencoding::decode`d then `serde_json::from_str` into `SiwxCookie`. There is no length cap before decode/parse, and `did`, `message`, `signature` are all attacker-chosen (which is fine *if* nonce+resource+expiry are enforced — see S1-1..S1-4). The signature path safely handles bad hex. This is LOW on its own (the cookie path does bind nonce+resource), noted for completeness and DoS surface.

**Impact.** Minor DoS (large cookie → JSON parse) and reinforces that the cookie is untrusted input whose only real gate is the nonce/resource check.

**Fix.** Bound cookie length; reject oversized blobs before parsing.

---

## S1-11 — PKCE supported and validated, but `plain` method accepted and PKCE not mandatory for public clients
**Severity: INFO**
**Files:** `src/oidc.rs:780-811` (PKCE verify), `1058-1062` (defaults method to S256 when challenge present but method absent), `oidc.rs:768-777` (public clients with `auth_method=None` need no secret)

**What the code does.** PKCE is correctly verified with constant-time comparison and S256 hashing when a challenge was issued, and it sensibly defaults a bare challenge to S256. But `plain` is still accepted (`oidc.rs:798`), and PKCE is not *required* for `token_endpoint_auth_method=none` public clients — a client can register with no secret and request a code with no `code_challenge`, in which case the code is bearer-only. Combined with the broad `CorsLayer::any()` (`axum_lib.rs:946-955`), this is worth tightening.

**Fix.** Reject `plain`; require PKCE (S256) for any client authenticating with `none`.

---

## S1-12 — Positive observations (correctly implemented controls)
**Severity: INFO**

- **EIP-191 / Ed25519 / P-256 signature verification** (`aqua-auth` pkh/key modules) correctly binds signature↔message↔DID; wrong-key, tampered-message, and bad-length cases are rejected (covered by upstream tests).
- **WebAuthn assertion verifier** (`aqua-auth/webauthn.rs`) checks rpIdHash == SHA256(rp_id), origin equality, `type=="webauthn.get"`, base64url challenge equality, UP flag, and the P-256 signature over `authData || SHA256(clientData)`. siwx-oidc additionally enforces the **UV** flag (`webauthn.rs:291-294`) and **sign-count regression** (`webauthn.rs:314-333`). RP ID/origin are derived from `base_url`/config and passed correctly (`axum_lib.rs`, `webauthn.rs:477-513`).
- **SIWE login nonce** is server-generated (`oidc.rs:939-943`), stored in the session, and checked (`oidc.rs:1382-1386`); the **auth code** is consumed atomically via `SETNX` (`db/redis.rs:367-409`); **double sign-in** is blocked atomically (`try_mark_session_signed_in`).
- **redirect_uri** is validated against the client's registered set with the query stripped (`oidc.rs:945-960`).
- **Secrets** (client secret, registration access token, PKCE) use constant-time comparison (`oidc.rs:46-48,760,805,1510`).
- **Passkey→wallet linking** is ownership-gated by a CAIP-122 proof in `link_start` (`axum_lib.rs:494-499`), preventing arbitrary cross-user link creation — the key risk for that feature is handled.

---

## Suggested remediation priority
1. **S1-1** (CRITICAL) — add server-issued single-use nonces + operation binding to device approval and account re-auth; do not authorize on a bare valid signature.
2. **S1-2 / S1-4** (HIGH) — enforce `Issued At`/`Expiration Time` and centralize CAIP-122 envelope validation so all four callers are uniform.
3. **S1-3** (HIGH) — apply resource/audience binding to every code-issuing/approval flow, not just the cookie login path.
4. **S1-5, S1-7, S1-8** (MEDIUM) — fix the guessable passkey ceremony session-id, the `Secure`-flag keying, and the non-atomic / long-lived `verified_did`.
