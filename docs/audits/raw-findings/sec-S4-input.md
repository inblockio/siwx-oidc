# Security Audit — Dimension S4: Input validation, injection, DoS, error/info leakage, dependency & crypto hygiene

**Target:** `/home/waldknoten-01/siwx-oidc` (Axum OIDC provider, Redis-backed; CAIP-122 wallet + WebAuthn → OIDC for Matrix Synapse).
**Scope:** Redis key injection, SSRF, unbounded-input/DoS, open redirect, error/info leakage, CORS, security headers, static-file traversal, dependency & crypto hygiene.
**Method:** Read of `axum_lib.rs`, `oidc.rs`, `db/redis.rs`, `db/mod.rs`, `synapse_client.rs`, `device_auth.rs`, `webauthn.rs`, `introspect.rs`, `config.rs`, `Cargo.toml`; `cargo audit` (installed during audit, ran against `Cargo.lock`).

## Summary

The most serious issue is an **open redirect / authorization-code interception at `GET /sign_in`** (S4-1): unlike `/authorize`, `sign_in` never re-validates the attacker-controlled `redirect_uri` against the registered client, and the token endpoint never binds the code to a redirect_uri. For the WebAuthn / server-verified-DID path there is *no* redirect_uri constraint at all (the CAIP-122 `Resources:` check only covers the wallet path), and PKCE is optional, so a public client's auth code can be delivered to an attacker-chosen origin. Secondary findings: the **ES256 private signing key is logged in full at `info` level** when auto-generated (S4-2); **unauthenticated, unbounded dynamic client registration** with 30-day TTL and no rate limit (S4-3); **WebAuthn credentials and account-link mappings are stored with no TTL** and registration only requires a free anonymous session, enabling Redis storage exhaustion (S4-4); and **`cargo audit` reports 5 advisories incl. a reachable panic in `rustls-webpki` and the `rsa` Marvin timing side-channel** (S4-5). Lower-severity issues: wildcard CORS with `Allow-Headers: authorization` in the app itself (relies on Caddy to strip — fragile, S4-6), no HTTP security headers (S4-7), the user_code device-approval flow has no brute-force counter (S4-8), error responses surface internal `anyhow`/Redis/Synapse strings to clients (S4-9), `KEYS`-based full-keyspace scans on revoke/purge (S4-10), and a few INFO-level notes. SSRF surface is constrained (ENS/Synapse targets are operator config, not attacker-controlled). Redis key construction uses `/`-delimited prefixes with user-controlled suffixes but no observed namespace-escape because the suffixes are UUIDs, base64url (no `/`), or signature-verified DIDs.

### Severity counts

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 0 | — |
| HIGH | 4 | S4-1, S4-2, S4-3, S4-4 |
| MEDIUM | 4 | S4-5, S4-6, S4-8, S4-9 |
| LOW | 3 | S4-7, S4-10, S4-11 |
| INFO | 3 | S4-12, S4-13, S4-14 |

---

## HIGH

### S4-1 — Open redirect / auth-code interception at `GET /sign_in` (redirect_uri not re-validated; not bound at token endpoint)
**Severity:** HIGH
**File:** `src/oidc.rs:1265-1430` (`sign_in`), final emission `src/oidc.rs:1426-1429`; token side `src/oidc.rs:724-811` (`token_authorization_code`); contrast with `src/oidc.rs:925-960` (`authorize` *does* validate).
**Status:** CONFIRMED (code path), exploitability HIGH for the WebAuthn/server-verified path and for public clients.

**Scenario.**
- `GET /authorize` validates `redirect_uri` against the registered client's `redirect_uris` (`oidc.rs:947-960`).
- `GET /sign_in` takes `redirect_uri`, `state`, `client_id` again as query params (`SignInParams`, `oidc.rs:1184-1194`). It looks up the *session* by cookie but **never calls `get_client` and never checks `redirect_uri` against the client registration**. It mints the auth code and appends it to whatever `redirect_uri` was supplied: `let mut url = params.redirect_uri.url().clone(); url.query_pairs_mut().append_pair("code", ...)` (`oidc.rs:1426-1428`).
- Path B (wallet/CAIP-122) has a partial guard: the redirect_uri must appear in the signed message's `Resources:` list (`oidc.rs:1388-1394`). **Path A (server-verified DID, i.e. every WebAuthn/passkey login, and the link flow) has NO redirect_uri check whatsoever** (`oidc.rs:1301-1326`).
- The token endpoint never receives or checks `redirect_uri` (`TokenForm` has no `redirect_uri` field, `oidc.rs:414-426`; `token_authorization_code` never compares one). PKCE is only enforced if a `code_challenge` was stored (`oidc.rs:781`), and public clients (`token_endpoint_auth_method = none`, `oidc.rs:768-769`) need no secret.

An attacker who can get a passkey-authenticating victim to follow a crafted `/sign_in?...&redirect_uri=https://attacker.example/cb&state=...` (e.g. by controlling the flow after a passkey ceremony, or because the front-end is driven by query params) receives the authorization `code` at their origin and, for a public client with no PKCE, exchanges it at `/token`. Even with PKCE, this is a working open redirect (arbitrary external URL with attacker `state`), usable for phishing and to leak any other query data echoed by the RP.

**Impact.** Account/session takeover for public or PKCE-less clients; open redirect for all clients. This is the canonical OAuth "redirect_uri not validated at the right step / not bound at token exchange" defect (RFC 6749 §4.1.3, §10.6).

**Fix.**
1. In `sign_in`, load the client (`get_client(params.client_id)`) and reject if `params.redirect_uri` (query stripped) is not in `metadata.redirect_uris()` — mirror the exact check in `authorize` (`oidc.rs:945-960`). Apply it on **both** Path A and Path B.
2. Persist the validated `redirect_uri` in `CodeEntry` and require `redirect_uri` in `TokenForm`, comparing it constant-time at the token endpoint (RFC 6749 §4.1.3).
3. Consider making PKCE mandatory for public clients.

---

### S4-2 — ES256 private signing key logged in full at INFO when auto-generated
**Severity:** HIGH (when `SIWEOIDC_SIGNING_KEY_PEM` unset)
**File:** `src/axum_lib.rs:790-792`.
**Status:** CONFIRMED.

```rust
info!("Generating ES256 signing key...");
let key = EcdsaSigningKey::generate(...);
info!("Generated ES256 key. PEM:\n{}", key.to_pem().unwrap());
```

**Scenario.** If no signing-key PEM is configured (the documented default — `config.rs:14-15`, `signing_key_pem: None`), the server prints the **PKCS#8 private key** to stdout/stderr at `info` level. In the Docker deploy these logs go to the container log aggregator. Anyone with log access recovers the key used to sign all ID tokens.

**Impact.** Full ID-token forgery → impersonation of any DID/user to every OIDC RP (including Synapse). Directly contradicts the repo's own logging rule ("Never log secrets, tokens, cookies, or signing key material", CLAUDE.md). The auto-generated-key default also means the key rotates on every restart (sessions break) — a correctness foot-gun that pushes operators toward leaving it generated.

**Fix.** Remove the PEM from the log line. At most log a fingerprint/`kid`. Strongly recommend logging a `warn!` that an ephemeral key was generated and instructing operators to set `SIWEOIDC_SIGNING_KEY_PEM` for production, but never emit the private material.

---

### S4-3 — Unauthenticated, unbounded dynamic client registration (no rate limit, 30-day TTL)
**Severity:** HIGH
**File:** route `src/axum_lib.rs:840` (`POST /register` → `register`), handler `src/oidc.rs:1439-1488`; TTL `src/db/mod.rs:16` (`CLIENT_LIFETIME = 30 days`).
**Status:** CONFIRMED.

**Scenario.** `POST /register` is open (no auth, no CORS/origin restriction, no rate limit). Each call writes a `clients/{uuid}` entry (with a full attacker-supplied `CoreClientMetadata`, incl. arbitrary `redirect_uris`) to Redis with a 30-day TTL. An attacker can:
- Flood Redis with millions of client entries (memory-exhaustion DoS — each holds attacker-controlled metadata of bounded-but-nontrivial size; combined with the default 2MB body limit per request).
- Register clients with arbitrary `redirect_uris` to chain with S4-1 (no admin review of redirect targets).

**Impact.** Redis memory-exhaustion DoS; uncontrolled registration of clients whose redirect_uris feed the open-redirect path.

**Fix.** Gate `/register` behind auth (initial access token / admin), or at minimum add rate limiting (per-IP, e.g. via `tower_governor`) and a global cap on the number of dynamically-registered clients. Validate/normalize redirect_uris at registration (require https, reject obvious internal hosts). Consider a shorter TTL plus a renewal flow.

---

### S4-4 — WebAuthn credentials & link mappings stored with NO TTL; registration only needs a free anonymous session → Redis storage exhaustion
**Severity:** HIGH
**File:** `src/webauthn.rs:178-183` (`webauthn:credential/*` `set_raw`, no TTL), `src/webauthn.rs:456-458` (`webauthn:link/*` `set_raw`, no TTL); registration gate `src/axum_lib.rs:412-446`, `src/webauthn.rs:123-193`.
**Status:** CONFIRMED.

**Scenario.** `POST /webauthn/register/finish` stores a serialized `Passkey` JSON at `webauthn:credential/{cred_id_b64}` with **no expiry** (`set_raw`). The only precondition is a session cookie, which any anonymous caller obtains for free from `GET /authorize` (S4-3-style: a registered/default client_id is required for `/authorize`, but the default-clients map plus open `/register` makes one trivially available). An attacker scripts register_start/register_finish with self-minted authenticator responses (a software authenticator) and writes unbounded permanent entries.

Note this is also a latent **GDPR/erasure footprint** issue: these entries persist forever unless `purge_identity` runs, and they grow `authenticate_start`'s allow-list (`webauthn.rs:206-220` does `KEYS webauthn:credential/*` on every passkey-auth start — see S4-10), so storage exhaustion also degrades every login.

**Impact.** Unbounded permanent Redis growth (memory DoS); per-login `KEYS` scan cost grows linearly with stored credentials (amplifies S4-10 into a login-time DoS).

**Fix.** Either (a) require an authenticated/owned session before allowing standalone passkey registration, or (b) cap credentials per session/IP and add a generous TTL (or a background reaper) for credentials that are never linked or used. Replace the per-login `KEYS` scan (S4-10) with a server-side discoverable-credential model or a secondary index so credential count cannot make login O(n).

---

## MEDIUM

### S4-5 — Vulnerable / unmaintained dependencies (`cargo audit`: 5 vulns, 5 warnings)
**Severity:** MEDIUM
**File:** `Cargo.lock` (transitive). Crates: `rsa 0.9.10`, `rustls-webpki 0.103.9`, `rand 0.8.5`/`0.9.2`, plus unmaintained `derivative`, `paste`, `proc-macro-error2`.
**Status:** CONFIRMED (cargo audit ran; see verbatim output below).

Highlights:
- **`rustls-webpki 0.103.9`** — RUSTSEC-2026-0104 (reachable panic in CRL parsing), plus RUSTSEC-2026-0099/0098/0049 (name-constraint / CRL matching bugs). This is on the TLS path (`reqwest` rustls-tls used for ENS, Synapse, introspection calls). A reachable panic during cert/CRL handling is a potential DoS. **Fix available:** upgrade to `>=0.103.13`.
- **`rsa 0.9.10`** — RUSTSEC-2023-0071 (Marvin timing side-channel, no fixed upgrade). Pulled in transitively; siwx-oidc's own token/signature crypto is P-256 (ES256), so direct exposure is likely limited to TLS/cert handling, but it is present.
- **`rand 0.8.5` / `0.9.2`** — RUSTSEC-2026-0097 ("unsound with a custom logger using `rand::rng()`"). `rand 0.8` is used directly for nonces, codes, secrets, and tokens (`oidc.rs:939`, `1019`, `1445`; `introspect.rs:32-37`; `device_auth.rs:26-30`). The advisory is a narrow soundness edge case, not a predictability flaw, but the version is flagged.
- Unmaintained: `derivative 2.2.0`, `paste 1.0.15`, `proc-macro-error2 2.0.1` (build/macro-time only).

**Fix.** `cargo update -p rustls-webpki` to `>=0.103.13` (highest priority — has a fix and is on the live TLS path). Bump `rand` to a patched release and re-audit. Track `rsa`/unmaintained crates; add `cargo audit` (or `cargo deny`) to CI as a gate.

**Verbatim `cargo audit` summary:**
```
    Scanning Cargo.lock for vulnerabilities (569 crate dependencies)
Crate:     rsa
Version:   0.9.10
Title:     Marvin Attack: potential key recovery through timing sidechannels
ID:        RUSTSEC-2023-0071   Severity: 5.9 (medium)   Solution: No fixed upgrade is available!

Crate:     rustls-webpki  Version: 0.103.9
  RUSTSEC-2026-0104  Reachable panic in certificate revocation list parsing   (fix: >=0.103.13)
  RUSTSEC-2026-0099  Name constraints accepted for certs asserting a wildcard name (fix: >=0.103.12)
  RUSTSEC-2026-0098  Name constraints for URI names incorrectly accepted       (fix: >=0.103.12)
  RUSTSEC-2026-0049  CRLs not considered authoritative due to faulty matching  (fix: >=0.103.10)

Warning (unmaintained): derivative 2.2.0 (RUSTSEC-2024-0388)
Warning (unmaintained): paste 1.0.15 (RUSTSEC-2024-0436)
Warning (unmaintained): proc-macro-error2 2.0.1 (RUSTSEC-2026-0173)
Warning (unsound):      rand 0.8.5 (RUSTSEC-2026-0097)
Warning (unsound):      rand 0.9.2 (RUSTSEC-2026-0097)

error: 5 vulnerabilities found!
warning: 5 allowed warnings found
```

---

### S4-6 — Application-level wildcard CORS with `Allow-Headers: authorization` (depends on Caddy to strip)
**Severity:** MEDIUM (defense-in-depth; relies entirely on an external proxy rule)
**File:** `src/axum_lib.rs:946-955`.
**Status:** CONFIRMED in app; prod mitigation is external/operational (Caddy) per CLAUDE.md.

```rust
CorsLayer::new()
    .allow_origin(AllowOrigin::any())          // ACAO: *
    .allow_methods([GET, POST, OPTIONS])
    .allow_headers([CONTENT_TYPE, AUTHORIZATION])
```

**Scenario.** The app emits `Access-Control-Allow-Origin: *` and allows the `Authorization` header for all of GET/POST. Credentials are not via `allow_credentials(true)` (so cookies aren't readable cross-origin), but `Authorization: Bearer` is allowed cross-origin from any site. This permits any web origin to script authenticated calls to token/userinfo/introspect/account/Matrix-compat endpoints using a bearer token it already holds, and to read responses. The deployment relies on Caddy stripping the upstream ACAO (CLAUDE.md "CORS rule") — but that only addresses *dual-header* breakage, and the app's permissive posture is the source of truth if the proxy rule is ever wrong/missing (e.g. a second ingress, a direct-to-pod path, a misconfigured Caddyfile).

**Impact.** Cross-origin use of bearer-authenticated endpoints; the security boundary lives in an external, easily-misconfigured proxy rather than the app.

**Fix.** Replace `AllowOrigin::any()` with an explicit allow-list (the front-end origin / `base_url`). Do not allow `Authorization` cross-origin unless a specific origin needs it. Keep `allow_credentials` off. Make the app's own CORS posture correct so it does not depend on Caddy.

---

### S4-8 — Device-approval user_code has no brute-force/attempt limiter (only ~25.9 bits entropy, 30-min TTL)
**Severity:** MEDIUM
**File:** `src/device_auth.rs:12-35` (`generate_user_code`, 6 consonants of a 20-char alphabet ≈ 25.9 bits), TTL `src/db/mod.rs:25` (`DEVICE_CODE_LIFETIME = 1800s`); lookup paths `device_auth.rs:811-823` (`device_verify`), `835-917` (`device_approve`), and `axum_lib.rs:343-350` (`GET /device/verify` — unauthenticated).
**Status:** CONFIRMED (no counter); practical risk MEDIUM.

**Scenario.** `GET /device/verify?user_code=XXX-XXX` and `POST /device` look up pending device authorizations by `user_code` with **no per-code or global attempt counter and no IP rate limiting** at the app layer. The user_code space is 20^6 ≈ 6.4e7. The RFC 8628 device-code rate limit (`oidc.rs:576-589`) only throttles the *device's* polling of `/token`; it does not throttle an attacker guessing `user_code` against `/device/verify` or `/device`. An attacker who guesses a pending code before the human approves can race to **approve their own device** against the victim's session (the approval binds the attacker-chosen device, then the legitimate device polling `/token` receives tokens) — or at least enumerate pending logins. With 30-min TTL and no limiter, online guessing is feasible at scale, especially if many codes are pending.

Note the entropy meets RFC 8628's *recommended minimum for a 600s lifetime*, but the TTL here is 1800s (3×) and there is no rate limiter — the two together weaken the margin.

**Impact.** Device-login hijacking / session confusion via user_code guessing; enumeration of pending logins.

**Fix.** Add a strict rate limit / lockout on `user_code` lookups (per-IP and global), bound failed attempts per code, and/or shorten the device-code TTL toward 600s. Consider increasing user_code length when the client display can show it.

---

### S4-9 — Error responses leak internal error strings (anyhow / Redis / Synapse) to clients
**Severity:** MEDIUM
**File:** `src/axum_lib.rs:101-117` (`CustomError::into_response` returns `self.to_string()` bodies); examples of internal strings reaching `CustomError`: `oidc.rs:1124-1126` ("Could not decode/deserialize siwx cookie: {e}"), `device_auth.rs:877-878` ("Bad signature: {e}"), `redis.rs` pervasive `anyhow!("Redis GET: {e}")` etc., token endpoint wrap `axum_lib.rs:167-170` (`other.to_string()` into `error_description`).
**Status:** CONFIRMED.

**Scenario.** `CustomError::Other(anyhow::Error)` and several `BadRequest(format!(...))` paths render the inner error message verbatim into the HTTP body (`(StatusCode::INTERNAL_SERVER_ERROR, self.to_string())` / `(BAD_REQUEST, self.to_string())`). Many inner errors are `anyhow` chains carrying Redis driver messages ("Redis GET: ...", "Redis pool: ..."), serde parser detail, and (via the token-endpoint catch-all at `axum_lib.rs:167-170`) arbitrary internal strings echoed into the OAuth `error_description`. The token endpoint also wraps generic errors as `invalid_request` with the internal message, exposing implementation detail to any unauthenticated caller.

**Impact.** Information disclosure: backend topology (Redis), library/version fingerprinting, and internal logic hints that aid further attack. Not a direct compromise but raises attacker signal.

**Fix.** Map `CustomError::Other` to a generic "internal error" body and log the detail server-side only (the repo's own convention says to log at the boundary). For `BadRequest`, return stable, sanitized messages and avoid interpolating raw parser/driver errors. Never forward `other.to_string()` into `error_description`.

---

## LOW

### S4-7 — No HTTP security headers (HSTS, X-Content-Type-Options, CSP, X-Frame-Options, Referrer-Policy)
**Severity:** LOW
**File:** `src/axum_lib.rs:829-955` (router/layers — only Trace + CORS layers; no header-setting layer).
**Status:** CONFIRMED.

The service serves HTML (device approval `device_auth.rs:141`, account page `account.rs`) and JSON. No `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, or `Referrer-Policy` is set. The HTML pages interpolate sanitized but user-influenced values (`user_code`, `base`, `action`, `device_id`, `csrf`) into the DOM (`device_auth.rs:155,242`; `account.rs:939,996`); a CSP would harden against any residual injection. Caddy may add some of these in prod, but the app sets none. **Fix:** add a `SetResponseHeaderLayer`/middleware setting at least `nosniff`, `frame-ancestors 'none'`/`X-Frame-Options: DENY` on the HTML routes, HSTS on https, and a restrictive CSP for the served pages.

### S4-10 — `KEYS`-based full-keyspace scans on token revoke, identity purge, and every passkey-auth start (DoS / latency)
**Severity:** LOW (functional+DoS; severity raised to MEDIUM in combination with S4-4)
**File:** `src/db/redis.rs:73-84` (`keys_raw` → Redis `KEYS`), used by `revoke_tokens_where` (`redis.rs:222-243`, scans `token/*`), `purge_identity` (`redis.rs:167-213`, scans `webauthn:link/*` then `webauthn:credential/*`), and `webauthn.rs:206` (`authenticate_start` scans `webauthn:credential/*` on **every** passkey-auth start).
**Status:** CONFIRMED.

`KEYS` is O(N) over the whole keyspace and blocks the single-threaded Redis server. The token-revoke scans are bounded by token volume, but `authenticate_start` runs a `KEYS webauthn:credential/*` on every login, and combined with S4-4 (unbounded, no-TTL credentials) an attacker can inflate credential count to make each login (and each erase) progressively slower, eventually a server-wide stall. **Fix:** replace `KEYS` with `SCAN` (non-blocking) at minimum; better, maintain secondary indexes (e.g. `user:{username}:tokens` sets, `did:{did}:creds` sets) so revoke/purge/auth-start are O(matches) not O(keyspace).

### S4-11 — Redis key construction interpolates user-influenced suffixes via `format!("{prefix}/{value}")` (no escaping)
**Severity:** LOW (no confirmed escape today; latent)
**File:** `src/db/redis.rs` throughout (e.g. `device_codes/{device_code}` :491, `user_codes/{user_code}` :525,542, `token/{token}` :441, `clients/{client_id}` :256, `codes/{code}` :302); `webauthn.rs` (`webauthn:credential/{cred_id_b64}` :180, `:link/{cred_id_b64}` :457, `:challenge/{session_id}` :141); `axum_lib.rs:371,387` (`device_passkey_{user_code}`), `:676` (`account_passkey_{uuid}`).
**Status:** needs-verification (no exploit found), reported as latent risk.

All Redis keys are built as `"{static_prefix}/{value}"`. Redis keys are binary-safe so there is no classic delimiter-injection RCE, but a value containing the prefix delimiter could in principle collide namespaces. In practice the interpolated values are: UUIDs (`client_id`, `code`, `session_id`), base64url-no-pad (`cred_id_b64` — contains `-`/`_` but **no `/`**, so the documented "base64 device ids with `/`" confusion does not occur here), opaque base62 tokens, or signature-verified DIDs. The one user-controlled-at-entry value is `user_code` for the `user_codes/{user_code}` and `device_passkey_{user_code}` keys; `device_authorization` only ever stores server-generated codes, and `device_verify`/lookup paths reject unknown codes, so no escape is reachable. **Recommendation:** add an explicit allow-list/validation (or hex/percent-encode) for any value used as a key suffix that can originate from a request body, and assert `cred_id_b64`/`user_code` charset before key use, to keep this closed under future refactors. (`sanitize_user_code` at `device_auth.rs:128` already does this for the HTML path but is *not* applied on the `device_passkey_{user_code}` key build at `axum_lib.rs:371,387`.)

---

## INFO

### S4-12 — SSRF surface is constrained but worth noting (ENS HTTP API + on-chain provider)
**File:** `src/oidc.rs:296-368` (`resolve_name_http` does `GET {ens_api_url}/{checksummed_address}`; `resolve_name_onchain` connects to `eth_provider`); `synapse_client.rs` (Synapse endpoint).
**Status:** INFO (not attacker-controlled).
`ens_api_url`, `eth_provider`, and `synapse_endpoint` are all **operator config** (`config.rs:21-25,44`), not request input, so an attacker cannot point them at internal hosts. The only attacker-influenced component is `address_string` (the checksummed Ethereum address derived from a *signature-verified* DID), appended to the ENS API path. Because it is a validated 0x-hex address (parsed via `address_str.parse::<Address>()` before use, `oidc.rs:386`), it cannot inject a host or path-traverse the ENS URL. No SSRF confirmed. Keep ENS resolution behind a timeout (currently a fresh `reqwest::Client::new()` per call, `oidc.rs:302`, with no explicit timeout — a slow/hostile ENS endpoint can stall request handling; set `.timeout(...)`).

### S4-13 — `request_uri` / `request` (JAR / PAR) explicitly unsupported — good, but error is reflected to redirect_uri
**File:** `src/oidc.rs:964-977`. The handler correctly rejects `request_uri`/`request` (no SSRF via JAR pull). Note these rejections redirect to `params.redirect_uri` *before* (in the `state`-missing branch) the redirect_uri membership check at `oidc.rs:947-960` has been reached — but that branch is after the membership check in `authorize`, so it is constrained there. Informational; verifying ordering during the S4-1 fix is worthwhile.

### S4-14 — Token/code entropy and CSPRNG usage are adequate
**File:** `oidc.rs:939,1019,1445` (`rand::thread_rng()` Alphanumeric: 16-char nonces/secrets ≈ 95 bits; 11-char registration access token ≈ 65 bits), `introspect.rs:32-37` (32 base62 ≈ 190 bits), `account.rs:59` (two v4 UUIDs ≈ 244 bits), `device_auth.rs:26-30` (user_code ≈ 25.9 bits — see S4-8), auth code = v4 UUID (`oidc.rs:1423`, ≈122 bits). All use `thread_rng()` (a CSPRNG). Constant-time comparison is used for secrets/tokens (`constant_time_eq` and `subtle::ct_eq`, e.g. `oidc.rs:760,805,1510`; `introspect.rs:88`). The 11-char registration *access token* (`oidc.rs:1460-1466`, ~65 bits) is the weakest non-user_code secret — fine for now but consider widening to 32 chars for consistency with opaque tokens. Subject to RUSTSEC-2026-0097 caveat in S4-5, randomness hygiene is sound.
