# Token handling: standards and prior art

**Date:** 2026-10-02
**Code reviewed:** `3547bd2`
**Tracking issue:** [#30](https://github.com/inblockio/siwx-oidc/issues/30)
**Plan built on this record:** [2026-10-02-token-lifecycle-rework.md](2026-10-02-token-lifecycle-rework.md)

This is the reference record for how siwx-oidc should handle bearer credentials. It collects what
the standards require, how other authorization servers implement refresh-token rotation, and how
the Matrix clients behave. It is a dated snapshot: later standards revisions or client releases
may change individual rows, and the guides in `docs/` describe current behaviour.

## 1. Trigger and threat

A browser profile copied to another machine kept a working session without re-authentication.
That is expected for bearer tokens: the client's token store is the whole credential, and
Chromium does not encrypt web storage (localStorage, IndexedDB) at rest. Cookies are encrypted
with an OS-bound key and usually do not survive a cross-OS copy; tokens in web storage do.

The same capability is what infostealer malware uses. The browser-based-apps BCP names it
directly (§8.6): "More and more malware is specifically created to crawl user's machines looking
for browser profiles to obtain high-value tokens and session cookies".

The precondition (filesystem access to the profile) places this outside the vulnerability policy
in [SECURITY.md](../../SECURITY.md); everything below is defense in depth that limits or exposes
damage after a credential, the Redis store, or the logs are already compromised.

## 2. Standards

Quotes are verbatim from the published texts unless marked otherwise.

| Source | Requirement | Status at `3547bd2` |
|---|---|---|
| RFC 9700 §4.14.2 | "Authorization servers MUST utilize one of these methods to detect refresh token replay by malicious actors for public clients": sender-constrained refresh tokens, or rotation where "information about the relationship is retained by the authorization server" and, on replay, "it will revoke the active refresh token" | Rotation yes; relationship not retained after 60 s, so replay is undetectable |
| RFC 9700 §4.14.2, implementation note | "The grant to which a refresh token belongs may be encoded into the refresh token itself" so the server can find "all refresh tokens that need to be revoked" | Not done |
| OAuth 2.1, draft-ietf-oauth-v2-1-16 §4.3.1 | On replay under rotation the server "will revoke the active refresh token as well as the access authorization grant associated with it"; the server must "validate that the grant corresponding to this refresh token is still active"; "if a client_id is included in the request, ensure the refresh token was issued to the matching client" | No grant revocation on replay; no client check |
| OAuth 2.1 §1.3.2, §4.3.3 | Sliding expiry is allowed ("extended as long as the refresh token is used at least once every 7 days"); refresh tokens "SHOULD expire if the client has been inactive for some time" | Conforms (90-day inactivity expiry) |
| RFC 6749 §10.4 | "The authorization server MUST maintain the binding between a refresh token and the client to whom it was issued" | **Violated**: the refresh grant ignores `client_id` and the client secret |
| draft-ietf-oauth-browser-based-apps-27 §6.3.2.3 | The server "MUST either set a maximum lifetime on refresh tokens OR expire if the refresh token has not been used within some amount of time" and "upon issuing a rotated refresh token, MUST NOT extend the lifetime of the new refresh token beyond the lifetime of the initial refresh token if the refresh token has a preestablished expiration time". Rationale: "a stolen refresh token cannot be used indefinitely" | Conforms through the inactivity branch only; no absolute bound exists |
| browser-based-apps-27 §5.1.2 | "Refresh token rotation is not sufficient to prevent abuse of a refresh token. An attacker can easily ensure that the application will not use the latest refresh token" | Limits what reuse detection can promise (section 5) |
| browser-based-apps-27 §8.6 | WebCrypto "only ensures that the key is not exportable to the browser code, but does not place any requirements on the underlying storage of the key itself ... a non-exportable key cannot be relied on as a way to protect against exfiltration from the underlying filesystem" | Basis for not relying on DPoP in browsers |
| RFC 9449 (DPoP) §5, §11 | Refresh tokens of public clients using DPoP "MUST be bound to the respective public key"; the exfiltration analysis assumes a key that "cannot be exported, e.g., in a hardware or software security module" | Not implemented |
| FAPI 2.0 Security Profile §5.3.2.1 | Rotation is discouraged for confidential clients with sender-constrained tokens; where used, servers must "offer clients the time-limited option to retry with the old refresh token in case of failure" | Not our client profile (public clients, bearer tokens); confirms that lost-response recovery is a sanctioned pattern |
| RFC 6819 §5.1.4.1.3 | "The authorization server should not store credentials in clear text. Typical approaches are to store hashes instead or to encrypt credentials. If the credential lacks a reasonable entropy level (because it is a user password), an additional salt will harden the storage" | **Not done**: tokens are Redis keys in clear text |

Hardware binding in browsers: Chrome's Device Bound Session Credentials (DBSC) shipped in Chrome
145 on Windows and binds **cookies** to a TPM-held key
([announcement](https://developer.chrome.com/blog/dbsc-windows-announcement)). No equivalent for
OAuth tokens held in web storage was found. DBSC can apply to siwx-oidc's own cookies, not to
tokens held by relying-party clients.

## 3. Authorization servers

| Implementation | Rotation | Lost-response window | Replay inside the window | Replay outside the window | Lifetime model |
|---|---|---|---|---|---|
| Matrix Authentication Service (MAS), main `19fa53b9ac54` | always | **until the successor's access token is first used**, no timer | mints a new pair, revokes the unused successor | rejected; no revocation (source comment: "This is a replay, we *may* want to invalidate the session") | access TTL configurable; no refresh expiry found |
| Ory Hydra v26.2.0 (fosite v0.49.0) | always | `rotation_grace_period`, default 0 s, max 5 min | mints a new pair | revokes every token of the grant chain (`request_id`) | fixed lifespan |
| Auth0 | opt-in | reuse interval, off by default | not documented | invalidates the whole token family | absolute, 30 d default, rotation never extends it |
| Okta | opt-in | 0 to 60 s, default 30 s | not documented | revokes the newest refresh token and access tokens issued since authentication | inherits the original expiry; 7-day inactivity default |
| Keycloak | "Revoke Refresh Token", off by default | reuse counter, default 0 | mints a new token | `invalid_grant`, no session revocation | SSO session idle and max |
| Duende IdentityServer | off (`ReUse` is the default since v7) | none by default | n/a | rejected; revocation left to the operator | absolute 30 d default |
| AWS Cognito | opt-in | 0 to 60 s | not documented | not documented | absolute, rotated tokens keep the original expiry |
| **siwx-oidc at `3547bd2`** | always | 60 s timer | **returns the same successor** | `invalid_grant`, nothing recorded | sliding 90 d |

Observations:

- Returning the **same** successor (siwx-oidc) is stricter than minting a new pair (MAS, Hydra,
  Keycloak): it never creates a second live branch of the chain, so it needs no extra revocation
  step to stay single-chain.
- A **state-based** window (MAS) tolerates lost responses of any duration and still detects
  reuse with one predicate: has the successor been used?
- MAS stores refresh tokens in clear text (`WHERE refresh_token = $1`). Hydra stores only the
  HMAC part of a `key.signature` token (fosite `token/hmac/hmacsha.go`).
- Keycloak keeps rotation state per client session (latest token id, use counter): constant
  storage per session instead of one record per token.
- Duende's documentation argues against one-time refresh tokens on reliability grounds: a client
  that loses a response "has no way to recover without the user logging in again". The state-based
  window removes that objection.

## 4. Matrix clients

| Client | Behaviour | Evidence |
|---|---|---|
| Element Web | Only one tab runs a session (session lock since August 2023), so tabs cannot race a refresh | matrix-react-sdk #11416, #11425; `SessionLock.ts` |
| matrix-js-sdk | Deduplicates refresh in-process; logs out on **any** 4xx from the refresh request (`TokenRefreshLogoutError`) | `src/http-api/refresh.ts`, `src/oauth/tokenRefresher.ts` (develop) |
| matrix-rust-sdk (Element X) | Cross-process refresh lock with a session-hash check, so a process that sees a changed session reloads it instead of refreshing | `crates/matrix-sdk/src/authentication/oauth/cross_process.rs` |
| matrix-rust-sdk | A process suspended during the exchange can still send a stale token: "Being suspended during the token exchange can still produce a sign-out" | changelog, PR #6860 |
| MAS issue #2795 | Element X was signed out nightly after iOS suspended the app during a refresh and the response was lost; fixed by the state-based window | [element-hq/matrix-authentication-service#2795](https://github.com/element-hq/matrix-authentication-service/issues/2795) |

Not verified: whether the Element X iOS notification extension builds its client through the same
cross-process lock path as the main app.

Consequence: both clients already treat a failed refresh as terminal, so for a single holder a
server-side revocation on reuse costs nothing beyond what the client does anyway. It adds harm
only where two distinct holders exist, which is the case revocation is meant to end.

## 5. Principles adopted

1. **No credential at rest or in logs.** Store `SHA-256(token)`; unsalted is sufficient for
   tokens with at least 128 bits of entropy (RFC 6819). Encrypt the one value that must be
   returned later (the lost-response successor) under a key derived from the token that unlocks
   it. Log fingerprints only.
2. **The grant is the unit of state and revocation.** Encode a grant handle in the refresh token
   (RFC 9700 implementation note); keep constant-size rotation state per grant (Keycloak model).
3. **One live chain per grant**, enforced atomically (one Redis script), with the lost-response
   window decided by state, not time (MAS model), returning the same successor (siwx-oidc model).
4. **Any superseded token of a live grant is reuse.** Phase in revocation of the whole grant
   (OAuth 2.1) after a log-only soak.
5. **Bounded lifetime.** Inactivity expiry plus an absolute cap from the original authentication;
   rotation never extends the cap (browser-based-apps §6.3.2.3 rationale). Only a lifetime bound
   limits the copy-then-abandon case, which reuse detection cannot see (§5.1.2).
6. **Refresh tokens are bound to their client** (RFC 6749 §10.4).
7. **Sender-constraining is per platform.** DPoP adds nothing against a browser profile copy
   (§8.6); it does help native clients whose key lives in a hardware keystore.

## Sources

- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- RFC 6749: https://www.rfc-editor.org/rfc/rfc6749.html
- RFC 6819: https://www.rfc-editor.org/rfc/rfc6819.html
- RFC 9449: https://www.rfc-editor.org/rfc/rfc9449.html
- OAuth 2.1 draft 16: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.html
- OAuth 2.0 for Browser-Based Applications, draft 27: https://www.ietf.org/archive/id/draft-ietf-oauth-browser-based-apps-27.html
- FAPI 2.0 Security Profile: https://openid.net/specs/fapi-security-profile-2_0-final.html
- DBSC: https://developer.chrome.com/blog/dbsc-windows-announcement, https://w3c.github.io/webappsec-dbsc/
- MAS: https://github.com/element-hq/matrix-authentication-service (`crates/handlers/src/oauth2/token.rs`, `crates/tasks/src/cleanup/tokens.rs`)
- Ory Hydra and fosite: https://github.com/ory/hydra (`persistence/sql/persister_oauth2.go`), https://github.com/ory/fosite (`handler/oauth2/flow_refresh.go`, `token/hmac/hmacsha.go`)
- Auth0: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
- Okta: https://developer.okta.com/docs/guides/refresh-tokens/main/
- Keycloak: https://github.com/keycloak/keycloak (`TokenManager.java`, `validateTokenReuse`)
- Duende: https://docs.duendesoftware.com/identityserver/tokens/refresh/
- AWS Cognito: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html
- Element Web session lock: https://github.com/matrix-org/matrix-react-sdk/pull/11416, https://github.com/matrix-org/matrix-react-sdk/pull/11425
- matrix-rust-sdk: https://github.com/matrix-org/matrix-rust-sdk
