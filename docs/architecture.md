# Architecture

How siwx-oidc is put together: the layers, how to extend them, the sign-in flows, the DID
methods, the frontend, what lives in Redis, and where the project came from. The per-file code
map and the rules that protect all of this are in [AGENTS.md](../AGENTS.md). Matrix-specific
wiring (Synapse, tokens, devices, account management) is in
[matrix-integration.md](matrix-integration.md); identifiers and the published DID are in
[identity-model.md](identity-model.md).

## Crates

| Crate | Where | What |
|---|---|---|
| `siwx-oidc` | `src/` | The Axum server (binary `siwx-oidc`), the operator tool `migrate-credentials`, and a small library crate `siwx_oidc` (Redis layer, pure MXID and alias derivation, credential store) that integration tests link against. |
| `siwx-oidc-auth` | `siwx-oidc-auth/` | Headless client, library and CLI: key-based sign-in, refresh, device flow, DID verification. See [agents.md](agents.md). |
| `aqua-auth` | external, [inblockio/aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth) | DID parsing and CAIP-122 signature verification, WebAuthn assertion verification, the optional credential store. Pinned by git tag (`v0.7.0` at the time of writing) in both `Cargo.toml` files. |

## Three layers

```
Layer 1: aqua-auth          DID parsing + CAIP-122 proof verification (DIDMethod, CipherSuite)
Layer 2: src/<ceremony>.rs  server-side ceremonies that end in a verified DID
                            (webauthn.rs for passkeys, device_auth.rs for RFC 8628 approval)
Layer 3: src/oidc.rs        OIDC: authorize, sign_in, token, userinfo, discovery, JWKS
```

**The boundary:** aqua-auth verifies CAIP-122 proofs and nothing else. Any other way of
proving control of a key (WebAuthn today; SSH or PGP later) is a server-layer module that
produces a verified DID and stores it in the Redis session. `DIDMethod` is not extended for
non-CAIP-122 proofs.

**Why the ceremony lives in the server.** A cryptographic check is necessary but not
sufficient. NIST SP 800-63B makes authenticator verification the verifier's responsibility;
the W3C WebAuthn assertion procedure (Level 2, §7.2) is mostly checks against session and
origin state (challenge binding, origin, RP ID hash, flags, sign counter), with only the
signature step being cryptography; and webauthn-rs exposes the ceremony as one safe API for
that reason. All of that state is in the server, so that is where the ceremony runs.
Registration uses webauthn-rs; assertions are verified with aqua-auth's
`verify_webauthn_assertion` against the stored challenge.

**One issuance point.** Authorization codes are created only in `sign_in`. Tokens are minted by
`POST /token` (all grants), by `POST /_matrix/client/v3/refresh` (the Matrix client-server
refresh, in `compat.rs`) and, for siwx-oidc's own calls to Synapse, by
`POST /oauth2/admin_token`. A ceremony endpoint never issues a code; it stores `verified_did`
in the session and redirects to `/sign_in`, which enforces the configured DID methods and
`did:pkh` namespaces for every path.

## Extending the layers

aqua-auth has two traits:

- **`DIDMethod`**: the only trait the server sees. One implementation per DID method
  (`PkhMethod`, `KeyMethod`, `PeerMethod`). It parses the DID, supplies the fields of the
  CAIP-122 message and the OIDC `sub` (`canonical_subject`, the full DID), and verifies the
  signature.
- **`CipherSuite`**: internal to `did:pkh`, one per namespace (`Eip155Suite`, `Ed25519Suite`,
  `P256Suite`). The server never imports it.

The registries are plain functions, `all_did_methods()` and `all_cipher_suites()`, with no
`inventory`-style auto-registration (it is not WASM-safe). At startup the server asserts that
every configured method and namespace is registered, and panics otherwise.

| To add | Where | Guide |
|---|---|---|
| A DID method | one file plus one registry line in aqua-auth, then a tag bump here | [skills/add-did-method.md](../skills/add-did-method.md) |
| A `did:pkh` namespace | one file plus one registry line in aqua-auth, then a tag bump here | [skills/add-cipher-suite.md](../skills/add-cipher-suite.md) |
| An auth ceremony | a server module in `src/`, routes, and the verified-DID path of `sign_in` | [skills/add-auth-ceremony.md](../skills/add-auth-ceremony.md) |

New methods and namespaces are opt-in: operators enable them in
[configuration](configuration.md).

## Sign-in flows

**CAIP-122 (wallet, or any key the browser can sign with):**

1. `GET /authorize` validates the client, the redirect URI (exact match against the
   registration, query included), `response_type=code` (the only one accepted) and the `S256`
   PKCE challenge. It creates a session (`session/{sha256(id)}`, 300 s) that binds the validated
   request (client, redirect URI, state, response mode, challenge), sets the `session` cookie,
   and redirects to the login page with a nonce and the request's values, each percent-encoded
   so the page reads back the exact redirect URI its CAIP-122 message must bind.
2. The page builds a CAIP-122 message (for Ethereum, an EIP-4361 message) containing the
   nonce, has the wallet sign it, and sets the `siwx` cookie to `{did, message, signature}`.
3. `GET /sign_in` checks the DID method and namespace against configuration, verifies the
   signature through `find_did_method(did).verify(…)`, checks the nonce and that the bound
   redirect URI is in the message's `Resources:`, then issues a single-use code for the request
   bound to the session. `/sign_in` reads no authorization parameter from its query (the page
   still appends them to its link; they are ignored).
4. `POST /token` exchanges the code, with its PKCE `S256` verifier, for an ES256 ID token, an
   access token and a refresh token. PKCE is mandatory: `/authorize` refuses a request without a
   `code_challenge`, and `/token` refuses a code without one.

**Server-verified ceremony (passkey):**

1. `GET /authorize` as above.
2. `/webauthn/authenticate/start` and `/finish` run the WebAuthn ceremony. On success the
   server derives `did:key:zDn…` from the passkey's P-256 key (or takes the linked wallet DID,
   see [passkeys.md](passkeys.md)) and stores it as `verified_did` in the session.
3. `GET /sign_in` reads `verified_did` from the session (trusted, server-side) and issues the
   code for the bound request.
4. `POST /token` as above.

**Headless agent:** the same CAIP-122 flow, driven by `siwx-oidc-auth` with a local Ed25519 or
P-256 key (`did:key`), no browser. See [agents.md](agents.md).

**Device authorization (RFC 8628, used for Element X QR login):**

1. `POST /device_authorization` returns `device_code`, a `user_code` such as `WDJ-BMJ`, and the
   verification URI `/device`.
2. The device polls `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
3. The user opens `/device?user_code=…` and approves with a wallet signature or a passkey.
4. The next poll returns tokens and provisions the Synapse device.

The device-code grant is available only when siwx-oidc runs with a Synapse (`mas_shared_secret`
set). Details: [matrix-integration.md](matrix-integration.md).

## DID methods

| Method | Key types | Implemented in | Enabled by default |
|---|---|---|---|
| `did:pkh` | namespaces `eip155` (Ethereum, EIP-191), `ed25519`, `p256` | aqua-auth `pkh` (suites in `pkh` and `key`) | yes, all three namespaces |
| `did:key` | Ed25519 (`z6Mk…`), P-256 (`zDn…`) | aqua-auth `key` | yes |
| `did:peer` | numalgo 0, and numalgo 2 (first `V` key) | aqua-auth `peer` | no, opt-in |
| `did:web` | none | not implemented; would need an async resolver | no |

Passkeys produce `did:key:zDn…`, so `"key"` must stay in `supported_did_methods` for passkey
login. None of these is presented here as a finished standard: `did:key` is a W3C Credentials
Community Group draft, CAIP-122 has Review status at the Chain Agnostic Standards Alliance, and
the `ed25519`/`p256` `did:pkh` namespaces are aqua-auth extensions, not CAIP-standard
namespaces. EIP-4361 (Sign-In with Ethereum) is Final.

## Frontend

`js/ui/src/App.svelte` is the login page (Svelte 4, webpack 5, built into `static/build`).

- **Wallet:** `@wagmi/core` with the `injected()` connector, i.e. whatever EIP-1193 wallet the
  browser exposes (MetaMask, Brave, Coinbase extension). The SIWE message is built with
  `viem/siwe` (`createSiweMessage`). There is no WalletConnect/Reown and no project id.
- **Passkey:** the browser WebAuthn API against `/webauthn/authenticate/*`, with a "register a
  new passkey" path. No cookie carries the result; the verified DID stays in Redis.
- **Linking:** after a wallet sign-in the page offers to link a passkey to the wallet DID
  (`/link/webauthn/*`), so later passkey logins resolve to the wallet's account.

Wallet availability is detected locally (is a provider injected?); the server does not predict
which methods a user has. The `/device` approval page and the `/account` page are rendered by
the server (`device_auth.rs`, `account.rs`) with their own inline scripts.

## Redis keyspace

All state lives in one Redis (`redis_url`). Prefixes are defined in `src/db/mod.rs`,
`src/db/grant.rs`, `src/webauthn.rs` and `src/account.rs`.

A credential a client holds (a token, an authorization code, a device or user code, a login
session id, a ceremony id, a server-issued nonce, a client secret, a registration access token)
appears in a key or value only as its lowercase hex SHA-256 (`db::tokens::digest`). Each
digest-keyed prefix differs from the raw-keyed one an earlier build used, which the server still
reads, and uses once, for the entry's remaining lifetime: a client presenting a stored digest as
its credential reads a raw-keyed prefix nothing writes. A client entry keeps its key and stores
its two credentials under member names an earlier build did not use, for the same reason. The
`siwx_user` and `acct_session` cookies are still raw keys. Passkey credential ids are keys too:
they are public identifiers the server hands out in `allowCredentials`, not credentials.

| Key | TTL | Holds |
|---|---|---|
| `session/{sha256(id)}` | 300 s | `SessionEntry`: the CAIP-122 nonce, `verified_did`, sign-in count, and the authorization request `/authorize` bound to it (client, redirect URI, state, response mode, PKCE challenge, scope, OIDC nonce) |
| `session/{sha256(id)}/signed_in` | 300 s | one-shot flag against double sign-in |
| `code/{sha256(code)}` | 300 s | `CodeEntry` (DID, client, PKCE challenge, device id, localpart, requested scope); read and deleted in one atomic step on exchange |
| `sessions/{id}` (+ `/signed_in`), `codes/{code}` (+ `/consumed`) | 300 s | legacy: written by builds before digest keys and read until they expire. A legacy session moves to its digest key on its first write (a wallet sign-in writes none, so a session the previous build started keeps its raw key, spent, until it expires); a legacy signed-in flag still counts; a legacy code is consumed like a new one, unless a `/consumed` marker (left by older builds, which kept exchanged codes) exists. A legacy session holds the scope and the OIDC nonce beside its request; they are read into it |
| `clients/{client_id}` | 30 d | `ClientEntry`: metadata and the digests of the client secret and the registration access token (`secret_digest`, `access_token_digest`); `default_clients` are rewritten, digested, at every start. An entry an earlier build wrote (`secret`, `access_token` in the clear) authenticates as it is and is replaced by its digest-only form, keeping its expiry, on its first read |
| `grant/{sha256(handle)}` | 90 d after the last rotation, never past `absolute_exp`; a grant with no refresh token lives as long as its access token | the grant (`src/db/grant.rs`): kind, owner, client, device id, scope, `auth_time`, `auth_ms` (the authentication in milliseconds, compared with the epochs) and, when a cap applies, `absolute_exp` (all Redis `TIME`), generation, digests of the current and previous refresh token, whether the successor is used, and the sealed successor pair while it is unused. No token is stored |
| `at/{sha256(access token)}` | the token's lifetime: 300 s, admin 30–900 s, never past the grant's `absolute_exp` | grant id, generation, kind, `iat`, `exp` |
| `idx:grants:user/{username}`, `idx:grants:user_device/{username}/{device_id}` | the longest grant TTL written | SETs of grant ids, for atomic revocation |
| `token/{token}`, `idx:user_device/{username}/{device_id}` | access 300 s, refresh 90 d | legacy: tokens written before the grant record (`TokenMetadata`, classified by `db::legacy_token_kind`). Legacy access tokens stay readable until they expire; a legacy refresh token is lifted into a grant when it is first presented, which deletes its entry and index member; revocation still sweeps both keys. Nothing new is written there |
| `legacy_rt/{sha256(legacy refresh token)}` | 90 d from the lift | the grant id a legacy refresh token was lifted into, so a replay of it is judged like the grant's previous token |
| `epoch:global`, `epoch:client/{client_id}`, `epoch:user/{username}` | none | not-before epochs (I9), Unix milliseconds from Redis `TIME`, only moving later: every grant whose `auth_ms` is at or before the largest that applies is refused. `logout/all`, deactivation and erasure set the user epoch; an operator sets the others |
| `tombstone:device/{username}/{device_id}` | 900 s | refuses refresh while a device sweep runs (and the lift of a legacy refresh token of that device) |
| `tombstone:user/{username}` | 900 s | legacy: planted by builds before the user epoch; still read by the rotation and lift scripts for one release, never written |
| `caip122/{category}/{sha256(nonce)}` | 300 s | server-issued nonce for device approval (bound to the user code's digest) and account re-auth (bound to the action); read and deleted on use |
| `device_code/{sha256(device code)}` (+ `/redeemed`) | 1800 s | `DeviceCodeEntry` (RFC 8628, with the user code's digest) and its single-redemption claim |
| `user_code/{sha256(user code)}` | 1800 s | the device code's digest; the user code is hashed exactly as presented |
| `caip122_nonce/{category}/{nonce}` (+ `/consumed`), `device_codes/{device_code}` (+ `/redeemed`), `user_codes/{user_code}` | 300 s / 1800 s | legacy: read until they expire. A legacy device code is found by either code and updated and deleted in place; its claim is digest-keyed, and a legacy claim still counts |
| `account_session/{token}` | 600 s | `/account` session (`acct_session` cookie, `Path=/account`) |
| `user:session/{token}` | 30 d | DID behind the opaque `siwx_user` cookie (passkey-picker scoping) |
| `webauthn:ceremony/{sha256(ceremony id)}` | 120 s | registration or authentication ceremony state, read and deleted in one step; the ceremony id is the `session` cookie, the `session_id` the account re-auth start returns, or `device_passkey_{user_code}` |
| `webauthn:link_ceremony/{sha256(session id)}` | 120 s | link ceremony state |
| `webauthn:challenge/{id}`, `webauthn:link_challenge/{id}` | 120 s | legacy ceremony state, read until it expires |
| `webauthn:credential/{cred_id_b64}` | none | stored passkey (serialized `webauthn_rs::Passkey`) |
| `webauthn:link/{cred_id_b64}` | none | `{primary_did, label}`: the passkey signs in as this DID |
| `webauthn:by_did/{did}` | none | SET of credential ids for a DID (advisory index) |
| `aqua:webauthn:cred:{cred_id_b64}`, `aqua:webauthn:did:{did}` | none | aqua-auth credential store, only when `AQUA_WEBAUTHN_REDIS_URL` is set (may be another Redis) |

Passkeys and links have no TTL but are only as durable as Redis persistence; a flushed Redis
loses them. Troubleshooting commands: [troubleshooting.md](troubleshooting.md).

## Logging

`tracing` with an `EnvFilter` (default `siwx_oidc=info,tower_http=info,warn`, overridden by
`RUST_LOG`) and a human-readable or JSON formatter. Every request and response is logged with
method, path (never the query), status and latency. Credentials appear in logs only as
fingerprints. Level rules: [AGENTS.md](../AGENTS.md#logging-conventions);
settings: [configuration.md](configuration.md#logging).

## Lineage

siwx-oidc began as a fork of [siwe-oidc](https://github.com/spruceid/siwe-oidc) by Spruce
Systems, Inc. and contributors, an Ethereum-only Sign-In with Ethereum OpenID Connect provider
(licensed "MIT OR Apache-2.0", used here under Apache-2.0; `NOTICE` keeps the upstream
notices). Upstream has had no commits since July 2024. siwx-oidc generalised it from Ethereum
addresses to DIDs, added passkeys, RFC 8628 and the Matrix integration, and removed the
Cloudflare Workers target. `wrangler_example.toml` and the `example/demo` relying party were
upstream leftovers that nothing used, and have been removed.

**Breaking changes relative to siwe-oidc:**

1. The `sub` claim is the full DID: `eip155:1:0xAddr` became `did:pkh:eip155:1:0xAddr`.
2. The wallet cookie is `siwx` (was `siwe`), with payload `{did, message, signature}`.
3. `CodeEntry.address` became `CodeEntry.did` (a string). Flush Redis when upgrading.
4. Configuration adds `supported_did_methods` and `supported_pkh_namespaces`.

The configuration prefix and file name still accept the upstream spellings (`SIWEOIDC_`,
`siwe-oidc.toml`); see [configuration.md](configuration.md#names-and-precedence).

**Redis flushes in this project's own history:** two schema changes required or recommended a
flush. The move to refresh tokens changed standalone-mode token storage from `CodeEntry` to
`TokenMetadata` (the old `CodeEntry` path is still read as a fallback), and the Matrix
compliance work made `did` and `name` required fields of `TokenMetadata`. There are no tagged
releases, so a deployment that tracks `main` across such a change should flush Redis, or
accept that existing sessions end.
