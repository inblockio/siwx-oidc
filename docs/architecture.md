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

1. `GET /authorize` validates the client and redirect URI, creates a session (`sessions/{id}`,
   300 s) and sets the `session` cookie, then redirects to the login page with a nonce.
2. The page builds a CAIP-122 message (for Ethereum, an EIP-4361 message) containing the
   nonce, has the wallet sign it, and sets the `siwx` cookie to `{did, message, signature}`.
3. `GET /sign_in` checks the DID method and namespace against configuration, verifies the
   signature through `find_did_method(did).verify(…)`, checks the nonce and that the
   `redirect_uri` is in the message's `Resources:`, then issues a single-use code.
4. `POST /token` exchanges the code, with its PKCE `S256` verifier, for an ES256 ID token, an
   access token and a refresh token. PKCE is mandatory for `response_type=code`: `/authorize`
   refuses a request without a `code_challenge`.

**Server-verified ceremony (passkey):**

1. `GET /authorize` as above.
2. `/webauthn/authenticate/start` and `/finish` run the WebAuthn ceremony. On success the
   server derives `did:key:zDn…` from the passkey's P-256 key (or takes the linked wallet DID,
   see [passkeys.md](passkeys.md)) and stores it as `verified_did` in the session.
3. `GET /sign_in` reads `verified_did` from the session (trusted, server-side) and issues the code.
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
`src/webauthn.rs` and `src/account.rs`.

| Key | TTL | Holds |
|---|---|---|
| `sessions/{id}` | 300 s | `SessionEntry`: nonces, `verified_did`, sign-in count |
| `sessions/{id}/signed_in` | 300 s | one-shot flag against double sign-in |
| `codes/{code}` and `codes/{code}/consumed` | 300 s | `CodeEntry` (DID, client, PKCE challenge, device id, localpart) and its single-use flag |
| `clients/{client_id}` | 30 d | `ClientEntry` (secret, metadata); `default_clients` are rewritten at every start |
| `token/{token}` | access 300 s, refresh 90 d, admin 30–900 s | `TokenMetadata` (username, device id, scope, client, DID) |
| `token_rotated/{old_refresh}` | 60 s | successor pair for a lost refresh response |
| `idx:user_device/{username}/{device_id}` | 90 d | SET of token keys, for atomic revocation |
| `tombstone:device/{username}/{device_id}`, `tombstone:user/{username}` | 900 s | refuse refresh while a revoke or deactivation sweep runs |
| `caip122_nonce/{category}/{nonce}` (+ `/consumed`) | 300 s | server-issued nonce for device approval and account re-auth |
| `device_codes/{device_code}` (+ `/redeemed`) | 1800 s | `DeviceCodeEntry` (RFC 8628) and its single-redemption claim |
| `user_codes/{user_code}` | 1800 s | reverse lookup to the device code |
| `account_session/{token}` | 600 s | `/account` session (`acct_session` cookie, `Path=/account`) |
| `user:session/{token}` | 30 d | DID behind the opaque `siwx_user` cookie (passkey-picker scoping) |
| `webauthn:challenge/{session_id}` | 120 s | registration or authentication ceremony state |
| `webauthn:link_challenge/{session_id}` | 120 s | link ceremony state |
| `webauthn:credential/{cred_id_b64}` | none | stored passkey (serialized `webauthn_rs::Passkey`) |
| `webauthn:link/{cred_id_b64}` | none | `{primary_did, label}`: the passkey signs in as this DID |
| `webauthn:by_did/{did}` | none | SET of credential ids for a DID (advisory index) |
| `aqua:webauthn:cred:{cred_id_b64}`, `aqua:webauthn:did:{did}` | none | aqua-auth credential store, only when `AQUA_WEBAUTHN_REDIS_URL` is set (may be another Redis) |

Passkeys and links have no TTL but are only as durable as Redis persistence; a flushed Redis
loses them. Troubleshooting commands: [troubleshooting.md](troubleshooting.md).

## Logging

`tracing` with an `EnvFilter` (default `siwx_oidc=info,tower_http=info,warn`, overridden by
`RUST_LOG`) and a human-readable or JSON formatter. Every request and response is logged with
method, path, status and latency. Level rules: [AGENTS.md](../AGENTS.md#logging-conventions);
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
