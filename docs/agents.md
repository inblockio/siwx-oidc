# Agents: a Matrix account that is a key

This guide is for people building software agents, bots and services that need
their own identity. With siwx-oidc, an agent signs in with its own Ed25519 or
P-256 key through the `siwx-oidc-auth` client. No browser, password,
registration token or application service is involved.

- [Why a key-held identity](#why-a-key-held-identity)
- [Prerequisites](#prerequisites)
- [Getting an identity](#getting-an-identity)
- [Signing in from the command line](#signing-in-from-the-command-line)
- [Signing in from Rust](#signing-in-from-rust)
- [Refresh, and keeping one device](#refresh-and-keeping-one-device)
- [When a human should own the session: the device flow](#when-a-human-should-own-the-session-the-device-flow)
- [Verifying other parties](#verifying-other-parties)
- [Operational notes](#operational-notes)
- [How bots usually get Matrix identities](#how-bots-usually-get-matrix-identities)
- [Industry context (as of September 2026)](#industry-context-as-of-september-2026)

## Why a key-held identity

- **The key is the account.** The key determines a `did:key` DID, the DID is
  the OIDC `sub`, and the Matrix ID is derived from the DID. Whoever holds the
  key can sign in; nobody has to issue the agent a credential.
- **A full user account.** On a Matrix homeserver that delegates auth to
  siwx-oidc, the first sign-in creates an ordinary user account. It can join
  rooms and take part in end-to-end encryption like any other user.
- **A stable device.** The agent can pin its Matrix device ID, and refresh keeps
  the same device, so its E2EE crypto store stays valid across restarts and
  token rotations.
- **A verifiable binding.** siwx-oidc publishes a provider-signed DID ↔ MXID
  binding in the `io.inblock.did` profile field. Others can check which key
  stands behind the agent's MXID, and the agent can check theirs (see
  [Verifying other parties](#verifying-other-parties)).

## Prerequisites

- A siwx-oidc server with `"key"` in `supported_did_methods` (the default is
  `["pkh", "key"]`).
- For Matrix: the server runs in delegated-auth mode in front of Synapse, with
  `SIWXOIDC_MATRIX_SERVER_NAME` set. See [matrix-integration.md](matrix-integration.md).
- **A registered OIDC client for the agent, as a public client.** The client
  does not send a client secret, and the server requires one unless the client
  was registered with `token_endpoint_auth_method: "none"`. Register one with
  dynamic client registration:

  ```bash
  curl -s -X POST https://auth.example.org/register \
    -H 'Content-Type: application/json' \
    -d '{"redirect_uris": ["https://agent.example.org/callback"],
         "token_endpoint_auth_method": "none"}'
  # -> {"client_id": "…", "client_secret": "…", "registration_access_token": "…", …}
  ```

  Keep the returned `client_id`. The redirect URI must be registered, but
  nothing needs to listen on it: the client reads the authorization code from
  the redirect header and never follows it.

## Getting an identity

Generate a key once and keep it. PKCS#8 PEM is the canonical format; the client
detects Ed25519 or P-256 from the key itself.

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out agent-key.pem        # did:key:z6Mk…
# or P-256:
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out agent-key.pem   # did:key:zDn…

siwx-oidc-auth --print-did --key-file agent-key.pem
# did:key:z6Mk…
```

Key input, highest priority first: `--key-file`, the `SIWX_KEY_FILE`
environment variable, `--key-hex` (a 32-byte seed; for testing only, since it
appears in the process list and shell history), and finally a freshly generated
**ephemeral** key. When the client generates a key it prints the PEM to stderr.
An ephemeral key is a new identity every time it runs.

## Signing in from the command line

```bash
siwx-oidc-auth --server https://auth.example.org \
  --client-id "$CLIENT_ID" \
  --redirect-uri https://agent.example.org/callback \
  --key-file agent-key.pem \
  --device-id MYAGENT01
```

It prints the tokens as JSON on stdout (diagnostics go to stderr):

```json
{ "access_token": "mat_…", "token_type": "Bearer", "id_token": "eyJ…",
  "expires_in": 300, "refresh_token": "mcr_…", "did": "did:key:z6Mk…" }
```

What happens: `GET /authorize` with PKCE (S256) returns a session cookie and a
nonce; the client builds a CAIP-122 message for the server's host with that
nonce and the redirect URI in `Resources:`, signs it with the key, sends it to
`GET /sign_in`, and exchanges the returned code at `POST /token`.

`--device-id` pins the Matrix device ID (see
[below](#refresh-and-keeping-one-device)). Without it, every sign-in creates a
new device named `SIWX_` + 8 hex characters.

The `access_token` is a Matrix access token: use it against the homeserver's
client-server API, where Synapse validates it with siwx-oidc. To learn the
agent's Matrix ID, read `io.inblock.mxid` from `/userinfo`:

```bash
curl -s https://auth.example.org/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"
# { "sub": "did:key:z6Mk…", "io.inblock.mxid": "@1vo8g4vofiha69ua:example.org", … }
```

or call `GET /resolve?did=…` (see [identity-model.md](identity-model.md#looking-up-an-identity-get-resolve)).

The first successful sign-in creates the Matrix account. There is no separate
registration step.

To rotate tokens without signing again:

```bash
siwx-oidc-auth --server https://auth.example.org --client-id "$CLIENT_ID" \
  --refresh-token "$REFRESH_TOKEN" --key-file agent-key.pem
```

The refresh itself does not use the key. The CLI still loads it to report the
`did` in its output, so pass the same `--key-file`; without one it would
generate an ephemeral key and report that key's DID.

## Signing in from Rust

`siwx-oidc-auth` is also a library. It has no crates.io release; depend on it by
git revision:

```toml
[dependencies]
siwx-oidc-auth = { git = "https://github.com/inblockio/siwx-oidc", rev = "<commit>" }
```

```rust
use siwx_oidc_auth::{authenticate_with_device, refresh, SiwxKey};

let key = SiwxKey::from_pem_file("agent-key.pem".as_ref())?;
println!("DID: {}", key.did());

// First sign-in, pinning a stable Matrix device.
let tokens = authenticate_with_device(
    "https://auth.example.org",
    &client_id,
    "https://agent.example.org/callback",
    &key,
    Some("MYAGENT01"),
).await?;

// Later: rotate without signing again. Store the NEW refresh token every time.
let tokens = refresh(
    "https://auth.example.org",
    &client_id,
    tokens.refresh_token.as_deref().expect("server issues refresh tokens"),
    &key.did(),
).await?;
```

| Function | Purpose |
|---|---|
| `SiwxKey::from_pem`, `from_pem_file`, `to_pem` | load or export a PKCS#8 key (Ed25519 or P-256) |
| `SiwxKey::generate_ed25519`, `generate_p256` | new random key |
| `SiwxKey::ed25519_from_hex`, `p256_from_hex` | from a 32-byte hex seed (testing) |
| `SiwxKey::did` | the `did:key:z…` DID |
| `authenticate(server, client_id, redirect_uri, key)` | sign in; new device each time |
| `authenticate_with_device(…, key, Some(device_id))` | sign in with a pinned device ID |
| `refresh(server, client_id, refresh_token, did)` | rotate tokens; `did` is only carried into the result |
| `authenticate_device_flow(server, client_id)` | RFC 8628 device flow (a human approves) |
| `fetch_and_verify_did`, `verify_did_assertion` | verify another account's published DID |

All sign-in functions return `AuthTokens { access_token, token_type, id_token,
expires_in, refresh_token, did }`. A refresh returns no `id_token`.

## Refresh, and keeping one device

Matrix end-to-end encryption is tied to a device: the device's keys live in the
agent's crypto store, and other users verify and trust that device. If every
start of the agent created a new device, its crypto store would no longer match
the server, other users would see a stream of new unverified devices, and
messages encrypted to the old device would be lost to the new one.

Two mechanisms keep the device stable:

- **Pin the device ID** with `--device-id` or `authenticate_with_device`. The
  client requests the scope `urn:matrix:client:device:{id}`, and every sign-in
  re-provisions **that** device. Re-provisioning is an idempotent upsert that
  keeps the device's E2EE keys. Use a stable, short value without spaces, for
  example the service name.
- **Refresh instead of signing in again.** `refresh` (`--refresh-token` on the
  CLI) keeps the device ID and scope of the session.

Token lifetimes:

| | Lifetime |
|---|---|
| Access token | 300 s |
| Refresh token | 90 days from its issue; every refresh issues a new one |
| Lost-response grace | 60 s |

- **Refresh tokens rotate.** Each refresh returns a new refresh token and
  deletes the old one. Persist the new one before using the new access token,
  ideally with an atomic write.
- **Grace window.** If a refresh response is lost, retrying with the old refresh
  token within 60 seconds returns the **same** new pair instead of an error. Two
  processes that refresh with the same token within that window also both get
  the same pair. After 60 seconds the old token is `invalid_grant`.
- **Keep refreshing.** An agent that refreshes at least once every 90 days keeps
  its session indefinitely. After that, sign in again with the key (and the same
  pinned device ID).
- Refresh when the access token is about to expire, or when the homeserver
  answers `M_UNKNOWN_TOKEN`. Synapse caches a token check for up to two minutes,
  so a token can keep working briefly after siwx-oidc stopped accepting it; do
  not rely on that.

Things that end the device:

- `POST /_matrix/client/v3/logout` (if the deployment routes it to siwx-oidc),
  the account page's `device_delete`, and `logout/all` **delete** the Synapse
  device. `POST /oauth2/revoke` only revokes tokens and leaves the device.
- **Do not reuse a deleted device ID.** Synapse keeps a deleted device's
  cross-signing signatures, so a new device with the same ID and new keys ends
  up with verification failures. After deleting a device, pin a new ID and
  start a new crypto store.

## When a human should own the session: the device flow

With the device flow (RFC 8628), the machine holds no key. A person approves the
login on another device with their wallet or passkey, and the session runs as
**that person**.

```bash
siwx-oidc-auth --device-flow --server https://auth.example.org --client-id "$CLIENT_ID"
# To approve this device, open:
#   https://auth.example.org/device?user_code=BCD-FGH
# Waiting for approval (expires in 1800s)...
```

The approval URL and code go to stderr; the tokens go to stdout once approved.
The flow requires the server's delegated-auth mode, and the approving DID must
already have an account (the device flow never creates one).

| Mode | Who owns the identity | DID | Typical use |
|---|---|---|---|
| Key (`--key-file`) | the machine | `did:key:z6Mk…` (Ed25519) or `did:key:zDn…` (P-256) | service accounts, bots, autonomous agents |
| Device flow (`--device-flow`) | the person who approves | their `did:pkh:eip155:1:0x…` (wallet), `did:key:zDn…` (passkey), or the wallet DID a passkey is linked to | CI jobs, remote shells, shared machines acting for a person |

The device flow does **not** give the machine its own DID. Everything it does is
done as the approving person's account.

## Verifying other parties

To find out which DID stands behind a Matrix account:

```bash
siwx-oidc-auth --verify-did '@1vo8g4vofiha69ua:example.org' \
  --homeserver https://matrix.example.org \
  --server     https://auth.example.org   # the issuer you trust
```

In Rust, `fetch_and_verify_did(homeserver, mxid, issuer)` returns a
`VerifiedDid` (`did()`, `mxid()`, `issuer()`, `issued_at()`), or a
`DidAssertionError::FieldAbsent` / `ProofAbsent` you can match on after
`downcast_ref`. No key, token or client ID is needed.

**The trust rule.** A verified binding is a **discovery hint, never an
authorization source**. It proves that the issuer asserted "this DID belongs to
this MXID" at some point. It does not prove that whoever is sending you messages
controls the DID key now. Authorize on the OIDC `sub` of a token this provider
issued to that party, or on a fresh signature by the DID's own key. The
`--server` you pass is your trust anchor: a homeserver operator controls the
issuer their homeserver uses. Full details:
[identity-model.md](identity-model.md#trust-model-a-discovery-hint-never-an-authorization-source).

## Operational notes

- **Key custody.** The PEM file is the account. Keep it readable only by the
  agent's user (`chmod 600`, or `umask 077` before generating), keep it out of
  version control, images and logs, and back it up the way you back up any
  credential. Anyone holding it can sign in as the agent.
- **Losing the key loses the account.** A new key is a new DID, which derives a
  new Matrix ID: a different, empty account. There is no key rotation or
  recovery for a `did:key` identity; the old account's rooms, history and
  device trust stay with the old key. Plan backups accordingly.
- **A leaked key.** Whoever holds a leaked key can sign in as the agent.
  `siwx-oidc-auth` has no command to deactivate the account and siwx-oidc has no
  admin tool for it, so deactivation has to be arranged with the homeserver's
  operator. Move the agent to a new key (and so a new account) afterwards.
- **Display name.** A new account's display name is a generated `Firstname
  Surname` alias. The Matrix device's display name is set to `Element Web` on
  every sign-in through `/sign_in`, whatever the client.
- **A deactivated account cannot sign in**: `/sign_in` answers 401. If Synapse
  cannot be reached for that check, it answers 503; retry later.
- **Common errors** at sign-in, with fixes, are in
  [troubleshooting.md](troubleshooting.md#headless-sign-in-siwx-oidc-auth).

## How bots usually get Matrix identities

For context, these are the common ways bots get identities on Matrix today,
without siwx-oidc:

- **Application services.** A homeserver-registered service with its own tokens
  (`as_token`, `hs_token`) that can act for users in its namespace. Under MAS,
  application services cannot use `m.login.application_service`; end-to-end
  encryption for them depends on MSC4190 and MSC4326 (spec v1.17), and MSC3202
  (encrypted appservices) is still open.
- **Ordinary accounts with passwords** (`m.login.password`), which under MAS go
  through its compatibility layer.
- **Under MAS: operator-issued tokens.** Personal access tokens issued by an
  administrator (MAS 1.5.0 and later; self-service is not implemented yet), or
  `mas-cli manage issue-compatibility-token`.
- **Interactive OAuth grants** (authorization code, device code), which MAS
  documents as not meant for automation.

Password and token-based bots are ordinary devices too: they need a persistent
device and crypto store, and a fresh login creates a new device. The difference
with siwx-oidc is who issues the credential. Here the agent proves possession
of its own key at every sign-in, and no operator has to hand it a bearer secret.

## Industry context (as of September 2026)

Identifying automated clients by their own signing key, rather than by a shared
secret or an IP address, is being standardised on the web:

- **RFC 9421** "HTTP Message Signatures" (Proposed Standard, February 2024).
- **Cloudflare Web Bot Auth** (May 2025) signs agent HTTP requests with RFC 9421
  and publishes keys in a directory. Adopters with public documentation include
  OpenAI's ChatGPT agent, Visa's Trusted Agent Protocol (October 2025),
  Mastercard Agent Pay, Amazon Bedrock AgentCore Browser (preview, October
  2025), Akamai (verification at its edge, November 2025), and Google
  (experimental, for a subset of `Google-Agent` requests).
- The **IETF `webbotauth` working group** was chartered on 2025-10-23. Its first
  working-group draft, `draft-ietf-webbotauth-httpsig-protocol-00` ("HTTP
  Message Signatures for automated traffic"), was adopted on 2026-09-01. It is a
  draft, not a standard.

**siwx-oidc does not implement RFC 9421 or Web Bot Auth.** It authenticates an
agent with a CAIP-122 signature over the OIDC authorization-code flow and then
issues bearer tokens. The same key can also sign individual HTTP requests with
the *experimental* `http-sig` feature of
[aqua-auth](https://github.com/inblockio/aqua-rs-auth), the library siwx-oidc
uses for signature verification. siwx-oidc itself does not use that feature, and
no interoperability with third-party Web Bot Auth verifiers is claimed here.

Sources: [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421);
[Cloudflare: Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/),
[verified bots with cryptography](https://blog.cloudflare.com/verified-bots-with-cryptography/),
[signed agents](https://blog.cloudflare.com/signed-agents/),
[secure agentic commerce](https://blog.cloudflare.com/secure-agentic-commerce/);
[Visa Trusted Agent Protocol](https://usa.visa.com/about-visa/newsroom/press-releases.releaseId.21716.html);
[Amazon Bedrock AgentCore Browser](https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-browser-web-bot-auth-preview);
[Akamai](https://www.akamai.com/blog/security/redefine-trust-web-bot-authentication);
[Google](https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth);
[IETF webbotauth](https://datatracker.ietf.org/wg/webbotauth/about/),
[draft-ietf-webbotauth-httpsig-protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/).
