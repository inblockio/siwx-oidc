# siwx-oidc

**Key-first OpenID Connect provider and Matrix auth service: agents and people sign in with
their own key, no passwords.**

**siwx-oidc** is an OpenID Connect provider where the account *is* a key. People sign in with a
passkey or a wallet; software agents sign in with their own Ed25519/P-256 key, no browser and no
password. Every identity is a DID, carried as the OIDC `sub`. For Matrix it takes the place of
the Matrix Authentication Service (MAS) as Synapse's auth service, so giving an AI agent a full
end-to-end-encrypted Matrix account takes one key pair — and it publishes a signed DID↔MXID
binding anyone can verify.

> [!IMPORTANT]
> **Status: pathfinder project, non-commercial, provided as is.**
> siwx-oidc is a pathfinder project for agent identity on Matrix, run by inblock.io assets GmbH
> on a non-commercial basis. It is provided **as is**, without warranty (Apache-2.0 §§7–8).
> There is **no support offering, no SLA, and no commitment to maintain it for third-party
> deployments**: the maintainers maintain it for their own use (inblock.io runs it for its own
> people and AI agents), and interfaces may change without notice. There are no tagged releases
> yet; `main` is what runs. Contributions and security reports are welcome and handled
> best-effort.

## Matrix accounts for AI agents

An agent's key is its account. With `siwx-oidc-auth` (CLI and Rust library in this repository),
a software agent signs in headlessly with its own Ed25519 or P-256 key:

- **No password, registration token or appservice.** The agent's DID (`did:key:z6Mk…` for
  Ed25519, `did:key:zDn…` for P-256) is derived from its public key, and its Matrix ID is derived
  from the DID. The first sign-in creates the account.
- **No browser.** The client runs the OIDC authorization-code flow with PKCE and signs a
  CAIP-122 challenge locally.
- **A full Matrix user account.** It is an ordinary Synapse user, not a bridge or an appservice
  puppet, so the agent's Matrix client can join rooms and use end-to-end encryption like any
  other client.
- **A stable device.** Refreshing tokens keeps the Matrix device ID, so the agent's E2EE crypto
  store stays valid. `--device-id` pins one device across full re-authentications as well.
  Access tokens live 5 minutes; refresh tokens live 90 days and rotate on every use.
- **A verifiable binding.** siwx-oidc publishes a provider-signed `io.inblock.did` field in the
  agent's profile. With it, `GET /resolve` and `siwx-oidc-auth --verify-did` let others check
  which key stands behind an MXID (see [Identity model](#identity-model)).

### Example

```bash
# Build the client (from a checkout of this repository)
cargo install --path siwx-oidc-auth

# The key is the account: generate it once and keep it safe
openssl genpkey -algorithm Ed25519 -out agent.pem
siwx-oidc-auth --print-did --key-file agent.pem
# did:key:z6Mk…

# Register an OAuth client once. A public client: the agent holds no client secret.
# The redirect URI is never visited, but it must be registered and passed below.
curl -s -X POST https://siwx.example.com/register -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost/callback"],"token_endpoint_auth_method":"none",
       "grant_types":["authorization_code","refresh_token"],"response_types":["code"]}'
# {"client_id":"…", …}

# Sign in, pinning a stable Matrix device ID
siwx-oidc-auth --server https://siwx.example.com --client-id "$CLIENT_ID" \
  --redirect-uri http://localhost/callback --key-file agent.pem --device-id my-agent
# prints JSON: access_token, token_type ("bearer"), id_token, expires_in, refresh_token, did

# Later: new tokens without signing again; the device stays the same
siwx-oidc-auth --server https://siwx.example.com --client-id "$CLIENT_ID" \
  --refresh-token "$REFRESH_TOKEN" --key-file agent.pem
```

The `access_token` is the agent's Matrix access token; `GET /_matrix/client/v3/account/whoami`
on the homeserver returns its MXID and device ID. The same flow as a library call:

```rust
use siwx_oidc_auth::{authenticate_with_device, refresh, SiwxKey};

let key = SiwxKey::from_pem_file("agent.pem".as_ref())?;
let tokens = authenticate_with_device(
    "https://siwx.example.com", &client_id, "http://localhost/callback",
    &key, Some("my-agent"),
).await?;
// ...later, when the access token expires:
let tokens = refresh(
    "https://siwx.example.com", &client_id,
    tokens.refresh_token.as_deref().expect("refresh token"), &key.did(),
).await?;
```

The full agent guide, including the device-code flow for a human approving a headless machine,
is [docs/agents.md](docs/agents.md).

### Key-first agent identity on the web

Identifying an agent by a key it holds is also how AI agents are starting to identify themselves
to websites. Cloudflare introduced [Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/) in
May 2025, built on [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures).
OpenAI's ChatGPT agent was in the first cohort of Cloudflare's
[signed agents](https://blog.cloudflare.com/signed-agents/) (August 2025);
[Visa's Trusted Agent Protocol](https://usa.visa.com/about-visa/newsroom/press-releases.releaseId.21716.html)
(October 2025) builds on the same standard; Amazon Bedrock AgentCore Browser
[signs requests in preview](https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-browser-web-bot-auth-preview)
(October 2025), and [Google](https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth)
signs some agent requests experimentally. The IETF chartered the
[`webbotauth` working group](https://datatracker.ietf.org/wg/webbotauth/about/) on 2025-10-23;
its first working-group draft appeared on 2026-09-01.

siwx-oidc itself does **not** implement RFC 9421 or Web Bot Auth. Its agent path is CAIP-122
over the OIDC authorization-code flow. The same key can also sign HTTP requests through the
*experimental* `http-sig` feature of [aqua-auth](https://github.com/inblockio/aqua-rs-auth), the
crate siwx-oidc builds on; siwx-oidc does not use that feature, and nothing here has been tested
against third-party verifiers.

## People

People sign in on the login page, or approve a sign-in for another device.

| Method | Identity | Notes |
|---|---|---|
| Passkey (WebAuthn) | `did:key:zDn…` (P-256) | Register on the login page. A passkey can be linked to a wallet; it then signs in as the wallet's DID. |
| Wallet (CAIP-122 / Sign-In with Ethereum) | `did:pkh:eip155:1:0x…` | Browser wallets through EIP-1193 (for example MetaMask). |
| Device code / QR (RFC 8628) | the approving person's DID | Used by Element X's QR login and by `siwx-oidc-auth --device-flow` on machines without a browser. |

New accounts are created only through the login flow, at the first sign-in. A passkey sign-in
on the login page asks the user to confirm first (the page enforces this, not the server); a
wallet sign-in and an agent's headless sign-in create the account directly, with no confirmation
step. The account page and the device approval page refuse identities that have no account yet.
Accepted DID methods are configurable (`supported_did_methods`, default `["pkh","key"]`;
`did:peer` is available opt-in). Besides `eip155`, `did:pkh` accepts `ed25519` and `p256`
namespaces, which are aqua-auth extensions, not registered CAIP namespaces. See
[docs/passkeys.md](docs/passkeys.md).

## Identity model

Every user carries three identifiers with three different owners:

| Tier | Example | Owner | Mutable | Where it lives |
|---|---|---|---|---|
| Alias | `Firstname Surname`, generated from the DID | the user | yes | Synapse `displayname` |
| MXID | `@k3f9x2q7ab4d8m1p:example.org` (16 base36 characters from SHA-256 of the DID) | derived | no | Synapse user |
| DID | `did:key:z6Mk…`, `did:pkh:eip155:1:0x…` | the provider (signed binding) | no | OIDC `sub`; Synapse profile field `io.inblock.did` |

On every sign-in, siwx-oidc writes `io.inblock.did` into the user's Matrix profile: the exact DID
plus a compact ES256 JWS that binds it to that one MXID, signed with the provider's key (there is
no proof when the provider runs with an ephemeral key). The field is world-readable and federates,
so it never carries anything private. It is a **discovery hint, never an authorization source**:
authorize from the `sub` of a token this provider issued, or from a fresh signature by the DID's
key. `GET /resolve?did=…` or `?mxid=…` answers the lookup in either direction without
authentication and checks no signature; `siwx-oidc-auth --verify-did` checks the signature, the
issuer and the MXID binding. When a Matrix server name is configured, `/userinfo` also returns
the caller's MXID as the `io.inblock.mxid` claim. Accounts created before the current MXID
scheme keep their older localpart. The wire contract is in
[docs/identity-model.md](docs/identity-model.md).

## Matrix integration

siwx-oidc implements the Matrix OAuth 2.0 authentication API (Matrix spec v1.15 and later:
MSC3861 and its sub-proposals) and acts as the auth service in Synapse's
`matrix_authentication_service` integration:

```yaml
# homeserver.yaml
matrix_authentication_service:
  enabled: true
  endpoint: http://siwx-oidc:8000/   # where Synapse reaches siwx-oidc
  secret: "<shared secret>"          # the same value as SIWXOIDC_MAS_SHARED_SECRET
```

On the siwx-oidc side, `SIWXOIDC_MAS_SHARED_SECRET`, `SIWXOIDC_SYNAPSE_ENDPOINT` and
`SIWXOIDC_MATRIX_SERVER_NAME` turn the Matrix role on. In that role siwx-oidc answers Synapse's
token introspection, creates users and devices through Synapse's `/_synapse/mas/*` API at sign-in
(a fresh device per login unless the client pins one; device IDs are never recycled), serves the
device authorization grant (RFC 8628), account-management deep links (MSC4191) including
cross-signing reset (MSC4312), and token revocation, and mints short-lived admin-scoped tokens for
its own calls to Synapse's admin API. Details:
[docs/matrix-integration.md](docs/matrix-integration.md).
A complete Docker Compose deployment (Synapse, Element Web, siwx-oidc, Redis, Caddy) is
[siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server).

### What it depends on

- **Synapse.** Tested with Synapse 1.159 and 1.161. The integration uses Synapse's stable
  `matrix_authentication_service` block (available since 1.136); versions before 1.157 are
  untested. The bundled deployment runs 1.161.0. 1.157.0 removed the experimental
  `experimental_features.msc3861` mode.
- **An internal Synapse API.** Synapse's side of this integration (`/_synapse/mas/*`) is an
  internal API designed for MAS (Synapse 1.135.0 changelog), not a public, stable interface.
  siwx-oidc tracks it per Synapse release, so every Synapse upgrade is a compatibility check.
- **A patched Synapse, for write protection of `io.inblock.did`.** Stock Synapse lets users
  write any custom profile field, including this one. The bundled image carries a backport of
  [element-hq/synapse#19980](https://github.com/element-hq/synapse/pull/19980) (open) that denies
  users writes to it. Without the patch the field is still published and signed; a verifier
  rejects a tampered or copied value, and the user's next sign-in writes it back. Registry:
  [patches/synapse](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/synapse/README.md).
  The bundled Element Web build also carries patches:
  [patches/element-web](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/element-web/README.md).
- **Redis** holds all server state: clients, sessions, tokens and passkey credentials.
- **aqua-auth**, the external crate that parses DIDs and verifies CAIP-122 signatures and
  passkey assertions, pinned to tag `v0.7.0` of
  [inblockio/aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth).

### What it does not do

- No password login and no password registration.
- No upstream identity providers ("sign in with Google/Keycloak").
- No admin REST API or admin UI, and no client-credentials grant.
- No legacy `POST /_matrix/client/v3/login`. Clients that do not speak the Matrix OAuth 2.0 API
  cannot sign in.
- Only Synapse is tested. Tuwunel, Dendrite and Conduit are untested and unsupported.
- `/account` advertises two actions that are **not in the Matrix spec**,
  `org.matrix.account_erase` and `org.matrix.account_reactivate`. They are project-specific
  despite their prefix.

## Why not MAS?

[MAS](https://github.com/element-hq/matrix-authentication-service) (Matrix Authentication
Service) is Element's authentication service for Synapse, licensed AGPL-3.0-or-later or under a
commercial license. The two overlap on the Matrix OAuth plumbing and differ on the identity
model. MAS is a full account system; siwx-oidc makes a key the account and lacks most of MAS's
operator surface.

| | MAS | siwx-oidc |
|---|---|---|
| Headless sign-in with the agent's own key | No: bots use operator-issued personal access tokens, compatibility tokens or passwords | Yes (`siwx-oidc-auth`) |
| DID as the account identity | No | Yes: `sub` is the DID, the MXID is derived from it |
| Passkeys, wallets | Not natively (passkeys are an open draft PR) | Yes |
| Password login, registration controls, upstream IdPs | Yes | No |
| Legacy `/login` for non-OAuth clients | Yes (compatibility layer) | No |
| Admin API and UI, policy engine | Yes | No |
| Scale and support | Runs matrix.org; commercial support from Element | One organisation's deployment; no support offering |

The other way round is also possible in principle: MAS stays Synapse's auth service and uses
siwx-oidc as an upstream OIDC provider. This topology is untested. People would keep signing in
with passkeys and wallets, through MAS's login page. Headless agent sign-in with the agent's own
key would break, because MAS's upstream login is an interactive browser redirect; the DID would
stop being the account and become a linked upstream identity; and `io.inblock.did` publication
would break as built, because Synapse would introspect tokens at MAS. Sources and the full
analysis: [docs/comparison.md](docs/comparison.md).

## Quick start

### Server

```bash
docker run -d --name siwx-redis -p 6379:6379 redis   # or any Redis on localhost:6379
SIWXOIDC_BASE_URL=http://localhost:8000 cargo run --bin siwx-oidc
curl -s http://localhost:8000/.well-known/openid-configuration
```

Set the base URL to a host name: WebAuthn does not accept an IP literal such as the default
`http://127.0.0.1:8000` as its relying-party ID, and the server panics at startup with it. The
browser sign-in page (passkey, wallet) needs the frontend built once:
`cd js/ui && npm install && npm run build`. Agents do not need it.

Configuration comes from `siwx-oidc.toml` or `SIWXOIDC_*` environment variables. Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `SIWXOIDC_BASE_URL` | `http://127.0.0.1:8000` | Issuer URL; also the WebAuthn relying party |
| `SIWXOIDC_REDIS_URL` | `redis://localhost` | Redis connection |
| `SIWXOIDC_SIGNING_KEY_PEM` | generated at startup | ES256 signing key (PKCS#8 PEM). Set it in production: without it the key changes on every restart and no `io.inblock.did` proof is minted |
| `SIWXOIDC_SUPPORTED_DID_METHODS` | `["pkh","key"]` | DID methods accepted at sign-in |
| `SIWXOIDC_MATRIX_SERVER_NAME` | none | Matrix `server_name`; needed for MXIDs and DID publication |
| `SIWXOIDC_MAS_SHARED_SECRET` | none | Shared secret with Synapse; turns on introspection |

The legacy `SIWEOIDC_*` prefix and `siwe-oidc.toml` inherited from siwe-oidc are still read, with
no removal scheduled; when both prefixes set the same key, `SIWXOIDC_*` wins, and a startup
warning names the legacy variables in use. Full reference:
[docs/configuration.md](docs/configuration.md).

### Docker

`ghcr.io/inblockio/siwx-oidc:latest` is published from `main` (also tagged `main` and by commit).

```bash
docker network create siwx
docker run -d --name redis --network siwx redis
docker run --rm --network siwx -p 8000:8000 \
  -e SIWXOIDC_BASE_URL=http://localhost:8000 \
  -e SIWXOIDC_REDIS_URL=redis://redis:6379 \
  ghcr.io/inblockio/siwx-oidc:latest
```

The `SIWXOIDC_` names need an image built with the `SIWXOIDC_` rename or later; older images
read only `SIWEOIDC_`, which remains accepted either way.

### Agent client

See [Matrix accounts for AI agents](#matrix-accounts-for-ai-agents) above and
[docs/agents.md](docs/agents.md). `siwx-oidc-auth --help` lists every flag.

## Documentation

| Page | Content |
|---|---|
| [docs/README.md](docs/README.md) | Index of all documentation |
| [docs/agents.md](docs/agents.md) | Agent guide: `siwx-oidc-auth` CLI and library, device stability, refresh, verifying DIDs |
| [docs/identity-model.md](docs/identity-model.md) | The three tiers, the `io.inblock.did` wire contract, trust model, `/resolve`, `io.inblock.mxid` |
| [docs/matrix-integration.md](docs/matrix-integration.md) | Synapse wiring, dependencies, token model, device lifecycle, account management, QR login |
| [docs/passkeys.md](docs/passkeys.md) | WebAuthn architecture, passkey linking, picker scoping, new-account gate |
| [docs/configuration.md](docs/configuration.md) | Every setting, legacy names, key rotation, reverse proxy and CORS, Docker |
| [docs/architecture.md](docs/architecture.md) | Layers, code map, DID methods, frontend, Redis keyspace, lineage |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Passkey, QR, wallet and OIDC failures |
| [docs/comparison.md](docs/comparison.md) | MAS comparison and the MAS-first option, with sources |
| [docs/api/](docs/api/) | HTTP API: [openapi.yaml](docs/api/openapi.yaml) (enforced against the router) and a [guide](docs/api/README.md) |
| [docs/design/](docs/design/) | Design notes |
| [docs/audits/](docs/audits/) | Dated audits and live probes |
| [security/](security/) | Accepted advisory exceptions and VEX statements |
| [AGENTS.md](AGENTS.md) | Code rules and invariants for human and AI contributors |

## Workspace

| Crate | Contents |
|---|---|
| `siwx-oidc` (root) | The server (`siwx-oidc` binary, Axum + Redis) and `migrate-credentials`, a one-shot operator tool for the passkey credential store |
| `siwx-oidc-auth` | Headless client: Rust library and CLI (sign-in, refresh, device flow, DID verification) |

The browser sign-in page is a Svelte app in `js/ui/`, built into `static/`. CAIP-122 verification
and DID parsing live in the external aqua-auth crate.

## Lineage

siwx-oidc began as a fork of [siwe-oidc](https://github.com/spruceid/siwe-oidc) by Spruce
Systems, an OpenID Connect provider for Sign-In with Ethereum. Upstream has had no commits since
July 2024. siwx-oidc generalised it from Ethereum addresses to DIDs (`sub` is now a DID) and added
passkeys, the device authorization grant, refresh tokens, the headless client, the Matrix auth
service role and DID publication. The breaking changes against siwe-oidc are listed in
[docs/architecture.md](docs/architecture.md).

## Contributing, security, license

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), not in public issues.

Licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
