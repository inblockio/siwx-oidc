# siwx-oidc and MAS: comparison and options

Facts on this page are as of **2026-09-29**. MAS facts refer to its `main` branch on 2026-09-28
(latest stable release v1.25.1, 2026-09-21); siwx-oidc facts refer to this repository at that
date. Each claim links its source; the [Sources](#sources) section lists them together. If
something here is out of date, please open an issue.

## Short version

siwx-oidc and MAS overlap on the Matrix OAuth 2.0 plumbing and differ on the identity model.

[MAS](https://github.com/element-hq/matrix-authentication-service) (Matrix Authentication
Service) is Element's account system for Synapse: passwords, registration controls, upstream
identity providers, an admin API and UI, a compatibility layer for legacy clients, and operation
at matrix.org scale. siwx-oidc is an OpenID Connect provider whose account *is* a cryptographic
key, for people (passkeys, wallets) and for software agents (a local Ed25519 or P-256 key). MAS
has no native passkeys, wallets or DIDs, and no non-interactive user login with a key the user
holds. siwx-oidc lacks most of MAS's operator surface.

Neither is a drop-in replacement for the other.

## What each project is

**MAS** is "a user management and authentication service for Matrix homeservers, written and
maintained by Element" ([README](https://github.com/element-hq/matrix-authentication-service)).
It was "created to support the migration of Matrix to a next-generation of auth APIs per
MSC3861" and is "not intended to be a general purpose Identity Provider"
([architecture](https://element-hq.github.io/matrix-authentication-service/development/architecture.html)).
It is licensed AGPL-3.0-or-later or under an Element commercial license, reached v1.0.0 on
2025-08-13, and ships as part of Element Server Suite. matrix.org moved to MAS on 2025-04-07,
shifting "all 45M access tokens and 110M users from Synapse to MAS in under 30 minutes"
([matrix.org blog](https://matrix.org/blog/2025/04/morg-now-running-mas/)). It stores its state
in PostgreSQL and supports Synapse 1.136.0 or later
([homeserver setup](https://element-hq.github.io/matrix-authentication-service/setup/homeserver.html)).

**siwx-oidc** is an OpenID Connect provider in which every identity is a DID carried as the
OIDC `sub`. It is a pathfinder project run by inblock.io assets GmbH on a non-commercial basis,
at crate version 0.2.0 with no tagged releases, licensed Apache-2.0. It stores its state in Redis.
It has one known production deployment: its maintainers' own.

## How Synapse delegates authentication

Both take the same slot in Synapse, so the mechanism matters for the comparison.

- Synapse 1.136.0 (2025-08-12) stabilised delegation as the `matrix_authentication_service`
  config block (`enabled`, `endpoint`, `secret`) and deprecated the experimental
  `experimental_features.msc3861` block
  ([upgrade notes](https://element-hq.github.io/synapse/latest/upgrade.html#upgrading-to-v11360)).
  Synapse 1.157.0 (2026-07-21) removed the experimental block
  ([upgrade notes](https://element-hq.github.io/synapse/latest/upgrade.html#upgrading-to-v11570)).
- Synapse calls `{endpoint}/.well-known/openid-configuration` and
  `{endpoint}/oauth2/introspect` with the shared secret. The auth service calls back into
  Synapse's `/_synapse/mas/*` endpoints to create users and devices. Synapse describes that API
  as "a dedicated internal API for Matrix Authentication Service to Synapse communication"
  (1.135.0 changelog, [#18520](https://github.com/element-hq/synapse/pull/18520)); it is not a
  documented public interface.
- MSC3861 itself was accepted and merged into Matrix spec v1.15 (2025-06-26) together with its
  sub-proposals ([changelog](https://spec.matrix.org/v1.15/changelog/v1.15/)).

For siwx-oidc this means: it implements the auth-service side of an interface that Synapse calls
internal and documents for MAS. The interface changed materially between Synapse 1.135 and 1.157,
so every Synapse upgrade is a compatibility check for siwx-oidc. We found no Element statement on
third-party implementations of it, either way.

## Capability comparison

| Capability | MAS | siwx-oidc |
|---|---|---|
| Matrix OAuth 2.0 API (spec v1.15+) as Synapse's auth service | Yes | Yes |
| Headless sign-in with the user's **own key** | No. Interactive grants are "not meant for automation"; bots use admin-issued personal access tokens (since v1.5.0), `mas-cli manage issue-compatibility-token`, or passwords ([authorization](https://element-hq.github.io/matrix-authentication-service/topics/authorization.html), [CLI](https://element-hq.github.io/matrix-authentication-service/reference/cli/manage.html)) | Yes: `siwx-oidc-auth` runs the authorization-code flow with PKCE and signs a CAIP-122 challenge with a local Ed25519/P-256 key; refresh keeps the device ([`lib.rs`](../siwx-oidc-auth/src/lib.rs)) |
| DID as the account identity | No. `sub` is MAS's own user; an upstream subject is a linked identity | Yes: `sub` is the DID and the MXID is derived from it ([`mxid.rs`](../src/mxid.rs)) |
| Published, provider-signed DID↔MXID binding | No | Yes: the `io.inblock.did` profile field ([`did_assertion.rs`](../src/did_assertion.rs)), plus `GET /resolve` ([`resolve.rs`](../src/resolve.rs)) |
| Passkeys (WebAuthn) | Not shipped: "If you need some other feature that MAS doesn't support (such as TOTP or WebAuthn) …" ([architecture](https://element-hq.github.io/matrix-authentication-service/development/architecture.html)); draft PR [#4234](https://github.com/element-hq/matrix-authentication-service/pull/4234) open | Yes, did:key P-256, with linking to a wallet DID ([`webauthn.rs`](../src/webauthn.rs)) |
| Wallets (CAIP-122 / Sign-In with Ethereum) | No native support | Yes (`did:pkh`) |
| Device authorization grant (RFC 8628) | Yes, on by default | Yes ([`device_auth.rs`](../src/device_auth.rs)) |
| Account management deep links (MSC4191) | Yes | Yes, plus two actions that are not in the spec: `org.matrix.account_erase`, `org.matrix.account_reactivate` ([`account.rs`](../src/account.rs)) |
| Local password login and registration | Yes (password registration off by default; email, registration tokens, CAPTCHA) ([configuration](https://element-hq.github.io/matrix-authentication-service/reference/configuration.html)) | No passwords. An account is created at first sign-in; only the browser passkey login asks for a confirmation first (enforced by the login page), while wallet and headless sign-ins create it directly |
| Upstream OIDC identity providers | Yes, several, with claim mapping ([SSO setup](https://element-hq.github.io/matrix-authentication-service/setup/sso.html)) | No |
| Legacy `/login` for non-OAuth clients | Yes, compatibility layer (`m.login.password`, `m.login.sso`, `m.login.token`) | No. `GET /_matrix/client/v3/login` answers for discovery, but there is no `POST /login`; legacy clients cannot sign in ([`compat.rs`](../src/compat.rs)) |
| Client-credentials grant | Yes (useful for MAS's admin API; Synapse requires a user on the session) | No |
| Admin tooling | Admin REST API (OpenAPI), Element Admin UI, `mas-cli`, policy engine, rate and session limits ([admin API](https://element-hq.github.io/matrix-authentication-service/topics/admin-api.html)) | None beyond a self-minted, short-lived (30–900 s) Synapse admin token for its own calls ([`admin_token.rs`](../src/admin_token.rs)) |
| Storage | PostgreSQL | Redis |
| Homeservers | Synapse ≥ 1.136.0 | Synapse (tested with 1.159 and 1.161; versions before 1.157 untested); other homeservers untested |
| Maturity and support | v1.0 in 2025-08, v1.25.1 in 2026-09; runs matrix.org; commercial support from Element | Version 0.2.0, no releases; one organisation's deployment; no support offering |
| License | AGPL-3.0-or-later or commercial | Apache-2.0 |

## How bots get a Matrix account today

For context on the first rows above:

- **Application services** register with the homeserver and use `as_token`/`hs_token`
  ([Application Service API](https://spec.matrix.org/latest/application-service-api/)). Under
  MAS, `m.login.application_service` is not available, so appservice E2EE moves to
  MSC4190/MSC4326 device management
  ([MAS docs](https://element-hq.github.io/matrix-authentication-service/as-login.html)).
- **Password accounts** keep working under MAS through its compatibility layer;
  [areweoidcyet.com](https://areweoidcyet.com/) notes that `m.login.password` "isn't going away".
- **Personal access tokens** in MAS are admin-issued; self-service is not implemented yet
  ([#4492](https://github.com/element-hq/matrix-authentication-service/issues/4492)). They and
  compatibility tokens are bearer credentials issued by an operator, not proof that the bot holds
  a key.
- **siwx-oidc** lets the bot prove possession of its own key at every sign-in. The account is
  derived from the key, so there is nothing for an operator to issue.

## What siwx-oidc lacks that MAS has

Password login and self-registration controls (email verification, registration tokens,
CAPTCHA); upstream identity-provider federation; an admin REST API and UI; personal access tokens;
a full legacy `/login` compatibility layer (legacy clients cannot sign in to siwx-oidc); a policy
engine; the client-credentials grant; session limits and inactivity expiry; `syn2mas` migration
tooling; translations; commercial support; proven operation at matrix.org scale; and being the
service Synapse's integration is designed and versioned against.

## The MAS-first option

Instead of taking MAS's place, siwx-oidc could sit behind MAS as an upstream identity provider:

```
Synapse --matrix_authentication_service--> MAS --upstream_oauth2--> siwx-oidc
```

siwx-oidc would then no longer talk to Synapse. **This topology is untested.** From the MAS
configuration reference it looks plausible: MAS upstream providers support
`client_secret_post` and PKCE, both of which siwx-oidc supports (siwx-oidc requires S256 PKCE);
MAS's `id_token_signed_response_alg` defaults to RS256 and would have to be set to ES256, the only
algorithm siwx-oidc signs with. Whether MAS's default strict discovery validation accepts
siwx-oidc's metadata is not verified.

**What would keep working**

- People signing in with passkeys and wallets, through a provider button or redirect on MAS's
  login page (one more hop and MAS's own screens). Linked passkeys still resolve to the wallet DID
  inside siwx-oidc.
- Device-code and QR login, as MAS's device grant; the approving browser session is at MAS and
  redirects to siwx-oidc to authenticate.
- Account management (MSC4191), provided by MAS for the actions MAS supports.
- Everything MAS adds: optional passwords, other upstream providers, admin API and UI, personal
  access tokens, the compatibility layer, the policy engine, commercial support.
- siwx-oidc as a plain OIDC provider for other relying parties.

**What would break or degrade**

- **Headless agent sign-in with the agent's own key: breaks.** MAS offers no non-interactive user
  grant, and upstream login is a browser redirect through MAS's HTML pages. Agents would fall back
  to operator-issued personal access tokens or compatibility tokens, which are bearer credentials
  not bound to the agent's key.
- **The DID as the account: degrades.** MAS owns the account and Synapse sees MAS's user; the DID
  survives only as the linked upstream subject. MAS's default localpart template would take the
  DID, which is not a valid Matrix localpart
  ([user identifier grammar](https://spec.matrix.org/latest/appendices/#user-identifiers):
  DIDs contain `:`, and `did:key` contains uppercase). A custom template built from siwx-oidc's
  `io.inblock.mxid` userinfo claim might work; that claim needs a configured Matrix server name,
  and the combination is untested.
- **`io.inblock.did` publication: breaks as built.** siwx-oidc writes the field with an
  admin-scoped token that Synapse introspects at siwx-oidc. Under MAS-first, Synapse introspects
  at MAS, so those tokens are rejected. A replacement would need a MAS-issued admin-scoped token
  and a separate publisher, because MAS imports only localpart, display name, email and account
  name from upstream claims.
- **`GET /resolve`: degrades.** Its `?did=` path asks Synapse's `/_synapse/mas/*` API whether the
  localpart exists, using the shared secret, which siwx-oidc would no longer hold.
- siwx-oidc's account extras (erase with passkey purge, reactivate) and its login-only
  new-account gate would be replaced by MAS's behaviour.
- Two identity systems to operate (MAS with PostgreSQL, siwx-oidc with Redis), and an extra
  redirect on every human sign-in.

In that topology siwx-oidc would become a pure OIDC provider for DID-based sign-in (passkey,
wallet, headless key), usable by MAS or any other relying party. Its Synapse-specific parts
(introspection for Synapse, the admin-token mint, the Synapse client, the compatibility routes,
device provisioning, the `/account` Synapse actions, DID publication) would go unused.

## Other homeservers

siwx-oidc is tested only with Synapse. Tuwunel has its own built-in OAuth 2.0/OIDC server and can
use MAS as an upstream identity provider; separately, it implements a "private compatibility API"
so that MAS can provision users
([Tuwunel docs](https://matrix-construct.github.io/tuwunel/authentication/oidc-server.html)).
siwx-oidc has not been tried with it. [areweoidcyet.com](https://areweoidcyet.com/) lists Dendrite
and Conduit as not supporting the OAuth 2.0 API.

## Other OIDC providers

MAS documents that "any OIDC compliant provider should work" as an upstream, as long as it
supports the authorization-code flow, and suggests pairing MAS with Dex or Keycloak for SAML or
LDAP ([SSO setup](https://element-hq.github.io/matrix-authentication-service/setup/sso.html)). A
general-purpose provider in that slot inherits the MAS-first trade-offs above.

An earlier version of this page (2026-05-25) also surveyed wallet- and DID-to-OIDC projects. That
survey was removed in this revision because its claims could not be re-verified; it remains in the
git history.

## Sources

- MAS: [README](https://github.com/element-hq/matrix-authentication-service) ·
  [architecture](https://element-hq.github.io/matrix-authentication-service/development/architecture.html) ·
  [authorization and sessions](https://element-hq.github.io/matrix-authentication-service/topics/authorization.html) ·
  [configuration reference](https://element-hq.github.io/matrix-authentication-service/reference/configuration.html) ·
  [SSO / upstream providers](https://element-hq.github.io/matrix-authentication-service/setup/sso.html) ·
  [homeserver setup](https://element-hq.github.io/matrix-authentication-service/setup/homeserver.html) ·
  [admin API](https://element-hq.github.io/matrix-authentication-service/topics/admin-api.html) ·
  [`mas-cli manage`](https://element-hq.github.io/matrix-authentication-service/reference/cli/manage.html) ·
  [appservice login](https://element-hq.github.io/matrix-authentication-service/as-login.html) ·
  [releases](https://github.com/element-hq/matrix-authentication-service/releases) ·
  passkeys draft [#4234](https://github.com/element-hq/matrix-authentication-service/pull/4234) ·
  self-service PATs [#4492](https://github.com/element-hq/matrix-authentication-service/issues/4492)
- matrix.org on MAS: [blog post, 2025-04-08](https://matrix.org/blog/2025/04/morg-now-running-mas/)
- Synapse: [upgrade notes 1.136.0](https://element-hq.github.io/synapse/latest/upgrade.html#upgrading-to-v11360) ·
  [upgrade notes 1.157.0](https://element-hq.github.io/synapse/latest/upgrade.html#upgrading-to-v11570) ·
  [`matrix_authentication_service` config](https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html#matrix_authentication_service) ·
  [#18520](https://github.com/element-hq/synapse/pull/18520) (internal MAS API) ·
  [#18759](https://github.com/element-hq/synapse/pull/18759) (stabilisation)
- Matrix spec: [v1.15 changelog](https://spec.matrix.org/v1.15/changelog/v1.15/) ·
  [user identifiers](https://spec.matrix.org/latest/appendices/#user-identifiers) ·
  [Application Service API](https://spec.matrix.org/latest/application-service-api/) ·
  [areweoidcyet.com](https://areweoidcyet.com/)
- Tuwunel: [OIDC server](https://matrix-construct.github.io/tuwunel/authentication/oidc-server.html)
- siwx-oidc: the source files linked in the table above.
