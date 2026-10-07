# Matrix integration

siwx-oidc implements the Matrix OAuth 2.0 authentication API (Matrix spec v1.15
and later: MSC3861 and its sub-proposals) and acts as the authentication
service in Synapse's stable `matrix_authentication_service` integration. That
is the role the Matrix Authentication Service (MAS) plays in a default
deployment. siwx-oidc covers only part of what MAS offers; see
[What is not supported](#what-is-not-supported) and
[comparison.md](comparison.md).

Environment variables appear here as `SIWXOIDC_…`. The legacy `SIWEOIDC_…`
spelling is still accepted; see [configuration.md](configuration.md).

- [Two modes](#two-modes)
- [How Synapse is wired](#how-synapse-is-wired)
- [Dependencies and risks](#dependencies-and-risks)
- [MSC3861, the OAuth 2.0 API, and why there is no "MSC3861 mode" any more](#msc3861-the-oauth-20-api-and-why-there-is-no-msc3861-mode-any-more)
- [Token model](#token-model)
- [Admin-scoped token mint](#admin-scoped-token-mint)
- [Accounts and devices](#accounts-and-devices)
- [Account management (MSC4191)](#account-management-msc4191)
- [Device-code and QR login](#device-code-and-qr-login)
- [Cross-signing](#cross-signing)
- [Element X notes](#element-x-notes)
- [Gates that protect accounts](#gates-that-protect-accounts)
- [What is not supported](#what-is-not-supported)
- [Notes for implementers](#notes-for-implementers)

## Two modes

| | Standalone | Delegated auth (Synapse) |
|---|---|---|
| Enabled by | default | `SIWXOIDC_MAS_SHARED_SECRET` set |
| Synapse calls | none | also needs `SIWXOIDC_SYNAPSE_ENDPOINT` |
| Relying parties | any OIDC client | any OIDC client, plus Synapse and Matrix clients |
| Token introspection (`/oauth2/introspect`) | 404 | active |
| Device-code grant (`/device_authorization`, `/token`) | refused | active |
| DID publication, `/resolve`, account actions | off | also needs `SIWXOIDC_MATRIX_SERVER_NAME` |

Older text in this repository, and some error messages and code comments, call
the delegated-auth mode "MSC3861 mode". It means the same thing: the shared
secret is configured.

Discovery follows the mode. `introspection_endpoint`,
`introspection_endpoint_auth_methods_supported`,
`device_authorization_endpoint` and the device-code grant type in
`grant_types_supported` appear only in delegated-auth mode; a standalone
deployment advertises `authorization_code` and `refresh_token` only, and
refuses `/device_authorization` and the device-code grant with
`unsupported_grant_type`. `account_management_uri`,
`account_management_actions_supported` and `io.inblock.resolve_endpoint`
appear only when a Synapse client and `SIWXOIDC_MATRIX_SERVER_NAME` are both
configured, since without them `/resolve` answers 503 and every account action
400.

## How Synapse is wired

### Synapse configuration

```yaml
# homeserver.yaml (tested with Synapse 1.159 and 1.161; versions before 1.157 are untested)
matrix_authentication_service:
  enabled: true
  # Where Synapse reaches siwx-oidc. An internal address is fine and preferred.
  endpoint: "http://siwx-oidc:8000/"
  # A long random string. The same value goes into SIWXOIDC_MAS_SHARED_SECRET.
  secret: "<shared secret>"

# Only if you want io.inblock.did to be write-protected; needs the patched
# Synapse described below.
experimental_features:
  msc4133_key_denylist: ["io.inblock.did"]
```

### siwx-oidc configuration

```bash
SIWXOIDC_BASE_URL=https://auth.example.org        # public issuer URL
SIWXOIDC_MAS_SHARED_SECRET=<shared secret>        # same value as Synapse's secret
SIWXOIDC_SYNAPSE_ENDPOINT=http://synapse:8008     # Synapse, reachable from siwx-oidc
SIWXOIDC_MATRIX_SERVER_NAME=example.org           # Synapse's server_name
SIWXOIDC_SIGNING_KEY_PEM="$(cat signing-key.pem)" # durable PKCS#8 P-256 key
SIWXOIDC_REDIS_URL=redis://redis:6379
```

The full list, key rotation and Docker usage are in
[configuration.md](configuration.md).

### What Synapse calls

Synapse uses fixed paths under `endpoint`, not paths from discovery:

| Call | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | provider metadata |
| `POST /oauth2/introspect` with `Authorization: Bearer <secret>` | validate an access token presented to Synapse |

Introspection returns `active`, `username` (the Matrix localpart), `device_id`,
`scope` (containing `urn:matrix:client:api:*`), `sub` (the DID) and expiry.
Synapse caches an introspection result for up to two minutes. It drops the
cached result when the token's device no longer exists, so a sign-out that
deletes the device takes effect at once; a token revoked without deleting its
device can keep working at Synapse for up to two minutes.
siwx-oidc also accepts the secret as `client_secret` in the form body.

Synapse serves `GET /_matrix/client/v1/auth_metadata` (MSC2965) by forwarding
siwx-oidc's discovery document, including keys it does not know. That is how
Matrix clients find `account_management_uri`,
`account_management_actions_supported` and `io.inblock.resolve_endpoint`.

### What siwx-oidc calls

siwx-oidc uses two different credentials against Synapse, and they are not
interchangeable:

| Surface | Credential | Calls |
|---|---|---|
| `/_synapse/mas/*` | the shared secret | `provision_user`, `is_localpart_available`, `query_user`, `upsert_device`, `update_device_display_name`, `delete_device`, `allow_cross_signing_reset`, `delete_user` (deactivate/erase), `reactivate_user` |
| `/_synapse/admin/*` and the client-server API | a **minted admin-scoped token** ([below](#admin-scoped-token-mint)) | `GET /_synapse/admin/v2/users/{mxid}/devices` (list, view), `POST /_matrix/client/v3/keys/query` (cross-signing readback), `PUT`/`GET /_matrix/client/v3/profile/{mxid}/io.inblock.did` |

The shared secret answers 401 `M_UNKNOWN_TOKEN` on the second surface. A wrong
secret on the first surface answers 403. The `/_synapse/mas/*` routes take a
bare localpart in the body or query; the admin and client routes take a
percent-encoded MXID in the path.

The anonymous profile read of `io.inblock.did` (used by `/resolve`) is tried
without a token first and uses a minted token only if the homeserver refuses it.

Timeouts: 2 s to connect and 8 s per request to Synapse.

### Reverse proxy

- **Keep `/oauth2/introspect` and `/oauth2/admin_token` off the public
  internet.** Both accept the shared secret.
- siwx-oidc also serves a subset of the legacy Matrix client API. These routes
  take effect only if the reverse proxy in front of the homeserver sends them
  to siwx-oidc, the same arrangement as MAS's compatibility layer:
  - `GET /_matrix/client/v3/login` (advertises `m.login.sso` only)
  - `POST /_matrix/client/v3/logout` and `/logout/all`
  - `POST /_matrix/client/v3/refresh`
  - `DELETE /_matrix/client/v3/devices/{device_id}` and
    `POST /_matrix/client/v3/delete_devices` (the in-client session manager)
- Strip siwx-oidc's upstream CORS headers at the proxy; see
  [configuration.md](configuration.md).

## Dependencies and risks

- **`/_synapse/mas/*` is an internal Synapse API designed for MAS.** Synapse
  introduced it in 1.135.0 as "a dedicated internal API for Matrix
  Authentication Service to Synapse communication", and its configuration is
  documented for MAS. It is not a published, stable interface. siwx-oidc tracks
  it per Synapse release, and it changed materially between 1.135 and 1.157.
  **Treat every Synapse upgrade as a compatibility check.**
- **Tested versions.** Tested with Synapse 1.159 and 1.161. The integration uses
  Synapse's stable `matrix_authentication_service` block (available since
  1.136); versions before 1.157 are untested. The deployment this project
  maintains ([siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server))
  runs Synapse 1.161.0 with one patch (below); source-level claims in the code
  comments were checked against 1.159.0.
- **Known upstream bug.** An account with a `users` row but no `profiles` row
  (element-hq/synapse#19702) answers 500 on profile reads and writes, and
  displayname writes for it fail (affected: Synapse 1.160 and earlier; 1.161
  fixes some of the paths (#20149, #20172); #19702 remains open upstream; not
  re-verified against this deployment). #20149 and #20172 cover custom-field
  reads and admin writes, which may not include the displayname write the
  self-heal depends on. The handling described in
  [identity-model.md](identity-model.md#row-less-accounts-and-the-exact-500-rule)
  stays in place.
- **Element Web patches.** The Element Web build used with this deployment
  carries patches, listed with evidence and retirement conditions in the
  [Element Web patch registry](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/element-web/README.md).

### The Synapse patch for `io.inblock.did`

Stock Synapse lets any user write any custom profile field, including
`io.inblock.did`. Write protection therefore needs a patched Synapse: a
backport of [element-hq/synapse#19980](https://github.com/element-hq/synapse/pull/19980)
("Add allow- and deny-list of custom profile fields"), which is **open** and
not merged upstream. It adds `experimental_features.msc4133_key_denylist`; with
`["io.inblock.did"]` a user's `PUT` or `DELETE` of that field answers 403,
while a server admin (and so the provider's admin-scoped token) can still write
it. Registry, evidence and retirement condition:
[Synapse patch registry](https://github.com/inblockio/siwx-oidc-matrix-server/blob/main/patches/synapse/README.md).

- **Without the patch**, publication still works, but the field is
  user-writable. A consumer must then rely on the `proof` and its MXID binding
  (see [identity-model.md](identity-model.md#verifying-a-published-did)); the
  unsigned `did` member and `/resolve`'s `attested` flag prove nothing.
- **Denylist, never allowlist.** `msc4133_key_allowlist` restricts *every*
  custom field on the homeserver; an empty list is not "unset" and would block
  all custom-field writes.
- The backport takes only the configuration and profile-handler parts of the
  PR's head commit `d4758f2d2`. An earlier revision lacked the admin exemption
  and would have blocked the provider's own write. Capability advertisement is
  skipped: the policy is enforced but not announced to clients.
- The patch is applied with `patch --forward --batch --fuzz=0`, so a patch that
  no longer applies fails the image build instead of shipping an unpatched
  Synapse. The upstream option names are kept verbatim, so adopting the merged
  PR later needs no configuration change.
- Every Synapse version bump carries a forward-port of the patch. Check the
  registry's retirement condition first: a patch that stops applying may mean
  upstream merged it.

## MSC3861, the OAuth 2.0 API, and why there is no "MSC3861 mode" any more

**MSC3861** ("Next-generation auth for Matrix, based on OAuth 2.0/OIDC") is an
umbrella proposal. Its component proposals map OAuth 2.0 and OpenID Connect onto
Matrix APIs. It was accepted in April 2025 and merged into the spec in
**v1.15** (2025-06-26), "the OAuth 2.0 based authentication API, as per MSC3861
and its sub-proposals".

| Proposal | Topic | Relation to MSC3861 | Spec |
|---|---|---|---|
| MSC2964 | authorization code and refresh token grants | core sub-proposal | v1.15 |
| MSC2965 | server metadata discovery (`/_matrix/client/v1/auth_metadata`) | core sub-proposal | v1.15 |
| MSC2966 | dynamic client registration | core sub-proposal | v1.15 |
| MSC2967 | API scopes (`urn:matrix:client:api:*`, device scopes) | core sub-proposal | v1.15 |
| MSC4254 | RFC 7009 token revocation for logout | core sub-proposal | v1.15 |
| MSC3824 | OAuth 2.0 API aware clients | referenced by MSC3861, merged later | v1.18 |
| MSC4191 | account management deep links | referenced by MSC3861, merged later | v1.18 |
| MSC4190 | device management for application services | related | v1.17 |
| MSC4312 | resetting cross-signing keys (`m.oauth` UIA type) | related | v1.17 |
| MSC4341 | RFC 8628 device authorization grant | related | v1.18 |
| MSC4108 | QR-code sign-in and E2EE setup | separate proposal, not a dependency | **open**, not in the spec |

### Synapse timeline

| Synapse | Change |
|---|---|
| 1.87.0 (2023) | experimental MSC3861 support: `experimental_features.msc3861` delegates auth to an OIDC provider |
| 1.135.0 (2025) | adds the internal `/_synapse/mas/*` API for MAS |
| 1.136.0 (2025-08-12) | stabilises delegation as `matrix_authentication_service: {enabled, endpoint, secret}`; the experimental block is deprecated |
| 1.157.0 (2026-07-21) | removes `experimental_features.msc3861`; a non-empty block is a configuration error |

### Limitations of the old experimental mode

The experimental block was generic in form (`issuer`, `client_id`, client
authentication, an optional `introspection_endpoint`, `account_management_url`,
`admin_token`). The stabilising change (element-hq/synapse#18759) lists what it
improved on: the old mode needed a client provisioned on the provider side,
relied on discovery so deployments had to override the introspection endpoint
to avoid internet round trips, depended on `authlib`, and did not check that
the device in an introspection result still existed, so logout did not
invalidate a token until the cache expired. Earlier releases had also disabled
some admin APIs, user consent and third-party-ID changes in that mode, and
Synapse 1.130.0 removed automatic provisioning of missing users and devices.

The experimental `admin_token` option let the provider call
`/_synapse/admin/*` with a static token. It never existed in the stable block
and is gone with the experimental one. On 1.157 and later, admin rights come
only from the introspected scope (`urn:synapse:admin:*`), which is why
siwx-oidc mints its own admin-scoped tokens.

### How to read "MSC3861" in this project

MSC3861 itself is now plain spec, and the only Synapse setting that carried its
name no longer exists. The accurate description of siwx-oidc is: it implements
the Matrix OAuth 2.0 API (spec v1.15+) and acts as the auth service in
Synapse's `matrix_authentication_service` integration. Where older text, error
messages or code comments in this repository say "MSC3861 mode", read
"delegated-auth mode": the shared secret is configured and Synapse delegates
authentication to siwx-oidc.

## Token model

Both modes issue the same token formats and keep every token in a **grant**
(`src/db/grant.rs`), the one Redis record that owns a session's access and
refresh tokens:

| Token | Format |
|---|---|
| access | `mat_` + 32 base62 characters |
| minted admin token (a `service` grant's access token) | `msa_` + 32 base62 characters |
| refresh | `mcr_` + handle (22 base62 characters, about 131 random bits) + `_` + secret (32 base62 characters) |

The handle names the grant, so every refresh token of a chain, current or
superseded, leads to its grant; it is random and never derived from the device
ID. **No token is stored**: an access token is kept as the SHA-256 digest of the
token (`at/{digest}`), a refresh token as the digest in its grant's `current_rt`
or `previous_rt`, and the one value that must be handed back later, the
successor pair of a rotation, is encrypted under a key derived from the previous
refresh token (AES-256-GCM, HKDF-SHA256), which only its presenter holds. Log
lines name tokens by fingerprint only. The keyspace is in
[architecture.md](architecture.md#redis-keyspace).

| | Delegated auth | Standalone |
|---|---|---|
| Grant kind | `matrix_device` | `oidc` |
| Refresh token issued | always | only for `offline_access`, to a client whose registration allows the `refresh_token` grant |
| Scope recorded | `openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}` | the requested scopes among `openid`, `profile` and `offline_access`, as far as the client may have them (`openid` if none) |
| Access token TTL | 300 s | 300 s |
| Refresh token TTL | 7,776,000 s (90 days), renewed by each rotation | same |
| Absolute lifetime | none by default; with `grant_absolute_lifetime_secs` (or the per-client map) the grant ends at its authentication plus the cap, and no access token outlives that ([configuration.md](configuration.md#grant-lifetime)) | same |
| ID token TTL | 300 s by default (`id_token_ttl_secs`) | same |
| Introspection | active | 404 |
| Device ID | `SIWX_` + 8 hex characters, or the ID the client requested | empty |

The table describes a Matrix-class client. A generic-class client is issued an
`oidc` grant with no device even in delegated-auth mode (the table of code
exchanges below).

Minted admin tokens (`service` grants, no refresh token) use the prefix
`msa_`. Device codes use `dvc_`.

In delegated-auth mode the authorization-code grant of a Matrix-class client
records the Matrix scope above regardless of the scopes requested, and always
issues a refresh token. In
standalone mode ("generic mode": no `mas_shared_secret`) it grants least
privilege: the scope the request asked for, limited to `openid`, `profile` and
`offline_access`, and a refresh token only when `offline_access` was requested and
the client's registration allows the `refresh_token` grant (a registration that
lists no `grant_types` allows it). When the granted scope differs from the
request, the token response says so in `scope` (RFC 6749 §5.1). The requested scope
travels from `/authorize` through the session into the stored code. A code
written by the previous build has none, and is exchanged as it always was
(`openid profile` and a refresh token) for the 300 s it lives.

What a code exchange issues is decided by the deployment mode and by the class
of the client (`exchange_issuance`), and the code must be redeemed by a client of
the class it was issued to:

| Delegated auth | Client class | Issues |
|---|---|---|
| yes | Matrix | a `matrix_device` grant, as above |
| yes | generic | an `oidc` grant with no device: the scopes the client's entry allows of the scope the request bound (`client_policy::grant_for`, the call `/authorize` and `/sign_in` made), then the entry's `always_granted_scopes`; a refresh token only when `offline_access` is part of that and the registration allows the `refresh_token` grant; the granted scope in the response when it differs from the request |
| no | Matrix | an `oidc` grant, as above |
| no | generic | refused: start-up refuses such a client, which has no Synapse to supply its localpart |

The `oidc` grant of a generic-class client gets its own `sid` like any other, so
`/end_session` and back-channel logout apply to it. No ENS lookup runs for it:
the claims of a generic-class client would otherwise send the user's address to
a third party at every exchange and every userinfo call. A code redeemed by a
client of the other class (the client changed class after `sign_in` ran; a code
written before the class was recorded counts as Matrix) is `invalid_grant`,
and so is a generic-class code whose request grants no `openid`.

Clients request the Matrix scopes in either the stable form
(`urn:matrix:client:api:*`, `urn:matrix:client:device:{id}`) or the MSC2967
unstable form (`urn:matrix:org.matrix.msc2967.client:…`); both are advertised.

`/authorize` accepts only `response_type=code`, the only response type
discovery advertises, and requires PKCE with `S256` (`plain` is rejected). The
redirect URI must equal a registered one exactly, query included. `/authorize`
binds the validated request (client, redirect URI, state, response mode, PKCE
challenge) to the login session, and `/sign_in` issues the code for that
request. `/sign_in` reads no authorization parameter from its query: the login
page still appends them to its link, and they are ignored. A code is single use,
is deleted when it is exchanged, and is redeemable only at `POST /token` with
its verifier.

### Token kinds

Every token is either an **access token** or a **refresh token**: an access
token has an `at/…` entry that says so, a refresh token is known only to its
grant, and a legacy entry (`token/{raw}`, written before the grant record)
records its kind in its `TokenMetadata`. A minted admin token is an access
token. Each endpoint accepts exactly one kind:

| Endpoint | Accepts |
|---|---|
| `POST /token` (`grant_type=refresh_token`), `POST /_matrix/client/v3/refresh` | refresh token |
| `POST /oauth2/introspect`, `GET`/`POST /userinfo` | access token |
| `POST /_matrix/client/v3/logout`, `logout/all`, `DELETE /_matrix/client/v3/devices/{id}`, `POST /_matrix/client/v3/delete_devices` (bearer) | access token |
| `POST /oauth2/revoke` (RFC 7009) | either |

A token of the other kind is answered exactly like an unknown token
(`invalid_grant`, `M_UNKNOWN_TOKEN`, `{"active": false}`, or a no-op `200` for
logout), and is left untouched. Token entries written before the kind was
recorded are classified by their lifetime, which every earlier writer fixed:
at most 900 s is an access token (300 s user tokens, 30–900 s admin tokens),
90 days a refresh token. A long-lived entry that carries the admin scope fits
no earlier writer and is accepted nowhere; revocation still removes it.

### Grants of other relying parties at the Matrix side

In delegated-auth mode an `oidc` grant is a generic-class client's (a mail
client, say). It is not a Matrix session, whatever scope string it carries, so
the Matrix side does not act on it, and every refusal leaves the grant as it was:

| Endpoint | Answer for the token of an `oidc` grant |
|---|---|
| `POST /oauth2/introspect` | `{"active": false}`, exactly like an unknown token (the endpoint exists only in this mode) |
| `POST /_matrix/client/v3/logout`, `logout/all`, `DELETE /_matrix/client/v3/devices/{id}`, `POST /_matrix/client/v3/delete_devices` (access token as the bearer) | 401 `M_UNKNOWN_TOKEN`, and nothing is torn down. An unknown bearer is still the idempotent 200 at `logout` and `logout/all`; a token that is alive for its own client is not answered as a sign-out that happened |
| `POST /_matrix/client/v3/refresh` (refresh token) | `M_UNKNOWN_TOKEN`, exactly like an unknown token, before any script runs. The grant stays current for `POST /token`, where its client is authenticated. A legacy refresh token whose scope has no Matrix API, which the lift would turn into an `oidc` grant, is refused the same way and stays a legacy entry |

`POST /oauth2/revoke`, `POST /token`, `/userinfo` and `/end_session` serve
`oidc` grants as ever: the holder may always end its own token, and these are
the endpoints a relying party uses. `logout/all` by a Matrix session ends every
grant of the user, the generic-class client's included, as any sign-out of every
session does. Without a MAS shared secret (generic mode) every client holds
`oidc` grants, and the Matrix routes serve them unchanged. A token-store fault
on any of these paths is still the retryable 503 `M_UNKNOWN` (introspection:
500), never a refusal. Presenting the access token counts it as used for the
replay rule ([Lifecycle](#lifecycle)), as every presentation does.

One function decides all of it, `grant::is_matrix_credential`, an exhaustive
`match` over the grant kind: `matrix_device` and `service` (minted admin tokens)
grants, and tokens with no grant record (legacy entries), are Matrix credentials;
`oidc` grants are not. The bearer routes ask it through `CompatState::acts_on`,
which holds the refusal back unless `delegated_auth` is set (`CompatState::new`
reads it from the configuration, the same predicate as discovery).

### An empty `device_id` is JSON `null`

Introspection renders an empty `device_id` as `null`, never `""`. Synapse
treats a present-but-empty device ID as a zero-length device and fails the
request with a 500 ("Invalid device ID in introspection result"). Three kinds
of token have no device: minted admin tokens, standalone tokens, and
delegated-auth tokens whose device provisioning failed at sign-in. The last kind
is introspected by Synapse, so `null` is what keeps it working as a deviceless
token.

### Lifecycle

1. `POST /token` with `grant_type=authorization_code` consumes the code (reads
   and deletes it in one atomic step), checks the PKCE verifier against the
   challenge bound at `/authorize`, and creates a **grant**: one record that
   owns the access token and the refresh token (generic mode: a refresh token
   only for `offline_access`). Every token belongs to exactly one grant, and
   deleting the grant makes all its tokens inert at once.
2. `POST /token` with `grant_type=refresh_token` and `POST
   /_matrix/client/v3/refresh` **rotate both** through one atomic Redis script
   (`RedisClient::rotate_refresh_token`): a new access token and a new refresh
   token, after which the presented refresh token is the grant's previous one.
   The `device_id` and scope are carried over. The refresh response has no ID
   token. At `POST /token` the refresh is bound to the client it was issued
   to, see [Client binding](#client-binding). Concurrent refreshes of one
   token all receive the same new pair; the grant keeps one live chain.
3. **Lost responses.** A client that lost a rotation response (common on
   mobile) and retries with the previous refresh token receives the **same**
   successor pair, however late it retries, as long as that pair is unused.
   The pair counts as used once its access token is first accepted by
   introspection or `/userinfo`, or once its refresh token rotates. A replay
   after that, or of any older token of the grant, is **reuse**: it is answered
   like an unknown token (`invalid_grant`, `M_UNKNOWN_TOKEN`) and logged as one
   `warn!` security event, message `refresh token reuse detected`, fields
   `security_event="refresh_token_reuse"`, `grant_fp`, `generation`,
   `client_id`, `grant_kind`, `branch`, `grant_revoked` (fingerprints only).
   By default reuse revokes nothing (`grant_revoked=false`). With
   [`reuse_revokes_grant`](configuration.md#refresh-token-reuse) on, the same
   script also deletes the grant, as revoking its refresh token would: its
   access tokens are inactive at once, whoever holds its current refresh token
   is refused at the next refresh (the point of enforcement: one of the two
   holders is not the client), a generic RP is sent a back-channel logout
   token, and the Synapse device is not deleted; the answer is still the
   unknown-token answer and the event says `grant_revoked=true`. A replay of
   the previous token while its pair is unused is a lost response, never reuse,
   so it never revokes. The switch is off until the maintainers decide (design
   decision D2). Nothing new is minted for a replay and the refresh lifetime
   does not grow. `POST /_matrix/client/v3/refresh` applies the same rule; it
   carries no client identity, so it cannot bind the replay to a client. See
   [the 2026-06-23 audit](audits/2026-06-23-elementx-refresh-rotation-signout.md).
4. `POST /token` with the device-code grant provisions the Synapse device and
   issues tokens (see [below](#device-code-and-qr-login)).
5. `/userinfo` accepts an access token only. An authorization code is not a
   bearer token, before or after its exchange.
6. **RP-initiated logout.** Every grant issued with an ID token has a random
   session id, `sid`, which its ID token carries (both modes). `GET` or `POST
   /end_session` (OpenID Connect RP-Initiated Logout 1.0, advertised as
   `end_session_endpoint`) with an `id_token_hint` ends exactly the grant that
   `sid` names, if it belongs to the hint's client and subject: its access
   token is inactive at once and its refresh token is refused at both
   endpoints. The hint must be an ID token this provider signed, with the live
   or a retired key; an expired one is accepted. A `client_id` must be the
   hint's audience. A `post_logout_redirect_uri` is honoured only when the
   client registered it (`post_logout_redirect_uris`, matched exactly, query
   included), with `state` appended; without one the answer is a signed-out
   page. Any refusal is a 400 that ends nothing and never redirects; a store
   fault is a 503. End-session never deletes a Synapse device: in Matrix mode
   it ends the device's grant and leaves the device to the Matrix `logout` or
   the account page, like `/oauth2/revoke`. A grant issued before `sid`
   existed has none and ends by revocation, expiry or an epoch instead.
7. **Back-channel logout** (OpenID Connect Back-Channel Logout 1.0, generic
   mode). A client may register `backchannel_logout_uri` and
   `backchannel_logout_session_required`. Every active deletion of one of its
   `oidc` grants sends it a logout token: revocation of the refresh token,
   end-session, a refresh refused for an epoch, inactivity or the absolute
   expiry (the refusal deletes the grant), and the revocation of all of a
   user's grants (`logout/all`, deactivation, erasure). The deleting script
   queues the entry in a Redis outbox; a worker in every instance delivers it
   apart from the request, signing a fresh ES256 token per attempt (`typ`
   `logout+jwt`, `aud` the client, `sub` the DID, the grant's `sid`, `exp`
   two minutes after `iat`), and retries a failing RP five times in all with
   2 s doubling backoff before dropping the entry with a warning. **A grant
   whose Redis key simply expires sends nothing:** no script runs, nothing
   observes it, and the RP's own refresh token expired with it, so the RP
   learns of it at its next refresh (`invalid_grant`). Likewise an epoch that
   so far only refused an access token sends nothing until a refresh deletes
   the grant. A Matrix device grant never sends a logout token (Synapse is not
   a relying party here), so Matrix mode does not advertise
   `backchannel_logout_supported`. The URI passes an SSRF guard at
   registration and at every delivery (`https`, public addresses only, no
   redirects; an operator allowlist exempts named hosts): see
   [configuration.md](configuration.md#back-channel-logout).

**What Element Web sends on sign-out.** Element Web signed in through the
OAuth 2.0 API does not call `POST /_matrix/client/v3/logout`; it revokes both
tokens at `/oauth2/revoke` in parallel, each with `client_id` and
`token_type_hint` (matrix-js-sdk 42.4, `Lifecycle.ts` `doLogout`). In Matrix
mode either revocation ends the device's grants (the first one wins, the
second finds nothing and answers 200), and neither deletes the Synapse device
(`TeardownPolicy::TokensOnly`): the device stays until it is removed from the
session list or the account page. Grant-level RFC 7009 (provisional): for a
token with no device, a refresh token ends its grant and an access token only
itself. Pin: `h1_revoke_does_not_delete_device_but_logout_does`,
`teardown_policy_only_deletes_device_on_explicit_signout`,
`revoking_a_deviceless_refresh_token_revokes_its_grant_an_access_token_only_itself`,
`revoking_by_token_deletes_the_grant_of_an_accepted_token_only`.

**Lifetime.** A grant ends 90 days after its last refresh and, when an
absolute lifetime is configured (`grant_absolute_lifetime_secs`, per client
`grant_absolute_lifetime_secs_by_client`; none by default), at its
authentication plus that cap. The authentication is the sign-in or the
device approval, stamped from Redis `TIME`; a grant lifted from a legacy
refresh token counts from that token's issue time, the last refresh under the
previous build (the true sign-in was never recorded). Past either deadline
both refresh endpoints answer as for an unknown token (`invalid_grant`,
`M_UNKNOWN_TOKEN`) and delete the grant, and introspection answers inactive.
No access token's `exp` passes the absolute expiry. The deadline only moves
earlier: a lowered cap reaches a grant at its next refresh, a raised or
removed one extends nothing. For an Element user the end of a grant is a
sign-out, and signing in again usually means a new device with key-backup
restore, so choose a short cap with care.

A refresh is refused (`invalid_grant`, "Session has been revoked.") when the
device was just signed out (a short-lived device tombstone, 15 minutes, closes
the race between a refresh and the teardown) or when an epoch refuses the
grant.

### Epochs

An epoch is a persistent not-before timestamp (Unix milliseconds, Redis
`TIME`) for one scope: `epoch:global`, `epoch:client/{client_id}` or
`epoch:user/{username}`. Every grant authenticated at or before the largest
epoch that applies to it is refused at both refresh endpoints and is inactive
at introspection at once (Synapse may still answer from its two-minute
introspection cache); a grant authenticated later is untouched. One write
revokes a whole scope, with no enumeration.

`logout/all`, deactivation and erasure set the user epoch (and still delete
the user's grants). A sign-in right after `logout/all` therefore refreshes at
once; the user tombstone the epoch replaced refused that for 15 minutes. A
user tombstone planted by the previous build is still honoured until it
expires.

Global and client epochs have no HTTP endpoint. The start-up sync of static
clients sets the client epoch of a generic-class client that was removed,
changed class or changed its allowed scopes, and nothing else sets one on its
own ([Configuration](configuration.md#changes-that-end-a-generic-clients-sessions)).
An operator sets any epoch with a single script that takes the time from Redis
`TIME` and never moves an epoch earlier (provisional; it is what
`RedisClient::set_epoch` runs):

```bash
redis-cli -u "$REDIS_URL" EVAL "local t = redis.call('TIME') \
  local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) \
  local cur = tonumber(redis.call('GET', KEYS[1]) or '0') \
  if ms > cur then redis.call('SET', KEYS[1], string.format('%.0f', ms)) cur = ms end \
  return string.format('%.0f', cur)" 1 epoch:global      # or epoch:client/<client_id>
```

Every user of the scope signs in again; for Matrix clients that usually
means a new device with key-backup restore. An epoch has no TTL: deleting the
key lifts it for grants not yet refused (a grant refused at a refresh
endpoint is already deleted).

### Upgrading from a build before the grant record

Builds before the grant record stored each token as `token/{raw}` with its
`TokenMetadata`. After the upgrade no user signs in again:

- A legacy **access** token stays valid until it expires (at most 900 s): the
  access check reads the legacy entry when no `at/…` entry exists. This read
  fallback is removed one release after the upgrade.
- A legacy **refresh** token presented at either refresh endpoint is **lifted**
  into a new grant and answered with a pair in the current format. One script
  deletes the legacy entry, creates the grant with the legacy token as its
  previous refresh token and the new pair sealed under it, and writes a pointer
  `legacy_rt/{digest(legacy token)}` to the grant. A concurrent or later
  presentation of the same legacy token follows the pointer and gets the rule
  above: the same pair while it is unused, reuse after. `POST /token`
  authenticates the legacy entry's client as for any refresh; the Matrix endpoint
  lifts only a public client's token and leaves a confidential client's for
  `POST /token`. The grant records the client's confidentiality by the same rule
  as every issuance.
- Legacy grace pointers (`token_rotated/{raw}`, 60 s) are not read. A client
  that lost a refresh response in the minute before the upgrade signs in again.
- Legacy refresh tokens never presented expire on their own within 90 days;
  revocation sweeps them in the meantime.
- `siwx_user` hints and account sessions the previous build wrote by raw token
  (`user:session/…`, 30 days; `account_session/…`, 600 s) keep working until
  they expire; the build writes only the digest layout. `logout/all`,
  deactivation and erasure end the old entries too, by a prefix scan that goes
  with the legacy read.
- A rollback to a build before the grant record signs out every session that
  refreshed on the new build: the old build knows neither the grant tokens nor
  the lifted legacy tokens, whose entries are gone.
- A rollback to a build before digest-keyed credentials cannot read a client
  entry the new build wrote or upgraded (it has no `secret` member): those
  clients fail until they register again or the entry expires (30 days). The
  old build writes `default_clients` in the clear again at its start, and
  in-flight codes, sessions and device codes are lost.
- A rollback to a build before epochs and the absolute lifetime honours
  neither. Only a refresh deletes a grant an epoch refuses; the access check
  only refuses it, so after a rollback every grant under a global or client
  epoch that has not refreshed since is accepted again, and so is a grant issued
  after an epoch from an earlier code or approval. Under a user epoch only such
  a late grant comes back, because `logout/all`, deactivation and erasure delete
  the grants the user has when they run. Caps stop applying: the old rotation
  extends a grant to 90 days of inactivity again. The epoch keys outlive the
  rollback, so after rolling forward the same grants are refused again; to keep
  them refused during the rollback, delete them before rolling back.
- A rollback to a build before `sid` serves no `/end_session` (404) and issues
  ID tokens without `sid`. It ignores the grants' `sid` field and the
  `idx:grants:sid/*` keys: its rotation extends a grant but not the index
  entry, and its deletions leave the entry behind (it names a grant that is
  gone, and expires on its own). After rolling forward, end-session ends
  nothing for a grant whose index entry expired during the rollback; that grant
  still ends by revocation, expiry or an epoch. Its client registration reads
  `post_logout_redirect_uris` without knowing it, and a client update through
  the old build drops it.
- A rollback to a build before digest-keyed own sessions reads neither
  `siwx_user/…` nor `acct_session/…`: account pages ask for a new re-auth and
  passkey pickers are unscoped until the next sign-in. Nothing is lost that a
  sign-in does not restore; `logout/all` on the old build does not end the
  sessions written by the new one (they expire on their own, at most 30 days for
  a hint, which scopes a picker and authorizes nothing). Rolling forward reads the
  old build's raw-keyed sessions again for their remaining lifetime.
- A rollback to a build before back-channel logout sends no logout tokens and
  queues none. Entries queued before the rollback stay in
  `outbox:backchannel_logout` and are delivered when a build with the worker
  runs again, with fresh tokens; a deletion made during the rollback is never
  sent. Client registrations keep `backchannel_logout_uri` without the old build
  knowing it, and a client update through the old build drops it.

A token-store fault is never answered as a refusal. `POST
/_matrix/client/v3/refresh` and the device-deletion routes (`DELETE
/_matrix/client/v3/devices/{id}`, `POST /_matrix/client/v3/delete_devices`)
answer it with a retryable 503 `M_UNKNOWN`: a Matrix client takes
`M_UNKNOWN_TOKEN` for "signed out" and clears its crypto store, so reporting a
transient Redis fault that way would cost the session and its cryptographic
identity. The rotation script runs entirely or not at all, so a retry with the
same refresh token is safe.

### Client binding

An authorization code and a refresh token belong to the client they were issued
to, and `POST /token` authenticates that client by one rule for both grants
(`oidc::authenticate_code_client` and `oidc::authenticate_refresh_client`, which
share their checks and differ only in tolerating an expired registration, below):

1. The client named in the request must be the grant's client, else
   `invalid_grant`. It is named by `client_id` in the form or by the user name
   of an `Authorization: Basic` header; when both are present they must agree
   (else `invalid_request`).
2. A secret the request presents (`client_secret` in the form, or the
   `Authorization` password or Bearer value, which wins) must match the
   registration, else `invalid_client`. The registration holds only the
   secret's SHA-256 digest; the presented secret is digested and compared in
   constant time.
3. A request that presents none must come from a public client: registered
   with `token_endpoint_auth_method: none`, or with no method while
   `SIWXOIDC_REQUIRE_SECRET` is off. Otherwise `invalid_client`
   ("Secret required."). Element Web and Element X register as public clients and send
   `client_id` on refresh.

`invalid_client` is a 401 (RFC 6749 §5.2), with `WWW-Authenticate: Basic` when
the request attempted Basic. It used to be a 400. The replay of a lost response
is bound the same way, to the grant's client.

`POST /_matrix/client/v3/refresh` serves public clients only. The Matrix
client-server API gives a refresh request no client identity, so the endpoint
cannot authenticate a client: it refuses the refresh token of a grant whose
client is confidential exactly like an unknown token (`M_UNKNOWN_TOKEN`) and
leaves it untouched, so the client still refreshes at `POST /token` with its
secret. Each grant records at issuance whether its client is confidential, by
rule 3 above (a client without a registration counts as public). A public
client's token needs no authentication there; rule 1 cannot apply, since no
client is named.

Provisional choices, open for the maintainers:

- **A registration without `grant_types` allows the refresh grant**, and a
  generic-mode request that asks for no grantable scope is granted `openid`.
- **A public client may omit `client_id` at the refresh grant.** `siwx-oidc-auth`
  and the Matrix clients send it, an older agent may not; requiring it would
  sign those out.
- **A token can outlive its client's registration.** A dynamic registration
  lasts 30 days from its last use and a refresh token 90 days from its last use.
  An authorization request, a code or device-code exchange, an accepted refresh
  and a userinfo call each restore the registration, so a session in use keeps
  its client; a registration still lapses after 30 days without a use, and a
  client can be removed. A token whose client is gone keeps refreshing when the
  request names that client or none, and is refused when the request names
  another client or presents a secret (which can no longer be checked). Refusing
  it outright would sign out every session older than a registration. A
  generic-class static client is the exception: removing it sets its client
  epoch, so its grants end with it (see [Epochs](#epochs)).

An `Authorization` header at `/token` used to be answered with a 400 on every
request (two header extractors rejecting each other's scheme), so
`client_secret_basic` never worked. It is read now, and discovery advertises
`client_secret_basic`, `client_secret_post` and `none`.

### Introspection never turns a storage error into a logout

If Redis cannot be read, introspection answers **500**, never
`{"active": false}`. Synapse caches a negative result for two minutes, and an
inactive token is a hard logout that makes the client discard its crypto store.
Only a token that is genuinely absent, expired, or not an access token is
inactive.

## Admin-scoped token mint

`POST /oauth2/admin_token`, authenticated with the shared secret, mints a
short-lived token that Synapse accepts as a server admin:

```bash
curl -sS -X POST https://siwx-oidc.internal/oauth2/admin_token \
  -H "Authorization: Bearer $SHARED_SECRET"
# {"access_token":"msa_…","token_type":"Bearer","expires_in":300,
#  "scope":"urn:matrix:client:api:* urn:synapse:admin:*",
#  "user_id":"@siwx-admin:example.org"}
```

`SynapseClient` mints its own tokens the same way, in process, for the calls in
[What siwx-oidc calls](#what-siwx-oidc-calls). The HTTP endpoint exists for
operator scripts.

**How it works.** In Synapse's MAS integration, `is_server_admin()` is
`"urn:synapse:admin:*" in requester.scope`, and the scope comes from
siwx-oidc's own introspection response. The auth service can therefore issue
itself an admin credential.

**Constraints** (checked against Synapse 1.159.0 and pinned by unit tests):

- The scope must carry **both** `urn:matrix:client:api:*` and
  `urn:synapse:admin:*`. Synapse checks the client-API scope first and rejects
  an admin-only scope.
- The introspected `username` must be an **existing** Synapse user. The mint
  therefore provisions `SIWXOIDC_ADMIN_TOKEN_LOCALPART` (default `siwx-admin`)
  if it is missing. **This creates a real Matrix account on the homeserver.**
- The token has no device, so `device_id` is `null`.
- Because the client-API scope is required, the token can also act **as that
  service user** on the normal client API. That comes with the mechanism and is
  why the lifetime is short.

**Lifetime.** Minted on demand; the TTL (`SIWXOIDC_ADMIN_TOKEN_TTL_SECS`,
default 300) is clamped in code to 30–900 s (`clamp_admin_token_ttl`), so
configuration cannot turn it into a standing admin key. Do not keep a
long-lived admin credential in the environment.

**Caching caveat.** Synapse caches introspection for up to two minutes and drops
a cached result only when the token's device is gone. An admin token has no
device, so if siwx-oidc stops accepting one, it can keep working at Synapse for
up to two minutes. siwx-oidc's introspection response is the authority.

**Errors** carry `{"error", "error_description"}`: 404 `not_configured` (no
shared secret), 401 `unauthorized`, 503 `synapse_unavailable` or
`service_user_unavailable`, 500 `storage_error`.

## Accounts and devices

### Provisioning at sign-in

Every sign-in (wallet, passkey, headless key, device-code grant) goes through
`oidc::provision_synapse_device`. It runs the account half first
(`oidc::provision_synapse_account`: steps 1 to 3 below) and then the device
half (steps 4 and 5). It is best-effort: a Synapse failure is logged and never
fails the sign-in.

1. **Account.** If the resolved localpart is free, the account is created with
   `provision_user`, seeded with the generated alias as displayname (never the
   DID; see [identity-model.md](identity-model.md#the-alias)). A failure here is
   logged at `error`, because it can leave an account without a profile row.
2. **Existing account.** With `SIWXOIDC_MATRIX_SERVER_NAME` set, the profile is
   read. A provider-written displayname is migrated to the alias. If the
   profile row is confirmed absent (a 404 whose `errcode` is `M_UNKNOWN`), the
   account is re-provisioned. Any other answer, including `M_NOT_FOUND`, which
   Synapse 1.154.0 also returned for a present row with no displayname and no
   avatar, counts as present, so a deliberately cleared name is never
   overwritten.
3. **DID field.** `io.inblock.did` is published (see
   [identity-model.md](identity-model.md#publication)).
4. **Device.** `upsert_device` creates the device, or confirms it exists. The
   device ID is the one the client requested in its scope
   (`urn:matrix:client:device:{id}` or the MSC2967 unstable form); otherwise
   `SIWX_` + 8 hex characters. A device this sign-in creates is named after
   the OAuth client: its registered `client_name` (the untagged one, else the
   one with the smallest language tag), else its client ID, cut to Synapse's
   100-character limit. An existing device keeps its name. Synapse's
   `upsert_device` overwrites the name of an existing device whenever one is
   sent, so siwx-oidc upserts without a name and, only when Synapse answers
   201 (created), sets the name with `update_device_display_name`. Any other
   success status leaves the device unnamed.
5. **Cross-signing reset window.** `allow_cross_signing_reset` is called on
   every sign-in, so a client that is halfway through a key reset can publish
   replacement keys (see [Cross-signing](#cross-signing)).

The device-code grant returns the scope in its token response, so a client can
learn the device ID it was given. The authorization-code response of a Matrix
session does not include `scope`.

**Generic-class clients** (`default_clients` entries with `"class": "generic"`)
get the account half only: the Synapse account is created for a new identity and
the `io.inblock.did` field is published (steps 1 to 3), but no device is upserted
and no cross-signing reset is armed. Their localpart comes from the fallible
`resolve_identity`; when the homeserver cannot be asked, the sign-in answers 503
instead of guessing, because a generic client's localpart can become a permanent
mail address. `/authorize` refuses a request that would grant the client no
`openid` (an `invalid_scope` redirect), `/sign_in` checks it again before it
provisions anything, and the authorization code records the class of the client
it was issued to. The code exchange then issues an `oidc` grant with no device,
as the table of code exchanges above describes.

### No device recycling

Sign-in never deletes a device, and never deletes and then reuses a device ID.
Re-provisioning an existing ID is an idempotent upsert that keeps the device's
E2EE keys.

The reason: Synapse's device deletion does not remove the device's
cross-signing signatures, and its signature-upload handler skips new uploads
when a stale signature exists. Reusing a deleted device ID with new keys
therefore produces verification failures that cannot be repaired. Deleting a
device that is *ending* (below) is safe because its ID is never used again.

### Session teardown

Teardown always revokes the ending session's tokens. Whether it also deletes the
Synapse device depends on intent (`compat::TeardownPolicy`): an explicit
sign-out deletes the device, token hygiene does not.

| Endpoint | Policy | Synapse | Tokens |
|---|---|---|---|
| `POST /oauth2/revoke` (RFC 7009) | `TokensOnly` | nothing; the device is **never** deleted | the grants of this `(user, device)`: the access token and its paired refresh token |
| `POST /_matrix/client/v3/logout` | `DeleteDevice` | deletes this session's device | same as revoke |
| `POST /_matrix/client/v3/logout/all` | bulk | lists the user's devices and deletes each (best-effort per device) | all of the user's tokens |
| `DELETE /_matrix/client/v3/devices/{id}`, `POST …/delete_devices` | delete | deletes the named devices of the bearer's own account | tokens of each device |
| MSC4191 `device_delete` / `session_end` | delete | deletes the device after confirming it belongs to the user | tokens of the device |

- **Revoke never deletes the device.** Clients call RFC 7009 revocation on token
  rotation and when dialogs are dismissed. Deleting the device there raced
  in-flight key uploads and broke users' cross-signing identity in a June 2026
  incident.
- `logout/all` ends sessions; it does **not** deactivate the account. It also
  ends the user's own sessions at this provider: every `siwx_user` picker hint
  and `acct_session` account session of the DID (deactivation and erasure do
  too).
- All teardown is idempotent and never returns 500. Revoke always answers 200;
  logout and `logout/all` answer 200 (`{}`), also for an unknown token, unless
  the token store fails: then they answer the retryable 503 (`M_UNKNOWN`) of the
  refresh and device-deletion routes, never a success that revoked nothing. A
  failed logout leaves the bearer valid, so the client's retry tears the whole
  session down; the Synapse device deletes stay best-effort. Revoke keeps its
  best-effort fallback (it deletes the presented token where it can) and its
  200. In delegated-auth mode the access token of an `oidc` grant is the one
  bearer `logout` and `logout/all` do not answer 200: it is not a Matrix
  session, so it is a 401 `M_UNKNOWN_TOKEN` and nothing is torn down (see
  [Grants of other relying parties](#grants-of-other-relying-parties-at-the-matrix-side)).
  Without a Synapse client or server name, teardown
  revokes Redis tokens only. Revocation is keyed on the localpart (the grant's
  `username`, and `TokenMetadata.username` for a legacy entry), not the raw DID.
- In standalone mode tokens have no device, so revoke and logout remove only the
  presented credential: an access token alone, or, for a refresh token, its whole
  grant, the grant's live access token included (RFC 7009 §2.1). The second half
  is provisional, for the maintainers to confirm; before the grant record a
  revoked refresh token left its access token alive for up to 300 s.
- The legacy device-deletion routes accept the bearer token as authorization,
  with no user-interactive auth step, as MAS does for delegated device deletion.
  An unknown token answers 401 `M_UNKNOWN_TOKEN`; a token-store fault answers a
  retryable 503 `M_UNKNOWN` (see above), never a refusal.

## Account management (MSC4191)

siwx-oidc advertises `account_management_uri` (default `{base_url}/account`,
override with `SIWXOIDC_ACCOUNT_MANAGEMENT_URI`) and
`account_management_actions_supported`. Clients deep-link to
`/account?action=<action>[&device_id=<id>]`.

| Action | Aliases | Effect |
|---|---|---|
| `org.matrix.profile` | | show the DID and the Matrix ID |
| `org.matrix.devices_list` | `org.matrix.sessions_list` | list the user's Synapse devices |
| `org.matrix.device_view` | `org.matrix.session_view` | one device (needs `device_id`) |
| `org.matrix.device_delete` | `org.matrix.session_end` | sign one device out (needs `device_id`) |
| `org.matrix.cross_signing_reset` | | allow a cross-signing reset (MSC4312) |
| `org.matrix.account_deactivate` | | deactivate the account (`delete_user` with `erase: false`) and revoke all tokens |
| `io.inblock.account_erase` | `org.matrix.account_erase` | **not in the spec.** Erase the account (`delete_user` with `erase: true`: profile, media and room memberships), revoke all tokens, and delete the DID's passkey credentials and links |
| `io.inblock.account_reactivate` | `org.matrix.account_reactivate` | **not in the spec.** Reactivate an account deactivated with `erase: false` (`reactivate_user`). An erased account is refused, see below |

`io.inblock.account_erase` and `io.inblock.account_reactivate` are
project-specific: Matrix does not define them, so they carry this project's
namespace rather than `org.matrix.`, and other servers and clients will not
support them. Until 2026-09 they were advertised as `org.matrix.account_erase`
and `org.matrix.account_reactivate`; those names are still accepted as
aliases for one upgrade cycle but are no longer advertised. The `session_*`
names are the older aliases, accepted for clients that still send them. The
advertised list lives in one place, `account::SUPPORTED_ACTIONS`, which drives
discovery; `account::canonical_action` maps every accepted name, aliases
included, to the action it dispatches.

### How the page works

- **Re-authentication.** The first action needs a wallet (CAIP-122) signature or
  a passkey assertion. Wallet messages carry a single-use nonce bound to the
  action (`GET /account/nonce`) and must name `{base_url}/account?action=<action>`
  in `Resources:`, so a signature for one action cannot be replayed for another.
- **Account session.** A successful re-auth sets an `acct_session` cookie
  (`Path=/account`, `HttpOnly`, `SameSite=Strict`, 10 minutes) bound to the
  verified DID, and returns a CSRF token. Further actions go to
  `POST /account/action` with the cookie and the CSRF token, without a new
  signature. Deactivate and erase clear the cookie and end every account
  session and `siwx_user` hint of the user. The session is stored under the
  digest of the cookie value (`acct_session/{sha256}`), and the page's
  **Sign out** button (`POST /account/sign_out`) ends it together with this
  browser's `siwx_user` hint.
- **No action given.** `GET /account` with no or an empty `action` shows a menu
  (profile, sessions, deactivate, erase, reactivate). Element Web's generic
  "Manage account" opens the bare URL, and the menu is the only way an Element
  Web user reaches deactivation, since Element Web hides its own deactivation
  option for externally managed accounts. POSTs distinguish an empty action
  (400 `Missing action`) from an unknown one (400 `Unsupported action: …`).
- **Destructive actions.** Deactivate and erase show a warning and a checkbox
  before the authentication buttons. The checkbox is friction only; the
  signature is the authorization. The deactivation warning says "Your account
  stays deactivated until you reactivate it from this page. To delete your data
  permanently, use Erase instead.", because the user can reverse an
  `erase: false` deactivation with `io.inblock.account_reactivate`, which is
  exempt from the deactivation gate. Only the erase warning says "This cannot
  be undone."
- **Erasure is final because siwx-oidc makes it so, not Synapse.** Synapse's
  `reactivate_user` reactivates any deactivated account: it clears the erased
  flag and recreates a blank profile row (1.161.0, `activate_account`), and
  `query_user` does not report erasure. So erase first writes a marker to Redis
  with no expiry (`erased:user/{localpart}` and `erased:did/{sha256 of the
  canonical DID}`) and refuses to erase if it cannot; reactivate refuses an
  account carrying either marker with a 400, before Synapse is asked, and a
  marker it cannot read with a 503. The erased data itself (profile, media,
  room memberships, passkeys) is gone either way. A server admin can still
  reactivate the account in Synapse directly, and flushing Redis removes the
  markers.
- **Devices come from Synapse.** Listing and viewing use the Synapse admin API
  with a minted token, because the MAS API has no device-listing route (its
  device routes are write-only). `device_delete` deletes the Synapse device and
  revokes its OAuth tokens, so introspection reports them inactive.
- **Cross-signing reset** plants the grant, then reads back whether the user has
  a master cross-signing key. If the readback fails, the result is
  `reset_unconfirmed` with guidance rather than a success message.
- **Standalone.** Every action requires `SIWXOIDC_MATRIX_SERVER_NAME`, and all
  but `profile` require a Synapse client. Without them the action answers 400
  with a clear message, never 500.
- Deactivation and erasure set the user epoch first, so a refresh racing the
  sweep cannot restore access, and every grant from before is refused at once.
- Erasure removes the DID's `webauthn:link/*` entries and credentials, and
  standalone passkeys whose key derives to that `did:key`, so the DID cannot be
  signed into again from a leftover passkey.

Live check, which needs a real Synapse (the Synapse mock does not model
`auth_metadata`, and CI skips this test by name):
`cargo test --test e2e_msc3861 msc4191_metadata -- --ignored`.

## Device-code and QR login

siwx-oidc implements the RFC 8628 device authorization grant (MSC4341, spec
v1.18). Element X uses it for QR-code login; `siwx-oidc-auth --device-flow`
uses it for headless machines (see [agents.md](agents.md)).

1. The device calls `POST /device_authorization` with a registered `client_id`
   and optional `scope`. It receives `device_code` (`dvc_…`), `user_code`
   (`XXX-XXX`, 6 consonants), `verification_uri` (`{base_url}/device`),
   `verification_uri_complete`, `expires_in` (1800 s) and `interval` (5 s).
2. The device polls `POST /token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Until approval it
   receives `authorization_pending`; polling faster than the interval returns
   `slow_down`.
3. The user opens `/device?user_code=…` and approves with a wallet (a CAIP-122
   signature over a single-use nonce from `GET /device/nonce`, naming
   `{base_url}/device` in `Resources:`) or with a passkey
   (`/device/passkey/start`, `/device/passkey/finish`). They may also deny.
4. The next poll provisions the Synapse device (the ID from the device's scope,
   or a generated `SIWX_…`), publishes the DID field, and returns tokens with
   the granted scope. Exactly one poll can claim an approved code.

Rules:

- The grant needs delegated-auth mode. Without the shared secret, the token
  endpoint refuses it (`unsupported_grant_type`).
- **A generic-class client never gets it** (`unauthorized_client`): the grant
  mints a Matrix session. It is refused at `/device_authorization` and again at
  the poll, before anything is recorded or claimed, so a code issued while the
  client was Matrix-class cannot be redeemed after it became generic.
- **Existing accounts only.** Approval rejects a DID with no account (400) and a
  deactivated account (401). See [Gates](#gates-that-protect-accounts).
- The tokens belong to the **approving** user's DID, not to the device.
- The device code, the user code and the approval nonce are stored only as
  digests (`device_code/`, `user_code/`, `caip122/` in the
  [Redis keyspace](architecture.md#redis-keyspace)); the user code is hashed
  exactly as presented, which the approval page sends trimmed and upper-cased.

### MSC4108 and Secure Backup

MSC4108 (QR sign-in with E2EE setup) is **still an open proposal**, not part of
the spec. In Element's implementation, the already signed-in device transfers
its cross-signing private keys to the new device over the rendezvous channel.
If that device has no cross-signing keys (no Secure Backup), there is nothing
to transfer and the new device's login fails after approval. See
[troubleshooting.md](troubleshooting.md#qr-code-login-succeeds-at-the-server-then-fails-in-element-x).

siwx-oidc cannot observe that prerequisite: the private keys live on the
sending device. An earlier approval-page check of the published master key
raced first-time key setup and warned healthy users, so it was removed; the
approval response's `warning` is always absent now. The Element Web build used
with this deployment enforces recovery setup on the first device instead.

## Cross-signing

- **First-time setup** needs no extra step from the auth service. MSC3967 lets a
  user upload cross-signing keys without user-interactive auth when they have
  none yet, and Synapse implements it. It works the same with any auth service.
- Older Element Web releases treated a login through a delegated auth service as
  a restored session and skipped cross-signing setup. Element Web fixed this in
  [PR #30141](https://github.com/element-hq/element-web/pull/30141) ("Force
  verification even after logging in via delegate", merged 2025-06-17).
- **Resetting keys** (MSC4312). siwx-oidc calls `allow_cross_signing_reset` at
  every sign-in, and also offers `/account?action=org.matrix.cross_signing_reset`.
  When a client needs the user to approve a reset, it opens that URL from
  `account_management_uri`, the user re-authenticates, siwx-oidc plants the
  grant, and the client retries the upload.
- A failed cross-signing bootstrap is often silent on the client. Upstream
  context: [matrix-rust-sdk#1641](https://github.com/matrix-org/matrix-rust-sdk/issues/1641)
  and [element-meta#2410](https://github.com/element-hq/element-meta/issues/2410),
  both open. The [`cross-signing-bootstrap-and-debug`](../skills/cross-signing-bootstrap-and-debug.md)
  skill has a diagnostic flowchart.

## Element X notes

- **Keep discovery metadata in line with MAS.** Element X (matrix-rust-sdk)
  logs a failed cross-signing bootstrap and does not retry or show an error. In
  May 2026, passkey-first login on Element X reached a working session only
  after siwx-oidc's discovery document advertised
  `prompt_values_supported: ["login", "create"]`, as MAS does. The general
  lesson: when an Element X flow fails without an error, compare siwx-oidc's
  `/.well-known/openid-configuration` (and the homeserver's
  `/.well-known/matrix/client`) with a MAS deployment's. The case study is in
  [troubleshooting.md](troubleshooting.md#case-study-element-x-passkey-first-login).
- `response_modes_supported` advertises both `query` and `fragment`, because
  matrix-js-sdk v42 (Element Web 1.12.24 and later) requires both and otherwise
  falls back to legacy SSO. See
  [the 2026-07-25 finding](audits/2026-07-25-element-jssdk-v42-oauth-compat-finding.md).
- Element X still sends the MSC2967 unstable scopes
  (`urn:matrix:org.matrix.msc2967.client:…`), so both forms are advertised and
  accepted.
- Element X is distributed through app stores, so this project does not patch
  it. Element X users see their DID through
  `/account?action=org.matrix.profile` (Settings → Account → Manage account).
- The [`element-x-qr-code-specialist`](../skills/element-x-qr-code-specialist.md)
  skill and the [QR protocol reference](element-x-qr-code-protocol-spec.md)
  cover the QR flow in depth.

## Gates that protect accounts

Two gates run after the caller has proven control of a DID (a verified CAIP-122
signature or WebAuthn assertion) and before anything is provisioned.

**New identity.** Creating a Matrix account is allowed only through the login
flow (`/sign_in`). The account-management re-auth and QR/device approval reject
a DID that has no account under either localpart scheme.

**Deactivated account.** Synapse's delegated-auth path does not check whether an
account is deactivated; it trusts introspection. siwx-oidc therefore asks
Synapse (`/_synapse/mas/query_user`) before sign-in, account re-auth and device
approval, and refuses a deactivated account. `account_reactivate` is exempt,
since it exists for deactivated accounts.

| Flow | New identity | Deactivated | Check could not run |
|---|---|---|---|
| Login: wallet, headless key, passkey (`/sign_in`) | created; the passkey page asks the user to confirm first | 401 | 503 |
| Account re-auth (`/account/wallet`, `/account/passkey/finish`) | 400 | 401 | 503 |
| QR/device approval (`/device`, `/device/passkey/finish`) | 400, before the code is marked approved | 401 | 503 |

- Both gates **fail closed**. A check that could not run (Synapse unreachable,
  a rejected shared secret) is a 503 with a message that names the server as
  the problem and reveals nothing operational. It is never reported as "no
  account" or "deactivated".
- Both use the fallible `resolve_identity`, never the guess-legacy fallback. The
  deactivation gate runs **before** sign-in resolves the localpart: a guessed
  legacy localpart for a modern-only account would read as "no account" and let
  a deactivated user in.
- Without a Synapse client both gates are no-ops (standalone deployments).
- Details of the passkey-side confirmation, and the exact messages, are in
  [passkeys.md](passkeys.md#new-account-creation-policy).

## What is not supported

- **Password login**, and password or email-based registration.
- **Upstream identity providers** (Google, Keycloak, SAML, LDAP, …).
- **An admin REST API or admin UI.** The only admin-facing endpoint is the
  admin-token mint.
- **Legacy `POST /_matrix/client/v3/login`.** `GET` advertises `m.login.sso`,
  but there is no SSO redirect and no login route. **Clients that do not
  implement the OAuth 2.0 API cannot sign in.**
- Personal access tokens, the client-credentials grant, session limits and
  inactivity expiry.
- **Homeservers other than Synapse.** Only Synapse is tested. Tuwunel, Dendrite
  and Conduit are untested and unsupported.
- Write protection of `io.inblock.did` on unpatched Synapse (see
  [above](#the-synapse-patch-for-ioinblockdid)).

## Notes for implementers

Rules that protect behaviour described above. Each is explained at the named
symbol in the code.

- **An empty `device_id` goes on the wire as `null`, never `""`**
  (`introspect::render_device_id`).
- **A storage error in introspection is a 500, never `{"active": false}`**
  (`introspect::render_introspection`).
- **There is no `admin_token` setting.** Admin access to Synapse comes only from
  minted tokens whose scope carries both `urn:matrix:client:api:*` and
  `urn:synapse:admin:*` (`admin_token::ADMIN_SCOPE`). Keep the TTL clamp.
- **The MAS routes take a bare localpart; the admin and client routes take a
  percent-encoded MXID.** Do not unify them.
- **Revoke never deletes a device.** Device deletion belongs to explicit
  sign-out paths only (`compat::TeardownPolicy`).
- **Never delete and then reuse a device ID.** Sign-in only upserts.
- **Name a device only when this sign-in creates it.** `upsert_device` never
  carries a name, because a name sent with it overwrites the one the user
  chose; a device the upsert created (Synapse answers 201) is then named with
  `update_device_display_name`. The 201 is race-free, unlike a separate
  existence check.
- **`logout/all` never deactivates the account.**
- **Deny-list, never allow-list,** in the Synapse patch configuration.
- **Run the deactivation gate before `resolve_identity_or_legacy`** at sign-in,
  and use the fallible `resolve_identity` in both gates.
- **`account::SUPPORTED_ACTIONS` is the single list** of account actions for
  discovery and dispatch.
