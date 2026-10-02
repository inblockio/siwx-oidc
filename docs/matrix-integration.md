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

Both modes store token metadata (`TokenMetadata`) in Redis. Tokens are opaque
random strings.

| | Delegated auth | Standalone |
|---|---|---|
| Access token prefix | `mat_` | none |
| Refresh token prefix | `mcr_` | none |
| Scope recorded | `openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}` | `openid profile` |
| Access token TTL | 300 s | 300 s |
| Refresh token TTL | 7,776,000 s (90 days), renewed by each rotation | same |
| ID token TTL | 300 s by default (`id_token_ttl_secs`) | same |
| Introspection | active | 404 |
| Device ID | `SIWX_` + 8 hex characters, or the ID the client requested | empty |

Minted admin tokens use the prefix `msa_`. Device codes use `dvc_`.

The authorization-code grant records the Matrix scope above regardless of the
scopes requested. Clients request the Matrix scopes in either the stable form
(`urn:matrix:client:api:*`, `urn:matrix:client:device:{id}`) or the MSC2967
unstable form (`urn:matrix:org.matrix.msc2967.client:…`); both are advertised.

`/authorize` accepts only `response_type=code`, the only response type
discovery advertises, and requires PKCE with `S256` (`plain` is rejected). The
redirect URI must equal a registered one exactly, query included. `/authorize`
binds the validated request (client, redirect URI, state, response mode, PKCE
challenge) to the login session, and `/sign_in` issues the code for that
request. `/sign_in` reads no authorization parameter from its query: the login
page still appends them to its link, and they are ignored. A code is single use, is deleted when it is exchanged, and is redeemable
only at `POST /token` with its verifier.

### Token kinds

Every token is either an **access token** or a **refresh token**, recorded in
its `TokenMetadata`. A minted admin token is an access token. Each endpoint
accepts exactly one kind:

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
   challenge bound at `/authorize`, and stores an access token and a refresh
   token.
2. `POST /token` with `grant_type=refresh_token` **rotates both**: a new access
   token, a new refresh token, and the old refresh token is deleted. The
   `device_id` and scope are carried over. The refresh response has no ID
   token.
3. **Lost-response grace.** On a successful rotation, siwx-oidc records the old
   refresh token → the successor pair for `REFRESH_GRACE_TTL` (60 s). A client
   that lost the response (common on mobile) and retries with the old refresh
   token within that window receives the **same** successor pair instead of
   `invalid_grant`. Nothing new is minted and the refresh lifetime does not
   grow. The same mechanism applies to `POST /_matrix/client/v3/refresh`. See
   [the 2026-06-23 audit](audits/2026-06-23-elementx-refresh-rotation-signout.md).
4. `POST /token` with the device-code grant provisions the Synapse device and
   issues tokens (see [below](#device-code-and-qr-login)).
5. `/userinfo` accepts an access token only. An authorization code is not a
   bearer token, before or after its exchange.

A refresh is refused (`invalid_grant`, "Session has been revoked.") when the
device was just signed out or the account just deactivated. Short-lived Redis
tombstones (15 minutes) close the race between a refresh and a concurrent
teardown.

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
`oidc::provision_synapse_device`. It is best-effort: a Synapse failure is
logged and never fails the sign-in.

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
learn the device ID it was given. The authorization-code response does not
include `scope`.

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
| `POST /oauth2/revoke` (RFC 7009) | `TokensOnly` | nothing; the device is **never** deleted | all tokens of this `(user, device)`: the access token and its paired refresh token |
| `POST /_matrix/client/v3/logout` | `DeleteDevice` | deletes this session's device | same as revoke |
| `POST /_matrix/client/v3/logout/all` | bulk | lists the user's devices and deletes each (best-effort per device) | all of the user's tokens |
| `DELETE /_matrix/client/v3/devices/{id}`, `POST …/delete_devices` | delete | deletes the named devices of the bearer's own account | tokens of each device |
| MSC4191 `device_delete` / `session_end` | delete | deletes the device after confirming it belongs to the user | tokens of the device |

- **Revoke never deletes the device.** Clients call RFC 7009 revocation on token
  rotation and when dialogs are dismissed. Deleting the device there raced
  in-flight key uploads and broke users' cross-signing identity in a June 2026
  incident.
- `logout/all` ends sessions; it does **not** deactivate the account.
- All teardown is best-effort and idempotent, and never returns 500. Revoke,
  logout and `logout/all` always answer 200 (`{}` for the Matrix routes), even
  for an unknown token. Without a Synapse client or server name, teardown
  revokes Redis tokens only. Revocation is keyed on the localpart
  (`TokenMetadata.username`), not the raw DID.
- In standalone mode tokens have no device, so revoke and logout remove only the
  presented token.
- The legacy device-deletion routes accept the bearer token as authorization,
  with no user-interactive auth step, as MAS does for delegated device deletion.
  An unknown token answers 401 `M_UNKNOWN_TOKEN`.

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
  signature. Deactivate and erase clear the cookie.
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
- Deactivation and erasure plant a deactivation tombstone first, so a refresh
  racing the sweep cannot restore access.
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
- **Existing accounts only.** Approval rejects a DID with no account (400) and a
  deactivated account (401). See [Gates](#gates-that-protect-accounts).
- The tokens belong to the **approving** user's DID, not to the device.

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
