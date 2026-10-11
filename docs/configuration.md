# Configuration

Every setting of the siwx-oidc server, how to supply it, and how to run the server behind a
reverse proxy. Settings are read from `src/config.rs` (`Config` and its `Default`), which is
the source of truth for the defaults below. Matrix-side configuration (Synapse's
`matrix_authentication_service` block, the profile-field denylist) is in
[matrix-integration.md](matrix-integration.md).

## Names and precedence

Settings come from a TOML file and from environment variables, loaded with
[Figment](https://docs.rs/figment).

- **Environment prefix `SIWXOIDC_`**, e.g. `SIWXOIDC_BASE_URL`. The legacy prefix `SIWEOIDC_`
  (from the upstream siwe-oidc) is still accepted, with no removal scheduled. When both set the
  same key, `SIWXOIDC_` wins, and a startup warning names the legacy variables in use.
- **Config file `siwx-oidc.toml`** in the working directory, or else in the nearest parent
  directory that has one (Figment searches upwards). The legacy `siwe-oidc.toml` is still read,
  found the same way.
- **Precedence, lowest to highest:** defaults < `siwe-oidc.toml` < `siwx-oidc.toml` <
  `SIWEOIDC_*` < `SIWXOIDC_*`.
- **Keys go under a `[default]` table** in the file: the file's top-level tables are Figment
  profiles, and a bare top-level key is rejected at startup. Environment variables are merged
  into Figment's `global` profile, which outranks `default`, so an environment variable always
  beats the file.
- **Nested keys** use `__` in variable names: `SIWXOIDC_DEFAULT_CLIENTS__MYAPP='{"secret":…}'`
  sets the client `myapp`. Figment lowercases variable-derived keys.
- **Lists and maps** in variables use Figment's syntax: `SIWXOIDC_SUPPORTED_DID_METHODS='["pkh","key","peer"]'`,
  `SIWXOIDC_DEFAULT_CLIENTS='{myapp="{\"secret\":\"…\",…}"}'`.
- The headless client's `SIWX_KEY_FILE` is a separate, unprefixed variable (see
  [agents.md](agents.md)).

```toml
# siwx-oidc.toml
[default]
base_url = "https://id.example.org"
redis_url = "redis://redis:6379"
supported_did_methods = ["pkh", "key"]
```

## Reference

Env names are shown with the `SIWXOIDC_` prefix; each also works as `SIWEOIDC_…`.

### Server

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `address` | `SIWXOIDC_ADDRESS` | `127.0.0.1` (image: `0.0.0.0`) | IP address to bind. |
| `port` | `SIWXOIDC_PORT` | `8000` | Port to bind. `0` lets the system pick a free port; the `Listening on` log line names the one bound. |
| `base_url` | `SIWXOIDC_BASE_URL` | `http://127.0.0.1:8000` | Issuer URL, advertised in discovery and used in every endpoint URL. Also the default WebAuthn RP ID (its host) and origin. **Must have a hostname**, see below. |
| `redis_url` | `SIWXOIDC_REDIS_URL` | `redis://localhost` | Redis holding sessions, codes, tokens, clients and passkeys. |
| `log_format` | `SIWXOIDC_LOG_FORMAT` | `pretty` | `pretty` or `json`. See [Logging](#logging). |

**The default `base_url` does not start.** WebAuthn refuses an IP literal as RP ID, so with
pure defaults the server panics while building WebAuthn. Set `SIWXOIDC_BASE_URL` to a URL with
a hostname (`http://localhost:8000` for local work) or set `SIWXOIDC_RP_ID`.

### Signing keys

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `signing_key_pem` | `SIWXOIDC_SIGNING_KEY_PEM` | none: a key is generated at startup | P-256 private key, PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Signs ID tokens, signed userinfo and DID assertions (ES256). |
| `retired_signing_keys_pem` | `SIWXOIDC_RETIRED_SIGNING_KEYS_PEM` | none | One or more **public** P-256 keys (SPKI, `-----BEGIN PUBLIC KEY-----`), concatenated. Published in the JWKS so assertions signed before a rotation stay verifiable. Never used to sign. |
| `id_token_ttl_secs` | `SIWXOIDC_ID_TOKEN_TTL_SECS` | `300` | ID token lifetime in seconds. |

Generate a key:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signing-key.pem
```

Without a configured key the server generates one at every start and logs a warning with its
`kid`. Tokens then stop verifying after a restart, and **no DID assertion is minted**: profiles
get `{"did": …}` with no `proof` (see [identity-model.md](identity-model.md)). Configure a key
for any deployment that publishes DIDs.

The JWKS `kid` is derived from the public key (first 16 hex characters of SHA-256 over the
uncompressed point), so the same PEM always yields the same `kid` and a changed key shows up as
an unknown `kid` rather than a bad signature.

#### Key rotation

DID assertions are stored in Synapse profiles and carry no expiry, so the JWKS is their only
verification anchor. Rotating the signing key without publishing the old public key makes every
proof already written unverifiable for users who do not sign in again.

1. Generate the new key as above.
2. Extract the old key's public half: `openssl pkey -in old-key.pem -pubout -out old-key.pub.pem`.
3. Set `SIWXOIDC_SIGNING_KEY_PEM` to the new key and `SIWXOIDC_RETIRED_SIGNING_KEYS_PEM` to the
   old public key (append earlier retired keys; comments between blocks are allowed).
4. Restart. The JWKS now lists both `kid`s; only the new key signs. Each user's proof is
   re-minted under the new key at their next sign-in.

A **private** key in the retired list is a startup error, not a warning, and so is a malformed
block. Keeping a rotated-out, possibly compromised private key in the environment is exactly
what rotation is meant to end. Retiring a key does not neutralise a compromise: proofs minted
with a stolen key still verify against its retired entry. If a key is known to have been
abused, leave it out of the list and let its proofs fail; the next sign-in re-asserts.

### Sign-in methods

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `supported_did_methods` | `SIWXOIDC_SUPPORTED_DID_METHODS` | `["pkh", "key"]` | DID methods accepted at sign-in. Must be registered in aqua-auth (`pkh`, `key`, `peer`), or startup fails. Passkeys and headless agents produce `did:key`, so keep `"key"` for them. |
| `supported_pkh_namespaces` | `SIWXOIDC_SUPPORTED_PKH_NAMESPACES` | `["eip155", "ed25519", "p256"]` | `did:pkh` namespaces accepted. Must be registered in aqua-auth. |
| `rp_id` | `SIWXOIDC_RP_ID` | host of `base_url` | WebAuthn Relying Party ID. Browsers offer only passkeys registered for exactly this domain. An empty value (`SIWXOIDC_RP_ID=`) is unset, as for `SIWXOIDC_RP_ORIGIN` and `SIWXOIDC_LEGACY_RP_ID`. |
| `rp_origin` | `SIWXOIDC_RP_ORIGIN` | `base_url` | Expected WebAuthn origin (scheme, host, port). Set it with `rp_id` when the public origin differs from `base_url`. |
| `legacy_rp_id` | `SIWXOIDC_LEGACY_RP_ID` | unset | Opt-in for two relying parties. Set it together with a different `rp_id`: then `rp_id` / `rp_origin` name the unified RP (login default, assertions routed by rpIdHash), and `legacy_rp_id` the legacy RP (registration, linking, account and device flows; wallet-linked passkeys sign in through the login page's "passkey linked to a wallet" option). Without `legacy_rp_id` there is one RP, `rp_id` (else the host of `base_url`), exactly as before; an existing `SIWXOIDC_RP_ID` therefore keeps working unchanged. Example: `rp_id = inblock.io` with `base_url` host `dev.siwx.inblock.io` needs `legacy_rp_id = dev.siwx.inblock.io` to get the unified RP `inblock.io`. |

### Clients

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `default_clients` | `SIWXOIDC_DEFAULT_CLIENTS` | none | Map of client id to a JSON client entry, written to Redis at every start with no expiry. An id removed from the map is deleted at the next start; for a generic-class client that also ends its sessions, as does a change of its class or `allowed_scopes` ([details](#changes-that-end-a-generic-clients-sessions)). |
| `require_secret` | `SIWXOIDC_REQUIRE_SECRET` | `true` | Whether `POST /token` demands a client secret, at the code exchange and at the refresh grant alike, from a client whose metadata names no `token_endpoint_auth_method`. A client registered with `"none"` never needs one. |
| `mail_domain` | `SIWXOIDC_MAIL_DOMAIN` | none | Domain of the mailbox address (`<localpart>@<mail_domain>`) of an account that signs in to a generic client. A lowercase DNS name (at most 63 characters per label and 253 in all) that is not an IP address; required when a static client allows `io.inblock.mail`. With it set, `/userinfo` carries the `io.inblock.mailbox` claim where the rules in [identity-model.md](identity-model.md#the-ioinblockmailbox-userinfo-claim) allow it, and discovery lists the `io.inblock.mail` scope and that claim; without it, neither is listed. |

A client entry is `{"secret": "…", "metadata": {…}}`, where `metadata` is RFC 7591 client
metadata (at least `redirect_uris`); an optional `"access_token"` is the registration access
token that manages the client at `/client/{id}`. Clients can also register themselves through
`POST /register` (dynamic client registration), which is what Matrix clients do.
A dynamically registered client is kept for 30 days after its last use (an authorization
request, a code, device-code or refresh exchange, or a userinfo call); after that it must
register again. An authorization request counts only once it passed every check, the redirect
URI exactly as registered included, so whoever knows a client's id and one of its registered
redirect URIs can keep that registration from lapsing; it gives them nothing else.

Redis holds only the SHA-256 digests of the secret and of the registration access token, never
the values, for configured and registered clients alike. A registered client's secret is random;
a configured one is whatever you chose, and an unsalted digest of a weak secret can be guessed
offline by someone who can read Redis. Such a reader on the same host can usually read this
configuration too, where the secret is in the clear, so choose a long random secret and protect
the configuration as you would the secret.

A `default_clients` entry may also set `"class": "generic"` with `"allowed_scopes": ["openid", …]`,
for a client that is not a Matrix client. `POST /register` always creates the `matrix` class, and
an entry without a class is `matrix`. A generic entry may add `"always_granted_scopes"`, scopes
the client receives even when it does not request them, for a client that cannot ask for them; it
defaults to empty. Start-up refuses an entry that:

- is generic in a deployment without `mas_shared_secret` or without `synapse_endpoint`: a
  generic client's account and localpart come from Synapse, and the Synapse client exists only
  when both are set (without it a sign-in provisions no account and resolves no localpart);
- is generic without `openid` in `allowed_scopes`, with a scope that starts with `urn:matrix:` or
  `urn:synapse:`, with a registration access token, or allowing `io.inblock.mail` without
  `mail_domain`;
- is Matrix-class and sets `allowed_scopes` or `always_granted_scopes`;
- lists an `always_granted_scopes` entry that is not in `allowed_scopes`, or lists `openid`
  there (a client requests `openid`, it is never implied);
- names a scope that is not a single word of printable characters (RFC 6749 section 3.3).

`mail_domain` is checked as strictly, whether or not a client uses it. Each refusal is a fatal
error that names the client id (or the setting) and the rule, and it comes before anything is
written to Redis. A build that predates these members ignores them and reads a generic client
as a Matrix client, so every instance that shares one Redis must run a build that knows them.
Never roll back to such a build while a generic client is configured or stored: roll back only
after this build has started once without the generic client in `default_clients` (the sync
deletes the entry and ends its sessions) and the older build starts with a map that does not name
it, because otherwise the older build reads the entry as a Matrix client and the mail client's
next sign-in gets a Synapse device and the Matrix API scope.

A generic client is granted the scopes it requests that are in `allowed_scopes` (any other is
dropped), followed by its `always_granted_scopes`. A request that would grant it no `openid` is
refused: `/authorize` redirects back with `error=invalid_scope`, and an always-granted scope
never makes up for the missing `openid`. A generic sign-in provisions no Synapse device and
answers 503 when the homeserver cannot confirm the account; see
[Provisioning at sign-in](matrix-integration.md#provisioning-at-sign-in). The token endpoint
then issues the client an `oidc` grant with no device and exactly that scope, and a refresh token
only when `offline_access` is part of it and the client's registration allows the
`refresh_token` grant (list `offline_access` in `allowed_scopes` for a client that must refresh);
it never gets the device-code grant, and no ENS lookup runs for its claims.

```toml
[default]
mail_domain = "matrix.example.org"

[default.default_clients]
my-app = '{"secret":"change-me","metadata":{"redirect_uris":["https://app.example.org/callback"]}}'
webmail = '{"secret":"change-me","metadata":{"redirect_uris":["https://mail.example.org/callback"]},"class":"generic","allowed_scopes":["openid","profile","io.inblock.mail"],"always_granted_scopes":["io.inblock.mail"]}'
```

Every start makes the static clients in Redis equal that instance's `default_clients`: it writes
each entry, with no expiry, and deletes each client an earlier start wrote that the map no longer
names. Every instance that shares one Redis must therefore carry the same `default_clients` map,
because the last start wins: an instance with a different map overwrites or deletes the clients
of the others. A static client whose entry carries an `access_token` can still be changed
through its registration endpoint, but that change lasts only until the next start writes the
entry again, and it never gives the client an expiry.

With no `default_clients` there is nothing to write, so the server starts without Redis and
deletes the clients an earlier configuration left behind in the background. If Redis cannot be
reached it retries, after 1 s and then at doubling intervals up to 60 s, until one attempt
succeeds; until then those clients stay registered.

Removing a client, whether by dropping its id from `default_clients` or by `DELETE` on a
dynamically registered one, stops new authorizations and code exchanges for it. For a Matrix-class
client it does not end the sessions that already exist: a refresh token of a removed client still
refreshes (a request that presents a secret is refused, because the client can no longer be
checked), and each refresh issues a new refresh token, so a session keeps refreshing until it is
revoked (token revocation, sign-out or account deactivation), its refresh token goes unused for 90
days, or its absolute lifetime ends when one is set. A generic-class client's sessions do end; see
the next section.

### Changes that end a generic client's sessions

A generic client's session carries a scope this provider decided from the client's entry, so it
must not outlive that entry. The start-up sync therefore ends every session of a generic client,
for good, when the entry it finds in Redis and the configured one differ in one of these ways, or
when nothing is configured for the id any more (it was dropped from the map, or the server started
with no `default_clients` at all):

- the client is removed;
- its class changes, from `generic` to `matrix` or the other way round;
- its `allowed_scopes` change as a set: a scope added or removed counts, the order and a scope
  listed twice do not;
- its registration stops allowing the refresh grant: it listed no `grant_types` or listed
  `refresh_token`, and now lists `grant_types` without `refresh_token`. A refresh token is issued
  only while the registration allows it, so the sessions that hold one must not keep rotating
  under a registration that forbids it. Allowing the refresh grant again ends nothing.

It writes the client's epoch (`epoch:client/{client_id}`, see
[Epochs](matrix-integration.md#epochs)) before it overwrites or deletes the entry, and logs each
one as a warning that names the client and the reason (`removed`, `class_changed`,
`scopes_changed`, `refresh_withdrawn`). From then on every session of the client that was
authenticated before that moment is refused at the token endpoint's refresh grant and at
`/userinfo`; the user signs in again, and a sign-in after it works at once. Nothing else ends a
session: not a restart with the configuration unchanged, not a new secret or redirect URI, not a
change to `always_granted_scopes` alone, and not a change to a Matrix-class client (above). A
stored entry that is missing, or that this build cannot read, sets no epoch.

An instance started with another map, or without the generic client, therefore ends every
session of that client for good, and so does a rollback that carries an older map. The epoch has
no expiry and stays when the id is configured again: sessions from before it stay refused,
sessions from after it work. Deleting the `epoch:client/{client_id}` key lifts it for sessions
that no request has refused yet.

### Grant lifetime

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `grant_absolute_lifetime_secs` | `SIWXOIDC_GRANT_ABSOLUTE_LIFETIME_SECS` | none: no cap | Absolute lifetime of every grant, in seconds, counted from the authentication (the sign-in or the device approval). Past it the refresh token and every access token of the grant are refused, however recently it was refreshed. At least 1800. |
| `grant_absolute_lifetime_secs_by_client` | `SIWXOIDC_GRANT_ABSOLUTE_LIFETIME_SECS_BY_CLIENT__<client id>` | none | Map of client id to seconds, the same cap for one client. A per-client value overrides the global one for that client, longer or shorter, so a client (say Element) can get a longer cap than a short global default. At least 1800. |

With neither set, lifetimes are as before: an access token lives 300 s and a grant ends 90 days
after its last refresh. With a cap, a grant also ends at its authentication plus the cap, and no
access token lives past that moment. The deadline is written into the grant when it is issued
and only ever moves earlier: lowering a cap reaches an existing grant at its next refresh (its
access tokens then live at most 300 s more), raising or removing one never extends a grant. A
grant issued while no cap applied counts from its authentication once one is configured. All
of it runs on the Redis clock, so instances with skewed clocks agree. A value below 1800 s (a
device code's lifetime) is refused at startup: it could refuse a grant before its first token.

These defaults, and the rule that a per-client value overrides the global one rather than only
shortening it, are provisional (decision D1 in the token lifecycle design). Weigh the cost for
Matrix clients before setting a short cap: when a grant ends, Element signs out, and signing in
again usually creates a new device, which must be verified again and restore its key backup.
Agents that hold their own key (`siwx-oidc-auth`) re-authenticate without a person, so a short
cap costs them nothing.

The environment form lowercases the client id (`…_BY_CLIENT__MY-APP` names `my-app`); use the
file for a client id with capitals. Registered client ids are random, so the per-client map is
for configured clients (`default_clients`) and other ids you know; a client cannot yet ask for a
shorter cap in its own registration.

```toml
[default]
grant_absolute_lifetime_secs = 2592000   # 30 days

[default.grant_absolute_lifetime_secs_by_client]
my-app = 86400                           # 1 day
```

### Back-channel logout

A client may register a `backchannel_logout_uri` (OpenID Connect Back-Channel Logout 1.0). In
generic mode (no `mas_shared_secret`), every active deletion of one of its grants (revocation of
the refresh token, `/end_session`, a refresh refused for an epoch or expiry, revocation of all
of a user's grants) POSTs a signed logout token there, from a Redis outbox, with five attempts
and 2 s doubling backoff. A grant that simply expires sends nothing. Matrix mode sends none.

Because registration is open, the URI is checked at registration and at every delivery: it must
use `https` and every address its host resolves to must be public (not loopback, private,
CGNAT, link-local such as the cloud metadata address, multicast, unspecified or reserved).
Delivery connects only to the addresses it checked and follows no redirect.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `backchannel_logout_allowed_hosts` | `SIWXOIDC_BACKCHANNEL_LOGOUT_ALLOWED_HOSTS` | `[]` | Hosts exempt from the address check: a listed host may resolve to a private or loopback address and may use `http`. Matched against the URI's host, case-insensitively, on any port. For relying parties on a private network and for test stubs; every listed host is trusted with logout tokens for its clients. |
| `backchannel_logout_required_for_refresh` | `SIWXOIDC_BACKCHANNEL_LOGOUT_REQUIRED_FOR_REFRESH` | `false` | Refuse the dynamic registration (`400 invalid_client_metadata`) of a client that may receive refresh tokens (its `grant_types` lists `refresh_token` or is absent) unless it registers a `backchannel_logout_uri`. Generic mode only; ignored in Matrix mode. Provisional. |

```toml
[default]
backchannel_logout_allowed_hosts = ["rp.internal.example.org"]
backchannel_logout_required_for_refresh = true
```

### Refresh token reuse

A refresh token that was already rotated away (an older token of the chain, or the previous one
after its successor was used) is reuse: someone besides the client holds the chain, or the client
lost track of it. Reuse is always refused exactly like an unknown token and logged as one
`warn!` security event (`refresh token reuse detected`, `security_event="refresh_token_reuse"`,
with `grant_revoked` saying whether the grant was revoked). A retry with the previous token
while its successor is still unused is a lost response, answered with the same pair, and is
never reuse.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `reuse_revokes_grant` | `SIWXOIDC_REUSE_REVOKES_GRANT` | `false` | Off: reuse is refused and logged, nothing is revoked. On: reuse also revokes the grant, in the same atomic step that detected it, as revoking its refresh token would: its access tokens are inactive at once, the holder of its current refresh token is refused at its next refresh, a generic RP gets a back-channel logout token, and the Synapse device is not deleted (an Element user is signed out and usually signs in again as a new device). Read once at startup. |

Leave it off. Turning it on is decision D2 for the maintainers, with these exit criteria: at
least 30 days of reuse telemetry with the switch off from Element Web and Element X, every reuse
event explained, and no unexplained event for a session with a single holder (hypothesis H6 of
the token lifecycle design). A client that presents an older token on its own, for example a
second process refreshing beside the app without a shared lock, would otherwise be signed out.

### Legal documents

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `op_tos_uri` | `SIWXOIDC_OP_TOS_URI` | none | Your terms of service, advertised as `op_tos_uri` in discovery. |
| `op_policy_uri` | `SIWXOIDC_OP_POLICY_URI` | none | Your privacy policy, advertised as `op_policy_uri` in discovery. |

Each value must be an absolute `http` or `https` URL; anything else stops the server at startup
with an error naming the key. Unset or empty, the field is left out of discovery. There is no
default, because the documents are the operator's own. The footers of the login page, the
device-approval page and the account page link the same two values (the login page reads them
from discovery) and show no legal links when neither is set. The server also serves the files in
`static/legal/` at `/legal/terms-of-use.html` and `/legal/privacy-policy.html`: they are the
maintainers' documents for their own deployment, not templates, and nothing links or advertises
them unless a key points at them.

### ENS names (Ethereum sign-ins)

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `eth_provider` | `SIWXOIDC_ETH_PROVIDER` | none | Ethereum JSON-RPC URL. When set, the ENS reverse record is looked up on-chain first (classic reverse records only). |
| `ens_api_url` | `SIWXOIDC_ENS_API_URL` | none | HTTP ENS API, called as `GET {ens_api_url}/{checksummed address}`; must return JSON with `ens_primary`. An empty value disables it. |

ENS lookups are **opt-in**. With the defaults no lookup happens, no address leaves the server,
and the `name` claim is omitted. When either key is set, siwx-oidc looks up the ENS primary name
of a `did:pkh:eip155` subject when an ID token is issued and on every userinfo request, and puts
it in the `name` claim. Setting `ens_api_url` sends every Ethereum user's address to that API:
`https://api.ensdata.net` is a public one, operated by a third party. To avoid the third party,
point `ens_api_url` at an ENS API you operate, or set only `eth_provider` (with both set, a name
not found on-chain falls back to the HTTP API). Passkey and `did:key` sign-ins never trigger a
lookup.

### Matrix

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `mas_shared_secret` | `SIWXOIDC_MAS_SHARED_SECRET` | none | Secret shared with Synapse (its `matrix_authentication_service.secret`). Enables Matrix mode: `mat_`/`mcr_` token prefixes and Matrix scopes, `POST /oauth2/introspect`, `POST /oauth2/admin_token`, and the device-code grant. Without it those endpoints answer 404, the grant is refused, and discovery advertises neither introspection nor the device-code grant. |
| `synapse_endpoint` | `SIWXOIDC_SYNAPSE_ENDPOINT` | none | Synapse base URL as reachable from siwx-oidc (e.g. `http://synapse:8008`). With `mas_shared_secret` it enables the Synapse client: provisioning, devices, deactivation, DID publication, the sign-in gates. A generic-class `default_clients` entry needs both: start-up refuses it without either. |
| `matrix_server_name` | `SIWXOIDC_MATRIX_SERVER_NAME` | none | The homeserver's `server_name`. Needed to build MXIDs: DID publication, `GET /resolve`, the `io.inblock.mxid` userinfo claim, `/account` device actions and the passkey picker's account hint. Without it those degrade (skipped, omitted or 503), never 500. |
| `account_management_uri` | `SIWXOIDC_ACCOUNT_MANAGEMENT_URI` | `{base_url}/account` | MSC4191 account-management URL advertised in discovery; advertised only when a Synapse client and `matrix_server_name` are configured. |
| `admin_token_ttl_secs` | `SIWXOIDC_ADMIN_TOKEN_TTL_SECS` | `300` | Lifetime of a minted admin-scoped token. Clamped in code to 30–900 s. |
| `admin_token_localpart` | `SIWXOIDC_ADMIN_TOKEN_LOCALPART` | `siwx-admin` | Synapse user the admin token acts as. Created on first mint: this is a real Matrix account. |

**What gates DID publication.** The provider-signed `io.inblock.did` profile field needs no
setting of its own. It is published at sign-in when the Synapse client is enabled
(`synapse_endpoint` + `mas_shared_secret`) and `matrix_server_name` is set; without a server
name nothing is published, because the assertion binds an MXID. The `proof` inside it is
minted only with a configured `signing_key_pem`. Write protection of the field is Synapse
configuration, see [matrix-integration.md](matrix-integration.md).

### Guest mode

The guest server path (work package S1) is off by default. With `guest_enabled = false` every
other `guest_*` key is ignored. With it on, start-up checks the whole block (`validate_guest_config`)
and exits non-zero before binding a port when anything is wrong; the message lists every
problem and names each key. There is deliberately no key for a guest secret: a guest's identity is a
`did:key` the browser makes, and the server never holds or derives it. Lists use Figment's syntax,
for example `SIWXOIDC_GUEST_HOSTS='["alice","did:key:z6Mk…"]'`.

When guest mode is on, start-up refuses:

- a missing `mas_shared_secret`, `synapse_endpoint`, `matrix_server_name`, `guest_client_url` or `guest_client_id`;
- an empty `guest_client_redirect_uris` or `guest_hosts`;
- `supported_did_methods` without `key`;
- a `guest_client_topology` other than `same-site` or `cross-site`;
- a zero for `guest_session_max_secs` or any quota;
- any URL among `base_url`, `guest_client_url` and every `guest_client_redirect_uris` entry that is not `https`. When `base_url`'s host is `localhost`, `127.0.0.1` or `[::1]` (local development), `http` is allowed for all of them. `synapse_endpoint` is exempt from the `https` rule: it is an internal admin endpoint.


**The `/guest` routes.** With guest mode off, every path under `/guest` answers `503` with `{"error":"guest_unavailable"}`, and no other route changes. With it on, an unknown `/guest` path answers `404` with `{"error":"not_found"}`. Either way, every `/guest` response, errors included, carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`, and none of the global CORS layer. With guest mode on:

- A `POST` must be `application/json` (`415`) and at most 4 KiB (`413`). `claim/finish` takes up to 16 KiB.
- The routes a guest's browser calls with its cookie, or with no credential, refuse a `POST` with `403` (`forbidden_origin`) unless at least one of `Origin` and `Sec-Fetch-Site` is present and each present one names this provider (`Origin` equal to the origin of `base_url`, `Sec-Fetch-Site: same-origin`). They answer no CORS. A `GET` is not checked, since a guest reaches the join page from a link.
- The routes authorised by a Bearer token (the host's invitations) answer `Access-Control-Allow-Origin: *` without credentials and have no origin check.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `guest_enabled` | `SIWXOIDC_GUEST_ENABLED` | `false` | Master switch for the guest path. |
| `guest_client_url` | `SIWXOIDC_GUEST_CLIENT_URL` | none | The fixed Meet start URL a guest invitation leads to. Required when on. |
| `guest_client_id` | `SIWXOIDC_GUEST_CLIENT_ID` | none | The OIDC `client_id` of the Meet client: the only client that may use the `urn:io.inblock:guest` scope at `/authorize`. Required when on. At every start it is written as a static public client (no expiry, no secret that anyone knows, `token_endpoint_auth_method = none`, authorization-code and refresh grants) with exactly `guest_client_redirect_uris`; a `default_clients` entry with the same id, or a failure to write it, stops start-up. |
| `guest_client_redirect_uris` | `SIWXOIDC_GUEST_CLIENT_REDIRECT_URIS` | `[]` | Redirect URIs of the Meet client; the guest hand-off accepts exactly these (string-equal) and `/guest/continue` refuses any other. At least one when on. |
| `guest_hosts` | `SIWXOIDC_GUEST_HOSTS` | `[]` | Localparts or DIDs allowed to create invitations. At least one when on. |
| `guest_client_topology` | `SIWXOIDC_GUEST_CLIENT_TOPOLOGY` | `same-site` | `same-site` or `cross-site`: where the Meet client is deployed relative to this provider. With `same-site` (the default) `/authorize` answers a `Sec-Fetch-Site: cross-site` request carrying the guest marker with `access_denied`. |
| `guest_session_max_secs` | `SIWXOIDC_GUEST_SESSION_MAX_SECS` | `7200` | Longest lifetime of a guest session. |
| `guest_name_suffix` | `SIWXOIDC_GUEST_NAME_SUFFIX` | ` (Guest)` | Appended to the typed name to make the guest's display name ("First Second (Guest)"). It seeds the account and is written again, as the canonical name, in the second admin PUT of the hand-off. |
| `guest_email_policy` | `SIWXOIDC_GUEST_EMAIL_POLICY` | `off` | `off` (no address accepted), `optional` or `required`: whether a guest gives an e-mail address at redeem. The same for every invitation. |
| `guest_allow_open_links` | `SIWXOIDC_GUEST_ALLOW_OPEN_LINKS` | `false` | Allow invitations any holder of the link can use. |
| `guest_claim_enabled` | `SIWXOIDC_GUEST_CLAIM_ENABLED` | `false` | Allow a guest to claim a persistent account (`POST /guest/claim/start` and `/finish`, S7a). Needs `matrix_server_name` and a Synapse client (the gate reads the account and the room membership). The claimed account stays confined (the `io.inblock.guest` marker stays) until an operator promotes it. |
| `guest_max_guests` | `SIWXOIDC_GUEST_MAX_GUESTS` | `10` | Guests per invitation. |
| `guest_host_max_invites` | `SIWXOIDC_GUEST_HOST_MAX_INVITES` | `5` | Live invitations per host. |
| `guest_host_max_live_guests` | `SIWXOIDC_GUEST_HOST_MAX_LIVE_GUESTS` | `25` | Live guests per host. |
| `guest_host_invites_per_hour` | `SIWXOIDC_GUEST_HOST_INVITES_PER_HOUR` | `20` | Invitations a host may create per hour. |
| `guest_global_max_active` | `SIWXOIDC_GUEST_GLOBAL_MAX_ACTIVE` | `50` | Active guests across the deployment. |
| `guest_daily_mint_max` | `SIWXOIDC_GUEST_DAILY_MINT_MAX` | `500` | Guest identities minted per day across the deployment. |
| `guest_max_claimed` | `SIWXOIDC_GUEST_MAX_CLAIMED` | `200` | Claimed guest accounts across the deployment: the members of `guest:claimed`; only an erase of a claimed account frees a slot. |
| `guest_max_devices` | `SIWXOIDC_GUEST_MAX_DEVICES` | `8` | Devices per guest. A ninth device hand-off gets `temporarily_unavailable` on the redirect URI. |
| `guest_handoff_per_minute` | `SIWXOIDC_GUEST_HANDOFF_PER_MINUTE` | `3` | Device hand-offs per guest per minute (a sliding 60 s window per record). A fourth gets `temporarily_unavailable` on the redirect URI. |
| `guest_open_link_max_uses` | `SIWXOIDC_GUEST_OPEN_LINK_MAX_USES` | `10` | Uses of one open link. |
| `guest_open_link_max_ttl_secs` | `SIWXOIDC_GUEST_OPEN_LINK_MAX_TTL_SECS` | `86400` | Longest lifetime of an open link. |
| `guest_host_max_open_invites` | `SIWXOIDC_GUEST_HOST_MAX_OPEN_INVITES` | `1` | Live open links per host. |
| `guest_brake_reaping_count` | `SIWXOIDC_GUEST_BRAKE_REAPING_COUNT` | `50` | Guests reaped within `guest_brake_reaping_secs` that pause minting. |
| `guest_brake_reaping_secs` | `SIWXOIDC_GUEST_BRAKE_REAPING_SECS` | `900` | The window `guest_brake_reaping_count` is counted over. |
| `guest_reaper_interval_secs` | `SIWXOIDC_GUEST_REAPER_INTERVAL_SECS` | `15` | Seconds between two ticks of the guest reaper (a zero is read as `1`). The reaper starts with the server **whether or not `guest_enabled` is set**, so guests are still erased after guests are turned off; it needs `synapse_endpoint`, `mas_shared_secret` and `matrix_server_name` and is not started without them. |
| `guest_alert_reaping_secs` | `SIWXOIDC_GUEST_ALERT_REAPING_SECS` | `900` | Alert `reaping_stuck`: a guest record in `reaping` that has been due for longer than this. `0` turns the alert off. |
| `guest_alert_live_pct` | `SIWXOIDC_GUEST_ALERT_LIVE_PCT` | `80` | Alert `live_guests_high`: live guests (`guest:due` size) at this percentage of `guest_global_max_active`. `0` is off. |
| `guest_alert_daily_pct` | `SIWXOIDC_GUEST_ALERT_DAILY_PCT` | `80` | Alert `daily_mints_high`: guests minted today at this percentage of `guest_daily_mint_max`. `0` is off. |
| `guest_alert_refusals_per_min` | `SIWXOIDC_GUEST_ALERT_REFUSALS_PER_MIN` | `50` | Alert `refusal_burst`: more than this many refused guest requests in one minute, counted across instances in Redis (`guest:refusals/{minute}`). `0` is off. |
| `guest_orphan_report_secs` | `SIWXOIDC_GUEST_ORPHAN_REPORT_SECS` | `604800` | Seconds between two report-only orphan scans (Synapse accounts of `user_type` `io.inblock.guest` that have no guest record; the scan asks Synapse for typed accounts only, `not_user_type=`). `0` turns the scan off. With `guest_enabled = false` the scan runs only while a guest is still scheduled in `guest:due` (after guests were turned off); otherwise it takes no lease and makes no Synapse call. One instance per interval wins the Redis lease `guest:orphan_scan:lease`. |

**Kill switch (S6).** There is no HTTP admin endpoint, no config key and no restart: the operator writes Redis. `guest:control` is a HASH with two fields, `guest:banned_hosts` a SET.

```
HSET guest:control disabled 1            # engage (1 or true); HDEL guest:control disabled to clear
HSET guest:control reap_before <epoch>   # every unclaimed guest minted at or before it is due now; HDEL to clear
SADD guest:banned_hosts <host>           # host = the invite's host identity (TokenMetadata.username); SREM to clear
```

`disabled` refuses `POST /guest/invites` (403 `disabled`, with every other host route), peek and redeem (503 `disabled`), the hand-off (`/authorize` marker branch and `/guest/continue`), answers `/guest/resume` as `no_session`, and refuses the guest refresh (400 `invalid_grant`). `reap_before` is enforced twice: the refresh guard refuses a matching guest at once, and each reaper tick moves the deadline of every matching live record to now (a `claimed` account is never touched), so the normal reap follows even with Synapse down. A banned host cannot mint (403 `host_banned`), its invites answer as `revoked` at peek and redeem, and each tick makes its live guests due now. A value that does not parse, or a `guest:control` of another type (an old plain-string key), is an error: the refresh guard answers 5xx and the hand-off is refused; the reaper logs it and keeps reaping what is due. Every change is logged once per instance as `guest_control_changed`.

**Audit events and alerts (S6).** Events use `target: "guest_audit"` with an `event` field (`guest_invite_created`, `guest_minted`, `guest_signin`, `guest_refused` with `route` and `reason`; routes `invites`, `peek`, `redeem` (including `invalid_link`), `authorize`, `refresh` and `continue` (the error code), each counted for `refusal_burst`, `guest_reap` with `reason`, `outcome`, `attempts`, `guest_control_changed`, `guest_orphan`, `guest_orphan_scan`); they carry no name, e-mail, secret or token. Alerts are `error` lines on the same target with an `alert` field (`reaping_stuck`, `live_guests_high`, `daily_mints_high`, `refusal_burst`), at most one per condition per tick, thresholds from the `guest_alert_*` keys. The orphan scan only reports (`guest_orphan` with the localpart); it never erases or writes.

**The reaper (S5b).** Every instance runs a reaper that wakes every `guest_reaper_interval_secs` and tears down the guests in `guest:due` whose deadline has passed (a deadline that ran out, or one moved to now by `POST /guest/end`, the host's end routes or the kill switch), at most 16 per tick. It runs with guests turned off. Several instances can share one Redis: each entry is claimed with `SET guest:reap:lease/<localpart> <owner> NX PX 120000`, so one teardown never runs twice at once, and a holder that died is resumed by another instance when the 120 s lease expires. A failed teardown (the log line names the step and the localpart, never a name or a DID) is retried with a backoff of 15 s doubling to 15 min (`guest:reap:retry/<localpart>` gates the entry, `guest:reap:fail/<localpart>` counts). A guest whose record a hand-off still holds (its 120 s lease) is not a failure: the entry waits 10 s and is tried again, the count is not raised, and the audit event is `guest_reap` with `outcome=deferred` (so `deferred` events are not reaps). On SIGTERM the reaper takes no new guest and lets teardowns in flight finish for up to 5 s; anything still running is abandoned, its lease is given back and the next instance resumes it from the top (the teardown is idempotent). The host's `POST /guest/invites/{invite_id}/end` and `POST /guest/meetings/end` answer `503 unavailable` when the guests' deadlines cannot be moved to now, so they never answer 200 while a guest stays live; the host repeats the call.

**Host API (S2b).** `POST /guest/invites`, `GET /guest/invites`, `POST /guest/invites/{invite_id}/end` and `POST /guest/meetings/end` take a Bearer access token and answer `403` with a fixed `error` class: `not_a_host` (not in `guest_hosts`; a localpart entry matches the account's localpart, an entry starting `did:` matches the DID byte for byte), `admin_token`, `guest_token` (the account holds an unpromoted guest record) or `disabled` (`guest:control` is `disabled`). Create refuses over a limit with `400` and never clamps: `count` at most `guest_max_guests`, `expires_in` at most 259200 (default 86400), `session_secs` 600 to 14400 (default 7200), `kind: open` only with `guest_allow_open_links` (then `max_guests` at most `guest_open_link_max_uses` and `expires_in` at most `guest_open_link_max_ttl_secs`). A room that fails the template answers `422 room_template` with a `reasons` list. On power levels the template allows a per-type `events` override below 50 only for the call types (the four call-member state types at 0, plus the call keys, reaction, notification, decline and redaction types) and for `m.room.encrypted` (F14-R07: registered participants chat in the encrypted room; `events_default` stays 50, and the Synapse guest-policy module still refuses a guest's messages). `m.room.encrypted` is allowed, never required; any other override below 50 answers `room_power_levels`. The per-host quotas `guest_host_max_invites` (active links), `guest_host_max_open_invites` and `guest_host_invites_per_hour` answer `429 quota_exceeded` and write nothing. An invite id is 96 random bits (16 characters of base64url); the secret is `gi_` plus 32 base62 characters, and only its SHA-256 is stored.

**Peek and redeem (S3b).** `POST /guest/peek` and `POST /guest/redeem` carry the invite secret in the body and are authorised by nothing else. An unknown id, a wrong secret and a body that does not parse answer the same `404 {"error":"invalid_link"}`; after the secret verifies, an ended invite is `410` (`expired`, `exhausted`, `revoked`), a rejected input `422` with one reason class, a DID this server already knows `409 did_in_use`, a quota `429 quota_exceeded` with `quota` (`global_active` from `guest_global_max_active`, `daily_mint` from `guest_daily_mint_max`, `host_live_guests` from `guest_host_max_live_guests`) and the kill switch (`guest:control` = `disabled`) `503 disabled`. The browser proves possession of its `did:key` by signing a CAIP-122 message over the peek nonce; the signature is base64url without padding (standard base64 is accepted). The nonce key is derived from `signing_key_pem` when one is configured, else random per process: without a configured signing key a restart, or a second instance, invalidates nonces issued before it (they live five minutes). Success sets `__Host-guest_session` (`Secure; HttpOnly; SameSite=Lax; Path=/`, `Max-Age` to the deadline); with a plain-http `base_url` (local development) the cookie is `guest_session` without `Secure`. The deadline is Redis `TIME` plus the invite's `session_secs`. Redeem makes no Synapse write.

### Variables outside the config struct

| Variable | Meaning |
|---|---|
| `RUST_LOG` | Log filter, see [Logging](#logging). |
| `AQUA_WEBAUTHN_REDIS_URL` | Unset or empty (default): passkeys live only in `webauthn:credential/*`. Set to a Redis URL: every passkey write is mirrored into aqua-auth's credential store there and reads fall back through it. The server refuses to start if the URL is set but the store cannot be opened. The legacy namespace stays authoritative, so unsetting it loses nothing. |

The image also ships `migrate-credentials`, which backfills existing passkeys into that store:
`migrate-credentials [--apply] [--source-redis URL] [--target-redis URL]`. It is a dry run
without `--apply`, only adds keys, and can be re-run.

## Logging

Logs go to stdout through `tracing`. `RUST_LOG` sets the filter (default
`siwx_oidc=info,tower_http=info,warn`; for example `RUST_LOG=siwx_oidc=debug,tower_http=debug`).
`SIWXOIDC_LOG_FORMAT=json` switches to one JSON object per line for log aggregation. Secrets,
tokens and key material are never logged; the signing key appears only as its `kid` (and, for
a generated key, a public-key fingerprint). A credential that a log line has to refer to (a
token, authorization code, device code, user code, session id, passkey credential id) appears
as a fingerprint, the first eight hex characters of its SHA-256, which you can compute for a
value you hold to find the lines about it: `printf %s "$value" | sha256sum | cut -c1-8`. A
request is logged by method and path, never by query.

## Running locally

```bash
docker run -d --rm --name siwx-redis -p 6379:6379 redis:7-alpine  # Redis on localhost:6379
(cd js/ui && npm ci && npm run build)  # login page into static/build
SIWXOIDC_BASE_URL=http://localhost:8000 cargo run
```

Run from the repository root: static assets are served from `./static`.

## Docker

CI (`.github/workflows/docker.yml`) publishes `ghcr.io/inblockio/siwx-oidc`. A push to `main`
is tagged `main`, `latest` and `sha-<short commit>`; a push to the `fork-stable` branch is
tagged `fork-stable` and `sha-…` (pushes that change only docs are not built); a published
GitHub release with a semver tag `vX.Y.Z` is tagged `X.Y.Z`, `X.Y` and `sha-…`. There are no
releases yet, so no semver tags exist. The image contains the `siwx-oidc` server, the
`migrate-credentials` tool and the built login page; it sets `SIWXOIDC_ADDRESS=0.0.0.0` and
exposes port 8000. Because `SIWXOIDC_` outranks `SIWEOIDC_`, a legacy `SIWEOIDC_ADDRESS` cannot
override that image default: use `SIWXOIDC_ADDRESS`. A config file goes in the working
directory, `/siwx-oidc`. `GET /health` answers when the server is up.

- **Unprivileged user.** The server runs as UID/GID 10001, not root. It writes nothing to
  disk (all state is in Redis), so it needs no writable volume; a mounted config file only
  has to be readable by UID 10001. Keep the port at 1024 or above (the default 8000 is):
  an unprivileged process cannot bind a lower one unless the runtime allows it.
- **Stopping.** SIGTERM (`docker stop`) and SIGINT stop the server gracefully: it stops
  accepting connections, answers the requests already in flight and exits with status 0,
  logging one `shutting down` line naming the signal. With no request in flight a stop takes
  well under a second, not the 10 s grace period; an open idle connection does not delay it
  (`tests/graceful_shutdown.rs`).
- **License notices.** `/usr/share/licenses/siwx-oidc/` holds `LICENSE`, `NOTICE` and the
  third-party license texts generated during the build: `THIRD-PARTY-LICENSES-rust.txt` for
  the crates linked into the binaries (cargo-about, configured in `about.toml`) and
  `THIRD-PARTY-LICENSES-js.txt` for the npm packages bundled into the login page. The image
  is built on Alpine Linux 3.24.2. Its packages declare their licenses in
  `/lib/apk/db/installed`, and `/usr/share/licenses/alpine/` holds the text of every license
  they declare (SPDX license-list-data, pinned by tag and checksum). `NOTICE` says where the
  packages' source is: the aports tag `v3.24.2` and Alpine's `distfiles/v3.24/`.
- **Building it yourself.** The base images are pinned by digest and the build uses
  `Cargo.lock` and `package-lock.json` as they are (`--locked`, `npm ci`). The build fails
  when a dependency brings a license outside the accepted lists in `about.toml` and
  `js/ui/third-party-licenses.js` (review the license, then add it), when cargo-about warns,
  for example about a stale clarification checksum (`scripts/third-party-notices.sh`), and
  when an Alpine package declares a license with no text in the `alpine_licenses` stage or
  `NOTICE` does not name the Alpine release. How to bump a base image is described at the
  top of the `Dockerfile`.

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signing-key.pem
docker network create siwx
docker run -d --name redis --network siwx redis:7-alpine
docker run -d --name siwx-oidc --network siwx -p 8000:8000 \
  -e SIWXOIDC_BASE_URL=https://id.example.org \
  -e SIWXOIDC_REDIS_URL=redis://redis:6379 \
  -e SIWXOIDC_SIGNING_KEY_PEM="$(cat signing-key.pem)" \
  ghcr.io/inblockio/siwx-oidc:main
```

The `SIWXOIDC_` names need an image built with the `SIWXOIDC_` rename or later;
older images read only `SIWEOIDC_`, which remains accepted either way.

For a Matrix deployment add `SIWXOIDC_MAS_SHARED_SECRET`, `SIWXOIDC_SYNAPSE_ENDPOINT` and
`SIWXOIDC_MATRIX_SERVER_NAME`, and configure Synapse as described in
[matrix-integration.md](matrix-integration.md). A complete Synapse + Element Web + siwx-oidc
stack is maintained in [siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server).

Redis holds passkeys and account links with no TTL, and dynamically registered clients for
30 days; enable Redis persistence (AOF or RDB) or they are lost on restart.

## Reverse proxy and CORS

siwx-oidc answers cross-origin requests itself: it sends `Access-Control-Allow-Origin: *` for
`GET`, `POST` and `OPTIONS` with `Content-Type` and `Authorization` headers. If your reverse
proxy also sets CORS headers (for example a restricted origin for the homeserver's web client),
**strip the upstream ones** in the proxy. Otherwise the browser sees two
`Access-Control-Allow-Origin` values, rejects the response, and the OIDC flow fails without a
clear error. In Caddy:

```caddyfile
(strip_upstream_cors) {
	header_down -Access-Control-Allow-Origin
	header_down -Access-Control-Allow-Methods
	header_down -Access-Control-Allow-Headers
	header_down -Access-Control-Allow-Credentials
	header_down -Access-Control-Expose-Headers
	header_down -Access-Control-Max-Age
	header_down -Vary
}

id.example.org {
	header Access-Control-Allow-Origin "https://element.example.org"
	reverse_proxy siwx-oidc:8000 {
		import strip_upstream_cors
	}
}
```

Check with `curl -sI https://id.example.org/.well-known/openid-configuration -H "Origin: https://element.example.org" | grep -ci access-control-allow-origin`,
which must print `1`. A fuller example, including the Matrix client-server paths siwx-oidc
serves, is [e2e/real-stack/Caddyfile](../e2e/real-stack/Caddyfile). `GET /resolve` is
unauthenticated by design; if you want it rate-limited, do it in the proxy.
