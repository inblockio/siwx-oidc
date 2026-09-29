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
- **Config file `siwx-oidc.toml`** in the working directory. The legacy `siwe-oidc.toml` is
  still read.
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
| `port` | `SIWXOIDC_PORT` | `8000` | Port to bind. |
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
| `rp_id` | `SIWXOIDC_RP_ID` | host of `base_url` | WebAuthn Relying Party ID. Browsers offer only passkeys registered for exactly this domain. |
| `rp_origin` | `SIWXOIDC_RP_ORIGIN` | `base_url` | Expected WebAuthn origin (scheme, host, port). Set it with `rp_id` when the public origin differs from `base_url`. |

### Clients

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `default_clients` | `SIWXOIDC_DEFAULT_CLIENTS` | none | Map of client id to a JSON client entry, written to Redis at every start. |
| `require_secret` | `SIWXOIDC_REQUIRE_SECRET` | `true` | Whether `POST /token` demands a client secret from a client whose metadata names no `token_endpoint_auth_method`. A client registered with `"none"` never needs one. |

A client entry is `{"secret": "…", "metadata": {…}}`, where `metadata` is RFC 7591 client
metadata (at least `redirect_uris`). Clients can also register themselves through
`POST /register` (dynamic client registration), which is what Matrix clients do.

```toml
[default.default_clients]
my-app = '{"secret":"change-me","metadata":{"redirect_uris":["https://app.example.org/callback"]}}'
```

### ENS names (Ethereum sign-ins)

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `eth_provider` | `SIWXOIDC_ETH_PROVIDER` | none | Ethereum JSON-RPC URL. When set, the ENS reverse record is looked up on-chain first (classic reverse records only). |
| `ens_api_url` | `SIWXOIDC_ENS_API_URL` | `https://api.ensdata.net` | HTTP ENS API, called as `GET {ens_api_url}/{checksummed address}`; must return JSON with `ens_primary`. |

When an ID token is issued, and on every userinfo request, for a `did:pkh:eip155` subject,
siwx-oidc looks up the address's ENS primary name and, if found, puts it in the `name` claim.
**With the defaults this sends every Ethereum user's address to api.ensdata.net, a third
party.** There is currently no switch that disables the lookup: an empty `ens_api_url` is a
startup error (the field's code comment says otherwise, and is wrong). To keep addresses
in-house, point `ens_api_url` at an ENS API you operate, or at an address where nothing
listens (e.g. `http://127.0.0.1:9`); the lookup then fails quietly (logged at `debug`) and
`name` is omitted. Passkey and `did:key` sign-ins never trigger a lookup.

### Matrix

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `mas_shared_secret` | `SIWXOIDC_MAS_SHARED_SECRET` | none | Secret shared with Synapse (its `matrix_authentication_service.secret`). Enables Matrix mode: `mat_`/`mcr_` token prefixes and Matrix scopes, `POST /oauth2/introspect`, `POST /oauth2/admin_token`, and the device-code grant. Without it those endpoints answer 404 and the grant is refused. |
| `synapse_endpoint` | `SIWXOIDC_SYNAPSE_ENDPOINT` | none | Synapse base URL as reachable from siwx-oidc (e.g. `http://synapse:8008`). With `mas_shared_secret` it enables the Synapse client: provisioning, devices, deactivation, DID publication, the sign-in gates. |
| `matrix_server_name` | `SIWXOIDC_MATRIX_SERVER_NAME` | none | The homeserver's `server_name`. Needed to build MXIDs: DID publication, `GET /resolve`, the `io.inblock.mxid` userinfo claim, `/account` device actions and the passkey picker's account hint. Without it those degrade (skipped, omitted or 503), never 500. |
| `account_management_uri` | `SIWXOIDC_ACCOUNT_MANAGEMENT_URI` | `{base_url}/account` | MSC4191 account-management URL advertised in discovery. |
| `admin_token_ttl_secs` | `SIWXOIDC_ADMIN_TOKEN_TTL_SECS` | `300` | Lifetime of a minted admin-scoped token. Clamped in code to 30–900 s. |
| `admin_token_localpart` | `SIWXOIDC_ADMIN_TOKEN_LOCALPART` | `siwx-admin` | Synapse user the admin token acts as. Created on first mint: this is a real Matrix account. |

**What gates DID publication.** The provider-signed `io.inblock.did` profile field needs no
setting of its own. It is published at sign-in when the Synapse client is enabled
(`synapse_endpoint` + `mas_shared_secret`) and `matrix_server_name` is set; without a server
name nothing is published, because the assertion binds an MXID. The `proof` inside it is
minted only with a configured `signing_key_pem`. Write protection of the field is Synapse
configuration, see [matrix-integration.md](matrix-integration.md).

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
a generated key, a public-key fingerprint).

## Running locally

```bash
docker compose -f test/docker-compose.yml up -d redis          # Redis on localhost:6379
(cd js/ui && npm install --legacy-peer-deps && npm run build)  # login page into static/build
SIWXOIDC_BASE_URL=http://localhost:8000 cargo run
```

Run from the repository root: static assets are served from `./static`.

## Docker

CI publishes `ghcr.io/inblockio/siwx-oidc` on pushes to `main` that change more than docs
(tags `main`, `latest` and `sha-…`). There are no release tags yet. The image contains the `siwx-oidc` server, the
`migrate-credentials` tool and the built login page; it sets `SIWXOIDC_ADDRESS=0.0.0.0` and
exposes port 8000. Because `SIWXOIDC_` outranks `SIWEOIDC_`, a legacy `SIWEOIDC_ADDRESS` cannot
override that image default: use `SIWXOIDC_ADDRESS`. A config file goes in the working
directory, `/siwx-oidc`. `GET /health` answers when the server is up.

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
