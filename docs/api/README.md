# siwx-oidc HTTP API

`openapi.yaml` in this directory is the machine-readable description of every
route this service serves. It is **enforced**: `tests/openapi_covers_every_route.rs`
reads the router out of `src/axum_lib.rs` and fails the build if a route exists
there and not in the document, so an endpoint cannot ship undocumented.

```bash
# Render it, or import it into Postman/Insomnia/Bruno
npx @redocly/cli preview-docs docs/api/openapi.yaml
npx @redocly/cli lint         docs/api/openapi.yaml
```

Two parts of the API describe themselves at runtime and are authoritative over
anything written here:

```bash
curl -s https://siwx.example.com/.well-known/openid-configuration | jq
curl -s https://siwx.example.com/jwk | jq
```

## Which credential does an endpoint want?

This is the question that causes the most wasted time, because four different
credentials appear in this API and they are not interchangeable.

| Credential | Who holds it | Used on |
|---|---|---|
| Access token (`mat_…`) | the end user's client | `/userinfo`, the Matrix compat logout/device routes |
| MAS shared secret | **the homeserver only** | `/oauth2/introspect`, `/oauth2/admin_token` |
| Registration access token | the relying party | `/client/{id}` |
| Ceremony cookies | a browser mid-flow | `/sign_in`, `/link/webauthn/*`, `/account/*` |
| *(none)* | anyone | discovery, `/jwk`, `/resolve`, `/health`, device-grant start |

The MAS shared secret is a **server-to-server** credential. Those two routes
must not be reachable from the public internet; the reverse proxy in front of
this service is where that is enforced.

## The identity model, in one table

Three identifiers, three owners. Conflating any two is the bug class the split
exists to prevent — the DID used to live in `displayname`, which the user can
rewrite, so a consumer reading it could be handed *someone else's* DID.

| Tier | Value | Owner | Mutable |
|---|---|---|---|
| Alias | a generated `Firstname Surname` | the user | yes, freely |
| MXID | `@{base36(sha256(did)[..10])}:{server}` | derived | no — Synapse has no rename API |
| DID | `did:key:…` / `did:pkh:…` + the provider's signature | the provider | no |

## Common flows

**Authenticate headlessly and read your own identity**

```bash
siwx-oidc-auth --server https://siwx.example.com \
  --client-id my-service --redirect-uri https://app/callback \
  --key-file identity.pem            # -> {access_token, refresh_token, id_token, did}

curl -s https://siwx.example.com/userinfo -H "Authorization: Bearer $ACCESS_TOKEN" | jq
# { "sub": "did:key:…", "io.inblock.mxid": "@1vo8g4vofiha69ua:matrix.example.org", … }
```

**Look up the Matrix account behind a DID** (unauthenticated)

```bash
curl -s "https://siwx.example.com/resolve?did=did:key:z6Mkkx9…" | jq
# { "did": "did:key:z6Mkkx9…", "mxid": "@1vo8g4vofiha69ua:matrix.example.org",
#   "exists": true, "attested": true }

curl -s "https://siwx.example.com/resolve?mxid=@1vo8g4vofiha69ua:matrix.example.org" | jq
```

**Verify a published DID properly** — `attested: true` above verifies no
signature. This does:

```bash
siwx-oidc-auth --verify-did '@1vo8g4vofiha69ua:matrix.example.org' \
  --homeserver https://matrix.example.org \
  --server     https://siwx.example.com     # the ISSUER: a trust anchor, not a hint
```

## What a DID from this API does and does not prove

**A DID is a discovery hint and never an authorization source.** It tells you
what to look up, never what to permit.

A verified assertion proves exactly one thing: *the provider asserted this
DID ↔ MXID binding at `iat`*. It does not prove the holder controls the key
now. Authorization MUST resolve the DID from the `sub` claim of a token this
provider issued, or from a fresh signature by the DID's own key.

`/resolve`'s `attested` flag is weaker still: it says the profile field binds to
that account, with **no signature checked**. The verifier lives in
`siwx-oidc-auth` (a dev-dependency the shipped binary deliberately does not
link), which is why `--verify-did` above is a separate step rather than
something the endpoint does for you.

## Errors

Most routes return an OAuth-shaped body (`{"error": …}`) with a 4xx. Three
conventions are worth knowing because they look like bugs and are not:

- **`/oauth2/introspect` answers `200 {"active": false}` for an unknown token**,
  never a 4xx. Synapse caches a *negative* introspection result, so a 4xx here
  would be cached as a hard failure.
- **`authorization_pending` and `slow_down` on `/token`** are the normal answers
  while a device grant is still awaiting approval.
- **`/resolve` never returns 500.** A homeserver it cannot reach is a 502 naming
  what failed; a deployment with no homeserver configured is a 503. It will not
  guess an answer.

## Stability

`openapi.yaml` carries the crate version. The surface is pre-1.0 and additive
changes (new endpoints, new optional response fields) happen without ceremony.

Two response conventions are load-bearing rather than stylistic, and consumers
should code to them:

- **`/resolve` always returns all four keys**, `null` where unknown. A caller
  never needs both a key-presence branch and a null branch.
- **`io.inblock.mxid` on `/userinfo` is omitted entirely, never null**, when the
  deployment has no homeserver. A present key asserts the thing exists — the
  same rule the `io.inblock.did` profile field follows with its `proof`.

Breaking changes against the `siwe-oidc` predecessor are listed in the root
`CLAUDE.md` under "Breaking changes vs siwe-oidc".
