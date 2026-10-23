# Directory lookups: finding people with a verified DID

This guide is for services that need to answer "whom may this person find under
this name?" and fill a recipient field with a DID they can trust. The answer is
the one Element would give that person, because it comes from Synapse's own user
directory, and each person who has one comes back with a DID whose proof has been
checked.

`siwx_oidc_auth::directory` (in the `siwx-oidc-auth` crate) is the Rust client.
The TypeScript package for browser apps is a later step; it will run the same
[test vectors](#test-vectors).

- [Two transports, one result](#two-transports-one-result)
- [The result](#the-result)
- [Setting up a service](#setting-up-a-service)
- [Searching](#searching)
- [How a proof is checked](#how-a-proof-is-checked)
- [Caching](#caching)
- [Revoking a service](#revoking-a-service)
- [Errors](#errors)
- [Bounds](#bounds)
- [Test vectors](#test-vectors)
- [Known limits](#known-limits)

## Two transports, one result

| | `search_for_asker` | `search_as_user` |
|---|---|---|
| For | a service that is not the asker (a node, a portal) | an app that holds the user's own Matrix session (an agent, a client) |
| Credential | the service's own token, from signing in with **its own key** | the user's Matrix access token |
| Who is searched as | the asker, named by DID and resolved to an MXID at siwx-oidc | the token's owner |
| Search | the homeserver's directory module, which calls Synapse's `search_users` for the asker | `POST /_matrix/client/v3/user_directory/search` |
| DID of each hit | the raw `io.inblock.did` object, returned by the module with the row | read from the profile route, one request per local hit, at most 8 at a time |
| Proof check | in this client | in this client, the same code |

Both give the same people for the same asker. A shared secret is never involved:
the service proves itself with a signature, the way an agent does
([agents.md](agents.md)), and this is the service signing in, not OIDC login for
the users it serves.

## The result

```json
{ "results": [
    { "mxid": "@k3f9x2q7ab4d8m1p:example.org",
      "alias": "Ada Lovelace",
      "did": { "state": "verified", "value": "did:key:zDn…" } },
    { "mxid": "@…:example.org", "alias": "…", "did": { "state": "not_yet_published" } },
    { "mxid": "@…:example.org", "alias": "…", "did": { "state": "invalid" } } ],
  "limited": false }
```

- `alias` is the Synapse display name and may be absent. It is a search term and a
  label, never a key.
- Only `verified` carries a DID, and only a `verified` entry should be offered as a
  recipient. `value` is the `sub` of the verified proof, never the unsigned `did`
  member next to it.
- `not_yet_published`: no proof from this issuer. The person has no
  `io.inblock.did` field (they have not signed in since the field shipped), the
  field has no proof (the issuer's key was ephemeral, or the value is the old bare
  string), or the person is on another homeserver.
- `invalid`: a proof is there and does not verify (a bad signature, an unknown
  `kid`, a proof for another MXID, a malformed token).
- `limited` is true when the homeserver says more people matched, or when this
  client cut the answer to the `limit` asked for.

The types derive `Serialize` and not `Deserialize`, for the reason `VerifiedDid`
does: deserializing a "verified" value would be an entrance around the check. A
`Verified` state can only be made by this module.

As with every published DID, a verified one is a **discovery hint, not an
authorization source** ([identity-model.md](identity-model.md#trust-model-a-discovery-hint-never-an-authorization-source)).
It fills a recipient field. The grant that follows is a fresh signature by the
DID's key, never the directory's word.

## Setting up a service

Three things, once.

1. **A key.** The service's own Ed25519 or P-256 key, PKCS#8 PEM, mode 0600
   ([agents.md](agents.md#getting-an-identity)). Its DID is the service's Matrix
   account, created by its first sign-in.
2. **A public OIDC client.** Register it once and keep the id:

   ```rust
   let client_id = siwx_oidc_auth::directory::register_public_client(
       "https://auth.example.org",
       "https://service.example.org/callback", // registered, never visited
       "Directory Service",                    // names the Matrix device
   ).await?;
   ```

   This is the RFC 7591 registration of [agents.md](agents.md#prerequisites):
   `token_endpoint_auth_method: "none"` and the `authorization_code` and
   `refresh_token` grants. The `client_secret` and `registration_access_token` the
   server returns are dropped unread; the client is public because the service
   proves itself with its key. A dynamic client lapses after 30 days without a use
   (every sign-in renews it); a service refused as an unknown client registers
   again and keeps the new id.
3. **Admission on the homeserver.** The directory module answers only the
   accounts in its `admitted_services` setting, which names the service's MXID.
   Until it is there, every search is `NotAdmitted`.

Then, for the life of the process:

```rust
use siwx_oidc_auth::directory::*;
use siwx_oidc_auth::SiwxKey;

let key = SiwxKey::from_pem_file("/etc/service/key.pem".as_ref())?;
let session = ServiceSession::new(ServiceSessionConfig::new(
    "https://auth.example.org",   // issuer: also the trust anchor for proofs
    "https://matrix.example.org", // homeserver client API
    client_id,
    "https://service.example.org/callback",
    "directory-service",          // a FIXED device id, see below
    key,
))?;
let directory = DirectoryClient::new(DirectoryConfig::new(
    "https://auth.example.org",
    "https://matrix.example.org",
    "example.org",                // the homeserver's server name
))?;

let found = directory.search_for_asker(&session, asker_did, "ada", 10).await?;
```

**Hold one `DirectoryClient` and one `ServiceSession`.** The caches live in the
client, and the single-flight token renewal lives in the session. The client is
cheap to clone and clones share their caches.

### The service session

`ServiceSession` signs in with `authenticate_with_device` on the **fixed device
id** you give it, so a restart reuses one Matrix device instead of leaving a new
one behind each time. `access_token()` returns a token that is good now:

- it signs in on first use;
- it renews 30 seconds before the token expires (an access token lasts five
  minutes), with `refresh` first;
- renewal is single flight: callers that arrive while it runs wait for it and
  share the result, so a burst makes one refresh request;
- when the refresh fails (the grant is gone, the server restarted without its
  store) it falls back to a fresh sign-in with the key;
- a 401 from the homeserver triggers one fresh sign-in and one retry of the call.

**Tokens are held in memory and nowhere else.** Nothing in the module writes a
file or prints a line, and `Debug` output names no token and no key. After a
restart the service signs in again with its key, so no 90-day refresh token sits
on disk. The one secret at rest is the key file.

A sign-in the server refuses is `DirectoryError::SignIn`. `access_denied`
(deactivated or erased account) and `invalid_scope` (the fixed device id was
signed out and the server refuses to reuse it) are final; use
`siwx_oidc_auth::is_device_refused` on the source if you want to pick a new id.
`temporarily_unavailable` and network faults are retryable.

## Searching

### `search_for_asker(&session, asker_did, term, limit)`

1. `GET {issuer}/resolve?did=<asker>` maps the asker to an MXID
   ([identity-model.md](identity-model.md#looking-up-an-identity-get-resolve)). An
   account that does not exist, or a DID no sign-in could accept (a 400), gets the
   **empty result**, the same as no match, and the module is not called.
2. `POST {homeserver}/_synapse/client/io.inblock/directory/v1/search` with the
   service token and `{"asker": "@…", "term": "…", "limit": n}`. The module
   searches as the asker through Synapse's own `search_users`, so the visibility
   rule is Element's: public-room members, people who share a private room with
   the asker, minus locked users. It returns each hit as
   `{"user_id", "display_name", "did_field"}`; `did_field` is the raw
   `io.inblock.did` object, absent for remote users and for users without it.
   `{}` (the homeserver's directory is switched off) is an empty result.
3. The proof check, per hit.

The status codes: 401 signs the service in again once and retries once (a second
401 is `Unauthorized`); 403 is `NotAdmitted` (the service is not admitted, or its
account is locked or deactivated); 429 is `RateLimited`, with Synapse's
`retry_after_ms` when it gave one.

### `search_as_user(user_token, term, limit)`

`POST {homeserver}/_matrix/client/v3/user_directory/search` with the user's own
token and `{"search_term", "limit"}`, then, for each **local** hit,
`GET {homeserver}/_matrix/client/v3/profile/{mxid}/io.inblock.did` with **no
credential** (the route is public by default; a token would tell every
homeserver polled who is asking), at most eight at a time, then the proof check.
A user of another homeserver is `not_yet_published` and their profile is not
read. The user's token is never renewed here: a 401 is `Unauthorized` and the
caller, who owns the session, renews it.

## How a proof is checked

The rules are those of `verify_did_assertion`
([identity-model.md](identity-model.md#what-the-verifier-checks-in-order)), run
against the issuer's discovery document and key set fetched once and cached. The
public `verify_did_assertion` and `fetch_and_verify_did` are the same code in the
same order and keep their behaviour; the directory client only avoids fetching
the keys again for each proof.

Per hit:

| Input | State |
|---|---|
| user of another homeserver | `not_yet_published`, whatever the field says |
| no field, a bare string, an object with no `proof`, an empty `proof` | `not_yet_published` |
| a verified `(mxid, proof)` still cached | `verified`, no key needed |
| a malformed proof, a bad signature, an `alg` other than ES256, an unknown `kid`, an `iss` other than the issuer, a proof for another MXID | `invalid` |
| a proof that verifies and names this MXID | `verified`, value = the signed `sub` |
| the issuer's discovery or key set cannot be fetched | **an error for the whole search** |

An answer that could not be checked is never turned into a state. Only a proof
that was read and failed is `invalid`; a failure to get the keys is a retryable
`Unavailable` error and nothing of it is stored, so the next search asks again.
A proof whose header is malformed is judged without any key fetch, so a search
whose hits carry no proof fetches no keys at all.

## Caching

| What | Kept for | Bound |
|---|---|---|
| asker DID to MXID, found | 10 minutes | 4096 entries |
| asker DID, no such account | 60 seconds, so a new account is found soon | same cache |
| discovery document and key set | 5 minutes | one |
| a verified `(mxid, proof)` | 10 minutes | 4096 entries |

When a cache is full, expired entries go first, then those that would expire
soonest. A proof that fails is never cached as verified, and an error is never
cached as anything. The key is the pair (MXID, proof), so a proof copied into
another profile, or a changed proof for the same MXID, never reuses a verdict.

The defaults are the contract; `Tuning` and `Clock` are open so a test can move
time by hand. A warm search is one request, the module call.

## Revoking a service

If the service's key, or a token it holds, is stolen from the service host, the
thief can search as any asker until the service is cut off. In this order:

1. Remove the service's account from the module's `admitted_services` and restart
   Synapse. This is immediate: the next call is `NotAdmitted`.
2. Lock or deactivate the account. The module refuses a locked or deactivated
   requester, and deactivation also blocks a new sign-in.
3. Delete the service's device and its siwx-oidc grant.

An access token alone lasts five minutes, and Synapse caches a positive token
check for two. The service keeps no refresh token on disk, so a stolen disk image
yields the key but no grant. Rotate the key and register the new DID as the
admitted service.

A person's DID that stops being valid (the issuer drops a signing key, a
compromised key is rotated out) stops verifying within the verified-cache time,
ten minutes, and within five when the proof was not cached.

## Errors

`DirectoryError` is `#[non_exhaustive]`. Messages carry statuses and error codes,
never the search term, a token or a response body.

| Variant | Meaning | `is_retryable()` |
|---|---|---|
| `InvalidInput` | refused before any request: bounds, an empty asker or token, a session of another deployment | no |
| `NotAdmitted` | 403: the service is not admitted | no |
| `RateLimited { retry_after }` | 429 | yes |
| `Unauthorized` | the token was refused (for the service, even after a fresh sign-in) | no |
| `SignIn { source }` | the service could not sign in | by cause (see above) |
| `Unavailable` | network, timeout, 5xx, discovery or key set | yes |
| `UnexpectedStatus { status, errcode }` | a status the client does not act on | no |
| `Protocol` | an answer that is not the contract: malformed JSON, a row without a user id, a body over the cap | no |

## Bounds

Checked on the client, before any request.

- Term: 1 to 64 characters after trimming (characters, not bytes). The trimmed
  term is what is sent.
- Limit: 1 to 20. A module that returns more rows than asked for is cut to the
  limit and the result is `limited`.
- 5 seconds per request, from connect to the last byte of the body; the headless
  sign-in as a whole may take 30.
- Response bodies are read under a 256 KiB cap, discovery and key set included. A
  body that declares more is refused before it is read, and one that does not is
  cut off while streaming.
- Redirects are never followed, so a bearer token cannot be carried elsewhere.
- The session's issuer and homeserver must be those of the client, so a token
  is never sent to a homeserver it was not issued for.

## Test vectors

`siwx-oidc-auth/tests/vectors/directory/*.json` are the shared fixtures of the
Rust client and the TypeScript package. Each file is self-describing:

```json
{ "format": "siwx-oidc-auth.directory-vector/1",
  "name": "…", "description": "…",
  "transport": "module" | "user_directory",
  "issuer": "https://siwx.example.org", "server_name": "example.org",
  "jwks": { "keys": [ … public keys only … ] },
  "limit": 10,
  "module_response": { … } | "user_directory_response": { … }, "profiles": { … },
  "expected": { "results": [ … ], "limited": false } }
```

An implementation takes the `issuer` as its trust anchor and `jwks` as the key
set the issuer serves, runs the response through its proof check and compares the
output with `expected`. For `user_directory`, `profiles` holds the stored
`io.inblock.did` value of each local user (`null` is a 404). The proofs inside
were signed once, in a test that creates its key in memory and prints only the
public key and the finished proofs: no private key is stored, so the files can
live in this public repository.

They cover: a verified DID, no field, no proof (absent, empty, bare string), a
remote user, a proof for another MXID, a tampered payload, an unsigned `did`
member that disagrees with the signed `sub`, and a mixed answer for each
transport. To regenerate:

```bash
DIRECTORY_VECTORS_OUT=siwx-oidc-auth/tests/vectors/directory \
  cargo test -p siwx-oidc-auth --lib regenerate_directory_vectors -- --ignored
```

## Known limits

- **A new signing key is not seen for up to five minutes.** The key set is cached
  for five minutes and an unknown `kid` is `invalid`, as in `verify_did_assertion`;
  there is no refetch on an unknown `kid`. After a rotation, accounts whose proof
  was re-signed show `invalid` until the cache turns over. Proofs signed by the
  retired key are `invalid` from the moment the issuer drops it, which is the
  point of a rotation.
- **One unreadable profile fails a `search_as_user`.** A profile read that answers
  500 (an account with a `users` row and no `profiles` row, element-hq/synapse#19702)
  has an unknown state, and the result type has no state for "unknown". The whole
  search is a retryable error rather than a claim about one person. The module
  transport is unaffected: it reads the profiles on the homeserver.
- **`search_as_user` needs the profile route to be public.** A homeserver that sets
  `require_auth_for_profile_requests` refuses the anonymous read; use
  `search_for_asker`.
- **Remote users are never looked up.** They are `not_yet_published`; a foreign
  user's DID is read from their own homeserver and verified against that
  homeserver's issuer ([identity-model.md](identity-model.md#looking-up-an-identity-get-resolve)).
- **The service states who is asking.** The module trusts an admitted service's
  `asker`. Forwarding the user's own signed sign-in message for siwx-oidc to check
  is the upgrade that removes that trust; it needs siwx-oidc to keep the proof.
