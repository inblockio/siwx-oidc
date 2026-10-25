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
    { "mxid": "@…:other.example", "alias": "…",
      "did": { "state": "unconfirmed", "value": "did:pkh:eip155:1:0x…" } },
    { "mxid": "@…:example.org", "alias": "…", "did": { "state": "not_yet_published" } },
    { "mxid": "@…:example.org", "alias": "…", "did": { "state": "invalid" } } ],
  "limited": false }
```

- `alias` is the Synapse display name and may be absent. It is a search term and a
  label, never a key.
- `verified` and `unconfirmed` carry a DID in `value`; the others carry none.
  Only a `verified` entry is confirmed. `value` is the `sub` of the verified
  proof, never the unsigned `did` member next to it.
- `unconfirmed`: a person on **another homeserver** whose `io.inblock.did` profile
  field holds a well-formed DID, and `value` is that claim. Nobody has checked it:
  a foreign issuer is not ours to trust, so such a person is never `verified`,
  proof or no proof (see [People of other homeservers](#people-of-other-homeservers)).
  A client may let the sharer pick one **behind a strong warning**: a grant to a
  DID gives access to whoever holds that DID, the same as pasting a DID into the
  dialog, and the claimed one may not be the person's. A client that does not know
  the state must treat it as not selectable.
- `not_yet_published`: no proof from this issuer. The person has no
  `io.inblock.did` field (they have not signed in since the field shipped), the
  field has no proof (the issuer's key was ephemeral, or the value is the old bare
  string), or the person is on another homeserver and gave no usable claim.
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
    "example.org",                // the homeserver's server name, see below
))?;

let found = directory.search_for_asker(&session, asker_did, "ada", 10).await?;
```

**`server_name` is the homeserver's own name**, the part after the colon in its
users' MXIDs (Synapse's `server_name`), not the host the client API is served
from when the two differ (`matrix.example.org` behind a delegation of
`example.org`). The split between a local person, whose proof is checked, and a
person of another server, whose claim is only shown, rests on it, and a wrong
name would turn every local person into a foreign one: their valid proof ignored
and their unsigned `did` member shown as a claim. So the client checks it. The
asker of `search_for_asker`, and the owner of the token of `search_as_user`
(`GET /_matrix/client/v3/account/whoami`, asked once, with the first search),
are the homeserver's own people; one who is not on `server_name` is the
non-retryable `DirectoryError::ServerNameMismatch` and nothing else is asked or
read. (An asker who does not exist has no MXID to check and gets the empty
result.) A mismatch is never kept: every search says it again until the
configuration is corrected. Only the homeserver confirms the name, and only
through its `whoami`, asked by the first `search_as_user`, after which that
client asks it no more. Nothing else confirms it: not the asker's MXID, because
siwx-oidc builds it from its own configuration (with the same wrong name on both
sides it would match), and not a module answer, because the module answers an
asker that is not its own with a normal `200` and no results. The check of the
asker in `search_for_asker` is a refusal for that call only.

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
  share its outcome, so a burst makes one refresh request. A failure is shared
  the same way: eight callers behind an issuer that hangs wait for one sign-in
  timeout (30 seconds), not eight in a row, and all eight get the same
  `SignIn` error;
- after a failed attempt the same failure is answered, without a request, for
  `Tuning::failed_sign_in_cooldown` (5 seconds); the first call after that
  tries again. No more than one attempt is ever in flight;
- when the refresh is refused as invalid (400 or 401 `invalid_grant`: the grant
  is gone, the server restarted without its store) or gets no answer in time (the
  server may have rotated the token before the answer was lost), it falls back to
  a fresh sign-in with the key. A refresh answered **429** is different: the
  server did not process it, so the refresh token is kept and the call fails with
  the typed rate limit and its hint (below), shared by the callers that waited;
  the first call after the cooldown tries the same refresh token again. A refresh
  has one clock, `Tuning::flow_request_timeout` (10 seconds, the answer's body
  included), and no shorter timeout wraps it; the bound on a whole sign-in
  (`Tuning::sign_in_timeout`) is never shorter than that one request either (a
  smaller value is raised to it);
- a 401 from the homeserver triggers one fresh sign-in and one retry of the call
  (see "A host that owns the sign-in retries" below to take that over);
- the token's lifetime is the server's `expires_in`, read from any JSON number
  (`3600.5`, `1e20` and a count above `u64` included) and held between 10
  seconds and 24 hours; a missing or non-number `expires_in` (`null`, a string,
  ...) is 60 seconds. The new pair is kept whatever `expires_in` says. The bounds
  are `siwx_oidc_auth::TOKEN_LIFETIME_MIN_SECS`, `TOKEN_LIFETIME_MAX_SECS` and
  `TOKEN_LIFETIME_DEFAULT_SECS`.

**Tokens are held in memory and nowhere else.** Nothing in the module writes a
file or prints a line, and `Debug` output names no token and no key. After a
restart the service signs in again with its key, so no 90-day refresh token sits
on disk. The one secret at rest is the key file.

A sign-in the server refuses is `DirectoryError::SignIn`. `access_denied`
(deactivated or erased account) and `invalid_scope` (the fixed device id was
signed out and the server refuses to reuse it) are final; use
`siwx_oidc_auth::is_device_refused` on the source if you want to pick a new id.
`temporarily_unavailable` and network faults are retryable.

**A host that owns the sign-in retries.** A service that has its own gate for
sign-in attempts (its own backoff, one attempt for the whole process) turns the
client's retry off and renews through its gate:

```rust
let directory = DirectoryClient::new(
    DirectoryConfig::new(issuer, homeserver, server_name).with_sign_in_again_on_401(false),
)?;

let token = session.access_token().await?;      // through your gate
match directory.search_for_asker(&session, asker, term, 10).await {
    Err(DirectoryError::Unauthorized) => {
        // The module refused the token this call used. Drop it, then renew
        // through your gate and search again.
        session.invalidate_access_token(&token).await;
        let _renewed = session.access_token().await?;
        /* search again */
    }
    other => other?,
}
```

With `sign_in_again_on_401` off (default `true`, the behaviour above), a 401 from
the directory module is `DirectoryError::Unauthorized` at once: no sign-in, no
retry. `ServiceSession::invalidate_access_token(rejected)` discards the session's
access token and its refresh token when the access token is `rejected`, so the
next `access_token()` signs in with the key (a refused access token says nothing
good of its refresh token, and this is what the client's own retry does). It
discards only the token it names: when another caller has renewed already, the
call does nothing, so a burst of refused requests that report the same token costs
one renewal. A failed renewal's cooldown applies to the next `access_token()` as
ever. (`search_as_user` never renews: its 401 is `Unauthorized` either way.)

**A rate limit at the sign-in** is `AuthError::RateLimited { retry_after }` in the
source: a 429 at `/authorize`, `/sign_in`, `/token` or the refresh (something in
front of the server usually answers it; the server itself does not). It is
retryable, but not before `retry_after`. `DirectoryError::is_rate_limited()`
answers it, and `DirectoryError::retry_after()` gives the hint, for this and for
the homeserver's 429 alike:

```rust
match directory.search_for_asker(&session, asker, term, 10).await {
    Err(e) if e.is_rate_limited() => {
        let wait = e.retry_after().unwrap_or(Duration::from_secs(30));
        /* try again after `wait` */
    }
    other => other?,
}
```

`retry_after` is the numeric `Retry-After` header held to one hour
(`siwx_oidc_auth::RETRY_AFTER_MAX`); an HTTP-date, no header or anything that is
not a number of seconds is `None`, and the caller picks its backoff. The error
still prints "returned 429", without the body and without the hint.

**A client id the server does not know** is `AuthError::UnknownClient` in the
source, and `DirectoryError::is_unknown_client()` answers it directly. A dynamic
client lapses after 30 days without a use (see `register_public_client`), and
the server then answers `/authorize` for it with a 401 that has no
`WWW-Authenticate` header (and no OAuth `error` code: the body is plain text). It
is not retryable: register again, keep the new `client_id`, and build a new
session. A 401 *with* a `WWW-Authenticate` challenge is something in front of the
server (a proxy's auth wall): that is `AuthError::Unauthorized`, which is not an
unknown client, so registering again is not triggered by it and would not help.
Match the type, never the message text:

```rust
match directory.search_for_asker(&session, asker, term, 10).await {
    Err(e) if e.is_unknown_client() => { /* register_public_client(..), then a new session */ }
    other => other?,
}
```

(`siwx_oidc_auth::is_unknown_client(&anyhow_error)` does the same for the
code-flow entry points. The error still prints
`/authorize returned 401 Unauthorized instead of 303`, as the untyped error did,
so a consumer that matched that text keeps working until it matches the type.)

## Searching

### `search_for_asker(&session, asker_did, term, limit)`

1. `GET {issuer}/resolve?did=<asker>` maps the asker to an MXID
   ([identity-model.md](identity-model.md#looking-up-an-identity-get-resolve)). An
   account that does not exist, or a DID no sign-in could accept (a 400), gets the
   **empty result**, the same as no match, and the module is not called. An asker
   who is not on the configured `server_name` is `ServerNameMismatch`, and the
   module is not called either.
2. `POST {homeserver}/_synapse/client/io.inblock/directory/v1/search` with the
   service token and `{"asker": "@…", "term": "…", "limit": n}`. The module
   searches as the asker through Synapse's own `search_users`, so the visibility
   rule is Element's: public-room members, people who share a private room with
   the asker, minus locked users. It returns each hit as
   `{"user_id", "display_name", "did_field"}`; `did_field` is the raw
   `io.inblock.did` object, absent for remote users and for users without it
   (and never read for a remote user if it is there).
   `{}` (the homeserver's directory is switched off) is an empty result.
3. The claim read, for each hit on another homeserver
   ([below](#people-of-other-homeservers)).
4. The proof check, per local hit.

The status codes: 401 signs the service in again once and retries once (a second
401 is `Unauthorized`; with `sign_in_again_on_401` off the first one is, and
nothing signs in); 403 is `NotAdmitted` (the service is not admitted, or its
account is locked or deactivated); 429 is `RateLimited`, with the `Retry-After`
header or Synapse's `retry_after_ms` when it gave one (at most one hour).

### `search_as_user(user_token, term, limit)`

`POST {homeserver}/_matrix/client/v3/user_directory/search` with the user's own
token and `{"search_term", "limit"}`, then, for each hit,
`GET {homeserver}/_matrix/client/v3/profile/{mxid}/io.inblock.did` with **no
credential** (the route is public by default; a token would tell every
homeserver polled who is asking), at most eight at a time. The local profiles
are read first, and one that cannot be read ends the search before any foreign
server is asked; then the profiles of the people of other servers
([below](#people-of-other-homeservers)); then the proof check for the local
ones. A local profile that cannot be read fails the search; a remote one only
costs that person their claim. The first search of a client also asks
`GET /account/whoami` with the token, once, to check `server_name` (see
[Setting up a service](#setting-up-a-service)). The user's token is never
renewed here: a 401 is `Unauthorized` and the caller, who owns the session,
renews it.

## People of other homeservers

A person whose MXID is on another homeserver has no proof from this issuer, and
none from them would count. Their `io.inblock.did` field is still readable: it is
a profile field, and Synapse answers `GET /_matrix/client/v3/profile/{mxid}/io.inblock.did`
for a remote user by asking their homeserver over federation (checked on
Synapse 1.163, dev, 2026-10-25: 200 with the field for a remote user who has
one, 404 for one who has none, 502 for a homeserver that does not answer). The
client reads it the same way on both transports, with no credential, and reports
what the field *claims*.

| The remote person's profile | State |
|---|---|
| `{"did": "<a well-formed DID>", …}`, with a proof or without | `unconfirmed`, value = the `did` member |
| no field, `null`, a bare string, no `did` member, a `did` that is not a string or not a DID | `not_yet_published` |
| a 404, any other status, a body that is not JSON, no answer in time | `not_yet_published` |

- **Never `verified`.** The proof beside the claim is not looked at, and no key
  set is fetched for it. Verifying a foreign proof against a list of trusted
  foreign issuers is a separate, configured step that does not exist yet.
- **A well-formed DID** is the W3C syntax: `did:`, a method name of lowercase
  letters and digits, `:`, and an id of letters, digits, `. - _ :` and `%XX`, at
  most 2048 bytes, ASCII only. This is stricter than the `did:` prefix check that
  a signed `sub` gets, because a claim is text a stranger chose, shown to a
  person and pasted into a grant.
- **Bounded, and never failing the search.** Each remote read is held to
  `Tuning::remote_profile_timeout` (3 s) and all of them together to
  `Tuning::remote_profiles_timeout` (6 s), counted from the first remote read of
  the search and the wait for a place included. A read ends by the earlier of its
  own bound and that total, and what it found, a miss included, is kept. A slow
  or dead foreign server leaves that one person `not_yet_published`. The local
  people of the same answer are read before any foreign server is asked, so a
  slow one never delays their check, and the foreign reads have eight places of
  their own: at most sixteen slow servers can be waited out in one search (two
  waves of 3 s in the 6 s). A row behind them is not asked in that search and is
  `not_yet_published` in it; the next search asks it, since every server that was
  waited out is remembered for a minute. **Budget for it:** the remote reads add
  up to the total (6 s) to a search's critical path, so a host with a deadline of
  its own for a search sets it above that, or lowers
  `Tuning::remote_profiles_timeout` (it is raised to `remote_profile_timeout`
  when lower, and every duration of a `Tuning` is held to a year).
- **One read per person at a time.** Searches that want the same person at the
  same moment, on either transport, share one read and its outcome (a claim or a
  miss), and a person who appears twice in an answer is read once. A search that
  is dropped while it reads ends that read without an outcome, and one of the
  searches that waited reads instead. A read that ends never replaces an entry
  stored after it began, so a slow failure cannot put a miss over a fresher
  claim.
- **Show the claim as it is, never percent-decoded.** `%XX` escapes are legal DID
  syntax, and `did:web:example.com%3A8443` is not the identifier
  `did:web:example.com:8443`. A client displays and compares a claimed DID byte
  for byte; decoding it for display would show a DID the person never claimed.
- **Kept briefly, apart from the verified cache.** A claim is kept for
  `Tuning::unconfirmed_ttl` (5 minutes) so that a search as you type does not
  ask a foreign server on every keystroke; "no usable claim" (including a server
  that was too slow, and a read the total ended) for `Tuning::remote_miss_ttl`
  (1 minute), so that a dead server costs one wait, not one per search. A claim
  can change, so it is never kept as long as a verified DID, and it never enters
  the verified cache (`CacheStats::verified` does not count it,
  `CacheStats::remote_claims` does). A search that is dropped keeps nothing of
  the read it was running.
- **Nothing is logged.** Neither the claimed DID nor the search term appears in
  any output of this module.

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
| user of another homeserver | never `verified`: `unconfirmed` when the profile claims a well-formed DID, else `not_yet_published`; whatever the proof says ([above](#people-of-other-homeservers)) |
| no field, a bare string, an object with no `proof`, an empty `proof` | `not_yet_published` |
| a verified `(mxid, proof)` still cached | `verified`, no key needed |
| a malformed proof, a bad signature, an `alg` other than ES256, a `kid` the issuer's current key set lacks (after one refetch, see below), an `iss` other than the issuer, a proof for another MXID | `invalid` |
| a proof that verifies and names this MXID | `verified`, value = the signed `sub` |
| the issuer's discovery or key set cannot be fetched and none is held | **an error for the whole search** |
| a `kid` the held key set lacks, and the refetch for it fails or is rate limited | `invalid` in this answer, nothing kept; the search is not failed |

An answer that could not be checked is never turned into a state. Only a proof
that was read and failed is `invalid`; a failure to get any key set is a retryable
`Unavailable` error and nothing of it is stored, so the next search asks again.
A proof whose header is malformed is judged without any key fetch, so a search
whose hits carry no proof fetches no keys at all.

**The key set is fetched one request pair at a time.** Searches that need it
while a fetch is running wait for that fetch and share its outcome, success or
failure, so a burst of cold searches costs the issuer one discovery request and
one key-set request. Fetches never overlap, so a set that was fetched earlier
cannot replace one fetched later.

**An unknown `kid` is looked up again, once per 30 seconds.** A proof whose `kid`
is not in the cached key set is the sign of a rotation the cache has not seen.
The set is fetched again (discovery included) and the proof is verified against
the fresh set; if the `kid` is still absent the proof is `invalid`. At most one
such fetch is made per `Tuning::keys_refetch_interval` (30 seconds, counted from
the start of the latest fetch of any kind, a failed one included), so proofs
carrying made-up kids cost the issuer one fetch per interval. Inside the interval
a proof with an unknown `kid` is `invalid` against the set held. A refetch that
fails does not fail the search either: that proof is `invalid` in this answer
(and no verdict is kept, so the next search after the interval asks again), and
the other rows are answered from the set held. Only a search that has no usable
key set at all (none cached, and the fetch fails) fails, with the retryable
`Unavailable`.

## Caching

| What | Kept for | Bound |
|---|---|---|
| asker DID to MXID, found | 10 minutes | 4096 entries |
| asker DID, no such account | 60 seconds, so a new account is found soon | same cache |
| discovery document and key set | 5 minutes, or sooner on an unknown `kid` (at most one refetch per 30 seconds) | one |
| a verified `(mxid, proof)` | 10 minutes | 4096 entries |
| a remote person's claim | 5 minutes (`unconfirmed_ttl`) | 4096 entries, a cache of its own |
| a remote person with no usable claim, or a read that was too slow | 1 minute (`remote_miss_ttl`) | same cache |

When a cache is full, expired entries go first, then those that would expire
soonest. A proof that fails is never cached as verified, and an error is never
cached as anything. The key is the pair (MXID, proof), so a proof copied into
another profile, or a changed proof for the same MXID, never reuses a verdict.

The defaults are the contract; `Tuning` and `Clock` are open so a test can move
time by hand. Every duration of a `Tuning` is held to a year when a client or a
session is made, so `Duration::MAX` for "never" is a year and not an overflow. A
warm search is one request, the module call.

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
compromised key is rotated out) stops verifying within the key-cache time plus
the verified-cache time, fifteen minutes with the defaults: a proof first checked
against a key set fetched just before the drop is then kept for the full
verified-cache time. It stops within five minutes when the proof was not cached.

## Errors

`DirectoryError` is `#[non_exhaustive]`. Messages carry statuses and error codes,
never the search term, a token or a response body.

| Variant | Meaning | `is_retryable()` |
|---|---|---|
| `InvalidInput` | refused before any request: bounds, an empty asker or token, a session of another deployment | no |
| `NotAdmitted` | 403: the service is not admitted | no |
| `RateLimited { retry_after }` | 429 from the homeserver; `is_rate_limited()` and `retry_after()` also answer for a sign-in that was rate limited (below) | yes, after `retry_after` |
| `Unauthorized` | the token was refused (for the service, even after a fresh sign-in) | no |
| `SignIn { source }` | the service could not sign in; a 429 there is `AuthError::RateLimited` in the `source` (`is_rate_limited()`, `retry_after()`) | by cause (see above) |
| `Unavailable` | network, timeout, 5xx, discovery or key set | yes |
| `UnexpectedStatus { status, errcode }` | a status the client does not act on | no |
| `Protocol` | an answer that is not the contract: malformed JSON, a row without a user id, a body over the cap | no |
| `ServerNameMismatch` | the asker, or the owner of the user's token, is not on the configured `server_name` ([above](#setting-up-a-service)) | no |

## Bounds

Checked on the client, before any request.

- Term: 1 to 64 characters after trimming (characters, not bytes), with no
  control character (Unicode category Cc) anywhere in it. Trimming is exactly
  what the directory module does, Python's `str.strip()`: Unicode whitespace
  plus U+001C to U+001F. The module trims first and checks after, so a control
  character that is whitespace at an end (a tab, a newline, U+0085) is trimmed
  and any other (NUL, BEL, DEL) refuses the term. A term the module would answer
  with a 400 is refused here, before any request; the trimmed term is what is
  sent.
- Limit: 1 to 20. A module that returns more rows than asked for is cut to the
  limit and the result is `limited`.
- 5 seconds per request of the client (`Tuning::request_timeout`), from connect to
  the last byte of the body. The service session's own requests (the sign-in and
  the refresh) are held to 10 seconds each (`Tuning::flow_request_timeout`), the
  headless sign-in as a whole to 30 (`Tuning::sign_in_timeout`, never less than
  one request's 10).
- Response bodies are read under a 256 KiB cap, discovery and key set included. A
  body that declares more is refused before it is read, and one that does not is
  cut off while streaming. A success over the cap is a `Protocol` error. An
  error status over the cap is classified by its status all the same (a 401
  still signs the service in again, a 429 is `RateLimited`, a 5xx is
  `Unavailable`): only the body is dropped, with the hints it would have given.
  A 429 whose body cannot be read at all (the connection drops, the body stalls)
  is still `RateLimited`, with the `Retry-After` header's hint; any other status
  with an unreadable body is `Unavailable`.
- Redirects are never followed, so a bearer token cannot be carried elsewhere.
  The public `verify_did_assertion` follows none either for discovery and the key
  set: the same-origin rule for `jwks_uri` judges the URL the issuer named, and
  a redirect from it would carry the key fetch to another origin after the check.
  `fetch_and_verify_did` follows up to 3 redirects for its unauthenticated
  homeserver profile read only: the proof it returns is checked against the
  issuer's keys whatever host answered, so a homeserver behind a redirect works
  and nothing is gained by refusing it.
- The headless sign-in and refresh read an error answer under the same cap and
  report only its status and, when the body is JSON with an OAuth `error` that is
  a short token (letters, digits, `_`, `.`; at most 64), that code:
  `/token returned 400 Bad Request (invalid_grant)`. Never the body, which is
  whatever the server or a proxy in front of it chose to write. The same goes for
  the redirect of a refusal: only its `error` code (held to the same charset;
  anything else is `unrecognised_error`) is reported, never its
  `error_description`. A transport error names the endpoint (`GET /authorize
  failed`) and never the request URL, which carries the client id, the redirect
  URI, the scope, the code challenge and the state.
- An error answer whose status line arrives and whose body then stalls past the
  request timeout is `AuthError::TimedOut` (transient), at every endpoint
  (`/authorize`, `/sign_in`, `/token`, the refresh, the device flow, the
  registration), not that status: a 400 would read as final and a stall is worth a
  retry. A 429 stays the rate limit with its header's hint, whatever its body does.
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
`io.inblock.did` value of each local user (`null` is a 404). On both transports it
also holds the value a profile read of each **remote** user would return, from
which the claim is taken (`null` or a missing entry is a 404); a local user's entry
is not used on the `module` transport, whose answer carries the field. The proofs inside
were signed once, in a test that creates its key in memory and prints only the
public key and the finished proofs: no private key is stored, so the files can
live in this public repository.

They cover: a verified DID, no field, no proof (absent, empty, bare string), a
remote user (with no claim, and with each kind of claim: `unconfirmed-remote-user`), a proof for another MXID, a tampered payload, an unsigned `did`
member that disagrees with the signed `sub`, and a mixed answer for each
transport. To regenerate:

```bash
DIRECTORY_VECTORS_OUT=siwx-oidc-auth/tests/vectors/directory \
  cargo test -p siwx-oidc-auth --lib regenerate_directory_vectors -- --ignored
```

## Known limits

- **A new signing key is seen at once, a dropped one after the caches turn over.**
  A proof with a `kid` the cached key set lacks triggers one refetch (at most one
  per 30 seconds; if it fails, that proof is `invalid` in that answer and the
  search is not failed), so accounts whose proof was re-signed after a rotation
  verify on the next search. A key the issuer dropped keeps verifying proofs already
  cached as verified until that verdict expires, and the cached key set itself is
  replaced after five minutes: proofs signed by the retired key are `invalid` once
  both have expired (at most fifteen minutes with the defaults, see above).
- **One unreadable profile fails a `search_as_user`.** A profile read that answers
  500 (an account with a `users` row and no `profiles` row, element-hq/synapse#19702)
  has an unknown state, and the result type has no state for "unknown". The whole
  search is a retryable error rather than a claim about one person. The module
  transport is unaffected: it reads the profiles on the homeserver.
- **`search_as_user` needs the profile route to be public.** A homeserver that sets
  `require_auth_for_profile_requests` refuses the anonymous read; use
  `search_for_asker`.
- **A remote person's DID is never verified.** It is read through our homeserver and
  reported as `unconfirmed`. Verifying it against the foreign homeserver's issuer
  ([identity-model.md](identity-model.md#looking-up-an-identity-get-resolve)), for
  an operator-configured list of trusted foreign issuers, is a later step.
- **A remote read depends on federation.** A homeserver that does not federate with
  the person's, or that refuses profile lookups over federation
  (`allow_profile_lookup_over_federation` off), leaves them `not_yet_published`.
- **The service states who is asking.** The module trusts an admitted service's
  `asker`. Forwarding the user's own signed sign-in message for siwx-oidc to check
  is the upgrade that removes that trust; it needs siwx-oidc to keep the proof.
