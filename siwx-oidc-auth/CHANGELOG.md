# Changelog of `siwx-oidc-auth`

## Unreleased

Behaviour changes of the directory client and the headless client, from the review
of the directory client (PR 88) and its follow-ups (PR 103). A consumer that
matches error text should match the types named here instead.

### Changed

- **`search_for_asker` confirms `server_name` with the homeserver too.** The
  asker's MXID is built by the issuer from its own configuration, so an issuer
  and a client that shared one wrong (delegated) name agreed on it, the module
  answered the unknown asker with a plain empty `200`, and a host reported "ready"
  and served silent empty results. The first module search of a client now asks
  `GET /account/whoami` with the service's own token (the service account is a
  local user of the homeserver, so its real MXID is on the real name), once per
  client, before the module: another name is `DirectoryError::ServerNameMismatch`
  and the module is not asked. It shares the one latch with `search_as_user`
  (only `whoami` sets it, so a client asks once on either transport); a `whoami`
  that fails is the error of that search (`DirectoryError::Whoami`, see Breaking)
  and is not kept, and a 401 signs in again and retries once unless
  `sign_in_again_on_401` is `false`. The refusal of
  an asker string that is not on the name stays. An asker that does not exist
  still gets the empty result and asks nothing.
- **A rate limit is transient.** `AuthError::is_transient` (and
  `siwx_oidc_auth::is_transient`) is now also true for `AuthError::RateLimited`,
  and `DirectoryError::is_retryable()` for a sign-in rate limited at the server:
  retry after `retry_after`, when there is one.
- **The `Retry-After` hint of `DirectoryError::RateLimited` is held to one hour**
  (`RETRY_AFTER_MAX`), from the header and from Synapse's `retry_after_ms` alike,
  and the header is read as RFC 9110 `delay-seconds` (digits only: `+5` and `1e3`
  are no hint, as an HTTP-date always was).
- **No redirects for discovery and the key set.** `verify_did_assertion` (and
  `fetch_and_verify_did` through it) follows no redirect when it fetches the
  issuer's discovery document or key set: the `jwks_uri` was judged as the issuer
  named it, and a redirect from it would carry the key fetch to another origin
  after the check. A 3xx there is an error like any other non-success.
- **The profile read of `fetch_and_verify_did` follows up to 3 redirects.** It is
  unauthenticated and the proof it returns is checked against the issuer's keys
  whatever host answered, so a homeserver that redirects works.
- **Response bodies are read under a 256 KiB cap in the public verifier**, as in
  the directory client: a body that declares more is refused before it is read,
  one that does not is cut off while streaming, and a success over the cap is an
  error. An error status over the cap keeps its status.
- **Errors never print a response body.** The DID verifier, `/authorize`,
  `/sign_in`, `/token`, the refresh and the device flow report an error answer by
  its status and, when the body is JSON with a short `error` or `errcode`, that
  code. A success body of the wrong shape says so without serde's message (which
  quotes the value).
- **Errors never print what the server or the network wrote.** A refusal's
  `error_description`, the URL of a failed request (it carries the client id,
  redirect URI, scope, code challenge and state), the discovery `issuer`, the
  `jwks_uri` and a JWK's `use`, `key_ops`, `alg`, `kty` and `crv` are named by
  their member and never repeated. A refusal `error` outside the short charset of
  the OAuth vocabulary is reported as `unrecognised_error`.
- **No other server-written value reaches an error or stderr either.** The
  `/sign_in` redirect without a `code` is "the /sign_in redirect carries no
  'code'" (it printed the `Location`, which holds the state, client id and
  redirect URI). The DID verifier no longer repeats the proof's header `alg`,
  `typ`, `crit` or `kid`, its claims `iss`, `sub` or `mxid`, the `kid`s and
  `jwks_uri` of the key set, a JWK's `kid`, or a base64 decoder's offending
  symbol: each error names the member at fault. "no JWK with kid ..." is now "no
  JWK with the proof's `kid` in the issuer's JWKS (it offers N key(s))"; the
  `REPLAYED ASSERTION` text names the MXID it was presented for (the caller's)
  and not the one the proof binds. `DidAssertionError::ProofAbsent` keeps
  `unverified_did` as data for a caller that matches on it, but its `Display` no
  longer prints it and its `Debug` leaves it out. The device flow still prints the
  approval address and codes (the person must read them), with control
  characters dropped so they cannot drive the terminal.
- **`fetch_and_verify_did` no longer writes to stderr.** A plain `did` member that
  disagrees with the signed `sub` printed `warning: ... the plain member is
  `<value>` ...` with the homeserver's value; now the result carries
  `VerifiedDid::plain_did_disagrees()` and `siwx-oidc-auth --verify-did` tells the
  user that the two disagree, without the value. The flag is not part of the
  serialized result, so the CLI's JSON output is unchanged. A library caller that
  relied on the stderr line reads the flag instead.
- **`expires_in` is read tolerantly.** Any JSON number is accepted (`3600.5`,
  `1e20`, above `u64`) and held between `TOKEN_LIFETIME_MIN_SECS` (10) and
  `TOKEN_LIFETIME_MAX_SECS` (24 h); a missing or non-number value is
  `TOKEN_LIFETIME_DEFAULT_SECS` (60). A token answer is never refused for it, so
  the new pair is not lost after the refresh token was consumed.
- **A failed refetch for an unknown `kid` no longer fails a search.** The proof is
  `invalid` in that answer, nothing is cached, the rest of the answer is
  unaffected and the 30 s refetch limit still holds. Only a search with no usable
  key set at all fails.
- **Every request of the code flow, the refresh, the device flow and the
  registration has a timeout of 10 seconds** (`FLOW_REQUEST_TIMEOUT`), from the
  connection to the last byte of the answer. The HTTP client the flows build had
  none, so a server that accepted the connection and never answered held a
  sign-in until the caller's own cap (the directory session's `sign_in_timeout`,
  30 s, which stays). The entry points that take the caller's client
  (`authenticate_with_scope_using`) add none to it: set one on that client. The
  device flow's wait for the approval is not a request and is unchanged; each of
  its requests is held to the timeout.
- **A 429 at `register_public_client` (`POST /register`) is the typed
  `AuthError::RateLimited`**, with the bounded `Retry-After` hint, as at the other
  endpoints (`siwx_oidc_auth::is_rate_limited`, `is_transient`). Its other
  failures read as the flows' do: the status and, when the body is JSON with a
  short `error` or `errcode`, that code, never the body or the
  `error_description`. A failed request is now reported as "OIDC client
  registration request failed" with the cause after it (`{:#}`).

- **A refresh answered 429 keeps its refresh token** and fails with the typed
  `AuthError::RateLimited` and its hint (shared by the callers that waited, then
  answered for the cooldown), instead of signing in at once and losing the hint.
  The server did not process the request, so the token is unspent: the first call
  after the cooldown sends the same one. A refresh refused as invalid (400 or 401
  `invalid_grant`) or that gets no answer in time still falls back to a sign-in.
- **One clock for a refresh.** `ServiceSession` wrapped the refresh in
  `Tuning::request_timeout` (5 s), shorter than the 10 s per-request timeout
  inside it, so a refresh the server answered in time by the flow's clock could be
  abandoned for a sign-in (with the token already consumed). It is now held to
  `Tuning::flow_request_timeout` alone. `Tuning::sign_in_timeout` is raised to
  `flow_request_timeout` when it is smaller, so an outer bound is never shorter
  than the request it wraps.
- **A stalled error body is `AuthError::TimedOut`.** The status line of an error
  answer arrived and the body then timed out: this was reported as that status
  (a 400 reads as final), and is now the transient timeout at `/authorize`,
  `/sign_in`, `/token`, the refresh, the device flow and the registration. A 429
  stays `AuthError::RateLimited` with its header's hint.
- **A 429 from the directory whose body cannot be read is `RateLimited`** with the
  `Retry-After` header's hint (it was `Unavailable`, with the status and the hint
  dropped). Other statuses with an unreadable body are still `Unavailable`.
- **The rotation canary reports a rate-limited sign-in as `sign_in_failed`**, as it
  does a timeout, not as `sign_in_refused` (which says the server turned the
  identity down).

### Added

- **`DidState::Unconfirmed(ClaimedDid)`**, wire form
  `{"state":"unconfirmed","value":"did:..."}`, for a person on ANOTHER homeserver
  whose `io.inblock.did` profile field, read through our homeserver (Synapse asks
  theirs over federation), holds a well-formed DID. It is what they claim and
  nobody has checked: such a person is never `Verified`, proof or no proof. No
  field, a bare string, a value that is not a DID, an unreadable profile or a
  slow server leaves `NotYetPublished`, as before. A client may offer an
  `unconfirmed` person behind a strong warning; one that does not know the state
  must treat it as not selectable. `DidState::unconfirmed_did()`, `ClaimedDid`,
  `CacheStats::remote_claims`, and the `Tuning` fields `remote_profile_timeout`
  (3 s per read), `remote_profiles_timeout` (6 s for all of them of one search),
  `unconfirmed_ttl` (5 min) and `remote_miss_ttl` (1 min). Both transports read
  remote profiles, at most eight at a time (after the local reads, see "Changed
  (remote reads)"); a remote read never fails a search. Claims are kept apart from the verified cache. See "People of
  other homeservers" in `docs/directory.md`.
- **`DirectoryError::ServerNameMismatch`** (not retryable): the asker of a module
  search, or the owner of the token of a user search, is not on
  `DirectoryConfig::server_name`. The name must be the homeserver's own (the part
  after the colon of its users' MXIDs), not a delegated host; with a wrong one
  every local person would look like a person of another server, their valid
  proof ignored and their unsigned `did` shown as a claim. The search is now this
  error and nothing else is asked, and a mismatch is never kept. `search_as_user`
  learns the name from `GET /account/whoami` with the user's token, once per
  client. Only `whoami` confirms the name: a module answer or an asker that
  matched the name does not, since the module answers an asker it does not know
  with a normal empty `200`.
- **`DirectoryClient` and `ServiceSession` hold a `Tuning` to bounds when made**:
  every duration is taken at most a year (`Duration::MAX` for "never" is a year,
  not an overflow and a panic at `remote_profiles_timeout` or inside a spawned
  read), and `remote_profiles_timeout` is raised to at least
  `remote_profile_timeout`.
- **`DirectoryConfig::sign_in_again_on_401`** (default `true`) and
  `DirectoryConfig::with_sign_in_again_on_401(bool)`: a host that owns the sign-in
  retries sets it to `false`, and `DirectoryClient::search_for_asker` then returns
  `DirectoryError::Unauthorized` on a module 401 instead of signing in and
  retrying itself. **`ServiceSession::invalidate_access_token(rejected)`** makes
  the next `access_token()` renew (a fresh sign-in with the key) when the access
  token is `rejected`, and does nothing when another caller has renewed already.
  See "A host that owns the sign-in retries" in `docs/directory.md`.
- **`AuthError::RateLimited { retry_after }`**, `AuthError::is_rate_limited()`,
  `AuthError::retry_after()`, `siwx_oidc_auth::is_rate_limited` and
  `DirectoryError::is_rate_limited()` / `DirectoryError::retry_after()`: a 429 at
  `/authorize`, `/sign_in`, `/token` (the code exchange, the refresh and the
  device poll) or `/device_authorization` is a typed error, so a consumer stops
  matching "returned 429" in the text. `retry_after` is the numeric `Retry-After`
  header held to the new `RETRY_AFTER_MAX` (one hour); an HTTP-date, a missing
  header or anything else that is not a number of seconds gives `None`.
  `DirectoryError::is_rate_limited()` is true for `DirectoryError::RateLimited`
  and for a `DirectoryError::SignIn` whose source is the sign-in's 429, and
  `retry_after()` answers the hint of either. The error text still says
  "returned 429" and carries neither the body nor the hint. The enum is
  `#[non_exhaustive]`, so a variant is additive.
- **`AuthError::UnknownClient`**, `siwx_oidc_auth::is_unknown_client` and
  `DirectoryError::is_unknown_client`: `/authorize` answered 401 without a
  `WWW-Authenticate` header, which is siwx-oidc's own answer for a client id it
  does not know (a dynamic client lapses after 30 days without a use). Register
  again and keep the new id; it is never retryable.
- **`VerifiedDid::plain_did_disagrees()`**: whether the profile object's unsigned
  `did` member named another DID than the signed `sub`. `false` from
  `verify_did_assertion`, which sees the proof alone.
- **`AuthError::Unauthorized`**: a 401 at `/authorize` *with* a
  `WWW-Authenticate` challenge, a proxy's auth wall. It is not an unknown client
  and registering again does not help.
- **`AuthError::TimedOut`**, `AuthError::is_timed_out()` and
  `FLOW_REQUEST_TIMEOUT`: a request of a flow that got no answer within the
  request timeout, in the answer's head or its body, is a typed error and
  transient (`AuthError::is_transient`, `siwx_oidc_auth::is_transient` and
  `DirectoryError::is_retryable` are true). Its `error_code()` is `timed_out`; its
  text is "the server did not answer within the request timeout" and names no
  URL (the URL holds the client id, redirect URI and state). The directory
  session's own cap on the whole sign-in is still an untyped error, as before.
- **`Tuning::flow_request_timeout`** (default `FLOW_REQUEST_TIMEOUT`, 10 s): the
  per-request timeout of the directory session's sign-in and refresh.
- **`DirectoryResults::homeserver_answered()`**: true only when the homeserver
  itself answered the search (the directory module for `search_for_asker`, the user
  directory for `search_as_user`); an answer of nobody counts. It is false for the
  one result that asks no homeserver: `search_for_asker` returns the empty result
  for an asker the issuer does not know (or would not sign in) before the
  service's token and before the module, and a host could not tell that from a
  real, possibly empty, module answer. A host that takes a search for proof that
  the homeserver was reached (for example to clear a backoff it keeps against the
  service's token) should count a result only when this is true. It is not part of
  the serialized form (`{"results", "limited"}` is unchanged) and is kept in a
  private field, so `DirectoryResults` still cannot be deserialized and, as the
  one source-level catch, can no longer be built by a struct literal outside this
  crate (nothing but a search constructs it).

### Changed (remote reads)

- **A remote read ends by the earlier of its own bound and the search's total,
  and keeps its miss.** The total used to cut a read that waited for a place from
  outside, so nothing was kept and a dead server in the second wave of reads
  cost every search the same wait. Up to 16 slow servers (8 places, two bounds)
  are now waited out and remembered in one search.
- **The local profiles of a `search_as_user` are read before any foreign server is
  asked**, and a local read that fails ends the search before one is. The two no
  longer queue for the same eight places (the remote reads have eight of their
  own, counted from the first remote read): a slow foreign server cannot delay
  a local person's check. Remote reads add up to `remote_profiles_timeout` (6 s) to a search's critical
  path; a host with a deadline of its own budgets for it.
- **Reads of one remote person are single-flight.** Searches that want the same
  person at once share one read and its outcome, a person twice in an answer is
  read once, and a read never replaces an entry stored after it began (a slow
  failure no longer puts a 60 s miss over a fresher claim). A search that is
  dropped while it reads ends the read with no outcome and a waiting search reads
  instead.
- A claimed DID may carry `%XX` escapes (legal DID syntax): a client shows it raw,
  never percent-decoded.

### Breaking

- `search_for_asker` makes one more request, `GET /account/whoami` with the
  service's token, in the first search of a client that finds the asker (none
  after the name matched, on either transport). A homeserver that refuses `whoami`
  for the service account fails that search with `DirectoryError::Whoami` (below),
  not the plain error the module call would have had.
  A deployment whose issuer and client share a wrong `server_name` now gets
  `ServerNameMismatch` where it got an empty result.
- `search_as_user` makes one more request, `GET /account/whoami` with the user's
  token, in the first search of a client (none after the name matched). A homeserver
  that refuses `whoami` for the token fails the search with `DirectoryError::Whoami`
  (below), not the plain error the directory call would have had.
- **A `whoami` failure is `DirectoryError::Whoami(Box<DirectoryError>)`, not the
  plain error of its status.** The request of the `server_name` check came back as
  the same error as the directory module's own answer, so a host could not tell a
  homeserver URL (or a proxy) that does not answer `/_matrix/client/v3/account/whoami`
  from a module that is not registered or a service that is not admitted: a
  `whoami` 404 was `UnexpectedStatus { status: 404 }`, as the module's is. Every
  failure to get an answer from `whoami` (a 401 after the fresh sign-in, or at
  once with `sign_in_again_on_401` off, a 403, a 404, a 429, a 5xx, a timeout, a
  body without a user id) is now `Whoami` with the failure inside, on both
  transports. `ServerNameMismatch` stays its own error: `whoami` answered. New
  `DirectoryError::is_whoami()` and `whoami_cause()`; `is_retryable()`,
  `is_rate_limited()`, `retry_after()` and `is_unknown_client()` answer for the
  cause, and `std::error::Error::source()` returns it. A host that matched
  `Unauthorized`, `RateLimited`, `Unavailable`, `UnexpectedStatus` or `Protocol`
  from a first search must also look inside `Whoami`:
  `e.whoami_cause().unwrap_or(&e)` is the error whichever request failed. This
  includes `search_as_user` with a stale token, whose first search is
  `Whoami(Unauthorized)` and a later one, once the name is confirmed, the plain
  `Unauthorized` of the directory call. (The enum is `#[non_exhaustive]`, so a
  `match` with a wildcard arm still compiles.)
- **A failed lookup of the asker is `DirectoryError::Resolve(Box<DirectoryError>)`,
  not the plain error of its status.** `search_for_asker` asks the issuer's
  `GET /resolve` first, and its failure came back as the same error as the
  homeserver's or the directory module's own answer, so a host could not tell a
  proxy that answers 401 in front of the issuer from the service token being
  refused (and renewed it for nothing, or kept a token-refusal backoff it should
  have cleared), nor the issuer's 429 from the module's, nor an issuer without
  `/resolve` from a module that is not registered. Every failure of that request
  (a 401, a 404, a 429, a 5xx, a timeout, a body that is not the contract) is now
  `Resolve` with the failure inside; neither `whoami` nor the module is asked, the
  service does not sign in, and nothing is kept. An asker that does not exist, or a
  DID no sign-in could accept, is still the empty result, and an asker of another
  server is still `ServerNameMismatch`. New `DirectoryError::is_resolve()` and
  `resolve_cause()`; `is_retryable()`, `is_rate_limited()`, `retry_after()` and
  `is_unknown_client()` answer for the cause, and `std::error::Error::source()`
  returns it. A host that matched `Unauthorized`, `RateLimited`, `Unavailable`,
  `UnexpectedStatus` or `Protocol` from `search_for_asker` must also look inside
  `Resolve`; a host that renews the service token on `Unauthorized` should keep
  matching the module's and `whoami`'s refusal only
  (`e.whoami_cause().unwrap_or(&e)`), which a `Resolve(Unauthorized)` is not.
  (The enum is `#[non_exhaustive]`, so a `match` with a wildcard arm still
  compiles.)
- **A failure to get the issuer's discovery document or key set is
  `DirectoryError::IssuerKeys(Box<DirectoryError>)`, not the plain error of the
  directory.** After the module answered, the client fetches the issuer's public
  `/.well-known/openid-configuration` and the `jwks_uri` it names to verify the
  proofs of the rows. A failure there (a 401, a 403, a 404, a 429, a 5xx, a
  timeout, a body that is not the document or the key set, a document that names
  another issuer) came back as `Unavailable`, the same error as the module being
  unreachable, so a host could not tell a wall in front of the issuer's public
  documents from the module, nor see that the module had already taken the token.
  It is now `IssuerKeys` with that `Unavailable` inside (its text names the step
  and the status, never a body). Only a search that has no key set to judge by
  fails like this, as before and still not kept; a proof that is malformed, that
  the held key set does not verify, or whose `kid` the held set lacks while the
  refetch for it fails is still `invalid` for its row and fails nothing, and a key
  set that parses without a usable key still makes each proof `invalid`. New
  `DirectoryError::is_issuer_keys()` and `issuer_keys_cause()`;
  `is_retryable()`, `is_rate_limited()`, `retry_after()` and `is_unknown_client()`
  answer for the cause (so `is_retryable()` is unchanged for these failures), and
  `std::error::Error::source()` returns it. A host that matched `Unavailable`
  from a search to mean "the directory or its issuer is down" must also look
  inside `IssuerKeys`; a host that renews the service token on `Unauthorized`
  needs no change, and must not renew for an `IssuerKeys`, which holds no token
  refusal. (The enum is `#[non_exhaustive]`, so a `match` with a wildcard arm
  still compiles.)
- **A failed read of a local person's profile in `search_as_user` is
  `DirectoryError::Profile(Box<DirectoryError>)`, not the plain error of its
  status.** The read of `GET /_matrix/client/v3/profile/{mxid}/io.inblock.did` is
  sent without a credential, and its failure came back as the same error as the
  `user_directory/search` call, which does carry the user's token, so a host could
  not tell the profile route refusing the anonymous read (or a proxy in front of
  it) from the user's token being refused (and asked the user to sign in again for
  nothing), nor the rate limit of the profile route from that of the directory
  call. Every failure of a local profile read (a 401, a 403, a 429, a 5xx, a
  timeout, a body that is not JSON or over the cap) is now `Profile` with the
  failure inside; the first one still ends the search, aborts the reads running
  and keeps nothing. `user_directory/search` itself stays the plain error of its
  status (`Unauthorized`, `RateLimited`, `Unavailable`, ...). What touches one
  person only is unchanged and is no error: a profile that is absent (404), whose
  field is absent or `null`, or that is no proof is `not_yet_published`, a proof
  that does not verify is `invalid`; the profile of a person of another server
  still never fails a search; the module transport (`search_for_asker`) reads no
  local profile and never returns this. New `DirectoryError::is_profile()` and
  `profile_cause()`; `is_retryable()`, `is_rate_limited()`, `retry_after()` and
  `is_unknown_client()` answer for the cause (so `is_retryable()` is unchanged for
  these failures), and `std::error::Error::source()` returns it. A host that
  matched `Unavailable`, `RateLimited` or `Unauthorized` from `search_as_user` to
  mean "the directory is down", "the directory call is rate limited" or "the
  user's token is stale" must also look inside `Profile`, and must not ask the
  user to sign in again for a `Profile(Unauthorized)`: the profile read carries no
  token. (The enum is `#[non_exhaustive]`, so a `match` with a wildcard arm still
  compiles.)
- `DidState` has a new variant, `Unconfirmed`: a `match` on it that has no
  wildcard arm must handle it. A caller that offers recipients should keep
  offering `Verified` ones only unless it warns for `Unconfirmed`.
  `CacheStats` has a new public field (`remote_claims`), and `Tuning` four
  (above): code that builds `Tuning` with a struct literal and no
  `..Tuning::default()` must name them.
- `search_as_user` and `search_for_asker` now make one profile read per person of
  another homeserver (they made none), through our homeserver, with no credential.
- `AuthError` variants no longer carry the server's `error_description`:
  `DeviceRefused`, `AccessDenied` and `TemporarilyUnavailable` are unit variants,
  `SignInRefused` has only `error`, and `AuthError::description()` is removed.
  The description is free text; it is in no `Display` or `Debug`. (The enum is
  `#[non_exhaustive]`.)
- `Tuning` has a new public field, `flow_request_timeout`. Code that builds it
  with a struct literal and no `..Tuning::default()` must name it.
- `DirectoryConfig` is `#[non_exhaustive]`, so its new field
  `sign_in_again_on_401` breaks no caller that builds it with `DirectoryConfig::new`.
