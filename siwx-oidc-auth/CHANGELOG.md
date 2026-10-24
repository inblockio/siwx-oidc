# Changelog of `siwx-oidc-auth`

## Unreleased

Behaviour changes of the directory client and the headless client, from the review
of the directory client (PR 88) and its follow-ups (PR 103). A consumer that
matches error text should match the types named here instead.

### Changed

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

### Added

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

### Breaking

- `AuthError` variants no longer carry the server's `error_description`:
  `DeviceRefused`, `AccessDenied` and `TemporarilyUnavailable` are unit variants,
  `SignInRefused` has only `error`, and `AuthError::description()` is removed.
  The description is free text; it is in no `Display` or `Debug`. (The enum is
  `#[non_exhaustive]`.)
- `Tuning` has a new public field, `flow_request_timeout`. Code that builds it
  with a struct literal and no `..Tuning::default()` must name it.
