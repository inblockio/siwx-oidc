# Changelog of `siwx-oidc-auth`

## Unreleased

Behaviour changes of the directory client and the headless client, from the review
of the directory client (PR 88) and its follow-ups (PR 103). A consumer that
matches error text should match the types named here instead.

### Changed

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
- **`expires_in` is read tolerantly.** Any JSON number is accepted (`3600.5`,
  `1e20`, above `u64`) and held between `TOKEN_LIFETIME_MIN_SECS` (10) and
  `TOKEN_LIFETIME_MAX_SECS` (24 h); a missing or non-number value is
  `TOKEN_LIFETIME_DEFAULT_SECS` (60). A token answer is never refused for it, so
  the new pair is not lost after the refresh token was consumed.
- **A failed refetch for an unknown `kid` no longer fails a search.** The proof is
  `invalid` in that answer, nothing is cached, the rest of the answer is
  unaffected and the 30 s refetch limit still holds. Only a search with no usable
  key set at all fails.

### Added

- **`AuthError::UnknownClient`**, `siwx_oidc_auth::is_unknown_client` and
  `DirectoryError::is_unknown_client`: `/authorize` answered 401 without a
  `WWW-Authenticate` header, which is siwx-oidc's own answer for a client id it
  does not know (a dynamic client lapses after 30 days without a use). Register
  again and keep the new id; it is never retryable.
- **`AuthError::Unauthorized`**: a 401 at `/authorize` *with* a
  `WWW-Authenticate` challenge, a proxy's auth wall. It is not an unknown client
  and registering again does not help.

### Breaking

- `AuthError` variants no longer carry the server's `error_description`:
  `DeviceRefused`, `AccessDenied` and `TemporarilyUnavailable` are unit variants,
  `SignInRefused` has only `error`, and `AuthError::description()` is removed.
  The description is free text; it is in no `Display` or `Debug`. (The enum is
  `#[non_exhaustive]`.)
