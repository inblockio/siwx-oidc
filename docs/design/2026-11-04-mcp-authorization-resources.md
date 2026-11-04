# Resource indicators and JWT access tokens for MCP servers

**Date:** 2026-11-04
**Code reviewed:** `7529d08` (main)
**Status:** implemented on `feat/mcp-resources-jwt`; the open decisions below are the
maintainers'
**Tracking issue:** [#33](https://github.com/inblockio/siwx-oidc/issues/33), blockers 1 to 3
**Consumer:** `aqua-node-mcp` in inblockio/aqua-agents (PR #162), the first resource server

## 1. Goal

An MCP server (the MCP authorization specification of 2026-07-28, an OAuth 2.1 protected
resource) names siwx-oidc as its authorization server. For that, siwx-oidc must

1. bind a token to the resource the client asks for (RFC 8707 `resource`, token `aud`), so a
   token issued for one MCP server is refused by every other;
2. issue a token a third-party resource server can validate without a credential of this
   provider's (RFC 9068 JWT access tokens, verified against `/jwk`);
3. grant resource scopes, intersected with what the resource understands, without requiring
   `openid`, so a resource server can answer `403 insufficient_scope` and a client can step up.

Everything else in #33 (RFC 9207 `iss`, CIMD, the consent screen, loopback redirects, the
housekeeping) is untouched.

## 2. What was there (at `7529d08`)

| Area | State |
|---|---|
| `resource` parameter | ignored at `/authorize` and `/token` |
| Access token | opaque `mat_…` in every mode; the grant record behind it is the unit (design 2026-10-02) |
| Validation by a third party | `/oauth2/introspect` only with the MAS shared secret, no `aud` in its answer |
| Scope | `/authorize` requires `openid` or a Matrix scope; the exchange grants from `GENERIC_GRANTABLE_SCOPES` or the generic client's entry |
| Sign-in | a Matrix-class client's sign-in upserts a Synapse device; a generic-class one does not and never guesses a localpart |

## 3. Decisions

| Id | Decision | Why |
|---|---|---|
| D1 | Resources are configured, not registered: `resources`, a map of a name to `{"uri", "scopes"}`, the shape of `default_clients`, validated at start (`resource::Registry::parse`). | A resource server is an operator's deployment, like a static client. A map keyed by a name reaches the environment as `SIWXOIDC_RESOURCES__<name>`, which an array (`[[resources]]`) would not. Issue #33 proposed the array; the map is the same information. |
| D2 | The URI is matched byte for byte and must already be canonical (lowercase scheme and host, no default port, no query, fragment, user information or trailing slash). | RFC 8707 compares resource indicators as strings, the MCP specification says the protected resource's `resource` equals its exact URL, and the MCP server compares `aud` as a string. Normalising on one side only would let two spellings pass on one side and fail on the other. Refusing a non-canonical entry at start is cheaper than a token nobody accepts. |
| D3 | One resource per request. | MCP clients send one. RFC 8707 allows several; a token for several resources would need an `aud` array and a scope per resource. Not needed by the consumer; out until it is. |
| D4 | The grant of a resource-bound request is `requested ∩ resource.scopes`, in the resource's order, plus `offline_access` when requested and the registration allows the refresh grant. `openid`, `profile` and every Matrix scope are dropped; nothing of the resource's asked for is `invalid_scope` at `/authorize`. | Least privilege, and one rule (`Registry::grant`) that `/authorize` checks and the exchange recomputes from the stored inputs, as `client_policy::grant_for` already does for generic clients. An empty grant would be a token that opens nothing, so it is refused before a sign-in. |
| D5 | No ID token for a resource-bound exchange, and `openid` not required. | The token is for the resource server. An ID token is for a relying party of this provider. A client that wants both runs two flows. This also keeps the signing-failure unwind one path: exactly one signature is made per exchange. |
| D6 | The JWT is the access token the client holds; the grant keeps its opaque token, which is never handed out. | The grant record, its indices, rotation, revocation, epochs and lifetimes stay exactly as they are (design 2026-10-02, I2, I3, I6, I9): the store is not taught about JWTs. The JWT carries the grant's `did`, `client_id`, `scope` and the instants the store decided (Redis `TIME`), so nothing in the JWT disagrees with the store. The opaque token stays as the grant's entry for the rotation script and revocation; nobody holds it, so nothing can present it. |
| D7 | The JWT is signed through `ProviderSigner` under a purpose of its own, `access_token`, with a shape the socket signer checks: `typ` `at+jwt`, `aud`, `client_id`, `scope`, `jti` required, an ID token's session members forbidden; and an ID token now forbids `client_id`, `scope` and `jti`. | The signer invariant: no message passes the check of two purposes, so no signature serves twice. Without the ID-token side an access-token payload would have passed as an ID token (found by the existing cross-purpose test). |
| D8 | A resource-bound sign-in provisions the account and publishes the DID, but upserts no device and arms no reset, whatever the client's class, and resolves the localpart with the fallible resolver. | An agent logging in to an MCP server must not accumulate Synapse devices. The grant is indexed by the localpart, so a user revocation reaches it only if the localpart is the account's: a guessed one (the Matrix-class fail-safe) would index it under a name the revocation never names. Same rule as a generic-class sign-in, same 503. |
| D9 | The class rule stays: a code is redeemed only by a client of the class it was issued to, resource or not. | Unchanged invariant; the resource row sits in front of the table, not instead of it. |
| D10 | A refresh of a resource grant answers a new JWT (new `jti`) over the rotation's instants; a replayed rotation answer gets a JWT of its own for the same remaining lifetime. | The rotation script writes the new opaque token; the JWT is minted from the grant and the pair it returns. A replay cannot return byte-identical JWT (the signature is fresh) and need not: the lifetime is the same. |
| D11 | Revocation is bounded by the token lifetime (300 s): no introspection for JWTs, no revocation list. | Issue #33's chosen alternative. The resource server verifies offline; 300 s is the bound a revoked grant's JWT lives. Documented where operators read it. |
| D12 | `/userinfo`, introspection and `/oauth2/revoke` do not accept the JWT. | They read the grant behind an opaque token. A JWT is for the resource server. Revoking the refresh token revokes the grant. |
| D13 | Discovery lists the resources' scopes in `scopes_supported`. | Some clients check that the scopes they will ask for are advertised. No RFC 8707 metadata flag exists. |

## 4. The flow

```
client                      siwx-oidc                                  store
  | GET /authorize?resource=R&scope=S ...
  |                           R configured?            no -> 303 invalid_target
  |                           grant(R, S) non-empty?   no -> 303 invalid_scope
  |                           bind {client, redirect, state, challenge, S, R} -> session
  | ... sign-in (wallet or passkey) ...
  |                           /sign_in: resource branch: account, DID field, no device
  |                           code {did, S, R, class} ----------------------> code
  | POST /token code, verifier[, resource=R']
  |                           R' absent or == R?       no -> 400 invalid_target
  |                           exchange_issuance_bound: oidc grant, no device,
  |                             scope = grant(R, S).scope, resource = R
  |                           issue_grant ---------------------------------> grant{resource=R}, at/{opaque}
  |                           mint JWT{iss, sub=did, aud=R, client_id, scope, iat, exp, jti}
  |                             (fails -> discard grant, restore code, 503/500)
  | 200 {access_token: JWT, refresh_token?, scope?, expires_in: 300}
  | POST /token refresh_token
  |                           rotate (one script) --------------------------> new pair
  |                           grant.resource? mint a new JWT over the pair's instants
```

## 5. What a resource server does with the token

Verify `alg` ES256 and `typ` `at+jwt`, find `kid` in `{issuer}/jwk`, verify the signature over
the received bytes, then `iss` equal to the discovery `issuer`, `aud` equal to its own canonical
URI as a string, `exp`, and the scopes it needs in `scope`. `sub` is the DID, exact case, the
same identity the profile field `io.inblock.did` publishes. `aqua-node-mcp` does exactly this
(`crates/aqua-node-mcp/src/auth.rs` in aqua-agents) and its tests mint tokens of this shape.

## 6. Verification

| What | Where |
|---|---|
| The registry's rules, each refusal by name and rule, never the value | `src/resource.rs` tests |
| The grant rule | `resource::tests::the_grant_is_the_requested_scopes_the_resource_lists_and_nothing_else` |
| The configuration reaches the registry from the file and the environment | `config::tests::resources_are_a_map_of_json_entries_from_the_file_and_the_environment` |
| The JWT's claims, order, raw signature, and that its shape passes the signer's check | `src/access_token.rs` tests |
| No purpose signs another's emission, with the new purpose | `signing::shape::tests::no_purpose_signs_what_another_purpose_emits`, `an_access_token_carries_exactly_what_rfc_9068_asks_and_no_session_member` |
| `/authorize`: `invalid_target`, `invalid_scope`, the binding, no `openid` needed | `oidc::resource_binding_tests::authorize_*` |
| The exchange: JWT for the resource, no ID token, the grant behind it, the scope reported, the opaque token not handed out; `resource` at `/token`; a removed resource; the class rule | `oidc::resource_binding_tests::a_resource_code_*`, `a_resource_removed_*`, `exchange_issuance_bound_*` |
| A refresh and a replay answer new JWTs for the same resource | `oidc::resource_binding_tests::a_resource_grant_refreshes_into_a_new_jwt_for_the_same_resource` |
| Ordinary requests unchanged | `oidc::resource_binding_tests::an_ordinary_exchange_still_hands_out_an_opaque_token_and_an_id_token`, every pre-existing suite |
| On the wire, through the wallet sign-in, against `/jwk` | `tests/e2e_resource_binding.rs` (mock stack, CI job `rust-e2e-mock`) |

## 7. Open decisions for the maintainers

- [ ] OD1: the map (`resources.<name>`) over the issue's `[[resources]]` array (D1).
- [ ] OD2: no ID token for a resource-bound request (D5), or `openid` honoured beside the
  resource when asked for (two signatures per exchange, two unwinds).
- [ ] OD3: one resource per request (D3), or `aud` arrays.
- [ ] OD4: a revocation bound of 300 s with no introspection for JWTs (D11), or an
  introspection credential per resource server (the issue's alternative) later.
- [ ] OD5: whether a resource server should also be allowed `offline_access` without the
  registration listing the refresh grant (today: the registration rule applies, as for every
  other grant).

## 8. Not in this change

RFC 9207 `iss` in the authorization response, CIMD, the consent screen's redirect host, RFC
8252 loopback redirect ports, the housekeeping list of #33, the device-code grant for resources,
and the e2e acceptance against a reference resource server (the consumer's own tests cover the
resource side).
