# AGENTS.md: rules for contributors to siwx-oidc

This file is the canonical rules file for human and AI contributors. Claude Code reads it
through `CLAUDE.md`; Cursor, Codex, Copilot and other agents read it directly. Background
lives in [`docs/`](docs/README.md); this file holds what you must know before changing code.

## What this is

siwx-oidc is an OpenID Connect provider where the account is a key. People sign in with a
passkey (`did:key`, P-256) or a wallet (CAIP-122 / Sign-In with Ethereum, `did:pkh`);
software agents sign in with their own Ed25519 or P-256 key through the headless
`siwx-oidc-auth` client. The OIDC `sub` is the user's DID. For Matrix it implements the
OAuth 2.0 authentication API and acts as the auth service in Synapse's
`matrix_authentication_service` integration, and it publishes a provider-signed DID↔MXID
binding in the profile field `io.inblock.did`.

**Status:** siwx-oidc is a pathfinder project for agent identity on Matrix, run by inblock.io
assets GmbH on a non-commercial basis. It is provided as is, without warranty (Apache-2.0
§§7–8). There is no support offering, no SLA, and no commitment to maintain it for third-party
deployments; the maintainers maintain it for their own use, and interfaces may change without
notice. There are no tagged releases yet; `main` is what runs.

## Code map

Workspace: the root package `siwx-oidc` (library crate `siwx_oidc` in `src/lib.rs`, binaries
`siwx-oidc` and `migrate-credentials`) plus `siwx-oidc-auth/`. Crypto comes from the external
crate [aqua-auth](https://github.com/inblockio/aqua-rs-auth), pinned by tag in both manifests.
Modules marked **lib** are compiled into the library crate, so `tests/*.rs` can link them;
everything else exists only in the binary crate.

| `src/` | Role |
|---|---|
| `main.rs` | Binary entry point. Declares the binary-only modules and calls `axum_lib::main`. |
| `lib.rs` | Library crate root. `synapse_client` is deliberately not re-exported (see Invariants). |
| `axum_lib.rs` | Startup: loads config through `config::figment()`, validates it (DID methods and pkh namespaces against the aqua-auth registries, signing key, retired keys, WebAuthn), `AppState`, the router, handler glue, the `siwx_user` / `acct_session` cookies, the CORS layer. |
| `config.rs` | `Config`, its defaults, and `figment()`: the one place config names and precedence are defined. Reference: [docs/configuration.md](docs/configuration.md). |
| `oidc.rs` | OIDC core: discovery, JWKS, `authorize`, `sign_in`, `token` (authorization-code, refresh-token and device-code grants; `authenticate_client` authenticates the client for the first two), `userinfo`, client registration, `EcdsaSigningKey` (ES256, key-derived `kid`), retired-key parsing, ENS claims, and `provision_synapse_device`, the single provisioning and DID-publication path. |
| `introspect.rs` | `POST /oauth2/introspect` (RFC 7662) for Synapse; opaque `mat_`/`mcr_` token generation. |
| `admin_token.rs` | `POST /oauth2/admin_token`: short-TTL token whose scope carries `urn:synapse:admin:*`. |
| `compat.rs` | `POST /oauth2/revoke` (RFC 7009) and the Matrix client-server endpoints siwx-oidc answers (login flows, logout, logout/all, refresh, device deletion); `TeardownPolicy`. |
| `device_auth.rs` | RFC 8628 device authorization: `/device_authorization`, the `/device` approval page (wallet and passkey), server-issued CAIP-122 nonces. |
| `account.rs` | MSC4191 `/account` page and actions, MSC4312 cross-signing reset, and the two non-spec actions `io.inblock.account_erase` / `io.inblock.account_reactivate`. `SUPPORTED_ACTIONS` is the single source of truth for discovery and dispatch; `canonical_action` maps `session_*` aliases to `device_*` and the legacy `org.matrix.account_erase` / `org.matrix.account_reactivate` names to the new ones. |
| `webauthn.rs` | Passkey ceremonies (register, authenticate, link), the new-identity and deactivation gates (`reject_if_new_identity`, `reject_if_deactivated`), picker scoping. |
| `synapse_client.rs` | Synapse client with two credentials: the MAS shared secret on `/_synapse/mas/*` (`provision_user`, `upsert_device`, `update_device_display_name`, `allow_cross_signing_reset`, `localpart_status`, `delete_device`, `deactivate_user`, `reactivate_user`) and a minted admin-scoped token (`admin_request`) on `/_synapse/admin/*` and the client-server API (`list_devices`, `get_device`, `has_cross_signing_keys`, `read_profile`, `publish_did_field`, `read_did_field`). |
| `did_assertion.rs` | `DID_PROFILE_FIELD`, `mint_did_assertion` (compact ES256 JWS), `did_profile_value`, `DidPublication`. |
| `resolve.rs` | `GET /resolve`, the public DID↔MXID lookup. |
| `localpart.rs` | Grandfathering policy: `resolve_identity` (fallible) and `resolve_identity_or_legacy` (fail-safe to legacy). |
| `mxid.rs` (lib) | Pure localpart derivation: `localpart_for`, `legacy_localpart`, `canonicalize`. `sha2` only. |
| `redact.rs` (lib) | `fingerprint`, `redact_key`, `redact_url`: what a log line may say about a credential. |
| `alias.rs` (lib) | `alias_for(did)`: the generated `Firstname Surname` a new account is seeded with. |
| `credential_identity.rs` (lib) | Which identity a stored passkey authenticates: a `webauthn:link/*` entry overrides the derived `did:key`. |
| `credential_store.rs` (lib) | Optional aqua-auth credential store, dual-write and read-through, enabled by `AQUA_WEBAUTHN_REDIS_URL`. |
| `credential_migration.rs` (lib) | Additive backfill of passkey credentials into the aqua-auth store. |
| `db/mod.rs` (lib) | `DBClient` trait, entry types (`CodeEntry`, `SessionEntry` with its bound `AuthorizationRequest`, `ClientEntry`, `DeviceCodeEntry`, `TokenMetadata` with its `TokenKind`), `legacy_token_kind`, Redis key prefixes and TTLs. |
| `db/redis.rs` (lib) | Redis implementation, incl. `revoke_device_tokens`, `revoke_all_user_tokens`, `get_passkeys_for_did`, `lookup_user_session`, `purge_identity`. |
| `bin/migrate-credentials.rs` | Operator tool for the credential backfill. Dry run unless `--apply`. |

| `siwx-oidc-auth/src/` | Role |
|---|---|
| `lib.rs` | `SiwxKey` (PEM, hex, generated), `authenticate`, `authenticate_with_device`, `refresh`, `authenticate_device_flow`, `AuthTokens`. |
| `did_assertion.rs` | The shipped verifier: `fetch_and_verify_did`, `verify_did_assertion`, `VerifiedDid`, `DidAssertionError`, `DID_PROFILE_FIELD`. |
| `main.rs` | CLI: `--key-file`, `--print-did`, `--server`, `--refresh-token`, `--device-flow`, `--verify-did <MXID> --homeserver <url>`. |

Other paths: `tests/` (integration suites, mostly `#[ignore]`d; see below), `e2e/` (mock
stack, Playwright suites, Element Web suites), `js/ui/` (Svelte login page, built into
`static/build`), `static/` (served pages and assets), `docs/api/` (OpenAPI document),
`docs/audits/` and `docs/design/` (evidence and design records), `security/` plus
`.cargo/audit.toml` (advisory exceptions, VEX), `scripts/` (live checks against a deployment),
`skills/` (agent skills).

## Architecture in brief

Three layers. **aqua-auth** verifies CAIP-122 proofs through the `DIDMethod` trait (and, inside
`did:pkh`, `CipherSuite`). **Ceremony modules** in `src/` (WebAuthn, the RFC 8628 approval page)
verify other proofs server-side and store a verified DID in the Redis session. **`oidc.rs`**
issues codes and tokens: authorization codes only in `sign_in`, tokens at `POST /token`
(authorization-code, refresh and device-code grants). Two more endpoints mint tokens:
`POST /_matrix/client/v3/refresh` (`compat.rs`) and `POST /oauth2/admin_token`
(`admin_token.rs`). Ceremonies never issue either and never extend `DIDMethod`. Full picture,
sign-in flows, Redis keyspace and lineage: [docs/architecture.md](docs/architecture.md).

## Build and test

```bash
cargo build --workspace
cargo fmt --all -- --check && cargo clippy --workspace --all-targets   # CI: RUSTFLAGS=-Dwarnings
docker run -d --rm --name siwx-redis -p 6379:6379 redis:7-alpine   # Redis on localhost:6379
cargo test --workspace                        # unit tests + non-ignored tests/; many need Redis
cargo run                                     # the server (needs Redis; see below)
cargo run -p siwx-oidc-auth -- --help         # the headless client
```

- **Most `tests/*.rs` tests are `#[ignore]`d.** They need a running siwx-oidc (and most a Synapse
  mock). Run a suite explicitly: `cargo test --test e2e_race_teardown -- --ignored --test-threads=1`.
  `cargo test --workspace` runs the unit tests of both crates plus 16 tests in seven files:
  `openapi_covers_every_route` (2), `localpart_vectors` (1) and `graceful_shutdown` (3), which
  need nothing; `account_linking_dual_write` (6), which needs the test Redis;
  `credential_migration_live` (2), which needs its own disposable, empty Redis named by
  `MIGRATION_TEST_REDIS_URL`; and the pure check `an_absent_strict_skips_variable_means_strict`
  in `e2e_account_lifecycle_live` and in `e2e_did_field_live` (1 each).
- **Redis-backed tests** get their Redis from `siwx_oidc::test_support` (`src/test_support.rs`):
  `SIWX_TEST_REDIS_URL`, default `redis://localhost`. When it is unreachable each test prints
  one `SKIP <test>: …` line to stderr and passes; with `SIWX_TEST_REQUIRE_REDIS=1` it fails
  instead, and so does `credential_migration_live` when `MIGRATION_TEST_REDIS_URL` is unset.
  CI sets both. Use the helper in any new Redis-backed test: `RedisClient::new` never connects
  (bb8 builds the pool with `min_idle` 0), so a `RedisClient::new(..).ok()` guard never skips,
  and without Redis the test fails after bb8's 30-second timeout.
- **Tests that pin what is logged** use `siwx_oidc::test_support::LogCapture`, which records the
  calling thread's log output at debug level (use it in a current-thread `#[tokio::test]`). The
  checks that apply to every log site live in `tests/log_hygiene.rs`.
- **Mock stack:** `e2e/up.sh` / `e2e/down.sh` start Redis, `e2e/synapse_mock.py` and siwx-oidc
  in podman; `bash e2e/run-all.sh` runs everything. See [e2e/README.md](e2e/README.md).
  `--test-threads=1` is required: the suites share one stack and reset the mock.
- **Live suites** need a real Synapse and run in no CI job: `e2e_did_field_live` (a patched
  Synapse), `e2e_account_lifecycle_live`, five of the six `e2e_msc4191_live` tests,
  `e2e_msc3861::msc4191_metadata_advertised_and_forwarded` and `e2e_messaging`. Set
  `E2E_STRICT_SKIPS=1` so a skipped assertion fails instead of passing.
- **Browser suites:** `e2e/browser/` (self-contained, runs in CI) and `e2e/element/` (needs
  Element Web, a real Synapse and the proxy from siwx-oidc-matrix-server).
- **aqua-auth's own tests** run in that repository, not here.
- **Running the server locally** needs `SIWXOIDC_BASE_URL` with a hostname
  (`http://localhost:8000`): the default `http://127.0.0.1:8000` makes WebAuthn refuse the IP
  literal as RP ID and startup panics. See [docs/configuration.md](docs/configuration.md).
- CI (`.github/workflows/ci.yml`) runs on pushes to `main` and `fork-stable` and on every pull
  request, forks included; it reads no secrets. Job `build` runs clippy on all targets and
  `cargo test --workspace` against two Redis services with `SIWX_TEST_REQUIRE_REDIS=1`; job
  `image` builds the container image without pushing it, which runs the license gates
  (`scripts/third-party-notices.sh`, `js/ui/third-party-licenses.js`, the Alpine license
  check); job `rust-e2e-mock` runs the promotable mock-stack suites; job `browser-e2e` runs
  `e2e/browser`. Actions are pinned by commit SHA.

**Route documentation is enforced.** `tests/openapi_covers_every_route.rs`
(`every_route_is_described_in_the_openapi_document`) parses the router in `axum_lib.rs` and
fails when a route is missing from [docs/api/openapi.yaml](docs/api/openapi.yaml). Add the
route to the document in the same change. `NOT_AN_API` exemptions are guarded by
`the_static_asset_exemptions_are_all_still_routes`.

**The Synapse mock is a hand-kept mirror.** When `synapse_client.rs` adds or moves an
endpoint, update `e2e/synapse_mock.py` in the same change (drift check in
[e2e/README.md](e2e/README.md)). A drifted mock turns suites red or, worse, green.

**A test must be able to fail.** A bound such as `n <= 1` is satisfied by zero, and a test
that prints "skipping" and returns ok is green forever. Assert the positive case, and make
skips loud and switchable into failures (`SIWX_TEST_REQUIRE_REDIS`, `E2E_STRICT_SKIPS`).
Known gap: `e2e_msc3861` and `e2e_messaging` skip their Matrix-side assertions with a plain
`eprintln!` when whoami is unavailable, with no `E2E_STRICT_SKIPS` gate.

## Invariants: do not "simplify" these

Each rule names what it protects and where it is pinned. The full rationale is in the linked
doc; read it before changing the code the rule covers.

### Identity and the `io.inblock.did` field ([docs/identity-model.md](docs/identity-model.md))

- **Three tiers, three owners.** Alias (`displayname`, user-owned), MXID (derived, immutable),
  DID (provider-owned, `io.inblock.did`). Never put a DID into `displayname`, never key
  anything on the alias. Pin: `h11_first_signin_seeds_displayname_with_the_alias_never_the_did`,
  `an_alias_never_contains_a_did`.
- **The DID keeps its exact case.** Never lowercase or normalise it; a `did:key` payload's case
  carries meaning. Only `mxid::canonicalize` folds, and only `did:pkh`. Pin:
  `payload_carries_exactly_the_four_claims_and_preserves_did_case`,
  `pkh_case_folding_is_canonical_lowercase`, `key_case_is_preserved_not_folded`.
- **Never rebuild a DID from a localpart.** MXID→DID is not invertible. Resolve DIDs from an
  OIDC `sub` or the profile field and compare byte for byte.
- **The field value is one object, `{did, proof}`, written in one PUT.** Not two fields.
- **`proof` is absent, never `null` or `""`, when the signing key is ephemeral.** Pin:
  `h5_ephemeral_key_publishes_a_did_with_no_proof_key`, `h5_ephemeral_key_mints_no_assertion`,
  and on the consumer side `an_empty_string_proof_is_proof_absent_never_a_proof`.
- **The field name is a three-sided contract**: `src/did_assertion.rs`,
  `siwx-oidc-auth/src/did_assertion.rs` and the homeserver denylist in siwx-oidc-matrix-server.
  Renaming it is a migration with a dual-read period, not an edit. Pin:
  `publish_uses_the_shared_field_constant`, `did_profile_field_is_the_wire_contract`.
- **Nothing private goes into the field.** It is world-readable and federates.
- **A published DID, verified or not, is a discovery hint, never an authorization source.**
  Authorize from an OIDC `sub` this provider issued or a fresh signature by the DID key.
- **Denylist, never allowlist**, on the homeserver: `msc4133_key_allowlist` would restrict every
  custom profile field. See [docs/matrix-integration.md](docs/matrix-integration.md).

### Signing keys and DID assertions

- **`kid` is derived from the public key** (`EcdsaSigningKey::fingerprint_of`). Both constructors
  go through `with_derived_kid`. Do not add a `kid` parameter or make `kid` optional. Pin:
  `h4_two_generated_keys_get_different_kids`,
  `h4_the_same_pem_yields_the_same_kid_across_constructions`,
  `published_jwk_always_carries_the_derived_kid`.
- **No `exp` in a DID assertion.** The binding is permanent. Pin: `payload_has_no_exp_claim`.
- **ES256 signatures are raw `r‖s`, 64 bytes, never DER.** Pin:
  `signature_is_64_raw_bytes_never_der`, which covers the DID-assertion signature only. ID
  tokens share `sign_es256` by construction (`PrivateSigningKey::sign` delegates to it); no
  separate test pins that.
- **Claim and header order is struct declaration order**; those bytes are signed. Pin:
  `minted_jws_has_exactly_three_parts_and_the_exact_header`.
- **An ephemeral key mints no assertion at all.** `mint_did_assertion` returns `None`.
- **Retired keys are public-only.** A private PEM in `…_RETIRED_SIGNING_KEYS_PEM` is a startup
  error, and a malformed one is never skipped. Pin: `a_private_key_is_refused_with_the_openssl_fix`,
  `malformed_retired_keys_are_a_hard_error_never_a_skip`,
  `a_retired_key_keeps_the_exact_kid_it_had_while_live`.

### The shipped verifier (`siwx-oidc-auth`)

- **The mxid binding is inside `fetch_and_verify_did`, with no opt-out.** Do not add an unbound
  variant; without it one user's proof verifies in another user's profile. Pin:
  `h6_valid_assertion_replayed_for_another_user_is_rejected`,
  `h6_a_proof_that_omits_the_mxid_claim_binds_nothing_and_is_rejected`.
- **`alg` is checked before any network I/O**; `none` and `HS*` are rejected by name. Pin:
  `h7_alg_none_is_rejected_before_any_key_is_fetched`, `h7_hmac_alg_is_rejected_before_any_key_is_fetched`.
- **An unknown `kid` is a hard error naming the kid**, never a try-every-key fallback. Pin:
  `h7_unknown_kid_error_names_the_kid`.
- **Verify over the received bytes**, not a re-serialisation; `iss` must equal the discovery
  `issuer`; the verified `sub` beats the plain `did` member. Pin: `iss_mismatch_is_rejected`,
  `fetch_plain_did_disagreement_returns_the_verified_sub`.

### Publication and the Synapse client ([docs/matrix-integration.md](docs/matrix-integration.md))

- **One call site.** Publication happens only in `oidc::provision_synapse_device`, reached by
  both sign-in paths. It is best-effort and never fails sign-in.
- **Re-asserted on every sign-in.** That is how a clobbered value self-heals; do not optimise
  it away. Pin: `clobbered_did_field_is_restored_at_next_signin_live` (live).
- **No server name, or a degraded identity, publishes nothing.** Pin:
  `no_server_name_skips_publication_without_disturbing_provisioning`,
  `a_degraded_identity_provisions_but_never_publishes_an_assertion`.
- **`classify_publish_status` matches exactly 500, never `is_server_error()`**, and a 500 is only
  a candidate row-less account that the profile probe must confirm. 502/503/504 stay errors.
  Pin: `publish_status_500_is_only_a_candidate_rowless_account`,
  `publish_status_other_5xx_is_a_genuine_error`, `d1_500_with_a_present_profile_row_is_a_genuine_error`.
- **Two credentials, two route families.** The MAS shared secret works only on
  `/_synapse/mas/*`; `/_synapse/admin/*` and the client-server API take a minted admin token.
  The mxid is a percent-encoded path segment on profile routes and a bare localpart in the
  body on `/_synapse/mas/*`; do not unify them. An `Err` from a read means "state unknown".
- **`localpart_status` has three verdicts** (`Available`, `InUse`, `Unusable`). `Unusable` is only
  `M_INVALID_USERNAME` or `M_EXCLUSIVE`; every other 4xx, an unreadable body, and a rejected MAS
  secret are errors, never verdicts. Do not widen that allowlist. Pin:
  `exactly_three_errcodes_produce_a_verdict_and_every_other_shape_produces_none`,
  `an_unusable_localpart_is_never_reported_as_taken`,
  `a_rejected_mas_secret_is_an_error_never_a_verdict_about_the_localpart`.
  Background: [docs/audits/2026-09-12-localpart-availability-conflation.md](docs/audits/2026-09-12-localpart-availability-conflation.md).
- **Row-absence is decided by `errcode`** (`M_UNKNOWN` = absent), not by a 404 alone. Pin:
  `profile_404_m_unknown_no_row_found_is_absent`,
  `profile_404_m_not_found_profile_was_not_found_is_present`.
- **`synapse_client` stays out of `lib.rs`.** It depends on binary-only modules, and compiling it
  into both crates produced two types with one name.

### Localparts and aliases

- **The fail-safe direction is LEGACY, never modern.** `resolve_identity_or_legacy` falls back to
  the legacy localpart so an existing user is never severed from their account. Pin:
  `fail_safe_fallback_is_legacy_never_modern`,
  `a_proxy_404_never_severs_a_grandfathered_account_onto_the_modern_localpart`.
- **Read-only lookups use the fallible `resolve_identity`**, never the guessing variant.
- **Alias word lists are append-only.** An index is `digest mod len`; reordering renames future
  accounts. Pin: `vectors_are_pinned`.
- **The alias is written once** and never re-asserted, so a user's chosen name survives.
- **Displayname migration is byte-equal**: only a displayname equal to a string we seeded (the
  raw DID or the bare localpart) is rewritten. A cleared displayname is left alone. Pin:
  `provider_written_displayname_matches_only_our_own_seeds`,
  `alias_migration_leaves_a_cleared_displayname_alone`.

### Sign-in gates ([docs/passkeys.md](docs/passkeys.md))

- **New accounts are created only through the login flow (`/sign_in`).** Only the browser
  passkey login asks for confirmation, and the frontend enforces it; wallet and headless
  sign-ins create the account directly. Account re-auth and device approval reject an unknown
  identity via `reject_if_new_identity`.
- **Both gates fail closed and report two different facts**: the check ran and said no (400 /
  401) versus the check could not run (503). Pin:
  `reject_if_new_identity_fails_closed_on_synapse_error`,
  `a_rejected_mas_shared_secret_is_a_detection_failure_not_a_new_identity`,
  `reject_if_deactivated_fails_closed_on_synapse_error`.
- **`reject_if_deactivated` runs before `resolve_identity_or_legacy` in `sign_in`.** Feeding the
  gate that resolver's legacy guess lets a deactivated modern-only account sign in. Pin:
  `sign_in_refuses_a_deactivated_account_before_resolving_or_provisioning`,
  `a_partial_probe_fault_fails_sign_in_closed_before_any_legacy_guess` (they drive `sign_in`
  against a recording homeserver); rationale at the call site.
- **Standalone deployments degrade, never 500.** No Synapse client means the gates are no-ops.

### Tokens, sessions and devices ([docs/matrix-integration.md](docs/matrix-integration.md))

- **Each endpoint accepts only its token kind.** `TokenMetadata.kind` is access or refresh;
  a minted admin token is an access token. The refresh endpoints (`grant_type=refresh_token`,
  `/_matrix/client/v3/refresh`) take refresh tokens; introspection, `/userinfo` and the
  bearer-authenticated Matrix routes take access tokens; `/oauth2/revoke` takes either. A wrong
  kind is answered exactly like an unknown token and is never deleted by the refusal. Entries
  written before the kind existed are classified in one place, `db::legacy_token_kind`, by
  lifetime; `set_token` refuses an entry without a kind. Pin (mock stack):
  `the_refresh_grant_accepts_only_a_refresh_token`,
  `the_matrix_refresh_endpoint_accepts_only_a_refresh_token`,
  `neither_refresh_endpoint_accepts_an_admin_token`, `a_refresh_token_is_not_a_bearer_credential`;
  unit: `every_legacy_entry_shape_is_classified`,
  `a_long_lived_admin_scoped_legacy_entry_has_no_kind`, `set_token_refuses_an_entry_without_a_kind`,
  `a_refresh_token_is_inactive`, `a_refresh_token_as_the_bearer_tears_nothing_down`.
- **The authorization request, PKCE challenge included, is bound at `/authorize`, and `sign_in`
  reads no authorization parameter from its query.** Only `response_type=code` with an `S256`
  challenge is accepted; the validated request (client, redirect URI, state, response mode,
  challenge; the nonce sits beside it in the session) is stored in the session, and `sign_in`
  issues the code for exactly that request. The handler has no `Query` extractor: the login page
  still appends the parameters to its `/sign_in` link, `encodeURI`-encoded and therefore altered
  for some values, and they are never parsed. A session without a bound request (older build) is
  refused; `/token` refuses a code without a challenge. `authorize` percent-encodes every value
  on the login page URL, because the page's CAIP-122 message binds the redirect URI it reads
  there. Pin (mock stack): `authorize_accepts_only_the_code_response_type`,
  `the_code_is_bound_to_the_challenge_sent_to_authorize`, `sign_in_ignores_a_state_in_its_query`,
  `sign_in_ignores_a_client_in_its_query`,
  `the_login_page_round_trip_keeps_the_exact_redirect_uri_and_state`,
  `unregistered_redirect_uri_at_sign_in_is_rejected`,
  `discovery_advertises_only_the_code_response_type`; unit:
  `sign_in_issues_the_code_for_the_bound_request`,
  `authorize_hands_the_login_page_the_exact_values`, `a_session_without_a_bound_request_is_refused`,
  `authorize_binds_the_request_to_the_session`.
- **Redirect URIs match the registration exactly**, query included (RFC 9700 §4.1.3), through
  the one helper `oidc::redirect_uri_is_registered` used by `authorize` and `sign_in`. Pin:
  `redirect_uri_matching_is_exact`, `redirect_uris_match_the_registration_exactly` (mock stack).
- **Codes are single use and deleted on exchange.** `try_consume_code` reads and deletes the
  entry in one atomic step; a code is redeemable only at `/token`, and `/userinfo` never reads
  codes. Pin: `a_consumed_code_leaves_no_entry`,
  `concurrent_consumers_of_one_code_have_exactly_one_winner`, `userinfo_accepts_only_an_access_token`,
  `an_authorization_code_is_never_a_bearer_token` (mock stack).
- **Discovery advertises only what is implemented.** `subject_types_supported` is `["public"]`
  because the `sub` is the user's DID, identical for every client; advertising `pairwise` would
  promise a per-client identifier. `scopes_supported` lists `offline_access` because generic mode
  honours it (next bullet). Pin: `discovery_advertises_public_subjects_only`,
  `discovery_advertises_offline_access`; the response types are pinned by
  `discovery_advertises_only_the_code_response_type`.
- **Generic mode issues a refresh token only for `offline_access`, and the scope it records is
  the one requested and granted** (I10). Generic mode is a deployment with no
  `mas_shared_secret`. The code exchange grants the requested scopes among `openid`, `profile`
  and `offline_access`, issues a refresh token only when `offline_access` was requested and the
  client's registration allows the `refresh_token` grant, and says the granted scope in the
  response when it differs from the request. The request's scope travels `/authorize` → session →
  `CodeEntry.scope`; a code written by the previous build has none and is exchanged as it always
  was for its 300 s. **Matrix mode is untouched**: the Matrix scope for the device and a refresh
  token whatever was requested, because Synapse and the Matrix clients depend on exactly that.
  Provisional: a registration without `grant_types` allows the refresh grant; a request that asks
  for nothing grantable is granted `openid`. Pin: `generic_mode_issues_a_refresh_token_only_for_offline_access`,
  `generic_mode_grants_offline_access_only_to_a_client_that_may_refresh`,
  `generic_mode_issues_the_scope_that_was_requested_and_supported`,
  `the_generic_grant_follows_the_request_and_the_registration`,
  `generic_mode_exchanges_a_code_with_no_recorded_scope_as_before`,
  `matrix_mode_issues_the_matrix_scope_and_a_refresh_token_whatever_was_requested`,
  `sign_in_issues_the_code_for_the_bound_request` (the scope reaches the code),
  `a_code_written_before_the_scope_travelled_has_none`.
- **The headless client asks for what it relies on, in every flow.** `siwx-oidc-auth` requests
  `offline_access` (it refreshes, and a generic-mode server issues a refresh token only for it)
  and `urn:matrix:client:api:*` (its access token is used against the Matrix client-server API)
  in the code flow, with or without a proposed device, and in the device flow. A server ignores a
  scope it has no use for, so the request is harmless against any deployment, including 3547bd2.
  It must not be trimmed back to `openid profile`: an agent built that way gets no refresh token
  from a generic-mode server. Pin: `every_flow_asks_for_offline_access_and_the_matrix_api`,
  `build_scope_none_asks_for_what_the_client_relies_on`, `build_scope_some_requests_stable_device`,
  and on the wire `the_code_flow_sends_the_scope_it_relies_on`,
  `the_device_flow_sends_the_scope_it_relies_on`.
- **An empty `device_id` is JSON `null` on the wire, never `""`.** Synapse rejects `""`. Pin:
  `empty_device_id_renders_as_json_null`, `deviceless_token_body_carries_device_id_null`.
- **Refresh rotation keeps a 60 s grace pointer**: any replay of the old refresh token within
  60 s returns the same successor pair, so a client that lost the response recovers. Pin:
  `refresh_grace_window_tolerates_replay` (mock stack).
- **A refresh token is bound to the client it was issued to, through the one helper the code
  exchange uses too.** `oidc::authenticate_client` serves both grants, so they cannot drift: a
  request that names another client (`client_id` in the form or the Basic user name) is
  `invalid_grant`; a confidential client (registered `token_endpoint_auth_method` other than
  `none`, or none while `require_secret`) must present its secret, else `invalid_client`, a 401
  (RFC 6749 §5.2, with `WWW-Authenticate: Basic` after a Basic attempt). The grace replay is bound
  to the successor token's client. Provisional, recorded in docs/matrix-integration.md: a public
  client may omit `client_id`; a token whose client registration has expired (30 days against 90)
  keeps refreshing unless the request names another client or presents a secret;
  `POST /_matrix/client/v3/refresh` carries no client identity and is not bound. Read the
  `Authorization` header with `HeaderMap::typed_get`, never as two typed-header extractors, which
  reject each other's scheme and turn every request that has the header into a 400. Pin: unit
  `a_refresh_token_is_refused_to_a_client_it_was_not_issued_to`,
  `a_confidential_client_must_authenticate_to_refresh`,
  `a_public_client_refreshes_with_or_without_naming_itself`,
  `an_unset_authentication_method_follows_require_secret`,
  `a_token_outlives_its_clients_registration_but_not_its_binding`,
  `the_grace_replay_is_bound_to_the_client_too`, `a_basic_header_names_the_client_like_the_form_does`,
  `the_code_exchange_and_the_refresh_grant_authenticate_clients_identically`,
  `invalid_client_is_a_401_and_every_other_token_error_a_400`; mock stack:
  `a_refresh_token_is_refused_to_another_client`, `a_confidential_client_must_authenticate_to_refresh`,
  `a_public_client_refreshes_without_client_credentials`,
  `a_basic_authorization_header_authenticates_the_code_exchange`.
- **Never infer token validity from Synapse**: it caches introspection for two minutes. Our
  introspection answer is the authority.
- **No device-id recycling.** Sign-in upserts a fresh `SIWX_…` id and never deletes. Pin:
  `h2_sequential_signins_mint_distinct_device_ids` (mock stack).
- **A device is named only when a sign-in creates it**, after the OAuth client
  (`client_name`, else `client_id`), never a fixed brand. Synapse's `upsert_device`
  overwrites an existing device's name whenever one is sent, so the upsert never carries
  a name, and only a device it created (201) is then named via
  `update_device_display_name`. Pin:
  `upsert_names_only_a_device_this_sign_in_creates`,
  `a_client_supplied_device_that_exists_keeps_its_name`,
  `sign_in_names_a_new_device_after_the_registered_client`.
- **`/oauth2/revoke` never deletes a device.** Only explicit sign-out (`logout`, MSC4191
  `device_delete`) does; `logout/all` never deactivates the account. Pin:
  `teardown_policy_only_deletes_device_on_explicit_signout`,
  `h1_revoke_does_not_delete_device_but_logout_does`,
  `logout_all_invalidates_all_sessions_without_deactivating`.
- **Revocation keys on `TokenMetadata.username`** (the localpart), not the raw DID.

### Passkeys ([docs/passkeys.md](docs/passkeys.md))

- **Enumeration safety.** The picker is scoped only by the opaque `siwx_user` token; a forged,
  guessed or expired token is a Redis miss and yields usernameless login with zero credential
  ids. Never accept a client-supplied DID or identifier as the scope. Pin:
  `forged_user_cookie_yields_usernameless_empty_allow_credentials`,
  `user_session_create_lookup_roundtrip_and_forged_miss`.
- **`webauthn:by_did` is advisory**; `get_passkeys_for_did` self-heals by scanning. Pin:
  `get_passkeys_for_did_scan_fallback_equals_index`.
- **Only `VerifyError::UnknownCredential` becomes a 401** with the `unknown_credential`
  discriminator, and only that triggers `signalUnknownCredential`. Pin:
  `unknown_credential_maps_to_401_discriminator`, `other_verify_error_stays_internal_error`.
- **No server-side method prediction.** The login page does not grey out a method from a server hint.
- **A link overrides the derived DID**, for every reader (`credential_identity`); the credential
  store mirror never writes `webauthn:link/*`. Pin: `a_link_still_overrides_the_derived_did`,
  `mirroring_never_writes_the_link_namespace`.

### `/resolve`, userinfo and admin tokens

- **`/resolve` answers exactly four fields** (`did`, `mxid`, `exists`, `attested`). Adding one
  breaks the "nothing a caller could not compute" argument for leaving it unauthenticated.
  Pin: `a_successful_lookup_returns_all_four_keys_with_null_where_unknown` (mock stack).
- **`/resolve` never guesses.** A probe failure is a 502 with whatever was resolved; no Synapse
  or server name is a 503; a repeated parameter is a 400 in the error envelope. Pin:
  `an_unreachable_homeserver_is_a_502_never_a_guessed_mxid`,
  `a_standalone_deployment_degrades_with_503_never_500`,
  `a_repeated_query_parameter_is_rejected_with_the_documented_error_envelope`.
  Rate limiting belongs in the reverse proxy, not in-process.
- **`/resolve` refuses a `did` no sign-in could accept, with a 400 before any probe**
  (`resolve::check_did`: the sign-in parsers minus the signature, run on `canonicalize(did)`).
  Never stricter than sign-in and never narrowed to `supported_did_methods`; a false reject is
  the worse failure. Pin: `a_value_that_is_not_a_did_is_rejected_before_any_probe`,
  `a_value_that_is_not_a_did_is_rejected_without_asking_the_homeserver`,
  `valid_dids_still_resolve_in_every_spelling_the_lookup_honours` (live).
- **`io.inblock.mxid` in userinfo is omitted, never `null`**, is read from `TokenMetadata`
  (never re-derived), and appears in the JSON and signed-JWT variants alike. Pin:
  `without_a_matrix_server_name_the_claim_is_omitted_not_null`,
  `the_claim_name_on_the_wire_is_io_inblock_mxid`, `the_signed_jwt_variant_carries_the_claim_too`,
  `a_token_without_a_recorded_localpart_omits_the_claim_rather_than_deriving_one`.
- **`io.inblock.resolve_endpoint` in discovery is read by an Element Web patch**; it is advertised
  only when `/resolve` can answer; account management likewise, and the device grant only in
  delegated-auth mode, where `/device_authorization` is also the only place it is served. Pin:
  `provider_metadata_advertises_resolve_only_when_it_can_answer`,
  `account_management_is_advertised_only_when_the_actions_can_run`,
  `device_authorization_is_refused_outside_delegated_auth_mode`.
- **Admin tokens: both scopes, `device_id` null, TTL clamped in code to 30–900 s.** Never put a
  long-lived admin credential in configuration. Pin: `admin_scope_carries_both_required_scopes`,
  `ttl_clamp_caps_a_long_lived_request`, `ttl_clamp_raises_an_unusably_short_request`.
- **`account::SUPPORTED_ACTIONS` is the one list** behind discovery and dispatch. Pin:
  `supported_actions_cover_acceptance_criteria`, `canonical_action_collapses_session_aliases`.
- **Actions outside the Matrix spec use the `io.inblock.` namespace, never `org.matrix.`**
  (which belongs to matrix.org). The pre-rename `org.matrix.account_erase` /
  `org.matrix.account_reactivate` stay accepted aliases for one upgrade cycle and are never
  advertised. Pin: `non_spec_actions_are_advertised_only_under_the_io_inblock_namespace`,
  `legacy_erase_and_reactivate_names_are_accepted_as_aliases`.

### Structure

- **Config names: `SIWXOIDC_` over the legacy `SIWEOIDC_`, `siwx-oidc.toml` over the legacy
  `siwe-oidc.toml`**, both still read. Load config only through `config::figment()`; never drop
  a legacy name without a deprecation period. Pin: `config::tests`, e.g.
  `new_env_prefix_beats_legacy_when_both_are_set`, `full_precedence_ladder`.
- **Registries are plain functions** (`all_did_methods`, `all_cipher_suites`), no `inventory`
  crate (not WASM-safe). New DID methods and namespaces are opt-in through config.
- **aqua-auth has no logging** and no knowledge of ceremonies.
- **SIGTERM and SIGINT shut the server down gracefully**, answering requests already in flight.
  In the image it is PID 1, which ignores a signal it has no handler for, so without
  `shutdown_signal` `docker stop` waits 10 s and SIGKILLs. Pin:
  `sigterm_finishes_and_exits_zero_with_an_idle_connection_open`,
  `sigint_finishes_and_exits_zero_with_an_idle_connection_open`,
  `a_request_in_flight_when_sigterm_arrives_is_still_answered`.
- **Credential store: dual-write, not cut-over.** The legacy `webauthn:credential/*` namespace
  stays authoritative; mirror writes are best-effort; the backfill is additive and idempotent.
  Pin: `backfill_is_additive_link_aware_counter_preserving_and_idempotent` (needs its own
  empty Redis, `MIGRATION_TEST_REDIS_URL`; CI provides one).

## Logging conventions

The subscriber is set up in `axum_lib::main` with `EnvFilter`; the default filter is
`siwx_oidc=info,tower_http=info,warn`, overridden by `RUST_LOG`. `…_LOG_FORMAT=json` gives
structured output.

| Level | Use for |
|---|---|
| `error!` | Unrecoverable failures that halt a request or corrupt state (signing key load, Redis pool exhausted, a failed first-sign-in `provision_user`) |
| `warn!` | Recoverable or unexpected-but-handled conditions (best-effort Synapse failures, invalid client input, auth failures, an ephemeral signing key) |
| `info!` | Significant state changes and request lifecycle (sign-in, ceremony start/finish, startup) |
| `debug!` | Internal detail (Redis key operations, token metadata, ENS attempts) |

- Never log secrets, tokens, cookies or key material. Log a public-key fingerprint or `kid`.
- **Logs carry fingerprints of credentials, never the values.** A log site that would name an
  access or refresh token, authorization code, device code, user code, session id, cookie,
  client secret, registration access token or passkey credential id, directly or inside a Redis
  key, names `redact::fingerprint(..)` of it (`redact_key(..)` for a `namespace/identifier` key,
  `redact_url(..)` for a URL that carries a password). The fingerprint is the first eight hex
  characters of the SHA-256, so an operator can compute it for a value they hold; it is kept
  short because a user code has about 34 bits of entropy. Request logging records method and
  path, never the query, and that holds for the span too: tower-http's default span prints the
  whole URI in front of every debug line. A struct that holds a credential prints its fingerprint
  under `Debug` (`RotatedToken`, `DeviceCodeEntry`). Pin:
  `the_redis_code_and_token_paths_log_fingerprints_never_values`,
  `a_struct_that_holds_a_credential_prints_its_fingerprint_under_debug`,
  `no_log_site_names_a_credential_without_its_fingerprint` (a scan of every log macro in `src/`,
  which covers the sites no test reaches),
  `the_device_flow_logs_fingerprints_never_its_codes`,
  `a_device_poll_that_loses_the_claim_logs_the_code_only_as_a_fingerprint`,
  `the_ceremony_starts_log_session_ids_only_as_fingerprints`,
  `request_logging_names_the_path_and_never_the_query`,
  `the_boot_check_never_prints_the_redis_password`. A new log site that names a credential
  variable fails the scan; add the variable name to `CREDENTIAL_NAMES` in `tests/log_hygiene.rs`
  when you introduce a new kind of credential.
- Use structured fields (`info!(did = %did, "sign_in success")`), not string interpolation.
- Log errors at the boundary (`CustomError::into_response`). Modules that bypass `CustomError`
  (`introspect`, `compat`, `resolve`) log their own errors.

## Conventions

- **Commits:** Conventional Commits (`fix(resolve): …`, `docs(audit): …`, `test(ci): …`).
- **Comments and docs state what is true and why.** History belongs in commit messages and
  `docs/audits/`. A comment that says "do not simplify" must say what breaks.
- **Keep the docs in step with the code** in the same change: `docs/api/openapi.yaml` for routes,
  [docs/configuration.md](docs/configuration.md) for config fields, and the matching page in
  [docs/](docs/README.md) for behaviour.
- **Wire and config compatibility:** `sub` is the full DID; the wallet cookie is `siwx` with
  `{did, message, signature}`; PKCS#8 PEM is the canonical key format; the frontend uses
  injected EIP-1193 wallets only (no WalletConnect, no project id).
- **Status wording:** describe Matrix support precisely (see [docs/matrix-integration.md](docs/matrix-integration.md)):
  "auth service in Synapse's `matrix_authentication_service` integration", not "replaces MAS" or
  "MSC3861 mode". `/_synapse/mas/*` is an internal Synapse API designed for MAS.

## Public-repo hygiene

This repository is public. Never commit infrastructure access details (host names or IPs of
maintainer machines, SSH users and ports, stack paths), personal data (real users' MXIDs,
wallet addresses, IP addresses; use `example.org` and generated test identities), secrets or
key material, or maintainer session plans and handovers. Maintainer operations material lives
outside this repository, in a private operations repository and the gitignored
`CLAUDE.local.md` (`/internal/` stays gitignored as a guard). Report vulnerabilities as described
in [SECURITY.md](SECURITY.md).

## External repos

| Repo | Role |
|---|---|
| [inblockio/aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth) (crate `aqua-auth`) | Layer 1: `DIDMethod`/`CipherSuite`, CAIP-122 verification, WebAuthn assertion verification, credential store. Pinned by tag in both `Cargo.toml` files; bump both together. |
| [inblockio/siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server) | Synapse + Element Web deployment, the Synapse patch registry (`patches/synapse/README.md`) and the `io.inblock.did` denylist. |
| [spruceid/siwe-oidc](https://github.com/spruceid/siwe-oidc) | The Ethereum-only predecessor this project was forked from. Lineage: [docs/architecture.md](docs/architecture.md#lineage). |

## Skills

`skills/*.md` are task guides for agents, usable by humans too. Claude Code picks up the ones
symlinked from `.claude/commands/` as `/skill-name`.

| Skill | Purpose |
|---|---|
| `add-did-method` | Add a DID method to aqua-auth (layer 1) |
| `add-cipher-suite` | Add a `did:pkh` cipher suite to aqua-auth (layer 1) |
| `add-auth-ceremony` | Add a server-side auth ceremony (layer 2) |
| `authenticate-siwe-matrix` | End-to-end flow: Element Web → siwx-oidc → Synapse |
| `debug-oidc` | Debug an OIDC sign-in |
| `deploy-check` | Post-deployment checklist with Synapse |
| `docker-build` | Build and verify the Docker image |
| `cross-signing-bootstrap-and-debug` | Cross-signing bootstrap and reset (MSC3967, MSC4312, MSC4191) |
| `element-x-qr-code-specialist` | Element X QR login (RFC 8628, MSC4108) |
