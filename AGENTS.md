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
crate [aqua-auth](https://github.com/inblockio/aqua-auth), pinned by tag in both manifests.
Modules marked **lib** are compiled into the library crate, so `tests/*.rs` can link them;
everything else exists only in the binary crate.

| `src/` | Role |
|---|---|
| `main.rs` | Binary entry point. Declares the binary-only modules and calls `axum_lib::main`. |
| `lib.rs` | Library crate root. `synapse_client` is deliberately not re-exported (see Invariants). |
| `axum_lib.rs` | Startup: loads config through `config::figment()`, validates it (DID methods and pkh namespaces against the aqua-auth registries, signing key, retired keys, WebAuthn), `store_default_clients` (digested), `AppState`, the router, handler glue, the `siwx_user` / `acct_session` cookies, the CORS layer. |
| `config.rs` | `Config`, its defaults, and `figment()`: the one place config names and precedence are defined. Reference: [docs/configuration.md](docs/configuration.md). |
| `oidc.rs` | OIDC core: discovery, JWKS, `authorize`, `sign_in`, `token` (authorization-code, refresh-token and device-code grants; `authenticate_code_client` and `authenticate_refresh_client` authenticate the client for the first two, and `client_is_confidential` decides which clients must present a secret), `userinfo`, client registration, RP-initiated logout (`end_session`, `verify_id_token_hint`), `EcdsaSigningKey` (ES256, key-derived `kid`), retired-key parsing, ENS claims, and `provision_synapse_device`, the single provisioning and DID-publication path. |
| `introspect.rs` | `POST /oauth2/introspect` (RFC 7662) for Synapse; opaque `mat_`/`mcr_` token generation. |
| `admin_token.rs` | `POST /oauth2/admin_token`: short-TTL token whose scope carries `urn:synapse:admin:*`. |
| `compat.rs` | `POST /oauth2/revoke` (RFC 7009) and the Matrix client-server endpoints siwx-oidc answers (login flows, logout, logout/all, refresh, device deletion); `TeardownPolicy`. |
| `device_auth.rs` | RFC 8628 device authorization: `/device_authorization`, the `/device` approval page (wallet and passkey), server-issued CAIP-122 nonces. |
| `account.rs` | MSC4191 `/account` page and actions, MSC4312 cross-signing reset, and the two non-spec actions `io.inblock.account_erase` / `io.inblock.account_reactivate`. `SUPPORTED_ACTIONS` is the single source of truth for discovery and dispatch; `canonical_action` maps `session_*` aliases to `device_*` and the legacy `org.matrix.account_erase` / `org.matrix.account_reactivate` names to the new ones. The account session (`create_account_session`) lives in the `OwnSession::Account` layout; the page's sign-out is `POST /account/sign_out` (handler in `axum_lib.rs`). |
| `webauthn.rs` | Passkey ceremonies (register, authenticate, link), the new-identity and deactivation gates (`reject_if_new_identity`, `reject_if_deactivated`), picker scoping. |
| `synapse_client.rs` | Synapse client with two credentials: the MAS shared secret on `/_synapse/mas/*` (`provision_user`, `upsert_device`, `update_device_display_name`, `allow_cross_signing_reset`, `localpart_status`, `delete_device`, `deactivate_user`, `reactivate_user`) and a minted admin-scoped token (`admin_request`) on `/_synapse/admin/*` and the client-server API (`list_devices`, `get_device`, `has_cross_signing_keys`, `read_profile`, `publish_did_field`, `read_did_field`). |
| `did_assertion.rs` | `DID_PROFILE_FIELD`, `mint_did_assertion` (compact ES256 JWS), `did_profile_value`, `DidPublication`. |
| `resolve.rs` | `GET /resolve`, the public DID↔MXID lookup. |
| `backchannel.rs` | OpenID Connect Back-Channel Logout: `mint_logout_token`, the SSRF guard (`refused_class`, `UriGuard`), `deliver`, and the outbox `Worker` started by `axum_lib::main`. |
| `localpart.rs` | Grandfathering policy: `resolve_identity` (fallible) and `resolve_identity_or_legacy` (fail-safe to legacy). |
| `mxid.rs` (lib) | Pure localpart derivation: `localpart_for`, `legacy_localpart`, `canonicalize`. `sha2` only. |
| `redact.rs` (lib) | `fingerprint`, `redact_key`, `redact_url`: what a log line may say about a credential. |
| `alias.rs` (lib) | `alias_for(did)`: the generated `Firstname Surname` a new account is seeded with. |
| `credential_identity.rs` (lib) | Which identity a stored passkey authenticates: a `webauthn:link/*` entry overrides the derived `did:key`. |
| `credential_store.rs` (lib) | Optional aqua-auth credential store, dual-write and read-through, enabled by `AQUA_WEBAUTHN_REDIS_URL`. |
| `credential_migration.rs` (lib) | Additive backfill of passkey credentials into the aqua-auth store. |
| `db/mod.rs` (lib) | `DBClient` trait, entry types (`CodeEntry`, `SessionEntry` with its bound `AuthorizationRequest`, `ClientEntry` with the digests of its secret and registration access token and `client_entry_without_plaintext`, `DeviceCodeEntry` and the `DeviceCodeRef` naming its layout, `TokenMetadata` with its `TokenKind`), `Ceremony`, `OwnSession` (the `siwx_user` and `acct_session` layouts), `legacy_token_kind`, Redis key prefixes and TTLs. |
| `db/redis.rs` (lib) | Redis implementation, incl. `revoke_device_tokens`, `revoke_all_user_tokens` (grants, then legacy `token/*` entries), `get_passkeys_for_did`, the own sessions (`create_own_session`, `lookup_own_session`, `end_own_session`, `revoke_own_sessions`; `lookup_user_session` for the picker), `purge_identity`. |
| `db/outbox.rs` (lib) | The back-channel logout outbox (`outbox:backchannel_logout`): `LogoutEntry`, claim under a lease, retry, complete. Entries are queued by `drop_grant` in `db/grant.rs`. |
| `db/grant.rs` (lib) | The grant record and its Lua scripts: `issue_grant`, the access check `check_access_token` (with the legacy read fallback), `rotate_refresh_token` (the one rotation script), `ReuseEvent`, grant revocation, and the legacy migration (`peek_refresh_token`, `lift_legacy_refresh_token`). Keyspace and decision table in its module docs. |
| `db/tokens.rs` (lib) | Token formats (`mat_`, `msa_`, `mcr_{handle}_{secret}`), `parse_refresh_token` (never panics), `digest` (the SHA-256 every credential a client holds is stored as). |
| `db/seal.rs` (lib) | The sealed successor pair: AES-256-GCM under a key HKDF-derived from the previous refresh token, so only its presenter can open it. |
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
  `cargo test --workspace` runs the unit tests of both crates plus 22 tests in ten files:
  `openapi_covers_every_route` (2), `localpart_vectors` (1), `graceful_shutdown` (3),
  `log_hygiene_credential_store` (1) and `log_capture_callsite_interest` (1), which
  need nothing; `account_linking_dual_write` (6), which needs the test Redis, and `log_hygiene`
  (4, one of them needs it);
  `credential_migration_live` (2), which needs its own disposable, empty Redis named by
  `MIGRATION_TEST_REDIS_URL`; and the pure check `an_absent_strict_skips_variable_means_strict`
  in `e2e_account_lifecycle_live` and in `e2e_did_field_live` (1 each). In the headless
  client's crate it also runs the three pure checks of `siwx-oidc-auth/tests/live_upgrade.rs`'s
  helpers.
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
  `e2e_backchannel_logout` needs a second siwx-oidc in generic mode (no MAS shared secret, its
  own port and Redis database, `localhost` in `SIWXOIDC_BACKCHANNEL_LOGOUT_ALLOWED_HOSTS`) and
  uses the stub relying party in the Synapse mock (`/__rp/*`); see e2e/README.md.
- **Live suites** need a real Synapse and run in no CI job: `e2e_did_field_live` (a patched
  Synapse), `e2e_account_lifecycle_live`, five of the six `e2e_msc4191_live` tests,
  `e2e_msc3861::msc4191_metadata_advertised_and_forwarded` and `e2e_messaging`. Set
  `E2E_STRICT_SKIPS=1` so a skipped assertion fails instead of passing. The headless client's
  `siwx-oidc-auth/tests/live_deployment.rs` runs against a whole deployment named by
  `SIWX_SERVER` and `SIWX_HOMESERVER`, and creates and deactivates a throwaway account; see
  e2e/README.md.
- **Upgrade qualification suites** prove that what a deployment holds survives a switch of
  the siwx-oidc build, and run before every promotion (none in CI). `e2e/upgrade-from.sh
  <old-image> [<new>]` runs a mock upgrade from an image to this tree's build, Redis kept: the
  R1/R2 stages of `e2e_race_teardown` and the live suite below, with the Synapse mock as the
  homeserver (it forwards `POST /_matrix/client/v3/refresh` and `DELETE …/devices/{id}` to
  siwx-oidc, as a deployment's edge does). `siwx-oidc-auth/tests/live_upgrade.rs` mints
  sessions in every shape a deployment holds before the switch and checks them after it,
  in stages (`QUALIFY_STAGE=mint|check|cleanup`, state in a 0700 `QUALIFY_STATE_DIR`),
  against a real deployment or the mock; `siwx-oidc-auth/examples/soak.rs` holds a population
  of sessions across the switch. Each creates and deactivates throwaway accounts; see
  e2e/README.md.
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
  check); job `rust-e2e-mock` runs the promotable mock-stack suites (plus a generic-mode
  server for `e2e_backchannel_logout`); job `browser-e2e` runs
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
  challenge, scope, nonce) is stored in the session as one value, and `sign_in` issues the code
  for exactly that request; a session the previous build stored, with the scope and the nonce
  beside the request, is read into it. The handler has no `Query` extractor: the login page
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
  `authorize_binds_the_request_to_the_session`,
  `a_previous_build_session_reads_its_scope_and_nonce_into_the_request`,
  `a_session_the_previous_build_bound_issues_its_code_with_its_scope_and_nonce`.
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
  `discovery_advertises_only_the_code_response_type`, and the client authentication methods
  (`client_secret_basic`, `client_secret_post`, `none`: what `POST /token` reads) by
  `discovery_advertises_every_client_authentication_method_the_token_endpoint_accepts`.
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
- **The grant is the unit** (I2). Every access and refresh token belongs to exactly one grant
  (`grant/{digest(handle)}`, `src/db/grant.rs`); issuance creates it, rotation and revocation act
  on it, and the access check reads the grant behind the `at/…` entry, so deleting a grant makes
  all its tokens inert at once. Indices hold grant ids, never token keys. A grant with no refresh
  token (a `service` grant, a generic-mode grant without `offline_access`) lives as long as its
  access token. Pin: `issue_grant_writes_the_grant_its_access_entry_and_both_indices`,
  `an_access_token_resolves_to_its_grant_until_the_grant_is_gone`,
  `revoking_a_device_deletes_its_grants_only_and_plants_the_tombstone`,
  `revoking_a_user_deletes_every_grant_of_the_user`,
  `revoking_by_token_deletes_the_grant_of_an_accepted_token_only`,
  `revoking_a_deviceless_refresh_token_revokes_its_grant_an_access_token_only_itself`.
- **One rotation script, one live chain** (I3). Both refresh endpoints rotate only through
  `RedisClient::rotate_refresh_token`, one Lua script that reads `now` from Redis `TIME` and
  writes the new access entry itself, so no interleaving can fork the chain or mint a token for a
  grant being revoked. Do not add a second refresh path or move a check out of the script. Pin:
  `concurrent_refreshes_at_the_token_endpoint_converge_on_one_pair`,
  `concurrent_refreshes_at_the_matrix_endpoint_converge_on_one_pair` (mock stack),
  `concurrent_rotations_of_one_token_converge_on_one_pair`,
  `the_current_refresh_token_rotates_into_a_new_pair`.
- **A grant's absolute expiry is fixed at the authentication, only moves earlier, and runs on
  Redis `TIME`** (I6). With a cap configured (`grant_absolute_lifetime_secs`, the per-client map;
  unset by default, D1 provisional) a grant gets `absolute_exp` = `auth_time` + its client's cap
  when it is issued or lifted: the client's per-client value when one is set (longer or shorter),
  else the global default (provisional, maintainers to confirm). The rotation script recomputes
  min(`absolute_exp`, `auth_time` + the cap now configured), refuses and deletes the grant past
  it like an inactive one, and writes it back; so a lowered cap applies at the next rotation and
  nothing extends it. No access token's `exp` (nor the TTL of its entry or of the grant) passes
  it, and the access check refuses a token whose grant is past it, judging a grant written
  without `absolute_exp` against `auth_time` + its client's cap. `auth_time` is the sign-in or
  the device approval, stamped from Redis `TIME` (a lifted legacy grant: the legacy entry's
  `iat`, never later than now); never compute a deadline from an instance clock, and never let
  a rotation, a replay or a raised cap move `absolute_exp` later. With no cap, lifetimes are
  exactly as before. Pin: `h5_no_sequence_outlives_the_absolute_expiry` (property test, seeded,
  `H5_SEED` replays a failure), `an_access_token_never_outlives_its_grants_absolute_expiry`,
  `a_grant_written_without_a_cap_is_capped_from_its_auth_time`,
  `a_lowered_cap_applies_at_the_next_rotation_and_a_raised_one_never_extends`,
  `a_lifted_grant_counts_its_cap_from_the_legacy_issue_time`,
  `a_per_client_cap_overrides_the_global_default`,
  `a_device_grant_counts_its_lifetime_from_the_approval`,
  `an_absolute_grant_lifetime_shorter_than_a_device_code_is_refused`. The access check also judges
  a token's own `exp` on Redis `TIME`, and introspection and both refresh endpoints answer
  `expires_in` from the store's instant (`check_access_token_at`, `RotatedPair::expires_in`),
  never `Utc::now()`. Pin: `the_access_check_judges_exp_on_redis_time`,
  `expires_in_counts_from_the_stores_redis_time`.
- **Epochs refuse every older grant of a scope with one write; the user epoch replaced the user
  tombstone** (I9). `epoch:global`, `epoch:client/{client_id}` and `epoch:user/{username}` hold
  Unix milliseconds from Redis `TIME`, have no TTL and only move later (`RedisClient::set_epoch`).
  A grant whose `auth_ms` (the authentication in milliseconds, beside `auth_time`) is at or before
  the largest epoch that applies is refused by the rotation script (which deletes it), by the
  access check (introspection answers inactive at once; Synapse's two-minute cache is the known
  limit) and by the lift script; a legacy access token is judged by its `iat`. A grant
  authenticated in the epoch's own millisecond is refused; a grant written without `auth_ms`
  counts from the start of its `auth_time` second. `logout/all`, deactivation and erasure set the
  user epoch in the script that deletes the user's grants, so a sign-in after them refreshes at
  once. Never plant the user tombstone again, and keep the scripts READING it until one release
  after Phase 3: one a previous build planted must still refuse for its 900 s. The device
  tombstone stays: it closes the race between a device sweep and the lift of a legacy refresh
  token. Global and client epochs have no HTTP endpoint, to add no remote surface: an operator
  sets them ([docs/matrix-integration.md](docs/matrix-integration.md#epochs)). An unset epoch
  is none, never 0. Teardown's resolver (`resolve_refresh_token`) treats a refused refresh token as
  unknown, so revoking it tears nothing down. The comparisons made in Rust (a legacy access
  token, teardown) follow the scripts' rule to the millisecond. Pin:
  `e1_one_user_epoch_refuses_every_older_grant_of_the_user`,
  `e1_after_logout_all_a_new_sign_in_refreshes_at_once`,
  `the_epoch_comparison_is_at_or_before_to_the_millisecond`,
  `the_legacy_access_check_refuses_at_or_before_the_epoch_to_the_millisecond`,
  `the_teardown_resolver_refuses_at_or_before_the_epoch_to_the_millisecond`,
  `e1_a_client_epoch_refuses_that_clients_older_grants_only`,
  `e1_a_global_epoch_refuses_every_older_grant`, `a_legacy_token_older_than_an_epoch_is_refused`,
  `set_epoch_takes_redis_time_and_never_moves_earlier`,
  `the_scripts_name_the_epoch_keys_the_library_writes`,
  `a_tombstoned_device_or_user_refuses_rotation_and_replay`,
  `revoking_a_refresh_token_an_epoch_refuses_leaves_a_newer_grant_of_the_device`; mock stack:
  `e1_after_logout_all_older_grants_are_refused_and_a_new_sign_in_refreshes_at_once`,
  `e1_a_client_epoch_refuses_that_clients_older_grants_only`,
  `e1_a_global_epoch_refuses_every_older_grant`,
  `e1_a_user_tombstone_written_by_the_previous_build_still_refuses_refresh`.
- **No credential a client holds is stored in the clear** (I1): tokens, authorization codes,
  device and user codes, session identifiers (the login `session` cookie, the WebAuthn,
  account re-auth and device-approval ceremony ids, the `siwx_user` picker hint and the
  `acct_session` account session), the device-approval and account re-auth
  CAIP-122 nonces, client secrets and registration access tokens. Each appears in a key or value only as its SHA-256
  (`db::tokens::digest`); access tokens are keyed `at/{digest}`, refresh tokens are kept as
  digests in their grant, and the successor pair of a rotation is sealed under the previous
  refresh token (`db::seal`); no key or value holds a token, its body, or a refresh token's
  handle or secret. A client entry keeps the digests of its secret and registration access token
  (`ClientEntry::secret_matches` / `access_token_matches` compare digests in constant time, on
  every path: code exchange, refresh grant, `/client/{id}`), and `default_clients` are written
  digested. Each digest-keyed prefix, and the client entry's member names, differ from what an
  earlier build wrote, so a stored digest presented as a credential matches nothing; do not
  "unify" them. Entries an earlier build wrote are read for their remaining lifetime and used
  once: `token/{raw}` (lifted), `codes/`, `sessions/`, `device_codes/`, `user_codes/`,
  `caip122_nonce/`, `webauthn:challenge/`, `webauthn:link_challenge/`, and a plaintext client entry,
  upgraded atomically on first read without losing a field (marked
  `TODO(remove one release after Phase 2b)`; plaintext clients live 30 days); and the own
  sessions `user:session/` (30 days) and `account_session/` (600 s), read, ended by the account
  page's sign-out and swept by prefix when the user's sessions are revoked (marked `TODO(remove`
  at `KV_USER_SESSION_PREFIX` and `KV_LEGACY_ACCOUNT_SESSION_PREFIX`). Accepted deploy
  residue: the previous build's consumed device-approval nonce keeps its user code for up to
  300 s after an upgrade, and the previous build's login sessions (with their signed-in flags)
  keep their raw keys until they expire (300 s), also after a sign-in on the new build, which
  writes no session; a spent session cannot sign in again. Not covered: the account page's
  CSRF token, kept in the value of the digest-keyed account session, which authorizes nothing
  without the session cookie; passkey credential ids
  (`webauthn:credential/{id}`, `webauthn:link/{id}`), which are public identifiers the server
  hands out in `allowCredentials`, not bearer credentials; a grant's `sid` (stored in the grant
  and as the key `idx:grants:sid/{sid}`), which every RP that holds the ID token receives and
  which ends a session only together with an ID token this provider signed; the back-channel
  outbox entries (`outbox:backchannel_logout`: a client id, the DID, the `sid` and the grant
  id, no credential; logout tokens are signed at delivery and never stored); and the login
  CAIP-122 nonce, a
  challenge kept in the value of the digest-keyed session, which authenticates nothing without
  the session id and a signature. Pin (mock stack, each scans the whole stack Redis):
  `no_token_the_client_holds_is_stored_in_the_clear`,
  `no_code_or_session_the_client_holds_is_stored_in_the_clear`,
  `no_client_secret_or_registration_token_is_stored_in_the_clear`,
  `legacy_tokens_keep_working_after_the_upgrade`, `in_flight_codes_and_sessions_survive_the_upgrade`;
  unit: `a_stored_digest_presented_as_a_code_is_not_a_code`,
  `a_stored_digest_presented_as_a_credential_matches_nothing`,
  `every_client_authentication_compares_digests_of_what_is_presented`,
  `concurrent_first_reads_of_a_plaintext_client_all_authenticate_and_leave_one_digested_entry`,
  `an_upgrade_never_overwrites_an_entry_that_changed_since_it_was_read`,
  `default_clients_are_stored_only_as_digests_and_authenticate`,
  `device_and_user_codes_are_stored_only_as_digests`, `ceremony_state_is_digest_keyed_and_taken_once`,
  `caip122_nonces_are_stored_by_digest_and_used_once`, `a_wrong_token_cannot_open_the_successor`,
  `the_sealed_value_names_neither_token_and_is_fresh_each_time`,
  `malformed_refresh_tokens_are_unknown_never_a_panic`.
- **Reuse is recognised and logged, never silently accepted** (I5). A refresh token whose
  handle names a live grant but that is neither `current_rt` nor the unused `previous_rt` is
  answered exactly like an unknown token and emits one `warn!` with the stable message
  `refresh token reuse detected` and the fields `security_event="refresh_token_reuse"`,
  `grant_fp`, `generation`, `client_id`, `grant_kind`, `branch`, `grant_revoked`
  (fingerprints only). The rest is the switch `reuse_revokes_grant`, read once at startup
  (`RedisClient::with_reuse_enforcement`). **Off** (the default, phase A): nothing is revoked
  (`grant_revoked=false`); storage per grant stays constant however long the chain. **On**
  (phase B): the rotation script that detected the reuse also deletes the grant, in the same
  atomic step, through `drop_grant` (an `oidc` grant queues its back-channel logout, the `sid`
  index entry goes) and drops its index entries; the event says `grant_revoked=true`; the answer
  stays the unknown-token answer; the Synapse device is never deleted and no device tombstone is
  planted (as with revoke). The current holder of the grant is refused from then on, its access
  token at once and its refresh token at its next refresh: that is the point of enforcement. A
  replay of the previous token while its successor is unused is a lost response (I4), never
  reuse, so it never revokes. The switch stays off until the maintainers decide (D2: at least 30
  days of phase-A telemetry from Element Web and Element X, every reuse event explained, no
  unexplained single-holder event, H6). Pin:
  `h3_a_thousand_rotations_recognise_every_superseded_token_in_constant_storage`,
  `rotating_the_successor_counts_as_its_use_and_older_tokens_are_reuse`,
  `the_reuse_event_carries_its_fields_and_fingerprints_only`,
  `a_replay_an_hour_later_returns_the_same_pair_and_after_use_is_reuse` (the event at `/token`),
  `the_matrix_endpoint_logs_one_reuse_event_for_a_superseded_refresh_token` (the event at
  `/_matrix/client/v3/refresh`),
  `a_replay_returns_the_same_pair_until_the_new_access_token_is_used` (mock stack, switch off);
  `with_enforcement_off_reuse_leaves_the_grant_intact`,
  `with_enforcement_on_reuse_deletes_the_grant_and_never_the_device`,
  `with_enforcement_on_a_lost_response_replay_returns_the_same_pair_and_deletes_nothing`,
  `with_reuse_enforcement_a_superseded_token_at_the_token_endpoint_ends_its_grant`,
  `with_reuse_enforcement_the_matrix_endpoint_ends_the_grant_and_never_the_device` (in process:
  the shared mock stack runs one server with the default, which the mock-stack pins need),
  `reuse_enforcement_is_off_by_default_and_read_under_both_prefixes`.
- **Tokens of a build before the grant record keep working; nobody signs in again** (design 5.8).
  A legacy access entry stays readable until it expires (`check_access_token`'s read fallback,
  removed one release later). A legacy refresh token is lifted into a grant by one script the
  first time either refresh endpoint sees it (`lift_legacy_refresh_token`), with its client
  authenticated as for any refresh and its confidentiality decided by `client_is_confidential`;
  the `legacy_rt/…` pointer sends every later presentation through the rotation script as the
  grant's previous token. Legacy grace pointers are not read. Pin:
  `legacy_tokens_keep_working_after_the_upgrade` (mock stack; a real upgrade with
  `E2E_R1_STAGE=mint`/`check`), `a_legacy_refresh_token_is_lifted_once_and_its_replays_follow_the_same_rule`,
  `concurrent_presentations_of_one_legacy_token_converge_on_one_pair`,
  `a_legacy_token_that_may_not_be_lifted_stays_untouched`,
  `a_legacy_refresh_token_is_lifted_for_its_own_client_with_its_confidentiality`,
  `the_matrix_endpoint_lifts_a_public_clients_legacy_token_but_not_a_confidential_ones`,
  `a_lifted_legacy_token_is_resolved_and_revoked_like_its_grants_previous_token`.
- **A replay of the immediately previous refresh token returns the same successor pair if, and
  only if, the successor is unused** (I4). Both refresh endpoints run the one rotation script
  (`RedisClient::rotate_refresh_token`), so concurrent refreshes of one token all get the same
  pair and leave one live chain. The successor counts as used once its access token is first
  accepted by introspection or `/userinfo`, or once its refresh token rotates; after that the
  replay is reuse, answered like an unknown token (`invalid_grant` at `/token`, `M_UNKNOWN_TOKEN`
  at `/_matrix/client/v3/refresh`). No timer decides it: the decision reads grant state, never a
  clock. A replay whose successor was rotated away or whose grant was revoked is refused the same
  way. At `/token` the replay is also bound to the client (next invariant); the Matrix endpoint
  carries no client and cannot bind it to one. Pin (mock stack):
  `concurrent_refreshes_at_the_token_endpoint_converge_on_one_pair`,
  `concurrent_refreshes_at_the_matrix_endpoint_converge_on_one_pair`,
  `a_replay_returns_the_same_pair_until_the_new_access_token_is_used`,
  `a_replay_after_more_than_a_minute_still_returns_the_same_pair`; unit:
  `a_replay_an_hour_later_returns_the_same_pair_and_after_use_is_reuse`,
  `a_replay_whose_successor_has_been_rotated_or_revoked_is_refused`,
  `a_replay_is_bound_to_the_client_too`, `a_matrix_refresh_replay_needs_its_successor_live`,
  `concurrent_rotations_of_one_token_converge_on_one_pair`.
- **A refresh token is bound to the client it was issued to, through the helpers the code
  exchange uses too.** `oidc::authenticate_code_client` (strict) and
  `oidc::authenticate_refresh_client` (tolerates an expired registration) share
  `check_named_client`, `check_client_secret` and `client_is_confidential`, so the grants cannot
  drift: a request that names another client (`client_id` in the form or the Basic user name) is
  `invalid_grant`; a confidential client (registered `token_endpoint_auth_method` other than
  `none`, or none while `require_secret`) must present its secret, else `invalid_client`, a 401
  (RFC 6749 §5.2, with `WWW-Authenticate: Basic` after a Basic attempt). The replay of a lost
  response is bound to the grant's client like a rotation. Provisional, recorded in docs/matrix-integration.md: a public
  client may omit `client_id`; a token whose client registration has expired (30 days against 90)
  keeps refreshing unless the request names another client or presents a secret.
  `POST /_matrix/client/v3/refresh` carries no client identity, so it refuses a confidential
  client's refresh token exactly like an unknown token, leaving it untouched for `/token`; the
  grant records at issuance whether its client is confidential, by the same rule
  (`client_is_confidential`, the only place that decides it). At `/token` the client is
  authenticated before the rotation script runs (RFC 6749 order), so a superseded token presented
  with a wrong secret is `invalid_client`, not the unknown-token answer. Read the
  `Authorization` header with `HeaderMap::typed_get`, never as two typed-header extractors, which
  reject each other's scheme and turn every request that has the header into a 400. A Basic user
  name and password are form-urldecoded before they are compared (RFC 6749 §2.3.1: a secret with
  a space, `+` or `%` arrives escaped); a Bearer token is taken as sent. Pin: unit
  `a_refresh_token_is_refused_to_a_client_it_was_not_issued_to`,
  `a_confidential_client_must_authenticate_to_refresh`,
  `a_public_client_refreshes_with_or_without_naming_itself`,
  `an_unset_authentication_method_follows_require_secret`,
  `a_token_outlives_its_clients_registration_but_not_its_binding`,
  `a_replay_is_bound_to_the_client_too`, `a_basic_header_names_the_client_like_the_form_does`,
  `basic_credentials_are_form_urldecoded_before_they_are_compared`,
  `a_plain_basic_secret_and_a_bearer_token_are_taken_as_sent`,
  `the_code_exchange_and_the_refresh_grant_authenticate_clients_identically`,
  `a_grant_records_its_client_as_confidential_exactly_when_token_demands_a_secret`,
  `invalid_client_is_a_401_and_every_other_token_error_a_400`; mock stack:
  `a_refresh_token_is_refused_to_another_client`, `a_confidential_client_must_authenticate_to_refresh`,
  `a_public_client_refreshes_without_client_credentials`,
  `a_basic_authorization_header_authenticates_the_code_exchange`,
  `the_matrix_endpoint_refuses_a_confidential_clients_refresh_token` (unit and mock stack).
- **A token-store fault is a retryable 503 `M_UNKNOWN` at the Matrix routes, never
  `M_UNKNOWN_TOKEN`**, which a Matrix client takes for "signed out" (it clears its crypto store):
  `POST /_matrix/client/v3/refresh` and the device-deletion routes (`username_from_bearer`
  returns the store error instead of folding it into "unknown"). Pin:
  `a_store_fault_at_the_matrix_refresh_endpoint_is_a_retryable_503`,
  `a_store_fault_on_a_bearer_route_is_a_retryable_503`.
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
- **Every grant issued with an ID token has its own random `sid`, and every ID token carries
  it** (I8). The `sid` is 22 random base62 characters (`tokens::new_session_id`), never derived
  from the grant handle, a token or the device id; `idx:grants:sid/{sid}` names the grant for
  exactly the grant's lifetime (issue and rotation set both TTLs; every script that deletes a
  grant goes through the one Lua helper `drop_grant`, which drops the index entry and is where
  back-channel logout enqueues). A `service` grant has none, and a grant issued before `sid`
  existed (or lifted from a legacy token) never gets one: a refresh response has no ID token,
  so no RP could learn it. Pin: `every_grant_with_an_id_token_has_its_own_random_sid`,
  `the_sid_index_lives_and_dies_with_its_grant`,
  `the_scripts_name_the_sid_index_the_library_reads`,
  `every_id_token_carries_the_sid_of_its_grant`.
- **RP-initiated logout (`/end_session`) checks everything before it ends anything, ends
  exactly the grant the hint's `sid` names, and never deletes a Matrix device.** The
  `id_token_hint` must be an ID token this provider signed (live or retired key, by `kid`,
  over the received bytes, `alg` ES256 only, `iss` this provider; expiry not checked); a
  `client_id` must be its audience; the grant must belong to the hint's `aud` and `sub`; a
  `post_logout_redirect_uri` is honoured only when registered for that client, matched exactly
  through the one helper `oidc::post_logout_redirect_uri_is_registered`, with `state` appended.
  Any refusal is a 400 that ends nothing and never redirects (no open redirect); a store fault
  is a 503. Pin: `end_session_deletes_exactly_the_grant_its_hint_names_and_never_a_device`,
  `end_session_redirects_only_to_an_exactly_registered_uri_with_state`,
  `end_session_refuses_a_foreign_or_tampered_hint` (mock stack);
  `an_id_token_hint_verifies_with_the_live_or_a_retired_key_expired_or_not`,
  `a_tampered_foreign_unsigned_or_misissued_hint_is_refused`,
  `post_logout_redirect_uri_matching_is_exact`,
  `end_session_ends_the_named_oidc_grant_and_redirects_with_state`,
  `end_grant_by_sid_deletes_exactly_the_named_grant_of_its_client_and_did`,
  `a_store_fault_while_ending_the_grant_or_reading_the_client_is_a_503`,
  `registration_stores_and_echoes_post_logout_redirect_uris_and_refuses_a_fragment`,
  `discovery_advertises_the_end_session_endpoint`.
- **Every active deletion of an `oidc` grant sends its RP a back-channel logout token, through a
  durable outbox, and never blocks the request that deleted it** (OpenID Connect Back-Channel
  Logout 1.0). `drop_grant` queues the entry (client, `sub`, `sid`, grant id) in
  `outbox:backchannel_logout` in the same script as the deletion: RFC 7009 revocation of the
  refresh token, `/end_session`, a rotation refused for an epoch or for inactivity or absolute
  expiry (the script deletes the grant then), revocation of all of a user's grants
  (`logout/all`, deactivation, erasure), and a reuse event while `reuse_revokes_grant` is on. A grant whose key simply expires runs no script and
  sends nothing (nothing observes it, and the RP's refresh token expired with it); an epoch that
  only refuses an access token deletes nothing and sends nothing until a rotation deletes the
  grant. A `matrix_device` or `service` grant never sends one (Synapse is not an RP here), so
  discovery advertises `backchannel_logout_supported` / `_session_supported` in generic mode
  only. The worker (`backchannel::Worker`, one per instance) claims entries under a lease
  (atomic, so instances never deliver one twice at once), signs a fresh token per attempt (ES256
  with the live key and its `kid`, raw r||s, header `typ` `logout+jwt`; claims `iss`, `aud` =
  client id, `iat`, `exp` = `iat` + 120 s, a random `jti`, `sub` = the DID, `sid` when the grant
  has one, `events`; never a `nonce`) and POSTs `logout_token=…`; 200 and 204 are success,
  anything else is retried with exponential backoff, five attempts in all, then dropped with a
  `warn!` naming the client and the grant fingerprint, never the URI or the token. A client that
  requires a `sid` gets no token for a grant without one. D4 (provisional): with
  `backchannel_logout_required_for_refresh`, generic-mode registration refuses a client that may
  refresh without a `backchannel_logout_uri`. Pin:
  `every_active_deletion_of_an_oidc_grant_queues_one_logout_entry`,
  `the_outbox_leases_retries_and_completes_an_entry`,
  `drop_grant_names_the_outbox_the_worker_reads`,
  `with_enforcement_on_reuse_deletes_the_grant_and_never_the_device` (reuse),
  `the_logout_token_has_the_spec_header_claims_and_a_raw_signature`,
  `the_worker_delivers_retries_a_failing_rp_then_drops_it_with_a_warning`,
  `the_d4_switch_requires_a_backchannel_uri_from_a_client_that_may_refresh`,
  `discovery_advertises_backchannel_logout_only_in_generic_mode`; generic-mode server and stub RP:
  `revoking_a_refresh_token_sends_the_rp_a_verifiable_logout_token`,
  `end_session_sends_a_logout_token_for_the_grant_it_ends`,
  `a_failing_rp_is_retried_a_bounded_number_of_times_then_dropped`,
  `discovery_advertises_back_channel_logout_with_sessions`.
- **A `backchannel_logout_uri` passes the SSRF guard at registration and at every delivery**
  (`backchannel::UriGuard`; registration stays open, D3). No fragment; `https`; every address the
  host resolves to outside the refused classes of `backchannel::refused_class` (unspecified,
  loopback, RFC 1918 and RFC 4193 private, CGNAT, link-local including the cloud metadata
  address, multicast, reserved; IPv4 inside IPv6, mapped, compatible or NAT64, judged as IPv4).
  Delivery connects only to the addresses it checked (the HTTP client is pinned to them, so a
  second DNS answer cannot slip in), through no proxy, following no redirect, with timeouts of a
  few seconds, and ignores the response body. A refused URI is a 400 `invalid_client_metadata`
  at registration and client update, and at delivery the entry is dropped without a connection.
  Only a host on the operator's `backchannel_logout_allowed_hosts` skips the address check (and
  may use `http`); the fragment rule still applies. Pin:
  `the_address_classifier_refuses_every_internal_class`,
  `the_uri_guard_checks_scheme_fragment_and_every_resolved_address`,
  `delivery_connects_only_to_a_checked_or_listed_host_and_follows_no_redirect`,
  `delivery_connects_only_to_the_checked_address_never_a_second_resolution`,
  `delivery_uses_no_proxy_even_when_the_environment_names_one` (a child process of the test
  binary carries the proxy variables),
  `registration_stores_backchannel_logout_metadata_and_refuses_an_unsafe_uri`;
  generic-mode server and stub RP:
  `a_uri_on_a_refused_address_is_refused_at_registration_and_never_delivered_to`.
- **siwx-oidc's own sessions are digest-keyed and end with the user's sessions.** The
  `siwx_user` picker hint (`siwx_user/{digest}`, 30 days) and the `acct_session` account session
  (`acct_session/{digest}`, 600 s) are stored under the digest of the cookie value, and each is
  indexed under the digest of the canonical DID (`idx:own_sessions/{digest}`, a sorted set scored
  by expiry) in the same script that writes it. `logout/all`, deactivation and erasure end every
  own session of the DID through that index (`revoke_own_sessions`; a `did:pkh` address in any
  case is the same user); the account page's **Sign out** (`POST /account/sign_out`) ends only
  this browser's two sessions and clears both cookies. `/end_session` leaves the hint alone: it
  ends an RP's grant, and the hint authorizes nothing. The lookup reads the digest key and then
  the legacy key with two `GET`s, never one `MGET`, so a store fault is an error and not a miss.
  Enumeration safety is unchanged (see "Passkeys"). Pin:
  `own_sessions_are_keyed_by_the_digest_of_the_token`, `a_legacy_own_session_is_read_and_ended`,
  `revoking_own_sessions_ends_every_session_of_the_did_and_no_other`; mock stack:
  `no_own_session_the_client_holds_is_stored_in_the_clear`,
  `logout_all_ends_every_own_session_of_the_user`,
  `deactivation_ends_every_own_session_of_the_user`, `erasure_ends_every_own_session_of_the_user`,
  `account_sign_out_ends_this_browsers_account_session_and_picker_hint`.
- **A sign-out never reports success while revoking nothing.** `logout` and `logout/all` answer a
  token-store fault (reading the bearer, revoking the tokens, ending the own sessions) with the
  retryable 503 (`M_UNKNOWN`) of the refresh and device-deletion routes. A failed `logout`
  deletes nothing as a last resort: a deleted access token would turn the client's retry into a
  no-op while the device's refresh token lived on. For the same reason `logout/all` ends the
  own sessions FIRST, then the Synapse devices (best-effort), and revokes the grants, and with
  them the bearer, LAST: a fault ending the own sessions revokes no grant, so the retry with the
  same bearer runs the whole sign-out again. Residual: a fault in the grant sweep after it wrote
  the user epoch (a Redis script does not roll back) is a 503 whose retry is the 200 no-op; the
  own sessions are already ended and the epoch refuses every grant of the user, but grants the
  sweep did not reach stay stored until their TTL, and an OIDC one sends its back-channel logout
  token only when its RP next refreshes. RFC 7009 revocation keeps its best-effort fallback and
  its 200. The account page's sign-out answers a fault with 503 too (`oidc::store_unavailable`).
  Pin: `a_store_fault_during_logout_is_a_retryable_503_and_the_retry_tears_down`,
  `a_store_fault_during_logout_all_is_a_retryable_503`,
  `a_logout_all_retry_after_an_own_session_fault_ends_the_own_sessions_and_the_grants`.
- **`/oauth2/revoke` never deletes a device.** Only explicit sign-out (`logout`, MSC4191
  `device_delete`) does; `logout/all` never deactivates the account. Pin:
  `teardown_policy_only_deletes_device_on_explicit_signout`,
  `h1_revoke_does_not_delete_device_but_logout_does`,
  `logout_all_invalidates_all_sessions_without_deactivating`.
- **Revocation keys on the username** (the localpart: a grant's `username`, a legacy entry's
  `TokenMetadata.username`), not the raw DID.

### Passkeys ([docs/passkeys.md](docs/passkeys.md))

- **Enumeration safety.** The picker is scoped only by the opaque `siwx_user` token; a forged,
  guessed or expired token is a Redis miss and yields usernameless login with zero credential
  ids. Never accept a client-supplied DID or identifier as the scope. Pin:
  `forged_user_cookie_yields_usernameless_empty_allow_credentials`,
  `a_did_shaped_forged_user_cookie_yields_usernameless_empty_allow_credentials`,
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
  under `Debug` (`SuccessorPair`, `IssuedGrant`, `DeviceCodeEntry`). Pin:
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
| [inblockio/aqua-auth](https://github.com/inblockio/aqua-auth) (crate `aqua-auth`) | Layer 1: `DIDMethod`/`CipherSuite`, CAIP-122 verification, WebAuthn assertion verification, credential store. Pinned by tag in both `Cargo.toml` files; bump both together. |
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
