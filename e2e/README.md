# Account-management E2E harness

End-to-end tests proving the MSC4191 `/account` flows (device/session deletion +
account erasure) work **in a real headless browser** with a **single** re-auth,
for both **Ethereum wallet** and **passkey**.

Everything runs in podman (the host sandbox reaps host processes that bind a
listening socket, so all listeners are containerised). `ubuntu:rolling` matches
the host glibc, so the natively-built debug binary runs as-is.

## One-shot

```bash
bash e2e/run-all.sh
```

Brings the stack up and runs: unit tests → HTTP-level Rust E2E → legacy CS-API
probe → headless browser E2E (wallet + passkey).

## Pieces

| File | What |
|------|------|
| `up.sh` / `down.sh` | Start/stop Redis + Synapse mock + siwx-oidc (podman) |
| `synapse_mock.py` | Faithful in-memory mock of the Synapse endpoints siwx-oidc calls — both credential surfaces (see below) — with `/__seed_user`, `/__seed_device`, `/__profile`, `/__state`, `/__set_secret`, `/__reject_admin_token`, `/__fail`, `/__reset` test hooks |
| `../tests/e2e_race_teardown.rs` | The race/teardown hazard register (H1..H14), the grandfathered-localpart invariant, and the attested-DID sign-in path. Run: `cargo test --test e2e_race_teardown -- --ignored --test-threads=1` |
| `../tests/e2e_account_management.rs` | Drives the exact HTTP requests the page JS makes — real EIP-191 wallet signatures, the account-session cookie, `/account/action`. Run: `cargo test --test e2e_account_management -- --ignored --test-threads=1` |
| `../tests/e2e_client_lifetime.rs` | Static clients carry no TTL and still authorize; a dynamic client's next use restores its 30-day lifetime. Needs the static client `e2estatic` that `env.sh` and the CI job configure. Run: `cargo test --test e2e_client_lifetime -- --ignored --test-threads=1` |
| `../tests/e2e_generic_client.rs` | A generic-class client (the kind a mail client is) against the Matrix-mode server, signed in through the headless client's `authenticate_with_scope_using`: the mailbox claim, no `email`, no Matrix scope or device, introspection inactive, the Matrix routes refusing its tokens, the `invalid_token` challenge, and nothing the client holds stored in the clear in the stack's Redis (the search of the I1 scans below, for this client's session, code, verifier, tokens and secret; it reads `E2E_REDIS_URL` like them and skips loudly without one). Needs the static client `maile2e` and `SIWXOIDC_MAIL_DOMAIN`, which `env.sh` and the CI job set on the Matrix-mode server only (see "Back-channel logout" for why). Run: `cargo test --test e2e_generic_client -- --ignored --test-threads=1` |
| `../tests/e2e_backchannel_logout.rs` | H7, OpenID Connect Back-Channel Logout against a **generic-mode** siwx-oidc and the stub RP below. Run (see "Back-channel logout" below): `SIWX_GENERIC_HOST=… E2E_GENERIC_REDIS_URL=… cargo test --test e2e_backchannel_logout -- --ignored --test-threads=1` |
| `legacy-cs-api-probe.sh` | `DELETE /_matrix/client/v3/devices/{id}` + `/delete_devices` with Redis-seeded bearers: a grant's access token and a legacy `token/{raw}` access entry (`REDIS_CONTAINER` names the Redis container) |
| `browser/account.spec.mjs` | Playwright: mock `window.ethereum` (real ethers signing) + CDP WebAuthn virtual authenticator, driving the real `/account` DOM. Run: `bash browser/run.sh` |

## Stack endpoints

- siwx-oidc: `$SIWEOIDC_BASE_URL` (default http://localhost:18080)
- Synapse mock: http://localhost:8090 (MAS surface: Bearer `testsecret`)
- Redis: 127.0.0.1:6379 (podman)

Every port is overridable through `env.sh` (`SIWEOIDC_PORT`, `SYNAPSE_MOCK_PORT`,
`SIWEOIDC_REDIS_PORT`), which matters on a machine already running the
e2e-harness stack — it holds 18080/18081/18448, and a stray redis often holds
6379. The Rust suites read `SIWEOIDC_HOST` and `SYNAPSE_MOCK`, so point those at
whatever ports you brought the stack up on. `e2e_race_teardown` also searches
the stack's Redis for tokens stored in the clear
(`no_token_the_client_holds_is_stored_in_the_clear`) and for codes, device and
user codes, session and ceremony ids and nonces stored in the clear
(`no_code_or_session_the_client_holds_is_stored_in_the_clear`) and for client secrets and
registration access tokens stored in the clear
(`no_client_secret_or_registration_token_is_stored_in_the_clear`); they read `E2E_REDIS_URL`,
else `SIWXOIDC_REDIS_URL`, `SIWEOIDC_REDIS_URL` (set by `env.sh`) or
`REDIS_HOST`/`REDIS_PORT`, and skips loudly without one (a failure under
`E2E_STRICT_SKIPS=1`):

```bash
SIWEOIDC_PORT=18191 SYNAPSE_MOCK_PORT=18190 SIWEOIDC_REDIS_PORT=16379 \
  SIWEOIDC_SYNAPSE_ENDPOINT=http://localhost:18190 bash e2e/up.sh
SIWEOIDC_HOST=http://localhost:18191 SYNAPSE_MOCK=http://localhost:18190 \
  E2E_REDIS_URL=redis://localhost:16379 \
  cargo test --test e2e_race_teardown -- --ignored --test-threads=1
SIWEOIDC_HOST=http://localhost:18191 SYNAPSE_MOCK=http://localhost:18190 \
  cargo test --test e2e_account_management -- --ignored --test-threads=1
```

`legacy_tokens_keep_working_after_the_upgrade` (same suite, same Redis URL)
writes the token layout of builds before the grant record itself and checks that
the server lifts it. For a real upgrade, run it in two stages around a binary
swap that keeps Redis: `E2E_R1_STAGE=mint E2E_R1_SESSIONS=<file>` against the
previous build (it signs in and asserts the legacy layout was written), then
`E2E_R1_STAGE=check E2E_R1_SESSIONS=<file>` against the new build within 300 s,
while the legacy access tokens are still live.

`in_flight_codes_and_sessions_survive_the_upgrade` does the same for an issued
code, a started login session, an approved and a pending device code: it
rewrites what the server stored into the raw-keyed layout of builds before
digest keys and checks each completes once. For a real upgrade:
`E2E_R2_STAGE=mint E2E_R2_FILE=<file>` against the previous build, then
`E2E_R2_STAGE=check E2E_R2_FILE=<file>` against the new build within 300 s,
keeping Redis and the mock.

## Back-channel logout: the stub relying party

`synapse_mock.py` also carries a stub OpenID Connect relying party under
`/__rp/{name}/…`. It is new test surface, not part of the Synapse mirror below,
and siwx-oidc never calls it unless a test registers it:

| Route | What |
|------|------|
| `POST /__rp/{name}/backchannel_logout` | records the request (content type and raw body) and answers 200, or 500 / a 303 per the mode |
| `POST /__rp/{name}/mode` | `{"mode": "ok" \| "500" \| "redirect"}` |
| `GET /__rp/{name}/received` | `{"received": [{"content_type", "body"}], "redirected": n}` |
| `ANY /__rp/{name}/redirected` | the 303 target; counts a followed redirect (siwx-oidc follows none) |

Any name works; `/__reset` clears every RP. Back-channel logout tokens are sent
only for `oidc` grants, which only a generic-mode server issues, so the suite
needs a second siwx-oidc next to the stack: no MAS shared secret, no Synapse
endpoint or server name, its own port and Redis database, and `localhost` in
`SIWXOIDC_BACKCHANNEL_LOGOUT_ALLOWED_HOSTS` so it may deliver to the stub on
loopback (the SSRF guard refuses loopback otherwise). It also starts without the
mail client `maile2e` and the mail domain that `env.sh` exports for the first
server: a generic-class client needs a Synapse, so a generic-mode server refuses
to start with one. CI starts it on :18081 with Redis database 1:

```bash
env -u SIWXOIDC_MAS_SHARED_SECRET -u SIWXOIDC_SYNAPSE_ENDPOINT -u SIWXOIDC_MATRIX_SERVER_NAME \
  -u SIWXOIDC_MAIL_DOMAIN -u SIWXOIDC_DEFAULT_CLIENTS__MAILE2E \
  SIWXOIDC_PORT=18081 SIWXOIDC_BASE_URL=http://localhost:18081 \
  SIWXOIDC_REDIS_URL=redis://localhost:6379/1 \
  SIWXOIDC_BACKCHANNEL_LOGOUT_ALLOWED_HOSTS='["localhost"]' ./target/debug/siwx-oidc &
SIWX_GENERIC_HOST=http://localhost:18081 SYNAPSE_MOCK=http://localhost:8090 \
  E2E_GENERIC_REDIS_URL=redis://localhost:6379/1 \
  cargo test --test e2e_backchannel_logout -- --ignored --test-threads=1
```

`E2E_GENERIC_REDIS_URL` lets one test store a client whose URI registration
refuses, to prove delivery checks again; without it that part skips, and fails
under `E2E_STRICT_SKIPS=1` (absent means strict). The retry test waits for all
five attempts (about 35 s).

## The mock MUST be updated whenever `synapse_client.rs` moves an endpoint

`synapse_mock.py` is a hand-maintained MIRROR of the route list in
`src/synapse_client.rs`. Nothing links the two, so the mock drifts **silently**:
when a call moves, the mock keeps answering 404/401 and the suites above go red
for a reason that has nothing to do with the product. That is not hypothetical —
it is exactly what happened between commit `db79e75` and the 2026-09-10 audit
(finding D12). Two structural changes landed:

1. the **Synapse 1.157 port**, which deleted the `admin_token` shim and moved
   `delete_device` / `deactivate_user` / `reactivate_user` onto `/_synapse/mas/*`
   while putting `list_devices` behind a **minted admin-scoped token**; and
2. the **attested DID profile field**, which added
   `PUT /_matrix/client/v3/profile/{mxid}/io.inblock.did` and
   `GET /_matrix/client/v3/profile/{mxid}`.

Because both suites are `#[ignore]`d — outside `cargo test --workspace` **and**
outside the e2e-harness check list — nothing executed them across either change,
so the drift was invisible until someone ran them by hand. A mock that drifts is
worse than no mock: it produces confident green.

**One-line drift check** (prints nothing when the mock is in sync):

```bash
grep -oE '"\{\}/[^"]*"' src/synapse_client.rs | tr -d '"' | sed 's/^{}//' \
  | cut -d'?' -f1 | sed 's#/{}.*##' | sort -u \
  | while read -r r; do grep -q -- "$r" e2e/synapse_mock.py \
      || echo "MISSING FROM MOCK: $r"; done
```

Run it after touching `synapse_client.rs`. Against the pre-D12 mock it prints the
five routes that were missing, which is how it was validated. It is a **route**
check only — it cannot see a changed HTTP verb, body shape or credential, so a
green check still means "run the two suites".

## Two credential surfaces (since Synapse 1.157)

The mock models both, because a mock with one credential cannot catch the bug
class the split introduced:

| Surface | Credential | How the mock checks it |
|---|---|---|
| `/_synapse/mas/*` | MAS shared secret | exact string equality, as Synapse does |
| `/_synapse/admin/*` + authenticated C-S API | minted `msa_` admin token | **real introspection** at `$SYNAPSE_MOCK_OIDC_BASE/oauth2/introspect`, then Synapse's own two-step check: the C-S API scope first (401), then `"urn:synapse:admin:*" in scope` (403) |
| unauthenticated C-S API (`GET` profile) | none | matches `require_auth_for_profile_requests: false` |

Introspecting for real is what makes an authorization regression fail here rather
than in production: dropping either half of `admin_token::ADMIN_SCOPE` turns
`wallet_single_reauth_covers_list_delete_profile` red. Sniffing the `msa_` prefix
instead would authorise everything and hide exactly that. `SYNAPSE_MOCK_OIDC_BASE`
has **no default** for the same reason — unset, the admin surface refuses rather
than rubber-stamps.

## What it proves

- One wallet signature (or one passkey ceremony) covers a whole account session:
  list sessions → sign a device out → view profile, with no further prompt.
- Device sign-out deletes the Synapse device and revokes its tokens.
- Account erasure runs `deactivate(erase=true)` and clears the session, and a
  later reactivation is refused before Synapse is asked (the mock, like Synapse
  1.161, would reactivate an erased account). A plain deactivation stays
  reversible.
- The legacy in-client session-manager delete endpoints work.
- An admin-token rejection fails legibly (400 naming the admin token), never a
  misleading "device not found" or a 500.

## The headless client against a live deployment

`siwx-oidc-auth/tests/live_deployment.rs` is one `#[ignore]`d test that drives the
`siwx-oidc-auth` library against a real deployment (siwx-oidc in Matrix mode and its
homeserver), not the mock stack. With a freshly generated key it registers a public client,
signs in with a proposed device, uses the access token at `whoami`, rotates the refresh token,
replays the previous one before and after the successor's first use (same pair, then
refused), verifies the published DID binding, and deactivates the account it created. Each
run creates one throwaway account; the deactivation runs even when a check failed.

```bash
SIWX_SERVER=https://siwx.example.org SIWX_HOMESERVER=https://matrix.example.org \
  cargo test -p siwx-oidc-auth --test live_deployment -- --ignored --nocapture
```

The targets come only from these two variables; a missing one fails the test unless
`E2E_STRICT_SKIPS=0`. Every check prints `ok` or `FAILED`, so a run against an older server
names each property it lacks.
