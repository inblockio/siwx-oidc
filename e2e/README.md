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
| `../tests/e2e_backchannel_logout.rs` | H7, OpenID Connect Back-Channel Logout against a **generic-mode** siwx-oidc and the stub RP below. Run (see "Back-channel logout" below): `SIWX_GENERIC_HOST=… E2E_GENERIC_REDIS_URL=… cargo test --test e2e_backchannel_logout -- --ignored --test-threads=1` |
| `upgrade-from.sh` | Mock upgrade from a previous image to this tree's build, Redis kept: see "Upgrade qualification" below |
| `element/upgrade-survival.sh` | Element Web upgrade continuity (T2) on the pinned lab: capture on the baseline image, switch only siwx-oidc, assert in the same browser profile: see "Upgrade qualification" below |
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
loopback (the SSRF guard refuses loopback otherwise). CI starts it on :18081
with Redis database 1:

```bash
env -u SIWXOIDC_MAS_SHARED_SECRET -u SIWXOIDC_SYNAPSE_ENDPOINT -u SIWXOIDC_MATRIX_SERVER_NAME \
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

## Upgrade qualification

Four suites prove that what a deployment holds survives a switch of the siwx-oidc build. They
run before a promotion, not in CI. Each creates throwaway accounts and deactivates them.

### Mock upgrade from an image (`upgrade-from.sh`)

```bash
bash e2e/upgrade-from.sh registry.example.org/siwx-oidc@sha256:<digest-of-the-old-build> [<new>]
```

`<new>` is a siwx-oidc binary (run in `ubuntu:rolling`, like `up.sh`) or an image; the default
builds this tree. The script starts a private stack on its own ports (siwx-oidc :18391, mock
:18390, Redis :16390; `UPGRADE_*_PORT` overrides them) with the OLD image, runs the mint stages,
replaces only siwx-oidc with the NEW build (same Redis, same mock, same configuration), runs the
check stages and tears the stack down. The stages, all from this tree:

| Stage | Suite |
|---|---|
| R1 | `e2e_race_teardown::legacy_tokens_keep_working_after_the_upgrade` (`E2E_R1_STAGE`) |
| R2 | `e2e_race_teardown::in_flight_codes_and_sessions_survive_the_upgrade` (`E2E_R2_STAGE`); a login session the old build started without a bound request must be refused with "restart the sign-in" |
| T1 | `siwx-oidc-auth/tests/live_upgrade.rs` (below) with the mock as the homeserver |
| T4 | `siwx-oidc-auth/examples/soak.rs` (below), only with `UPGRADE_SOAK_SECS` (480 or more to see every session switch format): started on the old build and held across the switch, which then leaves siwx-oidc down for `UPGRADE_SWAP_GAP_SECS` (default 20) |

The evidence (one log per stage, Redis key prefixes before and after, both servers' logs, a
summary naming the old image's revision label and the new build's revision) goes to
`UPGRADE_RUN_DIR`, by default `~/.cache/siwx-oidc-upgrade-from/<time>`, mode 0700: it holds this
throwaway stack's test credentials. The exit status is 0 only when every stage passed. As a
negative control, run it with the old image as `<new>` too: the R1 and T1 checks must fail.

For T1, the mock answers `GET /_matrix/client/v3/sync` with an empty sync and forwards
`POST /_matrix/client/v3/refresh` and `DELETE /_matrix/client/v3/devices/{id}` to siwx-oidc,
as a deployment's edge does (Synapse does not serve either under delegated authentication).

### Live upgrade continuity (`live_upgrade.rs`)

Run against a deployment around its switch, in three stages:

```bash
export SIWX_SERVER=https://siwx.example.org SIWX_HOMESERVER=https://matrix.example.org
export QUALIFY_STATE_DIR=$HOME/.cache/qualify/live-upgrade
QUALIFY_STAGE=mint    cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture mint_
# switch siwx-oidc, keeping its Redis; then, within 300 s for the access-token check:
QUALIFY_STAGE=check   cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture check_
QUALIFY_STAGE=cleanup cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture cleanup_
```

`mint` signs in one throwaway account per shape a deployment holds: an agent device
(`AQUA_…`); the same with its client registration deleted (RFC 7592, as an expired one); an
Element X device id (43 characters with `/` and `+`); a session for
`POST /_matrix/client/v3/refresh` on the homeserver; an access token kept unused; an account
with two devices for `DELETE /_matrix/client/v3/devices/{id}`; and, last, a session rotated just
before the switch whose previous refresh token is kept. `check` runs one test per check, each on
its own session: every refresh token refreshes into the current format `mcr_{handle}_{secret}`
and whoami names the same account and device; the unused access token is still accepted (a
skip, and a failure under `E2E_STRICT_SKIPS`, once its 300 s have passed); the device deletion
removes the device from the homeserver's list and refuses its refresh token; the previous
refresh token of the session rotated before a switch from a build before the grant record is
refused and the client signs in again to the same account and device (after a mint on a
current build it is a lost response and gets the same pair back). Each check deactivates its
account, also when it failed. `cleanup` deactivates whatever a check did not, verifies that
every account refuses a new sign-in, and removes the state.

`QUALIFY_STATE_DIR` holds keys and refresh tokens: `mint` creates it with mode 0700, every
stage refuses one that others may read, and the state file is 0600. The targets must be the
same at every stage. A test run in another stage than its own, a missing target or state, and
a skip all fail unless `E2E_STRICT_SKIPS=0`. `DELETE /_matrix/client/v3/devices/{id}` goes to
`SIWX_DEVICE_DELETE_BASE`, by default the homeserver: the edge must route it to siwx-oidc
(Synapse answers `404 M_UNRECOGNIZED` under delegated authentication). On a deployment whose
edge does not, set it to the siwx-oidc URL; the check then proves siwx-oidc's handling only.

### Element Web upgrade continuity (`element/upgrade-survival.sh`)

What a person in Element Web notices across the switch, on the lab stack of
siwx-oidc-matrix-server pinned by image digest (`docker-compose.local.yml` plus
`docker-compose.qualify.yml`, see that repository's README):

```bash
# the lab, every image by digest (the overlay refuses to start without them)
export REDIS_IMAGE_REF=redis:<version>@sha256:<digest>
export SYNAPSE_IMAGE_REF=registry.example.org/synapse@sha256:<digest>
export ELEMENT_IMAGE_REF=registry.example.org/element-web@sha256:<digest>
export BASELINE_IMAGE=registry.example.org/siwx-oidc@sha256:<the deployed build>
export CANDIDATE_IMAGE=registry.example.org/siwx-oidc@sha256:<the build to promote>
export LAB_COMPOSE_DIR=<siwx-oidc-matrix-server checkout> LAB_PROJECT=<compose project> LAB_ENV_FILE=.env.qualify
(cd "$LAB_COMPOSE_DIR" && SIWX_OIDC_IMAGE_REF=$BASELINE_IMAGE docker compose -p "$LAB_PROJECT" \
  -f docker-compose.local.yml -f docker-compose.qualify.yml --env-file "$LAB_ENV_FILE" up -d)

export ELEMENT_URL=http://localhost:28088 MATRIX_URL=http://localhost:28080 SIWX_URL=http://localhost:28081
export QUALIFY_STATE_DIR=$HOME/.cache/qualify/<run-id>/t2      # fresh, mode 0700
export CTRF_OUTPUT=$HOME/.cache/qualify/<run-id>/t2/ctrf/playwright-ctrf.json
bash e2e/element/upgrade-survival.sh                 # QUALIFY_STAGE=mint|switch|check, default all three
```

`mint` checks that the lab's siwx-oidc runs `BASELINE_IMAGE` (by image id, the container
resolved by compose service) and runs `ew-upgrade-capture.spec.mjs` in a persistent Chromium
profile (`launchPersistentContext`, so Element's session and its IndexedDB crypto store live on
disk like a user's): user A signs in with a wallet through Element and sets the recovery key
(cross-signing, secret storage, key backup); user B signs in in a second browser; A creates an
encrypted room, B joins, each sends a message and decrypts the other's; a second device of A is
signed in headlessly; a passkey account is registered in A's browser (a CDP virtual
authenticator, whose credential is exported to the state, since it dies with the browser); and
Spotlight resolves B's DID to B's MXID. `switch` runs
`SIWX_OIDC_IMAGE_REF=$CANDIDATE_IMAGE docker compose … up -d --no-deps siwx-oidc`, waits for
health, checks the candidate runs, and that every other service kept its `StartedAt`.
`check` reopens the profile on the candidate (`ew-upgrade-assert.spec.mjs`), one test per check:

| Test | Passes when |
|---|---|
| EW-UA1 | Element opens signed in: no login screen, no trip to the provider |
| EW-UA2 | same account and device id; the candidate's own `/userinfo` accepts the token Element holds (Synapse caches introspection for two minutes, so a whoami alone could pass on a forgotten token) |
| EW-UA3 | no "verify this session" or recovery-key prompt; cross-signing, secret storage, key backup and this device's verification are what they were |
| EW-UA4 | both messages from before the switch decrypt and show in the timeline |
| EW-UA5 | a message typed into the composer reaches the homeserver, encrypted |
| EW-UA6 | Spotlight still turns B's DID into B's MXID |
| EW-UA7 | the passkey from the baseline signs in to the same account, and the picker is scoped by the hint cookie the baseline set |
| EW-UA8 | the Sessions manager signs out the second device (Element hands it to the provider's account page under delegated authentication: wallet re-auth, "Sign out this session"); the device leaves the homeserver and its refresh token, issued by the baseline, is refused |
| EW-UA9 | a second tab takes the session over and the first gets it back, still accepted by the candidate, with no sign-out call |
| EW-UA10 | Element refreshed its token at the candidate within `T2_REFRESH_WAIT_S` (default 420 s): every refresh answered 200, the first one with a current-format refresh token |
| EW-UZ | cleanup: A, B and the passkey account are deactivated |

The targets come only from `ELEMENT_URL`, `MATRIX_URL` and `SIWX_URL`; the image references must
be digests. `QUALIFY_STATE_DIR` holds the browser profile, the throwaway accounts' wallet keys,
a refresh token and the passkey (files 0600); `mint` refuses a directory that already holds a
profile, and `check` refuses state older than `T2_MAX_STATE_AGE_S` (default 3600). Each phase
writes a CTRF report (`playwright-ctrf-json-reporter`) next to `CTRF_OUTPUT`, and the driver
merges them with its own steps into `CTRF_OUTPUT`. When the qualification driver switches the
image itself, run `QUALIFY_STAGE=mint`, switch, then `QUALIFY_STAGE=check`; without
`LAB_PROJECT` the image checks are reported as skipped and left to the caller.

Negative control: `T2_NEGATIVE=flush-redis` flushes the lab's Redis between the switch and the
check, and the check must fail. It does: EW-UA2, EW-UA7, EW-UA9, EW-UA10 and EW-UZ fail; the
checks that only read Element's own storage, Synapse or the account page (EW-UA1, UA3 to UA6,
UA8) pass inside Synapse's two-minute introspection cache, which is why EW-UA2 asks the
provider itself.

`T2_DIRECTION=rollback` runs the same three stages from the candidate to the baseline (the
rollback drill): `mint` expects the candidate, `switch` installs the baseline, `check` expects
the baseline. The default is `upgrade`.

#### The Element Web swap (T2-EW, `T2_SWAP=element-web`)

The same driver replaces ONLY the element-web image, with Redis, siwx-oidc, Synapse and the edge
kept, which is what a promotion of Element Web does. The two images come from
`ELEMENT_BASELINE_IMAGE` and `ELEMENT_CANDIDATE_IMAGE` (digests), the switch sets
`ELEMENT_IMAGE_REF`, and the lab needs `SIWX_OIDC_IMAGE_REF` in its place:

```bash
export T2_SWAP=element-web                                  # T2_DIRECTION=rollback for candidate -> baseline
export ELEMENT_BASELINE_IMAGE=registry.example.org/element-web@sha256:<the deployed build>
export ELEMENT_CANDIDATE_IMAGE=registry.example.org/element-web@sha256:<the build to promote>
export REDIS_IMAGE_REF=... SYNAPSE_IMAGE_REF=... SIWX_OIDC_IMAGE_REF=...   # what the lab runs, digests
export LAB_COMPOSE_DIR=... LAB_PROJECT=... LAB_ENV_FILE=.env.qualify
export ELEMENT_URL=... MATRIX_URL=... SIWX_URL=... QUALIFY_STATE_DIR=... CTRF_OUTPUT=...
bash e2e/element/upgrade-survival.sh                        # QUALIFY_STAGE=mint|switch|check as above
```

What carries state across an Element switch is the browser: the session, the crypto store and
the encrypted search index of siwx-oidc-matrix-server `patches/element-web` entry 6 (IndexedDB
database `element-eventindex`). `mint` runs `ew-upgrade-ew-capture.spec.mjs` in a persistent
profile: user A signs in with a wallet and sets the recovery key (EW-EC1); in an encrypted room
three messages with unique tokens are sent, one is then edited (a real `m.replace`) and one
redacted, and the index must find the kept one, the edited one by its new text and not the
redacted one (EW-EC2); a sentinel event with its own token is fed to the index manager directly
and never sent to the homeserver (EW-EC3); then the index is flushed and its fingerprint is
recorded: a SHA-256 fingerprint of the per-index salt in its `meta` row (random, created with the
index, kept until the index is deleted), the chunk and checkpoint record counts, and the
manager's own stats (EW-EC4). Nothing is read as content. `check` runs
`ew-upgrade-ew-assert.spec.mjs` on the other build:

| Test | Passes when |
|---|---|
| EW-EA1 | Element opens signed in: no login screen, no trip to the provider |
| EW-EA2 | same account and device id |
| EW-EA3 | the index was NOT reset: same salt fingerprint, chunk records present, the sentinel found within 15 s (no crawl can bring it back), and the hydrated index holds at least as many events as before |
| EW-EA4 | the kept and the edited message are found within 15 s (time to the first hit recorded) |
| EW-EA5 | the edited message is found by its new text under its original event id, and not by its pre-edit text |
| EW-EA6 | the redacted message is not found (no hit, count 0) |
| EW-EA7 | a message sent from the composer after the switch is indexed and found |
| EW-EZ | cleanup: A is deactivated |

EA4 to EA6 cannot tell a surviving index from a rebuilt one, since the crawler refills a small
room in seconds; EA3 can. Negative control: `T2_NEGATIVE=drop-eventindex` makes the check delete
the profile's `element-eventindex` database (from Element's static `config.json`, so no Element
code runs) before it opens Element; EW-EA3 must then fail.

### Population soak (`examples/soak.rs`)

```bash
SIWX_SERVER=https://siwx.example.org SIWX_HOMESERVER=https://matrix.example.org \
  cargo run -p siwx-oidc-auth --example soak -- --sessions 25 --duration 1800
```

Holds N throwaway sessions (every third on an Element X shaped device), refreshes each at its
access token's expiry, and calls whoami and `GET /_matrix/client/v3/sync?timeout=0` once a
minute per session. One JSON line per minute on stdout (refreshes ok and refused by reason,
401s, device changes, unavailable requests, sessions in the current format), then a final
line. It exits 1 on any refused refresh, any 401, any change of account or device, any session
unavailable for more than 120 s in a row, or any session still in the previous format 330 s after
the first refresh into the current one; connection errors and 502/503/504 are retried and
counted, not failures, within those 120 s. Every account is deactivated at the end, also on
SIGINT or SIGTERM (exit 3: interrupted, not a pass).
