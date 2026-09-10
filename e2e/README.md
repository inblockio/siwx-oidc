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
| `legacy-cs-api-probe.sh` | `DELETE /_matrix/client/v3/devices/{id}` + `/delete_devices` with a Redis-seeded bearer |
| `browser/account.spec.mjs` | Playwright: mock `window.ethereum` (real ethers signing) + CDP WebAuthn virtual authenticator, driving the real `/account` DOM. Run: `bash browser/run.sh` |

## Stack endpoints

- siwx-oidc: `$SIWEOIDC_BASE_URL` (default http://localhost:18080)
- Synapse mock: http://localhost:8090 (MAS surface: Bearer `testsecret`)
- Redis: 127.0.0.1:6379 (podman)

Every port is overridable through `env.sh` (`SIWEOIDC_PORT`, `SYNAPSE_MOCK_PORT`,
`SIWEOIDC_REDIS_PORT`), which matters on a machine already running the
e2e-harness stack — it holds 18080/18081/18448, and a stray redis often holds
6379. The Rust suites read `SIWEOIDC_HOST` and `SYNAPSE_MOCK`, so point those at
whatever ports you brought the stack up on:

```bash
SIWEOIDC_PORT=18191 SYNAPSE_MOCK_PORT=18190 SIWEOIDC_REDIS_PORT=16379 \
  SIWEOIDC_SYNAPSE_ENDPOINT=http://localhost:18190 bash e2e/up.sh
SIWEOIDC_HOST=http://localhost:18191 SYNAPSE_MOCK=http://localhost:18190 \
  cargo test --test e2e_race_teardown -- --ignored --test-threads=1
SIWEOIDC_HOST=http://localhost:18191 SYNAPSE_MOCK=http://localhost:18190 \
  cargo test --test e2e_account_management -- --ignored --test-threads=1
```

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
grep -oE '"\{\}[^"]*"' src/synapse_client.rs | tr -d '"' | sed 's/^{}//' \
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
- Account erasure runs `deactivate(erase=true)` and clears the session.
- The legacy in-client session-manager delete endpoints work.
- An admin-token rejection fails legibly (400 naming the admin token), never a
  misleading "device not found" or a 500.
