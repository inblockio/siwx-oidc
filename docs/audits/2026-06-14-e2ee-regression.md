# siwx-oidc — REAL End-to-End-ENCRYPTED two-participant Matrix messaging regression

**Date:** 2026-06-15
**Tool:** the connector at `~/aqua-matrix-agent` (matrix-sdk 0.17, e2e-encryption; auth via siwx-oidc).
**Stack:** LOCAL real stack — `siwx-real-oidc` (http://localhost:8081) + `siwx-real-synapse`
(http://localhost:8448, server_name `localhost`) + a **prod-mirroring Caddy edge**
`siwx-real-caddy` (http://localhost:8450), MSC3861 delegated auth. NOT prod.

## Verdicts

| Req | What it proves | Verdict |
|-----|----------------|---------|
| **R-K1** | Two distinct DIDs log in via local siwx-oidc, get provisioned on local Synapse, share an **encrypted** room (`m.room.encryption` set), each sends, the other **DECRYPTS** — both directions, plaintext asserted equal. | **PASS** |
| **R-K2** | After the exchange, ONE participant's device is signed out via **matrix-sdk's NATIVE `logout()`** (the deployed in-client "Sign out this session" path) routed through the **edge** to siwx-oidc; the OTHER still decrypts history, the room stays encrypted, and its own crypto is undamaged. | **PASS** |

Both verified by RUNNING against the live local stack + edge, with independent
server-side (Synapse admin API) corroboration that the bytes on the wire are
ciphertext and that the signed-out device was really deleted.

The R-K2 device sign-out now exercises the **real client → edge → siwx-oidc**
path (no workaround). See "The edge route" below for why the edge is required.

---

## The edge route (why it exists, what it routes) — load-bearing

### The problem: native CS-API logout 404s under MSC3861

matrix-sdk's `client.matrix_auth().logout()` POSTs the **homeserver's** native
Client-Server API logout, `POST /_matrix/client/v3/logout`. Under MSC3861
delegated-auth mode **Synapse disables its native CS-API logout / device-management
endpoints** and answers `404 "Unrecognized request"`. Those endpoints are **owned by
siwx-oidc** (`src/compat.rs` + the route table in `src/axum_lib.rs`):

| Method + path | siwx-oidc handler | Effect |
|---|---|---|
| `GET  /_matrix/client/v3/login` | `compat::login_flows` | advertise `m.login.sso` (Sign in with Wallet) |
| `POST /_matrix/client/v3/logout` | `compat::logout` | `TeardownPolicy::DeleteDevice` — delete the bearer's Synapse device + revoke its tokens |
| `POST /_matrix/client/v3/logout/all` | `compat::logout_all` | list + delete ALL the user's devices, revoke ALL tokens (session invalidation, not deactivation) |
| `DELETE /_matrix/client/v3/devices/{id}` | `compat::delete_device` | legacy in-client single-device sign-out |
| `POST /_matrix/client/v3/delete_devices` | `compat::delete_devices` | legacy in-client bulk device sign-out |
| `POST /_matrix/client/v3/refresh` | `compat::refresh` | token refresh |

(Contrast: `POST /oauth2/revoke` is `TeardownPolicy::TokensOnly` — token hygiene,
never deletes the device. The `/account?action=org.matrix.device_delete` MSC4191
action is the other explicit-intent delete path.)

### The fix: a prod-mirroring edge

PROD solves this with a Caddy method-route on `matrix.inblock.io` that forwards
exactly those paths to siwx-oidc (source of truth:
`~/siwx-oidc-matrix-server/Caddyfile.production`, which routes `login`/`logout`/
`refresh`; the deployed account-management edge route also forwards the legacy
device-management paths that siwx-oidc registers). The bare local real stack had
**no edge**, so a native `logout()` 404'd and the earlier draft of this regression
signed B out by POSTing **siwx-oidc directly** at `:8081`.

This regression now stands up a **local edge that mirrors prod**:

- Container `siwx-real-caddy` (image `caddy:2-alpine`) on the `siwx-real-net`
  podman network, published at **`127.0.0.1:8450`**.
- Caddyfile persisted in-repo at **`e2e/real-stack/Caddyfile`**; bring-up script
  **`e2e/real-stack-edge.sh`**.
- Routes the six siwx-oidc-owned paths above → `siwx-real-oidc:8081`; routes ALL
  other `/_matrix/*` + `/.well-known/*` (sync, rooms, keys, whoami, auth_metadata,
  …) → `siwx-real-synapse:8008` (Synapse's INTERNAL podman port). SEC-0003 parity:
  `/_synapse/admin/*` and `/_synapse/mas/*` are denied (404) at the edge.

The connector then points its Matrix homeserver at the **edge** (`:8450`, not
Synapse `:8448`), so the native `logout()` lands on siwx-oidc through exactly the
client → edge → siwx-oidc path the deployed Element device sign-out takes.

### Before / after (HTTP-level proof, `e2e/real-stack-edge.sh verify`)

```
== direct to Synapse (127.0.0.1:8448) — MSC3861 disables native logout ==
POST /_matrix/client/v3/logout -> HTTP 404
== through the edge (127.0.0.1:8450) — reaches siwx-oidc compat::logout ==
POST /_matrix/client/v3/logout -> HTTP 200
== login-flows discovery through the edge ==
GET  /_matrix/client/v3/login  -> HTTP 200
```

Non-owned paths still reach Synapse through the edge (sanity):
`GET /_matrix/client/versions → 200`, `GET /_matrix/client/v3/account/whoami → 401`
(no token, from Synapse), `GET /_matrix/client/v1/auth_metadata → 200` (MSC2965).

---

## How it works (connector internals studied first)

- **Login (headless, what key/DID):** `AgentClient::connect(AgentConfig)` loads an Ed25519
  PEM, derives a `did:key:z6Mk…`, runs the CAIP-122 sign-in against siwx-oidc
  (`siwx_oidc_auth::authenticate_with_device`), and pins a **stable** Synapse `device_id`
  derived from the DID (`AQUA_<sha256(did)[..12]>`). siwx-oidc provisions the Synapse user
  + device via MSC3861; Synapse introspects the opaque token. Crypto state persists in a
  per-identity SQLite store; cross-signing is bootstrapped on first connect.
- **Encrypted room:** `send_dm` → `ensure_dm_room` → matrix-sdk `Client::create_dm`, which
  (with the `e2e-encryption` feature on) seeds the room with
  `RoomEncryptionEventContent::with_recommended_defaults()` = **`m.megolm.v1.aes-sha2`**.
  So every DM room the connector makes is E2EE by construction.
- **Decryption proof seam:** `AgentClient::messages()` tags any undecryptable event as the
  literal body `"[unable to decrypt]"` (via `event.kind.is_utd()`); a successfully decrypted
  text event returns its real plaintext body. So "body != `[unable to decrypt]` and equals
  what was sent" IS the decryption assertion.
- **Native logout seam (R-K2):** the connector exposes the raw matrix-sdk `Client` via
  `agent.client()`; the test calls `agent.client().matrix_auth().logout()`. The client's
  homeserver URL is `AgentConfig.matrix_url` (here the edge), so the native logout POSTs
  the edge and is routed to siwx-oidc — the deployed device-sign-out path, not a bypass.

The existing `tests/e2e.rs::e2ee_bidirectional_messaging` already did the R-K1 shape, but
**hardcoded the PROD URLs** with no override. The adaptation below adds local-stack
overrides + an explicit `m.room.encryption` assertion, and adds the R-K2 native-logout test.

---

## Connector adaptation (what changed, and where to productize)

All changes are **test-only**, confined to
`crates/aqua-matrix-agent/tests/e2e.rs`. **No `src/` (lib/main/media) was touched**, so
nothing the deployed image builds is affected. Saved as a standalone patch at
`docs/audits/patches/e2ee-connector-localstack.patch` and as branch
`regression/local-e2ee-track2` in `~/aqua-matrix-agent`.

> NOTE: a concurrent agent owns `~/aqua-matrix-agent`'s working tree (branch
> `fix/delivery-inbox-promise`, unrelated uncommitted changes). The adaptation was
> built/run in a **separate git worktree** at `~/aqua-matrix-agent-e2ee` of the
> `regression/local-e2ee-track2` branch, so the concurrent tree was never touched.

1. **URL + store overrides in `agent_config()`** (mirrors the existing `SIWX_E2E_KEY_A/B`
   pattern; defaults stay prod so existing behaviour is unchanged):
   - `SIWX_E2E_SIWX_URL`   → `siwx_url`   (default `https://siwx-oidc.inblock.io`)
   - `SIWX_E2E_MATRIX_URL` → `matrix_url` (default `https://matrix.inblock.io`) — **point
     this at the EDGE (`http://localhost:8450`), not Synapse directly**, so the native
     logout reaches siwx-oidc.
   - `SIWX_E2E_STORE_ROOT` → crypto store root (default `<repo>/.e2e-store`); a separate
     root is REQUIRED when running the same key against a different homeserver (the crypto
     store binds to (homeserver, device_id)).
2. **Explicit encryption assertion** added to `e2ee_bidirectional_messaging`: after the room
   resolves, assert `room.latest_encryption_state().is_encrypted()` from **both** A's and B's
   views (rigorous R-K1 "the room is encrypted" check, beyond just "not UTD").
3. **New test `e2ee_device_logout_history_survives` (R-K2)**, gated behind `SIWX_E2E_RUN_RK2=1`
   so it never logs out the prod test device by accident. It signs Agent B's device out via
   **matrix-sdk's native `client.matrix_auth().logout()`** (NOT a direct POST to siwx-oidc),
   relying on the edge to route that to siwx-oidc, then asserts A's survivability (history
   decrypt + room still encrypted + A's crypto intact).

To **productize** later: commit `tests/e2e.rs` from `regression/local-e2ee-track2` (or apply
the patch) and wire the env vars into `e2e/run-local-e2ee.sh`.

---

## Exact commands to reproduce

```bash
# 0) Real stack must be UP (siwx-real-oidc/synapse/redis on siwx-real-net).
#    Recipe: /tmp/track2-real-stack.md ; restart with:
#    podman start siwx-real-redis siwx-real-oidc siwx-real-synapse

# 1) Add the prod-mirroring edge (siwx-real-caddy on :8450) — from the siwx-oidc repo:
cd ~/siwx-oidc
bash e2e/real-stack-edge.sh up
bash e2e/real-stack-edge.sh verify   # shows the 404->200 before/after

# 2) Set up the connector regression worktree (the concurrent agent owns the main tree):
git -C ~/aqua-matrix-agent worktree add ~/aqua-matrix-agent-e2ee regression/local-e2ee-track2
cd ~/aqua-matrix-agent-e2ee
# apply the test adaptation (or it may already be present on the branch):
git apply ~/siwx-oidc/docs/audits/patches/e2ee-connector-localstack.patch || true

# 3) Mint two fresh throwaway did:key identities (no network):
mkdir -p /tmp/rk-e2ee/keys /tmp/rk-e2ee/store
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/a.pem --print-did
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/b.pem --print-did
```

**R-K1 — encrypted bidirectional messaging (client points at the EDGE):**

```bash
cd ~/aqua-matrix-agent-e2ee
SIWX_E2E_SIWX_URL=http://localhost:8081 \
SIWX_E2E_MATRIX_URL=http://localhost:8450 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/a.pem \
SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store \
cargo test --test e2e --features e2e e2ee_bidirectional_messaging \
  -- --nocapture --test-threads=1
```

**R-K2 — native device sign-out via the edge** (add `SIWX_E2E_RUN_RK2=1`; use a
FRESH store + fresh keys so the access tokens are full-life — the test runs ~3-4
min and the access-token TTL is 300s):

```bash
cd ~/aqua-matrix-agent-e2ee
SIWX_E2E_RUN_RK2=1 \
SIWX_E2E_SIWX_URL=http://localhost:8081 \
SIWX_E2E_MATRIX_URL=http://localhost:8450 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/rk2-a.pem \
SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/rk2-b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store-rk2 \
cargo test --test e2e --features e2e e2ee_device_logout_history_survives \
  -- --nocapture --test-threads=1
```

> Gotcha: keep R-K1 and R-K2 on SEPARATE store roots + identities. The matrix-sdk
> crypto store binds to (homeserver, device_id). Reusing a store created against a
> different homeserver URL collides the server's one-time keys / Olm identity with a
> fresh local store → `400 "One time key … already exists"` + `InvalidSignature`
> (all events become `[unable to decrypt]`). Also: R-K2's native `logout()`
> invalidates B's session client-side immediately (unlike the old direct-POST,
> which left B's matrix-sdk session alive on its ~2-min introspection cache), so do
> not `sync` B after the logout — and give A a full-life token (fresh store).

---

## Captured evidence

### R-K1 — two distinct identities provisioned on local Synapse (via the edge)

```
Agent A connected: @did-key-z6mkom3ewgqeqqed9wcrtekbcr7b4x1kkkpn5ghtzgqvztj6:localhost (did:key:z6Mkom3eWgQEQQED9WCRTeKbcR7B4x1KkKpn5GHTzgQvZTj6)
Agent B connected: @did-key-z6mkpcc8sdhuys5vw5m6fsjuyddbrzhe68oealhgzmxbpklx:localhost (did:key:z6MkpcC8sdHuYS5VW5M6FSJUYDdBrzHe68oeALhGZmXbPKLX)
```
Different DIDs → different Matrix users on `localhost`. (`assert_ne!` on user_id holds.)
The connector's homeserver URL was `http://localhost:8450` (the edge).

### R-K1 — the room is ENCRYPTED (both participants agree)

Connector view (test output):
```
Room !ZlOdbLCdSblxYjBGkh:localhost encryption (A's view): Encrypted
Room !ZlOdbLCdSblxYjBGkh:localhost encryption (B's view): Encrypted
m.room.encryption CONFIRMED set (Megolm) — both participants agree the room is encrypted
```

Independent server-side proof (Synapse admin API, `m.room.encryption` state event):
```json
{
  "type": "m.room.encryption",
  "sender": "@did-key-z6mkom3ewgqeqqed9wcrtekbcr7b4x1kkkpn5ghtzgqvztj6:localhost",
  "content": { "algorithm": "m.megolm.v1.aes-sha2",
               "rotation_period_ms": 604800000, "rotation_period_msgs": 100 },
  "room_id": "!ZlOdbLCdSblxYjBGkh:localhost",
  "state_key": "",
  "event_id": "$swEjiPfLO5HLHIxnAHkfDp98MigY_j_F0RQn1-pY1uc"
}
```

Ciphertext census (Synapse admin `/messages` over the R-K1 room): the server holds
only ciphertext — **`m.room.encrypted: 5`, `m.room.message: 0`**.

### R-K1 — decryption both directions (test output)

```
Agent B sent: e2e-test-b-to-a-edf80efa-... (event: $etw33qD17PKEWmPffbysu8F6Wz-n-bglXQGLJ2y9vig)
Agent A received and decrypted: e2e-test-b-to-a-edf80efa-...
Agent A sent: e2e-test-a-to-b-edf80efa-... (event: $AuGowRMGitHeYBfRHnHhoEFUGuNXQZJ_qVm1zT1HI-s)
Agent B received and decrypted: e2e-test-a-to-b-edf80efa-...

E2EE bidirectional test PASSED
  Messages verified decryptable in both directions
test result: ok. 1 passed; 0 failed; ... finished in 102.41s
```
The receiver's body equals the sender's exact string (asserted) and is never
`[unable to decrypt]`. Server holds only ciphertext; only the two clients hold the
Megolm keys. **R-K1 = PASS.**

### R-K2 — NATIVE device sign-out via the edge + survivability

```
B = @did-key-z6mkkdgdrrwnr9qy9a8w2vm6ptdbwdqyuykpb44ulyd8xedf:localhost  device=Some("AQUA_ecaeffdc7799")
B sent pre-logout message: rk2-before-logout-1d9fe47c-...
PRECONDITION OK: A decrypted B's pre-logout message
Signing Agent B's device out via matrix-sdk NATIVE logout (POST http://localhost:8450/_matrix/client/v3/logout → edge → siwx-oidc) ...
Agent B device signed out via NATIVE client→edge→siwx-oidc logout (siwx-oidc deleted the Synapse device + revoked B's tokens, no 404)
R-K2 (1) PASS: A still decrypts B's pre-logout message after B's sign-out: rk2-before-logout-1d9fe47c-...
Room !pDrQiHSIvtHJlyMtpd:localhost encryption after B logout (A's view): Encrypted
R-K2 (2) PASS: room E2EE intact (m.room.encryption still set) after B's sign-out
R-K2 (3) PASS: A sent + read-back-decrypted a NEW message after B's sign-out: rk2-after-logout-1d9fe47c-...

R-K2 device-logout survivability test PASSED
  B's device signed out via matrix-sdk NATIVE logout → edge → siwx-oidc (no 404)
test result: ok. 1 passed; 0 failed; ... finished in 218.49s
```

The native logout returned without error (no `404 Unrecognized request`) —
matrix-sdk's `matrix_auth().logout()` reached siwx-oidc's `compat::logout` through
the edge. Independent server-side proof the device was really deleted (Synapse admin
`/users/<B>/devices` after sign-out):
```
B device count: 0      # B's AQUA_ecaeffdc7799 was deleted by siwx-oidc (DeleteDevice teardown)
A device count: 1      # A's AQUA_8f969886cf7d untouched (A was not signed out)
```
A — a separate device/session — kept decryptable history, an encrypted room, and a working
Megolm session through B's sign-out. No collateral cross-signing/crypto damage. **R-K2 = PASS.**

---

## R-K2 finding (productized into the harness)

The naive in-client path **`matrix-sdk client.matrix_auth().logout()` 404s against a
bare Synapse** on this stack: it POSTs Synapse's native `/_matrix/client/v3/logout`,
and Synapse in MSC3861 delegated-auth mode **disables that endpoint** → `404
"Unrecognized request"`. The logout endpoint is **owned by siwx-oidc**
(`compat::logout`, `TeardownPolicy::DeleteDevice`: deletes the Synapse device +
revokes the session's tokens). PROD forwards `/_matrix/client/v3/logout` (and the
sibling owned paths) to siwx-oidc with a Caddy method-route on matrix.inblock.io.

This regression mirrors that with the local **`siwx-real-caddy` edge** (`e2e/real-stack/Caddyfile`),
so the connector points its homeserver at the edge and the native sign-out reaches
siwx-oidc through the **same client → edge → siwx-oidc path the deployed Element
device sign-out uses** — the direct-to-:8081 workaround is no longer needed.

---

## Safety / hygiene

- Everything ran against **localhost only** (`:8081`/`:8448`/`:8450`); prod
  (`siwx-oidc.inblock.io`/`matrix.inblock.io`) was never contacted — overrides verified in
  every command and in the connected user ids (`…:localhost`).
- No `aqua-agent-*` (prod) or `siwx-e2e-*` (mock) container was touched. The edge is a NEW
  `siwx-real-caddy` container added in front; the existing `siwx-real-*` containers were not
  recreated. Nothing pushed.
- `/home/waldknoten-01/siwx-oidc` doc/script changes only (the edge Caddyfile + bring-up
  script + this audit). siwx-oidc `src/` was not modified.
- Connector change is test-only (`tests/e2e.rs`); `src/` untouched → deployed image behaviour
  unaffected. Built/run in the separate worktree `~/aqua-matrix-agent-e2ee`; captured as
  `docs/audits/patches/e2ee-connector-localstack.patch` + branch `regression/local-e2ee-track2`.
- Memory verdict GREEN throughout.

## The local real stack + edge are LEFT RUNNING (per requirement)
```
siwx-real-redis:   Up
siwx-real-oidc:    Up
siwx-real-synapse: Up
siwx-real-caddy:   Up   (edge, http://localhost:8450)
```
Edge teardown: `bash e2e/real-stack-edge.sh down` (or `podman rm -f siwx-real-caddy`).
Full real-stack teardown: see `/tmp/track2-real-stack.md` §(b).
