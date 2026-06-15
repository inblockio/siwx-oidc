# siwx-oidc — REAL End-to-End-ENCRYPTED two-participant Matrix messaging regression

**Date:** 2026-06-15
**Tool:** the connector at `~/aqua-matrix-agent` (matrix-sdk 0.17, e2e-encryption; auth via siwx-oidc).
**Stack:** LOCAL real stack — `siwx-real-oidc` (http://localhost:8081) + `siwx-real-synapse`
(http://localhost:8448, server_name `localhost`), MSC3861 delegated auth. NOT prod.

## Verdicts

| Req | What it proves | Verdict |
|-----|----------------|---------|
| **R-K1** | Two distinct DIDs log in via local siwx-oidc, get provisioned on local Synapse, share an **encrypted** room (`m.room.encryption` set), each sends, the other **DECRYPTS** — both directions, plaintext asserted equal. | **PASS** |
| **R-K2** | After the exchange, ONE participant's device is signed out via siwx-oidc; the OTHER still decrypts history, the room stays encrypted, and its own crypto is undamaged. | **PASS** |

Both verified by RUNNING against the live local stack, with independent server-side
(Synapse admin API) corroboration that the bytes on the wire are ciphertext.

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

The existing `tests/e2e.rs::e2ee_bidirectional_messaging` already does the R-K1 shape, but
**hardcoded the PROD URLs** with no override. The fix below adds local-stack overrides + an
explicit `m.room.encryption` assertion, and adds an R-K2 test.

---

## Connector adaptation (what changed, and where to productize)

All changes are **test-only**, confined to
`crates/aqua-matrix-agent/tests/e2e.rs`. **No `src/` (lib/main/media) was touched**, so
nothing the deployed image builds is affected. Saved as a standalone patch at
`/tmp/rk-e2ee/connector-e2e-localstack.patch` and as branch
`regression/local-e2ee-track2` in `~/aqua-matrix-agent`.

> NOTE: a concurrent agent owns `~/aqua-matrix-agent`'s working tree and has unrelated
> uncommitted `src/lib.rs` changes (working tree is on branch `fix/delivery-inbox-promise`).
> I deliberately did **not** commit/stash/touch their tree; my adaptation lives only in the
> patch file + my own branch, both of which carry just the `tests/e2e.rs` delta.

1. **URL + store overrides in `agent_config()`** (mirrors the existing `SIWX_E2E_KEY_A/B`
   pattern; defaults stay prod so existing behaviour is unchanged):
   - `SIWX_E2E_SIWX_URL`   → `siwx_url`   (default `https://siwx-oidc.inblock.io`)
   - `SIWX_E2E_MATRIX_URL` → `matrix_url` (default `https://matrix.inblock.io`)
   - `SIWX_E2E_STORE_ROOT` → crypto store root (default `<repo>/.e2e-store`); a separate
     root is REQUIRED when running the same key against a different homeserver (the crypto
     store binds to (homeserver, device_id)).
2. **Explicit encryption assertion** added to `e2ee_bidirectional_messaging`: after the room
   resolves, assert `room.latest_encryption_state().is_encrypted()` from **both** A's and B's
   views (rigorous R-K1 "the room is encrypted" check, beyond just "not UTD").
3. **New test `e2ee_device_logout_history_survives` (R-K2)**, gated behind `SIWX_E2E_RUN_RK2=1`
   so it never logs out the prod test device by accident. It signs Agent B's device out and
   asserts A's survivability (history decrypt + room still encrypted + A's crypto intact).

To **productize** later: commit `tests/e2e.rs` from `regression/local-e2ee-track2` (or apply
the patch) and wire the five env vars into a small `e2e/run-local-e2ee.sh`.

---

## Exact commands to reproduce

Fresh, throwaway local identities (do NOT reuse the prod-bound `agent.pem`/`agent-b.pem`
stores — different homeserver):

```bash
mkdir -p /tmp/rk-e2ee/keys /tmp/rk-e2ee/store
cd ~/aqua-matrix-agent
# mint two distinct did:key identities (creates the PEMs if absent; no network)
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/local-a.pem --print-did
./target/debug/aqua-matrix-agent --key-file /tmp/rk-e2ee/keys/local-b.pem --print-did
#   A did:key:z6MkjNTbxaAnJuw3tYHge7ujDGy6e9wy8QoPioaQQ2U9wesA
#   B did:key:z6Mkw2mNRQQJcfJBwc7TLRdA4uTTfafPWD8z5aKNzowe2vJU

# Apply the test adaptation if not already present in the tree:
#   git -C ~/aqua-matrix-agent apply /tmp/rk-e2ee/connector-e2e-localstack.patch
# (or: git checkout regression/local-e2ee-track2)
```

**R-K1 — encrypted bidirectional messaging:**

```bash
cd ~/aqua-matrix-agent
SIWX_E2E_SIWX_URL=http://localhost:8081 \
SIWX_E2E_MATRIX_URL=http://localhost:8448 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/local-a.pem \
SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/local-b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store \
cargo test --test e2e --features e2e e2ee_bidirectional_messaging \
  -- --nocapture --test-threads=1
```

**R-K2 — device sign-out survivability** (add `SIWX_E2E_RUN_RK2=1`):

```bash
cd ~/aqua-matrix-agent
SIWX_E2E_RUN_RK2=1 \
SIWX_E2E_SIWX_URL=http://localhost:8081 \
SIWX_E2E_MATRIX_URL=http://localhost:8448 \
SIWX_E2E_KEY_A=/tmp/rk-e2ee/keys/local-a.pem \
SIWX_E2E_KEY_B=/tmp/rk-e2ee/keys/local-b.pem \
SIWX_E2E_STORE_ROOT=/tmp/rk-e2ee/store \
cargo test --test e2e --features e2e e2ee_device_logout_history_survives \
  -- --nocapture --test-threads=1
```

---

## Captured evidence

### R-K1 — two distinct identities provisioned on local Synapse

```
Agent A connected: @did-key-z6mkjntbxaanjuw3tyhge7ujdgy6e9wy8qopioaqq2u9wesa:localhost (did:key:z6MkjNTbxaAnJuw3tYHge7ujDGy6e9wy8QoPioaQQ2U9wesA)
Agent B connected: @did-key-z6mkw2mnrqqjcfjbwc7tlrda4uttfafpwd8z5aknzowe2vju:localhost (did:key:z6Mkw2mNRQQJcfJBwc7TLRdA4uTTfafPWD8z5aKNzowe2vJU)
```
Different DIDs → different Matrix users on `localhost`. (`assert_ne!` on user_id holds.)

### R-K1 — the room is ENCRYPTED (both participants agree)

Connector view (test output):
```
Room !hrCLLhuUZJBuqoQQeg:localhost encryption (A's view): Encrypted
Room !hrCLLhuUZJBuqoQQeg:localhost encryption (B's view): Encrypted
m.room.encryption CONFIRMED set (Megolm) — both participants agree the room is encrypted
```

Independent server-side proof (Synapse admin API, `m.room.encryption` state event):
```json
{
  "type": "m.room.encryption",
  "sender": "@did-key-z6mkjntbxaanjuw3tyhge7ujdgy6e9wy8qopioaqq2u9wesa:localhost",
  "content": { "algorithm": "m.megolm.v1.aes-sha2",
               "rotation_period_ms": 604800000, "rotation_period_msgs": 100 },
  "room_id": "!hrCLLhuUZJBuqoQQeg:localhost",
  "state_key": "",
  "event_id": "$olprUDbmBqynGsA7R9i3zQZDAIvOSEG7Oh5UhX2OoI8"
}
```

### R-K1 — the encrypted event on the wire vs the decrypted plaintext

What the SERVER stores (ciphertext only — `m.room.encrypted`, Megolm; admin
`/messages` census: `m.room.encrypted: 8`, **`m.room.message: 0`**):
```
event_id   : $_N9_ZWhY6JcH3m7qPwhF2Fihy9aseiIYCp5ReSSvvjE
type       : m.room.encrypted
sender     : @did-key-z6mkw2mnrqqjcfjbwc7tlrda4uttfafpwd8z5aknzowe2vju:localhost  (Agent B)
algorithm  : m.megolm.v1.aes-sha2
session_id : 2+BsT8jBYCQMkYt0xISqs1LCDauHVjVN+L3gIjdNdpg
ciphertext : AwgBErABB0RRVciLzod7/xRl3NxWtKfWyIaVLXhZashYxP9tYywcfxFZiPBt7hJZOC6ANFTKIg5oCB3Z...[339 b64 chars]
```

What the RECEIVING CONNECTOR decrypts it to (both directions, test output):
```
# B → A
Agent B sent: e2e-test-b-to-a-3443128b-10e3-4ec0-a642-86f269b0f662 (event: $a7Cerh_7lDUbYUbq9PCArSkLtBVucxl2Jk3zB6SjFkc)
Agent A received and decrypted: e2e-test-b-to-a-3443128b-10e3-4ec0-a642-86f269b0f662
# A → B
Agent A sent: e2e-test-a-to-b-3443128b-10e3-4ec0-a642-86f269b0f662 (event: $t99BqtY5kojyW7D_Y0Smb2a7pYXUDEGhu784_R_Qk6A)
Agent B received and decrypted: e2e-test-a-to-b-3443128b-10e3-4ec0-a642-86f269b0f662

E2EE bidirectional test PASSED
  Messages verified decryptable in both directions
test result: ok. 1 passed; 0 failed; ... finished in 104.23s
```
The receiver's body equals the sender's exact string (asserted) and is never
`[unable to decrypt]`. Server holds only ciphertext; only the two clients hold the Megolm
keys. **R-K1 = PASS.**

### R-K2 — device sign-out + survivability

```
B sent pre-logout message: rk2-before-logout-d0ac8b91-35fa-4d84-8a6a-e21e00882925
PRECONDITION OK: A decrypted B's pre-logout message
Signing Agent B's device out via siwx-oidc http://localhost:8081/_matrix/client/v3/logout (explicit DeleteDevice) ...
siwx-oidc /logout HTTP 200 OK: {}
Agent B device signed out (siwx-oidc deleted the Synapse device + revoked B's tokens)
R-K2 (1) PASS: A still decrypts B's pre-logout message after B's sign-out: rk2-before-logout-d0ac8b91-...
Room !hrCLLhuUZJBuqoQQeg:localhost encryption after B logout (A's view): Encrypted
R-K2 (2) PASS: room E2EE intact (m.room.encryption still set) after B's sign-out
R-K2 (3) PASS: A sent + read-back-decrypted a NEW message after B's sign-out: rk2-after-logout-d0ac8b91-...

R-K2 device-logout survivability test PASSED
test result: ok. 1 passed; 0 failed; ... finished in 245.29s
```

Independent server-side proof the device was really deleted (Synapse admin
`/users/<B>/devices` after sign-out):
```
device count: 0      # B's AQUA_75c69b115f8a was deleted by siwx-oidc (DeleteDevice teardown)
```
A — a separate device/session — kept decryptable history, an encrypted room, and a working
Megolm session through B's sign-out. No collateral cross-signing/crypto damage. **R-K2 = PASS.**

---

## R-K2 finding (load-bearing, worth productizing into siwx-oidc docs)

The naive path **`matrix-sdk client.matrix_auth().logout()` does NOT work** on this stack:
it POSTs to the **homeserver's** native `/_matrix/client/v3/logout`, and Synapse in MSC3861
delegated-auth mode **disables that endpoint** → `404 "Unrecognized request"`. The logout
endpoint is **owned by siwx-oidc** (`compat::logout`, `TeardownPolicy::DeleteDevice`:
deletes the Synapse device + revokes the session's tokens). In prod a Caddy method-route
forwards `/_matrix/client/v3/logout` to siwx-oidc; the **local stack has no Caddy**, so the
test signs B out by POSTing **siwx-oidc directly** at
`http://localhost:8081/_matrix/client/v3/logout` with B's live bearer token
(`agent_b.client().access_token()`). This is also the relevant signal for the deployed
in-client device sign-out: it must reach siwx-oidc, not Synapse's native CS-API.

(Contrast: `POST /oauth2/revoke` is `TokensOnly` — token hygiene, never deletes the device.
The `/account?action=org.matrix.device_delete` MSC4191 action is the other explicit-intent
delete path.)

---

## Safety / hygiene

- Everything ran against **localhost only** (`:8081`/`:8448`); prod
  (`siwx-oidc.inblock.io`/`matrix.inblock.io`) was never contacted — overrides verified in
  every command and in the connected user ids (`…:localhost`).
- No `aqua-agent-*` (prod) or `siwx-e2e-*` (mock) container was touched; nothing pushed.
- `/home/waldknoten-01/siwx-oidc` was **read-only** (only studied `compat.rs` for the R-K2
  finding); no edits.
- Connector change is test-only (`tests/e2e.rs`); `src/` untouched → deployed image behaviour
  unaffected. Captured as `/tmp/rk-e2ee/connector-e2e-localstack.patch` + branch
  `regression/local-e2ee-track2`.
- Memory verdict GREEN throughout; the connector was already built (incremental compiles ~20s).

## The local real stack is LEFT RUNNING (per requirement)
```
siwx-real-redis: Up 9 hours
siwx-real-oidc: Up 9 hours
siwx-real-synapse: Up 9 hours
```
Teardown (only if/when desired) is in `/tmp/track2-real-stack.md` §(b).
