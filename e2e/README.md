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
| `synapse_mock.py` | Faithful in-memory mock of the Synapse admin/MAS endpoints siwx-oidc calls, with `/__seed_device`, `/__state`, `/__set_secret`, `/__reset` test hooks |
| `../tests/e2e_account_management.rs` | Drives the exact HTTP requests the page JS makes — real EIP-191 wallet signatures, the account-session cookie, `/account/action`. Run: `cargo test --test e2e_account_management -- --ignored --test-threads=1` |
| `legacy-cs-api-probe.sh` | `DELETE /_matrix/client/v3/devices/{id}` + `/delete_devices` with a Redis-seeded bearer |
| `browser/account.spec.mjs` | Playwright: mock `window.ethereum` (real ethers signing) + CDP WebAuthn virtual authenticator, driving the real `/account` DOM. Run: `bash browser/run.sh` |

## Stack endpoints

- siwx-oidc: http://localhost:8080
- Synapse mock: http://localhost:8090 (Bearer `testsecret`)
- Redis: 127.0.0.1:6379 (podman)

## What it proves

- One wallet signature (or one passkey ceremony) covers a whole account session:
  list sessions → sign a device out → view profile, with no further prompt.
- Device sign-out deletes the Synapse device and revokes its tokens.
- Account erasure runs `deactivate(erase=true)` and clears the session.
- The legacy in-client session-manager delete endpoints work.
- An admin-token rejection fails legibly (400 naming the admin token), never a
  misleading "device not found" or a 500.
