# siwx-oidc

CAIP-122 to OpenID Connect bridge — Sign-In With X for any DID method.

siwx-oidc lets any OIDC relying party authenticate users via DID-based
cryptographic identity. Users sign a CAIP-122 challenge with their wallet (or a
local key); siwx-oidc issues standard OIDC tokens (ID token, access token) in
return.

It is the modular, multi-DID successor to
[siwe-oidc](https://github.com/inblockio/siwe-oidc) (Ethereum-only).

## Supported DID methods

| DID Method | Key types | Notes |
|-----------|-----------|-------|
| `did:pkh` | eip155 (Ethereum), ed25519, p256 | Default. Cipher suites ported from [aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth). |
| `did:key` | Ed25519 (`z6Mk…`), P-256 (`zDn…`) | Opt-in via config. Used by the headless client. |
| `did:peer` | Variant 0, Variant 2 (V-key) | Opt-in via config. |

## Workspace

| Crate | Description |
|-------|-------------|
| **siwx-oidc** (root) | Axum server — OIDC provider with Redis backend |
| **siwx-core** | Traits (`DIDMethod`, `CipherSuite`), crypto verification, no async |
| **siwx-oidc-auth** | Headless OIDC client — authenticate from CLI/CI with a local key |

## Quick start (server)

### Dependencies

- Redis (or a Redis-compatible database)
- Rust 1.75+

### Running

```bash
# Start Redis
redis-server &

# Run the server (generates an ES256 signing key on first start)
cargo run
```

The OIDC discovery endpoint is at `http://127.0.0.1:8000/.well-known/openid-configuration`.

### Configuration

Configure via `siwe-oidc.toml` or environment variables (prefix `SIWEOIDC_`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SIWEOIDC_ADDRESS` | IP address to bind | `127.0.0.1` |
| `SIWEOIDC_PORT` | Port | `8000` |
| `SIWEOIDC_BASE_URL` | Advertised OIDC issuer URL | `http://127.0.0.1:8000` |
| `SIWEOIDC_REDIS_URL` | Redis connection URL | `redis://localhost` |
| `SIWEOIDC_SIGNING_KEY_PEM` | PKCS#8 PEM for ES256 signing key (generated if absent) | — |
| `SIWEOIDC_REQUIRE_SECRET` | Require client secret for token exchange | `false` |
| `SIWEOIDC_SUPPORTED_DID_METHODS` | DID methods accepted at sign-in | `["pkh"]` |
| `SIWEOIDC_SUPPORTED_PKH_NAMESPACES` | did:pkh namespaces accepted | `["eip155","ed25519","p256"]` |

To enable `did:key` (required for the headless client):
```toml
# siwe-oidc.toml
[supported_did_methods]
0 = "pkh"
1 = "key"
```

## Quick start (headless client)

The headless client authenticates to a siwx-oidc server without a browser,
using a local `did:key` private key. Useful for services, CI, and automated
testing.

### Generate a persistent identity

```bash
# Generate an Ed25519 key (default)
openssl genpkey -algorithm Ed25519 -out identity.pem

# See the DID derived from this key
cargo run -p siwx-oidc-auth -- --print-did --key-file identity.pem
```

### Authenticate

```bash
cargo run -p siwx-oidc-auth -- \
  --server https://siwx.example.com \
  --client-id my-service \
  --redirect-uri https://myapp.example.com/callback \
  --key-file identity.pem
```

Output: JSON with `access_token`, `id_token`, `token_type`, `expires_in`, and
`did`.

### Key input priority

1. `--key-file <path>` — PKCS#8 PEM file (auto-detects Ed25519 vs P-256)
2. `SIWX_KEY_FILE` env var — same as `--key-file`, for container orchestration
3. `--key-hex <hex>` — 32-byte hex seed (requires `--key-type`), for dev/testing
4. (none) — generates an ephemeral key and prints the PEM to stderr

### Token refresh

Tokens expire (default: 30 seconds). To refresh, call `authenticate()` again —
the flow is stateless and the key is deterministic. For long-running services,
re-authenticate before `expires_in` elapses.

### Library usage

```rust
use siwx_oidc_auth::{SiwxKey, authenticate};

let key = SiwxKey::from_pem_file("identity.pem".as_ref())?;
let tokens = authenticate(
    "https://siwx.example.com",
    "my-client-id",
    "https://app.example.com/callback",
    &key,
).await?;
```

## Frontend

The Svelte frontend (`js/ui/`) handles browser-based sign-in for `did:pkh:eip155`
(Ethereum) using Web3Modal + Wagmi.

```bash
cd js/ui && npm install && npm run build
```

The build output goes to `static/` which the server serves automatically.

> The frontend uses WalletConnect — set the `PROJECT_ID` environment variable
> when building.

## Architecture

The extensibility model uses two traits:

- **`DIDMethod`** — primary, server-visible dispatch. One implementation per DID
  method (`PkhMethod`, `KeyMethod`, `PeerMethod`).
- **`CipherSuite`** — secondary, internal to `did:pkh`. One implementation per
  cipher suite (`Eip155Suite`, `Ed25519Suite`, `P256Suite`).

Adding a new DID method requires one file and one line in `all_did_methods()`.
Adding a new cipher suite (for did:pkh) requires one file and one line in
`all_cipher_suites()`.

Registries are manual static functions — no `inventory` crate (WASM-unsafe).

## Breaking changes vs siwe-oidc

1. **`sub` claim**: `eip155:1:0xAddr` → `did:pkh:eip155:1:0xAddr`
2. **Sign-in cookie**: `siwe` → `siwx`; payload `{ did, message, signature }`
3. **CodeEntry**: `address: Address` → `did: String` — flush Redis on upgrade
4. **Config**: adds `supported_did_methods` + `supported_pkh_namespaces`

## License

MIT OR Apache-2.0
