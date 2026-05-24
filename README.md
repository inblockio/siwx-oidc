# siwx-oidc

OpenID Connect identity provider that authenticates users via wallet signatures (CAIP-122) and WebAuthn passkeys. Users sign a challenge with their existing wallet or tap a biometric; siwx-oidc issues standard OIDC tokens with the user's DID as the subject claim.

Any OIDC relying party can consume these tokens. The primary deployment target is Matrix Synapse, where siwx-oidc **replaces MAS entirely** via MSC3861, handling token introspection, device provisioning, cross-signing management, and the full device lifecycle including QR code login.

Single Rust binary (~18MB Alpine Docker image). Redis as the only dependency.

## What makes this different

No other open-source project combines these three things:

1. **Wallet signature as primary OIDC identity.** The DID derived from the wallet or passkey is the canonical identity. No username, no password, no email. General IAM platforms (Keycloak, authentik) treat wallet login as peripheral "social login" bound to a traditional account.

2. **Full MSC3861 compliance.** Token introspection, device provisioning via Synapse admin API, cross-signing reset (MSC4312), account management discovery (MSC4191). MAS implements this protocol but accepts no wallet auth.

3. **Multi-ceremony, multi-chain, single identity.** CAIP-122 (any chain), WebAuthn passkeys, and RFC 8628 device codes all converge into one DID-based identity. A user can authenticate with MetaMask on desktop, Face ID on mobile, or a QR code on a headless device, and all sessions resolve to the same account.

The upstream predecessor ([spruceid/siwe-oidc](https://github.com/nickreynolds/siwe-oidc)) was Ethereum-only, had no passkeys, no refresh tokens, no MSC3861 support, and was abandoned in mid-2024.

## Authentication methods

| Method | Flow | Identity | Use case |
|--------|------|----------|----------|
| Wallet (CAIP-122) | Browser sign + cookie | `did:pkh:eip155:1:0x...` | Primary login (desktop) |
| WebAuthn passkey | Biometric prompt | `did:key:zDn...` (P-256) | Passwordless mobile/desktop |
| Linked passkey | Biometric prompt | Wallet DID (linked) | Same identity, no wallet needed |
| Device code (RFC 8628) | QR code / user code | Approver's DID | Element X QR login, CI, headless |
| Headless client | Local PEM key | `did:key:z6Mk...` (Ed25519) | Service accounts, bots |

Users can link a passkey to their wallet DID, so future biometric logins produce the same identity as wallet logins.

## Supported DID methods

| DID Method | Key types | Default |
|-----------|-----------|---------|
| `did:pkh` | eip155 (Ethereum), ed25519, p256 | Yes |
| `did:key` | Ed25519 (`z6Mk...`), P-256 (`zDn...`) | Opt-in |
| `did:peer` | Variant 0, Variant 2 (V-key) | Opt-in |

## Workspace

| Crate | Description |
|-------|-------------|
| **siwx-oidc** (root) | Axum server with Redis backend |
| **siwx-oidc-auth** | Headless OIDC client (library + CLI) |

Crypto verification lives in the external [aqua-auth](https://github.com/inblockio/aqua-auth) crate (DIDMethod/CipherSuite traits, pure library, no async).

## Quick start (server)

### Dependencies

- Redis (or Redis-compatible store)
- Rust 1.75+

### Running

```bash
redis-server &
cargo run
```

Discovery endpoint: `http://127.0.0.1:8000/.well-known/openid-configuration`

### Configuration

Configure via `siwe-oidc.toml` or environment variables (prefix `SIWEOIDC_`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SIWEOIDC_ADDRESS` | Bind address | `127.0.0.1` |
| `SIWEOIDC_PORT` | Port | `8000` |
| `SIWEOIDC_BASE_URL` | Advertised OIDC issuer URL | `http://127.0.0.1:8000` |
| `SIWEOIDC_REDIS_URL` | Redis connection URL | `redis://localhost` |
| `SIWEOIDC_SIGNING_KEY_PEM` | PKCS#8 PEM for ES256 signing key | auto-generated |
| `SIWEOIDC_SUPPORTED_DID_METHODS` | DID methods accepted | `["pkh"]` |
| `SIWEOIDC_SUPPORTED_PKH_NAMESPACES` | did:pkh namespaces | `["eip155","ed25519","p256"]` |
| `SIWEOIDC_RP_ID` | WebAuthn Relying Party ID (domain) | hostname of BASE_URL |
| `SIWEOIDC_RP_ORIGIN` | WebAuthn expected origin | BASE_URL |
| `SIWEOIDC_MATRIX_SERVER_NAME` | Matrix server_name for cross-signing | (none) |

To enable passkey login and the headless client, add `"key"` to supported methods:
```toml
# siwe-oidc.toml
[supported_did_methods]
0 = "pkh"
1 = "key"
```

## Headless client (siwx-oidc-auth)

Authenticate without a browser, using a local key or device authorization grant.

### Authorization code flow (machine identity)

```bash
# Generate a persistent Ed25519 identity
openssl genpkey -algorithm Ed25519 -out identity.pem

# Print the DID
cargo run -p siwx-oidc-auth -- --print-did --key-file identity.pem

# Authenticate
cargo run -p siwx-oidc-auth -- \
  --server https://siwx.example.com \
  --client-id my-service \
  --redirect-uri https://myapp.example.com/callback \
  --key-file identity.pem

# Refresh without re-authenticating
cargo run -p siwx-oidc-auth -- \
  --server https://siwx.example.com \
  --client-id my-service \
  --refresh-token "<token>" \
  --key-file identity.pem
```

### Device flow (human identity on headless machine)

```bash
# Prints user code + verification URL, polls until approved
cargo run -p siwx-oidc-auth -- --device-flow \
  --server https://siwx.example.com \
  --client-id my-service
```

The approving user's DID (wallet or passkey) becomes the session identity.

### Library usage

```rust
use siwx_oidc_auth::{SiwxKey, authenticate, refresh};

let key = SiwxKey::from_pem_file("identity.pem".as_ref())?;
let tokens = authenticate(
    "https://siwx.example.com",
    "my-client-id",
    "https://app.example.com/callback",
    &key,
).await?;

// Later: refresh without re-signing
let new_tokens = refresh(
    "https://siwx.example.com",
    "my-client-id",
    &tokens.refresh_token.unwrap(),
).await?;
```

### Key input priority

1. `--key-file <path>` - PKCS#8 PEM (auto-detects Ed25519 vs P-256)
2. `SIWX_KEY_FILE` env var
3. `--key-hex <hex>` - 32-byte hex seed (requires `--key-type`)
4. (none) - generates ephemeral key, prints PEM to stderr

## Frontend

The Svelte frontend (`js/ui/`) provides browser-based sign-in with two methods:

- **Sign-In with Ethereum** - direct browser wallet detection (MetaMask, Brave, Coinbase) via EIP-1193
- **Sign-In with Passkey** - WebAuthn biometric prompt, with registration flow for new users
- **Link Passkey to Wallet** - after wallet login, optionally link a passkey for future biometric logins

```bash
cd js/ui && npm install && npm run build
```

Build output goes to `static/` which the server serves automatically.

## Matrix integration (MSC3861)

siwx-oidc implements the full MSC3861 surface required by Synapse delegated auth:

| Endpoint | Purpose |
|----------|---------|
| `POST /oauth2/introspect` | Token introspection (Synapse validates access tokens) |
| `POST /oauth2/revoke` | Token revocation |
| `GET /account` | Account management page (MSC4191) |
| `POST /device_authorization` | RFC 8628 device code grant (Element X QR login) |
| Device provisioning | Synapse admin API: create/delete devices per login |
| Cross-signing reset | `allow_cross_signing_reset` on every login (MSC4312) |

Token model: access tokens (5min TTL, `mat_` prefix), refresh tokens (24h TTL, `mcr_` prefix), rotation on refresh.

## Architecture

Three-layer model:

```
Layer 1: aqua-auth (external)     - Crypto: DIDMethod trait, CipherSuite trait, registries
Layer 2: src/{ceremony}.rs        - Auth ceremonies: CAIP-122, WebAuthn, RFC 8628
Layer 3: src/oidc.rs              - OIDC token issuance (all ceremonies converge here)
```

Key boundary: aqua-auth handles CAIP-122 proof verification only. Non-CAIP-122 ceremonies (WebAuthn, device code) are server-layer modules that produce a verified DID. The `DIDMethod` trait is not extended for these.

Extensibility:
- New DID method = one file + one line in `all_did_methods()`
- New cipher suite = one file + one line in `all_cipher_suites()`
- New auth ceremony = one server module + integration with sign_in

## Deployment

Docker image published to GHCR on push to `main` via GitHub Actions.

```bash
# Pull and run
docker pull ghcr.io/inblockio/siwx-oidc:latest
docker run -e SIWEOIDC_REDIS_URL=redis://redis:6379 ghcr.io/inblockio/siwx-oidc
```

For Matrix Synapse deployment (docker-compose with Synapse, Redis, Element Web, Caddy), see [siwx-oidc-matrix-server](https://github.com/inblockio/siwx-oidc-matrix-server).

## Building and testing

```bash
# Build the full workspace
cargo build --workspace

# Run server tests (needs Redis on localhost:6379)
cargo test --bin siwx-oidc

# Run the server
cargo run

# Run the headless client
cargo run -p siwx-oidc-auth -- --help
```

## Breaking changes vs siwe-oidc

1. **`sub` claim**: `eip155:1:0xAddr` -> `did:pkh:eip155:1:0xAddr`
2. **Sign-in cookie**: `siwe` -> `siwx`; payload `{ did, message, signature }`
3. **CodeEntry**: `address: Address` -> `did: String` (flush Redis on upgrade)
4. **Config**: adds `supported_did_methods`, `supported_pkh_namespaces`, WebAuthn settings

## License

MIT OR Apache-2.0
