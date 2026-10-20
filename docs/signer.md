# The signing key in its own process: `siwx-signer`

siwx-oidc signs ID tokens, signed userinfo responses, the DID assertion in the
`io.inblock.did` profile field and back-channel logout tokens with one ES256 (P-256) key.
By default that key lives in the siwx-oidc process (`signing_key_pem`, or a key generated at
start). With `signing_backend = socket` it lives only in `siwx-signer`, a second binary in the
same image, run as its own service: siwx-oidc then holds no private key, in memory, in its
environment or in its container, and asks the signer for each signature over a Unix socket.

The configuration options are in [configuration.md](configuration.md#signing-backends).

## Commands

```text
siwx-signer serve --key-file <path> --socket <path> --issuer <url> [options]
siwx-signer self-test --key-file <path>
siwx-signer keygen --out <path>
siwx-signer kid --key-file <path>
```

| `serve` option | Environment | Default | Meaning |
|---|---|---|---|
| `--key-file` | `SIWX_SIGNER_KEY_FILE` | required | The P-256 private key, PKCS#8 PEM, readable by its owner only (no group or other bits, else a start error). |
| `--socket` | `SIWX_SIGNER_SOCKET` | required | The socket to listen on. A stale socket at the path (nothing accepts connections on it) is replaced; one that a running signer still serves is a start error, and anything else there is refused. Created with mode `0660`. |
| `--issuer` | `SIWX_SIGNER_ISSUER` | required | siwx-oidc's `base_url`: set both from the same value. Every token's `iss` must equal it, read as a URL (`https://example.org` and `https://example.org/` are the same). siwx-oidc refuses to start when it differs. |
| `--allowed-uid` | `SIWX_SIGNER_ALLOWED_UID` | `10001` | The only peer uid served (`SO_PEERCRED`); the image runs siwx-oidc as 10001. |
| `--max-token-lifetime-secs` | `SIWX_SIGNER_MAX_TOKEN_LIFETIME_SECS` | `3600` | The longest `exp - iat` signed. siwx-oidc refuses to start when its `id_token_ttl_secs` (default 300) or the logout token lifetime (120 s) is above it. |
| `--max-clock-skew-secs` | `SIWX_SIGNER_MAX_CLOCK_SKEW_SECS` | `300` | How far `iat` may be from the signer's clock. |
| `--rate-alarm-per-minute` | `SIWX_SIGNER_RATE_ALARM_PER_MINUTE` | `600` | A `rate_alarm` warning when the signatures made in one minute exceed this (refusals sign nothing and do not count); `0` turns it off. |
| `--read-timeout-ms` | `SIWX_SIGNER_READ_TIMEOUT_MS` | `2000` | Bound on reading one request. |

- **`serve`** makes the process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`: no core dump, no
  ptrace attach by the same uid), loads the key and listens. SIGTERM stops it and removes the
  socket, but only while the socket at the path is still the one it bound: when an old and a
  new signer overlap in a restart, the old one's stop leaves the new one's socket in place.
- **`self-test`** loads the key, signs a fixed internal message and verifies the signature;
  exit 0 when that works. It is the container healthcheck and signs nothing outward.
- **`keygen`** writes a fresh key into an **existing, empty** regular file with exactly one
  link that only its owner can read (create it first with its owner and mode `0600`). It
  checks the path before it opens it and the open file again, never creates the file (no
  `O_CREAT`), never follows a symlink, refuses a FIFO or device at once (`O_NONBLOCK`) and a
  file with a second hard link (the key would exist under another name), never overwrites a
  non-empty file, fsyncs, and prints only `kid=<kid>`.
- **`kid`** prints only `kid=<kid>` for a key file. The `kid` is derived exactly as siwx-oidc
  derives it (first 16 hex characters of SHA-256 over the uncompressed public point).

Nothing the binary prints or logs carries key bytes or the bytes it signs; a panic prints its
location only. The key file is read into one buffer sized from its length and wiped after
parsing. Usage errors exit 2, failures exit 1.

## Running it

The signer runs as its own service with its own uid, no network, a read-only root, the key file
mounted read-only, and a socket directory it shares with siwx-oidc through a group. A compose
sketch (paths and ids are examples; prepare the socket directory as
`install -d -o 10002 -g 10003 -m 0750 ./signer-socket` and the key file owned by 10002 with
mode `0400`; a key file with any group or other permission bit is a start error, so a secret
mounted with a default mode such as `0444` needs its mode set):

```yaml
services:
  siwx-signer:
    image: ghcr.io/inblockio/siwx-oidc:<tag>
    entrypoint: ["siwx-signer", "serve"]
    user: "10002:10003"
    environment:
      SIWX_SIGNER_KEY_FILE: /run/secrets/signing_key
      SIWX_SIGNER_SOCKET: /run/siwx-signer/signer.sock
      SIWX_SIGNER_ISSUER: https://auth.example.org
      SIWX_SIGNER_ALLOWED_UID: "10001"
    volumes:
      - ./secrets/signing_key:/run/secrets/signing_key:ro
      - ./signer-socket:/run/siwx-signer
    read_only: true
    network_mode: none
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    ulimits:
      core: 0
    healthcheck:
      test: ["CMD", "siwx-signer", "self-test", "--key-file", "/run/secrets/signing_key"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped

  siwx-oidc:
    image: ghcr.io/inblockio/siwx-oidc:<tag>
    group_add: ["10003"]
    environment:
      SIWXOIDC_BASE_URL: https://auth.example.org
      SIWXOIDC_SIGNING_BACKEND: socket
      SIWXOIDC_SIGNER_SOCKET: /run/siwx-signer/signer.sock
    volumes:
      - ./signer-socket:/run/siwx-signer
    depends_on:
      siwx-signer:
        condition: service_healthy
```

The socket directory's mode (`0750`, group shared) lets siwx-oidc reach the socket but not
create, remove or replace anything in the directory; the socket's own mode (`0660`) lets the
group connect; the uid check then refuses every peer but `--allowed-uid`.

siwx-oidc must get no `signing_key_pem` from any layer (either environment prefix, either config
file): with `socket` that is a start error. At start it asks the signer for its public key and
exits non-zero when the signer cannot be reached within `signer_timeout_ms`, names a `kid` its
key does not derive to, signs for another issuer than siwx-oidc's `base_url`, or would refuse
the token lifetimes siwx-oidc uses (`id_token_ttl_secs` of 0 or above the signer's
`--max-token-lifetime-secs`): a signer that would refuse every token stops the start, instead
of a green healthcheck over failing sign-ins. Its start log then reads
`signing backend=socket kid=<kid>`, and `/jwk` publishes that key (plus
`retired_signing_keys_pem`, which works as with any backend).

A client registration (`POST /register`, and its update) with a `userinfo_signed_response_alg`
other than `ES256` is refused as `invalid_client_metadata` under `socket`: the signer signs
ES256 only.

### Key birth and rotation

1. Pre-create an empty file owned by the signer's uid with mode `0600`.
2. Run `siwx-signer keygen --out <file>` in a one-off container with no network that mounts
   only that file, read-write. It prints the new `kid`.
3. Tighten the file to `0400` and name it after its `kid` (`siwx-signer kid --key-file <file>`
   prints it again), so a mount names the key version it holds.

Rotation follows [configuration.md](configuration.md#key-rotation): point the signer at the new
key file and put the old key's public half (`openssl pkey -in <old key> -pubout`) in siwx-oidc's
`retired_signing_keys_pem` so DID assertions minted under it stay verifiable, unless the old key
was abused. siwx-oidc reads the signer's public key, issuer and lifetime limit once, at start:
restart it after the signer moves to a new key (or a new `--issuer` or limit). Until then every
answer fails its `kid` check and is a 503, never a token under a key the JWKS does not publish.

## Protocol (version 1)

A Unix stream socket, one request per connection. The client writes one JSON object, which holds
no newline, then `\n`; a client may half-close instead of sending the newline. The signer answers
one JSON object and `\n`, then closes. A request is at most 64 KiB, newline included. Every
message carries `"v": 1`; a request without it, or with another version, is `bad_version`.

| Request | Answer |
|---|---|
| `{"v":1,"op":"public"}` | `{"v":1,"kid":"…","jwk":{…},"alg":"ES256","issuer":"https://example.org/","max_token_lifetime_secs":3600}` |
| `{"v":1,"op":"sign","purpose":"<purpose>","msg":"<base64url>"}` | `{"v":1,"kid":"…","sig":"<base64url>"}` |
| anything refused | `{"v":1,"error":"<code>"}` |

`purpose` is `id_token`, `did_proof`, `logout_token` or `userinfo`. `msg` is the JWS signing
input (`BASE64URL(header).BASE64URL(payload)`) in unpadded base64url; `sig` is the raw ES256
signature (r‖s, 64 bytes, never DER). The error codes are `bad_request` (not JSON, an unknown
`op` or `purpose`, a member that does not belong, `msg` not unpadded base64url), `too_large`,
`bad_version`, `shape` (below) and `internal`. An error never echoes the request. A peer of
another uid gets no answer at all.

The `public` answer names the signer's `issuer` (as a URL string) and its
`--max-token-lifetime-secs`, which siwx-oidc checks at start (above); an answer without them is
not a `public` answer. siwx-oidc checks every `sign` answer: the `kid` must be the one it derived
at start, and the signature must verify against the cached public key. A mismatch is an error,
never a token.

### What the signer signs

Only JWS signing inputs whose header and payload are JSON objects, in the shapes siwx-oidc
emits:

| Purpose | Header | Payload |
|---|---|---|
| `id_token` | `alg` ES256, `kid` the signer's, `typ` absent or `JWT` | `iss` = `--issuer`, `sub`, `aud`, `iat` and `exp` bounded; no `events`, no `mxid` |
| `userinfo` | as `id_token` | `iss`, `sub`, `aud`; none of `exp`, `iat`, `nonce`, `at_hash`, `c_hash`, `auth_time`, `sid`, `mxid`, `events` |
| `logout_token` | as `id_token`, `typ` `logout+jwt` | `iss`, `sub`, `aud`, `jti`, the back-channel logout `events` member, `iat` and `exp` bounded; no `nonce`, no `mxid` |
| `did_proof` | as `id_token`, `typ` `JWT` | exactly `iss`, `sub` (a DID), `mxid`, `iat` bounded; no `exp` |

"Bounded": `iat` within `--max-clock-skew-secs` of the signer's clock and `exp` after `iat` by at
most `--max-token-lifetime-secs`. A header holds nothing beyond `alg`, `kid` and `typ`, and no
object in the header or the payload names a member twice (a verifier that keeps the first of
two `iss` would read another token than the one checked). A refused message is answered `shape`
and logged with a fixed reason (`iss`, `exp`, `typ`, `duplicate_member`, …), never with its
bytes.

The purposes do not overlap: no message passes two of them. A userinfo response carries no time
and none of the members that make an ID token or a DID proof, so a userinfo signature is never an
ID token without an end and never a DID binding (siwx-oidc's userinfo names the Matrix ID
`io.inblock.mxid`, never `mxid`); an ID token and a logout token carry no `mxid`, which the DID
verifier requires.

These checks narrow what a compromised siwx-oidc process can have signed: no foreign issuer, no
unbounded lifetime, no other key's `kid`, no non-JWS bytes, no signature for one purpose that
serves as another.
They do not stop it from having well-formed tokens signed for any subject while it runs (it also
holds the other secrets of the deployment). That residual is what the counts, the rate alarm
and key rotation are for.

## When a signature cannot be had

A signature fails when the signer is down, does not answer within `signer_timeout_ms`, fails on
its own side (`internal`), or answers with a `kid` or a signature that does not check out. Then:

| Path | Answer |
|---|---|
| `POST /token` (code and device-code grants) | the retryable 503 `temporarily_unavailable` with `Retry-After`; no token |
| `GET`/`POST /userinfo` for a client registered for a signed response | 503; the unsigned JSON answer needs no signer and keeps working |
| the `io.inblock.did` profile field at sign-in | not written (never `{did}` without a proof over a good one); sign-in itself goes on, and the next sign-in re-asserts the field |
| back-channel logout | not sent; the entry stays queued with its attempt count unchanged and is retried when its lease ends |

A signer that refuses the message itself (`shape`, or a protocol refusal) refuses it again on
every retry: `POST /token` and signed userinfo answer it with a 500 `server_error` and no
`Retry-After`, and siwx-oidc logs the failure. It means siwx-oidc and the signer disagree about
what a token looks like; the start check above catches the configuration cases.

A code exchange or device-code grant whose ID token cannot be signed answers nothing, and leaves
nothing behind that nobody holds: the grant it issued is discarded (with no back-channel logout:
no relying party ever got its `sid`), the authorization code is put back for the rest of its
lifetime, and a device-code poll deletes the Matrix device it created (a device that already
existed is left alone) and releases its claim on the still-approved code. The retry that the
503 invites therefore redeems the same code once the signer is back.

## Logs

The signer logs one line per request: the operation, the purpose, the `kid`, the message length,
the peer uid and the result, never the message and never key material. Each minute that saw
requests ends with a `sign counts (last minute)` line (per purpose, and the refusals apart), and
a minute whose signatures exceed `--rate-alarm-per-minute` logs one `rate_alarm` warning; a
refusal signs nothing and does not count towards it. A refused peer logs `peer_refused uid=<n>`.

## Guest peek nonces

The guest flow's peek nonce key is derived from `signing_key_pem` when one is configured, else
random per process. With `socket` there is no PEM in siwx-oidc, so it is random per process: a
restart, or a second instance, invalidates the nonces issued before it (they live five minutes).
