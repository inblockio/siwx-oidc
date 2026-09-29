# Troubleshooting

Symptoms, causes and fixes, grouped by flow. Environment variables appear as
`SIWXOIDC_…`; the legacy `SIWEOIDC_…` spelling is still accepted (see
[configuration.md](configuration.md)). Some error messages printed by the server
still name the legacy spelling.

- [Where to look first](#where-to-look-first)
- [Headless sign-in (siwx-oidc-auth)](#headless-sign-in-siwx-oidc-auth)
- [Wallet (CAIP-122) sign-in](#wallet-caip-122-sign-in)
- [Passkey sign-in](#passkey-sign-in)
- [Account page and device approval](#account-page-and-device-approval)
- [QR code login succeeds at the server, then fails in Element X](#qr-code-login-succeeds-at-the-server-then-fails-in-element-x)
- [Cross-signing](#cross-signing)
- [Case study: Element X passkey-first login](#case-study-element-x-passkey-first-login)
- [Published DID and `/resolve`](#published-did-and-resolve)
- [Inspecting Redis](#inspecting-redis)

The repository's [`skills/`](../skills/) directory has longer checklists:
[`debug-oidc`](../skills/debug-oidc.md) for the OIDC flow,
[`cross-signing-bootstrap-and-debug`](../skills/cross-signing-bootstrap-and-debug.md),
[`element-x-qr-code-specialist`](../skills/element-x-qr-code-specialist.md),
[`authenticate-siwe-matrix`](../skills/authenticate-siwe-matrix.md) for the
end-to-end Element Web flow, and [`deploy-check`](../skills/deploy-check.md)
before a deployment.

## Where to look first

- **Logs.** The default filter is `siwx_oidc=info,tower_http=info,warn`;
  override it with `RUST_LOG`. `SIWXOIDC_LOG_FORMAT=json` gives structured
  output. Every error response is logged with a discriminator: `bad_request`,
  `unauthorized`, `unknown_credential`, `service_unavailable` (a dependency is
  down and the server refused on purpose) and `internal_error` (unexpected).
- **Discovery.** `GET /.well-known/openid-configuration` and `GET /jwk` describe
  the running server: issuer, endpoints, grant types, account-management
  actions, and the signing keys.
- **Startup warnings.** A warning that the server "Generated ephemeral ES256
  signing key" means no `SIWXOIDC_SIGNING_KEY_PEM` is set: tokens stop verifying
  at every restart and published DIDs carry no `proof`.

## Headless sign-in (siwx-oidc-auth)

| Error printed by the client | Cause | Fix |
|---|---|---|
| `/authorize returned 401 Unauthorized instead of 303` | the `client_id` is not registered | register a client ([agents.md](agents.md#prerequisites)) |
| `failed to parse authorize redirect query params` | the `redirect_uri` is not registered for that client; the server redirected to `/error?message=unregistered_redirect_uri` | pass exactly a registered redirect URI (query strings are ignored in the comparison) |
| `/sign_in returned 400 …: DID method 'key' is not enabled on this server` | `supported_did_methods` does not contain `"key"` | add it (it is in the default) |
| `/sign_in returned 401 …: Signature verification failed` | the signature does not match the DID in the message | check the key file; do not edit the generated message |
| `/sign_in returned 401 …: This account has been deactivated …` | the account was deactivated | a deactivated account cannot sign in |
| `/sign_in returned 503 …` | the deactivation check could not reach Synapse | check Synapse and the shared secret; retry |
| `/token returned 400 …: {"error":"invalid_client","error_description":"Secret required."}` | the client was registered as a confidential client | register it with `token_endpoint_auth_method: "none"` |
| `/token refresh returned 400 …: invalid_grant` | the refresh token was already rotated (more than 60 s ago), expired, or its session was revoked | sign in again with the key; always store the newest refresh token |
| `/token error: unsupported_grant_type: device_code grant requires MSC3861 mode.` with `--device-flow` | the server is not in delegated-auth mode ("MSC3861 mode" is the older name) | the device flow needs a Synapse-backed deployment |
| every run shows a different DID | no key was given, so an ephemeral key was generated | pass `--key-file` or set `SIWX_KEY_FILE` |
| a new Matrix device on every run | no pinned device ID | use `--device-id` / `authenticate_with_device`, and refresh instead of signing in again |

## Wallet (CAIP-122) sign-in

- **"Nonce mismatch"**: the session (5 minutes) expired, or was replaced,
  between `/authorize` and `/sign_in`. Start again from the client.
- **"Signature verification failed"**: the DID in the `siwx` cookie does not
  match the key that signed.
- **"Missing or mismatched resource in CAIP-122 message"**: the `redirect_uri`
  is not listed in the message's `Resources:`.
- **"CAIP-122 signature has expired"**: the message carries an `Expiration
  Time` in the past. The login page sets 48 hours.
- **"did:pkh namespace '…' is not enabled on this server"**: the namespace is
  missing from `supported_pkh_namespaces`.
- **"Session has already logged in"**: `/sign_in` was replayed for a session
  that already completed; start a new login.
- **"redirect_uri is not registered for this client."**: as for the headless
  client.

## Passkey sign-in

1. **"DID method 'key' is not enabled on this server"**: passkeys produce
   `did:key:zDn…`; add `"key"` to `supported_did_methods`.
2. **"No registration challenge found (expired or already used)"** or **"No
   auth challenge found (expired or already used)"**: a ceremony challenge
   lives 120 s and is single-use. The user took too long or reloaded. Start
   again.
3. **The server does not start: "Failed to initialize WebAuthn — check …"**:
   the base URL has no host, or `SIWXOIDC_RP_ORIGIN` is not a valid URL. Behind
   a reverse proxy, set `SIWXOIDC_RP_ID` and `SIWXOIDC_RP_ORIGIN` explicitly.
4. **The browser offers no passkeys, or reports `NotAllowedError`**: the RP ID
   does not match. Browsers only offer passkeys registered for the exact RP ID,
   so the domain users see must match `SIWXOIDC_RP_ID`. `NotAllowedError` also
   appears when the user cancels.
5. **HTTP 401 `unknown_credential`**: the selected passkey is not stored on this
   server (a different Redis, a flushed Redis without persistence, or an erased
   account). The page shows a message and, where the browser supports it, asks
   the platform to remove the stale passkey. Check with
   `redis-cli --scan --pattern 'webauthn:credential/*'`. See
   [passkeys.md](passkeys.md#unknown-credentials).
6. **A passkey registered long ago does not appear in the picker**: it may
   predate the requirement for discoverable credentials. Sign in another way
   and register or link a new passkey
   ([passkeys.md](passkeys.md#migration-notes)).
7. **The picker shows only one account's passkeys**: the `siwx_user` cookie
   scoped it to the last signed-in user. "Use a different passkey" (`all: true`)
   shows all of them ([passkeys.md](passkeys.md#scoping-the-passkey-picker)).
8. **"User Verification flag not set"** or **"Sign count regression"**: the
   authenticator did not verify the user, or reported a counter lower than the
   stored one (a possible cloned authenticator).
9. **"Session not found"**: the OIDC session (5 minutes) expired between
   `/webauthn/authenticate/finish` and `/sign_in`. Look for proxy delays.
10. **The login page asks to confirm a new account**: the passkey resolves to a
    DID with no account. If the user expected an existing account, they chose a
    different passkey than the one they registered with, or their passkey was
    never linked to their wallet.

## Account page and device approval

| Response | Meaning |
|---|---|
| 400 "This passkey/wallet is not linked to an existing account. Create an account at sign-in first." | the DID has no account; accounts are created only at login |
| 401 "This account has been deactivated and cannot sign in. …" | the account is deactivated (`account_reactivate` is still allowed) |
| 503 "The server could not complete a required account check right now. …" | Synapse could not be reached, or it rejected the shared secret. Look for `service_unavailable` in the logs |
| 400 "Missing action" | the account page was POSTed without an action (the bare page is a menu) |
| 400 "Unsupported action: …" | an action the server does not advertise |
| 400 "This action requires the Matrix server_name to be configured" or "This action requires Synapse integration" | the account actions need `SIWXOIDC_MATRIX_SERVER_NAME` and a Synapse client |
| "User code not found or expired" | the device code (30 minutes) expired; start the QR login again |
| "Invalid, expired, or replayed device-approval nonce" | the wallet signed an old or reused nonce; reload the approval page |

## QR code login succeeds at the server, then fails in Element X

**Symptom.** The approval page shows "Device approved", the server logs show
tokens were issued, and Element X reports a login failure 30 to 60 seconds
later.

**Cause.** The approving Element Web session has no cross-signing keys (no
Secure Backup). In the QR flow (MSC4108, still an open proposal), the existing
device sends its cross-signing private keys to the new one over the rendezvous
channel. With nothing to send, the rendezvous expires and Element X aborts.

**Fix.** Set up Secure Backup in Element Web first:

1. Sign in to Element Web with the wallet or passkey.
2. Settings → Security & Privacy → set up Secure Backup.
3. Finish the key backup setup.
4. Then use "Link new device" for Element X.

The server cannot detect this condition, because the private keys live on the
sending device. An earlier approval-time warning based on the published master
key raced first-time key setup and warned healthy users; it was removed in June
2026.

## Cross-signing

- **First-time setup** works without user-interactive auth (MSC3967) as long as
  the user has no cross-signing keys yet. Element Web releases before the fix in
  [element-web#30141](https://github.com/element-hq/element-web/pull/30141)
  (merged 2025-06-17) skipped setup after a login through a delegated auth
  service.
- **Reset** needs the MSC4312 grant. siwx-oidc grants it at every sign-in, and
  the client can also send the user to
  `/account?action=org.matrix.cross_signing_reset`. If the reset result is
  "unconfirmed", the grant was planted but the follow-up readback failed; retry
  the upload.
- **What to check**: Synapse's logs around `keys/device_signing/upload`, the
  browser console for `bootstrapCrossSigning` and `keys/device_signing/upload`
  requests, and siwx-oidc's logs for `allow_cross_signing_reset`.

The [`cross-signing-bootstrap-and-debug`](../skills/cross-signing-bootstrap-and-debug.md)
skill has the full flowchart.

## Case study: Element X passkey-first login

A resolved case, kept because the failure mode can return.

**Goal.** On Element X mobile, a user enters the homeserver, creates a passkey
with biometrics, and lands in a working end-to-end-encrypted session, with no
wallet, no recovery phrase and no manual verification.

**Symptom (May 2026).** The passkey step succeeded, then Element X showed "Can't
confirm your digital identity", and reset failed. Synapse's logs showed that
Element X never called `keys/device_signing/upload`.

**Investigation.**

1. Element Web passkey login worked against the same server, so the sign-in
   itself was correct.
2. QR login worked for users who already had cross-signing, so tokens,
   introspection and scopes were correct.
3. The matrix-rust-sdk code path supports MSC3967 (upload without
   user-interactive auth), so that was not the blocker.
4. Comparing siwx-oidc's metadata with a MAS deployment's found differences.

**Cause.** Cross-signing bootstrap in matrix-rust-sdk failed before the upload
request, because of discovery metadata the SDK expected. The SDK logs such an
error and does not retry or tell the user
([matrix-rust-sdk#1641](https://github.com/matrix-org/matrix-rust-sdk/issues/1641),
[element-meta#2410](https://github.com/element-hq/element-meta/issues/2410),
both open).

**Fix (2026-05-25).** Discovery advertises
`prompt_values_supported: ["login", "create"]`, as MAS does. At the same time
the `m.authentication` object in the homeserver's `/.well-known/matrix/client`
was aligned (its `account` link); later analysis credited the fix to
`prompt_values_supported`. After the change, passkey-first login worked
end-to-end on Element X for iOS; Android was not confirmed at the time.

**Lesson.** When an Element X flow fails with no visible error, diff
`/.well-known/openid-configuration` and `/.well-known/matrix/client` against a
MAS deployment before looking anywhere else.

## Published DID and `/resolve`

- **The profile has `{"did": …}` but no `proof`**: the server runs with an
  ephemeral signing key. Set `SIWXOIDC_SIGNING_KEY_PEM`; the next sign-in
  re-publishes with a proof.
- **Verification fails with "no JWK with kid …"**: the key that signed the proof
  is no longer in `/jwk`. The signing key was rotated without listing the old
  public key in `SIWXOIDC_RETIRED_SIGNING_KEYS_PEM`, or the key was ephemeral.
  The user's next sign-in re-asserts with the current key.
- **"REPLAYED ASSERTION"**: the proof is valid but binds a different MXID. It
  was copied from another account; do not trust it.
- **"ISSUER MISMATCH"**: the `--server` you passed serves a discovery document
  naming a different issuer. Pass the issuer URL itself.
- **`jwks_uri` "is on a different origin"**: the verifier fetches keys only from
  the issuer's own origin. Serve `/jwk` from the issuer's host.
- **The field is never written**: check that `SIWXOIDC_MATRIX_SERVER_NAME` is
  set, and look for `publishing the attested DID profile field failed` or
  `attested DID field NOT asserted` in the logs. The latter means identity
  resolution had to guess at that sign-in; the next healthy sign-in publishes.
- **A user could overwrite `io.inblock.did`**: the homeserver runs without the
  denylist patch ([matrix-integration.md](matrix-integration.md#the-synapse-patch-for-ioinblockdid)).
- **`/resolve` answers 503**: the deployment has no server name or no Synapse
  client. **502**: Synapse could not be asked; the body says what failed. **504**:
  the lookup took more than 10 seconds.
- **A 500 from Synapse on a profile read or write for one account** (Synapse
  1.159 and earlier): that account has no profile row
  (element-hq/synapse#19702). See
  [identity-model.md](identity-model.md#row-less-accounts-and-the-exact-500-rule).

## Inspecting Redis

Use `--scan` rather than `KEYS` on a production Redis; `KEYS` blocks the server
while it runs.

```bash
# Passkey credentials, links and the per-DID index
redis-cli --scan --pattern 'webauthn:credential/*'
redis-cli GET 'webauthn:credential/<cred_id_b64>'
redis-cli --scan --pattern 'webauthn:link/*'
redis-cli SMEMBERS 'webauthn:by_did/<did>'

# Ceremony challenges in flight (120 s)
redis-cli --scan --pattern 'webauthn:challenge/*'

# OIDC sessions (5 minutes); a passkey sign-in stores verified_did here
redis-cli --scan --pattern 'sessions/*'
redis-cli GET 'sessions/<session_id>' | python3 -m json.tool

# Device-code grants (30 minutes)
redis-cli --scan --pattern 'device_codes/*'
redis-cli GET 'device_codes/<device_code>' | python3 -m json.tool
redis-cli --scan --pattern 'user_codes/*'

# Tokens and their metadata (username = localpart, device_id, scope, DID)
redis-cli GET 'token/<access or refresh token>' | python3 -m json.tool
```

Values can contain tokens and DIDs. Treat the output as sensitive.
