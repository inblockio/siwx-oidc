# Passkeys

People can sign in to siwx-oidc with a passkey (WebAuthn). A passkey's P-256
public key determines a `did:key` DID, so a passkey is an identity on its own,
with no wallet and no password. A passkey can also be linked to an existing
wallet identity, so that it signs the user in as their wallet DID.

Environment variables appear here as `SIWXOIDC_…`. The legacy `SIWEOIDC_…`
spelling is still accepted; see [configuration.md](configuration.md).

- [Architecture](#architecture)
- [From passkey to DID](#from-passkey-to-did)
- [Endpoints](#endpoints)
- [Linking a passkey to a wallet](#linking-a-passkey-to-a-wallet)
- [Redis keys](#redis-keys)
- [Scoping the passkey picker](#scoping-the-passkey-picker)
- [New-account creation policy](#new-account-creation-policy)
- [Unknown credentials](#unknown-credentials)
- [Migration notes](#migration-notes)
- [Notes for implementers](#notes-for-implementers)

## Architecture

WebAuthn is an authentication *ceremony*, not a DID method: challenge binding,
origin and RP ID checks, flags and the signature counter all need server-side
session state. So passkeys are implemented in the server layer
(`src/webauthn.rs`), which produces a verified DID, and are not added to
aqua-auth's `DIDMethod` trait (see [architecture.md](architecture.md) and the
[original design plan](design/webauthn-plan.md)).

- **Registration** uses the `webauthn-rs` safe API (`=0.6.1-dev`). New
  registrations require a **discoverable (resident) credential**, so the
  authenticator can offer the user's own passkey without the server listing
  credential IDs. Registration is **create-only**: the passkey is stored with
  an atomic set-if-absent before any index or mirror write, so a credential ID
  that is already registered is refused (HTTP 400,
  `{"error":"registration failed"}`) and the stored passkey, the
  `webauthn:by_did` index and the credential-store mirror stay as they were
  (`registering_an_existing_credential_id_is_refused_and_the_stored_blob_is_unchanged`).
- **Assertion** is verified with aqua-auth's `verify_webauthn_assertion`
  (P-256), against the challenge stored for the session. The server also
  requires the **user-verification** flag and rejects a **signature-counter
  regression** (a possible cloned authenticator).
- **Sign-in.** After a successful assertion, `/webauthn/authenticate/finish`
  stores the verified DID in the Redis session. `/sign_in` then trusts that
  server-side value instead of a client-supplied CAIP-122 cookie, and continues
  as for any other sign-in (see
  [matrix-integration.md](matrix-integration.md#provisioning-at-sign-in)).
- **Relying Party.** `SIWXOIDC_RP_ID` defaults to the host of
  `SIWXOIDC_BASE_URL`, and `SIWXOIDC_RP_ORIGIN` to the base URL. Browsers only
  offer passkeys registered for the exact RP ID.
- For passkey sign-in, `"key"` must be in `supported_did_methods` (it is in the
  default).

## From passkey to DID

```
passkey P-256 public key → compressed SEC1 (33 bytes) → multicodec p256-pub → base58btc
                         → did:key:zDn…
```

The derivation is aqua-auth's (`p256_compressed_from_passkey`,
`did_key_from_p256_compressed`), the same encoding as its `did:key` module.
From there the Matrix ID follows the usual rules
([identity-model.md](identity-model.md#the-matrix-id-derivation-and-grandfathering)).
Each passkey is its own DID, so two passkeys are two accounts unless one is
linked to the other's identity.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /webauthn/register/start` | registration options (`CreationChallengeResponse`) |
| `POST /webauthn/register/finish` | verify the attestation, store the credential if its id is new; returns `{did, credential_id}`, or 400 `{"error":"registration failed"}` for an id already registered |
| `POST /webauthn/authenticate/start` | assertion options, scoped by the `siwx_user` cookie (below), plus `detected_mxid` |
| `POST /webauthn/authenticate/finish` | verify the assertion, store the verified DID; returns `{ok, did, new_user, mxid}` |
| `POST /link/webauthn/start` | begin registering a passkey for the caller's wallet DID |
| `POST /link/webauthn/finish` | verify the attestation, store the credential and the link |
| `POST /device/passkey/start`, `/device/passkey/finish` | approve a device-code login with a passkey |
| `POST /account/passkey/start`, `/account/passkey/finish` | re-authenticate for an account action |

Every ceremony runs inside the OIDC session started by `GET /authorize`
(`session` cookie). After registering, the login page immediately runs a sign-in
with the new passkey.

## Linking a passkey to a wallet

A wallet user can register a passkey that signs them in as their **wallet DID**
rather than as a new `did:key`:

1. After a wallet signature, the login page offers "Link a passkey".
2. `POST /link/webauthn/start` verifies the `siwx` cookie (the CAIP-122 message,
   signature and session nonce) to prove the caller controls the wallet DID.
3. `POST /link/webauthn/finish` stores the credential and a link entry
   `webauthn:link/{cred_id}` → `{primary_did, label}`.
4. At every later assertion, `credential_identity::resolve_credential_identity`
   applies the rule: a link entry **overrides** the DID derived from the
   passkey. Signing in with that passkey produces the wallet DID.

## Redis keys

| Key | TTL | Content |
|---|---|---|
| `webauthn:ceremony/{sha256(ceremony id)}` | 120 s | ceremony state (registration state or assertion challenge), read and deleted in one step |
| `webauthn:credential/{cred_id_b64}` | none | the stored passkey (serialised `webauthn_rs::Passkey`, including its counter) |
| `webauthn:link/{cred_id_b64}` | none | `{primary_did, label}` for a linked passkey |
| `webauthn:link_ceremony/{sha256(session id)}` | 120 s | link ceremony state and the wallet DID |
| `webauthn:by_did/{did}` | none | set of credential IDs that resolve to the DID |
| `siwx_user/{sha256(token)}` | 30 days | opaque login user session: token → DID (indexed under `idx:own_sessions/…`; a legacy `user:session/{token}` is read until it expires) |
| `device_code/{sha256(device code)}` | 1800 s | device-code grant state (with the user code's digest) |
| `user_code/{sha256(user code)}` | 1800 s | user code → the device code's digest |

Ceremony, device and user codes are keyed by their digest so the store never holds a value a
client presents; entries a build before digest keys wrote under `webauthn:challenge/`,
`webauthn:link_challenge/`, `device_codes/` and `user_codes/` are read until they expire. See
[architecture.md](architecture.md#redis-keyspace).

For login and linking, `{session_id}` is the OIDC session. The device-approval
flow uses `device_passkey_{user_code}`, and the account page uses
`account_passkey_{uuid}`, which the start response returns to the page.

**The `webauthn:by_did` index** is maintained when a passkey is registered
(under its `did:key`) and when one is linked (under the wallet DID), and pruned
on erasure. It is advisory: if it is missing, `get_passkeys_for_did` scans the
credential keyspace and fills it back in
(`get_passkeys_for_did_scan_fallback_equals_index`), so a missed update costs a
scan and never hides a passkey. A failed index update never fails the
registration.

**Optional shared credential store.** Setting `AQUA_WEBAUTHN_REDIS_URL` makes
siwx-oidc also write credentials to aqua-auth's credential store at that Redis
(dual-write) and read from it first, falling back to the keys above. The keys
above stay authoritative, so turning it off loses nothing. Link entries are
never mirrored. Existing passkeys are backfilled by the `migrate-credentials`
tool (`src/bin/migrate-credentials.rs`, shipped in the image next to the
server): `migrate-credentials [--apply] [--source-redis URL] [--target-redis URL]`.
It is a dry run unless given `--apply`, only adds keys, and can be re-run; the
logic is the library module `credential_migration`. If the variable names a
Redis that cannot be opened, the server refuses to start.

## Scoping the passkey picker

A usernameless (discoverable) sign-in sends an empty `allowCredentials`, so the
platform shows every passkey the user has for the RP. For a returning user,
`/webauthn/authenticate/start` narrows the offer to that user's own passkeys,
but only when the caller proves who they are with an **opaque server token**,
never with an identifier the client supplies.

- **The `siwx_user` cookie.** Set after a successful `/sign_in` and after an
  account re-auth: `Path=/`, `HttpOnly`, `SameSite=Strict`, `Secure` on https,
  `Max-Age` 30 days. Its value is a random token; the DID lives only in Redis, under
  the token's digest (`siwx_user/{sha256(token)}`). It is separate from the
  `acct_session` cookie of the account page (`Path=/account`).
- **Ending it.** The account page's **Sign out** (`POST /account/sign_out`) ends this
  browser's hint and account session and clears both cookies. `logout/all`,
  deactivation and erasure end every hint and account session of the user. RP-initiated
  logout (`/end_session`) leaves the hint alone: it ends an RP's grant, the hint is not
  a session at this provider (it authorizes nothing), and a navigation to `/end_session`
  from an RP on another site does not carry the `SameSite=Strict` cookie anyway.
- **Scoping.** `authenticate_start` looks up the token, and sets
  `allowCredentials` to exactly the credentials of that DID: its own passkeys
  plus any linked to it. The response adds `detected_mxid`
  (`@localpart:server`) only when scoped, so the page can show "signing in as".
  The device-approval and account pages scope their pickers the same way.
- **No passkeys for that DID** (for example a wallet-only user): the offer stays
  usernameless rather than presenting an empty list that blocks every key.
- **Escape hatch.** `{"all": true}` in the body, or `?all=1`, forces a
  usernameless offer even with a valid cookie ("use a different passkey").
- **No method prediction.** The server does not predict which sign-in methods
  will work on the device. Wallet availability is detected in the browser, and
  the passkey button is always offered; the ceremony itself decides. See
  [the 2026-06-19 design note](design/2026-06-19-passkey-offer-scoping-minimal-behavior.md).

**Enumeration-safety invariant.** A forged, guessed or expired `siwx_user`
value is a Redis miss, so the request is treated as usernameless: it reveals no
credential IDs and no `detected_mxid`. The hint is never a plaintext DID or a
free-form identifier. The scoping is only an offer: the assertion is still
verified, and the account and device gates still run under the proven DID.

## New-account creation policy

An unrecognised passkey or wallet resolves to a DID with no Matrix account, and
signing in would create one. Accounts may be created **only through the login
flow**; the account page and the QR/device approval refuse.

"New" is decided read-only, before any Synapse write, by
`localpart::resolve_identity` (`ResolvedIdentity.is_new`): true only when
**neither** the legacy nor the modern localpart is taken.

| Flow | New identity |
|---|---|
| **Passkey login** (`/webauthn/authenticate/finish`) | **Confirm first.** `finish` returns `{ok, did, new_user: true, mxid}` and provisions nothing. The login page shows "this passkey will create a new account" with *Continue* and *try another passkey*. Provisioning happens only at `/sign_in`, after *Continue*; cancelling leaves no Synapse state. |
| **Wallet and headless-key login** (`/sign_in`) | Created at `/sign_in`. There is no separate confirmation step; the signature is the explicit act. |
| **Account re-auth** (`/account/wallet`, `/account/passkey/finish`) | **Refused** by `reject_if_new_identity`: 400 with `NEW_IDENTITY_REJECT_MSG`, or 503 when the check could not run. |
| **QR/device approval** (`/device`, `/device/passkey/finish`) | **Refused** the same way, before the device code is marked approved, so the token grant never provisions. |

`new_user` and `mxid` are reported only when a Synapse client (and, for `mxid`,
a server name) is configured; otherwise `new_user` is `false` and `mxid` empty.

### 400 and 503 are different answers

`reject_if_new_identity` **fails closed**, and reports two facts differently:

| Outcome | Status | Message |
|---|---|---|
| The check ran and found no account | 400 | `NEW_IDENTITY_REJECT_MSG`: "This passkey/wallet is not linked to an existing account. Create an account at sign-in first." |
| The check could not run (Synapse unreachable, shared secret rejected) | 503 | `IDENTITY_CHECK_UNAVAILABLE_MSG`: "The server could not complete a required account check right now. Nothing has been changed. …" |

Nothing is provisioned either way. Until 2026-09-12 both cases returned the
first message, which told users with a working account to create one because of
a fault they could not fix. The 503 message names the server as the problem and
reveals nothing operational
(`the_detection_failure_message_leaks_no_server_internals`).

The deactivation gate (`reject_if_deactivated`) makes the same split: 401 with
`DEACTIVATED_REJECT_MSG` when the account is deactivated, 503 with
`DEACTIVATION_CHECK_UNAVAILABLE_MSG` when the check could not run. The two
"could not run" messages are deliberately identical
(`the_two_unavailable_messages_are_deliberately_indistinguishable`), so they do
not reveal which gate was passed. Every call site of both gates runs after the
caller has proven control of the DID, so answering "deactivated" leaks nothing
to a stranger. Both gates are no-ops without a Synapse client. Where each gate
runs is summarised in
[matrix-integration.md](matrix-integration.md#gates-that-protect-accounts).

## Unknown credentials

A passkey the server does not know (stored in a different Redis, lost with a
flushed Redis, or removed by erasure) is not a server error.
`verify_credential` returns `VerifyError::UnknownCredential` for exactly that
case: the credential lookup missed. Every other failure (challenge, signature,
flags, counter) stays an internal error.

The handlers answer **401** with a machine-readable body:

```json
{ "error": "unknown_credential",
  "credential_id": "<base64url id the client presented>",
  "message": "This passkey is no longer valid on this server. Remove it from your device's passkey settings, or sign in another way and register a new passkey." }
```

The login, device-approval and account pages key on `error` and, where the
browser supports it, call
`PublicKeyCredential.signalUnknownCredential({rpId, credentialId})` so the
platform removes the stale passkey from its picker. This reveals nothing: it
echoes only the ID the client just presented. Browser support is partial, so the
401 and its message are the guaranteed behaviour. The signal is sent only for
this discriminator, so a valid passkey is never pruned because of an unrelated
failure.

`signalAllAcceptedCredentials` is not implemented.

## Migration notes

- **Passkeys registered before discoverable credentials were required** may be
  non-resident. The usernameless picker cannot surface them, and the server
  cannot fix that, because it never stored them as resident. The way forward is
  to sign in another way and register a new passkey (or link one to the wallet).
  The unknown-credential message points users there.
- **Erasure removes passkeys.** `account_erase` deletes the DID's link entries
  and their credentials, and any standalone passkey whose key derives to that
  `did:key`, so an erased identity cannot be signed into again from a leftover
  passkey.
- **Redis must be persistent.** Credentials have no TTL. A Redis without
  persistence loses every registered passkey on restart, and every user then
  hits the unknown-credential path.

## Notes for implementers

- **The picker hint is an opaque server token, never a DID or a client-supplied
  identifier.** A miss must fall back to usernameless.
- **The picker is only an offer.** Authorization always runs under the DID the
  assertion proved.
- **Keep the credential lookup before signature verification** in
  `verify_credential`; that ordering is what makes an unknown passkey a 401
  rather than a 500. Only `VerifyError::UnknownCredential` may trigger
  `signalUnknownCredential`.
- **A link entry overrides the derived DID**, and that rule lives only in
  `credential_identity::resolve_credential_identity`.
- **New accounts are created only through login.** `reject_if_new_identity` and
  `reject_if_deactivated` fail closed, and report "could not check" (503)
  separately from the finding itself.
- **The `webauthn:by_did` index is advisory.** A failed index write must never
  fail a registration or link.
