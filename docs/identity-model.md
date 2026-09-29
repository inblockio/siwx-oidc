# Identity model

Every account in siwx-oidc carries three identifiers, and each has a different
owner. Most identity bugs in this area come from treating two of them as the
same thing. This page defines the three identifiers, the wire format of the
provider-signed DID binding, how to verify it, and how to look an identity up.

Environment variables appear here as `SIWXOIDC_…`. The legacy `SIWEOIDC_…`
spelling is still accepted; see [configuration.md](configuration.md).

- [The three tiers](#the-three-tiers)
- [The Matrix ID: derivation and grandfathering](#the-matrix-id-derivation-and-grandfathering)
- [The alias](#the-alias)
- [The `io.inblock.did` profile field](#the-ioinblockdid-profile-field)
- [Trust model: a discovery hint, never an authorization source](#trust-model-a-discovery-hint-never-an-authorization-source)
- [The signing key and its `kid`](#the-signing-key-and-its-kid)
- [Publication](#publication)
- [Verifying a published DID](#verifying-a-published-did)
- [Looking up an identity: `GET /resolve`](#looking-up-an-identity-get-resolve)
- [The `io.inblock.mxid` userinfo claim](#the-ioinblockmxid-userinfo-claim)
- [Notes for implementers](#notes-for-implementers)

## The three tiers

| Tier | Value | Owner | Mutable | Where it lives |
|---|---|---|---|---|
| **Alias** | a generated pseudonym, `Firstname Surname` (`alias::alias_for`) | **the user** | yes, freely | Synapse `displayname` |
| **MXID** | `@{localpart}:{server_name}`, localpart = 16 lowercase base36 characters (`mxid::localpart_for`) | derived from the DID | **no**, Synapse has no user-rename API | Synapse `users` row |
| **DID** | `did:key:…` / `did:pkh:…`, plus the provider's signature | **the provider** | **no** | Synapse profile field `io.inblock.did` |

The DID is also the OIDC `sub` claim of every ID token this provider issues.
That is the identity an application authorizes on (see the
[trust model](#trust-model-a-discovery-hint-never-an-authorization-source)).

### The boundary is structural

Synapse's write guard for custom profile fields sits in
`ProfileHandler.set_profile_field`. A write to `displayname` goes through
`set_field` → `set_displayname` and never passes that method. So the alias
**cannot** be locked, and the DID field **cannot** be written by the user, by
construction. This was measured on one Synapse image
([2026-09-10 ACL probe](audits/2026-09-10-msc4133-acl-probe.md), leg 5): a
plain user's `PUT` to `displayname` answers **200**, their `PUT` to
`io.inblock.did` answers **403**. Adding `displayname` to the denylist would
change nothing.

The write protection of `io.inblock.did` needs a patched Synapse. See
[matrix-integration.md](matrix-integration.md#the-synapse-patch-for-ioinblockdid).

### Why the split exists

Until 2026-09-10 tiers 1 and 3 were the same field. `provision_user`'s second
argument is the user's displayname, and it was passed the raw DID. The only
published copy of a user's DID therefore lived in a field the user can rewrite,
and a consumer that read displayname as the DID could be handed **someone
else's** DID. The displayname is now seeded with a generated alias, and the DID
lives in its own write-protected field with a provider signature.

## The Matrix ID: derivation and grandfathering

### The modern localpart

`mxid::localpart_for(did)` is:

```
localpart = base36( first 10 bytes of SHA-256( canonicalize(did) ) )
            left-padded with "0" to exactly 16 characters, alphabet [0-9a-z]
```

- **Exactly 16 characters, one alphanumeric run, no separators.** Every output
  fits Synapse's length and character limits for any DID of any length.
- **80 bits of hash.** `did:key` and `did:peer` identities are self-issued, so
  anyone can generate keys in bulk. Two DIDs that hash to the same localpart
  would be the *same* Matrix account, so the width is chosen against an
  attacker grinding keys toward a target's localpart, not against accidental
  collisions. `36^16 ≈ 2^82.7`, so the 80-bit value always fits without
  truncation.
- **Why it is short.** The older derivation (below) produced MXIDs of 80+
  characters made of five hyphen-separated words. In an A/B test we ran on
  2026-09-09 (see the comment in `src/mxid.rs`), matrix.org's policy server
  refused long DID-derived MXIDs and accepted the 16-character form. This is
  our own observation, not documented matrix.org behaviour.

### Canonicalisation is method-aware

`mxid::canonicalize(did)` lowercases **only** `did:pkh`:

- `did:pkh:*` is lowercased. The mixed case of an `0x…` Ethereum address is an
  EIP-55 checksum, not identity, so a mixed-case and an all-lowercase wallet DID
  are one account.
- `did:key:*` and `did:peer:*` keep their case. They are multibase base58btc,
  where case is part of the encoded key. Lowercasing would map two different
  public keys onto one account.

Any other method is passed through unchanged (case preserved by default).

### The legacy localpart

`mxid::legacy_localpart(did)` replaces `:` with `-` and lowercases the whole
string: `did:pkh:eip155:1:0x7a76…` becomes `did-pkh-eip155-1-0x7a76…`. Every
account created before 2026-09-09 is keyed on this shape. Synapse has no rename
API, so this function is permanent.

### Grandfathering: which shape does a DID get?

`localpart::resolve_identity(did, synapse)` decides, in order:

1. No Synapse client configured: the legacy localpart, `is_new: false`
   (standalone deployments have no Matrix account to protect).
2. The legacy localpart is **in use**: keep it. The account predates the new
   scheme.
3. The legacy localpart is **unusable** (Synapse answered `M_INVALID_USERNAME`
   or `M_EXCLUSIVE`, and nothing else): fall through to the modern probe. No
   account can exist under a name Synapse refuses, so no one is cut off from an
   account. A very long `did:peer:2`, whose legacy form exceeds Synapse's
   255-character user ID limit, takes this path.
4. The modern localpart is **in use**: use it (already migrated, or created
   under the new scheme).
5. The modern localpart is **available**: use it, `is_new: true`. No account
   exists under either shape.
6. The modern localpart is **unusable**: a hard error. This should be
   unreachable and is treated as a misconfiguration.

Every probe error is returned as an error, never as a verdict. In particular, a
rejected MAS shared secret (401/403) is an error, never "the localpart is
taken". See the
[2026-09-12 availability audit](audits/2026-09-12-localpart-availability-conflation.md)
for what went wrong when these were conflated.

### The fail-safe direction is LEGACY

`localpart::resolve_identity_or_legacy` is the infallible variant used where a
request must produce *some* localpart (sign-in provisioning, the device-code
grant, and the cosmetic "signing in as" display). On any probe error it returns
the **legacy** localpart with `degraded: true`, never the modern one.

- Guessing legacy for a new user yields a badly shaped but working account,
  which is recoverable.
- Guessing modern for an existing user cuts them off from their rooms, DMs and
  keys, and Synapse cannot rename the account back. That is not recoverable.

The asymmetry does not change as the share of modern accounts grows. A
`degraded` identity is still provisioned, but its DID binding is **not
published** (see [Publication](#publication)): a signed assertion for a guessed
MXID would be a second account claiming the same DID with provider authority.

Callers that can afford to fail instead of guessing use the fallible
`resolve_identity`: `GET /resolve`, the deactivation gate, the new-identity
gate, and every account-management action.

### The MXID cannot be turned back into a DID

The localpart is a hash. A `did:key` "reconstructed" from a legacy localpart is
a **different key**, because the legacy form was lowercased (in one real case
17 of 48 base58 characters differed; tracked as siwx-oidc#17). Obtain a DID from
the OIDC `sub` claim or from the `io.inblock.did` field, and compare DIDs
byte-for-byte (with the `did:pkh` case-folding above).

## The alias

`alias::alias_for(did)` derives a human-readable name (`"Firstname Surname"`)
from the DID. It is the displayname a new account starts with.

- **Seed**: `SHA-256("siwx-oidc/alias/v1\0" || mxid::canonicalize(did))`. The
  same canonicalisation as the MXID, so a mixed-case `did:pkh` and its lowercase
  twin get one name. The domain prefix keeps it from being a second projection
  of the MXID's digest.
- **Words**: the first name is indexed by digest bytes 0..4, the surname by
  bytes 4..8, each `mod` its list length. The lists hold 271 first names and 306
  surnames (82,926 combinations).
- **Collisions are expected.** The first one is due around 288 accounts. The
  alias is decoration: Matrix clients disambiguate duplicate display names by
  MXID, and the DID is published separately. Never key anything on it.
- **It carries no DID and no key material**, so it cannot be mistaken for an
  identifier.
- **Written once**, at first sign-in (and by the self-heal that recreates a
  missing profile row). It is never re-asserted, so a name the user chooses
  survives every later sign-in.
- **Append-only lists.** An index is `digest mod len`, so appending changes what
  *future* accounts are seeded with, never what an existing account shows.
  Reordering or deleting entries has the same effect and no benefit.

The alias is a deterministic public function of the DID, so anyone holding a
candidate DID can compute it and compare. That confirms nothing beyond what the
`io.inblock.did` field already publishes. If the DID-to-account binding ever
had to become private, the alias would need a different seed.

### Migration of names the provider wrote

An existing account whose displayname is **byte-equal** to a string the
provider itself once seeded (the raw DID, before 2026-09-10, or the bare
localpart, 2026-09-10 to 2026-09-11) is rewritten to the alias at its next
sign-in. Anything else is left alone, including a displayname the user
**cleared** (Synapse reports that as a profile with no `displayname`). The
comparison is exact, never a prefix or case-folded match: the test is "nothing
but our own provisioning could have produced this exact string". Implemented by
`provider_written_displayname` in `src/oidc.rs`.

## The `io.inblock.did` profile field

### Value

The field holds one JSON **object**, written in a single `PUT`
(`did_assertion::did_profile_value`):

```json
{ "did": "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB",
  "proof": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6…" }
```

- `did` is the DID in its **exact case**, never normalised or lowercased.
- `proof` is **absent** (not `null`, not `""`) when the provider's signing key
  is ephemeral. See [the signing key](#the-signing-key-and-its-kid).
- One field rather than two (`…did` and `…did.proof`): one write cannot leave
  the DID and its proof out of step, and it is one entry in the homeserver's
  denylist.

### `proof`: a compact ES256 JWS

RFC 7515 §3.1 compact serialisation:

```
signing_input = BASE64URL(header_json) "." BASE64URL(payload_json)
signature     = ES256 over signing_input: raw r‖s, exactly 64 bytes, never DER
proof         = signing_input "." BASE64URL(signature)
BASE64URL     = base64url without padding

header_json  = {"alg":"ES256","typ":"JWT","kid":"<key fingerprint>"}
payload_json = {"iss":"<issuer>","sub":"<exact-case DID>","mxid":"@<localpart>:<server_name>","iat":<unix seconds>}
```

- Member order in both documents is the declaration order of
  `DidAssertionHeader` and `DidAssertionClaims`. A conforming verifier checks
  the received bytes, so order does not affect verification, but it is fixed.
- `iss` is the provider's issuer (`SIWXOIDC_BASE_URL`), the value OIDC discovery
  reports as `issuer`.
- `sub` is the DID, the same claim the ID token carries, so a consumer can
  compare assertion `sub` to ID-token `sub` with no translation step.
- `mxid` is the account the assertion binds. It is what stops replay: a
  verifier must compare it to the account the proof was read from.
- **There is no `exp`.** The binding is permanent: localparts are not recycled
  and a DID does not stop belonging to its user. An expiry would turn a
  statement that stays true into a credential that goes stale, and would require
  re-minting for accounts that may never sign in again. The test
  `payload_has_no_exp_claim` fails if one is added.

The same signing routine (`EcdsaSigningKey::sign_es256`) signs ID tokens and
assertions, so the two cannot use different signature encodings
(`signature_is_64_raw_bytes_never_der`).

### The field name is a three-sided contract

The literal `io.inblock.did` must match in three independently deployed places,
and a mismatch fails silently:

| Side | Where |
|---|---|
| provider | `DID_PROFILE_FIELD` in `src/did_assertion.rs` |
| consumer | `DID_PROFILE_FIELD` in `siwx-oidc-auth/src/did_assertion.rs` (checked equal by the interop tests) |
| homeserver | `experimental_features.msc4133_key_denylist` in the Synapse configuration (see [matrix-integration.md](matrix-integration.md#the-synapse-patch-for-ioinblockdid)) |

A rename is a migration, not an edit. All three sides move together, and
consumers must read both names for a full upgrade cycle, or every account that
has not signed in since the rename reads as "no published DID". The homeserver
side fails **open**: a denylist that still names the old field leaves the new
one user-writable.

The name must satisfy Synapse's namespaced identifier grammar
`^[a-z][a-z0-9_.-]{0,254}$`, which excludes uppercase and colons. That is also
why a DID can never be a field *name*.

## Trust model: a discovery hint, never an authorization source

**Authorization MUST resolve the DID from the OIDC `sub` claim of a token this
provider issued, or from a fresh signature by the DID's own key.** A DID read
from a profile, with or without a proof, tells you what to *look up*, never what
to *permit*.

A verified assertion proves one thing: **the issuer asserted this DID ↔ MXID
binding at `iat`**. It does not prove that whoever you are talking to controls
the DID key now, and it grants nothing.

Two further limits:

- **The issuer is the trust anchor, and the verifier chooses it.** A homeserver
  operator controls which issuer their homeserver advertises and can sign any
  binding they like. For a federated peer, a verified result is as trustworthy
  as that peer's operator. Only a signature by the DID's own key could do
  better, and the assertion format carries none.
- **Everything in this object is world-readable, forever.**
  `GET /_matrix/client/v3/profile/{user}/{field}` requires authentication only
  when Synapse's `require_auth_for_profile_requests` is set, which defaults to
  false, and custom profile fields federate. Nothing private may ever be added:
  no email, no session ID, no internal identifier.

## The signing key and its `kid`

The `kid` of the provider's ES256 key is derived from the key: the first 16 hex
characters of SHA-256 over the SEC1 uncompressed public key
(`EcdsaSigningKey::fingerprint_of`). It is not configured.

Assertions are stored durably in the homeserver, so the `kid` must name the key,
not a slot. With a constant `kid`, a restart that generates a new key would
leave every stored assertion failing as a silent "bad signature"; with a derived
`kid`, the failure is an explicit "kid not present in JWKS"
(`h4_two_generated_keys_get_different_kids`,
`h4_the_same_pem_yields_the_same_kid_across_constructions`).

- **Configured key** (`SIWXOIDC_SIGNING_KEY_PEM`): assertions are minted with a
  `proof`.
- **No configured key**: the provider generates an ephemeral key at startup.
  `mint_did_assertion` then returns `None`, and profiles receive
  `{"did": …}` with **no** `proof`. A proof signed by a key that disappears at
  the next restart would be permanently unverifiable in someone else's
  database. The startup log says so at `warn`.
- **Rotation.** Because assertions have no `exp`, the JWKS at `/jwk` is their
  only verification anchor. List the public half of every retired key in
  `SIWXOIDC_RETIRED_SIGNING_KEYS_PEM`, or proofs already written become
  unverifiable for users who do not sign in again. Retiring a key does not
  neutralise a compromise: a key compromised before retirement can still mint
  proofs that verify. If a key was abused, drop it from the list and let the
  next sign-in re-assert. Details in
  [configuration.md](configuration.md).

## Publication

- **One call site.** The field is written by `oidc::provision_synapse_device`,
  which both sign-in paths use: `/sign_in` (wallet, passkey, headless key) and
  the device-code grant (QR login). The issuer written into `iss` is
  `SIWXOIDC_BASE_URL`, the value discovery reports.
- **Best-effort.** A publication failure never fails a sign-in. Every outcome is
  logged, the same contract as device provisioning and the cross-signing reset
  grant next to it.
- **Re-asserted on every sign-in.** Synapse's write guard is prospective only:
  it blocks new user writes but does not validate a value written before the
  denylist existed (upstream shares the gap; review thread `r3783167037` on
  element-hq/synapse#19980). Re-asserting at every sign-in corrects a clobbered
  value at the user's next login, with no migration job. The write is
  idempotent. Covered live by `clobbered_did_field_is_restored_at_next_signin_live`.
- **Not asserted for a guessed identity.** When identity resolution was
  `degraded` (Synapse unreachable, legacy localpart guessed), the assertion is
  skipped for that sign-in and written at the next healthy one.
- **Requires `SIWXOIDC_MATRIX_SERVER_NAME`.** The assertion binds an MXID, which
  cannot be built without the server name. A standalone deployment skips
  publication; it never fails and never guesses an MXID.
- **Wire details.** `PUT /_matrix/client/v3/profile/{mxid}/io.inblock.did` with
  body `{"io.inblock.did": <value>}`, authenticated with a **minted admin-scoped
  token** (see
  [matrix-integration.md](matrix-integration.md#admin-scoped-token-mint)); the
  MAS shared secret is not accepted on this route. On 401/403 the client
  re-mints once. The MXID is a percent-encoded path segment here, while the
  `/_synapse/mas/*` routes take a bare localpart in the body. A **404** on this
  `PUT` means the homeserver does not know the user (or has no MSC4133 profile
  route), not that the field is unset.

### Row-less accounts and the exact-500 rule

An account with a `users` row but no `profiles` row
(element-hq/synapse#19702) answers **500** on profile reads and writes where a
healthy account answers 404 (affected: Synapse 1.160 and earlier; 1.161 fixes
some of the paths (#20149, #20172); #19702 remains open upstream; not
re-verified against this deployment). #20149 and #20172 cover custom-field
reads and admin writes, which may not include the displayname write the
self-heal depends on.

The handling stays in place:

- `classify_publish_status` treats **exactly** 500 as "possibly row-less", and
  deliberately not `is_server_error()`: 502/503/504 stay hard errors, so an
  outage is never reported as a known upstream bug.
- A 500 alone is only a hypothesis. A follow-up probe of the whole profile
  (`SynapseClient::has_profile_row`) must confirm the row is absent (a 404 with
  `errcode: M_UNKNOWN`) before the outcome is reported as
  `PublishOutcome::RowLessAccount` and logged at `warn`. Twisted's generic 500
  body is identical for an exhausted database pool, so the status code alone
  proves nothing. Anything unconfirmed is an error.
- `RowLessAccount` is a separate outcome from `Written` because "published" and
  "state unknown" are different facts.

## Verifying a published DID

### From the command line

```bash
siwx-oidc-auth --verify-did '@k3f9x2q7ab4d8m1p:example.org' \
  --homeserver https://matrix.example.org \
  --server     https://auth.example.org   # the ISSUER: a trust anchor, not a hint
```

On success it prints the verified binding:

```json
{ "did": "did:key:zDn…", "mxid": "@k3f9x2q7ab4d8m1p:example.org",
  "issuer": "https://auth.example.org/", "issued_at": 1757500000 }
```

Reading and verifying needs no key, no client ID and no token: the profile read
is anonymous and the JWKS is public. Sending a token would only reveal the
caller to every homeserver it polls.

### From Rust

```rust
use siwx_oidc_auth::{fetch_and_verify_did, DidAssertionError};

match fetch_and_verify_did("https://matrix.example.org",
                           "@k3f9x2q7ab4d8m1p:example.org",
                           "https://auth.example.org").await {
    Ok(v) => println!("{} is bound to {} (asserted at {})", v.did(), v.mxid(), v.issued_at()),
    Err(e) => match e.downcast_ref::<DidAssertionError>() {
        Some(DidAssertionError::FieldAbsent { .. }) => { /* no published DID */ }
        Some(DidAssertionError::ProofAbsent { .. }) => { /* unsigned: treat as absent */ }
        _ => { /* any other failure: do not trust the DID */ }
    },
}
```

- `fetch_and_verify_did(homeserver, mxid, issuer)` is the entry point to use. It
  passes the MXID it fetched **from** as the MXID it verifies **against**, so the
  replay check cannot be forgotten.
- `verify_did_assertion(issuer, jws, expected_mxid)` verifies a proof you already
  hold. `expected_mxid` is required; there is no unbound variant.
- Both return `VerifiedDid`, whose accessors `did()`, `mxid()`, `issuer()` and
  `issued_at()` all come from the signed payload. The type has no public
  constructor and does not implement `Deserialize`, so holding one means a
  verification ran (`verified_did_cannot_be_deserialized`).

### What the verifier checks, in order

1. Exactly three dot-separated parts.
2. The header, **before any network request**: `alg` must be `ES256`; `none` and
   the `HS*` family are rejected by name (RFC 8725 §3.1); any `crit` header is
   rejected (RFC 7515 §4.1.11); `typ` must be `JWT` or absent; `kid` must be
   present.
3. Discovery is fetched from `{issuer}/.well-known/openid-configuration`, and
   its `issuer` must equal the URL it was fetched from (OpenID Connect Discovery
   1.0 §4.3; only a trailing slash is forgiven).
4. `jwks_uri` must be on the same origin as the issuer (scheme, host, effective
   port).
5. The JWK is selected by `kid` with **no fallback**. An unknown `kid` is a hard
   error that names the `kid`, so a rotated or ephemeral key fails visibly.
6. The JWK's own `use`, `key_ops` and `alg` restrictions are honoured.
7. The signature must be exactly 64 raw bytes (r‖s) and is verified over the
   **received** first two parts, never over re-serialised JSON.
8. `iss` must equal the pinned issuer; `sub` must start with `did:`; `mxid` must
   be byte-equal to the expected MXID; `iat` must be present.

There is no age check, because there is no expiry.

`fetch_and_verify_did` additionally distinguishes:

- **Field absent** (404, or `null`): `DidAssertionError::FieldAbsent`.
- **No `proof`** (ephemeral issuer key, an empty-string proof, or the older bare
  string form): `DidAssertionError::ProofAbsent`, carrying `unverified_did`.
  Treat it as absent, not as a usable DID.
- **Any other failure** (bad signature, wrong issuer, unknown `kid`, replay,
  unreadable profile): an untyped error. The only correct response to all of
  them is the same: do not trust the DID.
- If the object's plain `did` member disagrees with the signed `sub`, the
  **signed** value is returned and a warning is printed. The plain member is
  not covered by the signature.
- A failed profile read (for example a 500) is an error, never "field absent".

### How the two sides are kept compatible

The minter (`src/did_assertion.rs`) and the verifier
(`siwx-oidc-auth/src/did_assertion.rs`) were written independently against one
specification. The `interop_with_the_shipped_verifier` test module mints on the
server side, serves the real JWKS over HTTP, and verifies with the shipped
client verifier, including the replay case. `siwx-oidc-auth` is a
dev-dependency of the server, so the server binary does not link it.

Live coverage against the local end-to-end stack (`#[ignore]`d, run with
`--ignored`), in `tests/e2e_did_field_live.rs`:
`did_field_is_published_verifiable_and_public_live`,
`did_field_user_write_is_forbidden_live`,
`clobbered_did_field_is_restored_at_next_signin_live`.

Element Web's `resolve-did-search` patch (in siwx-oidc-matrix-server) is a
second verifier that follows the same rules in the browser; see
[api/README.md](api/README.md).

## Looking up an identity: `GET /resolve`

The directory lookup for the table above: which Matrix account belongs to a
DID, and which DID a Matrix account publishes. Read-only; it provisions
nothing (`src/resolve.rs`).

```bash
curl -s "https://auth.example.org/resolve?did=did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB"
curl -s "https://auth.example.org/resolve?mxid=@k3f9x2q7ab4d8m1p:example.org"
```

```json
{ "did": "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB",
  "mxid": "@k3f9x2q7ab4d8m1p:example.org",
  "exists": true,
  "attested": true }
```

### Request

- **Exactly one** of `did` or `mxid`. Zero or both is a 400. An empty value
  counts as absent, so `?did=X&mxid=` is one selector. A repeated parameter is a
  400 in the normal error envelope.
- `did` is at most 2048 bytes; `mxid` at most 255 bytes (Matrix's user ID
  limit).
- An `mxid` on a different homeserver is a 400. Read a foreign user's DID from
  that homeserver's own (public, federated) profile route and verify it against
  that homeserver's issuer.

### Response

All four keys are always present, `null` where unknown.

| Field | `?did=` | `?mxid=` |
|---|---|---|
| `did` | the queried DID, or the published spelling when the account publishes the same DID | the DID the account publishes, or `null` |
| `mxid` | the MXID the grandfathering rule resolves (legacy for pre-2026-09 accounts) | the queried MXID |
| `exists` | an account exists under the legacy or the modern localpart | the localpart is taken on this homeserver |
| `attested` | the account's `io.inblock.did` field is present and binds to this DID | the published DID derives to this localpart, under either scheme |

**`attested` verifies no signature.** It compares the field's `did` member,
under `mxid::canonicalize` on the `?did=` path and by re-deriving the localpart
on the `?mxid=` path. An account whose deployment has an ephemeral key (no
`proof`) still reports `attested: true`. A caller that needs cryptographic
assurance runs `siwx-oidc-auth --verify-did`. The shipped server binary does
not link the verifier.

### Errors

Errors use the envelope `{"error": "<code>", "message": "…"}`, plus `mxid` when
one was already resolved. The route never returns 500.

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_request` | the request is wrong (selectors, a malformed or foreign MXID, over-length input, a localpart Synapse refuses) |
| 502 | `upstream_error` | the homeserver could not be asked or gave an unreadable answer; the state is unknown |
| 503 | `unavailable` | this deployment cannot answer: no `SIWXOIDC_MATRIX_SERVER_NAME`, or no Synapse client (standalone) |
| 504 | `upstream_timeout` | the whole lookup exceeded 10 seconds |

The `?did=` path uses the fallible `resolve_identity`, never the
guess-legacy variant. The guess exists so a sign-in does not cut a user off
from their account; a read-only lookup has no account to protect, and a wrong
answer is worse than an honest 502.

### Discovery

When the deployment can answer (server name and Synapse client both
configured), OIDC discovery advertises the endpoint under
`io.inblock.resolve_endpoint`. Synapse forwards unknown discovery keys to
`/_matrix/client/v1/auth_metadata`, so a client can find a homeserver's
resolver there.

### Why it is unauthenticated

Authentication would buy rate limiting, not secrecy:

- DID → localpart is a pure SHA-256 function in the public library crate
  (`mxid::localpart_for`, `mxid::legacy_localpart`). Anyone can compute it
  offline.
- MXID → DID reads a profile field that Synapse serves without authentication
  by default and that federates.
- `exists` is already observable through the same public profile route.

Rate limiting belongs at the reverse proxy. The response stays at four fields:
adding anything a caller could not compute or fetch themselves would break this
argument.

One side effect exists only on homeservers that set
`require_auth_for_profile_requests: true`: the anonymous profile read is
refused, and the lookup retries with a minted admin token. Minting provisions
the provider's admin service user if it is missing and stores a token in Redis.
It never touches the account being looked up. On a stock homeserver it does not
happen.

## The `io.inblock.mxid` userinfo claim

`/userinfo` carries the caller's Matrix ID next to the DID:

```json
{ "iss": "https://auth.example.org/", "aud": ["my-client"],
  "sub": "did:key:zDn…", "preferred_username": "did:key:zDn…",
  "io.inblock.mxid": "@k3f9x2q7ab4d8m1p:example.org" }
```

- Namespaced because no registered claim exists for a Matrix ID, and named to
  match `io.inblock.did`. The wire name is a serde `rename` literal, checked by
  `userinfo_mxid_claim_tests::the_claim_name_on_the_wire_is_io_inblock_mxid`.
- Built from the localpart recorded at sign-in (`TokenMetadata.username`) and
  `SIWXOIDC_MATRIX_SERVER_NAME`. No Synapse round trip and no re-derivation,
  which could contradict the grandfathering decision made at sign-in.
- **Omitted, never `null`,** when there is no server name, or when an old
  authorization-code entry records no localpart. Consumers then fall back to
  `GET /resolve?did=…`.
- `sub` and `preferred_username` are unchanged (both the DID). The claim is in
  both the JSON and the signed-JWT userinfo variants
  (`userinfo_signed_response_alg`).

## Notes for implementers

These rules protect properties that are easy to break by "simplifying" code.
Each is enforced by a test or explained in the code at the named symbol.

- **Never seed or read the displayname as a DID.** The alias tier exists so the
  DID never lives in a user-writable field.
- **Never rebuild a DID from a localpart.** Resolve it from `sub` or the
  `io.inblock.did` field; compare byte-for-byte under `mxid::canonicalize`.
- **Keep canonicalisation method-aware.** Fold case for `did:pkh` only.
- **The fallback localpart is legacy, never modern**, and a `degraded` identity
  is never published.
- **`Unusable` is an errcode allowlist** (`M_INVALID_USERNAME`, `M_EXCLUSIVE`).
  Widening it lets a transient upstream fault read as "no account can exist".
- **Do not add `exp` to the assertion**, and do not add an age check to the
  verifier.
- **`proof` is absent, never `null` or `""`,** when the key is ephemeral.
- **Do not reintroduce a caller-supplied `kid`**, and do not make `kid`
  optional. Both constructors go through `with_derived_kid`.
- **Signatures are raw r‖s, never DER.**
- **Do not add an unbound verifier.** The MXID binding inside
  `fetch_and_verify_did` is the security property.
- **Keep the exact-500 rule** in `classify_publish_status`, and keep the
  confirmation probe before reporting `RowLessAccount`.
- **Nothing private in `io.inblock.did`**, and nothing beyond four fields in
  `/resolve`.
- **Renaming the field is a three-sided migration** with a dual-read period.
- **Append to the alias lists; never reorder.**
- **`io.inblock.mxid` is omitted, never `null`.**
