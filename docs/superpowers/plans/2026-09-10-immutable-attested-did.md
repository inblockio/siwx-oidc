# Plan — an immutable, provider-attested DID identity attribute

**Date:** 2026-09-10. **Branch:** `feat/opaque-mxid-localpart` (off `dev`).
**Predecessor:** the opaque-localpart migration, committed at `c2cab99`.
**Handover this executes:** `docs/2026-09-10-HANDOVER-did-publication-and-field-protection.md` §3.

---

## The goal, in one sentence

Give every siwx-oidc user exactly **one** DID that a relying party can read from
their Matrix profile, that the user cannot alter, and that carries the
provider's signature proving it is theirs.

## The three-tier identity model this establishes

| Tier | Value | Owner | Mutable? | Where it lives |
|---|---|---|---|---|
| **Alias** | a human display name | **the user** | yes, freely | Synapse `displayname` |
| **MXID** | `@{base36(sha256(did)[..10])}:{server}` | derived | no (no rename API) | Synapse `users` row |
| **DID** | `did:key:zDn…` / `did:pkh:…` + provider signature | **the provider** | no | Synapse profile field `io.inblock.did` |

Today tiers 1 and 3 are **conflated**: `provision_user(localpart, did)` writes the
raw DID into `displayname`, a field the user can rewrite at will. So the only
published copy of a user's DID is user-controlled — a consumer reading
displayname-as-DID can be handed *someone else's* DID. Separating the tiers is
therefore part of the security fix, not cosmetics.

## Design

### One field, an object value

`io.inblock.did` holds a JSON **object**, written atomically:

```json
{
  "did":   "did:key:zDnaeUKTWUXc1mxSoRrEfV6wPWmQyHrKuTHLZgAkyUKfSbeMB",
  "proof": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjNmMmE…"
}
```

Verified against the Synapse v1.159.0 source (see §"Grounding"): custom field
values are `JsonValue | dict[str, JsonValue]`, canonical-JSON-encoded into a
JSONB column. There is **no string constraint** on custom fields — the only
`isinstance(…, str)` checks in the write path are for `displayname` and
`avatar_url`. Objects and arrays round-trip (`storage/…/profile.py:319-321`
deserializes them explicitly on read).

**Why one field and not two** (`io.inblock.did` + `io.inblock.did.proof`):

- **Atomicity.** One PUT is one canonical-JSON blob. Two fields can drift — one
  write lands, the other fails — leaving a proof that disagrees with the plain
  DID beside it.
- **One denylist entry**, so a smaller Synapse patch surface to forward-port.
- **`proof` is naturally optional.** When the signing key is ephemeral we write
  `{"did": …}` with no `proof` key at all (see H5). Two fields would have to
  express that as an absent second field, which reads as "the write failed".
- A consumer parses JSON either way — `GET …/io.inblock.did` returns
  `{"io.inblock.did": <value>}` whether the value is a string or an object — so
  the string form buys nothing.

Field name `io.inblock.did` satisfies Synapse's Common Namespaced Identifier
Grammar, `^[a-z][a-z0-9_.-]{0,254}$` (`util/stringutils.py:53`). Note this
grammar forbids uppercase and colons, which is why a DID cannot be a field
*name*.

### The proof is a compact ES256 JWS

Header: `{"alg":"ES256","typ":"JWT","kid":"<key-derived>"}`
Payload:

```json
{ "iss": "<base_url>", "sub": "<exact-case DID>", "mxid": "@local:server", "iat": 1757… }
```

- **`sub` is the DID** — deliberately the same claim the ID token already carries
  (CLAUDE.md breaking change #1), so a consumer can compare the assertion's `sub`
  to the ID token's `sub` with no translation.
- **`mxid` is what stops replay.** Without it, user B copies A's valid proof into
  B's profile and it verifies. The shipped verifier compares this claim to the
  profile it read the proof *from*, and that comparison is inside the helper —
  not advice in a doc.
- **No `exp`.** The binding is permanent: localparts are never recycled and a DID
  never stops being that user's DID. A stale assertion stays *true* rather than
  becoming a stale credential.

### `kid` must identify the key, not the slot

`axum_lib.rs:1197-1211` currently stamps `kid = "key1"` on **both** the
configured key and the randomly generated one. Assertions are stored durably in
Synapse but may be signed by a key that dies at restart, so with a constant `kid`
every stored assertion would silently stop verifying — same `kid`, different key,
"bad signature". Deriving `kid` from the public key (`public_key_fingerprint()`,
which already exists) turns that into an honest, diagnosable "kid not present in
JWKS".

And the stronger guard: when `signing_key_pem` is absent we **do not mint a proof
at all**, because writing a durable assertion with a key we know will not survive
the process is writing garbage into someone's profile.

### Reads are public — say so

`GET /_matrix/client/v3/profile/{user}/{field}` authenticates only when
`require_auth_for_profile_requests` is set, which defaults to **False**
(`config/server.py:561`), and custom fields federate via `on_profile_query`.
Anything written here is world-readable. A DID is public by nature, so this is
fine — but it must be documented so nothing private is ever added to the object.

### The write channel

Inside `oidc::provision_synapse_device`, which is the **single** function both
sign-in call sites (`oidc.rs:770` device-code grant, `oidc.rs:1925` sign_in)
already route through. One insertion point covers both flows.

`PUT /_matrix/client/v3/profile/{mxid}/io.inblock.did` with a minted
admin-scoped token (`synapse_client::admin_request`, which also re-mints once on
401/403). Best-effort: it never fails sign-in. Re-asserted on **every** sign-in,
so a user-clobbered value self-heals at next login with no janitor process.

**A 500 from this route means "row-less account, state unknown", not "error"** —
`element-hq/synapse#19702` is still present in 1.159.0 on both reads and writes
(`_check_profile_size` and `get_profile_field` both subscript an unguarded
`txn.fetchone()`), so an account with a `users` row but no `profiles` row 500s
where a healthy account 404s. 3 of 102 dev accounts are in that state.

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| **H1** | siwx-oidc PUTs `io.inblock.did` with a minted admin-scoped token | Synapse accepts the write to another user's profile and the value reads back identically | minted token carries `urn:synapse:admin:*`; MSC4133 stable route is unconditional on 1.159.0; target has a `profiles` row | unit: mock-Synapse asserts method/path/bearer/body. live: PUT then GET returns the object |
| **H2** | the PUT is issued against a row-less account (#19702) and 500s | publish returns without error, logs at `warn`, and sign-in still completes | #19702 unfixed in the pinned image | unit: mock returns 500 → publish is `Ok`, sign_in path unaffected |
| **H3** | a user overwrites `io.inblock.did` and then signs in again | the provider's value is restored, with no operator action | re-assert runs on every sign-in | live: user PUT bogus → sign in → GET shows the correct object |
| **H4** | the signing key is ephemeral and the process restarts | the new key yields a **different** `kid`, so old assertions fail as "unknown kid", never as a silent bad signature | `public_key_fingerprint()` is collision-free enough at 16 hex chars | unit: two generated keys → different kids; one PEM → stable kid across constructions |
| **H5** | `signing_key_pem` is absent | a loud startup warning is emitted and the written object carries **no** `proof` key (the `did` key is still written) | — | unit: the gate function returns `None` for an ephemeral key |
| **H6** | user B copies A's valid proof into B's profile | the shipped verifier rejects it, because the `mxid` claim ≠ the profile it was read from | verifier is actually used (it is the only exported path) | unit: valid JWS + mismatched `expected_mxid` → `Err`. live: same, end to end |
| **H7** | the proof's payload, signature, or `alg` is altered | verification fails | — | unit: tampered payload, truncated sig, `alg:none`, `alg:HS256`, unknown `kid` — each → `Err` |
| **H8** | the server mints an assertion and the client crate verifies it against the server's real JWKS | it verifies | both sides agree on r‖s (not DER) ES256 encoding | integration test spanning both crates |
| **H9** | the backported #19980 guard is applied and `msc4133_key_denylist: ["io.inblock.did"]` is set | a user's own PUT **and** DELETE of that field answer 403, while the admin-token PUT still answers 200 | `by_admin` is exempt in the upstream guard | live: three curl legs against the patched image |
| **H10** | the upstream hunks are rebased onto v1.159.0 | the image builds, Synapse starts, and every other profile operation is unchanged | 1.159.0's function bodies match the anchors found | `podman build` + container healthy + `/_matrix/client/versions` 200 + full harness green |
| **H11** | the DID is published only into the ACL-protected field, and `displayname` is seeded with something that is not the DID | no user-writable surface carries a provider-asserted DID | nothing else writes the DID to a user-writable place | unit: `provision_user` is never called with the DID. live: a new account's displayname ≠ its DID |
| **H12** | all of the above ship | the existing suite stays green and sign-in / token / introspect are unaffected | — | `cargo test --workspace` EXIT=0, ≥18 targets ok; clippy `-D warnings`; `fmt --check` |

## Acceptance criteria

| # | Criterion | Hypotheses |
|---|---|---|
| **AC1** | A new user's Synapse profile carries `io.inblock.did` = `{did, proof}`, with `did` the exact-case DID | H1, H11 |
| **AC2** | `proof` is an ES256 compact JWS binding `iss`, `sub`=DID, `mxid`, `iat`, with a key-derived `kid` | H4, H5 |
| **AC3** | The user cannot change or delete the field (403 both ways) | H9, H10 |
| **AC4** | siwx-oidc can still (re)write it, and does so on every sign-in | H1, H3, H9 |
| **AC5** | `siwx-oidc-auth` ships a verifier that fetches, verifies, and **enforces the mxid binding**; a replayed proof is rejected | H6, H7, H8 |
| **AC6** | The alias (`displayname`) is user-settable and is not the DID | H11 |
| **AC7** | Suite green, clippy clean, fmt clean; no regression | H2, H12 |
| **AC8** | Synapse patch registry exists with why / evidence / retirement condition; CLAUDE.md documents the wire contract and the "discovery hint, not authorization" rule | — |

## Boundary conditions

**Invariants — must not be violated**

1. **Sign-in never fails because of this feature.** Every new Synapse call is
   best-effort, exactly like `upsert_device` and `allow_cross_signing_reset`.
2. **The fail-safe localpart direction stays legacy-on-error** (pinned by
   `fail_safe_fallback_is_legacy_never_modern`). Nothing here may change it.
3. **The field is a discovery hint, never an authorization source.** Authorization
   resolves the DID from the OIDC `sub`, or from a signature by the DID key
   itself. This must be stated in the field's own doc comment and in CLAUDE.md.
4. **No secrets in the object.** Profile reads are unauthenticated and federate.
5. **Never write a durable assertion with an ephemeral key.**
6. **Keep upstream's config key names verbatim** (`msc4133_key_denylist`), so
   adopting the merged PR is a no-op for our config.
7. **Do not open a competing upstream PR** while #19980's author is active.

**Exclusions — explicitly out of scope**

- **Production deploy.** Memory `prod-promotion-gate` fixes the order; this stops
  at local-harness verification.
- **Posting to GitHub upstream** (#19980 / #18525). Handover open question 2 —
  it names inblock.io publicly and is Tim's call.
- **A friendly-name generator for the alias.** Seeding `displayname` with the
  localpart is the minimum that separates the tiers; a nicer generator is a
  product decision, not a security one.
- **Migrating existing accounts' displaynames.** Grandfathering applies here too:
  we do not rewrite a displayname a user may have already set.

**Risks (assumptions inverted)**

1. *The #19980 hunks may not rebase onto 1.159.0.* Upstream targets `develop`.
   Mitigation: exact 1.159.0 anchors are already extracted (insert after
   `handlers/profile.py:699` and `:782`); if the diff will not apply, hand-write
   the equivalent guard against those anchors and record the divergence.
2. *This becomes our first Synapse patch*, creating a forward-port obligation on
   every bump — and 1.157→1.159 was already forced by a security release.
   Mitigation: registry discipline + an explicit retirement condition.
3. *`patch` and `git` are absent from `matrixdotorg/synapse:v1.159.0`* (verified).
   The build must install `patch` and resolve the site-packages path dynamically
   rather than hard-coding `python3.13`.

---

## Grounding (facts verified for this plan, not assumed)

Synapse **v1.159.0** source, fetched at tag:

- `handlers/profile.py:633-664` — `isinstance(str)` applies to `displayname` and
  `avatar_url` only; custom fields fall to the untyped `else` branch.
- `handlers/profile.py:700-704` — `if not by_admin and target_user != requester.user: raise AuthError(403, …)`; `by_admin=True` short-circuits.
- `handlers/profile.py:786-787` — the delete twin raises `AuthError(**400**, …)`,
  an upstream inconsistency worth knowing when asserting status codes.
- `rest/client/profile.py:167-172, 209-216` — `by_admin` comes from
  `auth.is_server_admin(requester)`.
- `api/auth/mas.py:274-275` — under MAS that is literally
  `"urn:synapse:admin:*" in requester.scope`.
- `rest/client/profile.py:100-103` — the stable v3 route is registered
  **unconditionally**; `msc4133_enabled` only adds an unstable alias. No config
  change needed to read or write the field.
- `config/server.py:561-563` — `require_auth_for_profile_requests` defaults False.
- `storage/…/profile.py:52-53, 673-736` — 64 KiB whole-profile cap; no per-value
  cap for custom fields.
- `util/stringutils.py:53` — field-name grammar `^[a-z][a-z0-9_.-]{0,254}$`.

siwx-oidc, this repo:

- `oidc.rs:770` and `oidc.rs:1925` are the only two callers of
  `provision_synapse_device` — one insertion point covers both flows.
- `synapse_client.rs:263` `admin_request` already handles minting + one retry.
- `oidc.rs:100-108` `public_key_fingerprint()` already exists, unused by `kid`.
- `axum_lib.rs:1197-1211` hard-codes `kid = "key1"` for both key paths.
- `localpart.rs:233` `spawn_mock_synapse` is the in-process mock harness these
  tests extend.
