# HANDOVER — publishing the DID, signing it, and protecting the field

**Written:** 2026-09-10. **Branch:** `feat/opaque-mxid-localpart` (off `dev`).
**Predecessor work:** the localpart migration, complete and verified — see §1.
**Next work:** §3, four items, in order.

---

## 0. Read this first: the tree is UNCOMMITTED

At handover time the branch has ~300 lines of verified, green work sitting in the
working tree with **no commit**. `git status --short`:

```
 M src/account.rs   M src/axum_lib.rs   M src/db/mod.rs   M src/db/redis.rs
 M src/lib.rs       M src/main.rs       M src/oidc.rs     M src/webauthn.rs
 M tests/e2e_account_management.rs      M tests/e2e_race_teardown.rs
?? src/localpart.rs ?? src/mxid.rs
?? docs/design/2026-09-09-did-profile-field-feasibility.md
?? docs/superpowers/plans/2026-09-09-upstream-profile-field-write-policy.md
```

**Step 0 is to commit it** (Tim's call — it had not been given when this was
written). This repo has prior history of a subagent hard-resetting a live
checkout and destroying uncommitted edits (memory `agent-committed-to-live-checkout`).
Do not dispatch any agent into this checkout until the tree is clean.

### Reproducing the test environment

The suite needs Redis on `localhost:6379`, which this machine does not run:

```bash
docker run -d --rm -p 6379:6379 --name siwx-test-redis redis:7-alpine
cargo test --workspace --no-fail-fast   # expect EXIT=0, 18 targets "ok"
docker stop siwx-test-redis
```

**Verification trap:** `grep -c "^test result: FAILED"` returns 0 both when
everything passes *and* when nothing compiled. Check `$?` and count
`^test result: ok` lines instead. This produced one false green during the
predecessor work.

## 1. What is already done (do not redo)

Decisions locked by Tim, 2026-09-09:

| Decision | Value |
|---|---|
| Localpart scheme | 16-char lowercase base36 = `base36(first 10 bytes of SHA-256(canonical_did))`, ≈2^82.7 |
| Canonicalisation | Method-aware: lowercase `did:pkh:*` only; exact bytes for `did:key:` / `did:peer:` |
| Migration | **Grandfather** — an account existing under the legacy localpart keeps it forever |
| Profile field name | `io.inblock.did` (reverse-DNS per MSC4133; `org.inblock.io.did` was rejected as malformed) |
| Field integrity | Signed assertion, shipped together with a verifier — not a bare string |
| Write protection | Upstream Synapse PR #19980, carried as an interim local patch |

Code, all green (exit 0, 18 targets, clippy `-D warnings` clean on lib and bin,
`fmt --check` clean):

- **`src/mxid.rs`** (library, `pub mod mxid`) — pure derivation: `localpart_for`,
  `legacy_localpart`, `canonicalize`, `encode_base36_padded`. 9 tests.
- **`src/localpart.rs`** (binary) — `ResolvedIdentity`, `resolve_identity`,
  `resolve_identity_or_legacy`. 6 tests incl. an in-process Synapse mock.
- Eight call sites rewired; `CodeEntry.localpart: Option<String>` added with
  `#[serde(default)]` so pre-migration Redis entries fall back to
  `legacy_localpart`; `reject_if_deactivated` migrated too (it was NOT in the
  original task list and would otherwise have silently stopped detecting
  deactivation for modern-scheme accounts).

**The fail-safe direction is load-bearing and must survive all future edits:**
when Synapse is unreachable, fall back to `legacy_localpart`, **never**
`localpart_for`. A wrong-shaped MXID for a new user is recoverable; a modern
localpart handed to an existing user severs them from their account, and Synapse
has no rename API. Pinned by `fail_safe_fallback_is_legacy_never_modern`.

## 2. Facts established by live probe — do not re-derive these

All verified 2026-09-09 against dev (`ssh -p 8022 dev@207.154.209.103`,
container `matrix-staging-matrix_synapse-1`, Synapse **1.159.0**, SQLite at
`/data/homeserver.db`, HTTP listener on **:8080** — not 8008).

**The base36 shape passes matrix.org's policy server.** Controlled A/B in
`#element-dev:matrix.org`, same body (`test`), minutes apart, dev's
`m.room.policy` state events confirmed present first:

| Sender | MXID len | words | Result |
|---|---|---|---|
| `@37rb2h7bdij3o1qm:dev.matrix.inblock.io` | 39 | 1 | **200, signed by `beta2.matrix.org ed25519:policy_server`** |
| `@did-pkh-eip155-1-0x7a760ea…:dev.…` | 82 | 5 | **400 `M_FORBIDDEN`** |

The refusal is current, so matrix.org has not relaxed its thresholds. Which of
the two filters binds, and at what threshold, is still unknown — we only know
our shape clears both. Test artifacts were cleaned up (message redacted with
reason `testing`, account deactivated, devices and tokens deleted).

**MSC4133 on 1.159.0:**
- `ProfileFieldRestServlet` registers the **stable** `/_matrix/client/v3/profile/{userId}/{field}`
  route *unconditionally*; `experimental_features.msc4133_enabled` gates only a
  redundant `unstable/uk.tcpip.msc4133/...` alias. **No config change needed.**
- A server admin can write another user's field: the servlet sets
  `by_admin = await self.auth.is_server_admin(requester)`, the handler checks
  `if not by_admin and target_user != requester.user: raise AuthError(403, ...)`,
  and under MAS `is_server_admin` is literally `"urn:synapse:admin:*" in requester.scope`
  (`synapse/api/auth/mas.py:274`) — exactly what `POST /oauth2/admin_token` mints.
- **The field is user-writable with no value validation.** A user can set
  `io.inblock.did` on their own profile to any string, including someone else's
  DID. This is why §3b exists.
- Custom fields **do** federate: `handlers/profile.py::on_profile_query` returns
  `get_profile_fields(user)` for a whole-profile query and the named field for a
  targeted one, gated only by `allow_profile_lookup_over_federation`. Our server
  is authoritative for our users, so protecting the write protects remote readers.
- Custom fields do **not** propagate into the user directory or into room state,
  so a consumer must fetch each profile explicitly. There is no `m.room.member`
  shortcut.
- Limits: field name ≤255 bytes; whole profile blob ≤65536 bytes; no per-field
  count cap; no field-specific rate limiter.
- **`element-hq/synapse#19702` is still present in 1.159.0, on reads as well as
  writes** — `_check_profile_size` (write) and `get_profile_field` (read) both do
  an unguarded `txn.fetchone()` then subscript it. On a `users` row with no
  `profiles` row this is an uncaught `TypeError` → bare **500**, where a healthy
  account 404s. 3 of 102 dev accounts are in that state (erasure artifacts).
  So `oidc.rs`'s self-heal branch remains correctly documented as inert.

Full evidence: `docs/design/2026-09-09-did-profile-field-feasibility.md`.

## 3. The work

### 3a. Publish the DID as a profile field

Write `io.inblock.did` right after `provision_user`, using the minted admin
token, via `PUT /_matrix/client/v3/profile/{mxid}/io.inblock.did`.

- Define the field name as **one constant**, in one place. It is a wire contract
  with aqua-agents; changing it later means dual-reading both keys.
- **Best-effort, never fails sign-in.** Same contract as every other Synapse call
  on that path.
- **Treat a 500 from this route as "row-less account, state unknown", not as a
  hard error** — see the #19702 note above. A 404 means "no such field", which is
  a normal first-write case.
- Re-assert on **every** sign-in, not only at provisioning. It is idempotent, and
  it makes a user-clobbered value self-heal at next login without a janitor
  process.
- Note the value already goes somewhere today: `provision_user(&localpart, did)`
  sets the account's **displayname** to the verbatim mixed-case DID. Decide
  deliberately whether to keep that (it is ugly in Element and user-editable) or
  replace it with something human — a deterministic friendly name from the DID
  seed is the design discussed, and displayname is where readability belongs,
  since it feeds no policyserv filter and needs no uniqueness.

### 3b. Make the value self-authenticating (signed assertion)

Publish a compact JWS rather than a bare DID string, signed with the existing
ES256 provider key.

- Payload binds **both** identifiers: `iss`, `sub` = the exact-case DID, `mxid`,
  `iat`. No `exp` — the binding is permanent and localparts are never recycled,
  so a stale assertion stays true rather than becoming a stale credential.
- **Include `kid`.** `config.rs`: *"If absent, a random key is generated on
  startup."* Assertions are stored durably in Synapse but may be signed by an
  ephemeral key, so without `kid` + a multi-key JWKS every stored assertion
  silently stops verifying after a restart. Additionally: refuse to start, or at
  minimum warn loudly, if this feature is enabled while the signing key is
  generated rather than configured.
- **The `mxid` claim is what stops replay.** Without it, user B copies user A's
  valid assertion into B's profile and it verifies. See 3c.

### 3c. Ship a verifier in `siwx-oidc-auth`

A signed assertion nobody verifies is worth exactly as much as a plain string,
so this is not optional follow-up — it ships in the same increment.

One call that: fetches the issuer's JWKS from OIDC discovery, verifies the
signature, and **asserts that the `mxid` claim equals the profile the assertion
was read from**. That last check must be inside the helper, not advice in a
doc — it is the whole security property.

Document the field as: *discovery hint; authorisation MUST come from the OIDC
`sub` or from a signature by the DID key itself.* The aqua node's grant ceremony
already requires the latter and is safe without any of this; the assertion
protects the *next* consumer.

### 3d. Interim Synapse patch for the write ACL

**Do not write a new PR.** [element-hq/synapse#19980](https://github.com/element-hq/synapse/pull/19980)
already implements this (successor to the stale #18562, both fixing #18525,
which asks for our exact semantics). Verified from its diff:

```python
if not by_admin and self._is_profile_field_disallowed(field_name):
    raise SynapseError(403, "Changing this profile field is disabled on this server", Codes.FORBIDDEN)
```

Admins are exempt, so our admin token still writes. The same guard covers
`delete_profile_field`, so a user cannot delete the field either. Our config
would be one line: `experimental.msc4133_key_denylist: ["io.inblock.did"]`
(denylist, not allowlist — an allowlist would forbid every *other* custom field
server-wide, which is not our call to make for our users).

Interim patch scope: backport only the `handlers/profile.py` +
`config/experimental.py` hunks onto our pinned `matrixdotorg/synapse:v1.159.0`.
Skip `capabilities.py` and the upstream tests — the capability advertisement is
a client-facing nicety we do not need, and every skipped line is a line we do
not forward-port.

- **This would be our first Synapse patch.** The image is stock today, so this
  creates a forward-port obligation on every bump — and 1.157→1.159 was already
  *forced* by a security release. Needs the same registry discipline as
  `patches/element-web/README.md`: why, evidence, retirement condition.
- **Retirement condition:** #19980 merges and ships in a Synapse we have adopted.
  Then delete the patch; the `homeserver.yaml` denylist entry remains.
- **Unverified:** whether the hunks rebase cleanly onto 1.159.0 (the upstream
  diff targets `develop`). Check before committing to this.
- Keep upstream's config key names **verbatim**, so adopting the merged version
  is a no-op for our config.

Upstream engagement plan and our positions on the PR's three open questions:
`docs/superpowers/plans/2026-09-09-upstream-profile-field-write-policy.md`.
Nothing has been posted upstream. Do not open a competing PR while the author is
active.

## 4. Open questions Tim has not answered

1. Commit the branch? (§0 — blocking for any further agent dispatch.)
2. Comment on #19980 / #18525 publicly under Tim's account? Doing so names
   inblock.io publicly as an MSC4133 deployer.
3. Carry the interim patch, or accept an unprotected field until upstream merges,
   given the signature already covers verifying consumers?
4. Should the upstream plan also exist as a shareable page for the steelman pass?
5. Displayname: keep the raw DID, or switch to a deterministic friendly name (3a)?

## 5. Things that will bite you

- **Never run bare `printenv` in a container to list env var names.** A multiline
  value defeats `cut`/`grep` filtering; this leaked dev's ES256 signing key into
  a session on 2026-09-09 (rotation waived by Tim — dev holds no critical data).
  Use `printenv NAME`, or reference `$VAR` inside the container without printing.
- **Synapse's HTTP listener on dev is :8080**, not the conventional :8008.
- **`is_localpart_available` maps any 4xx to `Ok(false)`** ("taken"), including
  `M_INVALID_USERNAME`. Safe for both our derivations, which are always
  syntactically valid — but not safe for an arbitrary caller-supplied localpart.
- **The MAS shared secret does not work on `/_synapse/admin/*` on 1.157+.** Mint
  an admin-scoped token (`src/admin_token.rs`).
- **A minted admin token cannot send messages** (`device_id: null` → hard 500 in
  `transactions.py`). A device is required to send.
- Redacted events keep their original content in the local DB until the censor
  job runs (`redaction_retention_period`, 7d default). Clients render them
  redacted immediately.
