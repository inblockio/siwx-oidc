# MSC4133 `org.aqua-protocol.did` profile field — feasibility on Synapse 1.159.0

**Date:** 2026-09-09
**Context:** repo issue #17 (MXID→DID inversion incident). Proposes publishing the
exact-case DID as an MSC4133 extended profile field, `org.aqua-protocol.did`, so
downstream agents stop trying to reconstruct it from the (lowercased, one-way)
Matrix localpart.
**Method:** read the installed Synapse 1.159.0 source inside the live dev container
(`matrix-staging-matrix_synapse-1`, `ssh -p 8022 dev@207.154.209.103`), cross-checked
against the running config (`/data/homeserver.yaml`) and the live SQLite DB
(`/data/homeserver.db`, opened read-only), plus three safe, read-only `curl GET`
probes against `https://dev.matrix.inblock.io`. No POST/PUT was sent to the
homeserver; no secrets were printed (only the `experimental_features` and
`require_auth_for_profile_requests` config keys were grepped, never the file as a
whole).

---

## Q1. Does Synapse 1.159.0 implement MSC4133 extended profile fields, and is it flag-gated?

**Verdict: Yes, implemented — and the part we need is *not* gated by the experimental flag.**

`synapse/rest/client/profile.py` registers `ProfileFieldRestServlet` unconditionally.
Its `PATTERNS` list already includes the **stable** v3 arbitrary-field route:

```python
class ProfileFieldRestServlet(RestServlet):
    PATTERNS = [
        *client_patterns("/profile/(?P<user_id>[^/]*)/(?P<field_name>displayname)$", v1=True),
        *client_patterns("/profile/(?P<user_id>[^/]*)/(?P<field_name>avatar_url)$", v1=True),
        re.compile(
            r"^/_matrix/client/v3/profile/(?P<user_id>[^/]*)/(?P<field_name>[^/]*)$",
        ),
    ]
    ...
    def __init__(self, hs: "HomeServer"):
        ...
        if hs.config.experimental.msc4133_enabled:
            self.PATTERNS.append(
                re.compile(
                    r"^/_matrix/client/v3/unstable/uk\.tcpip\.msc4133/profile/(?P<user_id>[^/]*)/(?P<field_name>[^/]*)$"
                )
            )

def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ProfileFieldRestServlet(hs).register(http_server)
    if hs.config.experimental.msc4133_enabled:
        UnstableProfileFieldRestServlet(hs).register(http_server)
    ProfileRestServlet(hs).register(http_server)
```
(`synapse/rest/client/profile.py`, class `ProfileFieldRestServlet`)

`hs.config.experimental.msc4133_enabled` defaults to `False`:

```python
# MSC4133: Custom profile fields
self.msc4133_enabled: bool = experimental.get("msc4133_enabled", False)
```
(`synapse/config/experimental.py:245`)

**The flag only controls whether the legacy unstable-prefixed alias
(`/_matrix/client/unstable/uk.tcpip.msc4133/profile/...`) is *also* registered.**
The stable `/_matrix/client/v3/profile/{userId}/{field_name}` route — which is what
MSC4133 actually needed — is registered by the unconditional
`ProfileFieldRestServlet(hs).register(http_server)` call regardless of the flag.

**Dev deployment config** (`/data/homeserver.yaml`, `experimental_features:` block,
key names only, no secrets):
```
experimental_features:
  msc4108_enabled: true
  msc4143_enabled: true
  msc3266_enabled: true
  msc4222_enabled: true
```
`msc4133_enabled` is absent → defaults to `False` on dev.

**Live confirmation** (read-only GETs, safe — profile is a public route):
```
GET /_matrix/client/unstable/uk.tcpip.msc4133/profile/{...}/org.aqua-protocol.did
→ 404 {"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}   (flag off, as predicted)

GET /_matrix/client/v3/profile/{active-user}/org.aqua-protocol.did
→ 404 {"errcode":"M_NOT_FOUND","error":"Profile was not found"}     (route works, field just unset)
```

**What this means for us:** we do **not** need to set
`experimental_features.msc4133_enabled: true` on dev or prod to use
`org.aqua-protocol.did`. The stable v3 route already works today with the
deployment's current config.

---

## Q2. Who is allowed to write another user's profile field — can a server admin?

**Verdict: Yes. A server admin (including a minted admin-scoped token) can write
any user's field, because the authorization check is explicitly bypassed for
admin-originated requests.**

REST layer, `ProfileFieldRestServlet.on_PUT` (`synapse/rest/client/profile.py`):
```python
requester = await self.auth.get_user_by_req(
    request, allow_guest=field_name == ProfileFields.DISPLAYNAME
)
user = UserID.from_string(user_id)
is_admin = await self.auth.is_server_admin(requester)
...
await self.profile_handler.dispatch_set_profile_field(
    target_user=user,
    requester=requester,
    field_name=field_name,
    new_value=new_value,
    by_admin=is_admin,
    propagate=propagate,
)
```

That `is_admin` flag becomes `by_admin` all the way down to the store-facing
handler, `ProfileHandler.set_profile_field` (`synapse/handlers/profile.py`):
```python
if not self.hs.is_mine(target_user):
    raise SynapseError(400, "User is not hosted on this homeserver")

if not by_admin and target_user != requester.user:
    raise AuthError(403, "Cannot set another user's profile")
```
When `by_admin=True`, the ownership check (`target_user != requester.user`) is
skipped entirely — an admin requester can target *any* local user.

`is_server_admin` for MAS-delegated deployments (which is what siwx-oidc runs) is:
```python
async def is_server_admin(self, requester: Requester) -> bool:
    return "urn:synapse:admin:*" in requester.scope
```
(`synapse/api/auth/mas.py:274-275`)

`requester.scope` here is populated verbatim from **siwx-oidc's own introspection
response** — exactly the mechanism already documented in `CLAUDE.md` for
`POST /oauth2/admin_token` (`src/admin_token.rs`). A token minted with scope
`urn:matrix:client:api:* urn:synapse:admin:*` and presented as a Bearer token on
`PUT /_matrix/client/v3/profile/{target}/org.aqua-protocol.did` will set
`is_admin=True` and succeed, regardless of which account `{target}` is.

**What this means for us:** siwx-oidc can write `org.aqua-protocol.did` on the
target user's profile itself, right after `provision_user`, using the *existing*
admin-token-mint machinery — no per-user token, no client cooperation required.

---

## Q3. Can the user overwrite it afterwards? (the load-bearing security caveat)

**Verdict: Yes, trivially — this field is a discovery hint, never an authorization
source.**

`ProfileHandler.set_profile_field` (same function quoted in Q2) is reached with
`by_admin=False` for a normal user's own `PUT /_matrix/client/v3/profile/{self}/{field}`
request. The check is:
```python
if not by_admin and target_user != requester.user:
    raise AuthError(403, "Cannot set another user's profile")
```
For `target_user == requester.user` this is simply **not an error** — there is no
value validation anywhere in the write path (`_set_profile_field_txn` only enforces
byte-size limits, see Q4; nothing checks that a `did:key:z6Mk…` field actually
corresponds to the account's real signing key or matches the OIDC `sub` that
provisioned the account). A user can `PUT` any string into their own
`org.aqua-protocol.did` — including someone else's DID, a malformed string, or
garbage — with a plain 200.

**What this means for us:** `org.aqua-protocol.did` must be documented and treated
purely as a **discovery hint for UX/tooling** (e.g. "here's probably the exact-case
DID to show/copy"). It must never be trusted as an authorization or identity source.
The only trustworthy source of a DID remains the OIDC `sub` claim (verified at
token-issuance time) or a namespaced profile field that only siwx-oidc itself
(via the admin path in Q2) is allowed to write — and even the admin write is only
as trustworthy as "siwx-oidc believed this was the right DID at provisioning time,"
not a live signature. Any consumer doing something security-sensitive with the DID
(the exact incident #17 tried to avoid) must still resolve it from the OIDC `sub`,
never from this profile field, and the field's own doc string should say so
explicitly.

---

## Q4. Size / count / rate limits on extended profile fields

**Verdict: One byte-size cap on field *name*, one byte-size cap on the *whole
profile blob*, no explicit per-user field-count cap, no field-specific rate limiter.**

Field name length, `synapse/rest/client/profile.py`:
```python
if len(field_name.encode("utf-8")) > MAX_CUSTOM_FIELD_LEN:
    raise SynapseError(400, "Field name too long", errcode=Codes.KEY_TOO_LARGE)
```
```python
# handlers/profile.py
MAX_DISPLAYNAME_LEN = 256
MAX_AVATAR_URL_LEN = 1000
# Field name length is specced at 255 bytes.
MAX_CUSTOM_FIELD_LEN = 255
```

Whole-profile byte budget, `synapse/storage/databases/main/profile.py`:
```python
MAX_PROFILE_SIZE = 65536
...
def _check_profile_size(self, txn, user_id, new_field_name, new_value) -> None:
    ...
    total_bytes = (...)  # existing displayname + avatar_url + all custom `fields` JSON
    total_bytes += len(encode_canonical_json({new_field_name: new_value}))
    if total_bytes > MAX_PROFILE_SIZE:
        raise StoreError(400, "Profile too large", Codes.PROFILE_TOO_LARGE)
```
This is a **65536-byte cap on the sum** of displayname + avatar_url + every custom
field (JSON-encoded), not a per-field cap and not an explicit field-*count* cap —
count is only implicitly bounded by the shared byte budget. No rate limiter
(`@ratelimit`-style decorator or `Ratelimiter` call) is present in
`ProfileFieldRestServlet`; only the global/default HTTP rate limits apply.

**What this means for us:** a DID string (`did:key:z6Mk…` / `did:pkh:eip155:1:0x…`,
well under 100 bytes) is trivially inside every one of these limits. Not a
constraint on this design.

---

## Q5. Is there a MAS-surface (`/_synapse/mas/*`) alternative?

**Verdict: No. The MAS surface exposes displayname, avatar_url, email, lock status,
and devices — nothing generic for a custom profile field.**

Full inventory of `synapse/rest/synapse/mas/`:

| Resource (file) | Route | What it does |
|---|---|---|
| `MasQueryUserResource` (users.py) | `GET /_synapse/mas/query_user` | read displayname/avatar/suspended/deactivated |
| `MasProvisionUserResource` (users.py) | `POST /_synapse/mas/provision_user` | create-or-update user; `set_displayname`/`unset_displayname`, `set_avatar_url`/`unset_avatar_url`, `set_emails`/`unset_emails`, `locked` — **no custom-field parameter** |
| `MasIsLocalpartAvailableResource` (users.py) | `GET /_synapse/mas/is_localpart_available` | localpart availability check |
| `MasDeleteUserResource` (users.py) | `POST /_synapse/mas/delete_user` | deactivate/erase |
| `MasReactivateUserResource` (users.py) | `POST /_synapse/mas/reactivate_user` | reactivate |
| `MasSetDisplayNameResource` / `MasUnsetDisplayNameResource` (users.py) | `POST /_synapse/mas/{set,unset}_displayname` | displayname only |
| `MasAllowCrossSigningResetResource` (users.py) | `POST /_synapse/mas/allow_cross_signing_reset` | cross-signing UIA bypass |
| `MasUpsertDeviceResource` / `MasDeleteDeviceResource` / `MasUpdateDeviceDisplayNameResource` / `MasSyncDevicesResource` (devices.py) | `POST /_synapse/mas/*device*` | device lifecycle, write-only (matches `CLAUDE.md`'s existing description) |

All of these authenticate via the MAS shared secret, checked in
`MasBaseResource.assert_request_is_from_mas` → `auth.is_request_using_the_shared_secret`
(`synapse/rest/synapse/mas/_base.py`), not per-user tokens. But there is no
`set_profile_field`/`set_custom_field` endpoint anywhere in this package —
`MasProvisionUserResource.PostBody` (users.py) only has `set_displayname`,
`set_avatar_url`, `set_emails`, `unset_*`, `locked`. Confirmed by grepping the
whole `synapse/rest/synapse/mas/` tree for a generic field setter: none exists.

**What this means for us:** the MAS shared secret cannot be used to write
`org.aqua-protocol.did`. The admin-scoped minted token (Q2) hitting the standard
`/_matrix/client/v3/profile/{userId}/{field_name}` route is the only available
write channel — there's no shortcut via the shared-secret surface.

---

## Q6. Is `element-hq/synapse#19702` still present in 1.159.0? Is the self-heal in `oidc.rs` now live?

**Verdict: No — the underlying crash is still present in 1.159.0, in both the
write path *and* (newly confirmed) the read path of the MSC4133 custom-field code.
The `provision_synapse_device` self-heal branch is still inert.**

### The crash, read from source

Write path, `synapse/storage/databases/main/profile.py::_check_profile_size`
(called from `_set_profile_field_txn`, called by every `set_displayname` /
`set_profile_field`, MAS or client-facing):
```python
size_sql = """
SELECT LENGTH(json_remove(fields, ?)), LENGTH(displayname), LENGTH(avatar_url)
FROM profiles
WHERE user_id = ?
"""
txn.execute(size_sql, (f'$."{new_field_name}"', user_id.localpart))
row = cast(tuple[int | None, int | None, int | None], txn.fetchone())

total_bytes = (
    (row[0] - 1 if row[0] else 0)   # <-- row[0] on a bare SELECT that matched
    ...                              #     zero rows: txn.fetchone() is None here,
)                                    #     so row[0] raises TypeError immediately.
```
For a user with a `users` row but **no** `profiles` row, the `WHERE user_id = ?`
matches zero rows, `txn.fetchone()` returns `None`, and `row[0]` on the very first
term raises an unguarded `TypeError` — never converted to a graceful `SynapseError`,
so it surfaces as a bare `500 M_UNKNOWN "Internal server error"`.

Read path (previously undocumented — **new finding**, not just the write-side bug
`oidc.rs` describes), `synapse/storage/databases/main/profile.py::get_profile_field`
(SQLite branch):
```python
txn.execute(
    "SELECT JSON_TYPE(fields, ?), JSON_EXTRACT(fields, ?) FROM profiles WHERE user_id = ?",
    (field_path, field_path, user_id.localpart),
)
value_type, value = cast(tuple[str | None, JsonValue | dict[str, JsonValue]], txn.fetchone())
if not value_type:
    raise StoreError(404, "No row found")
```
Same defect: `txn.fetchone()` returns `None` on a row-less profile, and the tuple
**unpack** `value_type, value = None` raises `TypeError: cannot unpack non-iterable
NoneType object` before the graceful `if not value_type: raise StoreError(404, ...)`
line is ever reached. By contrast, the *spec-standard* fields (`displayname`,
`avatar_url`) go through `get_profile_displayname`/`get_profile_avatar_url`, which
use `simple_select_one_onecol` — a shared helper that already handles "no row"
gracefully. **Only the new MSC4133 custom-field code path has this raw,
unguarded `fetchone()` bug**; it looks like a fresh regression introduced by the
MSC4133 implementation itself, not a straight recurrence of the original
displayname-only #19702 report.

### Live confirmation (safe, read-only GETs — no state changed)

Three accounts on dev currently have a `users` row with **no** matching `profiles`
row (confirmed via read-only SQLite query on `/data/homeserver.db`):
```
users: 102   profiles: 99   → 3 accounts with no profiles row, all deactivated=1
  @did-key-zdnaeskrgk1qmczqwg6rvbskbq7bnh3nhra7gdpdbvmtuv87r:dev.matrix.inblock.io
  @did-pkh-eip155-1-0x83477e7ba0b901dc8a3ae78ee50fe2cb67861b0d:dev.matrix.inblock.io
  @did-pkh-eip155-1-0xa79bbdade22853874b6df6beb80f05a8a5577761:dev.matrix.inblock.io
```
These are erased/deactivated accounts, not fresh-provisioning failures — Synapse's
own erasure path (`ProfileHandler.delete_profile_upon_deactivation` →
`store.delete_profile`, invoked when `account_erase` runs with `erase=true`)
deletes the `profiles` row on purpose, and (unlike `account_reactivate`, which
explicitly calls `store.create_profile` — "The profile row is deleted on erasure,
so recreate it if missing" — `synapse/handlers/deactivate_account.py:355`) an
erased-and-never-reactivated account stays row-less indefinitely.

Probing one of those three with a plain, read-only GET (public route, no auth
needed — `require_auth_for_profile_requests` is unset in `/data/homeserver.yaml`
→ default `false`):
```
GET /_matrix/client/v3/profile/{row-less user}/org.aqua-protocol.did
→ 500 {"errcode":"M_UNKNOWN","error":"Internal server error"}    ← crash confirmed live

GET /_matrix/client/v3/profile/{row-less user}/displayname
→ 404 {"errcode":"M_NOT_FOUND","error":"Profile was not found"}  ← the OLD field path is fine
```
Control, on an active user (who does have a `profiles` row):
```
GET /_matrix/client/v3/profile/{active user}/org.aqua-protocol.did   (field never set)
→ 404 {"errcode":"M_NOT_FOUND","error":"Profile was not found"}      ← works correctly once a row exists

GET /_matrix/client/v3/profile/{active user}/displayname
→ 200 {"displayname":"did:key:z6MknwPR8neFZcaoPu8pJLeicmyVnFvPh6wyBAVPu2suG8rV"}
```
(This last one is a nice incidental confirmation that `provision_user`'s
displayname-as-DID convention, documented in `CLAUDE.md`, is live and working on
dev today.)

### Why new provisioning is *mostly* safe, and why the self-heal is still inert

`synapse/handlers/register.py::register_user` defaults a missing displayname to
the localpart before calling storage:
```python
elif default_display_name is None:
    default_display_name = localpart
```
and `storage/databases/main/registration.py::register_user` creates the `profiles`
row **in the same transaction** as the `users` row, whenever
`create_profile_with_displayname` is truthy:
```python
if create_profile_with_displayname:
    txn.execute(
        "INSERT INTO profiles(full_user_id, user_id, displayname) VALUES (?,?,?)",
        (user_id, user_id_obj.localpart, create_profile_with_displayname),
    )
```
Because that fallback always makes the value truthy, and because it's atomic with
the `users` insert, a **brand-new** account provisioned via
`MasProvisionUserResource`'s `register_user()` call can no longer end up
half-provisioned from that specific race — which is good news, but it is not the
same thing as "the crash is fixed." The crash (`_check_profile_size` /
`get_profile_field` blowing up on a `None` row) is a property of
`storage/databases/main/profile.py`, completely independent of how a row-less state
arose. It still fires for:
- pre-existing row-less accounts (the 3 on dev today — erasure artifacts),
- any future erasure-without-reactivation,
- and, in principle, any other future code path that manages to create a `users`
  row without a `profiles` row.

`src/oidc.rs::provision_synapse_device`'s self-heal branch calls
`SynapseClient::has_profile_row` (a GET) to detect the row-less state, then
re-calls `provision_user`, which (for an *existing* localpart) calls
`MasProvisionUserResource`'s existing-user branch →
`profile_handler.dispatch_set_profile_field(DISPLAYNAME, by_admin=True)` → the
exact `_check_profile_size` crash quoted above. **The self-heal's own comments are
correct and still accurate**: it is currently inert on 1.159.0, because 1.159.0 has
not moved past the upstream defect. Nothing in this audit found evidence that the
fix has landed; if anything, we found the *read* side of the same class of bug is
also unfixed, which the existing `oidc.rs` comments didn't previously call out.

**What this means for us:** if we write `org.aqua-protocol.did` via the admin-token
path, it will succeed for the overwhelming majority of accounts (any account that
has ever had `provision_user` complete once, which per the registration-atomicity
finding above is now the normal case), but will 500 on the small, currently-nonzero
population of row-less accounts on this deployment — and, unlike the displayname
field, even a **read** of `org.aqua-protocol.did` on such an account will 500
rather than degrading to 404. Any code that reads this field back (a client, a
downstream agent, a support tool) needs to treat a 500 from this specific route as
"field state unknown / account may be row-less," not as a hard failure worth
surfacing to a user. This nuance should be added to `oidc.rs`'s self-heal comment
and to the eventual `org.aqua-protocol.did` implementation's own docs.

---

## Recommendation

**Workable on 1.159.0 as-is, with two caveats — no config change needed.**

1. **Write channel:** mint a short-TTL admin-scoped token (existing
   `POST /oauth2/admin_token` machinery, `src/admin_token.rs`) and `PUT
   /_matrix/client/v3/profile/{userId}/org.aqua-protocol.did` right after
   `provision_user`, the same place `provision_user` already sets displayname to
   the DID. No `experimental_features.msc4133_enabled` flag needed — leave it
   unset/`false`; only the legacy unstable-prefixed alias needs that flag, and we
   don't need the alias.
2. **Never treat the field as authoritative.** Document in the field's own
   description (and in `CLAUDE.md`) that `org.aqua-protocol.did` is a discovery
   hint only — any user can overwrite their own copy with an arbitrary value
   (Q3), and even our own admin-written copy is only as good as what siwx-oidc
   believed at provisioning time. Authorization-sensitive code must keep resolving
   the DID from the OIDC `sub` claim, never from this field — this is the exact
   discipline that issue #17 already established for the localpart problem; this
   field doesn't change it, it only fixes the *display/discovery* half.
3. **Handle the row-less-account edge case defensively.** Both the write (`PUT`)
   and — newly discovered here — the **read** (`GET`) of a custom field 500 on an
   account with a `users` row but no `profiles` row (currently 3/102 accounts on
   dev, all erasure artifacts). Wrap both the write-after-provision call and any
   future read-back of `org.aqua-protocol.did` to treat a 500 from this specific
   endpoint as "unknown," not as an error worth surfacing loudly — this is a
   narrower, already-anticipated instance of the existing `has_profile_row`
   self-heal discipline in `oidc.rs`, just extended to cover reads as well as
   writes.
4. No MAS-surface shortcut exists (Q5) — the admin-token route is the only
   channel; budget for it rather than looking for a shared-secret alternative.
5. Sizing is a non-issue (Q4) — a DID string is nowhere near the 255-byte
   field-name cap or the 65536-byte whole-profile cap.

**Next-best channel, if the admin-token write path is ever judged too fragile
(e.g., if the row-less-account rate grows):** none of the alternatives are
better — displayname already carries the DID today and is the fallback that
already ships. `org.aqua-protocol.did` should be treated as an additive,
best-effort enhancement layered on top of the existing displayname-as-DID
convention, not a replacement for it.
