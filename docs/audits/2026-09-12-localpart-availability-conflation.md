# Audit + remediation — `is_localpart_available` conflated INVALID with TAKEN

**Date:** 2026-09-12. **Branch:** `feat/opaque-mxid-localpart`.
**Found during:** a production-readiness review of the MXID ↔ DID mapping work
(`docs/audits/2026-09-10-attested-did-audit.md` covers the work up to `01d37f6`;
this defect is in code that pass did not reach).
**Severity:** wrong identity resolution, and a documented security gate silently
disarmed. Latent on today's deployments, live on `GET /resolve`.

## The defect

`SynapseClient::is_localpart_available` mapped **any** 4xx from
`GET /_synapse/mas/is_localpart_available` to `Ok(false)` = "the localpart is
taken". Synapse does not mean that. The endpoint is a thin wrapper over
`RegistrationHandler.check_username`, which raises `400` with a **discriminating
errcode**:

| Cause | Status | errcode |
|---|---|---|
| already registered | 400 | `M_USER_IN_USE` — the **only** one that means taken |
| invalid characters / empty / leading `_` / guest-numeric | 400 | `M_INVALID_USERNAME` |
| resulting user ID longer than `MAX_USERID_LENGTH` (255) | 400 | `M_INVALID_USERNAME` |
| appservice-exclusive namespace | 400 | `M_EXCLUSIVE` |

(One nuance, corrected during remediation: for `M_EXCLUSIVE` it is not true that
"no account can exist" — an *appservice* may own users in that namespace. What is
true, and what the code says, is that no account **we could provision** can exist
there, and such a user is not ours to grandfather. The fall-through is correct
either way.)
| **MAS shared secret rejected** | **403** | (`assert_request_is_from_mas`) |

Read from Synapse **1.159.0** itself — `rest/synapse/mas/users.py:266`,
`handlers/register.py::check_username`, `rest/synapse/mas/_base.py:46`,
`api/constants.py:86` — in image `localhost/siwx-synapse:1.159-msc4133acl`, the
version dev and prod run. (An earlier read against a local 1.154.0 container was
discarded as insufficient evidence.)

So two distinct wrong answers were being presented as fact:

1. A localpart Synapse **refuses** read as "an account already exists there".
2. A **wrong or rotated MAS shared secret** made *every* localpart read as taken.

## Why it matters: the new-account gate was disarmed

`localpart::resolve_identity` probes the **legacy** localpart first, and returns
`{localpart: legacy, is_new: false}` when it reads as taken. `is_new` is the
input to the new-account gates. `webauthn::reject_if_new_identity` matches:

```rust
Ok(resolved) if resolved.is_new => reject,
Ok(_)                           => PASS,
Err(e)                          => reject,   // "must not silently create an account"
```

A wrongly-`Ok(false)` legacy probe yields `Ok({is_new: false})`, so the gate
**passes** — on exactly the QR/device-approval and account-re-auth paths that
CLAUDE.md documents as hard-REJECT for a new identity. The 403 case did the same
for every identity at once.

Note the shape of this: the gate's own doc comment already said it intends to
fail closed on a detection failure. The probe was reporting a detection failure
as a successful detection, so the gate could not honour its own contract.

## Trigger

`@` + localpart + `:` + server_name ≤ 255, and the legacy localpart is the DID
with `:` → `-` (length-preserving). On dev (`dev.matrix.inblock.io`) that leaves
a **232-character** budget.

| DID method | legacy localpart length | safe? |
|---|---|---|
| `did:pkh:eip155:…` | ~60 | yes |
| `did:key:z6Mk…` / `zDn…` | ~60–70 | yes |
| **`did:peer:2.Ez….Vz….SeyJ0…`** | **200–500+** | **no** |

`did:peer` is listed in CLAUDE.md as supported-and-opt-in, and `aqua-auth`'s peer
module accepts variant 2 with **no length cap** — so the crypto layer will hand
exactly such a DID to `resolve_identity`. The defect is dormant only because
every shipped deployment sets `SIWEOIDC_SUPPORTED_DID_METHODS=["pkh","key"]`.

## Live reproduction (dev, before the fix)

```
GET /resolve?did=<287-char did:peer:2>
  -> 502  "could not read the published DID of @did-peer-2.ez6lspsrlxbahg2…"
GET /resolve?did=<48-char did:key>
  -> 200  {"did":…,"mxid":"@0xrp0dgs37ek1qtq:…","exists":false,"attested":false}
```

Reaching `read_did_field` at all proves `is_new == false`, i.e. the 252-character
localpart was classified as an existing account. The short control resolves
correctly.

## A falsified comment

`src/localpart.rs` justified the old mapping by arguing that both derivations
"always produce a syntactically valid Matrix localpart (`[a-z0-9._=/-]`)". That
reasoning is about the **character class** only and never considered
`MAX_USERID_LENGTH`. `src/resolve.rs` carried the matching claim that the mapping
"is correct for the derived localparts every other caller hands it". A 252-char
derived localpart falsifies both. Both are corrected in place rather than
deleted, so a future reader cannot reinstate the reasoning.

## Remediation

Landed on `feat/opaque-mxid-localpart`, 2026-09-12.

### 1. The probe stops guessing — `src/synapse_client.rs`

```rust
pub enum LocalpartStatus { Available, InUse, Unusable { errcode: String, message: String } }
pub async fn localpart_status(&self, localpart: &str) -> Result<LocalpartStatus>
```

- `2xx` → `Available`.
- **`401`/`403` bail BEFORE the 4xx branch** — 403 *is* a client error, and
  letting it fall through is the entire defect. A rejected credential is an
  `Err` that says so, and says explicitly that it is not a verdict about the
  localpart.
- Other `4xx` → `M_USER_IN_USE` is an **allowlist of one** → `InUse`; everything
  else, including a missing `errcode` and a non-JSON body, → `Unusable`. The
  fail direction is deliberate: "an account exists" is the damaging answer,
  because it silently grandfathers an identity that has none.
- `5xx` → `Err`, unchanged.

`is_localpart_available` survives as the deliberately two-valued wrapper, with
`Unusable` mapped to `Err` rather than a silent `false`.

### 2. The policy stops being masked — `src/localpart.rs`

`resolve_identity` now falls through to the modern probe when the **legacy**
localpart is `Unusable`. This is the fix proper: a localpart Synapse refuses can
hold no account, so nothing is grandfathered and nobody is severed — and
`localpart_for` is always 16 base36 characters, always within every limit. **The
opaque-localpart scheme had already solved long DIDs; the legacy probe's failure
was hiding the solution.** A `Unusable` on the *modern* probe is a hard `Err`.

### 3. The lookup blames the right party — `src/resolve.rs`

`resolve_mxid` matches on `localpart_status` and renders `Unusable` as a **400**,
not a 502. It is the one call site handed a *caller-supplied* localpart rather
than a derived one, so a refusal is a property of the request.

### 4. An unrelated defect found while testing the above — `src/axum_lib.rs`

`/resolve` took `Query<ResolveQuery>` directly, so a query string serde could not
deserialize was rejected **before the handler ran** and answered with axum's
`text/plain` body — escaping the documented `{"error","message"}` envelope that
`docs/api/openapi.yaml` declares `required`. Live on dev:
`?did=a&did=b` → `400 Failed to deserialize query string: .: duplicate field ` did` `.
The handler now takes `Result<Query<_>, QueryRejection>` and converts the
rejection into a `ResolveError`. Verified over real HTTP on all six error paths.

## Tests

| Where | Added | Pins |
|---|---|---|
| `synapse_client.rs` | 9 | each `LocalpartStatus` mapping; `an_unusable_localpart_is_never_reported_as_taken`; `a_rejected_mas_secret_is_an_error_never_a_verdict_about_the_localpart`; two for `query_user`, which had none |
| `localpart.rs` | 5 | `a_did_whose_legacy_localpart_is_over_length_resolves_to_the_modern_one_and_is_new` (252-char `did:peer:2` vector, 264-char user ID on `matrix.test`); the gate-inversion case; legacy-unusable-plus-modern-in-use; 403 → `Err`; both-unusable → `Err` |
| `resolve.rs` | 1 | `an_mxid_the_homeserver_refuses_is_a_400_never_a_502_or_a_phantom_account` |
| `tests/e2e_resolve_http.rs` | 12 (new file) | the HTTP layer `/resolve` never had: envelope on every error, all four keys present, GET-only/405, content-type, and an 18-input hostile corpus that must never 500 |
| `mxid.rs` | 1 | `did:peer` case preservation, which the module documented but only pinned for `did:key` |

Both central invariants are **mutation-tested**: breaking the guard makes a named
test fail, and the file is restored byte-identically (checksum verified) before
re-running green.

`cargo test --workspace`: **342 passed, 0 failed** (was 326). `clippy --workspace
--all-targets -D warnings` and `fmt --check` clean. The four CI-promoted e2e
suites against a mock stack: **43/43**.

## One behaviour change, recorded rather than hidden

`e2e_account_management::wrong_mas_shared_secret_fails_closed_not_open` asserted
**401** and now asserts **400**. It is not a weakened test — the invariant it
names (fail closed, mint no session, never 2xx/5xx) is unchanged and now asserted
explicitly. What changed is *which guard rejects*: the old 401 was reached only
because the wrong secret made the identity look like an existing account, so
`reject_if_new_identity` passed and the request travelled on to
`reject_if_deactivated`, whose probe was equally broken. With the conflation
fixed, the first Synapse-dependent guard is the one that fails — by its own
documented "detection failed → reject" rule.

**Open wart:** that 400 carries `NEW_IDENTITY_REJECT_MSG`, which tells the user to
create an account when the real cause is a server credential misconfiguration.
Safe (nothing is provisioned, and sign-in is equally broken) but a misleading
diagnosis. Giving `reject_if_new_identity` a distinct error for "detection
failed" is the recommended follow-up; it was not done here because it changes a
user-visible message beyond the scope of this fix.
