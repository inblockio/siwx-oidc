# R3 adversarial re-check — "Redis hiccups for ~2s" — ADOPT-MODIFIED

**Date:** 2026-07-25
**Scope:** requirement **R3** only, from
`docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md` §2
(hypotheses `H-D2`, `H-D3`; tasks `T1`, `T2`, `T4`).
**Method:** `/logic-model` — every claim below is a falsifiable if-then link, tagged
**VERIFIED** (file:line / config path / crate source) or **ASSUMPTION**.
**Code baseline:** `HEAD = c826468`. All line numbers cite `git show HEAD:<file>` unless
stated. `src/oidc.rs` is **dirty in the working tree** (56 insertions); none of the in-flight
hunks touch the refresh path, but they shift it +5 lines. Cite HEAD, not the worktree.
**Constraint honoured:** no source, config, plan or audit file was modified; no container was
started, stopped or restarted. Static reads only.

---

## 0. Verdict up front

| | |
|---|---|
| **Verdict** | **ADOPT-MODIFIED** |
| **R3 as written** | **Premise REFUTED.** "Today: session terminated" is **false** for the stated fault (~2s Redis blip). bb8 absorbs it. |
| **D1** (`compat.rs:479`) | **Real, but on a zero-traffic path.** Demote to hygiene. It does **not** justify R3. |
| **D2** (`oidc.rs:583-591`, `compat.rs:602-612`) | **Real, correctly described, and severe if hit** — but reachable only through a knife-edge mid-request fault, ~1e-4 per fault event at this deployment's scale. |
| **T2 implementable?** | **Yes, trivially.** The trait already distinguishes all three cases. The plan's stated risk here is a non-issue. |
| **Net recommendation** | Ship **T2** (≈10 lines + 2 unit tests, bounded-safe). Ship **T1** as hygiene, not as R3 justification. **Cut T4** as scoped — its headline hypothesis is refuted statically, for free, by this document. |

---

## 1. CONTEXT — what R3 claims, and what actually runs

R3's causal chain, as the plan states it:

```
L1  Redis fault (~2s)
  → L2  refresh/introspect read returns Err
  → L3  Err mapped to a terminal auth error (401 M_UNKNOWN_TOKEN / 400 invalid_grant)
  → L4  client treats it as a hard logout, wipes the crypto store
  → L5  re-login mints a NEW Matrix device with no cross-signing secrets
  → L7  only unlock path left is the 4S recovery phrase
```

The chain is sound **as a shape**. This re-check attacks it at **L1→L2**, which is the link
the plan never tested, and finds it does not hold for the stated fault.

---

## 2. Q1 — Are D1 and D2 real as described?

### 2.1 Evidence table

| # | Claim | Status | Evidence (HEAD `c826468`) |
|---|---|---|---|
| E1 | D1: `compat::refresh` maps a Redis `Err` on the refresh-token lookup to `401 M_UNKNOWN_TOKEN` | **VERIFIED** | `src/compat.rs:479-487` — `Err(_) => { return (StatusCode::UNAUTHORIZED, Json({"errcode":"M_UNKNOWN_TOKEN", ...})) }`. Plan's line ref is exact. |
| E2 | D2: post-mint recheck uses `.unwrap_or(true)` in **both** refresh handlers | **VERIFIED** | `src/oidc.rs:587` + `:591`; `src/compat.rs:607` + `:612`. Plan's ranges (`oidc.rs:585-591`, `compat.rs:605-612`) are correct. |
| E3 | Ordering: the **old** refresh token is deleted **before** the recheck | **VERIFIED** | `src/oidc.rs:578` (`let _ = db_client.delete_token(&rt).await;`) precedes the recheck at `:583-591`. Mirror: `src/compat.rs:594` precedes `:602-612`. *Correction: the plan cites `oidc.rs:576`; the actual statement is at `:578`. Off by two, immaterial.* |
| E4 | Ordering: the **grace pointer is written only after** the recheck | **VERIFIED** | `src/oidc.rs:607-617` (`set_rotated_token`), after the `if revoked_now { … return Err }` block at `:592-599`. Mirror: `src/compat.rs:633-644` after `:613-627`. The source comment at `oidc.rs:604-606` states this ordering is deliberate ("so it can never resolve to rolled-back tokens"). |
| E5 | On the D2 path the client is left with no usable token | **VERIFIED in outcome, CORRECTED in mechanism** | See §2.3. |
| E6 | **NEW — the plan under-reports D2.** `compat::refresh`'s **pre**-mint tombstone checks *also* `.unwrap_or(true)` | **VERIFIED** | `src/compat.rs:511`, `:516` → `401 M_UNKNOWN_TOKEN "Session has been revoked"` at `:527-533`. All **four** tombstone reads in `compat.rs` fail closed on I/O error; the plan names only the last two. |
| E7 | **NEW — D1 does not exist on the live path.** `oidc::token_refresh`'s lookup and pre-mint checks propagate with `?`, not `.unwrap_or` | **VERIFIED** | `src/oidc.rs:490` (`get_token(&rt).await?`), `:531`, `:532` (`.await?`), `:561`, `:576` (`set_token(...).await?`). `?` yields `CustomError::Other(anyhow)` → **HTTP 500** (`src/axum_lib.rs:133-134`). |
| E8 | `introspect` already behaves correctly under a Redis fault | **VERIFIED** (confirms plan F4) | `src/introspect.rs:94-101` — Redis `Err` → `StatusCode::INTERNAL_SERVER_ERROR`; missing token → `{"active": false}` (`:121`). |

### 2.2 The correction that matters most: D1 is *only* a compat defect

The plan presents D1 as "the refresh-token lookup returns 401 on a Redis I/O error", which
reads as a property of refresh in general. It is not. On the **OAuth `POST /token`** path —
the one Element X and Element Web actually use (§3.2) — **every** pre-mint Redis error already
returns **HTTP 500**, which is exactly what T1 asks for. Verified per-step:

| Step in `oidc::token_refresh` | Line | Error handling | Status on Redis `Err` |
|---|---|---|---|
| 1. `get_token(&rt)` | `:490` | `?` | **500** ✅ |
| 2. `is_device_revoked` (pre-mint) | `:531` | `?` | **500** ✅ |
| 3. `is_user_deactivated` (pre-mint) | `:532` | `?` | **500** ✅ |
| 4. `set_token` (new access) | `:561` | `?` | **500** ✅ |
| 5. `set_token` (new refresh) | `:576` | `?` | **500** ✅ |
| 6. `delete_token` (old refresh) | `:578` | `let _ =` | ignored |
| 7. `is_device_revoked` (**recheck**) | `:585-587` | `.unwrap_or(true)` | **400 `invalid_grant`** ❌ **D2** |
| 8. `is_user_deactivated` (**recheck**) | `:589-591` | `.unwrap_or(true)` | **400 `invalid_grant`** ❌ **D2** |
| 9. `set_rotated_token` (grace) | `:607-617` | `let _ =` | ignored |

**Steps 7 and 8 are the only two places in the entire live refresh path where a Redis I/O
error becomes a terminal auth error.** That is the whole of R3's real code surface.

This has a structural consequence the plan misses, developed in §3.3: **a full Redis outage
cannot reach D2 at all**, because steps 1–5 would 500 first.

### 2.3 Is the client "left holding nothing"? — outcome yes, mechanism different

The plan says the rollback deletes the new pair while the old one is already gone. Under a
genuine I/O fault that is **not** what happens to the stored state:

- The rollback deletes at `oidc.rs:593-594` are `let _ = …` — best-effort. If Redis is faulting,
  **they fail too**, so the freshly minted pair *survives* in Redis (access 300s TTL, refresh 90d).
- The old-refresh delete at `:578` is also `let _ = …`, so it may equally have failed, leaving
  the old token alive.

So the durable state is *not* necessarily "nothing". **The damage is the error class, not the
data loss.** The client receives `400 invalid_grant` — which matrix-rust-sdk treats as
terminal — and signs out, never retrying, while a perfectly usable token pair sits unreferenced
in Redis. Worse, the 90-day refresh token becomes an unreachable orphan.

**The plan's conclusion (client is signed out) is correct; its reasoning (both tokens deleted)
is not.** This matters for the fix design: see §5.2 — it is *why* "fail retryable" is the wrong
fix and "fail open" is the right one.

---

## 3. Q2 — REACHABILITY (the question that decides the verdict)

### 3.1 Does the Redis client layer surface a ~2s blip as `Err`? — **NO**

**VERIFIED** from vendored crate source.

`RedisClient::new` builds the pool with **no overrides at all**:

```rust
// src/db/redis.rs:48-51
let pool = bb8::Pool::builder()
    .build(manager.clone())
    .await
```

So every bb8 default applies (`bb8-0.9.1/src/api.rs:235-248`):

| Setting | Default | Consequence |
|---|---|---|
| `connection_timeout` | **30 s** | the budget `pool.get()` is allowed to spend retrying |
| `retry_connection` | **true** | connection-creation failures are retried, not returned |
| `test_on_check_out` | **true** | every checkout is PING-validated before use |
| `max_size` | 10 | pool depth |

The `get()` implementation (`bb8-0.9.1/src/inner.rs:83-134`) closes the argument:

- A pooled connection that fails `is_valid` is marked `ConnectionState::Invalid` and the loop
  **`continue`s** (`:110-116`) — it does not return an error.
- Connection creation retries with exponential backoff (200 ms → doubling, capped at
  `connection_timeout/2`) until `Instant::now() - start > connection_timeout`
  (`inner.rs:216-226`).
- The whole loop is wrapped in `timeout(connection_timeout, future)` (`:124-130`); only on
  expiry does it yield `Err(RunError::TimedOut)`.

`bb8-redis-0.26.0/src/lib.rs:68-74` confirms `is_valid` is a real `PING` round trip.

> **⇒ A ~2-second Redis fault is absorbed by `pool.get()` with ~2 s of added latency and
> returns `Ok`. It does not produce an `Err`. The `Err` arm needs an outage exceeding
> `connection_timeout` = 30 s, or a socket that dies mid-command after a successful PING.**

**This refutes R3's premise as literally written.** `H-D2`'s fault-injection design ("pause
Redis ~2s → assert 5xx on all three endpoints") would, if run, mostly observe **200 OK with
elevated latency** — not the 5xx it predicts and not the 401 it fears.

Side-finding: bb8's default `error_sink` is `NopErrorSink` (`api.rs:245`), so the retries
during a blip are **silently swallowed** — no log line is emitted. Any future fault-injection
work should not expect log evidence of an absorbed blip.

### 3.2 Is `compat::refresh` on a live code path? — **ROUTED, BUT ZERO TRAFFIC**

This is the sharpest single finding for D1. **VERIFIED** on all three legs:

**(a) It is routed — including in production.** Not dead by configuration:
- Registered: `src/axum_lib.rs:1278-1281` → `post(compat::refresh)`.
- Prod edge: `../siwx-oidc-matrix-server/deploy.sh:126-128` —
  `handle /_matrix/client/v3/refresh { reverse_proxy siwx-oidc:8081 }`, appended to the
  external `portal-caddy-1` Caddyfile. Also reachable via the `siwx-oidc.inblock.io`
  catch-all vhost (`deploy.sh:142-145`).
- Same split in `Caddyfile.production:47-52`, `e2e/real-stack/Caddyfile:111-117`,
  `Caddyfile.local:82-87`, `Caddyfile.e2e:89-94`.

**(b) Synapse would not serve it anyway**, so the split is correct, not redundant:
`synapse/rest/client/login.py:730-732` returns early from `register_servlets` when
`msc3861.enabled` is true — `RefreshTokenServlet` is never mounted. MSC3861 is enabled at
`../siwx-oidc-matrix-server/entrypoints/matrix_server.sh:22`. Independently,
`refreshable_access_token_lifetime` is unset repo-wide, which alone would suppress the
servlet (`login.py:736-739`).

**(c) No client can ever call it.** A CS-API refresh token is obtainable **only** from
`POST /_matrix/client/v3/login`. Synapse's `LoginRestServlet` is unregistered by the same
early return at `login.py:732`, and siwx-oidc registers **only `GET`** on that path
(`axum_lib.rs:1258`, `compat::login_flows`). **There is no `POST /login` anywhere in this
stack**, so no client can enter the state that would make it call CS-API refresh.

**(d) What Element actually uses:** `POST /token` with `grant_type=refresh_token`.
`docs/audits/2026-06-23-elementx-refresh-rotation-signout.md:32` and the two-sites table at
`:80-81` attribute every prod `invalid_grant` line to `src/oidc.rs::token_refresh`, and label
`compat::refresh` "legacy CS-API refresh path". The grace fix was applied there purely for
parity (`:125`; plan `2026-06-23-refresh-token-grace.md:18`, H4), not because of traffic.

**(e) Who calls it today:** only `#[ignore]`d live-stack tests —
`tests/e2e_msc3861.rs:461-475`, `tests/e2e_race_teardown.rs:1189`, `:1305`, `:1481-1496`.

> **⇒ Stated plainly, as required: nothing calls `compat::refresh` in this deployment. D1 is
> theoretical, and R3's weight rests on D2 alone.**
>
> Caveat, so this is not over-read: the endpoint is **publicly routed and accepts tokens**, so
> it is a live *security* surface even at zero traffic. Fix D1 and E6 for hygiene and parity —
> just do not count them as R3 justification.

### 3.3 Structural bound: a Redis *outage* cannot reach D2 at all

Follows from the step table in §2.2. To arrive at step 7, the request must already have
completed steps 1–5 successfully — one `GET`, two tombstone `GET`s, and two `SET EX`+`SADD`+
`EXPIRE` writes. All five are `?`-guarded and would return **500** if Redis were unavailable.

> **⇒ D2 fires only if Redis is healthy for steps 1–5 and then faults specifically at step 7
> or 8 of the *same in-flight request*. It is a mid-request knife-edge, not an outage
> phenomenon.**

Two fault shapes can produce it:
1. **Socket death at the fault edge.** The transition instant lands between a successful
   `is_valid` PING and the subsequent command. Window ≈ one command RTT (sub-millisecond on a
   container-local Redis).
2. **Pool exhaustion / degradation beginning mid-request.** A request past step 5 hits step 7,
   whose `pool.get()` then times out after 30 s → `Err` → D2. Window ≈ the residual request
   duration.

### 3.4 Exposure arithmetic

Let **N** = concurrently active clients, access-token TTL = **300 s**
(`src/db/mod.rs:61`), so each client refreshes ≈ every 300 s.

**(i) Refreshes landing anywhere in a 2 s window** (what the plan implicitly assumes is the
exposure):

```
rate            = N / 300  refreshes·s⁻¹
in a 2 s window = 2N / 300 = N / 150
```

| N | refreshes in a 2 s window |
|---|---|
| 10 | 0.067 (≈ 1 per 15 such faults) |
| 150 | 1.0 |
| 1 000 | 6.7 |

**(ii) …but per §3.1 none of those are harmed** — bb8 absorbs the 2 s and they return `Ok`.
The correct exposure is the probability that a refresh is *in flight past step 5* at the
fault instant:

```
P(refresh in flight)          ≈ N × t_req / 300           t_req ≈ 10 ms (9 Redis round trips + HTTP)
P(in the step-6..8 slice)     ≈ 3/9 ≈ 0.33
P(D2 fires per fault event)   ≈ N × 0.010/300 × 0.33 ≈ N × 1.1e-5
```

| N | P(D2 fires per Redis fault event) |
|---|---|
| 10 | **≈ 1.1e-4** — about 1 in 9 000 faults |
| 1 000 | ≈ 1.1e-2 — about 1 in 90 faults |

**Fleet size at this deployment is small.** `docs/audits/2026-06-23-elementx-refresh-rotation-signout.md:54`
records **7 `invalid_grant` events over ~4 days** across the whole deployment, from a
lost-response mechanism that fires on a low-percentage fraction of mobile refreshes. Back-solving
puts N in the **single digits to low tens**, not hundreds.
*(Note: the plan's `H-D5` cites a "~548/72h baseline". That is an order of magnitude apart from
this audit's 7-per-4-days and the two are not reconciled anywhere. Flagged as an inconsistency in
the plan's own evidence base — not resolved here, out of R3's scope, but `H-D5`'s metric target
should not be relied on until it is.)*

> **⇒ At realistic N, D2 is expected to fire on the order of once per ~10 000 Redis fault
> events. It is real; it is very nearly unreachable.**

### 3.5 Second-order dampener: Synapse caches introspection

**VERIFIED** in `synapse/api/auth/msc3861_delegated.py:205-212` — a `ResponseCache` keyed on
the raw access token, `timeout=Duration(minutes=2)`.

Semantics that matter (`:304-305`, `:363-364`; `synapse/util/caches/response_cache.py:236-255`):
`should_cache` is set **after** a successful JSON decode but **before** `active` is inspected —
so **successes and `active:false` are cached for 2 min; transport failures are not cached** and
are retried on the next request.

Since clients hold long-poll `/sync` open continuously, cache entries are warm. **A 2 s blip is
therefore absorbed twice over on the introspection path: once by bb8, once by Synapse's cache.**

The inverse is the real hazard, and it is worth recording even though it is out of R3's scope:
if siwx-oidc ever answers `200 {"active": false}` during a fault, **that negative answer is
cached for 2 minutes** and every request in the window gets a hard 401 with no re-introspection.
There is no invalidation hook (`msc3861_delegated.py:193-196` says so explicitly). `introspect.rs`
correctly returns 500 rather than `active:false` on a Redis error (E8), so this is currently safe —
but it is a **standing invariant worth an explicit regression test**, because a well-intentioned
"make introspect resilient" change that swaps the 500 for `active:false` would amplify a 2 s blip
into a 2-minute fleet-wide hard logout. **This is a larger latent risk than D2 itself.**

---

## 4. Q3 — Is the amplifier real?

### 4.1 The `soft_logout` claim — **CONFIRMED**

Whole-tree grep of Synapse **1.154.0** (`matrix_synapse-1.154.0.dist-info/METADATA:2-3`) for
`soft_logout` returns exactly two files:

- `synapse/api/auth/internal.py:226-230` — the **only** `soft_logout=True` in an auth path,
  on the **native** DB-token expiry branch.
- `synapse/api/errors.py:331` — `UserLockedError`, a different class.
- `synapse/api/errors.py:474-486` — the definition. `InvalidClientTokenError.__init__` defaults
  `soft_logout=False` (`:478`), hardcodes `errcode="M_UNKNOWN_TOKEN"` (`:480`), inherits HTTP 401
  (`:463-464`), and **always emits the key** in the body (`:483-486`).

Negative proof: `grep -n soft_logout synapse/api/auth/msc3861_delegated.py synapse/api/auth/mas.py
synapse/api/auth/base.py synapse/api/auth/__init__.py` → **exit 1, zero matches.**

`msc3861_delegated.py:520-521`: `active:false` → `InvalidClientTokenError("Token is not active")`
→ `{"errcode":"M_UNKNOWN_TOKEN", "soft_logout": false}`. `:512-514`: transport failure →
`SynapseError(503)`.

> **⇒ Plan fact F1 is CONFIRMED. Under MSC3861 there is no cheap logout.**

New, unrecorded fact worth carrying: Synapse 1.154 has a **third** auth backend preferred over
MSC3861 — `synapse/server.py:740-748` selects `MasDelegatedAuth` when `config.mas.enabled`.
`synapse/api/auth/mas.py:327-333` has identical error semantics. Assumption **A2**
("Synapse keeps the F1 contract") should be re-asserted against `mas.py`, not only
`msc3861_delegated.py`, on the next upgrade.

### 4.2 …but it is **not** the amplifier for D2

This is a precision correction the plan needs.

| | Chain | Terminal signal | Amplifier |
|---|---|---|---|
| **R1** (restart / flush) | token absent → `introspect` `active:false` → Synapse | `401 M_UNKNOWN_TOKEN`, `soft_logout:false` | the `soft_logout` finding — **applies** |
| **R3 / D2** | recheck I/O error → `oidc::token_refresh` returns direct to the client | **`400 invalid_grant`** from `POST /token` | matrix-rust-sdk's terminal treatment of `invalid_grant` — `soft_logout` **never involved** |

D2's response is produced by `CustomError::BadRequestToken` → **HTTP 400**
(`src/axum_lib.rs:112`). It is returned by siwx-oidc's OAuth token endpoint **directly to the
client**. Synapse's auth code never sees it, so `soft_logout` is not in the picture.

The severities nonetheless converge, and the second link is independently evidenced:
`docs/audits/2026-06-23-elementx-refresh-rotation-signout.md:17` and `:44` —
"matrix-rust-sdk treats `invalid_grant` on the refresh grant as unrecoverable → Element-X signs
the session out", corroborated by the prod log signature at `:54-60` (paired `invalid_grant`
lines each followed by `POST /oauth2/revoke`).

> **⇒ Both endpoints' 401/400 are session-terminal, so the plan's severity claim survives. But
> citing `soft_logout` as *D2's* amplifier is a category error — it belongs to R1. The correct
> D2 amplifier is the SDK's `invalid_grant` handling, and that one is already evidenced in the
> repo.**

---

## 5. Q4 — Would the proposed fix be safe, and is it implementable?

### 5.1 Implementability — **YES, and the plan's stated doubt is unfounded**

`H-D3` lists as an assumption: *"Tombstone read is distinguishable from an I/O error at the DB
trait."* It is — the trait already returns a three-valued type:

```rust
// src/db/mod.rs:205, :211
async fn is_device_revoked(&self, username: &str, device_id: &str) -> Result<bool>;
async fn is_user_deactivated(&self, username: &str) -> Result<bool>;
```

`anyhow::Result<bool>` gives exactly the required three-way:

| Trait result | Meaning | Required action |
|---|---|---|
| `Ok(true)` | tombstone present — **definite** | `Revoked` → roll back (I8) |
| `Ok(false)` | tombstone absent — **definite** | `NotRevoked` → commit |
| `Err(e)` | I/O / pool failure — **indistinguishable** | `Unknown(io)` → commit + `warn!` |

The Redis implementation does **not** collapse these. `src/db/redis.rs:838-847`:
`is_device_revoked` / `is_user_deactivated` return `Ok(self.get_raw(key).await?.is_some())`,
and `get_raw` (`:85-96`) propagates both the pool error and the command error as `Err`. A
missing key is `Ok(None)` → `Ok(false)`. There is no internal `unwrap_or`.

> **⇒ `.unwrap_or(true)` is the *only* thing collapsing the distinction, and it is at the call
> site. T2 is a 6-line `match` at four call sites. No trait change, no new error enum, no
> migration.**

### 5.2 Safety — fail **open**, not fail **retryable**

The instinctive safer-looking fix — "on `Err`, return 503 so the client retries" — is **wrong
here**, and §2.3 explains why. By step 7 the old refresh token has already been deleted
(`:578`) and the grace pointer has **not** yet been written (`:607`). Returning *any* error
strands the client: it retries with an old token that is gone and has no grace record, and
gets `invalid_grant` anyway. **Fail-retryable converts a rare bug into a guaranteed one.**

Committing is the only outcome that leaves the client with a working session, which is what
T2 specifies. The plan's design is correct.

### 5.3 Does fail-open resurrect a genuinely revoked session? — **bounded, and the margin is 2×**

This is the plan's own top-ranked risk (§9 Risk 1) and invariant **I8**. It resolves favourably,
by an argument that is verifiable and worth encoding as a test:

- For D2 to fire on a *genuinely revoked* session, the tombstone must have been planted
  **between step 3 and step 7 of the same request** — steps 2–3 already read it cleanly
  (they use `?`; had they errored, the request would have 500'd and never reached step 7).
- So at fail-open time the tombstone is **≈ 0 seconds old**.
- `TOMBSTONE_TTL_SECS = 600` (`src/db/redis.rs:17`); `ACCESS_TOKEN_TTL = 300`
  (`src/db/mod.rs:61`).
- The resurrected session must refresh again within 300 s. That next refresh hits the
  **pre-mint** check (`oidc.rs:531-532`, `?`-guarded), which — Redis now healthy — reads a
  tombstone with ~300 s of TTL remaining and refuses.

```
tombstone lifetime (600 s)  >  2 × access-token TTL (300 s)   ⇒  self-terminates in ≤ 1 cycle
```

> **⇒ Fail-open grants at most one extra refresh cycle (≤ 300 s) of access to a revoked
> device, then self-heals. I8 is respected: the change is confined to the indistinguishable
> `Err` arm; `Ok(true)` still rolls back.**

**Added requirement, not in the plan (recommended as a T2 sub-item):** that safety argument
depends entirely on `TOMBSTONE_TTL_SECS > ACCESS_TOKEN_TTL`. Nothing currently enforces it. A
future tuning of the tombstone TTL below 300 s would silently make fail-open **unbounded** —
a permanently resurrected session. Add a compile-time or unit-test assertion:

```rust
const _: () = assert!(TOMBSTONE_TTL_SECS > crate::db::ACCESS_TOKEN_TTL);
```

### 5.4 Scope correction for T2

T2 names two sites. There are **four** (E2 + E6). `compat.rs:511` and `:516` — the *pre*-mint
checks — must be included, or `compat::refresh` keeps a fail-closed I/O path that T1 will then
contradict. T2's file list should read: `src/oidc.rs:585-591`; `src/compat.rs:506-516` **and**
`:602-612`.

---

## 6. Assumptions register

| ID | Assumption | Why it is not verified | Risk if wrong | How to settle |
|---|---|---|---|---|
| **A-R1** | Redis returns `-LOADING` (and thus fails bb8's `PING`) during AOF replay after a restart | No `redis-server` binary or source found in local container storage (bounded `find` over 1 199 overlay dirs, no hit). Prod runs bare `image: redis` (`docker-compose.yml:30`), version unpinned | **This is the one branch that would flip the verdict.** If `PING` *succeeds* during LOADING, `is_valid` passes and every subsequent command returns `Err(-LOADING)` for the whole replay — D1/D2 would fire on **every** request for seconds-to-minutes, not once per 10 000 faults | Restart Redis with a large AOF and poll `PING` during replay. Weak counter-evidence *for* my reading: prod's own healthcheck is `redis-cli ping` with `siwx-oidc depends_on: condition: service_healthy` (`docker-compose.yml:32-36, 51-52`), which is only a meaningful readiness gate if PING fails during loading |
| **A-R2** | `t_req ≈ 10 ms` for a refresh request (§3.4) | Not measured; inferred from 9 container-local Redis round trips + HTTP | Exposure scales linearly. Even a 10× error (100 ms) leaves P ≈ 1.1e-3 at N=10 — still "very nearly unreachable" | Time `POST /token` against the real stack |
| **A-R3** | N (concurrent active clients) is single-digit to low-tens | Back-solved from 7 `invalid_grant` / 4 days (`2026-06-23` audit:54), not counted directly | If N were ~1 000, D2 exposure rises to ~1 in 90 faults — still low, but no longer negligible | `redis-cli --scan --pattern 'token/*' \| wc -l` on prod (read-only) |
| **A-R4** | matrix-rust-sdk treats `400 invalid_grant` on the refresh grant as terminal | Evidenced from this repo's own prod-log forensics (`2026-06-23` audit:17, 44, 54-60), not read from SDK source | If the SDK retried instead, D2 would be self-healing and T2 unnecessary | Read `matrix-rust-sdk` OAuth refresh error handling upstream |
| **A-R5** | Synapse stays on the F1 contract | Version-dependent; **1.154.0 adds a preferred `MasDelegatedAuth` backend** (`server.py:740-748`) | A future backend could set `soft_logout=True`, softening R1 (not R3) | Re-grep `soft_logout` across `synapse/api/auth/*.py` on every Synapse upgrade — include `mas.py` |

---

## 7. VERDICT

### **ADOPT-MODIFIED**

**Modification, in three parts:**

1. **Rewrite R3's premise. It is factually wrong.**
   Replace *"Redis hiccups for ~2s. Today: session terminated"* with:
   > **R3 — Redis faults mid-request during a token rotation.** Today: the post-mint revocation
   > recheck treats an I/O error as a revocation tombstone and returns `invalid_grant`, signing
   > the client out. Required: an indistinguishable I/O error commits the rotation (fail open);
   > a definite tombstone still rolls back.
   >
   > *A ~2 s Redis blip is already absorbed by bb8's 30 s `connection_timeout` with
   > `retry_connection: true`, and, on the introspection path, again by Synapse's 2-minute
   > `ResponseCache`. It does not terminate sessions today.*

2. **Ship T2** — the corrected four call sites (§5.4), plus the tombstone-TTL assertion (§5.3),
   plus the two unit tests `H-D3` already specifies. Trivially implementable (§5.1),
   bounded-safe (§5.3), ~10 lines.

3. **Demote T1, cut T4 as scoped.**
   - **T1** → hygiene/parity. `compat::refresh` should return 503 (D1 + E6), but it carries
     **zero traffic** (§3.2), and the live path is **already correct** (E7). It buys no user-visible
     behaviour. Do it because a publicly-routed token endpoint should not lie about error class,
     not because R3 needs it.
   - **T4** → **cut as written.** Its headline hypothesis (`H-D2`: "2 s outage → 5xx everywhere")
     has now been answered statically from crate source, for free, and the answer is *"no — 200 OK
     with added latency"*. Building a Redis pause/kill harness to observe an absorbed blip is
     effort spent confirming a null result. **Redirect that budget** to the two things that are
     genuinely unverified and higher-value:
     - **A-R1** — the Redis `-LOADING` question. One restart-and-poll observation. It is the
       single fact that could flip this verdict, and it costs minutes.
     - **The `active:false` caching invariant** (§3.5) — a regression test pinning
       `introspect` to *500-on-Redis-error, never `active:false`*. Because Synapse caches a
       negative for 2 minutes with no invalidation hook, a future "resilience" change there
       would turn a 2 s blip into a 2-minute fleet-wide hard logout. **That is a strictly larger
       latent risk than D2, and it is currently unguarded.**

### Which user-visible product behaviour does R3 buy?

**Honestly: at current fleet scale, approximately none that a user will ever notice.**

The chain R3 serves is real and correctly drawn — a terminal refresh error signs the session
out; Element wipes the crypto store; re-login mints a **new** Matrix device (`oidc.rs`, sign-in
path) that has no cross-signing private keys; with no other verified session live, the only
remaining unlock is the 4S recovery phrase — and per the plan's own **F16** the reload verify
gate currently offers **no recovery-key entry field**, so that user's only exit is a destructive
identity reset. A single `invalid_grant` really can end in a half-reset user.

But R3's *fault* does not occur. The 2 s blip is absorbed twice over. The residual defect, D2,
needs Redis to be healthy for five consecutive operations and then fail on the sixth within the
same request — expected roughly once per ~10 000 fault events at N≈10 (§3.4).

**So the case for shipping T2 is not frequency — it is asymmetry, and it is still a good case:**

| | |
|---|---|
| Cost | ~10 lines across 4 call sites + 2 unit tests + 1 const assertion. No trait change, no migration, no new dependency |
| Consequence if it does fire | Unrecoverable-without-the-phrase logout, landing on a verify gate that (per F16) has no phrase field — i.e. forced destructive reset |
| Correctness | `.unwrap_or(true)` on a **rollback** path is a latent bug independent of frequency. It makes the security-critical revocation guard behave differently depending on network weather |

That is worth doing. **What is not worth doing is T4's harness** (~days of work to observe a
null result) or treating D1 as load-bearing (zero-traffic endpoint).

**R3 should survive — rewritten, with T2 as its whole content.** The plan should stop citing it
as a driver of forced logins in production: the measured `invalid_grant` population
(`2026-06-23` audit:54) is attributed to **lost rotation responses on mobile**, which is **R2**
and is already fixed by the grace window (`3f40485`, on `main`, per plan **F12** not yet
deployed). **Deploying that** — plan task **T9**, currently parked behind the Phase-3 audit
gate — is worth strictly more user-visible relief than everything R3 contains, and R3 should
not be allowed to borrow credit for it.
