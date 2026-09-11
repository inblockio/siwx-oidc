# HANDOVER — the attested DID identity attribute is done; what is left

**Written:** 2026-09-10. **Branch:** `feat/opaque-mxid-localpart` (off `dev`), unmerged.
**Executes:** `docs/2026-09-10-HANDOVER-did-publication-and-field-protection.md` §3 (all four items).
**Plan + hypothesis register:** `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`.
**Audit:** `docs/audits/2026-09-10-attested-did-audit.md`. **ACL evidence:** `docs/audits/2026-09-10-msc4133-acl-probe.md`.

---

## 0. State

Both repos have **clean trees**. `siwx-oidc-matrix-server` carries one uncommitted
`Caddyfile.dev-aquafire` change that belongs to **someone else's in-flight Excalidraw
work** — it was deliberately left untouched throughout and must not be swept into a
commit here.

| Repo | Commits added |
|---|---|
| `siwx-oidc` | `c2cab99` `8d39fbe` `64eb620` `fc681b4` `01d37f6` `58865de` `1a6740e` |
| `siwx-oidc-matrix-server` | `9105a33` `a351300` `9736d59` |

`cargo test --workspace`: EXIT=0, 19 targets ok, 279 passed, 0 failed.
`clippy --workspace --all-targets -- -D warnings`: clean (was failing on pre-existing
drift before this branch). `fmt --check`: clean.
`e2e-harness/run.sh full`: `pass=15 fail=0`; see §4 for why OVERALL still says FAIL.

## 1. What now exists

Three tiers, with the boundary enforced **structurally** rather than by convention —
Synapse's guard sits in `ProfileHandler.set_profile_field`, while `displayname` routes
through `set_field` → `set_displayname` and can never reach it:

| Tier | Value | Owner | Mutable |
|---|---|---|---|
| Alias | a display name | the user | yes |
| MXID | `@{base36(sha256(did)[..10])}:{server}` | derived | no (no rename API) |
| DID | `io.inblock.did` = `{did, proof}` | the provider | no |

Demonstrated live, one account, end to end: the user set their alias to
`"Whatever I Like"` (200) while their PUT **and** DELETE of `io.inblock.did` were each
refused **403 M_FORBIDDEN**, and the shipped verifier confirmed the DID.

**The homeserver image is no longer stock.** It carries
`patches/synapse/msc4133-profile-field-write-policy.patch` (a backport of
element-hq/synapse#19980) plus a registry. Every Synapse bump now has a forward-port
obligation — run the dry-run procedure in `patches/synapse/README.md` *before* merging a
tag change. The build fails loudly if the patch stops applying (proven by deliberately
corrupting a context line).

## 2. Decisions taken that Tim may want to revisit

The predecessor handover left five open questions. Two were answered by doing the work,
one is answered here, and two are deliberately **not** done.

1. **Commit the branch?** Done — the ~300 uncommitted lines were verified green first
   (18 targets, 195 passed) and committed as `c2cab99`.
2. **Comment on #19980 / #18525 publicly?** **NOT DONE.** It names inblock.io publicly as
   an MSC4133 deployer, which is Tim's call, not an implementation detail. The material a
   comment would need is ready in
   `docs/superpowers/plans/2026-09-09-upstream-profile-field-write-policy.md`.
3. **Carry the interim patch?** **Yes, carried.** #19980 is `CHANGES_REQUESTED`,
   `mergeable: false`/dirty, and has had no activity since 2026-08-14, with the maintainer
   floating stabilising MSC4133 first. Waiting was not a plan.
4. **A shareable page for the steelman pass?** Not done; nobody needed it.
5. **Displayname: raw DID or a friendly name?** **Neither — it is now the localpart.**
   This is the decision most worth a second opinion. The reasoning is security, not
   aesthetics (a user-writable field must not carry a provider-asserted-looking DID), and
   the localpart was chosen as the minimum that separates the tiers: non-empty so the
   `profiles` row is still created, and exactly what Element renders when displayname is
   unset. A nicer generated name is a product decision that was explicitly left alone.

## 3. What was found by auditing, and fixed

An independent adversarial pass confirmed the security property and found six real
defects, all fixed in `58865de`. Two are worth knowing about because they were *claims
that turned out to be wrong*, not merely missing code:

- **A real Synapse outage was logging as a reassuring known bug.** Any 500 on the profile
  PUT was excused as synapse#19702. Measured: the #19702 body and a genuine database-write
  500 (produced with a scoped SQLite trigger) are **byte-identical**. The code now
  confirms the row is actually absent before excusing anything.
- **One key rotation permanently voided every proof ever written.** Assertions carry no
  `exp` by design, so the JWKS is their only anchor, and it held exactly the live key.
  `SIWEOIDC_RETIRED_SIGNING_KEYS_PEM` now keeps retired **public** keys published. A
  private PEM there is a hard startup error — the motivating case is a *compromised* key,
  and accepting the private form makes "keep the compromised secret in the environment
  forever" the easy path, which is the exact shape of the 2026-09-09 dev exposure.

## 4. Known-not-done, stated plainly

- **`run.sh full` still reports `OVERALL: FAIL`.** `fail=0`; the five non-passes are the
  `connector.*` checks refusing to run against a **dirty checkout in a third repo**
  (`aqua-connector`, branch `feat/scribe-daily-ux`, an uncommitted `Cargo.lock`). That
  guard is load-bearing and was deliberately not bypassed with `E2E_ALLOW_DIRTY=1`.
  Whoever owns that branch should commit it.
- **`e2e_account_lifecycle_live` fails at the harness's own documented `MATRIX_HOST`**
  (`:18080`) because the Caddy edge does not proxy `/_synapse/admin/*`; it passes at
  `:18448`. Pre-existing, not from this work, but it means that suite has been running
  against a host the harness would not use.
- **`e2e_race_teardown` and `e2e_account_management` are still `#[ignore]`d** and outside
  both `cargo test --workspace` and the harness check list. They now PASS (14/14, 6/6)
  against a modernised mock, and `e2e/README.md` carries a one-line drift check, but
  nothing runs them automatically. This is D12's structural half and it is open.
- **Not deployed anywhere.** Everything above is the local hermetic harness. Dev and prod
  are untouched, per the plan's exclusions and memory `prod-promotion-gate`.
- **The login-path probe count grew** from ~2 to ~5 Synapse calls. Timeouts now bound each
  *call* (2s connect / 8s request), but not a *login* — `/sign_in` can make up to ~8
  sequential calls. A per-login deadline is the real fix and was deliberately not
  attempted.

## 5. Next steps, in order

1. **Merge to `dev`**, then deploy: push to `dev` builds `:dev` and dev-aquafire
   auto-converges in ~9 min. **The Synapse image must be rebuilt too** — this is the first
   deploy where `siwx-oidc-matrix-server`'s image change is load-bearing, and without it
   the field is published but unprotected.
2. **Re-run the live checks on dev**, not just locally. The three
   `siwx-oidc.did_field.*` harness checks are the script.
3. **Prod is gated** by memory `prod-promotion-gate`: aqua-auth migration lands → e2e on
   dev → repeat the A/V agent test → only then prod. This work rides that gate; it does
   not jump it.
4. **Before any Synapse bump**, run the patch dry-run procedure.

---

## 2026-09-11 follow-up — merged to `dev`, and what the merge cost

**Both repos are pushed.** `siwx-oidc-matrix-server` main (`9105a33` `a351300`
`9736d59`) is on origin and its CI published the patched Synapse image, which is the
proof the vendored patch still applies. `siwx-oidc`'s branch is pushed and
fast-forwarded onto `origin/dev` at `375e8a9`, so the dev-aquafire converge now carries
both halves — the publisher and the homeserver-side denylist. `aqua-auth` needed no
action: `dev` had already pinned it to tag `v0.7.0`, and the merge brought that along.

### The merge conflicted in three files, all of it duplicate work

`dev` and this branch independently modernised the e2e Synapse mock for the Synapse
1.157+ two-surface auth split. Every conflict resolved onto this branch's version,
which is a superset (it also serves the profile routes the DID work needs); the one
thing `dev` had that this branch did not was a differently-spelled admin-rejection
lever (`__set_admin_token_valid` vs `__reject_admin_token`), and one spelling is kept.
No coverage was dropped: `dev` retargeted the admin-rejection test onto the admin
lever, and this branch had already done that AND kept the MAS-secret half alive as its
own test.

### Two failures the merge exposed, both fixed here

- **The mock could not introspect on CI.** `SYNAPSE_MOCK_OIDC_BASE` has no default on
  purpose, and only `e2e/up.sh` exports it; the CI jobs export `SIWEOIDC_BASE_URL`. So
  on CI the mock authorised no admin call at all and
  `wallet_single_reauth_covers_list_delete_profile` failed with a 400 on `devices_list`
  that reads exactly like a product bug. `SIWEOIDC_BASE_URL` is now a fallback (the
  stack's own spelling of the same value, not a guessed port); unset-both still fails
  closed.
- **The browser suite was still deriving the LEGACY localpart.** Six call sites across
  four specs; since `c2cab99` a new identity gets `mxid::localpart_for`, so every
  seeded device and every `detected_mxid` assertion named an account that does not
  exist — eight specs failed while provisioning worked correctly.
  `e2e/browser/mxid-helper.mjs` is now the suite's single derivation, mirroring
  `src/mxid.rs` (method-aware canonicalisation included) and pinned to the same four
  vectors. The Playwright container pin was also bumped to match the npm pin the
  1.62.1 bump moved alone, which killed all 27 specs locally at launch while CI, which
  installs its own browsers, stayed green.

### Verified

| Check | Result |
|---|---|
| `cargo test --workspace` (Redis up) | 283 passed, 0 failed |
| `clippy --workspace --all-targets -D warnings`, `fmt --check` | clean |
| `e2e_account_management -- --ignored --test-threads=1` | 6/6 |
| `e2e_race_teardown -- --ignored --test-threads=1` | 14/14, incl. `did_field_is_published_at_signin_…` |
| `e2e/browser/run.sh` | 27/27 |
| GitHub CI on the branch tip | build + rust-e2e-mock + browser-e2e all green |

### Still open

- **The real-stack harness run did not happen.** `e2e-harness/run.sh full` needs host
  ports 18080+18081 for its Caddy edge, and another session on this machine is holding
  18081 with its own `target/debug/siwx-oidc`. The three `siwx-oidc.did_field.*` checks
  are therefore still unrun since the merge — they DID pass before it, and the
  mock-stack twin of the publication path (`did_field_is_published_at_signin_…`) is
  green, but the live legs (public read, user write forbidden, clobber self-heal) want
  the real Synapse.
- Everything under §4 above that was not touched today still stands: the `run.sh full`
  connector guard, the `MATRIX_HOST` port mismatch in `e2e_account_lifecycle_live`, the
  missing per-login deadline, and the un-filed upstream comment.
- **Prod is still gated** by memory `prod-promotion-gate`. Nothing here jumps it.

### Live on dev-aquafire, 2026-09-11 — verified, with one leg structurally unrunnable

The converge landed the homeserver half FIRST (`matrix_synapse` on
`ghcr…/synapse:main`, live `/data/homeserver.yaml` carrying
`msc4133_key_denylist: [io.inblock.did]`), then the publisher. `/jwk` is the honest
liveness signal for the publisher: it served `kid: "key1"` before and
`kid: "01797b65f97f018b"` after, with an unchanged public key — so the configured
signing key survived the upgrade and assertions minted now verify.

`cargo test --test e2e_did_field_live -- --ignored` with `SIWEOIDC_HOST=https://dev.siwx.inblock.io`
and `MATRIX_HOST=https://dev.matrix.inblock.io`:

| Check | Result |
|---|---|
| `did_field_is_published_verifiable_and_public_live` | **pass** — published, ES256-verified through the shipped verifier, readable unauthenticated |
| `did_field_user_write_is_forbidden_live` | **pass** — the user's own token gets 403 on PUT *and* DELETE, and the displayname is not the DID |
| `clobbered_did_field_is_restored_at_next_signin_live` | **not runnable from outside the edge** — see below |

A live account from the run: `@2wjyn3jhbh7savin:dev.matrix.inblock.io` — the opaque
16-character localpart working end to end against a real Synapse.

**The self-heal leg cannot run against dev from outside, and that is correct
behaviour, not a defect.** It plants a pre-denylist clobber by minting an admin token,
and dev's Caddy deliberately answers `404` to `/oauth2/admin_token` (plan D22,
2026-08-30: the endpoint that vends Synapse admin authority must not sit on the public
internet as a guessing oracle against one static secret; both real callers are
in-network). So the test's 404 is the edge doing its job. Cover that leg on the local
harness, or from inside the compose network — never by opening the edge.

**Run it WITHOUT `E2E_STRICT_SKIPS=1` and a missing `MAS_SHARED_SECRET` reads as a
pass.** The first dev run reported 3/3; with `E2E_STRICT_SKIPS=1` the same run is
2 passed, 1 failed. Always set it for a verification run.

### Promotion to prod is a TWO-STEP, and the order is load-bearing

dev got the safe order by accident, not by design: both image refs there float on
tags (`.env` on dev-aquafire pins only redis and lk-jwt by digest), the Synapse image
build simply finished first, and the pull-model converge picked it up — `matrix_synapse`
was already running the patched image with `msc4133_key_denylist: [io.inblock.did]` in
its live `/data/homeserver.yaml` before the publisher half landed.

Prod does not float. It runs digest-pinned images and promotion is "digests,
dev-validated", so on prod the order is whatever a human writes into `.env` — and the
reverse order opens a real window: siwx-oidc starts publishing `io.inblock.did` while
Synapse is still unpatched, so every sign-in in that window writes a provider-asserted
field that any user can then overwrite. Re-assertion repairs it at the next sign-in,
but only after someone has had the opportunity to tamper.

So promote in two steps, never one `compose up`:

1. Bump the **Synapse** digest, converge, and confirm in the RUNNING container that
   `/data/homeserver.yaml` carries `msc4133_key_denylist: [io.inblock.did]`.
2. Only then bump the **siwx-oidc** digest.

`/jwk` is the honest liveness signal for step 2: the old binary serves `kid: "key1"`,
the new one serves a 16-hex-character key-derived kid.
