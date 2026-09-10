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
