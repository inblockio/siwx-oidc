# Audit — the 2026-09-12 slice, and the test surface that was supposed to guard it

**Date:** 2026-09-13. **Branch:** `feat/opaque-mxid-localpart`, audited at `489c2ac`.
**Method:** two independent passes, both briefed to find what is wrong or unproven
and told not to be agreeable. One attacked the code; one asked, of every test,
*can this fail?* Every finding below cites evidence the auditor gathered
themselves. Both verified the repo byte-identical afterwards (167 `.rs` files,
manifest diff empty; `git status` clean; HEAD unchanged).

**Why this audit existed.** The 2026-09-10 adversarial pass ended at `01d37f6`.
Everything after it — `GET /resolve`, the `io.inblock.mxid` claim, the OpenAPI
enforcement test, and the three 2026-09-12/13 identity fixes — had never been
attacked. That slice added a **public unauthenticated route**, which is the
highest-value target in the service.

## Verdict

**Not shippable to prod.** One blocker reproduced the 2026-09-10 audit's D4
end-to-end. Separately, and worse in kind: three green CI suites were shown to be
incapable of failing for the features they name.

## The blocker (FIXED)

**B1 — the `Unusable` fall-through severed a grandfathered user and published a
second verifying assertion.** `156b1f9` taught `resolve_identity` to fall through
to the modern localpart when the legacy probe answers `Unusable`, reasoning that
"a localpart Synapse refuses can hold no account". But
`classify_localpart_refusal` returned `Unusable` for **every** non-`M_USER_IN_USE`
4xx — a proxy `404`, a `429`, a non-JSON body, a missing errcode — none of which
prove anything about the localpart.

Reproduced with a real binary and a scriptable mock: a grandfathered user hits a
transient upstream fault, is provisioned a **brand-new empty account**, and a
**second, independently-verifying** `io.inblock.did` assertion is published. Both
verify with the shipped `siwx-oidc-auth` verifier. That is D4 verbatim — *"a
signed lie is strictly worse than no signature"* — and the `degraded` guard
written for D4 never fired, because the fall-through returns
`Ok { degraded: false }`, not `Err`. Synapse has no rename API; the severing is
permanent.

Note the pre-`156b1f9` code was **safer** for this class: any 4xx read as "taken",
so the user kept their account. The fix had traded a latent `did:peer` bug for a
live upstream-fault bug.

**Fixed** by making `Unusable` mean what its name claims — an errcode allowlist,
mirroring the `M_USER_IN_USE` allowlist-of-one already in the file:

| errcode | verdict |
|---|---|
| `M_USER_IN_USE` | `InUse` |
| `M_INVALID_USERNAME`, `M_EXCLUSIVE` | `Unusable` |
| anything else, absent, or non-JSON | **`Err` — indeterminate, never a verdict** |

`resolve_identity`'s body is unchanged; the new `Err` routes into
`resolve_identity_or_legacy`'s fail-safe legacy fallback with `degraded: true`,
the already-tested D4 suppression path.

**A lesson from the remediation itself.** The first version of the regression test
PASSED under mutation: it modelled the fault as global, so the *modern* probe
failed too and the resolver bailed on the modern arm — right answer, wrong reason,
defect invisible. The production-dangerous shape is a **transient** fault where
the legacy probe fails and the modern one answers normally. The mock lever is now
keyed per-localpart and the test runs a healthy control first. Only the mandated
mutation step caught this; a global-fault test would have shipped as false
assurance.

One qualifier kept honest: for `M_EXCLUSIVE` an *appservice* may own users in that
namespace, so `Unusable` means "no account **we** could provision or grandfather",
which is slightly weaker than the literal name. That is written into the variant
doc rather than left to the name.

## The test-surface findings — worse in kind than the blocker

A bug is one defect. A test that cannot fail hides every future defect in its area.

**T1 — a completely broken RFC 8628 device-code grant passes all four CI suites.**
The auditor patched the grant so it never claims a device code, rebuilt, and ran
everything: `e2e_account_management` 6/6, `e2e_oauth_binding` 11/11,
`e2e_race_teardown` 14/14, `e2e_resolve_http` 12/12, unit 259/259 — all green. The
only test that went red, `e2e_device_code::device_code_grant_end_to_end`, is
`#[ignore]`d and runs in **no CI job**.

The mechanism is `h9_device_code_approved_no_double_redemption`, which `ci.yml`
itself calls *"the single most consequential assertion in this job… must never be
skipped to obtain a green run"*. Its assertion is `minted.len() <= 1`, and **0
satisfies it**. It never checks that any poll succeeded.

**T2 — the deactivation gate can be deleted and nothing fails, anywhere.**
Disabling `reject_if_deactivated`'s positive arm leaves the unit suite and every
e2e suite green. **The positive case — a deactivated account is refused — has no
test at all.** This is the gate memory `deactivation-not-enforced-at-signin`
records as a shipped 2026-08-31 security fix.

**T3 — `h6_deactivate_racing_refresh_no_resurrection` still does not test its
race**, after the 2026-09-10 remediation that was supposed to fix exactly this.
Instrumented: `seeded=1 post_barrier=0` in all six rounds. The deactivate wins the
barrier every time, so the post-barrier loop never runs and the `total_minted > 0`
anti-vacuity guard is satisfied entirely by the seed. `h3` is the same shape with
no guard at all.

**T4 — the OpenAPI enforcement test is bypassable.** It splits on the literal
`.route(`, so `.nest(`, `.nest_service(`, `.route_service(`, `.merge(` and
`.fallback(` are invisible. `/build` and `/legal` are served, undocumented and
unexempted, with the test green. Mutation-proven by adding
`.route_service("/oauth2/secret_admin_backdoor", …)` — still green.

**T5 — the shipped verifier's entire claim-PRESENCE layer is untested.** Making
the `mxid` claim optional and defaulting it to `expected_mxid` — i.e. **making the
replay guard bypassable by omitting the claim** — breaks no test. The same holds
for `iss`, `sub` and `iat` presence, and for every `fetch_and_verify_did` branch
that decides which typed discriminator a consumer gets (`FieldAbsent` /
`ProofAbsent`) — the exact contract CLAUDE.md tells relying parties to branch on.
Only the *value* checks are pinned.

**T6 — 24 of 67 `#[ignore]`d tests run nowhere.** Nine pass today against the
plain mock stack and need one CI line each. The rest need a real Synapse — among
them all three `e2e_did_field_live` tests, i.e. **the whole attested-DID feature
end-to-end**.

## Open findings on `/resolve` — decisions, not mechanical fixes

- **F3 — `attested: true` for a different public key.** `binds_to_localpart` uses
  `legacy_localpart`, which lowercases, so a case-variant `did:key` binds to a
  grandfathered account's localpart. That is siwx-oidc#17 reintroduced at the
  lookup layer. Reachable on any homeserver without the MSC4133 backport, and for
  any value written before the denylist was deployed (the guard is prospective
  only). **Modern-shaped accounts are safe** — `localpart_for` preserves case —
  so this is bounded to grandfathered accounts, which today is every account on
  dev and prod. The legacy localpart is *genuinely* lossy here, so the fix is a
  product decision about what `attested` may claim, not a code tidy.
- **F2 — `?did=<arbitrary string>` returns `exists: true` plus a victim's real
  MXID**, same root cause. `attested:false` is not an adequate guard, because it
  is also the normal state of every account that has not signed in since DID
  publication shipped — so a consumer cannot distinguish "hasn't published yet"
  from "your DID does not own this MXID".
- **F4 — one unauthenticated `GET /resolve` provisions a Matrix account and mints
  an admin token.** The doc says it "never provisions, never writes, and never
  mints anything"; the OpenAPI tag says *Read-only*. Both are false: the path is
  `read_did_field` → `admin_bearer()` → `provision_user` + `set_token`. The mint
  is gratuitous at this call site, since the profile route is unauthenticated.
- **F5 — no end-to-end bound.** 22.55 s measured for one request; up to ~4 × 8 s.
  Timeouts bound each *call*, not the request. No `TimeoutLayer`.
- **F7 — `reject_if_deactivated` has the defect `5421096` just fixed next door**:
  it reports a probe *failure* as "This account has been deactivated". The
  2026-09-12 remediation declined to fix it here on the grounds that
  distinguishing would leak account state to an unauthenticated prober — but all
  five call sites run **after** the caller has proven control of the DID, and
  `/resolve?did=` already publishes `exists` to anyone. Second-order and more
  important: this gate runs *before* `resolve_identity_or_legacy` on the login
  path, so a persistent probe error can never reach the `degraded` fallback. The
  D4 guard protects a door that is never used.

## Claims found FALSE or overstated

1. `resolve.rs` — *"Read-only: it never provisions, never writes, and never mints
   anything."* False on all three counts (F4).
2. `resolve.rs` — *"the same answer any client gets from Matrix registration
   availability."* On dev, `GET /_matrix/client/v3/register/available` is
   `404 M_UNRECOGNIZED` (registration is delegated via MSC3861). The conclusion
   survives by another route; the cited mechanism does not exist.
3. `localpart.rs` — *"a localpart Synapse refuses can hold no account."* Falsified
   by B1; now true only because of the errcode allowlist.
4. `oidc.rs::mxid_claim` — the "never derive a localpart" promise is defeated one
   layer up in `token()`, which stamps `legacy_localpart(did)` into
   `TokenMetadata.username`.
5. `resolve.rs` — *"a rate limiter belongs at the reverse proxy."* None was
   deployed (12/12 × 200 on dev). Addressed separately in
   siwx-oidc-matrix-server `42dac7b`.
6. `e2e/synapse_mock.py:489` — still describes the pre-`156b1f9` "any 4xx = not
   available" behaviour, i.e. it now documents the defect.

## Process finding

A peer session was editing this checkout during the audit. `src/mxid.rs` changed
twice under the first auditor, producing impossible localparts
(`@0000aq6axxl56j7d` — four leading zeros twice, ≈2⁻⁶⁴) because the binary was
built while a peer's edit was on disk. It detected the anomaly, rebuilt from a
tree verified equal to HEAD, and re-confirmed every finding. **Mutation testing in
a shared checkout silently poisons other sessions' builds** — reinforcing memory
`two-sessions-one-checkout`.
