# Audit — the provider-attested DID identity attribute

**Date:** 2026-09-10. **Branch:** `feat/opaque-mxid-localpart`.
**Under audit:** siwx-oidc `42b78fa..01d37f6`; siwx-oidc-matrix-server `9105a33`, `a351300`, `9736d59`.
**Plan + hypothesis register:** `docs/superpowers/plans/2026-09-10-immutable-attested-did.md`.
**Method:** an independent adversarial pass, briefed to find what is wrong or unproven and
told not to be agreeable. Every "Confirmed" below cites a check the auditor ran or read
themselves, not the implementers' report.

## Verdict

**Shippable to dev; not yet to prod.** The core security claim survived attack: the ACL
probe was independently reproduced end to end, a genuine cross-account replay was planted
and refused, ten JOSE attacks were thrown at the verifier, and three guards were broken by
hand and confirmed to make named tests fail. What did not survive is the *framing* around
three claims — see "Corrections" — and five real defects were found, none of them a
blocker for dev, all of them worth closing before prod.

## Hypothesis trace

| ID | Status | Evidence |
|---|---|---|
| H1 publish works | **Confirmed** | Unauthenticated GET returns `{did, proof}` with exact DID case, on both a `did:pkh` and a `did:key` account |
| H2 row-less 500 | **Confirmed**, test weaker than the claim | Row-less state manufactured the product's own way (`delete_user erase:true`); PUT → 500. But the body is generic → **D1** |
| H3 self-heal | **Confirmed** | Foreign proof planted, re-login advanced `iat` 1789012050 → 1789012078 |
| H4 derived kid | **Confirmed** | Live JWKS `kid=35812a3e6e1db0d7`; both constructors funnel through `with_derived_kid`; no `kid` parameter remains |
| H5 ephemeral gate | **Confirmed** | Second instance with no PEM logged the refusal banner and minted no proof |
| H6 replay rejected | **Confirmed** | Live replay refused; mutation of the binding makes the named test fail |
| H7 tamper/alg | **Confirmed, 2 gaps** | 10 attacks refused; `crit` ignored and ECDSA `(r, n−s)` malleable → **D6** |
| H8 interop | **Confirmed** | Server-minted → real Synapse → shipped client CLI verified |
| H9 ACL | **Confirmed** | All five legs reproduced independently with a real user token |
| H10 patch applies | **Partial** | Guard correct in the running image; every caller traced. "Full harness green" was overstated → **Corrections** |
| H11 alias split | **Confirmed** | `displayname` is the localpart; mutation to the DID fails both `h11_*` tests |
| H12 no regression | **Confirmed** | EXIT=0, 19 targets, 256 passed; both false-green traps actively defeated |

Acceptance criteria AC1–AC6 and AC8 confirmed. **AC7 partial**: "no regression" is
established over the 256 non-ignored tests plus nine live suites the auditor ran, but ten
`--ignored` tests in two files are executed by neither `cargo test` nor the harness (**D12**).

## Defects

| ID | Severity | Summary |
|---|---|---|
| **D1** | should-fix | Any Synapse 500 is classified as the known row-less-account bug. The body is generic, so a real outage logs as a reassuring, self-resolving condition while publication is 100% down. The errcode discriminator already exists in the same file (`has_profile_row`) |
| **D2** | should-fix | Single-key JWKS + deliberate absence of `exp` means one `SIWEOIDC_SIGNING_KEY_PEM` rotation permanently voids every proof already written. Dev's key was exposed 2026-09-09 |
| **D3** | should-fix | The verifier never checks `discovery.issuer` against the URL it was fetched from (OIDC Discovery §4.3), and follows `jwks_uri` to any origin. `VerifiedDid.issuer` is therefore attacker-chosen text, contradicting its own doc comment |
| **D4** | should-fix | The fail-safe localpart fallback, correct in itself, now causes a **validly signed** assertion to be published for a duplicate account. Two accounts then carry verifying proofs for one DID |
| **D5** | should-fix | `Client::new()` has no timeout. Two new awaits are on the login path, and `detected_mxid_for` put a Synapse dependency on `/webauthn/authenticate/start`, which had none. "Never fails sign-in" holds for errors, not hangs |
| **D6** | nit | `crit` ignored (RFC 7515 §4.1.11 says MUST reject); JWK `use`/`key_ops`/`alg` unchecked; ECDSA signatures malleable |
| **D7** | nit | `VerifiedDid` has public fields and derives `Deserialize`, so one can be conjured from untrusted JSON without ever passing a signature check |
| **D8** | nit | Three wrong `src/oidc.rs:NNN` citations in the consumer crate's module docs |
| **D9** | nit | A test comment cites a module for a case-folding invariant that module does not test (it is pinned by `mxid::tests::pkh_case_folding_is_canonical_lowercase`) |
| **D10** | nit | 18 stray spaces mid-message in a log line |
| **D11** | nit (policy) | The denylist means a user cannot unpublish their own DID; the only route is account erasure. Worth documenting as the corollary of "world-readable" |
| **D12** | should-fix (process) | `e2e_race_teardown` and `e2e_account_management` run under neither `cargo test` nor the harness, because `e2e/synapse_mock.py` predates the MAS-endpoint migration. So `grandfathered_legacy_account_keeps_legacy_localpart_on_real_signin` — the only end-to-end proof of the invariant protecting every pre-migration user — is executed by nothing. It passes when run by hand |

## Corrections to claims made during this work

1. **"Full harness green"** (plan H10). `run.sh full` reports `OVERALL: FAIL` — 15 pass, 0
   fail, 5 harness-error. The five are the connector adapter refusing a dirty checkout in
   an unrelated repo, so no siwx-oidc check is implicated, but the bar as written was not
   met. The plan's verification column now states the correct bar.
2. **"A 500 from this route means row-less account, state unknown, not error."**
   Over-narrow, as above. The `502/503/504 stay hard errors` half is correct and does
   close the dead-upstream case; it does not close the sick-homeserver case.
3. **"A caller that stores this struct is storing only attested data"** (`VerifiedDid`).
   Attested by whoever answered at `issuer_base_url`, whose claimed identity was never
   checked against that URL.
4. **The audit brief itself was wrong.** It told the auditor this stack held two row-less
   accounts. It did not — the harness had been recreated with `--fresh` in between, and
   the auditor found 31 users / 31 profiles and had to manufacture one. The "3 of 102"
   figure is about the dev deployment, not the local harness.

## Not verified

- The Synapse patch's **upstream provenance** (that PR #19980's merge base is
  byte-identical to tag v1.159.0, and that head `d4758f2d2` was taken) — the auditor had
  no network. It was verified during implementation and is recorded in
  `../siwx-oidc-matrix-server/patches/synapse/README.md`; the auditor independently
  confirmed the patch text is internally consistent, applies at the live image's offsets,
  and matches the deployed bytes.
- The deliberate build-failure demonstration (corrupting a context line → exit 1) was run
  during implementation, not re-run by the auditor.
- `e2e_account_lifecycle_live` fails at the harness's documented `MATRIX_HOST` (`:18080`)
  because the Caddy edge does not proxy `/_synapse/admin/*`; it passes at `:18448`.
  Pre-existing and not attributable to this work, but it means that suite is running
  against a host the harness would not use.
- Everything here is the local e2e harness. Dev and prod are untouched, which is where the
  plan's exclusions said to stop.
