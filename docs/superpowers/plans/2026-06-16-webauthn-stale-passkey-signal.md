# WebAuthn stale-passkey handling: structured rejection + Signal API

**Date:** 2026-06-16
**Branch:** `audit/siwx-oidc-functional-harness` (stacks on top of the uncommitted discoverable fix)
**Skill:** process-pipeline (logic-model -> execute -> audit)

## Higher-order goal (derived)

Keep passkey login a reliable, low-friction, privacy-preserving front door for the
identity stack: revocation/staleness propagates back to the user's device without the
server ever enumerating credentials and without forcing an identifier, and an
unrecognized passkey produces a legible, actionable failure instead of a server fault.

## Background (ground-truthed)

- The auth flow is usernameless/discoverable: `authenticate_start` calls
  `start_discoverable_authentication()` with empty `allowCredentials`
  (`src/webauthn.rs:228`). The uncommitted discoverable fix on this branch made
  registrations require resident keys and removed the credential-enumeration leak.
- `verify_credential` (`src/webauthn.rs:247-349`) returns `anyhow::Result`. Six
  distinct failure strings exist; `"Credential not found: {id}"` is one (line 273).
- Today every failure maps via `#[from] anyhow::Error` to `CustomError::Other`
  (`src/oidc.rs:167`) -> HTTP 500, logged as `internal_error`
  (`src/axum_lib.rs:95,114`). So selecting a stale/unknown passkey returns a 500
  (server fault) carrying the raw `Credential not found: {id}` body.
- Three call sites share `verify_credential`: login finish
  (`webauthn_authenticate_finish`, `axum_lib.rs:467` via `authenticate_finish`),
  device-approval finish (`axum_lib.rs:388`), account-action finish
  (`account.rs:610`). All three frontends do `if (!resp.ok) show(await resp.text())`,
  i.e. they surface the raw 500 body verbatim.
- No Signal API usage anywhere. Client WebAuthn JS: `js/ui/src/App.svelte`
  (login, webpack-bundled), `src/device_auth.rs` and `src/account.rs` (server-rendered
  embedded JS).

## What we are building

1. **Step 2 (server, structured 4xx + discriminator):** isolate the
   credential-lookup miss into a typed error and return it as HTTP 401 with a
   machine-readable JSON body `{ "error": "unknown_credential", "credential_id": "<b64url>", "message": "..." }`,
   logged as `unknown_credential` (not `internal_error`). The other five failure
   modes are untouched and keep their current 500/Other behavior.
2. **Step 1 (frontend, Signal API + actionable message):** on the
   `unknown_credential` discriminator, feature-detect and call
   `PublicKeyCredential.signalUnknownCredential({ rpId, credentialId })` (best-effort,
   progressive enhancement), then show the actionable message. Gated strictly on the
   discriminator so a valid key is never signaled on any other failure.
3. **Adjustments folded in:** (a) 4xx + discriminator framing (Step 2 above);
   (b) strict trigger isolation from the other five failure modes (the typed variant
   is constructed at exactly one site, and the signal fires only on the discriminator);
   (c) pre-fix non-resident credential migration/re-enrollment documented as a known
   limitation, with the re-enrollment path surfaced in the user message and docs.

## Out of scope (reserve / fast-follow)

- `signalAllAcceptedCredentials` (needs a user handle / identity scope) and
  identifier-first `allowCredentials` (hard pre-filter, costs usernameless). Both
  remain held in reserve for hard prevention, per the logic-model recommendation.
- Rebuilding the `App.svelte` webpack bundle (npm/node unavailable on this host; the
  deploy model builds it in CI). The App.svelte source change ships and is verified by
  parity with the server-rendered pages plus CI build; see Boundary Conditions.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | The credential-lookup miss (`webauthn.rs:273`) is the only site constructing `VerifyError::UnknownCredential` | The other five failure modes (no/expired challenge, decode fail, empty cred id, signature fail, UV-flag unset, sign-count regression) still map to `CustomError::Other` -> 500 | `verify_credential` lookup happens before signature verification | `cargo build`; grep shows exactly one construction site; Rust test that a signature-fail / expired-challenge case is NOT `unknown_credential` |
| H2 | A finish request references a `credentialId` not in Redis (valid challenge present) | The endpoint returns HTTP 401 with JSON `{error:"unknown_credential", credential_id}` and logs `unknown_credential`, not `internal_error` | Lookup miss reachable before signature check | Rust integration test (status + body) and/or browser E2E network assertion |
| H3 | The finish response carries `error:"unknown_credential"` AND the browser supports `PublicKeyCredential.signalUnknownCredential` | The frontend calls it exactly once with `{rpId, credentialId}` matching the start challenge's `rpId` and the returned `credential_id` | CDP virtual authenticator; `rpId` present in the start challenge | Browser E2E spy assertion on `PublicKeyCredential.signalUnknownCredential` |
| H4 | `PublicKeyCredential.signalUnknownCredential` is absent (unsupported) | The frontend shows the actionable message and does not throw/crash | Feature detection guards the call | Browser E2E with the symbol stubbed undefined |
| H5 | The failure is any non-unknown-credential error (signature invalid, challenge expired, etc.) | The frontend does NOT call `signalUnknownCredential` (no valid key is pruned) | Discriminator is the sole trigger | Browser E2E forcing a signature/challenge failure; assert spy not called; server returns 500/Other |
| H6 | A user holds a pre-fix non-resident credential that no longer surfaces or resolves | The documented re-enrollment path (wallet sign-in -> link a new passkey, or register fresh) restores login, and the limitation is documented | Wallet/link path already works (existing tests) | Doc presence check; message text includes re-enroll guidance |
| H7 | The changes are applied | The existing passkey register -> login -> token happy path still passes (no regression) | Existing E2E harness runnable | `cargo test --bin siwx-oidc`; `e2e/browser/device-lifecycle.spec.mjs` green |

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|-----------|------------|
| AC1 | Selecting a stale/unknown passkey no longer returns 500; returns 401 + `unknown_credential` discriminator | H1, H2 |
| AC2 | The stale key is signaled for pruning on supported browsers | H3 |
| AC3 | A clear, actionable message shows on all browsers, including unsupported ones | H2, H4 |
| AC4 | Valid keys are never signaled/pruned (trigger isolation) | H1, H5 |
| AC5 | Pre-fix migration/re-enrollment documented; reserve options noted | H6 |
| AC6 | No regression to the happy-path passkey login | H7 |

## Tasks

### Task 1: Typed `VerifyError` and reclassify the lookup miss (server)

**Hypotheses:** H1
**Files:** `src/webauthn.rs`

- [ ] Add `pub enum VerifyError { UnknownCredential(String), Other(#[from] anyhow::Error) }` (thiserror), where `UnknownCredential` carries `cred_id_b64`.
- [ ] Change `verify_credential` return type to `Result<AuthenticateFinishResponse, VerifyError>`; the post-lookup `?` on anyhow operations auto-convert via `From`.
- [ ] Replace only the `webauthn.rs:273` `ok_or_else(|| anyhow!("Credential not found..."))` with `ok_or_else(|| VerifyError::UnknownCredential(cred_id_b64.clone()))`. Leave the other five failure sites as anyhow.
- [ ] Change `authenticate_finish` return type to `Result<_, VerifyError>` (its later anyhow ops auto-convert).
- [ ] `cargo build` clean; grep confirms exactly one `UnknownCredential(` construction.

### Task 2: `CustomError::UnknownCredential` 401 + JSON, mapped at all three call sites (server)

**Hypotheses:** H1, H2
**Files:** `src/oidc.rs`, `src/axum_lib.rs`, `src/account.rs`

- [ ] Add `CustomError::UnknownCredential(String)` variant (`src/oidc.rs`).
- [ ] In `IntoResponse` (`src/axum_lib.rs:80`): log it as `warn!(... "unknown_credential")` (NOT `internal_error`), and return `(StatusCode::UNAUTHORIZED, Json(json!({"error":"unknown_credential","credential_id":cred_id,"message":<actionable+re-enroll text>})))`.
- [ ] Add `From<VerifyError> for CustomError` (or a small `map` helper): `UnknownCredential -> CustomError::UnknownCredential`, `Other(e) -> CustomError::Other(e)`.
- [ ] Apply the mapping at the three call sites: `axum_lib.rs:388` (device), `axum_lib.rs:467` (login, via `authenticate_finish`), `account.rs:610` (account).
- [ ] `cargo build` clean.

### Task 3: Login frontend Signal API + message (`App.svelte`)

**Hypotheses:** H3, H4, H5
**Files:** `js/ui/src/App.svelte` (`handlePasskeySignIn`, ~lines 262-264)

- [ ] On `!finishResp.ok`, clone+parse JSON; if `body.error === 'unknown_credential'`: feature-detect `PublicKeyCredential.signalUnknownCredential`, and if present call `await PublicKeyCredential.signalUnknownCredential({ rpId: options.publicKey.rpId, credentialId: body.credential_id })` inside try/catch (best-effort); then throw/show `body.message`.
- [ ] Otherwise fall back to existing `await finishResp.text()` behavior. No signal call on any other branch.
- [ ] Note: bundle rebuild is CI's job (npm unavailable locally); verified by parity (Task 4/5) + CI.

### Task 4: Device + account frontends Signal API + message (server-rendered)

**Hypotheses:** H3, H4, H5
**Files:** `src/device_auth.rs` (`approvePasskey`, ~line 622), `src/account.rs` (`authPasskey`, ~line 1436)

- [ ] Apply the same discriminator handling as Task 3 in both embedded JS blocks (parse JSON, feature-detected `signalUnknownCredential`, actionable message via `showStatus`). These rebuild with `cargo`.
- [ ] `cargo build` clean; existing string-presence unit tests still pass.

### Task 5: Tests (Rust + browser E2E)

**Hypotheses:** H2, H3, H4, H5, H7
**Files:** `src/webauthn.rs` or a test module (Rust), `e2e/browser/stale-credential.spec.mjs` (new)

- [ ] Rust: integration/unit test that a finish with a valid challenge but an unregistered `rawId` yields 401 + `{error:"unknown_credential"}` (lookup precedes signature check). If seeding a challenge at unit level proves impractical, document and rely on the browser E2E for H2.
- [ ] Browser E2E (CDP virtual authenticator) against a server-rendered passkey page (account or device approval, both rebuilt by cargo): (a) inject a resident credential the server does not know; (b) attempt discoverable auth; (c) assert finish status 401 + discriminator; (d) spy asserts `signalUnknownCredential` called once with matching `{rpId, credentialId}`; (e) stub the symbol undefined and assert graceful message + no crash; (f) force a non-unknown failure and assert the spy is NOT called.
- [ ] Regression: `cargo test --bin siwx-oidc` and `e2e/browser/device-lifecycle.spec.mjs` green.

### Task 6: Docs (migration/re-enrollment + reserve options)

**Hypotheses:** H6
**Files:** `CLAUDE.md` (Troubleshooting item #5), this plan doc

- [ ] Update Troubleshooting #5 to describe the new 401 + `unknown_credential` behavior and the pre-fix non-resident credential limitation, with the re-enrollment path (wallet sign-in -> link a new passkey, or register fresh).
- [ ] Note `signalAllAcceptedCredentials` and identifier-first `allowCredentials` as the held-in-reserve hard-prevention options.

## Boundary Conditions

- **Assumption (load-bearing):** `verify_credential` performs the credential lookup
  (line 270-273) before signature verification (line 294). If a future refactor
  reorders these, H2's "lookup miss reachable" breaks. Guard: keep lookup before verify.
- **Constraint (npm/node unavailable on host):** the `App.svelte` bundle cannot be
  rebuilt locally. The source change ships and is verified by parity with the
  server-rendered device/account pages (identical client logic, fully E2E-tested here)
  plus the CI webpack build. Do not claim local browser verification of the login page.
- **Invariant (the top risk):** `signalUnknownCredential` must fire only on the
  `unknown_credential` discriminator. Never signal on signature-fail, expired-challenge,
  sign-count regression, or transient/infra errors, or a valid passkey could be pruned
  from the user's device (self-inflicted lockout). H5 guards this.
- **Invariant (no enumeration):** we only ever signal a credentialId the client just
  presented (echoed back in the error body). We never enumerate stored credentials.
  This preserves the property the discoverable fix just secured.
- **Exclusion:** no change to the registration flow, the discoverable fix, or the
  reserve options. No bundle rebuild. No `signalAllAcceptedCredentials`.
- **Status choice:** 401 Unauthorized for the unknown-credential body (an assertion was
  presented as proof of identity and could not be honored). Open to 400 if preferred;
  the discriminator, not the status, is what the frontend keys on.
