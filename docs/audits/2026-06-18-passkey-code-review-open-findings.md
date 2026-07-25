# Passkey work — code-review open findings (durable record)

These findings came from a multi-angle review run during the 2026-06-18 session
(reviewed `e64e606`/PR #12; most still apply on `db79e75`/PR #13). They existed only in
the chat transcript; persisted here so a follow-up session has entry points. Ranked
correctness-first. Status as of end of 2026-06-18.

| # | Severity | Status | File / entry point | Finding |
|---|----------|--------|--------------------|---------|
| 1 | High | OPEN | `src/webauthn.rs` `require_resident_key` + register_finish; webauthn-rs 0.6.0-dev | Resident-key requirement is set on the client-facing options only; `finish_passkey_registration` does not enforce discoverability, so a non-cooperating authenticator could store a non-resident credential that never surfaces in the discoverable picker. Mitigated in practice (platform authenticators honor `required`). Fix = enforce at the registration-state layer or check credProps/BE flag at finish. |
| 2 | High (test) | OPEN | `e2e/browser/device-lifecycle.spec.mjs` loginToToken (~218) | PKCE e2e is cosmetic: `code_challenge` is sent to `/authorize` but never forwarded to `/sign_in`, so `code_entry.code_challenge` stays None and the `code_verifier` is never validated. A real `/token` PKCE-binding regression would NOT be caught. Fix = forward the challenge to /sign_in. |
| 3 | Medium | OPEN | `src/webauthn.rs` verify_credential (the `from_str` paths ~302/357) | A present-but-corrupt or revoked-but-present credential returns 500/400 with no `unknown_credential` discriminator, so the stale-key prune/UX never fires. "Stale" is modeled as absent only. Low likelihood. |
| 4 | Medium-low | OPEN | `src/oidc.rs` From<VerifyError>; `src/axum_lib.rs`; `src/account.rs` | Login verify-failure returns 500 (raw `{:?}` Debug body) while device/account return 400 — pre-existing per-flow split, now the VerifyError->CustomError mapping is encoded in 3 places (From impl + 2 inline matches) that disagree on the Other arm. Consolidate to one mapping + a deliberate per-flow status. |
| 5 | Medium-low | OPEN | `js/ui/src/App.svelte` (login passkey error path) | The removed `allowCredentials.length===0` guard left zero-passkey users with a generic "cancelled"/NotAllowedError message instead of "register a passkey first." (Scoping work did not re-add a no-passkey hint.) |
| 6 | Low (test) | LIKELY ADDRESSED | `e2e/browser/stale-credential.spec.mjs` | Spec did not call `mockReset` -> order-dependent. The 2026-06-18 Task-7 work reworked `synapse_mock.py` fidelity + seeding; re-verify isolation. |
| 7 | Low (test) | OPEN | `e2e/browser/stale-credential.spec.mjs` H4 (~168) | H4 can pass for the wrong reason: the 401 JSON body contains "no longer valid", so the regex matches even if discriminator parsing broke and the raw body was dumped. Add a signal-count assertion. |
| 8 | Low (test) | OPEN | `e2e/browser/stale-credential.spec.mjs` installSignalSpy (~390) | Plain assignment to the static `PublicKeyCredential.signalUnknownCredential` may silently no-op if the native prop is non-configurable -> flaky. Use `Object.defineProperty`. |
| 9 | Low (test) | OPEN | `src/axum_lib.rs` unknown_credential_response_tests | The docstring asserts "every other failure stays 500" but only the From path is exercised; device/account Other->400 inline matches are untested. |
| 10 | Low (cleanup) | PARTIAL | `App.svelte` + `account.rs`/`device_auth.rs` embedded JS | signalUnknownCredential + discriminator block is copy-pasted across 3 frontends; App.svelte bundle is CI-built (now bundle-grep-verified, but drift risk remains). Consider a shared JS asset. |
| 11 | Low (cleanup) | OPEN | `e2e/browser/stale-credential.spec.mjs` | Re-implements `redisCommand`/`parseResp` from `device-lifecycle.spec.mjs`; extract a shared `redis-helper.mjs`. |
| 12 | Low (perf) | OPEN | `src/webauthn.rs` verify_credential (~357) | `cred_json` is deserialized twice per successful auth (Passkey + serde_json::Value for the counter). Pre-existing. |
| 13 | Low (footgun) | OPEN | `src/oidc.rs` CustomError::UnknownCredential | The `#[error(...)]` Display is dead (into_response builds the JSON by hand). A future generic `to_string()` path would break the frontend discriminator. |

**To regenerate against current code:** run `/code-review ultra` on `main` next session
(reviews the committed branch in the cloud) or a local multi-angle review of
`git diff e64e606..HEAD`. None of these block the shipped feature; #1 and #2 are the
highest-value fast-follows.
