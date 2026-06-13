# Plan: device_id sanitizer corrupts opaque Matrix device_ids (2026-06-13)

`siwx-oidc/src/account.rs::sanitize_device_id` strips a device_id to
`[A-Za-z0-9._-]` before it is used as the canonical identity for the account
management flow. Element X device_ids are **base64** (the device's key material),
carrying `+`, `/`, `=`. Stripping mutates the identity, so "Sign out" sends a
corrupted id, `get_device` finds no match, and the flow returns **"Device not
found"**. Every Element X session whose device_id contains `+`/`/`/`=` is therefore
**unmanageable** from the account page (the "Element X - Device removed (session
stale)" ghost on `matrix.inblock.io`, device_id `Yw+vNuhUTaNa+dAXjkVkBZk6xcPVsv3RrLGmjBtwHAg`).

## Evidence (traced, not assumed)

- **Producer (correct, verbatim):** `oidc.rs:615-635` extracts the **client-proposed**
  device_id from the OAuth scope `urn:matrix:client:device:<id>` (MSC2967) and provisions
  it verbatim; it only generates a `SIWX_<uuid>` when the scope carries none. Element X
  chooses the base64 id.
- **Single corruption point:** `account.rs:608-612` applies `.map(sanitize_device_id)` to
  the query device_id; the stripped value is embedded as `data-device-id="{device_id}"`
  at `account.rs:661` (the ONLY interpolation site), read back by JS via
  `document.body.dataset.deviceId` (`account.rs:1022`), POSTed (`:1045/:1087`), and passed
  to `execute_action` -> `get_device`/`delete_device`.
- **Every other layer already handles raw/opaque ids:** the Synapse admin client
  percent-encodes the path segment (`synapse_client.rs:286`); the POST handlers pass
  `req.device_id` raw (`account.rs:443/482`, no sanitize); the client-side device LIST
  already HTML-escapes with `esc()` (`account.rs:1115-1117`, set `& < > " '`).
- **Backend confirmation (prod, read-only):** the stuck device row still exists with E2EE
  keys intact (0 orphaned key rows for it); it is a live-but-abandoned device, not an
  orphaned-signature ghost.

## Steelman: the defect is the consumer, not the producer

The strongest case for fixing `sanitize_device_id` (consumer) rather than normalizing
device_ids at provisioning (producer):

1. **Spec.** Matrix device_ids are **opaque** strings (Client-Server API). No charset
   restriction exists; a consumer that assumes `[A-Za-z0-9._-]` is non-conformant.
2. **Producer is correct and not ours to change.** Element X picks the device_id; we
   re-use it verbatim by design.
3. **Rewriting at provisioning would re-break E2EE.** The device_id is the key under which
   the device's cross-signing signature and one-time keys live. Re-using the client id
   verbatim is exactly what stopped the identity-churn / "reset your digital identity" bug
   (CLAUDE.md device lifecycle; `docs/2026-05-19-device-verification-analysis.md`).
   Normalizing it would desync our id from Element X's real device identity ->
   re-introduce churn + verification failure, and could not fix already-provisioned ids.
4. **The sanitizer conflates two concerns:** "safe to interpolate into HTML" and "the
   identity to call the API with." Stripping mutates the identity to achieve display
   safety. The correct tool for display safety is **escaping** (lossless) -- which the
   codebase already uses client-side (`esc()`). The server reached for stripping. That is
   the single defect.

Counter-arguments rebutted:
- *"Just widen the allowlist to include `+/=`."* Un-breaks today but keeps a lossy denylist
  that the next legitimate opaque char defeats; not principled. (Acceptable only as an
  emergency interim.)
- *"Stopping the strip reintroduces XSS."* No: replace strip with context-correct
  HTML-attribute escaping at the one site (`:661`); the browser decodes the attribute back
  to the exact id for `dataset.deviceId`. Lossless and safe; a test asserts an XSS payload
  is escaped.

**Conclusion: fix the consumer.** Remove the strip; HTML-attribute-escape at render.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | Matrix device_ids are opaque and Element X supplies base64 verbatim via the OAuth scope | the defect is in the consumer (sanitizer), not the producer (provisioning) | `oidc.rs` reuses the client device_id verbatim; spec opaqueness | **CONFIRMED** code read `oidc.rs:615-635`; Matrix C-S API |
| H2 | `sanitize_device_id` strips `+`/`/`/`=` at `account.rs:611` | the rendered `data-device-id` is corrupted -> POSTed id mismatches -> `get_device` None -> "Device not found" | render->dataset->POST path as traced | new RED test `account_page_preserves_base64_device_id_in_attr` |
| H3 | remove the strip and HTML-attribute-escape at render (`:661`) | a base64 device_id round-trips exactly to `delete_device`; an XSS payload is escaped | browser decodes the attribute back to the exact value for the `dataset` read | GREEN tests (preserve-base64 + escape-xss); `cargo test` |
| H4 | the Synapse client + POST handlers already use raw ids | no other layer needs changing | `synapse_client.rs:286` encodes; `req.device_id` passed raw | **CONFIRMED** code read + grep call sites |
| H5 | delete orphaned `e2e_cross_signing_signatures` (anti-join `devices`) on prod | the 68 orphans are removed, live-device signatures untouched, total 162 -> 94 | table has no FK; anti-join correct; backup taken first | pre/post counts on prod; live-sig spot check |

## Acceptance Criteria

| # | Criterion | Hyp |
|---|----------|-----|
| AC1 | A device_id with `+`/`/`/`=` round-trips through `account_page` unchanged (regression test green) | H2,H3 |
| AC2 | An XSS payload in device_id is HTML-escaped in the rendered attribute (no raw `<script>`) | H3 |
| AC3 | `sanitize_device_id` removed; no production code strips the device_id identity | H3,H4 |
| AC4 | `cargo test` + `cargo clippy` green in siwx-oidc | H3 |
| AC5 | (gated, prod) orphan sweep: 0 orphaned cross-signing signatures remain; live-device signatures intact; backup exists | H5 |
| AC6 | Steelman (consumer-not-producer) documented | H1 |
| AC7 | (deploy, gated) siwx-oidc `:main` rebuilt + deployed; the stuck Element X device is then sign-out-able from the account UI (human gate) | H3 |

## Tasks (branch `fix/device-id-sanitizer-opaque-ids`)

- **Task 1 [H2,H3,H4] — code (TDD).** RED: add `account_page_preserves_base64_device_id_in_attr`
  and `account_page_escapes_xss_device_id` (both fail today). GREEN: add `html_attr_escape`
  (mirror the JS `esc` set `& < > " '`), remove `.map(sanitize_device_id)` at `:611` (keep
  raw), HTML-attribute-escape the device_id at the `:661` interpolation, delete the now-unused
  `sanitize_device_id` + its test `sanitize_device_id_keeps_safe_chars_strips_markup`. Keep
  `sanitize_action` (action is allowlisted). `cargo test` + `cargo clippy` green.
- **Task 2 [H1,AC6] — docs.** This plan carries the steelman; add a short note to siwx-oidc
  CLAUDE.md / device-lifecycle docs that device_ids are opaque and must be escaped-not-stripped.
- **Task 3 [H5] — prod orphan sweep (GATED write).** Runbook: backup `e2e_cross_signing_signatures`
  (or full DB), snapshot the 68 orphan rows, `DELETE` via anti-join, re-count (expect 0 orphan /
  94 total), spot-check a live device's signatures intact. Execute only on explicit go-ahead.
- **Task 4 [H3,AC7] — deploy (GATED).** Push branch -> merge -> CI builds siwx-oidc `:main` ->
  pull/up `siwx-oidc` on prod -> human gate: sign out the stuck Element X device from the account UI.

## Relationship to the stuck device

The stuck `Yw+...` device is a **live** device row, NOT an orphan, so the Task-3 sweep does
not touch it. Once Task 1 ships (Task 4 deploy), the user can sign it out normally from the
account page. No hand-deletion of that specific device is in scope unless requested.

## Execution note

Memory is AMBER; subagent fan-out is refused by admission control. Tasks 1-2 are one file +
docs, executed inline with staged commits (red, then green, then docs). Tasks 3-4 are
outward-facing/destructive and gated on the user.
