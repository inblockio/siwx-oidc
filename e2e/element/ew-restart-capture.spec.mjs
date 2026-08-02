/**
 * EW-T5-1: T5 phase 1 — capture pre-restart session state (H-D1).
 *
 * Plan: docs/superpowers/plans/2026-07-25-session-durability-no-forced-logins.md
 * Task T5 / Hypothesis H-D1: "If session state survives a full stack restart
 * (durable AOF, named volume, verified replay), then a client holding a valid
 * refresh token stays logged in with the SAME device_id; zero new device
 * provisions." This spec is the FIRST of two legs. It logs in, proves the
 * session is genuinely live, and writes everything the second leg needs to
 * disk so it survives the restart driven by `t5-restart-survival.sh` between
 * the two Playwright runs (each `run.sh` invocation is a fresh, short-lived
 * container — nothing survives in memory between phases, only the mounted
 * `/e2e` tree does).
 *
 * DEVICE_ID DERIVATION — read helpers/oidc-login.mjs and helpers/sessions.mjs
 * before picking a source, per the task brief. Two candidates existed:
 *
 *   (a) parse `urn:matrix:client:device:{id}` out of the /token response's
 *       `scope` field (loginWalletToTokens's own doc comment suggests this:
 *       "device_id often appears in the issued scope").
 *   (b) trust `loginWalletToTokens`'s returned `device_id`, which for
 *       `whoami: true` (the default, used here) comes from a real
 *       `GET /_matrix/client/v3/account/whoami` call.
 *
 * CHOSEN: (b), matrixWhoami. Verified by reading `src/oidc.rs`: neither
 * `token_authorization_code` (the grant this login flow uses) nor
 * `token_refresh` ever calls `response.set_scopes(...)` on the
 * `CoreTokenResponse` — only `token_device_code` does. The `oauth2` crate's
 * `StandardTokenResponse.scopes` field carries
 * `#[serde(skip_serializing_if = "Option::is_none")]`, so when unset the
 * `scope` key is OMITTED from the JSON body entirely, not merely empty. So
 * for a wallet login `body.scope` is always absent and the "often appears in
 * scope" comment is aspirational, not the real contract — which is exactly
 * why `loginWalletToTokens` falls back to (and, with `whoami: true`, always
 * uses) the whoami-derived `device_id`. Using scope here would just read
 * `undefined`. This finding is carried forward into ew-restart-assert.spec.mjs
 * (its "A. Refresh survives" leg), which treats the CS-API, not `scope`, as
 * the authoritative source for device_id continuity across the restart.
 *
 * State file: e2e/element/test-results/t5-state.json — inside the `/e2e` tree
 * `run.sh` bind-mounts into the container, so it is a real file on the HOST
 * disk and survives both the container exiting and the stack restart.
 */
import { test, expect } from '@playwright/test';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireElementStack, MATRIX_URL, SIWX_URL } from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { matrixWhoami, listDevices } from './helpers/sessions.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Exported so the phase-2 spec (which cannot import from this file — Playwright
// runs each spec file as its own isolated worker/process) can recompute the
// identical path independently. Keep both copies in sync if this ever moves.
// NOT under `test-results/`: that is Playwright's default `outputDir` (unset in
// playwright.config.mjs, so it defaults to `test-results`), and Playwright clears
// the output directory at the START of a run. Phase 4 is a separate `playwright
// test` invocation, so a state file living there would be deleted moments before
// the assert spec tried to read it -- surfacing as "phase 1 did not run" and
// looking exactly like a capture failure. Kept as a sibling file instead.
export const STATE_PATH = path.join(__dirname, '.t5-state.json');

// Lab convention: server_name is 'localhost' across the sibling EW-* specs
// (see ew-recovery-entry.spec.mjs SERVER_NAME, ew-verify-sas.spec.mjs). Purely
// cosmetic here — loginWalletToTokens never reads wallet.mxid, only
// wallet.did/wallet.wallet — but kept for house-style consistency.
const SERVER_NAME = 'localhost';

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-T5-1: capture pre-restart session state (device_id, tokens, device list)', async ({
  page,
}) => {
  test.setTimeout(120_000);

  const w = makeWallet(undefined, SERVER_NAME);

  // Full headless OIDC wallet login (DCR + PKCE + CAIP-122 + /token), with
  // Matrix scope so Synapse provisions a device. whoami defaults to true, so
  // the returned device_id/user_id are whoami-verified, not scope-parsed
  // (see the file header — this is a deliberate choice, not the default we
  // happened to get).
  const session = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });

  expect(session.access_token, 'login did not return an access_token').toBeTruthy();
  expect(session.refresh_token, 'login did not return a refresh_token').toBeTruthy();
  expect(session.device_id, 'login did not resolve a device_id via whoami').toBeTruthy();
  expect(session.client_id, 'loginWalletToTokens did not expose client_id').toBeTruthy();

  // --- PRE-restart liveness proof -------------------------------------
  // A SECOND, independent whoami call (loginWalletToTokens already made one
  // internally to resolve device_id above) — this is the "session is live"
  // assertion the task asks for, not a reuse of the login helper's own check.
  const who = await matrixWhoami(session.access_token, MATRIX_URL);
  expect(who.status, `pre-restart whoami failed: ${JSON.stringify(who.body)}`).toBe(200);
  expect(who.body.user_id).toBe(session.user_id);
  expect(who.body.device_id).toBe(session.device_id);

  const devices = await listDevices(session.access_token, MATRIX_URL);
  const deviceIds = devices.map((d) => d.device_id);
  expect(
    deviceIds,
    `session.device_id (${session.device_id}) not present in listDevices() output: ${JSON.stringify(deviceIds)}`,
  ).toContain(session.device_id);

  // --- Persist state for phase 2 (post-restart) ------------------------
  const state = {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    user_id: session.user_id,
    device_id: session.device_id,
    client_id: session.client_id,
    device_ids: deviceIds,
    device_count: deviceIds.length,
    captured_at_ms: Date.now(),
  };

  await fs.mkdir(path.dirname(STATE_PATH), { recursive: true });
  await fs.writeFile(STATE_PATH, JSON.stringify(state, null, 2), 'utf8');

  // eslint-disable-next-line no-console
  console.log(
    `[EW-T5-1] captured: user_id=${state.user_id} device_id=${state.device_id} ` +
      `device_count=${state.device_count} device_ids=${JSON.stringify(state.device_ids)} ` +
      `captured_at_ms=${state.captured_at_ms} -> ${STATE_PATH}`,
  );
});
