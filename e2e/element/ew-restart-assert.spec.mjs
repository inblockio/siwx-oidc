/**
 * EW-T5-2: T5 phase 2 — post-restart assertions (H-D1).
 *
 * Runs AFTER `t5-restart-survival.sh` has restarted the whole local stack
 * (siwx-oidc + matrix_synapse + redis + element-web + caddy) via
 * `docker-compose ... restart` (never `down`/`-v`, so the named `redis_data`
 * AOF volume survives). This spec reads the state `ew-restart-capture.spec.mjs`
 * wrote to `test-results/t5-state.json` and proves H-D1's claim end to end:
 * a client holding a pre-restart refresh token stays logged in under the
 * SAME device_id, with zero new Synapse device provisions.
 *
 * Each `run.sh` invocation is a fresh container/process, so this file cannot
 * import anything in-memory from the capture spec — only the state file
 * (mounted `/e2e` tree, a real file on the host disk) crosses the restart.
 *
 * FAILURE POLICY (plan section 8, "verification discipline"): assertion A is
 * explicitly load-bearing for H-D1 — a 400 invalid_grant there means the
 * hypothesis is REFUTED, and the thrown error says so in those words rather
 * than a generic HTTP-status message. Nothing here is weakened to make a
 * flaky run pass; the 240s conditional (D) exists precisely so a legitimate
 * access-token expiry cannot be *mis*read as a durability defect, while still
 * asserting the real defect loudly whenever it is legitimately in scope.
 */
import { test, expect } from '@playwright/test';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireElementStack, MATRIX_URL, SIWX_URL } from './helpers/element.mjs';
import { matrixWhoami, listDevices } from './helpers/sessions.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Must match ew-restart-capture.spec.mjs::STATE_PATH exactly (re-derived here,
// not imported — Playwright runs each spec file in its own worker, and phase 1
// and phase 2 are separate `run.sh`/container invocations besides).
// Must match ew-restart-capture.spec.mjs::STATE_PATH. Deliberately NOT under
// `test-results/` — Playwright clears its outputDir at the start of every run,
// and phase 4 is a separate invocation, so the state would be wiped before it
// could be read.
const STATE_PATH = path.join(__dirname, '.t5-state.json');

// ACCESS_TOKEN_TTL in src/oidc.rs is 300s. Leave 60s of safety margin so a
// legitimately-close-to-expiry token is treated as "may have expired" rather
// than asserted, per the task brief's explicit 240s cutoff.
const ACCESS_TOKEN_TTL_MS = 300_000;
const SAFETY_MARGIN_MS = 60_000;
const CUTOFF_MS = ACCESS_TOKEN_TTL_MS - SAFETY_MARGIN_MS; // 240_000

const REQUIRED_FIELDS = [
  'access_token',
  'refresh_token',
  'user_id',
  'device_id',
  'client_id',
  'device_ids',
  'device_count',
  'captured_at_ms',
];

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-T5-2: refresh survives restart, zero new devices, identity unchanged (H-D1)', async () => {
  test.setTimeout(120_000);

  // --- Load phase-1 state, with a clear "phase 1 didn't run" diagnosis ---
  let raw;
  try {
    raw = await fs.readFile(STATE_PATH, 'utf8');
  } catch (e) {
    throw new Error(
      `t5-state.json not found at ${STATE_PATH} (${e.code ?? e}). This means ` +
        'ew-restart-capture.spec.mjs (T5 phase 1) did not run before this spec, or ' +
        'the state file did not survive on the mounted /e2e tree. Run ' +
        't5-restart-survival.sh end to end rather than invoking this spec directly.',
    );
  }
  const state = JSON.parse(raw);
  const missing = REQUIRED_FIELDS.filter((k) => state[k] === undefined);
  expect(
    missing,
    `t5-state.json is missing required field(s) ${JSON.stringify(missing)} — phase 1 ` +
      `wrote an incomplete state file: ${raw.slice(0, 500)}`,
  ).toEqual([]);

  const elapsed = Date.now() - state.captured_at_ms;

  // ================= A. Refresh survives (LOAD-BEARING) =================
  // Exchange the pre-restart refresh_token. client_id is recorded even though
  // the current token_refresh handler (src/oidc.rs) does not validate it —
  // included so the request shape matches a real client and stays correct if
  // that ever changes.
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: state.refresh_token,
    client_id: state.client_id,
  });
  const tokenResp = await fetch(`${SIWX_URL.replace(/\/$/, '')}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  let tokenBody = {};
  try {
    tokenBody = await tokenResp.json();
  } catch {
    tokenBody = {};
  }

  if (tokenResp.status !== 200) {
    throw new Error(
      'H-D1 REFUTED: POST /token grant_type=refresh_token returned ' +
        `${tokenResp.status} (expected 200) for the refresh_token captured before ` +
        `the restart. Body: ${JSON.stringify(tokenBody).slice(0, 400)}. A ` +
        '400 invalid_grant here means the refresh token did NOT survive the ' +
        'restart — session state was not durable.',
    );
  }
  expect(tokenBody.access_token, 'refresh response (200) had no access_token').toBeTruthy();
  expect(
    tokenBody.access_token,
    'refresh response returned the SAME access_token as pre-restart — rotation did not happen',
  ).not.toBe(state.access_token);

  // scope / device_id in the refresh response — best-effort, not load-bearing.
  // MEASURED (src/oidc.rs): token_refresh builds new TokenMetadata carrying
  // `device_id` and stores it in Redis, but never calls
  // `response.set_scopes(...)` on the CoreTokenResponse it returns to the
  // client (only token_device_code does that). The oauth2 crate's
  // StandardTokenResponse has `#[serde(skip_serializing_if = "Option::is_none")]`
  // on `scopes`, so `scope` is OMITTED from the JSON body entirely here, same
  // as at login (see ew-restart-capture.spec.mjs's header comment). So this
  // leg does not hard-require `scope`; if the server ever starts echoing it,
  // assert it agrees with the captured device_id, but the AUTHORITATIVE
  // same-device_id proof is B/C below via the Matrix CS-API — the same ground
  // truth loginWalletToTokens itself trusts.
  if (typeof tokenBody.scope === 'string' && tokenBody.scope.length > 0) {
    const m = tokenBody.scope.match(
      /urn:matrix:(?:org\.matrix\.msc2967\.)?client:device:([^\s]+)/,
    );
    if (m) {
      expect(
        m[1],
        `refresh response scope carries device_id ${m[1]}, expected ${state.device_id}`,
      ).toBe(state.device_id);
    }
  }

  const newAccessToken = tokenBody.access_token;

  // ================= B. Zero new device provisions =======================
  const devicesAfter = await listDevices(newAccessToken, MATRIX_URL);
  const idsAfter = devicesAfter.map((d) => d.device_id);
  const newDevices = idsAfter.filter((id) => !state.device_ids.includes(id));
  const missingDevices = state.device_ids.filter((id) => !idsAfter.includes(id));

  expect(
    idsAfter,
    `device ${state.device_id} is missing after restart. before=${JSON.stringify(state.device_ids)} after=${JSON.stringify(idsAfter)}`,
  ).toContain(state.device_id);
  expect(
    newDevices,
    'restart+refresh silently provisioned NEW device id(s) — a device-recycling ' +
      `regression, not durability. before=${JSON.stringify(state.device_ids)} ` +
      `after=${JSON.stringify(idsAfter)} new=${JSON.stringify(newDevices)}`,
  ).toEqual([]);
  expect(
    missingDevices,
    `device(s) present before the restart vanished after it: ${JSON.stringify(missingDevices)}. ` +
      `before=${JSON.stringify(state.device_ids)} after=${JSON.stringify(idsAfter)}`,
  ).toEqual([]);
  expect(
    idsAfter.length,
    `device COUNT changed across the restart: before=${state.device_count} ` +
      `(${JSON.stringify(state.device_ids)}) after=${idsAfter.length} (${JSON.stringify(idsAfter)})`,
  ).toBe(state.device_count);

  // ================= C. Identity unchanged ================================
  const whoAfter = await matrixWhoami(newAccessToken, MATRIX_URL);
  expect(
    whoAfter.status,
    `post-restart whoami with the NEW access token failed: ${JSON.stringify(whoAfter.body)}`,
  ).toBe(200);
  expect(whoAfter.body.user_id, 'user_id changed across the restart').toBe(state.user_id);
  expect(whoAfter.body.device_id, 'device_id changed across the restart').toBe(state.device_id);

  // ================= D. Pre-restart access token (CONDITIONAL) ===========
  // The access token TTL is 300s. If the restart + poll-for-health + this
  // spec's own runtime ate more than 240s since capture, the old access token
  // may have expired on its own merits — asserting it would still work risks
  // misreporting a legitimate TTL expiry as a durability defect. Below the
  // cutoff, though, it MUST still work: anything else is a real defect (the
  // restart silently invalidated a still-live token), and that must be
  // asserted, not silently skipped.
  if (elapsed < CUTOFF_MS) {
    const oldWho = await matrixWhoami(state.access_token, MATRIX_URL);
    expect(
      oldWho.status,
      `[D] pre-restart access token stopped working ${elapsed}ms after capture ` +
        `(TTL=${ACCESS_TOKEN_TTL_MS}ms, well inside the ${CUTOFF_MS}ms budget) — this IS ` +
        `a durability defect: ${JSON.stringify(oldWho.body)}`,
    ).toBe(200);
    // eslint-disable-next-line no-console
    console.log(
      `[EW-T5-2][D] ASSERTED: elapsed=${elapsed}ms < cutoff=${CUTOFF_MS}ms — old access ` +
        `token still works (whoami status=${oldWho.status})`,
    );
  } else {
    // Loud, unmissable skip — never let this hide a real defect silently.
    // eslint-disable-next-line no-console
    console.log(
      `[EW-T5-2][D] SKIPPED (not a failure): elapsed=${elapsed}ms >= cutoff=${CUTOFF_MS}ms ` +
        `(TTL=${ACCESS_TOKEN_TTL_MS}ms). The pre-restart access token may have expired ` +
        'legitimately during the restart+health-poll window; not asserting so a slow ' +
        'restart cannot masquerade as a durability defect. The refresh path (A/B/C ' +
        'above) is unaffected by this and remains fully asserted.',
    );
  }

  // ================= Evidence block =======================================
  // eslint-disable-next-line no-console
  console.log(
    '[EW-T5-2] EVIDENCE ' +
      JSON.stringify(
        {
          elapsed_ms: elapsed,
          cutoff_ms: CUTOFF_MS,
          token_refresh_status: tokenResp.status,
          user_id: state.user_id,
          device_id: state.device_id,
          device_ids_before: state.device_ids,
          device_ids_after: idsAfter,
          device_count_before: state.device_count,
          device_count_after: idsAfter.length,
          whoami_after_status: whoAfter.status,
        },
        null,
        2,
      ),
  );
});
