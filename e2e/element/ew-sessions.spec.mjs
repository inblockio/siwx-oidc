/**
 * EW-S1–S4: Element session management against the live lab stack.
 *
 * Prefer API-level + OP account contracts Element uses (reliable) over SPA UI:
 *   EW-S1  OIDC discovery advertises account_management_uri; GET loads
 *   EW-S2  After wallet login, list devices via Matrix CS-API (+ OP action page)
 *   EW-S3  Two sessions → DELETE second device on edge → other still works
 *   EW-S4  POST logout on edge → whoami 401 for that token
 *
 * Stack: Element :28088, Matrix :28080, siwx :28081 (helpers/element.mjs).
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  SIWX_URL,
  MATRIX_URL,
} from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import {
  matrixWhoami,
  listDevices,
  deleteDevice,
  matrixLogout,
  introspectToken,
  fetchOidcDiscovery,
  fetchAccountPage,
} from './helpers/sessions.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test.beforeAll(async () => {
  await requireElementStack();
});

/** MAS shared secret for introspect asserts (optional — skip OP truth if absent). */
function loadMasSecret() {
  // Prefer env (CI); fall back to sibling matrix-server .env.local for lab hosts.
  if (process.env.MAS_SHARED_SECRET) return process.env.MAS_SHARED_SECRET.trim();
  const candidates = [
    process.env.MATRIX_SERVER_ENV,
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../siwx-oidc-matrix-server/.env.local',
    ),
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../../siwx-oidc-matrix-server/.env.local',
    ),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      const m = fs.readFileSync(p, 'utf8').match(/^MAS_SHARED_SECRET=(.+)$/m);
      if (m) return m[1].trim();
    } catch {
      /* try next */
    }
  }
  return null;
}

test('EW-S1: OIDC discovery advertises account_management_uri; GET that page loads', async () => {
  const oidc = await fetchOidcDiscovery(SIWX_URL);
  expect(oidc.account_management_uri).toBeTruthy();
  expect(String(oidc.account_management_uri)).toMatch(/\/account\/?$/);

  const actions = oidc.account_management_actions_supported || [];
  // MSC4191 core actions Element relies on for session management
  for (const a of [
    'org.matrix.devices_list',
    'org.matrix.device_delete',
    'org.matrix.profile',
  ]) {
    expect(actions, `missing action ${a}`).toContain(a);
  }

  // Bare account landing (Element "Manage account" with no action param)
  const landing = await fetchAccountPage(oidc.account_management_uri);
  expect(landing.status).toBe(200);
  expect(landing.text.toLowerCase()).toMatch(/account|session|profile|device/);

  // Deep-link devices_list page also loads (re-auth UI, not yet authed)
  const sessions = await fetchAccountPage(
    oidc.account_management_uri,
    'org.matrix.devices_list',
  );
  expect(sessions.status).toBe(200);
  expect(sessions.text).toMatch(/session|wallet|passkey|device/i);
});

test('EW-S2: after wallet login, list devices via Matrix CS-API (Element session path)', async ({
  page,
}) => {
  const w = makeWallet();
  const session = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });

  expect(session.device_id).toBeTruthy();
  expect(session.user_id).toMatch(/^@/);

  // Element's in-app session manager lists devices via CS-API against the
  // homeserver (Synapse), not the OP account page.
  const devices = await listDevices(session.access_token, MATRIX_URL);
  expect(devices.length).toBeGreaterThanOrEqual(1);
  const ids = devices.map((d) => d.device_id);
  expect(ids).toContain(session.device_id);

  // OP account_management deep-link still loads for the same identity flow
  // (re-auth gate — we only assert the page is live, not the full re-auth).
  const oidc = await fetchOidcDiscovery(SIWX_URL);
  const pageResp = await fetchAccountPage(
    oidc.account_management_uri,
    'org.matrix.devices_list',
  );
  expect(pageResp.status).toBe(200);
});

test('EW-S3: delete a SECOND device via edge DELETE /devices/{id}; other still works', async ({
  page,
  context,
}) => {
  const w = makeWallet();

  // Two independent OIDC logins = two Synapse devices for the same DID.
  // Fresh pages so session cookies / mock-wallet init scripts do not collide.
  const page1 = page;
  const session1 = await loginWalletToTokens(page1, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });

  const page2 = await context.newPage();
  const session2 = await loginWalletToTokens(page2, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });

  expect(session1.device_id).toBeTruthy();
  expect(session2.device_id).toBeTruthy();
  expect(session1.device_id).not.toBe(session2.device_id);
  expect(session1.user_id).toBe(session2.user_id);

  let devices = await listDevices(session2.access_token, MATRIX_URL);
  let ids = devices.map((d) => d.device_id);
  expect(ids).toEqual(expect.arrayContaining([session1.device_id, session2.device_id]));

  // Sign out session1's device using session2's token (Element session manager).
  const del = await deleteDevice(
    session2.access_token,
    session1.device_id,
    MATRIX_URL,
  );
  expect(del.status).toBe(200);

  devices = await listDevices(session2.access_token, MATRIX_URL);
  ids = devices.map((d) => d.device_id);
  expect(ids).not.toContain(session1.device_id);
  expect(ids).toContain(session2.device_id);

  // Token truth: deleted device's access token is inactive; survivor stays active.
  const secret = loadMasSecret();
  if (secret) {
    const i1 = await introspectToken(session1.access_token, secret, SIWX_URL);
    const i2 = await introspectToken(session2.access_token, secret, SIWX_URL);
    expect(i1.active).toBe(false);
    expect(i2.active).toBe(true);
  }

  // Survivor still works on the Matrix edge (whoami may be cache-warm — 200).
  const who2 = await matrixWhoami(session2.access_token, MATRIX_URL);
  expect(who2.status).toBe(200);
  expect(who2.body.device_id).toBe(session2.device_id);

  await page2.close();
});

test('EW-S4: POST /_matrix/client/v3/logout → whoami 401 for that token', async ({
  page,
}) => {
  const w = makeWallet();

  // whoami:false so Synapse has no warm introspection cache for this token.
  // (Synapse caches successful introspect for ~2 min; a prior whoami would
  // keep whoami returning 200 after logout until the cache expires.)
  const session = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
    whoami: false,
  });
  expect(session.access_token).toMatch(/^mat_/);

  const lo = await matrixLogout(session.access_token, MATRIX_URL);
  // RFC/compat: logout is 200 even if already gone; we expect a real session.
  expect(lo.status).toBe(200);

  // OP truth (immediate).
  const secret = loadMasSecret();
  if (secret) {
    const i = await introspectToken(session.access_token, secret, SIWX_URL);
    expect(i.active).toBe(false);
  }

  // Matrix edge whoami must reject the revoked token (uncached path).
  const who = await matrixWhoami(session.access_token, MATRIX_URL);
  expect(
    who.status,
    `expected 401 after logout, got ${who.status} ${JSON.stringify(who.body)}`,
  ).toBe(401);
});
