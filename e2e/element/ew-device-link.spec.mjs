/**
 * EW-D1: RFC 8628 device-code flow (Element "link new device" / headless approve).
 *
 * Against the live Element lab stack:
 *   1. Seed an existing identity via wallet OIDC login (device approval rejects
 *      brand-new identities — create-at-sign-in only).
 *   2. POST /device_authorization → device_code + user_code
 *   3. Approve with wallet CAIP-122 on POST /device (GET /device/nonce)
 *   4. Poll POST /token grant_type=device_code → mat_ + mcr_
 *   5. Matrix whoami on the new access token
 *
 * Mirrors tests/e2e_device_code.rs against the Element-lab ports.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  SIWX_URL,
  MATRIX_URL,
} from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import {
  registerDeviceClient,
  requestDeviceAuthorization,
  approveDeviceWithWallet,
  pollDeviceToken,
  matrixWhoami,
} from './helpers/device-code.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-D1: device_authorization → wallet approve → device_code token → Matrix whoami', async ({
  page,
}) => {
  const w = makeWallet();

  // 0. Seed: device approval rejects unprovisioned identities.
  const seed = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });
  expect(seed.access_token).toMatch(/^mat_/);
  expect(seed.user_id).toMatch(/^@/);
  const seedDeviceId = seed.device_id;

  // 1. Register a public client that can use device_code.
  const rc = await registerDeviceClient(SIWX_URL);
  expect(rc.client_id).toBeTruthy();

  // Request a deterministic device id in the scope so we can assert it later.
  const linkedDeviceId = `EWD1_${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
  const scope = `openid urn:matrix:client:api:* urn:matrix:client:device:${linkedDeviceId}`;

  const da = await requestDeviceAuthorization(
    { clientId: rc.client_id, scope },
    SIWX_URL,
  );
  expect(da.device_code).toBeTruthy();
  expect(da.user_code).toBeTruthy();
  expect(String(da.verification_uri || '')).toMatch(/\/device\/?$/);
  // Device codes carry the dvc_ prefix in this OP.
  expect(String(da.device_code)).toMatch(/^dvc_/);

  // Pre-approval poll must be authorization_pending (RFC 8628), not tokens.
  {
    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: da.device_code,
      client_id: rc.client_id,
    });
    const pending = await fetch(`${SIWX_URL.replace(/\/$/, '')}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(pending.status).toBeGreaterThanOrEqual(400);
    const pb = await pending.json().catch(() => ({}));
    expect(pb.error).toBe('authorization_pending');
  }

  // 2. Approve as the seeded user (wallet CAIP-122).
  const approve = await approveDeviceWithWallet(
    {
      wallet: w.wallet,
      did: w.did,
      userCode: da.user_code,
    },
    SIWX_URL,
  );
  expect(
    approve.status,
    `device approve must 200: ${typeof approve.body === 'string' ? approve.body : JSON.stringify(approve.body)}`,
  ).toBe(200);
  if (typeof approve.body === 'object' && approve.body.status) {
    expect(approve.body.status).toBe('approved');
  }

  // 3. Poll device_code grant → MSC3861 tokens.
  const token = await pollDeviceToken(
    {
      clientId: rc.client_id,
      deviceCode: da.device_code,
      intervalSec: da.interval || 2,
      maxWaitMs: 45_000,
    },
    SIWX_URL,
  );
  expect(token.access_token).toMatch(/^mat_/);
  expect(token.refresh_token).toMatch(/^mcr_/);
  const tokenScope = String(token.scope || '');
  expect(tokenScope).toContain(`urn:matrix:client:device:${linkedDeviceId}`);

  // 4. Matrix whoami on the linked device's token.
  const who = await matrixWhoami(token.access_token, MATRIX_URL);
  expect(
    who.status,
    `whoami after device_code must 200: ${JSON.stringify(who.body)}`,
  ).toBe(200);
  expect(who.body.user_id).toBe(seed.user_id);
  expect(who.body.device_id).toBe(linkedDeviceId);
  // Linked device is distinct from the seed login device.
  expect(who.body.device_id).not.toBe(seedDeviceId);
});
