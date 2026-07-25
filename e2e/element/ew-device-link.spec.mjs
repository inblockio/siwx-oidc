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
import {
  buildCrossSigningUpload,
  uploadDeviceSigning,
  keysQuery,
} from './helpers/crypto.mjs';
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

/**
 * Approve the pending user_code with the given wallet and poll the grant.
 * Returns the device_code token response.
 */
async function approveAndPoll(w, clientId, da) {
  const approve = await approveDeviceWithWallet(
    { wallet: w.wallet, did: w.did, userCode: da.user_code },
    SIWX_URL,
  );
  expect(
    approve.status,
    `device approve must 200: ${typeof approve.body === 'string' ? approve.body : JSON.stringify(approve.body)}`,
  ).toBe(200);
  return {
    approve,
    token: await pollDeviceToken(
      {
        clientId,
        deviceCode: da.device_code,
        intervalSec: da.interval || 2,
        maxWaitMs: 45_000,
      },
      SIWX_URL,
    ),
  };
}

test('EW-D2: approver with NO cross-signing → honest terminal — tokens granted, no fabricated crypto claim, dead-end detectable', async ({
  page,
  browser,
}) => {
  // The MSC4108 Phase-4 prerequisite (XS private keys on the SENDING device)
  // is not observable server-side; the removed approval-time pre-flight probe
  // was a confirmed false positive (raced first-time bootstrap). The honest
  // contract this spec pins:
  //   1. approval + token grant report TOKEN truth only (they succeed);
  //   2. the server fabricates NO crypto claim (no warning, no XS state);
  //   3. the M5 Q2 dead-end (T_ApprovedButDead) stays externally DETECTABLE:
  //      keys/query from the linked device shows the approver has no master
  //      key, which is exactly what a real client's Phase-4 would trip on.
  // A contrast leg (approver WITH cross-signing) proves the discriminator
  // actually discriminates.
  const rc = await registerDeviceClient(SIWX_URL);

  // --- Leg A: approver WITHOUT cross-signing (fresh account, no XS upload).
  const wA = makeWallet();
  const seedA = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: wA,
  });
  const daA = await requestDeviceAuthorization({ clientId: rc.client_id }, SIWX_URL);
  const { approve: approveA, token: tokenA } = await approveAndPoll(wA, rc.client_id, daA);

  // (2) No fabricated crypto claim on the approve terminal (H9 counterpart).
  if (typeof approveA.body === 'object' && approveA.body !== null) {
    expect(approveA.body.warning ?? null).toBeNull();
  }

  // (1) Token truth: the linked device signs in.
  expect(tokenA.access_token).toMatch(/^mat_/);
  const whoA = await matrixWhoami(tokenA.access_token, MATRIX_URL);
  expect(whoA.status).toBe(200);
  expect(whoA.body.user_id).toBe(seedA.user_id);

  // (3) The dead-end is detectable: no master cross-signing key published, so
  // a real client CANNOT complete MSC4108 Phase 4 — and nothing masks that.
  const kqA = await keysQuery(tokenA.access_token, seedA.user_id, MATRIX_URL);
  expect(kqA.status).toBe(200);
  expect(kqA.body.master_keys?.[seedA.user_id]).toBeUndefined();

  // --- Leg B (contrast): approver WITH published cross-signing keys.
  const ctxB = await browser.newContext();
  try {
    const pageB = await ctxB.newPage();
    const wB = makeWallet();
    const seedB = await loginWalletToTokens(pageB, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
      wallet: wB,
    });
    const up = await uploadDeviceSigning(
      seedB.access_token,
      buildCrossSigningUpload(seedB.user_id),
      MATRIX_URL,
    );
    expect(up.status, `XS upload must 200: ${up.body.slice(0, 200)}`).toBe(200);

    const daB = await requestDeviceAuthorization({ clientId: rc.client_id }, SIWX_URL);
    const { token: tokenB } = await approveAndPoll(wB, rc.client_id, daB);
    const kqB = await keysQuery(tokenB.access_token, seedB.user_id, MATRIX_URL);
    expect(kqB.status).toBe(200);
    expect(kqB.body.master_keys?.[seedB.user_id]).toBeTruthy();
  } finally {
    await ctxB.close();
  }
});
