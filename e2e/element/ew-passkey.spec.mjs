/**
 * EW-P1..P3: passkey (WebAuthn) through the full OIDC code flow against the
 * live Element lab stack (Matrix :28080, siwx :28081). Backlog P1 from the
 * 2026-07-25 handover.
 *
 *   EW-P1  Fresh passkey register → OIDC login. Asserts the new-user gate
 *          (finish reports new_user:true + mxid, provisioning deferred to
 *          /sign_in), did:key derivation, mat_ tokens, whoami.
 *   EW-P2  Returning passkey user on the same browser: siwx_user cookie scopes
 *          the picker (allowCredentials=1, detected_mxid) and a second login
 *          provisions a SECOND device on the same account (multi-device).
 *   EW-P3  Same passkey "synced" to a second browser context via CDP
 *          credential export/import (roaming-key model): usernameless start,
 *          same account, third… er, another device; both sessions live.
 *
 * Ceremonies use the CDP virtual authenticator (CTAP2, resident keys, UV) —
 * same primitive as the mock-suite passkey specs, here against real Synapse.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  SIWX_URL,
  MATRIX_URL,
} from './helpers/element.mjs';
import {
  loginPasskeyToTokens,
  exportPasskeys,
  importPasskeys,
} from './helpers/passkey-login.mjs';
import { listDevices, matrixWhoami } from './helpers/sessions.mjs';
import { addVirtualAuthenticator } from '../browser/webauthn-helper.mjs';

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-P1: fresh passkey → new-user gate → OIDC provisions + mat_ tokens + whoami', async ({
  page,
}) => {
  await addVirtualAuthenticator(page);

  const s = await loginPasskeyToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    register: true,
  });

  // Passkey P-256 pubkey → did:key:zDn…, and the login runs under exactly that DID.
  expect(s.registered_did).toMatch(/^did:key:zDn/);
  expect(s.did).toBe(s.registered_did);

  // First-ever ceremony on this browser: no siwx_user cookie yet, so start is
  // usernameless (empty allowCredentials) and leaks no identity hint.
  expect(s.allow_count).toBe(0);
  expect(s.detected_mxid).toBeNull();

  // New-user gate: finish REPORTS the pending identity, /sign_in provisions.
  expect(s.new_user).toBe(true);
  expect(s.mxid).toMatch(/^@/);

  // Real MSC3861 session against Synapse.
  expect(s.access_token).toMatch(/^mat_/);
  expect(s.user_id).toBe(s.mxid);
  expect(s.device_id).toBeTruthy();
});

test('EW-P2: returning passkey user → scoped picker + second device on the same passkey', async ({
  page,
}) => {
  await addVirtualAuthenticator(page);

  const first = await loginPasskeyToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    register: true,
  });
  expect(first.new_user).toBe(true);

  // Same page keeps the siwx_user cookie minted at the first /sign_in.
  const second = await loginPasskeyToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
  });

  // Returning user: picker scoped to exactly this DID's one credential, and
  // the account hint is surfaced for the frontend.
  expect(second.allow_count).toBe(1);
  expect(second.detected_mxid).toBe(first.user_id);
  expect(second.new_user).toBe(false);

  // Same identity, distinct second device (no recycling), both sessions live.
  expect(second.did).toBe(first.did);
  expect(second.user_id).toBe(first.user_id);
  expect(second.device_id).toBeTruthy();
  expect(second.device_id).not.toBe(first.device_id);

  const ids = (await listDevices(second.access_token)).map((d) => d.device_id);
  expect(ids).toContain(first.device_id);
  expect(ids).toContain(second.device_id);

  const who1 = await matrixWhoami(first.access_token);
  expect(who1.status).toBe(200);
  expect(who1.body.device_id).toBe(first.device_id);
});

test('EW-P3: same passkey in a second browser context (synced-key model) → same account, new device', async ({
  browser,
  page,
}) => {
  const authA = await addVirtualAuthenticator(page);

  const first = await loginPasskeyToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    register: true,
  });
  expect(first.new_user).toBe(true);

  // "Sync" the resident credential to device B (fresh context: no cookies).
  const creds = await exportPasskeys(authA);
  expect(creds.length).toBe(1);

  const ctxB = await browser.newContext();
  try {
    const pageB = await ctxB.newPage();
    const authB = await addVirtualAuthenticator(pageB);
    await importPasskeys(authB, creds, new URL(SIWX_URL).hostname);

    const second = await loginPasskeyToTokens(pageB, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
    });

    // Device B has no siwx_user cookie: start MUST fall back to usernameless
    // and leak no identity hint (enumeration-safety invariant).
    expect(second.allow_count).toBe(0);
    expect(second.detected_mxid).toBeNull();

    // The account already exists — no new-user gate on device B.
    expect(second.new_user).toBe(false);
    expect(second.did).toBe(first.did);
    expect(second.user_id).toBe(first.user_id);
    expect(second.device_id).not.toBe(first.device_id);

    const ids = (await listDevices(second.access_token)).map((d) => d.device_id);
    expect(ids).toContain(first.device_id);
    expect(ids).toContain(second.device_id);
  } finally {
    await ctxB.close();
  }
});
