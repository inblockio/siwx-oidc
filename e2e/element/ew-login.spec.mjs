/**
 * EW-L1: Element Web wallet login via OIDC (siwx-oidc).
 *
 * Requires the compose.local stack (Element :28088, Matrix :28080, siwx :28081
 * by default — see helpers/element.mjs). Uses a mock injected ethereum provider
 * when the OIDC flow lands on siwx.
 *
 * This is the first Element-driven smoke; session-management specs build on it.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  openElement,
  clearElementSession,
  ELEMENT_URL,
  SIWX_URL,
  MATRIX_URL,
} from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-L0: stack discovery + Element shell loads', async ({ page }) => {
  // Homeserver advertises OIDC issuer
  const wk = await (await fetch(`${MATRIX_URL}/.well-known/matrix/client`)).json();
  expect(wk['m.homeserver']?.base_url).toBeTruthy();
  const auth = wk['m.authentication'] || {};
  const issuer = auth.issuer || wk['m.authentication.issuer'];
  // Accept nested or dotted key shapes
  expect(String(issuer || auth).includes('8081') || auth.issuer).toBeTruthy();

  const oidc = await (await fetch(`${SIWX_URL}/.well-known/openid-configuration`)).json();
  expect(oidc.authorization_endpoint).toContain('/authorize');
  expect(oidc.account_management_uri || oidc.account_management_actions_supported).toBeTruthy();

  await clearElementSession(page);
  const state = await openElement(page);
  expect(['login', 'app', 'unknown']).toContain(state);
  // At minimum the document title or body should indicate Element loaded
  const title = await page.title();
  const bodyLen = await page.evaluate(() => (document.body?.innerText || '').length);
  expect(title.length + bodyLen).toBeGreaterThan(0);
});

test('EW-L1: wallet CAIP-122 through siwx produces Matrix whoami (headless OIDC)', async ({
  page,
}) => {
  // Full Element SPA "Continue with SSO" clicks are version-fragile. This test
  // hard-proves the OP + homeserver contract Element uses: DCR → authorize →
  // wallet CAIP-122 → sign_in → token → whoami on the Matrix edge, with the same
  // mock wallet Element would use after redirect to siwx.
  // Helper: helpers/oidc-login.mjs (R-A1 pattern from e2e/browser).
  const w = makeWallet();

  const session = await loginWalletToTokens(page, {
    siwxUrl: SIWX_URL,
    matrixUrl: MATRIX_URL,
    wallet: w,
  });

  expect(session.access_token).toMatch(/^mat_/);
  expect(session.refresh_token).toMatch(/^mcr_/);
  expect(session.user_id).toBeTruthy();
  expect(session.user_id).toMatch(/^@/);
  expect(session.device_id).toBeTruthy();
  // DID localpart is did-pkh-eip155-1-0x… (colons → dashes, lowercased)
  const localpart = w.did.replaceAll(':', '-').toLowerCase();
  expect(session.user_id.toLowerCase()).toContain(localpart);
});

/**
 * EW-L1b: Element restores the session — AUTH and CRYPTO — on reload.
 *
 * History: the pre-seeded-token approach was permanently unworkable; then this
 * spec documented a reload → "Confirm your digital identity" gate (FINDING 2,
 * 2026-07-25) — root-caused to the vendored force-first-device-recovery patch
 * gating on transient `isSecretStorageReady()` during session RESTORE. The
 * patch now treats server-side 4S existence (`secretStorage.hasKey()`) as
 * satisfying the recoverable-identity mandate (H1), so a set-up session must
 * restore straight to the app shell:
 *
 *  - AUTH: no OIDC /authorize round-trip, same user_id + device_id, never a
 *    logged-out login screen.
 *  - CRYPTO: NO identity-confirmation gate. The gate reappearing here is a
 *    REGRESSION of the FINDING 2 fix — fail loudly, do not re-widen this spec.
 */
test('EW-L1b: reload restores AUTH + CRYPTO (no OIDC round-trip, no identity gate)', async ({
  page,
}) => {
  test.setTimeout(360_000);
  const w = makeWallet(undefined, 'localhost');
  const session = await elementWalletClickLogin(page, w);
  expect(session.user_id).toBe(w.mxid);

  // Reload: any bounce through the OP's /authorize means the auth session was
  // NOT restored from storage.
  const authorizeHits = [];
  page.on('request', (r) => {
    if (r.url().startsWith(SIWX_URL) && r.url().includes('/authorize')) {
      authorizeHits.push(r.url());
    }
  });
  await page.reload({ waitUntil: 'domcontentloaded' });

  const chat = page.locator('.mx_MatrixChat');
  const gate = page.locator('.mx_CompleteSecurityBody');
  await chat.or(gate).first().waitFor({ timeout: 90_000 });

  // AUTH restore invariants.
  expect(new URL(page.url()).origin).toBe(new URL(ELEMENT_URL).origin);
  expect(authorizeHits).toHaveLength(0);
  const restored = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
  }));
  expect(restored.user_id).toBe(session.user_id);
  expect(restored.device_id).toBe(session.device_id);

  // CRYPTO restore invariant: the app shell, not the identity gate (H1).
  expect(
    await gate.count(),
    'identity-confirmation gate on reload = FINDING 2 regression (vendored patch restore gating)',
  ).toBe(0);
  await expect(chat).toBeVisible();
});
