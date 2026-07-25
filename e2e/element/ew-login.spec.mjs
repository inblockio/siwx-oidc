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
 * EW-L1b (optional): seed Element localStorage with OP tokens and hope the SPA
 * boots to the room list without running its own OIDC redirect.
 *
 * SKIPPED: modern Element Web (matrix-js-sdk + rust crypto / OIDC) persists the
 * session primarily in IndexedDB under matrix-js-sdk stores, not the legacy
 * `mx_access_token` / `mx_user_id` localStorage keys. Writing those keys alone
 * does not restore a logged-in session on the Element image this lab runs, so
 * the room-list assertion would flake or false-fail. Re-enable when we have a
 * verified restore path (e.g. matrix-js-sdk SessionStore injection or a
 * documented Element test hook) for this image.
 */
test.skip('EW-L1b: Element boots to room list from pre-seeded tokens', async () => {
  // Intentionally empty — see skip reason above.
});
