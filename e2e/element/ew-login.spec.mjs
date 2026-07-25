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
 * EW-L1b: Element restores the session from its OWN persisted storage.
 *
 * The original pre-seeded-token approach was permanently unworkable (Element
 * persists the session in IndexedDB matrix-js-sdk stores, not the legacy
 * mx_* localStorage keys). With the real DOM click-login available (EW-C1),
 * the honest form is: log in for real, reload, and pin what ACTUALLY happens:
 *
 *  - AUTH restore works: no OIDC /authorize round-trip, same user_id +
 *    device_id from storage, never a logged-out login screen.
 *  - CRYPTO does NOT restore (current known state, this Element build +
 *    force_verification): Element lands on the "Confirm your digital
 *    identity" gate whose ONLY exits are "Use another device" or identity
 *    RESET — no recovery-key entry, even though Secure Backup was completed
 *    seconds earlier. For a single-device user this is a reload → verify-gate
 *    → forced-reset loop: a lab REPRODUCTION of the prod "verify session
 *    loop / half-reset" forensics (docs/audits/2026-06-24-*). Tracked as a
 *    Phase-2 finding; if either branch below flips, behavior changed —
 *    re-evaluate and update the finding, don't paper over it.
 */
test('EW-L1b: reload restores AUTH session (no OIDC round-trip); crypto gate documented', async ({
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

  // AUTH restore invariants — these must hold on EVERY outcome.
  expect(new URL(page.url()).origin).toBe(new URL(ELEMENT_URL).origin);
  expect(authorizeHits).toHaveLength(0);
  const restored = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
  }));
  expect(restored.user_id).toBe(session.user_id);
  expect(restored.device_id).toBe(session.device_id);

  if (await chat.count()) {
    // Crypto restored too — behavior IMPROVED over the documented state.
    // Nothing more to assert; update the finding in the plan log.
    return;
  }

  // Current known terminal: the identity-confirmation gate, offering only
  // another-device verification or destructive reset (no recovery-key path).
  await expect(page.getByRole('button', { name: /use another device/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /remove this device/i })).toBeVisible();
});
