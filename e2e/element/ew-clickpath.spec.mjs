/**
 * EW-C1..C3: REAL Element Web DOM click-paths (backlog P2 from the 2026-07-25
 * handover). Unlike EW-L1 (headless OP contract), these drive the actual SPA:
 *
 *   EW-C1  Element (sso immediate → OIDC-native) → siwx login UI → "Sign in
 *          with Ethereum" (wagmi/viem against the mock EIP-1193 provider) →
 *          "Skip for now" → /sign_in → back in Element → mandatory Secure
 *          Backup wizard (force_verification) → app shell; session whoami
 *          matches the wallet DID mxid.
 *   EW-C2  User-menu "Sign out" from the Element chrome. Captures WHICH
 *          teardown endpoint OIDC-native Element uses (CS-API /v3/logout →
 *          siwx deletes the device; OP /oauth2/revoke → TokensOnly, device
 *          kept by design) and asserts the matching siwx behavior plus that
 *          the session token really dies.
 *   EW-C3  "Manage account" in Element settings opens the siwx /account page
 *          (MSC4191 account_management_uri) in a new tab.
 *
 * PRE-REQ (lab): Synapse msc3861.issuer_metadata must be the OP's FULL
 * metadata with only introspection_endpoint internal — an endpoints-only
 * dict fails matrix-js-sdk issuer validation and Element falls back to the
 * legacy /login/sso/redirect, which 404s under MSC3861. See
 * siwx-oidc-matrix-server entrypoints/matrix_server.sh.
 *
 * Element loads are slow (~60-90s to the wizard); each test budgets generously.
 */
import { test, expect } from '@playwright/test';
import {
  requireElementStack,
  ELEMENT_URL,
  SIWX_URL,
  MATRIX_URL,
} from './helpers/element.mjs';
import { loginWalletToTokens } from './helpers/oidc-login.mjs';
import { listDevices, matrixWhoami } from './helpers/sessions.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { makeWallet } from '../browser/wallet-helper.mjs';

test.beforeAll(async () => {
  await requireElementStack();
});

test('EW-C1: full SSO click-path — Element → siwx wallet UI → Secure Backup → app shell', async ({
  page,
}) => {
  test.setTimeout(360_000);
  const w = makeWallet(undefined, 'localhost');

  const session = await elementWalletClickLogin(page, w);

  // The session Element ended up with belongs to the wallet DID.
  expect(session.user_id).toBe(w.mxid);
  expect(session.device_id).toBeTruthy();

  // And it is a live Synapse session (not just localStorage residue).
  if (session.access_token) {
    const who = await matrixWhoami(session.access_token);
    expect(who.status).toBe(200);
    expect(who.body.user_id).toBe(w.mxid);
    expect(who.body.device_id).toBe(session.device_id);
  }
});

test('EW-C2: Element chrome "Sign out" — teardown endpoint + device policy + token death', async ({
  browser,
  page,
}) => {
  test.setTimeout(420_000);
  const w = makeWallet(undefined, 'localhost');

  // Observer session FIRST (same account, own device) so we can watch the
  // device list from outside the Element session being ended.
  const obsCtx = await browser.newContext();
  try {
    const obsPage = await obsCtx.newPage();
    const observer = await loginWalletToTokens(obsPage, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
      wallet: w,
    });

    const session = await elementWalletClickLogin(page, w);
    expect(session.user_id).toBe(w.mxid);
    const before = (await listDevices(observer.access_token)).map((d) => d.device_id);
    expect(before).toContain(session.device_id);

    // Record which teardown endpoints Element actually calls.
    const teardownCalls = [];
    page.on('request', (r) => {
      const u = r.url().replace(/\?.*$/, '');
      if (
        (r.method() === 'POST' && /\/logout$|\/logout\/all$|\/oauth2\/revoke$|\/delete_devices$/.test(u)) ||
        (r.method() === 'DELETE' && /\/devices\//.test(u))
      ) {
        teardownCalls.push(`${r.method()} ${u}`);
      }
    });

    // Element 1.12 OIDC-native chrome has no user-menu "Sign out"; the
    // affordance is Settings → Sessions → current session → Remove this
    // session (the backlog's "Settings → Sign out this session" path).
    await page.locator('.mx_UserMenu').click();
    await page.getByRole('menuitem', { name: /all settings/i }).click({ timeout: 20_000 });
    await page
      .locator('[role="tab"], .mx_TabbedView_tabLabel')
      .filter({ hasText: /sessions/i })
      .first()
      .click({ timeout: 20_000 });
    await page.getByRole('button', { name: /show details/i }).first().click({ timeout: 20_000 });
    await page
      .getByRole('button', { name: /remove this session/i })
      .first()
      .click({ timeout: 20_000 });
    // Confirm dialog: "Are you sure you want to remove this device?".
    await page
      .locator('.mx_Dialog')
      .getByRole('button', { name: /remove this device/i })
      .first()
      .click({ timeout: 15_000 });

    // Element must have fired SOME teardown call; wait for it.
    await expect.poll(() => teardownCalls.length, { timeout: 30_000 }).toBeGreaterThan(0);

    const deletesDevice = teardownCalls.some(
      (c) => /^DELETE .*\/devices\//.test(c) || /\/logout$|\/delete_devices$/.test(c),
    );
    if (deletesDevice) {
      // Explicit sign-out intent → siwx TeardownPolicy DeleteDevice: the
      // ending session's device must disappear from Synapse.
      await expect
        .poll(
          async () => (await listDevices(observer.access_token)).map((d) => d.device_id),
          { timeout: 60_000 },
        )
        .not.toContain(session.device_id);
    } else {
      // OP-side RFC 7009 revoke only → TokensOnly BY DESIGN (2026-06-12
      // incident): the device row stays; only the tokens die.
      const after = (await listDevices(observer.access_token)).map((d) => d.device_id);
      expect(after).toContain(session.device_id);
    }

    // Either way the session token must actually die. Synapse caches
    // successful introspections ~120s, so poll past the cache window.
    if (session.access_token) {
      await expect
        .poll(async () => (await matrixWhoami(session.access_token)).status, {
          timeout: 180_000,
          intervals: [5_000],
        })
        .toBe(401);
    }

    // Observer's own device must survive a single-session sign-out.
    const survivors = (await listDevices(observer.access_token)).map((d) => d.device_id);
    expect(survivors).toContain(observer.device_id);
  } finally {
    await obsCtx.close();
  }
});

test('EW-C3: Element settings "Manage account" opens siwx /account in a new tab', async ({
  page,
  context,
}) => {
  test.setTimeout(360_000);
  const w = makeWallet(undefined, 'localhost');

  await elementWalletClickLogin(page, w);

  // Element chrome: user menu → All settings. Externally-managed accounts
  // surface the MSC4191 account_management_uri as "Manage account".
  await page.locator('.mx_UserMenu').click();
  await page.getByRole('menuitem', { name: /all settings|settings/i }).first().click();
  const manage = page
    .getByRole('button', { name: /manage account/i })
    .or(page.getByRole('link', { name: /manage account/i }))
    .first();
  await expect(manage).toBeVisible({ timeout: 30_000 });

  const [popup] = await Promise.all([context.waitForEvent('page'), manage.click()]);
  await popup.waitForLoadState('domcontentloaded');
  expect(popup.url().startsWith(`${SIWX_URL.replace(/\/$/, '')}/account`)).toBe(true);
  await popup.close();
});
