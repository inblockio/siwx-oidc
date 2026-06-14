// Headless browser E2E for the siwx-oidc /account flows — the literal-browser
// proof that account management works end to end with a SINGLE re-authentication.
//
//   * Wallet path: window.ethereum is a mock provider that produces REAL EIP-191
//     signatures (ethers). We assert exactly ONE personal_sign for a whole
//     session (list + sign-out).
//   * Passkey path: a CDP WebAuthn virtual authenticator. We register a passkey,
//     authenticate once, and assert exactly ONE navigator.credentials.get for the
//     whole session (list + sign-out) — the sign-out reuses the session.
//
// The stack (siwx-oidc + Synapse mock + Redis) runs externally; see e2e/up.sh.

import { test, expect } from '@playwright/test';
import { makeWallet, DEFAULT_PRIV, injectMockWallet } from './wallet-helper.mjs';
import { countCeremonies, registerPasskeyInPage } from './webauthn-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';

// A fixed throwaway test key — never used anywhere real.
const { wallet, address: ADDRESS, mxid: WALLET_MXID } = makeWallet(DEFAULT_PRIV);

// -- mock helpers (Synapse stand-in) -----------------------------------------
async function mockReset() {
  await fetch(`${MOCK}/__reset`, { method: 'POST' });
}
async function mockSeed(mxid, deviceId) {
  await fetch(`${MOCK}/__seed_device`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: mxid, device_id: deviceId, display_name: 'Element' }),
  });
}
async function mockDevices(mxid) {
  const s = await (await fetch(`${MOCK}/__state`)).json();
  return (s.devices[mxid] || []).map((d) => d.device_id);
}

// Count navigator.credentials ceremonies, so we can prove "exactly one".
// Thin wrapper over the shared helper, preserved as a local name so the existing
// test bodies read unchanged.
async function instrumentCeremonyCounters(page) {
  await countCeremonies(page);
}

// Inject a mock EIP-1193 wallet that signs with the real ethers key (the fixed
// DEFAULT_PRIV identity this spec asserts against). Thin wrapper over the shared
// helper so call-sites stay identical.
async function injectWallet(page) {
  await injectMockWallet(page, wallet);
}

// `registerPasskeyInPage` is imported from ./webauthn-helper.mjs (the single
// source of truth for the in-page registration ceremony).

// ---------------------------------------------------------------------------

test('wallet: one signature covers list + sign-out (the multi-reauth defect)', async ({ page }) => {
  await mockReset();
  await mockSeed(WALLET_MXID, 'SIWX_browser_a');
  await mockSeed(WALLET_MXID, 'SIWX_browser_b');
  await instrumentCeremonyCounters(page);
  await injectWallet(page);

  await page.goto('/account?action=org.matrix.devices_list');
  // The ONE and only signature for the whole session:
  await page.click('#btn-wallet');
  await expect(page.locator('.device-row')).toHaveCount(2);

  // Sign out device A — in-page, via the session, NO second wallet prompt.
  await page.locator('.device-row', { hasText: 'SIWX_browser_a' })
    .getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByText('Session signed out')).toBeVisible();

  expect(await page.evaluate(() => window.__signCount())).toBe(1);
  const ids = await mockDevices(WALLET_MXID);
  expect(ids).not.toContain('SIWX_browser_a');
  expect(ids).toContain('SIWX_browser_b');
});

test('wallet: erase runs end-to-end after one signature', async ({ page }) => {
  await mockReset();
  await mockSeed(WALLET_MXID, 'SIWX_erase_x');
  await instrumentCeremonyCounters(page);
  await injectWallet(page);

  await page.goto('/account?action=org.matrix.account_erase');
  // Erase is gated by a confirm checkbox; then ONE signature erases.
  await page.locator('#confirm-erase').check();
  await page.click('#btn-wallet');
  await expect(page.getByText('Account erased')).toBeVisible();

  expect(await page.evaluate(() => window.__signCount())).toBe(1);
  const s = await (await fetch(`${MOCK}/__state`)).json();
  expect(s.lifecycle[WALLET_MXID]?.erased).toBe(true);
});

test('deep-link manage-session with a base64 (slash) device id resolves', async ({ page }) => {
  // REGRESSION (Element X / matrix-rust-sdk device ids are standard base64): the
  // "Manage this session" deep link carries a device_id containing '/'. It must
  // resolve to the session, not "That device is not among your active sessions".
  await mockReset();
  const dev = 'MjGFNfjj95k5VngxejhaWTG0i0/apJk84AyFCtzlVjQ';
  await mockSeed(WALLET_MXID, dev);
  await instrumentCeremonyCounters(page);
  await injectWallet(page);

  // Establish a session with one wallet signature (via the sessions list).
  await page.goto('/account?action=org.matrix.devices_list');
  await page.click('#btn-wallet');
  await expect(page.locator('.device-row')).toHaveCount(1);

  // Follow the deep link for the slash id (authenticated -> auto-runs, no new sig).
  await page.goto(`/account?action=org.matrix.device_view&device_id=${encodeURIComponent(dev)}`);
  // Success renders the device into #result-section (it would stay on the
  // auth-section with an error if the id were corrupted).
  await expect(page.locator('#result-section')).toContainText('Session details');
  await expect(page.locator('#result-section')).toContainText(dev);
  await expect(page.getByText('not among your active sessions')).toHaveCount(0);
  // The deep link reused the session: no wallet signature on this page.
  expect(await page.evaluate(() => window.__signCount())).toBe(0);
});

test('passkey: one ceremony covers list + sign-out (virtual authenticator)', async ({ page }) => {
  await mockReset();
  await instrumentCeremonyCounters(page);

  // CDP WebAuthn virtual authenticator.
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });

  // A 'session' cookie lets /webauthn/register/start run (value is just a key).
  await page.context().addCookies([{ name: 'session', value: 'browsertestsession', url: BASE }]);
  await page.goto('/account?action=org.matrix.devices_list');

  // Register a passkey and discover its did:key, then seed devices for it.
  const did = await page.evaluate(registerPasskeyInPage);
  expect(did).toMatch(/^did:key:zDn/);
  const pkMxid = `@${did.replaceAll(':', '-').toLowerCase()}:matrix.test`;
  await mockSeed(pkMxid, 'SIWX_pk_a');
  await mockSeed(pkMxid, 'SIWX_pk_b');

  // Authenticate once with the passkey:
  await page.click('#btn-passkey');
  await expect(page.locator('.device-row')).toHaveCount(2);

  // Sign out — via the session, NOT a second passkey ceremony.
  await page.locator('.device-row', { hasText: 'SIWX_pk_a' })
    .getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByText('Session signed out')).toBeVisible();

  const wa = await page.evaluate(() => window.__wa);
  expect(wa.create).toBe(1); // one registration
  expect(wa.get).toBe(1);    // one authentication for the whole session
  const ids = await mockDevices(pkMxid);
  expect(ids).not.toContain('SIWX_pk_a');
  expect(ids).toContain('SIWX_pk_b');
});
