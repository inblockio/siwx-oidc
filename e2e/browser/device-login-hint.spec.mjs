// Headless browser E2E for a device request that names its account
// (`login_hint=mxid:@localpart:server_name` at POST /device_authorization).
//
// The /device approval page must:
//   - show the account the request is for;
//   - refuse an approval by another account with a message naming both, and keep
//     the code pending;
//   - hide the passkey button when the account has no passkey that can approve,
//     and offer it (and approve with it) when it has one.
//
// The stack (siwx-oidc + Synapse mock + Redis) runs externally (e2e/up.sh, or the
// CI browser-e2e job). Run: bash e2e/browser/run.sh.

import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator, registerPasskey } from './webauthn-helper.mjs';
import { makeWallet, injectMockWallet } from './wallet-helper.mjs';
import { localpartFor } from './mxid-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:18080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
const SERVER_NAME = 'matrix.test'; // SIWEOIDC_MATRIX_SERVER_NAME of the e2e stack

async function mockReset() {
  await fetch(`${MOCK}/__reset`, { method: 'POST' });
}
// An existing account; with `did`, it publishes that DID as `io.inblock.did`.
async function mockSeedUser(localpart, did) {
  await fetch(`${MOCK}/__seed_user`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(did ? { localpart, did } : { localpart }),
  });
}

// Register a device-code client and start a device request, in page context.
async function startDeviceRequest(page, loginHint) {
  return page.evaluate(async (hint) => {
    const reg = await fetch('/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [location.origin + '/callback'],
        grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
        response_types: ['code'],
      }),
    });
    if (!reg.ok) throw new Error('register ' + reg.status + ' ' + (await reg.text()));
    const { client_id } = await reg.json();
    let body = 'client_id=' + encodeURIComponent(client_id);
    if (hint) body += '&login_hint=' + encodeURIComponent(hint);
    const r = await fetch('/device_authorization', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
    if (!r.ok) throw new Error('device_authorization ' + r.status + ' ' + (await r.text()));
    return (await r.json()).user_code;
  }, loginHint);
}

async function verifyStatus(page, userCode) {
  return page.evaluate(async (uc) => {
    const r = await fetch('/device/verify?user_code=' + encodeURIComponent(uc));
    return r.status;
  }, userCode);
}

test('hinted request: the page names the account, hides a passkey it lacks, refuses another wallet', async ({ page }) => {
  await mockReset();
  const expected = makeWallet();
  const other = makeWallet();
  // The expected account exists and publishes its DID, and no passkey signs in as it.
  await mockSeedUser(localpartFor(expected.did), expected.did);
  await mockSeedUser(localpartFor(other.did));
  expect(expected.mxid).toBe(`@${localpartFor(expected.did)}:${SERVER_NAME}`);

  // The person holds the OTHER wallet.
  await injectMockWallet(page, other);
  await page.goto('/account');
  const userCode = await startDeviceRequest(page, 'mxid:' + expected.mxid);

  await page.goto('/device?user_code=' + encodeURIComponent(userCode));
  const note = page.locator('#expected-account');
  await expect(note).toBeVisible();
  await expect(note).toContainText(`This request is for ${expected.mxid}.`);
  await expect(page.locator('#btn-passkey')).toBeHidden();
  await expect(page.locator('#passkey-unavailable')).toBeVisible();
  await expect(page.locator('#passkey-unavailable')).toContainText('Sign in with your wallet');
  await expect(page.locator('#btn-wallet')).toBeVisible();

  await page.click('#btn-wallet');
  const status = page.locator('#status-text');
  await expect(status).toContainText(`This request is for ${expected.mxid}.`);
  await expect(status).toContainText(`You signed in as ${other.mxid}.`);
  await expect(page.locator('#terminal-section')).toBeHidden();

  // The code is still pending: the right account can still approve it.
  expect(await verifyStatus(page, userCode)).toBe(200);
});

test('hinted request: an account with a passkey is offered it and approves with it', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'hint-passkey-reg', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const mxid = `@${localpartFor(did)}:${SERVER_NAME}`;
  await mockSeedUser(localpartFor(did), did);

  const userCode = await startDeviceRequest(page, 'mxid:' + mxid);
  await page.goto('/device?user_code=' + encodeURIComponent(userCode));
  await expect(page.locator('#expected-account')).toContainText(`This request is for ${mxid}.`);
  await expect(page.locator('#passkey-unavailable')).toBeHidden();
  await expect(page.locator('#btn-passkey')).toBeVisible();

  await page.click('#btn-passkey');
  await expect(page.locator('#terminal-title')).toHaveText('Device approved');
});

test('request without a hint: no account named, passkey offered as before', async ({ page }) => {
  await mockReset();
  await page.goto('/account');
  const userCode = await startDeviceRequest(page, null);
  await page.goto('/device?user_code=' + encodeURIComponent(userCode));
  await expect(page.locator('#auth-section')).toBeVisible();
  await expect(page.locator('#expected-account')).toBeHidden();
  await expect(page.locator('#btn-passkey')).toBeVisible();
  await expect(page.locator('#passkey-unavailable')).toBeHidden();
});
