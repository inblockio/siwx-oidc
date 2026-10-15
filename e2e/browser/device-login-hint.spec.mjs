// Headless browser E2E for a device request that names its account
// (`login_hint=mxid:@localpart:server_name` at POST /device_authorization).
//
// The /device approval page must:
//   - show the account the request is for;
//   - refuse an approval by another account with a message naming both, and keep
//     the code pending;
//   - hide the passkey button when the account has no passkey that can approve,
//     and offer it (and approve with it) when it has one, a passkey linked to a
//     wallet account included;
//   - say that an account is missing, not that it has no passkey.
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

// Start a login as the login page does: register a client and run /authorize, which
// sets the `session` cookie and redirects to the login page with the nonce to sign.
async function startLogin(page) {
  return page.evaluate(async () => {
    const b64u = (buf) => {
      let s = '';
      new Uint8Array(buf).forEach((x) => (s += String.fromCharCode(x)));
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const redirectUri = location.origin + '/callback';
    const reg = await fetch('/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'client_secret_post',
        grant_types: ['authorization_code'], response_types: ['code'],
      }),
    });
    if (!reg.ok) throw new Error('register ' + reg.status);
    const { client_id } = await reg.json();
    const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64u(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const q = new URLSearchParams({
      client_id, redirect_uri: redirectUri, scope: 'openid', response_type: 'code',
      state: 'st', code_challenge: challenge, code_challenge_method: 'S256',
    });
    const landed = new URL((await fetch('/authorize?' + q, { redirect: 'follow' })).url);
    const nonce = landed.searchParams.get('nonce');
    const domain = landed.searchParams.get('domain');
    if (!nonce || !domain) throw new Error('authorize did not yield a nonce; landed=' + landed);
    return { nonce, domain, redirectUri };
  });
}

// The login page's "Link a passkey" step (js/ui/src/App.svelte handleLinkPasskey):
// POST /link/webauthn/start, create the credential, POST /link/webauthn/finish.
async function linkPasskey(page) {
  return page.evaluate(async () => {
    const toBuf = (s) => {
      const b = (s + '='.repeat((4 - (s.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/');
      const r = atob(b); const u = new Uint8Array(r.length);
      for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
      return u.buffer;
    };
    const b64u = (buf) => {
      let s = '';
      new Uint8Array(buf).forEach((x) => (s += String.fromCharCode(x)));
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const sr = await fetch('/link/webauthn/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!sr.ok) throw new Error('link start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = toBuf(opts.publicKey.challenge);
    opts.publicKey.user.id = toBuf(opts.publicKey.user.id);
    for (const c of opts.publicKey.excludeCredentials || []) c.id = toBuf(c.id);
    const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
    const fr = await fetch('/link/webauthn/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
        response: {
          attestationObject: b64u(cred.response.attestationObject),
          clientDataJSON: b64u(cred.response.clientDataJSON),
        },
      }),
    });
    if (!fr.ok) throw new Error('link finish ' + fr.status + ' ' + (await fr.text()));
    return await fr.json();
  });
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

test('hinted request: a passkey linked to a wallet account is offered it and approves with it', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);
  const owner = makeWallet();
  // The wallet account exists and publishes its DID; it has no passkey of its own.
  await mockSeedUser(localpartFor(owner.did), owner.did);
  await page.goto('/account');

  // Before the link: the account has no passkey, so the page does not offer one.
  const before = await startDeviceRequest(page, 'mxid:' + owner.mxid);
  await page.goto('/device?user_code=' + encodeURIComponent(before));
  await expect(page.locator('#passkey-unavailable')).toBeVisible();
  await expect(page.locator('#btn-passkey')).toBeHidden();

  // The wallet signs in on the login page (its `siwx` cookie), then links a passkey.
  await page.goto('/account');
  const login = await startLogin(page);
  const now = new Date();
  const message =
    `${login.domain} wants you to sign in with your Ethereum account:\n${owner.address}\n\n` +
    `You are signing-in to ${login.domain}.\n\nURI: ${BASE}\nVersion: 1\nChain ID: 1\n` +
    `Nonce: ${login.nonce}\nIssued At: ${now.toISOString()}\n` +
    `Expiration Time: ${new Date(now.getTime() + 3600_000).toISOString()}\n` +
    `Resources:\n- ${login.redirectUri}`;
  const signature = await owner.wallet.signMessage(message);
  await page.context().addCookies([{
    name: 'siwx',
    value: encodeURIComponent(JSON.stringify({ did: owner.did, message, signature })),
    url: BASE,
  }]);
  const linked = await linkPasskey(page);
  expect(linked.primary_did).toBe(owner.did);

  // After the link: the same account is offered the passkey, and it approves.
  const userCode = await startDeviceRequest(page, 'mxid:' + owner.mxid);
  await page.goto('/device?user_code=' + encodeURIComponent(userCode));
  await expect(page.locator('#expected-account')).toContainText(`This request is for ${owner.mxid}.`);
  await expect(page.locator('#passkey-unavailable')).toBeHidden();
  await expect(page.locator('#btn-passkey')).toBeVisible();
  await page.click('#btn-passkey');
  await expect(page.locator('#terminal-title')).toHaveText('Device approved');
});

test('hinted request: an account that does not exist is said to be missing, not to lack a passkey', async ({ page }) => {
  await mockReset();
  await page.goto('/account');
  const ghost = makeWallet(); // never seeded in the mock
  const userCode = await startDeviceRequest(page, 'mxid:' + ghost.mxid);
  await page.goto('/device?user_code=' + encodeURIComponent(userCode));
  await expect(page.locator('#expected-account')).toContainText(`This request is for ${ghost.mxid}.`);
  await expect(page.locator('#btn-passkey')).toBeHidden();
  await expect(page.locator('#account-missing')).toBeVisible();
  await expect(page.locator('#passkey-unavailable')).toBeHidden();
  await expect(page.locator('#btn-wallet')).toBeVisible();
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
