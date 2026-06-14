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
import { Wallet } from 'ethers';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';

// A fixed throwaway test key — never used anywhere real.
const PRIV = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const wallet = new Wallet(PRIV);
const ADDRESS = wallet.address; // EIP-55 checksummed
const WALLET_MXID = `@${`did:pkh:eip155:1:${ADDRESS}`.replaceAll(':', '-').toLowerCase()}:matrix.test`;

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
async function instrumentCeremonyCounters(page) {
  await page.addInitScript(() => {
    window.__wa = { create: 0, get: 0 };
    if (navigator.credentials) {
      const c = navigator.credentials;
      const oc = c.create && c.create.bind(c);
      const og = c.get && c.get.bind(c);
      if (oc) c.create = (...a) => { window.__wa.create++; return oc(...a); };
      if (og) c.get = (...a) => { window.__wa.get++; return og(...a); };
    }
  });
}

// Inject a mock EIP-1193 wallet that signs with the real ethers key.
async function injectWallet(page) {
  await page.exposeFunction('__ethSign', (msg) => wallet.signMessage(msg));
  await page.addInitScript((addr) => {
    let n = 0;
    window.__signCount = () => n;
    window.ethereum = {
      isMetaMask: true,
      isConnected: () => true,
      request: async ({ method, params }) => {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'personal_sign') { n++; return await window.__ethSign(params[0]); }
        throw Object.assign(new Error('unsupported ' + method), { code: 4200 });
      },
      on() {}, removeListener() {},
    };
  }, ADDRESS);
}

// In-page WebAuthn registration ceremony (uses the virtual authenticator).
// Returns the derived did:key.
function registerPasskeyInPage() {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(b); const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  const bufToB64u = (buf) => {
    const by = new Uint8Array(buf); let s = '';
    by.forEach((x) => (s += String.fromCharCode(x)));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return (async () => {
    const sr = await fetch('/webauthn/register/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ display_name: null }),
    });
    if (!sr.ok) throw new Error('register start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    opts.publicKey.user.id = b64uToBuf(opts.publicKey.user.id);
    if (opts.publicKey.excludeCredentials)
      for (const c of opts.publicKey.excludeCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
    const att = cred.response;
    const fr = await fetch('/webauthn/register/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
        response: {
          attestationObject: bufToB64u(att.attestationObject),
          clientDataJSON: bufToB64u(att.clientDataJSON),
        },
      }),
    });
    if (!fr.ok) throw new Error('register finish ' + fr.status + ' ' + (await fr.text()));
    return (await fr.json()).did;
  })();
}

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
