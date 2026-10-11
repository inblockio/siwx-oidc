// The guest hand-off to the portal (S4b), driven by a real browser against the
// host-process stack (siwx-oidc + the Synapse mock + Redis).
//
// The spec plays the portal. The browser joins as a guest (the key stays in its
// IndexedDB), then the spec sends it to /authorize with the guest marker, PKCE S256 and
// prompt=none. The issuer's /guest/continue page signs with the stored key, /sign_in
// provisions and the browser lands on the redirect URI with a code. The spec exchanges
// it (public client, PKCE) and checks the ID token and userinfo carry `io.inblock.guest:
// true`, that the mock Synapse saw the marker PUT before the canonical-name PUT, and that
// /guest/context and /guest/resume answer.
//
// Second test (ST-43 / SY-4 shape): a refused marker PUT gives temporarily_unavailable on
// the redirect URI, no device and no code; with the PUT working again the same browser
// retries and the hand-off heals. Third: no cookie is interaction_required, and
// /guest/ended works with no cookie and forgets the key.
//
// Engine: GUEST_ENGINE=chromium|firefox|webkit. Env: SIWEOIDC_HOST, SYNAPSE_MOCK,
// GUEST_SEED_BIN, E2E_REDIS_URL, GUEST_CLIENT_ID, GUEST_REDIRECT.
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import os from 'node:os';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:18080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
const SEED = process.env.GUEST_SEED_BIN;
// Opt-in, like the --ignored cargo e2e suites: this spec needs a guest-enabled
// server and the guest_seed_invite example binary, which the default CI job
// (guest mode off) does not provide. Without GUEST_SEED_BIN it is skipped.
test.skip(!SEED, 'GUEST_SEED_BIN not set: needs a guest-enabled server (opt-in)');
const REDIS_URL = process.env.E2E_REDIS_URL || 'redis://localhost:6379';
const CLIENT = process.env.GUEST_CLIENT_ID || 'meet-guest';
const REDIRECT = process.env.GUEST_REDIRECT || `${BASE}/portal/callback`;
const ENGINE = process.env.GUEST_ENGINE || 'chromium';
const EXE = {
  firefox: `${os.homedir()}/.cache/ms-playwright/firefox-1532/firefox/firefox`,
  webkit: `${os.homedir()}/.cache/ms-playwright/webkit-2311/pw_run.sh`,
};
test.use({
  browserName: ENGINE,
  launchOptions: EXE[ENGINE] ? { executablePath: EXE[ENGINE] } : {},
});
test.describe.configure({ mode: 'serial' });

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function seedInvite() {
  if (!SEED) throw new Error('set GUEST_SEED_BIN to the guest_seed_invite example binary');
  const out = execFileSync(SEED, [REDIS_URL, 'single', '1'], { encoding: 'utf8' });
  const inv = JSON.parse(out.trim().split('\n').pop());
  return `${BASE}/guest/join/${inv.invite_id}#${inv.secret}`;
}

async function joinAsGuest(context, first = 'Ada', second = 'Lovelace') {
  const page = await context.newPage();
  await page.goto(seedInvite());
  await expect(page.locator('#join-form')).toBeVisible();
  await page.fill('#first_name', first);
  await page.fill('#second_name', second);
  await page.check('#consent');
  const redeemed = page.waitForResponse((r) => r.url().endsWith('/guest/redeem'));
  await page.click('#submit');
  expect((await redeemed).status()).toBe(200);
  await page.waitForLoadState('networkidle').catch(() => {});
  return page;
}

function pkce() {
  const verifier = b64u(crypto.randomBytes(32));
  return { verifier, challenge: b64u(crypto.createHash('sha256').update(verifier).digest()) };
}

/** The portal's authorize request, as a top-level navigation. Resolves to the URL the
 *  browser ends up on: the redirect URI with `code` or `error`. */
async function authorize(page, { device, pk }) {
  const q = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: `openid urn:matrix:client:api:* urn:matrix:client:device:${device} urn:io.inblock:guest`,
    state: 'st-' + device,
    nonce: 'n-' + device,
    code_challenge: pk.challenge,
    code_challenge_method: 'S256',
    prompt: 'none',
  });
  await page.route(`${REDIRECT}*`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'portal' }));
  await page.goto(`${BASE}/authorize?${q}`);
  await page.waitForURL((u) => u.href.startsWith(REDIRECT), { timeout: 20000 });
  const url = new URL(page.url());
  await page.unroute(`${REDIRECT}*`);
  return { url, state: 'st-' + device, nonce: 'n-' + device };
}

async function mock(path, init) {
  const r = await fetch(`${MOCK}${path}`, init);
  return r.json();
}
const fail = (endpoint, mode) =>
  mock('/__fail', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ endpoint, mode }) });

function claims(jwt) {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
}

async function exchange(code, verifier) {
  const r = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: verifier }),
  });
  return { status: r.status, body: await r.json() };
}

test(`hand-off to the portal (${ENGINE}): code, io.inblock.guest, marker PUT before name PUT`, async ({ browser }) => {
  await mock('/__reset', { method: 'POST' });
  const context = await browser.newContext();
  const page = await joinAsGuest(context);
  const pk = pkce();
  const { url, state, nonce } = await authorize(page, { device: 'PWDEV0001', pk });
  expect(url.searchParams.get('error')).toBeNull();
  expect(url.searchParams.get('state')).toBe(state);
  const code = url.searchParams.get('code');
  expect(code).toBeTruthy();

  const tok = await exchange(code, pk.verifier);
  expect(tok.status).toBe(200);
  const idc = claims(tok.body.id_token);
  expect(idc['io.inblock.guest']).toBe(true);
  expect(idc.nonce).toBe(nonce);
  expect(idc.sub).toMatch(/^did:key:/);
  expect(tok.body.scope ?? '').not.toContain('urn:io.inblock:guest');

  const info = await (await fetch(`${BASE}/userinfo`, { headers: { authorization: `Bearer ${tok.body.access_token}` } })).json();
  expect(info['io.inblock.guest']).toBe(true);

  // The mock Synapse saw the marker PUT, then the canonical-name PUT, in that order.
  const st = await mock('/__state');
  const puts = st.admin_puts.filter((p) => p.applied);
  expect(puts.map((p) => p.field)).toEqual(['user_type', 'displayname']);
  expect(puts[0].value).toBe('io.inblock.guest');
  expect(puts[1].value).toBe('Ada Lovelace (Guest)');
  const calls = st.calls.filter((c) => c.includes('provision_user') || c.includes('admin/v2/users') || c.includes('upsert_device'));
  const at = (needle) => calls.findIndex((c) => c.includes(needle));
  expect(at('provision_user')).toBeLessThan(at('admin/v2/users'));
  expect(at('admin/v2/users')).toBeLessThan(at('upsert_device'));

  // In-session reads.
  const ctx = await fetch(`${BASE}/guest/context`, { headers: { authorization: `Bearer ${tok.body.access_token}` } });
  expect(ctx.status).toBe(200);
  const cj = await ctx.json();
  expect(Object.keys(cj).sort()).toEqual(['deadline', 'invite_id', 'meeting_name', 'room_id']);
  expect((await fetch(`${BASE}/guest/context`)).status).toBe(401);
  const resume = await (await context.request.get(`${BASE}/guest/resume`)).json();
  expect(resume.state).toBe('active');
  expect(resume.first_name).toBe('Ada');
  expect(resume.did).toBe(idc.sub);
  expect(resume.seconds_left).toBeGreaterThan(0);

  // A code is single-use.
  expect((await exchange(code, pk.verifier)).status).toBe(400);
  await context.close();
});

test(`a refused marker PUT issues nothing and the retry heals (${ENGINE})`, async ({ browser }) => {
  await mock('/__reset', { method: 'POST' });
  const context = await browser.newContext();
  const page = await joinAsGuest(context, 'Grace', 'Hopper');
  await fail('admin_put_user_type', '500');
  const first = await authorize(page, { device: 'PWDEV0002', pk: pkce() });
  expect(first.url.searchParams.get('error')).toBe('temporarily_unavailable');
  expect(first.url.searchParams.get('code')).toBeNull();
  const st = await mock('/__state');
  expect(st.calls.some((c) => c.includes('upsert_device'))).toBe(false);
  expect(st.admin_puts.map((p) => [p.field, p.applied])).toEqual([['user_type', false]]);

  await fail('admin_put_user_type', 'off');
  const pk = pkce();
  const second = await authorize(page, { device: 'PWDEV0002', pk });
  expect(second.url.searchParams.get('error')).toBeNull();
  const tok = await exchange(second.url.searchParams.get('code'), pk.verifier);
  expect(tok.status).toBe(200);
  expect(claims(tok.body.id_token)['io.inblock.guest']).toBe(true);
  const after = await mock('/__state');
  expect(after.admin_puts.filter((p) => p.applied).map((p) => p.field)).toEqual(['user_type', 'displayname']);
  await context.close();
});

test(`no cookie is interaction_required; /guest/ended works with no cookie and forgets the key (${ENGINE})`, async ({ browser }) => {
  const bare = await browser.newContext();
  const p = await bare.newPage();
  const out = await authorize(p, { device: 'PWDEV0003', pk: pkce() });
  expect(out.url.searchParams.get('error')).toBe('interaction_required');
  await bare.close();

  const context = await browser.newContext();
  const page = await joinAsGuest(context, 'Alan', 'Turing');
  const keyBefore = await page.evaluate(() => new Promise((ok) => {
    const o = indexedDB.open('siwx-guest', 1);
    o.onsuccess = () => { const r = o.result.transaction('keys', 'readonly').objectStore('keys').getAll(); r.onsuccess = () => ok(r.result.length); };
  }));
  expect(keyBefore).toBeGreaterThan(0);
  await context.clearCookies(); // no cookie, no record needed
  await page.goto(`${BASE}/guest/ended`);
  await expect(page.locator('#status')).toHaveText('This guest account is deleted; this browser forgets its key.');
  await expect(page.locator('#app')).toHaveAttribute('data-forgotten', /true|false/);
  const keyAfter = await page.evaluate(() => new Promise((ok) => {
    const o = indexedDB.open('siwx-guest', 1);
    o.onsuccess = () => { const r = o.result.transaction('keys', 'readonly').objectStore('keys').getAll(); r.onsuccess = () => ok(r.result.length); };
  }));
  expect(keyAfter).toBe(0);
  await context.close();
});
