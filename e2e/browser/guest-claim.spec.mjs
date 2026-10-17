// The guest claim page (S7b) on the issuer origin, driven by a real browser against the
// host-process stack (siwx-oidc with guest + claim on, the Synapse mock, Redis) and a CDP
// virtual authenticator for the passkey.
//
// Vectors: the happy path CL-01 -> CL-06 (one finish, focus on each heading, the guest key
// forgotten, /guest/resume says claimed, a reload shows CL-E3, a replayed finish is 409);
// the e-mail choice only when the record holds an address (keep travels as `keep_email`);
// "No thanks" -> "Delete everything now" ends the session; a cancelled ceremony is CL-E6 and
// "Back" returns to CL-02 with the session intact; a late attestation is CL-E7; no PublicKey-
// Credential is CL-E5; no cookie is CL-E1; a lost finish is CL-E9 and a proxy 429 is CL-E10.
//
// Env: SIWEOIDC_HOST, SYNAPSE_MOCK, GUEST_SEED_BIN (cargo build --example guest_seed_invite),
// E2E_REDIS_URL, GUEST_CLIENT_ID, GUEST_REDIRECT. Server: SIWXOIDC_GUEST_ENABLED,
// SIWXOIDC_GUEST_CLAIM_ENABLED, SIWXOIDC_GUEST_EMAIL_POLICY=optional.
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { addVirtualAuthenticator } from './webauthn-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:18080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
const SEED = process.env.GUEST_SEED_BIN;
test.skip(!SEED, 'GUEST_SEED_BIN not set: needs a guest-enabled server (opt-in)');
const REDIS_URL = process.env.E2E_REDIS_URL || 'redis://localhost:6379';
const CLIENT = process.env.GUEST_CLIENT_ID || 'meet-guest';
const REDIRECT = process.env.GUEST_REDIRECT || `${BASE}/portal/callback`;
test.describe.configure({ mode: 'serial' });

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function seedInvite() {
  const out = execFileSync(SEED, [REDIS_URL, 'single', '1'], { encoding: 'utf8' });
  const inv = JSON.parse(out.trim().split('\n').pop());
  return `${BASE}/guest/join/${inv.invite_id}#${inv.secret}`;
}

/** Join as a guest, then run the hand-off once so the mock Synapse holds the account (the
 *  claim gate reads it). Returns a page on the issuer origin. */
async function liveGuest(context, { first = 'Ada', second = 'Lovelace', email } = {}) {
  const page = await context.newPage();
  await page.goto(seedInvite());
  await expect(page.locator('#join-form')).toBeVisible();
  await page.fill('#first_name', first);
  await page.fill('#second_name', second);
  if (email) await page.fill('#email', email);
  await page.check('#consent');
  const redeemed = page.waitForResponse((r) => r.url().endsWith('/guest/redeem'));
  await page.click('#submit');
  expect((await redeemed).status()).toBe(200);
  await page.waitForLoadState('networkidle').catch(() => {});

  const verifier = b64u(crypto.randomBytes(32));
  const q = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: `openid urn:matrix:client:api:* urn:matrix:client:device:CLM${Date.now()} urn:io.inblock:guest`,
    state: 'st',
    nonce: 'n',
    code_challenge: b64u(crypto.createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    prompt: 'none',
  });
  await page.route(`${REDIRECT}*`, (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'portal' }));
  await page.goto(`${BASE}/authorize?${q}`);
  await page.waitForURL((u) => u.href.startsWith(REDIRECT), { timeout: 20000 });
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
  await page.unroute(`${REDIRECT}*`);
  return page;
}

const at = (page, code) => expect(page.locator('#app')).toHaveAttribute('data-state', code);
const keyCount = (page) => page.evaluate(() => new Promise((ok) => {
  const o = indexedDB.open('siwx-guest', 1);
  o.onsuccess = () => {
    if (!o.result.objectStoreNames.contains('keys')) return ok(0);
    const r = o.result.transaction('keys', 'readonly').objectStore('keys').getAll();
    r.onsuccess = () => ok(r.result.length);
  };
  o.onerror = () => ok(0);
}));
const resume = async (context) => (await context.request.get(`${BASE}/guest/resume`)).json();
const focusedTag = (page) => page.evaluate(() => document.activeElement && document.activeElement.tagName);

test('happy path: CL-01 to CL-06, one finish, key forgotten, resume says claimed, reload is CL-E3', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context);
  await addVirtualAuthenticator(page);
  const finishes = [];
  page.on('request', (r) => { if (r.url().endsWith('/guest/claim/finish')) finishes.push(r.postDataJSON()); });

  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  expect(await focusedTag(page)).toBe('H2');
  await expect(page.locator('#who')).toHaveText('Ada Lovelace');
  await expect(page.locator('#cl-02')).toContainText('There is no recovery');
  await expect(page.locator('#cl-02')).toContainText('cannot add a second passkey');
  await expect(page.locator('#email-choice')).toBeHidden(); // the record holds no address
  expect(await keyCount(page)).toBeGreaterThan(0);

  await page.click('#create');
  await at(page, 'CL-06');
  expect(await focusedTag(page)).toBe('H2');
  await expect(page.locator('#live')).toHaveText('Your account is kept');
  await expect(page.locator('#cl-06')).toContainText('There is no recovery');
  await expect(page.locator('#back-to-call')).toBeVisible();
  expect(finishes).toHaveLength(1);
  expect(finishes[0].keep_email).toBe(false);
  expect(await keyCount(page)).toBe(0); // A1: the helper forgot the guest key
  expect((await resume(context)).state).toBe('claimed');

  // A replayed finish and a reload are both "already kept".
  const replay = await page.evaluate(async (body) => {
    const r = await fetch('/guest/claim/finish', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, json: await r.json() };
  }, finishes[0]);
  expect(replay.status).toBe(409);
  expect(replay.json.error).toBe('already_claimed');
  await page.reload();
  await at(page, 'CL-E3');
  await expect(page.locator('#err-text')).toHaveText('You already keep this account. Sign in with your passkey.');
  await expect(page.locator('#err-signin')).toBeVisible();
  await context.close();
});

test('the e-mail choice shows only when the record holds an address; keep travels as keep_email', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Grace', second: 'Hopper', email: 'grace@example.org' });
  await addVirtualAuthenticator(page);
  const finishes = [];
  page.on('request', (r) => { if (r.url().endsWith('/guest/claim/finish')) finishes.push(r.postDataJSON()); });
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await expect(page.locator('#email-choice')).toBeVisible();
  await expect(page.locator('#email-remove')).toBeChecked(); // the default is remove
  await expect(page.locator('#email-choice')).not.toContainText('grace@example.org'); // never the address
  await page.check('#email-keep');
  await page.click('#create');
  await at(page, 'CL-06');
  expect(finishes).toHaveLength(1);
  expect(finishes[0].keep_email).toBe(true);
  await context.close();
});

test('No thanks, then Delete everything now ends the session', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Alan', second: 'Turing' });
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await page.click('#decline');
  await at(page, 'CL-07');
  expect(await focusedTag(page)).toBe('H2');
  await expect(page.locator('#cl-07')).toContainText('ends at the deadline');
  await page.click('#delete-now');
  await at(page, 'CL-07-DONE');
  expect(await keyCount(page)).toBe(0);
  expect((await resume(context)).state).toBe('no_session');
  await page.reload();
  await at(page, 'CL-E1');
  await context.close();
});

test('a cancelled ceremony is CL-E6, Back is CL-02 with the session intact, the next try keeps the account', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Edsger', second: 'Dijkstra' });
  await addVirtualAuthenticator(page);
  await page.addInitScript(() => {
    const c = navigator.credentials;
    const real = c.create.bind(c);
    c.create = (...a) => (window.__cancel ? Promise.reject(new DOMException('cancelled', 'NotAllowedError')) : real(...a));
  });
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await page.evaluate(() => { window.__cancel = true; });
  await page.click('#create');
  await at(page, 'CL-E6');
  await expect(page.locator('#err-text')).toHaveText('Nothing was changed.');
  expect((await resume(context)).state).toBe('active');
  await page.click('#err-back');
  await at(page, 'CL-02');
  await page.evaluate(() => { window.__cancel = false; });
  await page.click('#create');
  await at(page, 'CL-06');
  await context.close();
});

test('an attestation older than 120 s is CL-E7', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Barbara', second: 'Liskov' });
  await addVirtualAuthenticator(page);
  await page.addInitScript(() => {
    const realNow = Date.now.bind(Date);
    let skew = 0;
    Date.now = () => realNow() + skew;
    const c = navigator.credentials;
    const real = c.create.bind(c);
    c.create = async (...a) => { const r = await real(...a); skew += 121000; return r; };
  });
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await page.click('#create');
  await at(page, 'CL-E7');
  await expect(page.locator('#err-text')).toContainText('It took too long');
  expect((await resume(context)).state).toBe('active');
  await context.close();
});

test('no PublicKeyCredential is CL-E5 and nothing is started', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Donald', second: 'Knuth' });
  await page.addInitScript(() => { delete window.PublicKeyCredential; });
  const starts = [];
  page.on('request', (r) => { if (r.url().endsWith('/guest/claim/start')) starts.push(1); });
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await page.click('#create');
  await at(page, 'CL-E5');
  expect(starts).toHaveLength(0);
  await page.click('#err-back');
  await at(page, 'CL-02');
  await context.close();
});

test('no cookie is CL-E1 with a Close button', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-E1');
  await expect(page.locator('#err-text')).toHaveText('This browser does not hold your guest session. Claim in the browser you joined with.');
  await expect(page.locator('#err-close')).toBeVisible();
  await context.close();
});

test('a lost finish is CL-E9 (nothing kept), a proxy 429 on start is CL-E10', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await liveGuest(context, { first: 'Margaret', second: 'Hamilton' });
  await addVirtualAuthenticator(page);
  await page.goto(`${BASE}/guest/claim`);
  await at(page, 'CL-02');
  await page.route('**/guest/claim/finish', (route) => route.abort());
  await page.click('#create');
  await at(page, 'CL-E9');
  await expect(page.locator('#err-text')).toHaveText('Try again in a moment. Nothing was kept yet.');
  await page.unroute('**/guest/claim/finish');
  await page.route('**/guest/claim/start', (route) => route.fulfill({ status: 429, contentType: 'application/json', body: '{}' }));
  await page.click('#err-back');
  await at(page, 'CL-02');
  await page.click('#create');
  await at(page, 'CL-E10');
  await page.unroute('**/guest/claim/start');
  await page.click('#err-back');
  await at(page, 'CL-02');
  await context.close();
});
