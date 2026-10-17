// The guest join page on the issuer origin (S3c): the real browser redeems a real invite
// against the host-process stack, and the key never leaves the browser.
//
//   * redeem: form -> proof of possession -> 200 -> redirect; Redis holds a `minted` record
//     with the page's DID (derived here from the PUBLIC key read out of IndexedDB);
//   * (a) no private key bytes on the network: every request body is the credentials,
//     the form fields, the DID and the proof, nothing else; the secret never rides a URL;
//   * (b) localStorage and sessionStorage are empty;
//   * (c) the IndexedDB key is a non-extractable CryptoKey and refuses export;
//   * (d) opening the same link again shows the used state and mints nothing;
//   * (e) framed, the page refuses (by header, and by script when the headers are stripped).
//
// Engine: GUEST_ENGINE=chromium|firefox|webkit (the last two from the Playwright cache
// through executablePath, as the SP-10 probe did). Env: SIWEOIDC_HOST, GUEST_SEED_BIN
// (cargo build --example guest_seed_invite), E2E_REDIS_URL, GUEST_REDIS_CONTAINER.
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import fs from 'node:fs';

// The page's own helper, loaded from a data: URL so no loader (Playwright's differs by
// version on a .js file outside a "type": "module" package) decides how it is parsed.
const { didFromRaw } = await import(
  `data:text/javascript;base64,${fs.readFileSync(new URL('../../static/guest/guest-key.js', import.meta.url)).toString('base64')}`
);

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:18080';
const SEED = process.env.GUEST_SEED_BIN;
// Opt-in, like the --ignored cargo e2e suites: this spec needs a guest-enabled
// server and the guest_seed_invite example binary, which the default CI job
// (guest mode off) does not provide. Without GUEST_SEED_BIN it is skipped.
test.skip(!SEED, 'GUEST_SEED_BIN not set: needs a guest-enabled server (opt-in)');
const REDIS_URL = process.env.E2E_REDIS_URL || 'redis://localhost:6379';
const REDIS_CT = process.env.GUEST_REDIS_CONTAINER || 'fps-redis-test';
const ENGINE = process.env.GUEST_ENGINE || 'chromium';
const EXE = {
  firefox: `${os.homedir()}/.cache/ms-playwright/firefox-1532/firefox/firefox`,
  webkit: `${os.homedir()}/.cache/ms-playwright/webkit-2311/pw_run.sh`,
};
test.use({
  browserName: ENGINE,
  launchOptions: EXE[ENGINE] ? { executablePath: EXE[ENGINE] } : {},
});

const redis = (...args) =>
  execFileSync('podman', ['exec', REDIS_CT, 'redis-cli', '--raw', ...args], { encoding: 'utf8' });

function seedInvite(kind = 'single', max = 1) {
  if (!SEED) throw new Error('set GUEST_SEED_BIN to the guest_seed_invite example binary');
  const out = execFileSync(SEED, [REDIS_URL, kind, String(max)], { encoding: 'utf8' });
  const inv = JSON.parse(out.trim().split('\n').pop());
  return { ...inv, link: `${BASE}/guest/join/${inv.invite_id}#${inv.secret}` };
}

/** The guest:acct hash whose `did` is `did`, or null. */
function accountOf(did) {
  const keys = redis('--scan', '--pattern', 'guest:acct/*').split('\n').filter(Boolean);
  for (const k of keys) {
    if (redis('HGET', k, 'did').trim() === did) {
      const flat = redis('HGETALL', k).split('\n');
      const h = {};
      for (let i = 0; i + 1 < flat.length; i += 2) h[flat[i]] = flat[i + 1];
      return h;
    }
  }
  return null;
}

/** Record every request of the context: method, url, headers, body. */
function record(context) {
  const seen = [];
  context.on('request', (r) =>
    seen.push({ method: r.method(), url: r.url(), body: r.postData() || '', headers: r.headers() }));
  return seen;
}

async function fillAndJoin(page, { first = 'Ada', second = 'Lovelace' } = {}) {
  await expect(page.locator('#join-form')).toBeVisible();
  await page.fill('#first_name', first);
  await page.fill('#second_name', second);
  await page.check('#consent');
  await page.click('#submit');
}

/** The stored key pair, inspected in the page: nothing private is read out of it. */
async function inspectKey(page) {
  return page.evaluate(async () => {
    const kp = await new Promise((ok, fail) => {
      const open = indexedDB.open('siwx-guest', 1);
      open.onerror = () => fail(open.error);
      open.onsuccess = () => {
        const req = open.result.transaction('keys', 'readonly').objectStore('keys').get('current');
        req.onsuccess = () => ok(req.result);
        req.onerror = () => fail(req.error);
      };
    });
    if (!kp) return { found: false };
    let exportRefused = false;
    try { await crypto.subtle.exportKey('pkcs8', kp.privateKey); } catch (_) { exportRefused = true; }
    let jwkRefused = false;
    try { await crypto.subtle.exportKey('jwk', kp.privateKey); } catch (_) { jwkRefused = true; }
    return {
      found: true,
      isCryptoKey: kp.privateKey instanceof CryptoKey && kp.publicKey instanceof CryptoKey,
      extractable: kp.privateKey.extractable,
      type: kp.privateKey.type,
      alg: kp.publicKey.algorithm.name,
      exportRefused,
      jwkRefused,
      raw: Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))),
    };
  });
}

const ALLOWED_BODY_KEYS = new Set(['invite_id', 'secret', 'first_name', 'second_name', 'email', 'consent', 'did', 'proof']);

test.describe.configure({ mode: 'serial' });

for (const forceP256 of [false, true]) {
  test(`redeem ${forceP256 ? 'with the P-256 fallback' : 'with the preferred key'} (${ENGINE}): key stays in the browser`, async ({ browser }) => {
    const context = await browser.newContext();
    if (forceP256) {
      // A browser without WebCrypto Ed25519: generateKey refuses it, P-256 is the fallback.
      await context.addInitScript(() => {
        const gen = crypto.subtle.generateKey.bind(crypto.subtle);
        crypto.subtle.generateKey = (alg, ...rest) => {
          const name = typeof alg === 'string' ? alg : alg && alg.name;
          return name === 'Ed25519' ? Promise.reject(new DOMException('no', 'NotSupportedError')) : gen(alg, ...rest);
        };
      });
    }
    const seen = record(context);
    const page = await context.newPage();
    const inv = seedInvite();

    await page.goto(inv.link);
    await expect(page.locator('#join-form')).toBeVisible();
    // The fragment is gone from the address bar as soon as the page has read it.
    expect(page.url()).toBe(`${BASE}/guest/join/${inv.invite_id}`);
    await fillAndJoin(page);
    await page.waitForURL(/\/error/);

    // Redirected to the guest client URL; Redis has a minted record with the page's DID.
    const key = await inspectKey(page);
    expect(key.found).toBe(true);
    const did = didFromRaw(key.alg, Uint8Array.from(key.raw));
    expect(did.startsWith(forceP256 ? 'did:key:zDn' : 'did:key:z6Mk')).toBe(true);
    expect(key.alg).toBe(forceP256 ? 'ECDSA' : 'Ed25519');
    const account = accountOf(did);
    expect(account, 'a guest:acct record for the page DID').not.toBeNull();
    expect(account.state).toBe('minted');
    expect(account.invite_id).toBe(inv.invite_id);
    expect(account.first_name).toBe('Ada');

    // (a) nothing but the public DID, the message and the signature went out.
    const posts = seen.filter((r) => r.method === 'POST');
    expect(posts.map((r) => new URL(r.url).pathname)).toEqual(['/guest/peek', '/guest/redeem']);
    for (const r of posts) {
      const body = JSON.parse(r.body);
      for (const k of Object.keys(body)) expect(ALLOWED_BODY_KEYS.has(k), `unexpected body key ${k}`).toBe(true);
      expect(r.body).not.toMatch(/pkcs8|"jwk"|"kty"|privateKey|PRIVATE|"d"\s*:/i);
    }
    const redeem = JSON.parse(posts[1].body);
    expect(redeem.did).toBe(did);
    expect(redeem.proof.message).toContain(did);
    expect(redeem.proof.message).not.toContain(inv.secret);
    expect(Object.keys(redeem.proof).sort()).toEqual(['message', 'signature']);
    // The secret travelled only in those two bodies: never in a URL, a header or a referrer.
    for (const r of seen) {
      expect(r.url).not.toContain(inv.secret);
      expect(JSON.stringify(r.headers)).not.toContain(inv.secret);
      if (r.method !== 'POST') expect(r.body).toBe('');
    }

    // (b) no key material, nor anything else, in web storage.
    const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }));
    expect(storage).toEqual({ local: 0, session: 0 });

    // (c) a CryptoKey that cannot be exported.
    expect(key.isCryptoKey).toBe(true);
    expect(key.extractable).toBe(false);
    expect(key.type).toBe('private');
    expect(key.exportRefused).toBe(true);
    expect(key.jwkRefused).toBe(true);

    // (d) the same link again: used, and nothing minted.
    const before = redis('--scan', '--pattern', 'guest:acct/*').split('\n').filter(Boolean).length;
    await page.goto(inv.link);
    await expect(page.locator('#blocked-text')).toContainText('already been used');
    await expect(page.locator('#join-form')).toBeHidden();
    const after = redis('--scan', '--pattern', 'guest:acct/*').split('\n').filter(Boolean).length;
    expect(after).toBe(before);
    await context.close();
  });
}

test(`a wrong secret and a stripped link show the invalid state (${ENGINE})`, async ({ page }) => {
  const inv = seedInvite();
  await page.goto(`${BASE}/guest/join/${inv.invite_id}#gi_notthesecretnotthesecretnotthesecr`);
  await expect(page.locator('#blocked-text')).toContainText('not valid');
  await page.goto(`${BASE}/guest/join/${inv.invite_id}`);
  await expect(page.locator('#blocked-text')).toContainText('not valid');
});

test(`(e) framed, the page refuses (${ENGINE})`, async ({ page }) => {
  const inv = seedInvite();
  const posts = [];
  page.on('request', (r) => { if (r.method() === 'POST') posts.push(r.url()); });
  await page.route(`${BASE}/embed-test`, (route) =>
    route.fulfill({ contentType: 'text/html', body: `<!doctype html><iframe id="f" src="${inv.link}"></iframe>` }));

  // 1. With the headers intact the browser itself refuses to render the frame.
  await page.goto(`${BASE}/embed-test`);
  await page.waitForTimeout(1500);
  const blocked = page.frameLocator('#f');
  await expect(blocked.locator('#join-form')).toHaveCount(0);
  await expect(blocked.locator('#status')).toHaveCount(0);
  expect(posts).toEqual([]);

  // 2. With XFO and CSP stripped (a proxy bug), the script still refuses and sends nothing.
  await page.route(/\/guest\/join\//, async (route) => {
    const res = await route.fetch();
    const headers = { ...res.headers() };
    delete headers['x-frame-options'];
    delete headers['content-security-policy'];
    await route.fulfill({ response: res, headers });
  });
  await page.goto(`${BASE}/embed-test`);
  await expect(page.frameLocator('#f').locator('#blocked-text')).toContainText('cannot be shown inside another page');
  await expect(page.frameLocator('#f').locator('#join-form')).toBeHidden();
  expect(posts).toEqual([]);
});
