// Headless browser E2E for the stale/revoked-passkey UX (2026-06-16).
//
// Proves the Signal-API iteration end to end against the REAL server, driving the
// server-rendered /account passkey page (whose embedded JS carries the change;
// rebuilt by `cargo`, unlike the webpack-bundled login page which CI builds). The
// login page (App.svelte) and the device page share byte-identical handling.
//
// Scenario: register a discoverable passkey (resident key in the virtual
// authenticator + a server record), then DELETE the server record so the resident
// key becomes "stale" (exactly what a revoked/flushed credential looks like). A
// subsequent passkey auth must:
//   H2  -> /account/passkey/finish returns 401 + {error:"unknown_credential", credential_id}
//   H3  -> the page calls PublicKeyCredential.signalUnknownCredential({rpId, credentialId})
//   H4  -> when the API is unsupported, it still shows the actionable message (no crash)
//   H5  -> a VALID passkey auth never fires signalUnknownCredential (trigger isolation)
//
// Prereq: the mock stack on :8080/:8090/:6379 must run the CURRENT binary
// (`bash e2e/up.sh` rebuilds + restarts it). Then: `bash e2e/browser/run.sh`.

import { test, expect } from '@playwright/test';
import net from 'node:net';
import { addVirtualAuthenticator, registerPasskey } from './webauthn-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
const CRED_PREFIX = 'webauthn:credential/';

// -- minimal RESP-over-TCP client: resolves on the first complete reply, handling
//    arrays (KEYS), integers (DEL), bulk/simple strings, and errors ---------------
function redisCmd(args) {
  return new Promise((resolve) => {
    const sock = net.connect(REDIS_PORT, REDIS_HOST);
    let buf = '';
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_) {}
      resolve(v);
    };
    sock.setTimeout(4000);
    sock.on('error', (e) => finish({ __error: String((e && e.message) || e) }));
    sock.on('timeout', () => finish({ __error: 'redis timeout' }));
    sock.on('connect', () => {
      let cmd = `*${args.length}\r\n`;
      for (const a of args) cmd += `$${Buffer.byteLength(a)}\r\n${a}\r\n`;
      sock.write(cmd);
    });
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      const v = parseResp(buf);
      if (v !== undefined) finish(v);
    });
  });
}

// Returns the parsed value, or undefined if more bytes are needed.
function parseResp(buf) {
  if (buf.length < 1) return undefined;
  const type = buf[0];
  const eol = buf.indexOf('\r\n');
  if (eol < 0) return undefined;
  const head = buf.slice(1, eol);
  if (type === '+') return head;
  if (type === '-') return { __error: head };
  if (type === ':') return parseInt(head, 10);
  if (type === '$') {
    const len = parseInt(head, 10);
    if (len < 0) return null;
    const start = eol + 2;
    if (buf.length < start + len + 2) return undefined;
    return buf.slice(start, start + len);
  }
  if (type === '*') {
    const count = parseInt(head, 10);
    if (count < 0) return null;
    const out = [];
    let pos = eol + 2;
    for (let n = 0; n < count; n++) {
      if (pos >= buf.length || buf[pos] !== '$') return undefined;
      const e2 = buf.indexOf('\r\n', pos);
      if (e2 < 0) return undefined;
      const len = parseInt(buf.slice(pos + 1, e2), 10);
      const start = e2 + 2;
      if (buf.length < start + len + 2) return undefined;
      out.push(buf.slice(start, start + len));
      pos = start + len + 2;
    }
    return out;
  }
  return undefined;
}

async function redisKeys(pattern) {
  const r = await redisCmd(['KEYS', pattern]);
  return Array.isArray(r) ? r : [];
}

// Spy/stub PublicKeyCredential.signalUnknownCredential BEFORE page scripts run, so
// feature detection is deterministic regardless of the test browser's native
// support. `enabled:false` removes the symbol to simulate an unsupported browser.
async function installSignalSpy(page, { enabled }) {
  await page.addInitScript((on) => {
    window.__signalCalls = [];
    const PKC = window.PublicKeyCredential;
    if (!PKC) return;
    if (on) {
      PKC.signalUnknownCredential = (opts) => {
        window.__signalCalls.push(opts);
        return Promise.resolve();
      };
    } else {
      try { delete PKC.signalUnknownCredential; } catch (_) {}
      PKC.signalUnknownCredential = undefined;
    }
  }, enabled);
}

// Register a discoverable passkey, then delete its server-side credential so the
// authenticator's resident key is now unknown to the server. Returns the base64url
// credential id (the suffix the server echoes back in the discriminator).
async function makeStaleCredential(page, sessionValue) {
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: sessionValue, url: BASE }]);
  await page.goto('/account');

  const before = await redisKeys(`${CRED_PREFIX}*`);
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const after = await redisKeys(`${CRED_PREFIX}*`);
  const newKeys = after.filter((k) => !before.includes(k));
  expect(newKeys.length).toBeGreaterThanOrEqual(1);

  const key = newKeys[0];
  await redisCmd(['DEL', key]);
  const post = await redisKeys(`${CRED_PREFIX}*`);
  expect(post).not.toContain(key);
  return key.slice(CRED_PREFIX.length);
}

test('H2/H3: stale passkey -> 401 discriminator + signalUnknownCredential + message', async ({ page }) => {
  await installSignalSpy(page, { enabled: true });
  const credId = await makeStaleCredential(page, 'stale-cred-supported');

  await page.goto('/account?action=org.matrix.devices_list');
  const finishP = page.waitForResponse((r) => r.url().includes('/account/passkey/finish'));
  await page.click('#btn-passkey');
  const resp = await finishP;

  // H2: structured 401, not a 500, with the machine-readable discriminator.
  expect(resp.status()).toBe(401);
  const body = await resp.json();
  expect(body.error).toBe('unknown_credential');
  expect(body.credential_id).toBe(credId);

  // The actionable message reaches the user.
  await expect(page.getByText(/no longer valid/i)).toBeVisible();

  // H3: the prune signal fired exactly once, scoped to the id we just presented.
  const calls = await page.evaluate(() => window.__signalCalls);
  expect(calls.length).toBe(1);
  expect(calls[0].credentialId).toBe(credId);
  expect(typeof calls[0].rpId).toBe('string');
  expect(calls[0].rpId.length).toBeGreaterThan(0);
});

test('H4: unsupported signalUnknownCredential -> message shown, no signal, no crash', async ({ page }) => {
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(e));

  await installSignalSpy(page, { enabled: false });
  await makeStaleCredential(page, 'stale-cred-unsupported');

  await page.goto('/account?action=org.matrix.devices_list');
  await page.click('#btn-passkey');

  await expect(page.getByText(/no longer valid/i)).toBeVisible();
  const calls = await page.evaluate(() => window.__signalCalls);
  expect(calls.length).toBe(0);
  expect(pageErrors).toEqual([]);
});

test('H5: a VALID passkey auth never fires signalUnknownCredential (trigger isolation)', async ({ page }) => {
  await installSignalSpy(page, { enabled: true });
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'valid-cred-iso', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);

  // `profile` succeeds on passkey auth alone (no stale credential, no 401).
  await page.goto('/account?action=org.matrix.profile');
  const finishP = page.waitForResponse((r) => r.url().includes('/account/passkey/finish'));
  await page.click('#btn-passkey');
  const resp = await finishP;
  expect(resp.status()).toBe(200);

  const calls = await page.evaluate(() => window.__signalCalls);
  expect(calls.length).toBe(0);
});
