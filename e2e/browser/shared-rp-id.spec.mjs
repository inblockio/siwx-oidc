// Shared WebAuthn RP ID (inblock.io) — cross-service + legacy-transition E2E.
//
// Hostnames: every page is served from a SUBDOMAIN of `inblock.localhost`
// (Chromium resolves *.localhost to loopback by itself, and treats it as a secure
// context over http), standing in for the real subdomains of inblock.io:
//
//   siwx-oidc.inblock.localhost:18290  siwx-oidc, PRE-change config (RP ID = own host)
//   siwx-oidc.inblock.localhost:18291  siwx-oidc, shared RP ID `inblock.localhost`
//                                      (legacy RP ID = its own host, the default)
//   aquafire.inblock.localhost:3291    aquafier (aqua-node), shared RP ID
//                                      `inblock.localhost`
//
// No page is ever served from the apex `inblock.localhost`: the shared RP ID is a
// registrable suffix of each page's host (WebAuthn L3 §5.1), nothing more.
// Both services share the aqua-auth credential store (AQUA_WEBAUTHN_REDIS_URL),
// which is what lets aquafier verify a credential siwx-oidc registered.
//
// Stack: ~/.cache/shared-rp-id/stack.sh (not part of e2e/up.sh). Run with
//   bash e2e/browser/run.sh shared-rp-id.spec.mjs
import { test, expect } from '@playwright/test';
import net from 'node:net';
import { addVirtualAuthenticator, registerPasskey } from './webauthn-helper.mjs';

const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
const SIWX_LEGACY = process.env.SRP_SIWX_LEGACY || 'http://siwx-oidc.inblock.localhost:18290';
const SIWX_SHARED = process.env.SRP_SIWX_SHARED || 'http://siwx-oidc.inblock.localhost:18291';
const AQF = process.env.SRP_AQF || 'http://aquafire.inblock.localhost:3291';
const CRED_PREFIX = 'webauthn:credential/';
const RP_PREFIX = 'webauthn:rp_id/';

// -- minimal RESP-over-TCP Redis client (same pattern as stale-credential.spec) --
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


async function newCredIdAfter(before) {
  const after = await redisCmd(['KEYS', `${CRED_PREFIX}*`]);
  const fresh = after.filter((k) => !before.includes(k));
  expect(fresh.length).toBe(1);
  return fresh[0].slice(CRED_PREFIX.length);
}

// A siwx-oidc login session: the `session` cookie keys the challenge, and
// authenticate/finish writes verified_did into `sessions/{id}`.
async function seedSession(page, base, id) {
  const entry = JSON.stringify({ siwe_nonce: 'n', oidc_nonce: null, secret: 's', signin_count: 0 });
  expect(await redisCmd(['SET', `sessions/${id}`, entry, 'EX', '300'])).toBe('OK');
  await page.context().addCookies([{ name: 'session', value: id, url: base }]);
}

// Login ceremony against siwx-oidc; `legacy` selects the older-passkey rpId.
function siwxLogin({ legacy }) {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const r = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  const bufToB64u = (buf) => {
    let s = '';
    new Uint8Array(buf).forEach((x) => (s += String.fromCharCode(x)));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return (async () => {
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(legacy ? { legacy: true } : {}),
    });
    if (!sr.ok) throw new Error('start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    const rpId = opts.publicKey.rpId;
    const legacyRpId = opts.legacy_rp_id || null;
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    for (const c of opts.publicKey.allowCredentials || []) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const r = cred.response;
    const fr = await fetch('/webauthn/authenticate/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
        response: {
          authenticatorData: bufToB64u(r.authenticatorData),
          clientDataJSON: bufToB64u(r.clientDataJSON),
          signature: bufToB64u(r.signature),
          userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
        },
      }),
    });
    if (!fr.ok) throw new Error('finish ' + fr.status + ' ' + (await fr.text()));
    const out = await fr.json();
    return { did: out.did, rpId, legacyRpId, credId: bufToB64u(cred.rawId) };
  })();
}

test('shared RP ID: one passkey, one did:key across siwx-oidc and aquafier; legacy passkeys still log in', async ({ page }) => {
  const { client, authenticatorId } = await addVirtualAuthenticator(page);

  // 1. LEGACY passkey: registered by siwx-oidc under the pre-change config
  //    (RP ID = siwx-oidc.inblock.localhost). The RP-ID record is then deleted so
  //    the row is byte-for-byte what a pre-change server stored (blob only).
  await page.goto(SIWX_LEGACY + '/health');
  await seedSession(page, SIWX_LEGACY, 'srp-legacy-reg');
  let before = await redisCmd(['KEYS', `${CRED_PREFIX}*`]);
  const legacyDid = await registerPasskey(page);
  const legacyCred = await newCredIdAfter(before);
  expect(await redisCmd(['GET', RP_PREFIX + legacyCred])).toBe('siwx-oidc.inblock.localhost');
  await redisCmd(['DEL', RP_PREFIX + legacyCred]);

  // 2. NEW passkey: registered by the shared-RP siwx-oidc (rp.id = inblock.localhost).
  await page.goto(SIWX_SHARED + '/health');
  await seedSession(page, SIWX_SHARED, 'srp-shared-reg');
  before = await redisCmd(['KEYS', `${CRED_PREFIX}*`]);
  const sharedDid = await registerPasskey(page);
  const sharedCred = await newCredIdAfter(before);
  expect(await redisCmd(['GET', RP_PREFIX + sharedCred])).toBe('inblock.localhost');
  expect(sharedDid).toMatch(/^did:key:zDn/);
  expect(sharedDid).not.toBe(legacyDid);

  // The authenticator itself holds each credential under its own RP ID.
  const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
  const rpOf = Object.fromEntries(credentials.map((c) => [c.credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), c.rpId]));
  expect(rpOf[sharedCred]).toBe('inblock.localhost');
  expect(rpOf[legacyCred]).toBe('siwx-oidc.inblock.localhost');

  // 3. siwx-oidc login, default ceremony: rpId = shared, the NEW passkey answers.
  await seedSession(page, SIWX_SHARED, 'srp-login-1');
  const a = await page.evaluate(siwxLogin, { legacy: false });
  expect(a.rpId).toBe('inblock.localhost');
  expect(a.legacyRpId).toBe('siwx-oidc.inblock.localhost');
  expect(a.credId).toBe(sharedCred);
  expect(a.did).toBe(sharedDid);

  // 4. siwx-oidc login, "Use an older passkey": rpId = legacy, the OLD passkey
  //    (no recorded RP ID) still logs in, verified against the legacy RP ID.
  await seedSession(page, SIWX_SHARED, 'srp-login-2');
  const b = await page.evaluate(siwxLogin, { legacy: true });
  expect(b.rpId).toBe('siwx-oidc.inblock.localhost');
  expect(b.credId).toBe(legacyCred);
  expect(b.did).toBe(legacyDid);

  // 5. aquafier login with the SAME credential siwx-oidc registered: the stock
  //    login page's Passkey.login() (rpId = inblock.localhost), served from
  //    aquafire.inblock.localhost. Same credential -> same did:key.
  await page.goto(AQF + '/login');
  const session = await page.evaluate(() => window.Passkey.login());
  expect(session.address).toBe(sharedDid);
  expect(session.did).toBe(sharedDid);
  const aqfStart = await page.evaluate(async () => {
    const r = await fetch('/auth/webauthn/login/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    return r.json();
  });
  expect(aqfStart.options.publicKey.rpId).toBe('inblock.localhost');

  console.log(JSON.stringify({ legacyDid, sharedDid, sharedCred, legacyCred, aquafierDid: session.did }));
});

// aquafier's own legacy path (Postgres credential store). Stack:
// ~/.cache/shared-rp-id/stack-aqf-legacy.sh — A1 = pre-change config on :3292
// (RP ID = aquafire.inblock.localhost), A2 = AQUAFIER_WEBAUTHN_RP_ID=inblock.localhost
// on :3293 with the default legacy RP ID, one shared Postgres. A1's rows are
// stored with rp_id NULL (a test trigger), exactly like pre-migration-037 rows.
const AQF1 = process.env.SRP_AQF1 || 'http://aquafire.inblock.localhost:3292';
const AQF2 = process.env.SRP_AQF2 || 'http://aquafire.inblock.localhost:3293';

test('aquafier: a pre-change passkey logs in via "older passkey"; new ones use the shared RP ID', async ({ page }) => {
  test.skip(!(await fetch(AQF1.replace('aquafire.inblock.localhost', '127.0.0.1') + '/status').then((r) => r.ok).catch(() => false)),
    'aquafier legacy stack not running');
  await addVirtualAuthenticator(page);
  // aquafier registers with webauthn-rs's default residentKey "discouraged", so
  // the CDP authenticator would mint a NON-discoverable credential that its
  // usernameless login can never find (pre-existing, independent of the RP ID;
  // real platform passkeys are always discoverable). Model a platform passkey.
  await page.addInitScript(() => {
    const c = navigator.credentials;
    const oc = c.create.bind(c);
    c.create = (o) => {
      if (o && o.publicKey) {
        o.publicKey.authenticatorSelection = { ...(o.publicKey.authenticatorSelection || {}), residentKey: 'required', requireResidentKey: true };
      }
      return oc(o);
    };
  });

  // Pre-change registration on A1 (rpId = aquafire.inblock.localhost).
  await page.goto(AQF1 + '/login');
  const old = await page.evaluate(() => window.Passkey.register({ display_name: 'old', nickname: 'old' }));
  expect(old.address).toMatch(/^did:key:zDn/);

  // A2 (shared RP ID): the legacy ceremony reaches the old passkey.
  await page.goto(AQF2 + '/login');
  const legacyStart = await page.evaluate(async () => {
    const r = await fetch('/auth/webauthn/login/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ legacy: true }) });
    return r.json();
  });
  expect(legacyStart.options.publicKey.rpId).toBe('aquafire.inblock.localhost');
  expect(legacyStart.legacy_rp_id).toBe('aquafire.inblock.localhost');
  const viaLegacy = await page.evaluate(() => window.Passkey.login({ legacy: true }));
  expect(viaLegacy.address).toBe(old.address);

  // Signed in (via the old passkey), the user adds a passkey on A2: it is
  // bound to the SAME account (aquafier's authenticated add-a-passkey path) but
  // created under the shared RP ID, and the default ceremony now finds it. This
  // is the in-product way off a legacy passkey for aquafier users.
  const fresh = await page.evaluate(() => window.Passkey.register({ display_name: 'new', nickname: 'new' }));
  expect(fresh.address).toBe(old.address);
  const sharedStart = await page.evaluate(async () => {
    const r = await fetch('/auth/webauthn/login/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    return r.json();
  });
  expect(sharedStart.options.publicKey.rpId).toBe('inblock.localhost');
  const viaShared = await page.evaluate(() => window.Passkey.login());
  expect(viaShared.address).toBe(old.address);
  console.log(JSON.stringify({ aquafierLegacyDid: old.address, aquafierSharedDid: fresh.address }));
});
