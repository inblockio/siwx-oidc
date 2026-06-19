// Headless browser E2E for the passkey-picker SCOPING + new-user GATE +
// account/QR new-identity REJECT + Secure-Backup false-positive REMOVAL
// (feat/passkey-scoping-new-user-gate, 2026-06-18).
//
// These are SERVER-CONTRACT tests: the webpack-bundled login page (App.svelte) is
// NOT rebuilt locally, so we drive fetch() in page context and assert on the JSON
// the server returns, plus the server-rendered /account + /device pages where the
// embedded JS is cargo-built. The login page consumes exactly the contract proven
// here (the new sibling fields + the new_user gate).
//
// Hypotheses (see docs/design/2026-06-18-passkey-scoping-and-new-user-gate.md):
//   H1  cookie-scoped authenticate/start -> allowCredentials == that DID's keys
//   H11 escape hatch ({"all":true} / ?all=1) -> usernameless again
//   H2  forged siwx_user cookie -> Redis miss -> empty allowCredentials, no leak
//   H4  new passkey at LOGIN -> finish {new_user:true, mxid}, NOTHING provisioned
//   H5  new passkey in ACCOUNT or QR/DEVICE flow -> 400 reject, nothing provisioned
//   H9  device approval for an EXISTING user -> no "no Secure Backup" warning
//
// The stack (siwx-oidc :8080 + Synapse mock :8090 + Redis :6379) runs externally
// (e2e/up.sh, which also rebuilds the binary). Run: bash e2e/browser/run.sh.

import { test, expect } from '@playwright/test';
import net from 'node:net';
import { addVirtualAuthenticator, registerPasskey } from './webauthn-helper.mjs';
import { makeWallet, injectMockWallet } from './wallet-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
const SERVER_NAME = 'matrix.test'; // SIWEOIDC_MATRIX_SERVER_NAME in e2e/up.sh
const CRED_PREFIX = 'webauthn:credential/';
const USER_SESSION_PREFIX = 'user:session/'; // KV_USER_SESSION_PREFIX (db/mod.rs)

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

async function redisKeys(pattern) {
  const r = await redisCmd(['KEYS', pattern]);
  return Array.isArray(r) ? r : [];
}

// -- mock (Synapse stand-in) helpers -----------------------------------------
async function mockReset() {
  await fetch(`${MOCK}/__reset`, { method: 'POST' });
}
async function mockState() {
  return (await fetch(`${MOCK}/__state`)).json();
}
// Mark a localpart as EXISTING so the new-identity gate treats it as a returning
// account (the mock would otherwise report every localpart as available = new).
async function mockSeedUser(localpart) {
  await fetch(`${MOCK}/__seed_user`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ localpart }),
  });
}
async function mockSeedDevice(mxid, deviceId) {
  await fetch(`${MOCK}/__seed_device`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: mxid, device_id: deviceId, display_name: 'Element' }),
  });
}

function didToLocalpart(did) {
  return did.replaceAll(':', '-').toLowerCase();
}
function didToMxid(did) {
  return `@${didToLocalpart(did)}:${SERVER_NAME}`;
}

// Register a passkey under a fresh `session` cookie and return both its derived
// did:key AND the base64url credential id (read back from the freshly-created
// webauthn:credential/* Redis key). The cred id is what authenticate/start scopes
// to, so we can assert allowCredentials byte-for-byte.
async function registerPasskeyWithCredId(page, sessionValue) {
  await page.context().addCookies([{ name: 'session', value: sessionValue, url: BASE }]);
  await page.goto('/account');
  const before = await redisKeys(`${CRED_PREFIX}*`);
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const after = await redisKeys(`${CRED_PREFIX}*`);
  const fresh = after.filter((k) => !before.includes(k));
  expect(fresh.length).toBe(1);
  return { did, credId: fresh[0].slice(CRED_PREFIX.length) };
}

// POST /webauthn/authenticate/start in page context (so the `session` +
// `siwx_user` cookies ride along) and return the parsed JSON wrapper.
async function authenticateStart(page, { body = '{}', query = '' } = {}) {
  return page.evaluate(async ({ body, query }) => {
    const r = await fetch('/webauthn/authenticate/start' + query, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    });
    if (!r.ok) throw new Error('authenticate/start ' + r.status + ' ' + (await r.text()));
    return r.json();
  }, { body, query });
}

// ---------------------------------------------------------------------------
// 1 + 2 + 3: SCOPING, ESCAPE, FORGED COOKIE — all on one page so two registered
// passkeys (DID A + DID B) coexist and we can prove the picker is scoped.
// ---------------------------------------------------------------------------
test('H1/H11/H2: cookie scopes the picker; escape + forged cookie fall back to usernameless', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);

  // Register passkey A (DID A) and passkey B (DID B) on this authenticator.
  const a = await registerPasskeyWithCredId(page, 'scope-sess');
  const b = await registerPasskeyWithCredId(page, 'scope-sess');
  expect(a.did).not.toBe(b.did);
  expect(a.credId).not.toBe(b.credId);

  // A `session` cookie is required for authenticate/start to store its challenge.
  await page.context().addCookies([{ name: 'session', value: 'scope-auth-sess', url: BASE }]);

  // (a) NO siwx_user cookie -> usernameless: allowCredentials EMPTY (the shipped
  //     enumeration-safe default; the picker would show every resident key).
  const unscoped = await authenticateStart(page);
  expect(unscoped.publicKey.allowCredentials || []).toEqual([]);
  expect(unscoped.detected_mxid == null).toBe(true);

  // (b) Mint a VALID opaque user-session token -> DID A, the exact way the server
  //     does (a Redis key user:session/{token} -> did). HttpOnly forbids JS from
  //     setting siwx_user, so we attach it via the browser context (the token is
  //     opaque; possession of it is the whole point).
  const token = 'e2etoken' + Date.now().toString(16) + Math.random().toString(16).slice(2);
  const setRes = await redisCmd(['SET', `${USER_SESSION_PREFIX}${token}`, a.did]);
  expect(setRes).toBe('OK');
  await page.context().addCookies([{ name: 'siwx_user', value: token, url: BASE }]);

  // SCOPING: authenticate/start now scopes to DID A's credentials ONLY.
  const scoped = await authenticateStart(page);
  const ids = (scoped.publicKey.allowCredentials || []).map((c) => c.id);
  expect(ids).toEqual([a.credId]);            // exactly A, never B
  expect(ids).not.toContain(b.credId);
  expect(scoped.detected_mxid).toBe(didToMxid(a.did));
  // No server-side method prediction: the offer is scoped by identity
  // (allowCredentials) only; method availability is resolved live/locally, so the
  // response carries no `methods` hint.
  expect(scoped.methods).toBeUndefined();

  // ESCAPE (H11): body {"all":true} forces usernameless even with the cookie.
  const escapeBody = await authenticateStart(page, { body: JSON.stringify({ all: true }) });
  expect(escapeBody.publicKey.allowCredentials || []).toEqual([]);
  expect(escapeBody.detected_mxid == null).toBe(true);

  // ESCAPE (H11): the ?all=1 query form does the same.
  const escapeQuery = await authenticateStart(page, { query: '?all=1' });
  expect(escapeQuery.publicKey.allowCredentials || []).toEqual([]);
  expect(escapeQuery.detected_mxid == null).toBe(true);

  // FORGED COOKIE (H2 enumeration-safety): a garbage siwx_user value is a Redis
  // miss -> usernameless, allowCredentials EMPTY, detected_mxid null. Zero leak.
  await page.context().clearCookies();
  await page.context().addCookies([
    { name: 'session', value: 'scope-auth-sess', url: BASE },
    { name: 'siwx_user', value: 'totally-forged-not-a-real-token', url: BASE },
  ]);
  const forged = await authenticateStart(page);
  expect(forged.publicKey.allowCredentials || []).toEqual([]);
  expect(forged.detected_mxid == null).toBe(true);
});

// ---------------------------------------------------------------------------
// 4: NEW-USER GATE (login). A brand-new passkey at /webauthn/authenticate/finish
// returns new_user:true + mxid and provisions NOTHING (provisioning happens only
// at /sign_in, which the browser reaches only after the user CONFIRMS the gate).
// ---------------------------------------------------------------------------
test('H4: login with a brand-new passkey -> new_user:true + mxid, nothing provisioned', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);

  // Register a fresh passkey -> a DID the mock has never seen (so it is "new").
  await page.context().addCookies([{ name: 'session', value: 'gate-reg-sess', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const mxid = didToMxid(did);

  // authenticate_finish must read the OIDC session row to stash verified_did, and
  // that row is created by /authorize (which also sets a fresh `session` cookie).
  // So run the canonical login start->get->finish AFTER establishing the session,
  // exactly as the real login page does. This proves the GATE seam: finish reports
  // new_user without provisioning (provisioning is /sign_in, which we do NOT call).
  const finish = await page.evaluate(async () => {
    const enc = encodeURIComponent;
    const q = (o) => Object.entries(o).map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
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
    // 1. Register a dynamic client + run /authorize to create the session row.
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
    const codeVerifier = bufToB64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challengeBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = bufToB64u(challengeBuf);
    const authorizeUrl = '/authorize?' + q({
      client_id, redirect_uri: redirectUri, scope: 'openid',
      response_type: 'code', state: 'st', code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    const authFollowed = await fetch(authorizeUrl, { redirect: 'follow' });
    if (!new URL(authFollowed.url).searchParams.get('nonce'))
      throw new Error('authorize did not yield a nonce; landed=' + authFollowed.url);

    // 2. The login passkey ceremony (start -> get -> finish) on this session.
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!sr.ok) throw new Error('start ' + sr.status);
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
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
    return { status: fr.status, body: fr.ok ? await fr.json() : await fr.text() };
  });

  // The gate: finish SUCCEEDS (200, ok:true) but flags the brand-new identity.
  expect(finish.status).toBe(200);
  expect(finish.body.ok).toBe(true);
  expect(finish.body.did).toBe(did);
  expect(finish.body.new_user).toBe(true);  // would CREATE an account at /sign_in
  expect(finish.body.mxid).toBe(mxid);

  // Nothing was provisioned: finish never touches Synapse beyond the read-only
  // is_localpart_available probe. No provision_user / upsert_device, no devices.
  const s = await mockState();
  expect(s.existing_users).not.toContain(didToLocalpart(did));
  expect(s.devices[mxid] || []).toEqual([]);
  expect(s.calls.some((c) => c.includes('provision_user'))).toBe(false);
  expect(s.calls.some((c) => c.includes('upsert_device'))).toBe(false);
});

// ---------------------------------------------------------------------------
// 5: ACCOUNT REJECT. A brand-new passkey on /account/passkey/finish is REJECTED
// with 400 + NEW_IDENTITY_REJECT_MSG; nothing provisioned. (New-account creation
// is reachable ONLY from login.)
// ---------------------------------------------------------------------------
test('H5: brand-new passkey on /account/passkey/finish -> 400 reject, nothing provisioned', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'acct-reject-sess', url: BASE }]);
  await page.goto('/account?action=org.matrix.profile');

  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const mxid = didToMxid(did);

  // Drive the account passkey re-auth via the server-rendered page button. The
  // brand-new identity must be rejected at finish.
  const finishP = page.waitForResponse((r) => r.url().includes('/account/passkey/finish'));
  await page.click('#btn-passkey');
  const resp = await finishP;

  expect(resp.status()).toBe(400);
  const text = await resp.text();
  // NEW_IDENTITY_REJECT_MSG (webauthn.rs): "...not linked to an existing account..."
  expect(text).toMatch(/not linked to an existing account/i);
  expect(text).toMatch(/Create an account at sign-in/i);

  // The page surfaces the reject; nothing provisioned.
  const s = await mockState();
  expect(s.existing_users).not.toContain(didToLocalpart(did));
  expect(s.devices[mxid] || []).toEqual([]);
  expect(s.calls.some((c) => c.includes('provision_user'))).toBe(false);
  expect(s.calls.some((c) => c.includes('upsert_device'))).toBe(false);
});

// ---------------------------------------------------------------------------
// 6: QR/DEVICE REJECT. A brand-new passkey on /device/passkey/finish is rejected;
// nothing provisioned and the device code is NOT approved.
// ---------------------------------------------------------------------------
test('H5: brand-new passkey on /device/passkey/finish -> 400 reject, device not approved', async ({ page }) => {
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'dev-reject-reg', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const mxid = didToMxid(did);

  // Mint a real device code (RFC 8628) so /device/passkey/{start,finish} have a
  // pending user_code to approve. device_authorization requires a REGISTERED
  // client, so dynamic-register one first.
  const userCode = await page.evaluate(async () => {
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
    const r = await fetch('/device_authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'client_id=' + encodeURIComponent(client_id),
    });
    if (!r.ok) throw new Error('device_authorization ' + r.status + ' ' + (await r.text()));
    return (await r.json()).user_code;
  });
  expect(userCode).toBeTruthy();

  // Run the device passkey ceremony: start (challenge for device_passkey_{code})
  // -> get -> finish. The brand-new identity must be rejected at finish.
  const result = await page.evaluate(async (uc) => {
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
    const sr = await fetch('/device/passkey/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user_code: uc }),
    });
    if (!sr.ok) throw new Error('device start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const r = cred.response;
    const fr = await fetch('/device/passkey/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        user_code: uc,
        id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
        response: {
          authenticatorData: bufToB64u(r.authenticatorData),
          clientDataJSON: bufToB64u(r.clientDataJSON),
          signature: bufToB64u(r.signature),
          userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
        },
      }),
    });
    return { status: fr.status, body: await fr.text() };
  }, userCode);

  expect(result.status).toBe(400);
  expect(result.body).toMatch(/not linked to an existing account/i);

  // Nothing provisioned/approved.
  const s = await mockState();
  expect(s.existing_users).not.toContain(didToLocalpart(did));
  expect(s.devices[mxid] || []).toEqual([]);
  expect(s.calls.some((c) => c.includes('provision_user'))).toBe(false);
});

// ---------------------------------------------------------------------------
// 7: FALSE-POSITIVE GONE. A device approval for an EXISTING user must NOT carry
// the old "no Secure Backup" warning. With the EXISTING user the new-identity
// reject does NOT fire, so approval succeeds and data.warning is absent/null.
// (Driven via the wallet path: it reaches the same warning seam as passkey and
// does not require a registered resident key for a pre-existing wallet DID.)
// ---------------------------------------------------------------------------
test('H9: device approval for an EXISTING user has no Secure-Backup warning', async ({ page }) => {
  await mockReset();
  // An EXISTING wallet account: mark its localpart taken so the new-identity gate
  // does NOT reject (this is a returning user linking a new device via QR).
  const w = makeWallet();
  await mockSeedUser(didToLocalpart(w.did));
  await mockSeedDevice(w.mxid, 'SIWX_existing'); // and it already has a device

  // Real EIP-191 signing via the mock EIP-1193 wallet + a CAIP-122 signer hook,
  // exactly as the device-lifecycle wallet path does.
  await injectMockWallet(page, w);
  await page.exposeFunction('__caipSign', (msg) => w.wallet.signMessage(msg));
  await page.goto('/account'); // any same-origin page so the fetch is same-origin

  // Mint a device code, fetch the approval nonce, build + sign the CAIP-122
  // message (byte-format copied from the device approval page JS), and approve.
  const result = await page.evaluate(async ({ did, address, origin }) => {
    const reg = await fetch('/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [origin + '/callback'],
        grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
        response_types: ['code'],
      }),
    });
    if (!reg.ok) throw new Error('register ' + reg.status + ' ' + (await reg.text()));
    const { client_id } = await reg.json();
    const da = await fetch('/device_authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'client_id=' + encodeURIComponent(client_id),
    });
    if (!da.ok) throw new Error('device_authorization ' + da.status + ' ' + (await da.text()));
    const { user_code } = await da.json();

    const nr = await fetch('/device/nonce?user_code=' + encodeURIComponent(user_code));
    if (!nr.ok) throw new Error('nonce ' + nr.status + ' ' + (await nr.text()));
    const np = await nr.json();

    const domain = new URL(origin).hostname; // matches device_page's `domain`
    let message = domain + ' wants you to sign in with your Ethereum account:\n' +
      address + '\n\nApprove device login.\n\nURI: ' + origin + '\nVersion: 1\nChain ID: 1\n' +
      'Nonce: ' + np.nonce + '\nIssued At: ' + new Date().toISOString() +
      '\nExpiration Time: ' + np.expiration_time;
    if (np.resources && np.resources.length) {
      message += '\nResources:';
      for (const r of np.resources) message += '\n- ' + r;
    }
    const signature = await window.__caipSign(message);

    const ar = await fetch('/device', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user_code, action: 'approve', did, message, signature }),
    });
    return { status: ar.status, body: ar.ok ? await ar.json() : await ar.text() };
  }, { did: w.did, address: w.address, origin: BASE });

  // The approval succeeded (existing user -> not rejected) ...
  expect(result.status).toBe(200);
  expect(result.body.status).toBe('approved');
  // ... and carries NO Secure-Backup warning (false positive removed 2026-06-18).
  // The field is `#[serde(skip_serializing_if = "Option::is_none")]`, so absent.
  expect(result.body.warning == null).toBe(true);
});
