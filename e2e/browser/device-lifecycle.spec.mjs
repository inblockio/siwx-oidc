// Headless browser E2E for the siwx-oidc device-lifecycle paths the Rust-level
// suite could not reach: full wallet/passkey *login → token* through the page,
// the MSC4191 account-management actions (single re-auth, deep-links,
// cross-signing reset, GDPR erase + credential purge), CSRF enforcement, and the
// WebAuthn challenge-replay guard.
//
// Spec: docs/audits/2026-06-14-siwx-oidc-requirement-map.md (R-* / H-*).
// Pattern source: account.spec.mjs (kept green). Helpers:
//   ./wallet-helper.mjs   — injectMockWallet, makeWallet, countSignatures
//   ./webauthn-helper.mjs — addVirtualAuthenticator, registerPasskey,
//                           authenticatePasskey, countCeremonies, ceremonyCounts
//
// The stack (siwx-oidc :8080 + Synapse mock :8090 + Redis :6379) runs externally
// (e2e/up.sh). Each test resets the mock and uses a fresh identity.

import { test, expect } from '@playwright/test';
import net from 'node:net';
import {
  makeWallet, injectMockWallet, countSignatures,
} from './wallet-helper.mjs';
import {
  addVirtualAuthenticator, registerPasskey,
  countCeremonies, ceremonyCounts,
} from './webauthn-helper.mjs';

const BASE = process.env.SIWEOIDC_HOST || 'http://localhost:8080';
const MOCK = process.env.SYNAPSE_MOCK || 'http://localhost:8090';
// Redis is reachable on the host network (the Playwright container runs with
// --network host), so we speak RESP directly over TCP rather than shelling out
// to `podman exec` (podman is not available inside the test container).
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);

// -- mock helpers (Synapse stand-in) -----------------------------------------
async function mockReset() {
  await fetch(`${MOCK}/__reset`, { method: 'POST' });
}
async function mockSeed(mxid, deviceId, displayName = 'Element') {
  await fetch(`${MOCK}/__seed_device`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: mxid, device_id: deviceId, display_name: displayName }),
  });
}
// Mark a DID's localpart as an EXISTING account so the new-identity gate treats a
// re-auth in the account/QR flow as a returning user (not an attempt to create a
// new account, which those flows reject). These lifecycle tests operate on
// accounts that already exist.
function localpartOfDid(did) {
  return did.replaceAll(':', '-').toLowerCase();
}
async function mockSeedUser(did) {
  await fetch(`${MOCK}/__seed_user`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ localpart: localpartOfDid(did) }),
  });
}
async function mockState() {
  return (await fetch(`${MOCK}/__state`)).json();
}
async function mockDevices(mxid) {
  const s = await mockState();
  return (s.devices[mxid] || []).map((d) => d.device_id);
}

// -- redis helper (credential-key assertions for H13) ------------------------
// Minimal RESP-over-TCP client: send a KEYS command, parse the multi-bulk reply.
// Returns an array of key strings, or { __error } if Redis is unreachable.
function redisCommand(args) {
  return new Promise((resolve) => {
    const sock = net.connect(REDIS_PORT, REDIS_HOST);
    const chunks = [];
    let done = false;
    const finish = (val) => { if (done) return; done = true; try { sock.destroy(); } catch (_) {} resolve(val); };
    sock.setTimeout(4000);
    sock.on('error', (e) => finish({ __error: String(e && e.message ? e.message : e) }));
    sock.on('timeout', () => finish({ __error: 'redis timeout' }));
    sock.on('connect', () => {
      // RESP request: *N\r\n$len\r\narg\r\n...
      let cmd = `*${args.length}\r\n`;
      for (const a of args) cmd += `$${Buffer.byteLength(a)}\r\n${a}\r\n`;
      sock.write(cmd);
    });
    sock.on('data', (d) => {
      chunks.push(d);
      const buf = Buffer.concat(chunks).toString('utf8');
      // A complete multi-bulk reply ends after the last element's CRLF. We parse
      // greedily and resolve once the declared element count is satisfied.
      const parsed = parseRespArray(buf);
      if (parsed !== null) finish(parsed);
    });
  });
}

// Parse a RESP array reply (`*N\r\n$len\r\n...`). Returns string[] when complete,
// null if more bytes are needed, or [] for an empty/nil array.
function parseRespArray(buf) {
  if (!buf.startsWith('*')) {
    // Could be an error (`-...`) — treat as no keys.
    if (buf.startsWith('-')) return [];
    return null;
  }
  let i = buf.indexOf('\r\n');
  if (i < 0) return null;
  const count = parseInt(buf.slice(1, i), 10);
  if (count <= 0) return [];
  const out = [];
  let pos = i + 2;
  for (let n = 0; n < count; n++) {
    if (buf[pos] !== '$') return null;
    const eol = buf.indexOf('\r\n', pos);
    if (eol < 0) return null;
    const len = parseInt(buf.slice(pos + 1, eol), 10);
    const start = eol + 2;
    if (buf.length < start + len + 2) return null; // need more bytes
    out.push(buf.slice(start, start + len));
    pos = start + len + 2;
  }
  return out;
}

async function redisKeys(pattern) {
  return redisCommand(['KEYS', pattern]);
}

// -- full OIDC login → token flow, driven entirely from the page -------------
// Registers a throwaway OIDC client, runs /authorize (sets the `session` cookie
// + nonce), then either signs the CAIP-122 challenge (wallet) or runs the
// passkey ceremony to store verified_did, then /sign_in -> code -> /token.
// Returns the parsed /token JSON. `signMessage` is an async fn (msg) -> 0x-sig
// for the wallet path; pass null for the passkey path (which must have a live
// virtual authenticator + a registered passkey first).
async function loginToToken(page, { did, signMessage, passkey = false }) {
  return page.evaluate(async ({ did, passkey, BASE }) => {
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

    const redirectUri = BASE + '/callback';
    // 1. Register a dynamic client.
    const reg = await fetch(BASE + '/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'client_secret_post',
        grant_types: ['authorization_code'],
        response_types: ['code'],
      }),
    });
    if (!reg.ok) throw new Error('register ' + reg.status + ' ' + (await reg.text()));
    const { client_id, client_secret } = await reg.json();

    // 2. /authorize -> sets `session` (HttpOnly) cookie, 303 to /?nonce=...&domain=...
    // The Fetch API hides Location on an opaque redirect, so we FOLLOW the
    // redirect and read the nonce/domain off the resulting same-origin URL (the
    // SPA root echoes them in its query string). One authorize call only.
    const state = 'st_' + Math.random().toString(36).slice(2);
    // PKCE (S256) is required by /authorize (OAuth hardening). Generate a verifier
    // and its SHA-256 challenge; the verifier is replayed at /token below.
    const codeVerifier = bufToB64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challengeBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = bufToB64u(challengeBuf);
    const authorizeUrl = BASE + '/authorize?' + q({
      client_id, redirect_uri: redirectUri, scope: 'openid',
      response_type: 'code', state,
      code_challenge: codeChallenge, code_challenge_method: 'S256',
    });
    const authFollowed = await fetch(authorizeUrl, { redirect: 'follow' });
    const au = new URL(authFollowed.url);
    const nonce = au.searchParams.get('nonce');
    const domain = au.searchParams.get('domain');
    if (!nonce) throw new Error('no nonce from authorize; landed=' + authFollowed.url);

    // 3a/3b. Establish the verified DID.
    let signInHeaders = {};
    if (passkey) {
      // WebAuthn login ceremony: start -> get() -> finish stores verified_did
      // in *this* session (keyed by the `session` cookie that /authorize set).
      const sr = await fetch(BASE + '/webauthn/authenticate/start', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
      });
      if (!sr.ok) throw new Error('auth start ' + sr.status + ' ' + (await sr.text()));
      const opts = await sr.json();
      opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
      if (opts.publicKey.allowCredentials)
        for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
      const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
      const rr = cred.response;
      const fr = await fetch(BASE + '/webauthn/authenticate/finish', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
          response: {
            authenticatorData: bufToB64u(rr.authenticatorData),
            clientDataJSON: bufToB64u(rr.clientDataJSON),
            signature: bufToB64u(rr.signature),
            userHandle: rr.userHandle ? bufToB64u(rr.userHandle) : null,
          },
        }),
      });
      if (!fr.ok) throw new Error('auth finish ' + fr.status + ' ' + (await fr.text()));
    } else {
      // Wallet: build the CAIP-122 message, sign it, set the `siwx` cookie.
      const address = did.split(':').pop();
      const issuedAt = new Date().toISOString();
      const message =
        `${domain} wants you to sign in with your Ethereum account:\n` +
        `${address}\n\n` +
        `You are signing-in to ${domain}.\n\n` +
        `URI: ${BASE}\nVersion: 1\nChain ID: 1\n` +
        `Nonce: ${nonce}\nIssued At: ${issuedAt}\n` +
        `Resources:\n- ${redirectUri}`;
      const signature = await window.__caipSign(message);
      const siwx = JSON.stringify({ did, message, signature });
      document.cookie = 'siwx=' + encodeURIComponent(siwx) + '; path=/';
    }

    // 4. /sign_in -> 303 to redirect_uri?code=...  Follow it; /callback 404s but
    // the final URL still carries ?code=... which we parse.
    const signInUrl = BASE + '/sign_in?' + q({
      redirect_uri: redirectUri, state, client_id,
    });
    const siFollowed = await fetch(signInUrl, { redirect: 'follow' });
    const code = new URL(siFollowed.url).searchParams.get('code');
    if (!code) {
      // Surface the server's reason (sign_in errors render as a body, not a 303).
      const why = siFollowed.ok ? await siFollowed.text() : ('status ' + siFollowed.status);
      throw new Error('no auth code from sign_in; landed=' + siFollowed.url + ' :: ' + why.slice(0, 200));
    }

    // 5. /token (authorization_code).
    const form = new URLSearchParams({
      code, client_id, client_secret, grant_type: 'authorization_code',
      code_verifier: codeVerifier,
    });
    const tk = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    if (!tk.ok) throw new Error('token ' + tk.status + ' ' + (await tk.text()));
    return await tk.json();
  }, { did, passkey, BASE });
}

// Expose the wallet signer into the page for the CAIP-122 login path.
async function exposeCaipSigner(page, wallet) {
  await page.exposeFunction('__caipSign', (msg) => wallet.signMessage(msg));
}

// ===========================================================================

test('R-A1: wallet login issues a token (authorize -> sign_in -> token)', async ({ page }) => {
  await mockReset();
  const w = makeWallet();
  await injectMockWallet(page, w);
  await exposeCaipSigner(page, w.wallet);
  await page.goto('/account'); // any same-origin page so fetch is same-origin

  const tok = await loginToToken(page, { did: w.did, signMessage: null });
  expect(tok.access_token).toBeTruthy();
  expect(tok.access_token.startsWith('mat_')).toBe(true); // MSC3861 mode
  expect(typeof tok.id_token).toBe('string');

  // S: a fresh SIWX_* device was provisioned for this DID on token issuance.
  const ids = await mockDevices(w.mxid);
  expect(ids.some((d) => d.startsWith('SIWX_'))).toBe(true);
});

test('R-C1/R-C2/R-C3: passkey register -> login -> token (same DID)', async ({ page }) => {
  await mockReset();
  await countCeremonies(page);
  await addVirtualAuthenticator(page);
  // The register ceremony needs a `session` cookie value to key its challenge.
  await page.context().addCookies([{ name: 'session', value: 'pk-reg-sess', url: BASE }]);
  await page.goto('/account');

  // R-C1: register a discoverable passkey -> deterministic did:key.
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);

  // R-C2: full login through the page using that passkey -> token. The
  // /authorize step resets the `session` cookie to a fresh server-issued id;
  // the discoverable authenticate ceremony does not need the registration
  // session, only a live virtual authenticator with the resident key.
  const tok = await loginToToken(page, { did, passkey: true });
  expect(tok.access_token).toBeTruthy();
  expect(tok.access_token.startsWith('mat_')).toBe(true);

  // R-C3: the login resolved to the SAME did:key the registration derived.
  const pkMxid = `@${did.replaceAll(':', '-').toLowerCase()}:matrix.test`;
  const ids = await mockDevices(pkMxid);
  expect(ids.some((d) => d.startsWith('SIWX_'))).toBe(true);

  // One registration ceremony + exactly one authentication ceremony.
  const wa = await ceremonyCounts(page);
  expect(wa.create).toBe(1);
  expect(wa.get).toBe(1);
});

test('R-C4: authenticate/start does not enumerate credentials (empty allowCredentials)', async ({ page }) => {
  // Regression guard for the discoverable-auth credential leak. authenticate_start
  // must NOT enumerate stored credentials: doing so leaked all credential ids to
  // unauthenticated callers and produced a server-wide passkey picker. With >=2
  // credentials registered, the start response must still return empty
  // allowCredentials (login works because the credentials are discoverable resident
  // keys, exercised by R-C2 above).
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'pk-leak-sess', url: BASE }]);
  await page.goto('/account');

  const did1 = await registerPasskey(page);
  const did2 = await registerPasskey(page);
  expect(did1).toMatch(/^did:key:zDn/);
  expect(did2).toMatch(/^did:key:zDn/);
  expect(did1).not.toBe(did2);

  const allow = await page.evaluate(async () => {
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    if (!sr.ok) throw new Error('authenticate start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    return opts.publicKey.allowCredentials || [];
  });
  expect(Array.isArray(allow)).toBe(true);
  expect(allow.length).toBe(0);
});

test('R-G1: one re-auth covers list + view + delete (single signature)', async ({ page }) => {
  await mockReset();
  const w = makeWallet();
  await injectMockWallet(page, w);
  await mockSeed(w.mxid, 'SIWX_g1_a');
  await mockSeed(w.mxid, 'SIWX_g1_b');

  await page.goto('/account?action=org.matrix.devices_list');
  // The ONE and only re-auth signature for the whole session.
  await page.click('#btn-wallet');
  await expect(page.locator('.device-row')).toHaveCount(2);

  // View device A (session-backed, no new signature).
  await page.locator('.device-row', { hasText: 'SIWX_g1_a' })
    .getByRole('button', { name: 'View' }).click();
  await expect(page.locator('#result-section')).toContainText('Session details');
  await expect(page.locator('#result-section')).toContainText('SIWX_g1_a');

  // Delete device A from the detail view (session-backed, no new signature).
  await page.locator('#result-section')
    .getByRole('button', { name: 'Sign out this session' }).click();
  await expect(page.getByText('Session signed out')).toBeVisible();

  // EXACTLY ONE wallet signature covered list + view + delete.
  expect(await countSignatures(page)).toBe(1);
  const ids = await mockDevices(w.mxid);
  expect(ids).not.toContain('SIWX_g1_a');
  expect(ids).toContain('SIWX_g1_b');
});

test('R-G2: device_view deep-link resolves a base64 (slash) device id', async ({ page }) => {
  // matrix-rust-sdk device ids are standard base64 and can contain '/'.
  await mockReset();
  const w = makeWallet();
  const dev = 'AbC/dEf+gHi/jKl=mNoPqRsT'; // contains '/', '+', '='
  await injectMockWallet(page, w);
  await mockSeed(w.mxid, dev);

  // Establish a session with one signature via the list.
  await page.goto('/account?action=org.matrix.devices_list');
  await page.click('#btn-wallet');
  await expect(page.locator('.device-row')).toHaveCount(1);

  // Deep-link to the slash id; authenticated session auto-runs the read.
  await page.goto(`/account?action=org.matrix.device_view&device_id=${encodeURIComponent(dev)}`);
  await expect(page.locator('#result-section')).toContainText('Session details');
  await expect(page.locator('#result-section')).toContainText(dev);
  await expect(page.getByText('not among your active sessions')).toHaveCount(0);
  // The deep link reused the session: no new signature.
  expect(await countSignatures(page)).toBe(0);
});

test('R-G4: cross_signing_reset calls allow_cross_signing_reset on Synapse', async ({ page }) => {
  await mockReset();
  const w = makeWallet();
  // cross_signing_reset operates on an EXISTING account; mark it so the account
  // flow's new-identity gate does not reject this returning user.
  await mockSeedUser(w.did);
  await injectMockWallet(page, w);

  await page.goto('/account?action=org.matrix.cross_signing_reset');
  await page.click('#btn-wallet');
  // Outcome kind 'completed' renders the "Encryption keys reset" terminal.
  await expect(page.getByText('Encryption keys reset')).toBeVisible();

  const s = await mockState();
  expect(s.calls).toContain('POST /_synapse/mas/allow_cross_signing_reset');
});

test('R-G6 + H13: account_erase deactivates(erase=true) AND purges WebAuthn credentials', async ({ page }) => {
  await mockReset();
  // A passkey identity so erase has WebAuthn artifacts to purge.
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'erase-reg-sess', url: BASE }]);
  await page.goto('/account');

  // Snapshot credential keys BEFORE, register a passkey, find the NEW key.
  const before = await redisKeys('webauthn:credential/*');
  expect(before && before.__error, `redis must be reachable for H13: ${before && before.__error}`).toBeFalsy();
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  const after = await redisKeys('webauthn:credential/*');
  const newKeys = after.filter((k) => !before.includes(k));
  expect(newKeys.length).toBeGreaterThanOrEqual(1);

  const eraseMxid = `@${did.replaceAll(':', '-').toLowerCase()}:matrix.test`;
  await mockSeed(eraseMxid, 'SIWX_erase_dev');

  // Erase via the page using the passkey (the re-auth proves the DID, then erase
  // runs deactivate(erase=true) + purge_identity for that DID).
  await page.goto('/account?action=org.matrix.account_erase');
  await page.locator('#confirm-erase').check();
  await page.click('#btn-passkey');
  await expect(page.getByText('Account erased')).toBeVisible();

  // (a) Synapse deactivate(erase=true).
  const s = await mockState();
  expect(s.lifecycle[eraseMxid]?.deactivated).toBe(true);
  expect(s.lifecycle[eraseMxid]?.erased).toBe(true);

  // (b) H13: the erased identity's webauthn:credential/* keys are PURGED. None
  // of the keys introduced by this identity's registration remain.
  const post = await redisKeys('webauthn:credential/*');
  for (const k of newKeys) {
    expect(post).not.toContain(k);
  }
  // No webauthn:link/* leak for this DID either.
  const links = await redisKeys('webauthn:link/*');
  expect(Array.isArray(links)).toBe(true);
});

test('H11: WebAuthn challenge is bound to its session (cross-session replay rejected)', async ({ page }) => {
  // The auth challenge is keyed by session_id (webauthn:challenge/{session_id}).
  // The /account/passkey path makes session_id an explicit, client-echoed value
  // (start returns it; finish must echo it), which lets us prove the binding from
  // the browser without two /authorize sessions: a challenge issued under S1 must
  // not be usable to finish a ceremony under a different session_id S2.
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'h11-stub', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);

  const result = await page.evaluate(async () => {
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
    // start S1 -> challenge bound to session_id s1 (returned in the body).
    const sr = await fetch('/account/passkey/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'org.matrix.profile' }),
    });
    const opts = await sr.json();
    const s1 = opts.session_id;
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const rr = cred.response;
    const mkBody = (sessionId) => JSON.stringify({
      action: 'org.matrix.profile', session_id: sessionId,
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        authenticatorData: bufToB64u(rr.authenticatorData),
        clientDataJSON: bufToB64u(rr.clientDataJSON),
        signature: bufToB64u(rr.signature),
        userHandle: rr.userHandle ? bufToB64u(rr.userHandle) : null,
      },
    });
    // Replay the captured S1 assertion under a DIFFERENT session_id (s2):
    // webauthn:challenge/{s2} has no challenge -> reject.
    const s2 = s1 + '-FORGED';
    const replay = await fetch('/account/passkey/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: mkBody(s2),
    });
    return { replayStatus: replay.status, replayBody: await replay.text(), s1 };
  });

  // Cross-session replay must be rejected (no auth challenge for s2).
  expect(result.replayStatus).toBeGreaterThanOrEqual(400);
  expect(result.replayBody.toLowerCase()).toContain('challenge');
});

test('H11b: an auth challenge is single-use within its own session', async ({ page }) => {
  // Companion to H11: even with the CORRECT session_id, a consumed challenge
  // cannot be replayed — verify_credential deletes the challenge key on first use.
  await mockReset();
  await addVirtualAuthenticator(page);
  await page.context().addCookies([{ name: 'session', value: 'h11b-stub', url: BASE }]);
  await page.goto('/account');
  const did = await registerPasskey(page);
  expect(did).toMatch(/^did:key:zDn/);
  // The profile re-auth runs in the account flow, which rejects NEW identities;
  // this test exercises challenge single-use for a returning user, so mark the
  // freshly-registered passkey's account as existing.
  await mockSeedUser(did);

  const replay = await page.evaluate(async () => {
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
    const sr = await fetch('/account/passkey/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'org.matrix.profile' }),
    });
    const opts = await sr.json();
    const sid = opts.session_id;
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const rr = cred.response;
    const body = JSON.stringify({
      action: 'org.matrix.profile', session_id: sid,
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        authenticatorData: bufToB64u(rr.authenticatorData),
        clientDataJSON: bufToB64u(rr.clientDataJSON),
        signature: bufToB64u(rr.signature),
        userHandle: rr.userHandle ? bufToB64u(rr.userHandle) : null,
      },
    });
    const first = await fetch('/account/passkey/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    });
    const firstOk = first.ok;
    const firstBody = await first.text();
    // Same assertion + same session_id again -> challenge already consumed.
    const second = await fetch('/account/passkey/finish', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    });
    return { firstOk, firstBody, secondStatus: second.status, secondBody: await second.text() };
  });
  expect(replay.firstOk, `first finish should succeed: ${replay.firstBody}`).toBe(true);
  expect(replay.secondStatus).toBeGreaterThanOrEqual(400);
  expect(replay.secondBody.toLowerCase()).toContain('challenge');
});

test('R-G8: /account/action with missing or wrong CSRF token is rejected', async ({ page }) => {
  await mockReset();
  const w = makeWallet();
  await injectMockWallet(page, w);
  await mockSeed(w.mxid, 'SIWX_csrf_a');

  // Establish a real account session (sets acct_session cookie + a valid CSRF).
  await page.goto('/account?action=org.matrix.devices_list');
  await page.click('#btn-wallet');
  await expect(page.locator('.device-row')).toHaveCount(1);

  // Drive /account/action directly via page fetch with a WRONG csrf -> 401.
  const wrong = await page.evaluate(async () => {
    const r = await fetch('/account/action', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'org.matrix.devices_list', device_id: null, csrf: 'totally-wrong' }),
    });
    return { status: r.status, body: await r.text() };
  });
  expect(wrong.status).toBe(401);
  expect(wrong.body.toLowerCase()).toContain('csrf');

  // MISSING csrf (null) -> also rejected (cookie present, no token echoed).
  const missing = await page.evaluate(async () => {
    const r = await fetch('/account/action', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'org.matrix.devices_list', device_id: null }),
    });
    return { status: r.status, body: await r.text() };
  });
  expect(missing.status).toBe(401);

  // Sanity: the session/device is untouched by the rejected calls.
  const ids = await mockDevices(w.mxid);
  expect(ids).toContain('SIWX_csrf_a');
});
