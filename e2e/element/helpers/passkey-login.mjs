/**
 * Headless passkey (WebAuthn) OIDC login against live siwx-oidc (MSC3861).
 *
 * Mirrors helpers/oidc-login.mjs `loginWalletToTokens`, but the auth ceremony is
 * a WebAuthn assertion (CDP virtual authenticator) instead of CAIP-122:
 *
 *   DCR → /authorize (session cookie) → [/webauthn/register] →
 *   /webauthn/authenticate/{start,finish} → /sign_in → /token → whoami
 *
 * The authenticate/start response is captured so specs can assert the
 * returning-user picker scoping contract (`detected_mxid`, allowCredentials)
 * and the new-user gate reported by authenticate/finish (`new_user`, `mxid`).
 *
 * The caller owns the virtual authenticator (addVirtualAuthenticator from
 * ../../browser/webauthn-helper.mjs) so multi-device specs can export/import
 * credentials between browser contexts via the CDP client it returns.
 */

import { registerPasskeyInPage } from '../../browser/webauthn-helper.mjs';

/**
 * Element-style DCR + PKCE + /authorize on the siwx origin. Establishes the
 * HttpOnly `session` cookie that keys the WebAuthn challenge and later
 * /sign_in. Page must already be able to navigate; this goes to the siwx
 * origin itself so all subsequent fetches are same-origin.
 *
 * @returns {Promise<{ client_id, codeVerifier, codeChallenge, state, redirectUri }>}
 */
export async function startOidcOnSiwx(page, { siwxUrl, clientName = 'ew-p-passkey-login' }) {
  const SIWX = siwxUrl.replace(/\/$/, '');
  await page.goto(`${SIWX}/.well-known/openid-configuration`, {
    waitUntil: 'domcontentloaded',
  });
  return page.evaluate(
    async ({ SIWX, clientName }) => {
      const enc = encodeURIComponent;
      const q = (o) =>
        Object.entries(o)
          .filter(([, v]) => v != null && v !== '')
          .map(([k, v]) => `${enc(k)}=${enc(v)}`)
          .join('&');
      const bufToB64u = (buf) => {
        const by = new Uint8Array(buf);
        let s = '';
        by.forEach((x) => (s += String.fromCharCode(x)));
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      };

      const redirectUri = SIWX + '/callback';
      const reg = await fetch(SIWX + '/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: clientName,
          redirect_uris: [redirectUri],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
        }),
      });
      if (!reg.ok) {
        throw new Error('register ' + reg.status + ' ' + (await reg.text()).slice(0, 300));
      }
      const { client_id } = await reg.json();

      const codeVerifier = bufToB64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
      const challengeBuf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(codeVerifier),
      );
      const codeChallenge = bufToB64u(challengeBuf);
      const state = 'ewp_' + Math.random().toString(36).slice(2);

      const authorizeUrl =
        SIWX +
        '/authorize?' +
        q({
          client_id,
          redirect_uri: redirectUri,
          scope: 'openid urn:matrix:client:api:*',
          response_type: 'code',
          state,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        });
      const authFollowed = await fetch(authorizeUrl, {
        redirect: 'follow',
        credentials: 'include',
      });
      if (!new URL(authFollowed.url).searchParams.get('nonce')) {
        throw new Error('no nonce from authorize; landed=' + authFollowed.url);
      }
      return { client_id, codeVerifier, codeChallenge, state, redirectUri };
    },
    { SIWX, clientName },
  );
}

/**
 * In-page WebAuthn AUTHENTICATION ceremony that ALSO captures the start
 * response, so callers can assert the picker-scoping contract. Same wire
 * behaviour as webauthn-helper.mjs::authenticatePasskeyInPage.
 *
 * @returns {{ start: { detected_mxid: string|null, allow_count: number }, finish: object }}
 */
export function authenticatePasskeyCapturingStart() {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(b);
    const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  const bufToB64u = (buf) => {
    const by = new Uint8Array(buf);
    let s = '';
    by.forEach((x) => (s += String.fromCharCode(x)));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return (async () => {
    const sr = await fetch('/webauthn/authenticate/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    if (!sr.ok) throw new Error('authenticate start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    const start = {
      detected_mxid: opts.detected_mxid ?? null,
      allow_count: (opts.publicKey.allowCredentials || []).length,
    };
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials)
      for (const c of opts.publicKey.allowCredentials) c.id = b64uToBuf(c.id);
    const cred = await navigator.credentials.get({ publicKey: opts.publicKey });
    const r = cred.response;
    const fr = await fetch('/webauthn/authenticate/finish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
          authenticatorData: bufToB64u(r.authenticatorData),
          clientDataJSON: bufToB64u(r.clientDataJSON),
          signature: bufToB64u(r.signature),
          userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
        },
      }),
    });
    if (!fr.ok) throw new Error('authenticate finish ' + fr.status + ' ' + (await fr.text()));
    return { start, finish: await fr.json() };
  })();
}

/**
 * /sign_in (verified_did from the Redis session — no siwx cookie) → /token.
 * Mirrors the wallet helper's final leg; PKCE ctx comes from startOidcOnSiwx.
 */
export async function finishOidcToTokens(page, { siwxUrl, oidc }) {
  const SIWX = siwxUrl.replace(/\/$/, '');
  return page.evaluate(
    async ({ SIWX, oidc }) => {
      const enc = encodeURIComponent;
      const q = (o) =>
        Object.entries(o)
          .filter(([, v]) => v != null && v !== '')
          .map(([k, v]) => `${enc(k)}=${enc(v)}`)
          .join('&');

      const signInUrl =
        SIWX +
        '/sign_in?' +
        q({
          redirect_uri: oidc.redirectUri,
          state: oidc.state,
          client_id: oidc.client_id,
          code_challenge: oidc.codeChallenge,
          code_challenge_method: 'S256',
        });
      const siFollowed = await fetch(signInUrl, { redirect: 'follow', credentials: 'include' });
      const code = new URL(siFollowed.url).searchParams.get('code');
      if (!code) {
        const why = siFollowed.ok ? await siFollowed.text() : 'status ' + siFollowed.status;
        throw new Error(
          'no auth code from sign_in; landed=' + siFollowed.url + ' :: ' + why.slice(0, 300),
        );
      }

      const form = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: oidc.redirectUri,
        client_id: oidc.client_id,
        code_verifier: oidc.codeVerifier,
      });
      const tr = await fetch(SIWX + '/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
      if (!tr.ok) {
        throw new Error('token ' + tr.status + ' ' + (await tr.text()).slice(0, 300));
      }
      const body = await tr.json();
      return {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        id_token: body.id_token,
        scope: body.scope || '',
      };
    },
    { SIWX, oidc },
  );
}

/**
 * Full passkey OIDC login → Matrix whoami.
 *
 * @param {import('@playwright/test').Page} page  Must already have a virtual
 *   authenticator attached (addVirtualAuthenticator).
 * @param {object} opts
 * @param {string} opts.siwxUrl
 * @param {string} opts.matrixUrl
 * @param {boolean} [opts.register=false]  Register a fresh passkey before
 *   authenticating (first-time user).
 * @param {boolean} [opts.whoami=true]  As in loginWalletToTokens: skip whoami
 *   to keep Synapse's ~2min introspection cache cold.
 * @returns {Promise<{
 *   access_token, refresh_token, device_id, user_id, did, client_id, scope,
 *   registered_did: string|null,
 *   new_user: boolean|undefined, mxid: string|undefined,
 *   detected_mxid: string|null, allow_count: number,
 * }>}
 */
export async function loginPasskeyToTokens(
  page,
  { siwxUrl, matrixUrl, register = false, whoami = true },
) {
  if (!siwxUrl || !matrixUrl) {
    throw new Error('loginPasskeyToTokens requires { siwxUrl, matrixUrl }');
  }
  const MATRIX = matrixUrl.replace(/\/$/, '');

  const oidc = await startOidcOnSiwx(page, { siwxUrl });

  let registered_did = null;
  if (register) {
    registered_did = await page.evaluate(registerPasskeyInPage);
  }

  const { start, finish } = await page.evaluate(authenticatePasskeyCapturingStart);
  if (!finish?.did) {
    throw new Error('authenticate finish returned no did: ' + JSON.stringify(finish));
  }

  const tok = await finishOidcToTokens(page, { siwxUrl, oidc });
  if (!tok?.access_token) {
    throw new Error('loginPasskeyToTokens: missing access_token in token response');
  }
  if (!String(tok.access_token).startsWith('mat_')) {
    throw new Error(
      'loginPasskeyToTokens: expected MSC3861 mat_ access token, got ' +
        String(tok.access_token).slice(0, 12),
    );
  }

  const scopeDevice =
    String(tok.scope || '').match(/urn:matrix:client:device:([^\s]+)/)?.[1] || '';

  const base = {
    access_token: tok.access_token,
    refresh_token: tok.refresh_token || '',
    id_token: tok.id_token,
    client_id: oidc.client_id,
    scope: tok.scope || '',
    did: finish.did,
    registered_did,
    new_user: finish.new_user,
    mxid: finish.mxid,
    detected_mxid: start.detected_mxid,
    allow_count: start.allow_count,
  };

  if (!whoami) {
    return { ...base, device_id: scopeDevice, user_id: '' };
  }

  const who = await fetch(`${MATRIX}/_matrix/client/v3/account/whoami`, {
    headers: { Authorization: `Bearer ${tok.access_token}` },
  });
  if (!who.ok) {
    throw new Error('whoami ' + who.status + ' ' + (await who.text()).slice(0, 300));
  }
  const whoBody = await who.json();
  if (!whoBody.user_id || !whoBody.device_id) {
    throw new Error('whoami missing user_id/device_id: ' + JSON.stringify(whoBody));
  }
  return { ...base, device_id: whoBody.device_id, user_id: whoBody.user_id };
}

/**
 * Export the resident credentials from a CDP virtual authenticator, e.g. to
 * simulate a passkey synced to another device (iCloud/Google model).
 * @param {{ client: import('playwright').CDPSession, authenticatorId: string }} auth
 */
export async function exportPasskeys({ client, authenticatorId }) {
  const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
  return credentials;
}

/**
 * Import previously exported credentials into another page's virtual
 * authenticator. `rpId` is required by CDP addCredential; pass the siwx host.
 */
export async function importPasskeys({ client, authenticatorId }, credentials, rpId) {
  for (const c of credentials) {
    await client.send('WebAuthn.addCredential', {
      authenticatorId,
      credential: {
        credentialId: c.credentialId,
        isResidentCredential: c.isResidentCredential,
        rpId: c.rpId || rpId,
        privateKey: c.privateKey,
        userHandle: c.userHandle,
        signCount: c.signCount,
      },
    });
  }
}
