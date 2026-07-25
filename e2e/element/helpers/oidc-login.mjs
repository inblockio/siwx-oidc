/**
 * Headless OIDC wallet login against live siwx-oidc (MSC3861).
 *
 * Mirrors e2e/browser/device-lifecycle.spec.mjs `loginToToken` / R-A1, but:
 *  - targets the Element-lab stack (configurable SIWX + Matrix URLs)
 *  - requests Matrix scopes so Synapse provisions a device
 *  - returns whoami-backed { access_token, refresh_token, device_id, user_id }
 *
 * The flow is OP-contract (DCR → authorize → CAIP-122 → sign_in → token → whoami),
 * not full Element SPA SSO click-path. Same crypto path Element uses after
 * redirecting to siwx.
 */

import { injectMockWallet } from '../../browser/wallet-helper.mjs';

/**
 * Expose ethers personal_sign as `window.__caipSign` for page-context CAIP-122.
 * Safe to call once per Playwright page.
 */
export async function exposeCaipSigner(page, walletOrBundle) {
  const wallet = walletOrBundle?.wallet ?? walletOrBundle;
  await page.exposeFunction('__caipSign', (msg) => wallet.signMessage(msg));
}

/**
 * Full wallet OIDC login → Matrix whoami.
 *
 * @param {import('@playwright/test').Page} page
 * @param {object} opts
 * @param {string} opts.siwxUrl   e.g. http://localhost:28081
 * @param {string} opts.matrixUrl e.g. http://localhost:28080
 * @param {{ wallet: import('ethers').Wallet, did: string, address?: string }} opts.wallet
 * @param {boolean} [opts.whoami=true]  When false, skip Matrix whoami (avoids
 *   Synapse's 2‑minute introspection cache so a subsequent logout → whoami can
 *   hard-assert 401 immediately — see EW-S4).
 * @returns {Promise<{
 *   access_token: string,
 *   refresh_token: string,
 *   device_id: string,
 *   user_id: string,
 *   id_token?: string,
 *   client_id: string,
 *   did: string,
 *   scope?: string,
 * }>}
 */
export async function loginWalletToTokens(page, { siwxUrl, matrixUrl, wallet, whoami = true }) {
  if (!siwxUrl || !matrixUrl || !wallet?.did || !wallet?.wallet) {
    throw new Error('loginWalletToTokens requires { siwxUrl, matrixUrl, wallet: makeWallet() bundle }');
  }

  const SIWX = siwxUrl.replace(/\/$/, '');
  const MATRIX = matrixUrl.replace(/\/$/, '');
  const did = wallet.did;

  // Mock EIP-1193 + CAIP signer on this page; must be installed before navigation
  // so init scripts attach on the siwx origin.
  await injectMockWallet(page, wallet);
  await exposeCaipSigner(page, wallet);

  // Any same-origin siwx document so subsequent fetch() is same-origin and
  // carries the HttpOnly `session` cookie from /authorize.
  await page.goto(`${SIWX}/.well-known/openid-configuration`, {
    waitUntil: 'domcontentloaded',
  });

  const tok = await page.evaluate(async ({ SIWX, did }) => {
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

    // Element-style DCR: public client, auth method none, Matrix-capable grants.
    const redirectUri = SIWX + '/callback';
    const reg = await fetch(SIWX + '/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'ew-l1-oidc-login',
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

    // PKCE S256 (required by /authorize).
    const codeVerifier = bufToB64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challengeBuf = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(codeVerifier),
    );
    const codeChallenge = bufToB64u(challengeBuf);
    const state = 'ewl1_' + Math.random().toString(36).slice(2);

    // /authorize → 303 to /?nonce=...&domain=...&code_challenge=...
    // Follow redirect so we can read nonce/domain from the final same-origin URL
    // and so the browser stores the HttpOnly `session` cookie.
    const authorizeUrl =
      SIWX +
      '/authorize?' +
      q({
        client_id,
        redirect_uri: redirectUri,
        // openid + Matrix API scope so sign_in provisions a Synapse device
        scope: 'openid urn:matrix:client:api:*',
        response_type: 'code',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      });
    const authFollowed = await fetch(authorizeUrl, { redirect: 'follow', credentials: 'include' });
    const au = new URL(authFollowed.url);
    const nonce = au.searchParams.get('nonce');
    const domain = au.searchParams.get('domain');
    if (!nonce) {
      throw new Error('no nonce from authorize; landed=' + authFollowed.url);
    }
    if (!domain) {
      throw new Error('no domain from authorize; landed=' + authFollowed.url);
    }

    // CAIP-122 message (wallet path). Resources MUST bind redirect_uri.
    // Expiration Time optional on login path (enforce-if-present).
    const address = did.split(':').pop();
    const issuedAt = new Date().toISOString();
    const message =
      `${domain} wants you to sign in with your Ethereum account:\n` +
      `${address}\n\n` +
      `You are signing-in to ${domain}.\n\n` +
      `URI: ${SIWX}\nVersion: 1\nChain ID: 1\n` +
      `Nonce: ${nonce}\nIssued At: ${issuedAt}\n` +
      `Resources:\n- ${redirectUri}`;

    if (typeof window.__caipSign !== 'function') {
      throw new Error('window.__caipSign not exposed — call exposeCaipSigner first');
    }
    const signature = await window.__caipSign(message);
    const siwx = JSON.stringify({ did, message, signature });
    document.cookie = 'siwx=' + encodeURIComponent(siwx) + '; path=/; SameSite=Strict';

    // /sign_in → 303 to redirect_uri?code=...  Pass PKCE through like App.svelte.
    // Follow; /callback 404s but final URL still carries ?code=.
    const signInUrl =
      SIWX +
      '/sign_in?' +
      q({
        redirect_uri: redirectUri,
        state,
        client_id,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      });
    const siFollowed = await fetch(signInUrl, { redirect: 'follow', credentials: 'include' });
    const code = new URL(siFollowed.url).searchParams.get('code');
    if (!code) {
      const why = siFollowed.ok
        ? await siFollowed.text()
        : 'status ' + siFollowed.status;
      throw new Error(
        'no auth code from sign_in; landed=' + siFollowed.url + ' :: ' + why.slice(0, 300),
      );
    }

    // /token (authorization_code + PKCE verifier). Public client: no secret.
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id,
      code_verifier: codeVerifier,
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
      client_id,
      did,
    };
  }, { SIWX, did });

  if (!tok?.access_token) {
    throw new Error('loginWalletToTokens: missing access_token in token response');
  }
  if (!String(tok.access_token).startsWith('mat_')) {
    throw new Error(
      'loginWalletToTokens: expected MSC3861 mat_ access token, got ' +
        String(tok.access_token).slice(0, 12),
    );
  }

  // device_id often appears in the issued scope (urn:matrix:client:device:ID).
  const scopeDevice =
    String(tok.scope || '').match(/urn:matrix:client:device:([^\s]+)/)?.[1] || '';

  if (!whoami) {
    return {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token || '',
      device_id: scopeDevice,
      user_id: '',
      id_token: tok.id_token,
      client_id: tok.client_id,
      did: tok.did,
      scope: tok.scope || '',
    };
  }

  // whoami on the Matrix edge (Caddy → introspect → Synapse).
  // NOTE: a successful whoami warms Synapse's 2‑minute introspection cache, so
  // a later logout will not flip whoami to 401 until the cache entry expires.
  // Use whoami:false when the next step is logout → whoami 401 (EW-S4).
  const who = await fetch(`${MATRIX}/_matrix/client/v3/account/whoami`, {
    headers: { Authorization: `Bearer ${tok.access_token}` },
  });
  if (!who.ok) {
    throw new Error(
      'whoami ' + who.status + ' ' + (await who.text()).slice(0, 300),
    );
  }
  const whoBody = await who.json();
  if (!whoBody.user_id || !whoBody.device_id) {
    throw new Error('whoami missing user_id/device_id: ' + JSON.stringify(whoBody));
  }

  return {
    access_token: tok.access_token,
    refresh_token: tok.refresh_token || '',
    device_id: whoBody.device_id,
    user_id: whoBody.user_id,
    id_token: tok.id_token,
    client_id: tok.client_id,
    did: tok.did,
    scope: tok.scope || '',
  };
}
