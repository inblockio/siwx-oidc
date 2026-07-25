/**
 * RFC 8628 device-authorization helpers for EW-D1 Element lab specs.
 *
 * Mirrors tests/e2e_device_code.rs: DCR → device_authorization → wallet approve
 * via CAIP-122 (GET /device/nonce) → poll device_code grant → Matrix whoami.
 */

import { SIWX_URL, MATRIX_URL } from './element.mjs';

/**
 * Register a public OIDC client that can use the device_code grant.
 */
export async function registerDeviceClient(siwxUrl = SIWX_URL) {
  const base = siwxUrl.replace(/\/$/, '');
  const r = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'ew-d1-device-link',
      // device_code grant does not use redirect_uris, but DCR still requires one
      // for many OP deployments; a placeholder is fine.
      redirect_uris: [`${base}/callback`],
      grant_types: [
        'urn:ietf:params:oauth:grant-type:device_code',
        'refresh_token',
      ],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });
  if (!r.ok) {
    throw new Error(`register ${r.status} ${(await r.text()).slice(0, 300)}`);
  }
  const body = await r.json();
  if (!body.client_id) {
    throw new Error('register missing client_id: ' + JSON.stringify(body));
  }
  return body;
}

/**
 * POST /device_authorization → { device_code, user_code, verification_uri, interval, ... }
 */
export async function requestDeviceAuthorization(
  { clientId, scope = 'openid urn:matrix:client:api:*' },
  siwxUrl = SIWX_URL,
) {
  const base = siwxUrl.replace(/\/$/, '');
  const form = new URLSearchParams({
    client_id: clientId,
    scope,
  });
  const r = await fetch(`${base}/device_authorization`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!r.ok) {
    throw new Error(
      `device_authorization ${r.status} ${(await r.text()).slice(0, 300)}`,
    );
  }
  return r.json();
}

/**
 * Sign the server-issued device-approval CAIP-122 message (GET /device/nonce)
 * and POST /device action=approve.
 *
 * @param {object} opts
 * @param {import('ethers').Wallet} opts.wallet
 * @param {string} opts.did
 * @param {string} opts.userCode
 * @param {string} [opts.siwxUrl]
 */
export async function approveDeviceWithWallet(
  { wallet, did, userCode },
  siwxUrl = SIWX_URL,
) {
  const base = siwxUrl.replace(/\/$/, '');
  const domain = new URL(base).hostname;
  const address = wallet.address;

  const nr = await fetch(
    `${base}/device/nonce?user_code=${encodeURIComponent(userCode)}`,
  );
  if (!nr.ok) {
    throw new Error(`device/nonce ${nr.status} ${(await nr.text()).slice(0, 300)}`);
  }
  const np = await nr.json();
  if (!np.nonce || !np.expiration_time) {
    throw new Error('device/nonce missing fields: ' + JSON.stringify(np));
  }

  const issuedAt = new Date().toISOString();
  let message =
    `${domain} wants you to sign in with your Ethereum account:\n` +
    `${address}\n\nApprove device login.\n\nURI: ${base}\nVersion: 1\nChain ID: 1\n` +
    `Nonce: ${np.nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${np.expiration_time}`;
  if (np.resources && np.resources.length) {
    message += '\nResources:';
    for (const r of np.resources) message += `\n- ${r}`;
  }

  const signature = await wallet.signMessage(message);
  const r = await fetch(`${base}/device`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      user_code: userCode,
      action: 'approve',
      did,
      message,
      signature,
    }),
  });
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: r.status, body };
}

/**
 * Poll POST /token with grant_type=device_code until tokens or terminal error.
 *
 * @returns {Promise<object>} token response body
 */
export async function pollDeviceToken(
  { clientId, deviceCode, intervalSec = 2, maxWaitMs = 60_000 },
  siwxUrl = SIWX_URL,
) {
  const base = siwxUrl.replace(/\/$/, '');
  const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
  const deadline = Date.now() + maxWaitMs;
  let sleepMs = Math.max(1000, (intervalSec || 2) * 1000);

  while (Date.now() < deadline) {
    const form = new URLSearchParams({
      grant_type: grantType,
      device_code: deviceCode,
      client_id: clientId,
    });
    const r = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const text = await r.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text };
    }

    if (r.ok && body.access_token) {
      return body;
    }

    const err = body.error || '';
    if (err === 'authorization_pending' || err === 'slow_down') {
      if (err === 'slow_down') sleepMs += 1000;
      await new Promise((res) => setTimeout(res, sleepMs));
      continue;
    }

    throw new Error(
      `device_code token poll terminal: status=${r.status} body=${text.slice(0, 400)}`,
    );
  }
  throw new Error(`device_code token poll timed out after ${maxWaitMs}ms`);
}

/**
 * Matrix whoami for a bearer token (re-export convenience).
 */
export async function matrixWhoami(accessToken, matrixUrl = MATRIX_URL) {
  const r = await fetch(
    `${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/account/whoami`,
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  let body = {};
  try {
    body = await r.json();
  } catch {
    body = {};
  }
  return { status: r.status, body };
}
