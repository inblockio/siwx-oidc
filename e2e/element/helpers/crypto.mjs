/**
 * Cross-signing / account-reset helpers for EW-X* Element lab specs.
 *
 * Mirrors tests/e2e_msc4191_live.rs (device_signing/upload + /account wallet
 * re-auth) in pure Node so Playwright only needs a page for OIDC login.
 */

import crypto from 'node:crypto';
import { MATRIX_URL, SIWX_URL } from './element.mjs';

/** Matrix unpadded standard base64 (no `=` padding). */
export function matrixB64(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/=+$/, '');
}

/**
 * Mint a fresh Ed25519 keypair via node:crypto and return raw 32-byte public
 * key + a privateKey object suitable for crypto.sign(null, msg, privateKey).
 */
function mkEd25519() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  // JWK `x` is base64url of the raw 32-byte Ed25519 public key.
  const pubBytes = Buffer.from(jwk.x, 'base64url');
  return { privateKey, pubBytes, pubB64: matrixB64(pubBytes) };
}

/**
 * Build a complete, validly-signed cross-signing key set for `userId`, suitable
 * for POST /_matrix/client/v3/keys/device_signing/upload.
 *
 * Port of tests/e2e_msc4191_live.rs::build_cross_signing_upload — master has no
 * signature; self/user-signing are signed by master over Matrix canonical JSON
 * (keys sorted: keys < usage < user_id; compact, no whitespace).
 */
export function buildCrossSigningUpload(userId) {
  const master = mkEd25519();
  const selfSigning = mkEd25519();
  const userSigning = mkEd25519();

  const signable = (pubkey, usage) =>
    `{"keys":{"ed25519:${pubkey}":"${pubkey}"},"usage":["${usage}"],"user_id":"${userId}"}`;

  const signWithMaster = (msg) =>
    matrixB64(crypto.sign(null, Buffer.from(msg, 'utf8'), master.privateKey));

  const selfSig = signWithMaster(signable(selfSigning.pubB64, 'self_signing'));
  const userSig = signWithMaster(signable(userSigning.pubB64, 'user_signing'));

  return {
    master_key: {
      user_id: userId,
      usage: ['master'],
      keys: { [`ed25519:${master.pubB64}`]: master.pubB64 },
    },
    self_signing_key: {
      user_id: userId,
      usage: ['self_signing'],
      keys: { [`ed25519:${selfSigning.pubB64}`]: selfSigning.pubB64 },
      signatures: {
        [userId]: { [`ed25519:${master.pubB64}`]: selfSig },
      },
    },
    user_signing_key: {
      user_id: userId,
      usage: ['user_signing'],
      keys: { [`ed25519:${userSigning.pubB64}`]: userSigning.pubB64 },
      signatures: {
        [userId]: { [`ed25519:${master.pubB64}`]: userSig },
      },
    },
  };
}

/**
 * POST keys/device_signing/upload. Retries a few times on transient 5xx
 * (fresh accounts can intermittently M_UNKNOWN on first upload).
 *
 * @returns {Promise<{ status: number, body: string }>}
 */
export async function uploadDeviceSigning(
  accessToken,
  body,
  matrixUrl = MATRIX_URL,
  { retries = 4 } = {},
) {
  const url = `${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/keys/device_signing/upload`;
  let last = { status: 500, body: '' };
  for (let attempt = 1; attempt <= retries; attempt++) {
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    const text = await r.text();
    last = { status: r.status, body: text };
    // Terminal contract outcomes — return immediately.
    if (r.status === 200 || r.status === 401 || r.status < 500) return last;
    // Transient 5xx: brief backoff then retry.
    await new Promise((res) => setTimeout(res, 250 * attempt));
  }
  return last;
}

/**
 * POST keys/query for the caller's own devices (session-authenticated).
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function keysQuery(accessToken, userId, matrixUrl = MATRIX_URL) {
  const url = `${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/keys/query`;
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      device_keys: userId ? { [userId]: [] } : {},
      timeout: 10000,
    }),
  });
  let body = {};
  try {
    body = await r.json();
  } catch {
    body = {};
  }
  return { status: r.status, body };
}

/**
 * CAIP-122 account-action message for POST /account/wallet, matching the
 * account page's authWallet JS + tests/e2e_msc4191_live.rs.
 *
 * @param {import('ethers').Wallet} wallet  ethers Wallet (for address + sign)
 * @param {string} action  e.g. org.matrix.cross_signing_reset
 * @param {string} [siwxUrl]
 */
export async function signAccountAction(wallet, action, siwxUrl = SIWX_URL) {
  const base = siwxUrl.replace(/\/$/, '');
  const domain = new URL(base).hostname;
  const address = wallet.address;

  const nr = await fetch(`${base}/account/nonce?action=${encodeURIComponent(action)}`);
  if (!nr.ok) {
    throw new Error(
      `account/nonce ${nr.status} ${(await nr.text()).slice(0, 300)}`,
    );
  }
  const np = await nr.json();
  if (!np.nonce || !np.expiration_time) {
    throw new Error('account/nonce missing nonce/expiration_time: ' + JSON.stringify(np));
  }
  const issuedAt = new Date().toISOString();
  let message =
    `${domain} wants you to sign in with your Ethereum account:\n` +
    `${address}\n\nConfirm account action.\n\nURI: ${base}\nVersion: 1\nChain ID: 1\n` +
    `Nonce: ${np.nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${np.expiration_time}`;
  if (np.resources && np.resources.length) {
    message += '\nResources:';
    for (const r of np.resources) message += `\n- ${r}`;
  }
  const signature = await wallet.signMessage(message);
  return { message, signature, did: `did:pkh:eip155:1:${address}` };
}

/**
 * POST /account/wallet for an MSC4191 action (wallet CAIP-122 re-auth).
 *
 * @returns {Promise<{ status: number, body: object|string }>}
 */
export async function postAccountWallet(
  { wallet, action, deviceId = null },
  siwxUrl = SIWX_URL,
) {
  const base = siwxUrl.replace(/\/$/, '');
  const { message, signature, did } = await signAccountAction(wallet, action, base);
  const r = await fetch(`${base}/account/wallet`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      action,
      did,
      message,
      signature,
      device_id: deviceId,
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
