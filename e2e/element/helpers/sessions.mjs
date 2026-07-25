/**
 * Session / device helpers for EW-S* specs against the live Element lab stack.
 *
 * Prefer Matrix CS-API + OP account endpoints (the contracts Element uses) over
 * fragile SPA selectors. Routes assumed:
 *   GET  {MATRIX}/_matrix/client/v3/devices          → Synapse
 *   DELETE {MATRIX}/_matrix/client/v3/devices/{id}   → siwx (Caddy edge)
 *   POST {MATRIX}/_matrix/client/v3/logout           → siwx (Caddy edge)
 *   POST {SIWX}/oauth2/introspect                    → siwx (token truth)
 */

import { MATRIX_URL, SIWX_URL } from './element.mjs';

/**
 * Matrix whoami for a bearer token.
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function matrixWhoami(accessToken, matrixUrl = MATRIX_URL) {
  const r = await fetch(`${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/account/whoami`, {
    headers: { Authorization: `Bearer ${accessToken}` },
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
 * List devices via Matrix CS-API (Synapse).
 * @returns {Promise<{ device_id: string, display_name?: string }[]>}
 */
export async function listDevices(accessToken, matrixUrl = MATRIX_URL) {
  const r = await fetch(`${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/devices`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) {
    throw new Error(`listDevices ${r.status} ${(await r.text()).slice(0, 300)}`);
  }
  const body = await r.json();
  return body.devices || [];
}

/**
 * DELETE /_matrix/client/v3/devices/{id} on the Matrix edge → siwx compat.
 * Element's in-client "Sign out this session" uses this path.
 */
export async function deleteDevice(accessToken, deviceId, matrixUrl = MATRIX_URL) {
  const r = await fetch(
    `${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/devices/${encodeURIComponent(deviceId)}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  );
  const text = await r.text();
  return { status: r.status, body: text };
}

/**
 * POST /_matrix/client/v3/logout on the Matrix edge → siwx compat.
 * Revokes the bearer session (and deletes its Synapse device).
 */
export async function matrixLogout(accessToken, matrixUrl = MATRIX_URL) {
  const r = await fetch(`${matrixUrl.replace(/\/$/, '')}/_matrix/client/v3/logout`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const text = await r.text();
  return { status: r.status, body: text };
}

/**
 * RFC 7662 introspection against the OP (token truth, bypasses Synapse cache).
 *
 * Prefer this for "token is dead" asserts right after logout/delete; Synapse
 * caches successful introspections for ~2 minutes so whoami can lag.
 *
 * @param {string} token
 * @param {string} clientSecret  MAS shared secret (Synapse client_secret)
 * @param {string} [siwxUrl]
 */
export async function introspectToken(
  token,
  clientSecret,
  siwxUrl = SIWX_URL,
  clientId = '0000000000000000000SYNAPSE',
) {
  const form = new URLSearchParams({
    token,
    client_id: clientId,
    client_secret: clientSecret,
  });
  const r = await fetch(`${siwxUrl.replace(/\/$/, '')}/oauth2/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!r.ok) {
    throw new Error(`introspect ${r.status} ${(await r.text()).slice(0, 300)}`);
  }
  return r.json();
}

/**
 * Load OIDC discovery + ensure account_management_uri is present.
 */
export async function fetchOidcDiscovery(siwxUrl = SIWX_URL) {
  const r = await fetch(
    `${siwxUrl.replace(/\/$/, '')}/.well-known/openid-configuration`,
  );
  if (!r.ok) {
    throw new Error(`openid-configuration ${r.status}`);
  }
  return r.json();
}

/**
 * GET the account management page (bare landing or deep-link action).
 */
export async function fetchAccountPage(accountUri, action) {
  const base = accountUri.replace(/\/$/, '');
  const url = action
    ? `${base}?action=${encodeURIComponent(action)}`
    : base;
  const r = await fetch(url);
  const text = await r.text();
  return { status: r.status, url, text };
}
