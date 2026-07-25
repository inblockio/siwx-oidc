/**
 * Element Web UI helpers for Phase 2.0 EW-* Playwright specs.
 *
 * The local stack serves Element at ELEMENT_URL (default http://localhost:8088)
 * with homeserver discovery pointing at http://localhost:8080 and OIDC at
 * http://localhost:8081 (see siwx-oidc-matrix-server/Caddyfile.local).
 */

// Defaults match Phase-2 lab remaps (portal-e2e often owns host :8080).
export const ELEMENT_URL = process.env.ELEMENT_URL || 'http://localhost:28088';
export const MATRIX_URL = process.env.MATRIX_URL || 'http://localhost:28080';
export const SIWX_URL = process.env.SIWX_URL || 'http://localhost:28081';

/** True if Element is reachable. */
export async function elementHealthy() {
  try {
    const r = await fetch(ELEMENT_URL, { method: 'GET' });
    return r.ok || r.status === 200;
  } catch {
    return false;
  }
}

/** True if Matrix client API is up. */
export async function matrixHealthy() {
  try {
    const r = await fetch(`${MATRIX_URL}/_matrix/client/versions`);
    return r.ok;
  } catch {
    return false;
  }
}

/** True if siwx OIDC discovery is up. */
export async function siwxHealthy() {
  try {
    const r = await fetch(`${SIWX_URL}/.well-known/openid-configuration`);
    return r.ok;
  } catch {
    return false;
  }
}

/**
 * Skip the suite cleanly when the Element stack is not running.
 * Call from test.beforeAll.
 */
export async function requireElementStack() {
  const ok =
    (await elementHealthy()) && (await matrixHealthy()) && (await siwxHealthy());
  if (!ok) {
    throw new Error(
      `Element stack not healthy. Need Element ${ELEMENT_URL}, Matrix ${MATRIX_URL}, siwx ${SIWX_URL}. ` +
        `Run: bash e2e/element/stack-up.sh`,
    );
  }
}

/**
 * Open Element and wait for either the welcome/login shell or an already-logged-in app.
 * Returns 'app' | 'login' | 'unknown'.
 */
export async function openElement(page) {
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  // Element loads a large SPA; wait for either login affordance or room list chrome.
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const state = await page.evaluate(() => {
      const body = document.body?.innerText || '';
      if (
        document.querySelector('[data-testid="room-list"]') ||
        document.querySelector('.mx_RoomList') ||
        body.includes('Home') && document.querySelector('.mx_MatrixChat')
      ) {
        return 'app';
      }
      if (
        body.includes('Sign in') ||
        body.includes('Continue') ||
        body.includes('homeserver') ||
        document.querySelector('[data-testid="login"]') ||
        document.querySelector('.mx_AuthPage')
      ) {
        return 'login';
      }
      return 'unknown';
    });
    if (state !== 'unknown') return state;
    await page.waitForTimeout(500);
  }
  return 'unknown';
}

/**
 * Best-effort: clear Element localStorage so each test starts logged out.
 */
export async function clearElementSession(page) {
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch (_) {}
  });
}
