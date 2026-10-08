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
 * Returns 'app' | 'login' | 'unknown' ('unknown' when neither appears within `timeout`).
 *
 * Signed out, Element does not stay on its own page: with `sso_redirect_options.immediate`
 * (siwx-oidc-matrix-server's Element config) it redirects to the provider's sign-in page a
 * few hundred milliseconds after `domcontentloaded`, while its own document still has an
 * empty body. A `page.evaluate` that runs as that navigation commits fails with "Execution
 * context was destroyed". So the landing is awaited with `page.waitForFunction`, which
 * Playwright runs again in each new document after a navigation: Element's empty document
 * reads as not landed yet, and the wait ends on the page the redirect leads to.
 */
export async function openElement(page, { timeout = 45_000 } = {}) {
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  // Element loads a large SPA; wait for either login affordance or room list chrome.
  try {
    const landed = await page.waitForFunction(
      () => {
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
        return null; // not landed yet: keep waiting
      },
      null,
      { timeout, polling: 250 },
    );
    return await landed.jsonValue();
  } catch (e) {
    if (e?.name === 'TimeoutError') return 'unknown';
    throw e;
  }
}

/**
 * Best-effort: clear Element localStorage so each test starts logged out.
 *
 * Cleared from Element's static `config.json`, a document on Element's origin that runs no
 * Element code. Clearing it from Element's own page raced Element's redirect to the provider
 * (see openElement): the clear could fail as the navigation committed, or run in the
 * provider's document and clear the wrong origin.
 */
export async function clearElementSession(page) {
  const elementBase = ELEMENT_URL.endsWith('/') ? ELEMENT_URL : `${ELEMENT_URL}/`;
  await page.goto(new URL('config.json', elementBase).href, { waitUntil: 'load' });
  await page.evaluate(() => {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch (_) {}
  });
}
