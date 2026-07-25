/**
 * Full Element Web DOM click-login (SSO immediate → OIDC-native → siwx UI →
 * back to the app shell), shared by ew-clickpath and ew-login specs.
 *
 * PRE-REQ (lab): Synapse msc3861.issuer_metadata must be the OP's FULL
 * metadata with only introspection_endpoint internal — an endpoints-only
 * dict fails matrix-js-sdk issuer validation and Element falls back to the
 * legacy /login/sso/redirect, which 404s under MSC3861. See
 * siwx-oidc-matrix-server entrypoints/matrix_server.sh.
 */
import { ELEMENT_URL, SIWX_URL } from './element.mjs';
import { injectMockWallet } from '../../browser/wallet-helper.mjs';

/**
 * Complete Element's mandatory first-device Secure Backup wizard
 * (force_verification + first-device-recovery): Continue (generate recovery
 * key) → Copy → Continue → Done. No-op if the app shell is already up.
 */
export async function completeSecureBackupWizard(page) {
  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();

  // "Setting up keys" spinner can run a while before the wizard renders.
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });
  if (await chat.count()) return;

  await btn(/^Continue$/).click(); // Set up Secure Backup (generate key default)
  await btn(/^Copy$/).click({ timeout: 120_000 }); // Save your Recovery Key
  await btn(/^Continue$/).click({ timeout: 30_000 });
  await btn(/^Done$/).click({ timeout: 60_000 }); // Secure Backup successful
  await chat.waitFor({ timeout: 90_000 });
}

/**
 * Drive the real Element → siwx → Element SSO click-path with a mock wallet,
 * completing the Secure Backup wizard. Returns Element's own session
 * identifiers from localStorage.
 */
export async function elementWalletClickLogin(page, wallet) {
  await injectMockWallet(page, wallet);

  // sso_redirect_options.immediate bounces a logged-out Element straight into
  // the OIDC-native authorize redirect → siwx login UI.
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, {
    timeout: 60_000,
  });

  // Real Svelte UI: wagmi connect → viem SIWE message → personal_sign (mock).
  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();

  // Post-signature interstitial: offer to link a passkey. Decline.
  await page.getByRole('button', { name: 'Skip for now' }).click();

  // /sign_in 303s back into Element, which finishes the code exchange, boots
  // crypto, and (first device) demands Secure Backup setup.
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, {
    timeout: 60_000,
  });
  await completeSecureBackupWizard(page);

  const session = await page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
    access_token: localStorage.getItem('mx_access_token'),
  }));
  if (!session.user_id || !session.device_id) {
    throw new Error('Element session storage missing: ' + JSON.stringify(session));
  }
  return session;
}
