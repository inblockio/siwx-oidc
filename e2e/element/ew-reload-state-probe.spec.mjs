// EW-PROBE: diagnostic, not an assertion suite.
//
// EW-R1-1 fails by TIMING OUT waiting for EITHER `.mx_MatrixChat` (app shell) OR
// `.mx_CompleteSecurityBody` (the verify gate) after a reload. Neither appearing
// within 120s means the user lands in a THIRD state that no existing spec names,
// so "the gate traps the user" cannot be the whole story and must not be assumed.
//
// This probe reproduces exactly that reload and dumps what is actually on screen,
// plus the SetupEncryptionStore phase and crypto readiness. It asserts nothing
// about correctness on purpose: its output is evidence for naming the state, and
// a probe that also asserted would obscure which part failed.
//
// Delete once the state is named and covered by a real spec.
import { test } from '@playwright/test';
import { injectMockWallet, makeWallet } from '../browser/wallet-helper.mjs';

const SERVER_NAME = process.env.SERVER_NAME || 'localhost';
const ELEMENT_URL = process.env.ELEMENT_URL || 'http://localhost:28088';
const SIWX_URL = process.env.SIWX_URL || 'http://localhost:28081';

// Inlined rather than imported from ew-recovery-entry.spec.mjs: importing a spec
// file would register that file's tests here too.
async function loginThroughWizard(page, walletBundle) {
  await injectMockWallet(page, walletBundle);
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });

  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  await page.getByRole('button', { name: 'Skip for now' }).click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });

  const chat = page.locator('.mx_MatrixChat');
  const btn = (name) => page.getByRole('button', { name, disabled: false }).first();
  await chat.or(btn(/^Continue$/)).first().waitFor({ timeout: 150_000 });

  if (!(await chat.count())) {
    await btn(/^Continue$/).click();
    const keyNode = page.locator('.mx_CreateSecretStorageDialog_recoveryKey code');
    await keyNode.waitFor({ timeout: 120_000 });
    const recoveryKey = (await keyNode.innerText()).trim();
    await btn(/^Copy$/).click({ timeout: 120_000 });
    await btn(/^Continue$/).click({ timeout: 30_000 });
    await btn(/^Done$/).click({ timeout: 60_000 });
    await chat.waitFor({ timeout: 90_000 });
    return recoveryKey;
  }
  return null;
}

const PHASE_NAMES = {
  0: 'Loading',
  1: 'Intro',
  2: 'Busy',
  3: 'Done',
  4: 'ConfirmSkip',
  5: 'Finished',
  6: 'ConfirmReset',
};

async function snapshot(page, label) {
  const dom = await page.evaluate(() => {
    const vis = (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    const store = window.mxSetupEncryptionStore;
    return {
      url: location.href,
      title: document.title,
      bodyClasses: document.body.className,
      // Which of the three candidate containers exist at all.
      containers: {
        matrixChat: !!document.querySelector('.mx_MatrixChat'),
        completeSecurityBody: !!document.querySelector('.mx_CompleteSecurityBody'),
        authPage: !!document.querySelector('.mx_AuthPage'),
        spinner: !!document.querySelector('.mx_Spinner'),
        errorBoundary: !!document.querySelector('.mx_ErrorBoundary'),
      },
      headings: [...document.querySelectorAll('h1,h2,h3')]
        .filter(vis)
        .map((h) => h.textContent.trim())
        .slice(0, 10),
      buttons: [...document.querySelectorAll('button,[role=button]')]
        .filter(vis)
        .map((b) => b.textContent.trim())
        .filter(Boolean)
        .slice(0, 20),
      inputs: [...document.querySelectorAll('input')].filter(vis).length,
      setupEncryptionPhase: store ? store.phase : null,
      bodyTextHead: document.body.innerText.replace(/\s+/g, ' ').slice(0, 400),
    };
  });

  const crypto = await page
    .evaluate(async () => {
      const cli = window.mxMatrixClientPeg?.get?.();
      const c = cli?.getCrypto?.();
      if (!c) return { available: false };
      return {
        available: true,
        crossSigningReady: await c.isCrossSigningReady().catch((e) => `ERR ${e}`),
        secretStorageReady: await c.isSecretStorageReady().catch((e) => `ERR ${e}`),
        keyId: (await c.getCrossSigningKeyId().catch(() => null)) ? 'present' : 'absent',
      };
    })
    .catch((e) => ({ available: false, error: String(e) }));

  const phase = dom.setupEncryptionPhase;
  console.log(
    `\n[EW-PROBE ${label}] phase=${phase} (${PHASE_NAMES[phase] ?? 'n/a'})\n` +
      `  containers: ${JSON.stringify(dom.containers)}\n` +
      `  headings:   ${JSON.stringify(dom.headings)}\n` +
      `  buttons:    ${JSON.stringify(dom.buttons)}\n` +
      `  inputs:     ${dom.inputs}\n` +
      `  crypto:     ${JSON.stringify(crypto)}\n` +
      `  url:        ${dom.url}\n` +
      `  bodyText:   ${dom.bodyTextHead}\n`,
  );
  return { dom, crypto };
}

test('EW-PROBE: what does a reloaded first device actually render?', async ({ page }) => {
  test.setTimeout(480_000);

  const w = makeWallet(undefined, SERVER_NAME);
  await loginThroughWizard(page, w);

  await snapshot(page, 'before-reload');

  await page.reload({ waitUntil: 'domcontentloaded' });

  // Sample repeatedly rather than waiting on one locator: the failure mode is
  // "neither container ever appears", so we need the trajectory, not a verdict.
  for (const t of [5, 15, 30, 60, 120]) {
    await page.waitForTimeout(t === 5 ? 5_000 : 10_000);
    await snapshot(page, `after-reload-~${t}s`);
  }
});
