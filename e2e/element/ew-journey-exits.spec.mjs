/**
 * EW-J — JOURNEY EXIT WALK. The product question, asked directly.
 *
 * The anchored goal, in the owner's words:
 *
 *     "All user exposed states are well defined and users never land in an
 *      undefined state. All states can be clearly recovered from."
 *
 * This spec tests exactly that, and nothing else. It is deliberately NOT built on
 * the ~89-state model: that model is inference over code and documents carrying
 * ~20 unsettled assumptions, and a model can be wrong about which states are even
 * REACHABLE. Walking the journey cannot be. Every screen recorded here is a screen
 * a real user actually reached in a real browser against a real stack.
 *
 * THE ONE INVARIANT
 *
 *     At every screen a user reaches, they must be able to DO something:
 *     either the app shell is present (they are in), or at least one enabled,
 *     visible control is offered (they can act).
 *
 * A screen with neither, that does not resolve, is a dead end -- the user's only
 * escape is a page reload they have no reason to expect, or abandoning the account.
 *
 * SCOPE, STATED HONESTLY. This walks the LAB. Verified by grepping the served
 * bundle at authoring time, the lab Element carries force-first-device-recovery
 * and the Busy-wedge fix, and does NOT carry the U5/U7 patches. The Busy-wedge fix
 * is UNPUSHED, so the lab is AHEAD of production. A green run here is a statement
 * about the lab, not about what users have today. Do not quote it as the latter.
 *
 * WHAT COUNTS AS AN EXIT is deliberately strict:
 *   - controls must be visible AND not disabled AND not aria-disabled.
 *     A greyed-out button is not an exit; it is the shape of the U5 complaint
 *     ("Show QR code", disabled, with a false explanation).
 *   - a spinner is not an exit; it is permission to wait, which is why the check
 *     polls before judging rather than sampling once.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, openElement } from './helpers/element.mjs';
import { elementWalletClickLogin, completeSecureBackupWizard } from './helpers/element-login.mjs';
import { makeWallet, injectMockWallet } from '../browser/wallet-helper.mjs';

const SERVER_NAME = 'localhost';

test.beforeAll(async () => {
  await requireElementStack();
});

/** One user-visible screen, reduced to "what can this person do?". */
async function readScreen(page) {
  return page
    .evaluate(() => {
      const vis = (el) => {
        const r = el.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return false;
        const cs = window.getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
      };
      const actionable = (el) =>
        vis(el) &&
        !el.hasAttribute('disabled') &&
        el.getAttribute('aria-disabled') !== 'true' &&
        el.getAttribute('aria-hidden') !== 'true';
      const label = (el) =>
        (el.innerText || '').replace(/\s+/g, ' ').trim() ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        '';

      const appShell = !!document.querySelector('.mx_MatrixChat');
      // When the app shell is up, the chrome is full of controls and counting them
      // says nothing. Only pre-shell / modal surfaces are interesting here.
      const scope =
        document.querySelector('.mx_Dialog') ||
        document.querySelector('.mx_CompleteSecurityBody') ||
        document.querySelector('.mx_AuthPage') ||
        (appShell ? null : document.body);

      const controls = scope
        ? [
            ...new Set(
              [...scope.querySelectorAll('button, [role="button"], a[href], input:not([type=hidden])')]
                .filter(actionable)
                .map(label)
                .filter(Boolean),
            ),
          ].slice(0, 25)
        : [];

      const disabled = scope
        ? [
            ...new Set(
              [...scope.querySelectorAll('button, [role="button"]')]
                .filter((el) => vis(el) && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true'))
                .map(label)
                .filter(Boolean),
            ),
          ].slice(0, 15)
        : [];

      return {
        url: location.href,
        appShell,
        spinner: !!document.querySelector('.mx_Spinner'),
        headings: [...document.querySelectorAll('h1,h2,h3')].filter(vis).map((h) => h.textContent.trim()).slice(0, 5),
        controls,
        disabled,
        body: (document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 220),
      };
    })
    .catch((e) => ({ error: String(e).slice(0, 160) }));
}

const hasExit = (s) => !!s && !s.error && (s.appShell || (s.controls || []).length > 0);

/**
 * Poll until the screen offers an exit, then return it. A screen is only called a
 * dead end after it has had `budgetMs` to resolve -- a transient spinner is not a
 * trap, and calling it one would produce a flaky test that gets deleted.
 */
async function settle(page, label, { budgetMs = 30_000, intervalMs = 2_000 } = {}) {
  let s = null;
  const deadline = Date.now() + budgetMs;
  for (;;) {
    s = await readScreen(page);
    if (hasExit(s)) break;
    if (Date.now() >= deadline) break;
    await page.waitForTimeout(intervalMs);
  }
  const verdict = hasExit(s) ? 'EXIT' : 'DEAD-END';
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] ${label.padEnd(34)} ${verdict.padEnd(9)} ` +
      `shell=${s.appShell} headings=${JSON.stringify(s.headings)} ` +
      `controls=${JSON.stringify(s.controls)}` +
      ((s.disabled || []).length ? ` disabledControls=${JSON.stringify(s.disabled)}` : ''),
  );
  return { ...s, label, verdict };
}

function assertExit(s) {
  expect(
    s.verdict,
    `DEAD END at "${s.label}" — the user has no enabled control and no app shell after the ` +
      `settle budget.\n  url: ${s.url}\n  headings: ${JSON.stringify(s.headings)}\n` +
      `  disabled-but-visible controls: ${JSON.stringify(s.disabled)}\n  body: ${s.body}\n` +
      `  This is the product invariant: a user must always be able to act. Do not resolve this ` +
      `by widening the budget — name the missing transition.`,
  ).toBe('EXIT');
}

// ---------------------------------------------------------------------------
// J1 — first login on a brand-new identity, through to a usable session.
// ---------------------------------------------------------------------------
test('EW-J1: first login (new wallet identity) — every screen offers an exit', async ({ page }) => {
  test.setTimeout(600_000);
  const w = makeWallet(undefined, SERVER_NAME);

  await injectMockWallet(page, w);
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  assertExit(await settle(page, 'J1.1 siwx login page'));

  // Driven step-by-step, NOT via elementWalletClickLogin, deliberately. That helper
  // completes the whole Secure Backup wizard internally, so sampling around it only
  // ever observes "logged out" and "in the app" -- the two screens nobody doubted.
  // The wizard's interior is where a dead end would actually live, so it is walked
  // one click at a time.
  await page.getByRole('button', { name: 'Sign in with Ethereum' }).click();
  assertExit(await settle(page, 'J1.2 after signature'));

  await page.getByRole('button', { name: 'Skip for now' }).click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 120_000 });
  assertExit(await settle(page, 'J1.3 back in Element', { budgetMs: 150_000 }));

  // Forced first-device recovery: Continue -> Copy -> Continue -> Done. Each step is
  // sampled BEFORE its click, so a screen that offers nothing is caught here rather
  // than being clicked past by a helper.
  const chat = page.locator('.mx_MatrixChat');
  const steps = [/^Continue$/, /^Copy$/, /^Continue$/, /^Done$/];
  for (let i = 0; i < steps.length; i += 1) {
    if (await chat.count()) break;
    const s = await settle(page, `J1.4.${i + 1} wizard step`, { budgetMs: 150_000 });
    assertExit(s);
    const btn = page.getByRole('button', { name: steps[i], disabled: false }).first();
    if (!(await btn.count())) break;
    await btn.click({ timeout: 120_000 }).catch(() => {});
  }

  assertExit(await settle(page, 'J1.5 after wizard', { budgetMs: 120_000 }));
  await expect(chat).toBeVisible({ timeout: 120_000 });
});

// ---------------------------------------------------------------------------
// J2 — reload. The single most common thing a user does, and historically the
// state that produced hard logouts and the verify gate.
// ---------------------------------------------------------------------------
test('EW-J2: reload an established session — every screen offers an exit', async ({ page }) => {
  test.setTimeout(600_000);
  const w = makeWallet(undefined, SERVER_NAME);
  await elementWalletClickLogin(page, w);
  await expect(page.locator('.mx_MatrixChat')).toBeVisible({ timeout: 120_000 });

  await page.reload({ waitUntil: 'domcontentloaded' });
  const s = await settle(page, 'J2.1 after reload', { budgetMs: 60_000 });
  assertExit(s);

  // Not an assertion, an observation worth having in the log: did the reload put
  // the user back in the app, or in front of a gate they must satisfy?
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] J2 reload outcome: ${s.appShell ? 'APP SHELL' : 'GATE — ' + JSON.stringify(s.headings)}`);
});

// ---------------------------------------------------------------------------
// J3 — THE DANGEROUS ONE. A second device, no other signed-in session, and the
// user does NOT have their recovery key to hand. This is the composition the
// audit calls "reset is the only visible exit" — and reset is the destructive
// path that orphans the message-key backup.
//
// This test does NOT assert that a non-destructive exit exists (that is the open
// product question). It asserts the weaker, non-negotiable invariant — the user
// can act at all — and RECORDS what they are offered, so the answer is measured
// rather than argued.
// ---------------------------------------------------------------------------
test('EW-J3: second device, no other session, no recovery key — what exits exist?', async ({ browser }) => {
  test.setTimeout(900_000);
  const w = makeWallet(undefined, SERVER_NAME);

  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  try {
    // Device A: establish the account and its 4S.
    const pageA = await ctxA.newPage();
    await elementWalletClickLogin(pageA, w);
    await expect(pageA.locator('.mx_MatrixChat')).toBeVisible({ timeout: 120_000 });

    // Device A goes away entirely — no live session to verify against.
    await ctxA.close();

    // Device B: same identity, fresh browser, nothing cached.
    const pageB = await ctxB.newPage();
    await injectMockWallet(pageB, w);
    await pageB.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
    await pageB.getByRole('button', { name: 'Sign in with Ethereum' }).click().catch(() => {});
    await pageB.getByRole('button', { name: 'Skip for now' }).click().catch(() => {});
    await pageB.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 120_000 });

    const gate = await settle(pageB, 'J3.1 second device gate', { budgetMs: 90_000 });
    assertExit(gate);

    // GROUNDED FINDING, recorded because it contradicts a document rather than
    // confirming one: "Use recovery key" IS offered here. U6 ("verify gate with no
    // recovery-key entry") is therefore fixed in this build, by direct observation
    // on the exact path the audit said was worst -- a new device with NO other
    // session. Asserted so a regression is caught, not just noted.
    expect(
      gate.controls.some((c) => /recovery key/i.test(c)),
      `U6 REGRESSION — the second-device gate offers no recovery-key entry. Controls: ` +
        `${JSON.stringify(gate.controls)}. Without it, a user with no live session has only the ` +
        `destructive path.`,
    ).toBe(true);

    // Now the part the first version of this test got WRONG. It classified the gate
    // as "no destructive controls" because its regex did not match "Can't confirm?"
    // -- which is precisely the disclosure that leads to reset. A classifier that
    // cannot see the destructive path will always report that none exists.
    // So: open it and look, rather than pattern-matching the top-level labels.
    const disclosure = pageB.getByRole('button', { name: /can'?t confirm/i }).first();
    let behind = null;
    if (await disclosure.count()) {
      await disclosure.click().catch(() => {});
      behind = await settle(pageB, 'J3.2 behind "Can\'t confirm?"', { budgetMs: 20_000 });
      assertExit(behind);
    }

    // NOT classified by label. Measured 2026-07-26: behind "Can't confirm?" the
    // destructive action is labelled **"Continue"**, under the heading "Are you sure
    // you want to reset your digital identity?". A regex over control labels cannot
    // see that, and the first version of this test duly reported "destructive=[]"
    // for a screen whose whole purpose is a destructive confirmation. Label-based
    // classification of destructive actions is unsound and is not used here.
    //
    // Instead: assert that the two exits that are non-destructive BY CONSTRUCTION
    // are present. "Use recovery key" unlocks; "Use another device" verifies from a
    // peer. Neither can orphan the backup. Their presence is the product claim.
    // eslint-disable-next-line no-console
    console.log(
      `[JOURNEY] J3 FULL exit set — gate=${JSON.stringify(gate.controls)} ` +
        `behindDisclosure=${JSON.stringify((behind && behind.controls) || [])} ` +
        `behindHeadings=${JSON.stringify((behind && behind.headings) || [])}`,
    );

    const nonDestructive = gate.controls.filter((c) => /recovery key|another device/i.test(c));
    expect(
      nonDestructive,
      `RESET IS THE ONLY EXIT at the second-device gate. Neither "Use recovery key" nor ` +
        `"Use another device" is offered, so every route forward runs through the reset ` +
        `confirmation — which orphans the user's message-key backup. Controls seen: ` +
        `${JSON.stringify(gate.controls)}. This would be the U5+U6+U7 composition actually ` +
        `reproducing; as measured on 2026-07-26 it does NOT.`,
    ).toHaveLength(2);
  } finally {
    await ctxA.close().catch(() => {});
    await ctxB.close().catch(() => {});
  }
});
