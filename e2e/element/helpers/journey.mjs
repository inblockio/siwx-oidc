/**
 * JOURNEY WALKING — the product invariant, reusable.
 *
 *     At every screen a user reaches, they must be able to DO something:
 *     either the app shell is present (they are in), or at least one enabled,
 *     visible control is offered (they can act).
 *
 * A screen with neither, that does not resolve within the settle budget, is a dead
 * end: the user's only escape is a page reload they have no reason to expect, or
 * abandoning the account.
 *
 * This deliberately does NOT depend on the state model. A model can be wrong about
 * which states are reachable; a walk cannot. Every screen these functions record is
 * one a real browser actually reached.
 *
 * WHAT COUNTS AS AN EXIT is strict on purpose:
 *   - a control must be visible AND not disabled AND not aria-disabled. A greyed-out
 *     button is not an exit.
 *   - a spinner is not an exit; it is permission to wait, which is why `settle`
 *     polls before judging instead of sampling once.
 */
import { expect } from '@playwright/test';

/** One user-visible screen, reduced to "what can this person do?". */
export async function readScreen(page) {
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
      // With the app shell up the chrome is full of controls and counting them says
      // nothing. Only pre-shell / modal surfaces are interesting.
      const scope =
        document.querySelector('.mx_Dialog') ||
        document.querySelector('.mx_CompleteSecurityBody') ||
        document.querySelector('.mx_AuthPage') ||
        (appShell ? null : document.body);

      const pick = (sel, filter) =>
        scope
          ? [...new Set([...scope.querySelectorAll(sel)].filter(filter).map(label).filter(Boolean))].slice(0, 25)
          : [];

      return {
        url: location.href,
        appShell,
        spinner: !!document.querySelector('.mx_Spinner'),
        headings: [...document.querySelectorAll('h1,h2,h3')].filter(vis).map((h) => h.textContent.trim()).slice(0, 5),
        controls: pick('button, [role="button"], a[href], input:not([type=hidden])', actionable),
        disabled: pick(
          'button, [role="button"]',
          (el) => vis(el) && (el.hasAttribute('disabled') || el.getAttribute('aria-disabled') === 'true'),
        ),
        body: (document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 220),
      };
    })
    .catch((e) => ({ error: String(e).slice(0, 160) }));
}

export const hasExit = (s) => !!s && !s.error && (s.appShell || (s.controls || []).length > 0);

/**
 * Poll until the screen offers an exit, then return it, logging one line per
 * checkpoint. A screen is only called a dead end after `budgetMs` — a transient
 * spinner is not a trap, and calling it one produces a flaky test that gets deleted.
 */
export async function settle(page, label, { budgetMs = 30_000, intervalMs = 2_000 } = {}) {
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
    `[JOURNEY] ${String(label).padEnd(34)} ${verdict.padEnd(9)} ` +
      `shell=${s.appShell} headings=${JSON.stringify(s.headings)} ` +
      `controls=${JSON.stringify(s.controls)}` +
      ((s.disabled || []).length ? ` disabledControls=${JSON.stringify(s.disabled)}` : ''),
  );
  return { ...s, label, verdict };
}

export function assertExit(s) {
  expect(
    s.verdict,
    `DEAD END at "${s.label}" — the user has no enabled control and no app shell after the ` +
      `settle budget.\n  url: ${s.url}\n  headings: ${JSON.stringify(s.headings)}\n` +
      `  disabled-but-visible controls: ${JSON.stringify(s.disabled)}\n  body: ${s.body}\n` +
      `  This is the product invariant: a user must always be able to act. Do not resolve this ` +
      `by widening the budget — name the missing transition.`,
  ).toBe('EXIT');
}
