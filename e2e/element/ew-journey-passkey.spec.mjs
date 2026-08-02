/**
 * EW-JP — JOURNEY EXIT WALK, PASSKEY BRANCH.
 *
 * Same product invariant as ew-journey-exits.spec.mjs, asked of the passkey
 * login journey instead of the wallet one:
 *
 *     At every screen a user reaches, they must be able to DO something:
 *     either the app shell is present (they are in), or at least one enabled,
 *     visible control is offered (they can act).
 *
 * WHY THIS SPEC EXISTS ALONGSIDE ew-passkey.spec.mjs. EW-P1/P2/P3 drive the
 * passkey OIDC flow entirely through `page.evaluate` fetches
 * (helpers/passkey-login.mjs): DCR -> /authorize -> /webauthn/* -> /sign_in ->
 * /token. They are wire-level tests and they are good ones, but they never
 * render, click, or look at a single screen. EW-P1 asserts the new-user gate as
 * a JSON field (`new_user: true`); it does not assert that a human is ever shown
 * a gate they can act on. The screen is the part nobody had checked — and the
 * first thing this walk found was a defect that only exists at the screen level
 * (EW-JP1b below), invisible to every wire-level test in the repo.
 *
 * WHAT IS DRIVEN BY CLICKING, AND WHY. Every step a user performs is a real DOM
 * click on the real Svelte login page and the real Element app. The helper
 * `loginPasskeyToTokens` is deliberately NOT used to move the journey forward —
 * it completes the whole ceremony internally, so sampling around it would only
 * ever observe "logged out" and "has tokens", which is precisely the vacuous
 * shape this effort exists to stop. Helpers ARE reused where a fetch is the
 * honest instrument rather than a shortcut: `startOidcOnSiwx` +
 * `authenticatePasskeyCapturingStart` back JP2's server-truth probe, which must
 * NOT be a click (clicking is what would create the account it checks for).
 *
 * A NOTED LIMIT OF THE INVARIANT ITSELF, found by this walk. On the siwx login
 * page the exit test is trivially satisfied: "Sign in with Ethereum" is enabled
 * at all times, including while a passkey ceremony is in flight and including
 * after one has silently failed. So `assertExit` can NEVER go red on that page,
 * and it does not catch EW-JP1b — a screen full of enabled controls where the
 * user's last action did nothing is, by this definition, not a dead end. The
 * invariant covers "can the user act?", not "did their action do anything".
 * On siwx surfaces the per-screen sentinels below carry the weight; `assertExit`
 * earns its keep on Element's screens, where controls really do disappear.
 *
 * SCOPE, STATED HONESTLY. This walks the LAB (Element :28088, Matrix :28080,
 * siwx :28081). A green run is a statement about the lab, not about production.
 *
 * LABELS ARE MEASURED, NOT GUESSED. Read off js/ui/src/App.svelte and confirmed
 * against the SERVED bundle (http://localhost:28081/build/bundle.js) on
 * 2026-07-26:
 *   - login page: "Sign in with Ethereum" (:526), "Sign in with Passkey" (:545),
 *     and the first-time affordance is "Create one" under "No passkey yet?"
 *     (:568) — it is NOT labelled "Register a new passkey".
 *   - new-user gate (:455-484): heading "Create a new account?", controls
 *     "Continue" (:471) and "Try another passkey" (:481). There is NO Cancel
 *     button; see JP2 for what "cancelling" therefore means.
 */
import { test, expect } from '@playwright/test';
import { requireElementStack, ELEMENT_URL, SIWX_URL } from './helpers/element.mjs';
import { settle, assertExit } from './helpers/journey.mjs';
import { addVirtualAuthenticator } from '../browser/webauthn-helper.mjs';
import {
  startOidcOnSiwx,
  authenticatePasskeyCapturingStart,
} from './helpers/passkey-login.mjs';

const GATE_HEADING = /create a new account/i;

test.beforeAll(async () => {
  await requireElementStack();
});

// ---------------------------------------------------------------------------
// Navigation primitives. These MOVE the journey; they never judge it — judging
// is `settle`/`assertExit` from helpers/journey.mjs, reused unforked.
// ---------------------------------------------------------------------------

/**
 * Logged-out Element bounces straight into the OIDC authorize redirect
 * (sso_redirect_options.immediate), landing on the siwx Svelte login page.
 * Same entry the wallet journeys use (helpers/element-login.mjs:49-52).
 */
async function gotoSiwxLoginPage(page) {
  await page.goto(ELEMENT_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 90_000 });
}

/** Element's own session identity, as Element itself stores it. */
async function elementSession(page) {
  return page.evaluate(() => ({
    user_id: localStorage.getItem('mx_user_id'),
    device_id: localStorage.getItem('mx_device_id'),
  }));
}

/**
 * Wait for the passkey ceremony to produce a TERMINAL screen before judging it.
 *
 * MEASURED 2026-07-26, and the reason this exists: `settle` is a DEAD-END
 * DETECTOR, not a page-transition waiter. It returns the instant any exit
 * exists, and the login page always has one. The first version of this spec
 * sampled 1.1s after the click and measured the mid-ceremony login page —
 * `EXIT ... disabledControls=["Authenticating...","Create one"]`. Its gate
 * sentinel caught that, which is exactly what that sentinel is for.
 *
 * Races the gate heading against the error banner so a failed ceremony reports
 * in seconds instead of burning the whole budget.
 */
async function waitForCeremonyScreen(page, timeout = 120_000) {
  const gate = page.getByRole('heading', { name: GATE_HEADING });
  const err = page.locator('.error-msg');
  await gate
    .or(err)
    .first()
    .waitFor({ state: 'visible', timeout })
    .catch(() => {});
}

/** Did the new-user gate become visible within `timeout`? */
async function gateAppeared(page, timeout) {
  return page
    .getByRole('heading', { name: GATE_HEADING })
    .first()
    .waitFor({ state: 'visible', timeout })
    .then(() => true)
    .catch(() => false);
}

/**
 * First-time passkey registration, all the way to the new-user gate.
 *
 * ROUTES AROUND A MEASURED PRODUCT DEFECT, ON PURPOSE AND VISIBLY. "Create one"
 * registers the credential and then stalls (EW-JP1b proves it and owns the
 * assertion); the user must click "Sign in with Passkey" themselves to get
 * anywhere. This helper takes that second click ONLY when the gate did not
 * appear on its own, so it keeps working — and keeps this walk meaningful —
 * the day the defect is fixed. `detoured` is returned so callers can log which
 * path the build actually took rather than assume.
 */
async function registerThenReachGate(page, prefix) {
  const regFinish = page.waitForResponse((r) => r.url().includes('/webauthn/register/finish'), {
    timeout: 120_000,
  });
  await page.getByRole('button', { name: /^Create one$/, disabled: false }).first().click();
  const reg = await regFinish;
  expect(reg.status(), `${prefix}: /webauthn/register/finish did not succeed`).toBe(200);

  let detoured = false;
  if (!(await gateAppeared(page, 15_000))) {
    detoured = true;
    // The stalled screen is itself part of the journey, so it is walked, not
    // skipped. It passes the exit test (see the header note) — recording it is
    // the point.
    assertExit(await settle(page, `${prefix} after "Create one" (stalled)`, { budgetMs: 15_000 }));
    await page
      .getByRole('button', { name: /sign in with passkey/i, disabled: false })
      .first()
      .click();
    await waitForCeremonyScreen(page);
  }

  const gate = await settle(page, `${prefix} new-user gate`, { budgetMs: 90_000 });
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] ${prefix} reached the gate via ${detoured ? 'DETOUR (JP1b defect)' : 'the direct chain'}`);
  return gate;
}

/**
 * Walk Element's forced first-device recovery wizard one click at a time,
 * sampling BEFORE each click so a screen that offers nothing is caught here
 * rather than clicked past. Lifted from EW-J1's loop (ew-journey-exits.spec.mjs)
 * because the passkey journey lands in exactly the same wizard.
 */
async function walkFirstDeviceWizard(page, prefix) {
  const chat = page.locator('.mx_MatrixChat');
  const steps = [/^Continue$/, /^Copy$/, /^Continue$/, /^Done$/];
  for (let i = 0; i < steps.length; i += 1) {
    if (await chat.count()) break;
    assertExit(await settle(page, `${prefix}.${i + 1} wizard step`, { budgetMs: 150_000 }));
    const btn = page.getByRole('button', { name: steps[i], disabled: false }).first();
    if (!(await btn.count())) break;
    await btn.click({ timeout: 120_000 }).catch(() => {});
  }
}

/**
 * SERVER TRUTH for "does the account the gate offered to create exist yet?".
 *
 * Deliberately NOT read from the browser UI (the UI is the thing under test) and
 * deliberately NOT a click (a click is what would create the account). Runs an
 * independent OIDC session + WebAuthn assertion with the SAME resident passkey
 * and reads the server's own new-identity verdict:
 *
 *     new_user == is_localpart_available(did_to_localpart(did))   [CLAUDE.md]
 *
 * `authenticate/finish` never provisions — only `/sign_in` does, and this never
 * calls it — so the probe is read-only with respect to account creation.
 * Navigates the page, so it must run AFTER the screens under test are walked.
 */
async function probeIdentityStillUnprovisioned(page) {
  await startOidcOnSiwx(page, { siwxUrl: SIWX_URL, clientName: 'ew-jp-probe' });
  const { finish } = await page.evaluate(authenticatePasskeyCapturingStart);
  return finish;
}

/**
 * Create a resident passkey the SERVER HAS NEVER SEEN: run the real
 * registration ceremony but never POST /webauthn/register/finish, so the
 * authenticator keeps the key and the server stores nothing.
 *
 * This is the stale/revoked-credential shape without needing Redis access from
 * inside the Playwright container (e2e/browser/stale-credential.spec.mjs gets
 * there by DELETEing the Redis record over a TCP socket; the lab's Redis is not
 * published to the host, so that route is unavailable here). From the server's
 * side the two are the same lookup miss (src/webauthn.rs:435-439).
 * Self-contained for page.evaluate.
 */
function createOrphanCredentialInPage() {
  const b64uToBuf = (s) => {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(b);
    const u = new Uint8Array(r.length);
    for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  };
  return (async () => {
    const sr = await fetch('/webauthn/register/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ display_name: null }),
    });
    if (!sr.ok) throw new Error('register start ' + sr.status + ' ' + (await sr.text()));
    const opts = await sr.json();
    opts.publicKey.challenge = b64uToBuf(opts.publicKey.challenge);
    opts.publicKey.user.id = b64uToBuf(opts.publicKey.user.id);
    if (opts.publicKey.excludeCredentials) {
      for (const c of opts.publicKey.excludeCredentials) c.id = b64uToBuf(c.id);
    }
    const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
    // NO /webauthn/register/finish, on purpose.
    return cred.id;
  })();
}

// ---------------------------------------------------------------------------
// JP1b — THE DEFECT, ASSERTED. Kept small and first so it is not buried.
//
// EXPECTED TO FAIL against the build measured on 2026-07-26. It is not a flaky
// test and not a harness artifact; it encodes a real bug found by this walk:
//
//   handlePasskeyRegister (App.svelte:357) sets `passkeyLoading = true` (:359),
//   and on success calls `await handlePasskeySignIn()` (:407) — but that
//   function's first statement is `if (passkeyLoading) return;` (:236), and
//   `passkeyLoading` is only cleared in the register handler's `finally` (:417),
//   i.e. AFTER the call. The chained sign-in is therefore a guaranteed no-op.
//
// Confirmed in the SERVED bundle, so this is what users get, not just what the
// source says: `async function j(e=!1){if(!g){...}}` where `j` is the sign-in
// handler and `g` is passkeyLoading; the register handler does `n(3,g=!0)` …
// `await j()` … `finally{n(3,g=!1)}`.
//
// Measured effect: register/start 200 -> register/finish 200 (the credential IS
// stored server-side) -> NOTHING. No authenticate/start, no gate, no error, no
// redirect, no status text. The user creates a passkey, is prompted for
// biometrics, and is returned to an unchanged "Sign in" page with no indication
// that anything happened or what to do next. Their only way forward is to guess
// that "Sign in with Passkey" now works.
//
// Note this is NOT caught by the exit invariant: the stalled page has three
// enabled controls. That gap is why this assertion is separate and explicit.
// ---------------------------------------------------------------------------
test('EW-JP1b: "Create one" must lead somewhere (KNOWN DEFECT — expected to fail)', async ({
  page,
}) => {
  test.setTimeout(300_000);
  await addVirtualAuthenticator(page);
  await gotoSiwxLoginPage(page);

  const before = page.url();
  const regFinish = page.waitForResponse((r) => r.url().includes('/webauthn/register/finish'), {
    timeout: 120_000,
  });
  await page.getByRole('button', { name: /^Create one$/, disabled: false }).first().click();
  const reg = await regFinish;
  expect(reg.status(), 'JP1b: registration itself failed — different bug than the one under test').toBe(200);

  // Give the UI every chance: any of a gate, an error, or a navigation counts as
  // "led somewhere". 20s is ~13x the observed end-to-end ceremony time.
  const outcome = await page
    .waitForFunction(
      (startUrl) => {
        if (location.href !== startUrl) return 'navigated';
        if (document.querySelector('.error-msg')) return 'error';
        if (document.querySelector('.gate-section')) return 'gate';
        return false;
      },
      before,
      { timeout: 20_000 },
    )
    .then((h) => h.jsonValue())
    .catch(() => null);

  const screen = await settle(page, 'JP1b after "Create one"', { budgetMs: 10_000 });
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP1b outcome=${outcome} verdict=${screen.verdict} ` +
      `headings=${JSON.stringify(screen.headings)} controls=${JSON.stringify(screen.controls)}`,
  );

  expect(
    outcome,
    `DEAD ACTION — "Create one" registered a passkey (register/finish 200, credential stored) and ` +
      `then produced no gate, no error, no redirect and no status. The user is returned to an ` +
      `unchanged login page after a biometric prompt, with nothing to tell them it worked or what ` +
      `to do next.\n` +
      `  Cause: handlePasskeyRegister (js/ui/src/App.svelte:359) sets passkeyLoading=true, then\n` +
      `  awaits handlePasskeySignIn() (:407), whose first line is "if (passkeyLoading) return;"\n` +
      `  (:236); passkeyLoading is only cleared in the finally at :417. The call is a no-op.\n` +
      `  Fix: clear passkeyLoading before the chained call, or extract the ceremony body so the\n` +
      `  re-entrancy guard is not re-tested on an internal call.\n` +
      `  Note the exit invariant does NOT catch this: the stalled screen still offers ` +
      `${JSON.stringify(screen.controls)}.`,
  ).not.toBeNull();
});

// ---------------------------------------------------------------------------
// JP1 — first-time passkey registration, through the new-user gate, into a
// working Element session. The whole journey a brand-new passkey user walks.
// ---------------------------------------------------------------------------
test('EW-JP1: first-time passkey → new-user gate → session — every screen offers an exit', async ({
  page,
}) => {
  test.setTimeout(900_000);
  await addVirtualAuthenticator(page);

  await gotoSiwxLoginPage(page);
  const login = await settle(page, 'JP1.1 siwx login page');
  assertExit(login);

  // ANTI-VACUITY. Without this, a login page that failed to render its passkey
  // affordances would still "have an exit" (the Ethereum button) and the walk
  // would sail past the very journey it claims to test.
  expect(
    login.controls.some((c) => /sign in with passkey/i.test(c)),
    `JP1 needs the login page to offer passkey sign-in; it offered ${JSON.stringify(login.controls)}.`,
  ).toBe(true);
  expect(
    login.controls.some((c) => /^create one$/i.test(c)),
    `JP1 needs the first-time registration affordance ("Create one" under "No passkey yet?"); ` +
      `the page offered ${JSON.stringify(login.controls)}.`,
  ).toBe(true);

  const gate = await registerThenReachGate(page, 'JP1.2');
  assertExit(gate);

  // ANTI-VACUITY, THE LOAD-BEARING ONE. If the ceremony silently failed the page
  // would still be the login page — which has an exit. Requiring the gate's own
  // heading is what makes "EXIT" here mean "the gate is reachable and actionable"
  // rather than "some screen was up". This sentinel has already earned its keep
  // twice: it caught the mid-ceremony sampling bug and then the JP1b defect.
  expect(
    (gate.headings || []).join(' '),
    `JP1 never reached the new-user gate. Screen was headings=${JSON.stringify(gate.headings)} ` +
      `controls=${JSON.stringify(gate.controls)}. An unrecognised passkey MUST be gated before ` +
      `provisioning (CLAUDE.md, new-account creation policy), and the user must see it.`,
  ).toMatch(GATE_HEADING);

  // The gate's exit must be a REAL one: enabled, not a greyed-out Continue.
  expect(
    gate.controls.some((c) => /^continue$/i.test(c)),
    `JP1 gate offers no enabled "Continue" — the confirm path is not actionable. ` +
      `enabled=${JSON.stringify(gate.controls)} disabled=${JSON.stringify(gate.disabled)}.`,
  ).toBe(true);

  const gateMxid = (await page.locator('.gate-mxid').first().textContent().catch(() => null))?.trim();
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP1 gate — mxid=${gateMxid} controls=${JSON.stringify(gate.controls)} ` +
      `disabled=${JSON.stringify(gate.disabled)}`,
  );
  expect(
    gateMxid,
    'JP1 gate must name the account it is about to create; the mxid affordance was absent/empty.',
  ).toMatch(/^@/);

  // Confirm. /sign_in provisions and redirects back into Element.
  await page.getByRole('button', { name: /^Continue$/, disabled: false }).first().click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 150_000 });
  assertExit(await settle(page, 'JP1.3 back in Element', { budgetMs: 150_000 }));

  await walkFirstDeviceWizard(page, 'JP1.4');

  const done = await settle(page, 'JP1.5 after wizard', { budgetMs: 150_000 });
  assertExit(done);
  await expect(page.locator('.mx_MatrixChat')).toBeVisible({ timeout: 150_000 });

  // The destination, asserted as a destination. Element's own stored session is
  // the account the gate named — so Continue provisioned exactly the identity it
  // advertised, and the journey ended in a usable session.
  const sess = await elementSession(page);
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] JP1 destination — session=${JSON.stringify(sess)} gateMxid=${gateMxid}`);
  expect(sess.user_id, 'JP1 ended without an Element session user_id').toBe(gateMxid);
  expect(sess.device_id, 'JP1 ended without an Element device_id').toBeTruthy();
});

// ---------------------------------------------------------------------------
// JP2 — THE CANCEL BRANCH of the new-user gate.
//
// A FINDING BEFORE A TEST: the gate has no Cancel button. Measured on
// App.svelte:469-483 and confirmed on screen, it offers exactly two controls —
// "Continue" and "Try another passkey". So "cancelling" is not a click on
// Cancel; it is declining to confirm. This test asks the two questions that
// actually matter:
//
//   1. Does declining strand the user?  ("Try another passkey" is the only
//      non-committal control; where does it lead, and can they act there?)
//   2. Does reaching the gate leave Synapse state?  The policy claims
//      "Cancel = no /sign_in = zero Synapse state" (CLAUDE.md). That is a claim
//      about the server, so it is measured on the server, not read off the UI.
// ---------------------------------------------------------------------------
test('EW-JP2: declining the new-user gate strands nobody and provisions nothing', async ({ page }) => {
  test.setTimeout(600_000);
  await addVirtualAuthenticator(page);

  await gotoSiwxLoginPage(page);
  assertExit(await settle(page, 'JP2.1 siwx login page'));

  const gate = await registerThenReachGate(page, 'JP2.2');
  assertExit(gate);
  expect(
    (gate.headings || []).join(' '),
    `JP2 never reached the gate; screen was ${JSON.stringify(gate.headings)}.`,
  ).toMatch(GATE_HEADING);

  const gateMxid = (await page.locator('.gate-mxid').first().textContent().catch(() => null))?.trim();
  expect(gateMxid, 'JP2 gate did not name the pending account').toMatch(/^@/);

  // RECORDED, because it contradicts the shape people assume this gate has:
  // there is no Cancel. Asserted so that if a Cancel is ever added, this test is
  // revisited rather than quietly continuing to exercise the wrong control.
  const hasCancel = gate.controls.some((c) => /^cancel$/i.test(c));
  const hasTryAnother = gate.controls.some((c) => /try another passkey/i.test(c));
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP2 gate affordances — hasCancel=${hasCancel} hasTryAnother=${hasTryAnother} ` +
      `controls=${JSON.stringify(gate.controls)} disabled=${JSON.stringify(gate.disabled)}`,
  );
  expect(
    hasTryAnother,
    `JP2 needs the gate's non-committal control ("Try another passkey"); the gate offered ` +
      `${JSON.stringify(gate.controls)}. With neither Cancel nor Try-another, confirming would ` +
      `be the ONLY way off this screen — a gate you cannot decline is not a gate.`,
  ).toBe(true);

  // Decline. The only resident key is the one just registered, so the picker
  // re-offers it; the question is whether the user can still act afterwards.
  await page.getByRole('button', { name: /try another passkey/i, disabled: false }).first().click();
  await waitForCeremonyScreen(page);
  const afterDecline = await settle(page, 'JP2.3 after declining', { budgetMs: 90_000 });
  assertExit(afterDecline);
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP2 decline destination — headings=${JSON.stringify(afterDecline.headings)} ` +
      `controls=${JSON.stringify(afterDecline.controls)}`,
  );

  // Wherever declining lands, a forward path must remain. Anything else means
  // the user declined once and lost the ability to sign in at all.
  expect(
    afterDecline.controls.some((c) => /continue|passkey|ethereum/i.test(c)),
    `DECLINING STRANDED THE USER — after "Try another passkey" no sign-in route remains. ` +
      `headings=${JSON.stringify(afterDecline.headings)} controls=${JSON.stringify(afterDecline.controls)}`,
  ).toBe(true);

  // THE SERVER-SIDE HALF. Independent OIDC session, same passkey, read-only.
  // Must run last: it navigates the page away from the screens above.
  const probe = await probeIdentityStillUnprovisioned(page);
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] JP2 server truth — ${JSON.stringify(probe)} (gate named ${gateMxid})`);
  expect(probe.did, 'JP2 probe did not complete a passkey assertion').toMatch(/^did:key:zDn/);
  expect(
    probe.new_user,
    `ZERO-STATE VIOLATED — after reaching the gate and declining, the server no longer reports ` +
      `${gateMxid} as a new identity (new_user=${probe.new_user}). Something provisioned the ` +
      `account without the user ever confirming, which is exactly what the login-only gate ` +
      `exists to prevent (CLAUDE.md: "Cancel = no /sign_in = zero Synapse state").`,
  ).toBe(true);
  expect(probe.mxid, 'JP2 probe resolved a different identity than the gate named').toBe(gateMxid);
});

// ---------------------------------------------------------------------------
// JP3 — RETURNING passkey login. Same passkey, same browser, signing in again
// after the Element session is gone. This is the ordinary case (a user coming
// back), and the one where a gate must NOT appear: the account now exists.
// ---------------------------------------------------------------------------
test('EW-JP3: returning passkey login lands in a session — every screen offers an exit', async ({
  page,
}) => {
  test.setTimeout(900_000);
  await addVirtualAuthenticator(page);

  // --- establish the account exactly as JP1 does (a returning user must first
  //     have returned FROM somewhere) ---
  await gotoSiwxLoginPage(page);
  assertExit(await settle(page, 'JP3.1 siwx login page (first visit)'));
  const gate = await registerThenReachGate(page, 'JP3.2');
  assertExit(gate);
  expect(
    (gate.headings || []).join(' '),
    'JP3 setup never reached the new-user gate.',
  ).toMatch(GATE_HEADING);
  await page.getByRole('button', { name: /^Continue$/, disabled: false }).first().click();
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 150_000 });
  await walkFirstDeviceWizard(page, 'JP3.3');
  await expect(page.locator('.mx_MatrixChat')).toBeVisible({ timeout: 150_000 });
  const first = await elementSession(page);
  expect(first.user_id, 'JP3 setup failed: no first session').toBeTruthy();

  // --- the session goes away; the passkey and the siwx_user cookie do not.
  //     This is "I got logged out / cleared my client and came back". ---
  await page.evaluate(() => {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch (_) {}
  });

  await gotoSiwxLoginPage(page);
  const back = await settle(page, 'JP3.4 siwx login page (returning)');
  assertExit(back);
  expect(
    back.controls.some((c) => /sign in with passkey/i.test(c)),
    `JP3 returning user is offered no passkey sign-in: ${JSON.stringify(back.controls)}.`,
  ).toBe(true);

  // Sign in with the SAME passkey — no registration this time.
  await page.getByRole('button', { name: /sign in with passkey/i, disabled: false }).first().click();

  // A returning identity must not be gated (the account exists), so the terminal
  // outcome here is a REDIRECT, not a screen. Wait for it; if a gate appears
  // instead this times out and the screen is then measured and reported rather
  // than guessed at.
  const landedInElement = await page
    .waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 150_000 })
    .then(() => true)
    .catch(() => false);

  const afterAuth = await settle(page, 'JP3.5 after passkey assertion', { budgetMs: 120_000 });
  assertExit(afterAuth);
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP3 post-assertion — landedInElement=${landedInElement} url=${afterAuth.url} ` +
      `shell=${afterAuth.appShell} headings=${JSON.stringify(afterAuth.headings)}`,
  );
  expect(
    landedInElement,
    `RETURNING USER DID NOT GET BACK IN — signing in with an already-provisioned passkey never ` +
      `returned to Element. Stuck at ${afterAuth.url} with headings=${JSON.stringify(afterAuth.headings)} ` +
      `controls=${JSON.stringify(afterAuth.controls)}.`,
  ).toBe(true);
  expect(
    (afterAuth.headings || []).join(' '),
    `RETURNING USER WAS GATED AS NEW — signing in with an already-provisioned passkey showed the ` +
      `new-account gate. Either the identity was not recognised or the gate fires on the wrong ` +
      `predicate; both would mean a returning user is invited to create a duplicate account.`,
  ).not.toMatch(GATE_HEADING);

  const landed = await settle(page, 'JP3.6 returning destination', { budgetMs: 180_000 });
  assertExit(landed);

  // THE DESTINATION, asserted as a destination rather than assumed. A second
  // login on an existing account is a SECOND DEVICE, so Element may present a
  // verification gate instead of the app shell — that is a legitimate screen and
  // the invariant already covers it. What must hold either way is that a real
  // Matrix session now exists, on the SAME account, as a DIFFERENT device.
  const second = await elementSession(page);
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP3 destination — shell=${landed.appShell} headings=${JSON.stringify(landed.headings)} ` +
      `controls=${JSON.stringify(landed.controls)} first=${JSON.stringify(first)} ` +
      `second=${JSON.stringify(second)}`,
  );
  expect(
    second.user_id,
    `JP3 returning login did not produce an Element session (user_id=${second.user_id}). The ` +
      `screens may all have offered exits, but the user never got back in.`,
  ).toBe(first.user_id);
  expect(second.device_id, 'JP3 returning login produced no device_id').toBeTruthy();
  expect(
    second.device_id,
    'JP3 returning login reused the first device id — sign-in must provision a fresh device ' +
      '(CLAUDE.md: no recycling).',
  ).not.toBe(first.device_id);
});

// ---------------------------------------------------------------------------
// JP4 — a credential the server does not know (stale / revoked / flushed).
//
// The contract (CLAUDE.md + src/axum_lib.rs:120-130): HTTP 401 with
// {error:"unknown_credential", ...}, NOT a 500, and the user gets an actionable
// message rather than a dead end.
// ---------------------------------------------------------------------------
test('EW-JP4: unknown credential → actionable message, not a dead end or a 500', async ({ page }) => {
  test.setTimeout(600_000);
  await addVirtualAuthenticator(page);

  await gotoSiwxLoginPage(page);
  assertExit(await settle(page, 'JP4.1 siwx login page'));

  // The only resident key in this context is one the server never stored.
  const orphanId = await page.evaluate(createOrphanCredentialInPage);
  expect(orphanId, 'JP4 failed to mint an orphan credential').toBeTruthy();

  const finishResp = page
    .waitForResponse((r) => r.url().includes('/webauthn/authenticate/finish'), { timeout: 120_000 })
    .catch(() => null);
  await page.getByRole('button', { name: /sign in with passkey/i, disabled: false }).first().click();
  const resp = await finishResp;

  // NOT a 500, and carrying the machine-readable discriminator the frontends key
  // on. A raw 500 here is the regression this contract was written against.
  expect(resp, 'JP4 never observed a /webauthn/authenticate/finish response').not.toBeNull();
  const status = resp.status();
  const body = await resp.json().catch(() => ({}));
  // eslint-disable-next-line no-console
  console.log(`[JOURNEY] JP4 finish — status=${status} body=${JSON.stringify(body).slice(0, 200)}`);
  expect(
    status,
    `UNKNOWN CREDENTIAL RETURNED ${status}, not 401. A stale passkey must be a typed 401 with a ` +
      `discriminator, never a raw server error (src/axum_lib.rs:120-130).`,
  ).toBe(401);
  expect(body.error).toBe('unknown_credential');
  expect(body.credential_id, 'JP4 401 did not echo the presented credential id').toBeTruthy();

  // THE SCREEN. The invariant, plus the thing that makes this screen survivable:
  // the user is told what happened and can still act.
  const screen = await settle(page, 'JP4.2 after unknown credential', { budgetMs: 60_000 });
  assertExit(screen);
  // eslint-disable-next-line no-console
  console.log(
    `[JOURNEY] JP4 screen — headings=${JSON.stringify(screen.headings)} ` +
      `controls=${JSON.stringify(screen.controls)} body=${JSON.stringify(screen.body)}`,
  );
  expect(
    screen.body,
    `JP4 showed no actionable message after a rejected passkey. The 401 body carries one; if the ` +
      `page swallows it the user sees a login screen that silently does nothing when clicked, ` +
      `which is a dead end with extra steps. body=${JSON.stringify(screen.body)}`,
  ).toMatch(/no longer valid/i);
  expect(
    screen.controls.some((c) => /sign in with passkey/i.test(c)) &&
      screen.controls.some((c) => /sign in with ethereum/i.test(c)),
    `JP4 left the user without a retry route: ${JSON.stringify(screen.controls)}. The message is ` +
      `only actionable if the actions it names are still offered.`,
  ).toBe(true);
});
