/**
 * ZZ-REPRO: reproduction probe for two reported Element Web UI bugs
 * (dev.element.inblock.io, source-built 1.12.24):
 *
 *   S1  "Settings -> Sessions" is missing a back button when drilled into
 *       a single session's details.
 *   S2  Broken avatar picture display (profile picture / user menu / room
 *       timeline — scope unknown).
 *
 * Temp probe (zz prefix). Self-contained: only reuses the already-proven
 * login flow from ew-download.spec.mjs and the already-proven
 * openSessionsTab/findDeviceListItem navigation from helpers/verify-sas.mjs
 * (ew-h3-second-device-walk.spec.mjs's docstring explains why the naive
 * `#/settings/sessions` hash route is a no-op in this build — reuse the
 * helper that actually works instead of re-deriving navigation).
 *
 * Evidence is dumped to SCRATCH/repro/*.png and SCRATCH/repro/findings.txt
 * (both created fresh on every run). No assertions on the bug hypotheses
 * themselves — this spec's job is to RECORD what happens, not to pass/fail
 * on whether the bugs exist.
 *
 * Run:
 *   ELEMENT_URL=https://dev.element.inblock.io \
 *   MATRIX_URL=https://dev.matrix.inblock.io \
 *   SIWX_URL=https://dev.siwx.inblock.io \
 *   npx playwright test ew-zz-repro-sessions-avatar
 */
import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { ELEMENT_URL, SIWX_URL, MATRIX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { openSessionsTab } from "./helpers/verify-sas.mjs";
import { loginWalletToTokens } from "./helpers/oidc-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

const SHOT_DIR =
  "/tmp/claude-1000/-home-waldknoten-01-siwx-oidc/217301e4-e5dc-48b7-9e1e-3ed16251fb53/scratchpad/repro";
const AVATAR_FILE = "/home/waldknoten-01/.aqua-matrix-test/janie-avatar.jpg";

fs.mkdirSync(SHOT_DIR, { recursive: true });
const findingsPath = path.join(SHOT_DIR, "findings.txt");
fs.writeFileSync(findingsPath, `ZZ-REPRO run started ${new Date().toISOString()}\n\n`);

function log(line) {
  const s = typeof line === "string" ? line : JSON.stringify(line);
  fs.appendFileSync(findingsPath, s + "\n");
  // eslint-disable-next-line no-console
  console.log(s);
}

let shotN = 0;
async function shot(page, name) {
  shotN += 1;
  const file = path.join(SHOT_DIR, `${String(shotN).padStart(2, "0")}-${name}.png`);
  await page.screenshot({ path: file }).catch((e) => log(`>>> SCREENSHOT FAILED ${name}: ${e}`));
  log(`>>> screenshot: ${file}`);
  return file;
}

/**
 * Collect every avatar-bearing element on the page (BaseAvatar always sets
 * data-testid="avatar-img" on the wrapper — see apps/web/src/components/views/avatars/BaseAvatar.tsx
 * in the vendored source), whether it resolved to a real <img> or fell back
 * to the initial-letter placeholder (compound-web Avatar.tsx: no src -> renders
 * getInitialLetter(name) text instead of an <img> at all).
 */
async function collectAvatars(page, label) {
  const records = await page.evaluate(() => {
    const out = [];
    // data-testid is stripped from this production build (verified empirically —
    // [data-testid="avatar-img"] matches zero nodes even where avatars visibly
    // render), so match on class name instead. BaseAvatar always adds
    // "mx_BaseAvatar" to its wrapper's className (apps/web/src/components/views/avatars/BaseAvatar.tsx
    // in the vendored source); fall back to any element whose class contains
    // "avatar" case-insensitively, plus any bare <img> pointed at _matrix media
    // that isn't already inside a matched wrapper.
    const wrapperSet = new Set();
    document.querySelectorAll('[class*="BaseAvatar" i], [class*="avatar" i]').forEach((el) => {
      // Prefer the innermost element that actually contains (or is) the avatar
      // image/letter, not an outer layout div that merely has "avatar" in a
      // descendant's class — skip if a descendant is already a better match.
      wrapperSet.add(el);
    });
    document.querySelectorAll('img').forEach((img) => {
      if (/_matrix\/(client\/v1\/)?media/.test(img.src) || /mxc:/.test(img.src)) {
        wrapperSet.add(img.closest('[class*="avatar" i]') || img);
      }
    });
    // Keep only innermost matches — drop any wrapper that CONTAINS another
    // matched wrapper, so a layout div wrapping mx_BaseAvatar doesn't also
    // get counted as its own separate "avatar element".
    const all = Array.from(wrapperSet);
    const nodes = all.filter((el) => !all.some((other) => other !== el && el.contains(other)));
    nodes.forEach((el, i) => {
      const img = el.tagName === "IMG" ? el : el.querySelector("img");
      const rect = el.getBoundingClientRect();
      out.push({
        index: i,
        wrapperTag: el.tagName,
        wrapperClass: el.className,
        ariaLabel: el.getAttribute("aria-label"),
        dataColor: el.getAttribute("data-color"),
        visible: rect.width > 0 && rect.height > 0,
        rect: { w: Math.round(rect.width), h: Math.round(rect.height) },
        hasImg: !!img,
        img: img
          ? {
              src: img.src,
              alt: img.alt,
              naturalWidth: img.naturalWidth,
              naturalHeight: img.naturalHeight,
              complete: img.complete,
            }
          : null,
        fallbackText: !img ? (el.textContent || "").trim() : null,
      });
    });
    return out;
  });
  log(`\n--- avatar snapshot: ${label} (${records.length} avatar element(s)) ---`);
  for (const r of records) {
    if (r.hasImg) {
      const broken = r.img.naturalWidth === 0 || r.img.naturalHeight === 0;
      log(
        `  [${r.index}] class="${r.wrapperClass}" aria-label="${r.ariaLabel}" ` +
          `visible=${r.visible} rect=${JSON.stringify(r.rect)} img.src=${r.img.src} ` +
          `naturalWidth=${r.img.naturalWidth} naturalHeight=${r.img.naturalHeight} ` +
          `complete=${r.img.complete} ${broken ? "*** BROKEN ***" : "ok"}`,
      );
    } else {
      log(
        `  [${r.index}] class="${r.wrapperClass}" aria-label="${r.ariaLabel}" ` +
          `visible=${r.visible} rect=${JSON.stringify(r.rect)} ` +
          `NO <img> — showing fallback text="${r.fallbackText}" (initial-letter placeholder)`,
      );
    }
  }
  return records;
}

/** Full raw HTML dump of the settings dialog content, for selector discovery
 * (written only to findings.txt, not echoed to console — this build strips
 * data-testid attributes so class names have to be read straight off the DOM). */
async function dumpFullHTML(page, label) {
  const html = await page
    .locator(".mx_SettingsDialog_content")
    .first()
    .evaluate((el) => el.outerHTML)
    .catch((e) => `<<dump failed: ${e}>>`);
  fs.appendFileSync(findingsPath, `\n\n=== FULL HTML DUMP: ${label} ===\n${html}\n=== END DUMP ===\n`);
}

/** Dump every element in the DOM that looks like a back-navigation control. */
async function dumpBackNav(page, label) {
  const info = await page.evaluate(() => {
    const vis = (el) => {
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      return {
        display: cs.display,
        visibility: cs.visibility,
        w: Math.round(r.width),
        h: Math.round(r.height),
        onscreen: r.width > 0 && r.height > 0 && cs.display !== "none" && cs.visibility !== "hidden",
      };
    };
    const sels = ['[class*="back" i]', '[aria-label*="back" i]', '[data-testid*="back" i]'];
    const seen = new Set();
    const found = [];
    for (const sel of sels) {
      document.querySelectorAll(sel).forEach((el) => {
        if (seen.has(el)) return;
        seen.add(el);
        found.push({
          matchedSelector: sel,
          tag: el.tagName,
          className: el.className,
          ariaLabel: el.getAttribute("aria-label"),
          dataTestid: el.getAttribute("data-testid"),
          text: (el.textContent || "").trim().slice(0, 60),
          outerHTML: el.outerHTML.slice(0, 500),
          visibility: vis(el),
        });
      });
    }
    const dialogHeader = document.querySelector(".mx_Dialog_header");
    const settingsContent = document.querySelector(".mx_SettingsDialog_content");
    const tabbedView = document.querySelector(".mx_TabbedView");
    return {
      backControls: found,
      dialogHeaderHTML: dialogHeader ? dialogHeader.outerHTML.slice(0, 1500) : null,
      settingsContentFirst400: settingsContent
        ? settingsContent.outerHTML.slice(0, 400)
        : null,
      tabbedViewPresent: !!tabbedView,
    };
  });
  log(`\n--- back-nav DOM dump: ${label} ---`);
  log(`  back-matching elements found: ${info.backControls.length}`);
  for (const b of info.backControls) {
    log(
      `    matched="${b.matchedSelector}" tag=${b.tag} class="${b.className}" ` +
        `aria-label="${b.ariaLabel}" data-testid="${b.dataTestid}" text="${b.text}" ` +
        `visibility=${JSON.stringify(b.visibility)}`,
    );
    log(`    outerHTML: ${b.outerHTML}`);
  }
  log(`  .mx_Dialog_header outerHTML: ${info.dialogHeaderHTML}`);
  log(`  .mx_TabbedView present: ${info.tabbedViewPresent}`);

  // Ground-truth pass: ACCESSIBLE NAME match via getByRole, computed by the
  // browser's real accessibility tree (handles aria-labelledby-to-a-portaled-
  // span, which compound-web's Tooltip/IconButton use — a raw attribute
  // grep for aria-label misses these; see BaseCard.tsx's back button, which
  // wires its label through IconButton's `tooltip` prop, not aria-label).
  const roleBackButtons = page.getByRole("button", { name: /back/i });
  const roleBackCount = await roleBackButtons.count();
  log(`  getByRole('button', name=/back/i) across whole page: count=${roleBackCount}`);
  for (let i = 0; i < roleBackCount; i++) {
    const b = roleBackButtons.nth(i);
    const visible = await b.isVisible().catch(() => false);
    const text = await b.innerText().catch(() => "<icon-only, no text>");
    const box = await b.boundingBox().catch(() => null);
    log(`    [${i}] visible=${visible} text=${JSON.stringify(text)} box=${JSON.stringify(box)}`);
  }
  info.roleBackCount = roleBackCount;
  return info;
}

test("ZZ-REPRO: session-management back button + avatar rendering", async ({ page, context }) => {
  test.setTimeout(300_000);

  // -------------------------------------------------------------------
  // Global listeners: console, page errors, non-2xx/3xx responses, media.
  // -------------------------------------------------------------------
  const consoleLines = [];
  const mediaResponses = [];
  const badResponses = [];
  const requestFailures = [];

  page.on("console", (m) => {
    const line = `[console:${m.type()}] ${m.text().slice(0, 400)}`;
    consoleLines.push(line);
    if (/error|warn/i.test(m.type())) log(line);
  });
  page.on("pageerror", (e) => {
    const line = `[pageerror] ${String(e).slice(0, 400)}`;
    consoleLines.push(line);
    log(line);
  });
  page.on("requestfailed", (r) => {
    const line = `[requestfailed] ${r.method()} ${r.url().slice(0, 160)} :: ${r.failure()?.errorText}`;
    requestFailures.push(line);
    log(line);
  });
  page.on("response", (r) => {
    const url = r.url();
    const status = r.status();
    if (/\/_matrix\/(client\/v1\/)?media\//.test(url)) {
      mediaResponses.push({ url, status });
      log(`[media] ${status} ${url.replace(/^https?:\/\/[^/]+/, "")}`);
    }
    if (status >= 400) {
      const line = `[http ${status}] ${r.request().method()} ${url.slice(0, 200)}`;
      badResponses.push(line);
      log(line);
    }
  });

  // -------------------------------------------------------------------
  // Login (mock wallet, wallet SSO through siwx) — verbatim pattern from
  // ew-download.spec.mjs, the reference working flow for this lab.
  // -------------------------------------------------------------------
  const wallet = makeWallet();
  await injectMockWallet(page, wallet);
  await page.goto(ELEMENT_URL, { waitUntil: "domcontentloaded" });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole("button", { name: "Sign in with Ethereum" }).click();

  const gateBtn = page.getByRole("button", { name: "Continue" }).first();
  const skipBtn = page.getByRole("button", { name: "Skip for now" }).first();
  for (let i = 0; i < 2; i++) {
    const which = await Promise.race([
      gateBtn.waitFor({ timeout: 20_000 }).then(() => "gate").catch(() => null),
      skipBtn.waitFor({ timeout: 20_000 }).then(() => "skip").catch(() => null),
      page
        .waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 20_000 })
        .then(() => "element")
        .catch(() => null),
    ]);
    if (which === "gate") await gateBtn.click();
    else if (which === "skip") await skipBtn.click();
    else break;
  }
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(page);
  log(`>>> logged in as ${wallet.mxid} (${wallet.did})`);
  await page.waitForTimeout(2000);

  // =====================================================================
  // S2 — AVATAR
  // =====================================================================
  log("\n\n========== S2: AVATAR REPRO ==========");

  // Open user menu -> All settings (lands on Account tab by default).
  await page.locator(".mx_UserMenu").click();
  await page.getByRole("menuitem", { name: /all settings/i }).click({ timeout: 20_000 });
  await page.locator(".mx_UserSettingsDialog").waitFor({ timeout: 20_000 });
  // Make sure we're on the Account tab (default, but be explicit).
  const accountTab = page
    .locator('[role="tab"], .mx_TabbedView_tabLabel')
    .filter({ hasText: /^account$/i })
    .first();
  if (await accountTab.count()) await accountTab.click({ timeout: 10_000 }).catch(() => {});
  await page.waitForTimeout(1000);

  await shot(page, "settings-profile-before-upload");
  await collectAvatars(page, "settings profile tab, before upload");

  // Locate the hidden avatar file input (rendered unconditionally by
  // AvatarSetting.tsx alongside the avatar-menu trigger) and upload directly —
  // Playwright's setInputFiles does not require the input to be visible, and
  // fires the same change event the app's onFileChanged listens for.
  const fileInput = page.locator('.mx_UserSettingsDialog input[type="file"]').first();
  const fileInputCount = await fileInput.count();
  log(`>>> avatar file input found: count=${fileInputCount}`);
  expect(fileInputCount, "AvatarSetting file input not found in Account tab").toBeGreaterThan(0);

  await fileInput.setInputFiles(AVATAR_FILE);
  log(`>>> set avatar file: ${AVATAR_FILE}`);

  // Wait for the "Uploading image..." toast to appear then disappear (best
  // effort — if it never appears we just wait a fixed settle window).
  const uploadingToast = page.getByText(/uploading image/i);
  await uploadingToast.waitFor({ timeout: 10_000 }).catch(() => log(">>> upload toast never appeared (or was too fast to catch)"));
  await uploadingToast.waitFor({ state: "hidden", timeout: 30_000 }).catch(() => log(">>> upload toast never disappeared within 30s"));
  await page.waitForTimeout(3000);

  await shot(page, "avatar-uploaded-settings");
  const afterUploadSettings = await collectAvatars(page, "settings profile tab, AFTER upload");

  // (b) user menu avatar — close the settings dialog and look at the top-left.
  const closeBtn = page.locator('.mx_UserSettingsDialog [aria-label="Close dialog" i], .mx_UserSettingsDialog .mx_Dialog_cancelButton').first();
  if (await closeBtn.count()) {
    await closeBtn.click({ timeout: 10_000 }).catch(() => {});
  } else {
    await page.keyboard.press("Escape");
  }
  await page.locator(".mx_UserSettingsDialog").waitFor({ state: "hidden", timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(1500);
  await shot(page, "user-menu-avatar");
  const userMenuAvatars = await collectAvatars(page, "app shell (user menu top-left)");

  // (c) room timeline avatar — create a room via the live client, send a message.
  const roomId = await page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({ name: "avatar-probe", preset: "private_chat" });
    return r.room_id;
  });
  log(`>>> created probe room ${roomId}`);
  await page.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, roomId);
  await page.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 });
  await page.locator(".mx_MessageComposer [contenteditable], .mx_MessageComposer textarea").first().click();
  await page.keyboard.type("avatar repro probe message");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(4000);

  await shot(page, "timeline-avatar");
  const timelineAvatars = await collectAvatars(page, "room timeline (after own message)");

  const allAvatarRecords = { afterUploadSettings, userMenuAvatars, timelineAvatars };
  const anyBroken = [...afterUploadSettings, ...userMenuAvatars, ...timelineAvatars].some(
    (r) => r.hasImg && (r.img.naturalWidth === 0 || r.img.naturalHeight === 0),
  );
  const anyFallback = [...afterUploadSettings, ...userMenuAvatars, ...timelineAvatars].some((r) => !r.hasImg);
  log(
    `\n>>> S2 SUMMARY: anyBrokenImg(naturalWidth/Height==0)=${anyBroken} anyFallbackToInitials=${anyFallback}`,
  );
  log(`>>> S2 media responses so far: ${JSON.stringify(mediaResponses)}`);

  // =====================================================================
  // S1 — SESSIONS / BACK BUTTON
  // =====================================================================
  log("\n\n========== S1: SESSIONS BACK-BUTTON REPRO ==========");

  // Create a SECOND session for the SAME wallet on a fresh page (headless
  // OIDC token flow — no full Element boot needed) so the Sessions tab has
  // an "other sessions" entry to drill into, not just the current one.
  let secondSession = null;
  try {
    const page2 = await context.newPage();
    secondSession = await loginWalletToTokens(page2, {
      siwxUrl: SIWX_URL,
      matrixUrl: MATRIX_URL,
      wallet,
    });
    log(`>>> second session created: device_id=${secondSession.device_id}`);
    await page2.close();
  } catch (e) {
    log(`>>> could not create a second session (continuing with current-session-only): ${String(e).slice(0, 300)}`);
  }

  await openSessionsTab(page);
  await page.locator('.mx_UserSettingsDialog').waitFor({ timeout: 20_000 });
  await page.waitForTimeout(2000);

  await shot(page, "sessions-tab");
  await dumpBackNav(page, "Sessions tab, top level (before drilling in)");
  await dumpFullHTML(page, "Sessions tab, top level (before drilling in)");

  // This build strips data-testid attributes (verified empirically for
  // avatars above), so drive the "Current session" row the way a user does:
  // by its visible text / row, discovered from the DOM dump rather than
  // guessed selectors from the vendored source snapshot (whose accordion
  // design (chevron-DOWN inline expand) does not match what's on screen here
  // — the live build shows a chevron-RIGHT "push to a screen" affordance).
  const currentSessionHeading = page.getByText("Current session", { exact: true }).first();
  await currentSessionHeading.waitFor({ timeout: 15_000 }).catch(() => log(">>> 'Current session' heading not found"));
  // The row is the nearest clickable ancestor/sibling containing the device
  // name + "Verified"/"Last activity" metadata that follows the heading.
  const currentRow = page
    .locator('[class*="Tile" i], [class*="session" i], [role="button"], button, a')
    .filter({ hasText: /last activity/i })
    .first();
  const hasCurrentRow = (await currentRow.count()) > 0;
  log(`>>> current-session row (matched by 'last activity' text) present: ${hasCurrentRow}`);
  if (hasCurrentRow) {
    const rowText = await currentRow.innerText().catch(() => "<unreadable>");
    log(`>>> current-session row text: ${JSON.stringify(rowText)}`);
    await currentRow.click({ timeout: 10_000 }).catch((e) => log(`>>> current-session row click failed: ${e}`));
    await page.waitForTimeout(1500);
    await shot(page, "session-details-current");
    await dumpBackNav(page, "Sessions tab, CURRENT session drilled in");
    await dumpFullHTML(page, "Sessions tab, CURRENT session drilled in");

    // Can we get back without closing the whole dialog? Try, in order: (1) a
    // REAL button whose ACCESSIBLE NAME (not raw class/attribute — this build
    // strips data-testid, and compound-web's IconButton wires its tooltip text
    // via aria-labelledby to a portaled span, not a plain aria-label, so a
    // naive `[class*="back" i]` / `[aria-label*="back" i]` attribute selector
    // both misses real back buttons AND wrongly matches `.mx_Dialog_background`
    // — the modal backdrop div, which merely contains "background" — clicking
    // it hung a prior run for the full budget) contains "back", scoped inside
    // the dialog so we never touch the backdrop; (2) the Sessions tab in the
    // left nav (a "soft back" a user might try); (3) Escape.
    const dialogVisibleBefore = await page.locator(".mx_UserSettingsDialog").isVisible();
    const explicitBackBtn = page
      .locator(".mx_UserSettingsDialog")
      .getByRole("button", { name: /back/i })
      .first();
    const explicitBackCount = await explicitBackBtn.count();
    log(`>>> explicit back button (accessible-name match, scoped inside the dialog) present: ${explicitBackCount > 0}`);

    if (explicitBackCount > 0) {
      // Tight timeout: fail fast on a bad match instead of burning the whole
      // test budget on Playwright's actionability retry loop.
      await explicitBackBtn.click({ timeout: 5000 }).catch((e) => log(`>>> explicit back click failed: ${e}`));
      await page.waitForTimeout(1000);
      const dialogVisibleAfter = await page.locator(".mx_UserSettingsDialog").isVisible();
      log(`>>> after clicking explicit back control: dialog still open=${dialogVisibleAfter}`);
      await shot(page, "session-details-current-after-explicit-back");
    } else {
      // Re-click the Sessions tab in the left nav — the only other in-dialog
      // affordance that plausibly returns to the list without closing the dialog.
      const sessionsTabLink = page
        .locator('[role="tab"], .mx_TabbedView_tabLabel')
        .filter({ hasText: /^sessions$/i })
        .first();
      const sessionsTabCount = await sessionsTabLink.count();
      log(`>>> no explicit back control; trying the left-nav 'Sessions' tab link instead (present=${sessionsTabCount > 0})`);
      if (sessionsTabCount > 0) {
        await sessionsTabLink.click({ timeout: 10_000 }).catch((e) => log(`>>> sessions-tab re-click failed: ${e}`));
        await page.waitForTimeout(1000);
      }
      const dialogVisibleAfter = await page.locator(".mx_UserSettingsDialog").isVisible();
      const backOnListNow = await page.getByText("Current session", { exact: true }).first().isVisible().catch(() => false);
      log(
        `>>> after re-clicking 'Sessions' nav tab: dialog still open=${dialogVisibleAfter}, ` +
          `back-on-list-view(saw 'Current session' heading again)=${backOnListNow}`,
      );
      await shot(page, "session-details-current-after-nav-reclick");
    }
    log(`>>> dialog was open before drill-in=${dialogVisibleBefore}`);
  } else {
    log(">>> could not locate a clickable current-session row — cannot test drill-in for current session");
  }

  // --- other session (if the second login succeeded) ---
  const otherHeading = page.getByText(/other session/i).first();
  const hasOtherHeading = (await otherHeading.count()) > 0;
  log(`>>> 'Other sessions' heading present: ${hasOtherHeading}`);
  if (hasOtherHeading) {
    await otherHeading.scrollIntoViewIfNeeded().catch(() => {});
    await shot(page, "other-sessions-section");
    // Any row below the heading that isn't the current session.
    const otherRow = page
      .locator('[class*="Tile" i], [role="button"], button, a')
      .filter({ hasText: /siwx|last activity/i })
      .nth(1); // [0] is typically the current session row already handled above
    const otherRowCount = await otherRow.count();
    log(`>>> other-session candidate rows found: ${otherRowCount}`);
    if (otherRowCount > 0) {
      const otherRowText = await otherRow.innerText().catch(() => "<unreadable>");
      log(`>>> other-session row text: ${JSON.stringify(otherRowText)}`);
      await otherRow.click({ timeout: 10_000 }).catch((e) => log(`>>> other-session row click failed: ${e}`));
      await page.waitForTimeout(1500);
      await shot(page, "session-details-other");
      await dumpBackNav(page, "Sessions tab, OTHER session drilled in");
      await dumpFullHTML(page, "Sessions tab, OTHER session drilled in");

      const dialogVisible2 = await page.locator(".mx_UserSettingsDialog").isVisible();
      log(`>>> after drilling into OTHER session: dialog still open=${dialogVisible2}`);
    }
  } else {
    log(">>> no 'Other sessions' section found (second-session creation may not have propagated yet, or that section is titled differently — see full HTML dump)");
  }

  // -------------------------------------------------------------------
  // Findings summary tail.
  // -------------------------------------------------------------------
  log("\n\n========== RUN SUMMARY ==========");
  log(`console lines captured: ${consoleLines.length}`);
  log(`request failures: ${requestFailures.length}`);
  log(`non-2xx/3xx responses: ${badResponses.length}`);
  log(`media (_matrix media) responses: ${mediaResponses.length}`);
  log(`avatar records (post-upload settings / user-menu / timeline): ${JSON.stringify(allAvatarRecords).slice(0, 4000)}`);

  fs.appendFileSync(
    findingsPath,
    `\n\n--- ALL CONSOLE LINES (${consoleLines.length}) ---\n` + consoleLines.join("\n") + "\n",
  );
  fs.appendFileSync(
    findingsPath,
    `\n--- ALL NON-2xx/3xx RESPONSES (${badResponses.length}) ---\n` + badResponses.join("\n") + "\n",
  );
  fs.appendFileSync(
    findingsPath,
    `\n--- ALL REQUEST FAILURES (${requestFailures.length}) ---\n` + requestFailures.join("\n") + "\n",
  );
  fs.appendFileSync(
    findingsPath,
    `\n--- ALL MEDIA RESPONSES (${mediaResponses.length}) ---\n` +
      mediaResponses.map((m) => `${m.status} ${m.url}`).join("\n") +
      "\n",
  );

  // This spec's purpose is evidence collection, not pass/fail on the bug
  // hypotheses. The only hard assertion is that the probe actually ran the
  // steps (avatar input existed, sessions tab opened) — already asserted
  // above / implicit in the waitFor calls not throwing.
  expect(true).toBe(true);
});
