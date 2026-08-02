/**
 * ZZ-REPRO2: three follow-up reproduction probes for the S1/S2 Element Web
 * bug reports (dev.element.inblock.io, source-built 1.12.24), run after the
 * first pass (ew-zz-repro-sessions-avatar.spec.mjs) found:
 *   - avatars render fine at the settings/user-menu/timeline surfaces tested
 *     so far (all naturalWidth/Height > 0, no broken <img>s)
 *   - Settings -> Sessions has NO back-button mechanism at all in this build
 *     (neither the vendored-source accordion pattern nor an explicit "back"
 *     control) — the drilled-in session view is reached by pushing a new
 *     screen, and the only way back is re-clicking the "Sessions" tab
 *
 * This file probes three narrower hypotheses for where S1/S2 might actually
 * live:
 *   A. Settings/Sessions back button at NARROW viewport (480x800, 375x667) —
 *      TabbedView's `mx_TabbedView_responsive` class only hides tab-label
 *      TEXT below 1024px per the vendored CSS (_TabbedView.pcss) and adds no
 *      back mechanism, but the live deployed build may differ from that
 *      vendored snapshot, or the dialog may simply become unusable at phone
 *      width without any affordance to prove/disprove except by looking.
 *   B. DM avatar propagation race — a DM room's avatar (the OTHER member's
 *      profile picture) may show the initial-letter fallback if their
 *      profile info arrives after first render, and never self-heal until a
 *      full reload.
 *   C. Right-panel member-info "back" button (BaseCard.tsx: a real
 *      ChevronLeft back button IS coded, but only rendered when
 *      `rightPanelStore.roomPhaseHistory.length > 1` — i.e. only when the
 *      member-info card was reached via a PRIOR card, not when opened
 *      directly from a timeline avatar click). Tests both the 1-hop
 *      (direct, back expected ABSENT by design) and 2/3-hop (via Room info
 *      -> People, back expected PRESENT and functional) paths so an absence
 *      in the 1-hop case isn't mistaken for the bug.
 *
 * Same lab, same login flow as ew-zz-repro-sessions-avatar.spec.mjs. Findings
 * go to a SEPARATE file (findings2.txt) to avoid clobbering pass 1's evidence.
 *
 * Run:
 *   ELEMENT_URL=https://dev.element.inblock.io \
 *   MATRIX_URL=https://dev.matrix.inblock.io \
 *   SIWX_URL=https://dev.siwx.inblock.io \
 *   npx playwright test ew-zz-repro2-narrow-and-dm
 */
import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { ELEMENT_URL, SIWX_URL, MATRIX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

const SHOT_DIR =
  "/tmp/claude-1000/-home-waldknoten-01-siwx-oidc/217301e4-e5dc-48b7-9e1e-3ed16251fb53/scratchpad/repro";
const AVATAR_FILE = "/home/waldknoten-01/.aqua-matrix-test/janie-avatar.jpg";

fs.mkdirSync(SHOT_DIR, { recursive: true });
const findingsPath = path.join(SHOT_DIR, "findings2.txt");
fs.writeFileSync(findingsPath, `ZZ-REPRO2 run started ${new Date().toISOString()}\n\n`);

function log(line) {
  const s = typeof line === "string" ? line : JSON.stringify(line);
  fs.appendFileSync(findingsPath, s + "\n");
  // eslint-disable-next-line no-console
  console.log(s);
}

let shotN = 9; // continue numbering after pass 1's 01-08
async function shot(page, name) {
  shotN += 1;
  const file = path.join(SHOT_DIR, `${String(shotN).padStart(2, "0")}-${name}.png`);
  await page.screenshot({ path: file }).catch((e) => log(`>>> SCREENSHOT FAILED ${name}: ${e}`));
  log(`>>> screenshot: ${file}`);
  return file;
}

/** Same generic, selector-agnostic avatar collector as pass 1 (data-testid is
 * stripped in this production build — proven empirically in pass 1). */
async function collectAvatars(page, label) {
  const records = await page.evaluate(() => {
    const wrapperSet = new Set();
    document.querySelectorAll('[class*="BaseAvatar" i], [class*="avatar" i]').forEach((el) => wrapperSet.add(el));
    document.querySelectorAll("img").forEach((img) => {
      if (/_matrix\/(client\/v1\/)?media/.test(img.src) || /mxc:/.test(img.src)) {
        wrapperSet.add(img.closest('[class*="avatar" i]') || img);
      }
    });
    const all = Array.from(wrapperSet);
    const nodes = all.filter((el) => !all.some((other) => other !== el && el.contains(other)));
    const out = [];
    nodes.forEach((el, i) => {
      const img = el.tagName === "IMG" ? el : el.querySelector("img");
      const rect = el.getBoundingClientRect();
      out.push({
        index: i,
        wrapperClass: el.className,
        ariaLabel: el.getAttribute("aria-label"),
        visible: rect.width > 0 && rect.height > 0,
        rect: { w: Math.round(rect.width), h: Math.round(rect.height) },
        hasImg: !!img,
        img: img
          ? {
              src: img.src,
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
        `  [${r.index}] class="${r.wrapperClass}" aria-label="${r.ariaLabel}" visible=${r.visible} ` +
          `rect=${JSON.stringify(r.rect)} img.src=${r.img.src} naturalWidth=${r.img.naturalWidth} ` +
          `naturalHeight=${r.img.naturalHeight} complete=${r.img.complete} ${broken ? "*** BROKEN ***" : "ok"}`,
      );
    } else {
      log(
        `  [${r.index}] class="${r.wrapperClass}" aria-label="${r.ariaLabel}" visible=${r.visible} ` +
          `rect=${JSON.stringify(r.rect)} NO <img> — fallback text="${r.fallbackText}"`,
      );
    }
  }
  return records;
}

/** Accessible-name back-button scan (ground truth — see pass-1 postmortem:
 * raw attribute selectors both miss compound-web's aria-labelledby-wired
 * tooltips AND false-positive-match the dialog backdrop). Scoped to `root`
 * (a locator) to avoid ever touching page chrome outside it. */
async function scanBackButtons(page, root, label) {
  const scope = root ?? page;
  const buttons = scope.getByRole("button", { name: /back/i });
  const count = await buttons.count();
  log(`\n--- accessible-name back-button scan: ${label} — count=${count} ---`);
  const results = [];
  for (let i = 0; i < count; i++) {
    const b = buttons.nth(i);
    const visible = await b.isVisible().catch(() => false);
    const text = await b.innerText().catch(() => "<icon-only>");
    const box = await b.boundingBox().catch(() => null);
    log(`  [${i}] visible=${visible} text=${JSON.stringify(text)} box=${JSON.stringify(box)}`);
    results.push({ visible, text, box });
  }
  return { count, results };
}

/** Tolerant wallet-SSO login (verbatim pattern from ew-download.spec.mjs /
 * ew-zz-repro-sessions-avatar.spec.mjs): handles the optional new-account
 * "Continue" gate and the passkey-link "Skip for now" offer in either order. */
async function loginViaWalletUI(page, wallet) {
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
    if (which === "gate") await gateBtn.click({ timeout: 10_000 });
    else if (which === "skip") await skipBtn.click({ timeout: 10_000 });
    else break;
  }
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(page);
}

function wireListeners(page, tag) {
  page.on("console", (m) => {
    if (/error|warn/i.test(m.type())) log(`[${tag}:console:${m.type()}] ${m.text().slice(0, 300)}`);
  });
  page.on("pageerror", (e) => log(`[${tag}:pageerror] ${String(e).slice(0, 300)}`));
  page.on("requestfailed", (r) => log(`[${tag}:requestfailed] ${r.method()} ${r.url().slice(0, 160)}`));
  page.on("response", (r) => {
    const status = r.status();
    if (status >= 400) log(`[${tag}:http ${status}] ${r.request().method()} ${r.url().slice(0, 200)}`);
    if (/\/_matrix\/(client\/v1\/)?media\//.test(r.url())) log(`[${tag}:media] ${status} ${r.url().replace(/^https?:\/\/[^/]+/, "")}`);
  });
}

// =========================================================================
// A — narrow viewport back button
// =========================================================================
test("ZZ-REPRO2 A: Settings/Sessions back button at narrow viewport widths", async ({ page }) => {
  test.setTimeout(300_000);
  wireListeners(page, "A");

  const wallet = makeWallet();
  await loginViaWalletUI(page, wallet);
  log(`>>> [A] logged in as ${wallet.mxid}`);
  await page.waitForTimeout(1500);

  for (const vp of [
    { w: 1280, h: 800, label: "1280x800-baseline" },
    { w: 480, h: 800, label: "480x800" },
    { w: 375, h: 667, label: "375x667-phone" },
  ]) {
    log(`\n\n========== [A] viewport ${vp.label} ==========`);
    await page.setViewportSize({ width: vp.w, height: vp.h });
    await page.waitForTimeout(500);

    await page.locator(".mx_UserMenu").click({ timeout: 10_000 });
    await page.getByRole("menuitem", { name: /all settings/i }).click({ timeout: 20_000 });
    await page.locator(".mx_UserSettingsDialog").waitFor({ timeout: 20_000 });
    const sessionsTabLink = page
      .locator('[role="tab"], .mx_TabbedView_tabLabel')
      .filter({ hasText: /sessions/i })
      .first();
    await sessionsTabLink.click({ timeout: 20_000 });
    await page.waitForTimeout(1500);

    await shot(page, `narrow-${vp.label}-sessions-top`);

    const geom = await page.evaluate(() => {
      const rectOf = (el) => {
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { w: Math.round(r.width), h: Math.round(r.height), x: Math.round(r.x), y: Math.round(r.y) };
      };
      const tabs = document.querySelector(".mx_TabbedView_tabLabels");
      const panel = document.querySelector(".mx_TabbedView_tabPanel");
      const dlg = document.querySelector(".mx_UserSettingsDialog");
      return {
        tabsRect: rectOf(tabs),
        tabsDisplay: tabs ? getComputedStyle(tabs).display : null,
        panelRect: rectOf(panel),
        dialogRect: rectOf(dlg),
        tabbedViewClasses: document.querySelector(".mx_TabbedView")?.className ?? null,
      };
    });
    log(`>>> [A] ${vp.label} geometry: ${JSON.stringify(geom)}`);

    await scanBackButtons(page, page.locator(".mx_UserSettingsDialog"), `[A] ${vp.label} Sessions top level`);

    // Drill into the current session and re-check.
    const currentRow = page
      .locator('[role="button"], button, a')
      .filter({ hasText: /last activity/i })
      .first();
    if (await currentRow.count()) {
      await currentRow.click({ timeout: 10_000 }).catch((e) => log(`>>> [A] ${vp.label} current-row click failed: ${e}`));
      await page.waitForTimeout(1200);
      await shot(page, `narrow-${vp.label}-session-details`);
      const scan = await scanBackButtons(page, page.locator(".mx_UserSettingsDialog"), `[A] ${vp.label} drilled into current session`);
      log(`>>> [A] ${vp.label} SUMMARY: back-button count when drilled in = ${scan.count}`);
    } else {
      log(`>>> [A] ${vp.label}: could not find current-session row to drill into`);
    }

    // Close for the next viewport iteration.
    await page.keyboard.press("Escape");
    await page.waitForTimeout(500);
  }

  expect(true).toBe(true);
});

// =========================================================================
// B/C — DM avatar propagation race + right-panel member-info back button
// =========================================================================
test("ZZ-REPRO2 B/C: DM avatar propagation race + right-panel member back button", async ({ browser }) => {
  test.setTimeout(300_000);

  const contextA = await browser.newContext();
  const contextB = await browser.newContext();
  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();
  wireListeners(pageA, "A");
  wireListeners(pageB, "B");

  const walletA = makeWallet();
  const walletB = makeWallet();

  await loginViaWalletUI(pageA, walletA);
  log(`>>> [B/C] A logged in: ${walletA.mxid} (${walletA.did})`);

  // A uploads an avatar BEFORE the DM is created, so B's first-render of the
  // DM room has a real avatar to (fail to) fetch — the race under test is
  // "profile arrives after room-list/timeline first paint", not "no avatar
  // was ever set".
  await pageA.locator(".mx_UserMenu").click({ timeout: 10_000 });
  await pageA.getByRole("menuitem", { name: /all settings/i }).click({ timeout: 20_000 });
  await pageA.locator(".mx_UserSettingsDialog").waitFor({ timeout: 20_000 });
  const fileInput = pageA.locator('.mx_UserSettingsDialog input[type="file"]').first();
  await fileInput.setInputFiles(AVATAR_FILE);
  const uploadingToast = pageA.getByText(/uploading image/i);
  await uploadingToast.waitFor({ timeout: 10_000 }).catch(() => {});
  await uploadingToast.waitFor({ state: "hidden", timeout: 30_000 }).catch(() => {});
  await pageA.waitForTimeout(2000);
  log(">>> [B/C] A's avatar uploaded");
  await pageA.keyboard.press("Escape");
  await pageA.waitForTimeout(500);

  await loginViaWalletUI(pageB, walletB);
  log(`>>> [B/C] B logged in: ${walletB.mxid} (${walletB.did})`);
  await pageB.waitForTimeout(1000);

  // B creates a DM with A (client-level, like ew-download/ew-media-burst do
  // for rooms — the ceremony under test is avatar rendering, not the
  // "start chat" UI flow) and marks it via m.direct account data so Element
  // treats it as a real DM (useDmMember / DMRoomMap).
  const dmRoomId = await pageB.evaluate(async (aMxid) => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({ preset: "trusted_private_chat", is_direct: true, invite: [aMxid] });
    let direct = {};
    try {
      direct = (await cli.getAccountDataFromServer("m.direct")) || {};
    } catch {
      /* ignore, start fresh */
    }
    direct[aMxid] = [...(direct[aMxid] || []), r.room_id];
    await cli.setAccountData("m.direct", direct);
    return r.room_id;
  }, walletA.mxid);
  log(`>>> [B/C] DM room created: ${dmRoomId}`);

  // A joins.
  await pageA.evaluate(async (rid) => {
    const cli = window.mxMatrixClientPeg.get();
    await cli.joinRoom(rid);
  }, dmRoomId);
  log(">>> [B/C] A joined the DM");
  await pageA.waitForTimeout(1500);

  // A sends a message so there's a timeline event to click on for scenario C.
  await pageA.evaluate(async (rid) => {
    const cli = window.mxMatrixClientPeg.get();
    await cli.sendTextMessage(rid, "hello from A (DM avatar + back-button probe)");
  }, dmRoomId);
  log(">>> [B/C] A sent a message");

  // --- B: navigate to the DM room FRESH (first paint = the race window) ---
  await pageB.evaluate((rid) => {
    window.location.hash = `#/room/${rid}`;
  }, dmRoomId);
  await pageB.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 }).catch((e) => log(`>>> [B/C] B composer wait failed: ${e}`));
  await pageB.waitForTimeout(2500);

  await shot(pageB, "dm-b-view-first-paint");
  const dmAvatarsFirstPaint = await collectAvatars(pageB, "B's view of DM room, FIRST PAINT (race window)");

  // --- B: full reload — does the SAME avatar self-heal, or stay broken? ---
  await pageB.reload({ waitUntil: "domcontentloaded" });
  await pageB.waitForTimeout(4000);
  const onRoom = await pageB.locator(".mx_MessageComposer").isVisible().catch(() => false);
  if (!onRoom) {
    await pageB.evaluate((rid) => {
      window.location.hash = `#/room/${rid}`;
    }, dmRoomId);
    await pageB.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 }).catch(() => {});
  }
  await pageB.waitForTimeout(2000);

  await shot(pageB, "dm-b-view-after-reload");
  const dmAvatarsAfterReload = await collectAvatars(pageB, "B's view of DM room, AFTER RELOAD");

  const initialsBeforeReload = dmAvatarsFirstPaint.filter((r) => !r.hasImg).length;
  const initialsAfterReload = dmAvatarsAfterReload.filter((r) => !r.hasImg).length;
  log(
    `\n>>> [B/C] S2-DM SUMMARY: avatar-elements-showing-initials-fallback ` +
      `firstPaint=${initialsBeforeReload}/${dmAvatarsFirstPaint.length} ` +
      `afterReload=${initialsAfterReload}/${dmAvatarsAfterReload.length} ` +
      `(if firstPaint has more fallbacks than afterReload, that's the propagation-race signature)`,
  );

  // =======================================================================
  // C — right-panel member-info back button
  // =======================================================================
  log("\n\n========== [C] right-panel member-info back button ==========");

  // --- 1-hop: click the sender's name/avatar directly in the timeline. ---
  // Per BaseCard.tsx, a back button only renders when
  // rightPanelStore.roomPhaseHistory.length > 1 — opening MemberInfo as the
  // FIRST card should legitimately show NO back button. This is expected,
  // not a bug — recorded explicitly so it isn't misread as one.
  const senderEl = pageB
    .locator('[class*="EventTile_avatar" i], [class*="SenderProfile" i], [class*="DisambiguatedProfile" i]')
    .first();
  const hasSenderEl = (await senderEl.count()) > 0;
  log(`>>> [C] sender avatar/name element in timeline present: ${hasSenderEl}`);
  if (hasSenderEl) {
    await senderEl.click({ timeout: 10_000 }).catch((e) => log(`>>> [C] sender element click failed: ${e}`));
    await pageB.waitForTimeout(1500);
    await shot(pageB, "rightpanel-memberinfo-1hop");
    const rightPanelPresent = (await pageB.locator('[class*="BaseCard" i]').count()) > 0;
    log(`>>> [C] 1-hop: right-panel card present=${rightPanelPresent}`);
    if (rightPanelPresent) {
      const scan1 = await scanBackButtons(pageB, pageB.locator('[class*="BaseCard" i]').first(), "[C] 1-hop MemberInfo (direct from timeline)");
      log(`>>> [C] 1-hop SUMMARY: back-button count=${scan1.count} (expected 0 by design — no prior card in history)`);
      // Close button should still exist so the user isn't trapped.
      const closeScan = await pageB.locator('[class*="BaseCard" i]').first().getByRole("button", { name: /close/i }).count();
      log(`>>> [C] 1-hop: close-button count=${closeScan}`);
    }
  }

  // --- 2/3-hop: Room info -> People -> member (a real card-history chain). ---
  const roomInfoBtn = pageB.getByRole("button", { name: /room info/i }).first();
  const hasRoomInfoBtn = (await roomInfoBtn.count()) > 0;
  log(`>>> [C] "Room info" header button present: ${hasRoomInfoBtn}`);
  if (hasRoomInfoBtn) {
    await roomInfoBtn.click({ timeout: 10_000 }).catch((e) => log(`>>> [C] Room info click failed: ${e}`));
    await pageB.waitForTimeout(1200);
    await shot(pageB, "rightpanel-roominfo");
    const scanRoomInfo = await scanBackButtons(pageB, pageB.locator('[class*="BaseCard" i]').first(), "[C] Room info (1st card, back expected ABSENT)");
    log(`>>> [C] Room info SUMMARY: back-button count=${scanRoomInfo.count} (expected 0 — first card)`);

    const peopleEntry = pageB.getByText(/^people$/i).first();
    const hasPeopleEntry = (await peopleEntry.count()) > 0;
    log(`>>> [C] "People" entry in Room info present: ${hasPeopleEntry}`);
    if (hasPeopleEntry) {
      await peopleEntry.click({ timeout: 10_000 }).catch((e) => log(`>>> [C] People click failed: ${e}`));
      await pageB.waitForTimeout(1200);
      await shot(pageB, "rightpanel-memberlist-2hop");
      const scanMemberList = await scanBackButtons(pageB, pageB.locator('[class*="BaseCard" i]').first(), "[C] MemberList (2nd card, back expected PRESENT)");
      log(`>>> [C] MemberList SUMMARY: back-button count=${scanMemberList.count} (expected >=1 — second card in history)`);

      if (scanMemberList.count > 0) {
        // Prove it actually WORKS: click it, confirm we land back on Room info
        // without the whole right panel closing.
        const backBtn = pageB.locator('[class*="BaseCard" i]').first().getByRole("button", { name: /back/i }).first();
        await backBtn.click({ timeout: 5000 }).catch((e) => log(`>>> [C] back-button click failed: ${e}`));
        await pageB.waitForTimeout(1000);
        await shot(pageB, "rightpanel-after-back-click");
        const rightPanelStillOpen = (await pageB.locator('[class*="BaseCard" i]').count()) > 0;
        log(`>>> [C] after clicking back from MemberList: right panel still open=${rightPanelStillOpen}`);
      }

      // Now go one level deeper: click an actual member row for the 3rd card.
      const memberRow = pageB.locator('[class*="MemberList" i] [role="button"], [class*="MemberList" i] li').first();
      if (await memberRow.count()) {
        await memberRow.click({ timeout: 10_000 }).catch((e) => log(`>>> [C] member row click failed: ${e}`));
        await pageB.waitForTimeout(1200);
        await shot(pageB, "rightpanel-memberinfo-3hop");
        const scanMemberInfo3 = await scanBackButtons(pageB, pageB.locator('[class*="BaseCard" i]').first(), "[C] MemberInfo via People list (3rd card, back expected PRESENT)");
        log(`>>> [C] MemberInfo-3hop SUMMARY: back-button count=${scanMemberInfo3.count} (expected >=1)`);
      } else {
        log(">>> [C] no member row found in MemberList to drill into");
      }
    }
  }

  expect(true).toBe(true);
});
