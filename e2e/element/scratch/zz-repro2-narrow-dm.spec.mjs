/**
 * ZZ-REPRO2: targeted second pass for the 2026-08-01 reports, covering the
 * conditions the wide-viewport single-account first pass could not see:
 *
 *   R2-1  NARROW viewport (480x800, then 375x667): Settings -> Sessions in
 *         mx_TabbedView_responsive collapsed mode. The responsive back
 *         control in the dialog is the ONLY back button that screen ever
 *         has — record whether it exists, is visible, and works.
 *   R2-2  DM avatar (upstream #31856): account B opens a DM with account A
 *         (who has a profile picture). Record whether B sees A's photo or
 *         an initial-letter fallback in the room header, before AND after
 *         a reload (the bug is a first-render race).
 *   R2-3  Right-panel member-info card (BaseCard) back chevron — the code
 *         upstream refactored in 1.12.20->1.12.24 (singleton -> context).
 *
 * Evidence: SCRATCH/repro2/*.png + findings2.txt. Records, not assertions.
 *
 * Run:
 *   ELEMENT_URL=https://dev.element.inblock.io \
 *   MATRIX_URL=https://dev.matrix.inblock.io \
 *   SIWX_URL=https://dev.siwx.inblock.io \
 *   npx playwright test ew-zz-repro2-narrow-dm
 */
import { test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { ELEMENT_URL, SIWX_URL, MATRIX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

const SHOT_DIR =
  "/tmp/claude-1000/-home-waldknoten-01-siwx-oidc/217301e4-e5dc-48b7-9e1e-3ed16251fb53/scratchpad/repro2";
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

async function shot(page, name) {
  const file = path.join(SHOT_DIR, `${name}.png`);
  await page.screenshot({ path: file }).catch((e) => log(`>>> SCREENSHOT FAILED ${name}: ${e}`));
  log(`>>> screenshot: ${file}`);
}

// Verbatim working login flow (ew-download.spec.mjs pattern).
async function login(page) {
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
  await page.waitForTimeout(2000);
  const uid = await page.evaluate(() => localStorage.getItem("mx_user_id"));
  log(`>>> logged in: ${uid}`);
  return { wallet, uid };
}

// In-page client API call. The localStorage mx_access_token goes stale under
// this deployment's 300 s token rotation (observed: M_UNKNOWN_TOKEN), so ask
// the LIVE MatrixClient for its current token instead (mxMatrixClientPeg is
// exposed on window by Element Web).
async function api(page, method, pathq, body) {
  return await page.evaluate(
    async ({ method, pathq, body, base }) => {
      const cli = window.mxMatrixClientPeg?.get?.();
      const tok = cli?.getAccessToken?.() || localStorage.getItem("mx_access_token");
      const r = await fetch(base + pathq, {
        method,
        headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      return { status: r.status, json: await r.json().catch(() => null) };
    },
    { method, pathq, body, base: MATRIX_URL },
  );
}

// Dump every plausible back-navigation control in the dialog / card region.
async function dumpBackControls(page, label) {
  const rec = await page.evaluate(() => {
    const sels = [
      '[class*="BaseCard_back" i]',
      '[class*="backButton" i]',
      '[aria-label*="back" i]',
      '[data-testid*="back" i]',
      ".mx_Dialog_header [role=button]",
      ".mx_Dialog_header button",
      '[class*="TabbedView"] [role=button]',
    ];
    const seen = new Set();
    const out = [];
    for (const sel of sels) {
      document.querySelectorAll(sel).forEach((el) => {
        if (seen.has(el)) return;
        seen.add(el);
        const cls = String(el.className);
        if (cls.includes("Dialog_background")) return; // scrim, not a control
        const r = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        out.push({
          sel,
          tag: el.tagName,
          cls: cls.slice(0, 120),
          aria: el.getAttribute("aria-label"),
          text: (el.textContent || "").slice(0, 40),
          visible: cs.display !== "none" && cs.visibility !== "hidden" && r.width > 0 && r.height > 0,
          rect: { w: Math.round(r.width), h: Math.round(r.height) },
        });
      });
    }
    return out;
  });
  log(`--- back controls @ ${label}: ${rec.length} candidates ---`);
  for (const r of rec) log(`    ${JSON.stringify(r)}`);
  return rec;
}

async function describeHeaderAvatar(page, label) {
  const rec = await page.evaluate(() => {
    const header = document.querySelector('[class*="RoomHeader" i], header');
    if (!header) return { found: false };
    const img = header.querySelector("img");
    if (img)
      return {
        found: true,
        kind: "img",
        src: img.src.slice(0, 160),
        naturalWidth: img.naturalWidth,
        naturalHeight: img.naturalHeight,
        complete: img.complete,
      };
    const av = header.querySelector('[class*="avatar" i]');
    return {
      found: !!av,
      kind: "fallback",
      cls: av ? String(av.className).slice(0, 120) : null,
      text: av ? (av.textContent || "").slice(0, 10) : null,
    };
  });
  log(`>>> header avatar @ ${label}: ${JSON.stringify(rec)}`);
  return rec;
}

test("R2-1: narrow-viewport Settings->Sessions back control", async ({ browser }) => {
  test.setTimeout(300_000);
  const ctx = await browser.newContext({ viewport: { width: 480, height: 800 } });
  const page = await ctx.newPage();
  page.on("console", (m) => {
    if (m.type() === "error") log(`[console:error] ${m.text().slice(0, 160)}`);
  });
  await login(page);

  for (const vp of [
    { width: 480, height: 800, tag: "480x800" },
    { width: 375, height: 667, tag: "375x667" },
  ]) {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.waitForTimeout(500);
    log(`\n===== R2-1 viewport ${vp.tag} =====`);
    await page.locator(".mx_UserMenu").click();
    await page.getByRole("menuitem", { name: /all settings/i }).click({ timeout: 20_000 });
    await page.locator(".mx_UserSettingsDialog").waitFor({ timeout: 20_000 });
    await page.waitForTimeout(800);
    await shot(page, `10-settings-opened-${vp.tag}`);
    const responsiveState = await page.evaluate(() => {
      const tv = document.querySelector(".mx_TabbedView");
      const labels = document.querySelector(".mx_TabbedView_tabLabels");
      const lr = labels ? labels.getBoundingClientRect() : null;
      return {
        tabbedViewClasses: tv ? String(tv.className) : null,
        tabListVisible: !!lr && lr.width > 0,
        tabListWidth: lr ? Math.round(lr.width) : null,
      };
    });
    log(`>>> responsive state: ${JSON.stringify(responsiveState)}`);

    // Navigate to the Sessions tab (click its label if the list is reachable).
    const sessionsTab = page
      .locator('[role="tab"], .mx_TabbedView_tabLabel')
      .filter({ hasText: /^sessions$/i })
      .first();
    if (await sessionsTab.count()) {
      await sessionsTab.click({ timeout: 10_000 }).catch((e) => log(`>>> sessions tab click failed: ${e}`));
      await page.waitForTimeout(800);
    } else {
      log(">>> sessions tab label NOT reachable at this width");
    }
    await shot(page, `11-sessions-content-${vp.tag}`);
    const controls = await dumpBackControls(page, `sessions content ${vp.tag}`);

    // Try the most plausible back control, if any is visible.
    const clickable = controls.find(
      (c) => c.visible && (/back/i.test(c.cls) || /back/i.test(c.aria || "")),
    );
    if (clickable) {
      log(`>>> clicking back candidate: ${JSON.stringify(clickable)}`);
      await page
        .locator(`[class*="back" i], [aria-label*="back" i]`)
        .first()
        .click({ timeout: 5000 })
        .catch((e) => log(`>>> back click failed: ${e}`));
      await page.waitForTimeout(600);
      await shot(page, `12-after-back-${vp.tag}`);
      const after = await page.evaluate(() => {
        const labels = document.querySelector(".mx_TabbedView_tabLabels");
        const lr = labels ? labels.getBoundingClientRect() : null;
        return { tabListVisible: !!lr && lr.width > 0 };
      });
      log(`>>> after back click, tab list visible: ${JSON.stringify(after)}`);
    } else {
      log(`>>> NO visible back-labelled control at ${vp.tag} — S1 candidate ${
        responsiveState.tabListVisible ? "(but tab list still visible, so maybe not needed)" : "(tab list HIDDEN: user would be STUCK -> REPRODUCED)"
      }`);
    }
    // QR flow back button (the "Show QR code" screen lives in this same tab
    // and renders its own header back control for the reciprocate intent —
    // check its presence/visibility at this width too).
    const qrBtn = page.getByRole("button", { name: /show qr code/i }).first();
    if (await qrBtn.count()) {
      await qrBtn.click({ timeout: 10_000 }).catch((e) => log(`>>> qr open failed: ${e}`));
      await page.waitForTimeout(2500);
      await shot(page, `13-qr-screen-${vp.tag}`);
      await dumpBackControls(page, `QR screen ${vp.tag}`);
      const qrBack = page.locator('[data-testid="back-button"], .mx_LoginWithQR_BackButton').first();
      log(
        `>>> QR back button: count=${await qrBack.count()} visible=${
          (await qrBack.count()) ? await qrBack.isVisible().catch(() => false) : "n/a"
        }`,
      );
      // leave the QR screen so the rendezvous doesn't linger
      await page.keyboard.press("Escape");
      await page.waitForTimeout(500);
    }
    // Close settings for the next iteration.
    await page.keyboard.press("Escape");
    await page.waitForTimeout(500);
  }
  await ctx.close();
});

test("R2-2 + R2-3: DM avatar (#31856) and right-panel back chevron", async ({ browser }) => {
  test.setTimeout(420_000);
  // ---- Account A: login + set profile picture ----
  const ctxA = await browser.newContext();
  const A = await ctxA.newPage();
  const a = await login(A);
  await A.locator(".mx_UserMenu").click();
  await A.getByRole("menuitem", { name: /all settings/i }).click({ timeout: 20_000 });
  await A.locator(".mx_UserSettingsDialog").waitFor({ timeout: 20_000 });
  await A.waitForTimeout(1000);
  const fileInput = A.locator('.mx_UserSettingsDialog input[type="file"]').first();
  await fileInput.setInputFiles(AVATAR_FILE, { timeout: 20_000 });
  await A.waitForTimeout(3000); // upload + profile set
  const prof = await api(A, "GET", `/_matrix/client/v3/profile/${encodeURIComponent(a.uid)}`);
  log(`>>> A profile after upload: ${JSON.stringify(prof)}`);
  await A.keyboard.press("Escape");

  // ---- Account B: login, create DM with A ----
  const ctxB = await browser.newContext();
  const B = await ctxB.newPage();
  const b = await login(B);
  const create = await api(B, "POST", "/_matrix/client/v3/createRoom", {
    is_direct: true,
    preset: "trusted_private_chat",
    invite: [a.uid],
  });
  log(`>>> B createRoom: ${JSON.stringify(create)}`);
  const roomId = create.json?.room_id;
  await api(B, "PUT", `/_matrix/client/v3/user/${encodeURIComponent(b.uid)}/account_data/m.direct`, {
    [a.uid]: [roomId],
  });
  // A joins and says something (so B has a timeline event with A's avatar).
  const join = await api(A, "POST", `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/join`, {});
  log(`>>> A join: ${JSON.stringify(join)}`);
  await api(A, "PUT", `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/t${Date.now()}`, {
    msgtype: "m.text",
    body: "hello from A (avatar probe)",
  });

  // ---- B: first render of the DM ----
  await B.goto(`${ELEMENT_URL}/#/room/${roomId}`, { waitUntil: "domcontentloaded" });
  await B.waitForTimeout(5000);
  await shot(B, "20-B-dm-first-render");
  await describeHeaderAvatar(B, "B first render");

  // ---- B: reload and re-check (the #31856 race window) ----
  await B.reload({ waitUntil: "domcontentloaded" });
  await B.waitForTimeout(6000);
  await shot(B, "21-B-dm-after-reload");
  await describeHeaderAvatar(B, "B after reload");

  // ---- R2-3: right-panel member card ----
  const senderAvatar = B.locator(".mx_EventTile_avatar").first();
  if (await senderAvatar.count()) {
    await senderAvatar.click({ timeout: 10_000 }).catch((e) => log(`>>> sender avatar click failed: ${e}`));
  } else {
    // Fallback: room info -> people -> member
    log(">>> no timeline avatar; opening member via room info");
    await B.getByRole("button", { name: /room info/i }).click({ timeout: 10_000 }).catch(() => {});
    await B.waitForTimeout(800);
    await B.getByText(/people/i).first().click({ timeout: 10_000 }).catch(() => {});
    await B.waitForTimeout(800);
    await B.getByText(a.uid.slice(1, 20)).first().click({ timeout: 10_000 }).catch(() => {});
  }
  await B.waitForTimeout(1500);
  await shot(B, "30-B-userinfo-card");
  const cardState = await B.evaluate(() => {
    const card = document.querySelector('[class*="UserInfo" i], [class*="BaseCard" i]');
    if (!card) return { cardFound: false };
    const img = card.querySelector("img");
    return {
      cardFound: true,
      cardCls: String(card.className).slice(0, 100),
      avatarImg: img ? { src: img.src.slice(0, 140), naturalWidth: img.naturalWidth } : null,
    };
  });
  log(`>>> userinfo card: ${JSON.stringify(cardState)}`);
  await dumpBackControls(B, "userinfo card open");

  await ctxA.close();
  await ctxB.close();
});
