/**
 * EW-DL: encrypted file download regression probe (2026-07-31 prod incident).
 *
 * Covers the exact gap that let the regression ship: nobody ever clicked
 * "download file" in the e2e lab. Logs everything; asserts a browser download
 * event fires for an encrypted attachment.
 *
 * Run against dev-staging (same source-built element as prod):
 *   ELEMENT_URL=https://dev.element.inblock.io \
 *   MATRIX_URL=https://dev.matrix.inblock.io \
 *   SIWX_URL=https://dev.siwx.inblock.io \
 *   npx playwright test ew-download
 */
import { test, expect } from "@playwright/test";
import { ELEMENT_URL, SIWX_URL } from "./helpers/element.mjs";
import { completeSecureBackupWizard } from "./helpers/element-login.mjs";
import { makeWallet, injectMockWallet } from "../browser/wallet-helper.mjs";

test("EW-DLD: micro-drag clicks vs clean clicks", async ({ page }) => {
  test.setTimeout(300_000);
  const logs = [];
  const downloads = [];
  page.on("console", (m) => logs.push(`[${m.type()}] ${m.text().slice(0, 250)}`));
  page.on("pageerror", (e) => logs.push(`[pageerror] ${String(e).slice(0, 250)}`));
  page.on("download", (d) => {
    downloads.push(d.suggestedFilename());
    console.log(`>>> DOWNLOAD EVENT: ${d.suggestedFilename()}`);
    d.cancel().catch(() => {});
  });
  page.on("response", (r) => {
    if (r.status() >= 400 && /usercontent|bundles/.test(r.url()))
      console.log(`>>> HTTP ${r.status()} ${r.url().slice(0, 140)}`);
    if (/\/_matrix\/(client\/v1\/)?media\//.test(r.url()))
      console.log(`>>> MEDIA ${r.status()} ${r.url().replace(/https:\/\/[^/]+/, "").slice(0, 110)}`);
  });

  // --- login: wallet through siwx, tolerant of the new-user gate ---
  const wallet = makeWallet();
  await injectMockWallet(page, wallet);
  await page.goto(ELEMENT_URL, { waitUntil: "domcontentloaded" });
  await page.waitForURL((u) => u.origin === new URL(SIWX_URL).origin, { timeout: 60_000 });
  await page.getByRole("button", { name: "Sign in with Ethereum" }).click();

  // Optional new-user creation gate ("Create a new account?" -> Continue)
  const gateBtn = page.getByRole("button", { name: "Continue" }).first();
  const skipBtn = page.getByRole("button", { name: "Skip for now" }).first();
  for (let i = 0; i < 2; i++) {
    const which = await Promise.race([
      gateBtn.waitFor({ timeout: 20_000 }).then(() => "gate").catch(() => null),
      skipBtn.waitFor({ timeout: 20_000 }).then(() => "skip").catch(() => null),
      page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 20_000 }).then(() => "element").catch(() => null),
    ]);
    if (which === "gate") await gateBtn.click();
    else if (which === "skip") await skipBtn.click();
    else break;
  }
  await page.waitForURL((u) => u.origin === new URL(ELEMENT_URL).origin, { timeout: 60_000 });
  await completeSecureBackupWizard(page);
  console.log(">>> logged in");

  // --- create an encrypted room via the live client ---
  const roomId = await page.evaluate(async () => {
    const cli = window.mxMatrixClientPeg.get();
    const r = await cli.createRoom({
      name: "dl-probe",
      preset: "private_chat",
      initial_state: [{ type: "m.room.encryption", state_key: "", content: { algorithm: "m.megolm.v1.aes-sha2" } }],
    });
    return r.room_id;
  });
  console.log(`>>> room ${roomId}`);
  await page.evaluate((rid) => { window.location.hash = `#/room/${rid}`; }, roomId);
  await page.locator(".mx_MessageComposer").waitFor({ timeout: 30_000 });

  // --- send a real ENCRYPTED attachment (MSC-spec m.file) via the live client ---
  // Encrypt in-page with WebCrypto rather than driving the file picker: the
  // ceremony under test is the DOWNLOAD click path, not the upload widget.
  await page.evaluate(async (rid) => {
    const cli = window.mxMatrixClientPeg.get();
    const plaintext = new TextEncoder().encode("e2e download probe content");

    const key = await crypto.subtle.generateKey({ name: "AES-CTR", length: 256 }, true, ["encrypt"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv.subarray(0, 8)); // high 8 bytes random, counter half zero
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, key, plaintext),
    );
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ct));
    const b64 = (u8) => btoa(String.fromCharCode(...u8));
    const unpadded = (u8) => b64(u8).replace(/=+$/, "");

    const { content_uri: url } = await cli.uploadContent(new Blob([ct], { type: "application/octet-stream" }), {
      includeFilename: false,
      type: "application/octet-stream",
    });

    await cli.sendMessage(rid, {
      msgtype: "m.file",
      body: "dl-probe.pdf",
      file: {
        v: "v2",
        url,
        iv: unpadded(iv),
        hashes: { sha256: unpadded(digest) },
        key: { alg: "A256CTR", ext: true, k: jwk.k, key_ops: ["encrypt", "decrypt"], kty: "oct" },
      },
      info: { mimetype: "application/pdf", size: plaintext.length },
    });
  }, roomId);
  const tile = page.getByText("dl-probe.pdf", { exact: false }).last();
  await tile.waitFor({ timeout: 60_000 });
  await page.waitForTimeout(2000);
  console.log(">>> file event visible");

  // Service-worker state decides whether media fetches get authenticated at all.
  console.log(
    ">>> SW:",
    JSON.stringify(
      await page.evaluate(async () => {
        const reg = await navigator.serviceWorker?.getRegistration();
        return {
          hasReg: !!reg,
          active: reg?.active?.state ?? null,
          scope: reg?.scope ?? null,
          controlling: !!navigator.serviceWorker?.controller,
        };
      }),
    ),
  );

  // --- click path 1: the file tile body ---
  await tile.click();
  await page.waitForTimeout(5000);
  console.log(`>>> after tile click: downloads=${JSON.stringify(downloads)}`);

  // --- click path 2: hover action-bar Download button ---
  if (downloads.length === 0) {
    await tile.hover();
    const dlBtn = page.getByRole("button", { name: /download/i }).first();
    if (await dlBtn.count()) {
      await dlBtn.click();
      await page.waitForTimeout(5000);
    }
    console.log(`>>> after action-bar click: downloads=${JSON.stringify(downloads)}`);
  }

  const firstCount = downloads.length;
  console.log(`>>> phase1 (clean synthetic click) downloads=${firstCount}`);

  // --- PHASE 2: human-like click with 4px of mouse travel (micro-drag) ---
  const box = await tile.boundingBox();
  const cx = box.x + box.width / 2, cy = box.y + box.height / 2;
  await page.mouse.move(cx - 2, cy - 2);
  await page.mouse.down();
  await page.mouse.move(cx + 2, cy + 1, { steps: 3 }); // ~4px travel while pressed
  await page.mouse.up();
  await page.waitForTimeout(5000);
  console.log(`>>> phase2 (micro-drag click) downloads=${JSON.stringify(downloads)}`);

  // --- PHASE 3: micro-drag on the hover action-bar download button ---
  await tile.hover();
  const dlBtn3 = page.getByRole("button", { name: /download/i }).first();
  if (await dlBtn3.count()) {
    const bb = await dlBtn3.boundingBox();
    if (bb) {
      const bx = bb.x + bb.width / 2, by = bb.y + bb.height / 2;
      await page.mouse.move(bx - 2, by - 1);
      await page.mouse.down();
      await page.mouse.move(bx + 2, by + 2, { steps: 3 });
      await page.mouse.up();
      await page.waitForTimeout(5000);
    }
  }
  console.log(`>>> phase3 (micro-drag on action button) downloads=${JSON.stringify(downloads)}`);
  console.log("=== console lines ===");
  for (const l of logs.filter((l) => /error|404|SW:|worker|download|decrypt|rageshake|verif/i.test(l))) console.log(l.slice(0, 220));
  console.log(`>>> VERDICT: clean=${firstCount>0} afterMicroDrags=${downloads.length}`);
  expect(firstCount, "clean click").toBeGreaterThan(0);
});
