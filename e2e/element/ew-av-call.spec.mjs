/**
 * EW-AV1: one Element Call through the served Element Web, with a call agent as the other side.
 *
 * The browser signs in with a throwaway wallet, accepts the DM a call agent creates (any MatrixRTC
 * client that invites the browser's account to a DM and publishes audio and video in a call
 * there), and joins the agent's call from the room header with Chromium's fake camera and
 * microphone. It then samples WebRTC statistics in the Element Call frame: what it
 * sends (outbound-rtp) and what it receives from the agent (inbound-rtp), per kind. It leaves the
 * call and deactivates its account.
 *
 * This file only drives the browser. An orchestrator starts the agent after `browser.json`
 * appears in EW_AV_DIR, reads the browser account from it, and judges the SFU's byte counters
 * against a one-agent control (the agent alone sends to nobody, so the SFU's transmit rate stays
 * near zero). Without EW_AV_DIR the test is skipped, so a plain lab run never waits for an agent
 * that is not there.
 *
 * Files written to EW_AV_DIR: browser.json (the account), room.json (encryption and power
 * levels), stats.json (samples), call.png (the call view), outcome.json.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { test, expect } from '@playwright/test';
import { makeWallet } from '../browser/wallet-helper.mjs';
import { requireElementStack, SIWX_URL } from './helpers/element.mjs';
import { elementWalletClickLogin } from './helpers/element-login.mjs';
import { deactivateWalletAccount } from './helpers/upgrade.mjs';

const AV_DIR = process.env.EW_AV_DIR;
const CALL_MEMBER = 'org.matrix.msc3401.call.member';

test.use({
  launchOptions: {
    args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
  },
  permissions: ['camera', 'microphone'],
});

const write = (name, value) =>
  fs.writeFile(path.join(AV_DIR, name), JSON.stringify(value, null, 2) + '\n');

/** Every RTCPeerConnection a frame creates, so the test can read its statistics. */
function collectPeerConnections() {
  const Orig = window.RTCPeerConnection;
  if (!Orig || Orig.__avCollected) return;
  const pcs = (window.__avPcs = []);
  class Collected extends Orig {
    constructor(...args) {
      super(...args);
      pcs.push(this);
    }
  }
  Collected.__avCollected = true;
  window.RTCPeerConnection = Collected;
}

/** Byte and frame totals over the frame's open peer connections. */
async function rtpTotals(frame) {
  return frame.evaluate(async () => {
    const t = {
      at: Date.now(),
      pcs: 0,
      out: { audio: 0, video: 0 },
      in: { audio: 0, video: 0 },
      framesDecoded: 0,
      audioSamplesReceived: 0,
    };
    for (const pc of window.__avPcs || []) {
      if (pc.connectionState === 'closed') continue;
      t.pcs += 1;
      const stats = await pc.getStats();
      stats.forEach((r) => {
        if (r.type === 'outbound-rtp' && r.kind) t.out[r.kind] += r.bytesSent || 0;
        if (r.type === 'inbound-rtp' && r.kind) {
          t.in[r.kind] += r.bytesReceived || 0;
          if (r.kind === 'video') t.framesDecoded += r.framesDecoded || 0;
          if (r.kind === 'audio') t.audioSamplesReceived += r.totalSamplesReceived || 0;
        }
      });
    }
    return t;
  });
}

async function visibleButtons(scope) {
  return scope
    .getByRole('button')
    .evaluateAll((els) => els.filter((e) => e.offsetParent !== null).map((e) => e.getAttribute('aria-label') || e.textContent.trim()))
    .catch((e) => [`(unreadable: ${e.message})`]);
}

test('EW-AV1: a call through the served Element Web sends and receives audio and video', async ({
  browser,
}) => {
  test.skip(!AV_DIR, 'needs EW_AV_DIR and a call agent started by the orchestrator');
  test.setTimeout(600_000);
  await requireElementStack();

  const context = await browser.newContext();
  await context.addInitScript(collectPeerConnections);
  const page = await context.newPage();
  const wallet = makeWallet();
  const outcome = { steps: [] };
  const step = (s) => {
    outcome.steps.push(`${new Date().toISOString()} ${s}`);
    // eslint-disable-next-line no-console
    console.log(`[AV] ${s}`);
  };

  try {
    const session = await elementWalletClickLogin(page, wallet);
    step(`signed in as ${session.user_id}`);
    await write('browser.json', { user_id: session.user_id, at: new Date().toISOString() });
    await page.getByRole('button', { name: 'Dismiss' }).click({ timeout: 5_000 }).catch(() => {});

    // The agent creates the DM and invites us; nothing else knows this fresh account.
    let roomId = null;
    for (let i = 0; i < 120 && !roomId; i++) {
      roomId = await page.evaluate(() => {
        const cli = window.mxMatrixClientPeg.get();
        const r = cli.getRooms().find((x) => x.getMyMembership() === 'invite');
        return r ? r.roomId : null;
      });
      if (!roomId) await page.waitForTimeout(2_000);
    }
    expect(roomId, 'no invite from the call agent within 240 s').not.toBeNull();
    step(`invited to ${roomId}`);
    await page.evaluate((rid) => window.mxMatrixClientPeg.get().joinRoom(rid), roomId);
    await page.evaluate((rid) => {
      window.location.hash = `#/room/${rid}`;
    }, roomId);
    await page.locator('.mx_MessageComposer').waitFor({ timeout: 60_000 });
    step('joined the DM');

    // Wait for the agent's call membership, then record the room facts the call depends on.
    let agentMember = null;
    for (let i = 0; i < 90 && !agentMember; i++) {
      agentMember = await page.evaluate(
        ({ rid, type }) => {
          const cli = window.mxMatrixClientPeg.get();
          const room = cli.getRoom(rid);
          const ev = room?.currentState
            .getStateEvents(type)
            .find((e) => e.getSender() !== cli.getUserId() && Object.keys(e.getContent()).length > 0);
          return ev ? ev.getSender() : null;
        },
        { rid: roomId, type: CALL_MEMBER },
      );
      if (!agentMember) await page.waitForTimeout(2_000);
    }
    expect(agentMember, 'the agent never published a call membership').not.toBeNull();
    const roomFacts = await page.evaluate(
      ({ rid, type }) => {
        const cli = window.mxMatrixClientPeg.get();
        const room = cli.getRoom(rid);
        const pl = room.currentState.getStateEvents('m.room.power_levels', '')?.getContent() || {};
        const enc = room.currentState.getStateEvents('m.room.encryption', '')?.getContent() || null;
        return {
          encryption: enc && enc.algorithm,
          state_default: pl.state_default,
          call_member_level: (pl.events || {})[type],
          users: pl.users,
          members: room.getJoinedMembers().map((m) => m.userId),
        };
      },
      { rid: roomId, type: CALL_MEMBER },
    );
    await write('room.json', { room_id: roomId, agent: agentMember, ...roomFacts });
    step(`agent ${agentMember} is in a call; room ${JSON.stringify(roomFacts)}`);

    // Join from the room header. While a call is ongoing the header shows "Join" (accessible
    // name "Join video call", data-testid join-call-button) and the "Video call" button carries
    // its disabled reason as its name (RoomHeader.tsx).
    const join = page.locator('.mx_RoomHeader').getByTestId('join-call-button');
    await join.waitFor({ timeout: 60_000 });
    step(`header join button: "${await join.getAttribute('aria-label')}"`);
    await join.click();
    step('clicked the header join button');

    let frame = null;
    for (let i = 0; i < 60 && !frame; i++) {
      frame = page.frames().find((f) => /element-call/.test(f.url())) || null;
      if (!frame) await page.waitForTimeout(1_000);
    }
    expect(frame, `no Element Call frame; buttons: ${JSON.stringify(await visibleButtons(page))}`).not.toBeNull();
    outcome.frame = new URL(frame.url()).origin + new URL(frame.url()).pathname;
    step(`Element Call frame ${outcome.frame}`);

    // A lobby asks to join; a skipped lobby joins at once.
    const lobbyJoin = frame.getByRole('button', { name: /^Join( call)?$/i });
    await lobbyJoin.click({ timeout: 20_000 }).then(
      () => step('clicked Join in the call lobby'),
      () => step('no lobby Join button (lobby skipped)'),
    );

    // Sample for 40 s once the frame has a peer connection.
    const samples = [];
    for (let i = 0; i < 30; i++) {
      const t = await rtpTotals(frame);
      if (t.pcs > 0) break;
      await page.waitForTimeout(1_000);
    }
    for (let i = 0; i < 9; i++) {
      samples.push(await rtpTotals(frame));
      if (i < 8) await page.waitForTimeout(5_000);
    }
    await write('stats.json', samples);
    await page.screenshot({ path: path.join(AV_DIR, 'call.png') });
    const first = samples[0];
    const last = samples[samples.length - 1];
    outcome.delta = {
      seconds: (last.at - first.at) / 1000,
      sent_audio: last.out.audio - first.out.audio,
      sent_video: last.out.video - first.out.video,
      received_audio: last.in.audio - first.in.audio,
      received_video: last.in.video - first.in.video,
      frames_decoded: last.framesDecoded - first.framesDecoded,
      audio_samples_received: last.audioSamplesReceived - first.audioSamplesReceived,
    };
    step(`over ${outcome.delta.seconds}s: ${JSON.stringify(outcome.delta)}`);

    expect(last.pcs, 'the call frame has no open peer connection').toBeGreaterThan(0);
    expect(outcome.delta.sent_audio, 'browser sent no audio').toBeGreaterThan(0);
    expect(outcome.delta.sent_video, 'browser sent no video').toBeGreaterThan(0);
    expect(outcome.delta.received_audio, 'browser received no audio from the agent').toBeGreaterThan(0);
    expect(outcome.delta.received_video, 'browser received no video from the agent').toBeGreaterThan(0);

    const leave = frame.getByRole('button', { name: /leave|hang up|end call/i }).first();
    await leave.click({ timeout: 10_000 }).then(
      () => step('left the call'),
      () => step('no leave button found'),
    );
  } catch (e) {
    outcome.error = e.message.split('\n')[0];
    await page.screenshot({ path: path.join(AV_DIR, 'failure.png') }).catch(() => {});
    await fs
      .writeFile(path.join(AV_DIR, 'failure-aria.yml'), await page.locator('body').ariaSnapshot())
      .catch(() => {});
    throw e;
  } finally {
    outcome.deactivate = await deactivateWalletAccount(wallet.wallet, SIWX_URL).catch((e) => `error ${e.message}`);
    step(`account deactivation: ${outcome.deactivate}`);
    await write('outcome.json', outcome).catch(() => {});
    await context.close();
  }
});
