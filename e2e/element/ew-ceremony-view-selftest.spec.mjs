/**
 * EW-C1 — self-test for the M4c ceremony-view watcher (`helpers/ceremony-view.mjs`).
 *
 * WHY THIS EXISTS: **a watcher that has never failed is unproven.** That lesson is
 * already paid for on this branch — the T6 readiness gate was only trusted after
 * being sabotaged and observed to exit 1. An I-C1 assertion that has only ever run
 * against healthy labs proves nothing about whether it can see a wedge.
 *
 * So this drives the classifier and the invariant over synthetic samples built from
 * the ACTUAL MEASURED states in the record, and asserts BOTH directions:
 *
 *   - `T_C_Wedged`      phase=2, zero controls, crypto healthy, held 180s
 *                       (EW-V1 assertion 8, red on three consecutive runs)
 *                       -> MUST throw
 *   - `T_C_OkAwaitAck`  phase=3, controls ["Done"], crypto healthy
 *                       (EW-R1-2 instrumented run: 10 samples ~3s->~30s, all
 *                       phase=3, crossSigningReady=true, keyId=present)
 *                       -> MUST NOT throw
 *
 * Those two are OPPOSITE IN KIND and were once indistinguishable. If this file ever
 * goes green with the wedge case removed, the watcher is decorative again.
 *
 * Pure logic: no browser, no stack, no lab. It is therefore CI-promotable as-is
 * (matrix C-0 / plan B5) even though the rest of `e2e/element` is not.
 */
import { test, expect } from '@playwright/test';
import {
  assertCeremonyInvariant,
  classifyCeremonySample,
  longestWedgeRun,
  summarizeSamples,
} from './helpers/ceremony-view.mjs';

/** Build a sample the same way `ceremonySample` does, so parity is preserved. */
const mk = (at, over = {}) => {
  const crypto = { available: true, crossSigningReady: true, secretStorageReady: true, ...(over.crypto || {}) };
  const s = {
    at,
    ceremonyVisible: true,
    appShell: false,
    phase: 2,
    controls: [],
    headings: ['Verify this device'],
    keyId: null,
    keyInfoPresent: false,
    ...over,
    crypto,
  };
  s.cryptoHealthy = crypto.crossSigningReady === true;
  s.classification = classifyCeremonySample(s);
  return s;
};

/** A run of samples every 3s, as the real loops poll. */
const series = (count, over = {}, step = 3_000) =>
  Array.from({ length: count }, (_, i) => mk(i * step, typeof over === 'function' ? over(i) : over));

test('EW-C1a: the classifier separates the two states that were once indistinguishable', () => {
  // The wedge, exactly as measured: Busy, zero buttons, crypto perfectly healthy.
  const wedged = mk(0, { phase: 2, controls: [] });
  expect(wedged.classification).toBe('T_C_Wedged');

  // Success-awaiting-acknowledgement, exactly as measured. Opposite in kind, and
  // the state that a missing harness click once made look like a product defect.
  const awaitAck = mk(0, { phase: 3, controls: ['Done'], keyId: 'present', keyInfoPresent: true });
  expect(awaitAck.classification).toBe('T_C_OkAwaitAck');

  // Healthy transient Busy — the `C_Working` the matrix says nothing distinguished.
  expect(mk(0, { phase: 2, controls: ['Skip'] }).classification).toBe('C_Working');

  expect(mk(0, { phase: 1, controls: ['Verify with another device'] }).classification).toBe('C_Gate');
  expect(mk(0, { appShell: true, ceremonyVisible: false }).classification).toBe('T_C_App');
  expect(mk(0, { phase: 6, controls: ['Reset'] }).classification).toBe('T_C_ResetOffered');
});

test('EW-C1b: a disabled control is not an exit', () => {
  // U5's shape: a control is present but greyed out. Counting it would let a state
  // that traps the user satisfy I-C1. `ceremonySample` filters these in the DOM;
  // this pins the intent so a future "simplification" of that filter is caught.
  expect(mk(0, { phase: 2, controls: [] }).classification).toBe('T_C_Wedged');
  expect(mk(0, { phase: 2, controls: ['Continue'] }).classification).toBe('C_Working');
});

test('EW-C1c: I-C1 FIRES on a sustained wedge — the direction that proves it works', () => {
  // 180s of Busy with zero controls: the exact budget EW-V1 observed, three times.
  const samples = series(61, { phase: 2, controls: [] });
  expect(longestWedgeRun(samples).ms).toBe(180_000);

  let threw = null;
  try {
    assertCeremonyInvariant(samples, { label: 'selftest sustained wedge' });
  } catch (e) {
    threw = e;
  }
  expect(threw, 'I-C1 did not fire on a 180s buttonless wedge — the watcher is blind').not.toBeNull();
  expect(threw.message).toContain('I-C1 BREACH');
  expect(threw.message).toContain('T_C_Wedged');
  // The message must name the state and carry the evidence, not just fail.
  expect(threw.message).toContain('ZERO actionable controls');
  expect(threw.message).toContain('crossSigningReady=true');
});

test('EW-C1d: I-C1 does NOT fire on the valid terminal, nor on a brief transition', () => {
  // T_C_OkAwaitAck sustained indefinitely is CORRECT — the user has a Done button.
  // A watcher that failed here would be deleted within a week, and it would be right to.
  const ok = series(20, { phase: 3, controls: ['Done'], keyId: 'present' });
  expect(() => assertCeremonyInvariant(ok, { label: 'selftest await-ack' })).not.toThrow();
  expect(summarizeSamples(ok)).toEqual({ T_C_OkAwaitAck: 20 });

  // A brief buttonless blip mid-transition (2 samples = 3s) is C_Working, not a wedge.
  const blip = [
    mk(0, { phase: 1, controls: ['Verify with another device'] }),
    mk(3_000, { phase: 2, controls: [] }),
    mk(6_000, { phase: 2, controls: [] }),
    mk(9_000, { phase: 3, controls: ['Done'] }),
    mk(12_000, { appShell: true, ceremonyVisible: false }),
  ];
  // 3000, not 6000: the run is the OBSERVED span between the first and last
  // breaching sample, a deliberate lower bound on the true dwell. See the note on
  // `longestWedgeRun`. This expectation is what pins that choice.
  expect(longestWedgeRun(blip).ms).toBe(3_000);
  expect(() => assertCeremonyInvariant(blip, { label: 'selftest blip' })).not.toThrow();
});

test('EW-C1f: the dwell threshold is what separates a blip from a wedge', () => {
  // Same shape, same crypto, same zero controls — only duration differs. This is
  // the C_Working / T_C_Wedged boundary stated as an executable claim.
  const under = series(7, { phase: 2, controls: [] }); // 18s observed span
  const over = series(9, { phase: 2, controls: [] }); // 24s observed span

  expect(longestWedgeRun(under).ms).toBe(18_000);
  expect(longestWedgeRun(over).ms).toBe(24_000);

  expect(() => assertCeremonyInvariant(under, { label: 'selftest under-dwell' })).not.toThrow();
  expect(() => assertCeremonyInvariant(over, { label: 'selftest over-dwell' })).toThrow(/I-C1 BREACH/);
});

test('EW-C1e: an unreadable crypto probe cannot manufacture a breach', () => {
  // I-C1 is scoped to "while the underlying crypto is healthy". If the probe fails
  // or returns an ERR string, the state is NOT healthy, so it must not be reported
  // as a wedge — otherwise a torn-down store mid-navigation reads as a product
  // defect, which is trap #1 on this branch (a harness gap presenting as a defect,
  // three times).
  const unreadable = series(61, { phase: 2, controls: [], crypto: { crossSigningReady: 'ERR boom' } });
  expect(unreadable[0].classification).toBe('C_Working');
  expect(() => assertCeremonyInvariant(unreadable, { label: 'selftest unreadable' })).not.toThrow();

  // A probe that threw entirely is Unknown, and is neither pass nor breach.
  const broken = [{ at: 0, error: 'dom: boom', classification: classifyCeremonySample({ error: 'x' }) }];
  expect(broken[0].classification).toBe('Unknown');
  expect(() => assertCeremonyInvariant(broken, { label: 'selftest broken' })).not.toThrow();
});
