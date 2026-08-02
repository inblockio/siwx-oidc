/**
 * M4c — the ceremony view (Element client), as an ASSERTING watcher.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The map's §M4c names six states. Five of them were already observable, and two
 * specs already logged everything needed to tell them apart — but only ever as
 * DIAGNOSTICS. `ew-recovery-entry.spec.mjs::samplePostUnlockState` says so in its
 * own doc comment ("not an assertion, asserts nothing"), and EW-V1's assertion 8
 * catches the wedge only INDIRECTLY, by waiting 180s for an app shell that never
 * arrives. Nothing anywhere states the discriminator itself.
 *
 * That is the coverage gap recorded against `C_Working` in the coverage matrix
 * (§5.9, "Uncovered — no test distinguishes a healthy transient Busy (>=1 button)
 * from `T_C_Wedged` (zero buttons); the distinction is button count; nothing
 * asserts it directly"), and it is the distinction invariant **I-C1** rests on:
 *
 *     no terminal may present zero user-actionable controls
 *     while the underlying crypto is healthy.
 *
 * The cost of not having it is on record. `T_C_OkAwaitAck` (phase 3, a "Done"
 * button nobody clicked) and `T_C_Wedged` (phase 2, zero buttons) are OPPOSITE in
 * kind, yet both render as "no app shell" — so at the altitude the tests asserted
 * at they were the same event. That ambiguity produced two wrong diagnoses, one
 * withdrawn P0, and a "defect" that was really a missing click in the harness.
 *
 * WHAT IS AND IS NOT CLAIMED
 * --------------------------
 * This module asserts that **no observed sample breaches I-C1**, and it classifies
 * every sample by name. It deliberately does NOT assert "a `C_Working` sample was
 * observed": a healthy client may pass through Busy faster than the poll interval,
 * so requiring the sighting would be flaky — and a flaky invariant test gets
 * deleted, which is the failure mode this whole effort exists to prevent.
 *
 * DWELL, AND WHY IT IS NOT A FUDGE FACTOR
 * ---------------------------------------
 * A momentary zero-control render mid-transition is `C_Working`, not a breach.
 * `T_C_Wedged` is defined by PERSISTENCE — the observed wedge held for the full
 * 180s budget and only a reload cleared it. So the invariant is evaluated over the
 * longest CONTIGUOUS run of breaching samples, not over any single one.
 *
 * SCOPE OF "CONTROL"
 * ------------------
 * Controls are counted **inside the ceremony surface** and exclude anything
 * `disabled` / `aria-disabled` / `aria-hidden`. A greyed-out button is not an exit;
 * counting it would let U5-shaped states ("Show QR code", disabled with a false
 * reason) satisfy an invariant they actually breach.
 *
 * Sampling NEVER throws — a probe-side failure degrades to a recorded error string,
 * exactly as `samplePostUnlockState` does, so a torn-down store mid-navigation can
 * never masquerade as a product defect. Only `assertCeremonyInvariant` throws.
 */

/** `SetupEncryptionStore.Phase`, mirrored from the store. */
export const PHASE_NAMES = {
  0: 'Loading',
  1: 'Intro',
  2: 'Busy',
  3: 'Done',
  4: 'ConfirmSkip',
  5: 'Finished',
  6: 'ConfirmReset',
};

/** Controls whose label means "this destroys something" — drives T_C_ResetOffered. */
const RESET_LABEL = /reset|forgot|start over|can't access|cannot access/i;

/**
 * One instant of the ceremony view, reduced to the M4c discriminator.
 *
 * Never throws. On probe failure returns a sample with `error` set and
 * `classification` `Unknown`, which `assertCeremonyInvariant` ignores rather than
 * counting as either a pass or a breach.
 *
 * @returns {Promise<object>} sample
 */
export async function ceremonySample(page, { at = null } = {}) {
  const dom = await page
    .evaluate(() => {
      const vis = (el) => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return false;
        const cs = window.getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
      };
      const label = (el) =>
        (el.innerText || '').replace(/\s+/g, ' ').trim() ||
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        '';
      const actionable = (el) =>
        vis(el) &&
        !el.hasAttribute('disabled') &&
        el.getAttribute('aria-disabled') !== 'true' &&
        el.getAttribute('aria-hidden') !== 'true';

      const store = window.mxSetupEncryptionStore;
      // The ceremony surface. `.mx_CompleteSecurityBody` is the gate; the 4S
      // unlock stacks `.mx_AccessSecretStorageDialog` on top of it.
      const gate = document.querySelector('.mx_CompleteSecurityBody');
      const dialog = document.querySelector('.mx_AccessSecretStorageDialog');
      const roots = [gate, dialog].filter((el) => vis(el));

      const controls = roots
        .flatMap((root) => [
          ...root.querySelectorAll('button, [role="button"], a[href], input:not([type="hidden"])'),
        ])
        .filter(actionable)
        .map(label)
        .filter(Boolean);

      return {
        phase: store ? (store.phase ?? null) : null,
        keyId: store ? (store.keyId ?? null) : null,
        keyInfoPresent: !!(store && store.keyInfo),
        hasDevicesToVerifyAgainst: store ? (store.hasDevicesToVerifyAgainst ?? null) : null,
        ceremonyVisible: roots.length > 0,
        appShell: !!document.querySelector('.mx_MatrixChat'),
        spinner: !!document.querySelector('.mx_Spinner'),
        controls: [...new Set(controls)].slice(0, 20),
        headings: [...document.querySelectorAll('h1,h2,h3')]
          .filter(vis)
          .map((h) => h.textContent.trim())
          .slice(0, 6),
      };
    })
    .catch((e) => ({ error: `dom: ${String(e).slice(0, 160)}` }));

  const crypto = await page
    .evaluate(async () => {
      const cli = window.mxMatrixClientPeg?.get?.();
      const c = cli?.getCrypto?.();
      if (!c) return { available: false };
      const safe = async (fn) => {
        try {
          return await fn();
        } catch (e) {
          return `ERR ${String(e).slice(0, 80)}`;
        }
      };
      return {
        available: true,
        crossSigningReady: await safe(() => c.isCrossSigningReady()),
        secretStorageReady: await safe(() => c.isSecretStorageReady()),
        keyIdPresent: !!(await safe(() => c.getCrossSigningKeyId())),
      };
    })
    .catch((e) => ({ available: false, error: String(e).slice(0, 160) }));

  const sample = {
    at: at ?? null,
    ...dom,
    crypto,
    // I-C1 is scoped to "while the underlying crypto is healthy". Anything other
    // than a literal `true` (including an `ERR ...` string) is NOT healthy, so an
    // unreadable probe can never manufacture a breach.
    cryptoHealthy: crypto?.crossSigningReady === true,
  };
  sample.classification = classifyCeremonySample(sample);
  return sample;
}

/**
 * Name the sample as one of M4c's states.
 *
 * The ordering matters: app shell wins over everything (the user is out), and the
 * wedge test is applied only when the ceremony is actually on screen.
 *
 * @returns {'T_C_App'|'C_Gate'|'C_Working'|'T_C_OkAwaitAck'|'T_C_Wedged'|'T_C_ResetOffered'|'Unknown'}
 */
export function classifyCeremonySample(s) {
  if (!s || s.error) return 'Unknown';
  if (s.appShell) return 'T_C_App';
  if (!s.ceremonyVisible) return 'Unknown';

  const controls = s.controls || [];
  const n = controls.length;

  if (s.phase === 6 || (n > 0 && controls.every((c) => RESET_LABEL.test(c)))) {
    return 'T_C_ResetOffered';
  }
  // Terminal-but-unacknowledged: the ceremony finished and is waiting on a click.
  // This is a VALID terminal — it was mistaken for a trap once, at real cost.
  if (s.phase === 3 || s.phase === 5) return n > 0 ? 'T_C_OkAwaitAck' : 'T_C_Wedged';
  if (s.phase === 1) return 'C_Gate';

  // Busy / Loading. The whole discriminator lives on this line.
  if (n === 0 && s.cryptoHealthy) return 'T_C_Wedged';
  return 'C_Working';
}

/** Count classifications, for the run log. */
export function summarizeSamples(samples) {
  const byState = {};
  for (const s of samples) byState[s.classification] = (byState[s.classification] || 0) + 1;
  return byState;
}

/**
 * Longest CONTIGUOUS run of `T_C_Wedged`, in wall-clock ms, using each sample's
 * `at` timestamp. Returns the run itself so the failure message can carry it.
 *
 * This is the OBSERVED span (`last.at - first.at`), which is deliberately a
 * conservative LOWER BOUND on the true dwell: the state may have begun just after
 * the previous sample and ended just before the next. Two samples 3s apart score
 * 3000, not 6000, and a lone sample scores 0.
 *
 * Do not "correct" this by padding a half-interval on each side. Over-estimating
 * the dwell is how an invariant starts manufacturing breaches it never witnessed,
 * and a watcher that cries wolf gets deleted — which is the outcome this whole
 * module exists to prevent. Under-measuring only ever costs sensitivity, and the
 * poll interval (3s) is already an order of magnitude below the dwell (20s).
 */
export function longestWedgeRun(samples) {
  let best = { ms: 0, samples: [] };
  let run = [];
  const flush = () => {
    if (run.length) {
      const ms = (run[run.length - 1].at ?? 0) - (run[0].at ?? 0);
      if (ms >= best.ms) best = { ms, samples: run };
    }
    run = [];
  };
  for (const s of samples) {
    if (s.classification === 'T_C_Wedged') run.push(s);
    else flush();
  }
  flush();
  return best;
}

/**
 * **The I-C1 assertion.** Throws iff the ceremony view held zero user-actionable
 * controls, with healthy crypto, for longer than `dwellMs`.
 *
 * `dwellMs` defaults to 20s: an order of magnitude above a render transition, an
 * order of magnitude below the 180s the real wedge sustained.
 */
export function assertCeremonyInvariant(samples, { dwellMs = 20_000, label = 'ceremony' } = {}) {
  const usable = samples.filter((s) => s.classification !== 'Unknown');
  const worst = longestWedgeRun(samples);
  const summary = summarizeSamples(samples);

  // eslint-disable-next-line no-console
  console.log(
    `[I-C1 ${label}] samples=${samples.length} usable=${usable.length} ` +
      `states=${JSON.stringify(summary)} longestWedgeRun=${Math.round(worst.ms / 1000)}s`,
  );

  if (worst.ms > dwellMs) {
    const first = worst.samples[0];
    const last = worst.samples[worst.samples.length - 1];
    throw new Error(
      `I-C1 BREACH — T_C_Wedged sustained ${Math.round(worst.ms / 1000)}s (> ${Math.round(dwellMs / 1000)}s dwell) on "${label}".\n` +
        `  The ceremony view presented ZERO actionable controls while crypto was healthy.\n` +
        `  This is the named terminal T_C_Wedged (register U10) — not a slow transition:\n` +
        `    phase=${first.phase} (${PHASE_NAMES[first.phase] ?? 'n/a'}) -> ${last.phase} (${PHASE_NAMES[last.phase] ?? 'n/a'})\n` +
        `    crossSigningReady=${first.crypto?.crossSigningReady} secretStorageReady=${first.crypto?.secretStorageReady}\n` +
        `    keyId=${JSON.stringify(first.keyId)} keyInfoPresent=${first.keyInfoPresent}\n` +
        `    headings=${JSON.stringify(last.headings)}\n` +
        `    controls=[] across ${worst.samples.length} consecutive samples\n` +
        `  A user in this state has no way forward except reloading the page.\n` +
        `  Do not resolve this by widening the dwell — name the transition that is missing.`,
    );
  }
  return { summary, longestWedgeMs: worst.ms };
}
