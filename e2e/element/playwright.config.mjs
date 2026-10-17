import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// A CTRF report (https://ctrf.io) next to the list output when a caller asks for one:
// CTRF_OUTPUT names the file, CTRF_OUTPUT_DIR a directory (file ctrf-report.json).
// run.sh mounts either location into the container at the same path.
const reporter = [['list']];
if (process.env.CTRF_OUTPUT || process.env.CTRF_OUTPUT_DIR) {
  const out = process.env.CTRF_OUTPUT;
  reporter.push([
    'playwright-ctrf-json-reporter',
    {
      outputDir: out ? path.dirname(out) : process.env.CTRF_OUTPUT_DIR,
      outputFile: out ? path.basename(out) : 'ctrf-report.json',
      testType: 'e2e',
      appName: 'siwx-oidc e2e/element',
    },
  ]);
}

// External stack: Element :8088, Matrix edge :8080, siwx :8081 (compose.local).
export default defineConfig({
  testDir: '.',
  testMatch: 'ew-*.spec.mjs',
  // The T2 upgrade pair runs only under its driver (upgrade-survival.sh), which sets
  // QUALIFY_STATE_DIR; a plain run of the whole suite leaves it out.
  testIgnore: process.env.QUALIFY_STATE_DIR ? [] : ['**/ew-upgrade-*.spec.mjs'],
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  reporter,
  use: {
    baseURL: process.env.ELEMENT_URL || 'http://localhost:8088',
    headless: true,
    ...devices['Desktop Chrome'],
    // Element can be slow on first load
    navigationTimeout: 60_000,
  },
});
