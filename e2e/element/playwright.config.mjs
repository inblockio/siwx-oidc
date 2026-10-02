import { defineConfig, devices } from '@playwright/test';
import { ELEMENT_URL } from './helpers/element.mjs';

// External stack (compose.local): Element, Matrix edge and siwx on the host ports
// from stack-env.sh, handed in by run.sh as ELEMENT_URL / MATRIX_URL / SIWX_URL.
export default defineConfig({
  testDir: '.',
  testMatch: 'ew-*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  reporter: [['list']],
  use: {
    baseURL: ELEMENT_URL,
    headless: true,
    ...devices['Desktop Chrome'],
    // Element can be slow on first load
    navigationTimeout: 60_000,
  },
});
