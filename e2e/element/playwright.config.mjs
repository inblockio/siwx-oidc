import { defineConfig, devices } from '@playwright/test';

// External stack: Element :8088, Matrix edge :8080, siwx :8081 (compose.local).
export default defineConfig({
  testDir: '.',
  testMatch: 'ew-*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  reporter: [['list']],
  use: {
    baseURL: process.env.ELEMENT_URL || 'http://localhost:8088',
    headless: true,
    ...devices['Desktop Chrome'],
    // Element can be slow on first load
    navigationTimeout: 60_000,
  },
});
