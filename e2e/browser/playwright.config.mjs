import { defineConfig, devices } from '@playwright/test';

// The siwx-oidc stack runs externally (e2e/up.sh); we do not manage a webServer.
export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter: [['list']],
  use: {
    baseURL: process.env.SIWEOIDC_HOST || 'http://localhost:8080',
    headless: true,
    ...devices['Desktop Chrome'],
  },
});
