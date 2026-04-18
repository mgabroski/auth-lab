/**
 * frontend/playwright.config.mts
 *
 * Single Playwright config for the repo.
 *
 * TOPOLOGY MODES:
 * - yarn dev
 *   Host-run local dev:
 *     frontend -> localhost:3000
 *     cp       -> localhost:3002
 *   Valid for tenant-auth smoke.
 *
 * - yarn dev:stack
 *   Full Docker topology with the real public proxy:
 *     browser -> Caddy *.lvh.me:3000 -> backend / frontend / cp
 *   Required for CP proxy-host smoke and full same-origin routing proof.
 *
 * IMPORTANT:
 * - Not every spec is valid in every topology.
 * - auth.spec.ts works in host-run dev and full-stack dev.
 * - cp-smoke.spec.ts requires the real proxy topology (yarn dev:stack or CI CP workflow).
 *
 * WHY workers: 1:
 * - Real DB state and a shared Mailpit inbox. Serialising tests avoids
 *   race conditions on seeded rows and email pickup.
 */

import { defineConfig, devices } from '@playwright/test';

const PROXY_PORT = 3000;
const PRIMARY_TENANT = 'goodwill-open';

export default defineConfig({
  testDir: './test/e2e',

  timeout: 60_000,

  expect: {
    // Real SSR + auth bootstrap takes longer than a local mock response.
    timeout: 15_000,
  },

  workers: 1,
  fullyParallel: false,

  use: {
    baseURL: `http://${PRIMARY_TENANT}.lvh.me:${PROXY_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // No webServer block — the stack must already be running.
  // yarn dev / yarn dev:stack handles startup and seeding separately.
});
