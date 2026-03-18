/**
 * frontend/playwright.config.mts
 *
 * Single Playwright config for the repo.
 * Targets the real Docker Compose stack: Caddy proxy at *.lvh.me:3000.
 *
 * PREREQUISITES (stack must be running before tests execute):
 *   yarn dev        — starts infra + seeds + backend + frontend (host-run)
 *   yarn dev:stack  — starts full Docker topology including Caddy proxy
 *
 * TOPOLOGY:
 *   browser → Caddy *.lvh.me:3000 → backend:3001 / frontend:3000
 *   *.lvh.me resolves to 127.0.0.1 in public DNS — no /etc/hosts needed.
 *
 * WHY workers: 1:
 *   Real DB state and a shared Mailpit inbox. Serialising tests avoids
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
  // yarn dev / yarn dev:stack handles startup and seeding automatically.
});
