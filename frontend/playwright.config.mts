import { defineConfig, devices } from '@playwright/test';

const frontendPort = 3100;
const backendPort = 3101;

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  use: {
    baseURL: `http://acme.localhost:${frontendPort}`,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'node ./test/e2e/mock-auth-backend.mjs',
      port: backendPort,
      timeout: 15_000,
      // Mock backend is cheap to start; safe to reuse locally.
      reuseExistingServer: !process.env.CI,
    },
    {
      command: 'next dev --hostname 0.0.0.0 --port 3100',
      env: {
        ...process.env,
        INTERNAL_API_URL: `http://127.0.0.1:${backendPort}`,
        NODE_ENV: 'test',
      },
      port: frontendPort,
      timeout: 120_000,
      // WHY false (not !process.env.CI):
      //
      // The Next.js dev server must always be started fresh by Playwright
      // so that INTERNAL_API_URL is guaranteed to point to the mock backend
      // on port 3101. If a stale server from a previous test run (or from
      // `yarn dev` on this port) is reused, it may use a different
      // INTERNAL_API_URL or none at all. That causes every browser-side
      // API call routed through the /api/[...path] Route Handler to go to
      // the wrong backend, silently failing all login/signup/auth flows.
      //
      // The Next.js startup time (typically 20-30s cold, <5s warm rebuild)
      // is acceptable given the correctness guarantee.
      reuseExistingServer: false,
    },
  ],
});
