import { defineConfig, devices } from '@playwright/test';

const frontendPort = 3100;
const backendPort = 3101;

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  // WHY workers: 1:
  //
  // All three E2E tests share a single Next.js dev server on port 3100.
  // Next.js dev mode is not designed for concurrent SSR load — running tests
  // in parallel causes request context collisions in next/headers (cookies(),
  // headers()) because AsyncLocalStorage context can bleed between concurrent
  // requests in the dev server. The symptom is: a test's SSR page calls
  // ssrFetch('/auth/me') but reads an empty cookie store because the incoming
  // Cookie header from the browser request was associated with a different
  // concurrent request's context. The affected request returns 401, the page
  // redirects to /auth/login, and the test fails intermittently.
  //
  // The member login test is most affected because it has no continuation step
  // (no MFA setup page, no verify-email page) — it navigates directly from
  // login to /app, which is the tightest timing window.
  //
  // workers: 1 serializes tests so only one runs at a time. This eliminates
  // the concurrency issue at the cost of slightly longer total test runtime
  // (~45s vs ~22s). That is an acceptable tradeoff for a dev-mode E2E suite.
  //
  // In a production CI environment running against a real compiled Next.js
  // server (next build && next start), fullyParallel: true would be safe
  // because the production server handles concurrent requests correctly.
  workers: 1,
  fullyParallel: false,
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
      // Mock backend is stateless-per-session and cheap to start.
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
      // WHY false: the Next.js dev server must always start fresh so that
      // INTERNAL_API_URL is guaranteed to point to the mock backend on port
      // 3101. A stale server from a previous run may have a dead or different
      // INTERNAL_API_URL, silently breaking all auth flow proxying.
      reuseExistingServer: false,
    },
  ],
});
