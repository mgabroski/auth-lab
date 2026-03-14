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
      reuseExistingServer: !process.env.CI,
    },
  ],
});
