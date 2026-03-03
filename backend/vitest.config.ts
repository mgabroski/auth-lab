import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.spec.ts'],
    setupFiles: ['test/setup-env.ts'],
    clearMocks: true,
    restoreMocks: true,

    // 🔒 Critical: DB-backed tests must not run concurrently against the same database.
    sequence: {
      concurrent: false,
    },
    maxConcurrency: 1,

    // Also ensure the worker pool itself is single-process.
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
  },
});
