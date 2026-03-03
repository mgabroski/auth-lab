import 'dotenv/config';

// Ensure test-only helpers (eg. resetDb) cannot accidentally run under a non-test NODE_ENV.
// Vitest does not always set NODE_ENV automatically.
if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = 'test';
}
