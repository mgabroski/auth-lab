/**
 * frontend/test/e2e/auth/auth-test-context.ts
 *
 * WHY:
 * - Shared real-stack auth smoke constants for the split auth E2E specs.
 * - Keeps tenant hosts and seeded personas in one place after splitting the
 *   legacy 1,100+ line auth.spec.ts file.
 */

const PROXY_PORT = 3000;
const OPEN_TENANT = 'goodwill-open';
const INVITE_ONLY_TENANT = 'goodwill-ca';

export const AUTH_E2E = Object.freeze({
  PROXY_PORT,
  OPEN_TENANT,
  INVITE_ONLY_TENANT,
  OPEN_ORIGIN: `http://${OPEN_TENANT}.lvh.me:${PROXY_PORT}`,
  INVITE_ONLY_ORIGIN: `http://${INVITE_ONLY_TENANT}.lvh.me:${PROXY_PORT}`,
  MEMBER_EMAIL: 'member@example.com',
  MEMBER_PASSWORD: 'Password123!',
  E2E_ADMIN_EMAIL: 'e2e-admin@example.com',
  E2E_RECOVERY_ADMIN_EMAIL: 'e2e-recovery-admin@example.com',
  E2E_RESET_MEMBER_EMAIL: 'e2e-reset-member@example.com',
  E2E_ADMIN_PASSWORD: 'Password123!',
});
