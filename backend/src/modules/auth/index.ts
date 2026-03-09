/**
 * src/modules/auth/index.ts
 *
 * WHY:
 * - Defines the public surface of the auth module.
 * - Prevents other modules from coupling to internal query paths.
 *
 * RULES:
 * - Only export stable contracts needed by other modules.
 * - Internal flows, policies, helpers, and dal are not exported.
 */

export { getMfaSecretForUser } from './queries/mfa.queries';
export type { MfaSecret } from './queries/mfa.queries';
