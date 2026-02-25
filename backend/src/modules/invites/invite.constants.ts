/**
 * backend/src/modules/invites/invite.constants.ts
 *
 * WHY:
 * - Single source of truth for invite TTL and admin rate limit config.
 * - Prevents magic numbers scattered across service and test files.
 *
 * RULES:
 * - Must not import from DB, HTTP, or framework code.
 * - Rate limit objects use the same shape as AUTH_RATE_LIMITS for consistency.
 */

export const INVITE_TTL_DAYS = 7;

export const ADMIN_INVITE_RATE_LIMITS = {
  createInvite: {
    perAdminPerTenant: { limit: 10, windowSeconds: 3600 },
  },
  resendInvite: {
    perAdminPerTenant: { limit: 10, windowSeconds: 3600 },
  },
} as const;
