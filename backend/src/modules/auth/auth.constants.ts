/**
 * backend/src/modules/auth/auth.constants.ts
 *
 * WHY:
 * - Central place for auth domain constants shared across flows.
 * - Keeps refactors safe: values are single-sourced and reused without behavior change.
 *
 * RULES:
 * - Must not import from DB/HTTP/framework code.
 * - Keep values identical to pre-refactor inline constants.
 */

export const AUTH_RATE_LIMITS = {
  login: {
    perEmail: { limit: 5, windowSeconds: 900 },
    perIp: { limit: 20, windowSeconds: 900 },
  },
  register: {
    perEmail: { limit: 5, windowSeconds: 900 },
    perIp: { limit: 20, windowSeconds: 900 },
  },
  forgotPassword: {
    perEmail: { limit: 3, windowSeconds: 3600 }, // silent
  },
  resetPassword: {
    perIp: { limit: 5, windowSeconds: 900 }, // hard 429
  },
  mfaVerify: {
    perUser: { limit: 5, windowSeconds: 900 }, // hard 429
  },
  mfaRecover: {
    perUser: { limit: 5, windowSeconds: 900 }, // hard 429
  },
} as const;
