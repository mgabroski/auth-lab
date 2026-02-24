/**
 * backend/src/modules/auth/auth.constants.ts
 *
 * WHY:
 * - Central place for auth domain constants shared across flows.
 * - Keeps refactors safe: values are single-sourced and reused without behavior change.
 *
 * RULES:
 * - Must not import from DB/HTTP/framework code.
 *
 * BRICK 11 UPDATE:
 * - Added signup rate limits (perEmail hard, perIp hard).
 * - Added resendVerification rate limit (perEmail silent — same pattern as forgotPassword).
 * - Added verifyEmail rate limit (perIp hard — Decision 5: 10/IP/15min).
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

  // Brick 10 (SSO)
  ssoStart: {
    perIp: { limit: 20, windowSeconds: 900 },
  },
  ssoCallback: {
    perIp: { limit: 20, windowSeconds: 900 },
  },

  // Brick 11 (Public Signup + Email Verification)
  signup: {
    perEmail: { limit: 5, windowSeconds: 900 }, // hard 429
    perIp: { limit: 20, windowSeconds: 900 }, // hard 429
  },
  verifyEmail: {
    perIp: { limit: 10, windowSeconds: 900 }, // hard 429 — Decision 5
  },
  resendVerification: {
    perEmail: { limit: 3, windowSeconds: 3600 }, // silent — same pattern as forgotPassword
  },
} as const;

/**
 * MFA recovery codes count is a product + security invariant.
 * Locked at 8.
 */
export const MFA_RECOVERY_CODES_COUNT = 8 as const;

/**
 * Email verification token TTL.
 * User has 24 hours to click the link.
 */
export const EMAIL_VERIFICATION_TTL_SECONDS = 60 * 60 * 24; // 24 hours
