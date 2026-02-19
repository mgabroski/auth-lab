/**
 * backend/src/shared/http/require-auth-context.ts
 *
 * WHY:
 * - Controllers must not duplicate "require session/auth" logic.
 * - Centralizes authContext validation to prevent drift across endpoints.
 *
 * RULES:
 * - HTTP-only helper (may depend on Fastify request typing).
 * - Must NOT touch DB, services, or transactions.
 * - Throws AppError so error-handler maps it consistently.
 */

import type { FastifyRequest } from 'fastify';
import { AppError } from './errors';
import type { MembershipRole } from '../../modules/memberships/membership.types';

export type RequiredAuthContext = Readonly<{
  sessionId: string;
  userId: string;
  tenantId: string;
  membershipId: string;
  role: MembershipRole;
  mfaVerified: boolean;
}>;

export type RequireSessionOptions = Readonly<{
  role?: MembershipRole;
  requireMfa?: boolean;
}>;

/**
 * Controller guard: requires a session, and optionally enforces role + MFA.
 *
 * Guard sequence (LOCKED):
 * 1) no session -> 401 "Authentication required"
 * 2) wrong role -> 403 "Insufficient role."
 * 3) mfaVerified false (when requireMfa) -> 403 "MFA verification required."
 */
export function requireSession(
  req: FastifyRequest,
  opts: RequireSessionOptions = {},
): RequiredAuthContext {
  const ctx = req.authContext;
  if (!ctx) throw AppError.unauthorized('Authentication required');

  if (!ctx.sessionId || !ctx.userId || !ctx.tenantId || !ctx.membershipId || !ctx.role) {
    throw AppError.unauthorized('Authentication required');
  }

  if (opts.role && ctx.role !== opts.role) {
    throw AppError.forbidden('Insufficient role.');
  }

  if (opts.requireMfa && ctx.mfaVerified !== true) {
    throw AppError.forbidden('MFA verification required.');
  }

  return {
    sessionId: ctx.sessionId,
    userId: ctx.userId,
    tenantId: ctx.tenantId,
    membershipId: ctx.membershipId,
    role: ctx.role,
    mfaVerified: ctx.mfaVerified,
  };
}

// Backward-compatible alias (legacy name used by older controllers)
export function requireAuthContext(req: FastifyRequest): RequiredAuthContext {
  return requireSession(req);
}
