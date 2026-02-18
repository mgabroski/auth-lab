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

export function requireAuthContext(req: FastifyRequest): RequiredAuthContext {
  const ctx = req.authContext;
  if (!ctx) throw AppError.unauthorized('Not authenticated');

  if (!ctx.sessionId || !ctx.userId || !ctx.tenantId || !ctx.membershipId || !ctx.role) {
    throw AppError.unauthorized('Not authenticated');
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
