/**
 * backend/src/shared/http/require-auth-context.ts
 *
 * WHY:
 * - Centralizes session/auth guards so controllers don’t drift.
 *
 * RULES:
 * - No DB access.
 * - Throws AppError for consistent error handling.
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
  emailVerified: boolean;
}>;

export type RequireSessionOptions = Readonly<{
  role?: MembershipRole;
  requireMfa?: boolean;
  requireEmailVerified?: boolean;
}>;

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

  if (opts.requireEmailVerified && ctx.emailVerified !== true) {
    throw AppError.forbidden('Email verification required.');
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
    emailVerified: ctx.emailVerified,
  };
}
