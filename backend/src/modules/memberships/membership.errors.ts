/**
 * backend/src/modules/memberships/membership.errors.ts
 *
 * WHY:
 * - Memberships module owns its domain semantics.
 * - Keeps shared/http/errors.ts small and stable.
 *
 * SECURITY:
 * - "No access" errors must not reveal whether a user exists in another tenant.
 * - Suspended messages are intentionally vague.
 *
 * RULES:
 * - Use AppError as the transport primitive.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const MembershipErrors = {
  membershipNotFound(meta?: AppErrorMeta) {
    return AppError.notFound('You do not have access to this workspace.', meta);
  },

  membershipNotActive(meta?: AppErrorMeta) {
    return AppError.forbidden('Your membership is not active.', meta);
  },

  membershipSuspended(meta?: AppErrorMeta) {
    return AppError.forbidden('Your account has been suspended.', meta);
  },

  membershipStillInvited(meta?: AppErrorMeta) {
    return AppError.conflict('You need to accept your invitation first.', meta);
  },

  membershipAlreadyExists(meta?: AppErrorMeta) {
    return AppError.conflict('A membership already exists for this user and tenant.', meta);
  },
} as const;
