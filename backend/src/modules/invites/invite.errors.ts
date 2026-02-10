/**
 * backend/src/modules/invites/invite.errors.ts
 *
 * WHY:
 * - Invites module owns its domain semantics.
 * - Prevents shared/http/errors.ts from becoming a giant god-file.
 *
 * SECURITY:
 * - Token failures must not leak whether a token exists.
 * - Cross-tenant mismatches intentionally return NOT_FOUND.
 *
 * RULES:
 * - Use AppError as the transport primitive.
 * - Never include raw tokens in meta.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const InviteErrors = {
  invalidToken(meta?: AppErrorMeta) {
    return AppError.notFound('Invite not found', meta);
  },

  inviteNotFound(meta?: AppErrorMeta) {
    return AppError.notFound('Invite not found', meta);
  },

  inviteExpired(meta?: AppErrorMeta) {
    return AppError.conflict('Invite has expired', meta);
  },

  inviteAlreadyAccepted(meta?: AppErrorMeta) {
    return AppError.conflict('Invite already accepted', meta);
  },

  inviteNotPending(meta?: AppErrorMeta) {
    return AppError.conflict('Invite is not valid', meta);
  },

  tenantMismatch(meta?: AppErrorMeta) {
    return AppError.notFound('Invite not found', meta);
  },
} as const;
