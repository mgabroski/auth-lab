/**
 * backend/src/modules/invites/admin/admin-invite.errors.ts
 *
 * WHY:
 * - Admin invite operations have distinct failure modes from public invite acceptance.
 * - Keeping these here prevents invite.errors.ts from conflating public and admin semantics.
 *
 * RULES:
 * - Use AppError as the transport primitive.
 * - Never include raw tokens in meta.
 * - Cross-tenant lookups return 404 — never 403 — to avoid leaking existence.
 */

import { AppError, type AppErrorMeta } from '../../../shared/http/errors';

export const AdminInviteErrors = {
  emailAlreadyMember(meta?: AppErrorMeta) {
    return AppError.conflict('This email already has an active membership.', meta);
  },

  emailSuspended(meta?: AppErrorMeta) {
    return AppError.forbidden('This user account has been suspended.', meta);
  },

  inviteAlreadyExists(meta?: AppErrorMeta) {
    return AppError.conflict('An active invite already exists for this email.', meta);
  },

  emailDomainNotPermitted(meta?: AppErrorMeta) {
    return AppError.forbidden('This email domain is not permitted for this workspace.', meta);
  },

  inviteNotFound(meta?: AppErrorMeta) {
    return AppError.notFound('Invite not found.', meta);
  },

  inviteNotResendable(meta?: AppErrorMeta) {
    return AppError.conflict('Only pending invites can be resent.', meta);
  },

  inviteNotCancellable(meta?: AppErrorMeta) {
    return AppError.conflict('Only pending invites can be cancelled.', meta);
  },
} as const;
