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

type ErrorFactory = (meta?: AppErrorMeta) => AppError;

export const AdminInviteErrors: Record<string, ErrorFactory> = {
  emailAlreadyMember(meta?: AppErrorMeta): AppError {
    return AppError.conflict('This email already has an active membership.', meta);
  },

  emailSuspended(meta?: AppErrorMeta): AppError {
    return AppError.forbidden('This user account has been suspended.', meta);
  },

  inviteAlreadyExists(meta?: AppErrorMeta): AppError {
    return AppError.conflict('An active invite already exists for this email.', meta);
  },

  emailDomainNotPermitted(meta?: AppErrorMeta): AppError {
    return AppError.validationError('This email domain is not permitted for this workspace.', meta);
  },

  inviteNotFound(meta?: AppErrorMeta): AppError {
    return AppError.notFound('Invite not found.', meta);
  },

  inviteNotCancellable(meta?: AppErrorMeta): AppError {
    return AppError.conflict('This invite can no longer be cancelled.', meta);
  },

  inviteNotResendable(meta?: AppErrorMeta): AppError {
    return AppError.conflict('This invite can no longer be resent.', meta);
  },
};
