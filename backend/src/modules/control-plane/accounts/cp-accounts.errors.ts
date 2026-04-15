/**
 * backend/src/modules/control-plane/accounts/cp-accounts.errors.ts
 *
 * WHY:
 * - Module-scoped semantic error factories for CP accounts.
 * - Keeps shared AppError clean of CP-specific semantics.
 */

import { AppError } from '../../../shared/http/errors';

export const CpAccountErrors = {
  notFound(accountKey: string) {
    return AppError.notFound(`CP account not found: ${accountKey}`);
  },

  accountKeyConflict(accountKey: string) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message: `Account key is already taken: ${accountKey}`,
      meta: { accountKey },
    });
  },

  accessDependencyConflict(message: string, meta?: Record<string, unknown>) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message,
      meta,
    });
  },

  integrationsDependencyConflict(message: string, meta?: Record<string, unknown>) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message,
      meta,
    });
  },

  personalValidation(message: string, meta?: Record<string, unknown>) {
    return AppError.validationError(message, meta);
  },
} as const;
