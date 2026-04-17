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

  reservedAccountKey(accountKey: string) {
    return AppError.validationError(`Account key is reserved and cannot be used: ${accountKey}`, {
      accountKey,
    });
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

  integrationsValidation(message: string, meta?: Record<string, unknown>) {
    return AppError.validationError(message, meta);
  },

  personalValidation(message: string, meta?: Record<string, unknown>) {
    return AppError.validationError(message, meta);
  },

  statusToggleUnavailable(accountKey: string) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message: `Status toggle is available only after the account has been published once: ${accountKey}`,
      meta: { accountKey },
    });
  },

  activationReadyConflict(blockingReasons: string[]) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message: 'Active publish is blocked until Activation Ready passes.',
      meta: { blockingReasons },
    });
  },

  tenantProvisioningConflict(accountKey: string) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message: `Cannot publish account because tenant key is already provisioned outside Control Plane: ${accountKey}`,
      meta: { accountKey },
    });
  },
} as const;
