/**
 * backend/src/modules/control-plane/accounts/cp-accounts.errors.ts
 *
 * WHY:
 * - Module-scoped semantic error factories for CP accounts.
 * - Keeps shared AppError clean of module-specific semantics.
 *
 * RULES:
 * - All factories return AppError instances.
 * - No raw throws here — callers throw the returned value.
 * - Error messages are operator-facing (internal CP surface).
 */

import { AppError } from '../../../shared/http/errors';

export const CpAccountErrors = {
  /**
   * Thrown when the requested accountKey does not exist in cp_accounts.
   */
  notFound(accountKey: string) {
    return AppError.notFound(`CP account not found: ${accountKey}`);
  },

  /**
   * Thrown when a POST /cp/accounts is submitted with an accountKey
   * that already exists in cp_accounts.
   */
  accountKeyConflict(accountKey: string) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message: `Account key is already taken: ${accountKey}`,
      meta: { accountKey },
    });
  },
} as const;
