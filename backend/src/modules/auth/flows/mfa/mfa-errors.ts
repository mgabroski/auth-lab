/**
 * backend/src/modules/auth/flows/mfa/mfa-errors.ts
 *
 * WHY:
 * - Keep MFA error mapping consistent across MFA flows.
 * - Pure HTTP error factories (no DB).
 */

import { AppError } from '../../../../shared/http/errors';

export const MfaErrors = {
  alreadyConfigured(): Error {
    // 409
    return AppError.conflict('MFA is already configured.');
  },
  noSetupInProgress(): Error {
    // 409
    return AppError.conflict('No MFA setup in progress.');
  },
  invalidCode(): Error {
    // 401 (authenticated but invalid MFA code)
    return AppError.unauthorized('Invalid code. Please try again.');
  },
  invalidRecoveryCode(): Error {
    // 401
    return AppError.unauthorized('Invalid recovery code.');
  },
  mfaNotConfigured(): Error {
    // 409
    return AppError.conflict('MFA is not configured.');
  },
  alreadyVerified(): Error {
    // 403
    return AppError.forbidden('MFA is already verified for this session.');
  },
};
