import type { AppDeps } from '../../src/app/di';

export type AuthCryptoHelpers = Readonly<{
  generateTotpSecret: () => string;
  encryptSecret: (plaintextSecret: string) => string;
  generateTotpCode: (plaintextSecret: string) => string;
  hashRecoveryCode: (recoveryCode: string) => string;
}>;

/**
 * WHY:
 * - Tests sometimes need to seed VERIFIED MFA secrets / recovery codes directly in the DB.
 * - Production AuthService must not expose @testOnly crypto helpers (SRP).
 *
 * RULES:
 * - Test-only helper.
 * - Delegates to real crypto primitives from AppDeps (totp/encryption/hmac hasher).
 * - Does NOT call HTTP endpoints or open transactions.
 */
export function createAuthCryptoHelpers(
  deps: Pick<AppDeps, 'totpService' | 'encryptionService' | 'mfaKeyedHasher'>,
): AuthCryptoHelpers {
  return {
    generateTotpSecret: () => deps.totpService.generateSecret(),
    encryptSecret: (plaintextSecret: string) => deps.encryptionService.encrypt(plaintextSecret),
    generateTotpCode: (plaintextSecret: string) =>
      deps.totpService.generateCodeForTest(plaintextSecret),
    hashRecoveryCode: (recoveryCode: string) => deps.mfaKeyedHasher.hash(recoveryCode),
  };
}
