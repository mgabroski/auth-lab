/**
 * backend/src/modules/auth/flows/mfa/setup-mfa-flow.ts
 *
 * WHY:
 * - Deep module for MFA setup (Brick 9a).
 * - Keeps AuthService thin; preserves behavior exactly.
 *
 * RULES:
 * - If verified secret exists -> conflict
 * - If unverified secret exists -> delete + recreate
 * - Creates recovery codes, stores keyed hashes
 * - Audits setup started
 */

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../../shared/db/db';

import type { TotpService } from '../../../../shared/security/totp';
import type { EncryptionService } from '../../../../shared/security/encryption';
import type { KeyedHasher } from '../../../../shared/security/keyed-hasher';

import type { MfaRepo } from '../../dal/mfa.repo';
import { getMfaSecretForUser } from '../../queries/mfa.queries';

import { auditMfaSetupStarted } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';
import { MFA_RECOVERY_CODES_COUNT } from '../../auth.constants';

const RECOVERY_CODE_LENGTH = 16;
const RECOVERY_CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export async function setupMfaFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    mfaRepo: MfaRepo;
    totpService: TotpService;
    encryptionService: EncryptionService;
    mfaKeyedHasher: KeyedHasher;
  };
  input: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  };
}): Promise<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }> {
  const { deps, input } = params;

  const audit = new AuditWriter(deps.auditRepo, {
    requestId: input.requestId,
    ip: input.ip,
    userAgent: input.userAgent,
  }).withContext({
    tenantId: input.tenantId,
    userId: input.userId,
    membershipId: input.membershipId,
  });

  const existing = await getMfaSecretForUser(deps.db, input.userId);
  if (existing?.isVerified) throw MfaErrors.alreadyConfigured();

  if (existing && !existing.isVerified) {
    await deps.mfaRepo.deleteUnverifiedMfaSecret({ userId: input.userId });
  }

  const plaintextSecret = deps.totpService.generateSecret();
  const secretEncrypted = deps.encryptionService.encrypt(plaintextSecret);

  await deps.mfaRepo.insertMfaSecret({
    userId: input.userId,
    secretEncrypted,
  });

  const { randomBytes } = await import('node:crypto');

  const recoveryCodes: string[] = [];
  for (let i = 0; i < MFA_RECOVERY_CODES_COUNT; i++) {
    const bytes = randomBytes(RECOVERY_CODE_LENGTH);
    let code = '';
    for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
      code += RECOVERY_CODE_CHARSET[bytes[j] % RECOVERY_CODE_CHARSET.length];
    }
    recoveryCodes.push(code);
  }

  const codeHashes = recoveryCodes.map((code) => deps.mfaKeyedHasher.hash(code));

  await deps.mfaRepo.insertRecoveryCodes({
    userId: input.userId,
    codeHashes,
  });

  // R-07: QR label is userId (no cross-module user lookup)
  const qrCodeUri = deps.totpService.buildUri(plaintextSecret, input.userId);

  await auditMfaSetupStarted(audit, { userId: input.userId });

  return { secret: plaintextSecret, qrCodeUri, recoveryCodes };
}
