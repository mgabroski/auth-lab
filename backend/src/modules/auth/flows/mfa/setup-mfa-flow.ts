/**
 * backend/src/modules/auth/flows/mfa/setup-mfa-flow.ts
 *
 * WHY:
 * - Deep module for MFA setup (Brick 9a).
 * - Keeps AuthService thin; preserves behavior exactly.
 *
 * RULES:
 * - If verified secret exists -> conflict
 * - If unverified secret exists -> delete + recreate (inside transaction)
 * - Creates recovery codes, stores keyed hashes
 * - Audits setup started (inside transaction — success audit commits atomically)
 *
 * X3 — MFA setup atomicity:
 * - Previously: insertMfaSecret → insertRecoveryCodes → audit ran sequentially
 *   with no transaction. A crash after insertMfaSecret left an orphaned secret
 *   with zero recovery codes, blocking the user from any MFA path without admin
 *   intervention.
 * - Fix: all DB writes (delete old secret if present, insert new secret, insert
 *   recovery codes, audit) are wrapped in a single transaction. Either all
 *   succeed or none do.
 * - Pure computation (generateSecret, encrypt, generate codes, compute hashes,
 *   build QR URI) is kept OUTSIDE the transaction — no I/O inside tx boundaries
 *   that isn't DB work.
 *
 * X9 — Unbiased recovery code generation:
 * - Previously: bytes[j] % 62 introduces modulo bias. 256 % 62 = 8, so the
 *   first 8 charset characters appear with probability 5/256 instead of 4/256.
 *   Cryptographic selection must use a uniform distribution.
 * - Fix: rejection sampling. MAX_UNBIASED = 256 - (256 % 62) = 248. Any byte
 *   >= 248 is discarded and a new byte is drawn. Expected overhead: ~3.1%
 *   extra bytes drawn per character — negligible.
 */

import { randomBytes } from 'node:crypto';

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../../shared/db/db';

import { AppError } from '../../../../shared/http/errors';
import type { TotpService } from '../../../../shared/security/totp';
import type { EncryptionService } from '../../../../shared/security/encryption';
import type { KeyedHasher } from '../../../../shared/security/keyed-hasher';

import type { MfaRepo } from '../../dal/mfa.repo';
import { getUserById } from '../../../users';
import { getMfaSecretForUser } from '../../queries/mfa.queries';

import { auditMfaSetupStarted } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';
import { MFA_RECOVERY_CODES_COUNT } from '../../auth.constants';

// ─── Recovery code generation constants (X9) ───────────────────────────────
const RECOVERY_CODE_LENGTH = 16;
const RECOVERY_CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const CHARSET_LEN = RECOVERY_CODE_CHARSET.length; // 62
/**
 * MAX_UNBIASED = 256 - (256 % 62) = 248.
 * Bytes in [248, 255] are rejected and resampled so that the remaining
 * [0, 247] range maps onto charset indices with a perfectly uniform distribution.
 */
const MAX_UNBIASED = 256 - (256 % CHARSET_LEN); // 248

/**
 * Returns a single charset index using rejection sampling.
 * Expected iterations per call: 256 / 248 ≈ 1.032 (negligible overhead).
 */
function unbiasedCharIndex(): number {
  let byte: number;
  do {
    byte = randomBytes(1)[0];
  } while (byte >= MAX_UNBIASED);
  return byte % CHARSET_LEN;
}

/**
 * Generates `count` recovery codes of `RECOVERY_CODE_LENGTH` characters each,
 * drawn uniformly from `RECOVERY_CODE_CHARSET`.
 */
function generateUnbiasedRecoveryCodes(count: number): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    let code = '';
    for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
      code += RECOVERY_CODE_CHARSET[unbiasedCharIndex()];
    }
    codes.push(code);
  }
  return codes;
}

// ─── Flow ──────────────────────────────────────────────────────────────────

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

  // ── Guard: read existing state OUTSIDE transaction ────────────────────────
  const existing = await getMfaSecretForUser(deps.db, input.userId);
  if (existing?.isVerified) throw MfaErrors.alreadyConfigured();

  // ── Pure computation OUTSIDE transaction (no I/O) ─────────────────────────
  // Generate all values before opening the transaction so the tx window is as
  // narrow as possible — only DB writes belong inside.
  const plaintextSecret = deps.totpService.generateSecret();
  const secretEncrypted = deps.encryptionService.encrypt(plaintextSecret);

  // X9: unbiased rejection-sampling replaces the old bytes[j] % 62 pattern.
  const recoveryCodes = generateUnbiasedRecoveryCodes(MFA_RECOVERY_CODES_COUNT);
  const codeHashes = recoveryCodes.map((code) => deps.mfaKeyedHasher.hash(code));

  // QR URI is pure computation (no DB) — computed outside tx.
  const user = await getUserById(deps.db, input.userId);
  if (!user) throw AppError.unauthorized('Session expired. Please sign in again.');

  // LOCK-2: Authenticator label must be the verified user email, not userId.
  const qrCodeUri = deps.totpService.buildUri(plaintextSecret, user.email);

  // ── Atomic transaction: all-or-nothing DB writes (X3) ────────────────────
  // Two-phase audit rule: success audit (auditMfaSetupStarted) goes INSIDE
  // the transaction so it commits atomically with the data it describes.
  await deps.db.transaction().execute(async (trx) => {
    const txMfaRepo = deps.mfaRepo.withDb(trx);

    // If a stale unverified secret exists, replace it atomically.
    // Doing this inside the transaction ensures we never end up with a deleted
    // secret but no replacement (e.g. crash between delete and insert).
    if (existing && !existing.isVerified) {
      await txMfaRepo.deleteUnverifiedMfaSecret({ userId: input.userId });
    }

    await txMfaRepo.insertMfaSecret({
      userId: input.userId,
      secretEncrypted,
    });

    await txMfaRepo.insertRecoveryCodes({
      userId: input.userId,
      codeHashes,
    });

    // Success audit inside transaction — commits with the data it describes.
    const txAudit = new AuditWriter(deps.auditRepo.withDb(trx), {
      requestId: input.requestId,
      ip: input.ip,
      userAgent: input.userAgent,
    }).withContext({
      tenantId: input.tenantId,
      userId: input.userId,
      membershipId: input.membershipId,
    });

    await auditMfaSetupStarted(txAudit, { userId: input.userId });
  });

  return { secret: plaintextSecret, qrCodeUri, recoveryCodes };
}
