/**
 * backend/src/shared/outbox/outbox-encryption.ts
 *
 * WHY:
 * - Outbox payload must never store raw token or raw email.
 * - Supports key rotation via version prefixes: "v1:..." / "v2:..."
 *
 * RULES:
 * - Uses AES-256-GCM via EncryptionService.
 * - Every encrypted field is prefixed with keyVersion: `${version}:${ciphertext}`
 * - decrypt requires the version to be known; unknown/missing version throws.
 * - Raw email must never appear in JSON.stringify(encryptedPayload).
 */

import { EncryptionService } from '../security/encryption';

export type OutboxEncVersion = `v${number}`;

export type OutboxEncryptionConfig = {
  defaultVersion: OutboxEncVersion;
  keysByVersion: Record<OutboxEncVersion, string>; // base64 32-byte keys
};

export type RawOutboxPayload = {
  token: string;
  toEmail: string;
  tenantKey?: string;
  userId?: string;
  inviteId?: string;
  role?: string;
};

export type EncryptedOutboxPayload = {
  tokenEnc: string; // "v1:..."
  toEmailEnc: string; // "v1:..."
  tenantKey?: string;
  userId?: string;
  inviteId?: string;
  role?: string;
};

function assertVersionKnown(cfg: OutboxEncryptionConfig, version: OutboxEncVersion): void {
  const key = cfg.keysByVersion[version];
  if (!key) {
    throw new Error(`OutboxEncryption: missing key for version ${version}`);
  }
}

function parseVersionedCiphertext(input: string): {
  version: OutboxEncVersion;
  ciphertext: string;
} {
  const idx = input.indexOf(':');
  if (idx <= 0) {
    throw new Error('OutboxEncryption: ciphertext missing version prefix');
  }
  const version = input.slice(0, idx) as OutboxEncVersion;
  const ciphertext = input.slice(idx + 1);
  if (!version.startsWith('v') || ciphertext.length === 0) {
    throw new Error('OutboxEncryption: invalid versioned ciphertext format');
  }
  return { version, ciphertext };
}

export class OutboxEncryption {
  constructor(private readonly cfg: OutboxEncryptionConfig) {
    assertVersionKnown(cfg, cfg.defaultVersion);
  }

  encryptPayload(
    payload: RawOutboxPayload,
    version: OutboxEncVersion = this.cfg.defaultVersion,
  ): EncryptedOutboxPayload {
    assertVersionKnown(this.cfg, version);

    const svc = new EncryptionService(this.cfg.keysByVersion[version]);
    const tokenEnc = `${version}:${svc.encrypt(payload.token)}`;
    const toEmailEnc = `${version}:${svc.encrypt(payload.toEmail.toLowerCase())}`;

    return {
      tokenEnc,
      toEmailEnc,
      tenantKey: payload.tenantKey,
      userId: payload.userId,
      inviteId: payload.inviteId,
      role: payload.role,
    };
  }

  decryptPayload(payload: EncryptedOutboxPayload): RawOutboxPayload {
    const token = this.decryptField(payload.tokenEnc);
    const toEmail = this.decryptField(payload.toEmailEnc);

    return {
      token,
      toEmail,
      tenantKey: payload.tenantKey,
      userId: payload.userId,
      inviteId: payload.inviteId,
      role: payload.role,
    };
  }

  decryptField(versionedCiphertext: string): string {
    const { version, ciphertext } = parseVersionedCiphertext(versionedCiphertext);
    assertVersionKnown(this.cfg, version);

    const svc = new EncryptionService(this.cfg.keysByVersion[version]);
    return svc.decrypt(ciphertext);
  }
}
