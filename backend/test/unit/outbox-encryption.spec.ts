import { describe, it, expect } from 'vitest';

import {
  OutboxEncryption,
  type OutboxEncryptionConfig,
} from '../../src/shared/outbox/outbox-encryption';

/**
 * backend/test/unit/outbox-encryption.spec.ts
 *
 * WHY:
 * - Ensures raw token + raw email are never stored in outbox payload.
 * - Ensures rotation behavior is explicit (unknown version / missing key => throw).
 *
 * RULES:
 * - Raw email must never appear in JSON.stringify(encryptedPayload).
 * - Avoid `any` in tests; construct typed configs.
 */

function base64Key32(char = 'a'): string {
  // 32 bytes -> base64
  return Buffer.from(char.repeat(32), 'utf8').toString('base64');
}

function cfgV1Only(): OutboxEncryptionConfig {
  return {
    defaultVersion: 'v1',
    keysByVersion: {
      v1: base64Key32('a'),
    },
  };
}

describe('OutboxEncryption', () => {
  it('encrypts token+email and decrypts back to original', () => {
    const enc = new OutboxEncryption(cfgV1Only());

    const raw = {
      token: 'tok_1234567890',
      toEmail: 'User@Example.com',
      tenantKey: 'goodwill-ca',
      userId: 'u1',
      inviteId: 'i1',
      role: 'MEMBER',
    };

    const encrypted = enc.encryptPayload(raw);

    expect(typeof encrypted.tokenEnc).toBe('string');
    expect(typeof encrypted.toEmailEnc).toBe('string');
    expect(encrypted.tokenEnc.startsWith('v1:')).toBe(true);
    expect(encrypted.toEmailEnc.startsWith('v1:')).toBe(true);

    const decrypted = enc.decryptPayload(encrypted);

    expect(decrypted.token).toBe(raw.token);
    expect(decrypted.toEmail).toBe('user@example.com');
    expect(decrypted.tenantKey).toBe(raw.tenantKey);
    expect(decrypted.userId).toBe(raw.userId);
    expect(decrypted.inviteId).toBe(raw.inviteId);
    expect(decrypted.role).toBe(raw.role);

    // PII rule: raw email must not appear
    const serialized = JSON.stringify(encrypted);
    expect(serialized.includes('User@Example.com')).toBe(false);
    expect(serialized.includes('user@example.com')).toBe(false);

    // Token must not appear either
    expect(serialized.includes(raw.token)).toBe(false);
  });

  it('throws when ciphertext has unknown version prefix', () => {
    const enc = new OutboxEncryption(cfgV1Only());
    expect(() => enc.decryptField('v9:AAAA')).toThrow(/missing key for version v9/i);
  });

  it('throws when ciphertext is missing version prefix', () => {
    const enc = new OutboxEncryption(cfgV1Only());
    expect(() => enc.decryptField('AAAA')).toThrow(/missing version prefix/i);
  });

  it('throws if defaultVersion has no configured key', () => {
    // This is a *runtime* invalid config (types allow v2, but key is missing).
    const bad: OutboxEncryptionConfig = {
      defaultVersion: 'v2',
      keysByVersion: { v1: base64Key32('x') },
    };

    expect(() => new OutboxEncryption(bad)).toThrow();
  });
});
