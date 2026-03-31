import { describe, expect, it } from 'vitest';

import {
  OutboxEncryption,
  type OutboxEncryptionConfig,
} from '../../src/shared/outbox/outbox-encryption';

/**
 * backend/test/unit/outbox-encryption.spec.ts
 *
 * WHY:
 * - Ensures raw token + raw email are never stored in outbox payload.
 * - Ensures rotation behavior is explicit and durable:
 *   - old ciphertext stays decryptable after rotation
 *   - new writes use the new default version
 *   - unknown/missing versions still fail closed
 *
 * RULES:
 * - Raw email must never appear in JSON.stringify(encryptedPayload).
 * - Avoid `any` in tests; construct typed configs.
 */

function base64Key32(char = 'a'): string {
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

function cfgV1V2(defaultVersion: 'v1' | 'v2' = 'v2'): OutboxEncryptionConfig {
  return {
    defaultVersion,
    keysByVersion: {
      v1: base64Key32('a'),
      v2: base64Key32('b'),
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

    const serialized = JSON.stringify(encrypted);
    expect(serialized.includes('User@Example.com')).toBe(false);
    expect(serialized.includes('user@example.com')).toBe(false);
    expect(serialized.includes(raw.token)).toBe(false);
  });

  it('decrypts legacy v1 ciphertext after rotation and uses v2 for new writes', () => {
    const legacyEnc = new OutboxEncryption(cfgV1Only());
    const rotatedEnc = new OutboxEncryption(cfgV1V2('v2'));

    const raw = {
      token: 'tok_rotation_123',
      toEmail: 'RotateMe@Example.com',
      tenantKey: 'goodwill-open',
      userId: 'u-rotation',
      inviteId: 'i-rotation',
      role: 'ADMIN',
    };

    const legacyCipher = legacyEnc.encryptPayload(raw);

    expect(legacyCipher.tokenEnc.startsWith('v1:')).toBe(true);
    expect(legacyCipher.toEmailEnc.startsWith('v1:')).toBe(true);

    const decryptedLegacy = rotatedEnc.decryptPayload(legacyCipher);

    expect(decryptedLegacy).toEqual({
      token: raw.token,
      toEmail: 'rotateme@example.com',
      tenantKey: raw.tenantKey,
      userId: raw.userId,
      inviteId: raw.inviteId,
      role: raw.role,
    });

    const rotatedCipher = rotatedEnc.encryptPayload(raw);

    expect(rotatedCipher.tokenEnc.startsWith('v2:')).toBe(true);
    expect(rotatedCipher.toEmailEnc.startsWith('v2:')).toBe(true);

    const decryptedRotated = rotatedEnc.decryptPayload(rotatedCipher);

    expect(decryptedRotated).toEqual({
      token: raw.token,
      toEmail: 'rotateme@example.com',
      tenantKey: raw.tenantKey,
      userId: raw.userId,
      inviteId: raw.inviteId,
      role: raw.role,
    });
  });

  it('supports explicit version selection during a staged rotation window', () => {
    const enc = new OutboxEncryption(cfgV1V2('v2'));

    const raw = {
      token: 'tok_explicit_v1',
      toEmail: 'Compat@Example.com',
    };

    const encrypted = enc.encryptPayload(raw, 'v1');

    expect(encrypted.tokenEnc.startsWith('v1:')).toBe(true);
    expect(encrypted.toEmailEnc.startsWith('v1:')).toBe(true);

    const decrypted = enc.decryptPayload(encrypted);

    expect(decrypted).toEqual({
      token: raw.token,
      toEmail: 'compat@example.com',
    });
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
    const bad: OutboxEncryptionConfig = {
      defaultVersion: 'v2',
      keysByVersion: { v1: base64Key32('x') },
    };

    expect(() => new OutboxEncryption(bad)).toThrow();
  });
});
