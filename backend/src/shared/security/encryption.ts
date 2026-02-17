/**
 * src/shared/security/encryption.ts
 *
 * WHY:
 * - TOTP secrets must be encrypted at rest (AES-256-GCM).
 * - If the mfa_secrets table is breached, the attacker cannot generate valid
 *   TOTP codes without also obtaining MFA_ENCRYPTION_KEY from the environment.
 *   This is defense-in-depth on top of database access controls.
 *
 * FORMAT:
 * - Stored as: base64(iv || authTag || ciphertext)
 * - iv: 12 bytes (GCM standard nonce size)
 * - authTag: 16 bytes (GCM authentication tag, ensures integrity)
 * - ciphertext: variable length
 *
 * KEY:
 * - 32-byte raw key (AES-256 requires 256-bit key = 32 bytes).
 * - The env var MFA_ENCRYPTION_KEY is expected as a base64-encoded 32-byte key.
 *   Generate with: openssl rand -base64 32
 *
 * RULES:
 * - A new random IV is generated for EVERY encryption call (never reuse IVs).
 * - No business logic here. No DB access.
 * - Caller is responsible for providing the key from config (never hardcoded).
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // bytes — GCM standard
const TAG_LENGTH = 16; // bytes — GCM auth tag

export class EncryptionService {
  private readonly key: Buffer;

  constructor(base64Key: string) {
    this.key = Buffer.from(base64Key, 'base64');

    if (this.key.length !== 32) {
      throw new Error(
        `EncryptionService: key must be 32 bytes (256 bits). Got ${this.key.length} bytes. ` +
          'Generate with: openssl rand -base64 32',
      );
    }
  }

  /**
   * Encrypts plaintext using AES-256-GCM.
   * Returns a single base64 string: base64(iv || authTag || ciphertext).
   */
  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv, { authTagLength: TAG_LENGTH });

    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Pack: iv (12) || authTag (16) || ciphertext (n)
    const packed = Buffer.concat([iv, authTag, encrypted]);
    return packed.toString('base64');
  }

  /**
   * Decrypts a base64 string produced by encrypt().
   * Throws if the ciphertext has been tampered with (GCM auth tag mismatch).
   */
  decrypt(packed64: string): string {
    const packed = Buffer.from(packed64, 'base64');

    if (packed.length < IV_LENGTH + TAG_LENGTH) {
      throw new Error('EncryptionService: ciphertext too short to be valid');
    }

    const iv = packed.subarray(0, IV_LENGTH);
    const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = packed.subarray(IV_LENGTH + TAG_LENGTH);

    const decipher = createDecipheriv(ALGORITHM, this.key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  }
}
