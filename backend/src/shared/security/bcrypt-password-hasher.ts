/**
 * backend/src/shared/security/bcrypt-password-hasher.ts
 *
 * WHY:
 * - Bcrypt is a battle-tested password hashing algorithm.
 * - We encapsulate it behind PasswordHasher so the rest of the app stays clean.
 *
 * HOW TO USE:
 * - const hasher = new BcryptPasswordHasher({ cost: 12 })
 * - const hash = await hasher.hash('secret')
 * - const ok = await hasher.verify('secret', hash)
 */

import bcrypt from 'bcrypt';
import type { PasswordHasher } from './password-hasher';

export class BcryptPasswordHasher implements PasswordHasher {
  private readonly cost: number;

  constructor(opts?: { cost?: number }) {
    this.cost = opts?.cost ?? 12;
  }

  async hash(plain: string): Promise<string> {
    return bcrypt.hash(plain, this.cost);
  }

  async verify(plain: string, hash: string): Promise<boolean> {
    return bcrypt.compare(plain, hash);
  }
}
