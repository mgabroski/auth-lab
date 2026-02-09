/**
 * backend/src/shared/security/sha256-token-hasher.ts
 *
 * WHY:
 * - Concrete TokenHasher implementation using SHA-256.
 * - Fast, deterministic, widely supported.
 *
 * HOW TO USE:
 * - const hasher = new Sha256TokenHasher()
 * - const hash = hasher.hash(token)
 */

import { createHash } from 'node:crypto';
import type { TokenHasher } from './token-hasher';

export class Sha256TokenHasher implements TokenHasher {
  hash(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }
}
