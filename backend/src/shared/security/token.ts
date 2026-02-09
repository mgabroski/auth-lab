/**
 * backend/src/shared/security/token.ts
 *
 * WHY:
 * - Token generation should be consistent and strong across the system.
 * - We generate raw tokens that are safe for URLs.
 *
 * HOW TO USE:
 * - const token = generateSecureToken()
 * - Send token to user (email link), store only hash in DB.
 */

import { randomBytes } from 'node:crypto';

export function generateSecureToken(bytes: number = 32): string {
  // URL-safe base64 (no + / =)
  return randomBytes(bytes).toString('base64url');
}
