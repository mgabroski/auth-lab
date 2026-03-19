/**
 * frontend/test/e2e/helpers/totp.ts
 *
 * WHY:
 * - Playwright E2E tests for the MFA verify loop (test 11) and invite acceptance
 *   (test 12) need to compute a valid TOTP code from a base32 secret to simulate
 *   what a real authenticator app would do.
 * - Implementing this with Node.js built-ins (crypto module) avoids adding any
 *   new npm dependency to the frontend workspace.
 * - The algorithm is RFC 6238 TOTP, which is HMAC-SHA1(key, counter) with
 *   dynamic truncation to a 6-digit code. This is the same algorithm the backend
 *   TotpService uses (via the otpauth library). The results are identical.
 *
 * RULES:
 * - Only used by E2E tests. Never imported by application code.
 * - window param matches the backend's ±1 step tolerance. Passing window=0
 *   gives the current slot; window=1 gives the next slot (30 s ahead).
 *   Tests should use window=0 first. If clock skew causes a failure in CI,
 *   the test can retry with window=1 or window=-1.
 */

import { createHmac } from 'node:crypto';

/**
 * Decode a base32 string to a Uint8Array.
 * Accepts both uppercase and lowercase input. Ignores padding characters.
 */
function base32Decode(input: string): Uint8Array {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of cleaned) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`[totp] Invalid base32 character: '${char}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Generate a TOTP code for the given base32-encoded secret.
 *
 * @param base32Secret  Base32 TOTP secret as returned by POST /auth/mfa/setup
 * @param window        Time-step offset: 0 = current 30s slot, ±1 = adjacent slots.
 *                      Use 0 in tests. The backend accepts ±1 for clock tolerance.
 * @returns 6-digit code string, zero-padded (e.g. '012345')
 */
export function generateTotp(base32Secret: string, window = 0): string {
  const keyBytes = base32Decode(base32Secret);

  // Counter = floor(unix_seconds / 30) + window
  const counter = Math.floor(Date.now() / 1000 / 30) + window;

  // Encode counter as big-endian 8-byte buffer (HOTP spec)
  const counterBuf = Buffer.alloc(8);
  // High 32 bits
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  // Low 32 bits
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  // HMAC-SHA1(key, counter)
  const hmac = createHmac('sha1', Buffer.from(keyBytes));
  hmac.update(counterBuf);
  const digest = hmac.digest();

  // Dynamic truncation (RFC 4226 §5.3)
  const offset = digest[digest.length - 1] & 0x0f;
  const code =
    (((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff)) %
    1_000_000;

  return String(code).padStart(6, '0');
}
