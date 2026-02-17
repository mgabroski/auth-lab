/**
 * src/shared/security/totp.ts
 *
 * WHY:
 * - Thin wrapper over the otpauth library (RFC 6238 TOTP).
 * - Keeps the TOTP implementation detail isolated so we can swap libraries
 *   without touching MFA service code.
 *
 * RULES:
 * - No business logic here.
 * - No DB access.
 * - Secret is always passed in as a base32 string (decrypted by caller before use).
 * - generateSecret() returns a base32 string suitable for direct use in OTP URIs.
 *
 * WINDOW:
 * - ±1 step tolerance = 90-second window (prev, current, next 30s slot).
 * - RFC 6238 recommendation. Handles clock drift between client and server.
 * - otpauth `window` parameter: 1 means ±1 step.
 */

import * as OTPAuth from 'otpauth';

export class TotpService {
  private readonly issuer: string;

  private readonly ALGORITHM = 'SHA1';
  private readonly DIGITS = 6;
  private readonly PERIOD = 30;
  private readonly WINDOW = 1; // ±1 step tolerance

  constructor(issuer: string) {
    this.issuer = issuer;
  }

  /**
   * Generates a new random TOTP secret.
   * Returns a base32-encoded string ready for storage (after encryption).
   */
  generateSecret(): string {
    const secret = new OTPAuth.Secret({ size: 20 });
    return secret.base32;
  }

  /**
   * Builds a TOTP URI for QR code generation.
   * The URI is scanned by authenticator apps (Google Authenticator, Authy, etc.)
   *
   * @param secret - base32 secret (decrypted, plaintext)
   * @param email  - user's email (shown in authenticator app as account label)
   */
  buildUri(secret: string, email: string): string {
    const totp = new OTPAuth.TOTP({
      issuer: this.issuer,
      label: email,
      algorithm: this.ALGORITHM,
      digits: this.DIGITS,
      period: this.PERIOD,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    return totp.toString();
  }

  /**
   * Verifies a 6-digit TOTP code against the secret.
   * Returns true if the code is valid within ±1 step tolerance.
   *
   * @param secret - base32 secret (decrypted, plaintext)
   * @param code   - 6-digit code from authenticator app
   */
  verify(secret: string, code: string): boolean {
    const totp = new OTPAuth.TOTP({
      issuer: this.issuer,
      algorithm: this.ALGORITHM,
      digits: this.DIGITS,
      period: this.PERIOD,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({ token: code, window: this.WINDOW });
    return delta !== null;
  }

  /**
   * TEST-ONLY helper: generates a valid code for the current time window.
   * Used by E2E tests to avoid duplicating OTP library usage in service/tests.
   *
   * @testOnly
   */
  generateCodeForTest(secret: string): string {
    const totp = new OTPAuth.TOTP({
      issuer: this.issuer,
      algorithm: this.ALGORITHM,
      digits: this.DIGITS,
      period: this.PERIOD,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    return totp.generate();
  }
}
