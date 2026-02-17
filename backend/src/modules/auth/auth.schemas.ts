/**
 * src/modules/auth/auth.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for the Auth module.
 * - Prevents invalid payloads from reaching services.
 *
 * RULES:
 * - Use Zod for runtime validation.
 * - Password rules: 8+ chars (more rules can be added later).
 * - Email normalized to lowercase in service, not here.
 * - Token min-length guards against obviously garbage values but does not
 *   validate the token cryptographically (that is the service's job).
 */

import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1, 'Name is required').max(200),
  inviteToken: z.string().min(20, 'Invalid invite token'),
});

export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

export type LoginInput = z.infer<typeof loginSchema>;

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
});

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;

export const resetPasswordSchema = z.object({
  /**
   * Raw reset token from the email link.
   * min(20) guards against obviously empty/garbage values.
   * The service validates cryptographic correctness (hash lookup + expiry).
   */
  token: z.string().min(20, 'Invalid reset token'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters'),
});

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// MFA (Brick 9)
// ─────────────────────────────────────────────────────────────────────────────

export const mfaCodeSchema = z.object({
  // 6-digit TOTP code
  code: z.string().regex(/^\d{6}$/, 'Code must be a 6-digit number'),
});

export type MfaCodeInput = z.infer<typeof mfaCodeSchema>;

export const mfaRecoverSchema = z.object({
  // Recovery codes are short printable tokens; exact validation is service-side.
  recoveryCode: z.string().min(8, 'Invalid recovery code').max(64, 'Invalid recovery code'),
});

export type MfaRecoverInput = z.infer<typeof mfaRecoverSchema>;
