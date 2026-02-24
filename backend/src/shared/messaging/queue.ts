/**
 * src/shared/messaging/queue.ts
 *
 * WHY:
 * - Decouples "I need to send an email" from "here is how emails are sent".
 * - Auth service enqueues messages; the transport (SQS, SendGrid, etc.) is
 *   wired at the DI layer only. The service never changes when transport changes.
 *
 * RULES:
 * - Queue interface depends on nothing else in this codebase (shared → nothing).
 * - Message types are discriminated unions on the `type` field.
 * - Messages must be JSON-serializable.
 * - Raw tokens are allowed here — they travel to the email renderer so the
 *   tenant-scoped link can be built. They are never stored anywhere.
 * - Never put password hashes, session tokens, or bcrypt output in messages.
 *
 * BRICK 11 UPDATE:
 * - Added SignupVerificationEmailMessage for public signup email verification.
 * - Added to QueueMessage union.
 */

// ── Message types ─────────────────────────────────────────────

export type ResetPasswordEmailMessage = {
  type: 'auth.reset-password-email';
  userId: string;
  email: string;
  /**
   * Raw (un-hashed) reset token — goes into the email link only, never stored.
   * The link format is: https://{tenantKey}.hubins.com/reset-password?token={resetToken}
   */
  resetToken: string;
  /**
   * Needed to build the correct tenant-scoped reset URL without the email
   * renderer needing to query the database.
   */
  tenantKey: string;
};

/**
 * Brick 11 — Public Signup: email verification link sent to new users.
 *
 * The link format is:
 *   https://{tenantKey}.hubins.com/verify-email?token={verificationToken}
 *
 * Raw token travels here only — never stored, sent to email renderer only.
 */
export type SignupVerificationEmailMessage = {
  type: 'auth.signup-verification-email';
  userId: string;
  email: string;
  /**
   * Raw (un-hashed) verification token — goes into the email link only.
   */
  verificationToken: string;
  /**
   * Needed to build the correct tenant-scoped verification URL.
   */
  tenantKey: string;
};

// Union — add new message types as bricks grow
export type QueueMessage = ResetPasswordEmailMessage | SignupVerificationEmailMessage;

// ── Queue interface ───────────────────────────────────────────

export interface Queue {
  enqueue(message: QueueMessage): Promise<void>;
}
