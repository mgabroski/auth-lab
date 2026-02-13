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
 * - Raw reset token is allowed here — it travels to the email renderer so the
 *   tenant-scoped link can be built. It is never stored anywhere.
 * - Never put password hashes, session tokens, or bcrypt output in messages.
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

// Union — add new message types as bricks grow (invites, email verification, MFA...)
export type QueueMessage = ResetPasswordEmailMessage;

// ── Queue interface ───────────────────────────────────────────

export interface Queue {
  enqueue(message: QueueMessage): Promise<void>;
}
