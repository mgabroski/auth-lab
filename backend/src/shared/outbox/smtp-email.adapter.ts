/**
 * backend/src/shared/outbox/smtp-email.adapter.ts
 *
 * WHY:
 * - Production email delivery via SMTP (works with AWS SES, Postmark, Mailgun,
 *   or any standard SMTP relay by pointing SMTP_HOST at their endpoint).
 * - Implements the same EmailAdapter interface as NoopEmailAdapter so DI can
 *   swap implementations without touching any flow or worker code.
 *
 * RULES:
 * - Must never log raw tokens or raw recipient emails — use emailHash.
 * - send() is called at-least-once by the outbox worker. The idempotencyKey
 *   deduplication is owned at the outbox DB layer (UNIQUE constraint on
 *   idempotency_key). This adapter does not need to deduplicate — the worker
 *   will not re-send a message that was already marked 'sent' in the DB.
 * - All 3 message types (password.reset, email.verify, invite.created) must
 *   produce a well-formed email. If a new message type is added to OutboxRepo,
 *   this file must be updated to handle it.
 * - Never swallow errors. Throw RetryableEmailError for transient failures
 *   (SMTP connection issues). Throw NonRetryableEmailError for permanent
 *   failures (invalid recipient, auth failure). The worker handles retry
 *   scheduling and dead-lettering based on which error type is thrown.
 *
 * TEMPLATE DESIGN:
 * - Plain text only to avoid HTML injection risks and maximize deliverability.
 * - Token links are constructed from tenantKey + configurable public base URL.
 * - All templates include the Hubins brand name and the tenant name where known.
 */

import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

import type { Logger } from '../logger/logger';
import type { TokenHasher } from '../security/token-hasher';
import type { EmailAdapter, PlainOutboxPayload } from './email.adapter';
import type { OutboxMessageType } from './outbox.repo';
import { RetryableEmailError, NonRetryableEmailError } from './outbox.worker';

// ─── Config ──────────────────────────────────────────────────────────────────

export type SmtpEmailAdapterConfig = {
  host: string;
  port: number;
  /** Whether to use TLS from connection start (true for port 465). */
  secure: boolean;
  /** Optional — omit for relay servers that do not require auth. */
  auth?: {
    user: string;
    pass: string;
  };
  /** RFC 5321 "From" header value. E.g. "Hubins <noreply@hubins.com>" */
  from: string;
  /**
   * Public base URL used to construct token links.
   * E.g. "https://{tenantKey}.hubins.com"
   * The adapter replaces "{tenantKey}" with the actual tenant key from the payload.
   */
  publicBaseUrl: string;
};

// ─── Email templates ──────────────────────────────────────────────────────────

function buildPasswordResetEmail(opts: {
  token: string;
  tenantKey: string | undefined;
  publicBaseUrl: string;
}): { subject: string; text: string } {
  const origin = opts.tenantKey
    ? opts.publicBaseUrl.replace('{tenantKey}', opts.tenantKey)
    : opts.publicBaseUrl;

  const link = `${origin}/auth/reset-password?token=${encodeURIComponent(opts.token)}`;

  return {
    subject: 'Reset your Hubins password',
    text: [
      'You requested a password reset for your Hubins account.',
      '',
      'Click the link below to set a new password. This link expires in 1 hour.',
      '',
      link,
      '',
      'If you did not request this, you can safely ignore this email.',
      'Your password will not change unless you click the link above.',
      '',
      '— Hubins',
    ].join('\n'),
  };
}

function buildEmailVerifyEmail(opts: {
  token: string;
  tenantKey: string | undefined;
  publicBaseUrl: string;
}): { subject: string; text: string } {
  const origin = opts.tenantKey
    ? opts.publicBaseUrl.replace('{tenantKey}', opts.tenantKey)
    : opts.publicBaseUrl;

  const link = `${origin}/verify-email?token=${encodeURIComponent(opts.token)}`;

  return {
    subject: 'Verify your Hubins email address',
    text: [
      'Please verify your email address to activate your Hubins account.',
      '',
      'Click the link below to complete verification. This link expires in 24 hours.',
      '',
      link,
      '',
      'If you did not create a Hubins account, you can safely ignore this email.',
      '',
      '— Hubins',
    ].join('\n'),
  };
}

function buildInviteCreatedEmail(opts: {
  token: string;
  tenantKey: string | undefined;
  role: string | undefined;
  publicBaseUrl: string;
}): { subject: string; text: string } {
  const origin = opts.tenantKey
    ? opts.publicBaseUrl.replace('{tenantKey}', opts.tenantKey)
    : opts.publicBaseUrl;

  const link = `${origin}/accept-invite?token=${encodeURIComponent(opts.token)}`;
  const roleLabel = opts.role === 'ADMIN' ? 'an admin' : 'a member';

  return {
    subject: "You've been invited to join Hubins",
    text: [
      `You've been invited to join a Hubins workspace as ${roleLabel}.`,
      '',
      'Click the link below to accept the invitation. This link expires in 7 days.',
      '',
      link,
      '',
      'If you were not expecting this invitation, you can safely ignore this email.',
      '',
      '— Hubins',
    ].join('\n'),
  };
}

function buildEmailContent(
  type: OutboxMessageType,
  payload: PlainOutboxPayload,
  publicBaseUrl: string,
): { subject: string; text: string } {
  switch (type) {
    case 'password.reset':
      return buildPasswordResetEmail({
        token: payload.token,
        tenantKey: payload.tenantKey,
        publicBaseUrl,
      });

    case 'email.verify':
      return buildEmailVerifyEmail({
        token: payload.token,
        tenantKey: payload.tenantKey,
        publicBaseUrl,
      });

    case 'invite.created':
      return buildInviteCreatedEmail({
        token: payload.token,
        tenantKey: payload.tenantKey,
        role: payload.role,
        publicBaseUrl,
      });

    default: {
      // Exhaustive check — TypeScript will error if a new type is added to
      // OutboxMessageType without updating this switch.
      const _exhaustive: never = type;
      void _exhaustive;
      throw new NonRetryableEmailError(`Unknown outbox message type: ${String(type)}`);
    }
  }
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * SMTP-backed EmailAdapter for production use.
 *
 * SMTP errors are classified into two categories:
 * - Retryable (5xx SMTP, connection refused, ETIMEDOUT): worker will retry with backoff.
 * - Non-retryable (5xx permanent rejection, invalid recipient): worker dead-letters immediately.
 *
 * Classification heuristic:
 * - responseCode 5xx where the server explicitly rejects the message permanently → NonRetryable
 * - Everything else → Retryable (conservative fail-safe; worst case is an extra retry)
 */
export class SmtpEmailAdapter implements EmailAdapter {
  private readonly transporter: Transporter;

  constructor(
    private readonly config: SmtpEmailAdapterConfig,
    private readonly deps: {
      logger: Logger;
      tokenHasher: TokenHasher;
    },
  ) {
    this.transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
    });
  }

  async send(opts: {
    to: string;
    type: OutboxMessageType;
    payload: PlainOutboxPayload;
    idempotencyKey: string;
  }): Promise<void> {
    const emailHash = this.deps.tokenHasher.hash(opts.to.toLowerCase());

    this.deps.logger.info({
      msg: 'email.smtp.sending',
      event: 'email.smtp.sending',
      type: opts.type,
      idempotencyKey: opts.idempotencyKey,
      emailHash,
    });

    const { subject, text } = buildEmailContent(opts.type, opts.payload, this.config.publicBaseUrl);

    try {
      await this.transporter.sendMail({
        from: this.config.from,
        to: opts.to,
        subject,
        text,
      });

      this.deps.logger.info({
        msg: 'email.smtp.sent',
        event: 'email.smtp.sent',
        type: opts.type,
        idempotencyKey: opts.idempotencyKey,
        emailHash,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      const responseCode =
        err instanceof Error && 'responseCode' in err
          ? (err as { responseCode?: number }).responseCode
          : undefined;

      this.deps.logger.warn({
        msg: 'email.smtp.error',
        event: 'email.smtp.error',
        type: opts.type,
        idempotencyKey: opts.idempotencyKey,
        emailHash,
        responseCode,
        error: message,
      });

      // Permanent SMTP rejection (e.g., 550 user not found, 521 server
      // does not accept mail). Dead-letter immediately — retrying will not help.
      if (typeof responseCode === 'number' && responseCode >= 500) {
        throw new NonRetryableEmailError(`SMTP permanent rejection (${responseCode}): ${message}`);
      }

      // Everything else — connection errors, timeouts, 4xx temporary failures.
      // Throw RetryableEmailError so the worker schedules a retry with backoff.
      throw new RetryableEmailError(`SMTP transient error: ${message}`);
    }
  }
}
