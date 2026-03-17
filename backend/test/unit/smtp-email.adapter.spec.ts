import { beforeEach, describe, expect, it, vi } from 'vitest';
import winston from 'winston';

import { Sha256TokenHasher } from '../../src/shared/security/sha256-token-hasher';
import { SmtpEmailAdapter } from '../../src/shared/outbox/smtp-email.adapter';
import { NonRetryableEmailError, RetryableEmailError } from '../../src/shared/outbox/outbox.worker';

type SentMail = {
  from: string;
  to: string;
  subject: string;
  text: string;
};

const sendMail = vi.fn<(message: SentMail) => Promise<unknown>>();

vi.mock('nodemailer', () => ({
  default: {
    createTransport: vi.fn(() => ({
      sendMail,
    })),
  },
}));

const logger = winston.createLogger({
  silent: true,
  transports: [],
});

function buildAdapter(publicBaseUrl = 'http://{tenantKey}.localhost:3000') {
  return new SmtpEmailAdapter(
    {
      host: 'localhost',
      port: 1025,
      secure: false,
      from: 'Hubins <noreply@hubins.local>',
      publicBaseUrl,
    },
    {
      logger,
      tokenHasher: new Sha256TokenHasher(),
    },
  );
}

function getSentMail(): SentMail {
  const mail = sendMail.mock.calls[0]?.[0];

  if (!mail) {
    throw new Error('Expected sendMail to be called with a message payload.');
  }

  return mail;
}

describe('SmtpEmailAdapter', () => {
  beforeEach(() => {
    sendMail.mockReset();
  });

  it('builds an invite email with the tenant-derived accept-invite link', async () => {
    sendMail.mockResolvedValueOnce({});
    const adapter = buildAdapter();

    await adapter.send({
      to: 'admin@example.com',
      type: 'invite.created',
      payload: {
        token: 'invite-token',
        toEmail: 'admin@example.com',
        tenantKey: 'goodwill-ca',
        role: 'ADMIN',
      },
      idempotencyKey: 'idemp-1',
    });

    expect(sendMail).toHaveBeenCalledTimes(1);

    const mail = getSentMail();
    expect(mail.to).toBe('admin@example.com');
    expect(mail.subject).toBe("You've been invited to join Hubins");
    expect(mail.text).toContain(
      'http://goodwill-ca.localhost:3000/accept-invite?token=invite-token',
    );
  });

  it('builds a verify-email message with the tenant-derived verification link', async () => {
    sendMail.mockResolvedValueOnce({});
    const adapter = buildAdapter();

    await adapter.send({
      to: 'user@example.com',
      type: 'email.verify',
      payload: {
        token: 'verify-token',
        toEmail: 'user@example.com',
        tenantKey: 'goodwill-open',
      },
      idempotencyKey: 'idemp-2',
    });

    const mail = getSentMail();
    expect(mail.to).toBe('user@example.com');
    expect(mail.subject).toBe('Verify your Hubins email address');
    expect(mail.text).toContain(
      'http://goodwill-open.localhost:3000/verify-email?token=verify-token',
    );
  });

  it('builds a password-reset message with the tenant-derived reset link', async () => {
    sendMail.mockResolvedValueOnce({});
    const adapter = buildAdapter();

    await adapter.send({
      to: 'user@example.com',
      type: 'password.reset',
      payload: {
        token: 'reset-token',
        toEmail: 'user@example.com',
        tenantKey: 'goodwill-open',
      },
      idempotencyKey: 'idemp-3',
    });

    const mail = getSentMail();
    expect(mail.to).toBe('user@example.com');
    expect(mail.subject).toBe('Reset your Hubins password');
    expect(mail.text).toContain(
      'http://goodwill-open.localhost:3000/auth/reset-password?token=reset-token',
    );
  });

  it('classifies SMTP 5xx provider rejections as non-retryable', async () => {
    const err = Object.assign(new Error('Invalid login'), { responseCode: 535 });
    sendMail.mockRejectedValueOnce(err);
    const adapter = buildAdapter();

    await expect(
      adapter.send({
        to: 'user@example.com',
        type: 'email.verify',
        payload: {
          token: 'verify-token',
          toEmail: 'user@example.com',
          tenantKey: 'goodwill-open',
        },
        idempotencyKey: 'idemp-4',
      }),
    ).rejects.toBeInstanceOf(NonRetryableEmailError);
  });

  it('classifies connection failures as retryable', async () => {
    sendMail.mockRejectedValueOnce(new Error('connect ETIMEDOUT 127.0.0.1:1025'));
    const adapter = buildAdapter();

    await expect(
      adapter.send({
        to: 'user@example.com',
        type: 'password.reset',
        payload: {
          token: 'reset-token',
          toEmail: 'user@example.com',
          tenantKey: 'goodwill-open',
        },
        idempotencyKey: 'idemp-5',
      }),
    ).rejects.toBeInstanceOf(RetryableEmailError);
  });
});
